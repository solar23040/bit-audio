package com.solar23040.bitaudio

import android.content.Context
import android.util.Log
import com.bitaudio.crypto.AndroidKeystoreSecretStore
import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.DefaultCrypto
import com.bitaudio.crypto.IdentityManager
import com.meshvoice.transport.BleConfig
import com.meshvoice.transport.BleTransport
import com.solar23040.bitaudio.data.Channel
import com.solar23040.bitaudio.data.ChannelRepository
import com.solar23040.bitaudio.mesh.ChannelId
import com.solar23040.bitaudio.mesh.MeshMessage
import com.solar23040.bitaudio.mesh.node.FilePacketStore
import com.solar23040.bitaudio.mesh.node.MeshChannel
import com.solar23040.bitaudio.mesh.node.MeshConfig
import com.solar23040.bitaudio.mesh.node.MeshNode
import com.solar23040.bitaudio.transport.MeshRuntime
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import java.io.Closeable
import java.io.File
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Real mesh runtime: `BleTransport` below, [MeshNode] above, with the app's
 * channel repository kept in sync.
 *
 * [MeshRuntime] is the stable app-facing seam; `:app` owns only this glue.
 * Identity/keystore access and the packet store load happen on [scope], never on
 * the main thread. BLE scanning is established by [BleTransport.start];
 * [setScanning] only ensures the transport is running because pausing the
 * scanner would also drop established GATT links.
 */
class BleMeshRuntime(
    context: Context,
    private val channels: ChannelRepository,
    private val scope: CoroutineScope,
    private val clock: () -> Long = System::currentTimeMillis,
) : MeshRuntime, Closeable {

    private val appContext = context.applicationContext
    private val transport = BleTransport(
        context = appContext,
        config = BleConfig(),
        externalScope = scope,
        onError = { Log.w(TAG, "BLE transport error", it) },
    )
    private val storeDelegate = lazy { FilePacketStore(File(appContext.filesDir, STORE_DIRECTORY)) }
    private val store by storeDelegate
    private val crypto by lazy { DefaultCrypto(IdentityManager(AndroidKeystoreSecretStore(appContext))) }

    private val knownChannels = HashMap<String, ChannelSnapshot>()
    private val messageListeners = CopyOnWriteArrayList<(MeshMessage) -> Unit>()
    private val readyListeners = CopyOnWriteArrayList<() -> Unit>()
    private var node: MeshNode? = null
    private var startJob: Job? = null
    private var channelJob: Job? = null
    private val lifecycleLock = Any()

    @Volatile
    private var started = false

    override val isAvailable: Boolean = true

    /** Active mesh instance, or null while the service is stopped. */
    val mesh: MeshNode? get() = synchronized(lifecycleLock) { node }

    override fun start() {
        synchronized(lifecycleLock) {
            if (started) return
            started = true
        }
        startJob = scope.launch {
            val newNode = MeshNode(
                transport = transport,
                crypto = crypto,
                localPublicKey = crypto.publicKey,
                config = MeshConfig(),
                store = store,
                clock = clock,
                externalScope = scope,
            )
            synchronized(lifecycleLock) {
                if (!started) {
                    newNode.close()
                    return@launch
                }
                node = newNode
                syncChannels(newNode, channels.channels.value)
                // Fan every delivery out through the stable listener list so a
                // service restart does not re-subscribe the UI/pipeline.
                newNode.onMessage { message -> fanOut(message) }
                newNode.start()
                transport.start()
                channelJob = scope.launch {
                    channels.channels.collect { updated -> syncChannels(newNode, updated) }
                }
            }
            notifyReady()
        }
    }

    override suspend fun publish(channelId: String, payload: ByteArray): Boolean {
        val active = synchronized(lifecycleLock) { node } ?: return false
        return runCatching {
            active.publish(ChannelId.fromHex(channelId), payload)
        }.isSuccess
    }

    override fun onMessage(callback: (MeshMessage) -> Unit): AutoCloseable {
        messageListeners.add(callback)
        return AutoCloseable { messageListeners.remove(callback) }
    }

    override fun onReady(callback: () -> Unit): AutoCloseable {
        readyListeners.add(callback)
        return AutoCloseable { readyListeners.remove(callback) }
    }

    private fun fanOut(message: MeshMessage) {
        for (listener in messageListeners) {
            runCatching { listener(message) }
        }
    }

    private fun notifyReady() {
        for (listener in readyListeners) {
            runCatching { listener() }
        }
    }

    override fun stop() {
        synchronized(lifecycleLock) {
            if (!started) return
            started = false
            startJob?.cancel()
            startJob = null
            channelJob?.cancel()
            channelJob = null
            node?.close()
            node = null
            knownChannels.clear()
            transport.close()
        }
    }

    override fun setScanning(enabled: Boolean) {
        if (!started) return
        if (enabled) transport.start()
    }

    override fun close() {
        stop()
        if (storeDelegate.isInitialized()) store.close()
    }

    private fun syncChannels(mesh: MeshNode, updated: List<Channel>) {
        val liveIds = updated.mapTo(HashSet()) { it.id }
        knownChannels.keys.filter { it !in liveIds }.forEach { id ->
            runCatching { mesh.removeChannel(ChannelId.fromHex(id)) }
            knownChannels.remove(id)
        }

        for (channel in updated) {
            val previous = knownChannels[channel.id]
            if (previous != null && previous.key == channel.key && previous.ttl == channel.ttl) continue
            val key = runCatching { Base64.getUrlDecoder().decode(channel.key) }.getOrNull() ?: continue
            if (key.size != ChannelKeys.KEY_SIZE) continue
            val derivedId = ChannelId.fromBytes(ChannelKeys.channelId(key))
            if (derivedId.hex != channel.id) continue
            mesh.addChannel(
                MeshChannel(
                    id = derivedId,
                    key = key,
                    members = emptyList(),
                    ttl = channel.ttl,
                ),
            )
            knownChannels[channel.id] = ChannelSnapshot(channel.key, channel.ttl)
        }
    }

    private data class ChannelSnapshot(val key: String, val ttl: Int)

    private companion object {
        const val TAG = "BleMeshRuntime"
        const val STORE_DIRECTORY = "mesh-store"
    }
}
