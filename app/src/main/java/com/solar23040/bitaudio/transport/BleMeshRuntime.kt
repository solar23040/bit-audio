package com.solar23040.bitaudio.transport

import android.content.Context
import android.util.Log
import com.bitaudio.crypto.AndroidKeystoreSecretStore
import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.DefaultCrypto
import com.bitaudio.crypto.IdentityManager
import com.meshvoice.transport.BleTransport
import com.solar23040.bitaudio.data.Channel
import com.solar23040.bitaudio.mesh.ChannelId
import com.solar23040.bitaudio.mesh.MeshMessage
import com.solar23040.bitaudio.mesh.engine.MeshChannel
import com.solar23040.bitaudio.mesh.engine.MeshEngine
import com.solar23040.bitaudio.mesh.engine.store.SqliteMeshStore
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

/**
 * Real BLE mesh runtime: [BleTransport] under [MeshEngine], with sealed frames
 * persisted in [SqliteMeshStore] so an offline clip is handed off when a peer
 * appears.
 *
 * The engine and its receive callback are rebuilt on every [start] because
 * [BleTransport.stop] drops all callbacks; the store outlives the engine so
 * counters and queued frames survive a service restart.
 *
 * Roster note: a channel currently contains only the local Ed25519 key. The
 * 0x03 `MEMBER_ANNOUNCE` exchange that adds remote keys is not implemented in
 * this phase, so remote packets are rejected as unknown senders even though the
 * transport and store-and-forward path are live.
 */
class BleMeshRuntime(
    context: Context,
    private val channels: StateFlow<List<Channel>>,
    private val scope: CoroutineScope,
) : MeshRuntime, AutoCloseable {

    private val appContext = context.applicationContext
    private val lock = Any()
    private val transport = BleTransport(
        appContext,
        externalScope = scope,
        onError = { error -> Log.w(TAG, "BLE transport error", error) },
    )
    private val store = SqliteMeshStore(appContext)

    private var crypto: DefaultCrypto? = null
    private var engine: MeshEngine? = null
    private var channelJob: Job? = null
    private var syncedKeys: Map<ChannelId, String> = emptyMap()
    private val messageListeners = CopyOnWriteArrayList<(MeshMessage) -> Unit>()
    private val readyListeners = CopyOnWriteArrayList<() -> Unit>()

    @Volatile
    private var running = false

    override val isAvailable: Boolean = true

    init {
        // Keep the engine's channel set in step with channels created or joined
        // while the service is already running.
        channelJob = scope.launch {
            channels.collect { current ->
                synchronized(lock) { syncChannelsLocked(current) }
            }
        }
    }

    override fun start() {
        synchronized(lock) {
            if (running) return
            val identity = crypto ?: try {
                DefaultCrypto(IdentityManager(AndroidKeystoreSecretStore(appContext)))
                    .also { crypto = it }
            } catch (e: Exception) {
                Log.e(TAG, "Could not load the mesh identity", e)
                return
            }

            val mesh = try {
                MeshEngine(
                    transport = transport,
                    crypto = identity,
                    localPublicKey = identity.publicKey,
                    externalScope = scope,
                    store = store,
                )
            } catch (e: Exception) {
                Log.e(TAG, "Could not create the mesh engine", e)
                return
            }

            engine = mesh
            syncChannelsLocked(channels.value)
            mesh.onMessage { message -> fanOut(message) }
            transport.start()
            running = true
        }
        notifyReady()
    }

    override suspend fun publish(channelId: String, payload: ByteArray): Boolean {
        val active = synchronized(lock) { engine } ?: return false
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
        synchronized(lock) {
            if (!running) return
            running = false
            engine?.close()
            engine = null
            transport.stop()
        }
    }

    /**
     * [BleTransport] exposes no scan-pause API, so switching the duty cycle on
     * only guarantees the transport is running; switching it off leaves the
     * radio up rather than making this node undiscoverable.
     */
    override fun setScanning(enabled: Boolean) {
        if (enabled) start()
    }

    override fun close() {
        stop()
        channelJob?.cancel()
        channelJob = null
        store.close()
    }

    /** Rebuilds the engine's channel set. Caller holds [lock]. */
    private fun syncChannelsLocked(current: List<Channel>) {
        val mesh = engine ?: return
        val desired = LinkedHashMap<ChannelId, Pair<String, MeshChannel>>()
        for (channel in current) {
            val meshChannel = toMeshChannel(channel) ?: continue
            desired[meshChannel.channelId] = channel.key to meshChannel
        }

        for (id in syncedKeys.keys - desired.keys) {
            mesh.removeChannel(id)
        }
        for ((id, entry) in desired) {
            if (syncedKeys[id] == entry.first) continue
            mesh.addChannel(entry.second)
        }
        syncedKeys = desired.mapValues { it.value.first }
    }

    private fun toMeshChannel(channel: Channel): MeshChannel? {
        val identity = crypto ?: return null
        val key = runCatching { Base64.getUrlDecoder().decode(channel.key) }.getOrNull() ?: return null
        if (key.size != ChannelKeys.KEY_SIZE) return null
        return runCatching {
            MeshChannel(key, listOf(identity.publicKey))
        }.getOrNull()
    }

    private companion object {
        const val TAG = "BleMeshRuntime"
    }
}
