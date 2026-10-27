package com.solar23040.bitaudio

import android.content.Context
import android.util.Log
import com.bitaudio.crypto.AndroidKeystoreSecretStore
import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.DefaultCrypto
import com.bitaudio.crypto.IdentityFingerprint
import com.bitaudio.crypto.IdentityManager
import com.meshvoice.transport.BleTransport
import com.solar23040.bitaudio.data.Channel
import com.solar23040.bitaudio.data.ChannelRepository
import com.solar23040.bitaudio.mesh.ChannelId
import com.solar23040.bitaudio.mesh.MeshMessage
import com.solar23040.bitaudio.mesh.NearbyPeer
import com.solar23040.bitaudio.mesh.engine.MeshChannel
import com.solar23040.bitaudio.mesh.engine.MeshEngine
import com.solar23040.bitaudio.mesh.engine.store.SqliteMeshStore
import com.solar23040.bitaudio.transport.MeshRuntime
import java.io.Closeable
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

/**
 * Real BLE mesh runtime: [BleTransport] under [MeshEngine], with sealed frames
 * persisted in [SqliteMeshStore] so an offline clip is handed off when a peer
 * appears.
 *
 * The nearby channel is always present inside the engine; private channels are
 * added from [ChannelRepository] as they are created or joined.
 */
class BleMeshRuntime(
    context: Context,
    private val channels: ChannelRepository,
    private val scope: CoroutineScope,
) : MeshRuntime, Closeable {

    private val appContext = context.applicationContext
    private val lock = Any()
    private val transport = BleTransport(
        context = appContext,
        externalScope = scope,
        onError = { error -> Log.w(TAG, "BLE transport error", error) },
    )
    private val store = SqliteMeshStore(appContext)

    private var identityManager: IdentityManager? = null
    private var crypto: DefaultCrypto? = null
    private var engine: MeshEngine? = null
    private var channelJob: Job? = null
    private var peerMirrorJob: Job? = null
    private var syncedKeys: Map<ChannelId, String> = emptyMap()
    private val messageListeners = CopyOnWriteArrayList<(MeshMessage) -> Unit>()
    private val readyListeners = CopyOnWriteArrayList<() -> Unit>()

    private val _nearbyPeers = MutableStateFlow<List<NearbyPeer>>(emptyList())
    override val nearbyPeers: StateFlow<List<NearbyPeer>> = _nearbyPeers.asStateFlow()

    private val _fingerprint = MutableStateFlow("")
    override val identityFingerprint: StateFlow<String> = _fingerprint.asStateFlow()

    @Volatile
    private var nickname: String = ""

    @Volatile
    private var discoverable: Boolean = true

    @Volatile
    private var running = false

    override val isAvailable: Boolean = true

    init {
        // Keep the engine's channel set in step with channels created or joined
        // while the service is already running.
        channelJob = scope.launch {
            channels.channels.collect { current ->
                synchronized(lock) { syncChannelsLocked(current) }
            }
        }
        // Settings needs the fingerprint even before the foreground service starts.
        scope.launch(Dispatchers.IO) {
            synchronized(lock) {
                val manager = identityManager ?: runCatching {
                    IdentityManager(AndroidKeystoreSecretStore(appContext))
                }.getOrNull() ?: return@launch
                identityManager = manager
                val identity = crypto ?: runCatching { DefaultCrypto(manager) }.getOrNull()
                    ?: return@launch
                crypto = identity
                _fingerprint.value = IdentityFingerprint.of(identity.publicKey)
            }
        }
    }

    override fun start() {
        synchronized(lock) {
            if (running) return
            val manager = identityManager ?: runCatching {
                IdentityManager(AndroidKeystoreSecretStore(appContext))
            }.getOrElse { error ->
                Log.e(TAG, "Could not load the mesh identity", error)
                return
            }.also { identityManager = it }

            val identity = crypto ?: runCatching { DefaultCrypto(manager) }.getOrElse { error ->
                Log.e(TAG, "Could not create the crypto layer", error)
                return
            }.also {
                crypto = it
                _fingerprint.value = IdentityFingerprint.of(it.publicKey)
            }

            val mesh = try {
                MeshEngine(
                    transport = transport,
                    crypto = identity,
                    localPublicKey = identity.publicKey,
                    externalScope = scope,
                    store = store,
                    initialNickname = nickname,
                    discoverable = discoverable,
                )
            } catch (e: Exception) {
                Log.e(TAG, "Could not create the mesh engine", e)
                return
            }

            engine = mesh
            syncedKeys = emptyMap()
            syncChannelsLocked(channels.channels.value)
            mesh.onMessage { message -> fanOut(message) }
            peerMirrorJob = scope.launch {
                mesh.peers().collect { peers -> _nearbyPeers.value = peers }
            }
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

    override fun setNickname(nickname: String) {
        val clean = nickname.trim().take(32)
        if (clean.isBlank()) return
        this.nickname = clean
        synchronized(lock) { engine }?.setNickname(clean)
    }

    override fun setDiscoverable(enabled: Boolean) {
        discoverable = enabled
        synchronized(lock) { engine }?.setDiscoverable(enabled)
    }

    override fun rotateIdentity() {
        val wasRunning = synchronized(lock) {
            val active = running
            if (!active) {
                false
            } else {
                running = false
                peerMirrorJob?.cancel()
                peerMirrorJob = null
                engine?.close()
                engine = null
                transport.stop()
                true
            }
        }
        runCatching {
            val manager = identityManager ?: runCatching {
                IdentityManager(AndroidKeystoreSecretStore(appContext))
            }.getOrElse { error ->
                Log.e(TAG, "Could not load the mesh identity", error)
                return
            }.also { identityManager = it }
            manager.rotate()
            synchronized(lock) { crypto = null }
            _fingerprint.value = IdentityFingerprint.of(manager.identity().publicKey)
            _nearbyPeers.value = emptyList()
        }.onFailure { error ->
            Log.e(TAG, "Could not rotate the identity", error)
        }
        if (wasRunning) start()
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
            peerMirrorJob?.cancel()
            peerMirrorJob = null
            engine?.close()
            engine = null
            transport.stop()
            syncedKeys = emptyMap()
            _nearbyPeers.value = emptyList()
        }
    }

    override fun setScanning(enabled: Boolean) {
        if (enabled) start()
    }

    override fun close() {
        stop()
        channelJob?.cancel()
        channelJob = null
        store.close()
    }

    /** Rebuilds the engine's private-channel set. Caller holds [lock]. */
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
