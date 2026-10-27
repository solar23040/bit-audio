package com.solar23040.bitaudio

import com.solar23040.bitaudio.mesh.MeshMessage
import com.solar23040.bitaudio.mesh.NearbyPeer
import com.solar23040.bitaudio.transport.MeshRuntime
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Integration seam for the BLE mesh.
 *
 * Phase 2 replaces the offline instance with the real `:mesh` implementation.
 * The service and scan duty-cycler only talk to this interface, so wiring the
 * transport later does not require UI changes.
 */
class OfflineMeshRuntime : MeshRuntime {
    override val isAvailable: Boolean = false

    private val _nearbyPeers = MutableStateFlow<List<NearbyPeer>>(emptyList())
    override val nearbyPeers: StateFlow<List<NearbyPeer>> = _nearbyPeers.asStateFlow()

    private val _fingerprint = MutableStateFlow("")
    override val identityFingerprint: StateFlow<String> = _fingerprint.asStateFlow()

    override fun start() = Unit

    override fun stop() = Unit

    override fun setScanning(enabled: Boolean) = Unit

    override fun setNickname(nickname: String) = Unit

    override fun setDiscoverable(enabled: Boolean) = Unit

    override fun rotateIdentity() = Unit

    /** Nothing is listening, so notes stay Queued until a real mesh is wired in. */
    override suspend fun publish(channelId: String, payload: ByteArray): Boolean = false

    override fun onMessage(callback: (MeshMessage) -> Unit): AutoCloseable =
        AutoCloseable { }

    override fun onReady(callback: () -> Unit): AutoCloseable = AutoCloseable { }
}
