package com.solar23040.bitaudio.transport

import com.solar23040.bitaudio.mesh.MeshMessage
import com.solar23040.bitaudio.mesh.NearbyPeer
import kotlinx.coroutines.flow.StateFlow

/**
 * App-facing send/receive boundary for the mesh.
 *
 * [publish] and [onMessage] mirror `:mesh`'s `Mesh` contract, but are keyed by
 * the channel ID string the app stores and return `false` instead of throwing
 * while the radio is down. The voice pipeline depends on this interface, not on
 * `:mesh`, so it can be unit-tested against any mesh implementation.
 */
interface MeshPort {
    /**
     * Publish one Opus payload on [channelId].
     *
     * Returns false when the mesh is not running yet or the channel is unknown;
     * the caller keeps the note queued and retries later.
     */
    suspend fun publish(channelId: String, payload: ByteArray): Boolean

    /** Register a plaintext delivery callback. Close the handle to unsubscribe. */
    fun onMessage(callback: (MeshMessage) -> Unit): AutoCloseable
}

/** App-facing lifecycle for the mesh transport. Implemented by the Phase 2 glue. */
interface MeshRuntime : MeshPort {
    /** False while the real BLE/mesh implementation is not wired in. */
    val isAvailable: Boolean

    /** Peers currently heard on the public nearby channel. */
    val nearbyPeers: StateFlow<List<NearbyPeer>>

    /** Short fingerprint of this install's identity key, empty until loaded. */
    val identityFingerprint: StateFlow<String>

    fun start()

    fun stop()

    /** Scan duty-cycle hook; safe to call when BLE is not running. */
    fun setScanning(enabled: Boolean)

    /** Update the nickname sent in future announcements. */
    fun setNickname(nickname: String)

    /** When false, stop announcing this device on the nearby channel. */
    fun setDiscoverable(enabled: Boolean)

    /** Creates a fresh Ed25519 identity; the old one can no longer decrypt. */
    fun rotateIdentity()

    /**
     * Registers a callback fired once the mesh is ready to publish (after every
     * [start]). This is where queued notes are retried. Close the handle to
     * unsubscribe. Callbacks run on a worker thread and must not block.
     */
    fun onReady(callback: () -> Unit): AutoCloseable
}
