package com.meshvoice.transport

import kotlinx.coroutines.flow.Flow

/**
 * A directly reachable BLE peer.
 *
 * [address] is the current BLE MAC address. Android may rotate it, so mesh-level identity must
 * not depend on it; [Peer] is only the transport hop address.
 */
data class Peer(
    val address: String,
    val name: String? = null,
    val rssi: Int = 0,
)

/**
 * Byte-oriented transport between directly connected devices.
 *
 * Implementations fragment and reassemble payloads, so callers can pass a whole mesh packet.
 * Delivery is best-effort: the mesh layer (TTL, dedup, store-and-forward) remains responsible for
 * end-to-end delivery.
 */
interface Transport {
    /** Queues [bytes] for [peer]. Non-blocking; failures are reported through the error callback. */
    fun send(peer: Peer, bytes: ByteArray)

    /** Installs the receive callback. A later call replaces the previous callback. */
    fun onReceive(cb: (Peer, ByteArray) -> Unit)

    /** Emits peers as they are discovered while scanning. */
    fun peers(): Flow<Peer>
}
