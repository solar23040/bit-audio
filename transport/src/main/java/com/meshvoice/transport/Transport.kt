package com.meshvoice.transport

import kotlinx.coroutines.flow.Flow

/**
 * A directly reachable neighbour.
 *
 * [id] identifies the link and is only meaningful while the link exists; it is not a mesh sender
 * identity. [address] is the BLE MAC when known (Android may rotate it), and [rssi] is the last scan
 * reading.
 */
data class Peer(
    val id: String,
    val address: String? = null,
    val rssi: Int? = null,
)

data class ReceivedFrame(
    val from: Peer,
    val bytes: ByteArray,
)

/** Raised when a frame cannot be handed to the transport. */
class TransportException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Byte-oriented transport between directly connected devices.
 *
 * Implementations fragment and reassemble payloads, so callers can pass one complete mesh packet.
 * The transport does not guarantee delivery, ordering, or deduplication; the mesh layer owns those.
 */
interface Transport {
    /** Hands one complete frame to [peer]. Suspends while the link is being established. */
    suspend fun send(peer: Peer, bytes: ByteArray)

    /** Registers a receive callback. Close the returned handle to unregister it. */
    fun onReceive(callback: (ReceivedFrame) -> Unit): AutoCloseable

    /** Emits the current neighbour set on subscription and after it changes. */
    fun peers(): Flow<List<Peer>>
}
