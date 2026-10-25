package com.solar23040.bitaudio.mesh.store

import com.solar23040.bitaudio.mesh.ChannelId

/**
 * One sealed packet kept for store-and-forward. The payload is never stored in
 * plaintext: [frame] is the exact signed wire frame produced by the publisher.
 */
data class StoredPacket(
    val channel: ChannelId,
    val messageId: String,
    val chunkIndex: Int,
    val timestampMs: Long,
    val expiresAtMs: Long,
    val frame: ByteArray,
) {
    init {
        require(messageId.length == 16) { "messageId must be 16 hex characters" }
        require(chunkIndex >= 0) { "chunkIndex must be >= 0" }
        require(frame.size in 107..512) { "frame size out of range: ${frame.size}" }
    }
}

/**
 * Persistence boundary for store-and-forward.
 *
 * Production uses [SqliteMeshStore]; tests and the simulator use
 * [InMemoryMeshStore]. Implementations must be safe to call from multiple
 * coroutines and must never block for long on the caller's thread in
 * production (SQLite writes are short and bounded).
 */
interface MeshStore : AutoCloseable {

    /** Inserts or replaces one packet. */
    fun save(packet: StoredPacket)

    /** Returns packets whose expiry is strictly after [nowMs]. */
    fun loadUnexpired(nowMs: Long): List<StoredPacket>

    /** Deletes expired packets and returns how many were removed. */
    fun deleteExpired(nowMs: Long): Int

    /** Last allocated per-channel message counter; the first call returns 1. */
    fun nextCounter(channel: ChannelId): Long

    /** Number of stored rows, including not-yet-swept expired entries. */
    fun size(): Int

    fun clear()

    override fun close() = Unit
}

/**
 * Process-local store. Packets are bounded so a long-running test or a busy
 * simulator cannot grow without limit; the oldest rows are evicted first.
 */
class InMemoryMeshStore(
    private val maxPackets: Int = 4_096,
    initialCounters: Map<ChannelId, Long> = emptyMap(),
) : MeshStore {

    init {
        require(maxPackets > 0) { "maxPackets must be > 0" }
    }

    private val lock = Any()
    private val packets = LinkedHashMap<String, StoredPacket>()
    private val counters = HashMap<ChannelId, Long>()

    init {
        initialCounters.forEach { (channel, value) ->
            require(value >= 0) { "counter must be >= 0" }
            counters[channel] = value
        }
    }

    override fun save(packet: StoredPacket) = synchronized(lock) {
        val key = keyOf(packet)
        packets.remove(key)
        packets[key] = packet.copy(frame = packet.frame.copyOf())
        while (packets.size > maxPackets) {
            val iterator = packets.keys.iterator()
            if (!iterator.hasNext()) break
            iterator.next()
            iterator.remove()
        }
    }

    override fun loadUnexpired(nowMs: Long): List<StoredPacket> = synchronized(lock) {
        packets.values
            .filter { it.expiresAtMs > nowMs }
            .map { it.copy(frame = it.frame.copyOf()) }
    }

    override fun deleteExpired(nowMs: Long): Int = synchronized(lock) {
        var removed = 0
        val iterator = packets.entries.iterator()
        while (iterator.hasNext()) {
            if (iterator.next().value.expiresAtMs <= nowMs) {
                iterator.remove()
                removed++
            }
        }
        removed
    }

    override fun nextCounter(channel: ChannelId): Long = synchronized(lock) {
        val next = (counters[channel] ?: 0L) + 1L
        counters[channel] = next
        next
    }

    override fun size(): Int = synchronized(lock) { packets.size }

    override fun clear() = synchronized(lock) {
        packets.clear()
        counters.clear()
    }

    private fun keyOf(packet: StoredPacket): String =
        "${packet.channel.hex}:${packet.messageId}:${packet.chunkIndex}"
}
