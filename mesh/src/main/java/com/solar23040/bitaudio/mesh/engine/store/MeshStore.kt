package com.solar23040.bitaudio.mesh.engine.store

import com.solar23040.bitaudio.mesh.ChannelId

/**
 * One sealed packet kept for store-and-forward.
 *
 * [frame] is the exact signed wire frame produced by the publisher; plaintext
 * is never stored.
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
 * Persistence boundary for store-and-forward. Implementations are thread-safe,
 * copy retained byte arrays, and never expose plaintext.
 */
interface MeshStore : AutoCloseable {
    fun save(packet: StoredPacket)

    fun loadUnexpired(nowMs: Long): List<StoredPacket>

    fun deleteExpired(nowMs: Long): Int

    /** Last allocated per-channel counter; the first call returns 1. */
    fun nextCounter(channel: ChannelId): Long

    fun size(): Int

    override fun close() = Unit
}

/** Process-local store used by unit tests and the simulator. */
class InMemoryMeshStore(
    private val maxPackets: Int = 4_096,
    initialCounters: Map<ChannelId, Long> = emptyMap(),
) : MeshStore {

    private data class Key(val channel: String, val messageId: String, val chunkIndex: Int)

    private val lock = Any()
    private val packets = LinkedHashMap<Key, StoredPacket>()
    private val counters = HashMap<ChannelId, Long>()

    init {
        require(maxPackets > 0) { "maxPackets must be > 0" }
        initialCounters.forEach { (channel, value) ->
            require(value >= 0) { "counter must be >= 0" }
            counters[channel] = value
        }
    }

    override fun save(packet: StoredPacket) = synchronized(lock) {
        val key = Key(packet.channel.hex, packet.messageId, packet.chunkIndex)
        packets.remove(key)
        packets[key] = packet.copy(frame = packet.frame.copyOf())
        while (packets.size > maxPackets) {
            val oldest = packets.keys.iterator()
            if (!oldest.hasNext()) break
            oldest.next()
            oldest.remove()
        }
        Unit
    }

    override fun loadUnexpired(nowMs: Long): List<StoredPacket> = synchronized(lock) {
        packets.values
            .filter { it.expiresAtMs > nowMs }
            .sortedWith(compareBy({ it.timestampMs }, { it.chunkIndex }))
            .map { it.copy(frame = it.frame.copyOf()) }
    }

    override fun deleteExpired(nowMs: Long): Int = synchronized(lock) {
        val before = packets.size
        packets.entries.removeAll { it.value.expiresAtMs <= nowMs }
        before - packets.size
    }

    override fun nextCounter(channel: ChannelId): Long = synchronized(lock) {
        val next = (counters[channel] ?: 0L) + 1L
        counters[channel] = next
        next
    }

    override fun size(): Int = synchronized(lock) { packets.size }
}
