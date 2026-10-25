package com.solar23040.bitaudio.mesh.node

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/** One store-and-forward entry. Only sealed packets are persisted, never plaintext. */
data class StoredMessage(
    val key: String,
    val channelId: String,
    val messageId: String,
    val createdAtMs: Long,
    val timestampMs: Long,
    val expiresAtMs: Long,
    /** Sealed wire packets in chunk order. */
    val packets: List<ByteArray>,
)

/**
 * Persistence boundary for store-and-forward. Implementations must be
 * thread-safe and must copy every byte array they keep or return.
 */
interface PacketStore : AutoCloseable {
    /** Replaces the entry with the same [StoredMessage.key]. */
    fun put(message: StoredMessage)

    /** Adds one sealed chunk. Returns false when the entry is full or invalid. */
    fun append(
        key: String,
        channelId: String,
        messageId: String,
        chunkIndex: Int,
        packet: ByteArray,
        createdAtMs: Long,
        timestampMs: Long,
        expiresAtMs: Long,
    ): Boolean

    /** Entries that have not expired at [nowMs], oldest first. */
    fun snapshot(nowMs: Long): List<StoredMessage>

    fun remove(key: String)

    /** Drops expired entries and returns how many were removed. */
    fun expire(nowMs: Long): Int

    /**
     * Allocates the next per-(channel, identity) message counter. Counters
     * start at 1 and are never reused within a retention window.
     */
    fun nextCounter(counterKey: String): Long

    override fun close() = Unit
}

/** In-memory store used by tests and the simulator. */
class InMemoryPacketStore(
    private val maxMessages: Int = 512,
    private val maxBytes: Long = 8L * 1024L * 1024L,
) : PacketStore {

    private data class MutableMessage(
        val channelId: String,
        val messageId: String,
        val createdAtMs: Long,
        val timestampMs: Long,
        val expiresAtMs: Long,
        val packets: MutableMap<Int, ByteArray>,
    )

    private val messages = LinkedHashMap<String, MutableMessage>()
    private val counters = HashMap<String, Long>()
    private var storedBytes = 0L

    init {
        require(maxMessages > 0)
        require(maxBytes > 0)
    }

    @Synchronized
    override fun put(message: StoredMessage) {
        require(message.packets.all { it.size in MeshPacket.HEADER_SIZE..MeshPacket.MAX_PACKET_SIZE })
        remove(message.key)
        val mutable = MutableMessage(
            channelId = message.channelId,
            messageId = message.messageId,
            createdAtMs = message.createdAtMs,
            timestampMs = message.timestampMs,
            expiresAtMs = message.expiresAtMs,
            packets = LinkedHashMap(),
        )
        message.packets.forEachIndexed { index, packet ->
            mutable.packets[index] = packet.copyOf()
            storedBytes += packet.size
        }
        messages[message.key] = mutable
        enforceLimits(message.createdAtMs)
    }

    @Synchronized
    override fun append(
        key: String,
        channelId: String,
        messageId: String,
        chunkIndex: Int,
        packet: ByteArray,
        createdAtMs: Long,
        timestampMs: Long,
        expiresAtMs: Long,
    ): Boolean {
        if (packet.size !in MeshPacket.HEADER_SIZE..MeshPacket.MAX_PACKET_SIZE) return false
        if (chunkIndex !in 0 until MeshPacket.MAX_CHUNKS) return false
        val existing = messages[key]
        if (existing != null) {
            if (existing.packets.containsKey(chunkIndex)) return true
            existing.packets[chunkIndex] = packet.copyOf()
            storedBytes += packet.size
        } else {
            if (messages.size >= maxMessages) return false
            val mutable = MutableMessage(
                channelId = channelId,
                messageId = messageId,
                createdAtMs = createdAtMs,
                timestampMs = timestampMs,
                expiresAtMs = expiresAtMs,
                packets = linkedMapOf(chunkIndex to packet.copyOf()),
            )
            messages[key] = mutable
            storedBytes += packet.size
        }
        enforceLimits(createdAtMs)
        return true
    }

    @Synchronized
    override fun snapshot(nowMs: Long): List<StoredMessage> {
        expire(nowMs)
        return messages.map { (key, value) ->
            value.toStored(key)
        }
    }

    @Synchronized
    override fun remove(key: String) {
        val removed = messages.remove(key) ?: return
        storedBytes -= removed.packets.values.sumOf { it.size.toLong() }
    }

    @Synchronized
    override fun expire(nowMs: Long): Int {
        val expired = messages.filterValues { it.expiresAtMs <= nowMs }.keys.toList()
        expired.forEach(::remove)
        return expired.size
    }

    @Synchronized
    override fun nextCounter(counterKey: String): Long {
        val next = (counters[counterKey] ?: 0L) + 1
        counters[counterKey] = next
        return next
    }

    private fun enforceLimits(nowMs: Long) {
        expire(nowMs)
        while (messages.size > maxMessages || storedBytes > maxBytes) {
            val oldest = messages.keys.firstOrNull() ?: break
            remove(oldest)
        }
    }

    private fun MutableMessage.toStored(key: String): StoredMessage = StoredMessage(
        key = key,
        channelId = channelId,
        messageId = messageId,
        createdAtMs = createdAtMs,
        timestampMs = timestampMs,
        expiresAtMs = expiresAtMs,
        packets = packets.entries.sortedBy { it.key }.map { it.value.copyOf() },
    )
}

/**
 * File-backed store-and-forward queue.
 *
 * The message file and the counter file are replaced atomically through a
 * same-directory temporary file. A corrupt or truncated file is treated as an
 * empty store so a bad write can never prevent the app from starting.
 */
class FilePacketStore(
    private val directory: File,
    private val maxMessages: Int = 512,
    private val maxBytes: Long = 8L * 1024L * 1024L,
) : PacketStore {

    private val messagesFile = File(directory, "mesh-store.bin")
    private val countersFile = File(directory, "mesh-counters.bin")
    private val messages = LinkedHashMap<String, MutableMessage>()
    private val counters = HashMap<String, Long>()
    private var storedBytes = 0L

    init {
        require(maxMessages > 0)
        require(maxBytes > 0)
        directory.mkdirs()
        load()
    }

    @Synchronized
    override fun put(message: StoredMessage) {
        require(message.packets.all { it.size in MeshPacket.HEADER_SIZE..MeshPacket.MAX_PACKET_SIZE })
        remove(message.key)
        val mutable = MutableMessage(
            channelId = message.channelId,
            messageId = message.messageId,
            createdAtMs = message.createdAtMs,
            timestampMs = message.timestampMs,
            expiresAtMs = message.expiresAtMs,
        )
        message.packets.forEachIndexed { index, packet ->
            mutable.packets[index] = packet.copyOf()
            storedBytes += packet.size
        }
        messages[message.key] = mutable
        enforceLimits(message.createdAtMs)
        persistMessages()
    }

    @Synchronized
    override fun append(
        key: String,
        channelId: String,
        messageId: String,
        chunkIndex: Int,
        packet: ByteArray,
        createdAtMs: Long,
        timestampMs: Long,
        expiresAtMs: Long,
    ): Boolean {
        if (packet.size !in MeshPacket.HEADER_SIZE..MeshPacket.MAX_PACKET_SIZE) return false
        if (chunkIndex !in 0 until MeshPacket.MAX_CHUNKS) return false
        val existing = messages[key]
        if (existing != null) {
            if (existing.packets.containsKey(chunkIndex)) return true
            existing.packets[chunkIndex] = packet.copyOf()
            storedBytes += packet.size
        } else {
            if (messages.size >= maxMessages) return false
            messages[key] = MutableMessage(
                channelId = channelId,
                messageId = messageId,
                createdAtMs = createdAtMs,
                timestampMs = timestampMs,
                expiresAtMs = expiresAtMs,
            ).also {
                it.packets[chunkIndex] = packet.copyOf()
            }
            storedBytes += packet.size
        }
        enforceLimits(createdAtMs)
        persistMessages()
        return true
    }

    @Synchronized
    override fun snapshot(nowMs: Long): List<StoredMessage> {
        expire(nowMs)
        return messages.map { (key, value) -> value.toStored(key) }
    }

    @Synchronized
    override fun remove(key: String) {
        val removed = messages.remove(key) ?: return
        storedBytes -= removed.packets.values.sumOf { it.size.toLong() }
        persistMessages()
    }

    @Synchronized
    override fun expire(nowMs: Long): Int {
        val expired = messages.filterValues { it.expiresAtMs <= nowMs }.keys.toList()
        expired.forEach { key ->
            val removed = messages.remove(key) ?: return@forEach
            storedBytes -= removed.packets.values.sumOf { it.size.toLong() }
        }
        if (expired.isNotEmpty()) persistMessages()
        return expired.size
    }

    @Synchronized
    override fun nextCounter(counterKey: String): Long {
        val next = (counters[counterKey] ?: 0L) + 1
        counters[counterKey] = next
        persistCounters()
        return next
    }

    private fun enforceLimits(nowMs: Long) {
        val expired = messages.filterValues { it.expiresAtMs <= nowMs }.keys.toList()
        expired.forEach { key ->
            val removed = messages.remove(key) ?: return@forEach
            storedBytes -= removed.packets.values.sumOf { it.size.toLong() }
        }
        while (messages.size > maxMessages || storedBytes > maxBytes) {
            val oldest = messages.keys.firstOrNull() ?: break
            val removed = messages.remove(oldest) ?: break
            storedBytes -= removed.packets.values.sumOf { it.size.toLong() }
        }
    }

    private fun load() {
        runCatching { loadMessages() }.getOrElse {
            messages.clear()
            counters.clear()
            storedBytes = 0
        }
        runCatching { loadCounters() }.getOrElse { counters.clear() }
    }

    private fun loadMessages() {
        if (!messagesFile.isFile) return
        DataInputStream(FileInputStream(messagesFile).buffered()).use { input ->
            if (input.readInt() != MAGIC) throw IOException("bad message store magic")
            if (input.readInt() != VERSION) throw IOException("unsupported message store version")
            val count = input.readInt()
            if (count !in 0..MAX_LOADED_MESSAGES) throw IOException("bad message count")
            repeat(count) {
                val key = input.readUTF().takeIf { it.length in 1..MAX_KEY_LENGTH }
                    ?: throw IOException("bad key")
                val channelId = input.readUTF()
                val messageId = input.readUTF()
                val createdAtMs = input.readLong()
                val timestampMs = input.readLong()
                val expiresAtMs = input.readLong()
                val packetCount = input.readInt()
                if (packetCount !in 0..MeshPacket.MAX_CHUNKS) throw IOException("bad packet count")
                val mutable = MutableMessage(
                    channelId = channelId,
                    messageId = messageId,
                    createdAtMs = createdAtMs,
                    timestampMs = timestampMs,
                    expiresAtMs = expiresAtMs,
                )
                repeat(packetCount) {
                    val chunkIndex = input.readInt()
                    val length = input.readInt()
                    if (chunkIndex !in 0 until MeshPacket.MAX_CHUNKS) throw IOException("bad chunk index")
                    if (length !in MeshPacket.HEADER_SIZE..MeshPacket.MAX_PACKET_SIZE) {
                        throw IOException("bad packet length")
                    }
                    val packet = ByteArray(length)
                    input.readFully(packet)
                    mutable.packets[chunkIndex] = packet
                    storedBytes += packet.size
                }
                messages[key] = mutable
            }
        }
        enforceLimits(System.currentTimeMillis())
    }

    private fun loadCounters() {
        if (!countersFile.isFile) return
        DataInputStream(FileInputStream(countersFile).buffered()).use { input ->
            if (input.readInt() != MAGIC) throw IOException("bad counter store magic")
            if (input.readInt() != VERSION) throw IOException("unsupported counter store version")
            val count = input.readInt()
            if (count !in 0..MAX_LOADED_COUNTERS) throw IOException("bad counter count")
            repeat(count) {
                val key = input.readUTF()
                val value = input.readLong()
                if (value < 0) throw IOException("bad counter value")
                counters[key] = value
            }
        }
    }

    private fun persistMessages() {
        val payload = ByteArrayOutputStream()
        DataOutputStream(payload).use { output ->
            output.writeInt(MAGIC)
            output.writeInt(VERSION)
            output.writeInt(messages.size)
            for ((key, message) in messages) {
                output.writeUTF(key)
                output.writeUTF(message.channelId)
                output.writeUTF(message.messageId)
                output.writeLong(message.createdAtMs)
                output.writeLong(message.timestampMs)
                output.writeLong(message.expiresAtMs)
                val packets = message.packets.entries.sortedBy { it.key }
                output.writeInt(packets.size)
                for ((chunkIndex, packet) in packets) {
                    output.writeInt(chunkIndex)
                    output.writeInt(packet.size)
                    output.write(packet)
                }
            }
        }
        writeAtomically(messagesFile, payload.toByteArray())
    }

    private fun persistCounters() {
        val payload = ByteArrayOutputStream()
        DataOutputStream(payload).use { output ->
            output.writeInt(MAGIC)
            output.writeInt(VERSION)
            output.writeInt(counters.size)
            for ((key, value) in counters) {
                output.writeUTF(key)
                output.writeLong(value)
            }
        }
        writeAtomically(countersFile, payload.toByteArray())
    }

    private fun writeAtomically(target: File, bytes: ByteArray) {
        directory.mkdirs()
        val temporary = File(directory, "${target.name}.tmp")
        temporary.writeBytes(bytes)
        if (!temporary.renameTo(target)) {
            temporary.copyTo(target, overwrite = true)
            temporary.delete()
        }
    }

    private fun MutableMessage.toStored(key: String): StoredMessage = StoredMessage(
        key = key,
        channelId = channelId,
        messageId = messageId,
        createdAtMs = createdAtMs,
        timestampMs = timestampMs,
        expiresAtMs = expiresAtMs,
        packets = packets.entries.sortedBy { it.key }.map { it.value.copyOf() },
    )

    private class MutableMessage(
        val channelId: String,
        val messageId: String,
        val createdAtMs: Long,
        val timestampMs: Long,
        val expiresAtMs: Long,
    ) {
        val packets = sortedMapOf<Int, ByteArray>()
    }

    private companion object {
        const val MAGIC = 0x424D5348 // "BMSH"
        const val VERSION = 1
        const val MAX_LOADED_MESSAGES = 10_000
        const val MAX_LOADED_COUNTERS = 10_000
        const val MAX_KEY_LENGTH = 160
    }
}
