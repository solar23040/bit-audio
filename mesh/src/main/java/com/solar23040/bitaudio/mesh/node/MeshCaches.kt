package com.solar23040.bitaudio.mesh.node

/**
 * Bounded, thread-safe cache with per-entry expiry. Access order is not used;
 * entries are removed oldest-first when the cache is full.
 */
internal class ExpiringCache<V>(
    private val maxEntries: Int,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private data class Entry<V>(val value: V, val expiresAtMs: Long)

    private val entries = LinkedHashMap<String, Entry<V>>()

    init {
        require(maxEntries > 0) { "maxEntries must be > 0" }
    }

    /** Returns the live value, or null when absent or expired. */
    @Synchronized
    fun get(key: String): V? {
        val entry = entries[key] ?: return null
        if (entry.expiresAtMs <= clock()) {
            entries.remove(key)
            return null
        }
        return entry.value
    }

    /** Stores [value] until [expiresAtMs]. Returns false if the key already exists. */
    @Synchronized
    fun putIfAbsent(key: String, value: V, expiresAtMs: Long): Boolean {
        val existing = entries[key]
        if (existing != null && existing.expiresAtMs > clock()) return false
        entries.remove(key)
        entries[key] = Entry(value, expiresAtMs)
        trim()
        return true
    }

    @Synchronized
    fun put(key: String, value: V, expiresAtMs: Long) {
        entries.remove(key)
        entries[key] = Entry(value, expiresAtMs)
        trim()
    }

    @Synchronized
    fun prune() {
        val now = clock()
        entries.entries.removeAll { it.value.expiresAtMs <= now }
    }

    @Synchronized
    fun clear() {
        entries.clear()
    }

    @Synchronized
    fun size(): Int = entries.size

    private fun trim() {
        while (entries.size > maxEntries) {
            val oldest = entries.keys.iterator()
            if (!oldest.hasNext()) break
            oldest.next()
            oldest.remove()
        }
    }
}

/** Reassembles plaintext chunks per (channel, identity, message). */
internal class ReassemblyBuffer(
    private val maxMessages: Int,
    private val timeoutMs: Long,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private class Partial(
        val totalChunks: Int,
        val timestampMs: Long,
        val createdAtMs: Long,
        val chunks: Array<ByteArray?>,
        var plaintextBytes: Int,
    )

    private val partials = LinkedHashMap<String, Partial>()

    init {
        require(maxMessages > 0)
        require(timeoutMs > 0)
    }

    /** Adds one opened chunk. Returns the complete plaintext when the last chunk arrives. */
    @Synchronized
    fun offer(
        key: String,
        timestampMs: Long,
        totalChunks: Int,
        chunkIndex: Int,
        plaintext: ByteArray,
    ): ByteArray? {
        if (totalChunks !in 1..MeshPacket.MAX_CHUNKS) return null
        if (chunkIndex !in 0 until totalChunks) return null
        expire()

        var partial = partials[key]
        if (partial == null) {
            while (partials.size >= maxMessages) {
                val oldest = partials.keys.iterator()
                if (!oldest.hasNext()) break
                oldest.next()
                oldest.remove()
            }
            partial = Partial(
                totalChunks = totalChunks,
                timestampMs = timestampMs,
                createdAtMs = clock(),
                chunks = arrayOfNulls(totalChunks),
                plaintextBytes = 0,
            )
            partials[key] = partial
        }
        if (partial.totalChunks != totalChunks || partial.timestampMs != timestampMs) return null
        if (partial.chunks[chunkIndex] != null) return null

        partial.chunks[chunkIndex] = plaintext.copyOf()
        partial.plaintextBytes += plaintext.size
        if (partial.plaintextBytes > MeshPacket.MAX_PLAINTEXT_MESSAGE_SIZE) {
            partials.remove(key)
            return null
        }

        if (partial.chunks.any { it == null }) return null
        partials.remove(key)
        val complete = ByteArray(partial.plaintextBytes)
        var offset = 0
        for (chunk in partial.chunks) {
            val bytes = chunk ?: return null
            bytes.copyInto(complete, offset)
            offset += bytes.size
        }
        return complete
    }

    @Synchronized
    fun expire() {
        val cutoff = clock() - timeoutMs
        partials.entries.removeAll { it.value.createdAtMs < cutoff }
    }

    @Synchronized
    fun remove(key: String) {
        partials.remove(key)
    }

    @Synchronized
    fun clear() {
        partials.clear()
    }

    @Synchronized
    fun size(): Int = partials.size
}
