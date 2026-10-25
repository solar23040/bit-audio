package com.solar23040.bitaudio.mesh.cache

/**
 * Bounded, expiring dedup set with LRU eviction.
 *
 * Used for packet chunks (keyed by channel + resolved identity + msg_id +
 * chunk_idx) and for completed messages. Access updates recency; expiry is
 * measured from first insertion, matching the replay window. All methods are
 * thread-safe and never block on I/O.
 */
internal class SeenIdCache(
    private val maxEntries: Int,
    private val expiryMs: Long,
    private val clock: () -> Long,
) {
    init {
        require(maxEntries > 0) { "maxEntries must be > 0" }
        require(expiryMs > 0) { "expiryMs must be > 0" }
    }

    private val lock = Any()

    // Access-order: oldest (least recently used) entry is first.
    private val entries = object : LinkedHashMap<String, Long>(16, 0.75f, true) {}

    private var nextSweepAt = 0L

    /**
     * Records [key]. Returns true the first time (inside [expiryMs]) and false
     * for a duplicate or an expired re-insert after expiry.
     */
    fun markSeen(key: String): Boolean = synchronized(lock) {
        val now = clock()
        val insertedAt = entries[key]
        if (insertedAt != null) {
            if (now - insertedAt <= expiryMs) return@synchronized false
            entries.remove(key)
        }

        entries[key] = now
        if (now >= nextSweepAt) {
            sweep(now)
            nextSweepAt = now + minOf(expiryMs, SWEEP_INTERVAL_MS)
        }
        trim()
        true
    }

    /** True when [key] is present and not expired. Refreshes LRU order. */
    fun isSeen(key: String): Boolean = synchronized(lock) {
        val insertedAt = entries[key] ?: return@synchronized false
        if (clock() - insertedAt > expiryMs) {
            entries.remove(key)
            false
        } else {
            true
        }
    }

    fun size(): Int = synchronized(lock) { entries.size }

    fun clear() = synchronized(lock) {
        entries.clear()
        nextSweepAt = 0L
    }

    private fun sweep(now: Long) {
        val iterator = entries.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value > expiryMs) iterator.remove()
        }
    }

    private fun trim() {
        while (entries.size > maxEntries) {
            val iterator = entries.keys.iterator()
            if (!iterator.hasNext()) return
            iterator.next()
            iterator.remove()
        }
    }

    private companion object {
        const val SWEEP_INTERVAL_MS = 1_000L
    }
}
