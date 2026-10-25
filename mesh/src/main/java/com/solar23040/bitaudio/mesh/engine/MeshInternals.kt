package com.solar23040.bitaudio.mesh.engine

import java.security.MessageDigest

/** Stable per-identity cache key derived from the resolved Ed25519 key. */
internal class IdentityTag(publicKey: ByteArray) {
    private val digest: ByteArray = MessageDigest.getInstance("SHA-256").run {
        update(TAG_DOMAIN)
        update(publicKey)
        digest()
    }

    /** First 8 bytes as lowercase hex, used in the dedup/counter caches. */
    val hex: String = digest.copyOf(8).toHexString()

    private companion object {
        val TAG_DOMAIN = "bit-audio/mesh-identity-tag/v1".toByteArray(Charsets.US_ASCII)
    }
}

/**
 * Bounded FIFO cache of `(channel, identity, msg_id, chunk_idx)` keys. Entries
 * are inserted only after signature verification so unauthenticated peers
 * cannot poison it.
 */
internal class SeenPacketCache(
    private val maxEntries: Int,
    private val ttlMs: Long,
    private val clock: () -> Long,
) {
    data class Key(
        val channelHex: String,
        val identityTag: String,
        val messageIdHex: String,
        val chunkIndex: Int,
    )

    private val entries = LinkedHashMap<Key, Long>()

    /** Returns false when the key is already present. */
    @Synchronized
    fun firstSeen(key: Key): Boolean {
        val now = clock()
        purgeExpired(now)
        if (entries.containsKey(key)) return false

        entries[key] = now + ttlMs
        while (entries.size > maxEntries) {
            val oldest = entries.keys.iterator()
            if (!oldest.hasNext()) break
            oldest.next()
            oldest.remove()
        }
        return true
    }

    @Synchronized
    fun clear() {
        entries.clear()
    }

    private fun purgeExpired(now: Long) {
        // Insertion order matches expiry order because ttl is constant.
        val iterator = entries.entries.iterator()
        while (iterator.hasNext()) {
            if (iterator.next().value <= now) iterator.remove() else break
        }
    }
}

/**
 * Per-key token bucket. [clock] is in milliseconds, so tests can drive it
 * deterministically instead of sleeping.
 */
internal class RateLimiter(
    private val limit: RateLimit,
    private val clock: () -> Long,
) {
    private class Bucket(var tokens: Double, var lastRefillMs: Long)

    // Access-order: least recently used key is evicted first.
    private val buckets = LinkedHashMap<String, Bucket>(16, 0.75f, true)

    @Synchronized
    fun tryAcquire(key: String): Boolean {
        val now = clock()
        val bucket = buckets[key] ?: Bucket(limit.burst, now).also { buckets[key] = it }

        val elapsedMs = (now - bucket.lastRefillMs).coerceAtLeast(0)
        if (elapsedMs > 0) {
            val refill = elapsedMs * limit.perSecond / 1000.0
            bucket.tokens = minOf(limit.burst, bucket.tokens + refill)
            bucket.lastRefillMs = now
        }

        while (buckets.size > MAX_TRACKED_KEYS) {
            val oldest = buckets.keys.iterator()
            if (!oldest.hasNext()) break
            oldest.next()
            oldest.remove()
        }

        if (bucket.tokens < 1.0) return false
        bucket.tokens -= 1.0
        return true
    }

    private companion object {
        const val MAX_TRACKED_KEYS = 4096
    }
}

/** Big-endian 64-bit view of an 8-byte message ID, for the replay cache. */
internal fun messageIdToLong(messageId: ByteArray): Long {
    var value = 0L
    for (byte in messageId) {
        value = (value shl 8) or (byte.toLong() and 0xFF)
    }
    return value
}

internal fun ByteArray.toHexString(): String {
    val digits = "0123456789abcdef"
    return buildString(size * 2) {
        this@toHexString.forEach { byte ->
            val value = byte.toInt() and 0xFF
            append(digits[value ushr 4])
            append(digits[value and 0x0F])
        }
    }
}
