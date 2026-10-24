package com.bitaudio.crypto

/** Result of inspecting an incoming packet's timestamp/ID/counter. */
enum class ReplayVerdict {
    /** First time seen and inside the timestamp window: process it. */
    ACCEPT,

    /** Message ID or replay counter already seen. */
    REPLAY,

    /** Timestamp too old for the accepted window. */
    STALE,

    /** Timestamp too far in the future (clock skew or forged header). */
    FUTURE,
}

/**
 * Anti-replay state for the mesh layer.
 *
 * Three independent checks:
 *  1. Timestamp window (default +/-120 s). Store-and-forward content must be
 *     timestamped/expired by `:mesh`; a clip older than the window is rejected
 *     here by design.
 *  2. Per-message ID cache per sender (FIFO, bounded) — cheap duplicate drop.
 *  3. Optional per-sender sliding counter window (64 bits), so packets that
 *     arrive out of order still pass while replays inside the window fail.
 *
 * The current packet format has no replay-counter field, so `counter` is null
 * until Agent A adds one. Timestamp + message-ID already rejects replays of
 * captured packets; the counter closes the gap for packets with equal `ts`.
 *
 * Thread-safe. Keyed by the (possibly rotating) 8-byte sender ID.
 */
class ReplayGuard(
    private val timestampWindowSeconds: Long = 120,
    private val maxSeenIdsPerSender: Int = 2048,
    private val maxSenders: Int = 1024,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    init {
        require(timestampWindowSeconds > 0) { "timestampWindowSeconds must be > 0" }
        require(maxSeenIdsPerSender >= 1) { "maxSeenIdsPerSender must be >= 1" }
        require(maxSenders >= 1) { "maxSenders must be >= 1" }
    }

    // Access-order map: least recently used sender is evicted first.
    private val senders = LinkedHashMap<Long, SenderState>(16, 0.75f, true)

    fun check(
        senderId: ByteArray,
        messageId: Long,
        timestampSeconds: Long,
        counter: Long? = null,
    ): ReplayVerdict {
        require(senderId.size == ID_SIZE) { "sender ID must be $ID_SIZE bytes" }

        val nowSeconds = clock() / 1000L
        if (timestampSeconds > nowSeconds + timestampWindowSeconds) return ReplayVerdict.FUTURE
        if (timestampSeconds < nowSeconds - timestampWindowSeconds) return ReplayVerdict.STALE

        return synchronized(this) {
            val key = senderId.toLongKey()
            val state = senders.getOrPut(key) { SenderState() }
            while (senders.size > maxSenders) {
                val oldest = senders.keys.iterator()
                if (!oldest.hasNext()) break
                oldest.next()
                oldest.remove()
            }

            when {
                state.seen.containsKey(messageId) -> ReplayVerdict.REPLAY
                counter != null && !recordCounter(state, counter) -> ReplayVerdict.REPLAY
                else -> {
                    recordSeen(state, messageId)
                    ReplayVerdict.ACCEPT
                }
            }
        }
    }

    /** Drops cached state for a sender, e.g. after its identity rotates. */
    fun forget(senderId: ByteArray) {
        require(senderId.size == ID_SIZE) { "sender ID must be $ID_SIZE bytes" }
        synchronized(this) {
            senders.remove(senderId.toLongKey())
        }
    }

    private fun recordSeen(state: SenderState, messageId: Long) {
        while (state.seen.size >= maxSeenIdsPerSender) {
            val oldest = state.seen.keys.iterator()
            if (!oldest.hasNext()) break
            oldest.next()
            oldest.remove()
        }
        state.seen[messageId] = true
    }

    /** Returns false when [counter] was already seen or is too old. */
    private fun recordCounter(state: SenderState, counter: Long): Boolean {
        if (counter < 0) return false

        if (state.highestCounter == Long.MIN_VALUE) {
            state.highestCounter = counter
            state.counterBitmap = 1L
            return true
        }

        val highest = state.highestCounter
        if (counter > highest) {
            val shift = counter - highest
            state.counterBitmap = if (shift >= COUNTER_WINDOW_BITS) {
                1L
            } else {
                (state.counterBitmap shl shift.toInt()) or 1L
            }
            state.highestCounter = counter
            return true
        }

        val offset = highest - counter
        if (offset >= COUNTER_WINDOW_BITS) return false
        val mask = 1L shl offset.toInt()
        if (state.counterBitmap and mask != 0L) return false
        state.counterBitmap = state.counterBitmap or mask
        return true
    }

    private class SenderState {
        val seen = LinkedHashMap<Long, Boolean>()
        var highestCounter: Long = Long.MIN_VALUE
        var counterBitmap: Long = 0L
    }

    private fun ByteArray.toLongKey(): Long {
        var value = 0L
        for (byte in this) {
            value = (value shl 8) or (byte.toLong() and 0xff)
        }
        return value
    }

    private companion object {
        const val ID_SIZE = 8
        const val COUNTER_WINDOW_BITS = 64
    }
}
