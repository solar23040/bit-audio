package com.bitaudio.crypto

/** Result of inspecting a received message's timestamp, ID and counter. */
enum class ReplayVerdict {
    /** Not seen before, inside the retention window: process it. */
    ACCEPT,

    /** This message ID was already accepted. */
    REPLAY,

    /** Timestamp older than the retention window. */
    EXPIRED,

    /** Timestamp too far in the future (clock skew or forged header). */
    FUTURE,

    /** Counter already maps to a different message ID for this identity/channel. */
    COUNTER_REUSED,

    /** Counter outside the u32 range, or malformed channel/identity input. */
    INVALID,
}

/**
 * Replay detection for received messages, following the rules in
 * `docs/packet-format.md`:
 *
 *  - reject timestamps more than [futureSkewSeconds] in the future;
 *  - reject messages older than [retentionSeconds];
 *  - cache completed messages by `(channel_id, resolved identity, msg_id)`;
 *  - cache `(channel_id, resolved identity, counter) -> msg_id` and reject a
 *    counter reused for a different message;
 *  - do **not** apply a monotonic "counter must increase" rule: store-and-forward
 *    and mesh reordering legitimately deliver older counters, so a late message
 *    with an unseen ID and a valid timestamp is accepted.
 *
 * Key by the **resolved identity** (stable Ed25519 public key), never by the
 * rotating `sender_id`; otherwise a new epoch resets the cache.
 *
 * The cache is bounded ([maxMessagesPerSender], [maxSenders]); entries evicted
 * early can be replayed. Mesh still owns persistence and its own dedup keys.
 * All methods are thread-safe.
 */
class ReplayGuard(
    private val retentionSeconds: Long = 24 * 60 * 60,
    private val futureSkewSeconds: Long = 120,
    private val staleForRelaySeconds: Long = 120,
    private val maxMessagesPerSender: Int = 8192,
    private val maxSenders: Int = 256,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    init {
        require(retentionSeconds > 0) { "retentionSeconds must be > 0" }
        require(futureSkewSeconds >= 0) { "futureSkewSeconds must be >= 0" }
        require(staleForRelaySeconds >= 0) { "staleForRelaySeconds must be >= 0" }
        require(maxMessagesPerSender >= 1) { "maxMessagesPerSender must be >= 1" }
        require(maxSenders >= 1) { "maxSenders must be >= 1" }
    }

    // Access-order map of (channel, identity) -> state; least recently used is
    // evicted when a malicious sender floods channel identities.
    private val senders = LinkedHashMap<String, SenderState>(16, 0.75f, true)

    fun check(
        channelId: ByteArray,
        identityPublicKey: ByteArray,
        messageId: Long,
        counter: Long,
        timestampMs: Long,
    ): ReplayVerdict {
        if (channelId.size != CHANNEL_ID_SIZE ||
            identityPublicKey.size != Ed25519.PUBLIC_KEY_SIZE ||
            counter < 1 ||
            counter > MAX_COUNTER
        ) {
            return ReplayVerdict.INVALID
        }

        val nowMs = clock()
        if (timestampMs > nowMs + futureSkewSeconds * 1000L) return ReplayVerdict.FUTURE
        if (timestampMs < nowMs - retentionSeconds * 1000L) return ReplayVerdict.EXPIRED

        return synchronized(this) {
            val key = cacheKey(channelId, identityPublicKey)
            val state = senders.getOrPut(key) { SenderState() }
            evictSenders()
            prune(state, nowMs)

            if (state.messages.containsKey(messageId)) {
                return@synchronized ReplayVerdict.REPLAY
            }

            val counterOwner = state.counterToMessage[counter]
            if (counterOwner != null) {
                return@synchronized if (counterOwner == messageId) {
                    ReplayVerdict.REPLAY
                } else {
                    ReplayVerdict.COUNTER_REUSED
                }
            }

            state.messages[messageId] = MessageRecord(messageId, counter, timestampMs)
            state.counterToMessage[counter] = messageId
            if (counter > state.highestCounter) state.highestCounter = counter
            enforceBound(state)
            ReplayVerdict.ACCEPT
        }
    }

    /**
     * True when a packet is too old to rebroadcast (default 120 s). Mesh still
     * delivers such packets locally; store-and-forward uses this to stop old
     * packets circulating. Not a rejection test.
     */
    fun isStale(timestampMs: Long): Boolean =
        clock() - timestampMs > staleForRelaySeconds * 1000L

    /** Highest counter seen for diagnostics/rate limiting, if any. */
    fun highestCounter(channelId: ByteArray, identityPublicKey: ByteArray): Long? =
        synchronized(this) {
            senders[cacheKey(channelId, identityPublicKey)]?.highestCounter
        }

    /** Drops cached state for one identity in one channel (e.g. roster removal). */
    fun forget(channelId: ByteArray, identityPublicKey: ByteArray) {
        synchronized(this) {
            senders.remove(cacheKey(channelId, identityPublicKey))
        }
    }

    private fun prune(state: SenderState, nowMs: Long) {
        val cutoff = nowMs - retentionSeconds * 1000L
        val iterator = state.messages.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value.timestampMs < cutoff) {
                if (state.counterToMessage[entry.value.counter] == entry.value.messageId) {
                    state.counterToMessage.remove(entry.value.counter)
                }
                iterator.remove()
            }
        }
    }

    private fun enforceBound(state: SenderState) {
        while (state.messages.size > maxMessagesPerSender) {
            val oldest = state.messages.entries.iterator()
            if (!oldest.hasNext()) break
            val record = oldest.next().value
            if (state.counterToMessage[record.counter] == record.messageId) {
                state.counterToMessage.remove(record.counter)
            }
            oldest.remove()
        }
    }

    private fun evictSenders() {
        while (senders.size > maxSenders) {
            val oldest = senders.keys.iterator()
            if (!oldest.hasNext()) break
            oldest.next()
            oldest.remove()
        }
    }

    private fun cacheKey(channelId: ByteArray, identityPublicKey: ByteArray): String =
        channelId.toHexString() + ":" + identityPublicKey.toHexString()

    private fun ByteArray.toHexString(): String = buildString(size * 2) {
        for (byte in this@toHexString) {
            val value = byte.toInt() and 0xff
            append(HEX[value ushr 4])
            append(HEX[value and 0x0f])
        }
    }

    private class SenderState {
        val messages = LinkedHashMap<Long, MessageRecord>()
        val counterToMessage = HashMap<Long, Long>()
        var highestCounter: Long = 0
    }

    private class MessageRecord(
        val messageId: Long,
        val counter: Long,
        val timestampMs: Long,
    )

    private companion object {
        const val CHANNEL_ID_SIZE = 8
        const val MAX_COUNTER = 0xFFFF_FFFFL
        const val HEX = "0123456789abcdef"
    }
}
