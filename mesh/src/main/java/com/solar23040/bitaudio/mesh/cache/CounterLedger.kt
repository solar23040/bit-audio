package com.solar23040.bitaudio.mesh.cache

import com.solar23040.bitaudio.mesh.ChannelId

/**
 * Remembers `(channel, resolved identity, counter) -> msg_id` for the
 * retention window.
 *
 * A counter that was first seen with one message ID must not later appear with
 * a different one: that is a replay. Reordered and store-and-forward traffic is
 * fine, so there is deliberately no "must be greater than the last counter"
 * rule.
 */
internal class CounterLedger(
    private val retentionMs: Long,
    private val clock: () -> Long,
) {
    private data class Entry(val messageId: String, val expiresAtMs: Long)

    private data class Key(
        val channel: ChannelId,
        val identityHex: String,
        val counter: Long,
    )

    private val lock = Any()
    private val entries = HashMap<Key, Entry>()

    /** Returns true when the counter is consistent with [messageId]. */
    fun accept(channel: ChannelId, identityHex: String, counter: Long, messageId: String): Boolean =
        synchronized(lock) {
            val now = clock()
            prune(now)

            val key = Key(channel, identityHex, counter)
            val existing = entries[key]
            when {
                existing == null -> {
                    entries[key] = Entry(messageId, now + retentionMs)
                    true
                }
                existing.expiresAtMs <= now -> {
                    entries[key] = Entry(messageId, now + retentionMs)
                    true
                }
                existing.messageId == messageId -> true
                else -> false
            }
        }

    fun size(): Int = synchronized(lock) { entries.size }

    private fun prune(now: Long) {
        val iterator = entries.entries.iterator()
        while (iterator.hasNext()) {
            if (iterator.next().value.expiresAtMs <= now) iterator.remove()
        }
    }
}
