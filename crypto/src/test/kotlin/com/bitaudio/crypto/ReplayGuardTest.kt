package com.bitaudio.crypto

import org.junit.Assert.assertEquals
import org.junit.Test

class ReplayGuardTest {

    private val sender = ByteArray(8) { 7 }
    private val otherSender = ByteArray(8) { 9 }
    private val now = 1_700_000_000L

    private fun guard(clockSeconds: Long = now): ReplayGuard =
        ReplayGuard(timestampWindowSeconds = 60, clock = { clockSeconds * 1000L })

    @Test
    fun `first packet is accepted, duplicate message id is rejected`() {
        val guard = guard()
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, messageId = 1, timestampSeconds = now))
        assertEquals(ReplayVerdict.REPLAY, guard.check(sender, messageId = 1, timestampSeconds = now))
    }

    @Test
    fun `different senders have independent replay state`() {
        val guard = guard()
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, messageId = 1, timestampSeconds = now))
        assertEquals(ReplayVerdict.ACCEPT, guard.check(otherSender, messageId = 1, timestampSeconds = now))
        assertEquals(ReplayVerdict.REPLAY, guard.check(sender, messageId = 1, timestampSeconds = now))
    }

    @Test
    fun `timestamp window rejects stale and future packets`() {
        val guard = guard()
        assertEquals(ReplayVerdict.STALE, guard.check(sender, messageId = 1, timestampSeconds = now - 61))
        assertEquals(ReplayVerdict.FUTURE, guard.check(sender, messageId = 2, timestampSeconds = now + 61))
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, messageId = 3, timestampSeconds = now - 60))
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, messageId = 4, timestampSeconds = now + 60))
    }

    @Test
    fun `rejected timestamps do not poison the cache`() {
        val guard = guard()
        assertEquals(ReplayVerdict.STALE, guard.check(sender, messageId = 1, timestampSeconds = now - 100))
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, messageId = 1, timestampSeconds = now))
    }

    @Test
    fun `counter window allows reordering but rejects duplicates and old packets`() {
        val guard = guard()

        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, 1, now, counter = 100))
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, 2, now, counter = 110))
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, 3, now, counter = 105))
        assertEquals(ReplayVerdict.REPLAY, guard.check(sender, 4, now, counter = 105))
        assertEquals(ReplayVerdict.REPLAY, guard.check(sender, 5, now, counter = 100))

        // 45 is more than 64 behind the high-water mark of 110.
        assertEquals(ReplayVerdict.REPLAY, guard.check(sender, 6, now, counter = 45))
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, 7, now, counter = 111))
        assertEquals(ReplayVerdict.REPLAY, guard.check(sender, 8, now, counter = 110))
    }

    @Test
    fun `counter state is per sender`() {
        val guard = guard()
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, 1, now, counter = 5))
        assertEquals(ReplayVerdict.ACCEPT, guard.check(otherSender, 2, now, counter = 5))
    }

    @Test
    fun `negative counter is rejected`() {
        val guard = guard()
        assertEquals(ReplayVerdict.REPLAY, guard.check(sender, 1, now, counter = -1))
    }

    @Test
    fun `forget clears a sender`() {
        val guard = guard()
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, 1, now))
        assertEquals(ReplayVerdict.REPLAY, guard.check(sender, 1, now))

        guard.forget(sender)
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, 1, now))
    }

    @Test
    fun `seen id cache stays bounded`() {
        val guard = ReplayGuard(
            timestampWindowSeconds = 60,
            maxSeenIdsPerSender = 2,
            clock = { now * 1000L },
        )
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, 1, now))
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, 2, now))
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, 3, now))

        // ID 1 was evicted; with the timestamp window this only happens for
        // packets still inside the window, which is the accepted trade-off.
        assertEquals(ReplayVerdict.ACCEPT, guard.check(sender, 1, now))
        assertEquals(ReplayVerdict.REPLAY, guard.check(sender, 3, now))
    }
}
