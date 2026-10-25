package com.bitaudio.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReplayGuardTest {

    private val channelA = ByteArray(8) { 1 }
    private val channelB = ByteArray(8) { 2 }
    private val alice = ByteArray(32) { 3 }
    private val bob = ByteArray(32) { 4 }
    private val nowMs = 1_700_000_000_000L

    private fun guard(
        retentionSeconds: Long = 24 * 60 * 60,
        clockMs: Long = nowMs,
        maxMessagesPerSender: Int = 8192,
    ): ReplayGuard = ReplayGuard(
        retentionSeconds = retentionSeconds,
        maxMessagesPerSender = maxMessagesPerSender,
        clock = { clockMs },
    )

    @Test
    fun `first message is accepted, duplicate message id is rejected`() {
        val guard = guard()
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 1, counter = 1, timestampMs = nowMs),
        )
        assertEquals(
            ReplayVerdict.REPLAY,
            guard.check(channelA, alice, messageId = 1, counter = 1, timestampMs = nowMs),
        )
    }

    @Test
    fun `late counters are accepted but cannot be reused for another message`() {
        val guard = guard()
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 10, counter = 10, timestampMs = nowMs),
        )
        // Store-and-forward may deliver counter 5 after counter 10.
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 11, counter = 5, timestampMs = nowMs),
        )
        assertEquals(
            ReplayVerdict.COUNTER_REUSED,
            guard.check(channelA, alice, messageId = 12, counter = 5, timestampMs = nowMs),
        )
        assertEquals(10L, guard.highestCounter(channelA, alice))
    }

    @Test
    fun `same counter and message is a duplicate, not a counter reuse`() {
        val guard = guard()
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 1, counter = 1, timestampMs = nowMs),
        )
        assertEquals(
            ReplayVerdict.REPLAY,
            guard.check(channelA, alice, messageId = 1, counter = 1, timestampMs = nowMs),
        )
    }

    @Test
    fun `channel and identity are both part of the replay key`() {
        val guard = guard()
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 1, counter = 1, timestampMs = nowMs),
        )
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelB, alice, messageId = 1, counter = 1, timestampMs = nowMs),
        )
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, bob, messageId = 1, counter = 1, timestampMs = nowMs),
        )
    }

    @Test
    fun `future skew is 120 seconds`() {
        val guard = guard()
        assertEquals(
            ReplayVerdict.FUTURE,
            guard.check(channelA, alice, messageId = 1, counter = 1, timestampMs = nowMs + 120_001),
        )
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 2, counter = 2, timestampMs = nowMs + 120_000),
        )
    }

    @Test
    fun `timestamps older than retention are expired`() {
        val guard = guard(retentionSeconds = 60)
        assertEquals(
            ReplayVerdict.EXPIRED,
            guard.check(channelA, alice, messageId = 1, counter = 1, timestampMs = nowMs - 60_001),
        )
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 2, counter = 2, timestampMs = nowMs - 60_000),
        )
    }

    @Test
    fun `invalid counters are rejected`() {
        val guard = guard()
        assertEquals(
            ReplayVerdict.INVALID,
            guard.check(channelA, alice, messageId = 1, counter = 0, timestampMs = nowMs),
        )
        assertEquals(
            ReplayVerdict.INVALID,
            guard.check(channelA, alice, messageId = 2, counter = 0x1_0000_0000L, timestampMs = nowMs),
        )
    }

    @Test
    fun `malformed channel or identity is invalid without throwing`() {
        val guard = guard()
        assertEquals(
            ReplayVerdict.INVALID,
            guard.check(ByteArray(7), alice, messageId = 1, counter = 1, timestampMs = nowMs),
        )
        assertEquals(
            ReplayVerdict.INVALID,
            guard.check(channelA, ByteArray(31), messageId = 1, counter = 1, timestampMs = nowMs),
        )
    }

    @Test
    fun `stale helper only affects rebroadcast decisions`() {
        val guard = guard()
        assertTrue(guard.isStale(nowMs - 120_001))
        assertFalse(guard.isStale(nowMs - 120_000))
    }

    @Test
    fun `forget drops the identity state`() {
        val guard = guard()
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 1, counter = 1, timestampMs = nowMs),
        )
        guard.forget(channelA, alice)
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 1, counter = 1, timestampMs = nowMs),
        )
    }

    @Test
    fun `bounded cache evicts oldest messages`() {
        val guard = guard(maxMessagesPerSender = 1)
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 1, counter = 1, timestampMs = nowMs),
        )
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 2, counter = 2, timestampMs = nowMs),
        )
        // The bounded-cache trade-off: an evicted ID can be accepted again.
        assertEquals(
            ReplayVerdict.ACCEPT,
            guard.check(channelA, alice, messageId = 1, counter = 1, timestampMs = nowMs),
        )
    }
}
