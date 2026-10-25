package com.bitaudio.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RotatingSenderIdTest {

    private val channelSecret = ByteArray(32) { 0x11 }
    private val alice = ByteArray(32) { 0x22 }
    private val bob = ByteArray(32) { 0x33 }
    private val timestampMs = 1_700_000_000_000L

    @Test
    fun `id is deterministic inside an epoch`() {
        val first = RotatingSenderId.derive(channelSecret, alice, timestampMs)
        val second = RotatingSenderId.derive(channelSecret, alice, timestampMs + 10)

        assertEquals(RotatingSenderId.ID_SIZE, first.size)
        assertArrayEquals(first, second)
    }

    @Test
    fun `id changes across epochs`() {
        val epoch = RotatingSenderId.epochFor(timestampMs)
        val current = RotatingSenderId.deriveForEpoch(channelSecret, alice, epoch)
        val next = RotatingSenderId.deriveForEpoch(channelSecret, alice, epoch + 1)
        val previous = RotatingSenderId.deriveForEpoch(channelSecret, alice, epoch - 1)

        assertFalse(current.contentEquals(next))
        assertFalse(current.contentEquals(previous))
    }

    @Test
    fun `sender id matches the wire-format vector`() {
        // id_key = HMAC-SHA256(0x11 * 32, "bit-audio/sender-id-key/v1")
        // epoch  = 1_700_000_000_000 / 900_000 = 1_888_888
        assertEquals(1_888_888L, RotatingSenderId.epochFor(timestampMs))
        assertEquals(
            "9d3622fe80b2a426",
            RotatingSenderId.derive(channelSecret, alice, timestampMs).toHex(),
        )
    }

    @Test
    fun `id is channel-scoped and sender-scoped`() {
        val baseline = RotatingSenderId.derive(channelSecret, alice, timestampMs)
        val otherChannel = RotatingSenderId.derive(ByteArray(32) { 0x44 }, alice, timestampMs)
        val otherSender = RotatingSenderId.derive(channelSecret, bob, timestampMs)

        assertFalse(baseline.contentEquals(otherChannel))
        assertFalse(baseline.contentEquals(otherSender))
    }

    @Test
    fun `peer directory resolves a sender id`() {
        val directory = PeerDirectory(listOf(alice, bob))
        val senderId = RotatingSenderId.derive(channelSecret, alice, timestampMs)

        assertArrayEquals(alice, directory.resolve(channelSecret, senderId, timestampMs))
        assertNull(directory.resolve(ByteArray(32) { 0x55 }, senderId, timestampMs))
        assertNull(directory.resolve(channelSecret, ByteArray(8) { 0x66 }, timestampMs))
    }

    @Test
    fun `peer directory tolerates one epoch of clock skew`() {
        val directory = PeerDirectory(listOf(alice))
        val epoch = RotatingSenderId.epochFor(timestampMs)
        val previousEpochId = RotatingSenderId.deriveForEpoch(channelSecret, alice, epoch - 1)

        assertArrayEquals(alice, directory.resolve(channelSecret, previousEpochId, timestampMs))
        assertNull(directory.resolve(channelSecret, previousEpochId, timestampMs, epochSkew = 0))
    }

    @Test
    fun `peer directory deduplicates and copies keys`() {
        val mutable = alice.copyOf()
        val directory = PeerDirectory()

        assertTrue(directory.add(mutable))
        assertFalse(directory.add(mutable))
        assertEquals(1, directory.size)

        mutable[0] = 0
        val senderId = RotatingSenderId.derive(channelSecret, alice, timestampMs)
        assertNotNull(directory.resolve(channelSecret, senderId, timestampMs))
    }

    @Test
    fun `invalid key sizes are rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            RotatingSenderId.derive(ByteArray(31), alice, timestampMs)
        }
        assertThrows(IllegalArgumentException::class.java) {
            RotatingSenderId.derive(channelSecret, ByteArray(31), timestampMs)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PeerDirectory().add(ByteArray(31))
        }
    }
}
