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
    private val timestamp = 1_700_000_000L

    @Test
    fun `id is deterministic inside an epoch`() {
        val first = RotatingSenderId.derive(channelSecret, alice, timestamp)
        val second = RotatingSenderId.derive(channelSecret, alice, timestamp + 10)

        assertEquals(RotatingSenderId.ID_SIZE, first.size)
        assertArrayEquals(first, second)
    }

    @Test
    fun `id changes across epochs`() {
        val epoch = RotatingSenderId.epochFor(timestamp)
        val current = RotatingSenderId.deriveForEpoch(channelSecret, alice, epoch)
        val next = RotatingSenderId.deriveForEpoch(channelSecret, alice, epoch + 1)
        val previous = RotatingSenderId.deriveForEpoch(channelSecret, alice, epoch - 1)

        assertFalse(current.contentEquals(next))
        assertFalse(current.contentEquals(previous))
    }

    @Test
    fun `id is channel-scoped and sender-scoped`() {
        val baseline = RotatingSenderId.derive(channelSecret, alice, timestamp)
        val otherChannel = RotatingSenderId.derive(ByteArray(32) { 0x44 }, alice, timestamp)
        val otherSender = RotatingSenderId.derive(channelSecret, bob, timestamp)

        assertFalse(baseline.contentEquals(otherChannel))
        assertFalse(baseline.contentEquals(otherSender))
    }

    @Test
    fun `peer directory resolves a sender id`() {
        val directory = PeerDirectory(listOf(alice, bob))
        val senderId = RotatingSenderId.derive(channelSecret, alice, timestamp)

        assertArrayEquals(alice, directory.resolve(channelSecret, senderId, timestamp))
        assertNull(directory.resolve(ByteArray(32) { 0x55 }, senderId, timestamp))
        assertNull(directory.resolve(channelSecret, ByteArray(8) { 0x66 }, timestamp))
    }

    @Test
    fun `peer directory tolerates one epoch of clock skew`() {
        val directory = PeerDirectory(listOf(alice))
        val epoch = RotatingSenderId.epochFor(timestamp)
        val previousEpochId = RotatingSenderId.deriveForEpoch(channelSecret, alice, epoch - 1)

        assertArrayEquals(alice, directory.resolve(channelSecret, previousEpochId, timestamp))
        assertNull(directory.resolve(channelSecret, previousEpochId, timestamp, epochSkew = 0))
    }

    @Test
    fun `peer directory deduplicates and copies keys`() {
        val mutable = alice.copyOf()
        val directory = PeerDirectory()

        assertTrue(directory.add(mutable))
        assertFalse(directory.add(mutable))
        assertEquals(1, directory.size)

        mutable[0] = 0
        val senderId = RotatingSenderId.derive(channelSecret, alice, timestamp)
        assertNotNull(directory.resolve(channelSecret, senderId, timestamp))
    }

    @Test
    fun `invalid key sizes are rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            RotatingSenderId.derive(ByteArray(31), alice, timestamp)
        }
        assertThrows(IllegalArgumentException::class.java) {
            RotatingSenderId.derive(channelSecret, ByteArray(31), timestamp)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PeerDirectory().add(ByteArray(31))
        }
    }
}
