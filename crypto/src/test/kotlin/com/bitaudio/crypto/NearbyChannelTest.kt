package com.bitaudio.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NearbyChannelTest {

    @Test
    fun `nearby key is deterministic and matches the documented channel id`() {
        val first = NearbyChannel.key()
        val second = NearbyChannel.key()

        assertTrue(first.contentEquals(second))
        assertEquals(ChannelKeys.KEY_SIZE, first.size)
        assertEquals(16, NearbyChannel.channelIdHex.length)
        assertTrue(NearbyChannel.channelIdHex.all { it in '0'..'9' || it in 'a'..'f' })
        assertTrue(NearbyChannel.channelId().contentEquals(ChannelKeys.channelId(first)))
        assertTrue(NearbyChannel.matches(NearbyChannel.channelId()))
        assertFalse(NearbyChannel.matches(ChannelKeys.channelId(ChannelKeys.generate())))
    }

    @Test
    fun `fingerprint is six lowercase hex characters and follows the key`() {
        val manager = IdentityManager(InMemorySecretStore())
        val first = IdentityFingerprint.of(manager.identity().publicKey)
        val repeat = IdentityFingerprint.of(manager.identity().publicKey)

        assertEquals(6, first.length)
        assertTrue(first.all { it in '0'..'9' || it in 'a'..'f' })
        assertEquals(first, repeat)

        manager.rotate()
        val rotated = IdentityFingerprint.of(manager.identity().publicKey)
        assertNotEquals(first, rotated)
    }
}
