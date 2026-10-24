package com.bitaudio.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityManagerTest {

    @Test
    fun `identity is created once and cached`() {
        val manager = IdentityManager(InMemorySecretStore())
        val first = manager.identity()
        val second = manager.identity()

        assertSame(first, second)
        assertEquals(32, first.publicKey.size)
    }

    @Test
    fun `identity survives a new manager on the same store`() {
        val store = InMemorySecretStore()
        val original = IdentityManager(store).identity()

        val reloaded = IdentityManager(store).identity()
        assertArrayEquals(original.publicKey, reloaded.publicKey)
        assertNotSame(original, reloaded)
    }

    @Test
    fun `rotation replaces the persisted identity`() {
        val store = InMemorySecretStore()
        val manager = IdentityManager(store)
        val before = manager.identity().publicKey

        val rotated = manager.rotate()
        assertFalse(before.contentEquals(rotated.publicKey))
        assertSame(rotated, manager.identity())
        assertArrayEquals(rotated.publicKey, IdentityManager(store).identity().publicKey)
    }

    @Test
    fun `identity signs and verifies`() {
        val identity = IdentityManager(InMemorySecretStore()).identity()
        val message = "voice note".toByteArray()
        val signature = identity.sign(message)

        assertEquals(Ed25519.SIGNATURE_SIZE, signature.size)
        assertTrue(Ed25519.verify(identity.publicKey, message, signature))
    }

    @Test
    fun `corrupt stored seed is reported`() {
        val store = InMemorySecretStore()
        store.write(IdentityManager.DEFAULT_STORAGE_KEY, ByteArray(31))
        val manager = IdentityManager(store)

        assertThrows(IllegalStateException::class.java) { manager.identity() }
    }

    @Test
    fun `public key getter returns a copy`() {
        val identity = IdentityManager(InMemorySecretStore()).identity()
        val first = identity.publicKey
        first[0] = (first[0].toInt() xor 1).toByte()

        assertFalse(first.contentEquals(identity.publicKey))
    }
}
