package com.bitaudio.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CryptoTest {

    private val manager = IdentityManager(InMemorySecretStore())
    private val crypto = DefaultCrypto(manager)

    @Test
    fun `public key matches the managed identity`() {
        assertArrayEquals(manager.identity().publicKey, crypto.publicKey)
        assertEquals(Ed25519.PUBLIC_KEY_SIZE, crypto.publicKey.size)
    }

    @Test
    fun `sign then verify`() {
        val data = "packet bytes".toByteArray()
        val signature = crypto.sign(data)

        assertEquals(Ed25519.SIGNATURE_SIZE, signature.size)
        assertTrue(crypto.verify(crypto.publicKey, data, signature))
    }

    @Test
    fun `tampered data or signature fails verification`() {
        val data = "packet bytes".toByteArray()
        val signature = crypto.sign(data)

        assertFalse(crypto.verify(crypto.publicKey, data + byteArrayOf(0), signature))
        signature[0] = (signature[0].toInt() xor 1).toByte()
        assertFalse(crypto.verify(crypto.publicKey, data, signature))
        assertFalse(crypto.verify(crypto.publicKey, data, ByteArray(0)))
    }

    @Test
    fun `seal then open`() {
        val channelKey = ChannelKeys.generate()
        val aad = "header".toByteArray()
        val plaintext = ByteArray(1024) { it.toByte() }

        val sealed = crypto.seal(channelKey, plaintext, aad)
        assertArrayEquals(plaintext, crypto.open(channelKey, sealed, aad))
    }

    @Test
    fun `sealing rejects wrong key and wrong aad`() {
        val channelKey = ChannelKeys.generate()
        val sealed = crypto.seal(channelKey, "clip".toByteArray(), "header-a".toByteArray())

        assertNull(crypto.open(ChannelKeys.generate(), sealed, "header-a".toByteArray()))
        assertNull(crypto.open(channelKey, sealed, "header-b".toByteArray()))
        assertNull(crypto.open(channelKey, sealed.copyOf(sealed.size - 1), "header-a".toByteArray()))
    }
}
