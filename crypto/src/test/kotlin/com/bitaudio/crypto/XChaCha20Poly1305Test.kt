package com.bitaudio.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class XChaCha20Poly1305Test {

    // draft-irtf-cfrg-xchacha-03, section 2.2.1.
    private val hchachaKey = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val hchachaNonce = hex("000000090000004a0000000031415927")
    private val hchachaSubkey = hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")

    // draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    private val vectorKey = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    private val vectorNonce = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
    private val vectorAad = hex("50515253c0c1c2c3c4c5c6c7")
    private val vectorPlaintext = hex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373" +
            "206f66202739393a204966204920636f756c64206f6666657220796f75206f6e" +
            "6c79206f6e652074697020666f7220746865206675747572652c2073756e7363" +
            "7265656e20776f756c642062652069742e"
    )
    private val vectorCiphertext = hex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
            "21f9664c97637da9768812f615c68b13b52e"
    )
    private val vectorTag = hex("c0875924c1c7987947deafd8780acf49")

    @Test
    fun `hchacha20 test vector`() {
        assertArrayEquals(hchachaSubkey, HChaCha20.derive(hchachaKey, hchachaNonce))
    }

    @Test
    fun `xchacha20-poly1305 test vector`() {
        val sealed = XChaCha20Poly1305.sealWithNonce(
            vectorKey,
            vectorNonce,
            vectorPlaintext,
            vectorAad,
        )
        assertArrayEquals(vectorCiphertext + vectorTag, sealed)
        assertArrayEquals(
            vectorPlaintext,
            XChaCha20Poly1305.openWithNonce(vectorKey, vectorNonce, sealed, vectorAad),
        )
    }

    @Test
    fun `round trip with random nonce`() {
        val key = ChannelKeys.generate()
        val aad = "header".toByteArray()
        val message = ByteArray(4096) { (it * 31).toByte() }

        val sealed = XChaCha20Poly1305.seal(key, message, aad)
        assertEquals(XChaCha20Poly1305.NONCE_SIZE + message.size + XChaCha20Poly1305.TAG_SIZE, sealed.size)
        assertArrayEquals(message, XChaCha20Poly1305.open(key, sealed, aad))
    }

    @Test
    fun `empty plaintext round trips`() {
        val key = ChannelKeys.generate()
        val sealed = XChaCha20Poly1305.seal(key, ByteArray(0), ByteArray(0))
        assertEquals(XChaCha20Poly1305.MIN_SEALED_SIZE, sealed.size)
        assertArrayEquals(ByteArray(0), XChaCha20Poly1305.open(key, sealed, ByteArray(0)))
    }

    @Test
    fun `wrong key fails to open`() {
        val sealed = XChaCha20Poly1305.seal(ChannelKeys.generate(), "secret".toByteArray(), ByteArray(0))
        assertNull(XChaCha20Poly1305.open(ChannelKeys.generate(), sealed, ByteArray(0)))
    }

    @Test
    fun `tampered ciphertext fails to open`() {
        val key = ChannelKeys.generate()
        val sealed = XChaCha20Poly1305.seal(key, "secret".toByteArray(), ByteArray(0))
        sealed[sealed.size - 1] = (sealed[sealed.size - 1].toInt() xor 1).toByte()
        assertNull(XChaCha20Poly1305.open(key, sealed, ByteArray(0)))
    }

    @Test
    fun `tampered aad fails to open`() {
        val key = ChannelKeys.generate()
        val sealed = XChaCha20Poly1305.seal(key, "secret".toByteArray(), "header-a".toByteArray())
        assertNotNull(XChaCha20Poly1305.open(key, sealed, "header-a".toByteArray()))
        assertNull(XChaCha20Poly1305.open(key, sealed, "header-b".toByteArray()))
    }

    @Test
    fun `truncated or malformed blobs fail to open`() {
        val key = ChannelKeys.generate()
        assertNull(XChaCha20Poly1305.open(key, ByteArray(0), ByteArray(0)))
        assertNull(XChaCha20Poly1305.open(key, ByteArray(XChaCha20Poly1305.MIN_SEALED_SIZE - 1), ByteArray(0)))
        assertNull(XChaCha20Poly1305.open(key.copyOf(16), ByteArray(XChaCha20Poly1305.MIN_SEALED_SIZE), ByteArray(0)))
    }

    @Test
    fun `random nonces differ between seals`() {
        val key = ChannelKeys.generate()
        val first = XChaCha20Poly1305.seal(key, "same".toByteArray(), ByteArray(0))
        val second = XChaCha20Poly1305.seal(key, "same".toByteArray(), ByteArray(0))
        assertFalse(first.contentEquals(second))
    }

    @Test
    fun `aad is required to open`() {
        val key = ChannelKeys.generate()
        val sealed = XChaCha20Poly1305.seal(key, "secret".toByteArray(), ByteArray(0))
        assertNotNull(XChaCha20Poly1305.open(key, sealed, ByteArray(0)))
        assertTrue(XChaCha20Poly1305.open(key, sealed, ByteArray(0))!!.contentEquals("secret".toByteArray()))
    }
}
