package com.bitaudio.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Ed25519Test {

    // RFC 8032, section 7.1.
    private val seed1 = hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    private val publicKey1 = hex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    private val signature1 = hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )

    private val seed2 = hex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    private val publicKey2 = hex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    )
    private val message2 = hex("72")
    private val signature2 = hex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )

    private val seed3 = hex(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
    )
    private val publicKey3 = hex(
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    )
    private val message3 = hex("af82")
    private val signature3 = hex(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    )

    @Test
    fun `test vector 1 - empty message`() {
        assertArrayEquals(publicKey1, Ed25519.publicKeyFromSeed(seed1))
        assertArrayEquals(signature1, Ed25519.sign(seed1, ByteArray(0)))
        assertTrue(Ed25519.verify(publicKey1, ByteArray(0), signature1))
    }

    @Test
    fun `test vector 2 - one byte message`() {
        assertArrayEquals(publicKey2, Ed25519.publicKeyFromSeed(seed2))
        assertArrayEquals(signature2, Ed25519.sign(seed2, message2))
        assertTrue(Ed25519.verify(publicKey2, message2, signature2))
    }

    @Test
    fun `test vector 3 - two byte message`() {
        assertArrayEquals(publicKey3, Ed25519.publicKeyFromSeed(seed3))
        assertArrayEquals(signature3, Ed25519.sign(seed3, message3))
        assertTrue(Ed25519.verify(publicKey3, message3, signature3))
    }

    @Test
    fun `tampered message is rejected`() {
        val tampered = message2.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(Ed25519.verify(publicKey2, tampered, signature2))
    }

    @Test
    fun `signature from another key is rejected`() {
        assertFalse(Ed25519.verify(publicKey2, message2, signature1))
        assertFalse(Ed25519.verify(publicKey1, ByteArray(0), signature2))
    }

    @Test
    fun `malformed sizes are rejected without throwing`() {
        assertFalse(Ed25519.verify(publicKey2, message2, signature2.copyOf(63)))
        assertFalse(Ed25519.verify(publicKey2.copyOf(31), message2, signature2))
        assertFalse(Ed25519.verify(ByteArray(32), message2, signature2))
    }

    @Test
    fun `generated seeds produce verifiable signatures`() {
        val seed = Ed25519.generateSeed()
        assertEquals(Ed25519.SEED_SIZE, seed.size)
        val publicKey = Ed25519.publicKeyFromSeed(seed)
        val message = "hello mesh".toByteArray()
        val signature = Ed25519.sign(seed, message)
        assertTrue(Ed25519.verify(publicKey, message, signature))
    }
}
