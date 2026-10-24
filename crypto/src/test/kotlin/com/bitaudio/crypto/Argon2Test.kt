package com.bitaudio.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class Argon2Test {

    @Test
    fun `rfc 9106 argon2id test vector`() {
        // Password[32] = 0x01, Salt[16] = 0x02, Secret[8] = 0x03, AD[12] = 0x04.
        val password = CharArray(32) { '\u0001' }
        val salt = ByteArray(16) { 0x02.toByte() }
        val secret = ByteArray(8) { 0x03.toByte() }
        val associatedData = ByteArray(12) { 0x04.toByte() }

        val params = Argon2Params(
            iterations = 3,
            memoryKib = 32,
            parallelism = 4,
            outputLength = 32,
            secret = secret,
            associatedData = associatedData,
        )

        val key = ChannelKeys.fromPassphrase(password, salt, params)
        assertArrayEquals(
            hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"),
            key,
        )
    }

    @Test
    fun `derivation is deterministic and salt-dependent`() {
        val passphrase = "correct horse battery staple".toCharArray()
        val params = Argon2Params(iterations = 1, memoryKib = 64, parallelism = 1)

        val first = ChannelKeys.fromPassphrase(passphrase, ByteArray(16) { 1 }, params)
        val again = ChannelKeys.fromPassphrase(passphrase, ByteArray(16) { 1 }, params)
        val otherSalt = ChannelKeys.fromPassphrase(passphrase, ByteArray(16) { 2 }, params)

        assertArrayEquals(first, again)
        assertFalse(first.contentEquals(otherSalt))
        assertEquals(ChannelKeys.KEY_SIZE, first.size)
    }

    @Test
    fun `output length is honoured`() {
        val params = Argon2Params(iterations = 1, memoryKib = 32, parallelism = 1, outputLength = 24)
        val key = ChannelKeys.fromPassphrase("pw".toCharArray(), ByteArray(8) { 9 }, params)
        assertEquals(24, key.size)
    }

    @Test
    fun `short salt is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            ChannelKeys.fromPassphrase("pw".toCharArray(), ByteArray(7), Argon2Params())
        }
    }

    @Test
    fun `empty passphrase is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            ChannelKeys.fromPassphrase(CharArray(0), ByteArray(16), Argon2Params())
        }
    }

    @Test
    fun `qr secret is copied and validated`() {
        val secret = ByteArray(32) { 7 }
        val key = ChannelKeys.fromQrSecret(secret)
        secret.fill(0)
        assertArrayEquals(ByteArray(32) { 7 }, key)

        assertThrows(IllegalArgumentException::class.java) {
            ChannelKeys.fromQrSecret(ByteArray(31))
        }
    }

    @Test
    fun `channel id is stable and key-scoped`() {
        val key = ChannelKeys.generate()
        assertArrayEquals(ChannelKeys.channelId(key), ChannelKeys.channelId(key.copyOf()))
        assertEquals(ChannelKeys.CHANNEL_ID_SIZE, ChannelKeys.channelId(key).size)
        assertFalse(ChannelKeys.channelId(key).contentEquals(ChannelKeys.channelId(ChannelKeys.generate())))
    }
}
