package com.bitaudio.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketCryptoTest {

    private val manager = IdentityManager(InMemorySecretStore())
    private val crypto = DefaultCrypto(manager)
    private val channelKey = ChannelKeys.generate()
    private val header = ByteArray(40) { it.toByte() }
    private val payload = "opus frame data".toByteArray()

    @Test
    fun `signing bytes bind header and payload`() {
        val baseline = PacketCrypto.signingBytes(header, payload)

        assertFalse(baseline.contentEquals(PacketCrypto.signingBytes(header, payload + byteArrayOf(1))))
        assertFalse(
            baseline.contentEquals(
                PacketCrypto.signingBytes(
                    header.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() },
                    payload,
                )
            )
        )
    }

    @Test
    fun `packet signature verifies and detects tampering`() {
        val signature = PacketCrypto.signPacket(crypto, header, payload)
        val publicKey = manager.identity().publicKey

        assertTrue(PacketCrypto.verifyPacket(crypto, publicKey, header, payload, signature))
        assertFalse(PacketCrypto.verifyPacket(crypto, publicKey, header, payload + byteArrayOf(0), signature))
        assertFalse(
            PacketCrypto.verifyPacket(
                crypto,
                publicKey,
                header.copyOf().also { it[1] = (it[1].toInt() xor 1).toByte() },
                payload,
                signature,
            )
        )
    }

    @Test
    fun `sealed payload is bound to its header`() {
        val sealed = PacketCrypto.sealPayload(crypto, channelKey, header, payload)

        assertArrayEquals(payload, PacketCrypto.openPayload(crypto, channelKey, header, sealed))
        assertNull(
            PacketCrypto.openPayload(
                crypto,
                channelKey,
                header.copyOf().also { it[2] = (it[2].toInt() xor 1).toByte() },
                sealed,
            )
        )
        assertNull(PacketCrypto.openPayload(crypto, ChannelKeys.generate(), header, sealed))
    }

    @Test
    fun `associated data is domain separated from signing bytes`() {
        val aad = PacketCrypto.associatedData(header)
        assertFalse(aad.contentEquals(PacketCrypto.signingBytes(header, payload)))
        assertFalse(aad.contentEquals(header))
    }
}
