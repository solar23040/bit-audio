package com.bitaudio.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketCryptoTest {

    private val manager = IdentityManager(InMemorySecretStore())
    private val crypto = DefaultCrypto(manager)
    private val channelKey = ChannelKeys.generate()
    private val header = ByteArray(PacketCrypto.HEADER_PREFIX_SIZE) { it.toByte() }
        .also { it[PacketCrypto.TTL_OFFSET] = 5 }
    private val payload = "abc".toByteArray()

    @Test
    fun `ttl is canonicalised out of the transcript and aad`() {
        val higherTtl = header.copyOf().also { it[PacketCrypto.TTL_OFFSET] = 7 }

        assertArrayEquals(
            PacketCrypto.signingBytes(header, payload),
            PacketCrypto.signingBytes(higherTtl, payload),
        )
        assertArrayEquals(
            PacketCrypto.associatedData(header),
            PacketCrypto.associatedData(higherTtl),
        )
    }

    @Test
    fun `transcript layout is pinned to the wire spec`() {
        // SHA-256 of the exact signing input and AAD for header bytes 0..42
        // with ttl=5 and payload "abc". Computed independently of this module.
        assertEquals(
            "91123f510aa3f48d2c460ca6ab263f217a76da6a4dd14516cd6abceb0712fd03",
            PacketCrypto.signingBytes(header, payload).sha256Hex(),
        )
        assertEquals(
            "2f0c99234176fc96d795f185532a063b8e4ffef0d6a63a70d51a34c115449a23",
            PacketCrypto.associatedData(header).sha256Hex(),
        )
    }

    @Test
    fun `all non-ttl header bytes are covered`() {
        val baseline = PacketCrypto.signingBytes(header, payload)
        val baselineAad = PacketCrypto.associatedData(header)

        for (offset in 0 until PacketCrypto.HEADER_PREFIX_SIZE) {
            if (offset == PacketCrypto.TTL_OFFSET) continue
            val changed = header.copyOf().also { it[offset] = (it[offset].toInt() xor 1).toByte() }
            assertFalse(
                "header byte $offset must be covered by the signature",
                baseline.contentEquals(PacketCrypto.signingBytes(changed, payload)),
            )
            assertFalse(
                "header byte $offset must be covered by the AAD",
                baselineAad.contentEquals(PacketCrypto.associatedData(changed)),
            )
        }
    }

    @Test
    fun `packet signature verifies and detects tampering`() {
        val signature = PacketCrypto.signPacket(crypto, header, payload)
        val publicKey = manager.identity().publicKey

        assertTrue(PacketCrypto.verifyPacket(crypto, publicKey, header, payload, signature))
        assertFalse(PacketCrypto.verifyPacket(crypto, publicKey, header, payload + byteArrayOf(0), signature))

        val changed = header.copyOf().also { it[27] = (it[27].toInt() xor 1).toByte() }
        assertFalse(PacketCrypto.verifyPacket(crypto, publicKey, changed, payload, signature))

        // A relay decrements ttl; the signature must still verify.
        val relayed = header.copyOf().also { it[PacketCrypto.TTL_OFFSET] = 4 }
        assertTrue(PacketCrypto.verifyPacket(crypto, publicKey, relayed, payload, signature))
    }

    @Test
    fun `sealed payload is bound to the canonical header`() {
        val sealed = PacketCrypto.sealPayload(crypto, channelKey, header, payload)

        assertArrayEquals(payload, PacketCrypto.openPayload(crypto, channelKey, header, sealed))

        val relayed = header.copyOf().also { it[PacketCrypto.TTL_OFFSET] = 4 }
        assertArrayEquals(payload, PacketCrypto.openPayload(crypto, channelKey, relayed, sealed))

        val changed = header.copyOf().also { it[28] = (it[28].toInt() xor 1).toByte() }
        assertNull(PacketCrypto.openPayload(crypto, channelKey, changed, sealed))
        assertNull(PacketCrypto.openPayload(crypto, ChannelKeys.generate(), header, sealed))
    }

    @Test
    fun `chunk plaintext limit matches the packet budget`() {
        assertEquals(365, PacketCrypto.MAX_PLAINTEXT_CHUNK_SIZE)

        val max = ByteArray(PacketCrypto.MAX_PLAINTEXT_CHUNK_SIZE) { it.toByte() }
        val sealed = PacketCrypto.sealPayload(crypto, channelKey, header, max)
        assertEquals(PacketCrypto.MAX_PAYLOAD_SIZE, sealed.size)

        assertThrows(IllegalArgumentException::class.java) {
            PacketCrypto.sealPayload(crypto, channelKey, header, ByteArray(PacketCrypto.MAX_PLAINTEXT_CHUNK_SIZE + 1))
        }
    }

    @Test
    fun `malformed header prefix fails verification and opening without throwing`() {
        val shortHeader = ByteArray(PacketCrypto.HEADER_PREFIX_SIZE - 1)
        val signature = PacketCrypto.signPacket(crypto, header, payload)
        assertFalse(
            PacketCrypto.verifyPacket(
                crypto,
                manager.identity().publicKey,
                shortHeader,
                payload,
                signature,
            ),
        )

        val sealed = PacketCrypto.sealPayload(crypto, channelKey, header, payload)
        assertNull(PacketCrypto.openPayload(crypto, channelKey, shortHeader, sealed))
    }

    @Test
    fun `wrong header prefix size is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            PacketCrypto.signingBytes(ByteArray(PacketCrypto.HEADER_PREFIX_SIZE - 1), payload)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PacketCrypto.associatedData(ByteArray(PacketCrypto.HEADER_PREFIX_SIZE + 1))
        }
    }
}
