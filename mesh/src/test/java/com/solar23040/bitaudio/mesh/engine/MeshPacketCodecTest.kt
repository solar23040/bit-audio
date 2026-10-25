package com.solar23040.bitaudio.mesh.engine

import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.DefaultCrypto
import com.bitaudio.crypto.IdentityManager
import com.bitaudio.crypto.InMemorySecretStore
import com.bitaudio.crypto.PacketCrypto
import com.solar23040.bitaudio.mesh.ChannelId
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MeshPacketCodecTest {

    private val crypto = DefaultCrypto(IdentityManager(InMemorySecretStore()))
    private val channelId = ChannelId.fromBytes(ChannelKeys.channelId(ChannelKeys.generate()))
    private val channelKey = ChannelKeys.generate()
    private val messageId = ByteArray(8) { it.toByte() }
    private val senderId = ByteArray(8) { (it + 8).toByte() }

    @Test
    fun `packet round-trips its header`() {
        val packet = packet(ttl = 4, chunkIndex = 2, totalChunks = 3)
        val decoded = requireNotNull(MeshPacketCodec.decode(packet))

        assertEquals(MeshPacketCodec.TYPE_VOICE_DATA, decoded.header.type)
        assertArrayEquals(messageId, decoded.header.messageId)
        assertEquals(channelId, decoded.header.channelId)
        assertArrayEquals(senderId, decoded.header.senderId)
        assertEquals(4, decoded.header.ttl)
        assertEquals(2, decoded.header.chunkIndex)
        assertEquals(3, decoded.header.totalChunks)
        assertEquals(1_700_000_000_123L, decoded.header.timestampMs)
        assertEquals(7L, decoded.header.counter)
    }

    @Test
    fun `relaying with a lower TTL keeps the signature valid`() {
        val packet = packet(ttl = 5, chunkIndex = 0, totalChunks = 1)
        val decoded = requireNotNull(MeshPacketCodec.decode(packet))
        val canonical = MeshPacketCodec.headerBytes(decoded.header.copy(ttl = 0))
        assertTrue(
            PacketCrypto.verifyPacket(
                crypto,
                crypto.publicKey,
                canonical,
                decoded.sealedPayload,
                decoded.signature,
            ),
        )

        val relayed = requireNotNull(MeshPacketCodec.withTtl(packet, 4))
        val relayedDecoded = requireNotNull(MeshPacketCodec.decode(relayed))
        val relayedCanonical = MeshPacketCodec.headerBytes(relayedDecoded.header.copy(ttl = 0))

        assertEquals(4, relayedDecoded.header.ttl)
        assertTrue(
            PacketCrypto.verifyPacket(
                crypto,
                crypto.publicKey,
                relayedCanonical,
                relayedDecoded.sealedPayload,
                relayedDecoded.signature,
            ),
        )
    }

    @Test
    fun `malformed frames are rejected`() {
        val valid = packet(ttl = 5, chunkIndex = 0, totalChunks = 1)

        assertNull(MeshPacketCodec.decode(ByteArray(MeshPacketCodec.HEADER_SIZE - 1)))
        assertNull(MeshPacketCodec.decode(valid + ByteArray(406)))
        assertNull(MeshPacketCodec.decode(valid.copyOf().also { it[0] = 2.toByte() }))
        assertNull(MeshPacketCodec.decode(valid.copyOf().also { it[26] = 0.toByte() }))
        assertNull(MeshPacketCodec.decode(valid.copyOf().also { it[26] = 9.toByte() }))
        assertNull(
            MeshPacketCodec.decode(
                valid.copyOf().also { it[29] = 0.toByte(); it[30] = 0.toByte() },
            ),
        )
        assertNull(
            MeshPacketCodec.decode(
                valid.copyOf().also {
                    it[27] = 0.toByte()
                    it[28] = 2.toByte()
                    it[29] = 0.toByte()
                    it[30] = 1.toByte()
                },
            ),
        )
    }

    @Test
    fun `ttl helper refuses out-of-range values`() {
        val valid = packet(ttl = 5, chunkIndex = 0, totalChunks = 1)
        assertNull(MeshPacketCodec.withTtl(valid, 0))
        assertNull(MeshPacketCodec.withTtl(valid, 9))
        assertFalse(valid.contentEquals(MeshPacketCodec.withTtl(valid, 4)!!))
    }

    private fun packet(ttl: Int, chunkIndex: Int, totalChunks: Int): ByteArray {
        val header = MeshPacketHeader(
            type = MeshPacketCodec.TYPE_VOICE_DATA,
            messageId = messageId,
            channelId = channelId,
            senderId = senderId,
            ttl = ttl,
            chunkIndex = chunkIndex,
            totalChunks = totalChunks,
            timestampMs = 1_700_000_000_123L,
            counter = 7L,
        )
        val canonical = MeshPacketCodec.headerBytes(header.copy(ttl = 0))
        val plaintext = ByteArray(20) { it.toByte() }
        val sealed = PacketCrypto.sealPayload(crypto, channelKey, canonical, plaintext)
        val signature = PacketCrypto.signPacket(crypto, canonical, sealed)
        return MeshPacketCodec.encode(header, signature, sealed)
    }
}
