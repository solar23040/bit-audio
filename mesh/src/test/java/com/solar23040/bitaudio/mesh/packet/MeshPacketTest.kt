package com.solar23040.bitaudio.mesh.packet

import java.nio.ByteBuffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class MeshPacketTest {

    @Test
    fun `encode and decode round trip every header field`() {
        val packet = packet()
        val frame = packet.encode()

        assertEquals(MeshPacket.HEADER_SIZE + packet.payload.size, frame.size)
        assertEquals(MeshPacket.VERSION, frame[0].toInt())
        assertEquals(MeshPacket.TYPE_VOICE_DATA, frame[1].toInt())
        assertArrayEquals(packet.msgId, frame.copyOfRange(2, 10))
        assertArrayEquals(packet.channelId, frame.copyOfRange(10, 18))
        assertArrayEquals(packet.senderId, frame.copyOfRange(18, 26))
        assertEquals(5, frame[26].toInt())

        val buffer = ByteBuffer.wrap(frame)
        assertEquals(1, buffer.getShort(27).toInt())
        assertEquals(3, buffer.getShort(29).toInt())
        assertEquals(1_700_000_000_123L, buffer.getLong(31))
        assertEquals(42L, buffer.getInt(39).toLong() and 0xFFFF_FFFFL)
        assertArrayEquals(packet.signature, frame.copyOfRange(43, 107))
        assertArrayEquals(packet.payload, frame.copyOfRange(107, frame.size))

        val decoded = MeshPacket.decode(frame)
        assertNotNull(decoded)
        requireNotNull(decoded)
        assertEquals(packet.version, decoded.version)
        assertEquals(packet.type, decoded.type)
        assertArrayEquals(packet.msgId, decoded.msgId)
        assertArrayEquals(packet.channelId, decoded.channelId)
        assertArrayEquals(packet.senderId, decoded.senderId)
        assertEquals(packet.ttl, decoded.ttl)
        assertEquals(packet.chunkIdx, decoded.chunkIdx)
        assertEquals(packet.totalChunks, decoded.totalChunks)
        assertEquals(packet.timestampMs, decoded.timestampMs)
        assertEquals(packet.counter, decoded.counter)
        assertArrayEquals(packet.signature, decoded.signature)
        assertArrayEquals(packet.payload, decoded.payload)
    }

    @Test
    fun `canonical header zeroes only the ttl byte`() {
        val packet = packet()
        val prefix = packet.headerPrefix()
        val canonical = packet.canonicalHeader()

        assertEquals(MeshPacket.PREFIX_SIZE, prefix.size)
        assertEquals(MeshPacket.PREFIX_SIZE, canonical.size)
        assertEquals(5, prefix[26].toInt())
        assertEquals(0, canonical[26].toInt())

        for (index in prefix.indices) {
            if (index == 26) continue
            assertEquals("byte $index", prefix[index], canonical[index])
        }
    }

    @Test
    fun `decode accepts a maximum size frame`() {
        val packet = packet(payload = ByteArray(MeshPacket.MAX_PAYLOAD_SIZE) { it.toByte() })
        val frame = packet.encode()

        assertEquals(MeshPacket.MAX_FRAME_SIZE, frame.size)
        val decoded = requireNotNull(MeshPacket.decode(frame))
        assertEquals(frame.size, decoded.encode().size)
    }

    @Test
    fun `decode rejects malformed frames and header values`() {
        val valid = packet().encode()

        assertNull("short frame", MeshPacket.decode(valid.copyOfRange(0, MeshPacket.HEADER_SIZE - 1)))
        assertNull("long frame", MeshPacket.decode(valid.copyOf(513)))
        assertNull("unknown version", MeshPacket.decode(valid.copyOf().also { it[0] = 2 }))
        assertNull("ttl zero", MeshPacket.decode(valid.copyOf().also { it[26] = 0 }))
        assertNull("ttl too high", MeshPacket.decode(valid.copyOf().also { it[26] = 9 }))
        assertNull("zero chunks", MeshPacket.decode(valid.copyOf().also { it[29] = 0; it[30] = 0 }))
        assertNull("too many chunks", MeshPacket.decode(valid.copyOf().also { it[29] = 1; it[30] = 1 }))
        assertNull("chunk index out of range", MeshPacket.decode(valid.copyOf().also { it[27] = 0; it[28] = 3 }))
    }

    @Test
    fun `encode rejects oversized payloads`() {
        assertThrows(IllegalArgumentException::class.java) {
            packet(payload = ByteArray(MeshPacket.MAX_PAYLOAD_SIZE + 1))
        }
    }

    private fun packet(
        payload: ByteArray = ByteArray(40) { it.toByte() },
    ): MeshPacket = MeshPacket(
        version = MeshPacket.VERSION,
        type = MeshPacket.TYPE_VOICE_DATA,
        msgId = ByteArray(8) { index -> (index + 1).toByte() },
        channelId = ByteArray(8) { index -> (index + 11).toByte() },
        senderId = ByteArray(8) { index -> (index + 21).toByte() },
        ttl = 5,
        chunkIdx = 1,
        totalChunks = 3,
        timestampMs = 1_700_000_000_123L,
        counter = 42L,
        signature = ByteArray(MeshPacket.SIGNATURE_SIZE) { index -> index.toByte() },
        payload = payload,
    )
}
