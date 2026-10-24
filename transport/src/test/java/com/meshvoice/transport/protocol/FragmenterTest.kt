package com.meshvoice.transport.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class FragmenterTest {
    @Test
    fun `15 KB payload splits into bounded frames and round-trips`() {
        val payload = ByteArray(15 * 1024) { (it % 251).toByte() }
        val frames = Fragmenter.fragment(transferId = 0x12345678, payload, maxFrameBytes = 240)

        assertEquals(69, frames.size)
        val parsed = frames.map { frame ->
            assertTrue(frame.size <= 240)
            val chunk = ChunkCodec.decode(frame)
            assertNotNull(chunk)
            chunk!!
        }
        assertEquals(parsed.first().header.totalChunks, parsed.size)
        assertEquals(ChunkCodec.crc32(payload), parsed.first().header.payloadCrc)
        parsed.forEachIndexed { index, chunk ->
            assertEquals(index, chunk.header.seq)
            assertEquals(0x12345678, chunk.header.transferId)
        }

        val rebuilt = ByteArrayOutputStream()
        parsed.forEach { rebuilt.write(it.data) }
        assertArrayEquals(payload, rebuilt.toByteArray())
    }

    @Test
    fun `empty payload still has one chunk`() {
        val frames = Fragmenter.fragment(7, ByteArray(0), maxFrameBytes = 64)
        assertEquals(1, frames.size)
        val chunk = requireNotNull(ChunkCodec.decode(frames.first()))
        assertEquals(0, chunk.header.dataLength)
        assertEquals(0, chunk.data.size)
        assertEquals(0, chunk.header.payloadCrc)
    }

    @Test
    fun `decoder rejects malformed headers`() {
        val frame = Fragmenter.fragment(1, ByteArray(300), maxFrameBytes = 240).first()
        assertNull(ChunkCodec.decode(frame.copyOf(10)))

        val badVersion = frame.copyOf()
        badVersion[0] = 0x7F
        assertNull(ChunkCodec.decode(badVersion))

        val truncatedData = frame.copyOf(frame.size - 1)
        assertNull(ChunkCodec.decode(truncatedData))

        val shiftedSeq = frame.copyOf()
        shiftedSeq[5] = 0x7F
        shiftedSeq[6] = 0x7F
        assertNull(ChunkCodec.decode(shiftedSeq))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `frame size below header is rejected`() {
        Fragmenter.fragment(1, ByteArray(10), maxFrameBytes = ChunkCodec.HEADER_SIZE)
    }
}
