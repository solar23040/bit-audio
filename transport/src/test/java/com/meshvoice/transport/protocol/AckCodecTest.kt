package com.meshvoice.transport.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AckCodecTest {
    @Test
    fun `bitmap round-trips including trailing partial byte`() {
        val received = BooleanArray(13) { it % 3 == 0 }
        val encoded = AckCodec.encode(transferId = 42, totalChunks = 13, received = received)

        assertTrue(AckCodec.isAck(encoded))
        assertEquals(AckCodec.sizeFor(13), encoded.size)
        val decoded = requireNotNull(AckCodec.decode(encoded))
        assertEquals(42, decoded.transferId)
        assertEquals(13, decoded.totalChunks)
        assertArrayEquals(received, decoded.received)
    }

    @Test
    fun `truncated ack is rejected`() {
        val encoded = AckCodec.encode(1, 20, BooleanArray(20) { true })
        assertNull(AckCodec.decode(encoded.copyOf(encoded.size - 1)))
        assertNull(AckCodec.decode(encoded.copyOf(AckCodec.HEADER_SIZE - 1)))
    }

    @Test
    fun `chunk frame is not mistaken for an ack`() {
        val frame = Fragmenter.fragment(5, ByteArray(64), maxFrameBytes = 64).first()
        assertFalse(AckCodec.isAck(frame))
        assertNull(AckCodec.decode(frame))
    }
}
