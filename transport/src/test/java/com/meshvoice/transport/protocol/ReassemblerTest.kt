package com.meshvoice.transport.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ReassemblerTest {
    private val settings = TransferSettings(
        maxFrameBytes = 64,
        reassemblyTimeoutMs = 1_000,
        completedCacheMs = 2_000,
        maxConcurrentIncoming = 4,
    )

    @Test
    fun `out-of-order chunks reassemble and ack progress`() {
        var now = 1_000L
        val reassembler = Reassembler(settings) { now }
        val payload = ByteArray(300) { it.toByte() }
        val chunks = fragments(payload)
        var completed: ByteArray? = null

        for ((index, seq) in listOf(6, 0, 2, 1, 4, 3, 5).withIndex()) {
            val outcome = reassembler.offer("peer", chunks[seq], now)
            val ack = requireNotNull(AckCodec.decode(outcome.ack))
            assertEquals(index + 1, ack.received.count { it })
            if (outcome.completed != null) completed = outcome.completed
        }

        assertArrayEquals(payload, requireNotNull(completed))
    }

    @Test
    fun `duplicate after completion is acked but not delivered twice`() {
        var now = 1_000L
        val reassembler = Reassembler(settings) { now }
        val chunks = fragments(ByteArray(300) { it.toByte() })
        var completed: ByteArray? = null
        for (chunk in chunks) {
            completed = reassembler.offer("peer", chunk, now).completed ?: completed
        }
        assertTrue(completed != null)

        val duplicate = reassembler.offer("peer", chunks.last(), now)
        assertNull(duplicate.completed)
        val ack = requireNotNull(AckCodec.decode(duplicate.ack))
        assertTrue(ack.received.all { it })
    }

    @Test
    fun `unfinished transfer expires`() {
        var now = 1_000L
        val reassembler = Reassembler(settings) { now }
        val chunks = fragments(ByteArray(300) { it.toByte() })

        reassembler.offer("slow", chunks[0], now)
        assertEquals(1, reassembler.activeCount())

        now += settings.reassemblyTimeoutMs + 1
        reassembler.expire(now)
        assertEquals(0, reassembler.activeCount())

        val outcome = reassembler.offer("slow", chunks[1], now)
        assertNull(outcome.completed)
        val ack = requireNotNull(AckCodec.decode(outcome.ack))
        assertTrue(ack.received[1])
        assertFalse(ack.received[0])
    }

    @Test
    fun `CRC failure asks for a full retransmit`() {
        var now = 1_000L
        val reassembler = Reassembler(settings) { now }
        val chunks = fragments(ByteArray(300) { it.toByte() })
        val corrupt = chunks.mapIndexed { index, chunk ->
            if (index == 2) {
                val data = chunk.data.copyOf()
                data[0] = (data[0].toInt() xor 0xFF).toByte()
                chunk.copy(data = data)
            } else {
                chunk
            }
        }

        var completed: ByteArray? = null
        var finalAck: ByteArray? = null
        for (chunk in corrupt) {
            val outcome = reassembler.offer("crc", chunk, now)
            if (outcome.completed != null) completed = outcome.completed
            finalAck = outcome.ack
        }

        assertNull(completed)
        val ack = requireNotNull(AckCodec.decode(requireNotNull(finalAck)))
        assertFalse(ack.received.any { it })
    }

    @Test
    fun `conflicting duplicate resets the transfer`() {
        var now = 1_000L
        val reassembler = Reassembler(settings) { now }
        val chunks = fragments(ByteArray(300) { it.toByte() })

        reassembler.offer("peer", chunks[0], now)
        val data = chunks[0].data.copyOf()
        data[0] = (data[0].toInt() xor 0xFF).toByte()
        val conflict = reassembler.offer("peer", chunks[0].copy(data = data), now)

        assertNull(conflict.completed)
        val ack = requireNotNull(AckCodec.decode(conflict.ack))
        assertFalse(ack.received.any { it })
    }

    private fun fragments(payload: ByteArray): List<ChunkCodec.Parsed> =
        Fragmenter.fragment(transferId = 77, payload = payload, maxFrameBytes = 64)
            .map { requireNotNull(ChunkCodec.decode(it)) }
}
