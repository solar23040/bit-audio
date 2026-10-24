package com.meshvoice.transport.protocol

import com.meshvoice.transport.Peer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TransferEngineTest {
    private val peer = Peer("AA:BB:CC:DD:EE:01")

    @Test
    fun `selective ack retransmits only missing chunks`() {
        var now = 1_000L
        val engine = TransferEngine(settings = settings(), clock = { now })
        val payload = ByteArray(300) { it.toByte() }
        val started = engine.startTransfer(peer, payload, maxFrameBytes = 64)

        val received = BooleanArray(started.chunks.size) { it != 2 && it != 5 }
        val ack = AckCodec.encode(started.transferId, started.chunks.size, received)
        engine.receive(peer, ack)

        now += 60
        val retransmissions = engine.poll(now)
        assertEquals(1, retransmissions.size)
        val missingSeq = retransmissions.first().chunks.map {
            requireNotNull(ChunkCodec.decode(it)).header.seq
        }
        assertEquals(listOf(2, 5), missingSeq)

        engine.markRetransmitted(peer, started.transferId, now)
        assertEquals(1, engine.activeOutgoingCount())

        engine.receive(peer, AckCodec.encode(started.transferId, started.chunks.size, BooleanArray(received.size) { true }))
        assertEquals(0, engine.activeOutgoingCount())
    }

    @Test
    fun `delivers chunks received through another engine`() {
        var now = 2_000L
        val sender = TransferEngine(settings = settings(), clock = { now })
        val receiver = TransferEngine(settings = settings(), clock = { now })
        val payload = ByteArray(500) { (it * 7).toByte() }
        val started = sender.startTransfer(peer, payload, maxFrameBytes = 64)

        var delivered: ByteArray? = null
        started.chunks.reversed().forEach { frame ->
            val result = receiver.receive(Peer("sender"), frame)
            result.deliveries.forEach { delivered = it }
        }

        assertEquals(payload.size, requireNotNull(delivered).size)
        assertTrue(requireNotNull(delivered).contentEquals(payload))
    }

    @Test
    fun `gives up after retransmission limit`() {
        var now = 1_000L
        var failure: String? = null
        val engine = TransferEngine(
            settings = settings(ackTimeoutMs = 50, maxRetransmissions = 2),
            clock = { now },
            onTransferFailed = { _, _, reason -> failure = reason },
        )
        val started = engine.startTransfer(peer, ByteArray(100), maxFrameBytes = 64)

        now += 60
        assertEquals(1, engine.poll(now).size)
        engine.markRetransmitted(peer, started.transferId, now)

        now += 60
        assertTrue(engine.poll(now).isEmpty())
        assertEquals(0, engine.activeOutgoingCount())
        assertNotNull(failure)
    }

    @Test
    fun `malformed frames are ignored`() {
        val engine = TransferEngine(settings = settings(), clock = { 1_000L })
        val result = engine.receive(peer, byteArrayOf(0x01, 0x02, 0x03))
        assertTrue(result.acks.isEmpty())
        assertTrue(result.deliveries.isEmpty())
        assertNull(result.deliveries.firstOrNull())
    }

    @Test(expected = IllegalArgumentException::class)
    fun `payload above limit is rejected`() {
        val engine = TransferEngine(
            settings = settings().copy(maxPayloadBytes = 10),
            clock = { 1_000L },
        )
        engine.startTransfer(peer, ByteArray(11), maxFrameBytes = 64)
    }

    private fun settings(
        ackTimeoutMs: Long = 50,
        maxRetransmissions: Int = 5,
    ) = TransferSettings(
        maxFrameBytes = 64,
        ackTimeoutMs = ackTimeoutMs,
        maxRetransmissions = maxRetransmissions,
        transferTtlMs = 10_000,
        reassemblyTimeoutMs = 5_000,
        completedCacheMs = 5_000,
        maxPayloadBytes = 64 * 1024,
    )
}
