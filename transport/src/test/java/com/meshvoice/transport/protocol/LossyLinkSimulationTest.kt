package com.meshvoice.transport.protocol

import com.meshvoice.transport.Peer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

/**
 * Phase 1 acceptance for Agent C without phones: 15 KB through the real fragmentation, ack and
 * retransmission code with 10% loss in both directions.
 */
class LossyLinkSimulationTest {
    @Test
    fun `15 KB payload survives 10 percent loss in both directions`() {
        val random = Random(0x5EED)
        val settings = TransferSettings(
            maxFrameBytes = 240,
            ackTimeoutMs = 300,
            maxRetransmissions = 40,
            transferTtlMs = 60_000,
            reassemblyTimeoutMs = 30_000,
            completedCacheMs = 120_000,
            maxPayloadBytes = 64 * 1024,
        )
        var now = 1_000L
        val sender = TransferEngine(settings = settings, clock = { now })
        val receiver = TransferEngine(settings = settings, clock = { now })
        val senderPeer = Peer("AA:BB:CC:DD:EE:01")
        val receiverPeer = Peer("AA:BB:CC:DD:EE:02")
        val payload = random.nextBytes(15 * 1024)
        val delivered = ArrayList<ByteArray>()

        val started = sender.startTransfer(receiverPeer, payload, maxFrameBytes = 240)
        deliver(
            receiver = receiver,
            receiverSees = senderPeer,
            frames = started.chunks,
            sender = sender,
            senderSees = receiverPeer,
            random = random,
            delivered = delivered,
        )

        var guard = 0
        while (delivered.isEmpty() || sender.activeOutgoingCount() > 0) {
            check(guard++ < 2_000) { "transfer did not converge (${sender.activeOutgoingCount()} pending)" }
            now += 100
            val retransmissions = sender.poll(now)
            for (retransmission in retransmissions) {
                sender.markRetransmitted(retransmission.peer, retransmission.transferId, now)
                deliver(
                    receiver = receiver,
                    receiverSees = senderPeer,
                    frames = retransmission.chunks,
                    sender = sender,
                    senderSees = receiverPeer,
                    random = random,
                    delivered = delivered,
                )
            }
        }

        assertEquals(1, delivered.size)
        assertArrayEquals(payload, delivered.first())
        assertEquals(0, sender.activeOutgoingCount())
        assertEquals(0, receiver.activeIncomingCount())
        assertTrue(guard > 0)
    }

    private fun deliver(
        receiver: TransferEngine,
        receiverSees: Peer,
        frames: List<ByteArray>,
        sender: TransferEngine,
        senderSees: Peer,
        random: Random,
        delivered: MutableList<ByteArray>,
    ) {
        for (frame in frames) {
            if (random.nextInt(100) < LOSS_PERCENT) continue
            val result = receiver.receive(receiverSees, frame)
            delivered.addAll(result.deliveries)
            for (ack in result.acks) {
                if (random.nextInt(100) >= LOSS_PERCENT) {
                    sender.receive(senderSees, ack)
                }
            }
        }
    }

    private companion object {
        const val LOSS_PERCENT = 10
    }
}
