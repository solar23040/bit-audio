package com.solar23040.bitaudio.mesh.node

import com.bitaudio.crypto.PacketCrypto
import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.LinkConfig
import com.solar23040.bitaudio.mesh.MeshMessage
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class MeshLineTest {

    @Test
    fun fiveNodeLineDeliversExactlyOnceWithoutLoops() = runTest {
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            externalScope = backgroundScope,
        )
        val nodes = (0 until 5).map { testMeshNode(network, "n$it", backgroundScope) }
        nodes.zipWithNext { left, right -> network.connect(left.transport, right.transport) }
        val channel = testChannel(nodes)

        val received = ArrayList<MeshMessage>()
        nodes[4].mesh.onMessage { received.add(it) }

        val payload = ByteArray(15_000).also { SecureRandom().nextBytes(it) }
        nodes[0].mesh.publish(channel, payload)
        repeat(10) { runCurrent() }

        assertEquals(1, received.size)
        assertArrayEquals(payload, received.single().payload)
        assertEquals(4, received.single().hopCount)
    }

    @Test
    fun fifteenKilobyteClipFitsEveryMeshFrameAndTheTransportBoundary() = runTest {
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            externalScope = backgroundScope,
        )
        val recorder = RecordingTransport()
        val nodes = (0 until 3).map {
            testMeshNode(network, "n$it", backgroundScope, recording = recorder)
        }
        nodes.zipWithNext { left, right -> network.connect(left.transport, right.transport) }
        val channel = testChannel(nodes)

        val received = ArrayList<MeshMessage>()
        nodes[2].mesh.onMessage { received.add(it) }

        val payload = ByteArray(15_000).also { SecureRandom().nextBytes(it) }
        nodes[0].mesh.publish(channel, payload)
        repeat(10) { runCurrent() }

        assertTrue("expected at least 42 packets, got ${recorder.sent.size}", recorder.sent.size >= 42)
        recorder.sent.forEach { frame ->
            assertTrue(
                "mesh frame is ${frame.size} bytes, limit is ${MeshPacket.MAX_PACKET_SIZE}",
                frame.size <= MeshPacket.MAX_PACKET_SIZE,
            )
            assertNotNull(MeshPacket.decode(frame))
        }
        val stored = nodes[0].store.snapshot(System.currentTimeMillis()).single()
        assertEquals(42, stored.packets.size)
        assertArrayEquals(payload, received.single().payload)
    }

    @Test
    fun storedMessageIsHandedOffWhenAPeerIsDiscovered() = runTest {
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            externalScope = backgroundScope,
        )
        val sender = testMeshNode(network, "sender", backgroundScope)
        val receiver = testMeshNode(network, "receiver", backgroundScope)
        val channel = testChannel(listOf(sender, receiver))

        val received = ArrayList<MeshMessage>()
        receiver.mesh.onMessage { received.add(it) }
        runCurrent()

        sender.mesh.publish(channel, "stored-while-offline".toByteArray())
        repeat(3) { runCurrent() }
        assertTrue("delivered before a link existed", received.isEmpty())

        network.connect(sender.transport, receiver.transport)
        repeat(10) { runCurrent() }

        assertEquals(1, received.size)
        assertArrayEquals("stored-while-offline".toByteArray(), received.single().payload)
    }

    @Test
    fun ttlChangeDoesNotInvalidateTheSignature() = runTest {
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            externalScope = backgroundScope,
        )
        val node = testMeshNode(network, "n0", backgroundScope)
        val channel = testChannel(listOf(node))
        node.mesh.publish(channel, ByteArray(600) { it.toByte() })
        repeat(3) { runCurrent() }

        val stored = node.store.snapshot(System.currentTimeMillis()).single()
        val original = MeshPacket.decode(stored.packets.first())!!
        val relayed = original.withTtl(original.ttl - 1)
        val canonical = relayed.canonicalPrefix()
        assertTrue(
            PacketCrypto.verifyPacket(
                node.crypto,
                node.publicKey,
                canonical,
                relayed.sealedChunk,
                relayed.signature,
            ),
        )
        // TTL is the only byte that relays may change.
        val before = original.toWire()
        val after = relayed.toWire()
        assertEquals(before.size, after.size)
        assertEquals(4, after[26].toInt())
        assertArrayEquals(before.copyOfRange(0, 26), after.copyOfRange(0, 26))
        assertArrayEquals(before.copyOfRange(27, before.size), after.copyOfRange(27, after.size))
    }
}
