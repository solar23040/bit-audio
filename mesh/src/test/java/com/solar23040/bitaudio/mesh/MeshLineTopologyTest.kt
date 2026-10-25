package com.solar23040.bitaudio.mesh

import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MeshLineTopologyTest {

    @Test
    fun `five node line delivers end to end without loops or duplicates`() = runTest {
        val world = MeshWorld(
            scope = backgroundScope,
            clock = TestClock(),
            nodeIds = listOf("n0", "n1", "n2", "n3", "n4"),
        )

        // Independent frame counters sit beside the mesh callbacks so we can
        // prove the flood stays bounded (no loop storm).
        val deliveries = world.nodes.keys.associateWith { AtomicInteger(0) }
        world.nodes.forEach { (id, node) ->
            node.transport.onReceive { deliveries.getValue(id).incrementAndGet() }
        }

        (0..3).forEach { index -> world.connect("n$index", "n${index + 1}") }

        // 3 chunks at the 365-byte plaintext limit.
        val payload = ByteArray(1_000) { index -> (index % 251).toByte() }
        world.node("n0").mesh.publish(world.channel.id, payload)
        advanceUntilIdle()

        assertArrayEquals(payload, world.node("n4").messages.single().payload)

        // Every relay in the line delivered exactly once; the publisher did not
        // deliver its own message to itself.
        (1..4).forEach { index ->
            assertEquals("n$index deliveries", 1, world.node("n$index").messages.size)
        }
        assertEquals(0, world.node("n0").messages.size)

        // One publish over a 4-link line: 4 frame deliveries per chunk, 12
        // total. Relays never echo back to the ingress peer, so a higher count
        // means the flood is looping.
        assertEquals(12, deliveries.values.sumOf { it.get() })
        assertTrue(world.node("n4").messages.single().hopCount >= 3)

        world.close()
    }

    @Test
    fun `ring topology delivers once per node without a loop storm`() = runTest {
        val world = MeshWorld(
            scope = backgroundScope,
            clock = TestClock(),
            nodeIds = listOf("n0", "n1", "n2", "n3", "n4"),
        )

        val deliveries = world.nodes.keys.associateWith { AtomicInteger(0) }
        world.nodes.forEach { (id, node) ->
            node.transport.onReceive { deliveries.getValue(id).incrementAndGet() }
        }

        // 4 links around a ring plus the closing n4-n0 link.
        (0..3).forEach { index -> world.connect("n$index", "n${index + 1}") }
        world.connect("n4", "n0")

        val payload = ByteArray(1_000) { index -> (index % 251).toByte() }
        world.node("n0").mesh.publish(world.channel.id, payload)
        advanceUntilIdle()

        (1..4).forEach { index ->
            assertEquals("n$index deliveries", 1, world.node("n$index").messages.size)
        }
        assertEquals(0, world.node("n0").messages.size)
        assertArrayEquals(payload, world.node("n4").messages.single().payload)

        // Two directions meet at n3; dedup drops the second copy there.
        // 6 deliveries per chunk = 18 for three chunks.
        assertEquals(18, deliveries.values.sumOf { it.get() })

        world.close()
    }

    @Test
    fun `rebroadcast is delayed by the jitter window`() = runTest {
        val world = MeshWorld(
            scope = backgroundScope,
            clock = TestClock(),
            nodeIds = listOf("n0", "n1", "n2"),
        )
        world.connect("n0", "n1")
        world.connect("n1", "n2")

        // One chunk, so n1 has everything and can schedule its rebroadcast.
        world.node("n0").mesh.publish(world.channel.id, ByteArray(100))
        runCurrent()

        assertEquals(1, world.node("n1").messages.size)
        assertTrue("n2 must wait for the jitter", world.node("n2").messages.isEmpty())

        advanceTimeBy(19L)
        runCurrent()
        assertTrue("jitter is at least 20 ms", world.node("n2").messages.isEmpty())

        advanceUntilIdle()
        assertEquals(1, world.node("n2").messages.size)

        world.close()
    }
}
