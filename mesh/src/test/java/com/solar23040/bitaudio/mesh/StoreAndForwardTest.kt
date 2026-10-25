package com.solar23040.bitaudio.mesh

import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class StoreAndForwardTest {

    @Test
    fun `late joining peer receives clips relayed before it appeared`() = runTest {
        val world = MeshWorld(
            scope = backgroundScope,
            clock = TestClock(),
            nodeIds = listOf("a", "b", "c"),
        )
        world.connect("a", "b")

        val payload = ByteArray(800) { index -> (index % 199).toByte() }
        world.node("a").mesh.publish(world.channel.id, payload)
        advanceUntilIdle()

        assertEquals(1, world.node("b").messages.size)
        assertTrue("c is still isolated", world.node("c").messages.isEmpty())
        assertTrue("relay b kept the sealed packets", world.node("b").store.size() > 0)

        world.connect("b", "c")
        advanceUntilIdle()

        assertEquals("late joiner delivered once", 1, world.node("c").messages.size)
        assertArrayEquals(payload, world.node("c").messages.single().payload)
        assertEquals("existing peer not re-delivered", 1, world.node("b").messages.size)

        world.close()
    }

    @Test
    fun `expired stored packets are dropped instead of replayed`() = runTest {
        val clock = TestClock()
        val retentionMs = MeshWorld.DEFAULT_RETENTION_MS
        val world = MeshWorld(
            scope = backgroundScope,
            clock = clock,
            nodeIds = listOf("a", "b", "c"),
            retentionMs = retentionMs,
        )
        world.connect("a", "b")

        world.node("a").mesh.publish(world.channel.id, ByteArray(400) { index -> index.toByte() })
        advanceUntilIdle()
        assertEquals(1, world.node("b").messages.size)
        assertTrue(world.node("b").store.size() > 0)

        clock.now += retentionMs + 1L

        world.connect("b", "c")
        advanceUntilIdle()

        assertTrue("expired clip must not be replayed", world.node("c").messages.isEmpty())
        assertEquals("expired rows must be swept", 0, world.node("b").store.size())
        assertEquals(0, world.node("b").mesh.expireStored())

        world.close()
    }
}
