package com.meshvoice.transport

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FakeTransportTest {
    private fun TestScope.fastNetwork(lossRate: Double = 0.0): FakeNetwork =
        FakeNetwork(
            defaultLink = LinkConfig(lossRate = lossRate, latencyMs = 0L..0L),
            seed = 7,
            externalScope = backgroundScope,
        )

    @Test
    fun deliversFrameBetweenConnectedPeers() = runTest {
        val network = fastNetwork()
        val a = network.addNode("a")
        val b = network.addNode("b")
        network.connect(a, b)

        val received = CompletableDeferred<ReceivedFrame>()
        b.onReceive { frame -> received.complete(frame) }

        a.send(Peer("b"), byteArrayOf(1, 2, 3))

        val frame = received.await()
        assertEquals("a", frame.from.id)
        assertArrayEquals(byteArrayOf(1, 2, 3), frame.bytes)
    }

    @Test
    fun dropsAllFramesAtFullLoss() = runTest {
        val network = fastNetwork(lossRate = 1.0)
        val a = network.addNode("a")
        val b = network.addNode("b")
        network.connect(a, b)

        var received = false
        b.onReceive { received = true }
        a.send(Peer("b"), byteArrayOf(9))
        advanceUntilIdle()

        assertFalse(received)
    }

    @Test
    fun topologyChangesAreVisibleInSnapshots() = runTest {
        val network = fastNetwork()
        val a = network.addNode("a")
        val b = network.addNode("b")
        val c = network.addNode("c")

        network.connect(a, b)
        network.connect(b, c)

        assertEquals(listOf(Peer("b")), network.snapshot("a"))
        assertEquals(listOf(Peer("a"), Peer("c")), network.snapshot("b"))
        assertEquals(listOf(Peer("b")), network.snapshot("c"))

        network.disconnect(b, c)
        assertEquals(listOf(Peer("a")), network.snapshot("b"))
        assertTrue(network.snapshot("c").isEmpty())
    }

    @Test
    fun peerFlowEmitsDiscoveredNeighbours() = runTest {
        val network = fastNetwork()
        val a = network.addNode("a")
        val b = network.addNode("b")

        network.connect(a, b)

        assertEquals(listOf(Peer("b")), a.peers().first())
    }

    @Test
    fun sendToUnlinkedPeerIsDropped() = runTest {
        val network = fastNetwork()
        val a = network.addNode("a")
        val b = network.addNode("b")

        var received = false
        b.onReceive { _ -> received = true }
        a.send(Peer("b"), byteArrayOf(1))
        advanceUntilIdle()
        assertFalse(received)
    }

    @Test
    fun closingHandleStopsThatCallbackOnly() = runTest {
        val network = fastNetwork()
        val a = network.addNode("a")
        val b = network.addNode("b")
        network.connect(a, b)

        var oldCount = 0
        var newCount = 0
        val oldHandle = b.onReceive { _ -> oldCount++ }
        b.onReceive { _ -> newCount++ }
        oldHandle.close()

        a.send(Peer("b"), byteArrayOf(1))
        advanceUntilIdle()

        assertEquals(0, oldCount)
        assertEquals(1, newCount)
    }

    @Test
    fun removingNodeDisconnectsIt() = runTest {
        val network = fastNetwork()
        val a = network.addNode("a")
        val b = network.addNode("b")
        network.connect(a, b)

        network.removeNode("b")

        assertTrue(network.snapshot("a").isEmpty())
        a.send(Peer("b"), byteArrayOf(1))
        advanceUntilIdle()
    }

    @Test
    fun callbackExceptionsDoNotBreakTheNetwork() = runTest {
        val network = fastNetwork()
        val a = network.addNode("a")
        val b = network.addNode("b")
        network.connect(a, b)

        var delivered = 0
        b.onReceive { _ ->
            delivered += 1
            if (delivered == 1) error("consumer bug")
        }

        a.send(Peer("b"), byteArrayOf(1))
        a.send(Peer("b"), byteArrayOf(2))
        advanceUntilIdle()

        assertEquals(2, delivered)
    }
}
