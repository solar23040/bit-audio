package com.solar23040.bitaudio.sim

import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.LinkConfig
import com.meshvoice.transport.Peer
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class LineTopologyTest {
    @Test
    fun lineOfFiveExposesOnlyAdjacentPeers() = runTest {
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            externalScope = backgroundScope,
        )
        val nodes = (0 until 5).map { network.addNode("n$it") }
        nodes.zipWithNext { left, right -> network.connect(left, right) }

        assertEquals(listOf(Peer("n1")), network.snapshot("n0"))
        assertEquals(listOf(Peer("n0"), Peer("n2")), network.snapshot("n1"))
        assertEquals(listOf(Peer("n1"), Peer("n3")), network.snapshot("n2"))
        assertEquals(listOf(Peer("n2"), Peer("n4")), network.snapshot("n3"))
        assertEquals(listOf(Peer("n3")), network.snapshot("n4"))
    }
}
