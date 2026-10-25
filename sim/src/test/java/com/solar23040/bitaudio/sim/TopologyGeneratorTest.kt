package com.solar23040.bitaudio.sim

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TopologyGeneratorTest {
    @Test
    fun lineBuildsAdjacentLinksOnly() {
        val graph = TopologyGenerator.build(
            nodeCount = 5,
            topology = Topology.LINE,
            seed = 1L,
            randomEdgeProbability = 0.1,
        )

        assertEquals(4, graph.edgeCount)
        assertEquals(
            listOf(Edge(0, 1), Edge(1, 2), Edge(2, 3), Edge(3, 4)),
            graph.edges,
        )
        assertEquals(listOf(1), graph.neighbours(0))
        assertEquals(listOf(0, 2), graph.neighbours(1))
        assertEquals(listOf(3), graph.neighbours(4))
        assertEquals((0 until 5).toSet(), graph.reachableFrom(0))
    }

    @Test
    fun gridHasFourNeighbourInteriorAndCorrectEdgeCount() {
        val graph = TopologyGenerator.build(
            nodeCount = 9,
            topology = Topology.GRID,
            seed = 1L,
            randomEdgeProbability = 0.1,
        )

        assertEquals(12, graph.edgeCount)
        assertEquals(listOf(1, 3), graph.neighbours(0))
        assertEquals(listOf(1, 3, 5, 7), graph.neighbours(4))
        assertEquals(listOf(5, 7), graph.neighbours(8))
        assertEquals((0 until 9).toSet(), graph.reachableFrom(4))
    }

    @Test
    fun randomGraphIsSymmetricConnectedAndDeterministic() {
        val first = TopologyGenerator.build(100, Topology.RANDOM, seed = 7L, randomEdgeProbability = 0.02)
        val second = TopologyGenerator.build(100, Topology.RANDOM, seed = 7L, randomEdgeProbability = 0.02)

        assertEquals(first.edges, second.edges)
        assertEquals((0 until 100).toSet(), first.reachableFrom(0))
        assertTrue("random graph should keep a spanning chain", first.edgeCount >= 99)
        assertEquals("edges must be unique", first.edges.size, first.edges.toSet().size)

        first.edges.forEach { edge ->
            assertTrue(edge.a < edge.b)
            assertTrue(edge.b in first.neighbours(edge.a))
            assertTrue(edge.a in first.neighbours(edge.b))
        }
    }

    @Test
    fun zeroProbabilityRandomGraphFallsBackToAChain() {
        val graph = TopologyGenerator.build(10, Topology.RANDOM, seed = 1L, randomEdgeProbability = 0.0)

        assertEquals(9, graph.edgeCount)
        assertEquals((0 until 10).toSet(), graph.reachableFrom(3))
    }
}
