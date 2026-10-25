package com.solar23040.bitaudio.sim

import kotlin.math.ceil
import kotlin.math.sqrt

/** Undirected link between two node indexes. */
data class Edge(val a: Int, val b: Int) {
    init {
        require(a >= 0 && b >= 0) { "Edge indexes must not be negative: $a-$b" }
        require(a != b) { "Self links are not allowed: $a" }
    }
}

/** Immutable topology plus adjacency and reachability helpers. */
data class TopologyGraph(
    val nodeCount: Int,
    val edges: List<Edge>,
) {
    init {
        require(nodeCount >= 1) { "nodeCount must be at least 1: $nodeCount" }
        require(edges.all { it.a < nodeCount && it.b < nodeCount }) {
            "Edge references a node outside 0..${nodeCount - 1}"
        }
        require(edges.distinct().size == edges.size) { "edges must not contain duplicates" }
    }

    private val adjacency: List<List<Int>> = run {
        val neighbours = List(nodeCount) { mutableListOf<Int>() }
        edges.forEach { edge ->
            neighbours[edge.a].add(edge.b)
            neighbours[edge.b].add(edge.a)
        }
        neighbours.map { it.sorted() }
    }

    val edgeCount: Int get() = edges.size

    fun neighbours(node: Int): List<Int> {
        require(node in 0 until nodeCount) { "Unknown node: $node" }
        return adjacency[node]
    }

    /** Nodes reachable from [node], including [node] itself. */
    fun reachableFrom(node: Int): Set<Int> {
        require(node in 0 until nodeCount) { "Unknown node: $node" }
        val visited = HashSet<Int>(nodeCount)
        val queue = ArrayDeque<Int>()
        visited.add(node)
        queue.addLast(node)
        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()
            for (next in adjacency[current]) {
                if (visited.add(next)) queue.addLast(next)
            }
        }
        return visited
    }
}

/** Deterministic topology generation for LINE, GRID and RANDOM networks. */
object TopologyGenerator {
    fun build(
        nodeCount: Int,
        topology: Topology,
        seed: Long,
        randomEdgeProbability: Double,
    ): TopologyGraph {
        require(nodeCount >= 1) { "nodeCount must be at least 1: $nodeCount" }
        require(randomEdgeProbability in 0.0..1.0) {
            "randomEdgeProbability must be in [0, 1]: $randomEdgeProbability"
        }
        val edges = when (topology) {
            Topology.LINE -> lineEdges(nodeCount)
            Topology.GRID -> gridEdges(nodeCount)
            Topology.RANDOM -> randomEdges(nodeCount, randomEdgeProbability, seed)
        }
        return TopologyGraph(
            nodeCount = nodeCount,
            edges = edges.sortedWith(compareBy({ it.a }, { it.b })),
        )
    }

    private fun lineEdges(nodeCount: Int): List<Edge> =
        (0 until nodeCount - 1).map { Edge(it, it + 1) }

    private fun gridEdges(nodeCount: Int): List<Edge> {
        val columns = ceil(sqrt(nodeCount.toDouble())).toInt().coerceAtLeast(1)
        val edges = ArrayList<Edge>()
        for (node in 0 until nodeCount) {
            val isRowEnd = (node + 1) % columns == 0
            if (!isRowEnd && node + 1 < nodeCount) edges.add(Edge(node, node + 1))
            if (node + columns < nodeCount) edges.add(Edge(node, node + columns))
        }
        return edges
    }

    private fun randomEdges(nodeCount: Int, probability: Double, seed: Long): List<Edge> {
        val random = kotlin.random.Random(seed)
        val edges = LinkedHashSet<Edge>()
        for (first in 0 until nodeCount) {
            for (second in first + 1 until nodeCount) {
                if (random.nextDouble() < probability) edges.add(Edge(first, second))
            }
        }

        // Join any remaining components with a deterministic chain so isolated
        // nodes do not silently look like routing failures.
        val parent = IntArray(nodeCount) { it }
        fun find(value: Int): Int {
            var root = value
            while (parent[root] != root) root = parent[root]
            var current = value
            while (parent[current] != current) {
                val next = parent[current]
                parent[current] = root
                current = next
            }
            return root
        }
        fun union(first: Int, second: Int): Boolean {
            val firstRoot = find(first)
            val secondRoot = find(second)
            if (firstRoot == secondRoot) return false
            parent[secondRoot] = firstRoot
            return true
        }
        edges.forEach { union(it.a, it.b) }
        for (node in 1 until nodeCount) {
            if (find(node) != find(node - 1)) {
                edges.add(Edge(node - 1, node))
                union(node - 1, node)
            }
        }
        return edges.toList()
    }
}
