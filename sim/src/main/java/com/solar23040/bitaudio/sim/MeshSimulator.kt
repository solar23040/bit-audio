package com.solar23040.bitaudio.sim

import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.FakeTransport
import com.meshvoice.transport.LinkConfig
import com.meshvoice.transport.Peer
import com.meshvoice.transport.ReceivedFrame
import java.util.Random
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Raised when a run does not go quiet within [SimConfig.maxSimulationMs]. */
class SimulationTimeoutException(message: String) : Exception(message)

/**
 * N-node flood simulator on top of [FakeNetwork].
 *
 * Each node is a [FakeTransport]; links use the configured loss and latency.
 * Messages are published from non-malicious origins, flooded with a TTL and a
 * seen cache, and every transmission is counted for airtime. The network is
 * closed when the run finishes if this simulator created it.
 *
 * Pass [externalNetwork] when running under `runTest` so the network uses the
 * test scheduler (virtual time) instead of wall-clock delays.
 */
class MeshSimulator(
    private val config: SimConfig,
    private val externalNetwork: FakeNetwork? = null,
) {
    suspend fun run(
        scope: CoroutineScope,
        clock: () -> Long = { System.currentTimeMillis() },
    ): SimResult {
        val graph = TopologyGenerator.build(
            nodeCount = config.nodes,
            topology = config.topology,
            seed = config.seed,
            randomEdgeProbability = config.randomEdgeProbability,
        )
        val network = externalNetwork ?: FakeNetwork(
            defaultLink = LinkConfig(config.lossRate, config.latencyMs),
            seed = config.seed,
            externalScope = scope,
        )
        val ownsNetwork = externalNetwork == null
        val transports = (0 until config.nodes).map { network.addNode("n$it") }
        graph.edges.forEach { edge ->
            network.connect(
                transports[edge.a],
                transports[edge.b],
                LinkConfig(lossRate = config.lossRate, latencyMs = config.latencyMs),
            )
        }

        val malicious = selectMaliciousNodes()
        val origins = selectOrigins(malicious)
        val runtime = Runtime(
            graph = graph,
            transports = transports,
            malicious = malicious,
            origins = origins,
            scope = scope,
            clock = clock,
        )
        try {
            runtime.start()
            runtime.publish()
            runtime.awaitIdle()
            return runtime.snapshot()
        } finally {
            runtime.close()
            if (ownsNetwork) network.close()
        }
    }

    private fun selectMaliciousNodes(): Set<Int> {
        if (config.maliciousIndices.isNotEmpty()) return config.maliciousIndices.toSet()
        if (config.maliciousNodeCount == 0) return emptySet()
        val random = kotlin.random.Random(config.seed xor 0x5EED5EEDL)
        return (0 until config.nodes)
            .shuffled(random)
            .take(config.maliciousNodeCount)
            .toSet()
    }

    private fun selectOrigins(malicious: Set<Int>): List<Int> {
        val candidates = (0 until config.nodes)
            .filter { it !in malicious }
            .ifEmpty { (0 until config.nodes).toList() }
        val random = kotlin.random.Random(config.seed xor 0x0C0FFEEL)
        val shuffled = candidates.shuffled(random)
        return (0 until config.messages).map { shuffled[it % shuffled.size] }
    }

    private inner class Runtime(
        private val graph: TopologyGraph,
        private val transports: List<FakeTransport>,
        private val malicious: Set<Int>,
        private val origins: List<Int>,
        private val scope: CoroutineScope,
        private val clock: () -> Long,
    ) {
        private val lock = Any()
        private val random = Random(config.seed xor 0xA11CEL)
        private val pending = AtomicInteger(0)
        private val seen = Array(config.nodes) { HashSet<Int>() }
        private val transmissions = LongArray(config.nodes)
        private val receptions = LongArray(config.nodes)
        private val duplicates = LongArray(config.nodes)
        private val deliveredByNode = IntArray(config.nodes)
        private val airtime = LongArray(config.nodes)
        private val handles = ArrayList<AutoCloseable>()
        private val startedAt = clock()
        private val states: List<MessageState> = List(config.messages) { index ->
            val payload = ByteArray(config.payloadBytes) { position ->
                ((position * 31 + index * 17) and 0xFF).toByte()
            }
            MessageState(index, origins[index], payload)
        }

        fun start() {
            for (node in 0 until config.nodes) {
                handles += transports[node].onReceive { frame -> onFrame(node, frame) }
            }
        }

        fun publish() {
            val publishStart = startedAt
            states.forEachIndexed { index, state ->
                pending.incrementAndGet()
                scope.launch {
                    try {
                        val waitMs = publishStart + config.publishStaggerMs * index - clock()
                        if (waitMs > 0) delay(waitMs)

                        var createdAt = 0L
                        synchronized(lock) {
                            createdAt = clock()
                            state.createdAt = createdAt
                            seen[state.origin].add(state.id)
                        }
                        val packet = SimPacket(
                            messageId = state.id,
                            origin = state.origin,
                            createdAtMs = createdAt,
                            hops = 0,
                            ttl = config.ttl,
                            payload = state.payload,
                        )
                        for (neighbour in graph.neighbours(state.origin)) {
                            transmit(state.origin, neighbour, packet)
                        }
                    } finally {
                        pending.decrementAndGet()
                    }
                }
            }
        }

        suspend fun awaitIdle() {
            val deadline = clock() + config.maxSimulationMs
            while (pending.get() > 0) {
                if (clock() > deadline) {
                    throw SimulationTimeoutException(
                        "Simulation '${config.name}' did not go quiet within " +
                            "${config.maxSimulationMs} ms",
                    )
                }
                delay(config.idlePollMs)
            }
        }

        fun snapshot(): SimResult {
            val messageMetrics: List<MessageMetrics>
            val nodeMetrics: List<NodeMetrics>
            val duration: Long
            val expectedByOrigin = HashMap<Int, Int>()
            synchronized(lock) {
                messageMetrics = states.map { state ->
                    val expected = expectedByOrigin.getOrPut(state.origin) {
                        graph.reachableFrom(state.origin).size - 1
                    }
                    MessageMetrics(
                        messageId = state.id,
                        origin = state.origin,
                        expectedDeliveries = expected,
                        deliveredNodes = state.deliveredNodes.toSet(),
                        hops = state.hops.toList(),
                        latenciesMs = state.latenciesMs.toList(),
                        duplicateReceptions = state.duplicateReceptions,
                        transmissions = state.transmissions,
                        airtimeBytes = state.airtimeBytes,
                    )
                }
                nodeMetrics = (0 until config.nodes).map { node ->
                    NodeMetrics(
                        node = node,
                        malicious = node in malicious,
                        transmissions = transmissions[node],
                        receptions = receptions[node],
                        duplicateReceptions = duplicates[node],
                        deliveredMessages = deliveredByNode[node],
                        airtimeBytes = airtime[node],
                    )
                }
                duration = (clock() - startedAt).coerceAtLeast(0L)
            }
            val metrics = MetricsCalculator.summarize(
                messages = messageMetrics,
                durationMs = duration,
                linkBytesPerSecond = config.linkBytesPerSecond,
            )
            return SimResult(
                config = config,
                graph = graph,
                origins = origins,
                maliciousNodes = malicious,
                metrics = metrics,
                messages = messageMetrics,
                nodeMetrics = nodeMetrics,
            )
        }

        fun close() {
            handles.forEach { runCatching { it.close() } }
            handles.clear()
        }

        private fun onFrame(node: Int, frame: ReceivedFrame) {
            val packet = SimPacket.decode(frame.bytes) ?: return
            if (packet.messageId !in states.indices) return
            val state = states[packet.messageId]

            val relay = synchronized(lock) {
                receptions[node]++
                if (!seen[node].add(packet.messageId)) {
                    duplicates[node]++
                    state.duplicateReceptions++
                    return@synchronized false
                }
                if (node != state.origin) {
                    state.deliveredNodes.add(node)
                    state.hops.add(packet.hops)
                    state.latenciesMs.add((clock() - state.createdAt).coerceAtLeast(0L))
                    deliveredByNode[node]++
                }
                packet.ttl > 0
            }
            if (!relay) return

            if (node in malicious && config.maliciousBehavior == MaliciousBehavior.DROP) return
            val copies = if (
                node in malicious && config.maliciousBehavior == MaliciousBehavior.DUPLICATE
            ) {
                config.duplicateFactor
            } else {
                1
            }
            for (neighbour in graph.neighbours(node)) {
                repeat(copies) {
                    transmit(node, neighbour, packet)
                }
            }
        }

        private fun transmit(from: Int, to: Int, packet: SimPacket) {
            if (packet.messageId !in states.indices) return
            val state = states[packet.messageId]
            val wirePacket = packet.copy(hops = packet.hops + 1, ttl = packet.ttl - 1)
            if (wirePacket.ttl < 0) return
            val bytes = wirePacket.encode()
            synchronized(lock) {
                transmissions[from]++
                airtime[from] += bytes.size
                state.transmissions++
                state.airtimeBytes += bytes.size
            }

            pending.incrementAndGet()
            scope.launch {
                try {
                    val jitter = sampleJitter()
                    if (jitter > 0) delay(jitter)
                    transports[from].send(Peer(id = "n$to"), bytes)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Throwable) {
                    // A failed link is part of the simulation; the packet is lost.
                } finally {
                    pending.decrementAndGet()
                }
            }
        }

        private fun sampleJitter(): Long = synchronized(random) {
            if (config.jitterMs.first == config.jitterMs.last) {
                config.jitterMs.first
            } else {
                val span = config.jitterMs.last - config.jitterMs.first + 1
                config.jitterMs.first + (random.nextDouble() * span).toLong()
            }
        }
    }

    private class MessageState(
        val id: Int,
        val origin: Int,
        val payload: ByteArray,
    ) {
        var createdAt: Long = 0L
        val deliveredNodes = HashSet<Int>()
        val hops = ArrayList<Int>()
        val latenciesMs = ArrayList<Long>()
        var duplicateReceptions: Long = 0L
        var transmissions: Long = 0L
        var airtimeBytes: Long = 0L
    }
}
