package com.meshvoice.transport

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.Random
import java.util.TreeSet
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Per-link simulation settings. Latency is sampled uniformly from [latencyMs]
 * (both ends inclusive); [lossRate] is the probability that a frame is dropped.
 */
data class LinkConfig(
    val lossRate: Double = 0.0,
    val latencyMs: LongRange = 2L..10L,
) {
    init {
        require(lossRate in 0.0..1.0) { "lossRate must be in [0, 1]: $lossRate" }
        require(latencyMs.first >= 0 && latencyMs.first <= latencyMs.last) {
            "latencyMs must be a non-negative, non-empty range: $latencyMs"
        }
    }

    internal fun sampleLatency(random: Random): Long {
        if (latencyMs.first == latencyMs.last) return latencyMs.first
        val span = latencyMs.last - latencyMs.first + 1
        return latencyMs.first + (random.nextDouble() * span).toLong()
    }
}

/**
 * In-memory network used by unit tests and the simulator.
 *
 * Nodes connect explicitly. [FakeTransport.send] is suspending: latency is applied
 * to the caller and a lost frame is silently dropped. Callback exceptions are
 * contained so one bad consumer cannot stop the simulation.
 */
class FakeNetwork(
    private val defaultLink: LinkConfig = LinkConfig(),
    seed: Long = DEFAULT_SEED,
    externalScope: CoroutineScope? = null,
) {
    private val random = Random(seed)
    private val lock = Any()
    private val nodes = LinkedHashMap<String, Node>()
    private val links = HashMap<LinkKey, LinkConfig>()
    private val ownsScope = externalScope == null
    private val scope: CoroutineScope =
        externalScope ?: CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** Create a node and return its transport handle. */
    fun addNode(id: String): FakeTransport {
        require(id.isNotBlank()) { "Node id must not be blank" }
        synchronized(lock) {
            require(id !in nodes) { "Node already exists: $id" }
            nodes[id] = Node()
        }
        return FakeTransport(this, id)
    }

    /** Remove a node and all of its links, simulating a phone going away. */
    fun removeNode(id: String) {
        synchronized(lock) {
            if (nodes.remove(id) == null) return
            links.keys.removeAll { it.a == id || it.b == id }
            nodes.values.forEach { node ->
                node.neighbours.remove(id)
            }
            nodes.keys.toList().forEach(::refreshPeers)
        }
    }

    /** Connect two nodes. Calling this again replaces the link settings. */
    fun connect(a: String, b: String, link: LinkConfig? = null) {
        require(a != b) { "A node cannot connect to itself: $a" }
        synchronized(lock) {
            require(a in nodes) { "Unknown node: $a" }
            require(b in nodes) { "Unknown node: $b" }
            links[LinkKey.of(a, b)] = link ?: defaultLink
            nodes.getValue(a).neighbours.add(b)
            nodes.getValue(b).neighbours.add(a)
            refreshPeers(a)
            refreshPeers(b)
        }
    }

    fun connect(a: FakeTransport, b: FakeTransport, link: LinkConfig? = null) {
        connect(a.id, b.id, link)
    }

    /** Remove the link between two nodes, if one exists. */
    fun disconnect(a: String, b: String) {
        synchronized(lock) {
            if (links.remove(LinkKey.of(a, b)) == null) return
            nodes[a]?.neighbours?.remove(b)
            nodes[b]?.neighbours?.remove(a)
            refreshPeers(a)
            refreshPeers(b)
        }
    }

    fun disconnect(a: FakeTransport, b: FakeTransport) {
        disconnect(a.id, b.id)
    }

    /** Current neighbours of [id], sorted by id. Useful in topology tests. */
    fun snapshot(id: String): List<Peer> = synchronized(lock) {
        nodes[id]?.neighbours?.map { Peer(id = it) } ?: emptyList()
    }

    internal fun peers(id: String): Flow<List<Peer>> {
        val node = synchronized(lock) { nodes[id] } ?: error("Unknown node: $id")
        return node.peers.asStateFlow()
    }

    internal fun addReceiver(id: String, callback: (ReceivedFrame) -> Unit): AutoCloseable {
        val node = synchronized(lock) { nodes[id] } ?: error("Unknown node: $id")
        node.receivers.add(callback)
        return AutoCloseable { node.receivers.remove(callback) }
    }

    internal suspend fun send(fromId: String, toId: String, bytes: ByteArray) {
        val link = synchronized(lock) {
            if (fromId !in nodes) null else links[LinkKey.of(fromId, toId)]
        } ?: return

        if (random.nextDouble() < link.lossRate) return
        val latency = link.sampleLatency(random)
        if (latency > 0) delay(latency)

        val receivers = synchronized(lock) {
            nodes[toId]?.receivers?.toList()
        } ?: return
        val frame = ReceivedFrame(from = Peer(id = fromId), bytes = bytes.copyOf())
        for (receiver in receivers) {
            runCatching { receiver(frame) }
        }
    }

    /** Cancel the owned scope. Call when the network is no longer needed. */
    fun close() {
        if (ownsScope) scope.cancel()
    }

    private fun refreshPeers(id: String) {
        val node = nodes[id] ?: return
        node.peers.value = node.neighbours.map { Peer(id = it) }
    }

    private class Node {
        val neighbours = TreeSet<String>()
        val peers = MutableStateFlow<List<Peer>>(emptyList())
        val receivers = CopyOnWriteArrayList<(ReceivedFrame) -> Unit>()
    }

    internal data class LinkKey(val a: String, val b: String) {
        companion object {
            fun of(first: String, second: String): LinkKey =
                if (first < second) LinkKey(first, second) else LinkKey(second, first)
        }
    }

    companion object {
        const val DEFAULT_SEED: Long = 0x5EEDL
    }
}

/** A [Transport] backed by [FakeNetwork] instead of BLE hardware. */
class FakeTransport internal constructor(
    private val network: FakeNetwork,
    val id: String,
) : Transport {
    override suspend fun send(peer: Peer, bytes: ByteArray) {
        network.send(id, peer.id, bytes)
    }

    override fun onReceive(callback: (ReceivedFrame) -> Unit): AutoCloseable =
        network.addReceiver(id, callback)

    override fun peers(): Flow<List<Peer>> = network.peers(id)

    /** Convenience for simulator code; equivalent to `network.connect(this, other)`. */
    fun connectTo(other: FakeTransport, link: LinkConfig? = null) {
        network.connect(this, other, link)
    }

    fun disconnectFrom(other: FakeTransport) {
        network.disconnect(this, other)
    }

    override fun toString(): String = "FakeTransport($id)"
}
