package com.solar23040.bitaudio.sim

/** How the simulator wires [SimConfig.nodes] nodes before traffic starts. */
enum class Topology {
    /** A chain: node `i` is linked only to `i - 1` and `i + 1`. */
    LINE,

    /** A roughly square grid with four-neighbour links. */
    GRID,

    /**
     * Erdos-Renyi random links with probability [SimConfig.randomEdgeProbability].
     * A deterministic spanning chain is added so the graph is always connected.
     */
    RANDOM,
}

/** What a compromised node does with packets it is asked to relay. */
enum class MaliciousBehavior {
    /** Receives and delivers locally, but never forwards. */
    DROP,

    /** Forwards every packet [SimConfig.duplicateFactor] times. */
    DUPLICATE,
}

/**
 * One simulator run.
 *
 * Traffic is plain TTL flooding: the origin sends to every neighbour, each node
 * forwards the first copy it sees once (with jitter), and nodes drop anything
 * already in their seen cache. This is a reference implementation of the mesh
 * flooding rules, independent of the `:mesh` module, so metrics can be used to
 * tune TTL, jitter, and duplicate policy before integration.
 */
data class SimConfig(
    val name: String = "sim",
    val nodes: Int = 50,
    val topology: Topology = Topology.LINE,
    /** Probability that a single transmission is silently dropped. */
    val lossRate: Double = 0.10,
    /** Per-transmission one-way delay range, in milliseconds. */
    val latencyMs: LongRange = 10L..50L,
    /** Extra relay delay sampled per transmission, in milliseconds. */
    val jitterMs: LongRange = 0L..30L,
    /** Maximum number of edges a packet may traverse. */
    val ttl: Int = 6,
    /** Number of messages published during the run. */
    val messages: Int = 6,
    /** Opaque payload size; it only affects airtime in this simulator. */
    val payloadBytes: Int = 256,
    /** Number of random nodes to mark malicious when [maliciousIndices] is empty. */
    val maliciousNodeCount: Int = 0,
    /** Explicit malicious node indexes. Overrides [maliciousNodeCount]. */
    val maliciousIndices: List<Int> = emptyList(),
    val maliciousBehavior: MaliciousBehavior = MaliciousBehavior.DUPLICATE,
    /** Copies sent by a malicious node in [MaliciousBehavior.DUPLICATE] mode. */
    val duplicateFactor: Int = 2,
    /** Link probability for [Topology.RANDOM]. */
    val randomEdgeProbability: Double = 0.08,
    val seed: Long = 42L,
    /** Delay between successive message publications. */
    val publishStaggerMs: Long = 50L,
    /** Used to turn transmitted bytes into an airtime estimate. */
    val linkBytesPerSecond: Long = 20_000L,
    val idlePollMs: Long = 5L,
    /** Hard ceiling for one run; exceeding it fails the test instead of hanging. */
    val maxSimulationMs: Long = 120_000L,
) {
    init {
        require(name.isNotBlank()) { "name must not be blank" }
        require(nodes >= 2) { "nodes must be at least 2: $nodes" }
        require(lossRate in 0.0..1.0) { "lossRate must be in [0, 1]: $lossRate" }
        require(latencyMs.first >= 0 && latencyMs.first <= latencyMs.last) {
            "latencyMs must be a non-negative, non-empty range: $latencyMs"
        }
        require(jitterMs.first >= 0 && jitterMs.first <= jitterMs.last) {
            "jitterMs must be a non-negative, non-empty range: $jitterMs"
        }
        require(ttl >= 1) { "ttl must be at least 1: $ttl" }
        require(messages >= 1) { "messages must be at least 1: $messages" }
        require(payloadBytes >= 0) { "payloadBytes must not be negative: $payloadBytes" }
        require(maliciousNodeCount in 0 until nodes) {
            "maliciousNodeCount must be in [0, nodes): $maliciousNodeCount"
        }
        require(maliciousIndices.distinct().size == maliciousIndices.size) {
            "maliciousIndices must not contain duplicates"
        }
        require(maliciousIndices.all { it in 0 until nodes }) {
            "maliciousIndices must be valid node indexes: $maliciousIndices"
        }
        require(maliciousIndices.isEmpty() || maliciousIndices.size < nodes) {
            "at least one node must be able to publish"
        }
        require(duplicateFactor >= 1) { "duplicateFactor must be at least 1: $duplicateFactor" }
        require(randomEdgeProbability in 0.0..1.0) {
            "randomEdgeProbability must be in [0, 1]: $randomEdgeProbability"
        }
        require(publishStaggerMs >= 0) { "publishStaggerMs must not be negative" }
        require(linkBytesPerSecond > 0) { "linkBytesPerSecond must be positive" }
        require(idlePollMs > 0) { "idlePollMs must be positive" }
        require(maxSimulationMs > 0) { "maxSimulationMs must be positive" }
    }
}
