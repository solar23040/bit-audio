package com.solar23040.bitaudio.mesh

import com.solar23040.bitaudio.mesh.packet.MeshPacket
import kotlin.random.Random

/**
 * Tuning knobs for [FloodMesh]. Defaults follow `docs/packet-format.md`.
 *
 * [clock] is injectable so tests can advance time without sleeping; production
 * uses wall-clock milliseconds. [random] only drives rebroadcast jitter.
 */
data class MeshConfig(
    /** TTL applied to locally published packets. Must be inside 1..8. */
    val defaultTtl: Int = 5,
    /** Rebroadcast delay range, sampled per packet. */
    val jitterMs: LongRange = 20L..200L,
    /** How long sealed packets are kept for store-and-forward (default 24 h). */
    val retentionMs: Long = 24L * 60L * 60L * 1000L,
    /** Packets older than this are delivered locally but never re-flooded. */
    val staleAfterMs: Long = 120_000L,
    /** Reject timestamps further than this into the future (clock skew guard). */
    val maxFutureSkewMs: Long = 120_000L,
    /** Abandon incomplete messages after this long. */
    val reassemblyTimeoutMs: Long = 120_000L,
    /** Bound on simultaneously reassembled messages. */
    val maxPartialMessages: Int = 32,
    /** Maximum in-flight relay tasks; further packets are dropped, not queued. */
    val maxRelayQueue: Int = 64,
    /** Bound on the chunk dedup cache. */
    val maxSeenChunks: Int = 8_192,
    /** Chunk dedup entries expire with the reassembly window. */
    val seenExpiryMs: Long = 120_000L,
    /** Bound on the completed-message cache, kept for the retention window. */
    val maxCompletedMessages: Int = 2_048,
    val clock: () -> Long = { System.currentTimeMillis() },
    val random: Random = Random.Default,
) {
    init {
        require(defaultTtl in MeshPacket.MIN_TTL..MeshPacket.MAX_TTL) {
            "defaultTtl must be in ${MeshPacket.MIN_TTL}..${MeshPacket.MAX_TTL}: $defaultTtl"
        }
        require(jitterMs.first >= 0 && jitterMs.first <= jitterMs.last) {
            "jitterMs must be a non-negative, non-empty range: $jitterMs"
        }
        require(retentionMs > 0) { "retentionMs must be > 0" }
        require(staleAfterMs >= 0) { "staleAfterMs must be >= 0" }
        require(maxFutureSkewMs >= 0) { "maxFutureSkewMs must be >= 0" }
        require(reassemblyTimeoutMs > 0) { "reassemblyTimeoutMs must be > 0" }
        require(maxPartialMessages > 0) { "maxPartialMessages must be > 0" }
        require(maxRelayQueue > 0) { "maxRelayQueue must be > 0" }
        require(maxSeenChunks > 0) { "maxSeenChunks must be > 0" }
        require(seenExpiryMs > 0) { "seenExpiryMs must be > 0" }
        require(maxCompletedMessages > 0) { "maxCompletedMessages must be > 0" }
    }
}
