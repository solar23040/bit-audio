package com.solar23040.bitaudio.mesh

/** Token-bucket limit: [burst] packets may arrive back to back, then [perSecond]. */
data class RateLimit(
    val perSecond: Double,
    val burst: Double,
) {
    init {
        require(perSecond > 0.0) { "perSecond must be > 0" }
        require(burst >= 1.0) { "burst must be >= 1" }
    }
}

/**
 * Local policy for [MeshEngine]. Packet-format limits (512-byte frames, 256
 * chunks) are fixed by the wire contract and are not configurable here.
 */
data class MeshConfig(
    /** TTL stamped on locally published packets. Receivers accept only 1..8. */
    val defaultTtl: Int = 5,
    /** How long replay/dedup state and reassembly results are retained. */
    val retentionMs: Long = 24L * 60 * 60 * 1000,
    /** Packets older than this are delivered locally but never rebroadcast. */
    val staleAfterMs: Long = 120_000,
    /** Reject packets whose timestamp is further than this into the future. */
    val maxClockSkewMs: Long = 120_000,
    /** Give up on a partially reassembled message after this long. */
    val reassemblyTimeoutMs: Long = 120_000,
    /** Random delay before forwarding a valid packet. */
    val jitterMs: LongRange = 20L..200L,
    /** Reassembled plaintext limit for one message. */
    val maxPlaintextBytes: Int = 64 * 1024,
    /** Verified packets accepted per resolved sender identity. */
    val perSenderRate: RateLimit = RateLimit(perSecond = 200.0, burst = 400.0),
    /** Frames accepted per directly connected neighbour, before any crypto. */
    val perNeighbourRate: RateLimit = RateLimit(perSecond = 1000.0, burst = 2000.0),
    /** Bound on the seen-packet cache. */
    val maxSeenPackets: Int = 20_000,
    /** Bound on simultaneously reassembled messages. */
    val maxPartialMessages: Int = 256,
) {
    init {
        require(defaultTtl in 1..8) { "defaultTtl must be in 1..8" }
        require(retentionMs > 0) { "retentionMs must be > 0" }
        require(staleAfterMs > 0) { "staleAfterMs must be > 0" }
        require(maxClockSkewMs >= 0) { "maxClockSkewMs must be >= 0" }
        require(reassemblyTimeoutMs > 0) { "reassemblyTimeoutMs must be > 0" }
        require(jitterMs.first >= 0 && jitterMs.first <= jitterMs.last) {
            "jitterMs must be a non-negative, non-empty range: $jitterMs"
        }
        require(jitterMs.last - jitterMs.first < Int.MAX_VALUE) { "jitterMs is too large" }
        require(maxPlaintextBytes in 1..MAX_PLAINTEXT_BYTES) {
            "maxPlaintextBytes must be in 1..$MAX_PLAINTEXT_BYTES"
        }
        require(maxSeenPackets >= 1) { "maxSeenPackets must be >= 1" }
        require(maxPartialMessages >= 1) { "maxPartialMessages must be >= 1" }
    }

    companion object {
        /** Also the reassembly contract limit. */
        const val MAX_PLAINTEXT_BYTES: Int = 64 * 1024
    }
}
