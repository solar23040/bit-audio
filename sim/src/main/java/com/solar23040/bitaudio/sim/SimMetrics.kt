package com.solar23040.bitaudio.sim

/** Metrics for one published message. */
data class MessageMetrics(
    val messageId: Int,
    val origin: Int,
    val expectedDeliveries: Int,
    val deliveredNodes: Set<Int>,
    val hops: List<Int>,
    val latenciesMs: List<Long>,
    val duplicateReceptions: Long,
    val transmissions: Long,
    val airtimeBytes: Long,
) {
    val deliveredCount: Int get() = deliveredNodes.size

    val deliveryRate: Double
        get() = if (expectedDeliveries <= 0) 0.0 else deliveredCount.toDouble() / expectedDeliveries

    val averageHops: Double get() = averageInts(hops)
    val maxHops: Int get() = hops.maxOrNull() ?: 0
    val averageLatencyMs: Double get() = averageLongs(latenciesMs)

    /** Receptions of this message, including copies dropped by the dedup cache. */
    val receptions: Long get() = deliveredCount.toLong() + duplicateReceptions
}

/** Aggregate metrics for a whole run. */
data class SimMetrics(
    val messages: Int,
    val expectedDeliveries: Int,
    val deliveredDeliveries: Int,
    val deliveryRate: Double,
    val transmissions: Long,
    val receptions: Long,
    val duplicateReceptions: Long,
    val duplicateRatio: Double,
    val averageHops: Double,
    val maxHops: Int,
    val averageLatencyMs: Double,
    val p95LatencyMs: Long,
    val airtimeBytes: Long,
    val airtimeMs: Double,
    val durationMs: Long,
)

/** Per-node traffic, useful for spotting hot relays or misbehaving nodes. */
data class NodeMetrics(
    val node: Int,
    val malicious: Boolean,
    val transmissions: Long,
    val receptions: Long,
    val duplicateReceptions: Long,
    val deliveredMessages: Int,
    val airtimeBytes: Long,
)

/** Pure aggregation so the formulas can be tested without running a network. */
object MetricsCalculator {
    fun summarize(
        messages: List<MessageMetrics>,
        durationMs: Long,
        linkBytesPerSecond: Long,
    ): SimMetrics {
        require(durationMs >= 0) { "durationMs must not be negative: $durationMs" }
        require(linkBytesPerSecond > 0) { "linkBytesPerSecond must be positive" }

        val expected = messages.sumOf { it.expectedDeliveries }
        val delivered = messages.sumOf { it.deliveredCount }
        val transmissions = messages.sumOf { it.transmissions }
        val duplicates = messages.sumOf { it.duplicateReceptions }
        val receptions = delivered.toLong() + duplicates
        val hops = messages.flatMap { it.hops }
        val latencies = messages.flatMap { it.latenciesMs }
        val airtimeBytes = messages.sumOf { it.airtimeBytes }

        return SimMetrics(
            messages = messages.size,
            expectedDeliveries = expected,
            deliveredDeliveries = delivered,
            deliveryRate = if (expected == 0) 0.0 else delivered.toDouble() / expected,
            transmissions = transmissions,
            receptions = receptions,
            duplicateReceptions = duplicates,
            duplicateRatio = if (receptions == 0L) 0.0 else duplicates.toDouble() / receptions,
            averageHops = averageInts(hops),
            maxHops = hops.maxOrNull() ?: 0,
            averageLatencyMs = averageLongs(latencies),
            p95LatencyMs = percentile(latencies, 0.95),
            airtimeBytes = airtimeBytes,
            airtimeMs = airtimeBytes.toDouble() / linkBytesPerSecond * 1000.0,
            durationMs = durationMs,
        )
    }

    /** Nearest-rank percentile; empty input returns 0. */
    fun percentile(values: List<Long>, fraction: Double): Long {
        if (values.isEmpty()) return 0L
        require(fraction in 0.0..1.0) { "fraction must be in [0, 1]: $fraction" }
        val sorted = values.sorted()
        val index = ((sorted.size - 1) * fraction).toInt().coerceIn(0, sorted.lastIndex)
        return sorted[index]
    }
}

private fun averageInts(values: List<Int>): Double =
    if (values.isEmpty()) 0.0 else values.sum().toDouble() / values.size

private fun averageLongs(values: List<Long>): Double {
    if (values.isEmpty()) return 0.0
    var total = 0L
    values.forEach { total += it }
    return total.toDouble() / values.size
}
