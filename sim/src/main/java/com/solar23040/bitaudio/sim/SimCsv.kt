package com.solar23040.bitaudio.sim

/** Result of a single simulated scenario. */
data class SimResult(
    val config: SimConfig,
    val graph: TopologyGraph,
    val origins: List<Int>,
    val maliciousNodes: Set<Int>,
    val metrics: SimMetrics,
    val messages: List<MessageMetrics>,
    val nodeMetrics: List<NodeMetrics>,
) {
    fun toSummaryCsv(): String = SimCsv.summaryCsv(listOf(this))

    fun toMessageCsv(): String = SimCsv.messageCsv(listOf(this))
}

/** CSV rendering. Every floating-point value uses `Locale.ROOT` and 6 decimals. */
object SimCsv {
    val SUMMARY_HEADER: String = listOf(
        "scenario",
        "nodes",
        "topology",
        "edges",
        "loss_rate",
        "latency_min_ms",
        "latency_max_ms",
        "jitter_min_ms",
        "jitter_max_ms",
        "messages",
        "ttl",
        "malicious_nodes",
        "malicious_behavior",
        "transmissions",
        "receptions",
        "duplicates",
        "delivered",
        "expected",
        "delivery_rate",
        "avg_hops",
        "max_hops",
        "avg_latency_ms",
        "p95_latency_ms",
        "duplicate_ratio",
        "airtime_bytes",
        "airtime_ms",
        "duration_ms",
    ).joinToString(",")

    const val MESSAGE_HEADER: String =
        "scenario,message_id,origin,delivered,expected,delivery_rate,avg_hops,max_hops," +
            "avg_latency_ms,duplicates,transmissions,airtime_bytes"

    fun summaryCsv(results: List<SimResult>): String = buildString {
        append(SUMMARY_HEADER).append('\n')
        results.forEach { result -> append(summaryRow(result)).append('\n') }
    }

    fun messageCsv(results: List<SimResult>): String = buildString {
        append(MESSAGE_HEADER).append('\n')
        results.forEach { result ->
            result.messages.forEach { message ->
                append(messageRow(result.config, message)).append('\n')
            }
        }
    }

    fun summaryRow(result: SimResult): String {
        val config = result.config
        val metrics = result.metrics
        return csv(
            csvName(config.name),
            config.nodes,
            config.topology.name.lowercase(),
            result.graph.edgeCount,
            decimal(config.lossRate),
            config.latencyMs.first,
            config.latencyMs.last,
            config.jitterMs.first,
            config.jitterMs.last,
            config.messages,
            config.ttl,
            result.maliciousNodes.size,
            config.maliciousBehavior.name.lowercase(),
            metrics.transmissions,
            metrics.receptions,
            metrics.duplicateReceptions,
            metrics.deliveredDeliveries,
            metrics.expectedDeliveries,
            decimal(metrics.deliveryRate),
            decimal(metrics.averageHops),
            metrics.maxHops,
            decimal(metrics.averageLatencyMs),
            metrics.p95LatencyMs,
            decimal(metrics.duplicateRatio),
            metrics.airtimeBytes,
            decimal(metrics.airtimeMs),
            metrics.durationMs,
        )
    }

    fun messageRow(config: SimConfig, message: MessageMetrics): String = csv(
        csvName(config.name),
        message.messageId,
        message.origin,
        message.deliveredCount,
        message.expectedDeliveries,
        decimal(message.deliveryRate),
        decimal(message.averageHops),
        message.maxHops,
        decimal(message.averageLatencyMs),
        message.duplicateReceptions,
        message.transmissions,
        message.airtimeBytes,
    )

    private fun csv(vararg values: Any): String = values.joinToString(",")

    private fun decimal(value: Double): String = String.format(java.util.Locale.ROOT, "%.6f", value)

    private fun csvName(value: String): String =
        value.replace(',', '_').replace('\n', ' ').replace('\r', ' ').trim()
}
