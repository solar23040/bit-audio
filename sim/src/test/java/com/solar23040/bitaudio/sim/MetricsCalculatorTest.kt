package com.solar23040.bitaudio.sim

import org.junit.Assert.assertEquals
import org.junit.Test

class MetricsCalculatorTest {
    @Test
    fun aggregatesDeliveryHopsLatencyDuplicatesAndAirtime() {
        val messages = listOf(
            MessageMetrics(
                messageId = 0,
                origin = 0,
                expectedDeliveries = 2,
                deliveredNodes = setOf(1),
                hops = listOf(1),
                latenciesMs = listOf(10L),
                duplicateReceptions = 2L,
                transmissions = 10L,
                airtimeBytes = 1_000L,
            ),
            MessageMetrics(
                messageId = 1,
                origin = 0,
                expectedDeliveries = 3,
                deliveredNodes = setOf(2, 3),
                hops = listOf(2, 4),
                latenciesMs = listOf(20L, 40L),
                duplicateReceptions = 0L,
                transmissions = 20L,
                airtimeBytes = 2_000L,
            ),
        )

        val metrics = MetricsCalculator.summarize(
            messages = messages,
            durationMs = 500L,
            linkBytesPerSecond = 1_000L,
        )

        assertEquals(2, metrics.messages)
        assertEquals(5, metrics.expectedDeliveries)
        assertEquals(3, metrics.deliveredDeliveries)
        assertEquals(0.6, metrics.deliveryRate, 1e-9)
        assertEquals(30L, metrics.transmissions)
        assertEquals(5L, metrics.receptions)
        assertEquals(2L, metrics.duplicateReceptions)
        assertEquals(0.4, metrics.duplicateRatio, 1e-9)
        assertEquals(7.0 / 3.0, metrics.averageHops, 1e-9)
        assertEquals(4, metrics.maxHops)
        assertEquals(70.0 / 3.0, metrics.averageLatencyMs, 1e-9)
        assertEquals(20L, metrics.p95LatencyMs)
        assertEquals(3_000L, metrics.airtimeBytes)
        assertEquals(3_000.0, metrics.airtimeMs, 1e-9)
        assertEquals(500L, metrics.durationMs)

        assertEquals(0.5, messages[0].deliveryRate, 1e-9)
        assertEquals(2.0 / 3.0, messages[1].deliveryRate, 1e-9)
        assertEquals(3L, messages[0].receptions)
    }

    @Test
    fun emptySamplesProduceZeroMetrics() {
        val metrics = MetricsCalculator.summarize(
            messages = emptyList(),
            durationMs = 0L,
            linkBytesPerSecond = 1_000L,
        )

        assertEquals(0, metrics.messages)
        assertEquals(0, metrics.expectedDeliveries)
        assertEquals(0, metrics.deliveredDeliveries)
        assertEquals(0.0, metrics.deliveryRate, 0.0)
        assertEquals(0L, metrics.transmissions)
        assertEquals(0L, metrics.receptions)
        assertEquals(0.0, metrics.duplicateRatio, 0.0)
        assertEquals(0.0, metrics.averageHops, 0.0)
        assertEquals(0, metrics.maxHops)
        assertEquals(0L, metrics.p95LatencyMs)
        assertEquals(0L, metrics.airtimeBytes)
        assertEquals(0.0, metrics.airtimeMs, 0.0)
    }

    @Test
    fun percentileHandlesEmptySingleAndBoundaries() {
        assertEquals(0L, MetricsCalculator.percentile(emptyList(), 0.95))
        assertEquals(7L, MetricsCalculator.percentile(listOf(7L), 0.95))
        assertEquals(10L, MetricsCalculator.percentile(listOf(10L, 20L, 30L), 0.0))
        assertEquals(30L, MetricsCalculator.percentile(listOf(10L, 20L, 30L), 1.0))
        assertEquals(20L, MetricsCalculator.percentile(listOf(30L, 10L, 20L), 0.5))
    }
}
