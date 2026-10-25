@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package com.solar23040.bitaudio.sim

import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.LinkConfig
import java.nio.file.Files
import java.util.Locale
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MeshSimulatorTest {
    @Test
    fun reliableLineDeliversEveryMessageAndMeasuresHops() = runTest {
        val config = SimConfig(
            name = "line-5-reliable",
            nodes = 5,
            topology = Topology.LINE,
            lossRate = 0.0,
            latencyMs = 0L..0L,
            jitterMs = 0L..0L,
            ttl = 8,
            messages = 5,
            payloadBytes = 64,
            seed = 11L,
            publishStaggerMs = 0L,
        )

        val result = runSim(config)

        assertEquals(20, result.metrics.expectedDeliveries)
        assertEquals(20, result.metrics.deliveredDeliveries)
        assertEquals(1.0, result.metrics.deliveryRate, 1e-9)
        assertEquals(2.0, result.metrics.averageHops, 1e-9)
        assertEquals(4, result.metrics.maxHops)

        // Five nodes have sum(degree) = 8 transmissions per message; every edge
        // is also traversed in reverse, which is the duplicate reception.
        assertEquals(40L, result.metrics.transmissions)
        assertEquals(20L, result.metrics.duplicateReceptions)
        assertEquals(0.5, result.metrics.duplicateRatio, 1e-9)
        assertEquals(40L * (SimPacket.HEADER_BYTES + 64), result.metrics.airtimeBytes)
        assertEquals(0.0, result.metrics.averageLatencyMs, 0.0)
        assertTrue(result.metrics.durationMs >= 0L)
    }

    @Test
    fun lossyLineDropsSomeDeliveries() = runTest {
        val config = SimConfig(
            name = "line-20-lossy",
            nodes = 20,
            topology = Topology.LINE,
            lossRate = 0.4,
            latencyMs = 0L..0L,
            jitterMs = 0L..0L,
            ttl = 25,
            messages = 4,
            payloadBytes = 64,
            seed = 5L,
            publishStaggerMs = 0L,
        )

        val result = runSim(config)

        assertTrue("expected at least one delivery", result.metrics.deliveryRate > 0.0)
        assertTrue("expected loss to break the chain", result.metrics.deliveryRate < 1.0)
        assertTrue("transmissions should exceed unique deliveries", result.metrics.transmissions > result.metrics.deliveredDeliveries)
    }

    @Test
    fun maliciousDropNodePartitionsTraffic() = runTest {
        val baseline = SimConfig(
            name = "line-5-honest",
            nodes = 5,
            topology = Topology.LINE,
            lossRate = 0.0,
            latencyMs = 0L..0L,
            jitterMs = 0L..0L,
            ttl = 8,
            messages = 4,
            payloadBytes = 64,
            seed = 21L,
            publishStaggerMs = 0L,
        )
        val partitioned = baseline.copy(
            name = "line-5-drop",
            maliciousIndices = listOf(2),
            maliciousBehavior = MaliciousBehavior.DROP,
        )

        val honest = runSim(baseline)
        val dropped = runSim(partitioned)

        assertEquals(1.0, honest.metrics.deliveryRate, 1e-9)
        // Origins avoid the malicious node, so each side delivers only its own
        // nodes plus the silent relay itself: 2 of 4 destinations per message.
        assertEquals(0.5, dropped.metrics.deliveryRate, 1e-9)
        assertEquals(listOf(2), dropped.maliciousNodes.toList())
    }

    @Test
    fun maliciousDuplicateNodeInflatesDuplicatesAndAirtime() = runTest {
        val baseline = SimConfig(
            name = "line-7-honest",
            nodes = 7,
            topology = Topology.LINE,
            lossRate = 0.0,
            latencyMs = 0L..0L,
            jitterMs = 0L..0L,
            ttl = 12,
            messages = 6,
            payloadBytes = 64,
            seed = 33L,
            publishStaggerMs = 0L,
        )
        val duplicating = baseline.copy(
            name = "line-7-dup",
            maliciousIndices = listOf(3),
            maliciousBehavior = MaliciousBehavior.DUPLICATE,
            duplicateFactor = 4,
        )

        val honest = runSim(baseline)
        val duplicate = runSim(duplicating)

        assertEquals(1.0, honest.metrics.deliveryRate, 1e-9)
        assertEquals(1.0, duplicate.metrics.deliveryRate, 1e-9)
        assertTrue(
            "malicious relay should create more duplicate receptions",
            duplicate.metrics.duplicateReceptions > honest.metrics.duplicateReceptions,
        )
        assertTrue(
            "malicious relay should increase duplicate ratio",
            duplicate.metrics.duplicateRatio > honest.metrics.duplicateRatio,
        )
        assertTrue(
            "malicious relay should burn more airtime",
            duplicate.metrics.airtimeBytes > honest.metrics.airtimeBytes,
        )
    }

    @Test
    fun csvContainsSummaryAndPerMessageRows() = runTest {
        val config = SimConfig(
            name = "csv-check",
            nodes = 6,
            topology = Topology.GRID,
            lossRate = 0.0,
            latencyMs = 0L..0L,
            jitterMs = 0L..0L,
            ttl = 10,
            messages = 3,
            payloadBytes = 32,
            seed = 4L,
            publishStaggerMs = 0L,
        )
        val result = runSim(config)

        val summaryLines = result.toSummaryCsv().trim().lines()
        assertEquals(2, summaryLines.size)
        assertEquals(SimCsv.SUMMARY_HEADER, summaryLines[0])
        val header = summaryLines[0].split(',')
        val row = summaryLines[1].split(',')
        assertEquals("csv-check", row[0])
        assertEquals("6", row[header.indexOf("nodes")])
        assertEquals("grid", row[header.indexOf("topology")])
        assertEquals(
            String.format(Locale.ROOT, "%.6f", result.metrics.deliveryRate),
            row[header.indexOf("delivery_rate")],
        )
        assertEquals(
            result.metrics.airtimeBytes.toString(),
            row[header.indexOf("airtime_bytes")],
        )

        val messageLines = result.toMessageCsv().trim().lines()
        assertEquals(1 + result.messages.size, messageLines.size)
        assertEquals(SimCsv.MESSAGE_HEADER, messageLines[0])
        result.messages.forEachIndexed { index, message ->
            val cells = messageLines[index + 1].split(',')
            assertEquals(message.messageId.toString(), cells[1])
            assertEquals(message.origin.toString(), cells[2])
        }

        val directory = Files.createTempDirectory("mesh-sim-csv").toFile()
        try {
            val files = SimulationReport(listOf(result)).writeTo(directory)
            assertEquals(2, files.size)
            assertTrue(files[0].isFile && files[0].length() > 0)
            assertTrue(files[1].isFile && files[1].length() > 0)
            assertTrue(files[0].readText().startsWith(SimCsv.SUMMARY_HEADER))
            assertTrue(files[1].readText().startsWith(SimCsv.MESSAGE_HEADER))
        } finally {
            directory.deleteRecursively()
        }
    }

    private suspend fun TestScope.runSim(config: SimConfig): SimResult {
        val network = FakeNetwork(
            defaultLink = LinkConfig(config.lossRate, config.latencyMs),
            seed = config.seed,
            externalScope = backgroundScope,
        )
        return MeshSimulator(config, network).run(backgroundScope) { testScheduler.currentTime }
    }
}
