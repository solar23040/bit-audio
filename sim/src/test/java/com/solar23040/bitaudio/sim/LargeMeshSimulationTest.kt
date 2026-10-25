@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package com.solar23040.bitaudio.sim

import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.LinkConfig
import java.io.File
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CI guard: the default 50-100 node scenarios must finish inside a strict
 * timeout and produce a usable CSV report. Delays run on the test scheduler,
 * so the simulation uses virtual time and does not wait for wall-clock BLE
 * latency.
 */
class LargeMeshSimulationTest {
    @Test(timeout = 240_000)
    fun runsFiftyToHundredNodesWithinTimeLimitAndWritesCsv() = runTest(timeout = 180.seconds) {
        val results = SimulationScenarios.phase1().map { config ->
            val network = FakeNetwork(
                defaultLink = LinkConfig(config.lossRate, config.latencyMs),
                seed = config.seed,
                externalScope = backgroundScope,
            )
            MeshSimulator(config, network).run(backgroundScope) { testScheduler.currentTime }
        }

        assertEquals(SimulationScenarios.phase1().size, results.size)
        assertTrue(
            "suite must cover 50 and 100 node runs",
            results.any { it.config.nodes == 50 } && results.any { it.config.nodes == 100 },
        )
        results.forEach { result ->
            assertTrue(
                "${result.config.name}: no deliveries recorded",
                result.metrics.deliveredDeliveries > 0,
            )
            assertTrue(
                "${result.config.name}: no transmissions recorded",
                result.metrics.transmissions > 0,
            )
            assertTrue(
                "${result.config.name}: invalid delivery rate ${result.metrics.deliveryRate}",
                result.metrics.deliveryRate in 0.0..1.0,
            )
            assertTrue(
                "${result.config.name}: invalid duplicate ratio ${result.metrics.duplicateRatio}",
                result.metrics.duplicateRatio in 0.0..1.0,
            )
        }

        val directory = File("build/reports/sim")
        val files = SimulationReport(results).writeTo(directory)
        assertEquals(2, files.size)
        assertTrue(files.all { it.isFile && it.length() > 0 })

        println("Simulator CSV written to ${directory.absolutePath}")
        results.forEach { result ->
            val metrics = result.metrics
            println(
                "${result.config.name}: nodes=${result.config.nodes} " +
                    "delivery=${"%.3f".format(metrics.deliveryRate)} " +
                    "avgHops=${"%.2f".format(metrics.averageHops)} " +
                    "avgLatencyMs=${"%.1f".format(metrics.averageLatencyMs)} " +
                    "duplicates=${"%.3f".format(metrics.duplicateRatio)} " +
                    "airtimeBytes=${metrics.airtimeBytes}",
            )
        }
    }
}
