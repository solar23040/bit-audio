package com.solar23040.bitaudio.sim

import java.io.File
import java.io.IOException

/** A collection of runs rendered to the CSV files consumed by CI and Agent D. */
data class SimulationReport(val runs: List<SimResult>) {
    fun summaryCsv(): String = SimCsv.summaryCsv(runs)

    fun messagesCsv(): String = SimCsv.messageCsv(runs)

    /** Writes both CSV files and returns them in summary, messages order. */
    fun writeTo(directory: File): List<File> {
        if (!directory.exists() && !directory.mkdirs()) {
            throw IOException("Could not create report directory: ${directory.absolutePath}")
        }
        val summary = File(directory, "mesh-sim-summary.csv")
        val messages = File(directory, "mesh-sim-messages.csv")
        summary.writeText(summaryCsv())
        messages.writeText(messagesCsv())
        return listOf(summary, messages)
    }
}

/** Default scenarios: 50-100 nodes across topologies, loss, and malicious nodes. */
object SimulationScenarios {
    fun phase1(): List<SimConfig> = listOf(
        SimConfig(
            name = "line-50-loss10",
            nodes = 50,
            topology = Topology.LINE,
            lossRate = 0.10,
            messages = 6,
        ),
        SimConfig(
            name = "grid-50-loss10",
            nodes = 50,
            topology = Topology.GRID,
            lossRate = 0.10,
            messages = 6,
        ),
        SimConfig(
            name = "random-50-loss10",
            nodes = 50,
            topology = Topology.RANDOM,
            lossRate = 0.10,
            messages = 6,
        ),
        SimConfig(
            name = "grid-100-loss10",
            nodes = 100,
            topology = Topology.GRID,
            lossRate = 0.10,
            messages = 4,
        ),
        SimConfig(
            name = "random-100-loss15-drop5",
            nodes = 100,
            topology = Topology.RANDOM,
            lossRate = 0.15,
            messages = 4,
            maliciousNodeCount = 5,
            maliciousBehavior = MaliciousBehavior.DROP,
        ),
        SimConfig(
            name = "random-100-loss15-dup5",
            nodes = 100,
            topology = Topology.RANDOM,
            lossRate = 0.15,
            messages = 4,
            maliciousNodeCount = 5,
            maliciousBehavior = MaliciousBehavior.DUPLICATE,
            duplicateFactor = 2,
        ),
    )
}
