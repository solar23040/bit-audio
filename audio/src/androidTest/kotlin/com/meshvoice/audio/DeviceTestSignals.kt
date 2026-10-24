package com.meshvoice.audio

import java.util.Random
import kotlin.math.PI
import kotlin.math.sin
import kotlin.math.sqrt

/** Same deterministic signal as the JVM tests, duplicated because test source sets do not mix. */
internal object DeviceTestSignals {

    fun voiceLikePcm(durationMs: Int): ShortArray {
        val sampleRate = AudioConfig.SAMPLE_RATE_HZ
        val sampleCount = durationMs * sampleRate / 1_000
        val pcm = ShortArray(sampleCount)
        val random = Random(42L)
        var phase = 0.0

        for (index in 0 until sampleCount) {
            val time = index.toDouble() / sampleRate
            val syllablePosition = (time % 1.5) / 1.5
            val envelope = when {
                syllablePosition < 0.12 -> 0.0
                syllablePosition < 0.24 -> (syllablePosition - 0.12) / 0.12
                syllablePosition < 0.78 -> 1.0
                else -> 1.0 - (syllablePosition - 0.78) / 0.22
            }.coerceIn(0.0, 1.0)

            val f0 = 115.0 + 25.0 * sin(2 * PI * 0.7 * time) +
                8.0 * sin(2 * PI * 2.3 * time)
            phase += 2 * PI * f0 / sampleRate

            val voice = sin(phase) +
                0.45 * sin(2 * phase) +
                0.22 * sin(3 * phase) +
                0.10 * sin(4 * phase)
            val noise = (random.nextDouble() * 2.0 - 1.0) * 0.015
            val sample = (voice * 0.22 * envelope + noise) * Short.MAX_VALUE
            pcm[index] = sample.toInt()
                .coerceIn(Short.MIN_VALUE.toInt(), Short.MAX_VALUE.toInt())
                .toShort()
        }
        return pcm
    }

    fun bestCorrelation(reference: ShortArray, decoded: ShortArray, maxLag: Int): Double {
        require(reference.size == decoded.size) { "Signals must have the same length" }
        val window = minOf(8_000, reference.size)
        val start = (reference.size - window) / 2
        var best = -1.0

        for (lag in -maxLag..maxLag) {
            val from = maxOf(0, -lag - start)
            val to = minOf(window, decoded.size - lag - start)
            if (to <= from) continue

            var sumAB = 0.0
            var sumAA = 0.0
            var sumBB = 0.0
            for (offset in from until to) {
                val a = reference[start + offset].toDouble()
                val b = decoded[start + offset + lag].toDouble()
                sumAB += a * b
                sumAA += a * a
                sumBB += b * b
            }
            val denominator = sqrt(sumAA * sumBB)
            val correlation = if (denominator == 0.0) 0.0 else sumAB / denominator
            if (correlation > best) best = correlation
        }
        return best
    }
}
