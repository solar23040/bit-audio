package com.solar23040.bitaudio.pipeline

import kotlin.math.abs

/**
 * Downsamples PCM to [bars] normalised 0..1 peaks for the note list waveform.
 *
 * This is display data only: each bar is the loudest sample in its bucket, with
 * a small floor so silent bars stay visible.
 */
internal fun waveformPeaks(pcm: ShortArray, bars: Int = 48): List<Float> {
    if (pcm.isEmpty()) return List(bars) { 0.08f }
    require(bars > 0) { "bars must be positive" }

    val bucketSize = pcm.size.toDouble() / bars
    return List(bars) { bar ->
        val start = (bar * bucketSize).toInt().coerceIn(0, pcm.lastIndex)
        val end = (((bar + 1) * bucketSize).toInt()).coerceIn(start + 1, pcm.size)
        var peak = 0
        for (index in start until end) {
            val magnitude = abs(pcm[index].toInt())
            if (magnitude > peak) peak = magnitude
        }
        (peak / 32768f).coerceAtLeast(0.06f)
    }
}
