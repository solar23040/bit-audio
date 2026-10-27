package com.solar23040.bitaudio.util

import com.meshvoice.audio.EncodedAudioClip
import com.meshvoice.audio.OpusClipCodec
import kotlin.math.abs

/**
 * Reads duration and waveform peaks from a clip payload.
 *
 * Nearby clips are Opus payloads from `:audio`; older/local clips are complete
 * RIFF/WAVE files. Anything else is rejected instead of being written to disk.
 */
object AudioPayload {

    data class Info(val durationMs: Long, val peaks: List<Float>)

    fun inspect(bytes: ByteArray): Info? {
        if (isWav(bytes)) {
            val info = WavInfo.inspect(bytes)
            if (info.durationMs <= 0L) return null
            return Info(info.durationMs, info.peaks)
        }

        val clip = runCatching { EncodedAudioClip.fromPayload(bytes) }.getOrNull() ?: return null
        val peaks = runCatching { peaksOf(OpusClipCodec().decode(clip)) }.getOrDefault(emptyList())
        return Info(clip.durationMs.toLong(), peaks)
    }

    fun isWav(bytes: ByteArray): Boolean =
        bytes.size >= 12 &&
            bytes[0] == 'R'.code.toByte() &&
            bytes[1] == 'I'.code.toByte() &&
            bytes[2] == 'F'.code.toByte() &&
            bytes[3] == 'F'.code.toByte()

    private fun peaksOf(pcm: ShortArray, bars: Int = 48): List<Float> {
        if (pcm.isEmpty()) return emptyList()
        val bucket = (pcm.size.toDouble() / bars).coerceAtLeast(1.0)
        return List(bars) { bar ->
            val start = (bar * bucket).toInt().coerceIn(0, pcm.lastIndex)
            val end = ((bar + 1) * bucket).toInt().coerceIn(start + 1, pcm.size)
            var peak = 0
            for (index in start until end) {
                val magnitude = abs(pcm[index].toInt())
                if (magnitude > peak) peak = magnitude
            }
            (peak / 32768f).coerceIn(0.06f, 1f)
        }
    }
}
