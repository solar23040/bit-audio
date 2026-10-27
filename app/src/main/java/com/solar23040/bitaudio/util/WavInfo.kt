package com.solar23040.bitaudio.util

/**
 * Minimal WAV reader for clips recorded by the app shell.
 *
 * Incoming nearby payloads are Opus blobs (see [AudioPayload]); this reader only
 * handles local/legacy RIFF/WAVE files. Invalid or unknown payloads fall back to
 * `0 ms` and an empty peak list instead of throwing.
 */
object WavInfo {

    data class Info(val durationMs: Long, val peaks: List<Float>)

    fun inspect(bytes: ByteArray): Info {
        val dataOffset = findDataChunk(bytes) ?: return Info(0, emptyList())
        val sampleRate = findSampleRate(bytes) ?: DEFAULT_SAMPLE_RATE
        val dataSize = dataOffset.second
        val duration = if (sampleRate > 0) {
            dataSize.toLong() * 1_000L / (sampleRate.toLong() * BYTES_PER_SAMPLE)
        } else {
            0L
        }
        val peaks = peaksOf(
            bytes = bytes,
            start = dataOffset.first,
            length = dataSize,
            readLength = bytes.size - dataOffset.first,
        )
        return Info(duration, peaks)
    }

    private fun findDataChunk(bytes: ByteArray): Pair<Int, Int>? {
        if (bytes.size < 12) return null
        if (!chunkId(bytes, 0).contentEquals(RIFF) || !chunkId(bytes, 8).contentEquals(WAVE)) {
            return null
        }
        var offset = 12
        while (offset + 8 <= bytes.size) {
            val id = chunkId(bytes, offset)
            val size = readIntLe(bytes, offset + 4).coerceAtLeast(0)
            val payload = offset + 8
            if (id.contentEquals(DATA)) {
                val available = (bytes.size - payload).coerceAtLeast(0)
                return payload to minOf(size, available)
            }
            val next = payload + size + (size and 1)
            if (next <= offset || next > bytes.size) return null
            offset = next
        }
        return null
    }

    private fun findSampleRate(bytes: ByteArray): Int? {
        if (bytes.size < 12) return null
        var offset = 12
        while (offset + 8 <= bytes.size) {
            val id = chunkId(bytes, offset)
            val size = readIntLe(bytes, offset + 4).coerceAtLeast(0)
            val payload = offset + 8
            if (id.contentEquals(FMT) && size >= 8 && payload + 8 <= bytes.size) {
                return readIntLe(bytes, payload + 4).takeIf { it > 0 }
            }
            val next = payload + size + (size and 1)
            if (next <= offset || next > bytes.size) return null
            offset = next
        }
        return null
    }

    private fun peaksOf(bytes: ByteArray, start: Int, length: Int, readLength: Int): List<Float> {
        val available = minOf(length, readLength).coerceAtLeast(0) / BYTES_PER_SAMPLE
        if (available <= 0) return emptyList()

        val bucket = (available.toDouble() / PEAK_BARS).coerceAtLeast(1.0)
        val peaks = ArrayList<Float>(PEAK_BARS)
        for (bar in 0 until PEAK_BARS) {
            val begin = (bar * bucket).toInt().coerceIn(0, available - 1)
            val end = ((bar + 1) * bucket).toInt().coerceIn(begin + 1, available)
            var max = 0
            for (index in begin until end) {
                val position = start + index * BYTES_PER_SAMPLE
                if (position + 1 >= bytes.size) break
                val sample = ((bytes[position + 1].toInt() shl 8) or
                    (bytes[position].toInt() and 0xFF)).toShort().toInt()
                val magnitude = if (sample == Short.MIN_VALUE.toInt()) 32768 else kotlin.math.abs(sample)
                if (magnitude > max) max = magnitude
            }
            peaks += (max / 32768f).coerceIn(0.06f, 1f)
        }
        return peaks
    }

    private fun chunkId(bytes: ByteArray, offset: Int): ByteArray =
        bytes.copyOfRange(offset, minOf(offset + 4, bytes.size))

    private fun readIntLe(bytes: ByteArray, offset: Int): Int {
        if (offset + 4 > bytes.size) return 0
        return (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)
    }

    private val RIFF = "RIFF".toByteArray(Charsets.US_ASCII)
    private val WAVE = "WAVE".toByteArray(Charsets.US_ASCII)
    private val DATA = "data".toByteArray(Charsets.US_ASCII)
    private val FMT = "fmt ".toByteArray(Charsets.US_ASCII)

    private const val BYTES_PER_SAMPLE = 2
    private const val DEFAULT_SAMPLE_RATE = 16_000
    private const val PEAK_BARS = 48
}
