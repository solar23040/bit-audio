package com.meshvoice.audio

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal RIFF/WAVE PCM16 reader and writer. Used by tests and useful for debug clip export.
 * Only uncompressed PCM16 mono/stereo is supported.
 */
object WavFile {

    data class PcmAudio(
        val sampleRate: Int,
        val channels: Int,
        val samples: ShortArray,
    ) {
        init {
            require(sampleRate > 0) { "sampleRate must be positive" }
            require(channels in 1..2) { "Only mono and stereo are supported" }
            require(samples.size % channels == 0) {
                "Sample count is not a multiple of the channel count"
            }
        }

        val frameCount: Int get() = samples.size / channels

        val durationMs: Int
            get() = (frameCount.toLong() * 1_000 / sampleRate).toInt()
    }

    fun read(bytes: ByteArray): PcmAudio {
        require(bytes.size >= RIFF_HEADER_BYTES) { "File is too short to be a WAV file" }
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        require(buffer.readFourCc() == "RIFF") { "Missing RIFF header" }
        buffer.int // RIFF size; chunk sizes are authoritative.
        require(buffer.readFourCc() == "WAVE") { "Missing WAVE signature" }

        var formatChannels = 0
        var formatSampleRate = 0
        var formatBits = 0
        var formatCode = 0
        var dataOffset = -1
        var dataSize = -1

        while (buffer.remaining() >= 8) {
            val chunkId = buffer.readFourCc()
            val chunkSize = buffer.int.toLong() and 0xFFFF_FFFFL
            val chunkStart = buffer.position()
            val chunkEnd = chunkStart + chunkSize
            require(chunkEnd <= buffer.limit()) { "Chunk $chunkId extends past end of file" }

            when (chunkId) {
                "fmt " -> {
                    require(chunkSize >= 16) { "fmt chunk is too short" }
                    formatCode = buffer.short.toInt() and 0xFFFF
                    formatChannels = buffer.short.toInt() and 0xFFFF
                    formatSampleRate = buffer.int
                    buffer.int // byte rate
                    buffer.short // block align
                    formatBits = buffer.short.toInt() and 0xFFFF
                }

                "data" -> {
                    dataOffset = chunkStart
                    dataSize = chunkSize.toInt()
                }
            }

            val paddedEnd = chunkEnd + (chunkSize and 1L)
            buffer.position(paddedEnd.coerceAtMost(buffer.limit().toLong()).toInt())
        }

        require(formatCode == WAVE_FORMAT_PCM) {
            "Unsupported WAV format code: $formatCode (only PCM is supported)"
        }
        require(formatBits == 16) { "Unsupported WAV bit depth: $formatBits (only PCM16 is supported)" }
        require(formatChannels in 1..2) { "Unsupported channel count: $formatChannels" }
        require(formatSampleRate > 0) { "Invalid sample rate: $formatSampleRate" }
        require(dataOffset >= 0 && dataSize >= 0) { "WAV file has no data chunk" }

        val bytesPerFrame = formatChannels * 2
        require(dataSize % bytesPerFrame == 0) { "Data chunk is not frame aligned" }

        val sampleCount = dataSize / 2
        val samples = ShortArray(sampleCount)
        buffer.position(dataOffset)
        buffer.asShortBuffer().get(samples)

        return PcmAudio(formatSampleRate, formatChannels, samples)
    }

    fun write(audio: PcmAudio): ByteArray {
        val dataSize = audio.samples.size * 2
        val fileSize = RIFF_HEADER_BYTES + dataSize
        val buffer = ByteBuffer.allocate(fileSize).order(ByteOrder.LITTLE_ENDIAN)

        buffer.putFourCc("RIFF")
        buffer.putInt(36 + dataSize)
        buffer.putFourCc("WAVE")
        buffer.putFourCc("fmt ")
        buffer.putInt(16)
        buffer.putShort(WAVE_FORMAT_PCM.toShort())
        buffer.putShort(audio.channels.toShort())
        buffer.putInt(audio.sampleRate)
        buffer.putInt(audio.sampleRate * audio.channels * 2)
        buffer.putShort((audio.channels * 2).toShort())
        buffer.putShort(16)
        buffer.putFourCc("data")
        buffer.putInt(dataSize)
        for (sample in audio.samples) {
            buffer.putShort(sample)
        }
        return buffer.array()
    }

    private fun ByteBuffer.readFourCc(): String {
        val fourCc = ByteArray(4)
        get(fourCc)
        return String(fourCc, Charsets.US_ASCII)
    }

    private fun ByteBuffer.putFourCc(value: String) {
        put(value.toByteArray(Charsets.US_ASCII))
    }

    private const val RIFF_HEADER_BYTES = 44
    private const val WAVE_FORMAT_PCM = 1
}
