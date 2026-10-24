package com.meshvoice.audio

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * An encoded voice note: an ordered list of one-frame Opus packets plus the original PCM length.
 *
 * Use [toPayload] when handing the clip to the mesh layer. The payload is self-delimiting, so
 * Agent C can fragment it into any chunk size and Agent D can route it as one opaque blob.
 */
class EncodedAudioClip(
    frames: List<ByteArray>,
    val sampleCount: Int,
) {
    val frames: List<ByteArray> = frames.map { it.copyOf() }

    init {
        require(sampleCount in 1..AudioConfig.MAX_CLIP_SAMPLES) {
            "sampleCount out of range: $sampleCount"
        }
        val expectedFrames =
            (sampleCount + AudioConfig.FRAME_SAMPLES - 1) / AudioConfig.FRAME_SAMPLES
        require(this.frames.size == expectedFrames) {
            "Expected $expectedFrames frames for $sampleCount samples, got ${this.frames.size}"
        }
        require(
            this.frames.all {
                it.isNotEmpty() && it.size <= AudioConfig.MAX_OPUS_PACKET_BYTES
            }
        ) { "One or more Opus frames have an invalid size" }
    }

    val frameCount: Int get() = frames.size

    val durationMs: Int
        get() = (sampleCount.toLong() * 1_000 / AudioConfig.SAMPLE_RATE_HZ).toInt()

    val encodedByteCount: Int get() = frames.sumOf { it.size }

    fun toPayload(): ByteArray {
        val payloadSize = HEADER_BYTES + frames.sumOf { 2 + it.size }
        val buffer = ByteBuffer.allocate(payloadSize).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put(PAYLOAD_VERSION.toByte())
        buffer.put(CODEC_OPUS_16K_MONO_20MS.toByte())
        buffer.putShort(frames.size.toShort())
        buffer.putInt(sampleCount)
        for (frame in frames) {
            buffer.putShort(frame.size.toShort())
            buffer.put(frame)
        }
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncodedAudioClip) return false
        if (sampleCount != other.sampleCount || frames.size != other.frames.size) return false
        return frames.indices.all { frames[it].contentEquals(other.frames[it]) }
    }

    override fun hashCode(): Int {
        var result = sampleCount
        for (frame in frames) {
            result = 31 * result + frame.contentHashCode()
        }
        return result
    }

    companion object {
        const val PAYLOAD_VERSION = 1
        const val CODEC_OPUS_16K_MONO_20MS = 1

        private const val HEADER_BYTES = 8

        fun fromPayload(payload: ByteArray): EncodedAudioClip {
            require(payload.size >= HEADER_BYTES) {
                "Audio payload is too short: ${payload.size} bytes"
            }
            val buffer = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN)

            val version = buffer.get().toInt() and 0xFF
            require(version == PAYLOAD_VERSION) { "Unsupported audio payload version: $version" }

            val codec = buffer.get().toInt() and 0xFF
            require(codec == CODEC_OPUS_16K_MONO_20MS) {
                "Unsupported audio codec: $codec"
            }

            val frameCount = buffer.getShort().toInt() and 0xFFFF
            val sampleCount = buffer.getInt()
            require(frameCount in 1..AudioConfig.MAX_FRAMES) {
                "Frame count out of range: $frameCount"
            }
            require(sampleCount in 1..AudioConfig.MAX_CLIP_SAMPLES) {
                "Sample count out of range: $sampleCount"
            }
            val expectedFrames =
                (sampleCount + AudioConfig.FRAME_SAMPLES - 1) / AudioConfig.FRAME_SAMPLES
            require(frameCount == expectedFrames) {
                "Frame count $frameCount does not match $sampleCount samples"
            }

            val frames = ArrayList<ByteArray>(frameCount)
            repeat(frameCount) {
                require(buffer.remaining() >= 2) { "Truncated frame length" }
                val length = buffer.getShort().toInt() and 0xFFFF
                require(length in 1..AudioConfig.MAX_OPUS_PACKET_BYTES) {
                    "Invalid frame length: $length"
                }
                require(buffer.remaining() >= length) { "Truncated frame payload" }
                val frame = ByteArray(length)
                buffer.get(frame)
                frames += frame
            }
            require(!buffer.hasRemaining()) { "Unexpected trailing bytes in audio payload" }

            return EncodedAudioClip(frames, sampleCount)
        }
    }
}
