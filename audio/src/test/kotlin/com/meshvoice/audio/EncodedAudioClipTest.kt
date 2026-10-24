package com.meshvoice.audio

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class EncodedAudioClipTest {

    @Test
    fun payloadRoundTrips() {
        val clip = EncodedAudioClip(
            frames = listOf(ByteArray(10) { 1 }, ByteArray(12) { 2 }),
            sampleCount = 500,
        )
        val parsed = EncodedAudioClip.fromPayload(clip.toPayload())

        assertEquals(clip, parsed)
        assertEquals(500, parsed.sampleCount)
        assertEquals(2, parsed.frameCount)
        assertEquals(31, parsed.durationMs)
    }

    @Test
    fun rejectsUnsupportedPayloadVersion() {
        val payload = samplePayload()
        payload[0] = 2
        assertThrows(IllegalArgumentException::class.java) {
            EncodedAudioClip.fromPayload(payload)
        }
    }

    @Test
    fun rejectsTrailingBytes() {
        val payload = samplePayload() + byteArrayOf(0)
        assertThrows(IllegalArgumentException::class.java) {
            EncodedAudioClip.fromPayload(payload)
        }
    }

    @Test
    fun rejectsTruncatedFrame() {
        val payload = samplePayload()
        assertThrows(IllegalArgumentException::class.java) {
            EncodedAudioClip.fromPayload(payload.copyOf(payload.size - 1))
        }
    }

    @Test
    fun rejectsSampleCountThatDoesNotMatchFrameCount() {
        assertThrows(IllegalArgumentException::class.java) {
            EncodedAudioClip(listOf(ByteArray(3)), sampleCount = 500)
        }
    }

    @Test
    fun rejectsOversizedOpusFrame() {
        assertThrows(IllegalArgumentException::class.java) {
            EncodedAudioClip(
                listOf(ByteArray(AudioConfig.MAX_OPUS_PACKET_BYTES + 1)),
                sampleCount = 320,
            )
        }
    }

    @Test
    fun rejectsTooManyFramesInPayload() {
        val frameCount = AudioConfig.MAX_FRAMES + 1
        val buffer = ByteBuffer.allocate(9 + frameCount * 3).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put(EncodedAudioClip.PAYLOAD_VERSION.toByte())
        buffer.put(EncodedAudioClip.CODEC_OPUS_16K_MONO_20MS.toByte())
        buffer.putShort(frameCount.toShort())
        buffer.putInt(AudioConfig.MAX_CLIP_SAMPLES)
        repeat(frameCount) {
            buffer.putShort(1)
            buffer.put(0)
        }

        assertThrows(IllegalArgumentException::class.java) {
            EncodedAudioClip.fromPayload(buffer.array())
        }
    }

    @Test
    fun emptyClipIsRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            EncodedAudioClip(emptyList(), sampleCount = 0)
        }
    }

    private fun samplePayload(): ByteArray = EncodedAudioClip(
        frames = listOf(ByteArray(10) { 1 }, ByteArray(12) { 2 }),
        sampleCount = 500,
    ).toPayload()
}
