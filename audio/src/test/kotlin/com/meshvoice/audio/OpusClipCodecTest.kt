package com.meshvoice.audio

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class OpusClipCodecTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private fun realCodec() = OpusClipCodec {
        OpusAudioCodec(TestOpusEngine(), AudioConfig.BITRATE_BPS)
    }

    @Test
    fun tenSecondWavRoundTripsUnderTargetSize() {
        val pcm = TestSignals.voiceLikePcm(10_000)
        val wav = WavFile.write(WavFile.PcmAudio(AudioConfig.SAMPLE_RATE_HZ, 1, pcm))
        val file = tempFolder.newFile("sample.wav")
        file.writeBytes(wav)

        val loaded = WavFile.read(file.readBytes())
        assertEquals(AudioConfig.SAMPLE_RATE_HZ, loaded.sampleRate)
        assertEquals(1, loaded.channels)

        val clip = realCodec().encode(loaded.samples)
        val payload = clip.toPayload()

        assertTrue(
            "10 s payload should stay under the target: ${payload.size} bytes",
            payload.size < AudioConfig.TARGET_MAX_CLIP_BYTES,
        )
        assertEquals(500, clip.frameCount)
        assertEquals(10_000, clip.durationMs)

        val decoded = realCodec().decode(EncodedAudioClip.fromPayload(payload))
        assertEquals(loaded.samples.size, decoded.size)
        assertTrue("Decoded audio is silent", decoded.any { it.toInt() != 0 })

        val correlation = TestSignals.bestCorrelation(loaded.samples, decoded, maxLag = 400)
        assertTrue("Decoded audio is too different from the source: $correlation", correlation > 0.6)
    }

    @Test
    fun rejectsClipOverFifteenSecondHardCap() {
        val tooLong = ShortArray(AudioConfig.MAX_CLIP_SAMPLES + 1)
        assertThrows(IllegalArgumentException::class.java) {
            OpusClipCodec { OneByteCodec }.encode(tooLong)
        }
    }

    @Test
    fun acceptsExactlyFifteenSeconds() {
        val clip = OpusClipCodec { OneByteCodec }
            .encode(ShortArray(AudioConfig.MAX_CLIP_SAMPLES))
        assertEquals(AudioConfig.MAX_FRAMES, clip.frameCount)
        assertEquals(AudioConfig.MAX_CLIP_SAMPLES, clip.sampleCount)
    }

    @Test
    fun padsPartialFinalFrame() {
        val clip = OpusClipCodec { OneByteCodec }.encode(ShortArray(321) { 1 })
        assertEquals(2, clip.frameCount)
        assertEquals(321, clip.sampleCount)
    }

    @Test
    fun decodesExactlyTheOriginalSampleCount() {
        val pcm = TestSignals.voiceLikePcm(250)
        val clip = realCodec().encode(pcm)
        val decoded = realCodec().decode(clip)
        assertEquals(pcm.size, decoded.size)
    }

    private object OneByteCodec : AudioCodec {
        override fun encode(pcm: ShortArray): ByteArray = byteArrayOf(1)

        override fun decode(packet: ByteArray): ShortArray =
            ShortArray(AudioConfig.FRAME_SAMPLES)

        override fun close() = Unit
    }
}
