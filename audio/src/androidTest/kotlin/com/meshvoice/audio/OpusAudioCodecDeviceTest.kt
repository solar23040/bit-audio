package com.meshvoice.audio

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OpusAudioCodecDeviceTest {

    @Test
    fun nativeVersionIsAvailable() {
        assertTrue(OpusNative.version().isNotBlank())
    }

    @Test
    fun jniCodecRoundTripsTenSecondClipUnderTargetSize() {
        val pcm = DeviceTestSignals.voiceLikePcm(10_000)
        val clip = OpusClipCodec().encode(pcm)
        val payload = clip.toPayload()

        assertTrue(
            "10 s payload should stay under the target: ${payload.size} bytes",
            payload.size < AudioConfig.TARGET_MAX_CLIP_BYTES,
        )
        assertEquals(500, clip.frameCount)
        assertEquals(10_000, clip.durationMs)

        val decoded = OpusClipCodec().decode(EncodedAudioClip.fromPayload(payload))
        assertEquals(pcm.size, decoded.size)
        assertTrue("Decoded audio is silent", decoded.any { it.toInt() != 0 })

        val correlation = DeviceTestSignals.bestCorrelation(pcm, decoded, maxLag = 400)
        assertTrue("Decoded audio is too different from the source: $correlation", correlation > 0.6)
    }

    @Test
    fun fifteenSecondCapIsEnforcedByJniPipeline() {
        val pcm = DeviceTestSignals.voiceLikePcm(AudioConfig.MAX_CLIP_DURATION_MS)
        val clip = OpusClipCodec().encode(pcm)
        assertEquals(AudioConfig.MAX_FRAMES, clip.frameCount)
        assertTrue(clip.toPayload().size < 25_000)
    }
}
