package com.meshvoice.audio

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class WavFileTest {

    @Test
    fun monoRoundTrips() {
        val samples = shortArrayOf(0, 1, -1, 32_767, -32_768, 1234)
        val audio = WavFile.PcmAudio(
            sampleRate = AudioConfig.SAMPLE_RATE_HZ,
            channels = 1,
            samples = samples,
        )

        val parsed = WavFile.read(WavFile.write(audio))

        assertEquals(AudioConfig.SAMPLE_RATE_HZ, parsed.sampleRate)
        assertEquals(1, parsed.channels)
        assertArrayEquals(samples, parsed.samples)
    }

    @Test
    fun stereoRoundTrips() {
        val samples = shortArrayOf(1, 2, 3, 4, 5, 6)
        val audio = WavFile.PcmAudio(sampleRate = 8_000, channels = 2, samples = samples)

        val parsed = WavFile.read(WavFile.write(audio))

        assertEquals(8_000, parsed.sampleRate)
        assertEquals(2, parsed.channels)
        assertEquals(3, parsed.frameCount)
        assertArrayEquals(samples, parsed.samples)
    }

    @Test
    fun skipsUnknownChunks() {
        val audio = WavFile.PcmAudio(
            sampleRate = AudioConfig.SAMPLE_RATE_HZ,
            channels = 1,
            samples = shortArrayOf(10, 20, 30),
        )
        val canonical = WavFile.write(audio)

        // Insert a JUNK chunk between "fmt " and "data".
        val dataOffset = 36
        val junk = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
            .put("JUNK".toByteArray(Charsets.US_ASCII))
            .putInt(4)
            .putInt(0)
            .array()
        val withJunk = canonical.copyOfRange(0, dataOffset) +
            junk +
            canonical.copyOfRange(dataOffset, canonical.size)

        val parsed = WavFile.read(withJunk)
        assertArrayEquals(audio.samples, parsed.samples)
    }

    @Test
    fun rejectsNonPcmFormat() {
        val wav = WavFile.write(
            WavFile.PcmAudio(AudioConfig.SAMPLE_RATE_HZ, 1, shortArrayOf(1, 2, 3))
        )
        wav[20] = 3 // IEEE float format code
        assertThrows(IllegalArgumentException::class.java) { WavFile.read(wav) }
    }

    @Test
    fun rejectsTruncatedFile() {
        assertThrows(IllegalArgumentException::class.java) {
            WavFile.read(ByteArray(20))
        }
    }

    @Test
    fun rejectsInvalidChannelCount() {
        assertThrows(IllegalArgumentException::class.java) {
            WavFile.PcmAudio(AudioConfig.SAMPLE_RATE_HZ, 3, ShortArray(6))
        }
    }
}
