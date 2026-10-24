package com.meshvoice.audio

import org.lwjgl.system.MemoryStack
import org.lwjgl.util.opus.Opus

/**
 * Test-only [OpusEngine] backed by the desktop libopus shipped with LWJGL.
 * It exercises the same Kotlin framing code as the Android JNI engine.
 */
internal class TestOpusEngine(
    bitrateBps: Int = AudioConfig.BITRATE_BPS,
) : OpusEngine {

    private var encoder = 0L
    private var decoder = 0L

    init {
        check(Opus.opus_get_version_string()?.isNotBlank() == true) { "libopus did not load" }

        encoder = Opus.opus_encoder_create(
            AudioConfig.SAMPLE_RATE_HZ,
            AudioConfig.CHANNEL_COUNT,
            Opus.OPUS_APPLICATION_VOIP,
            null,
        )
        check(encoder != 0L) { "Failed to create test Opus encoder" }
        check(Opus.opus_encoder_ctl(encoder, Opus.OPUS_SET_BITRATE(bitrateBps)) == Opus.OPUS_OK)
        check(Opus.opus_encoder_ctl(encoder, Opus.OPUS_SET_COMPLEXITY(5)) == Opus.OPUS_OK)
        check(
            Opus.opus_encoder_ctl(encoder, Opus.OPUS_SET_SIGNAL(Opus.OPUS_SIGNAL_VOICE)) ==
                Opus.OPUS_OK
        )

        decoder = Opus.opus_decoder_create(
            AudioConfig.SAMPLE_RATE_HZ,
            AudioConfig.CHANNEL_COUNT,
            null,
        )
        check(decoder != 0L) { "Failed to create test Opus decoder" }
    }

    override fun encode(pcm: ShortArray): ByteArray {
        val stack = MemoryStack.stackPush()
        try {
            val input = stack.mallocShort(pcm.size)
            input.put(pcm).flip()
            val output = stack.malloc(OUTPUT_BUFFER_BYTES)
            val written = Opus.opus_encode(encoder, input, pcm.size, output)
            check(written > 0) { "test opus_encode failed: $written" }
            val packet = ByteArray(written)
            output.get(packet)
            return packet
        } finally {
            stack.close()
        }
    }

    override fun decode(packet: ByteArray): ShortArray {
        val stack = MemoryStack.stackPush()
        try {
            val input = stack.malloc(packet.size)
            input.put(packet).flip()
            val output = stack.mallocShort(AudioConfig.FRAME_SAMPLES)
            val decoded = Opus.opus_decode(
                decoder,
                input,
                output,
                AudioConfig.FRAME_SAMPLES,
                0,
            )
            check(decoded > 0) { "test opus_decode failed: $decoded" }
            val pcm = ShortArray(decoded)
            output.get(pcm)
            return pcm
        } finally {
            stack.close()
        }
    }

    override fun close() {
        if (encoder != 0L) {
            Opus.opus_encoder_destroy(encoder)
            encoder = 0
        }
        if (decoder != 0L) {
            Opus.opus_decoder_destroy(decoder)
            decoder = 0
        }
    }

    private companion object {
        const val OUTPUT_BUFFER_BYTES = 4_000
    }
}
