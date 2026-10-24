package com.meshvoice.audio

/**
 * Splits PCM into 20 ms frames and encodes/decodes a complete clip with one stateful Opus codec.
 *
 * [encode] enforces the 15 s hard cap. The last partial frame is zero padded, and
 * [EncodedAudioClip.sampleCount] keeps the exact original length so playback can trim the padding.
 */
class OpusClipCodec(
    private val codecFactory: () -> AudioCodec = { OpusAudioCodec() },
) {

    fun encode(pcm: ShortArray): EncodedAudioClip {
        require(pcm.isNotEmpty()) { "Cannot encode an empty clip" }
        require(pcm.size <= AudioConfig.MAX_CLIP_SAMPLES) {
            "Clip is longer than ${AudioConfig.MAX_CLIP_DURATION_MS} ms"
        }

        val frameCount =
            (pcm.size + AudioConfig.FRAME_SAMPLES - 1) / AudioConfig.FRAME_SAMPLES
        val frames = ArrayList<ByteArray>(frameCount)
        val frame = ShortArray(AudioConfig.FRAME_SAMPLES)

        codecFactory().use { codec ->
            for (index in 0 until frameCount) {
                val offset = index * AudioConfig.FRAME_SAMPLES
                val count = minOf(AudioConfig.FRAME_SAMPLES, pcm.size - offset)
                if (count == AudioConfig.FRAME_SAMPLES) {
                    pcm.copyInto(frame, 0, offset, offset + count)
                } else {
                    frame.fill(0)
                    pcm.copyInto(frame, 0, offset, offset + count)
                }
                val packet = codec.encode(frame)
                require(packet.isNotEmpty()) { "Opus encoder returned an empty packet" }
                require(packet.size <= AudioConfig.MAX_OPUS_PACKET_BYTES) {
                    "Opus packet is too large: ${packet.size} bytes"
                }
                frames += packet
            }
        }

        return EncodedAudioClip(frames, pcm.size)
    }

    fun decode(clip: EncodedAudioClip): ShortArray {
        val pcm = ShortArray(clip.sampleCount)
        var written = 0

        codecFactory().use { codec ->
            for (frame in clip.frames) {
                if (written >= pcm.size) break
                val decoded = codec.decode(frame)
                val count = minOf(decoded.size, pcm.size - written)
                if (count <= 0) {
                    throw AudioCodecException("Opus decoder returned no samples")
                }
                decoded.copyInto(pcm, written, 0, count)
                written += count
            }
        }

        check(written == clip.sampleCount) {
            "Decoded $written samples, expected ${clip.sampleCount}"
        }
        return pcm
    }

    fun payloadFor(pcm: ShortArray): ByteArray = encode(pcm).toPayload()

    fun decodePayload(payload: ByteArray): ShortArray =
        decode(EncodedAudioClip.fromPayload(payload))
}
