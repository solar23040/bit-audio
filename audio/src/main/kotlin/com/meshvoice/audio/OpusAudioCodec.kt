package com.meshvoice.audio

/**
 * Opus codec configured for 16 kHz mono voice notes at 12 kbps.
 *
 * The public constructor uses the Android libopus JNI bridge. The internal constructor exists so
 * JVM tests can run the same framing code against a desktop libopus build.
 */
class OpusAudioCodec internal constructor(
    private val engine: OpusEngine,
    val bitrateBps: Int,
) : AudioCodec {

    private val lock = Any()
    private var closed = false

    @JvmOverloads
    constructor(
        bitrateBps: Int = AudioConfig.BITRATE_BPS,
        complexity: Int = 5,
        useVbr: Boolean = true,
        useDtx: Boolean = false,
        inbandFec: Boolean = false,
        packetLossPercent: Int = 0,
    ) : this(
        JniOpusEngine(
            bitrateBps = bitrateBps,
            complexity = complexity,
            useVbr = useVbr,
            useDtx = useDtx,
            inbandFec = inbandFec,
            packetLossPercent = packetLossPercent,
        ),
        bitrateBps,
    )

    override fun encode(pcm: ShortArray): ByteArray = synchronized(lock) {
        checkOpen()
        require(pcm.size == AudioConfig.FRAME_SAMPLES) {
            "Expected ${AudioConfig.FRAME_SAMPLES} samples per frame, got ${pcm.size}"
        }
        engine.encode(pcm)
    }

    override fun decode(packet: ByteArray): ShortArray = synchronized(lock) {
        checkOpen()
        require(packet.isNotEmpty()) { "Opus packet must not be empty" }
        require(packet.size <= AudioConfig.MAX_OPUS_PACKET_BYTES) {
            "Opus packet is too large: ${packet.size} bytes"
        }
        engine.decode(packet)
    }

    override fun close() = synchronized(lock) {
        if (!closed) {
            closed = true
            engine.close()
        }
    }

    private fun checkOpen() {
        check(!closed) { "Codec is closed" }
    }
}

internal class JniOpusEngine(
    bitrateBps: Int,
    complexity: Int,
    useVbr: Boolean,
    useDtx: Boolean,
    inbandFec: Boolean,
    packetLossPercent: Int,
) : OpusEngine {

    private var encoderHandle: Long = 0
    private var decoderHandle: Long = 0
    private var closed = false

    init {
        require(bitrateBps in 500..512_000) { "Bitrate out of range: $bitrateBps" }
        require(complexity in 0..10) { "Complexity out of range: $complexity" }
        require(packetLossPercent in 0..100) {
            "Packet loss percent out of range: $packetLossPercent"
        }

        try {
            encoderHandle = OpusNative.encoderCreate(
                AudioConfig.SAMPLE_RATE_HZ,
                AudioConfig.CHANNEL_COUNT,
                OPUS_APPLICATION_VOIP,
                bitrateBps,
                complexity,
                useVbr,
                useDtx,
                inbandFec,
                packetLossPercent,
                OPUS_SIGNAL_VOICE,
            )
            check(encoderHandle != 0L) { "Failed to create Opus encoder" }

            decoderHandle = OpusNative.decoderCreate(
                AudioConfig.SAMPLE_RATE_HZ,
                AudioConfig.CHANNEL_COUNT,
            )
            check(decoderHandle != 0L) { "Failed to create Opus decoder" }
        } catch (e: RuntimeException) {
            releaseNative()
            throw AudioCodecException("Failed to initialize Opus codec", e)
        } catch (e: LinkageError) {
            releaseNative()
            throw AudioCodecException("Failed to load the Opus native library", e)
        }
    }

    override fun encode(pcm: ShortArray): ByteArray {
        check(!closed) { "Codec is closed" }
        val output = ByteArray(OPUS_OUTPUT_BUFFER_BYTES)
        val written = try {
            OpusNative.encode(encoderHandle, pcm, pcm.size, output)
        } catch (e: RuntimeException) {
            throw AudioCodecException("Opus encode failed", e)
        }
        if (written <= 0) {
            throw AudioCodecException("Opus encoder produced no data ($written)")
        }
        return output.copyOf(written)
    }

    override fun decode(packet: ByteArray): ShortArray {
        check(!closed) { "Codec is closed" }
        val output = ShortArray(AudioConfig.FRAME_SAMPLES)
        val decoded = try {
            OpusNative.decode(
                decoderHandle,
                packet,
                AudioConfig.FRAME_SAMPLES,
                output,
            )
        } catch (e: RuntimeException) {
            throw AudioCodecException("Opus decode failed", e)
        }
        if (decoded <= 0) {
            throw AudioCodecException("Opus decoder produced no samples ($decoded)")
        }
        return if (decoded == output.size) output else output.copyOf(decoded)
    }

    override fun close() {
        if (closed) return
        closed = true
        releaseNative()
    }

    private fun releaseNative() {
        if (encoderHandle != 0L) {
            OpusNative.encoderDestroy(encoderHandle)
            encoderHandle = 0
        }
        if (decoderHandle != 0L) {
            OpusNative.decoderDestroy(decoderHandle)
            decoderHandle = 0
        }
    }

    private companion object {
        const val OPUS_APPLICATION_VOIP = 2048
        const val OPUS_SIGNAL_VOICE = 3001
        const val OPUS_OUTPUT_BUFFER_BYTES = 4_000
    }
}
