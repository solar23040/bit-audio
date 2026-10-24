package com.meshvoice.audio

/**
 * Phase 0 contract from docs/interfaces.md.
 *
 * Opus is stateful and frame based, so each [encode] call consumes exactly one
 * [AudioConfig.FRAME_SAMPLES]-sample (20 ms) PCM16 frame and each [decode] call consumes one
 * Opus packet. A codec instance must not be shared between an encoder and a decoder stream;
 * create one instance per direction.
 */
interface AudioCodec : AutoCloseable {
    fun encode(pcm: ShortArray): ByteArray

    fun decode(packet: ByteArray): ShortArray
}

/** Internal seam that keeps the Kotlin pipeline testable with a real libopus on the JVM. */
internal interface OpusEngine : AutoCloseable {
    fun encode(pcm: ShortArray): ByteArray

    fun decode(packet: ByteArray): ShortArray
}

/** Failure raised by capture or playback. */
class AudioException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Failure raised when the Opus codec cannot encode, decode, or initialize. */
class AudioCodecException(message: String, cause: Throwable? = null) : Exception(message, cause)
