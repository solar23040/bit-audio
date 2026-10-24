package com.meshvoice.audio

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import kotlin.math.max
import kotlin.math.min

/**
 * Decodes and plays a voice note through AudioTrack in streaming mode.
 *
 * [play] blocks until playback finishes, so call it from a background thread. [stop] may be called
 * from another thread (for example the UI) to cut playback short.
 */
class ClipPlayer(
    private val codecFactory: () -> AudioCodec = { OpusAudioCodec() },
) : AutoCloseable {

    private val lock = Any()

    private var activeTrack: AudioTrack? = null

    @Volatile
    private var stopRequested = false

    @Volatile
    private var playing = false

    val isPlaying: Boolean get() = playing

    fun play(clip: EncodedAudioClip) {
        stop()

        val track = createAudioTrack()
        synchronized(lock) {
            activeTrack = track
            stopRequested = false
            playing = true
        }

        try {
            if (track.state != AudioTrack.STATE_INITIALIZED) {
                throw AudioException("AudioTrack failed to initialize")
            }
            track.play()

            codecFactory().use { codec ->
                var remaining = clip.sampleCount
                for (frame in clip.frames) {
                    if (stopRequested || remaining <= 0) break

                    val decoded = codec.decode(frame)
                    val count = minOf(decoded.size, remaining)
                    if (count <= 0) {
                        throw AudioCodecException("Opus decoder returned no samples")
                    }
                    var offset = 0
                    while (offset < count && !stopRequested) {
                        val written = track.write(
                            decoded,
                            offset,
                            count - offset,
                            AudioTrack.WRITE_BLOCKING,
                        )
                        if (written < 0) {
                            throw AudioException("AudioTrack.write failed: $written")
                        }
                        if (written == 0) break
                        offset += written
                    }
                    remaining -= count
                }
            }
        } finally {
            try {
                track.stop()
            } catch (_: IllegalStateException) {
                // Not playing anymore.
            }
            track.release()
            synchronized(lock) {
                if (activeTrack === track) {
                    activeTrack = null
                }
                playing = false
                stopRequested = false
            }
        }
    }

    fun stop() {
        val track = synchronized(lock) {
            stopRequested = true
            activeTrack
        }
        if (track == null) return

        try {
            track.pause()
        } catch (_: IllegalStateException) {
            // Already stopped or released.
        }
        try {
            track.flush()
        } catch (_: IllegalStateException) {
            // Already stopped or released.
        }
    }

    override fun close() {
        stop()
    }

    private fun createAudioTrack(): AudioTrack {
        val minBuffer = AudioTrack.getMinBufferSize(
            AudioConfig.SAMPLE_RATE_HZ,
            AudioFormat.CHANNEL_OUT_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
        )
        if (minBuffer <= 0) {
            throw AudioException("AudioTrack minimum buffer unavailable: $minBuffer")
        }

        val bufferBytes = max(minBuffer, AudioConfig.FRAME_SAMPLES * 2 * 8)
        return AudioTrack.Builder()
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                    .build()
            )
            .setAudioFormat(
                AudioFormat.Builder()
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(AudioConfig.SAMPLE_RATE_HZ)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                    .build()
            )
            .setTransferMode(AudioTrack.MODE_STREAM)
            .setBufferSizeInBytes(bufferBytes)
            .build()
    }
}
