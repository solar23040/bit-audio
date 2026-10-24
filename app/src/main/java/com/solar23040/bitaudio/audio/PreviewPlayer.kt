package com.solar23040.bitaudio.audio

import android.media.AudioAttributes
import android.media.MediaPlayer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.coroutines.resume

/**
 * Interim local playback through MediaPlayer (WAV is supported natively).
 * Replaced by `:audio`'s AudioTrack/Opus player during Phase 2.
 */
class PreviewPlayer {
    private var player: MediaPlayer? = null

    fun stop() {
        val current = player ?: return
        player = null
        runCatching { current.stop() }
        runCatching { current.release() }
    }

    suspend fun play(file: File): Result<Unit> = withContext(Dispatchers.Main) {
        stop()
        suspendCancellableCoroutine { continuation ->
            val mediaPlayer = MediaPlayer()
            player = mediaPlayer
            var finished = false

            fun finish(result: Result<Unit>) {
                if (finished) return
                finished = true
                if (player === mediaPlayer) player = null
                runCatching { mediaPlayer.release() }
                if (continuation.isActive) continuation.resume(result)
            }

            try {
                mediaPlayer.setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build(),
                )
                mediaPlayer.setDataSource(file.absolutePath)
                mediaPlayer.setOnPreparedListener { it.start() }
                mediaPlayer.setOnCompletionListener { finish(Result.success(Unit)) }
                mediaPlayer.setOnErrorListener { _, what, extra ->
                    finish(
                        Result.failure(
                            IllegalStateException("Playback failed ($what/$extra)"),
                        ),
                    )
                    true
                }
                continuation.invokeOnCancellation { finish(Result.failure(IllegalStateException("Stopped"))) }
                mediaPlayer.prepareAsync()
            } catch (throwable: Throwable) {
                finish(Result.failure(throwable))
            }
        }
    }
}
