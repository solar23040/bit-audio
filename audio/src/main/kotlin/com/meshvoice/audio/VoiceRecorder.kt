package com.meshvoice.audio

import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Process
import androidx.annotation.RequiresPermission
import kotlin.math.max
import kotlin.math.min

/**
 * Hold-to-record microphone capture at 16 kHz mono PCM16.
 *
 * [start] returns immediately and a worker thread polls AudioRecord. [stop] returns the captured
 * PCM (up to the 15 s hard cap). Recording stops itself at the cap; [Recording.truncated] tells the
 * caller that more audio would have been captured.
 */
class VoiceRecorder @JvmOverloads constructor(
    private val maxDurationMs: Int = AudioConfig.MAX_CLIP_DURATION_MS,
) : AutoCloseable {

    data class Recording(
        val pcm: ShortArray,
        val truncated: Boolean,
        val error: String?,
    ) {
        val durationMs: Int
            get() = (pcm.size.toLong() * 1_000 / AudioConfig.SAMPLE_RATE_HZ).toInt()
    }

    private val lock = Any()

    @Volatile
    private var recording = false

    @Volatile
    private var stopRequested = false

    @Volatile
    private var truncated = false

    @Volatile
    private var failure: String? = null

    private var worker: Thread? = null
    private var audioRecord: AudioRecord? = null
    private var buffer: ClipBuffer? = null

    init {
        require(maxDurationMs in 1..AudioConfig.MAX_CLIP_DURATION_MS) {
            "maxDurationMs must be between 1 and ${AudioConfig.MAX_CLIP_DURATION_MS}"
        }
    }

    val isRecording: Boolean get() = recording

    /** Last capture error, if any. Cleared on the next [start]. */
    val lastFailure: String? get() = failure

    @RequiresPermission(android.Manifest.permission.RECORD_AUDIO)
    fun start() {
        synchronized(lock) {
            check(!recording && worker == null) { "Recorder is already running" }

            val record = createAudioRecord()
            val maxSamples = (maxDurationMs.toLong() * AudioConfig.SAMPLE_RATE_HZ / 1_000)
                .toInt()
                .coerceAtMost(AudioConfig.MAX_CLIP_SAMPLES)
            val clipBuffer = ClipBuffer(maxSamples)

            stopRequested = false
            truncated = false
            failure = null
            audioRecord = record
            buffer = clipBuffer
            recording = true

            val thread = Thread(
                { recordLoop(record, clipBuffer) },
                "mesh-voice-recorder",
            )
            worker = thread
            thread.start()
        }
    }

    /**
     * Stops capture and returns the recorded PCM, or null if no samples were captured.
     * The returned [Recording.error] is non-null when capture stopped because of a failure.
     */
    fun stop(): Recording? {
        val state = synchronized(lock) {
            val thread = worker ?: return null
            stopRequested = true
            Triple(thread, audioRecord, buffer)
        }
        val thread = state.first
        val record = state.second
        val clipBuffer = state.third

        thread.interrupt()
        try {
            thread.join(STOP_TIMEOUT_MS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }

        val stillRunning = thread.isAlive
        val pcm = clipBuffer?.snapshot() ?: ShortArray(0)
        val wasTruncated = truncated
        val error = failure

        if (!stillRunning) {
            synchronized(lock) {
                record?.release()
                audioRecord = null
                buffer = null
                worker = null
                recording = false
            }
        }

        return if (pcm.isEmpty()) null else Recording(pcm, wasTruncated, error)
    }

    /** Stops capture and discards the samples. */
    fun cancel() {
        stop()
    }

    override fun close() {
        cancel()
    }

    @RequiresPermission(android.Manifest.permission.RECORD_AUDIO)
    private fun createAudioRecord(): AudioRecord {
        val minBuffer = AudioRecord.getMinBufferSize(
            AudioConfig.SAMPLE_RATE_HZ,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
        )
        if (minBuffer <= 0) {
            throw AudioException("AudioRecord minimum buffer unavailable: $minBuffer")
        }

        val bufferBytes = max(minBuffer, AudioConfig.FRAME_SAMPLES * 2 * 8)
        val record = try {
            AudioRecord.Builder()
                .setAudioSource(MediaRecorder.AudioSource.MIC)
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                        .setSampleRate(AudioConfig.SAMPLE_RATE_HZ)
                        .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
                        .build()
                )
                .setBufferSizeInBytes(bufferBytes)
                .build()
        } catch (e: SecurityException) {
            throw AudioException("Microphone permission is required", e)
        } catch (e: IllegalArgumentException) {
            throw AudioException("AudioRecord rejected the capture format", e)
        }

        if (record.state != AudioRecord.STATE_INITIALIZED) {
            record.release()
            throw AudioException("AudioRecord failed to initialize")
        }
        return record
    }

    @RequiresPermission(android.Manifest.permission.RECORD_AUDIO)
    private fun recordLoop(record: AudioRecord, clipBuffer: ClipBuffer) {
        Process.setThreadPriority(Process.THREAD_PRIORITY_AUDIO)
        val chunk = ShortArray(AudioConfig.FRAME_SAMPLES)

        try {
            record.startRecording()
            if (record.recordingState != AudioRecord.RECORDSTATE_RECORDING) {
                throw AudioException("AudioRecord did not start")
            }

            while (!stopRequested && !clipBuffer.isFull) {
                val remaining = clipBuffer.capacity - clipBuffer.size
                val read = record.read(
                    chunk,
                    0,
                    min(chunk.size, remaining),
                    AudioRecord.READ_NON_BLOCKING,
                )
                when {
                    read > 0 -> clipBuffer.append(chunk, read)
                    read == 0 -> Thread.sleep(READ_POLL_MS)
                    read == AudioRecord.ERROR_DEAD_OBJECT -> {
                        throw AudioException("Audio device disconnected")
                    }

                    read == AudioRecord.ERROR_INVALID_OPERATION -> {
                        throw AudioException("AudioRecord is not initialized")
                    }

                    read == AudioRecord.ERROR_BAD_VALUE -> {
                        throw AudioException("AudioRecord rejected the read arguments")
                    }

                    else -> throw AudioException("AudioRecord read failed: $read")
                }
            }

            if (clipBuffer.isFull) {
                truncated = true
            }
        } catch (_: InterruptedException) {
            // stop() interrupts the polling sleep.
        } catch (t: Throwable) {
            failure = t.message ?: t::class.java.simpleName
        } finally {
            try {
                record.stop()
            } catch (_: IllegalStateException) {
                // Already stopped.
            }
            recording = false
        }
    }

    private companion object {
        const val READ_POLL_MS = 5L
        const val STOP_TIMEOUT_MS = 1_000L
    }
}
