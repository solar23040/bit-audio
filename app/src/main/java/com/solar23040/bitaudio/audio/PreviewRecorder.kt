package com.solar23040.bitaudio.audio

import android.annotation.SuppressLint
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream

data class RecordedClip(
    val file: File,
    val durationMs: Long,
    val peaks: List<Float>,
)

/**
 * Interim PCM/WAV capture used by the app shell until `:audio` exposes its
 * recorder/player API. 16 kHz mono signed 16-bit, matching `AudioConfig`.
 *
 * This is deliberately app-private and must not be used by the mesh pipeline;
 * Phase 2 swaps it for Agent B's Opus recorder.
 */
class PreviewRecorder {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val _isRecording = MutableStateFlow(false)
    val isRecording: StateFlow<Boolean> = _isRecording.asStateFlow()
    private val _amplitude = MutableStateFlow(0f)
    val amplitude: StateFlow<Float> = _amplitude.asStateFlow()

    private var audioRecord: AudioRecord? = null
    private var readJob: Job? = null
    private var outputFile: File? = null
    private var pcm = ByteArrayOutputStream()
    private val peaks = ArrayList<Float>()
    private var startedAt = 0L

    @SuppressLint("MissingPermission") // Callers gate on RECORD_AUDIO before recording.
    suspend fun start(file: File): Result<Unit> = withContext(Dispatchers.IO) {
        if (audioRecord != null) {
            return@withContext Result.failure(IllegalStateException("Recording already in progress"))
        }
        val minBuffer = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_IN, ENCODING)
        if (minBuffer <= 0) {
            return@withContext Result.failure(IllegalStateException("Microphone is unavailable"))
        }
        val bufferSize = minBuffer * 2
        val recorder = runCatching {
            AudioRecord(
                MediaRecorder.AudioSource.MIC,
                SAMPLE_RATE,
                CHANNEL_IN,
                ENCODING,
                bufferSize,
            )
        }.getOrElse { return@withContext Result.failure(it) }

        if (recorder.state != AudioRecord.STATE_INITIALIZED) {
            recorder.release()
            return@withContext Result.failure(IllegalStateException("Microphone is busy"))
        }

        outputFile = file
        pcm = ByteArrayOutputStream()
        synchronized(peaks) { peaks.clear() }
        startedAt = SystemClock.elapsedRealtime()
        try {
            recorder.startRecording()
        } catch (throwable: Throwable) {
            recorder.release()
            outputFile = null
            return@withContext Result.failure(throwable)
        }
        if (recorder.recordingState != AudioRecord.RECORDSTATE_RECORDING) {
            recorder.release()
            outputFile = null
            return@withContext Result.failure(IllegalStateException("Microphone did not start"))
        }

        audioRecord = recorder
        _isRecording.value = true
        readJob = scope.launch {
            val buffer = ByteArray(bufferSize)
            while (isActive) {
                val read = recorder.read(buffer, 0, buffer.size)
                if (read <= 0) {
                    if (read == AudioRecord.ERROR_DEAD_OBJECT || read == AudioRecord.ERROR_INVALID_OPERATION) {
                        break
                    }
                    continue
                }
                val level = peakOf(buffer, read)
                synchronized(pcm) { pcm.write(buffer, 0, read) }
                synchronized(peaks) { peaks.add(level) }
                _amplitude.value = (_amplitude.value * 0.65f) + (level * 0.35f)
                if (SystemClock.elapsedRealtime() - startedAt >= MAX_DURATION_MS) break
            }
        }
        Result.success(Unit)
    }

    suspend fun stop(): Result<RecordedClip> = withContext(Dispatchers.IO) {
        val recorder = audioRecord
            ?: return@withContext Result.failure(IllegalStateException("Not recording"))
        val file = outputFile
            ?: return@withContext Result.failure(IllegalStateException("Missing output file"))

        audioRecord = null
        _isRecording.value = false
        runCatching { recorder.stop() }
        val job = readJob
        readJob = null
        runCatching { recorder.release() }
        job?.join()
        _amplitude.value = 0f

        val data = synchronized(pcm) { pcm.toByteArray() }
        val peakSnapshot = synchronized(peaks) { peaks.toList() }
        outputFile = null

        if (data.isEmpty()) {
            file.delete()
            return@withContext Result.failure(IllegalStateException("No audio was captured"))
        }
        val writeResult = runCatching { writeWav(file, data) }
        if (writeResult.isFailure) {
            file.delete()
            return@withContext Result.failure(
                writeResult.exceptionOrNull() ?: IllegalStateException("Could not save clip"),
            )
        }
        Result.success(
            RecordedClip(
                file = file,
                durationMs = data.size.toLong() * 1000L / (SAMPLE_RATE.toLong() * BYTES_PER_SAMPLE),
                peaks = downsamplePeaks(peakSnapshot),
            ),
        )
    }

    suspend fun cancel() {
        val file = outputFile
        stop()
        file?.delete()
    }

    private fun peakOf(buffer: ByteArray, length: Int): Float {
        var peak = 0
        var index = 0
        while (index + 1 < length) {
            val sample = ((buffer[index + 1].toInt() shl 8) or
                (buffer[index].toInt() and 0xFF)).toShort().toInt()
            val magnitude = if (sample == Short.MIN_VALUE.toInt()) 32768 else kotlin.math.abs(sample)
            if (magnitude > peak) peak = magnitude
            index += 2
        }
        return (peak / 32768f).coerceIn(0f, 1f)
    }

    private companion object {
        const val SAMPLE_RATE = 16_000
        const val CHANNEL_IN = AudioFormat.CHANNEL_IN_MONO
        const val ENCODING = AudioFormat.ENCODING_PCM_16BIT
        const val BYTES_PER_SAMPLE = 2
        const val MAX_DURATION_MS = 15_000L
    }
}

private fun downsamplePeaks(peaks: List<Float>, bars: Int = 48): List<Float> {
    if (peaks.isEmpty()) return List(bars) { 0.08f }
    val result = ArrayList<Float>(bars)
    val bucketSize = peaks.size.toDouble() / bars
    for (bar in 0 until bars) {
        val start = (bar * bucketSize).toInt().coerceIn(0, peaks.lastIndex)
        val end = ((bar + 1) * bucketSize).toInt().coerceIn(start + 1, peaks.size)
        var max = 0f
        for (index in start until end) {
            if (peaks[index] > max) max = peaks[index]
        }
        result.add(max.coerceAtLeast(0.06f))
    }
    return result
}

private fun writeWav(file: File, pcm: ByteArray) {
    file.parentFile?.mkdirs()
    FileOutputStream(file).use { output ->
        val header = ByteArray(44)
        fun putAscii(offset: Int, value: String) {
            value.toByteArray(Charsets.US_ASCII).copyInto(header, offset)
        }
        fun putIntLe(offset: Int, value: Int) {
            header[offset] = (value and 0xFF).toByte()
            header[offset + 1] = ((value ushr 8) and 0xFF).toByte()
            header[offset + 2] = ((value ushr 16) and 0xFF).toByte()
            header[offset + 3] = ((value ushr 24) and 0xFF).toByte()
        }
        fun putShortLe(offset: Int, value: Int) {
            header[offset] = (value and 0xFF).toByte()
            header[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        }

        putAscii(0, "RIFF")
        putIntLe(4, 36 + pcm.size)
        putAscii(8, "WAVE")
        putAscii(12, "fmt ")
        putIntLe(16, 16)
        putShortLe(20, 1) // PCM
        putShortLe(22, 1) // mono
        putIntLe(24, 16_000)
        putIntLe(28, 16_000 * 2)
        putShortLe(32, 2)
        putShortLe(34, 16)
        putAscii(36, "data")
        putIntLe(40, pcm.size)
        output.write(header)
        output.write(pcm)
    }
}
