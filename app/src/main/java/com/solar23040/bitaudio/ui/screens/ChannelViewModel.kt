package com.solar23040.bitaudio.ui.screens

import android.annotation.SuppressLint
import android.os.SystemClock
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.meshvoice.audio.AudioConfig
import com.solar23040.bitaudio.AppGraph
import com.solar23040.bitaudio.audio.RecordedClip
import com.solar23040.bitaudio.data.VoiceNote
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

class ChannelViewModel(
    private val graph: AppGraph,
    private val channelId: String,
) : ViewModel() {
    private val _isRecording = MutableStateFlow(false)
    val isRecording: StateFlow<Boolean> = _isRecording.asStateFlow()

    private val _amplitude = MutableStateFlow(0f)
    val amplitude: StateFlow<Float> = _amplitude.asStateFlow()

    private val _startedAtElapsed = MutableStateFlow<Long?>(null)
    val startedAtElapsed: StateFlow<Long?> = _startedAtElapsed.asStateFlow()

    /** Mirrors the pipeline so auto-played incoming notes show the pause icon too. */
    val playingId: StateFlow<String?> = graph.playingNoteId

    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 4)
    val messages: SharedFlow<String> = _messages.asSharedFlow()

    private var recordingJob: Job? = null
    private var stopSignal: CompletableDeferred<Unit>? = null
    private var stopRequested = false

    @SuppressLint("MissingPermission") // The screen gates on RECORD_AUDIO before calling.
    fun startRecording() {
        if (recordingJob?.isActive == true) return
        stopRequested = false
        recordingJob = viewModelScope.launch {
            graph.stopPlayback()
            val channel = graph.channels.get(channelId)
            if (channel == null) {
                sendMessage("This channel is no longer available")
                return@launch
            }

            val started = withContext(Dispatchers.IO) { runCatching { graph.recorder.start() } }
            if (started.isFailure) {
                sendMessage("Could not start the microphone")
                return@launch
            }

            val signal = CompletableDeferred<Unit>()
            stopSignal = signal
            if (stopRequested) signal.complete(Unit)
            _isRecording.value = true
            _startedAtElapsed.value = SystemClock.elapsedRealtime()

            val levelJob = launch {
                while (isActive) {
                    _amplitude.value = graph.recorder.amplitude
                    delay(AMPLITUDE_POLL_MS)
                }
            }

            withTimeoutOrNull(MAX_CLIP_MS) { signal.await() }

            _startedAtElapsed.value = null
            stopSignal = null
            stopRequested = false
            levelJob.cancel()
            _amplitude.value = 0f

            // VoiceRecorder caps itself at 15 s, so a missed stop still sends.
            val recording = withContext(Dispatchers.IO) {
                runCatching {
                    val result = graph.recorder.stop()
                    result?.let { RecordedClip(pcm = it.pcm, durationMs = it.durationMs.toLong()) }
                }
            }.getOrNull()
            _isRecording.value = false

            if (recording == null || recording.isSilent) {
                sendMessage("Recording failed")
                return@launch
            }
            if (recording.durationMs < MIN_CLIP_MS) {
                sendMessage("Hold the button a little longer")
                return@launch
            }

            graph.addRecordedNote(channel, recording)
                .onFailure { error ->
                    sendMessage(error.message ?: "Could not send this clip")
                }
        }
    }

    fun stopRecording() {
        stopRequested = true
        stopSignal?.complete(Unit)
    }

    fun togglePlayback(note: VoiceNote) {
        if (playingId.value == note.id) {
            graph.stopPlayback()
            return
        }
        viewModelScope.launch {
            val result = graph.playNote(note)
            if (result.isFailure) sendMessage("Could not play this clip")
        }
    }

    fun stopPlayback() {
        graph.stopPlayback()
    }

    private fun sendMessage(text: String) {
        _messages.tryEmit(text)
    }

    override fun onCleared() {
        stopSignal?.complete(Unit)
        recordingJob?.cancel()
        graph.cancelActiveRecording()
        graph.stopPlayback()
        super.onCleared()
    }

    private companion object {
        val MAX_CLIP_MS = AudioConfig.MAX_CLIP_DURATION_MS.toLong()
        const val MIN_CLIP_MS = 350L
        const val AMPLITUDE_POLL_MS = 50L
    }
}
