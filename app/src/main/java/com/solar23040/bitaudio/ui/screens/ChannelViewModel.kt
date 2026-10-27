package com.solar23040.bitaudio.ui.screens

import android.os.SystemClock
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.solar23040.bitaudio.AppGraph
import com.solar23040.bitaudio.data.NoteState
import com.solar23040.bitaudio.data.VoiceNote
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

class ChannelViewModel(
    private val graph: AppGraph,
    private val channelId: String,
    private val nearby: Boolean = false,
) : ViewModel() {
    val isRecording = graph.recorder.isRecording
    val amplitude = graph.recorder.amplitude

    private val _startedAtElapsed = MutableStateFlow<Long?>(null)
    val startedAtElapsed: StateFlow<Long?> = _startedAtElapsed.asStateFlow()

    private val _playingId = MutableStateFlow<String?>(null)
    val playingId: StateFlow<String?> = _playingId.asStateFlow()

    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 4)
    val messages: SharedFlow<String> = _messages.asSharedFlow()

    private var recordingJob: Job? = null
    private var stopSignal: CompletableDeferred<Unit>? = null
    private var stopRequested = false
    private var playbackJob: Job? = null

    fun startRecording() {
        if (recordingJob?.isActive == true) return
        stopRequested = false
        recordingJob = viewModelScope.launch {
            val channel = if (nearby) null else graph.channels.get(channelId)
            if (!nearby && channel == null) {
                sendMessage("This channel is no longer available")
                return@launch
            }
            val file = graph.clips.newFile()
            val startResult = graph.recorder.start(file)
            if (startResult.isFailure) {
                graph.clips.delete(file.name)
                sendMessage("Could not start the microphone")
                return@launch
            }

            val signal = CompletableDeferred<Unit>()
            stopSignal = signal
            if (stopRequested) signal.complete(Unit)
            _startedAtElapsed.value = SystemClock.elapsedRealtime()

            withTimeoutOrNull(MAX_CLIP_MS) { signal.await() }

            _startedAtElapsed.value = null
            stopSignal = null
            stopRequested = false

            val stopResult = graph.recorder.stop()
            if (stopResult.isFailure) {
                graph.clips.delete(file.name)
                sendMessage("Recording failed")
                return@launch
            }
            val clip = stopResult.getOrThrow()
            if (clip.durationMs < MIN_CLIP_MS) {
                clip.file.delete()
                sendMessage("Hold the button a little longer")
                return@launch
            }
            if (nearby) {
                val note = graph.addNearbyRecordedNote(clip)
                if (note.state == NoteState.Failed) sendMessage("Could not encode this clip")
            } else {
                graph.addRecordedNote(requireNotNull(channel), clip)
            }
        }
    }

    fun stopRecording() {
        stopRequested = true
        stopSignal?.complete(Unit)
    }

    fun togglePlayback(note: VoiceNote) {
        val file = graph.clips.resolve(note.fileName)
        if (file == null) {
            sendMessage("That clip is missing from this phone")
            return
        }
        if (_playingId.value == note.id) {
            stopPlayback()
            return
        }

        playbackJob?.cancel()
        graph.stopPlayback()
        _playingId.value = note.id
        playbackJob = viewModelScope.launch {
            val result = graph.playClip(file)
            if (_playingId.value == note.id) _playingId.value = null
            if (result.isFailure) sendMessage("Could not play this clip")
        }
    }

    fun stopPlayback() {
        playbackJob?.cancel()
        playbackJob = null
        graph.stopPlayback()
        _playingId.value = null
    }

    private fun sendMessage(text: String) {
        _messages.tryEmit(text)
    }

    override fun onCleared() {
        stopSignal?.complete(Unit)
        recordingJob?.cancel()
        graph.cancelActiveRecording()
        playbackJob?.cancel()
        graph.stopPlayback()
        super.onCleared()
    }

    private companion object {
        const val MAX_CLIP_MS = 15_000L
        const val MIN_CLIP_MS = 350L
    }
}
