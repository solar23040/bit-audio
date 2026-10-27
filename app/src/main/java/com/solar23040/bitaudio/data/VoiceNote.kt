package com.solar23040.bitaudio.data

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

enum class NoteState {
    Sending,
    Queued,
    Delivered,
    Failed,
}

data class VoiceNote(
    val id: String,
    val channelId: String,
    val senderAlias: String,
    /** File name inside the app's private clips directory. */
    val fileName: String,
    val durationMs: Long,
    val sizeBytes: Long,
    /** Normalised 0..1 peaks for the waveform preview. */
    val peaks: List<Float>,
    val hopCount: Int,
    val outgoing: Boolean,
    val state: NoteState,
    val createdAt: Long,
    /** Identity fingerprint of the sender; empty for locally-authored notes. */
    val senderFingerprint: String = "",
)

class NoteRepository(context: Context, private val scope: CoroutineScope) {
    private val file = File(context.filesDir, "notes.json")
    private val mutex = Mutex()
    private val _notes = MutableStateFlow(load())
    val notes: StateFlow<List<VoiceNote>> = _notes.asStateFlow()

    fun forChannel(channelId: String): Flow<List<VoiceNote>> =
        _notes.map { all ->
            all.filter { it.channelId == channelId }.sortedByDescending { it.createdAt }
        }

    fun countForChannel(channelId: String): Int =
        _notes.value.count { it.channelId == channelId }

    fun add(note: VoiceNote) {
        _notes.value = _notes.value + note
        persist()
    }

    fun updateState(id: String, state: NoteState) {
        _notes.value = _notes.value.map { note ->
            if (note.id == id) note.copy(state = state) else note
        }
        persist()
    }

    /** Removes every note for a deleted channel and returns them so clips can be removed. */
    fun deleteChannel(channelId: String): List<VoiceNote> {
        val removed = _notes.value.filter { it.channelId == channelId }
        if (removed.isEmpty()) return removed
        _notes.value = _notes.value.filterNot { it.channelId == channelId }
        persist()
        return removed
    }

    /**
     * Drops undelivered notes older than [cutoff] and returns them so their
     * clips can be deleted. Delivered notes stay until the channel is removed.
     */
    fun removeExpired(cutoff: Long): List<VoiceNote> {
        val expired = _notes.value.expiredNotes(cutoff)
        if (expired.isEmpty()) return emptyList()
        val expiredIds = expired.mapTo(HashSet()) { it.id }
        _notes.value = _notes.value.filterNot { it.id in expiredIds }
        persist()
        return expired
    }

    private fun load(): List<VoiceNote> = runCatching {
        if (!file.isFile) return@runCatching emptyList()
        val array = JSONArray(file.readText())
        buildList {
            for (index in 0 until array.length()) {
                val json = array.optJSONObject(index) ?: continue
                val note = json.toNote() ?: continue
                add(note)
            }
        }
    }.getOrDefault(emptyList())

    private fun persist() {
        scope.launch {
            mutex.withLock {
                runCatching {
                    val array = JSONArray()
                    _notes.value.forEach { array.put(it.toJson()) }
                    val text = array.toString()
                    val temp = File(file.parentFile, "${file.name}.tmp")
                    temp.writeText(text)
                    if (!temp.renameTo(file)) {
                        file.writeText(text)
                        temp.delete()
                    }
                }
            }
        }
    }

    private fun VoiceNote.toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("channelId", channelId)
        put("senderAlias", senderAlias)
        put("fileName", fileName)
        put("durationMs", durationMs)
        put("sizeBytes", sizeBytes)
        put("peaks", JSONArray(peaks))
        put("hopCount", hopCount)
        put("outgoing", outgoing)
        put("state", state.name)
        put("createdAt", createdAt)
        put("senderFingerprint", senderFingerprint)
    }

    private fun JSONObject.toNote(): VoiceNote? = runCatching {
        val peaksJson = optJSONArray("peaks")
        val parsedPeaks = if (peaksJson == null) {
            emptyList()
        } else {
            List(peaksJson.length()) { index ->
                peaksJson.optDouble(index, 0.0).toFloat().coerceIn(0f, 1f)
            }
        }
        val parsedState = optString("state", NoteState.Queued.name)
            .let { name -> NoteState.entries.firstOrNull { it.name == name } ?: NoteState.Queued }
            // A crash mid-send leaves Sending behind; the clip is still safely on disk.
            .let { state -> if (state == NoteState.Sending) NoteState.Queued else state }
        VoiceNote(
            id = getString("id"),
            channelId = getString("channelId"),
            senderAlias = optString("senderAlias", "Unknown"),
            fileName = getString("fileName"),
            durationMs = optLong("durationMs", 0),
            sizeBytes = optLong("sizeBytes", 0),
            peaks = parsedPeaks,
            hopCount = optInt("hopCount", 0),
            outgoing = optBoolean("outgoing", true),
            state = parsedState,
            createdAt = optLong("createdAt", System.currentTimeMillis()),
            senderFingerprint = optString("senderFingerprint", ""),
        )
    }.getOrNull()?.takeIf { it.id.isNotBlank() && it.fileName.isNotBlank() }
}

/** Undelivered notes older than [cutoff] are outside the retention window. */
internal fun List<VoiceNote>.expiredNotes(cutoff: Long): List<VoiceNote> =
    filter { it.state != NoteState.Delivered && it.createdAt < cutoff }
