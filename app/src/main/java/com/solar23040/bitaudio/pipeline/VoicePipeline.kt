package com.solar23040.bitaudio.pipeline

import com.meshvoice.audio.AudioConfig
import com.meshvoice.audio.EncodedAudioClip
import com.meshvoice.audio.OpusClipCodec
import com.solar23040.bitaudio.data.NoteState
import com.solar23040.bitaudio.data.VoiceNote
import com.solar23040.bitaudio.mesh.MeshMessage
import com.solar23040.bitaudio.transport.MeshPort
import java.io.File
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Storage hooks the pipeline needs. Implemented by the app repositories in production. */
interface NoteSink {
    fun add(note: VoiceNote)

    fun all(): List<VoiceNote>

    fun updateDelivery(id: String, state: NoteState, hopCount: Int)
}

/** App-private clip directory. Implemented by `ClipStore`. */
interface ClipSource {
    fun newFile(): File

    fun resolve(fileName: String): File?
}

/** Playback hook so the pipeline can be tested without Android's AudioTrack. */
interface ClipPlayback {
    suspend fun play(clip: EncodedAudioClip)

    fun stop()
}

/**
 * End-to-end voice note glue: hold-to-talk PCM -> Opus -> `Mesh.publish`, and
 * `Mesh.onMessage` -> Opus -> stored note -> playback.
 *
 * Notes move Queued -> Sent once the mesh accepts the payload, and are marked
 * Delivered with the observed hop count on the receiving side (or if the mesh
 * ever echoes our own payload back as a receipt).
 *
 * The pipeline never throws at the mesh callback: malformed payloads are
 * dropped, and playback failures leave the note on disk. Clips are capped at
 * 15 s by [AudioConfig.MAX_CLIP_SAMPLES] before any encoding happens.
 */
class VoicePipeline(
    private val notes: NoteSink,
    private val clips: ClipSource,
    private val playback: ClipPlayback,
    private val scope: CoroutineScope,
    private val codecFactory: () -> OpusClipCodec = { OpusClipCodec() },
    private val clock: () -> Long = System::currentTimeMillis,
    /** Local policy hook: muted/blocked peers never reach storage or playback. */
    private val shouldAccept: (MeshMessage) -> Boolean = { true },
    /** Display name for a verified sender, resolved from the nearby peer list. */
    private val senderLabel: (MeshMessage) -> String = { "Peer ${it.senderId.take(4)}" },
    /** Nearby traffic is public; do not play a stranger's clip unprompted. */
    private val autoPlayReceived: (MeshMessage) -> Boolean = { true },
) {
    private val lock = Any()
    private val sendMutex = Mutex()
    private val playbackMutex = Mutex()

    private var port: MeshPort? = null
    private var subscription: AutoCloseable? = null

    private val _playingNoteId = MutableStateFlow<String?>(null)
    val playingNoteId: StateFlow<String?> = _playingNoteId.asStateFlow()

    /** Published payloads from this process, used to recognise a delivery echo. */
    private val outgoing = LinkedHashMap<Int, Outgoing>()

    /** Subscribes to [port] deliveries and replaces any previous subscription. */
    fun attach(port: MeshPort) {
        synchronized(lock) {
            subscription?.close()
            this.port = port
            subscription = port.onMessage { message -> scope.launch { receive(message) } }
        }
    }

    /**
     * Encodes [pcm], stores the payload locally, then publishes it.
     *
     * Returns the new note in Queued state when the mesh is unavailable; the
     * next [retryQueued] hands it over. Returns a failure for empty clips,
     * clips longer than 15 s, or an encoder/storage error.
     */
    suspend fun publish(
        channelId: String,
        alias: String,
        pcm: ShortArray,
        peaks: List<Float> = emptyList(),
    ): Result<VoiceNote> {
        if (pcm.isEmpty()) {
            return Result.failure(IllegalArgumentException("Cannot publish an empty clip"))
        }
        if (pcm.size > AudioConfig.MAX_CLIP_SAMPLES) {
            return Result.failure(
                IllegalArgumentException("Clips are capped at ${AudioConfig.MAX_CLIP_DURATION_MS / 1000} s"),
            )
        }

        val clip = runCatching { codecFactory().encode(pcm) }.getOrElse { return Result.failure(it) }
        val payload = clip.toPayload()

        val file = clips.newFile()
        val stored = runCatching { file.writeBytes(payload) }
        if (stored.isFailure) {
            runCatching { file.delete() }
            return Result.failure(stored.exceptionOrNull() ?: IllegalStateException("Could not save clip"))
        }

        val note = VoiceNote(
            id = UUID.randomUUID().toString(),
            channelId = channelId,
            senderAlias = alias,
            fileName = file.name,
            durationMs = clip.durationMs.toLong(),
            sizeBytes = payload.size.toLong(),
            peaks = peaks.ifEmpty { waveformPeaks(pcm) },
            hopCount = 0,
            outgoing = true,
            state = NoteState.Queued,
            createdAt = clock(),
        )
        notes.add(note)
        remember(note.id, payload)
        return Result.success(send(note, payload))
    }

    /** Re-publishes every note still Queued, for example after the mesh starts. */
    suspend fun retryQueued() {
        val queued = notes.all().filter { it.outgoing && it.state == NoteState.Queued }
        for (note in queued) {
            val file = clips.resolve(note.fileName) ?: continue
            val payload = runCatching { file.readBytes() }.getOrNull() ?: continue
            remember(note.id, payload)
            send(note, payload)
        }
    }

    /** Decodes a stored note and plays it. Returns a failure for missing/corrupt clips. */
    suspend fun play(note: VoiceNote): Result<Unit> {
        val file = clips.resolve(note.fileName)
            ?: return Result.failure(IllegalStateException("That clip is missing from this phone"))
        val clip = runCatching { EncodedAudioClip.fromPayload(file.readBytes()) }
            .getOrElse { return Result.failure(it) }
        return playClip(note.id, clip)
    }

    fun stopPlayback() {
        playback.stop()
        _playingNoteId.value = null
    }

    /**
     * Handles one verified mesh delivery. Runs on the pipeline scope, so it may
     * decode and write files; the mesh callback itself only launches this.
     */
    suspend fun receive(message: MeshMessage) {
        if (!shouldAccept(message)) return
        val payload = message.payload.copyOf()

        // A mesh-level receipt/echo for a note we published: upgrade its state
        // instead of listing a second, incoming copy.
        outgoingFor(payload)?.let { noteId ->
            notes.updateDelivery(noteId, NoteState.Delivered, message.hopCount)
            return
        }

        val clip = runCatching { EncodedAudioClip.fromPayload(payload) }.getOrNull() ?: return

        val file = clips.newFile()
        val stored = runCatching { file.writeBytes(payload) }
        if (stored.isFailure) {
            runCatching { file.delete() }
            return
        }

        val pcm = runCatching { codecFactory().decode(clip) }.getOrNull()
        val note = VoiceNote(
            id = UUID.randomUUID().toString(),
            channelId = message.channel.hex,
            senderAlias = senderLabel(message),
            fileName = file.name,
            durationMs = clip.durationMs.toLong(),
            sizeBytes = payload.size.toLong(),
            peaks = pcm?.let { waveformPeaks(it) } ?: emptyList(),
            hopCount = message.hopCount,
            outgoing = false,
            state = NoteState.Delivered,
            createdAt = clock(),
            senderFingerprint = message.senderFingerprint,
        )
        notes.add(note)
        if (autoPlayReceived(message)) playClip(note.id, clip)
    }

    private suspend fun send(note: VoiceNote, payload: ByteArray): VoiceNote {
        val active = synchronized(lock) { port } ?: return note
        val accepted = sendMutex.withLock {
            try {
                active.publish(note.channelId, payload)
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (_: Exception) {
                false
            }
        }
        if (!accepted) return note

        notes.updateDelivery(note.id, NoteState.Sent, note.hopCount)
        return note.copy(state = NoteState.Sent)
    }

    private suspend fun playClip(noteId: String, clip: EncodedAudioClip): Result<Unit> =
        playbackMutex.withLock {
            _playingNoteId.value = noteId
            try {
                playback.play(clip)
                Result.success(Unit)
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (error: Exception) {
                Result.failure(error)
            } finally {
                if (_playingNoteId.value == noteId) _playingNoteId.value = null
            }
        }

    private fun remember(noteId: String, payload: ByteArray) {
        synchronized(lock) {
            outgoing[payload.contentHashCode()] = Outgoing(noteId, payload.copyOf())
            while (outgoing.size > MAX_TRACKED_OUTGOING) {
                val oldest = outgoing.keys.firstOrNull() ?: break
                outgoing.remove(oldest)
            }
        }
    }

    private fun outgoingFor(payload: ByteArray): String? = synchronized(lock) {
        val entry = outgoing[payload.contentHashCode()] ?: return null
        if (!entry.payload.contentEquals(payload)) return null
        entry.noteId
    }

    private class Outgoing(val noteId: String, val payload: ByteArray)

    private companion object {
        const val MAX_TRACKED_OUTGOING = 32
    }
}
