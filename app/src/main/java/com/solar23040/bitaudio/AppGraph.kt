package com.solar23040.bitaudio

import android.content.Context
import android.os.SystemClock
import com.bitaudio.crypto.NearbyChannel
import com.meshvoice.audio.AudioConfig
import com.meshvoice.audio.ClipPlayer
import com.meshvoice.audio.EncodedAudioClip
import com.meshvoice.audio.OpusClipCodec
import com.solar23040.bitaudio.audio.PreviewPlayer
import com.solar23040.bitaudio.audio.PreviewRecorder
import com.solar23040.bitaudio.audio.RecordedClip
import com.solar23040.bitaudio.data.Channel
import com.solar23040.bitaudio.data.ChannelRepository
import com.solar23040.bitaudio.data.ClipStore
import com.solar23040.bitaudio.data.NoteRepository
import com.solar23040.bitaudio.data.NoteState
import com.solar23040.bitaudio.data.PeerPreferencesRepository
import com.solar23040.bitaudio.data.SettingsRepository
import com.solar23040.bitaudio.data.VoiceNote
import com.solar23040.bitaudio.invite.ChannelIdCodec
import com.solar23040.bitaudio.invite.ChannelInviteData
import com.solar23040.bitaudio.mesh.MeshMessage
import com.solar23040.bitaudio.transport.MeshRuntime
import com.solar23040.bitaudio.util.AudioPayload
import java.io.File
import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppGraph(context: Context) {
    private val appContext = context.applicationContext
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    val settings = SettingsRepository(appContext)
    val peerPrefs = PeerPreferencesRepository(appContext)
    val channels = ChannelRepository(appContext, scope)
    val notes = NoteRepository(appContext, scope)
    val clips = ClipStore(appContext)

    val recorder = PreviewRecorder()
    private val wavPlayer = PreviewPlayer()
    private val opusPlayer = ClipPlayer()

    /**
     * Real BLE transport + mesh. Nothing else in `:app` constructs transport or
     * mesh objects directly; the foreground service only sees [MeshRuntime].
     */
    val runtime: MeshRuntime = BleMeshRuntime(appContext, channels, scope)

    private val _nearbyChannelId = MutableStateFlow(NearbyChannel.channelIdHex)
    val nearbyChannelId: StateFlow<String> = _nearbyChannelId.asStateFlow()

    init {
        runtime.setNickname(settings.current.displayName)
        // Do not announce the default "Me" name before onboarding.
        runtime.setDiscoverable(settings.current.onboarded && settings.current.discoverable)
        runtime.onMessage { message -> scope.launch { onMeshMessage(message) } }
        scope.launch {
            val retentionMs = settings.current.retentionHours * 60L * 60L * 1000L
            val expired = notes.removeExpired(System.currentTimeMillis() - retentionMs)
            expired.forEach { clips.delete(it.fileName) }
        }
    }

    fun setNickname(nickname: String) {
        val wasOnboarded = settings.current.onboarded
        settings.setDisplayName(nickname)
        runtime.setNickname(settings.current.displayName)
        if (!wasOnboarded) runtime.setDiscoverable(settings.current.discoverable)
    }

    fun setDiscoverable(enabled: Boolean) {
        settings.setDiscoverable(enabled)
        runtime.setDiscoverable(settings.current.onboarded && enabled)
    }

    fun rotateIdentity() = runtime.rotateIdentity()

    fun createChannel(name: String, alias: String): Channel {
        val key = ChannelIdCodec.randomKey()
        val id = requireNotNull(ChannelIdCodec.derive(key)) { "Could not derive channel ID" }
        val cleanAlias = alias.trim().ifBlank { settings.current.displayName }
        val channel = Channel(
            id = id,
            name = name.trim().take(64).ifBlank { "Untitled channel" },
            key = key,
            alias = cleanAlias,
            ttl = settings.current.defaultTtl,
            createdAt = System.currentTimeMillis(),
        )
        channels.add(channel)
        settings.setDisplayName(cleanAlias)
        return channel
    }

    fun joinChannel(invite: ChannelInviteData, alias: String): Result<Channel> {
        val derived = ChannelIdCodec.derive(invite.key)
            ?: return Result.failure(IllegalArgumentException("Invalid channel key"))
        if (derived != invite.id) {
            return Result.failure(IllegalArgumentException("Invite channel ID is not valid"))
        }
        channels.get(invite.id)?.let { existing ->
            return if (existing.key == invite.key) {
                Result.success(existing)
            } else {
                Result.failure(IllegalStateException("Channel ID already exists with another key"))
            }
        }
        val cleanAlias = alias.trim().ifBlank { settings.current.displayName }
        val channel = Channel(
            id = invite.id,
            name = invite.name,
            key = invite.key,
            alias = cleanAlias,
            ttl = settings.current.defaultTtl,
            createdAt = System.currentTimeMillis(),
        )
        channels.add(channel)
        settings.setDisplayName(cleanAlias)
        return Result.success(channel)
    }

    fun deleteChannel(channel: Channel) {
        val removed = notes.deleteChannel(channel.id)
        clips.deleteChannel(removed)
        channels.remove(channel.id)
    }

    /**
     * Stores a finished private-channel clip locally and queues it for the mesh.
     * Private delivery stays disabled until roster exchange lands, so the note
     * remains Queued instead of pretending it was sent.
     */
    fun addRecordedNote(channel: Channel, clip: RecordedClip): VoiceNote {
        val note = VoiceNote(
            id = UUID.randomUUID().toString(),
            channelId = channel.id,
            senderAlias = channel.alias,
            fileName = clip.file.name,
            durationMs = clip.durationMs,
            sizeBytes = clip.file.length(),
            peaks = clip.peaks,
            hopCount = 0,
            outgoing = true,
            state = NoteState.Queued,
            createdAt = System.currentTimeMillis(),
        )
        notes.add(note)
        return note
    }

    /**
     * Publishes a hold-to-talk clip on the public nearby channel. The WAV stays
     * local for playback; the mesh gets a compact Opus payload because a WAV
     * clip is far larger than the mesh plaintext limit.
     */
    suspend fun addNearbyRecordedNote(clip: RecordedClip): VoiceNote {
        val encoded = withContext(Dispatchers.Default) {
            runCatching {
                val pcm = if (clip.pcm.size > AudioConfig.MAX_CLIP_SAMPLES) {
                    clip.pcm.copyOf(AudioConfig.MAX_CLIP_SAMPLES)
                } else {
                    clip.pcm
                }
                OpusClipCodec().payloadFor(pcm)
            }.getOrNull()
        }
        val note = VoiceNote(
            id = UUID.randomUUID().toString(),
            channelId = nearbyChannelId.value,
            senderAlias = settings.current.displayName,
            fileName = clip.file.name,
            durationMs = clip.durationMs,
            sizeBytes = encoded?.size?.toLong() ?: 0L,
            peaks = clip.peaks,
            hopCount = 0,
            outgoing = true,
            state = NoteState.Queued,
            createdAt = System.currentTimeMillis(),
        )
        notes.add(note)
        if (encoded == null || encoded.isEmpty()) {
            notes.updateState(note.id, NoteState.Failed)
            return note.copy(state = NoteState.Failed)
        }
        scope.launch {
            notes.updateState(note.id, NoteState.Sending)
            val sent = runCatching {
                runtime.publish(nearbyChannelId.value, encoded)
            }.getOrDefault(false)
            notes.updateState(note.id, if (sent) NoteState.Delivered else NoteState.Queued)
        }
        return note
    }

    private fun onMeshMessage(message: MeshMessage) {
        if (peerPrefs.isSuppressed(message.senderFingerprint)) return

        val payload = message.payload.copyOf()
        val info = AudioPayload.inspect(payload) ?: return
        val file = clips.newFile(if (AudioPayload.isWav(payload)) "wav" else "opus")
        val written = runCatching { file.writeBytes(payload) }
        if (written.isFailure) {
            runCatching { file.delete() }
            return
        }
        val fingerprint = message.senderFingerprint
        val alias = runtime.nearbyPeers.value
            .firstOrNull { it.fingerprint == fingerprint }
            ?.nickname
            ?: if (fingerprint.isNotEmpty()) "Peer ${fingerprint.take(6)}" else "Peer ${message.senderId.take(4)}"

        notes.add(
            VoiceNote(
                id = UUID.randomUUID().toString(),
                channelId = message.channel.hex,
                senderAlias = alias,
                fileName = file.name,
                durationMs = info.durationMs,
                sizeBytes = payload.size.toLong(),
                peaks = info.peaks,
                hopCount = message.hopCount,
                outgoing = false,
                state = NoteState.Delivered,
                createdAt = System.currentTimeMillis(),
                senderFingerprint = fingerprint,
            ),
        )
    }

    /** Plays a local WAV or an incoming Opus payload. */
    suspend fun playClip(file: File): Result<Unit> {
        val bytes = runCatching { file.readBytes() }.getOrElse {
            return Result.failure(it)
        }
        if (AudioPayload.isWav(bytes)) return wavPlayer.play(file)

        return withContext(Dispatchers.IO) {
            runCatching {
                val clip = EncodedAudioClip.fromPayload(bytes)
                opusPlayer.play(clip)
            }
        }
    }

    fun stopPlayback() {
        wavPlayer.stop()
        opusPlayer.stop()
    }

    fun cancelActiveRecording() {
        scope.launch { recorder.cancel() }
    }

    fun recordingElapsedMs(startedAtElapsedRealtime: Long): Long =
        (SystemClock.elapsedRealtime() - startedAtElapsedRealtime).coerceAtLeast(0L)
}
