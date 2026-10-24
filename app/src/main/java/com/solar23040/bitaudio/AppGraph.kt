package com.solar23040.bitaudio

import android.content.Context
import android.os.SystemClock
import com.solar23040.bitaudio.audio.PreviewPlayer
import com.solar23040.bitaudio.audio.PreviewRecorder
import com.solar23040.bitaudio.audio.RecordedClip
import com.solar23040.bitaudio.data.Channel
import com.solar23040.bitaudio.data.ChannelRepository
import com.solar23040.bitaudio.data.ClipStore
import com.solar23040.bitaudio.data.IdentityStore
import com.solar23040.bitaudio.data.NoteRepository
import com.solar23040.bitaudio.data.NoteState
import com.solar23040.bitaudio.data.SettingsRepository
import com.solar23040.bitaudio.data.VoiceNote
import com.solar23040.bitaudio.invite.ChannelIdCodec
import com.solar23040.bitaudio.invite.ChannelInviteData
import com.solar23040.bitaudio.transport.MeshRuntime
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.UUID

class AppGraph(context: Context) {
    private val appContext = context.applicationContext
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    val settings = SettingsRepository(appContext)
    val identity = IdentityStore(appContext)
    val channels = ChannelRepository(appContext, scope)
    val notes = NoteRepository(appContext, scope)
    val clips = ClipStore(appContext)

    init {
        scope.launch {
            val retentionMs = settings.current.retentionHours * 60L * 60L * 1000L
            val expired = notes.removeExpired(System.currentTimeMillis() - retentionMs)
            expired.forEach { clips.delete(it.fileName) }
        }
    }

    val recorder = PreviewRecorder()
    val player = PreviewPlayer()

    /**
     * Swap for the real BLE/mesh runtime in Phase 2. Nothing else in `:app`
     * constructs transport or mesh objects directly.
     */
    val runtime: MeshRuntime = OfflineMeshRuntime()

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
     * Stores a finished clip locally and queues it for the mesh.
     *
     * The Phase 2 glue calls `Mesh.publish(channelId, payload)` here and flips
     * the note to Delivered when the matching MeshMessage arrives.
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

    fun cancelActiveRecording() {
        scope.launch { recorder.cancel() }
    }

    fun recordingElapsedMs(startedAtElapsedRealtime: Long): Long =
        (SystemClock.elapsedRealtime() - startedAtElapsedRealtime).coerceAtLeast(0L)
}
