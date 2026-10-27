package com.solar23040.bitaudio

import android.content.Context
import android.os.SystemClock
import com.bitaudio.crypto.NearbyChannel
import com.meshvoice.audio.ClipPlayer
import com.meshvoice.audio.EncodedAudioClip
import com.meshvoice.audio.VoiceRecorder
import com.solar23040.bitaudio.audio.RecordedClip
import com.solar23040.bitaudio.data.Channel
import com.solar23040.bitaudio.data.ChannelRepository
import com.solar23040.bitaudio.data.ClipStore
import com.solar23040.bitaudio.data.NoteRepository
import com.solar23040.bitaudio.data.PeerPreferencesRepository
import com.solar23040.bitaudio.data.SettingsRepository
import com.solar23040.bitaudio.data.VoiceNote
import com.solar23040.bitaudio.invite.ChannelIdCodec
import com.solar23040.bitaudio.invite.ChannelInviteData
import com.solar23040.bitaudio.mesh.MeshMessage
import com.solar23040.bitaudio.pipeline.ClipPlayback
import com.solar23040.bitaudio.pipeline.VoicePipeline
import com.solar23040.bitaudio.transport.MeshRuntime
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

    val recorder = VoiceRecorder()
    val player = ClipPlayer()

    private val _nearbyChannelId = MutableStateFlow(NearbyChannel.channelIdHex)

    /** Public nearby channel every install shares. */
    val nearbyChannelId: StateFlow<String> = _nearbyChannelId.asStateFlow()

    /**
     * Real BLE transport + mesh. Nothing else in `:app` constructs transport or
     * mesh objects directly; the foreground service only sees [MeshRuntime].
     */
    val runtime: MeshRuntime = BleMeshRuntime(appContext, channels, scope)

    /** Record -> Opus -> publish, and receive -> Opus -> note -> playback. */
    val pipeline = VoicePipeline(
        notes = notes,
        clips = clips,
        playback = object : ClipPlayback {
            override suspend fun play(clip: EncodedAudioClip) {
                withContext(Dispatchers.IO) { player.play(clip) }
            }

            override fun stop() = player.stop()
        },
        scope = scope,
        shouldAccept = { message -> !peerPrefs.isSuppressed(message.senderFingerprint) },
        senderLabel = { message -> labelFor(message) },
        // Nearby is a public feed: new clips appear in the list but do not
        // start playing over whatever the user is already listening to.
        autoPlayReceived = { message -> message.channel.hex != _nearbyChannelId.value },
    )

    init {
        runtime.setNickname(settings.current.displayName)
        // Do not announce the default "Me" name before onboarding.
        runtime.setDiscoverable(settings.current.onboarded && settings.current.discoverable)
        pipeline.attach(runtime)
        runtime.onReady { scope.launch { pipeline.retryQueued() } }
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
     * Encodes a finished hold-to-talk clip with Opus, stores the payload, and
     * publishes it through the mesh. The note is Queued until `Mesh.publish`
     * accepts it, then Sent; a matching mesh delivery marks it Delivered.
     */
    suspend fun addRecordedNote(channel: Channel, clip: RecordedClip): Result<VoiceNote> =
        withContext(Dispatchers.IO) {
            pipeline.publish(channel.id, channel.alias, clip.pcm, clip.peaks)
        }

    /** Publishes a public hold-to-talk clip on the nearby channel. */
    suspend fun addNearbyRecordedNote(clip: RecordedClip): Result<VoiceNote> =
        withContext(Dispatchers.IO) {
            pipeline.publish(
                channelId = _nearbyChannelId.value,
                alias = settings.current.displayName,
                pcm = clip.pcm,
                peaks = clip.peaks,
            )
        }

    /** Plays a stored note (local or received); the pipeline reports the playing note ID. */
    suspend fun playNote(note: VoiceNote): Result<Unit> = pipeline.play(note)

    fun stopPlayback() = pipeline.stopPlayback()

    val playingNoteId: StateFlow<String?> get() = pipeline.playingNoteId

    fun cancelActiveRecording() {
        scope.launch { recorder.cancel() }
    }

    fun recordingElapsedMs(startedAtElapsedRealtime: Long): Long =
        (SystemClock.elapsedRealtime() - startedAtElapsedRealtime).coerceAtLeast(0L)

    private fun labelFor(message: MeshMessage): String {
        val fingerprint = message.senderFingerprint
        if (fingerprint.isNotEmpty()) {
            runtime.nearbyPeers.value
                .firstOrNull { it.fingerprint == fingerprint }
                ?.let { peer -> return peer.nickname }
            return "Peer ${fingerprint.take(6)}"
        }
        return "Peer ${message.senderId.take(4)}"
    }
}
