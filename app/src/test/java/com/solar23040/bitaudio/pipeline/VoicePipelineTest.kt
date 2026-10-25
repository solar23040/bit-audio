package com.solar23040.bitaudio.pipeline

import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.DefaultCrypto
import com.bitaudio.crypto.IdentityManager
import com.bitaudio.crypto.InMemorySecretStore
import com.meshvoice.audio.AudioCodec
import com.meshvoice.audio.AudioConfig
import com.meshvoice.audio.EncodedAudioClip
import com.meshvoice.audio.OpusClipCodec
import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.LinkConfig
import com.solar23040.bitaudio.data.NoteState
import com.solar23040.bitaudio.data.VoiceNote
import com.solar23040.bitaudio.mesh.ChannelId
import com.solar23040.bitaudio.mesh.MeshMessage
import com.solar23040.bitaudio.mesh.node.InMemoryPacketStore
import com.solar23040.bitaudio.mesh.node.MeshChannel
import com.solar23040.bitaudio.mesh.node.MeshConfig
import com.solar23040.bitaudio.mesh.node.MeshNode
import com.solar23040.bitaudio.transport.MeshPort
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.util.UUID
import kotlin.math.PI
import kotlin.math.sin
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Full voice pipeline over the in-memory network: node 1 records, Opus-encodes,
 * and publishes; the clip crosses node 2 and appears (and plays) on node 3.
 *
 * The codec is a lossless PCM stand-in so the assertions can compare samples
 * exactly; every other step is the production path (`OpusClipCodec` framing,
 * mesh encryption/signature/reassembly, `VoicePipeline` note handling).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class VoicePipelineTest {

    private val directories = mutableListOf<File>()

    @After
    fun cleanUp() {
        directories.forEach { dir -> dir.deleteRecursively() }
    }

    @Test
    fun clipPublishedOnNodeOnePlaysOnNodeThree() = runTest {
        val world = threeNodeLine()
        val senderClips = TestClips(newDirectory())
        val receiverClips = TestClips(newDirectory())

        val senderNotes = TestNotes()
        val senderPipeline = VoicePipeline(
            notes = senderNotes,
            clips = senderClips,
            playback = TestPlayback(),
            scope = backgroundScope,
            codecFactory = ::testCodec,
        )
        senderPipeline.attach(NodePort(world.mesh("n1")))

        val receiverNotes = TestNotes()
        val receiverPlayback = TestPlayback()
        val receiverPipeline = VoicePipeline(
            notes = receiverNotes,
            clips = receiverClips,
            playback = receiverPlayback,
            scope = backgroundScope,
            codecFactory = ::testCodec,
        )
        receiverPipeline.attach(NodePort(world.mesh("n3")))

        val pcm = sineWave(durationMs = 1_000)
        val published = senderPipeline.publish(world.channelHex, "Alice", pcm)

        // The publish call returns as soon as the mesh has accepted the payload.
        assertTrue(published.isSuccess)
        assertEquals(NoteState.Sent, published.getOrThrow().state)

        drain()

        // Node 1 keeps exactly its outgoing note. A peer's store-and-forward
        // hand-off can echo the payload back, which the pipeline treats as a
        // receipt; both Sent and Delivered are valid sender states here.
        val outgoing = senderNotes.items.single()
        assertTrue(outgoing.outgoing)
        assertTrue(
            "unexpected sender state ${outgoing.state}",
            outgoing.state == NoteState.Sent || outgoing.state == NoteState.Delivered,
        )

        // Node 3 received one note, marked Delivered with the relay hop count.
        val incoming = receiverNotes.items.single()
        assertFalse(incoming.outgoing)
        assertEquals(NoteState.Delivered, incoming.state)
        assertEquals(world.channelHex, incoming.channelId)
        assertEquals(1, incoming.hopCount)
        assertEquals(1_000L, incoming.durationMs)
        assertTrue(incoming.sizeBytes > 0)
        assertEquals(48, incoming.peaks.size)

        // The payload stored on node 3 is a complete, decodable clip.
        val stored = receiverClips.resolve(incoming.fileName)
        assertNotNull("stored clip is missing", stored)
        val decoded = testCodec().decode(EncodedAudioClip.fromPayload(requireNotNull(stored).readBytes()))
        assertArrayEquals(pcm, decoded)

        // And it was auto-played, with the same samples.
        val playedPcm = testCodec().decode(receiverPlayback.played.single())
        assertArrayEquals(pcm, playedPcm)
    }

    @Test
    fun clipQueuedWhileMeshIsDownIsPublishedWhenItStarts() = runTest {
        val world = threeNodeLine()
        val notes = TestNotes()
        val pipeline = VoicePipeline(
            notes = notes,
            clips = TestClips(newDirectory()),
            playback = TestPlayback(),
            scope = backgroundScope,
            codecFactory = ::testCodec,
        )

        // No port attached yet, as when the foreground service is not running.
        val queued = pipeline.publish(
            channelId = world.channelHex,
            alias = "Me",
            pcm = sineWave(durationMs = 200),
        )

        assertTrue(queued.isSuccess)
        assertEquals(NoteState.Queued, queued.getOrThrow().state)
        assertEquals(NoteState.Queued, notes.items.single().state)

        pipeline.attach(NodePort(world.mesh("n1")))
        pipeline.retryQueued()

        assertEquals(NoteState.Sent, notes.items.single().state)
    }

    @Test
    fun clipsLongerThanFifteenSecondsAreRejectedBeforeEncoding() = runTest {
        val clips = TestClips(newDirectory())
        val notes = TestNotes()
        val pipeline = VoicePipeline(
            notes = notes,
            clips = clips,
            playback = TestPlayback(),
            scope = backgroundScope,
            codecFactory = ::testCodec,
        )

        val tooLong = sineWave(durationMs = AudioConfig.MAX_CLIP_DURATION_MS + 20)

        val result = pipeline.publish("0123456789abcdef", "Me", tooLong)

        assertTrue(result.isFailure)
        assertTrue(notes.items.isEmpty())
        assertEquals(0, clips.directory.listFiles()?.size ?: 0)
    }

    // --- fixtures -----------------------------------------------------------

    private class World(
        val channelHex: String,
        private val nodes: Map<String, MeshNode>,
    ) {
        fun mesh(id: String): MeshNode = nodes.getValue(id)
    }

    private fun TestScope.threeNodeLine(): World {
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            externalScope = backgroundScope,
        )
        val ids = listOf("n1", "n2", "n3")
        val transports = ids.associateWith { network.addNode(it) }
        val cryptos = ids.associateWith {
            DefaultCrypto(IdentityManager(InMemorySecretStore()))
        }

        val key = ChannelKeys.generate()
        val channelId = ChannelId.fromBytes(ChannelKeys.channelId(key))
        val roster = cryptos.values.map { it.publicKey }

        val meshes = transports.mapValues { (id, transport) ->
            val crypto = cryptos.getValue(id)
            MeshNode(
                transport = transport,
                crypto = crypto,
                localPublicKey = crypto.publicKey,
                config = MeshConfig(rebroadcastJitterMs = 0L..0L),
                store = InMemoryPacketStore(),
                externalScope = backgroundScope,
            )
        }
        meshes.values.forEach { mesh ->
            mesh.addChannel(MeshChannel(id = channelId, key = key, members = roster, ttl = 5))
            mesh.start()
        }

        network.connect(transports.getValue("n1"), transports.getValue("n2"))
        network.connect(transports.getValue("n2"), transports.getValue("n3"))

        return World(channelId.hex, meshes)
    }

    /**
     * Runs the immediate tasks created by transport, mesh and pipeline. There is
     * no jitter or latency in this fixture, so no virtual time needs advancing;
     * `advanceUntilIdle` is avoided because the mesh keeps a 30 s maintenance
     * timer alive for as long as the test runs.
     */
    private fun TestScope.drain() {
        repeat(50) { runCurrent() }
    }

    private class NodePort(private val mesh: MeshNode) : MeshPort {
        override suspend fun publish(channelId: String, payload: ByteArray): Boolean =
            runCatching { mesh.publish(ChannelId.fromHex(channelId), payload) }.isSuccess

        override fun onMessage(callback: (MeshMessage) -> Unit): AutoCloseable =
            mesh.onMessage(callback)
    }

    private class TestNotes : NoteSink {
        val items = mutableListOf<VoiceNote>()

        override fun add(note: VoiceNote) {
            items += note
        }

        override fun all(): List<VoiceNote> = items.toList()

        override fun updateDelivery(id: String, state: NoteState, hopCount: Int) {
            val index = items.indexOfFirst { it.id == id }
            if (index >= 0) items[index] = items[index].copy(state = state, hopCount = hopCount)
        }
    }

    private class TestClips(val directory: File) : ClipSource {
        override fun newFile(): File = File(directory, "${UUID.randomUUID()}.opus")

        override fun resolve(fileName: String): File? =
            File(directory, fileName).takeIf { it.isFile }
    }

    private class TestPlayback : ClipPlayback {
        val played = mutableListOf<EncodedAudioClip>()

        override suspend fun play(clip: EncodedAudioClip) {
            played += clip
        }

        override fun stop() = Unit
    }

    /** Lossless PCM16 codec: the pipeline still uses the real clip framing. */
    private class TestCodec : AudioCodec {
        override fun encode(pcm: ShortArray): ByteArray {
            val buffer = ByteBuffer.allocate(pcm.size * 2).order(ByteOrder.LITTLE_ENDIAN)
            pcm.forEach { buffer.putShort(it) }
            return buffer.array()
        }

        override fun decode(packet: ByteArray): ShortArray {
            val buffer = ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN)
            return ShortArray(packet.size / 2) { buffer.short }
        }

        override fun close() = Unit
    }

    private fun testCodec(): OpusClipCodec = OpusClipCodec(codecFactory = { TestCodec() })

    private fun newDirectory(): File {
        val dir = Files.createTempDirectory("voice-pipeline").toFile()
        directories += dir
        return dir
    }

    private fun sineWave(durationMs: Int): ShortArray {
        val samples = AudioConfig.SAMPLE_RATE_HZ * durationMs / 1_000
        return ShortArray(samples) { index ->
            (sin(2.0 * PI * 440.0 * index / AudioConfig.SAMPLE_RATE_HZ) * 12_000).toInt().toShort()
        }
    }
}
