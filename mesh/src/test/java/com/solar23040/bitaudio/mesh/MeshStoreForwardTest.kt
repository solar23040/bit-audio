package com.solar23040.bitaudio.mesh

import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.DefaultCrypto
import com.bitaudio.crypto.IdentityManager
import com.bitaudio.crypto.InMemorySecretStore
import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.FakeTransport
import com.meshvoice.transport.LinkConfig
import com.solar23040.bitaudio.mesh.store.InMemoryMeshStore
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Integration tests for the Phase 2 BLE seam: a ~15 KB clip must fit the
 * 512-byte mesh frame limit, and a clip recorded while offline must be handed to
 * the first neighbour that appears without being re-flooded.
 */
class MeshStoreForwardTest {

    @Test
    fun `15 KB clip is split into frames of at most 512 bytes and reassembles`() = runTest {
        val harness = Harness(this, listOf("a", "b"))
        try {
            harness.network.connect("a", "b")
            advanceUntilIdle()
            val payload = ByteArray(15 * 1024) { index -> (index * 37 and 0xFF).toByte() }

            harness.meshes.getValue("a").publish(harness.channel.channelId, payload)
            advanceUntilIdle()

            val expectedChunks =
                (payload.size + MeshPacketCodec.MAX_CHUNK_PLAINTEXT - 1) /
                    MeshPacketCodec.MAX_CHUNK_PLAINTEXT
            val frames = harness.rawFrames.getValue("b")
            assertEquals(expectedChunks, frames.size)
            assertTrue(frames.all { it.size in 107..MeshPacketCodec.MAX_PACKET_SIZE })
            assertEquals(MeshPacketCodec.MAX_PACKET_SIZE, frames.maxOf { it.size })

            val delivered = harness.deliveries.getValue("b").single()
            assertArrayEquals(payload, delivered.payload)
            assertEquals(expectedChunks, harness.stores.getValue("a").size())
            assertEquals(expectedChunks, harness.stores.getValue("b").size())
        } finally {
            harness.closeAll()
        }
    }

    @Test
    fun `offline publish is handed off when a neighbour appears and does not flood`() = runTest {
        val harness = Harness(this, listOf("a", "b", "c"))
        try {
            // a is isolated; b can reach c.
            harness.network.connect("b", "c")
            advanceUntilIdle()
            val payload = ByteArray(15 * 1024) { index -> (index * 11 and 0xFF).toByte() }
            val expectedChunks =
                (payload.size + MeshPacketCodec.MAX_CHUNK_PLAINTEXT - 1) /
                    MeshPacketCodec.MAX_CHUNK_PLAINTEXT

            harness.meshes.getValue("a").publish(harness.channel.channelId, payload)
            advanceUntilIdle()

            assertEquals(expectedChunks, harness.stores.getValue("a").size())
            assertTrue(harness.deliveries.getValue("b").isEmpty())
            assertTrue(harness.deliveries.getValue("c").isEmpty())

            harness.network.connect("a", "b")
            advanceUntilIdle()

            val delivered = harness.deliveries.getValue("b").single()
            assertArrayEquals(payload, delivered.payload)
            // Replay is handed off with TTL 1, so b delivers locally but does not
            // relay to c, and stored frames were re-verified before sending.
            assertTrue(harness.rawFrames.getValue("c").isEmpty())
            assertTrue(harness.deliveries.getValue("c").isEmpty())
            assertTrue(
                harness.rawFrames.getValue("b").all { frame ->
                    MeshPacketCodec.decode(frame)?.header?.ttl == 1
                },
            )
            assertEquals(expectedChunks, harness.stores.getValue("b").size())
        } finally {
            harness.closeAll()
        }
    }

    @Test
    fun `persisted counter keeps increasing across engine restarts`() = runTest {
        val harness = Harness(this, listOf("a"))
        try {
            val store = harness.stores.getValue("a")
            val first = harness.meshes.getValue("a")
            first.publish(harness.channel.channelId, ByteArray(32) { 1 })
            advanceUntilIdle()

            val firstFrame = store.loadUnexpired(System.currentTimeMillis()).single()
            val firstCounter =
                requireNotNull(MeshPacketCodec.decode(firstFrame.frame)).header.counter
            first.close()

            val second = harness.newEngine("a")
            second.publish(harness.channel.channelId, ByteArray(32) { 2 })
            advanceUntilIdle()

            val secondFrame = store.loadUnexpired(System.currentTimeMillis())
                .single { it.messageId != firstFrame.messageId }
            val secondCounter =
                requireNotNull(MeshPacketCodec.decode(secondFrame.frame)).header.counter
            assertEquals(firstCounter + 1, secondCounter)
            second.close()
        } finally {
            harness.closeAll()
        }
    }

    private class Harness(private val testScope: TestScope, ids: List<String>) {
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            seed = 42L,
            externalScope = testScope.backgroundScope,
        )
        val nodes: Map<String, FakeTransport> = ids.associateWith { network.addNode(it) }
        val cryptos: Map<String, DefaultCrypto> = ids.associateWith {
            DefaultCrypto(IdentityManager(InMemorySecretStore()))
        }
        val channelKey: ByteArray = ChannelKeys.generate()
        val channel = MeshChannel(channelKey, cryptos.values.map { it.publicKey })
        val stores: Map<String, InMemoryMeshStore> = ids.associateWith { InMemoryMeshStore() }
        val deliveries: Map<String, MutableList<MeshMessage>> =
            ids.associateWith { CopyOnWriteArrayList<MeshMessage>() }
        val rawFrames: Map<String, MutableList<ByteArray>> =
            ids.associateWith { CopyOnWriteArrayList<ByteArray>() }
        val meshes: Map<String, MeshEngine> = ids.associateWith { createEngine(it) }

        init {
            for (id in ids) {
                meshes.getValue(id).onMessage { message -> deliveries.getValue(id).add(message) }
                nodes.getValue(id).onReceive { frame -> rawFrames.getValue(id).add(frame.bytes) }
            }
        }

        fun newEngine(id: String): MeshEngine = createEngine(id)

        private fun createEngine(id: String): MeshEngine = MeshEngine(
            transport = nodes.getValue(id),
            crypto = cryptos.getValue(id),
            localPublicKey = cryptos.getValue(id).publicKey,
            initialChannels = listOf(channel),
            config = MeshConfig(
                defaultTtl = 5,
                jitterMs = 1L..5L,
                perSenderRate = RateLimit(perSecond = 10_000.0, burst = 20_000.0),
                perNeighbourRate = RateLimit(perSecond = 10_000.0, burst = 20_000.0),
            ),
            externalScope = testScope,
            store = stores.getValue(id),
        )

        fun closeAll() {
            meshes.values.forEach { it.close() }
        }
    }
}
