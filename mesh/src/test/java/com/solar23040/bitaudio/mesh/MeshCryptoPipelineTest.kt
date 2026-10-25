package com.solar23040.bitaudio.mesh

import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.DefaultCrypto
import com.bitaudio.crypto.IdentityManager
import com.bitaudio.crypto.InMemorySecretStore
import com.bitaudio.crypto.PacketCrypto
import com.bitaudio.crypto.RotatingSenderId
import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.FakeTransport
import com.meshvoice.transport.LinkConfig
import com.meshvoice.transport.Peer
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * End-to-end pipeline tests on [FakeNetwork]. Four nodes in a line:
 * a - b - c - d, so d is three links (two relays) away from a.
 */
class MeshCryptoPipelineTest {

    @Test
    fun `tampered packet is not relayed or delivered`() = runTest {
        val harness = Harness(this)
        val valid = harness.buildPacket(payload = ByteArray(48) { 7 })
        val tampered = valid.copyOf()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 0x01).toByte()

        harness.nodes.getValue("a").send(Peer("b"), tampered)
        advanceUntilIdle()

        assertTrue(harness.rawFrames.getValue("c").isEmpty())
        assertTrue(harness.rawFrames.getValue("d").isEmpty())
        assertTrue(harness.deliveries.values.all { it.isEmpty() })
    }

    @Test
    fun `replayed packet is rejected`() = runTest {
        val harness = Harness(this)
        val packet = harness.buildPacket(payload = ByteArray(64) { 3 })

        harness.nodes.getValue("a").send(Peer("b"), packet)
        advanceUntilIdle()
        assertEquals(1, harness.deliveries.getValue("d").size)
        assertEquals(1, harness.rawFrames.getValue("c").size)

        harness.nodes.getValue("a").send(Peer("b"), packet)
        advanceUntilIdle()

        assertEquals(1, harness.deliveries.getValue("d").size)
        assertEquals(1, harness.rawFrames.getValue("c").size)
    }

    @Test
    fun `payload sealed with the wrong channel key is not delivered`() = runTest {
        val harness = Harness(this)
        // Real channel ID and real signing identity, but the payload is sealed
        // under a different channel key, so AEAD open fails after verification.
        val packet = harness.buildPacket(
            sealKey = ChannelKeys.generate(),
            payload = ByteArray(64) { 9 },
        )

        harness.nodes.getValue("a").send(Peer("b"), packet)
        advanceUntilIdle()

        assertTrue(harness.deliveries.values.all { it.isEmpty() })
        assertTrue(harness.rawFrames.getValue("c").isEmpty())
        assertTrue(harness.rawFrames.getValue("d").isEmpty())
    }

    @Test
    fun `valid packet crosses three hops and reassembles`() = runTest {
        val harness = Harness(this)
        val payload = ByteArray(800) { index -> (index * 31 and 0xFF).toByte() }

        harness.meshes.getValue("a").publish(harness.channel.channelId, payload)
        advanceUntilIdle()

        // b and c are relays but also channel members, so they deliver locally too.
        assertEquals(1, harness.deliveries.getValue("b").size)
        assertEquals(1, harness.deliveries.getValue("c").size)
        assertEquals(1, harness.deliveries.getValue("d").size)

        val received = harness.deliveries.getValue("d").single()
        assertEquals(harness.channel.channelId, received.channel)
        assertArrayEquals(payload, received.payload)
        // a -> b -> c -> d is three links, two TTL decrements after the origin.
        assertEquals(2, received.hopCount)

        val expectedSenderId = RotatingSenderId.derive(
            harness.channelKey,
            harness.cryptos.getValue("a").publicKey,
            received.timestampMs / 1000,
        ).toHexString()
        assertEquals(expectedSenderId, received.senderId)
    }

    private class Harness(scope: TestScope) {
        private val ids = listOf("a", "b", "c", "d")

        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            seed = 42L,
            externalScope = scope.backgroundScope,
        )
        val nodes: Map<String, FakeTransport> = ids.associateWith { network.addNode(it) }
        val cryptos: Map<String, DefaultCrypto> = ids.associateWith {
            DefaultCrypto(IdentityManager(InMemorySecretStore()))
        }
        val channelKey: ByteArray = ChannelKeys.generate()
        val channel = MeshChannel(channelKey, cryptos.values.map { it.publicKey })
        val deliveries: Map<String, MutableList<MeshMessage>> =
            ids.associateWith { CopyOnWriteArrayList<MeshMessage>() }
        val rawFrames: Map<String, MutableList<ByteArray>> =
            ids.associateWith { CopyOnWriteArrayList<ByteArray>() }
        val meshes: Map<String, MeshEngine>

        init {
            ids.zipWithNext { left, right ->
                network.connect(
                    nodes.getValue(left),
                    nodes.getValue(right),
                    LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
                )
            }

            val config = MeshConfig(
                defaultTtl = 5,
                jitterMs = 1L..5L,
                perSenderRate = RateLimit(perSecond = 10_000.0, burst = 20_000.0),
                perNeighbourRate = RateLimit(perSecond = 10_000.0, burst = 20_000.0),
            )
            meshes = ids.associateWith { id ->
                MeshEngine(
                    transport = nodes.getValue(id),
                    crypto = cryptos.getValue(id),
                    localPublicKey = cryptos.getValue(id).publicKey,
                    initialChannels = listOf(channel),
                    config = config,
                    // Relay jobs run on the foreground test scope so
                    // advanceUntilIdle() drains every hop.
                    externalScope = scope,
                )
            }

            for (id in ids) {
                meshes.getValue(id).onMessage { message -> deliveries.getValue(id).add(message) }
                nodes.getValue(id).onReceive { frame -> rawFrames.getValue(id).add(frame.bytes) }
            }
        }

        /** Crafts a protocol-valid packet as a channel member would. */
        fun buildPacket(
            signer: String = "a",
            sealKey: ByteArray = channelKey,
            senderIdChannelKey: ByteArray = channelKey,
            payload: ByteArray = ByteArray(32) { 0x42 },
            messageId: ByteArray = ByteArray(8) { 0x11 },
            counter: Long = 1,
            ttl: Int = 5,
            totalChunks: Int = 1,
            chunkIndex: Int = 0,
            timestampMs: Long = System.currentTimeMillis(),
        ): ByteArray {
            val crypto = cryptos.getValue(signer)
            val senderId = RotatingSenderId.derive(
                senderIdChannelKey,
                crypto.publicKey,
                timestampMs / 1000,
            )
            val header = MeshPacketHeader(
                type = MeshPacketCodec.TYPE_VOICE_DATA,
                messageId = messageId,
                channelId = channel.channelId,
                senderId = senderId,
                ttl = ttl,
                chunkIndex = chunkIndex,
                totalChunks = totalChunks,
                timestampMs = timestampMs,
                counter = counter,
            )
            val canonical = MeshPacketCodec.headerBytes(header.copy(ttl = 0))
            val sealed = PacketCrypto.sealPayload(crypto, sealKey, canonical, payload)
            val signature = PacketCrypto.signPacket(crypto, canonical, sealed)
            return MeshPacketCodec.encode(header, signature, sealed)
        }
    }
}
