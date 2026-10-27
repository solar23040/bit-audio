package com.solar23040.bitaudio.mesh.engine

import com.bitaudio.crypto.DefaultCrypto
import com.bitaudio.crypto.IdentityManager
import com.bitaudio.crypto.InMemorySecretStore
import com.bitaudio.crypto.NearbyChannel
import com.bitaudio.crypto.PacketCrypto
import com.bitaudio.crypto.RotatingSenderId
import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.FakeTransport
import com.meshvoice.transport.LinkConfig
import com.meshvoice.transport.Peer
import com.solar23040.bitaudio.mesh.ChannelId
import com.solar23040.bitaudio.mesh.MeshMessage
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Nearby discovery over [FakeNetwork]: three nodes in a line, a - b - c, so c
 * reaches a through one relay.
 */
class NearbyAnnounceTest {

    @Test
    fun `three nodes see each other and a relayed peer reports two hops`() = runTest {
        val harness = Harness(this, listOf("a", "b", "c"))
        try {
            harness.network.connect("a", "b")
            harness.network.connect("b", "c")
            harness.start(
                nicknames = mapOf("a" to "Alice", "b" to "Bob", "c" to "Carol"),
            )
            runCurrent()

            val peersA = harness.meshes.getValue("a").peers().value
            assertEquals(setOf("Alice", "Bob", "Carol"), peersA.map { it.nickname }.toSet())
            val bob = peersA.single { it.nickname == "Bob" }
            val carol = peersA.single { it.nickname == "Carol" }
            assertEquals(1, bob.hopCount)
            assertEquals(2, carol.hopCount)
            assertTrue(bob.isDirect)
            assertTrue(!carol.isDirect)

            val peersB = harness.meshes.getValue("b").peers().value
            assertEquals(setOf("Alice", "Carol"), peersB.map { it.nickname }.toSet())
            assertTrue(peersB.all { it.hopCount == 1 })

            val peersC = harness.meshes.getValue("c").peers().value
            assertEquals(setOf("Alice", "Bob"), peersC.map { it.nickname }.toSet())
            assertEquals(2, peersC.single { it.nickname == "Alice" }.hopCount)
            assertEquals(1, peersC.single { it.nickname == "Bob" }.hopCount)
        } finally {
            harness.closeAll()
        }
    }

    @Test
    fun `quiet peer disappears after the timeout`() = runTest {
        val harness = Harness(
            this,
            listOf("a", "b"),
            config = baseConfig(
                peerTimeoutMs = 1_000L,
                peerSweepIntervalMs = 100L,
            ),
        )
        try {
            harness.network.connect("a", "b")
            harness.start(nicknames = mapOf("a" to "Alice", "b" to "Bob"))
            runCurrent()
            assertEquals(listOf("Bob"), harness.meshes.getValue("a").peers().value.map { it.nickname })

            harness.network.disconnect("a", "b")
            advanceTimeBy(1_200L)
            runCurrent()

            assertTrue(harness.meshes.getValue("a").peers().value.isEmpty())
        } finally {
            harness.closeAll()
        }
    }

    @Test
    fun `announce with a broken signature is rejected`() = runTest {
        val harness = Harness(this, listOf("b", "x"))
        try {
            harness.network.connect("b", "x")
            harness.start(
                nicknames = mapOf("b" to "Bob"),
                discoverable = setOf("b"),
            )
            runCurrent()

            val mallory = DefaultCrypto(IdentityManager(InMemorySecretStore()))
            val valid = harness.announceFrame(mallory, "Mallory", counter = 1L, messageId = 1L)
            val forged = valid.copyOf().also {
                it[MeshPacketCodec.HEADER_PREFIX_SIZE] =
                    (it[MeshPacketCodec.HEADER_PREFIX_SIZE].toInt() xor 0x01).toByte()
            }

            harness.nodes.getValue("x").send(Peer("b"), forged)
            runCurrent()

            assertTrue(harness.meshes.getValue("b").peers().value.isEmpty())
        } finally {
            harness.closeAll()
        }
    }

    @Test
    fun `announce flood from one identity is rate-limited`() = runTest {
        val harness = Harness(
            this,
            listOf("b", "x"),
            config = baseConfig(announceRate = RateLimit(perSecond = 0.001, burst = 1.0)),
        )
        try {
            harness.network.connect("b", "x")
            harness.start(
                nicknames = mapOf("b" to "Bob"),
                discoverable = setOf("b"),
            )
            runCurrent()

            val mallory = DefaultCrypto(IdentityManager(InMemorySecretStore()))
            repeat(10) { index ->
                val frame = harness.announceFrame(
                    mallory,
                    if (index == 0) "First" else "Flood$index",
                    counter = index + 1L,
                    messageId = index + 1L,
                )
                harness.nodes.getValue("x").send(Peer("b"), frame)
            }
            runCurrent()

            val peers = harness.meshes.getValue("b").peers().value
            assertEquals(1, peers.size)
            assertEquals("First", peers.single().nickname)
        } finally {
            harness.closeAll()
        }
    }

    private fun baseConfig(
        peerTimeoutMs: Long = 90_000L,
        peerSweepIntervalMs: Long = 5_000L,
        announceRate: RateLimit = RateLimit(perSecond = 0.2, burst = 4.0),
    ): MeshConfig = MeshConfig(
        announceTtl = 2,
        announceIntervalMs = 1_000_000L,
        peerTimeoutMs = peerTimeoutMs,
        peerSweepIntervalMs = peerSweepIntervalMs,
        announceRate = announceRate,
        jitterMs = 0L..0L,
        perSenderRate = RateLimit(perSecond = 10_000.0, burst = 20_000.0),
        perNeighbourRate = RateLimit(perSecond = 10_000.0, burst = 20_000.0),
    )

    private class Harness(
        private val testScope: TestScope,
        private val ids: List<String>,
        private val config: MeshConfig = MeshConfig(
            announceTtl = 2,
            announceIntervalMs = 1_000_000L,
            announceRate = RateLimit(perSecond = 100.0, burst = 100.0),
            jitterMs = 0L..0L,
            perSenderRate = RateLimit(perSecond = 10_000.0, burst = 20_000.0),
            perNeighbourRate = RateLimit(perSecond = 10_000.0, burst = 20_000.0),
        ),
    ) {
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            seed = 7L,
            externalScope = testScope.backgroundScope,
        )
        val nodes: Map<String, FakeTransport> = ids.associateWith { network.addNode(it) }
        val cryptos: Map<String, DefaultCrypto> = ids.associateWith {
            DefaultCrypto(IdentityManager(InMemorySecretStore()))
        }
        val deliveries: Map<String, MutableList<MeshMessage>> =
            ids.associateWith { CopyOnWriteArrayList<MeshMessage>() }
        val meshes: MutableMap<String, MeshEngine> = LinkedHashMap()

        fun start(
            nicknames: Map<String, String>,
            discoverable: Set<String> = ids.toSet(),
        ) {
            for (id in ids) {
                val engine = MeshEngine(
                    transport = nodes.getValue(id),
                    crypto = cryptos.getValue(id),
                    localPublicKey = cryptos.getValue(id).publicKey,
                    config = config,
                    clock = { testScope.testScheduler.currentTime },
                    externalScope = testScope,
                    initialNickname = nicknames[id] ?: id,
                    discoverable = id in discoverable,
                )
                engine.onMessage { message -> deliveries.getValue(id).add(message) }
                meshes[id] = engine
            }
        }

        fun announceFrame(
            crypto: DefaultCrypto,
            nickname: String,
            counter: Long,
            messageId: Long,
            timestampMs: Long = testScope.testScheduler.currentTime,
        ): ByteArray {
            val payload = requireNotNull(
                NearbyAnnounceCodec.encode(
                    crypto.publicKey,
                    nickname,
                    NearbyAnnounceCodec.DEFAULT_CAPABILITIES,
                ),
            )
            val header = MeshPacketHeader(
                type = MeshPacketCodec.TYPE_MEMBER_ANNOUNCE,
                messageId = ByteArray(8) { index ->
                    ((messageId ushr (56 - index * 8)) and 0xFF).toByte()
                },
                channelId = ChannelId.fromBytes(NearbyChannel.channelId()),
                senderId = RotatingSenderId.derive(NearbyChannel.key(), crypto.publicKey, timestampMs),
                ttl = config.announceTtl,
                chunkIndex = 0,
                totalChunks = 1,
                timestampMs = timestampMs,
                counter = counter,
            )
            val canonical = MeshPacketCodec.headerBytes(header.copy(ttl = 0))
            val signature = PacketCrypto.signPacket(crypto, canonical, payload)
            return MeshPacketCodec.encode(header, signature, payload)
        }

        fun closeAll() {
            meshes.values.forEach { it.close() }
            network.close()
        }
    }
}
