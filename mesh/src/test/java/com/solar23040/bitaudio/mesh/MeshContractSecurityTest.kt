package com.solar23040.bitaudio.mesh

import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.Crypto
import com.bitaudio.crypto.DefaultCrypto
import com.bitaudio.crypto.Ed25519
import com.bitaudio.crypto.IdentityManager
import com.bitaudio.crypto.InMemorySecretStore
import com.bitaudio.crypto.PacketCrypto
import com.bitaudio.crypto.RotatingSenderId
import com.bitaudio.crypto.XChaCha20Poly1305
import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.FakeTransport
import com.meshvoice.transport.LinkConfig
import com.meshvoice.transport.Peer
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Agent H security suite for `:mesh` (SEC-002, SEC-008, SEC-016).
 *
 * Two layers:
 *
 * 1. The frame below was generated from `docs/packet-format.md` v1 by
 *    `security/attack-tests/contract_vector.py` (committed as
 *    `security/contract-vectors.json`). Verifying it here proves that the
 *    production `:crypto` transcript, AAD and ID derivations still match the
 *    documented wire format. If they drift, this test fails — that is SEC-016's
 *    regression guard.
 * 2. Attack frames travel through `FakeNetwork`: forged sender, replay,
 *    malformed headers and TTL=0 relay behaviour.
 *
 * `:mesh` is still interface-only on main (SEC-017), so the receiving node is a
 * test-only reference implementation of the documented rules. Replace
 * [TestNode] with the real `Mesh` when Agent D lands it; the frames and
 * assertions stay valid.
 */
class MeshContractSecurityTest {

    private val crypto: Crypto = DefaultCrypto(IdentityManager(InMemorySecretStore()))

    // ---- Fixed docs-v1 contract vector (test-only seeds) --------------------

    private val channelKey: ByteArray = ByteArray(32) { it.toByte() }
    private val aliceSeed: ByteArray = ByteArray(32) { (32 + it).toByte() }
    private val bobSeed: ByteArray = ByteArray(32) { (64 + it).toByte() }
    private val alicePublicKey: ByteArray = Ed25519.publicKeyFromSeed(aliceSeed)
    private val bobPublicKey: ByteArray = Ed25519.publicKeyFromSeed(bobSeed)

    @Test
    fun `python contract vector verifies with production crypto`() {
        val vectorFrames = listOf(hex(FRAME0_HEX), hex(FRAME1_HEX))
        val alicePublic = hex(PUBKEY_HEX)

        assertEquals(CHANNEL_ID_HEX, toHex(ChannelKeys.channelId(channelKey)))
        assertEquals(
            SENDER_ID_HEX,
            toHex(RotatingSenderId.derive(channelKey, alicePublic, NOW_MS / 1000)),
        )

        val rebuilt = ByteArrayOutputStream()
        for (frame in vectorFrames) {
            val packet = parse(frame)
            assertTrue("unexpected wire TTL", packet.ttl == 5)
            assertTrue(
                "contract-vector signature rejected by :crypto",
                PacketCrypto.verifyPacket(
                    crypto,
                    alicePublic,
                    packet.canonicalHeader,
                    packet.payload,
                    packet.signature,
                ),
            )
            val plaintext = PacketCrypto.openPayload(
                crypto,
                channelKey,
                packet.canonicalHeader,
                packet.payload,
            )
            assertTrue("contract-vector AEAD open failed", plaintext != null)
            rebuilt.write(plaintext!!)
        }
        assertArrayEquals("reassembled contract vector mismatch", hex(PLAINTEXT_HEX), rebuilt.toByteArray())

        // Relays decrement ttl on the wire; TTL is deliberately unsigned, so the
        // signature and AAD must still verify at the next hop (SEC-002).
        val relayed = vectorFrames[0].copyOf()
        relayed[26] = 4
        val packet = parse(relayed)
        assertTrue(
            "TTL decrement broke signature verification",
            PacketCrypto.verifyPacket(
                crypto,
                alicePublic,
                packet.canonicalHeader,
                packet.payload,
                packet.signature,
            ),
        )
        assertTrue(
            "TTL decrement broke AEAD open",
            PacketCrypto.openPayload(crypto, channelKey, packet.canonicalHeader, packet.payload) != null,
        )
    }

    // ---- FakeNetwork attack cases ------------------------------------------

    @Test
    fun `forged sender is dropped without relaying`() = runTest {
        val line = line("forged")
        val aliceSenderId = RotatingSenderId.derive(channelKey, alicePublicKey, NOW_MS / 1000)

        // Bob signs a frame that claims Alice's rotating ID.
        val forged = buildFrame(
            signingSeed = bobSeed,
            senderId = aliceSenderId,
            msgId = ByteArray(8) { 0x11 },
        )
        line.sender.send(Peer(line.middle.name), forged)
        advanceUntilIdle()

        assertTrue("forged frame delivered", line.middle.delivered.isEmpty())
        assertTrue("forged frame relayed", line.middle.relayedTtls.isEmpty())
        assertTrue("expected bad-signature drop: ${line.middle.dropped}", line.middle.dropped.contains("bad signature"))

        // An unlisted rotating ID must be dropped before signature work.
        val unknown = buildFrame(
            signingSeed = bobSeed,
            senderId = ByteArray(8) { 0x7f },
            msgId = ByteArray(8) { 0x12 },
        )
        line.sender.send(Peer(line.middle.name), unknown)
        advanceUntilIdle()
        assertTrue(
            "expected unresolved-sender drop: ${line.middle.dropped}",
            line.middle.dropped.contains("unresolved sender"),
        )
    }

    @Test
    fun `replayed packet is delivered once and relayed once`() = runTest {
        val line = line("replay")
        val frame = buildFrame(
            signingSeed = aliceSeed,
            senderId = RotatingSenderId.derive(channelKey, alicePublicKey, NOW_MS / 1000),
            msgId = ByteArray(8) { 0x21 },
        )

        line.sender.send(Peer(line.middle.name), frame)
        line.sender.send(Peer(line.middle.name), frame)
        advanceUntilIdle()

        assertTrue("replay delivered twice", line.middle.delivered.size == 1)
        assertTrue("replay not deduplicated: ${line.middle.dropped}", line.middle.dropped.contains("duplicate chunk"))
        assertTrue("replay relayed twice", line.middle.relayedTtls.size == 1)
    }

    @Test
    fun `malformed headers are rejected without crashing`() = runTest {
        val line = line("malformed")
        val valid = buildFrame(
            signingSeed = aliceSeed,
            senderId = RotatingSenderId.derive(channelKey, alicePublicKey, NOW_MS / 1000),
            msgId = ByteArray(8) { 0x31 },
        )
        val cases = linkedMapOf(
            "huge total_chunks" to patchU16(valid, 29, 0xFFFF),
            "chunk_idx overflow" to patchU16(valid, 27, 0xFFFF),
            "truncated header" to valid.copyOf(106),
            "oversize frame" to (valid + ByteArray(512)),
            "empty payload" to valid.copyOf(107),
            "ttl zero" to valid.copyOf().also { it[26] = 0 },
        )

        for ((name, frame) in cases) {
            val before = line.middle.dropped.size
            line.sender.send(Peer(line.middle.name), frame)
            advanceUntilIdle()
            assertTrue("$name was not rejected", line.middle.dropped.size > before)
        }
        assertTrue("malformed frame delivered", line.middle.delivered.isEmpty())
        assertTrue("malformed frame relayed", line.middle.relayedTtls.isEmpty())
    }

    @Test
    fun `ttl zero is dropped and ttl two relays exactly once`() = runTest {
        val line = line("ttl")

        val zero = buildFrame(
            signingSeed = aliceSeed,
            senderId = RotatingSenderId.derive(channelKey, alicePublicKey, NOW_MS / 1000),
            ttl = 0,
            msgId = ByteArray(8) { 0x41 },
        )
        line.sender.send(Peer(line.middle.name), zero)
        advanceUntilIdle()
        assertTrue("ttl=0 delivered", line.middle.delivered.isEmpty())
        assertTrue("ttl=0 relayed", line.middle.relayedTtls.isEmpty())
        assertTrue("expected ttl drop: ${line.middle.dropped}", line.middle.dropped.contains("bad ttl"))

        val one = buildFrame(
            signingSeed = aliceSeed,
            senderId = RotatingSenderId.derive(channelKey, alicePublicKey, NOW_MS / 1000),
            ttl = 1,
            msgId = ByteArray(8) { 0x42 },
            counter = 2,
            plaintext = "ttl one".toByteArray(),
        )
        line.sender.send(Peer(line.middle.name), one)
        advanceUntilIdle()
        assertTrue("ttl=1 delivery count", line.middle.delivered.size == 1)
        assertTrue("ttl=1 relayed", line.middle.relayedTtls.isEmpty())
        assertTrue("ttl=1 reached the far node", line.far.delivered.isEmpty())

        val two = buildFrame(
            signingSeed = aliceSeed,
            senderId = RotatingSenderId.derive(channelKey, alicePublicKey, NOW_MS / 1000),
            ttl = 2,
            msgId = ByteArray(8) { 0x43 },
            counter = 3,
            plaintext = "ttl two".toByteArray(),
        )
        line.sender.send(Peer(line.middle.name), two)
        advanceUntilIdle()
        assertTrue("ttl=2 delivery count", line.middle.delivered.size == 2)
        assertTrue("far delivery count", line.far.delivered.size == 1)
        assertArrayEquals("ttl two".toByteArray(), line.far.delivered.single())
        assertEquals("relay did not decrement ttl", listOf(1), line.middle.relayedTtls)
        assertTrue("far node rebroadcast a ttl=1 copy", line.far.relayedTtls.isEmpty())
    }

    // ---- Reference node and helpers ----------------------------------------

    private inner class TestNode(
        val name: String,
        private val network: FakeNetwork,
        private val transport: FakeTransport,
        private val roster: List<ByteArray>,
        private val scope: CoroutineScope,
    ) {
        val delivered = mutableListOf<ByteArray>()
        val relayedTtls = mutableListOf<Int>()
        val dropped = mutableListOf<String>()
        private val seen = mutableSetOf<String>()
        private val counters = mutableMapOf<String, ByteArray>()
        private val nowMs = NOW_MS
        private val expectedChannelId = ChannelKeys.channelId(channelKey)
        private val handle: AutoCloseable = transport.onReceive { frame ->
            onFrame(frame.from.id, frame.bytes)
        }

        fun close() {
            handle.close()
        }

        private fun onFrame(from: String, frame: ByteArray) {
            val reason = inspect(from, frame)
            if (reason != null) dropped.add(reason)
        }

        private fun inspect(from: String, frame: ByteArray): String? {
            if (frame.size < HEADER_LEN) return "truncated frame"
            if (frame.size > MAX_FRAME) return "oversize frame"
            if ((frame[0].toInt() and 0xFF) != VERSION) return "bad version"

            val packet = parse(frame)
            if (packet.ttl !in MIN_TTL..MAX_TTL) return "bad ttl"
            if (packet.totalChunks !in 1..MAX_TOTAL_CHUNKS) return "bad total_chunks"
            if (packet.chunkIdx >= packet.totalChunks) return "bad chunk_idx"
            if (packet.payload.size !in MIN_SEALED_PAYLOAD..MAX_PAYLOAD) return "bad payload size"
            if (packet.counter < 1) return "bad counter"
            if (packet.timestampMs > nowMs + FUTURE_SKEW_MS) return "future timestamp"
            if (packet.timestampMs < nowMs - RETENTION_MS) return "stale timestamp"
            if (!frame.copyOfRange(10, 18).contentEquals(expectedChannelId)) return "unknown channel"

            val identity = resolve(packet.senderId, packet.timestampMs) ?: return "unresolved sender"
            if (!PacketCrypto.verifyPacket(
                    crypto,
                    identity,
                    packet.canonicalHeader,
                    packet.payload,
                    packet.signature,
                )
            ) {
                return "bad signature"
            }

            // One counter maps to one msg_id per resolved identity.
            val identityHex = toHex(identity)
            val counterKey = "$identityHex:${packet.counter}"
            val mapped = counters[counterKey]
            if (mapped != null && !mapped.contentEquals(packet.msgId)) return "counter replay"
            counters[counterKey] = packet.msgId

            // Dedup only after authentication.
            val dedup = "$identityHex:${toHex(packet.msgId)}:${packet.chunkIdx}"
            if (!seen.add(dedup)) return "duplicate chunk"

            if (packet.totalChunks != 1) return "multi-chunk not supported by this oracle"

            val plaintext = PacketCrypto.openPayload(
                crypto,
                channelKey,
                packet.canonicalHeader,
                packet.payload,
            ) ?: return "AEAD failure"
            delivered.add(plaintext)

            // Relays change only the unsigned ttl.
            if (packet.ttl > 1 && nowMs - packet.timestampMs <= FUTURE_SKEW_MS) {
                val relayed = frame.copyOf().also { it[TTL_OFFSET] = (packet.ttl - 1).toByte() }
                relayedTtls.add(packet.ttl - 1)
                for (peer in network.snapshot(name)) {
                    if (peer.id != from) {
                        scope.launch { transport.send(peer, relayed) }
                    }
                }
            }
            return null
        }

        private fun resolve(senderId: ByteArray, timestampMs: Long): ByteArray? {
            val epoch = RotatingSenderId.epochFor(timestampMs / 1000)
            for (publicKey in roster) {
                for (candidate in (epoch - 1)..(epoch + 1)) {
                    val expected = RotatingSenderId.deriveForEpoch(channelKey, publicKey, candidate)
                    if (expected.contentEquals(senderId)) return publicKey
                }
            }
            return null
        }
    }

    private data class Line(
        val sender: FakeTransport,
        val middle: TestNode,
        val far: TestNode,
    )

    private fun TestScope.line(prefix: String): Line {
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            seed = 42L,
            externalScope = backgroundScope,
        )
        val sender = network.addNode("$prefix-a")
        val middleTransport = network.addNode("$prefix-b")
        val farTransport = network.addNode("$prefix-c")
        network.connect(sender, middleTransport)
        network.connect(middleTransport, farTransport)

        val roster = listOf(alicePublicKey, bobPublicKey)
        val middle = TestNode("$prefix-b", network, middleTransport, roster, backgroundScope)
        val far = TestNode("$prefix-c", network, farTransport, roster, backgroundScope)
        return Line(sender, middle, far)
    }

    private data class Parsed(
        val msgId: ByteArray,
        val senderId: ByteArray,
        val ttl: Int,
        val chunkIdx: Int,
        val totalChunks: Int,
        val timestampMs: Long,
        val counter: Int,
        val canonicalHeader: ByteArray,
        val signature: ByteArray,
        val payload: ByteArray,
    )

    private fun parse(frame: ByteArray): Parsed {
        val buffer = ByteBuffer.wrap(frame)
        return Parsed(
            msgId = frame.copyOfRange(2, 10),
            senderId = frame.copyOfRange(18, 26),
            ttl = frame[TTL_OFFSET].toInt() and 0xFF,
            chunkIdx = buffer.getShort(27).toInt() and 0xFFFF,
            totalChunks = buffer.getShort(29).toInt() and 0xFFFF,
            timestampMs = buffer.getLong(31),
            counter = buffer.getInt(39),
            canonicalHeader = frame.copyOfRange(0, HEADER_PREFIX_LEN).also { it[TTL_OFFSET] = 0 },
            signature = frame.copyOfRange(SIG_OFFSET, HEADER_LEN),
            payload = frame.copyOfRange(HEADER_LEN, frame.size),
        )
    }

    private fun buildFrame(
        signingSeed: ByteArray,
        senderId: ByteArray,
        ttl: Int = 5,
        msgId: ByteArray = ByteArray(8) { 0x01 },
        timestampMs: Long = NOW_MS,
        counter: Int = 1,
        plaintext: ByteArray = byteArrayOf(1, 2, 3),
        nonce: ByteArray = ByteArray(24) { 0x11 },
    ): ByteArray {
        val channelId = ChannelKeys.channelId(channelKey)
        val header = headerBytes(
            version = VERSION,
            type = 1,
            msgId = msgId,
            channelId = channelId,
            senderId = senderId,
            ttl = ttl,
            chunkIdx = 0,
            totalChunks = 1,
            timestampMs = timestampMs,
            counter = counter,
        )
        val canonical = header.copyOf().also { it[TTL_OFFSET] = 0 }
        val sealed = XChaCha20Poly1305.sealWithNonce(
            channelKey,
            nonce,
            plaintext,
            PacketCrypto.associatedData(canonical),
        )
        val payload = nonce + sealed
        val signature = Ed25519.sign(signingSeed, PacketCrypto.signingBytes(canonical, payload))
        return header + signature + payload
    }

    private fun headerBytes(
        version: Int,
        type: Int,
        msgId: ByteArray,
        channelId: ByteArray,
        senderId: ByteArray,
        ttl: Int,
        chunkIdx: Int,
        totalChunks: Int,
        timestampMs: Long,
        counter: Int,
    ): ByteArray {
        val buffer = ByteBuffer.allocate(HEADER_PREFIX_LEN)
        buffer.put(version.toByte())
        buffer.put(type.toByte())
        buffer.put(msgId)
        buffer.put(channelId)
        buffer.put(senderId)
        buffer.put(ttl.toByte())
        buffer.putShort(chunkIdx.toShort())
        buffer.putShort(totalChunks.toShort())
        buffer.putLong(timestampMs)
        buffer.putInt(counter)
        check(buffer.position() == HEADER_PREFIX_LEN) { "header prefix must be $HEADER_PREFIX_LEN bytes" }
        return buffer.array()
    }

    private fun patchU16(frame: ByteArray, offset: Int, value: Int): ByteArray =
        frame.copyOf().also {
            it[offset] = (value ushr 8).toByte()
            it[offset + 1] = value.toByte()
        }

    private fun hex(value: String): ByteArray =
        value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun toHex(value: ByteArray): String =
        value.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

}

private const val VERSION = 1
private const val HEADER_PREFIX_LEN = 43
private const val SIG_OFFSET = 43
private const val HEADER_LEN = 107
private const val TTL_OFFSET = 26
private const val MAX_FRAME = 512
private const val MAX_PAYLOAD = 405
private const val MIN_SEALED_PAYLOAD = 40
private const val MAX_TOTAL_CHUNKS = 256
private const val MIN_TTL = 1
private const val MAX_TTL = 8
private const val FUTURE_SKEW_MS = 120_000L
private const val RETENTION_MS = 24L * 60 * 60 * 1000
private const val NOW_MS = 1_700_000_000_000L

// Hardcoded values come from security/contract-vectors.json, generated by
// security/attack-tests/contract_vector.py from docs/packet-format.md v1.
private const val PUBKEY_HEX =
    "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"

private const val CHANNEL_ID_HEX =
    "0843eaeba3fd4abc"

private const val SENDER_ID_HEX =
    "5c782c4d14a64f04"

private const val PLAINTEXT_HEX =
    "6269742d617564696f20636f6e747261637420766563746f722076312e206269742d617564696f20636f6e74726163742076" +
        "6563746f722076312e206269742d617564696f20636f6e747261637420766563746f722076312e206269742d617564696f20" +
        "636f6e747261637420766563746f722076312e206269742d617564696f20636f6e747261637420766563746f722076312e20" +
        "6269742d617564696f20636f6e747261637420766563746f722076312e206269742d617564696f20636f6e74726163742076" +
        "6563746f722076312e206269742d617564696f20636f6e747261637420766563746f722076312e206269742d617564696f20" +
        "636f6e747261637420766563746f722076312e206269742d617564696f20636f6e747261637420766563746f722076312e20" +
        "6269742d617564696f20636f6e747261637420766563746f722076312e206269742d617564696f20636f6e74726163742076" +
        "6563746f722076312e206269742d617564696f20636f6e747261637420766563746f722076312e206269742d617564696f20" +
        "636f6e747261637420766563746f722076312e206269742d617564696f20636f6e747261637420766563746f722076312e20" +
        "6269742d617564696f20636f6e747261637420766563746f722076312e206269742d617564696f20636f6e74726163742076" +
        "6563746f722076312e206269"

private const val FRAME0_HEX =
    "010101020304050607080843eaeba3fd4abc5c782c4d14a64f0405000000020000018bcfe568000000002a5e41ffd0030231" +
        "8b5933fe209559fb62711b1120cedbdd1564989e1d53f3af248610de14f81866a895ef834124e023e01a30efa33f98ff8ff5" +
        "54e1b4440eaf0ba0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a024438f382a747c7811e4f4c891e260229c0c1c" +
        "0012de11ff80365543e50d7e23a62c6f222cfc499effcaeb19b20dc2538c7e45da3ba171ad1753c676154e15324e52d4f96c" +
        "655960e9e14d136fcd2f6008179f92d5fa1994fd991065e080c3b0573be5cd7b592e523487f8c3c881419c8c640d1514fac0" +
        "0bff93cd86f816f6611949d40decd22abf0308a400769055e82ea11cf87dfca7e99a3a87e5c63fe06d4a09a285a6667aa0fd" +
        "0d146dc777b2b2769c25dd14c76c0ffe031d563fb8c3d483e1a510800fb2dcf1263e1c4319cd04122d9fa0fd111ebdc7c10b" +
        "e1a928566f98506be5daf48d13d2930c84b0be74059d81b7a7388bdd5528de8a2f5dd2782d2bbfba4a936ba1d8ed47d388ee" +
        "3bf7f205f1b7081e188d4eb984c3f0b0602b0775fbc1cf447b9eea664cf89f0c7a7293d13e3e29485d6785190a50a4ac5d7b" +
        "62c7f0d1b6128d951d936bd0b920ee2c7d96960489c3dd4e7eedd1d7fec72a224cdbd93411cb056a5396a007f9ce342414b8" +
        "df31e8688608d419673770dc"

private const val FRAME1_HEX =
    "010101020304050607080843eaeba3fd4abc5c782c4d14a64f0405000100020000018bcfe568000000002ae0d5c3d3c70294" +
        "774627ef976e31f6ba8e2bfce5aaa2861b966e20f6ee8a4aa912878381a238720f23d404e7c7f6e8ffc317004f01cb6a0a1b" +
        "a6573911bfc602a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1ac1256158e169042cbbfa3fc00d0eaf0db9d01" +
        "614381982b10d5af02d55512917e58755a3e74e2f9e0c38200b990772628d28052aa80234bf992565bd5c9d5d93d0e99fbbd" +
        "f2673afa3c0c1873d09cc97de9c424dc7d0934621c81a01e658a65f59f76e54fabab857b377ac997007e537bb98b52ef1984" +
        "b1e3ad394fefae91071d0cfe6651a0ca4f0a24a9c223591d5db3b35835e6e23f19fa618c463b2227932372da"
