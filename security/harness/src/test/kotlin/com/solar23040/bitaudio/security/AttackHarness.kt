package com.solar23040.bitaudio.security

import com.bitaudio.crypto.ChannelKeys
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
import com.solar23040.bitaudio.mesh.ChannelId
import com.solar23040.bitaudio.mesh.Mesh
import com.solar23040.bitaudio.mesh.MeshMessage
import com.solar23040.bitaudio.mesh.engine.MeshChannel as EngineChannel
import com.solar23040.bitaudio.mesh.engine.MeshConfig as EngineConfig
import com.solar23040.bitaudio.mesh.engine.MeshEngine
import com.solar23040.bitaudio.mesh.engine.RateLimit
import com.solar23040.bitaudio.mesh.node.MeshChannel as NodeChannel
import com.solar23040.bitaudio.mesh.node.MeshConfig as NodeConfig
import com.solar23040.bitaudio.mesh.node.MeshNode
import java.nio.ByteBuffer
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope

/** Both mesh implementations must satisfy the same documented receive rules. */
internal enum class MeshKind { ENGINE, NODE }

/**
 * Three-node line `a - b - c` on [FakeNetwork]. `a` is a plain attacker
 * transport; `b` and `c` are real `:mesh` nodes with real `:crypto`.
 */
internal class Rig(
    testScope: TestScope,
    val kind: MeshKind,
    dispatcher: CoroutineDispatcher = StandardTestDispatcher(testScope.testScheduler),
) : AutoCloseable {

    private val job = SupervisorJob()
    private val scope = CoroutineScope(dispatcher + job)
    private val network = FakeNetwork(
        defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
        seed = 42L,
        externalScope = scope,
    )

    private val transports: Map<String, FakeTransport> = linkedMapOf(
        "a" to network.addNode("a"),
        "b" to network.addNode("b"),
        "c" to network.addNode("c"),
    )

    val channelKey: ByteArray = ByteArray(32) { index -> (index * 7 + 1).toByte() }
    val channelId: ChannelId = ChannelId.fromBytes(ChannelKeys.channelId(channelKey))

    val aliceSeed: ByteArray = ByteArray(32) { (32 + it).toByte() }
    val bobSeed: ByteArray = ByteArray(32) { (64 + it).toByte() }
    val alicePublicKey: ByteArray = Ed25519.publicKeyFromSeed(aliceSeed)
    val bobPublicKey: ByteArray = Ed25519.publicKeyFromSeed(bobSeed)

    private val nodeBSeed: ByteArray = ByteArray(32) { (96 + it).toByte() }
    private val nodeCSeed: ByteArray = ByteArray(32) { (128 + it).toByte() }
    private val nodeBPublicKey: ByteArray = Ed25519.publicKeyFromSeed(nodeBSeed)
    private val nodeCPublicKey: ByteArray = Ed25519.publicKeyFromSeed(nodeCSeed)

    private val roster: List<ByteArray> =
        listOf(alicePublicKey, bobPublicKey, nodeBPublicKey, nodeCPublicKey)

    private val rawC = CopyOnWriteArrayList<ByteArray>()
    private val rawHandle: AutoCloseable

    val delivered: Map<String, MutableList<MeshMessage>> = mapOf(
        "b" to CopyOnWriteArrayList<MeshMessage>(),
        "c" to CopyOnWriteArrayList<MeshMessage>(),
    )

    private val meshes: Map<String, Mesh> = mapOf(
        "b" to buildMesh("b", nodeBSeed),
        "c" to buildMesh("c", nodeCSeed),
    )

    init {
        network.connect("a", "b", LinkConfig(0.0, 0L..0L))
        network.connect("b", "c", LinkConfig(0.0, 0L..0L))
        meshes.forEach { (id, mesh) ->
            mesh.onMessage { delivered.getValue(id).add(it) }
        }
        (meshes.getValue("b") as? MeshNode)?.start()
        (meshes.getValue("c") as? MeshNode)?.start()
        rawHandle = transports.getValue("c").onReceive { frame -> rawC.add(frame.bytes.copyOf()) }
        // Let peer collectors and the initial (empty) store handoff settle before
        // the first frame, so later raw-frame counts only see real relays.
        testScope.testScheduler.runCurrent()
    }

    fun deliveredAt(id: String): List<MeshMessage> = delivered.getValue(id).toList()

    fun rawFramesAtC(): List<ByteArray> = rawC.toList()

    suspend fun send(from: String, to: String, frame: ByteArray) {
        transports.getValue(from).send(Peer(to), frame)
    }

    fun transport(id: String): FakeTransport = transports.getValue(id)

    override fun close() {
        rawHandle.close()
        meshes.values.forEach { mesh -> runCatching { (mesh as AutoCloseable).close() } }
        scope.cancel()
    }

    private fun buildMesh(id: String, seed: ByteArray): Mesh {
        val crypto = cryptoFromSeed(seed)
        val publicKey = crypto.publicKey
        return when (kind) {
            MeshKind.ENGINE -> MeshEngine(
                transport = transports.getValue(id),
                crypto = crypto,
                localPublicKey = publicKey,
                initialChannels = listOf(EngineChannel(channelKey, roster)),
                config = EngineConfig(
                    defaultTtl = 5,
                    jitterMs = 0L..0L,
                    perNeighbourRate = RateLimit(perSecond = 1_000_000.0, burst = 1_000_000.0),
                    perSenderRate = RateLimit(perSecond = 1_000_000.0, burst = 1_000_000.0),
                ),
                clock = { NOW_MS },
                externalScope = scope,
            )

            MeshKind.NODE -> MeshNode(
                transport = transports.getValue(id),
                crypto = crypto,
                localPublicKey = publicKey,
                config = NodeConfig(
                    defaultTtl = 5,
                    rebroadcastJitterMs = 0L..0L,
                    maintenanceIntervalMs = 3_600_000,
                ),
                clock = { NOW_MS },
                externalScope = scope,
            ).apply {
                addChannel(
                    NodeChannel(
                        id = channelId,
                        key = channelKey,
                        members = roster,
                        ttl = 5,
                    ),
                )
            }
        }
    }

    private fun cryptoFromSeed(seed: ByteArray): DefaultCrypto {
        val store = InMemorySecretStore()
        store.write(IdentityManager.DEFAULT_STORAGE_KEY, seed)
        return DefaultCrypto(IdentityManager(store))
    }

    companion object {
        const val NOW_MS: Long = 1_700_000_000_000L
    }
}

/** Builds v1 frames byte-for-byte from `docs/packet-format.md`. */
internal object Frames {

    const val VERSION = 1
    const val TYPE_VOICE_DATA = 1
    const val HEADER_PREFIX = 43
    const val HEADER = 107
    const val TTL_OFFSET = 26

    fun senderId(channelKey: ByteArray, publicKey: ByteArray, timestampMs: Long): ByteArray =
        RotatingSenderId.derive(channelKey, publicKey, timestampMs)

    fun build(
        channelKey: ByteArray,
        signingSeed: ByteArray,
        senderId: ByteArray,
        messageId: ByteArray = ByteArray(8) { 0x01 },
        ttl: Int = 5,
        chunkIndex: Int = 0,
        totalChunks: Int = 1,
        timestampMs: Long = Rig.NOW_MS,
        counter: Long = 1,
        plaintext: ByteArray = byteArrayOf(1, 2, 3),
        nonce: ByteArray = ByteArray(24) { 0x11 },
        type: Int = TYPE_VOICE_DATA,
        version: Int = VERSION,
        channelId: ByteArray = ChannelKeys.channelId(channelKey),
    ): ByteArray {
        val header = ByteBuffer.allocate(HEADER_PREFIX)
            .put(version.toByte())
            .put(type.toByte())
            .put(messageId)
            .put(channelId)
            .put(senderId)
            .put(ttl.toByte())
            .putShort(chunkIndex.toShort())
            .putShort(totalChunks.toShort())
            .putLong(timestampMs)
            .putInt(counter.toInt())
            .array()
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

    fun patchU16(frame: ByteArray, offset: Int, value: Int): ByteArray =
        frame.copyOf().also {
            it[offset] = (value ushr 8).toByte()
            it[offset + 1] = value.toByte()
        }

    fun patchU32(frame: ByteArray, offset: Int, value: Long): ByteArray =
        frame.copyOf().also {
            it[offset] = (value ushr 24).toByte()
            it[offset + 1] = (value ushr 16).toByte()
            it[offset + 2] = (value ushr 8).toByte()
            it[offset + 3] = value.toByte()
        }

    fun patchU64(frame: ByteArray, offset: Int, value: Long): ByteArray =
        frame.copyOf().also {
            for (index in 0 until 8) {
                it[offset + index] = (value ushr (56 - index * 8)).toByte()
            }
        }

    fun uniqueMessageId(value: Int): ByteArray = ByteArray(8) { index ->
        val shift = (7 - index) * 8
        ((value.toLong() ushr shift) and 0xFF).toByte()
    }
}
