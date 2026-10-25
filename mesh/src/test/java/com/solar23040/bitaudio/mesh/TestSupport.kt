package com.solar23040.bitaudio.mesh

import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.DefaultCrypto
import com.bitaudio.crypto.IdentityManager
import com.bitaudio.crypto.InMemorySecretStore
import com.bitaudio.crypto.PeerDirectory
import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.FakeTransport
import com.meshvoice.transport.LinkConfig
import com.solar23040.bitaudio.mesh.store.InMemoryMeshStore
import java.util.Collections
import kotlin.random.Random
import kotlinx.coroutines.CoroutineScope

internal class TestClock(var now: Long = 1_700_000_000_000L) {
    fun time(): Long = now
}

internal class MeshNode(
    val id: String,
    val transport: FakeTransport,
    val crypto: DefaultCrypto,
    val mesh: FloodMesh,
    val store: InMemoryMeshStore,
) {
    val messages: MutableList<MeshMessage> = Collections.synchronizedList(mutableListOf())
}

/**
 * In-memory world used by the mesh tests: one [FloodMesh] per node, all
 * sharing a channel key and a full member roster, backed by [FakeNetwork].
 */
internal class MeshWorld(
    scope: CoroutineScope,
    val clock: TestClock,
    nodeIds: List<String>,
    private val retentionMs: Long = DEFAULT_RETENTION_MS,
    storeFactory: (String) -> InMemoryMeshStore = { InMemoryMeshStore() },
) {
    val network = FakeNetwork(
        defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
        externalScope = scope,
    )

    val channel: MeshChannel
    val nodes: Map<String, MeshNode>

    init {
        val transports = nodeIds.associateWith { network.addNode(it) }
        val cryptos = nodeIds.associateWith {
            DefaultCrypto(IdentityManager(InMemorySecretStore()))
        }
        val roster = PeerDirectory(cryptos.values.map { it.publicKey })
        channel = MeshChannel(ChannelKeys.generate(), roster)

        nodes = nodeIds.associateWith { id ->
            val store = storeFactory(id)
            val nodeCrypto = cryptos.getValue(id)
            val mesh = FloodMesh(
                transport = transports.getValue(id),
                crypto = nodeCrypto,
                identityPublicKey = nodeCrypto.publicKey,
                initialChannels = listOf(channel),
                config = MeshConfig(
                    defaultTtl = 5,
                    jitterMs = 20L..200L,
                    retentionMs = retentionMs,
                    clock = clock::time,
                    random = Random(id.hashCode()),
                ),
                store = store,
                meshScope = scope,
            )
            MeshNode(
                id = id,
                transport = transports.getValue(id),
                crypto = nodeCrypto,
                mesh = mesh,
                store = store,
            ).also { node ->
                mesh.onMessage { message -> node.messages.add(message) }
            }
        }
    }

    fun connect(a: String, b: String) {
        network.connect(a, b)
    }

    fun node(id: String): MeshNode = nodes.getValue(id)

    fun close() {
        nodes.values.forEach { node ->
            node.mesh.close()
            node.store.close()
        }
    }

    companion object {
        const val DEFAULT_RETENTION_MS: Long = 24L * 60L * 60L * 1000L
    }
}
