package com.solar23040.bitaudio.mesh.node

import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.DefaultCrypto
import com.bitaudio.crypto.IdentityManager
import com.bitaudio.crypto.InMemorySecretStore
import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.FakeTransport
import com.meshvoice.transport.Peer
import com.meshvoice.transport.ReceivedFrame
import com.meshvoice.transport.Transport
import com.solar23040.bitaudio.mesh.ChannelId
import kotlinx.coroutines.CoroutineScope
import java.util.concurrent.CopyOnWriteArrayList

internal class TestMeshNode(
    val transport: FakeTransport,
    val crypto: DefaultCrypto,
    val store: InMemoryPacketStore,
    val mesh: MeshNode,
) {
    val publicKey: ByteArray get() = crypto.publicKey
}

internal fun testMeshNode(
    network: FakeNetwork,
    id: String,
    scope: CoroutineScope,
    jitterMs: Long = 0,
    recording: RecordingTransport? = null,
): TestMeshNode {
    val transport = network.addNode(id)
    val crypto = DefaultCrypto(IdentityManager(InMemorySecretStore()))
    val store = InMemoryPacketStore()
    val mesh = MeshNode(
        transport = recording?.let { it.delegate(transport) } ?: transport,
        crypto = crypto,
        localPublicKey = crypto.publicKey,
        config = MeshConfig(rebroadcastJitterMs = jitterMs..jitterMs),
        store = store,
        externalScope = scope,
    )
    return TestMeshNode(transport, crypto, store, mesh)
}

internal fun testChannel(nodes: List<TestMeshNode>, ttl: Int = 5): ChannelId {
    val key = ChannelKeys.generate()
    val id = ChannelId.fromBytes(ChannelKeys.channelId(key))
    val members = nodes.map { it.publicKey }
    nodes.forEach {
        it.mesh.addChannel(MeshChannel(id = id, key = key, members = members, ttl = ttl))
        it.mesh.start()
    }
    return id
}

/** Records what the mesh hands to the transport boundary. */
internal class RecordingTransport {
    val sent = CopyOnWriteArrayList<ByteArray>()
    val sentTo = CopyOnWriteArrayList<Peer>()

    fun delegate(transport: Transport): Transport = object : Transport by transport {
        override suspend fun send(peer: Peer, bytes: ByteArray) {
            sent.add(bytes.copyOf())
            sentTo.add(peer)
            transport.send(peer, bytes)
        }

        override fun onReceive(callback: (ReceivedFrame) -> Unit): AutoCloseable =
            transport.onReceive(callback)

        override fun peers() = transport.peers()
    }
}
