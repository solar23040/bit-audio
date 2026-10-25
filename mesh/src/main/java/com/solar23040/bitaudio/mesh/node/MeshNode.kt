package com.solar23040.bitaudio.mesh.node

import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.Crypto
import com.bitaudio.crypto.PacketCrypto
import com.bitaudio.crypto.PeerDirectory
import com.bitaudio.crypto.RotatingSenderId
import com.solar23040.bitaudio.mesh.ChannelId
import com.solar23040.bitaudio.mesh.Mesh
import com.solar23040.bitaudio.mesh.MeshException
import com.solar23040.bitaudio.mesh.MeshMessage
import com.meshvoice.transport.Peer
import com.meshvoice.transport.Transport
import com.meshvoice.transport.TransportException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.Closeable
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.random.Random

/** Routing knobs. Production defaults follow `docs/packet-format.md`. */
data class MeshConfig(
    val defaultTtl: Int = 5,
    val rebroadcastJitterMs: LongRange = 20L..200L,
    val dedupWindowMs: Long = 120_000,
    val reassemblyTimeoutMs: Long = 120_000,
    val retentionMs: Long = 24L * 60L * 60L * 1000L,
    val futureSkewMs: Long = 120_000,
    val staleAfterMs: Long = 120_000,
    val maxSeenPackets: Int = 32_768,
    val maxPartialMessages: Int = 256,
    val maxCompletedMessages: Int = 16_384,
    val maintenanceIntervalMs: Long = 30_000,
) {
    init {
        require(defaultTtl in MeshPacket.MIN_TTL..MeshPacket.MAX_TTL)
        require(rebroadcastJitterMs.first >= 0 && rebroadcastJitterMs.first <= rebroadcastJitterMs.last)
        require(dedupWindowMs > 0)
        require(reassemblyTimeoutMs > 0)
        require(retentionMs > 0)
        require(futureSkewMs >= 0)
        require(staleAfterMs >= 0)
        require(maxSeenPackets > 0)
        require(maxPartialMessages > 0)
        require(maxCompletedMessages > 0)
        require(maintenanceIntervalMs > 0)
    }
}

/** A channel this node can send and receive on. */
data class MeshChannel(
    val id: ChannelId,
    /** 32-byte channel secret from the QR invite. */
    val key: ByteArray,
    /** Known member Ed25519 public keys. The local identity is added automatically. */
    val members: Collection<ByteArray> = emptyList(),
    val ttl: Int = 5,
) {
    init {
        require(key.size == ChannelKeys.KEY_SIZE) {
            "channel key must be ${ChannelKeys.KEY_SIZE} bytes, got ${key.size}"
        }
        require(ttl in MeshPacket.MIN_TTL..MeshPacket.MAX_TTL) {
            "ttl must be in ${MeshPacket.MIN_TTL}..${MeshPacket.MAX_TTL}"
        }
        members.forEach {
            require(it.size == com.bitaudio.crypto.Ed25519.PUBLIC_KEY_SIZE) {
                "member key must be ${com.bitaudio.crypto.Ed25519.PUBLIC_KEY_SIZE} bytes"
            }
        }
    }
}

/**
 * Default [Mesh]: v1 packet codec, TTL flooding, dedup, reassembly and
 * store-and-forward over any [Transport] (BLE in the app, `FakeTransport` in
 * tests and the simulator).
 *
 * The mesh layer never sees transport-level fragments. It hands one complete
 * mesh packet (at most 512 bytes) to [Transport.send], and the BLE transport's
 * fragmenter adds selective acks and retransmission below that boundary.
 */
class MeshNode(
    private val transport: Transport,
    private val crypto: Crypto,
    localPublicKey: ByteArray,
    private val config: MeshConfig = MeshConfig(),
    private val store: PacketStore = InMemoryPacketStore(),
    private val clock: () -> Long = System::currentTimeMillis,
    externalScope: CoroutineScope? = null,
) : Mesh, Closeable {

    private val localPublicKey: ByteArray = localPublicKey.copyOf()
    private val scope = externalScope ?: CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val ownsScope = externalScope == null
    private val started = AtomicBoolean(false)

    private val channels = LinkedHashMap<ChannelId, ChannelState>()
    private val channelLock = Any()

    private val seen = ExpiringCache<Boolean>(config.maxSeenPackets, clock)
    private val completed = ExpiringCache<Boolean>(config.maxCompletedMessages, clock)
    private val counters = ExpiringCache<String>(config.maxCompletedMessages, clock)
    private val counterLock = Any()
    private val reassembly = ReassemblyBuffer(config.maxPartialMessages, config.reassemblyTimeoutMs, clock)

    private val callbacks = CopyOnWriteArrayList<(MeshMessage) -> Unit>()
    private val random = SecureRandom()
    private val jitterRandom = Random(clock())

    @Volatile
    private var currentPeers: List<Peer> = emptyList()

    private var receiveHandle: AutoCloseable? = null
    private var peerJob: Job? = null
    private var maintenanceJob: Job? = null

    init {
        require(this.localPublicKey.size == com.bitaudio.crypto.Ed25519.PUBLIC_KEY_SIZE) {
            "local public key must be ${com.bitaudio.crypto.Ed25519.PUBLIC_KEY_SIZE} bytes"
        }
    }

    /** Adds or replaces a channel and its roster. */
    fun addChannel(channel: MeshChannel) {
        val directory = PeerDirectory(channel.members)
        directory.add(localPublicKey)
        val state = ChannelState(
            id = channel.id,
            key = channel.key.copyOf(),
            directory = directory,
            ttl = channel.ttl,
        )
        synchronized(channelLock) {
            channels[channel.id]?.let { old -> old.key.fill(0) }
            channels[channel.id] = state
        }
    }

    fun removeChannel(id: ChannelId) {
        synchronized(channelLock) {
            channels.remove(id)?.key?.fill(0)
        }
    }

    /** Starts receiving, rebroadcasting and handing stored packets to new peers. */
    fun start() {
        if (!started.compareAndSet(false, true)) return
        receiveHandle = transport.onReceive(::onFrame)
        peerJob = scope.launch {
            transport.peers().collect { peers ->
                val previous = currentPeers.mapTo(HashSet()) { it.id }
                currentPeers = peers
                peers.filter { it.id !in previous }.forEach { peer ->
                    if (isActive) handOffStored(peer)
                }
            }
        }
        maintenanceJob = scope.launch {
            while (isActive) {
                delay(config.maintenanceIntervalMs)
                try {
                    store.expire(clock())
                    reassembly.expire()
                    seen.prune()
                    completed.prune()
                    counters.prune()
                } catch (t: Throwable) {
                    if (t is CancellationException) throw t
                }
            }
        }
    }

    override suspend fun publish(channel: ChannelId, payload: ByteArray) {
        val state = synchronized(channelLock) { channels[channel] }
            ?: throw MeshException("unknown channel: $channel")
        require(payload.size <= MeshPacket.MAX_PLAINTEXT_MESSAGE_SIZE) {
            "payload is too large: ${payload.size} bytes"
        }

        val now = clock()
        val messageId = ByteArray(ID_SIZE).also(random::nextBytes)
        val identityHex = localPublicKey.toHex()
        val counter = store.nextCounter("${channel.hex}:$identityHex")
        val chunks = payload.splitIntoChunks()
        val messageKey = MeshPacket.messageKey(channel.hex, identityHex, messageId.toHex())
        val packets = ArrayList<ByteArray>(chunks.size)

        for ((index, plaintext) in chunks.withIndex()) {
            val prefix = MeshPacket.headerPrefix(
                type = MeshPacket.TYPE_VOICE_DATA,
                messageId = messageId,
                channelId = channel.toBytes(),
                senderId = RotatingSenderId.derive(
                    channelSecret = state.key,
                    senderPublicKey = localPublicKey,
                    timestampMs = now,
                ),
                ttl = state.ttl,
                chunkIndex = index,
                totalChunks = chunks.size,
                timestampMs = now,
                counter = counter,
            )
            val canonical = prefix.copyOf().also { it[26] = 0 }
            val sealed = PacketCrypto.sealPayload(
                crypto = crypto,
                channelKey = state.key,
                headerPrefix = canonical,
                plaintext = plaintext,
            )
            val signature = PacketCrypto.signPacket(
                crypto = crypto,
                headerPrefix = canonical,
                sealedChunk = sealed,
            )
            val packet = MeshPacket(
                messageId = messageId,
                channelId = channel.toBytes(),
                senderId = prefix.copyOfRange(18, 26),
                ttl = state.ttl,
                chunkIndex = index,
                totalChunks = chunks.size,
                timestampMs = now,
                counter = counter,
                signature = signature,
                sealedChunk = sealed,
            )
            val wire = packet.toWire()
            check(wire.size <= MeshPacket.MAX_PACKET_SIZE) {
                "mesh packet is ${wire.size} bytes, limit is ${MeshPacket.MAX_PACKET_SIZE}"
            }
            packets.add(wire)
        }

        try {
            store.put(
                StoredMessage(
                    key = messageKey,
                    channelId = channel.hex,
                    messageId = messageId.toHex(),
                    createdAtMs = now,
                    timestampMs = now,
                    expiresAtMs = now + config.retentionMs,
                    packets = packets,
                ),
            )
        } catch (t: Throwable) {
            throw MeshException("could not persist outgoing message", t)
        }

        val peers = runCatching { transport.peers().first() }.getOrDefault(currentPeers)
        for (packet in packets) {
            for (peer in peers) {
                try {
                    transport.send(peer, packet)
                } catch (t: CancellationException) {
                    throw t
                } catch (_: TransportException) {
                    // The link is best effort; the message stays in store-and-forward.
                }
            }
        }
    }

    override fun onMessage(callback: (MeshMessage) -> Unit): AutoCloseable {
        callbacks.add(callback)
        return AutoCloseable { callbacks.remove(callback) }
    }

    override fun close() {
        if (!started.compareAndSet(true, false)) {
            if (ownsScope) scope.cancel()
            return
        }
        peerJob?.cancel()
        peerJob = null
        maintenanceJob?.cancel()
        maintenanceJob = null
        receiveHandle?.close()
        receiveHandle = null
        callbacks.clear()
        reassembly.clear()
        seen.clear()
        completed.clear()
        counters.clear()
        currentPeers = emptyList()
        if (ownsScope) scope.cancel()
    }

    private fun onFrame(frame: com.meshvoice.transport.ReceivedFrame) {
        scope.launch {
            try {
                processFrame(frame.from, frame.bytes)
            } catch (t: Throwable) {
                if (t is CancellationException) throw t
                // Attacker-controlled input must never escape the receive path.
            }
        }
    }

    private fun processFrame(from: Peer, wire: ByteArray) {
        val packet = MeshPacket.decode(wire) ?: return
        if (packet.ttl !in MeshPacket.MIN_TTL..MeshPacket.MAX_TTL) return

        val now = clock()
        if (packet.timestampMs > now + config.futureSkewMs) return
        if (packet.timestampMs < now - config.retentionMs) return

        val channelId = ChannelId.fromBytes(packet.channelId)
        val state = synchronized(channelLock) { channels[channelId] } ?: return
        val identity = state.directory.resolve(
            channelSecret = state.key,
            senderId = packet.senderId,
            timestampMs = packet.timestampMs,
        ) ?: return
        val identityHex = identity.toHex()

        val canonical = packet.canonicalPrefix()
        if (!PacketCrypto.verifyPacket(
                crypto = crypto,
                senderPublicKey = identity,
                headerPrefix = canonical,
                sealedChunk = packet.sealedChunk,
                signature = packet.signature,
            )
        ) {
            return
        }

        val plaintext = PacketCrypto.openPayload(
            crypto = crypto,
            channelKey = state.key,
            headerPrefix = canonical,
            sealedChunk = packet.sealedChunk,
        ) ?: return

        if (!acceptCounter(channelId.hex, identityHex, packet.messageIdHex, packet.counter, now)) return

        val nowMs = clock()
        val seenKey = MeshPacket.packetKey(channelId.hex, packet.messageIdHex, packet.chunkIndex)
        if (!seen.putIfAbsent(seenKey, true, nowMs + config.dedupWindowMs)) return

        val messageKey = MeshPacket.messageKey(channelId.hex, identityHex, packet.messageIdHex)
        try {
            store.append(
                key = messageKey,
                channelId = channelId.hex,
                messageId = packet.messageIdHex,
                chunkIndex = packet.chunkIndex,
                packet = wire,
                createdAtMs = nowMs,
                timestampMs = packet.timestampMs,
                expiresAtMs = nowMs + config.retentionMs,
            )
        } catch (_: Throwable) {
            // Delivery must not depend on storage; forwarding still proceeds.
        }

        val complete = reassembly.offer(
            key = messageKey,
            timestampMs = packet.timestampMs,
            totalChunks = packet.totalChunks,
            chunkIndex = packet.chunkIndex,
            plaintext = plaintext,
        )
        if (complete != null) deliver(channelId, state, packet, complete, identityHex, nowMs)

        val stale = nowMs - packet.timestampMs > config.staleAfterMs
        if (packet.ttl > 1 && !stale) {
            val forwarded = packet.withTtl(packet.ttl - 1).toWire()
            val ingressId = from.id
            val jitter = jitterMs()
            scope.launch {
                if (jitter > 0) delay(jitter)
                val peers = currentPeers
                for (peer in peers) {
                    if (peer.id == ingressId) continue
                    try {
                        transport.send(peer, forwarded)
                    } catch (t: CancellationException) {
                        throw t
                    } catch (_: TransportException) {
                        // Another neighbour may still get it; store-and-forward retries later.
                    }
                }
            }
        }
    }

    private fun deliver(
        channelId: ChannelId,
        state: ChannelState,
        packet: MeshPacket,
        payload: ByteArray,
        identityHex: String,
        nowMs: Long,
    ) {
        val deliveryKey = MeshPacket.messageKey(channelId.hex, identityHex, packet.messageIdHex)
        if (!completed.putIfAbsent(deliveryKey, true, nowMs + config.retentionMs)) return

        val message = MeshMessage(
            channel = channelId,
            messageId = packet.messageIdHex,
            senderId = packet.senderIdHex,
            timestampMs = packet.timestampMs,
            hopCount = (state.ttl - packet.ttl).coerceAtLeast(0),
            payload = payload,
        )
        for (callback in callbacks) {
            scope.launch {
                try {
                    callback(message)
                } catch (t: Throwable) {
                    if (t is CancellationException) throw t
                }
            }
        }
    }

    private fun acceptCounter(
        channelHex: String,
        identityHex: String,
        messageId: String,
        counter: Long,
        nowMs: Long,
    ): Boolean = synchronized(counterLock) {
        val key = "$channelHex:$identityHex:$counter"
        val existing = counters.get(key)
        if (existing != null && existing != messageId) return@synchronized false
        counters.put(key, messageId, nowMs + config.retentionMs)
        true
    }

    private fun handOffStored(peer: Peer) {
        scope.launch {
            val now = clock()
            for (message in store.snapshot(now)) {
                for (wire in message.packets) {
                    val packet = MeshPacket.decode(wire) ?: continue
                    val ttl = if (packet.ttl > 1) packet.ttl - 1 else packet.ttl
                    try {
                        transport.send(peer, packet.withTtl(ttl).toWire())
                    } catch (t: CancellationException) {
                        throw t
                    } catch (_: TransportException) {
                        return@launch
                    }
                }
            }
        }
    }

    private fun jitterMs(): Long {
        val range = config.rebroadcastJitterMs
        if (range.first == range.last) return range.first
        val span = range.last - range.first + 1
        return range.first + jitterRandom.nextLong(span)
    }

    private fun ByteArray.splitIntoChunks(): List<ByteArray> {
        if (isEmpty()) return listOf(ByteArray(0))
        val chunks = ArrayList<ByteArray>((size + MeshPacket.MAX_PLAINTEXT_CHUNK_SIZE - 1) / MeshPacket.MAX_PLAINTEXT_CHUNK_SIZE)
        var offset = 0
        while (offset < size) {
            val length = minOf(MeshPacket.MAX_PLAINTEXT_CHUNK_SIZE, size - offset)
            chunks.add(copyOfRange(offset, offset + length))
            offset += length
        }
        return chunks
    }

    private class ChannelState(
        val id: ChannelId,
        val key: ByteArray,
        val directory: PeerDirectory,
        val ttl: Int,
    )

    private companion object {
        const val ID_SIZE = 8
    }
}
