package com.solar23040.bitaudio.mesh

import com.bitaudio.crypto.Crypto
import com.bitaudio.crypto.Ed25519
import com.bitaudio.crypto.PacketCrypto
import com.bitaudio.crypto.RotatingSenderId
import com.meshvoice.transport.Peer
import com.meshvoice.transport.Transport
import com.solar23040.bitaudio.mesh.cache.CounterLedger
import com.solar23040.bitaudio.mesh.cache.SeenIdCache
import com.solar23040.bitaudio.mesh.packet.MeshPacket
import com.solar23040.bitaudio.mesh.store.InMemoryMeshStore
import com.solar23040.bitaudio.mesh.store.MeshStore
import com.solar23040.bitaudio.mesh.store.StoredPacket
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore

/**
 * TTL-flooding [Mesh] with signature verification, chunk dedup, jittered
 * rebroadcast, reassembly, and store-and-forward.
 *
 * Construction takes the local identity public key explicitly because
 * [Crypto] deliberately hides it; wiring code with `DefaultCrypto` can pass
 * `crypto.publicKey`.
 *
 * All peer input is untrusted: malformed frames are dropped silently and no
 * validation path throws on attacker bytes. [close] releases the transport
 * subscription and cancels mesh-owned coroutines.
 */
class FloodMesh(
    private val transport: Transport,
    private val crypto: Crypto,
    identityPublicKey: ByteArray,
    initialChannels: Collection<MeshChannel> = emptyList(),
    private val config: MeshConfig = MeshConfig(),
    store: MeshStore? = null,
    meshScope: CoroutineScope? = null,
) : Mesh, AutoCloseable {

    private val localPublicKey: ByteArray = identityPublicKey.copyOf()
    private val channels = ConcurrentHashMap<ChannelId, MeshChannel>()
    private val packetStore: MeshStore = store ?: InMemoryMeshStore()
    private val ownsStore: Boolean = store == null
    private val scope: CoroutineScope = meshScope
        ?: CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val ownsScope: Boolean = meshScope == null

    private val seenChunks = SeenIdCache(config.maxSeenChunks, config.seenExpiryMs, config.clock)
    private val completedMessages =
        SeenIdCache(config.maxCompletedMessages, config.retentionMs, config.clock)
    private val counterLedger = CounterLedger(config.retentionMs, config.clock)
    private val callbacks = CopyOnWriteArrayList<(MeshMessage) -> Unit>()
    private val relays = Semaphore(config.maxRelayQueue)
    private val secureRandom = SecureRandom()
    private val jitterLock = Any()

    /**
     * Expiry time of messages published on this device, keyed by channel +
     * msg_id. Store-and-forward never replays them: a freshly published packet
     * is already flooding at full TTL, and handing a ttl=1 copy to a peer would
     * deliver it there without the rest of the flood ever starting.
     */
    private val ownMessages = ConcurrentHashMap<String, Long>()

    private val assembliesLock = Any()
    private val assemblies = LinkedHashMap<AssemblyKey, Assembly>()

    init {
        require(localPublicKey.size == Ed25519.PUBLIC_KEY_SIZE) {
            "identity public key must be ${Ed25519.PUBLIC_KEY_SIZE} bytes"
        }
        initialChannels.forEach { channels[it.id] = it }
    }

    private val receiveHandle = transport.onReceive { frame ->
        val copy = frame.bytes.copyOf()
        val from = frame.from
        scope.launch { handleFrame(from, copy) }
    }

    private val peerJob = scope.launch { collectPeers() }

    /** Registers an additional channel after construction. */
    fun addChannel(channel: MeshChannel) {
        channels[channel.id] = channel
    }

    fun removeChannel(channel: ChannelId) {
        channels.remove(channel)
    }

    override suspend fun publish(channel: ChannelId, payload: ByteArray) {
        val meshChannel = channels[channel]
            ?: throw MeshException("Unknown channel: ${channel.hex}")
        if (payload.size > MeshPacket.MAX_PLAINTEXT_SIZE) {
            throw MeshException("Payload exceeds ${MeshPacket.MAX_PLAINTEXT_SIZE} bytes")
        }

        val frames = buildMessage(meshChannel, payload.copyOf())
        val peers = try {
            transport.peers().first()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            emptyList()
        }
        if (peers.isEmpty()) return

        // The caller may reuse its buffer as soon as this returns; every frame
        // is already an independent immutable byte array.
        coroutineScope {
            frames.forEach { frame ->
                peers.forEach { peer ->
                    launch {
                        runCatching { transport.send(peer, frame) }
                    }
                }
            }
        }
    }

    override fun onMessage(callback: (MeshMessage) -> Unit): AutoCloseable {
        callbacks.add(callback)
        return AutoCloseable { callbacks.remove(callback) }
    }

    override fun close() {
        receiveHandle.close()
        peerJob.cancel()
        if (ownsScope) scope.cancel()
        if (ownsStore) runCatching { packetStore.close() }
    }

    /**
     * Deletes expired store-and-forward rows. Called automatically on peer
     * discovery; exposed for periodic maintenance from the app.
     */
    fun expireStored(): Int = runCatching { packetStore.deleteExpired(config.clock()) }.getOrDefault(0)

    /** Number of stored rows (including expired rows not swept yet). */
    fun storedPacketCount(): Int = runCatching { packetStore.size() }.getOrDefault(0)

    // ---------------------------------------------------------------- publish

    private fun buildMessage(channel: MeshChannel, payload: ByteArray): List<ByteArray> {
        val totalChunks = if (payload.isEmpty()) {
            1
        } else {
            (payload.size + MeshPacket.PLAINTEXT_CHUNK_SIZE - 1) / MeshPacket.PLAINTEXT_CHUNK_SIZE
        }
        if (totalChunks > MeshPacket.MAX_TOTAL_CHUNKS) {
            throw MeshException("Payload needs $totalChunks chunks; maximum is ${MeshPacket.MAX_TOTAL_CHUNKS}")
        }

        val now = config.clock()
        val msgId = ByteArray(MeshPacket.ID_SIZE).also { secureRandom.nextBytes(it) }
        val messageIdHex = msgId.toHex()
        pruneOwnMessages(now)
        ownMessages[ownMessageKey(channel.id, messageIdHex)] = now + config.retentionMs
        val localIdentityHex = localPublicKey.toHex()
        val channelIdBytes = channel.id.toBytes()
        val senderId = RotatingSenderId.derive(
            channel.keyBytes(),
            localPublicKey,
            now / 1_000L,
        )
        val counter = try {
            packetStore.nextCounter(channel.id)
        } catch (failure: Exception) {
            throw MeshException("Mesh storage is unavailable", failure)
        }
        if (counter > MeshPacket.MAX_COUNTER) {
            throw MeshException("Message counter exhausted for channel ${channel.id.hex}")
        }

        val frames = ArrayList<ByteArray>(totalChunks)
        for (index in 0 until totalChunks) {
            val start = index * MeshPacket.PLAINTEXT_CHUNK_SIZE
            val end = minOf(payload.size, start + MeshPacket.PLAINTEXT_CHUNK_SIZE)
            val plaintext = if (start >= payload.size) ByteArray(0) else payload.copyOfRange(start, end)

            val base = MeshPacket(
                version = MeshPacket.VERSION,
                type = MeshPacket.TYPE_VOICE_DATA,
                msgId = msgId,
                channelId = channelIdBytes,
                senderId = senderId,
                ttl = config.defaultTtl,
                chunkIdx = index,
                totalChunks = totalChunks,
                timestampMs = now,
                counter = counter,
                signature = ByteArray(MeshPacket.SIGNATURE_SIZE),
                payload = ByteArray(0),
            )
            val canonical = base.canonicalHeader()
            val sealed = PacketCrypto.sealPayload(crypto, channel.keyBytes(), canonical, plaintext)
            if (sealed.size > MeshPacket.MAX_PAYLOAD_SIZE) {
                throw MeshException("Sealed chunk exceeds the frame limit")
            }
            val signature = PacketCrypto.signPacket(crypto, canonical, sealed)
            val frame = base.copy(signature = signature, payload = sealed).encode()

            // Remember our own chunks so a relayed echo is dropped before
            // reassembly: the publisher already has the clip and must not
            // deliver it to itself or re-flood the echo.
            seenChunks.markSeen(chunkKey(channel.id, localIdentityHex, messageIdHex, index))

            try {
                packetStore.save(
                    StoredPacket(
                        channel = channel.id,
                        messageId = messageIdHex,
                        chunkIndex = index,
                        timestampMs = now,
                        expiresAtMs = now + config.retentionMs,
                        frame = frame,
                    ),
                )
            } catch (failure: Exception) {
                throw MeshException("Mesh storage is full", failure)
            }
            frames.add(frame)
        }
        completedMessages.markSeen(completedKey(channel.id, localIdentityHex, messageIdHex))
        return frames
    }

    // ----------------------------------------------------------------- receive

    private fun handleFrame(ingress: Peer, bytes: ByteArray) {
        val packet = MeshPacket.decode(bytes) ?: return
        if (packet.type != MeshPacket.TYPE_VOICE_DATA) return
        if (packet.payload.size < MeshPacket.MIN_SEALED_CHUNK_SIZE) return

        val channel = channels[ChannelId.fromBytes(packet.channelId)] ?: return
        val now = config.clock()
        if (!isFresh(packet.timestampMs, now)) return

        val senderPublicKey = channel.roster.resolve(
            channel.keyBytes(),
            packet.senderId,
            packet.timestampMs / 1_000L,
        ) ?: return

        val canonical = packet.canonicalHeader()
        if (!PacketCrypto.verifyPacket(crypto, senderPublicKey, canonical, packet.payload, packet.signature)) {
            return
        }

        val identityHex = senderPublicKey.toHex()
        val messageIdHex = packet.msgId.toHex()
        if (!counterLedger.accept(channel.id, identityHex, packet.counter, messageIdHex)) return

        // Dedup is keyed by the stable identity, not the rotating sender ID.
        val seenKey = chunkKey(channel.id, identityHex, messageIdHex, packet.chunkIdx)
        if (!seenChunks.markSeen(seenKey)) return

        persist(channel, packet, now)
        acceptChunk(channel, identityHex, messageIdHex, packet, now)

        val stale = now - packet.timestampMs > config.staleAfterMs
        if (packet.ttl > 1 && !stale) {
            scheduleRebroadcast(ingress, packet)
        }
    }

    private fun isFresh(timestampMs: Long, now: Long): Boolean {
        if (timestampMs > now + config.maxFutureSkewMs) return false
        if (timestampMs < now - config.retentionMs) return false
        return true
    }

    private fun persist(channel: MeshChannel, packet: MeshPacket, now: Long) {
        runCatching {
            packetStore.save(
                StoredPacket(
                    channel = channel.id,
                    messageId = packet.msgId.toHex(),
                    chunkIndex = packet.chunkIdx,
                    timestampMs = packet.timestampMs,
                    expiresAtMs = now + config.retentionMs,
                    frame = packet.encode(),
                ),
            )
        }
    }

    private fun scheduleRebroadcast(ingress: Peer, packet: MeshPacket) {
        scope.launch {
            if (!relays.tryAcquire()) return@launch
            try {
                val jitter = nextJitterMs()
                if (jitter > 0) delay(jitter)

                val outbound = packet.copy(ttl = packet.ttl - 1).encode()
                val peers = try {
                    transport.peers().first()
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    emptyList()
                }

                coroutineScope {
                    peers.forEach { peer ->
                        if (peer.id == ingress.id) return@forEach
                        launch {
                            runCatching { transport.send(peer, outbound) }
                        }
                    }
                }
            } finally {
                relays.release()
            }
        }
    }

    private fun nextJitterMs(): Long = synchronized(jitterLock) {
        val range = config.jitterMs
        if (range.first >= range.last) {
            range.first
        } else {
            config.random.nextLong(range.first, range.last + 1L)
        }
    }

    // -------------------------------------------------------------- reassembly

    private fun acceptChunk(
        channel: MeshChannel,
        identityHex: String,
        messageIdHex: String,
        packet: MeshPacket,
        now: Long,
    ) {
        val key = AssemblyKey(channel.id, identityHex, messageIdHex)
        val complete: Assembly? = synchronized(assembliesLock) {
            pruneAssemblies(now)

            val existing = assemblies[key]
            if (existing != null &&
                (existing.totalChunks != packet.totalChunks || existing.timestampMs != packet.timestampMs)
            ) {
                assemblies.remove(key)
                null
            } else {
                val assembly = existing ?: Assembly(
                    messageIdHex = messageIdHex,
                    totalChunks = packet.totalChunks,
                    timestampMs = packet.timestampMs,
                    senderIdHex = packet.senderId.toHex(),
                    createdAtMs = now,
                ).also { assemblies[key] = it }

                if (assembly.packets.putIfAbsent(packet.chunkIdx, packet) == null) {
                    assembly.maxTtl = maxOf(assembly.maxTtl, packet.ttl)
                }

                if (assembly.packets.size >= assembly.totalChunks) {
                    assemblies.remove(key)
                    assembly
                } else {
                    null
                }
            }
        }

        if (complete != null) deliver(channel, identityHex, complete)
    }

    private fun deliver(channel: MeshChannel, identityHex: String, assembly: Assembly) {
        val plaintext = ByteArrayOutputStream()
        for (index in 0 until assembly.totalChunks) {
            val chunk = assembly.packets[index] ?: return
            val opened = PacketCrypto.openPayload(
                crypto,
                channel.keyBytes(),
                chunk.canonicalHeader(),
                chunk.payload,
            ) ?: return
            if (plaintext.size() + opened.size > MeshPacket.MAX_PLAINTEXT_SIZE) return
            plaintext.write(opened)
        }

        // Completed messages are deduplicated per resolved identity for the
        // whole retention window, so a late replay cannot deliver twice.
        val messageKey = completedKey(channel.id, identityHex, assembly.messageIdHex)
        if (!completedMessages.markSeen(messageKey)) return

        val message = MeshMessage(
            channel = channel.id,
            messageId = assembly.messageIdHex,
            senderId = assembly.senderIdHex,
            timestampMs = assembly.timestampMs,
            hopCount = (config.defaultTtl - assembly.maxTtl).coerceAtLeast(0),
            payload = plaintext.toByteArray(),
        )
        callbacks.forEach { callback ->
            runCatching { callback(message) }
        }
    }

    private fun pruneAssemblies(now: Long) {
        val iterator = assemblies.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.createdAtMs > config.reassemblyTimeoutMs) iterator.remove()
        }
        while (assemblies.size > config.maxPartialMessages) {
            val oldest = assemblies.keys.iterator()
            if (!oldest.hasNext()) return
            oldest.next()
            oldest.remove()
        }
    }

    private fun chunkKey(
        channel: ChannelId,
        identityHex: String,
        messageIdHex: String,
        chunkIdx: Int,
    ): String = "${channel.hex}:$identityHex:$messageIdHex:$chunkIdx"

    private fun completedKey(
        channel: ChannelId,
        identityHex: String,
        messageIdHex: String,
    ): String = "${channel.hex}:$identityHex:$messageIdHex"

    // ------------------------------------------------------ store and forward

    private suspend fun collectPeers() {
        val known = HashSet<String>()

        transport.peers().catch { /* transport shut down: stop watching */ }.collect { peers ->
            val current = peers.map { it.id }.toSet()
            val added = peers.filter { it.id !in known }
            known.retainAll(current)
            if (added.isEmpty()) return@collect
            known.addAll(added.map { it.id })

            try {
                replayStored(added)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                // A failed replay must not kill topology monitoring.
            }
        }
    }

    private suspend fun replayStored(peers: List<Peer>) {
        val now = config.clock()
        pruneOwnMessages(now)
        runCatching { packetStore.deleteExpired(now) }
        val stored = runCatching { packetStore.loadUnexpired(now) }.getOrDefault(emptyList())
        if (stored.isEmpty()) return

        coroutineScope {
            stored.forEach { packet ->
                // Our own packets are flooding at full TTL already.
                if (isOwnMessage(packet)) return@forEach
                val frame = staleFrame(packet.frame) ?: return@forEach
                peers.forEach { peer ->
                    launch {
                        runCatching { transport.send(peer, frame) }
                    }
                }
            }
        }
    }

    private fun isOwnMessage(packet: StoredPacket): Boolean =
        ownMessages[ownMessageKey(packet.channel, packet.messageId)] != null

    private fun pruneOwnMessages(now: Long) {
        ownMessages.entries.removeAll { entry -> entry.value <= now }
    }

    private fun ownMessageKey(channel: ChannelId, messageIdHex: String): String =
        "${channel.hex}:$messageIdHex"

    /**
     * Replayed packets keep their signature, timestamp and counter but travel
     * with TTL 1. Receivers therefore deliver them locally and never re-flood
     * them, which keeps store-and-forward from creating loops.
     */
    private fun staleFrame(frame: ByteArray): ByteArray? {
        if (frame.size < MeshPacket.HEADER_SIZE) return null
        val copy = frame.copyOf()
        copy[TTL_OFFSET] = 1
        return copy
    }

    private data class AssemblyKey(
        val channel: ChannelId,
        val identityHex: String,
        val messageIdHex: String,
    )

    private class Assembly(
        val messageIdHex: String,
        val totalChunks: Int,
        val timestampMs: Long,
        val senderIdHex: String,
        val createdAtMs: Long,
    ) {
        val packets = HashMap<Int, MeshPacket>()
        var maxTtl: Int = 0
    }

    private companion object {
        const val TTL_OFFSET = 26
    }
}

private fun ByteArray.toHex(): String {
    val digits = "0123456789abcdef"
    return buildString(size * 2) {
        for (byte in this@toHex) {
            val value = byte.toInt() and 0xFF
            append(digits[value ushr 4])
            append(digits[value and 0x0F])
        }
    }
}
