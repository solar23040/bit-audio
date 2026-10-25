package com.solar23040.bitaudio.mesh

import com.bitaudio.crypto.Crypto
import com.bitaudio.crypto.Ed25519
import com.bitaudio.crypto.PacketCrypto
import com.bitaudio.crypto.ReplayGuard
import com.bitaudio.crypto.ReplayVerdict
import com.bitaudio.crypto.RotatingSenderId
import com.meshvoice.transport.Peer
import com.meshvoice.transport.ReceivedFrame
import com.meshvoice.transport.Transport
import com.solar23040.bitaudio.mesh.store.MeshStore
import com.solar23040.bitaudio.mesh.store.StoredPacket
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * TTL-flooding mesh with signed, channel-encrypted packets.
 *
 * Send path: split the plaintext into chunks, seal each chunk with the channel
 * AEAD key (header as associated data), sign the transcript with [crypto], and
 * flood the packets to every neighbour.
 *
 * Receive path, in order and before any relay or delivery:
 * 1. cheap per-neighbour rate limit,
 * 2. packet decode and channel lookup,
 * 3. timestamp window,
 * 4. rotating sender ID resolution against the channel roster,
 * 5. signature verification,
 * 6. per-resolved-sender rate limit and replay/dedup checks,
 * 7. AEAD open, reassembly, local delivery, then jittered relay (TTL - 1).
 *
 * Every failure above is a silent drop: no relay, no callback, no error
 * response. [MeshException] is reserved for local misuse (unknown channel or
 * oversized payload).
 *
 * With a [store], every sealed frame is also persisted (never plaintext) and
 * replayed to newly discovered neighbours with TTL 1, so a clip recorded while
 * offline is handed to the next peer that appears. The store also owns the
 * per-channel counter, which therefore survives process death without ever
 * being reused for a different message.
 */
class MeshEngine(
    private val transport: Transport,
    private val crypto: Crypto,
    localPublicKey: ByteArray,
    initialChannels: Collection<MeshChannel> = emptyList(),
    private val config: MeshConfig = MeshConfig(),
    private val clock: () -> Long = System::currentTimeMillis,
    externalScope: CoroutineScope? = null,
    private val store: MeshStore? = null,
) : Mesh, AutoCloseable {

    private val identityPublicKey: ByteArray = localPublicKey.copyOf()
    private val localTag = IdentityTag(identityPublicKey)
    private val ownsScope = externalScope == null
    private val scope: CoroutineScope =
        externalScope ?: CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val random = SecureRandom()

    private val channels = ConcurrentHashMap<ChannelId, ChannelRuntime>()
    private val callbacks = CopyOnWriteArrayList<(MeshMessage) -> Unit>()
    private val seen = SeenPacketCache(config.maxSeenPackets, config.retentionMs, clock)
    private val neighbourLimiter = RateLimiter(config.perNeighbourRate, clock)
    private val senderLimiter = RateLimiter(config.perSenderRate, clock)

    private val reassemblyLock = Any()
    private val partials = LinkedHashMap<PartialKey, PartialMessage>()
    private val closed = AtomicBoolean(false)

    init {
        require(identityPublicKey.size == Ed25519.PUBLIC_KEY_SIZE) {
            "local public key must be ${Ed25519.PUBLIC_KEY_SIZE} bytes"
        }
        initialChannels.forEach(::addChannel)
    }

    /** Receives frames from the transport. Registered last so all state exists. */
    private val receiveHandle: AutoCloseable = transport.onReceive { frame -> onFrame(frame) }

    /** Replays stored packets to peers as they are discovered. */
    private val peerJob: Job? = if (store != null) {
        scope.launch { collectPeers() }
    } else {
        null
    }

    /** Add or replace the runtime state for [channel]. */
    fun addChannel(channel: MeshChannel) {
        channels[channel.channelId] = ChannelRuntime(
            channel = channel,
            retentionSeconds = maxOf(1L, config.retentionMs / 1000L),
            clock = clock,
        )
    }

    fun removeChannel(channel: ChannelId) {
        channels.remove(channel)
    }

    override suspend fun publish(channel: ChannelId, payload: ByteArray) {
        if (payload.size > config.maxPlaintextBytes) {
            throw MeshException(
                "Payload is ${payload.size} bytes, limit is ${config.maxPlaintextBytes}",
            )
        }
        val runtime = channels[channel] ?: throw MeshException("Unknown channel: $channel")

        val now = clock()
        val timestampSeconds = now / 1000L
        val messageId = ByteArray(MESSAGE_ID_SIZE).also(random::nextBytes)
        val messageIdHex = messageId.toHexString()
        val counter = store?.nextCounter(channel) ?: runtime.nextCounter()
        if (counter !in 1..0xFFFF_FFFFL) {
            throw MeshException("Counter exhausted on channel $channel")
        }
        if (!runtime.acceptCounter(localTag.hex, counter, messageIdHex)) {
            throw MeshException("Replay counter collision on channel $channel")
        }
        val senderId = RotatingSenderId.derive(
            runtime.channel.channelKey,
            identityPublicKey,
            timestampSeconds,
        )

        val totalChunks = maxOf(
            1,
            (payload.size + MeshPacketCodec.MAX_CHUNK_PLAINTEXT - 1) /
                MeshPacketCodec.MAX_CHUNK_PLAINTEXT,
        )
        if (totalChunks > MeshPacketCodec.MAX_TOTAL_CHUNKS) {
            throw MeshException("Payload needs $totalChunks chunks, limit is 256")
        }

        val packets = ArrayList<ByteArray>(totalChunks)
        for (index in 0 until totalChunks) {
            val from = index * MeshPacketCodec.MAX_CHUNK_PLAINTEXT
            val to = minOf(payload.size, from + MeshPacketCodec.MAX_CHUNK_PLAINTEXT)
            val header = MeshPacketHeader(
                type = MeshPacketCodec.TYPE_VOICE_DATA,
                messageId = messageId,
                channelId = channel,
                senderId = senderId,
                ttl = config.defaultTtl,
                chunkIndex = index,
                totalChunks = totalChunks,
                timestampMs = now,
                counter = counter,
            )
            packets += sealPacket(runtime, header, payload.copyOfRange(from, to))
        }

        // Persist before the first hop so a clip recorded with no neighbours is
        // handed off later. Storage is sealed frames only.
        store?.let { store ->
            try {
                expireStored()
                for (index in packets.indices) {
                    store.save(
                        StoredPacket(
                            channel = channel,
                            messageId = messageIdHex,
                            chunkIndex = index,
                            timestampMs = now,
                            expiresAtMs = now + config.retentionMs,
                            frame = packets[index],
                        ),
                    )
                }
            } catch (e: Exception) {
                throw MeshException("Could not store outgoing packets", e)
            }
        }

        // Seed our own replay/dedup state so a looped echo cannot be relayed or
        // delivered back to the publisher.
        for (index in packets.indices) {
            runtime.checkReplay(
                localTag.bytes,
                replayMessageId(messageId, index),
                timestampSeconds,
            )
            seen.firstSeen(
                SeenPacketCache.Key(channel.hex, localTag.hex, messageIdHex, index),
            )
        }

        val neighbours = transport.peers().first()
        for (packet in packets) {
            for (peer in neighbours) {
                try {
                    transport.send(peer, packet)
                } catch (_: Exception) {
                    // The frame is already in the store, so the next peer
                    // discovery or a later replay retries it.
                }
            }
        }
    }

    override fun onMessage(callback: (MeshMessage) -> Unit): AutoCloseable {
        callbacks.add(callback)
        return AutoCloseable { callbacks.remove(callback) }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        peerJob?.cancel()
        runCatching { receiveHandle.close() }
        if (ownsScope) scope.cancel()
        callbacks.clear()
        synchronized(reassemblyLock) { partials.clear() }
        seen.clear()
    }

    private fun sealPacket(
        runtime: ChannelRuntime,
        header: MeshPacketHeader,
        plaintext: ByteArray,
    ): ByteArray {
        val canonical = MeshPacketCodec.headerBytes(header.copy(ttl = 0))
        val sealed = PacketCrypto.sealPayload(
            crypto,
            runtime.channel.channelKey,
            canonical,
            plaintext,
        )
        val signature = PacketCrypto.signPacket(crypto, canonical, sealed)
        return MeshPacketCodec.encode(header, signature, sealed)
    }

    private fun onFrame(frame: ReceivedFrame) {
        try {
            handleFrame(frame)
        } catch (_: Exception) {
            // Peer input is untrusted: a malformed packet must never escape the
            // transport callback.
        }
    }

    private fun handleFrame(frame: ReceivedFrame) {
        if (!neighbourLimiter.tryAcquire(frame.from.id)) return

        val packet = MeshPacketCodec.decode(frame.bytes) ?: return
        val runtime = channels[packet.header.channelId] ?: return
        val now = clock()
        val timestampMs = packet.header.timestampMs
        if (timestampMs > now + config.maxClockSkewMs) return
        if (timestampMs < now - config.retentionMs) return
        if (packet.header.counter <= 0) return

        val senderPublicKey = runtime.channel.directory.resolve(
            runtime.channel.channelKey,
            packet.header.senderId,
            timestampMs / 1000L,
        ) ?: return

        val canonical = MeshPacketCodec.headerBytes(packet.header.copy(ttl = 0))
        if (!PacketCrypto.verifyPacket(
                crypto,
                senderPublicKey,
                canonical,
                packet.sealedPayload,
                packet.signature,
            )
        ) {
            return
        }

        // Rate limit on the resolved identity, never on the rotating ID, so a
        // new epoch does not reset the bucket.
        val tag = IdentityTag(senderPublicKey)
        if (!senderLimiter.tryAcquire(tag.hex)) return

        val messageIdHex = packet.header.messageId.toHexString()
        if (!runtime.acceptCounter(tag.hex, packet.header.counter, messageIdHex)) return

        val verdict = runtime.checkReplay(
            tag.bytes,
            replayMessageId(packet.header.messageId, packet.header.chunkIndex),
            timestampMs / 1000L,
        )
        if (verdict != ReplayVerdict.ACCEPT) return

        val seenKey = SeenPacketCache.Key(
            packet.header.channelId.hex,
            tag.hex,
            messageIdHex,
            packet.header.chunkIndex,
        )
        if (!seen.firstSeen(seenKey)) return

        val plaintext = PacketCrypto.openPayload(
            crypto,
            runtime.channel.channelKey,
            canonical,
            packet.sealedPayload,
        ) ?: return

        persistReceived(frame.bytes, packet, messageIdHex, now)

        val hopCount = (config.defaultTtl - packet.header.ttl).coerceAtLeast(0)
        deliverChunk(runtime, packet.header, tag, messageIdHex, hopCount, plaintext, now)

        if (packet.header.ttl > 1 && !isStale(timestampMs, now)) {
            relay(frame.bytes, packet.header.ttl - 1, frame.from)
        }
    }

    /**
     * Keep a verified, decrypted frame for store-and-forward. Frames go to the
     * store only after authentication, so a malicious neighbour cannot fill it.
     * A storage failure must not interrupt local delivery.
     */
    private fun persistReceived(
        frameBytes: ByteArray,
        packet: MeshPacket,
        messageIdHex: String,
        now: Long,
    ) {
        val store = store ?: return
        try {
            store.save(
                StoredPacket(
                    channel = packet.header.channelId,
                    messageId = messageIdHex,
                    chunkIndex = packet.header.chunkIndex,
                    timestampMs = packet.header.timestampMs,
                    expiresAtMs = now + config.retentionMs,
                    frame = frameBytes,
                ),
            )
        } catch (_: Exception) {
            // Delivery already succeeded; the packet simply is not retried.
        }
    }

    /** Watches topology changes and hands stored frames to each new neighbour. */
    private suspend fun collectPeers() {
        val known = HashSet<String>()
        try {
            transport.peers().collect { peers ->
                val current = peers.mapTo(HashSet()) { it.id }
                known.retainAll(current)
                val added = peers.filter { known.add(it.id) }
                if (added.isNotEmpty()) replayStored(added)
            }
        } catch (expected: CancellationException) {
            throw expected
        } catch (_: Exception) {
            // A broken transport flow stops handoff but never local delivery.
        }
    }

    /**
     * Re-sends stored frames to [peers] with TTL forced to 1: receivers deliver
     * and ack them locally but do not flood them again. The signature stays
     * valid because TTL is not signed, and it is re-verified before sending.
     */
    private fun replayStored(peers: List<Peer>) {
        val store = store ?: return
        val now = clock()
        val packets = try {
            expireStored()
            store.loadUnexpired(now)
        } catch (_: Exception) {
            return
        }
        if (packets.isEmpty()) return

        scope.launch {
            for (packet in packets) {
                if (closed.get()) return@launch
                val runtime = channels[packet.channel] ?: continue
                val decoded = MeshPacketCodec.decode(packet.frame) ?: continue
                if (decoded.header.channelId != packet.channel) continue
                if (decoded.header.messageId.toHexString() != packet.messageId) continue
                if (decoded.header.chunkIndex != packet.chunkIndex) continue

                val sender = runtime.channel.directory.resolve(
                    runtime.channel.channelKey,
                    decoded.header.senderId,
                    decoded.header.timestampMs / 1000L,
                ) ?: continue
                val canonical = MeshPacketCodec.headerBytes(decoded.header.copy(ttl = 0))
                if (!PacketCrypto.verifyPacket(
                        crypto,
                        sender,
                        canonical,
                        decoded.sealedPayload,
                        decoded.signature,
                    )
                ) {
                    continue
                }

                val frame = MeshPacketCodec.withTtl(packet.frame, 1) ?: continue
                for (peer in peers) {
                    try {
                        transport.send(peer, frame)
                    } catch (_: Exception) {
                        // The next topology change or retry will try again.
                    }
                }
            }
        }
    }

    private fun expireStored() {
        runCatching { store?.deleteExpired(clock()) }
    }

    /** Number of frames currently held by the store. */
    fun storedPacketCount(): Int = runCatching { store?.size() ?: 0 }.getOrDefault(0)

    private fun isStale(timestampMs: Long, now: Long): Boolean =
        now - timestampMs > config.staleAfterMs

    private fun relay(frameBytes: ByteArray, ttl: Int, ingress: Peer) {
        val forwarded = MeshPacketCodec.withTtl(frameBytes, ttl) ?: return
        scope.launch {
            delay(sampleJitterMs())
            val neighbours = try {
                transport.peers().first()
            } catch (_: Exception) {
                return@launch
            }
            for (peer in neighbours) {
                if (peer.id == ingress.id) continue
                try {
                    transport.send(peer, forwarded)
                } catch (_: Exception) {
                    // Drop for this link; flooding is best effort.
                }
            }
        }
    }

    private fun sampleJitterMs(): Long {
        val range = config.jitterMs
        if (range.first == range.last) return range.first
        val span = range.last - range.first + 1L
        return range.first + random.nextInt(span.toInt())
    }

    private fun deliverChunk(
        runtime: ChannelRuntime,
        header: MeshPacketHeader,
        tag: IdentityTag,
        messageIdHex: String,
        hopCount: Int,
        plaintext: ByteArray,
        now: Long,
    ) {
        val key = PartialKey(header.channelId.hex, tag.hex, messageIdHex)
        var message: MeshMessage? = null

        synchronized(reassemblyLock) {
            purgePartials(now)
            val existing = partials[key]
            if (existing != null &&
                (existing.totalChunks != header.totalChunks ||
                    existing.timestampMs != header.timestampMs ||
                    existing.counter != header.counter)
            ) {
                // The same (channel, sender, msg_id) with inconsistent routing
                // metadata is forged or corrupt: drop the whole reassembly.
                partials.remove(key)
                return
            }

            val partial = existing ?: PartialMessage(
                totalChunks = header.totalChunks,
                timestampMs = header.timestampMs,
                counter = header.counter,
                createdAt = now,
            ).also {
                if (partials.size >= config.maxPartialMessages) evictOldestPartial()
                partials[key] = it
            }

            if (partial.chunks[header.chunkIndex] != null) return
            if (partial.bytes + plaintext.size > config.maxPlaintextBytes) {
                partials.remove(key)
                return
            }

            partial.chunks[header.chunkIndex] = plaintext
            partial.bytes += plaintext.size
            if (partial.chunks.any { it == null }) return

            partials.remove(key)
            val payload = ByteArray(partial.bytes)
            var offset = 0
            for (chunk in partial.chunks) {
                val bytes = requireNotNull(chunk)
                bytes.copyInto(payload, offset)
                offset += bytes.size
            }
            message = MeshMessage(
                channel = header.channelId,
                messageId = messageIdHex,
                senderId = header.senderId.toHexString(),
                timestampMs = header.timestampMs,
                hopCount = hopCount,
                payload = payload,
            )
        }

        message?.let(::emit)
    }

    private fun emit(message: MeshMessage) {
        for (callback in callbacks) {
            runCatching { callback(message) }
        }
    }

    private fun purgePartials(now: Long) {
        val iterator = partials.entries.iterator()
        while (iterator.hasNext()) {
            if (now - iterator.next().value.createdAt > config.reassemblyTimeoutMs) {
                iterator.remove()
            }
        }
    }

    private fun evictOldestPartial() {
        var oldestKey: PartialKey? = null
        var oldestCreatedAt = Long.MAX_VALUE
        for ((key, partial) in partials) {
            if (partial.createdAt < oldestCreatedAt) {
                oldestCreatedAt = partial.createdAt
                oldestKey = key
            }
        }
        if (oldestKey != null) partials.remove(oldestKey)
    }

    private data class PartialKey(
        val channelHex: String,
        val identityTag: String,
        val messageIdHex: String,
    )

    private class PartialMessage(
        val totalChunks: Int,
        val timestampMs: Long,
        val counter: Long,
        val createdAt: Long,
    ) {
        val chunks: Array<ByteArray?> = arrayOfNulls(totalChunks)
        var bytes: Int = 0
    }

    /** Per-channel replay and counter state. */
    private class ChannelRuntime(
        val channel: MeshChannel,
        retentionSeconds: Long,
        clock: () -> Long,
    ) {
        private data class CounterKey(
            val identityTag: String,
            val counter: Long,
        )

        private val replayGuard = ReplayGuard(
            timestampWindowSeconds = retentionSeconds,
            maxSeenIdsPerSender = 4096,
            clock = clock,
        )

        private val nextCounter = AtomicLong(0L)
        private val counterToMessage = LinkedHashMap<CounterKey, String>()

        fun checkReplay(
            identityTag: ByteArray,
            packetId: Long,
            timestampSeconds: Long,
        ): ReplayVerdict = replayGuard.check(identityTag, packetId, timestampSeconds)

        fun nextCounter(): Long = nextCounter.incrementAndGet()

        /**
         * A counter maps to exactly one msg_id. Reusing it for a different
         * message is a replay; older counters stay valid for stored messages.
         */
        @Synchronized
        fun acceptCounter(identityTag: String, counter: Long, messageIdHex: String): Boolean {
            if (counter <= 0 || counter > 0xFFFF_FFFFL) return false
            val key = CounterKey(identityTag, counter)
            val known = counterToMessage[key]
            if (known != null) return known == messageIdHex

            counterToMessage[key] = messageIdHex
            while (counterToMessage.size > MAX_COUNTER_ENTRIES) {
                val oldest = counterToMessage.keys.iterator()
                if (!oldest.hasNext()) break
                oldest.next()
                oldest.remove()
            }
            return true
        }

        private companion object {
            const val MAX_COUNTER_ENTRIES = 4096
        }
    }

    private companion object {
        const val MESSAGE_ID_SIZE = 8
    }
}
