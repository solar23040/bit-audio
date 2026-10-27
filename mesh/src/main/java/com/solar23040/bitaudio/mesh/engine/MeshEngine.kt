package com.solar23040.bitaudio.mesh.engine

import com.bitaudio.crypto.Crypto
import com.bitaudio.crypto.Ed25519
import com.bitaudio.crypto.IdentityFingerprint
import com.bitaudio.crypto.NearbyChannel
import com.bitaudio.crypto.PacketCrypto
import com.bitaudio.crypto.ReplayGuard
import com.bitaudio.crypto.ReplayVerdict
import com.bitaudio.crypto.RotatingSenderId
import com.meshvoice.transport.Peer
import com.meshvoice.transport.ReceivedFrame
import com.meshvoice.transport.Transport
import com.solar23040.bitaudio.mesh.ChannelId
import com.solar23040.bitaudio.mesh.Mesh
import com.solar23040.bitaudio.mesh.MeshException
import com.solar23040.bitaudio.mesh.MeshMessage
import com.solar23040.bitaudio.mesh.NearbyPeer
import com.solar23040.bitaudio.mesh.engine.store.MeshStore
import com.solar23040.bitaudio.mesh.engine.store.StoredPacket
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
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
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
 *
 * Nearby discovery uses the public [NearbyChannel]. A discoverable node sends a
 * signed `MEMBER_ANNOUNCE` on peer connect and every
 * [MeshConfig.announceIntervalMs]; receivers rate-limit per identity, expire
 * quiet peers after [MeshConfig.peerTimeoutMs], and expose them through
 * [peers]. Announcements are authenticated but not encrypted.
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
    initialNickname: String = "",
    discoverable: Boolean = false,
    private val announceCapabilities: Int = NearbyAnnounceCodec.DEFAULT_CAPABILITIES,
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
    private val announceLimiter = RateLimiter(config.announceRate, clock)

    private val nearbyChannelId = ChannelId.fromBytes(NearbyChannel.channelId())
    private val localFingerprint = IdentityFingerprint.of(identityPublicKey)
    private val nearbyRecords = LinkedHashMap<String, NearbyRecord>()
    private val nearbyLock = Any()
    private val _nearbyPeers = MutableStateFlow<List<NearbyPeer>>(emptyList())

    @Volatile
    private var nickname: String = NearbyAnnounceCodec.sanitiseNickname(initialNickname) ?: ""

    @Volatile
    private var discoverableRequested: Boolean = discoverable

    @Volatile
    private var announceEnabled: Boolean = discoverable && nickname.isNotBlank()

    private val reassemblyLock = Any()
    private val partials = LinkedHashMap<PartialKey, PartialMessage>()
    private val closed = AtomicBoolean(false)

    init {
        require(identityPublicKey.size == Ed25519.PUBLIC_KEY_SIZE) {
            "local public key must be ${Ed25519.PUBLIC_KEY_SIZE} bytes"
        }
        initialChannels.forEach(::addChannel)
        // The nearby channel is always present: discovery and the public feed
        // must work on first launch without joining anything.
        if (!channels.containsKey(nearbyChannelId)) {
            addChannel(MeshChannel(NearbyChannel.key(), listOf(identityPublicKey)))
        }
    }

    /** Receives frames from the transport. Registered last so all state exists. */
    private val receiveHandle: AutoCloseable = transport.onReceive { frame -> onFrame(frame) }

    /**
     * Replays stored packets and announces to peers as they are discovered.
     * Started lazily so a plain non-discoverable engine has no long-lived peer
     * collector (and existing tests stay deterministic).
     */
    @Volatile
    private var peerJob: Job? = null

    /** Sends a fresh announcement on connect and then on a fixed interval. */
    @Volatile
    private var announceJob: Job? = null

    /** Removes quiet peers even when no new announce arrives. */
    @Volatile
    private var peerSweepJob: Job? = null

    init {
        // Runs after every backing field above has been initialised.
        if (store != null || announceEnabled) startPeerJob()
        if (announceEnabled) startAnnounceLoop()
    }

    private fun startPeerJob() {
        if (closed.get() || peerJob?.isActive == true) return
        peerJob = scope.launch { collectPeers() }
    }

    /** Add or replace the runtime state for [channel]. */
    fun addChannel(channel: MeshChannel) {
        channels[channel.channelId] = ChannelRuntime(
            channel = channel,
            retentionSeconds = maxOf(1L, config.retentionMs / 1000L),
            futureSkewSeconds = config.maxClockSkewMs / 1000L,
            clock = clock,
        )
    }

    fun removeChannel(channel: ChannelId) {
        channels.remove(channel)
    }

    /**
     * Live nearby peers, sorted direct-first. Entries disappear after
     * [MeshConfig.peerTimeoutMs] without an announcement.
     */
    fun peers(): StateFlow<List<NearbyPeer>> = _nearbyPeers.asStateFlow()

    /** Changes the nickname advertised in future announcements. */
    fun setNickname(value: String) {
        val clean = NearbyAnnounceCodec.sanitiseNickname(value) ?: return
        nickname = clean
        announceEnabled = discoverableRequested && clean.isNotBlank()
        if (announceEnabled) {
            startPeerJob()
            if (announceJob?.isActive == true) sendAnnounce() else startAnnounceLoop()
        }
    }

    /** Enables/disables outgoing announcements; receiving keeps working. */
    fun setDiscoverable(enabled: Boolean) {
        discoverableRequested = enabled
        announceEnabled = enabled && nickname.isNotBlank()
        if (announceEnabled) {
            startPeerJob()
            if (announceJob?.isActive == true) sendAnnounce() else startAnnounceLoop()
        } else {
            stopAnnounceLoop()
            if (store == null) {
                peerJob?.cancel()
                peerJob = null
            }
        }
    }

    /** Sends one announcement immediately, e.g. after a manual refresh. */
    fun announceNow() {
        if (nickname.isNotBlank()) sendAnnounce()
    }

    private fun startAnnounceLoop() {
        if (closed.get() || announceJob?.isActive == true) return
        announceJob = scope.launch {
            sendAnnounceNow(null)
            while (isActive && !closed.get()) {
                delay(config.announceIntervalMs)
                if (announceEnabled) sendAnnounceNow(null)
            }
        }
    }

    private fun stopAnnounceLoop() {
        announceJob?.cancel()
        announceJob = null
    }

    private fun sendAnnounce(peers: List<Peer>? = null) {
        if (nickname.isBlank() || closed.get()) return
        scope.launch { sendAnnounceNow(peers) }
    }

    private suspend fun sendAnnounceNow(peers: List<Peer>?) {
        if (nickname.isBlank() || closed.get()) return
        val frame = buildAnnounceFrame(clock()) ?: return
        val targets = peers ?: try {
            transport.peers().first()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            return
        }
        for (peer in targets) {
            try {
                transport.send(peer, frame)
            } catch (_: Exception) {
                // Best effort: the next interval or topology change retries.
            }
        }
    }

    private fun buildAnnounceFrame(now: Long): ByteArray? {
        val payload = NearbyAnnounceCodec.encode(identityPublicKey, nickname, announceCapabilities)
            ?: return null
        val runtime = channels[nearbyChannelId] ?: return null
        val counter = try {
            store?.nextCounter(nearbyChannelId) ?: runtime.nextCounter()
        } catch (_: Exception) {
            return null
        }
        if (counter !in 1..0xFFFF_FFFFL) return null

        val messageId = ByteArray(MESSAGE_ID_SIZE).also(random::nextBytes)
        val header = MeshPacketHeader(
            type = MeshPacketCodec.TYPE_MEMBER_ANNOUNCE,
            messageId = messageId,
            channelId = nearbyChannelId,
            senderId = RotatingSenderId.derive(
                runtime.channel.channelKey,
                identityPublicKey,
                now,
            ),
            ttl = config.announceTtl,
            chunkIndex = 0,
            totalChunks = 1,
            timestampMs = now,
            counter = counter,
        )
        val canonical = MeshPacketCodec.headerBytes(header.copy(ttl = 0))
        val signature = PacketCrypto.signPacket(crypto, canonical, payload)
        return runCatching { MeshPacketCodec.encode(header, signature, payload) }.getOrNull()
    }

    override suspend fun publish(channel: ChannelId, payload: ByteArray) {
        if (payload.size > config.maxPlaintextBytes) {
            throw MeshException(
                "Payload is ${payload.size} bytes, limit is ${config.maxPlaintextBytes}",
            )
        }
        val runtime = channels[channel] ?: throw MeshException("Unknown channel: $channel")

        val now = clock()
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
            now,
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
        // delivered back to the publisher. The replay guard tracks the completed
        // message, the seen cache each chunk.
        runtime.checkMessage(identityPublicKey, messageId, counter, now)
        for (index in packets.indices) {
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
        announceJob?.cancel()
        stopPeerSweep()
        runCatching { receiveHandle.close() }
        if (ownsScope) scope.cancel()
        callbacks.clear()
        synchronized(reassemblyLock) { partials.clear() }
        synchronized(nearbyLock) {
            nearbyRecords.clear()
            _nearbyPeers.value = emptyList()
        }
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
        val now = clock()
        val timestampMs = packet.header.timestampMs
        if (timestampMs > now + config.maxClockSkewMs) return
        if (timestampMs < now - config.retentionMs) return
        if (packet.header.counter <= 0) return

        if (packet.header.type == MeshPacketCodec.TYPE_MEMBER_ANNOUNCE) {
            handleAnnounce(frame, packet, now)
            return
        }

        val runtime = channels[packet.header.channelId] ?: return
        val nearby = packet.header.channelId == nearbyChannelId
        val senderPublicKey = if (nearby) {
            resolveNearbySender(packet.header.senderId, timestampMs) ?: return
        } else {
            runtime.channel.directory.resolve(
                runtime.channel.channelKey,
                packet.header.senderId,
                timestampMs,
            ) ?: return
        }

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
        deliverChunk(
            runtime,
            packet.header,
            tag,
            messageIdHex,
            hopCount,
            plaintext,
            now,
            senderPublicKey,
        )

        if (packet.header.ttl > 1 && !isStale(timestampMs, now)) {
            relay(frame.bytes, packet.header.ttl - 1, frame.from)
        }
    }

    /**
     * Handles one signed announcement. The payload carries the identity key, so
     * it can be verified before the sender is known. Duplicate msg_ids, reused
     * counters, bad signatures, malformed payloads and rate-limited floods are
     * all dropped silently.
     */
    private fun handleAnnounce(frame: ReceivedFrame, packet: MeshPacket, now: Long) {
        if (packet.header.channelId != nearbyChannelId) return
        if (packet.header.chunkIndex != 0 || packet.header.totalChunks != 1) return

        val payload = NearbyAnnounceCodec.decode(packet.sealedPayload) ?: return
        val canonical = MeshPacketCodec.headerBytes(packet.header.copy(ttl = 0))
        if (!PacketCrypto.verifyPacket(
                crypto,
                payload.publicKey,
                canonical,
                packet.sealedPayload,
                packet.signature,
            )
        ) {
            return
        }

        val fingerprint = IdentityFingerprint.of(payload.publicKey)
        // Our own announcement can loop back through another path; ignore it.
        if (fingerprint == localFingerprint) return
        val messageIdHex = packet.header.messageId.toHexString()
        val runtime = channels[nearbyChannelId] ?: return
        if (!runtime.acceptCounter(fingerprint, packet.header.counter, messageIdHex)) return

        val seenKey = SeenPacketCache.Key(nearbyChannelId.hex, fingerprint, messageIdHex, 0)
        if (!seen.firstSeen(seenKey)) return

        // One identity cannot refresh faster than the announce bucket allows.
        if (!announceLimiter.tryAcquire(fingerprint)) return

        val hopCount = (config.announceTtl - packet.header.ttl + 1).coerceAtLeast(1)
        recordPeer(
            publicKey = payload.publicKey,
            fingerprint = fingerprint,
            nickname = payload.nickname,
            capabilities = payload.capabilities,
            rssi = if (hopCount == 1) frame.from.rssi else null,
            hopCount = hopCount,
            now = now,
        )

        if (packet.header.ttl > 1 && !isStale(packet.header.timestampMs, now)) {
            relay(frame.bytes, packet.header.ttl - 1, frame.from)
        }
    }

    private fun recordPeer(
        publicKey: ByteArray,
        fingerprint: String,
        nickname: String,
        capabilities: Int,
        rssi: Int?,
        hopCount: Int,
        now: Long,
    ) {
        val key = publicKey.copyOf()
        synchronized(nearbyLock) {
            nearbyRecords.remove(fingerprint)
            nearbyRecords[fingerprint] = NearbyRecord(
                publicKey = key,
                nickname = nickname,
                capabilities = capabilities,
                rssi = rssi,
                hopCount = hopCount,
                lastSeenMs = now,
            )
            while (nearbyRecords.size > config.maxNearbyPeers) {
                val oldest = nearbyRecords.keys.iterator()
                if (!oldest.hasNext()) break
                oldest.next()
                oldest.remove()
            }
            _nearbyPeers.value = visiblePeers(now)
        }
        ensurePeerSweep()
    }

    private fun resolveNearbySender(senderId: ByteArray, timestampMs: Long): ByteArray? {
        val keys = synchronized(nearbyLock) {
            nearbyRecords.values.map { it.publicKey.copyOf() }
        }
        if (keys.isEmpty()) return null
        val channelKey = NearbyChannel.key()
        val epoch = RotatingSenderId.epochFor(timestampMs)
        for (candidateEpoch in (epoch - 1)..(epoch + 1)) {
            for (publicKey in keys) {
                val expected = RotatingSenderId.deriveForEpoch(channelKey, publicKey, candidateEpoch)
                if (expected.contentEquals(senderId)) return publicKey
            }
        }
        return null
    }

    private fun visiblePeers(now: Long): List<NearbyPeer> = nearbyRecords.values
        .asSequence()
        .filter { now - it.lastSeenMs <= config.peerTimeoutMs }
        .map {
            NearbyPeer(
                fingerprint = it.fingerprint,
                nickname = it.nickname,
                rssi = it.rssi,
                hopCount = it.hopCount,
                lastSeenMs = it.lastSeenMs,
                capabilities = it.capabilities,
            )
        }
        .sortedWith(compareBy({ it.hopCount }, { it.nickname.lowercase() }, { it.fingerprint }))
        .toList()

    private fun ensurePeerSweep() {
        if (closed.get() || peerSweepJob?.isActive == true) return
        peerSweepJob = scope.launch {
            while (isActive && !closed.get()) {
                delay(config.peerSweepIntervalMs)
                val now = clock()
                synchronized(nearbyLock) {
                    _nearbyPeers.value = visiblePeers(now)
                }
                if (synchronized(nearbyLock) { _nearbyPeers.value.isEmpty() }) {
                    stopPeerSweep()
                    return@launch
                }
            }
        }
    }

    private fun stopPeerSweep() {
        peerSweepJob?.cancel()
        peerSweepJob = null
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
                if (added.isEmpty()) return@collect
                replayStored(added)
                if (announceEnabled) sendAnnounceNow(added)
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

                val sender = if (decoded.header.channelId == nearbyChannelId) {
                    resolveNearbySender(decoded.header.senderId, decoded.header.timestampMs)
                } else {
                    runtime.channel.directory.resolve(
                        runtime.channel.channelKey,
                        decoded.header.senderId,
                        decoded.header.timestampMs,
                    )
                } ?: continue
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
        senderPublicKey: ByteArray,
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
            // The guard caches completed messages by (channel, identity, msg_id);
            // a second completed delivery of the same message is a replay.
            val verdict = runtime.checkMessage(
                senderPublicKey,
                header.messageId,
                header.counter,
                header.timestampMs,
            )
            if (verdict == ReplayVerdict.ACCEPT) {
                message = MeshMessage(
                    channel = header.channelId,
                    messageId = messageIdHex,
                    senderId = header.senderId.toHexString(),
                    timestampMs = header.timestampMs,
                    hopCount = hopCount,
                    payload = payload,
                    senderFingerprint = IdentityFingerprint.of(senderPublicKey),
                )
            }
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

    private class NearbyRecord(
        val publicKey: ByteArray,
        val nickname: String,
        val capabilities: Int,
        val rssi: Int?,
        val hopCount: Int,
        val lastSeenMs: Long,
    ) {
        val fingerprint: String
            get() = IdentityFingerprint.of(publicKey)
    }

    /** Per-channel replay and counter state. */
    private class ChannelRuntime(
        val channel: MeshChannel,
        retentionSeconds: Long,
        futureSkewSeconds: Long,
        clock: () -> Long,
    ) {
        private data class CounterKey(
            val identityTag: String,
            val counter: Long,
        )

        private val replayGuard = ReplayGuard(
            retentionSeconds = retentionSeconds,
            futureSkewSeconds = futureSkewSeconds,
            clock = clock,
        )

        private val nextCounter = AtomicLong(0L)
        private val counterToMessage = LinkedHashMap<CounterKey, String>()

        /** Completed-message replay check, keyed by the resolved stable identity. */
        fun checkMessage(
            identityPublicKey: ByteArray,
            messageId: ByteArray,
            counter: Long,
            timestampMs: Long,
        ): ReplayVerdict = replayGuard.check(
            channel.channelId.toBytes(),
            identityPublicKey,
            messageIdToLong(messageId),
            counter,
            timestampMs,
        )

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
