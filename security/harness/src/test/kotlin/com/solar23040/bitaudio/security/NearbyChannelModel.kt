package com.solar23040.bitaudio.security

import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.Ed25519
import com.bitaudio.crypto.RotatingSenderId
import com.meshvoice.transport.FakeTransport
import com.meshvoice.transport.ReceivedFrame
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

/**
 * Executable reference model for the proposed **Nearby** channel.
 *
 * Nearby is not implemented on `main` yet. `MEMBER_ANNOUNCE` is reserved in
 * `docs/packet-format.md`, the app has no nickname field on the wire, and the
 * UI's peer view is only the BLE link list. These classes pin the minimum
 * admission rules the eventual implementation must meet so the attack tests
 * below are useful now instead of after the feature ships.
 *
 * Deliberate properties:
 * - a frame is accepted only after an Ed25519 signature over every field;
 * - the long-term install key never appears on the wire: announces and public
 *   clips use a per-channel, per-epoch Ed25519 key and the v1 rotating sender
 *   ID derivation from `docs/packet-format.md`;
 * - the nickname is bound to the epoch identity, never used as a map key;
 * - registry size, frame rate and per-identity announce rate are bounded;
 * - peer count is local, authenticated state and ignores every claimed count.
 *
 * The model is intentionally small. It is not production code and it does not
 * define the final `MEMBER_ANNOUNCE` payload layout (Agent A owns the contract).
 */
internal data class NearbyRate(
    val perSecond: Double,
    val burst: Double,
) {
    init {
        require(perSecond > 0.0) { "perSecond must be > 0" }
        require(burst >= 1.0) { "burst must be >= 1" }
    }
}

internal data class NearbyLimits(
    /** Hard cap on remembered announces. Old entries are not evicted early. */
    val maxMembers: Int = 64,
    val perNeighbour: NearbyRate = NearbyRate(perSecond = 50.0, burst = 100.0),
    val perIdentityAnnounce: NearbyRate = NearbyRate(perSecond = 1.0, burst = 2.0),
    val perIdentityVoice: NearbyRate = NearbyRate(perSecond = 5.0, burst = 5.0),
    val maxClockSkewMs: Long = 120_000,
    /** How long a silent peer stays in the UI count. */
    val memberTtlMs: Long = 15 * 60 * 1000,
    val maxSeenFrames: Int = 4_096,
) {
    init {
        require(maxMembers > 0)
        require(maxClockSkewMs >= 0)
        require(memberTtlMs > 0)
        require(maxSeenFrames > 0)
    }
}

/** One verified Nearby frame. The identity is an epoch key, not the install key. */
internal data class NearbyFrame(
    val type: Int,
    val timestampMs: Long,
    val messageIdHex: String,
    val senderIdHex: String,
    val identityHex: String,
    val nickname: String,
    val body: ByteArray,
    val claimedPeerCount: Int,
)

/**
 * Reference wire format for the tests. The production control packet must use
 * the v1 header/signing rules; this layout only carries the fields the threats
 * depend on.
 */
internal object NearbyWire {
    const val VERSION = 1
    const val TYPE_VOICE = 0x01
    const val TYPE_ANNOUNCE = 0x03
    const val MAX_NICKNAME_BYTES = 32
    const val MAX_BODY_BYTES = 512
    const val MAX_FRAME_BYTES = 1_024

    private const val SIGNATURE_SIZE = Ed25519.SIGNATURE_SIZE
    private const val DOMAIN = "bit-audio/nearby-frame/v1"
    private const val EPOCH_DOMAIN = "bit-audio/nearby-epoch/v1"

    fun epochSeed(stableSeed: ByteArray, channelKey: ByteArray, epoch: Long): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(stableSeed, "HmacSHA256"))
        mac.update(EPOCH_DOMAIN.toByteArray(Charsets.US_ASCII))
        mac.update(ChannelKeys.channelId(channelKey))
        mac.update(epoch.toBigEndianBytes())
        return mac.doFinal()
    }

    fun epochPublicKey(stableSeed: ByteArray, channelKey: ByteArray, epoch: Long): ByteArray =
        Ed25519.publicKeyFromSeed(epochSeed(stableSeed, channelKey, epoch))

    fun senderId(
        stableSeed: ByteArray,
        channelKey: ByteArray,
        epoch: Long,
    ): ByteArray = RotatingSenderId.deriveForEpoch(
        channelKey,
        epochPublicKey(stableSeed, channelKey, epoch),
        epoch,
    )

    fun announce(
        channelKey: ByteArray,
        stableSeed: ByteArray,
        epoch: Long,
        timestampMs: Long,
        messageId: ByteArray,
        nickname: String,
        claimedPeerCount: Int = 0,
    ): ByteArray = build(
        type = TYPE_ANNOUNCE,
        channelKey = channelKey,
        stableSeed = stableSeed,
        epoch = epoch,
        timestampMs = timestampMs,
        messageId = messageId,
        nickname = nickname,
        body = ByteArray(0),
        claimedPeerCount = claimedPeerCount,
    )

    fun voice(
        channelKey: ByteArray,
        stableSeed: ByteArray,
        epoch: Long,
        timestampMs: Long,
        messageId: ByteArray,
        body: ByteArray,
    ): ByteArray = build(
        type = TYPE_VOICE,
        channelKey = channelKey,
        stableSeed = stableSeed,
        epoch = epoch,
        timestampMs = timestampMs,
        messageId = messageId,
        nickname = "",
        body = body,
        claimedPeerCount = 0,
    )

    fun decode(frame: ByteArray, channelKey: ByteArray): NearbyFrame? {
        if (frame.size < SIGNATURE_SIZE + 35 || frame.size > MAX_FRAME_BYTES) return null
        val signed = frame.copyOfRange(0, frame.size - SIGNATURE_SIZE)
        val signature = frame.copyOfRange(frame.size - SIGNATURE_SIZE, frame.size)
        return try {
            val reader = Reader(signed)
            if (reader.u8() != VERSION) return null
            val type = reader.u8()
            if (type != TYPE_VOICE && type != TYPE_ANNOUNCE) return null
            val epoch = reader.u64()
            val timestampMs = reader.u64()
            val messageId = reader.bytes(8)
            val senderId = reader.bytes(8)
            val epochPublicKey = reader.bytes(Ed25519.PUBLIC_KEY_SIZE)
            val claimedPeerCount = reader.u16()
            val nicknameBytes = reader.bytes(reader.u8())
            if (nicknameBytes.size > MAX_NICKNAME_BYTES) return null
            val nickname = nicknameBytes.toString(Charsets.UTF_8)
            val body = reader.bytes(reader.u16())
            if (body.size > MAX_BODY_BYTES) return null
            if (!reader.atEnd()) return null
            if (!Ed25519.verify(epochPublicKey, signed, signature)) return null

            // Bind the rotating ID to the claimed epoch key and channel. Without
            // this an attacker can copy a valid key into a different channel or
            // reuse it outside its epoch.
            val expected = RotatingSenderId.deriveForEpoch(
                channelKey,
                epochPublicKey,
                epoch,
            )
            if (!MessageDigest.isEqual(expected, senderId)) return null

            NearbyFrame(
                type = type,
                timestampMs = timestampMs,
                messageIdHex = messageId.toHex(),
                senderIdHex = senderId.toHex(),
                identityHex = epochPublicKey.toHex(),
                nickname = nickname,
                body = body.copyOf(),
                claimedPeerCount = claimedPeerCount,
            )
        } catch (_: RuntimeException) {
            null
        }
    }

    private fun build(
        type: Int,
        channelKey: ByteArray,
        stableSeed: ByteArray,
        epoch: Long,
        timestampMs: Long,
        messageId: ByteArray,
        nickname: String,
        body: ByteArray,
        claimedPeerCount: Int,
    ): ByteArray {
        require(messageId.size == 8)
        require(body.size <= MAX_BODY_BYTES)
        val nicknameBytes = nickname.toByteArray(Charsets.UTF_8)
        require(nicknameBytes.size <= MAX_NICKNAME_BYTES)
        require(claimedPeerCount in 0..0xFFFF)

        val epochKey = epochSeed(stableSeed, channelKey, epoch)
        val epochPublicKey = Ed25519.publicKeyFromSeed(epochKey)
        val senderId = RotatingSenderId.deriveForEpoch(channelKey, epochPublicKey, epoch)
        val writer = Writer()
            .u8(VERSION)
            .u8(type)
            .u64(epoch)
            .u64(timestampMs)
            .raw(messageId)
            .raw(senderId)
            .raw(epochPublicKey)
            .u16(claimedPeerCount)
            .u8(nicknameBytes.size)
            .raw(nicknameBytes)
            .u16(body.size)
            .raw(body)
        val signed = DOMAIN.toByteArray(Charsets.US_ASCII) + writer.toByteArray()
        val signature = Ed25519.sign(epochKey, signed)
        return signed + signature
    }

    private class Reader(private val bytes: ByteArray) {
        private var offset = 0

        fun u8(): Int {
            if (offset >= bytes.size) error("truncated")
            return bytes[offset++].toInt() and 0xFF
        }

        fun u16(): Int {
            val high = u8()
            val low = u8()
            return (high shl 8) or low
        }

        fun u64(): Long {
            var value = 0L
            repeat(8) { value = (value shl 8) or u8().toLong() }
            return value
        }

        fun bytes(length: Int): ByteArray {
            if (length < 0 || offset + length > bytes.size) error("truncated")
            return bytes.copyOfRange(offset, offset + length).also { offset += length }
        }

        fun atEnd(): Boolean = offset == bytes.size
    }

    private class Writer {
        private val out = ArrayList<Byte>(128)

        fun u8(value: Int): Writer = apply { out.add(value.toByte()) }

        fun u16(value: Int): Writer = apply {
            out.add((value ushr 8).toByte())
            out.add(value.toByte())
        }

        fun u64(value: Long): Writer = apply {
            for (index in 0 until 8) out.add((value ushr (56 - index * 8)).toByte())
        }

        fun raw(value: ByteArray): Writer = apply { value.forEach { out.add(it) } }

        fun toByteArray(): ByteArray = ByteArray(out.size) { out[it] }
    }
}

/**
 * Receive-side policy for one Nearby participant. It is deliberately the only
 * place admission, nickname binding and peer counting happen.
 */
internal class NearbyNode(
    transport: FakeTransport,
    private val channelKey: ByteArray,
    private val now: () -> Long,
    private val limits: NearbyLimits = NearbyLimits(),
) : AutoCloseable {

    private data class Member(
        var nickname: String,
        var firstSeenMs: Long,
        var lastSeenMs: Long,
        var announcedClaim: Int,
    )

    private val members = LinkedHashMap<String, Member>()
    private val seen = LinkedHashSet<String>()
    private val neighbourLimiter = NearbyBucket(limits.perNeighbour, now)
    private val announceLimiter = NearbyBucket(limits.perIdentityAnnounce, now)
    private val voiceLimiter = NearbyBucket(limits.perIdentityVoice, now)

    var droppedInvalid: Int = 0
        private set
    var droppedStale: Int = 0
        private set
    var droppedDuplicate: Int = 0
        private set
    var droppedRate: Int = 0
        private set
    var droppedCapacity: Int = 0
        private set
    var droppedUnknownVoice: Int = 0
        private set

    val delivered: MutableList<NearbyFrame> = mutableListOf()

    private val handle = transport.onReceive(::onFrame)

    @Synchronized
    fun memberCount(): Int {
        expire(now())
        return members.size
    }

    /** Local authenticated count; never a claim taken from a frame. */
    @Synchronized
    fun verifiedPeerCount(): Int = memberCount()

    @Synchronized
    fun memberNickname(identityHex: String): String? = members[identityHex]?.nickname

    /**
     * Two peers can pick the same nickname. The UI label must stay distinct, so
     * duplicate nicknames get a short fingerprint suffix.
     */
    @Synchronized
    fun displayLabel(identityHex: String): String? {
        val member = members[identityHex] ?: return null
        val duplicates = members.values.count { it.nickname == member.nickname }
        return if (duplicates == 1) {
            member.nickname
        } else {
            "${member.nickname} (${identityHex.take(6)})"
        }
    }

    @Synchronized
    fun expire(atMs: Long) {
        members.entries.removeIf { atMs - it.value.lastSeenMs > limits.memberTtlMs }
    }

    @Synchronized
    private fun onFrame(frame: ReceivedFrame) {
        val at = now()
        if (!neighbourLimiter.tryAcquire(frame.from.id)) {
            droppedRate++
            return
        }
        val packet = NearbyWire.decode(frame.bytes, channelKey)
        if (packet == null) {
            droppedInvalid++
            return
        }
        if (packet.timestampMs > at + limits.maxClockSkewMs ||
            packet.timestampMs < at - limits.memberTtlMs
        ) {
            droppedStale++
            return
        }
        val dedupKey = "${packet.identityHex}:${packet.messageIdHex}"
        if (!remember(dedupKey)) {
            droppedDuplicate++
            return
        }

        when (packet.type) {
            NearbyWire.TYPE_ANNOUNCE -> admitAnnounce(packet, at)
            NearbyWire.TYPE_VOICE -> acceptVoice(packet, at)
            else -> droppedInvalid++
        }
    }

    private fun admitAnnounce(packet: NearbyFrame, atMs: Long) {
        if (!announceLimiter.tryAcquire(packet.identityHex)) {
            droppedRate++
            return
        }
        val nickname = sanitizeNickname(packet.nickname)
        if (nickname == null) {
            droppedInvalid++
            return
        }

        val existing = members[packet.identityHex]
        if (existing != null) {
            existing.nickname = nickname
            existing.lastSeenMs = atMs
            existing.announcedClaim = packet.claimedPeerCount
            return
        }
        if (members.size >= limits.maxMembers) {
            droppedCapacity++
            return
        }
        members[packet.identityHex] = Member(
            nickname = nickname,
            firstSeenMs = atMs,
            lastSeenMs = atMs,
            announcedClaim = packet.claimedPeerCount,
        )
    }

    private fun acceptVoice(packet: NearbyFrame, atMs: Long) {
        if (members[packet.identityHex] == null) {
            droppedUnknownVoice++
            return
        }
        if (!voiceLimiter.tryAcquire(packet.identityHex)) {
            droppedRate++
            return
        }
        members[packet.identityHex]?.lastSeenMs = atMs
        delivered.add(packet)
    }

    @Synchronized
    private fun remember(key: String): Boolean {
        if (!seen.add(key)) return false
        while (seen.size > limits.maxSeenFrames) {
            val oldest = seen.iterator()
            if (!oldest.hasNext()) break
            oldest.next()
            oldest.remove()
        }
        return true
    }

    private fun sanitizeNickname(raw: String): String? {
        val clipped = raw.trim().take(32)
        if (clipped.isEmpty()) return null
        if (clipped.any { it.code < 0x20 || it.code == 0x7F }) return null
        return clipped
    }

    override fun close() = handle.close()
}

/** Jittered announce schedule; a fixed cadence is itself a tracking signal. */
internal object NearbySchedule {
    const val BASE_INTERVAL_MS = 30_000L
    const val JITTER_MS = 0L..5_000L

    fun nextDelayMs(random: Random): Long =
        BASE_INTERVAL_MS + random.nextLong(JITTER_MS.first, JITTER_MS.last + 1)
}

/** Per-key token bucket with the same semantics as the mesh rate limiter. */
private class NearbyBucket(
    private val rate: NearbyRate,
    private val clock: () -> Long,
) {
    private class Bucket(var tokens: Double, var lastMs: Long)

    private val buckets = LinkedHashMap<String, Bucket>(16, 0.75f, true)

    @Synchronized
    fun tryAcquire(key: String): Boolean {
        val at = clock()
        val bucket = buckets[key] ?: Bucket(rate.burst, at).also { buckets[key] = it }
        val elapsed = (at - bucket.lastMs).coerceAtLeast(0)
        if (elapsed > 0) {
            bucket.tokens = minOf(rate.burst, bucket.tokens + elapsed * rate.perSecond / 1000.0)
            bucket.lastMs = at
        }
        while (buckets.size > MAX_KEYS) {
            val oldest = buckets.keys.iterator()
            if (!oldest.hasNext()) break
            oldest.next()
            oldest.remove()
        }
        if (bucket.tokens < 1.0) return false
        bucket.tokens -= 1.0
        return true
    }

    private companion object {
        const val MAX_KEYS = 4_096
    }
}

internal fun ByteArray.containsSubsequence(needle: ByteArray): Boolean {
    if (needle.isEmpty()) return true
    if (needle.size > size) return false
    outer@ for (start in 0..size - needle.size) {
        for (index in needle.indices) {
            if (this[start + index] != needle[index]) continue@outer
        }
        return true
    }
    return false
}

internal fun ByteArray.toHex(): String {
    val digits = "0123456789abcdef"
    return buildString(size * 2) {
        this@toHex.forEach { byte ->
            val value = byte.toInt() and 0xFF
            append(digits[value ushr 4])
            append(digits[value and 0x0F])
        }
    }
}

private fun Long.toBigEndianBytes(): ByteArray = ByteArray(8) { index ->
    (this ushr (56 - index * 8)).toByte()
}
