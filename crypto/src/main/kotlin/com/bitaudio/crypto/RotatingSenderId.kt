package com.bitaudio.crypto

import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Rotating 8-byte sender IDs.
 *
 * `sender_id = trunc8(HMAC-SHA256(key, "bit-audio/sender-id/v1" || pubkey || epoch))`
 * where `key = HMAC-SHA256(channelKey, "bit-audio/sender-id-key/v1")`.
 *
 * Only channel members can compute the IDs, so outsiders cannot link packets
 * to an identity across epochs. Receivers resolve an ID back to a member key
 * by trying the keys in [PeerDirectory] for the packet's timestamp epoch
 * (+/- one epoch for clock skew). No extra bytes are needed in the packet.
 *
 * Limitation: packets from the same sender within one epoch are linkable to
 * each other (that is what lets the mesh route replies). Epoch length trades
 * privacy against resolution cost; 15 minutes is the default.
 */
object RotatingSenderId {

    const val ID_SIZE = 8
    const val DEFAULT_EPOCH_SECONDS = 15 * 60

    private val KEY_DOMAIN = "bit-audio/sender-id-key/v1".toByteArray(Charsets.US_ASCII)
    private val ID_DOMAIN = "bit-audio/sender-id/v1".toByteArray(Charsets.US_ASCII)

    fun epochFor(
        timestampSeconds: Long,
        epochSeconds: Int = DEFAULT_EPOCH_SECONDS,
    ): Long {
        require(epochSeconds > 0) { "epochSeconds must be > 0" }
        return Math.floorDiv(timestampSeconds, epochSeconds.toLong())
    }

    fun derive(
        channelSecret: ByteArray,
        senderPublicKey: ByteArray,
        timestampSeconds: Long,
        epochSeconds: Int = DEFAULT_EPOCH_SECONDS,
    ): ByteArray = deriveForEpoch(channelSecret, senderPublicKey, epochFor(timestampSeconds, epochSeconds))

    fun deriveForEpoch(
        channelSecret: ByteArray,
        senderPublicKey: ByteArray,
        epoch: Long,
    ): ByteArray {
        require(channelSecret.size == ChannelKeys.KEY_SIZE) { "channel secret must be ${ChannelKeys.KEY_SIZE} bytes" }
        require(senderPublicKey.size == Ed25519.PUBLIC_KEY_SIZE) {
            "sender public key must be ${Ed25519.PUBLIC_KEY_SIZE} bytes"
        }

        val idKey = hmacSha256(channelSecret, KEY_DOMAIN)
        return try {
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            mac.init(SecretKeySpec(idKey, HMAC_ALGORITHM))
            mac.update(ID_DOMAIN)
            mac.update(senderPublicKey)
            mac.update(epoch.toBigEndianBytes())
            mac.doFinal().copyOf(ID_SIZE)
        } finally {
            idKey.fill(0)
        }
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
        return mac.doFinal(data)
    }

    private fun Long.toBigEndianBytes(): ByteArray {
        val out = ByteArray(8)
        for (i in 0 until 8) {
            out[i] = (this ushr (56 - i * 8)).toByte()
        }
        return out
    }

    private const val HMAC_ALGORITHM = "HmacSHA256"
}

/**
 * Channel-scoped set of member Ed25519 public keys, learned from QR joins or
 * in-band membership announcements. Used to resolve rotating sender IDs.
 * Thread-safe.
 */
class PeerDirectory(initialPublicKeys: Collection<ByteArray> = emptyList()) {

    private val publicKeys = CopyOnWriteArrayList<ByteArray>()

    init {
        initialPublicKeys.forEach { add(it) }
    }

    /** Returns true when the key was new. */
    @Synchronized
    fun add(publicKey: ByteArray): Boolean {
        require(publicKey.size == Ed25519.PUBLIC_KEY_SIZE) {
            "peer public key must be ${Ed25519.PUBLIC_KEY_SIZE} bytes"
        }
        val copy = publicKey.copyOf()
        if (publicKeys.any { MessageDigest.isEqual(it, copy) }) return false
        publicKeys.add(copy)
        return true
    }

    @Synchronized
    fun remove(publicKey: ByteArray): Boolean =
        publicKeys.removeIf { MessageDigest.isEqual(it, publicKey) }

    fun snapshot(): List<ByteArray> = publicKeys.map { it.copyOf() }

    val size: Int
        get() = publicKeys.size

    /**
     * Maps a packet's rotating ID back to a member public key, trying the
     * timestamp's epoch and [epochSkew] epochs on either side.
     */
    fun resolve(
        channelSecret: ByteArray,
        senderId: ByteArray,
        timestampSeconds: Long,
        epochSeconds: Int = RotatingSenderId.DEFAULT_EPOCH_SECONDS,
        epochSkew: Int = 1,
    ): ByteArray? {
        require(senderId.size == RotatingSenderId.ID_SIZE) {
            "sender ID must be ${RotatingSenderId.ID_SIZE} bytes"
        }
        require(epochSeconds > 0) { "epochSeconds must be > 0" }
        require(epochSkew >= 0) { "epochSkew must be >= 0" }

        val epoch = RotatingSenderId.epochFor(timestampSeconds, epochSeconds)
        for (candidateEpoch in (epoch - epochSkew)..(epoch + epochSkew)) {
            for (publicKey in publicKeys) {
                val expected = RotatingSenderId.deriveForEpoch(channelSecret, publicKey, candidateEpoch)
                if (MessageDigest.isEqual(expected, senderId)) return publicKey.copyOf()
            }
        }
        return null
    }
}
