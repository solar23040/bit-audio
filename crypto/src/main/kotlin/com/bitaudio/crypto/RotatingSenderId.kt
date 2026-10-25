package com.bitaudio.crypto

import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Rotating 8-byte sender IDs, exactly as specified in
 * `docs/packet-format.md`:
 *
 * ```
 * id_key    = HMAC-SHA256(channel_key, "bit-audio/sender-id-key/v1")
 * epoch     = floor(timestamp_ms / 900000)
 * sender_id = HMAC-SHA256(id_key, "bit-audio/sender-id/v1" || identity_pubkey(32) || epoch_u64)[0..8]
 * ```
 *
 * Only channel members can compute IDs, so outsiders cannot link packets to an
 * identity across epochs. Within one epoch packets remain linkable to each
 * other, which is what lets the mesh route replies.
 *
 * Receivers resolve an ID against the channel roster for the packet's epoch and
 * +/- one epoch (`PeerDirectory.resolve`), then verify the signature with the
 * resolved stable key.
 */
object RotatingSenderId {

    const val ID_SIZE = 8
    const val EPOCH_MILLIS = 15 * 60 * 1000L

    private val KEY_DOMAIN = "bit-audio/sender-id-key/v1".toByteArray(Charsets.US_ASCII)
    private val ID_DOMAIN = "bit-audio/sender-id/v1".toByteArray(Charsets.US_ASCII)

    fun epochFor(timestampMs: Long): Long = Math.floorDiv(timestampMs, EPOCH_MILLIS)

    fun derive(
        channelSecret: ByteArray,
        senderPublicKey: ByteArray,
        timestampMs: Long,
    ): ByteArray = deriveForEpoch(channelSecret, senderPublicKey, epochFor(timestampMs))

    fun deriveForEpoch(
        channelSecret: ByteArray,
        senderPublicKey: ByteArray,
        epoch: Long,
    ): ByteArray {
        require(channelSecret.size == ChannelKeys.KEY_SIZE) {
            "channel secret must be ${ChannelKeys.KEY_SIZE} bytes"
        }
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
 * Channel-scoped roster of member Ed25519 public keys, learned from QR joins or
 * in-band membership announcements. Used to resolve rotating sender IDs back to
 * the stable signing key. Thread-safe.
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
     * Resolves [senderId] to a roster key using the epoch of [timestampMs] and
     * [epochSkew] epochs on either side (default 1, per the wire format).
     */
    fun resolve(
        channelSecret: ByteArray,
        senderId: ByteArray,
        timestampMs: Long,
        epochSkew: Int = 1,
    ): ByteArray? {
        require(senderId.size == RotatingSenderId.ID_SIZE) {
            "sender ID must be ${RotatingSenderId.ID_SIZE} bytes"
        }
        require(epochSkew >= 0) { "epochSkew must be >= 0" }

        val epoch = RotatingSenderId.epochFor(timestampMs)
        for (candidateEpoch in (epoch - epochSkew)..(epoch + epochSkew)) {
            for (publicKey in publicKeys) {
                val expected = RotatingSenderId.deriveForEpoch(channelSecret, publicKey, candidateEpoch)
                if (MessageDigest.isEqual(expected, senderId)) return publicKey.copyOf()
            }
        }
        return null
    }
}
