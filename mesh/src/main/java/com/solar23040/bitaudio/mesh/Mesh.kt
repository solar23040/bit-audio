package com.solar23040.bitaudio.mesh

/**
 * Public channel identifier: the first 8 bytes of the channel-ID derivation,
 * encoded as 16 lowercase hex characters. The channel secret is never exposed.
 */
@JvmInline
value class ChannelId private constructor(val hex: String) {
    init {
        require(hex.length == BYTE_LENGTH * 2) { "ChannelId must be 16 hex characters" }
        require(hex.all { it in '0'..'9' || it in 'a'..'f' }) { "ChannelId must be lowercase hex" }
    }

    fun toBytes(): ByteArray = ByteArray(BYTE_LENGTH) { index ->
        hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }

    override fun toString(): String = hex

    companion object {
        const val BYTE_LENGTH: Int = 8

        fun fromHex(value: String): ChannelId = ChannelId(value.lowercase())

        fun fromBytes(bytes: ByteArray): ChannelId {
            require(bytes.size == BYTE_LENGTH) {
                "ChannelId requires $BYTE_LENGTH bytes, got ${bytes.size}"
            }
            return ChannelId(
                buildString(BYTE_LENGTH * 2) {
                    bytes.forEach { byte ->
                        val value = byte.toInt() and 0xFF
                        append(HEX_DIGITS[value ushr 4])
                        append(HEX_DIGITS[value and 0x0F])
                    }
                },
            )
        }

        private const val HEX_DIGITS = "0123456789abcdef"
    }
}

/** A fully reassembled, verified, decrypted voice message. */
data class MeshMessage(
    val channel: ChannelId,
    /** 8-byte message ID as lowercase hex. */
    val messageId: String,
    /** 8-byte rotating sender ID as lowercase hex. */
    val senderId: String,
    val timestampMs: Long,
    /** Number of relays the message travelled through before local delivery. */
    val hopCount: Int,
    /** Plaintext Opus payload. */
    val payload: ByteArray,
    /**
     * First 6 hex characters of `SHA-256(identity key)`, when the sender's key
     * is known (always for nearby traffic). Empty for old/unknown senders.
     */
    val senderFingerprint: String = "",
)

/**
 * Mesh routing and store-and-forward boundary.
 *
 * [publish] seals and signs the payload, splits it into packets, and floods it
 * over the injected [com.meshvoice.transport.Transport]. Delivered messages are
 * deduplicated, reassembled, signature-checked, and decrypted before
 * [onMessage] fires. Callbacks run on a mesh-owned coroutine context and must
 * not block.
 */
interface Mesh {
    /**
     * Publish one voice payload on [channel].
     *
     * Suspends while the first hop is handed to the transport; relaying and
     * store-and-forward continue in the background.
     */
    suspend fun publish(channel: ChannelId, payload: ByteArray)

    /** Register a delivery callback. Close the returned handle to unsubscribe. */
    fun onMessage(callback: (MeshMessage) -> Unit): AutoCloseable
}

/** Raised when a payload cannot be published (unknown channel, storage full). */
class MeshException(message: String, cause: Throwable? = null) : Exception(message, cause)
