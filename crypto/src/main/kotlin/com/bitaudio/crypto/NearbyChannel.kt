package com.bitaudio.crypto

import java.security.MessageDigest

/**
 * The well-known public "nearby" channel.
 *
 * Every install derives the same 32-byte channel key from a fixed domain
 * string. The key is therefore public: packets on this channel are authenticated
 * with Ed25519, but they are **not confidential**. Anyone in radio range can
 * read them. Never use this channel for private conversations.
 *
 * The public channel ID is derived exactly like a QR channel ID, so the mesh
 * can route and filter it without special cases:
 *
 * ```
 * nearby_key     = SHA-256("bit-audio/nearby-channel-key/v1")
 * nearby_channel = SHA-256("bit-audio/channel-id/v1" || nearby_key)[0..8]
 * ```
 */
object NearbyChannel {

    const val NAME = "nearby"

    private val KEY_DOMAIN = "bit-audio/nearby-channel-key/v1".toByteArray(Charsets.US_ASCII)

    private val KEY: ByteArray = MessageDigest.getInstance("SHA-256")
        .digest(KEY_DOMAIN)
        .copyOf(ChannelKeys.KEY_SIZE)

    /** 32-byte public channel key. Returns a copy so callers cannot mutate it. */
    fun key(): ByteArray = KEY.copyOf()

    /** 8-byte public channel identifier. Returns a copy. */
    fun channelId(): ByteArray = ChannelKeys.channelId(KEY)

    /** 16 lowercase hex characters, as used by `ChannelId.hex` and the UI. */
    val channelIdHex: String
        get() = channelId().toHex()

    /** True when [channelId] is the public nearby channel. */
    fun matches(channelId: ByteArray): Boolean =
        channelId.size == ChannelKeys.CHANNEL_ID_SIZE &&
            MessageDigest.isEqual(channelId(), channelId)

    private fun ByteArray.toHex(): String {
        val digits = "0123456789abcdef"
        return buildString(size * 2) {
            this@toHex.forEach { byte ->
                val value = byte.toInt() and 0xFF
                append(digits[value ushr 4])
                append(digits[value and 0x0F])
            }
        }
    }
}
