package com.solar23040.bitaudio.invite

import com.solar23040.bitaudio.data.Channel
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.MessageDigest
import java.util.Base64
import java.util.Locale

/**
 * Public channel ID derivation shared with `:crypto`:
 * SHA-256("bit-audio/channel-id/v1" || key)[0..7], lowercase hex.
 *
 * This lives in `:app` only while the crypto implementation is being wired in
 * Phase 2; the final code should call `Crypto.channelId(channelKey)`.
 */
object ChannelIdCodec {
    private val DOMAIN = "bit-audio/channel-id/v1".toByteArray(Charsets.US_ASCII)

    fun derive(keyBase64: String): String? = runCatching {
        val key = Base64.getUrlDecoder().decode(keyBase64)
        if (key.size != KEY_SIZE) return@runCatching null
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(DOMAIN)
        digest.update(key)
        digest.digest().take(CHANNEL_ID_SIZE).toHex()
    }.getOrNull()

    fun isValid(id: String): Boolean =
        id.length == CHANNEL_ID_SIZE * 2 &&
            id.all { it in '0'..'9' || it in 'a'..'f' }

    fun randomKey(): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(KEY_SIZE).also {
            java.security.SecureRandom().nextBytes(it)
        })

    private fun ByteArray.toHex(): String = buildString(size * 2) {
        forEach { byte ->
            val value = byte.toInt() and 0xFF
            append(HEX[value ushr 4])
            append(HEX[value and 0x0F])
        }
    }

    private const val KEY_SIZE = 32
    private const val CHANNEL_ID_SIZE = 8
    private const val HEX = "0123456789abcdef"
}

data class ChannelInviteData(
    val id: String,
    val name: String,
    val key: String,
)

/**
 * QR invite payload:
 *
 * `bitaudio://join?v=1&id=<16 hex>&name=<url-encoded>&key=<base64url 32 bytes>`
 *
 * The channel key is a secret. Displaying the QR is equivalent to handing over
 * the channel; no key material is ever logged.
 */
object ChannelInvite {
    private const val PREFIX = "bitaudio://join?"
    private const val VERSION = "1"
    private const val KEY_SIZE = 32

    fun encode(channel: Channel): String = buildString {
        append(PREFIX)
        append("v=").append(VERSION)
        append("&id=").append(encodePart(channel.id))
        append("&name=").append(encodePart(channel.name))
        append("&key=").append(encodePart(channel.key))
    }

    fun parse(raw: String): Result<ChannelInviteData> {
        val trimmed = raw.trim()
        if (!trimmed.regionMatches(0, PREFIX, 0, PREFIX.length, ignoreCase = true)) {
            return Result.failure(IllegalArgumentException("Not a Bit Audio invite"))
        }
        val params = runCatching {
            trimmed.substring(PREFIX.length)
                .split('&')
                .mapNotNull { part ->
                    val separator = part.indexOf('=')
                    if (separator <= 0) return@mapNotNull null
                    decodePart(part.substring(0, separator)) to
                        decodePart(part.substring(separator + 1))
                }
                .toMap()
        }.getOrElse {
            return Result.failure(IllegalArgumentException("Malformed invite", it))
        }

        if (params["v"] != VERSION) {
            return Result.failure(IllegalArgumentException("Unsupported invite version"))
        }
        val name = params["name"]?.trim()?.takeIf { it.isNotEmpty() }
            ?: return Result.failure(IllegalArgumentException("Invite has no channel name"))
        val key = params["key"]?.takeIf { it.isNotBlank() }
            ?: return Result.failure(IllegalArgumentException("Invite has no channel key"))
        val keyBytes = runCatching {
            Base64.getUrlDecoder().decode(key)
        }.getOrNull()
        if (keyBytes == null || keyBytes.size != KEY_SIZE) {
            return Result.failure(IllegalArgumentException("Invite channel key must be 32 bytes"))
        }
        val derivedId = ChannelIdCodec.derive(key)
            ?: return Result.failure(IllegalArgumentException("Invite channel key is invalid"))
        val claimedId = params["id"]?.lowercase(Locale.US) ?: derivedId
        if (claimedId != derivedId) {
            return Result.failure(IllegalArgumentException("Invite channel ID does not match its key"))
        }
        return Result.success(
            ChannelInviteData(
                id = derivedId,
                name = name.take(MAX_NAME_LENGTH),
                key = key,
            ),
        )
    }

    private fun encodePart(value: String): String = URLEncoder.encode(value, "UTF-8")

    private fun decodePart(value: String): String = URLDecoder.decode(value, "UTF-8")

    private const val MAX_NAME_LENGTH = 64
}
