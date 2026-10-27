package com.solar23040.bitaudio.mesh.engine

import com.bitaudio.crypto.Ed25519
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * Plaintext payload of a `MEMBER_ANNOUNCE` (type `0x03`) packet.
 *
 * ```
 * version(1) | identity_pubkey(32) | nickname_len(1) | nickname(n) | capabilities(4)
 * ```
 *
 * Announce payloads are deliberately **not sealed**: the nearby channel key is
 * public, so confidentiality would be an illusion. Authenticity comes from the
 * Ed25519 signature in the packet header, which covers the canonical header and
 * these bytes. A receiver verifies the signature with the public key carried in
 * the payload.
 */
internal object NearbyAnnounceCodec {

    const val VERSION = 0x01
    const val MAX_NICKNAME_BYTES = 32
    const val MAX_PAYLOAD_SIZE = 1 + Ed25519.PUBLIC_KEY_SIZE + 1 + MAX_NICKNAME_BYTES + 4
    const val MIN_PAYLOAD_SIZE = 1 + Ed25519.PUBLIC_KEY_SIZE + 1 + 1 + 4

    const val CAP_VOICE = 1 shl 0
    const val CAP_RELAY = 1 shl 1
    const val CAP_DISCOVERABLE = 1 shl 2
    const val DEFAULT_CAPABILITIES = CAP_VOICE or CAP_RELAY or CAP_DISCOVERABLE

    data class Payload(
        val publicKey: ByteArray,
        val nickname: String,
        val capabilities: Int,
    )

    /** Returns null when the nickname cannot be encoded within the limits. */
    fun encode(publicKey: ByteArray, nickname: String, capabilities: Int): ByteArray? {
        if (publicKey.size != Ed25519.PUBLIC_KEY_SIZE) return null
        val clean = sanitiseNickname(nickname) ?: return null
        val nicknameBytes = clean.toByteArray(Charsets.UTF_8)
        if (nicknameBytes.size !in 1..MAX_NICKNAME_BYTES) return null

        val out = ByteArray(1 + publicKey.size + 1 + nicknameBytes.size + 4)
        out[0] = VERSION.toByte()
        publicKey.copyInto(out, 1)
        val lengthOffset = 1 + publicKey.size
        out[lengthOffset] = nicknameBytes.size.toByte()
        nicknameBytes.copyInto(out, lengthOffset + 1)
        val capabilitiesOffset = lengthOffset + 1 + nicknameBytes.size
        out[capabilitiesOffset] = (capabilities ushr 24).toByte()
        out[capabilitiesOffset + 1] = (capabilities ushr 16).toByte()
        out[capabilitiesOffset + 2] = (capabilities ushr 8).toByte()
        out[capabilitiesOffset + 3] = capabilities.toByte()
        return out
    }

    /** Strict parser: returns null for any malformed, oversized or truncated input. */
    fun decode(bytes: ByteArray): Payload? {
        if (bytes.size !in MIN_PAYLOAD_SIZE..MAX_PAYLOAD_SIZE) return null
        if ((bytes[0].toInt() and 0xFF) != VERSION) return null

        val publicKey = bytes.copyOfRange(1, 1 + Ed25519.PUBLIC_KEY_SIZE)
        val lengthOffset = 1 + Ed25519.PUBLIC_KEY_SIZE
        val nicknameLength = bytes[lengthOffset].toInt() and 0xFF
        if (nicknameLength !in 1..MAX_NICKNAME_BYTES) return null
        val nicknameStart = lengthOffset + 1
        val nicknameEnd = nicknameStart + nicknameLength
        val capabilitiesOffset = nicknameEnd
        if (capabilitiesOffset + 4 != bytes.size) return null

        val nickname = decodeUtf8(bytes, nicknameStart, nicknameLength) ?: return null
        if (sanitiseNickname(nickname) != nickname) return null

        val capabilities = ((bytes[capabilitiesOffset].toInt() and 0xFF) shl 24) or
            ((bytes[capabilitiesOffset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[capabilitiesOffset + 2].toInt() and 0xFF) shl 8) or
            (bytes[capabilitiesOffset + 3].toInt() and 0xFF)

        return Payload(
            publicKey = publicKey,
            nickname = nickname,
            capabilities = capabilities,
        )
    }

    /** Trims, strips control characters and truncates to the wire limit. */
    fun sanitiseNickname(value: String): String? {
        val filtered = value.trim().filter { character ->
            !character.isISOControl()
        }
        val bytes = filtered.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty()) return null
        if (bytes.size <= MAX_NICKNAME_BYTES) return filtered
        // Cut on a character boundary, never in the middle of a UTF-8 sequence.
        val builder = StringBuilder()
        var used = 0
        for (character in filtered) {
            val size = character.toString().toByteArray(Charsets.UTF_8).size
            if (used + size > MAX_NICKNAME_BYTES) break
            builder.append(character)
            used += size
        }
        return builder.toString().ifEmpty { null }
    }

    private fun decodeUtf8(bytes: ByteArray, offset: Int, length: Int): String? = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes, offset, length))
            .toString()
    } catch (_: CharacterCodingException) {
        null
    }
}
