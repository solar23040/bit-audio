package com.bitaudio.crypto

/**
 * Byte layouts shared by `:mesh` and `:crypto` for one packet
 * (`docs/packet-format.md`, v1).
 *
 * The 43-byte header prefix is everything before the signature:
 * `version, type, msg_id, channel_id, sender_id, ttl, chunk_idx,
 * total_chunks, timestamp_ms, counter`.
 *
 * Signing input:
 * `"bit-audio/packet-sign/v1" || u32be(43) || canonical_header || sealed_chunk`
 * where `canonical_header` is the prefix with `ttl` (offset 26) zeroed.
 *
 * AEAD associated data:
 * `"bit-audio/packet-seal/v1" || canonical_header`.
 *
 * The TTL is zeroed because every relay decrements it; all other header bytes
 * are covered. Always use these helpers instead of rebuilding byte arrays.
 */
object PacketCrypto {

    /** Header fields before the signature. */
    const val HEADER_PREFIX_SIZE = 43

    /** Byte offset of `ttl` inside the prefix. */
    const val TTL_OFFSET = 26

    /** Full v1 header, including the 64-byte signature. */
    const val HEADER_SIZE = 107

    /** Maximum mesh frame (header + payload). */
    const val MAX_PACKET_SIZE = 512

    /** Maximum sealed chunk carried by one packet. */
    const val MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE

    /** Maximum plaintext per chunk: sealed chunk must fit in 405 bytes. */
    const val MAX_PLAINTEXT_CHUNK_SIZE = MAX_PAYLOAD_SIZE - XChaCha20Poly1305.MIN_SEALED_SIZE

    private val SIGNING_DOMAIN = "bit-audio/packet-sign/v1".toByteArray(Charsets.US_ASCII)
    private val AEAD_DOMAIN = "bit-audio/packet-seal/v1".toByteArray(Charsets.US_ASCII)

    /** Returns a copy of [headerPrefix] with `ttl` zeroed. */
    fun canonicalHeader(headerPrefix: ByteArray): ByteArray {
        require(headerPrefix.size == HEADER_PREFIX_SIZE) {
            "header prefix must be $HEADER_PREFIX_SIZE bytes, got ${headerPrefix.size}"
        }
        return headerPrefix.copyOf().also { it[TTL_OFFSET] = 0 }
    }

    fun signingBytes(headerPrefix: ByteArray, sealedChunk: ByteArray): ByteArray {
        val canonical = canonicalHeader(headerPrefix)
        val out = ByteArray(SIGNING_DOMAIN.size + 4 + canonical.size + sealedChunk.size)
        var offset = 0
        SIGNING_DOMAIN.copyInto(out, offset)
        offset += SIGNING_DOMAIN.size

        val headerSize = canonical.size
        out[offset] = (headerSize ushr 24).toByte()
        out[offset + 1] = (headerSize ushr 16).toByte()
        out[offset + 2] = (headerSize ushr 8).toByte()
        out[offset + 3] = headerSize.toByte()
        offset += 4

        canonical.copyInto(out, offset)
        offset += canonical.size
        sealedChunk.copyInto(out, offset)
        return out
    }

    fun associatedData(headerPrefix: ByteArray): ByteArray {
        val canonical = canonicalHeader(headerPrefix)
        val out = ByteArray(AEAD_DOMAIN.size + canonical.size)
        AEAD_DOMAIN.copyInto(out, 0)
        canonical.copyInto(out, AEAD_DOMAIN.size)
        return out
    }

    /** Ed25519-signs one packet. */
    fun signPacket(crypto: Crypto, headerPrefix: ByteArray, sealedChunk: ByteArray): ByteArray =
        crypto.sign(signingBytes(headerPrefix, sealedChunk))

    /** Ed25519-verifies one packet. Malformed input returns false. */
    fun verifyPacket(
        crypto: Crypto,
        senderPublicKey: ByteArray,
        headerPrefix: ByteArray,
        sealedChunk: ByteArray,
        signature: ByteArray,
    ): Boolean = try {
        crypto.verify(
            senderPublicKey,
            signingBytes(headerPrefix, sealedChunk),
            signature,
        )
    } catch (_: IllegalArgumentException) {
        false
    }

    /**
     * Seals one plaintext chunk with the header as AAD. [plaintext] must be at
     * most [MAX_PLAINTEXT_CHUNK_SIZE] bytes so the result fits a packet.
     */
    fun sealPayload(
        crypto: Crypto,
        channelKey: ByteArray,
        headerPrefix: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        require(plaintext.size <= MAX_PLAINTEXT_CHUNK_SIZE) {
            "chunk plaintext must be <= $MAX_PLAINTEXT_CHUNK_SIZE bytes, got ${plaintext.size}"
        }
        return crypto.seal(channelKey, plaintext, associatedData(headerPrefix))
    }

    /** Opens one sealed chunk; null on wrong key, malformed input or AAD mismatch. */
    fun openPayload(
        crypto: Crypto,
        channelKey: ByteArray,
        headerPrefix: ByteArray,
        sealedChunk: ByteArray,
    ): ByteArray? = try {
        crypto.open(channelKey, sealedChunk, associatedData(headerPrefix))
    } catch (_: IllegalArgumentException) {
        null
    }
}
