package com.bitaudio.crypto

/**
 * Byte layouts shared by `:mesh` and `:crypto` for one packet.
 *
 * Signing covers `domain || u32(header length) || header || payload`, where the
 * header has the `sig` field removed (it is always the last header field).
 * AEAD associated data covers `domain || header`, binding every routing field
 * to the ciphertext.
 *
 * Relays verify `verifyPacket` and re-broadcast the packet unchanged.
 */
object PacketCrypto {

    private val SIGNING_DOMAIN = "bit-audio/packet-sign/v1".toByteArray(Charsets.US_ASCII)
    private val AEAD_DOMAIN = "bit-audio/packet-seal/v1".toByteArray(Charsets.US_ASCII)

    fun signingBytes(headerWithoutSignature: ByteArray, payload: ByteArray): ByteArray {
        val out = ByteArray(SIGNING_DOMAIN.size + 4 + headerWithoutSignature.size + payload.size)
        var offset = 0
        SIGNING_DOMAIN.copyInto(out, offset)
        offset += SIGNING_DOMAIN.size

        val headerSize = headerWithoutSignature.size
        out[offset] = (headerSize ushr 24).toByte()
        out[offset + 1] = (headerSize ushr 16).toByte()
        out[offset + 2] = (headerSize ushr 8).toByte()
        out[offset + 3] = headerSize.toByte()
        offset += 4

        headerWithoutSignature.copyInto(out, offset)
        offset += headerWithoutSignature.size
        payload.copyInto(out, offset)
        return out
    }

    fun associatedData(headerWithoutSignature: ByteArray): ByteArray {
        val out = ByteArray(AEAD_DOMAIN.size + headerWithoutSignature.size)
        AEAD_DOMAIN.copyInto(out, 0)
        headerWithoutSignature.copyInto(out, AEAD_DOMAIN.size)
        return out
    }

    /** Ed25519-signs one packet. */
    fun signPacket(crypto: Crypto, headerWithoutSignature: ByteArray, payload: ByteArray): ByteArray =
        crypto.sign(signingBytes(headerWithoutSignature, payload))

    /** Ed25519-verifies one packet. Malformed input returns false. */
    fun verifyPacket(
        crypto: Crypto,
        senderPublicKey: ByteArray,
        headerWithoutSignature: ByteArray,
        payload: ByteArray,
        signature: ByteArray,
    ): Boolean = crypto.verify(
        senderPublicKey,
        signingBytes(headerWithoutSignature, payload),
        signature,
    )

    /** Seals a message payload, binding its (unsigned) header as AAD. */
    fun sealPayload(
        crypto: Crypto,
        channelKey: ByteArray,
        headerWithoutSignature: ByteArray,
        payload: ByteArray,
    ): ByteArray = crypto.seal(channelKey, payload, associatedData(headerWithoutSignature))

    /** Opens a sealed payload; null on wrong key / tampered header / tampering. */
    fun openPayload(
        crypto: Crypto,
        channelKey: ByteArray,
        headerWithoutSignature: ByteArray,
        sealedPayload: ByteArray,
    ): ByteArray? = crypto.open(channelKey, sealedPayload, associatedData(headerWithoutSignature))
}
