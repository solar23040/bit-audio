package com.bitaudio.crypto

/**
 * Crypto boundary for the mesh pipeline. Everything is bytes so `:mesh` and
 * `:transport` never need to know which library is underneath.
 *
 * Signatures are Ed25519 over exactly the bytes handed in by the caller.
 * Sealed payloads are `nonce(24) || ciphertext || tag(16)` using
 * XChaCha20-Poly1305, and every returned array is freshly allocated.
 */
interface Crypto {

    /** Signs [data]. Returns a 64-byte Ed25519 signature. */
    fun sign(data: ByteArray): ByteArray

    /**
     * Verifies [signature] over [data] for [senderPublicKey].
     * Returns false (never throws) for malformed keys/signatures.
     */
    fun verify(senderPublicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean

    /**
     * Encrypts and authenticates [plaintext] under [channelKey].
     * [associatedData] is authenticated but not encrypted (bind the packet
     * header here). Returns `nonce || ciphertext || tag`.
     */
    fun seal(channelKey: ByteArray, plaintext: ByteArray, associatedData: ByteArray): ByteArray

    /**
     * Inverse of [seal]. Returns null for a wrong key, tampered ciphertext or
     * mismatched [associatedData]. Never throws on bad input.
     */
    fun open(channelKey: ByteArray, sealed: ByteArray, associatedData: ByteArray): ByteArray?
}

/**
 * Default [Crypto]: Ed25519 identity + XChaCha20-Poly1305 payload sealing.
 * One instance can be shared across threads.
 */
class DefaultCrypto(
    private val identityManager: IdentityManager,
) : Crypto {

    /** Local Ed25519 public key (32 bytes), safe to hand to the mesh layer. */
    val publicKey: ByteArray
        get() = identityManager.identity().publicKey

    override fun sign(data: ByteArray): ByteArray = identityManager.identity().sign(data)

    override fun verify(senderPublicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean =
        Ed25519.verify(senderPublicKey, data, signature)

    override fun seal(channelKey: ByteArray, plaintext: ByteArray, associatedData: ByteArray): ByteArray =
        XChaCha20Poly1305.seal(channelKey, plaintext, associatedData)

    override fun open(channelKey: ByteArray, sealed: ByteArray, associatedData: ByteArray): ByteArray? =
        XChaCha20Poly1305.open(channelKey, sealed, associatedData)
}
