package com.bitaudio.crypto

import java.security.SecureRandom
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * RFC 8032 Ed25519. Keys are raw 32-byte seeds / 32-byte public keys,
 * signatures are 64 bytes. Pure software: works on every Android version.
 */
object Ed25519 {

    const val SEED_SIZE = 32
    const val PUBLIC_KEY_SIZE = 32
    const val SIGNATURE_SIZE = 64

    private val random = SecureRandom()

    fun generateSeed(): ByteArray = ByteArray(SEED_SIZE).also { random.nextBytes(it) }

    /** Derives the public key without storing the seed anywhere. */
    fun publicKeyFromSeed(seed: ByteArray): ByteArray {
        require(seed.size == SEED_SIZE) { "Ed25519 seed must be $SEED_SIZE bytes, got ${seed.size}" }
        return Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
    }

    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        require(seed.size == SEED_SIZE) { "Ed25519 seed must be $SEED_SIZE bytes, got ${seed.size}" }
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    /** Returns false for any malformed input or bad signature; never throws. */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != PUBLIC_KEY_SIZE || signature.size != SIGNATURE_SIZE) return false
        return try {
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
            verifier.update(message, 0, message.size)
            verifier.verifySignature(signature)
        } catch (_: RuntimeException) {
            false
        }
    }
}
