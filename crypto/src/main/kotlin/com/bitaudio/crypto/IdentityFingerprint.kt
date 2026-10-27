package com.bitaudio.crypto

import java.security.MessageDigest

/**
 * Short, human-readable fingerprint of an Ed25519 identity key.
 *
 * `fingerprint = SHA-256(identity_public_key)[0..3]` rendered as 6 lowercase
 * hex characters. It is stable for the lifetime of an identity, safe to show in
 * the UI, and changes when the identity is rotated.
 */
object IdentityFingerprint {

    /** Number of hex characters shown in the UI. */
    const val LENGTH = 6

    private const val BYTES = LENGTH / 2

    fun of(publicKey: ByteArray): String {
        require(publicKey.size == Ed25519.PUBLIC_KEY_SIZE) {
            "identity public key must be ${Ed25519.PUBLIC_KEY_SIZE} bytes, got ${publicKey.size}"
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKey)
        val digits = "0123456789abcdef"
        return buildString(LENGTH) {
            for (index in 0 until BYTES) {
                val value = digest[index].toInt() and 0xFF
                append(digits[value ushr 4])
                append(digits[value and 0x0F])
            }
        }
    }
}
