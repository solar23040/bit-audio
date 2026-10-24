package com.bitaudio.crypto

import java.security.SecureRandom
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

/**
 * AEAD_XChaCha20_Poly1305 (draft-irtf-cfrg-xchacha).
 *
 * Wire format produced by [seal]: `nonce(24) || ciphertext || tag(16)`.
 * 24-byte random nonces make reuse negligible (192-bit random part), so no
 * per-key counter state has to survive restarts.
 */
object XChaCha20Poly1305 {

    const val KEY_SIZE = 32
    const val NONCE_SIZE = 24
    const val TAG_SIZE = 16
    const val MIN_SEALED_SIZE = NONCE_SIZE + TAG_SIZE

    private const val SUBKEY_NONCE_SIZE = 16
    private const val PREFIX_SIZE = 4
    private const val MASK_SIZE_BITS = TAG_SIZE * 8

    private val random = SecureRandom()

    fun randomNonce(): ByteArray = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }

    /**
     * Encrypts [plaintext] with a fresh nonce. Returns
     * `nonce || ciphertext || tag`.
     */
    fun seal(channelKey: ByteArray, plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        val nonce = randomNonce()
        return nonce + sealWithNonce(channelKey, nonce, plaintext, associatedData)
    }

    /**
     * Encrypts with a caller-supplied nonce. Only for test vectors and
     * deterministic protocols — reusing a nonce with the same key breaks the
     * AEAD completely.
     */
    fun sealWithNonce(
        channelKey: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        associatedData: ByteArray,
    ): ByteArray {
        require(channelKey.size == KEY_SIZE) { "channel key must be $KEY_SIZE bytes" }
        require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" }

        val cipher = openCipher(true, channelKey, nonce, associatedData)
        val out = ByteArray(cipher.getOutputSize(plaintext.size))
        var length = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        length += cipher.doFinal(out, length)
        return out.copyOf(length)
    }

    /**
     * Decrypts a `nonce || ciphertext || tag` blob. Returns null for a wrong
     * key, truncation, tampering or AAD mismatch; never throws.
     */
    fun open(channelKey: ByteArray, sealed: ByteArray, associatedData: ByteArray): ByteArray? {
        if (channelKey.size != KEY_SIZE || sealed.size < MIN_SEALED_SIZE) return null
        val nonce = sealed.copyOfRange(0, NONCE_SIZE)
        val ciphertext = sealed.copyOfRange(NONCE_SIZE, sealed.size)
        return openWithNonce(channelKey, nonce, ciphertext, associatedData)
    }

    /**
     * Decrypts `ciphertext || tag` with an explicit nonce. Returns null on
     * authentication failure; never throws.
     */
    fun openWithNonce(
        channelKey: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray,
    ): ByteArray? {
        if (channelKey.size != KEY_SIZE || nonce.size != NONCE_SIZE) return null
        if (ciphertext.size < TAG_SIZE) return null

        return try {
            val cipher = openCipher(false, channelKey, nonce, associatedData)
            val out = ByteArray(cipher.getOutputSize(ciphertext.size))
            var length = cipher.processBytes(ciphertext, 0, ciphertext.size, out, 0)
            length += cipher.doFinal(out, length)
            out.copyOf(length)
        } catch (_: Exception) {
            null
        }
    }

    private fun openCipher(
        forEncryption: Boolean,
        channelKey: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray,
    ): ChaCha20Poly1305 {
        val subkey = HChaCha20.derive(channelKey, nonce.copyOfRange(0, SUBKEY_NONCE_SIZE))
        val nonce12 = ByteArray(12)
        nonce.copyInto(nonce12, destinationOffset = PREFIX_SIZE, startIndex = SUBKEY_NONCE_SIZE, endIndex = NONCE_SIZE)
        return try {
            ChaCha20Poly1305().apply {
                init(
                    forEncryption,
                    AEADParameters(KeyParameter(subkey), MASK_SIZE_BITS, nonce12, associatedData),
                )
            }
        } finally {
            subkey.fill(0)
        }
    }
}
