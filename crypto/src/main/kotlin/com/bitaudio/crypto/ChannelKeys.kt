package com.bitaudio.crypto

import java.security.SecureRandom
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Argon2id parameters for passphrase-derived channel keys.
 *
 * Defaults are above the OWASP minimum (19 MiB, t=2, p=1) while staying
 * affordable on low-end phones. Tunable for measurements in Phase 4/5.
 * [secret] and [associatedData] are only needed to run RFC 9106 test vectors.
 */
class Argon2Params(
    val iterations: Int = 3,
    val memoryKib: Int = 32 * 1024,
    val parallelism: Int = 2,
    val outputLength: Int = ChannelKeys.KEY_SIZE,
    val secret: ByteArray? = null,
    val associatedData: ByteArray? = null,
) {
    init {
        require(iterations >= 1) { "iterations must be >= 1" }
        require(parallelism >= 1) { "parallelism must be >= 1" }
        require(memoryKib >= 8 * parallelism) {
            "Argon2 needs at least 8 KiB per lane (memoryKib=$memoryKib, parallelism=$parallelism)"
        }
        require(outputLength in 16..1024) { "outputLength must be in 16..1024" }
    }
}

/**
 * Channel key handling: 32-byte keys, either random (QR-created channel) or
 * derived from a shared passphrase with Argon2id.
 */
object ChannelKeys {

    const val KEY_SIZE = 32
    const val MIN_SALT_SIZE = 8
    const val SALT_SIZE = 16
    const val CHANNEL_ID_SIZE = 8

    private val CHANNEL_ID_DOMAIN = "bit-audio/channel-id/v1".toByteArray(Charsets.US_ASCII)
    private val random = SecureRandom()

    /** Random key for a channel created from a QR code. */
    fun generate(): ByteArray = ByteArray(KEY_SIZE).also { random.nextBytes(it) }

    /** Copies a key that arrived in a QR payload (expected to be 32 bytes). */
    fun fromQrSecret(secret: ByteArray): ByteArray {
        require(secret.size == KEY_SIZE) { "QR channel secret must be $KEY_SIZE bytes, got ${secret.size}" }
        return secret.copyOf()
    }

    /**
     * Derives a channel key from a shared passphrase.
     * The caller owns [passphrase] and should clear it after calling this.
     */
    fun fromPassphrase(
        passphrase: CharArray,
        salt: ByteArray,
        params: Argon2Params = Argon2Params(),
    ): ByteArray {
        require(passphrase.isNotEmpty()) { "passphrase must not be empty" }
        require(salt.size >= MIN_SALT_SIZE) { "salt must be at least $MIN_SALT_SIZE bytes" }

        val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(params.iterations)
            .withMemoryAsKB(params.memoryKib)
            .withParallelism(params.parallelism)
            .withSalt(salt)
        params.secret?.let { builder.withSecret(it) }
        params.associatedData?.let { builder.withAdditional(it) }

        val generator = Argon2BytesGenerator()
        generator.init(builder.build())

        val key = ByteArray(params.outputLength)
        val written = generator.generateBytes(passphrase, key)
        check(written == key.size) { "Argon2 produced $written of ${key.size} bytes" }
        return key
    }

    /** Stable short channel identifier for UI/logs (does not reveal the key). */
    fun channelId(channelKey: ByteArray): ByteArray {
        require(channelKey.size == KEY_SIZE) { "channel key must be $KEY_SIZE bytes" }
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update(CHANNEL_ID_DOMAIN)
        digest.update(channelKey)
        return digest.digest().copyOf(CHANNEL_ID_SIZE)
    }
}
