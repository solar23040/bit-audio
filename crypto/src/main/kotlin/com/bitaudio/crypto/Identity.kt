package com.bitaudio.crypto

/**
 * An install's long-term Ed25519 identity. The seed is never exposed outside
 * the module; callers only ever see the public key and signatures.
 */
class Identity internal constructor(seedBytes: ByteArray) {

    private val seed: ByteArray = seedBytes.copyOf()
    private val publicKeyBytes: ByteArray

    init {
        require(this.seed.size == Ed25519.SEED_SIZE) {
            "Identity seed must be ${Ed25519.SEED_SIZE} bytes, got ${this.seed.size}"
        }
        publicKeyBytes = Ed25519.publicKeyFromSeed(this.seed)
    }

    /** 32-byte Ed25519 public key. Returns a copy. */
    val publicKey: ByteArray
        get() = publicKeyBytes.copyOf()

    fun sign(message: ByteArray): ByteArray = Ed25519.sign(seed, message)

    internal fun seedCopy(): ByteArray = seed.copyOf()
}
