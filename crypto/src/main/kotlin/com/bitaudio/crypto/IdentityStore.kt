package com.bitaudio.crypto

/**
 * Minimal storage boundary for secrets. Android uses
 * [AndroidKeystoreSecretStore]; tests/previews use [InMemorySecretStore].
 */
interface SecretStore {
    /** Returns a copy of the stored value, or null when absent. */
    fun read(name: String): ByteArray?

    /** Stores a copy of [value], replacing any previous value. */
    fun write(name: String, value: ByteArray)

    fun delete(name: String)
}

/**
 * Non-persistent store for unit tests and previews. Never use on a device:
 * identities would be lost on process death.
 */
class InMemorySecretStore : SecretStore {

    private val values = mutableMapOf<String, ByteArray>()

    @Synchronized
    override fun read(name: String): ByteArray? = values[name]?.copyOf()

    @Synchronized
    override fun write(name: String, value: ByteArray) {
        values[name] = value.copyOf()
    }

    @Synchronized
    override fun delete(name: String) {
        values.remove(name)
    }
}

/**
 * Loads (or creates once) the Ed25519 seed and rotates it on demand.
 * Thread-safe; the identity is cached after the first read.
 */
class IdentityManager(
    private val store: SecretStore,
    private val storageKey: String = DEFAULT_STORAGE_KEY,
) {

    @Volatile
    private var cached: Identity? = null

    fun identity(): Identity {
        cached?.let { return it }
        return synchronized(this) {
            cached ?: loadOrCreate().also { cached = it }
        }
    }

    /** Creates a brand-new identity and persists it, invalidating the old one. */
    fun rotate(): Identity = synchronized(this) {
        val replacement = Identity(Ed25519.generateSeed())
        store.write(storageKey, replacement.seedCopy())
        cached = replacement
        replacement
    }

    private fun loadOrCreate(): Identity {
        val stored = store.read(storageKey)
        if (stored != null) {
            try {
                check(stored.size == Ed25519.SEED_SIZE) {
                    "Stored identity seed is corrupt (${stored.size} bytes)"
                }
                return Identity(stored)
            } finally {
                stored.fill(0)
            }
        }

        val created = Identity(Ed25519.generateSeed())
        store.write(storageKey, created.seedCopy())
        return created
    }

    companion object {
        const val DEFAULT_STORAGE_KEY = "identity.ed25519.v1"
    }
}
