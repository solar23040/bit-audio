package com.bitaudio.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Persists secrets as files encrypted with an AES-256-GCM key held in
 * AndroidKeyStore. The seed never touches disk in plaintext and does not
 * leave the device (files live in `noBackupFilesDir`).
 *
 * Ed25519 is not available in AndroidKeyStore below API 33, so the Ed25519
 * seed is kept in software and only its at-rest storage is hardware-backed.
 * The key is non-exportable, which is the property that matters here.
 */
class AndroidKeystoreSecretStore(
    context: Context,
    private val keyAlias: String = DEFAULT_KEY_ALIAS,
) : SecretStore {

    private val directory: File = context.applicationContext.noBackupFilesDir

    override fun read(name: String): ByteArray? {
        val file = fileFor(name)
        if (!file.exists()) return null

        val payload = file.readBytes()
        if (payload.size < GCM_IV_SIZE + GCM_TAG_SIZE) {
            throw IllegalStateException("Corrupt secret file: $name")
        }
        val iv = payload.copyOfRange(0, GCM_IV_SIZE)
        val ciphertext = payload.copyOfRange(GCM_IV_SIZE, payload.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(GCM_TAG_SIZE * 8, iv))
        return cipher.doFinal(ciphertext)
    }

    override fun write(name: String, value: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val payload = cipher.iv + cipher.doFinal(value)

        directory.mkdirs()
        val target = fileFor(name)
        val temporary = File(directory, "${target.name}.tmp")
        temporary.writeBytes(payload)
        if (!temporary.renameTo(target)) {
            // Same-directory rename should always work; fall back instead of losing the write.
            temporary.copyTo(target, overwrite = true)
            temporary.delete()
        }
    }

    override fun delete(name: String) {
        fileFor(name).delete()
        File(directory, "${fileFor(name).name}.tmp").delete()
    }

    @Synchronized
    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun fileFor(name: String): File {
        require(NAME_PATTERN.matches(name)) { "Invalid secret name" }
        return File(directory, "$name.bin")
    }

    companion object {
        const val DEFAULT_KEY_ALIAS = "bit-audio.secret-store.v1"

        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_SIZE = 12
        private const val GCM_TAG_SIZE = 16
        private val NAME_PATTERN = Regex("[A-Za-z0-9._-]{1,64}")
    }
}
