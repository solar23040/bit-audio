package com.solar23040.bitaudio.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.security.SecureRandom

/**
 * Temporary app-level sender ID.
 *
 * Phase 2 replaces this with the Ed25519 identity and rotating sender IDs owned
 * by `:crypto`. For now the UI needs a stable, non-secret value to show and
 * rotate from Settings.
 */
class IdentityStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
    private val _publicId = MutableStateFlow(
        prefs.getString(KEY_SENDER_ID, null) ?: newId().also {
            prefs.edit().putString(KEY_SENDER_ID, it).apply()
        },
    )
    val publicId: StateFlow<String> = _publicId.asStateFlow()

    fun rotate() {
        val next = newId()
        prefs.edit().putString(KEY_SENDER_ID, next).apply()
        _publicId.value = next
    }

    private fun newId(): String {
        val bytes = ByteArray(8)
        SecureRandom().nextBytes(bytes)
        return buildString(16) {
            bytes.forEach { byte ->
                val value = byte.toInt() and 0xFF
                append(HEX[value ushr 4])
                append(HEX[value and 0x0F])
            }
        }
    }

    private companion object {
        const val PREFS_FILE = "bit_audio_identity"
        const val KEY_SENDER_ID = "sender_id"
        const val HEX = "0123456789abcdef"
    }
}
