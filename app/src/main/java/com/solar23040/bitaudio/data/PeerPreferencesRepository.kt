package com.solar23040.bitaudio.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Per-identity mute/block list, stored locally.
 *
 * Keys are the 6-character identity fingerprints shown in the nearby list, so
 * the list survives sender-ID rotation and app restarts. Muting hides a peer's
 * clips; blocking also removes the peer from the nearby list.
 */
class PeerPreferencesRepository(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)

    private val _muted = MutableStateFlow(
        prefs.getStringSet(KEY_MUTED, emptySet())?.toSet() ?: emptySet(),
    )
    val muted: StateFlow<Set<String>> = _muted.asStateFlow()

    private val _blocked = MutableStateFlow(
        prefs.getStringSet(KEY_BLOCKED, emptySet())?.toSet() ?: emptySet(),
    )
    val blocked: StateFlow<Set<String>> = _blocked.asStateFlow()

    fun isMuted(fingerprint: String): Boolean = fingerprint.isNotBlank() && fingerprint in _muted.value

    fun isBlocked(fingerprint: String): Boolean =
        fingerprint.isNotBlank() && fingerprint in _blocked.value

    /** Clips from muted or blocked peers are never stored or played. */
    fun isSuppressed(fingerprint: String): Boolean =
        NearbyFeedFilter.isSuppressed(fingerprint, _muted.value, _blocked.value)

    fun setMuted(fingerprint: String, muted: Boolean) {
        val clean = fingerprint.trim()
        if (clean.isBlank()) return
        _muted.value = if (muted) _muted.value + clean else _muted.value - clean
        persist()
    }

    fun setBlocked(fingerprint: String, blocked: Boolean) {
        val clean = fingerprint.trim()
        if (clean.isBlank()) return
        _blocked.value = if (blocked) _blocked.value + clean else _blocked.value - clean
        persist()
    }

    private fun persist() {
        prefs.edit()
            .putStringSet(KEY_MUTED, _muted.value)
            .putStringSet(KEY_BLOCKED, _blocked.value)
            .apply()
    }

    private companion object {
        const val PREFS_FILE = "bit_audio_peers"
        const val KEY_MUTED = "muted"
        const val KEY_BLOCKED = "blocked"
    }
}
