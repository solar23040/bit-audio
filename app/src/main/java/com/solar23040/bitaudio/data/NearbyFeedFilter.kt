package com.solar23040.bitaudio.data

import com.solar23040.bitaudio.mesh.NearbyPeer

/**
 * Local visibility rules for the public nearby feed.
 *
 * Kept pure so the same rules are used by the receive path, the UI and the
 * unit tests: a muted fingerprint never contributes a clip and a blocked
 * fingerprint is also hidden from the peer list.
 */
object NearbyFeedFilter {

    fun isSuppressed(fingerprint: String, muted: Set<String>, blocked: Set<String>): Boolean =
        fingerprint.isNotBlank() && (fingerprint in muted || fingerprint in blocked)

    fun visiblePeers(peers: List<NearbyPeer>, blocked: Set<String>): List<NearbyPeer> =
        peers.filterNot { it.fingerprint.isNotBlank() && it.fingerprint in blocked }

    fun visibleNotes(
        notes: List<VoiceNote>,
        muted: Set<String>,
        blocked: Set<String>,
    ): List<VoiceNote> = notes.filterNot {
        isSuppressed(it.senderFingerprint, muted, blocked)
    }
}
