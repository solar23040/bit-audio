package com.solar23040.bitaudio.mesh

/**
 * A peer heard on the public nearby channel.
 *
 * [fingerprint] is the first 6 hex characters of `SHA-256(identity_public_key)`.
 * [hopCount] counts radio links: `1` means a direct neighbour, `2` means one
 * relay. [rssi] is only known for direct neighbours. [lastSeenMs] is wall-clock
 * time and entries expire after the mesh's local peer timeout.
 */
data class NearbyPeer(
    val fingerprint: String,
    val nickname: String,
    val rssi: Int?,
    /** Number of radio links from this device to the peer. */
    val hopCount: Int,
    val lastSeenMs: Long,
    val capabilities: Int,
) {
    /** A direct neighbour, i.e. no relay in between. */
    val isDirect: Boolean get() = hopCount <= 1
}
