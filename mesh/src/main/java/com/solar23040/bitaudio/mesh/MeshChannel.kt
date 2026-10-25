package com.solar23040.bitaudio.mesh

import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.Ed25519
import com.bitaudio.crypto.PeerDirectory

/**
 * One joined channel: its 32-byte secret and the roster of member Ed25519
 * public keys used to resolve rotating sender IDs.
 *
 * The channel ID is always derived from the key, never supplied separately, so
 * a packet can only be routed on a channel whose key this node actually holds.
 * The key stays private to the module; callers pass it in once.
 */
class MeshChannel(
    channelKey: ByteArray,
    val roster: PeerDirectory,
) {
    private val key: ByteArray = channelKey.copyOf()

    /** Public 8-byte channel identifier, hex encoded. */
    val id: ChannelId = ChannelId.fromBytes(ChannelKeys.channelId(this.key))

    init {
        require(key.size == ChannelKeys.KEY_SIZE) {
            "channel key must be ${ChannelKeys.KEY_SIZE} bytes, got $key.size"
        }
    }

    /** Adds a member key to the roster. Returns true when it was new. */
    fun addMember(publicKey: ByteArray): Boolean {
        require(publicKey.size == Ed25519.PUBLIC_KEY_SIZE) {
            "member public key must be ${Ed25519.PUBLIC_KEY_SIZE} bytes"
        }
        return roster.add(publicKey)
    }

    /**
     * Internal access for sealing/verification. Never expose this outside the
     * module or copy it into logs.
     */
    internal fun keyBytes(): ByteArray = key
}
