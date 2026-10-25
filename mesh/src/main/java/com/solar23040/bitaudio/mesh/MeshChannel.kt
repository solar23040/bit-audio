package com.solar23040.bitaudio.mesh

import com.bitaudio.crypto.ChannelKeys
import com.bitaudio.crypto.PeerDirectory

/**
 * Key and roster for one channel. The 32-byte channel key never leaves the
 * module: only the public [channelId] is exposed.
 *
 * [memberPublicKeys] is the roster used to resolve rotating sender IDs and to
 * verify packet signatures. The local identity must be in the roster.
 */
class MeshChannel(
    channelKey: ByteArray,
    memberPublicKeys: Collection<ByteArray> = emptyList(),
) {
    internal val channelKey: ByteArray = channelKey.copyOf()
    internal val directory: PeerDirectory = PeerDirectory(memberPublicKeys)

    /** Public 8-byte channel identifier; safe to log and show in the UI. */
    val channelId: ChannelId

    init {
        require(channelKey.size == ChannelKeys.KEY_SIZE) {
            "Channel key must be ${ChannelKeys.KEY_SIZE} bytes, got ${channelKey.size}"
        }
        channelId = ChannelId.fromBytes(ChannelKeys.channelId(this.channelKey))
    }

    /** Returns true when the key was new. */
    fun addMember(publicKey: ByteArray): Boolean = directory.add(publicKey)

    /** Returns true when the key was present. */
    fun removeMember(publicKey: ByteArray): Boolean = directory.remove(publicKey)
}
