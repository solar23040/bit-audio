package com.solar23040.bitaudio.mesh.node

import com.bitaudio.crypto.XChaCha20Poly1305
import java.security.MessageDigest

/**
 * One v1 mesh packet (`docs/packet-format.md`).
 *
 * The wire layout is one 107-byte header followed by one sealed chunk. The
 * signature is the last header field. The `ttl` byte is mutable: relays only
 * change it and never re-sign the packet.
 */
internal class MeshPacket(
    val messageId: ByteArray,
    val channelId: ByteArray,
    val senderId: ByteArray,
    val ttl: Int,
    val chunkIndex: Int,
    val totalChunks: Int,
    val timestampMs: Long,
    val counter: Long,
    val signature: ByteArray,
    val sealedChunk: ByteArray,
    val type: Int = TYPE_VOICE_DATA,
) {
    val messageIdHex: String get() = messageId.toHex()
    val channelIdHex: String get() = channelId.toHex()
    val senderIdHex: String get() = senderId.toHex()

    /** First 43 bytes of the header, with the real TTL. */
    fun headerPrefix(): ByteArray {
        val header = ByteArray(HEADER_PREFIX_SIZE)
        header[0] = VERSION.toByte()
        header[1] = type.toByte()
        messageId.copyInto(header, 2, 0, ID_SIZE)
        channelId.copyInto(header, 10, 0, ID_SIZE)
        senderId.copyInto(header, 18, 0, ID_SIZE)
        header[26] = ttl.toByte()
        putShort(header, 27, chunkIndex)
        putShort(header, 29, totalChunks)
        putLong(header, 31, timestampMs)
        putInt(header, 39, counter)
        return header
    }

    /** Header used for signing and AEAD: TTL is always zero on the wire input. */
    fun canonicalPrefix(): ByteArray = headerPrefix().also { it[26] = 0 }

    fun toWire(): ByteArray {
        val header = headerPrefix()
        val out = ByteArray(HEADER_SIZE + sealedChunk.size)
        header.copyInto(out, 0)
        signature.copyInto(out, HEADER_PREFIX_SIZE)
        sealedChunk.copyInto(out, HEADER_SIZE)
        return out
    }

    /** Copy with only the unsigned TTL byte changed. */
    fun withTtl(newTtl: Int): MeshPacket {
        require(newTtl in 0..MAX_TTL) { "ttl must be in 0..$MAX_TTL" }
        return MeshPacket(
            messageId = messageId,
            channelId = channelId,
            senderId = senderId,
            ttl = newTtl,
            chunkIndex = chunkIndex,
            totalChunks = totalChunks,
            timestampMs = timestampMs,
            counter = counter,
            signature = signature,
            sealedChunk = sealedChunk,
            type = type,
        )
    }

    companion object {
        const val VERSION = 1
        const val TYPE_VOICE_DATA = 0x01

        const val HEADER_PREFIX_SIZE = 43
        const val HEADER_SIZE = 107
        const val MAX_PACKET_SIZE = 512
        const val MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
        const val MAX_PLAINTEXT_CHUNK_SIZE = MAX_PAYLOAD_SIZE - XChaCha20Poly1305.MIN_SEALED_SIZE
        const val MAX_PLAINTEXT_MESSAGE_SIZE = 64 * 1024
        const val MAX_CHUNKS = 256
        const val MIN_TTL = 1
        const val MAX_TTL = 8

        /** Parses a wire frame, or returns null for malformed input. */
        fun decode(frame: ByteArray): MeshPacket? {
            if (frame.size < HEADER_SIZE || frame.size > MAX_PACKET_SIZE) return null
            if ((frame[0].toInt() and 0xFF) != VERSION) return null
            val type = frame[1].toInt() and 0xFF
            if (type != TYPE_VOICE_DATA) return null

            val chunkIndex = readShort(frame, 27)
            val totalChunks = readShort(frame, 29)
            if (totalChunks !in 1..MAX_CHUNKS || chunkIndex >= totalChunks) return null

            val sealedSize = frame.size - HEADER_SIZE
            if (sealedSize < XChaCha20Poly1305.MIN_SEALED_SIZE) return null

            return MeshPacket(
                messageId = frame.copyOfRange(2, 10),
                channelId = frame.copyOfRange(10, 18),
                senderId = frame.copyOfRange(18, 26),
                ttl = frame[26].toInt() and 0xFF,
                chunkIndex = chunkIndex,
                totalChunks = totalChunks,
                timestampMs = readLong(frame, 31),
                counter = readInt(frame, 39).toLong() and 0xFFFF_FFFFL,
                signature = frame.copyOfRange(HEADER_PREFIX_SIZE, HEADER_SIZE),
                sealedChunk = frame.copyOfRange(HEADER_SIZE, frame.size),
                type = type,
            )
        }

        fun seal(
            crypto: com.bitaudio.crypto.Crypto,
            channelKey: ByteArray,
            headerPrefix: ByteArray,
            plaintext: ByteArray,
        ): MeshPacket {
            require(plaintext.size <= MAX_PLAINTEXT_CHUNK_SIZE) {
                "chunk plaintext must be <= $MAX_PLAINTEXT_CHUNK_SIZE bytes"
            }
            val canonical = headerPrefix.copyOf().also { it[26] = 0 }
            val sealed = com.bitaudio.crypto.PacketCrypto.sealPayload(
                crypto = crypto,
                channelKey = channelKey,
                headerWithoutSignature = canonical,
                payload = plaintext,
            )
            return MeshPacket(
                messageId = headerPrefix.copyOfRange(2, 10),
                channelId = headerPrefix.copyOfRange(10, 18),
                senderId = headerPrefix.copyOfRange(18, 26),
                ttl = headerPrefix[26].toInt() and 0xFF,
                chunkIndex = readShort(headerPrefix, 27),
                totalChunks = readShort(headerPrefix, 29),
                timestampMs = readLong(headerPrefix, 31),
                counter = readInt(headerPrefix, 39).toLong() and 0xFFFF_FFFFL,
                signature = ByteArray(0),
                sealedChunk = sealed,
                type = headerPrefix[1].toInt() and 0xFF,
            )
        }

        fun headerPrefix(
            type: Int,
            messageId: ByteArray,
            channelId: ByteArray,
            senderId: ByteArray,
            ttl: Int,
            chunkIndex: Int,
            totalChunks: Int,
            timestampMs: Long,
            counter: Long,
        ): ByteArray {
            require(messageId.size == ID_SIZE)
            require(channelId.size == ID_SIZE)
            require(senderId.size == ID_SIZE)
            require(ttl in 0..MAX_TTL)
            require(chunkIndex in 0 until totalChunks)
            require(totalChunks in 1..MAX_CHUNKS)
            require(counter in 0..0xFFFF_FFFFL)
            val header = ByteArray(HEADER_PREFIX_SIZE)
            header[0] = VERSION.toByte()
            header[1] = type.toByte()
            messageId.copyInto(header, 2)
            channelId.copyInto(header, 10)
            senderId.copyInto(header, 18)
            header[26] = ttl.toByte()
            putShort(header, 27, chunkIndex)
            putShort(header, 29, totalChunks)
            putLong(header, 31, timestampMs)
            putInt(header, 39, counter)
            return header
        }

        fun messageKey(channelId: String, identityHex: String, messageId: String): String =
            "$channelId:$identityHex:$messageId"

        fun packetKey(channelId: String, messageId: String, chunkIndex: Int): String =
            "$channelId:$messageId:$chunkIndex"

        fun ByteArray.constantTimeEquals(other: ByteArray): Boolean =
            MessageDigest.isEqual(this, other)

        private fun putShort(out: ByteArray, offset: Int, value: Int) {
            out[offset] = (value ushr 8).toByte()
            out[offset + 1] = value.toByte()
        }

        private fun putInt(out: ByteArray, offset: Int, value: Long) {
            out[offset] = (value ushr 24).toByte()
            out[offset + 1] = (value ushr 16).toByte()
            out[offset + 2] = (value ushr 8).toByte()
            out[offset + 3] = value.toByte()
        }

        private fun putLong(out: ByteArray, offset: Int, value: Long) {
            for (index in 0 until 8) {
                out[offset + index] = (value ushr (56 - index * 8)).toByte()
            }
        }

        private fun readShort(bytes: ByteArray, offset: Int): Int =
            ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

        private fun readInt(bytes: ByteArray, offset: Int): Int =
            ((bytes[offset].toInt() and 0xFF) shl 24) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
                (bytes[offset + 3].toInt() and 0xFF)

        private fun readLong(bytes: ByteArray, offset: Int): Long {
            var value = 0L
            for (index in 0 until 8) {
                value = (value shl 8) or (bytes[offset + index].toLong() and 0xFF)
            }
            return value
        }

        private const val ID_SIZE = 8
    }
}

/** Lowercase hex used in message keys and the public API. */
internal fun ByteArray.toHex(): String = buildString(size * 2) {
    this@toHex.forEach { byte ->
        val value = byte.toInt() and 0xFF
        append(HEX[value ushr 4])
        append(HEX[value and 0x0F])
    }
}

private const val HEX = "0123456789abcdef"

/** A packet plus the neighbour it arrived from. */
internal data class InboundPacket(val from: com.meshvoice.transport.Peer, val packet: MeshPacket)
