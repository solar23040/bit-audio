package com.solar23040.bitaudio.mesh.engine

import com.solar23040.bitaudio.mesh.ChannelId

/**
 * Decoded v1 packet fields. The signature is kept separately from the header
 * because relays never modify it.
 */
internal data class MeshPacketHeader(
    val type: Int,
    /** 8 bytes, random per message. */
    val messageId: ByteArray,
    val channelId: ChannelId,
    /** 8-byte rotating sender ID. */
    val senderId: ByteArray,
    /** Mutable hop limit; excluded from the signature by canonicalisation. */
    val ttl: Int,
    val chunkIndex: Int,
    val totalChunks: Int,
    val timestampMs: Long,
    /** Per-message counter, shared by all chunks. */
    val counter: Long,
)

internal class MeshPacket(
    val header: MeshPacketHeader,
    val signature: ByteArray,
    val sealedPayload: ByteArray,
)

/** Wire codec for the 107-byte header described in docs/packet-format.md. */
internal object MeshPacketCodec {

    const val VERSION = 0x01
    const val TYPE_VOICE_DATA = 0x01

    const val HEADER_PREFIX_SIZE = 43
    const val SIGNATURE_SIZE = 64
    const val HEADER_SIZE = HEADER_PREFIX_SIZE + SIGNATURE_SIZE
    const val MAX_PACKET_SIZE = 512
    const val MAX_SEALED_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
    const val MIN_SEALED_PAYLOAD_SIZE = 24 + 16
    const val MAX_CHUNK_PLAINTEXT = MAX_SEALED_PAYLOAD_SIZE - MIN_SEALED_PAYLOAD_SIZE
    const val MAX_TOTAL_CHUNKS = 256
    const val MIN_TTL = 1
    const val MAX_TTL = 8

    private const val TTL_OFFSET = 26

    /** Serialises the header with its real [MeshPacketHeader.ttl]. */
    fun headerBytes(header: MeshPacketHeader): ByteArray {
        require(header.messageId.size == 8) { "messageId must be 8 bytes" }
        require(header.senderId.size == 8) { "senderId must be 8 bytes" }
        require(header.timestampMs >= 0) { "timestampMs must be non-negative" }
        require(header.counter in 0..0xFFFF_FFFFL) { "counter must fit in u32" }

        val out = ByteArray(HEADER_PREFIX_SIZE)
        out[0] = VERSION.toByte()
        out[1] = header.type.toByte()
        header.messageId.copyInto(out, 2)
        header.channelId.toBytes().copyInto(out, 10)
        header.senderId.copyInto(out, 18)
        out[TTL_OFFSET] = header.ttl.toByte()
        putU16(out, 27, header.chunkIndex)
        putU16(out, 29, header.totalChunks)
        putU64(out, 31, header.timestampMs)
        putU32(out, 39, header.counter)
        return out
    }

    fun encode(
        header: MeshPacketHeader,
        signature: ByteArray,
        sealedPayload: ByteArray,
    ): ByteArray {
        require(signature.size == SIGNATURE_SIZE) {
            "signature must be $SIGNATURE_SIZE bytes"
        }
        require(sealedPayload.size in MIN_SEALED_PAYLOAD_SIZE..MAX_SEALED_PAYLOAD_SIZE) {
            "sealed payload must be in $MIN_SEALED_PAYLOAD_SIZE..$MAX_SEALED_PAYLOAD_SIZE bytes"
        }

        val out = ByteArray(HEADER_SIZE + sealedPayload.size)
        headerBytes(header).copyInto(out, 0)
        signature.copyInto(out, HEADER_PREFIX_SIZE)
        sealedPayload.copyInto(out, HEADER_SIZE)
        return out
    }

    /** Returns null for any malformed or out-of-contract frame. */
    fun decode(frame: ByteArray): MeshPacket? {
        if (frame.size < HEADER_SIZE || frame.size > MAX_PACKET_SIZE) return null
        if ((frame[0].toInt() and 0xFF) != VERSION) return null
        if ((frame[1].toInt() and 0xFF) != TYPE_VOICE_DATA) return null

        val ttl = frame[TTL_OFFSET].toInt() and 0xFF
        if (ttl !in MIN_TTL..MAX_TTL) return null

        val chunkIndex = readU16(frame, 27)
        val totalChunks = readU16(frame, 29)
        if (totalChunks !in 1..MAX_TOTAL_CHUNKS) return null
        if (chunkIndex >= totalChunks) return null

        val sealedSize = frame.size - HEADER_SIZE
        if (sealedSize !in MIN_SEALED_PAYLOAD_SIZE..MAX_SEALED_PAYLOAD_SIZE) return null

        val header = MeshPacketHeader(
            type = frame[1].toInt() and 0xFF,
            messageId = frame.copyOfRange(2, 10),
            channelId = ChannelId.fromBytes(frame.copyOfRange(10, 18)),
            senderId = frame.copyOfRange(18, 26),
            ttl = ttl,
            chunkIndex = chunkIndex,
            totalChunks = totalChunks,
            timestampMs = readU64(frame, 31),
            counter = readU32(frame, 39),
        )
        return MeshPacket(
            header = header,
            signature = frame.copyOfRange(HEADER_PREFIX_SIZE, HEADER_SIZE),
            sealedPayload = frame.copyOfRange(HEADER_SIZE, frame.size),
        )
    }

    /**
     * Copy of [frame] with a new TTL. The signature stays valid because
     * canonicalisation zeroes the TTL, so a relay never re-signs.
     */
    fun withTtl(frame: ByteArray, ttl: Int): ByteArray? {
        if (ttl !in MIN_TTL..MAX_TTL) return null
        if (frame.size < HEADER_SIZE || frame.size > MAX_PACKET_SIZE) return null
        return frame.copyOf().also { it[TTL_OFFSET] = ttl.toByte() }
    }

    private fun putU16(out: ByteArray, offset: Int, value: Int) {
        out[offset] = (value ushr 8).toByte()
        out[offset + 1] = value.toByte()
    }

    private fun putU32(out: ByteArray, offset: Int, value: Long) {
        out[offset] = (value ushr 24).toByte()
        out[offset + 1] = (value ushr 16).toByte()
        out[offset + 2] = (value ushr 8).toByte()
        out[offset + 3] = value.toByte()
    }

    private fun putU64(out: ByteArray, offset: Int, value: Long) {
        for (i in 0 until 8) {
            out[offset + i] = (value ushr (56 - i * 8)).toByte()
        }
    }

    private fun readU16(frame: ByteArray, offset: Int): Int =
        ((frame[offset].toInt() and 0xFF) shl 8) or (frame[offset + 1].toInt() and 0xFF)

    private fun readU32(frame: ByteArray, offset: Int): Long =
        ((frame[offset].toLong() and 0xFF) shl 24) or
            ((frame[offset + 1].toLong() and 0xFF) shl 16) or
            ((frame[offset + 2].toLong() and 0xFF) shl 8) or
            (frame[offset + 3].toLong() and 0xFF)

    private fun readU64(frame: ByteArray, offset: Int): Long {
        var value = 0L
        for (i in 0 until 8) {
            value = (value shl 8) or (frame[offset + i].toLong() and 0xFF)
        }
        return value
    }
}
