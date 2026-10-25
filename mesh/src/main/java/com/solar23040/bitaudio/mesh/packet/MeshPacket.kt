package com.solar23040.bitaudio.mesh.packet

/**
 * One v1 mesh packet: fixed 107-byte header followed by one sealed chunk.
 *
 * Layout (big-endian):
 * ```
 *  0   1  version
 *  1   1  type
 *  2   8  msg_id
 * 10   8  channel_id
 * 18   8  sender_id
 * 26   1  ttl
 * 27   2  chunk_idx
 * 29   2  total_chunks
 * 31   8  timestamp_ms
 * 39   4  counter
 * 43  64  signature
 * 107 ..  payload (24-byte nonce + ciphertext + 16-byte tag)
 * ```
 * See `docs/packet-format.md`. The TTL byte is mutable in transit and is not
 * covered by the signature, so [canonicalHeader] zeroes it before signing,
 * sealing, or opening.
 */
internal data class MeshPacket(
    val version: Int,
    val type: Int,
    val msgId: ByteArray,
    val channelId: ByteArray,
    val senderId: ByteArray,
    val ttl: Int,
    val chunkIdx: Int,
    val totalChunks: Int,
    val timestampMs: Long,
    val counter: Long,
    val signature: ByteArray,
    val payload: ByteArray,
) {
    init {
        require(version == VERSION) { "unsupported version: $version" }
        require(type in 0..0xFF) { "type out of range: $type" }
        require(msgId.size == ID_SIZE) { "msg_id must be $ID_SIZE bytes" }
        require(channelId.size == ID_SIZE) { "channel_id must be $ID_SIZE bytes" }
        require(senderId.size == ID_SIZE) { "sender_id must be $ID_SIZE bytes" }
        require(ttl in MIN_TTL..MAX_TTL) { "ttl must be in $MIN_TTL..$MAX_TTL: $ttl" }
        require(totalChunks in 1..MAX_TOTAL_CHUNKS) {
            "total_chunks must be in 1..$MAX_TOTAL_CHUNKS: $totalChunks"
        }
        require(chunkIdx in 0 until totalChunks) {
            "chunk_idx must be in 0..${totalChunks - 1}: $chunkIdx"
        }
        require(counter in 0L..MAX_COUNTER) { "counter out of range: $counter" }
        require(signature.size == SIGNATURE_SIZE) { "signature must be $SIGNATURE_SIZE bytes" }
        require(payload.size <= MAX_PAYLOAD_SIZE) {
            "payload must be at most $MAX_PAYLOAD_SIZE bytes: ${payload.size}"
        }
    }

    /** Wire bytes for this packet (107 + payload size, at most 512). */
    fun encode(): ByteArray {
        val frame = ByteArray(HEADER_SIZE + payload.size)
        writePrefix(frame, ttl)
        signature.copyInto(frame, SIGNATURE_OFFSET)
        payload.copyInto(frame, HEADER_SIZE)
        return frame
    }

    /** 43-byte header prefix with the real on-wire TTL. */
    fun headerPrefix(): ByteArray = headerPrefix(ttl)

    /** 43-byte header prefix with [ttl] forced to zero; signed and used as AAD. */
    fun canonicalHeader(): ByteArray = headerPrefix(0)

    private fun headerPrefix(ttlValue: Int): ByteArray {
        val prefix = ByteArray(PREFIX_SIZE)
        writePrefix(prefix, ttlValue)
        return prefix
    }

    private fun writePrefix(target: ByteArray, ttlValue: Int) {
        target[VERSION_OFFSET] = version.toByte()
        target[TYPE_OFFSET] = type.toByte()
        msgId.copyInto(target, MSG_ID_OFFSET)
        channelId.copyInto(target, CHANNEL_ID_OFFSET)
        senderId.copyInto(target, SENDER_ID_OFFSET)
        target[TTL_OFFSET] = ttlValue.toByte()
        target[CHUNK_IDX_OFFSET] = (chunkIdx ushr 8).toByte()
        target[CHUNK_IDX_OFFSET + 1] = chunkIdx.toByte()
        target[TOTAL_CHUNKS_OFFSET] = (totalChunks ushr 8).toByte()
        target[TOTAL_CHUNKS_OFFSET + 1] = totalChunks.toByte()
        for (index in 0 until 8) {
            target[TIMESTAMP_OFFSET + index] = (timestampMs ushr (56 - index * 8)).toByte()
        }
        target[COUNTER_OFFSET] = (counter ushr 24).toByte()
        target[COUNTER_OFFSET + 1] = (counter ushr 16).toByte()
        target[COUNTER_OFFSET + 2] = (counter ushr 8).toByte()
        target[COUNTER_OFFSET + 3] = counter.toByte()
    }

    companion object {
        const val VERSION: Int = 0x01
        const val TYPE_VOICE_DATA: Int = 0x01

        const val ID_SIZE: Int = 8
        const val SIGNATURE_SIZE: Int = 64
        const val HEADER_SIZE: Int = 107
        const val PREFIX_SIZE: Int = 43
        const val MAX_FRAME_SIZE: Int = 512
        const val MAX_PAYLOAD_SIZE: Int = MAX_FRAME_SIZE - HEADER_SIZE
        const val PLAINTEXT_CHUNK_SIZE: Int = 365
        const val MIN_SEALED_CHUNK_SIZE: Int = 24 + 16
        const val MAX_TOTAL_CHUNKS: Int = 256
        const val MAX_PLAINTEXT_SIZE: Int = 64 * 1024
        const val MIN_TTL: Int = 1
        const val MAX_TTL: Int = 8

        /** Unsigned 32-bit counter, kept in a Long so comparison stays sane. */
        const val MAX_COUNTER: Long = 0xFFFF_FFFFL

        private const val VERSION_OFFSET = 0
        private const val TYPE_OFFSET = 1
        private const val MSG_ID_OFFSET = 2
        private const val CHANNEL_ID_OFFSET = 10
        private const val SENDER_ID_OFFSET = 18
        private const val TTL_OFFSET = 26
        private const val CHUNK_IDX_OFFSET = 27
        private const val TOTAL_CHUNKS_OFFSET = 29
        private const val TIMESTAMP_OFFSET = 31
        private const val COUNTER_OFFSET = 39
        private const val SIGNATURE_OFFSET = 43

        /**
         * Parses one frame. Returns null for every malformed or out-of-range
         * header; never throws on attacker-controlled bytes.
         */
        fun decode(frame: ByteArray): MeshPacket? {
            if (frame.size < HEADER_SIZE || frame.size > MAX_FRAME_SIZE) return null
            if ((frame[VERSION_OFFSET].toInt() and 0xFF) != VERSION) return null

            val type = frame[TYPE_OFFSET].toInt() and 0xFF
            val ttl = frame[TTL_OFFSET].toInt() and 0xFF
            if (ttl !in MIN_TTL..MAX_TTL) return null

            val chunkIdx = readU16(frame, CHUNK_IDX_OFFSET)
            val totalChunks = readU16(frame, TOTAL_CHUNKS_OFFSET)
            if (totalChunks !in 1..MAX_TOTAL_CHUNKS || chunkIdx >= totalChunks) return null

            return MeshPacket(
                version = VERSION,
                type = type,
                msgId = frame.copyOfRange(MSG_ID_OFFSET, MSG_ID_OFFSET + ID_SIZE),
                channelId = frame.copyOfRange(CHANNEL_ID_OFFSET, CHANNEL_ID_OFFSET + ID_SIZE),
                senderId = frame.copyOfRange(SENDER_ID_OFFSET, SENDER_ID_OFFSET + ID_SIZE),
                ttl = ttl,
                chunkIdx = chunkIdx,
                totalChunks = totalChunks,
                timestampMs = readU64(frame, TIMESTAMP_OFFSET),
                counter = readU32(frame, COUNTER_OFFSET),
                signature = frame.copyOfRange(SIGNATURE_OFFSET, HEADER_SIZE),
                payload = frame.copyOfRange(HEADER_SIZE, frame.size),
            )
        }

        private fun readU16(bytes: ByteArray, offset: Int): Int =
            ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

        private fun readU32(bytes: ByteArray, offset: Int): Long {
            var value = 0L
            for (index in 0 until 4) {
                value = (value shl 8) or (bytes[offset + index].toLong() and 0xFF)
            }
            return value
        }

        private fun readU64(bytes: ByteArray, offset: Int): Long {
            var value = 0L
            for (index in 0 until 8) {
                value = (value shl 8) or (bytes[offset + index].toLong() and 0xFF)
            }
            return value
        }
    }
}
