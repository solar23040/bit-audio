package com.solar23040.bitaudio.sim

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal on-the-wire flooding packet.
 *
 * Layout (big-endian): magic(4) | messageId(4) | origin(4) | createdAtMs(8) |
 * hops(4) | ttl(4) | payloadLength(4) | payload. The header is deliberately
 * counted in airtime even though this is not the production mesh format.
 */
internal data class SimPacket(
    val messageId: Int,
    val origin: Int,
    val createdAtMs: Long,
    /** Number of edges already traversed when the packet is received. */
    val hops: Int,
    /** Remaining relays; zero means "deliver locally, do not forward". */
    val ttl: Int,
    val payload: ByteArray,
) {
    fun encode(): ByteArray {
        require(payload.size <= MAX_PAYLOAD) { "Payload too large: ${payload.size}" }
        val buffer = ByteBuffer.allocate(HEADER_BYTES + payload.size).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(MAGIC)
        buffer.putInt(messageId)
        buffer.putInt(origin)
        buffer.putLong(createdAtMs)
        buffer.putInt(hops)
        buffer.putInt(ttl)
        buffer.putInt(payload.size)
        buffer.put(payload)
        return buffer.array()
    }

    companion object {
        const val MAGIC: Int = 0x4D534831 // "MSH1"
        const val HEADER_BYTES: Int = 4 + 4 + 4 + 8 + 4 + 4 + 4
        const val MAX_PAYLOAD: Int = 64 * 1024

        fun decode(bytes: ByteArray): SimPacket? {
            if (bytes.size < HEADER_BYTES) return null
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
            if (buffer.getInt() != MAGIC) return null
            val messageId = buffer.getInt()
            val origin = buffer.getInt()
            val createdAtMs = buffer.getLong()
            val hops = buffer.getInt()
            val ttl = buffer.getInt()
            val payloadLength = buffer.getInt()
            if (payloadLength < 0 || payloadLength > MAX_PAYLOAD) return null
            if (buffer.remaining() != payloadLength) return null
            val payload = ByteArray(payloadLength)
            buffer.get(payload)
            return SimPacket(
                messageId = messageId,
                origin = origin,
                createdAtMs = createdAtMs,
                hops = hops,
                ttl = ttl,
                payload = payload,
            )
        }
    }
}
