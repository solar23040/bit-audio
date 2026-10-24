package com.meshvoice.transport.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.CRC32

/**
 * Transport-level settings. Kept free of Android types so the fragmentation/reliability core can be
 * tested on the JVM.
 *
 * [maxFrameBytes] is the largest BLE write payload. 240 fits the 244-byte ATT payload of a 247 MTU
 * with margin for the 3-byte ATT write header.
 */
data class TransferSettings(
    val maxFrameBytes: Int = 240,
    val ackTimeoutMs: Long = 800,
    val maxRetransmissions: Int = 12,
    val transferTtlMs: Long = 300_000,
    val reassemblyTimeoutMs: Long = 30_000,
    val completedCacheMs: Long = 120_000,
    val maxPayloadBytes: Int = 128 * 1024,
    val maxChunks: Int = 1_800,
    val maxConcurrentIncoming: Int = 16,
) {
    init {
        require(maxFrameBytes > ChunkCodec.HEADER_SIZE) { "maxFrameBytes too small" }
        require(maxFrameBytes <= ChunkCodec.MAX_FRAME_BYTES) { "maxFrameBytes exceeds transport limit" }
        require(ackTimeoutMs > 0) { "ackTimeoutMs must be positive" }
        require(maxRetransmissions > 0) { "maxRetransmissions must be positive" }
        require(transferTtlMs > 0) { "transferTtlMs must be positive" }
        require(reassemblyTimeoutMs > 0) { "reassemblyTimeoutMs must be positive" }
        require(completedCacheMs > 0) { "completedCacheMs must be positive" }
        require(maxPayloadBytes > 0) { "maxPayloadBytes must be positive" }
        require(maxChunks in 1..ChunkCodec.MAX_CHUNKS) { "maxChunks must be in 1..${ChunkCodec.MAX_CHUNKS}" }
        require(maxConcurrentIncoming > 0) { "maxConcurrentIncoming must be positive" }
    }
}

internal object ChunkCodec {
    const val VERSION = 0x01
    const val HEADER_SIZE = 15

    /** Largest frame carried over one BLE write; 240 bytes + 3 ATT header fits MTU 247. */
    const val MAX_FRAME_BYTES = 240

    /** Bounded so a full ack bitmap fits in one frame (1800 bits = 225 bytes + 9-byte header). */
    const val MAX_CHUNKS = 1_800

    data class Header(
        val transferId: Int,
        val seq: Int,
        val totalChunks: Int,
        val dataLength: Int,
        val payloadCrc: Int,
    )

    data class Parsed(val header: Header, val data: ByteArray)

    fun crc32(bytes: ByteArray): Int {
        val crc = CRC32()
        crc.update(bytes)
        return crc.value.toInt()
    }

    fun encode(
        transferId: Int,
        seq: Int,
        totalChunks: Int,
        payloadCrc: Int,
        payload: ByteArray,
        offset: Int,
        length: Int,
    ): ByteArray {
        require(seq in 0 until totalChunks)
        require(totalChunks in 1..MAX_CHUNKS)
        require(offset >= 0 && length >= 0 && offset + length <= payload.size)
        require(length <= MAX_FRAME_BYTES - HEADER_SIZE)
        val buffer = ByteBuffer.allocate(HEADER_SIZE + length).order(ByteOrder.BIG_ENDIAN)
        buffer.put(VERSION.toByte())
        buffer.putInt(transferId)
        buffer.putShort(seq.toShort())
        buffer.putShort(totalChunks.toShort())
        buffer.putShort(length.toShort())
        buffer.putInt(payloadCrc)
        buffer.put(payload, offset, length)
        return buffer.array()
    }

    fun decode(frame: ByteArray): Parsed? {
        if (frame.size < HEADER_SIZE) return null
        val buffer = ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN)
        val version = buffer.get().toInt() and 0xFF
        if (version != VERSION) return null
        val transferId = buffer.int
        val seq = buffer.short.toInt() and 0xFFFF
        val totalChunks = buffer.short.toInt() and 0xFFFF
        val dataLength = buffer.short.toInt() and 0xFFFF
        val payloadCrc = buffer.int
        if (totalChunks !in 1..MAX_CHUNKS) return null
        if (seq !in 0 until totalChunks) return null
        if (dataLength != frame.size - HEADER_SIZE) return null
        if (dataLength > MAX_FRAME_BYTES - HEADER_SIZE) return null
        val data = ByteArray(dataLength)
        buffer.get(data)
        return Parsed(Header(transferId, seq, totalChunks, dataLength, payloadCrc), data)
    }
}

internal object AckCodec {
    const val TYPE = 0xA1
    const val HEADER_SIZE = 9

    data class Ack(
        val transferId: Int,
        val totalChunks: Int,
        val received: BooleanArray,
    )

    fun sizeFor(totalChunks: Int): Int = HEADER_SIZE + (totalChunks + 7) / 8

    fun isAck(frame: ByteArray): Boolean =
        frame.isNotEmpty() && (frame[0].toInt() and 0xFF) == TYPE

    fun encode(transferId: Int, totalChunks: Int, received: BooleanArray): ByteArray {
        require(totalChunks in 1..ChunkCodec.MAX_CHUNKS)
        require(received.size == totalChunks)
        val bitmapLength = (totalChunks + 7) / 8
        val bitmap = ByteArray(bitmapLength)
        for (i in 0 until totalChunks) {
            if (received[i]) {
                bitmap[i / 8] = (bitmap[i / 8].toInt() or (1 shl (i % 8))).toByte()
            }
        }
        val buffer = ByteBuffer.allocate(HEADER_SIZE + bitmapLength).order(ByteOrder.BIG_ENDIAN)
        buffer.put(TYPE.toByte())
        buffer.putInt(transferId)
        buffer.putShort(totalChunks.toShort())
        buffer.putShort(bitmapLength.toShort())
        buffer.put(bitmap)
        return buffer.array()
    }

    fun decode(frame: ByteArray): Ack? {
        if (!isAck(frame) || frame.size < HEADER_SIZE) return null
        val buffer = ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN)
        buffer.get()
        val transferId = buffer.int
        val totalChunks = buffer.short.toInt() and 0xFFFF
        val bitmapLength = buffer.short.toInt() and 0xFFFF
        if (totalChunks !in 1..ChunkCodec.MAX_CHUNKS) return null
        if (bitmapLength != (totalChunks + 7) / 8) return null
        if (frame.size != HEADER_SIZE + bitmapLength) return null
        val bitmap = ByteArray(bitmapLength)
        buffer.get(bitmap)
        val received = BooleanArray(totalChunks) { i ->
            ((bitmap[i / 8].toInt() shr (i % 8)) and 1) == 1
        }
        return Ack(transferId, totalChunks, received)
    }
}

internal object Fragmenter {
    fun fragment(transferId: Int, payload: ByteArray, maxFrameBytes: Int): List<ByteArray> {
        require(maxFrameBytes > ChunkCodec.HEADER_SIZE) { "frame too small" }
        require(maxFrameBytes <= ChunkCodec.MAX_FRAME_BYTES) { "frame too large" }
        val dataPerChunk = maxFrameBytes - ChunkCodec.HEADER_SIZE
        val totalChunks = if (payload.isEmpty()) {
            1
        } else {
            (payload.size + dataPerChunk - 1) / dataPerChunk
        }
        require(totalChunks <= ChunkCodec.MAX_CHUNKS) { "payload needs too many chunks: $totalChunks" }
        val payloadCrc = ChunkCodec.crc32(payload)
        val frames = ArrayList<ByteArray>(totalChunks)
        for (seq in 0 until totalChunks) {
            val offset = seq * dataPerChunk
            val length = minOf(dataPerChunk, payload.size - offset).coerceAtLeast(0)
            frames.add(
                ChunkCodec.encode(
                    transferId = transferId,
                    seq = seq,
                    totalChunks = totalChunks,
                    payloadCrc = payloadCrc,
                    payload = payload,
                    offset = offset,
                    length = length,
                ),
            )
        }
        return frames
    }
}
