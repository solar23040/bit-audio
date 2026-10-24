package com.meshvoice.transport.protocol

/**
 * Reassembles chunks per (peer, transfer id). Acks are full state bitmaps rather than deltas, so a
 * lost ack is harmless: the next ack or a retransmit produces the complete picture again.
 *
 * A CRC failure clears the transfer and returns an all-zero ack, asking the sender to resend
 * everything instead of delivering corrupt audio.
 */
internal class Reassembler(
    private val settings: TransferSettings,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private data class Key(val peer: String, val transferId: Int)

    private class Incoming(
        val totalChunks: Int,
        val payloadCrc: Int,
        var lastActivityAt: Long,
        val parts: Array<ByteArray?>,
        val received: BooleanArray,
        var receivedCount: Int,
        var receivedBytes: Int,
    )

    private class Completed(
        val totalChunks: Int,
        val payloadCrc: Int,
        val completedAt: Long,
    )

    data class Outcome(
        val ack: ByteArray,
        val completed: ByteArray? = null,
    )

    private val incoming = LinkedHashMap<Key, Incoming>()
    private val completed = LinkedHashMap<Key, Completed>()

    @Synchronized
    fun offer(peer: String, chunk: ChunkCodec.Parsed, now: Long = clock()): Outcome {
        val header = chunk.header
        val key = Key(peer, header.transferId)

        val alreadyDone = completed[key]
        if (alreadyDone != null) {
            if (alreadyDone.totalChunks == header.totalChunks && alreadyDone.payloadCrc == header.payloadCrc) {
                if (now - alreadyDone.completedAt <= settings.completedCacheMs) {
                    return Outcome(fullAck(header.transferId, alreadyDone.totalChunks), null)
                }
                completed.remove(key)
            } else {
                // Transfer id was reused for a different payload; accept it as a new transfer.
                completed.remove(key)
            }
        }

        var state = incoming[key]
        if (state == null) {
            if (incoming.size >= settings.maxConcurrentIncoming) evictOldest()
            state = Incoming(
                totalChunks = header.totalChunks,
                payloadCrc = header.payloadCrc,
                lastActivityAt = now,
                parts = arrayOfNulls(header.totalChunks),
                received = BooleanArray(header.totalChunks),
                receivedCount = 0,
                receivedBytes = 0,
            )
            incoming[key] = state
        }

        if (state.totalChunks != header.totalChunks || state.payloadCrc != header.payloadCrc) {
            incoming.remove(key)
            return Outcome(emptyAck(header.transferId, header.totalChunks), null)
        }

        state.lastActivityAt = now
        val seq = header.seq
        val existing = state.parts[seq]
        if (existing != null) {
            if (!existing.contentEquals(chunk.data)) {
                // Two different payloads claiming the same sequence: restart this transfer.
                incoming.remove(key)
                return Outcome(emptyAck(header.transferId, header.totalChunks), null)
            }
            return Outcome(AckCodec.encode(header.transferId, state.totalChunks, state.received), null)
        }

        if (state.receivedBytes + chunk.data.size > settings.maxPayloadBytes) {
            incoming.remove(key)
            return Outcome(emptyAck(header.transferId, header.totalChunks), null)
        }

        state.parts[seq] = chunk.data
        state.received[seq] = true
        state.receivedCount += 1
        state.receivedBytes += chunk.data.size

        if (state.receivedCount < state.totalChunks) {
            return Outcome(AckCodec.encode(header.transferId, state.totalChunks, state.received), null)
        }

        incoming.remove(key)
        val payload = assemble(state)
        if (payload == null || ChunkCodec.crc32(payload) != state.payloadCrc) {
            return Outcome(emptyAck(header.transferId, header.totalChunks), null)
        }

        completed[key] = Completed(state.totalChunks, state.payloadCrc, now)
        return Outcome(fullAck(header.transferId, state.totalChunks), payload)
    }

    @Synchronized
    fun expire(now: Long = clock()) {
        val states = incoming.entries.iterator()
        while (states.hasNext()) {
            if (now - states.next().value.lastActivityAt > settings.reassemblyTimeoutMs) {
                states.remove()
            }
        }
        val done = completed.entries.iterator()
        while (done.hasNext()) {
            if (now - done.next().value.completedAt > settings.completedCacheMs) {
                done.remove()
            }
        }
    }

    @Synchronized
    fun clear() {
        incoming.clear()
        completed.clear()
    }

    @Synchronized
    fun activeCount(): Int = incoming.size

    private fun assemble(state: Incoming): ByteArray? {
        if (state.receivedBytes > settings.maxPayloadBytes) return null
        val payload = ByteArray(state.receivedBytes)
        var offset = 0
        for (i in 0 until state.totalChunks) {
            val part = state.parts[i] ?: return null
            part.copyInto(payload, offset)
            offset += part.size
        }
        return payload
    }

    private fun evictOldest() {
        val oldest = incoming.minByOrNull { it.value.lastActivityAt } ?: return
        incoming.remove(oldest.key)
    }

    private fun emptyAck(transferId: Int, totalChunks: Int): ByteArray =
        AckCodec.encode(transferId, totalChunks, BooleanArray(totalChunks))

    private fun fullAck(transferId: Int, totalChunks: Int): ByteArray =
        AckCodec.encode(transferId, totalChunks, BooleanArray(totalChunks) { true })
}
