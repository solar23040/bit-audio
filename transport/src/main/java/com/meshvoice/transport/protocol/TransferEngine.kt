package com.meshvoice.transport.protocol

import com.meshvoice.transport.Peer
import kotlin.random.Random

/**
 * Pure-JVM reliability core: fragments outgoing payloads, applies selective acks, retransmits missing
 * chunks, and feeds inbound chunks to the [Reassembler].
 *
 * The BLE layer owns sockets and pacing; this class owns transfer state. All methods are
 * synchronized because GATT callbacks and the maintenance coroutine run on different threads.
 */
internal class TransferEngine(
    private val settings: TransferSettings = TransferSettings(),
    private val clock: () -> Long = System::currentTimeMillis,
    private val onTransferFailed: ((Peer, Int, String) -> Unit)? = null,
) {
    private data class TransferKey(val peerId: String, val transferId: Int)

    private class Outgoing(
        val peer: Peer,
        val transferId: Int,
        val chunks: List<ByteArray>,
        val acked: BooleanArray,
        val createdAt: Long,
        var lastAckAt: Long,
        var attempts: Int,
    )

    data class Started(val transferId: Int, val chunks: List<ByteArray>)

    data class Inbound(
        val acks: List<ByteArray> = emptyList(),
        val deliveries: List<ByteArray> = emptyList(),
    )

    data class Retransmission(
        val peer: Peer,
        val transferId: Int,
        val chunks: List<ByteArray>,
    )

    private val outgoing = LinkedHashMap<TransferKey, Outgoing>()
    private val reassembler = Reassembler(settings, clock)
    private var nextTransferId: Int = Random.nextInt(1, Int.MAX_VALUE)

    /**
     * Fragments [payload] and registers it for ack tracking. The caller must write the returned
     * chunks and call [markRetransmitted] if they are sent again.
     */
    @Synchronized
    fun startTransfer(
        peer: Peer,
        payload: ByteArray,
        maxFrameBytes: Int = settings.maxFrameBytes,
    ): Started {
        require(payload.size <= settings.maxPayloadBytes) {
            "payload ${payload.size} exceeds ${settings.maxPayloadBytes}"
        }
        val frameBytes = minOf(maxFrameBytes, settings.maxFrameBytes, ChunkCodec.MAX_FRAME_BYTES)
        require(frameBytes > ChunkCodec.HEADER_SIZE) { "frame size $frameBytes too small" }
        val dataPerChunk = frameBytes - ChunkCodec.HEADER_SIZE
        val totalChunks = if (payload.isEmpty()) {
            1
        } else {
            (payload.size + dataPerChunk - 1) / dataPerChunk
        }
        require(totalChunks <= settings.maxChunks) {
            "payload needs $totalChunks chunks, limit is ${settings.maxChunks}"
        }
        require(AckCodec.sizeFor(totalChunks) <= frameBytes) {
            "ack bitmap for $totalChunks chunks does not fit in $frameBytes bytes"
        }

        val transferId = allocateTransferId(peer.id)
        val chunks = Fragmenter.fragment(transferId, payload, frameBytes)
        val now = clock()
        outgoing[TransferKey(peer.id, transferId)] = Outgoing(
            peer = peer,
            transferId = transferId,
            chunks = chunks,
            acked = BooleanArray(chunks.size),
            createdAt = now,
            lastAckAt = now,
            attempts = 1,
        )
        return Started(transferId, chunks)
    }

    /** Handles one received frame. Chunk frames produce an ack; ack frames update outgoing state. */
    @Synchronized
    fun receive(peer: Peer, frame: ByteArray): Inbound {
        if (AckCodec.isAck(frame)) {
            val ack = AckCodec.decode(frame) ?: return Inbound()
            applyAck(peer, ack)
            return Inbound()
        }
        val chunk = ChunkCodec.decode(frame) ?: return Inbound()
        val outcome = reassembler.offer(peer.id, chunk)
        return Inbound(
            acks = listOf(outcome.ack),
            deliveries = outcome.completed?.let { listOf(it) } ?: emptyList(),
        )
    }

    /** Returns transfers whose ack timer expired. Call [markRetransmitted] after actually writing. */
    @Synchronized
    fun poll(now: Long = clock()): List<Retransmission> {
        reassembler.expire(now)
        val retransmissions = ArrayList<Retransmission>()
        val failures = ArrayList<Pair<Outgoing, String>>()
        val iterator = outgoing.values.iterator()
        while (iterator.hasNext()) {
            val state = iterator.next()
            if (state.acked.all { it }) {
                iterator.remove()
                continue
            }
            if (now - state.createdAt >= settings.transferTtlMs) {
                iterator.remove()
                failures.add(state to "ttl expired")
                continue
            }
            if (now - state.lastAckAt < settings.ackTimeoutMs) continue
            if (state.attempts >= settings.maxRetransmissions) {
                iterator.remove()
                failures.add(state to "retransmission limit reached")
                continue
            }
            val missing = ArrayList<ByteArray>()
            for (i in state.chunks.indices) {
                if (!state.acked[i]) missing.add(state.chunks[i])
            }
            if (missing.isEmpty()) {
                iterator.remove()
                continue
            }
            retransmissions.add(Retransmission(state.peer, state.transferId, missing))
        }
        for ((state, reason) in failures) {
            onTransferFailed?.invoke(state.peer, state.transferId, reason)
        }
        return retransmissions
    }

    /** Call after the chunks from [poll] were actually queued on a connection. */
    @Synchronized
    fun markRetransmitted(peer: Peer, transferId: Int, now: Long = clock()) {
        val state = outgoing[TransferKey(peer.id, transferId)] ?: return
        state.attempts += 1
        state.lastAckAt = now
    }

    @Synchronized
    fun expire(now: Long = clock()) {
        reassembler.expire(now)
    }

    @Synchronized
    fun clear() {
        outgoing.clear()
        reassembler.clear()
    }

    @Synchronized
    fun activeOutgoingCount(): Int = outgoing.size

    @Synchronized
    fun activeIncomingCount(): Int = reassembler.activeCount()

    private fun applyAck(peer: Peer, ack: AckCodec.Ack) {
        val key = TransferKey(peer.id, ack.transferId)
        val state = outgoing[key] ?: return
        if (ack.totalChunks != state.chunks.size) return

        var ackedBefore = 0
        for (acked in state.acked) if (acked) ackedBefore += 1

        var ackedAfter = 0
        for (i in state.acked.indices) {
            state.acked[i] = ack.received[i]
            if (state.acked[i]) ackedAfter += 1
        }
        state.lastAckAt = clock()
        if (ackedAfter > ackedBefore) state.attempts = 1
        if (ackedAfter == state.acked.size) outgoing.remove(key)
    }

    private fun allocateTransferId(peerId: String): Int {
        var candidate = nextTransferId
        repeat(1_000) {
            candidate = if (candidate == Int.MAX_VALUE) 1 else candidate + 1
            val collision = outgoing.keys.any { it.peerId == peerId && it.transferId == candidate }
            if (!collision) {
                nextTransferId = candidate
                return candidate
            }
        }
        error("could not allocate a transfer id")
    }
}
