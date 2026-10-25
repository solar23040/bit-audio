package com.solar23040.bitaudio.mesh.engine

import com.solar23040.bitaudio.mesh.ChannelId
import com.solar23040.bitaudio.mesh.engine.store.InMemoryMeshStore
import com.solar23040.bitaudio.mesh.engine.store.StoredPacket
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class MeshStoreTest {

    private val channel = ChannelId.fromHex("0011223344556677")
    private val messageId = "0123456789abcdef"

    @Test
    fun `counter starts at one and survives reuse`() {
        val store = InMemoryMeshStore()

        assertEquals(1L, store.nextCounter(channel))
        assertEquals(2L, store.nextCounter(channel))
        assertEquals(1L, store.nextCounter(ChannelId.fromHex("8899aabbccddeeff")))
    }

    @Test
    fun `expired packets are not loaded and can be purged`() {
        val store = InMemoryMeshStore()
        store.save(packet(chunkIndex = 0, expiresAtMs = 1_000))
        store.save(packet(chunkIndex = 1, expiresAtMs = 5_000))

        assertEquals(2, store.loadUnexpired(nowMs = 500).size)
        assertEquals(1, store.loadUnexpired(nowMs = 2_000).size)
        assertEquals(1, store.deleteExpired(nowMs = 2_000))
        assertEquals(1, store.size())
    }

    @Test
    fun `saved frames are copied and replace the same chunk`() {
        val store = InMemoryMeshStore()
        val frame = ByteArray(256) { 7 }
        store.save(packet(chunkIndex = 0, frame = frame, expiresAtMs = 10_000))
        frame.fill(9)

        val loaded = store.loadUnexpired(nowMs = 0).single()
        assertArrayEquals(ByteArray(256) { 7 }, loaded.frame)

        store.save(packet(chunkIndex = 0, frame = ByteArray(256) { 3 }, expiresAtMs = 10_000))
        assertEquals(1, store.size())
        assertArrayEquals(ByteArray(256) { 3 }, store.loadUnexpired(0).single().frame)
    }

    private fun packet(
        chunkIndex: Int,
        frame: ByteArray = ByteArray(128) { 1 },
        expiresAtMs: Long,
    ): StoredPacket = StoredPacket(
        channel = channel,
        messageId = messageId,
        chunkIndex = chunkIndex,
        timestampMs = 0,
        expiresAtMs = expiresAtMs,
        frame = frame,
    )
}
