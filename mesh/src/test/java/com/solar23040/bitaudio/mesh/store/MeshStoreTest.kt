package com.solar23040.bitaudio.mesh.store

import com.solar23040.bitaudio.mesh.ChannelId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MeshStoreTest {

    private val channel = ChannelId.fromHex("0102030405060708")

    @Test
    fun `unexpired packets load and expired packets are filtered`() {
        val now = 1_700_000_000_000L
        val store = InMemoryMeshStore()

        store.save(packet(expiresAtMs = now - 1L, chunkIndex = 0))
        store.save(packet(expiresAtMs = now + 1L, chunkIndex = 1))

        assertEquals(2, store.size())
        assertEquals(listOf(1), store.loadUnexpired(now).map { it.chunkIndex })
        assertEquals(1, store.deleteExpired(now))
        assertEquals(1, store.size())
        assertEquals(listOf(1), store.loadUnexpired(now).map { it.chunkIndex })
    }

    @Test
    fun `oldest packets are evicted when the bound is reached`() {
        val store = InMemoryMeshStore(maxPackets = 2)
        repeat(3) { index ->
            store.save(packet(expiresAtMs = Long.MAX_VALUE, chunkIndex = index))
        }

        assertEquals(2, store.size())
        assertEquals(listOf(1, 2), store.loadUnexpired(0L).map { it.chunkIndex }.sorted())
    }

    @Test
    fun `message counters start at one and increase`() {
        val store = InMemoryMeshStore()

        assertEquals(1L, store.nextCounter(channel))
        assertEquals(2L, store.nextCounter(channel))
        assertEquals(1L, store.nextCounter(ChannelId.fromHex("1112131415161718")))
    }

    @Test
    fun `clear removes packets and counters`() {
        val store = InMemoryMeshStore()
        store.save(packet(expiresAtMs = Long.MAX_VALUE, chunkIndex = 0))
        store.nextCounter(channel)

        store.clear()

        assertEquals(0, store.size())
        assertEquals(1L, store.nextCounter(channel))
        assertTrue(store.loadUnexpired(0L).isEmpty())
    }

    private fun packet(expiresAtMs: Long, chunkIndex: Int): StoredPacket = StoredPacket(
        channel = channel,
        messageId = "0011223344556677",
        chunkIndex = chunkIndex,
        timestampMs = 1_700_000_000_000L,
        expiresAtMs = expiresAtMs,
        frame = ByteArray(107),
    )
}
