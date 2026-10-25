package com.solar23040.bitaudio.mesh.node

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class PacketStoreTest {

    @Test
    fun fileStoreSurvivesRestartAndKeepsCountersMonotonic() {
        val directory = Files.createTempDirectory("mesh-store-test").toFile()
        try {
            val now = System.currentTimeMillis()
            val first = StoredMessage(
                key = "channel:identity:message",
                channelId = "channel",
                messageId = "message",
                createdAtMs = now,
                timestampMs = now,
                expiresAtMs = now + 60_000,
                packets = listOf(packet(0), packet(1)),
            )
            FilePacketStore(directory).use { store ->
                store.put(first)
                assertEquals(1L, store.nextCounter("channel:identity"))
                assertEquals(2L, store.nextCounter("channel:identity"))
            }

            FilePacketStore(directory).use { reopened ->
                assertEquals(3L, reopened.nextCounter("channel:identity"))
                val restored = reopened.snapshot(now + 1_000).single()
                assertEquals(first.channelId, restored.channelId)
                assertArrayEquals(first.packets[0], restored.packets[0])
                assertArrayEquals(first.packets[1], restored.packets[1])

                assertTrue(
                    reopened.append(
                        key = restored.key,
                        channelId = restored.channelId,
                        messageId = restored.messageId,
                        chunkIndex = 2,
                        packet = packet(2),
                        createdAtMs = now,
                        timestampMs = now,
                        expiresAtMs = now + 60_000,
                    ),
                )
                assertEquals(3, reopened.snapshot(now + 1_000).single().packets.size)
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun expiredMessagesAreNeverReplayed() {
        val directory = Files.createTempDirectory("mesh-store-expiry").toFile()
        try {
            val now = System.currentTimeMillis()
            val store = FilePacketStore(directory)
            store.put(
                StoredMessage(
                    key = "old",
                    channelId = "channel",
                    messageId = "old",
                    createdAtMs = now - 10_000,
                    timestampMs = now - 10_000,
                    expiresAtMs = now - 1,
                    packets = listOf(packet(0)),
                ),
            )
            assertEquals(0, store.snapshot(now).size)
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun packet(index: Int): ByteArray {
        val header = MeshPacket.headerPrefix(
            type = MeshPacket.TYPE_VOICE_DATA,
            messageId = ByteArray(8) { 1 },
            channelId = ByteArray(8) { 2 },
            senderId = ByteArray(8) { 3 },
            ttl = 5,
            chunkIndex = index,
            totalChunks = 3,
            timestampMs = 1L,
            counter = 1L,
        )
        return header + ByteArray(64) { index.toByte() }
    }
}
