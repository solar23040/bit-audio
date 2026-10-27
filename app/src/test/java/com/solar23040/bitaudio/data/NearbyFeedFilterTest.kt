package com.solar23040.bitaudio.data

import com.solar23040.bitaudio.mesh.NearbyPeer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NearbyFeedFilterTest {

    private fun note(id: String, fingerprint: String): VoiceNote = VoiceNote(
        id = id,
        channelId = "nearby",
        senderAlias = "Peer",
        fileName = "$id.opus",
        durationMs = 1_000,
        sizeBytes = 100,
        peaks = emptyList(),
        hopCount = 1,
        outgoing = false,
        state = NoteState.Delivered,
        createdAt = 1_000L,
        senderFingerprint = fingerprint,
    )

    @Test
    fun `muted and blocked peers never surface clips`() {
        val notes = listOf(
            note("keep", "aa11bb"),
            note("muted", "cc22dd"),
            note("blocked", "ee33ff"),
            note("local", ""),
        )

        val visible = NearbyFeedFilter.visibleNotes(
            notes = notes,
            muted = setOf("cc22dd"),
            blocked = setOf("ee33ff"),
        )

        assertEquals(listOf("keep", "local"), visible.map { it.id })
    }

    @Test
    fun `blocked peers are hidden from the nearby list`() {
        val peers = listOf(
            NearbyPeer("aa11bb", "Alice", -60, 1, 1L, 0),
            NearbyPeer("cc22dd", "Bob", null, 2, 1L, 0),
        )

        val visible = NearbyFeedFilter.visiblePeers(peers, blocked = setOf("cc22dd"))

        assertEquals(listOf("aa11bb"), visible.map { it.fingerprint })
    }

    @Test
    fun `blank fingerprints are not suppressed`() {
        assertFalse(NearbyFeedFilter.isSuppressed("", setOf("aa11bb"), setOf("cc22dd")))
        assertTrue(NearbyFeedFilter.isSuppressed("aa11bb", setOf("aa11bb"), emptySet()))
    }
}
