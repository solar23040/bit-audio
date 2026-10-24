package com.solar23040.bitaudio.data

import org.junit.Assert.assertEquals
import org.junit.Test

class RetentionTest {
    private val cutoff = 1_000_000L

    private fun note(
        id: String,
        createdAt: Long,
        state: NoteState,
    ): VoiceNote = VoiceNote(
        id = id,
        channelId = "channel",
        senderAlias = "Me",
        fileName = "$id.wav",
        durationMs = 1_000,
        sizeBytes = 100,
        peaks = emptyList(),
        hopCount = 0,
        outgoing = true,
        state = state,
        createdAt = createdAt,
    )

    @Test
    fun onlyUndeliveredNotesBeforeCutoffExpire() {
        val notes = listOf(
            note("old-queued", cutoff - 1, NoteState.Queued),
            note("old-sending", cutoff - 1, NoteState.Sending),
            note("old-failed", cutoff - 1, NoteState.Failed),
            note("old-delivered", cutoff - 1, NoteState.Delivered),
            note("new-queued", cutoff, NoteState.Queued),
        )

        val expired = notes.expiredNotes(cutoff).map { it.id }

        assertEquals(listOf("old-queued", "old-sending", "old-failed"), expired)
    }
}
