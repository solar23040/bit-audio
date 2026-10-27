package com.solar23040.bitaudio.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Card
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.solar23040.bitaudio.data.NoteState
import com.solar23040.bitaudio.data.VoiceNote
import com.solar23040.bitaudio.util.formatBytes
import com.solar23040.bitaudio.util.formatClock
import com.solar23040.bitaudio.util.formatDuration
import java.util.Locale

/** One playable voice note, used by both the private feed and nearby. */
@Composable
fun VoiceNoteCard(
    note: VoiceNote,
    isPlaying: Boolean,
    onPlay: () -> Unit,
    showFingerprint: Boolean = false,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                FilledIconButton(
                    onClick = onPlay,
                    colors = IconButtonDefaults.filledIconButtonColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    ),
                    modifier = Modifier.size(40.dp),
                ) {
                    Icon(
                        imageVector = if (isPlaying) Icons.Filled.Pause else Icons.Filled.PlayArrow,
                        contentDescription = if (isPlaying) "Stop playback" else "Play note",
                    )
                }
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    val sender = if (note.outgoing) {
                        "You"
                    } else if (showFingerprint && note.senderFingerprint.isNotEmpty()) {
                        "${note.senderAlias}#${note.senderFingerprint}"
                    } else {
                        note.senderAlias
                    }
                    Text(
                        text = sender,
                        style = MaterialTheme.typography.titleSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = formatClock(note.createdAt),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                DeliveryBadge(note.state)
            }
            Spacer(Modifier.height(10.dp))
            Waveform(
                peaks = note.peaks,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(34.dp),
                color = if (isPlaying) {
                    MaterialTheme.colorScheme.tertiary
                } else {
                    MaterialTheme.colorScheme.primary
                },
            )
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "${formatDuration(note.durationMs)} · ${formatBytes(note.sizeBytes)}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (!note.outgoing) {
                    Spacer(Modifier.weight(1f))
                    Text(
                        text = "${note.hopCount} hop" + if (note.hopCount == 1) "" else "s",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun DeliveryBadge(state: NoteState) {
    val label = when (state) {
        NoteState.Sent -> "Sent"
        NoteState.Queued -> "Queued"
        NoteState.Delivered -> "Delivered"
        NoteState.Failed -> "Failed"
    }
    val color = when (state) {
        NoteState.Sent -> MaterialTheme.colorScheme.tertiary
        NoteState.Queued -> MaterialTheme.colorScheme.secondary
        NoteState.Delivered -> MaterialTheme.colorScheme.primary
        NoteState.Failed -> MaterialTheme.colorScheme.error
    }
    Surface(
        shape = RoundedCornerShape(50),
        color = color.copy(alpha = 0.14f),
        contentColor = color,
    ) {
        Text(
            text = label.uppercase(Locale.US),
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
        )
    }
}
