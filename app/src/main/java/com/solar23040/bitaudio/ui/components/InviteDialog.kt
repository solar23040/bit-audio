package com.solar23040.bitaudio.ui.components

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.solar23040.bitaudio.data.Channel
import com.solar23040.bitaudio.invite.ChannelInvite
import com.solar23040.bitaudio.invite.generateQrCodeBitmap

@Composable
fun InviteDialog(channel: Channel, onDismiss: () -> Unit) {
    val payload = remember(channel.id, channel.key, channel.name) {
        ChannelInvite.encode(channel)
    }
    val bitmap = remember(payload) { generateQrCodeBitmap(payload) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Invite to ${channel.name}") },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                if (bitmap != null) {
                    Image(
                        bitmap = bitmap.asImageBitmap(),
                        contentDescription = "Channel QR code",
                        contentScale = ContentScale.Fit,
                        modifier = Modifier
                            .size(240.dp)
                            .background(Color.White, RoundedCornerShape(12.dp))
                            .padding(8.dp),
                    )
                } else {
                    Text("Could not render the QR code. Copy the invite code instead.")
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    text = "Have a friend scan this with Bit Audio. Anyone with the code " +
                        "can read this channel, so share it privately.",
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "Channel ${channel.id}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Done") }
        },
    )
}
