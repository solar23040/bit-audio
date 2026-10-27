package com.solar23040.bitaudio.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp
import com.solar23040.bitaudio.util.formatDuration

/** Hold-to-talk control shared by nearby and private channel screens. */
@Composable
fun TalkBar(
    isRecording: Boolean,
    elapsedMs: Long,
    amplitude: Float,
    hasMic: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    navigationPadding: Boolean = true,
) {
    val scale by animateFloatAsState(
        targetValue = if (isRecording) 1.06f else 1f,
        label = "micScale",
    )
    val insetModifier = if (navigationPadding) Modifier.navigationBarsPadding() else Modifier
    Surface(tonalElevation = 3.dp, shadowElevation = 12.dp) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .then(insetModifier)
                .padding(horizontal = 24.dp, vertical = 14.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = if (isRecording) {
                    "Recording ${formatDuration(elapsedMs)} / 0:15"
                } else {
                    "Hold to talk · 15s max"
                },
                style = MaterialTheme.typography.labelLarge,
                color = if (isRecording) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
            Spacer(Modifier.height(8.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth(0.7f)
                    .height(5.dp)
                    .clip(RoundedCornerShape(3.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant),
            ) {
                if (isRecording) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth(amplitude.coerceIn(0f, 1f))
                            .fillMaxHeight()
                            .background(MaterialTheme.colorScheme.error),
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            Box(
                modifier = Modifier
                    .size(84.dp)
                    .graphicsLayer {
                        scaleX = scale
                        scaleY = scale
                    }
                    .clip(CircleShape)
                    .background(
                        if (isRecording) {
                            MaterialTheme.colorScheme.error
                        } else {
                            MaterialTheme.colorScheme.primary
                        },
                    )
                    .pointerInput(hasMic) {
                        if (hasMic) {
                            detectTapGestures(
                                onPress = {
                                    onStart()
                                    tryAwaitRelease()
                                    onStop()
                                },
                            )
                        }
                    }
                    .clickable(enabled = !hasMic) { onStart() },
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = if (isRecording) Icons.Filled.Stop else Icons.Filled.Mic,
                    contentDescription = if (isRecording) "Send voice note" else "Hold to record",
                    tint = if (isRecording) {
                        MaterialTheme.colorScheme.onError
                    } else {
                        MaterialTheme.colorScheme.onPrimary
                    },
                    modifier = Modifier.size(36.dp),
                )
            }
        }
    }
}
