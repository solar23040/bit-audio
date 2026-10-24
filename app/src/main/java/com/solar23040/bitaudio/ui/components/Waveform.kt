package com.solar23040.bitaudio.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color

/**
 * Static waveform preview from stored peaks. Empty peak lists render a low
 * placeholder so incoming clips still get a visual anchor.
 */
@Composable
fun Waveform(
    peaks: List<Float>,
    modifier: Modifier = Modifier,
    color: Color = MaterialTheme.colorScheme.primary,
) {
    Canvas(modifier = modifier) {
        val bars = peaks.ifEmpty { List(36) { 0.08f } }
        val slotWidth = size.width / bars.size
        val barWidth = (slotWidth * 0.55f).coerceAtLeast(1.5f)
        val centerY = size.height / 2f
        bars.forEachIndexed { index, value ->
            val height = (value.coerceIn(0.06f, 1f) * size.height).coerceAtLeast(2f)
            drawRoundRect(
                color = color.copy(alpha = 0.85f),
                topLeft = Offset(
                    x = index * slotWidth + (slotWidth - barWidth) / 2f,
                    y = centerY - height / 2f,
                ),
                size = Size(barWidth, height),
                cornerRadius = CornerRadius(barWidth / 2f, barWidth / 2f),
            )
        }
    }
}
