package com.solar23040.bitaudio.util

import java.util.Locale

fun formatDuration(durationMs: Long): String {
    val totalSeconds = (durationMs.coerceAtLeast(0L) / 1000L)
    return String.format(Locale.US, "%d:%02d", totalSeconds / 60L, totalSeconds % 60L)
}

fun formatDurationPrecise(durationMs: Long): String {
    val totalSeconds = durationMs.coerceAtLeast(0L) / 1000L
    val tenths = (durationMs.coerceAtLeast(0L) % 1000L) / 100L
    return String.format(Locale.US, "%d:%02d.%d", totalSeconds / 60L, totalSeconds % 60L, tenths)
}

fun formatBytes(bytes: Long): String = when {
    bytes < 1024L -> "$bytes B"
    bytes < 1024L * 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024f)
    else -> String.format(Locale.US, "%.1f MB", bytes / (1024f * 1024f))
}

fun formatRelativeTime(timestampMs: Long): String =
    android.text.format.DateUtils.getRelativeTimeSpanString(
        timestampMs,
        System.currentTimeMillis(),
        android.text.format.DateUtils.MINUTE_IN_MILLIS,
    ).toString()

fun formatClock(timestampMs: Long): String =
    java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT).format(java.util.Date(timestampMs))
