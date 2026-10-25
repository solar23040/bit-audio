package com.solar23040.bitaudio.audio

import com.solar23040.bitaudio.pipeline.waveformPeaks

/**
 * A finished hold-to-talk capture, before it is encoded.
 *
 * [peaks] is display data for the note list; it is derived from the real PCM
 * when the caller does not supply it.
 */
data class RecordedClip(
    val pcm: ShortArray,
    val durationMs: Long,
    val peaks: List<Float> = waveformPeaks(pcm),
) {
    val isSilent: Boolean get() = pcm.isEmpty()
}
