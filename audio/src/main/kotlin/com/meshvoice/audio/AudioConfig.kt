package com.meshvoice.audio

/**
 * Wire and capture format for mesh voice notes.
 *
 * One clip is a sequence of Opus packets, each carrying exactly 20 ms of 16 kHz mono PCM16.
 * The 12 kbps target keeps a full 10 s clip around 15 KB before mesh headers.
 */
object AudioConfig {
    const val SAMPLE_RATE_HZ = 16_000
    const val CHANNEL_COUNT = 1
    const val FRAME_DURATION_MS = 20
    const val FRAME_SAMPLES = SAMPLE_RATE_HZ * FRAME_DURATION_MS / 1_000

    const val BITRATE_BPS = 12_000
    const val MAX_CLIP_DURATION_MS = 15_000
    const val MAX_CLIP_SAMPLES = SAMPLE_RATE_HZ * MAX_CLIP_DURATION_MS / 1_000
    const val MAX_FRAMES = MAX_CLIP_SAMPLES / FRAME_SAMPLES

    /** One Opus frame cannot exceed 1275 bytes. */
    const val MAX_OPUS_PACKET_BYTES = 1_275

    /** Acceptance target from the plan, not a hard failure condition. */
    const val TARGET_MAX_CLIP_BYTES = 20_000
}
