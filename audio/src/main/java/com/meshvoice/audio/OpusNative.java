package com.meshvoice.audio;

/**
 * Thin JNI bridge to libopus. Native methods are static so their symbol names are stable.
 * This class is an implementation detail; use {@link OpusAudioCodec} instead.
 */
final class OpusNative {

    static {
        System.loadLibrary("meshopus");
    }

    private OpusNative() {
    }

    static native String version();

    static native long encoderCreate(
            int sampleRate,
            int channels,
            int application,
            int bitrate,
            int complexity,
            boolean useVbr,
            boolean useDtx,
            boolean inbandFec,
            int packetLossPercent,
            int signal
    );

    static native int encode(long handle, short[] pcm, int frameSize, byte[] output);

    static native void encoderDestroy(long handle);

    static native long decoderCreate(int sampleRate, int channels);

    static native int decode(long handle, byte[] packet, int frameSize, short[] output);

    static native void decoderDestroy(long handle);
}
