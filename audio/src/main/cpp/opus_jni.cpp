#include <jni.h>

#include <cstdint>
#include <string>

#include "opus.h"

namespace {

void throwByName(JNIEnv *env, const char *className, const std::string &message) {
    jclass clazz = env->FindClass(className);
    if (clazz != nullptr) {
        env->ThrowNew(clazz, message.c_str());
    }
}

void throwIllegalArgument(JNIEnv *env, const std::string &message) {
    throwByName(env, "java/lang/IllegalArgumentException", message);
}

void throwIllegalState(JNIEnv *env, const std::string &message) {
    throwByName(env, "java/lang/IllegalStateException", message);
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_meshvoice_audio_OpusNative_version(JNIEnv *env, jclass) {
    return env->NewStringUTF(opus_get_version_string());
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_meshvoice_audio_OpusNative_encoderCreate(
        JNIEnv *env,
        jclass,
        jint sampleRate,
        jint channels,
        jint application,
        jint bitrate,
        jint complexity,
        jboolean useVbr,
        jboolean useDtx,
        jboolean inbandFec,
        jint packetLossPercent,
        jint signal
) {
    int error = OPUS_OK;
    OpusEncoder *encoder = opus_encoder_create(sampleRate, channels, application, &error);
    if (encoder == nullptr || error != OPUS_OK) {
        if (encoder != nullptr) {
            opus_encoder_destroy(encoder);
        }
        throwIllegalArgument(
                env,
                std::string("Failed to create Opus encoder: ") + opus_strerror(error)
        );
        return 0;
    }

    auto apply = [&](int result, const char *name) -> bool {
        if (result == OPUS_OK) {
            return true;
        }
        opus_encoder_destroy(encoder);
        throwIllegalState(
                env,
                std::string("opus_encoder_ctl(") + name + ") failed: " + opus_strerror(result)
        );
        return false;
    };

    if (!apply(opus_encoder_ctl(encoder, OPUS_SET_BITRATE(bitrate)), "bitrate")) {
        return 0;
    }
    if (!apply(opus_encoder_ctl(encoder, OPUS_SET_COMPLEXITY(complexity)), "complexity")) {
        return 0;
    }
    if (!apply(opus_encoder_ctl(encoder, OPUS_SET_VBR(useVbr == JNI_TRUE ? 1 : 0)), "vbr")) {
        return 0;
    }
    if (!apply(opus_encoder_ctl(encoder, OPUS_SET_DTX(useDtx == JNI_TRUE ? 1 : 0)), "dtx")) {
        return 0;
    }
    if (!apply(
            opus_encoder_ctl(encoder, OPUS_SET_INBAND_FEC(inbandFec == JNI_TRUE ? 1 : 0)),
            "inband_fec"
    )) {
        return 0;
    }
    if (!apply(
            opus_encoder_ctl(encoder, OPUS_SET_PACKET_LOSS_PERC(packetLossPercent)),
            "packet_loss_perc"
    )) {
        return 0;
    }
    if (!apply(opus_encoder_ctl(encoder, OPUS_SET_SIGNAL(signal)), "signal")) {
        return 0;
    }

    return reinterpret_cast<jlong>(encoder);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_meshvoice_audio_OpusNative_encode(
        JNIEnv *env,
        jclass,
        jlong handle,
        jshortArray pcm,
        jint frameSize,
        jbyteArray output
) {
    auto *encoder = reinterpret_cast<OpusEncoder *>(handle);
    if (encoder == nullptr) {
        throwIllegalState(env, "Opus encoder handle is null");
        return -1;
    }
    if (env->GetArrayLength(pcm) < frameSize) {
        throwIllegalArgument(env, "PCM buffer is smaller than frameSize");
        return -1;
    }
    if (env->GetArrayLength(output) <= 0) {
        throwIllegalArgument(env, "Output buffer is empty");
        return -1;
    }

    jshort *pcmData = env->GetShortArrayElements(pcm, nullptr);
    if (pcmData == nullptr) {
        throwIllegalState(env, "Unable to access PCM buffer");
        return -1;
    }
    jbyte *outputData = env->GetByteArrayElements(output, nullptr);
    if (outputData == nullptr) {
        env->ReleaseShortArrayElements(pcm, pcmData, JNI_ABORT);
        throwIllegalState(env, "Unable to access Opus output buffer");
        return -1;
    }

    int result = opus_encode(
            encoder,
            pcmData,
            frameSize,
            reinterpret_cast<unsigned char *>(outputData),
            env->GetArrayLength(output)
    );

    env->ReleaseShortArrayElements(pcm, pcmData, JNI_ABORT);
    env->ReleaseByteArrayElements(output, outputData, 0);

    if (result < 0) {
        throwIllegalState(env, std::string("opus_encode failed: ") + opus_strerror(result));
        return -1;
    }
    return result;
}

extern "C" JNIEXPORT void JNICALL
Java_com_meshvoice_audio_OpusNative_encoderDestroy(JNIEnv *, jclass, jlong handle) {
    if (handle != 0) {
        opus_encoder_destroy(reinterpret_cast<OpusEncoder *>(handle));
    }
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_meshvoice_audio_OpusNative_decoderCreate(
        JNIEnv *env,
        jclass,
        jint sampleRate,
        jint channels
) {
    int error = OPUS_OK;
    OpusDecoder *decoder = opus_decoder_create(sampleRate, channels, &error);
    if (decoder == nullptr || error != OPUS_OK) {
        if (decoder != nullptr) {
            opus_decoder_destroy(decoder);
        }
        throwIllegalArgument(
                env,
                std::string("Failed to create Opus decoder: ") + opus_strerror(error)
        );
        return 0;
    }
    return reinterpret_cast<jlong>(decoder);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_meshvoice_audio_OpusNative_decode(
        JNIEnv *env,
        jclass,
        jlong handle,
        jbyteArray packet,
        jint frameSize,
        jshortArray output
) {
    auto *decoder = reinterpret_cast<OpusDecoder *>(handle);
    if (decoder == nullptr) {
        throwIllegalState(env, "Opus decoder handle is null");
        return -1;
    }
    if (env->GetArrayLength(output) < frameSize) {
        throwIllegalArgument(env, "PCM output buffer is smaller than frameSize");
        return -1;
    }

    jbyte *packetData = env->GetByteArrayElements(packet, nullptr);
    if (packetData == nullptr) {
        throwIllegalState(env, "Unable to access Opus packet buffer");
        return -1;
    }
    jshort *outputData = env->GetShortArrayElements(output, nullptr);
    if (outputData == nullptr) {
        env->ReleaseByteArrayElements(packet, packetData, JNI_ABORT);
        throwIllegalState(env, "Unable to access PCM output buffer");
        return -1;
    }

    int result = opus_decode(
            decoder,
            reinterpret_cast<const unsigned char *>(packetData),
            env->GetArrayLength(packet),
            outputData,
            frameSize,
            0
    );

    env->ReleaseByteArrayElements(packet, packetData, JNI_ABORT);
    env->ReleaseShortArrayElements(output, outputData, 0);

    if (result < 0) {
        throwIllegalState(env, std::string("opus_decode failed: ") + opus_strerror(result));
        return -1;
    }
    return result;
}

extern "C" JNIEXPORT void JNICALL
Java_com_meshvoice_audio_OpusNative_decoderDestroy(JNIEnv *, jclass, jlong handle) {
    if (handle != 0) {
        opus_decoder_destroy(reinterpret_cast<OpusDecoder *>(handle));
    }
}
