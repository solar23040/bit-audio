# JNI entry points are looked up by symbol name.
-keep class com.meshvoice.audio.OpusNative { *; }
-keepclasseswithmembernames class com.meshvoice.audio.OpusNative {
    native <methods>;
}
