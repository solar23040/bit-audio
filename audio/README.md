# `:audio` — voice capture, Opus, playback

Agent B owns this module. It captures 16 kHz mono PCM16, encodes 20 ms Opus frames at
12 kbps, carries them in a self-delimiting clip payload, and plays them back.

## Public API

| Type | Purpose |
|---|---|
| `AudioConfig` | Format constants: 16 kHz mono, 20 ms / 320 samples, 12 kbps, 15 s cap. |
| `AudioCodec` | Phase 0 contract: one 20 ms frame in, one Opus packet out (and reverse). |
| `OpusAudioCodec` | libopus implementation of `AudioCodec`; thread-safe. |
| `OpusClipCodec` | Whole-clip helper: PCM ⇄ frames, enforces the 15 s cap. |
| `EncodedAudioClip` | Immutable clip (`frames`, `sampleCount`) and payload serialization. |
| `VoiceRecorder` | `AudioRecord` hold-to-record with a hard 15 s cap. |
| `ClipPlayer` | `AudioTrack` streaming playback; `stop()` is safe from the UI thread. |
| `WavFile` | PCM16 WAV read/write for tests and debug export. |

### Typical flow

```kotlin
// Caller must hold RECORD_AUDIO at runtime.
val recorder = VoiceRecorder()
recorder.start()
// ... user holds the button ...
val recording = recorder.stop() ?: return

val codec = OpusClipCodec()
val clip = codec.encode(recording.pcm)
val plaintextPayload = clip.toPayload()     // hand this to Mesh.publish()
// ...
val received = EncodedAudioClip.fromPayload(plaintextPayload)
ClipPlayer().play(received)                 // call from a background thread
```

`stop()` returns null when nothing was captured. A non-null `Recording.error` means capture
ended because of a device error; `truncated` means the 15 s cap was hit.

## Payload format (inside the mesh plaintext)

The audio module owns this container so Opus frame boundaries survive mesh fragmentation.
All integers are little-endian:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version = `1` |
| 1 | 1 | codec = `1` (Opus, 16 kHz mono, 20 ms frames) |
| 2 | 2 | frame count (`1..750`) |
| 4 | 4 | original PCM sample count (`1..240000`) |
| 8 | 2 | frame 0 length |
| 10 | n | frame 0 Opus packet |
| … | … | repeated length + packet |

`EncodedAudioClip.fromPayload` rejects bad versions, bad lengths, mismatched counts, and
trailing bytes without unbounded allocation. The mesh layer seals this whole byte array once.

## Implementation notes

- Native Opus is built from the official libopus **1.5.2** source, fetched by CMake at
  configure time and pinned with SHA-256
  `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`.
  libopus is BSD-2-Clause; see the `COPYING` file in the downloaded source.
- `src/main/java/.../OpusNative.java` is the thin JNI bridge. `consumer-rules.pro` keeps its
  symbol names for R8.
- NDK r27 is configured with `ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON` for 16 KB-page devices.
- `OpusAudioCodec` uses `OPUS_APPLICATION_VOIP`, voice signal mode, VBR, DTX off, in-band FEC
  off by default. FEC/DTX can be enabled through the constructor for later tuning.
- The encoder and decoder are separate libopus states. Do not share one `AudioCodec` instance
  between capture and playback.
- Playback decodes frame by frame, so a full 15 s clip does not need a second full-size PCM
  buffer.

## Tests

- **JVM unit tests** use LWJGL's real libopus as an oracle. They build a 10 s synthetic
  voice-like WAV, encode it through the same Kotlin framing code, assert the payload is under
  20 KB, decode it, and check waveform correlation. This runs in CI without a device.
  The LWJGL natives are `testRuntimeOnly`; they are not shipped in the app.
- **Instrumented tests** (`src/androidTest`) exercise the actual Android JNI bridge and assert
  the same 10 s size and quality targets. Run them on a physical phone/emulator when available.
- The plan forbids local builds; push and read the `build` GitHub Actions run instead.

## Contract note for Agent A

`AGENTS.md` freezes the `:audio` namespace to `com.meshvoice.audio` and `docs/interfaces.md`
mentions `audio/src/main/java/com/solar23040/bitaudio/audio/AudioCodec.kt`. That path is stale:
the implementation lives in `audio/src/main/kotlin/com/meshvoice/audio/`. The method signatures
match `docs/interfaces.md`, and codec failures use `AudioCodecException`.
