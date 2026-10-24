# `:app` — Agent F (UI / app shell)

Phase 3 shell for Bit Audio. This module is deliberately independent of the
other modules' implementation packages; they are still landing in Phase 1.

## What works now

- Channel list with local persistence.
- Create channel with a random 32-byte key and show its QR invite.
- Join via camera QR (ZXing) or pasted `bitaudio://join?...` code.
- Channel view: note list, waveform, sender alias, hop count, delivery state.
- Hold-to-talk recording (16 kHz mono PCM16, 15 s cap) and local playback.
- Permission flow for microphone, BLE (API 31+ split permissions), notifications.
- Foreground service with `connectedDevice` type and a Stop action.
- Scan duty-cycling (10 s on / 20 s off) driven from Settings while the service runs.
- Settings: display name, default TTL, retention, duty cycle, rotate sender ID.

Notes are stored as WAV files in app-private storage and marked **Queued**.
There is no radio in this build yet, so nothing leaves the phone.

## Integration seams (Agent A / Phase 2)

| App seam | Replace with |
|---|---|
| `OfflineMeshRuntime` (`transport/MeshRuntime.kt`) | Adapter that drives `:mesh` / `:transport`; set `isAvailable = true` |
| `PreviewRecorder` / `PreviewPlayer` (`audio/`) | `:audio` Opus recorder/player; `RecordedClip` keeps its shape |
| `ChannelIdCodec` (`invite/`) | `Crypto.channelId(ChannelKey)`; derivation is already domain-compatible |
| `IdentityStore` (`data/`) | `:crypto` Ed25519 identity and rotating sender IDs |
| `AppGraph.addRecordedNote` | Encrypt + publish through `Mesh.publish`; flip state on `MeshMessage` |

The QR payload is versioned (`v=1`) and carries the raw channel key. Treat a
shared invite as a shared secret.

## Build

Do not build locally. Push and let the `build` workflow run
`./gradlew test lintDebug assembleDebug`; download the APK artifact.
