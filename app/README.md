# `:app` — Agent F (UI / app shell)

Phase 3 shell for Bit Audio. This module is deliberately independent of the
other modules' implementation packages; they are still landing in Phase 1.

## What works now

- Channel list with local persistence.
- Create channel with a random 32-byte key and show its QR invite.
- Join via camera QR (ZXing) or pasted `bitaudio://join?...` code.
- Channel view: note list, waveform, sender alias, hop count, delivery state.
- Hold-to-talk recording through `:audio` (`VoiceRecorder`, 16 kHz mono PCM16, 15 s cap),
  Opus encoding, and `Mesh.publish(channel, payload)`.
- Incoming mesh notes are Opus-decoded, stored, listed as **Delivered** with their
  hop count, and played automatically.
- Note states: **Queued** (on disk, mesh down), **Sent** (handed to the mesh), **Delivered**.
- Permission flow for microphone, BLE (API 31+ split permissions), notifications.
- Foreground service with `connectedDevice` type and a Stop action.
- Scan duty-cycling (10 s on / 20 s off) driven from Settings while the service runs.
- Settings: display name, default TTL, retention, duty cycle, rotate sender ID.

Notes are stored as Opus payloads in app-private storage. A note recorded while
the service is stopped stays **Queued** and is retried when the mesh starts.

## Pipeline

`AppGraph.addRecordedNote` hands the capture to `VoicePipeline`
(`pipeline/`), which:

1. encodes the PCM with `OpusClipCodec`, rejects clips over 15 s, writes
   `EncodedAudioClip.toPayload()` to the clip directory, and records a Queued note;
2. calls `MeshRuntime.publish(channelId, payload)` and marks the note Sent;
3. subscribes to `Mesh.onMessage`, validates the payload, writes the received
   clip, records a Delivered note with `MeshMessage.hopCount`, and plays it.

`VoicePipelineTest` covers the whole path over `FakeNetwork`: a clip published on
node 1 plays on node 3 through node 2.

## Integration seams (Agent A / Phase 2)

| App seam | Replace with |
|---|---|
| `ChannelIdCodec` (`invite/`) | `Crypto.channelId(ChannelKey)`; derivation is already domain-compatible |
| `IdentityStore` (`data/`) | `:crypto` Ed25519 identity and rotating sender IDs |
| Mesh roster | `MEMBER_ANNOUNCE` exchange; today a channel contains only the local key |

The QR payload is versioned (`v=1`) and carries the raw channel key. Treat a
shared invite as a shared secret.

## Build

Do not build locally. Push and let the `build` workflow run
`./gradlew test lintDebug assembleDebug`; download the APK artifact.
