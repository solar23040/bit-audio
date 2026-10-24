# Bit Audio

Push-to-talk voice notes over a BLE mesh. No servers, no accounts.

Status: **Phase 0 (foundations)**. Interfaces, packet format, cloud CI, and an
in-memory fake transport are in place. See `pllan.md` for the full plan.

## Modules

| Module | Purpose | Owner |
|---|---|---|
| `:app` | Application shell, foreground service, UI | Agent F |
| `:audio` | Capture, Opus encode/decode, playback | Agent B |
| `:transport` | BLE link, fragmentation, `FakeTransport` | Agent C |
| `:mesh` | Packet codec, TTL flood, dedup, store-and-forward | Agent D |
| `:crypto` | Identity, signatures, channel keys, AEAD | Agent E |
| `:sim` | N-node simulator and metrics | Agent G |

Contracts live in [`docs/interfaces.md`](docs/interfaces.md) and the wire format
in [`docs/packet-format.md`](docs/packet-format.md).

## Build

This project is built **only in cloud CI** so no Android/Java toolchain is
needed on the development machine.

1. Push a branch to GitHub.
2. Open the **Actions** tab and wait for the `build` workflow.
3. Download the `bit-audio-debug-*` artifact and sideload the APK.

CI runs unit tests, Android lint, and `assembleDebug` on every push.

## Testing

Unit tests run in CI. Real BLE and multi-hop behaviour needs physical phones.
For everything else, use `FakeNetwork` / `FakeTransport` from `:transport`.
