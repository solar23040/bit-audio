# Attack harness (Agent H)

Black-box BLE attack tests for Phase 5. Frames are built to
[`docs/packet-format.md`](../../docs/packet-format.md) v1 and sent either to a
real test phone over GATT (`--sink ble`) or to Agent G's simulator as JSONL
(`--sink sim`). `--sink dry` prints frames without touching hardware.

> **Blocked on SEC-016:** `:crypto` currently derives channel/sender IDs and the
> signing/AAD bytes differently from the docs. Until Agent A reconciles the
> contract, frames from this harness will not verify in the app. The harness
> follows the authoritative docs.

## Setup

```bash
cd security/attack-tests
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python selfcheck.py
python fuzz_packets.py --self-check
```

`requirements.txt` installs only `bleak` (BLE client) and `PyNaCl` (Ed25519 +
XChaCha20-Poly1305). No Android/Gradle build is performed here.

Generate a local config (mode 0600, gitignored):

```bash
python make_config.py --out config.json
```

Fill in:

- `channel_key_hex` — the 32-byte key of a **dedicated test channel**. The app
  needs a debug/export path for this (Agent F). Without it, only dry-run and
  fuzz self-check work.
- `identity_seed_hex` — leave the generated value to use the harness as a test
  member. Its public key (`make_config.py` prints it) must be enrolled in the
  target channel's roster, otherwise the baseline is dropped as unknown.
- `victim.pubkey_hex` — roster public key to impersonate in spoofing tests.
  Sender IDs rotate every 15 min, so do **not** hardcode `sender_id_hex`.
- `ble.address`, `ble.rx_char_uuid` — target phone and the characteristic the
  app reads mesh frames from. `ble.tx_char_uuid` is needed for capture.
- `limits.max_pps` / `limits.max_frames` — hard safety caps (default 50 / 2000).

If the app's GATT layout is not known yet, leave `ble` as-is and use dry/sim.

## Sinks

| Sink | Use |
|---|---|
| `dry` | No hardware. Prints frame summaries/hex; all logic still runs. |
| `sim` | Appends JSONL `{"t_ms": …, "frame_hex": …}` to `sim_out` for `:sim`. |
| `ble` | Connects with bleak and writes frames to `rx_char_uuid`; requires `--i-own-this-device`. |

`sim` contract: Agent G preserves order and injects each frame as if it arrived
from a fake peer. No BLE retransmits/fragments are implied.

## Safety

- Only run against devices you own. `--sink ble` refuses to transmit without
  `--i-own-this-device`.
- Flood/fuzz are hard-capped by the config. Start at `--rate 10`, never run a
  flood in public or against someone else's phone.
- Capture files can contain sealed voice clips and metadata. They are
  gitignored under `captures/`; delete them when done.
- Never commit `config.json`, seeds or channel keys. `.gitignore` already covers
  them.

## Tests

All commands assume `config.json` and a test capture. Dry-run first, then
repeat with `--sink ble`.

### Spoofing (SEC-001/002)

```bash
python test_spoofing.py --sink dry
python test_spoofing.py --sink ble --i-own-this-device
```

Sends a valid baseline from the harness identity, a frame with the victim's
sender ID signed by the harness key, a header-rewritten frame, and a poison pair
(forged first, then the valid baseline with the **same** `msg_id`).

Expected: baseline plays; forged and modified frames are silently dropped; the
poison case delivers exactly one valid clip. Any duplicate/loss is a finding.

### Capture + replay (SEC-008)

```bash
python capture.py --config config.json --duration 120 --i-own-this-device
python test_replay.py --sink ble --i-own-this-device \
  --mode replay --capture-file captures/capture-<ts>.jsonl
python test_replay.py --sink ble --i-own-this-device \
  --mode rewrite-ts --capture-file captures/capture-<ts>.jsonl
python test_replay.py --sink ble --i-own-this-device \
  --mode swap-chunks --capture-file captures/capture-<ts>.jsonl
```

Capture assumes one complete mesh frame per GATT notification on
`tx_char_uuid` (revisit when Agent C publishes the notify contract). Prepare the
capture while a peer sends a clip that the target actually receives.

Expected: the replayed clip does not play twice; rewritten timestamps and
swapped chunk indexes are dropped; no corrupted playback.

### Malicious relay / tampering (SEC-002/009)

```bash
python test_malicious_relay.py --sink dry
python test_malicious_relay.py --sink ble --i-own-this-device
python test_malicious_relay.py --sink ble --i-own-this-device --include-ttl
```

Sends a valid baseline, then fresh messages with one mutated frame (25 non-TTL
mutations: header fields, signature, nonce/tag, truncation, oversize, etc.).
The baseline proves the identity is accepted; every mutation must disappear.

`--include-ttl` adds TTL-only mutations. TTL is intentionally unsigned (relays
decrement it), so `bump_ttl`/`ttl_16` may be delivered; the check is that
`ttl=0`, `ttl>16` are dropped and a raised TTL does not loop or amplify.

A true on-path drop/modify relay needs an ESP32 or a second adapter; injection
tests cover detection, not in-path suppression (see threat-model §10).

### Flood / DoS (SEC-003/004)

```bash
python test_flood.py --sink dry --mode mixed --duration 5
python test_flood.py --sink ble --i-own-this-device \
  --mode mixed --duration 20 --rate 50 --probe-uuid <readable-char>
```

Modes: `random` (garbage with plausible headers), `reassembly` (65,535-chunk
claims across 8 fake messages), `header` (ttl/version/index boundaries),
`mixed`.

Expected: link stays up, probe remains readable, valid clips still pass during
and after the flood, app counters show drops rather than growth. A disconnect
is a finding; attach the JSON report (`--json-out`).

### Metadata survey (SEC-005/011)

```bash
python test_metadata.py --duration 900 --uuid <app-service-uuid> \
  --json-out captures/metadata.json
```

Passive scan. Reports names, service/manufacturer/service data, address
lifetimes, approximate advert intervals, random-address class, and identical
payloads across addresses.

Expected: no stable device name/channel name; advertisement rotates; the app
service UUID is the only constant. Note that `channel_id` is public by design,
so channel-level traffic grouping is accepted and documented.

### Fuzzing (SEC-003/012)

```bash
python fuzz_packets.py --sink dry --iterations 2000
python fuzz_packets.py --sink sim --sim-out captures/fuzz.jsonl --duration 60
python fuzz_packets.py --sink ble --i-own-this-device --duration 3600 --rate 20
```

Four strategies: targeted `mutate`, `random`, field `boundary`, `crypto`
corruption. `--seed` reproduces a run. On a disconnect/`SinkError` the current
case and the last 20 frames are saved under `captures/fuzz/` and the script
exits 3; attach that file to the finding (it contains frame bytes, not keys).

A 1-hour run without crash/disconnect is the Phase 5 acceptance bar. Keep a
valid clip exchange going during/after to check the app is still usable.

### Nearby channel (pre-implementation)

The open **Nearby** channel is not implemented on `main`; `MEMBER_ANNOUNCE`
(type `0x03`) is still reserved. Its four threat cases are executable design
tests in the JVM harness, using the real `:crypto` and `FakeNetwork`:

```bash
# Same job as the mesh attacks; the init script adds the harness module.
./gradlew -I security/ci/harness.init.gradle \
  :security-harness:testDebugUnitTest \
  --tests "com.solar23040.bitaudio.security.MeshAttackTest"
```

`NearbyChannelAttackTest` (inherited by `MeshAttackTest` so the existing CI
filter runs it) covers sybil announce/clip flooding, nickname spoofing,
identity/timing tracking and peer-count inflation/eclipse. It attacks the
reference policy in `NearbyChannelModel.kt`, not production code. When Nearby
lands, retarget the tests and keep the assertions; see
[`../nearby-threat-model.md`](../nearby-threat-model.md) and SEC-018..SEC-021.

## What is not automated

- **Delivery observation** is manual (UI/sim logs). The harness proves it sent
  the right bytes; a human records what the target displayed. Automated
  assertions need an app debug log/export from Agent F.
- **True in-path relay** needs ESP32/dual-adapter firmware; only frame-level
  tampering/replay is injected here.
- **Valid Opus payloads.** Generated test messages contain random bytes, which
  is enough to observe delivery state but may not decode audibly. Use
  `--payload-file` once Agent B publishes a fixture/container.
- **Rosters.** Spoofing needs a real victim pubkey and the harness identity in
  the channel; both come from the app's debug/join flow.

## Files

| File | Purpose |
|---|---|
| `wire.py` | Packet layout, signing/AAD, seal/open, reassembly, v1 limits |
| `config.py` | Config/CLI/safety, rate limiter |
| `sinks.py` | dry / sim / bleak sinks |
| `mutations.py` | 30 frame mutations and expected outcomes |
| `captured.py` | Capture loading/grouping |
| `capture.py` | BLE notify capture |
| `test_spoofing.py` | Forged sender/header + cache poisoning |
| `test_replay.py` | Exact replay, timestamp rewrite, chunk swap |
| `test_malicious_relay.py` | Targeted tampering |
| `test_flood.py` | Rate/reassembly/header floods |
| `test_metadata.py` | Passive BLE metadata survey |
| `fuzz_packets.py` | Structure-aware fuzzer + self-check |
| `make_config.py` | Generate a local config |
| `selfcheck.py` | Wire/crypto/mutation self-test (no hardware) |
