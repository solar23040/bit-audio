# Nearby Channel Threat Model

Status: v0.1 (pre-implementation design review)
Owner: Agent H (Security)
Last updated: 2026-10-27
Related: [`threat-model.md`](threat-model.md), [`findings.md`](findings.md), [`../docs/packet-format.md`](../docs/packet-format.md), [`../pllan.md`](../pllan.md)

> **Scope warning:** the Nearby channel is **not implemented on `main`**.
> `MEMBER_ANNOUNCE` (`0x03`) is still reserved in the packet format, the app
> transports no nickname, and the UI's peer view is only the BLE link count.
> This document covers the feature as proposed for Phase 6 and pins the
> admission rules that must land with it. The attack cases in
> `security/harness/.../NearbyChannelAttackTest.kt` are executable acceptance
> criteria for that implementation, not evidence about shipped code.

---

## 1. What "Nearby" adds

The working assumption is an **open local channel**: a user taps "Nearby", sees
other people in radio range, can set a nickname, and can send public voice
clips. No QR, no invite secret, no server. Anyone running the app can join.

Data flow:

```
open Nearby → announce(self: epoch key, nickname, signed)
  → flood ANNOUNCE (type 0x03) like any control packet
  → peers verify, admit/bound, show nickname + fingerprint + peer count
record → Opus → sign (epoch key) → flood VOICE_DATA (type 0x01)
  → peers verify, decode, play
```

Openness is the security change. A normal channel is protected by a 32-byte
channel key from a QR invite; Nearby must assume the attacker can mint unlimited
valid identities and send valid frames at line rate.

### Assumptions and non-goals

- Voice clips in Nearby are *public to participants*. Encryption may still hide
  them from passive non-app sniffers, but not from anyone who joined.
- Nicknames are user-chosen labels, not unique account names.
- No moderation, reputation, block list, or central directory is in the MVP.
- An attacker with a radio can always jam, drop or forge its own frames. Nearby
  can bound the damage and make impersonation visible; it cannot make a shared
  radio lossless.

---

## 2. Assets and adversaries

| Asset | Impact if lost |
|---|---|
| Nearby membership list | Sybil inflation, battery/CPU burn, misleading crowd size |
| Nickname ↔ key binding | Impersonation and social engineering |
| Epoch identity key | Historical linkability; long-term tracking if it is the install key |
| Announce timing | Presence, arrival/departure and conversation-rhythm tracking |
| Peer count | False sense of crowd/trust; eclipse is hidden |
| Public clip plaintext | Nearby content is intentionally public, but not to non-participants |

Existing adversaries from [`threat-model.md`](threat-model.md) apply. Nearby
adds an important capability to ADV4 (flooder): **valid signatures are free**.
An outsider can generate a fresh Ed25519 key for every frame, so any rule that
depends on "not in the roster" does not apply.

| ID | Adversary | Capability | Goal |
|---|---|---|---|
| NAV1 | Sybil flooder | Unlimited fresh keys, signed announces and clips at line rate | Fill the member list, burn radio/CPU, crowd out real clips |
| NAV2 | Nickname spoofer | Fresh key announcing an existing nickname | Be mistaken for a known person |
| NAV3 | Tracker | Passive sniffer plus repeated observations | Link a device across epochs or infer presence/timing |
| NAV4 | Malicious relay | Forward/drop/reorder announces and clips, add claimed counts | Inflate the crowd, hide peers, split the local mesh |

---

## 3. Threats and required controls

### NT-1 — ANNOUNCE and public-clip sybil flood

**Attack:** one radio sends thousands of self-signed announces and public clips
from distinct keys. Signature verification is the expensive step; the registry,
reassembly table and UI list all grow.

**Required controls (must exist before merge):**

1. Per-neighbour ingress token bucket before parsing or signature work. Target
   ≤ 20 frames/s per neighbour and ≤ 100 frames/s globally, matching the mesh
   relay budget.
2. Per-identity announce bucket (target 1/s, burst 2) after signature
   verification, so one key cannot beacon-spam.
3. A hard registry cap (target 256 nearby identities) with an explicit drop
   policy. Do not grow an unbounded `Map` from network input.
4. Bound nickname (≤ 32 UTF-8 bytes), body size, `total_chunks` and reassembly
   exactly as `docs/packet-format.md` requires for voice.
5. Verify signature before dedup/registry/storage updates; never let an
   unauthenticated frame evict a verified entry.
6. Per-sender voice budget so 64 admitted sybils cannot each send at line rate.
7. Keep the valid-clip path working during a flood: a rate-limited attacker must
   not starve an already-admitted peer for more than the bucket window.

**Severity:** High — trivial DoS and resource exhaustion on a channel that is
on by default; no key or user interaction needed.

### NT-2 — Nickname impersonation

**Attack:** attacker announces nickname "Alice" with a different key. If the UI
maps nickname → person, stores the last announcement by name, or updates an
existing alias from network input, the attacker replaces or merges with Alice.

**Required controls:**

1. The registry key is the authenticated epoch identity, never the nickname.
2. A new key claiming an existing nickname adds a **second** entry; it never
   overwrites the first.
3. Show a short key fingerprint next to duplicate nicknames and on tap. A
   nickname alone is never a trust signal.
4. A key owner may change their own nickname; another key cannot change it.
5. Mark entries as "unverified" until the user confirms the fingerprint
   out-of-band, if reputation is added later.

**Severity:** High if the UI shows only a nickname; Medium with a visible,
stable fingerprint and duplicate disambiguation. Social engineering inside a
local crowd is the impact, not content decryption.

### NT-3 — Tracking via stable identity or announce timing

**Attack:** every announce carries the install's Ed25519 public key, or repeats
at a fixed cadence, letting any nearby sniffer follow a device across epochs,
channels or days. A silent or fixed 30 s beacon is an identifier even when the
nickname changes.

**Required controls:**

1. Do **not** put the long-term install key on the wire. Use a per-channel,
   per-epoch Ed25519 key derived with a secret (e.g. HMAC of the install seed,
   `channel_id` and epoch). Rotate every 15 minutes with the existing
   `RotatingSenderId` epoch.
2. Derive `sender_id` from that epoch key with the v1 derivation; a copied key
   must not authenticate in another channel or epoch.
3. Jitter announces (target 30 s base + 0–5 s) and coalesce multiple announces
   before relaying; never emit a fixed-period beacon.
4. Keep clip timing/size padding as a documented residual (see SEC-011); a
   member can still correlate one epoch's traffic.
5. Do not log epoch keys, nicknames or announce schedules to system logs.

**Severity:** Medium — metadata/privacy impact without a key; rises to High if
the stable install key or a fixed beacon is used.

### NT-4 — Fake peer count and eclipse

**Attack:** a relay sends `peer_count = 65535`, or relays forged peer-list
entries, so the UI claims a crowd that is not there. Conversely a malicious
relay drops announces and clips from one segment, making honest peers disappear
(eclipse).

**Required controls:**

1. Peer count is **local authenticated state**: distinct admitted identities
   recently heard (plus optionally direct BLE links), never a number taken from
   an announce or relay.
2. Deduplicate by identity, not by nickname or claimed count; repeating an
   announce with fresh `msg_id`s must not increase the count.
3. Expire silent peers (target 15 min) and label the number "nearby / recently
   heard", not "network size". A stale entry is not proof of presence.
4. Do not accept relay-supplied peer lists in the MVP. If a gossip list is added
   later, it must be signed by each listed identity and still not be authoritative.
5. Prefer direct links for liveness; keep multiple paths where possible. No
   flooding protocol can prevent a relay from dropping what it carries — show
   last-seen/uncertainty instead of claiming completeness.

**Severity:** Medium for fake count (misleading UI); High for a successful
eclipse (silent suppression of a segment), with the residual that suppression by
an in-path relay is inherent and must be documented.

---

## 4. Resource limits to review with Agent A

These are recommendations, not yet in `docs/packet-format.md`:

| Limit | Value | Why |
|---|---|---|
| Nearby registry | 256 identities | Bound memory/UI; drop new announces when full |
| Announcements | 1/s per identity, burst 2 | Stop beacon spam without losing re-announces |
| Ingress | 20 frames/s per neighbour, 100/s global | Match relay budget; protect signature verification |
| Public clips | Existing 64 KiB/message and voice rate limit | No new wire exception for Nearby |
| Nickname | 32 UTF-8 bytes, no control characters | Stable rendering and bounded payload |
| Peer expiry | 15 min without an authenticated announce | Count reflects recent presence |
| Announce cadence | 30 s + 0–5 s jitter, coalesced by relays | Resist timing fingerprints |

---

## 5. Attack-test mapping

Run by the `security-harness` job (the class is inherited by `MeshAttackTest`
so the existing CI filter executes it):

| Threat | Test | Assertion |
|---|---|---|
| NT-1 flood/sybil | `NearbyChannelAttackTest.sybil announce and public clip flood stays bounded` | 4,000 signed announces + 500 clips at 200/s leave `members <= cap`, produce rate/capacity drops, and still deliver the honest peer's clip |
| NT-2 nickname | `...nickname spoof with a different key cannot overwrite an identity` | Two keys with "Alice" stay two entries with distinct labels; a rename by one key does not touch the other; a bad signature never enters the registry |
| NT-3 tracking | `...stable install key and fixed announce cadence are not exposed` | Install public key bytes absent from announce frames; sender ID and epoch key change across epochs; jittered delays are not constant and differ per device |
| NT-4 count/eclipse | `...relay cannot inflate peer count or eclipse a direct peer` | Claimed 65,535 is ignored; duplicate claims do not add peers; a relay cannot invent Bob; the direct path still delivers Alice; silent peers expire to 0 |

Findings: SEC-018..SEC-021 in [`findings.md`](findings.md). The reference model
lives in `security/harness/src/test/kotlin/.../NearbyChannelModel.kt` and is
explicitly test-only. When production `MEMBER_ANNOUNCE`/Nearby code lands, point
the tests at it and keep the assertions; do not keep two implementations.

---

## 6. Residual risks (accept or fix before shipping)

1. **Sybil identities are free.** Rate/cap bounds protect availability, not
   trust. Do not build reputation, voting or "people nearby trust this" on an
   unauthenticated key. A proof-of-work/QR admission gate is future work.
2. **Eclipse is not detectable from inside one path.** A relay can drop frames.
   Show last-seen and allow direct paths; document that absence is not proof of
   absence.
3. **Nicknames are not unique.** Fingerprint display is the only defense against
   a deliberate duplicate. If users expect names to mean people, the feature is
   unsafe.
4. **Timing correlation remains.** Jitter and epoch rotation reduce, not remove,
   presence tracking. A well-placed observer still sees that Nearby traffic
   exists and when a clip is sent.
5. **Per-epoch identity means no cross-epoch reputation.** If the product later
   needs stable identities, the tracking trade-off must be re-reviewed rather
   than silently adding the install key to announces.
6. **Public means public.** Anyone admitted can replay a clip locally, record
   it, or send abusive content. This is the same accepted limitation as SEC-015.
