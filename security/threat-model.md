# Threat Model — Mesh Voice Notes

Status: v0.1 (design review, pre-implementation)
Owner: Agent H (Security)
Last updated: 2026-10-25
Related: [`findings.md`](findings.md), [`attack-tests/README.md`](attack-tests/README.md), [`../pllan.md`](../pllan.md)

---

## 1. Scope

In scope:

- Android app and its six modules (`app`, `audio`, `transport`, `mesh`, `crypto`, `sim`)
- BLE advertising, scanning, GATT client/server, fragmentation and reassembly
- TTL flooding, deduplication, jittered rebroadcast, store-and-forward relays
- Opus encoding/decoding at the edges
- Channel creation/joining via QR or passphrase
- Local persistence of identity keys, channel keys, relay queues and message history
- The trust the UI places in displayed sender aliases and delivery state

Out of scope for the MVP:

- Servers and accounts (the design has none)
- iOS, WiFi-Direct, live streaming
- Compromised/rooted OS, physical chip-off attacks, supply-chain implants
- Global traffic analysis with direction finding or many colluding receivers
- Legal coercion and rubber-hose attacks

Anything out of scope is listed again in §7 as an accepted residual risk so it
is not silently assumed to be protected.

---

## 2. System summary and data flow

```
record (16 kHz PCM16) → Opus (12 kbps, 20 ms frames) → per-chunk/channel seal
   → sign → fragment (~240 B) → BLE GATT write → TTL flood → relay(s)
   → dedup → verify → unseal → reassemble → play
```

Relevant properties:

- No central service. Every device is a potential relay, including devices
  that are not members of the channel.
- Relays store sealed clips while a destination is out of range and hand them
  over on peer discovery.
- Sender IDs are rotating ephemeral identifiers; the long-term Ed25519 identity
  key is per install. The channel key is shared out of band (QR/passphrase).
- The mesh admits any BLE frame it can parse; membership is proven only by the
  channel key and sender signature.

### 2.1 Trust boundaries

| ID | Boundary | What crosses it |
|---|---|---|
| TB1 | App sandbox ↔ Android OS/Keystore | identity private key operations, channel key, plaintext audio, files |
| TB2 | App ↔ BLE controller / radio | advertisements, GATT frames, connection metadata |
| TB3 | Local device ↔ mesh peers | signed + sealed frames, routing metadata, acks |
| TB4 | QR/passphrase channel invite | 32-byte channel key, channel identifier, (optional) member aliases |
| TB5 | App ↔ user/UI | sender alias, hop count, delivery state, playback |
| TB6 | Relay queue ↔ storage | sealed frames, sender ID, timestamps, sizes |

TB2 and TB3 are the hostile boundaries: anyone in radio range can read, inject,
replay, delay, drop, reorder or flood frames. The app cannot rely on BLE link
security (pairing/bonding) because the mesh has to talk to unpaired strangers.

---

## 3. Assets

| ID | Asset | Impact if lost |
|---|---|---|
| A1 | Voice clip plaintext | Private conversations exposed |
| A2 | Channel key | All current and stored channel traffic readable/forgeable by the holder; membership graph exposed |
| A3 | Identity private key | Sender impersonation, loss of non-repudiation |
| A4 | Channel roster, aliases, safety numbers | Social graph, impersonation of contacts |
| A5 | Metadata (who talks, when, clip size, proximity, relay graph) | Traffic analysis, presence/location tracking, relationship inference |
| A6 | Battery, radio airtime, storage | Denial of service, unusable app, device hot/battery drain |
| A7 | Routing/delivery state (msg IDs, chunk indexes, acks, dedup cache) | Suppression of legitimate clips, loops, duplicate playback |
| A8 | Relay queue contents | Offline message disclosure if channel key compromised later |

---

## 4. Adversaries

| ID | Adversary | Capabilities | Goals |
|---|---|---|---|
| ADV1 | Passive sniffer | BLE sniffer or second adapter; observes advertisements and GATT traffic; no channel key | Read content if key leaks, map devices, track presence, infer conversation timing |
| ADV2 | Active spoofer | Injects GATT writes / advertisements; can replay captured frames; may or may not hold the channel key | Impersonate a member, inject clips, poison caches, confuse UI |
| ADV3 | Malicious relay | Runs modified client/mesh logic, is on-path for some links; may hold channel key (rogue member) | Drop, delay, reorder, modify, duplicate, suppress, amplify traffic |
| ADV4 | Flooder | High-rate writes/advertisements, possibly from outside the channel | Crash parsers, exhaust memory/battery, crowd out real traffic, force reassembly work |
| ADV5 | Rogue member | Valid channel key and own identity; can create well-formed messages | Forge another member (needs their key), harass, disclose history, poison state |
| ADV6 | Curious relay | Honest-but-curious, stores and forwards frames | Learn metadata; retain clips longer than intended |
| ADV7 | Device thief / forensic attacker | Has the physical device, may have it unlocked or have a copy of app storage | Extract keys/history, impersonate user |
| ADV8 | Malicious invite | Controls a QR code or passphrase channel invite | Lure user into attacker-known channel, leak user's key material or metadata |

Not modelled: an adversary who can execute code in the app process, read
Keystore-protected keys, or observe the radio from many locations at once.

---

## 5. STRIDE analysis

| STRIDE | Where | Threat | Mitigation (owner) |
|---|---|---|---|
| **S**poofing | Sender field, BLE address, UI | Attacker claims another member's sender ID or clones an advertisement | Signature must bind `sender_id` to the claimed identity key; reject unknown/rotated IDs without valid membership proof (E); UI shows key fingerprint/safety number (F); rotating BLE identifiers (C/F) |
| **S**poofing | QR invite | Attacker supplies their own channel key as a "join" QR | QR includes channel name + key fingerprint; UI shows fingerprint before joining; verify out of band (F/E) |
| **T**ampering | Frame header | Change `ttl`, `chunk_idx`, `total_chunks`, `ts`, `sender_id` | Sign canonical header and use it as AEAD AAD; validate ranges before use (E/D) — see SEC-002 |
| **T**ampering | Payload/chunks | Flip bits, swap chunks between messages, splice old chunk into new message | Per-frame AEAD + signature; header in AAD prevents chunk confusion; reject partial messages on timeout (E/C/D) |
| **T**ampering | Relay storage | Modify queued clips at rest | Store sealed frames only; verify signature/AEAD again on dequeue (D/E) |
| **R**epudiation | Sender | Member denies sending a clip | Signatures give channel-internal attribution, not legal non-repudiation; document this limitation (E, MVP) |
| **I**nformation disclosure | Content | Sniffer/relay reads audio | XChaCha20-Poly1305 channel encryption; keys never leave device (E) |
| **I**nformation disclosure | Metadata | Stable BLE MAC/name, advertisement payload, message timing/size, relay graph | Rotating ephemeral sender IDs (E), BLE address rotation and minimal adv payload (C), padding/size buckets (D/E, stretch), retention limits (D) |
| **I**nformation disclosure | Keys | Channel/identity key extracted from storage | Keystore-backed identity key where available; software fallback wrapped by Keystore; no keys in logs/backups (E/F) |
| **D**enial of service | Parsing | Huge `total_chunks`, out-of-range indexes, truncated headers, oversized frames | Strict validation, caps, timeouts, fuzz tests in CI (C/D/A) — see SEC-003 |
| **D**enial of service | Relaying | High-rate frames with high TTL get rebroadcast, amplifying attack | Ingress rate limits, per-neighbor token buckets, TTL clamp, drop-when-full policy (D) — see SEC-004 |
| **D**enial of service | Storage/UI | Fill relay queue/history, battery drain from scanning | Quotas, expiry, scan duty cycling, foreground service (D/F) |
| **E**levation of privilege | Parser/Keystore | Memory corruption or logic bug turns a frame into code execution or key access | Memory-safe Kotlin where possible, JNI only for Opus, bounds checks at the JNI boundary, fuzzing (B/C/G) |
| **E**levation of privilege | Relay | A non-member gets relay-only capabilities treated as membership | Never infer membership from relay participation; only channel key + signature (D/E) |

---

## 6. Security requirements

These are the testable requirements Agent H will verify. "Verify" points at the
attack harness in [`attack-tests/`](attack-tests/) or the module tests owned by
another agent.

| ID | Requirement | Owner | Verify |
|---|---|---|---|
| R1 | A frame is accepted only if its signature verifies under the identity key bound to `sender_id` | E | spoofing test, SEC-001/002 |
| R2 | Signature covers the full canonical header (all fields except `sig`) **and** the payload; header is also AEAD AAD | E/D | tamper tests, SEC-002 |
| R3 | AEAD failure or signature failure drops the frame silently; no oracle is returned to the sender | E/D | relay/tamper tests |
| R4 | Replay is rejected by per-sender monotonic message counter, not only by wall-clock timestamp; state survives restart | E | replay test, SEC-008 |
| R5 | Replay/dedup state is updated only after authentication succeeds | D/E | cache-poison test, SEC-001 |
| R6 | Frame limits are enforced before allocation: `total_chunks ≤ 256`, `chunk_idx < total_chunks`, payload ≤ 240 B, frame ≤ 300 B, reassembly ≤ 32 KB | C/D | fuzz + reassembly flood, SEC-003 |
| R7 | Partial messages expire (≤ 30 s) and per-sender/total partial buffers are bounded | C/D | reassembly flood |
| R8 | TTL is clamped to 1–5 on ingress; TTL 0 is delivered locally but never relayed | D | malformed-header tests |
| R9 | Relay work is rate-limited per neighbor and globally; queue overflow drops oldest/newest explicitly, never blocks the UI | D | flood test, SEC-004 |
| R10 | Identity private key is generated in hardware-backed Keystore where available; software fallback is Keystore-wrapped and excluded from backups | E/F | design review + device inspection, SEC-006 |
| R11 | Channel key is never logged, never sent on the wire, and QR export requires an explicit user action; screen capture protection where available | E/F | code review, SEC-010 |
| R12 | Relay queue is encrypted-at-rest by already-sealed payloads, expires after a configured retention (default 24 h), and is capped (50 MB) | D/F | design review + storage inspection, SEC-014 |
| R13 | Rotating sender IDs change on the documented schedule and cannot be linked across epochs without the channel key | E | metadata test, SEC-005 |
| R14 | Malformed input never crashes the app or the parser; a 1-hour fuzz run against a live build stays up | C/D/G | `fuzz_packets.py`, SEC-003/012 |
| R15 | UI binds alias to the cryptographic identity and shows a stable safety number/fingerprint; unknown senders are visibly marked | F | UI review, SEC-013 |
| R16 | Acks/retransmit requests are authenticated or rate-limited so they cannot be used for amplification | C | design review, SEC-009 |

---

## 7. Privacy analysis

The MVP protects **content** against outsiders, not **who is talking to whom**.
Document this in the README; do not market it as anonymous.

Leaks and current intent:

| Leak | Detail | Mitigation | Residual |
|---|---|---|---|
| BLE address | Public/static MAC or long-lived random static address lets a sniffer follow a device | Random resolvable/static rotation by the OS/controller, no bonding requirement (C) | OS-dependent; some vendors expose identity addresses; BLE chipsets may rotate slowly |
| Advertisement payload | Device name, service UUID, channel name, manufacturer data can fingerprint the app and channel | Advertise only the app service UUID; no channel name/alias; shorten adv rotation (C/F) | App presence itself is detectable |
| Sender ID | 8-byte rotating ID appears in every frame | Rotate per epoch; unlinkable without channel key if random (E) | Same epoch reveals one sender's traffic volume; rotation schedule can be correlated with timing |
| Clip timing/size | PTT timing reveals conversation rhythm; sizes reveal speech duration | Size bucketing/padding (stretch), batching (stretch) | Not solved in MVP |
| Relay graph | Relays see which frames pass through them and when; store-and-forward reveals store/handoff times | TTL flooding already hides the immediate source; jitter (D) | A relay can infer local topology |
| Retention | Queued clips can outlive the conversation | 24 h default expiry, 50 MB cap, UI control (D/F) | Receiver history is kept until deleted |
| QR invite | Bearer secret in a screenshot/photo | Fingerprint confirmation, explicit share sheet, no auto-join (F/E) | Anyone who sees the QR can join |

---

## 8. Resource limits (v1 targets)

Concrete values for C/D to enforce and for Agent H to test. They are
deliberately generous versus the 15 s / ~20 KB clip target.

| Limit | Value | Rationale |
|---|---|---|
| Max frame | 300 B | Fits MTU 247 minus GATT overhead after fragmentation |
| Max chunk payload (sealed) | 240 B | ~100 frames for a 15 s listenable clip |
| Max `total_chunks` | 256 | 256 × 240 B ≈ 61 KB, 2× slack over target |
| Max reassembled clip | 32 KB | Bound memory and storage per message |
| Max concurrent partial messages | 4 per sender, 32 global | Stop reassembly-table exhaustion |
| Reassembly timeout | 30 s | BLE transfers are seconds; late chunks are not useful |
| TTL | 1–5, default 5; 0 = local only | Prevent unbounded floods |
| Dedup cache | 4096 IDs / 10 min sliding, bounded memory | Match realistic traffic, survive bursts |
| Relay rate | 20 frames/s per neighbor (burst 40), 100 frames/s global | Usable voice, bounded amplification |
| Verify rate | 20 signatures/s per claimed sender; cheapest checks first | Signature verification is CPU-expensive on low-end phones |
| Relay retention | 24 h default, user-configurable | Store-and-forward without indefinite retention |
| Relay storage | 50 MB global, 20 MB per channel; evict oldest | No disk exhaustion |
| History | User-deletable; no hidden copies | Privacy expectations |

The exact numbers can move, but the bounds must exist and be enforced **before**
allocation and before crypto.

---

## 9. Test mapping (Phase 5 checklist)

| Plan item | Harness | Finding |
|---|---|---|
| Spoofing: forged sender | `test_spoofing.py` | SEC-001, SEC-002 |
| Replay: capture and rebroadcast later | `test_replay.py`, `capture.py` | SEC-008 |
| Flood/DoS: high-rate packets, rate limiting | `test_flood.py`, `fuzz_packets.py` | SEC-003, SEC-004 |
| Metadata leaks: stable IDs, adv fingerprint, MAC rotation | `test_metadata.py` | SEC-005 |
| Fuzzing: chunk overflow, huge `total_chunks`, truncated headers | `fuzz_packets.py` | SEC-003, SEC-012 |
| Malicious relay: drop/modify, detection via signature | `test_malicious_relay.py` | SEC-002, SEC-009 |
| Threat model, STRIDE, findings | this document, `findings.md` | — |

Execution status is tracked at the top of [`findings.md`](findings.md). Live
runs are blocked until Phase 0 interfaces exist, Agent C's GATT service UUIDs
are known, and CI produces an APK to sideload.

---

## 10. Accepted risks and non-goals

1. **No anonymity.** A global or well-placed observer can tell that BLE mesh
   traffic is happening, and relays learn local topology and timing.
2. **No forward secrecy.** The channel key is static for the MVP. Compromise of
   the key exposes stored and future clips until members rotate it by creating
   a new channel. Documented, not fixed.
3. **Member trust is binary.** Any channel-key holder can send content and
   participate as a relay. Encryption does not make a malicious member honest.
   UI attribution and user judgment are the controls.
4. **Relay metadata is visible.** Sender ID, timestamps, sizes and message IDs
   are authenticated but not hidden from relays.
5. **Compromised endpoint.** Malware with app-process access, an unlocked stolen
   phone, or a rooted device defeats all of the above.
6. **No legal non-repudiation.** Ed25519 signatures prove channel membership at
   send time; they do not prove a human's intent.
7. **BLE stack flaws.** Android OEM BLE bugs can crash or hang the transport;
   the app must fail soft and reconnect, but cannot fix the stack.
8. **DoS cannot be fully prevented on a shared medium.** Rate limits reduce
   amplification and battery impact; a local jammer can always deny radio.
9. **In-path relay testing is deferred.** The Python harness injects frames
   through a GATT characteristic. A true on-path malicious relay (ESP32 or a
   second adapter) is planned after Agent C publishes the GATT layout; drop and
   corruption behaviour is still covered by injection tests.

---

## 11. Open design questions for Agent A

These affect the security claims and need an explicit answer in
`docs/interfaces.md` / `docs/packet-format.md`:

1. Is the signature per frame or per message? Per-frame is simpler to verify and
   drop; per-message is cheaper on airtime. The harness currently assumes
   per-frame and must be updated if this changes.
2. What exactly is signed — header + payload, or a canonical subset? It must
   include `ttl`, `chunk_idx`, `total_chunks`, `ts`, `sender_id`, `msg_id`
   (see SEC-002).
3. Is the AEAD nonce random per frame, or derived from `(msg_id, chunk_idx)`?
   Derived nonces avoid transmitting 24 B per frame but must never repeat under
   the same key; random 24 B XChaCha nonces are safe and simpler.
4. How is `sender_id` bound to the identity key, and where does a receiver get
   the roster (QR payload, first-seen trust, or trust-on-first-use)? "First
   seen" lets a spoofer win the race.
5. Does the anti-replay counter reset when the ephemeral sender ID rotates? If
   yes, an attacker can replay across epochs; if no, state must survive reboot
   and be keyed by the long-term identity, not the ephemeral ID.
6. Do relay acks get signed, or are they unauthenticated hints with rate limits?
   (SEC-009)
