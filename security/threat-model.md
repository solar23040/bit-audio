# Threat Model — Mesh Voice Notes

Status: v0.3 (mesh + crypto implemented; attack suite runs in CI on `FakeNetwork`)
Owner: Agent H (Security)
Last updated: 2026-10-26
Related: [`findings.md`](findings.md), [`attack-tests/README.md`](attack-tests/README.md), [`../pllan.md`](../pllan.md), [`../docs/packet-format.md`](../docs/packet-format.md), [`../docs/interfaces.md`](../docs/interfaces.md)

> **Contract status:** `docs/packet-format.md` v1, `:crypto` and the committed
> vector now agree; SEC-016 is fixed and verified in CI. The attack harness and
> tests build frames byte-for-byte from the docs.

---

## 1. Scope

In scope:

- Android app and its modules (`app`, `audio`, `transport`, `mesh`, `crypto`, `sim`)
- BLE advertising, scanning, GATT client/server, transport fragmentation
- Mesh packet format, TTL flooding, dedup, jitter, reassembly, store-and-forward
- Opus encoding/decoding at the edges
- Channel creation/joining via QR or passphrase
- Local persistence of identity keys, channel keys, relay queues and history
- The trust the UI places in displayed sender aliases and delivery state

Out of scope for the MVP:

- Servers and accounts (the design has none)
- iOS, WiFi-Direct, live streaming
- Compromised/rooted OS, physical chip-off attacks, supply-chain implants
- Global traffic analysis with direction finding or many colluding receivers
- Legal coercion and rubber-hose attacks

Anything out of scope is listed again in §10 as an accepted residual risk so it
is not silently assumed to be protected.

---

## 2. System summary and data flow

```
record 16 kHz PCM16 → Opus (12 kbps, 20 ms frames)
  → seal ONCE per message: nonce(24) || XChaCha20-Poly1305(ct||tag)
      AAD = channel_id(8) || msg_id(8) || timestamp_ms(8) || counter(4)
  → fragment sealed bytes into 405 B chunks
  → sign each packet: Ed25519(header[ttl=0, sig=0] || payload)
  → transport fragments for BLE (invisible to mesh)
  → TTL flood → relay verifies signature/roster, dedups, decrements ttl, rebroadcasts
  → receiver reassembles, opens AEAD once, emits plaintext to the app
```

Relevant properties:

- No central service. Every device is a potential relay, including devices that
  are not members of the channel. The docs require relays to be members and
  resolve the signer before forwarding, but the radio is open to anyone.
- Relays store sealed packets while a destination is out of range and hand them
  over on peer discovery. TTL is decremented on each hop; packets are not
  re-signed.
- Sender IDs rotate every 15 minutes and are derived with the channel key.
  `channel_id` is stable public metadata. The Ed25519 signing key is per install
  and stable.
- Membership is proven by the channel key (encryption) and the roster entry
  (signature resolution). A relay that only forwards does not become a member.
- The channel roster is established at join time; `MEMBER_ANNOUNCE` (roster
  sync) is reserved for Phase 2.

### 2.1 Trust boundaries

| ID | Boundary | What crosses it |
|---|---|---|
| TB1 | App sandbox ↔ Android OS/Keystore | identity private key operations, channel key, plaintext audio, files |
| TB2 | App ↔ BLE controller / radio | advertisements, GATT frames, connection metadata |
| TB3 | Local device ↔ mesh peers | signed+sealed packets, routing metadata, counters |
| TB4 | QR/passphrase channel invite | 32-byte channel key, channel identifier, member roster/aliases |
| TB5 | App ↔ user/UI | sender alias, hop count, delivery state, playback |
| TB6 | Relay queue ↔ storage | sealed packets, channel/sender IDs, timestamps, counters, sizes |

TB2 and TB3 are hostile: anyone in radio range can read, inject, replay, delay,
drop, reorder or flood frames. The app cannot rely on BLE link security for mesh
traffic because it must talk to unpaired strangers; transport-level link
encryption is optional hardening, not a trust boundary.

---

## 3. Assets

| ID | Asset | Impact if lost |
|---|---|---|
| A1 | Voice clip plaintext | Private conversations exposed |
| A2 | Channel key | All current/stored channel traffic readable and forgeable; channel ID linkability |
| A3 | Identity private key | Sender impersonation; roster poisoning |
| A4 | Channel roster, aliases, safety numbers | Social graph, impersonation of contacts |
| A5 | Metadata (channel ID, sender epoch ID, timing, size, counter, relay graph, proximity) | Traffic analysis, presence/location tracking, relationship inference |
| A6 | Battery, radio airtime, storage | Denial of service, unusable app, device hot/battery drain |
| A7 | Routing/delivery state (msg IDs, chunk indexes, counters, dedup/replay caches) | Suppression of legitimate clips, loops, duplicate playback |
| A8 | Relay queue contents | Offline message disclosure if channel key compromised later |

---

## 4. Adversaries

| ID | Adversary | Capabilities | Goals |
|---|---|---|---|
| ADV1 | Passive sniffer | BLE sniffer/second adapter; observes adverts and GATT traffic; no channel key | Track devices, group traffic by public `channel_id`, infer timing/volume; read content only if key leaks |
| ADV2 | Active spoofer | Injects GATT writes/adverts; replays captured packets; may hold the channel key | Impersonate a member, inject clips, poison caches, confuse UI |
| ADV3 | Malicious relay | Modified client/mesh logic, on-path for some links; may hold the channel key | Drop, delay, reorder, modify, duplicate, suppress, amplify |
| ADV4 | Flooder | High-rate writes/adverts, possibly from outside the channel | Crash parsers, exhaust memory/battery/airtime, crowd out real traffic |
| ADV5 | Rogue member | Valid channel key and own identity; produces well-formed packets | Forge another member (needs their key), harass, disclose history, poison state |
| ADV6 | Curious relay | Honest-but-curious; stores/forwards packets | Learn metadata; retain clips longer than intended |
| ADV7 | Device thief / forensic attacker | Physical device, unlocked or app-storage copy | Extract keys/history, impersonate user |
| ADV8 | Malicious invite | Controls a QR code or passphrase invite | Lure user into attacker-known channel, leak key material or metadata |

Not modelled: code execution in the app process, Keystore extraction, many
colluding receivers performing global traffic analysis, RF jamming.

---

## 5. STRIDE analysis

| STRIDE | Where | Threat | Mitigation (owner) |
|---|---|---|---|
| **S**poofing | `sender_id` | Attacker claims another member's rotating ID | Signature resolves `sender_id` to a roster key for the timestamp's epoch (±1); unknown IDs dropped (E); rotating IDs are channel-scoped (E) |
| **S**poofing | BLE address/advert | Clone or track a device | MAC rotation/minimal adv payload (C/F); do not treat BLE identity as a member identity |
| **S**poofing | QR invite | Attacker supplies their own channel QR | QR name + key fingerprint + confirmation; out-of-band verification (F/E) — SEC-010 |
| **T**ampering | Header | Change `channel_id`, `msg_id`, `sender_id`, indexes, timestamp, counter | All are in the signed transcript; AAD binds channel/msg/time/counter (E) — SEC-002 |
| **T**ampering | `ttl` | Raise TTL to extend flood | TTL is unsigned by design; accept 1..16, decrement once, dedup + rate limits contain inflation (D/E) — SEC-004 |
| **T**ampering | Payload/chunks | Flip bits, splice chunks, swap messages | Per-packet signature; single AEAD over the reassembled message; shared-header consistency; reject partials (E/C/D) |
| **T**ampering | Relay storage | Modify queued packets at rest | Store sealed packets only; verify signature and AEAD again on dequeue (D/E) |
| **R**epudiation | Sender | Member denies sending | Signatures give channel-internal attribution, not legal non-repudiation; document (E) |
| **I**nformation disclosure | Content | Sniffer/relay reads audio | XChaCha20-Poly1305 with a channel key that never leaves the device (E) |
| **I**nformation disclosure | Metadata | BLE MAC, adv name, public `channel_id`, per-epoch sender ID, timing/size, relay graph | MAC rotation + minimal adverts (C), 15-min sender epochs (E), retention limits (D); document residual channel/timing leaks (F) — SEC-005/011 |
| **I**nformation disclosure | Keys | Channel/identity key extracted | Keystore-backed identity where available; software fallback wrapped by Keystore; no keys in logs/backups (E/F) — SEC-006 |
| **D**enial of service | Parsing/reassembly | Huge `total_chunks`, out-of-range indexes, truncated/oversized frames, many partials | Strict pre-allocation caps: 512 B frame, 405 B payload, 162 chunks, 64 KiB reassembled, 120 s timeout (C/D) — SEC-003 |
| **D**enial of service | Relaying | High-rate high-TTL packets get rebroadcast | Ingress clamp, dedup, per-neighbour/global token buckets, bounded queue (D) — SEC-004 |
| **D**enial of service | Storage/UI | Fill queue/history; battery drain from scanning | Quotas, 24 h expiry, scan duty cycling, foreground service (D/F) — SEC-014 |
| **E**levation of privilege | Parser/JNI | Memory corruption from attacker bytes | Kotlin parsers, bounds checks at the Opus JNI boundary, fuzzing (B/C/G) |
| **E**levation of privilege | Relay | Non-member treated as member because it forwards | Membership is only channel key + roster signature; forwarding grants no trust (D/E) |

---

## 6. Security requirements

| ID | Requirement | Owner | Verify |
|---|---|---|---|
| R1 | A packet is accepted only if `sender_id` resolves to a roster key for the timestamp's epoch (current or ±1) and the Ed25519 signature verifies over the documented transcript | E | spoofing test, SEC-001/002 |
| R2 | Transcript = `header[ttl=0, sig=0] || payload`; all non-TTL header fields are included; AEAD AAD = `channel_id || msg_id || timestamp_ms || counter` | E/D | SEC-002/016, docs vectors |
| R3 | Signature, roster, freshness, or AEAD failure drops the packet silently; no error oracle | E/D | relay/tamper tests |
| R4 | Replay is rejected by `msg_id` cache + `(channel_id, identity, counter) -> msg_id` cache, persisted across restart; late store-and-forward messages remain acceptable | E/D | replay test, SEC-008 |
| R5 | Dedup/counter/replay state is updated only after authentication succeeds | D/E | poison test, SEC-001 |
| R6 | Pre-allocation limits: frame 107..512 B, payload 0..405 B, `total_chunks` 1..162, `chunk_idx < total_chunks`, reassembled ≤64 KiB | C/D | fuzz + reassembly flood, SEC-003 |
| R7 | Partial messages expire after 120 s; bounded per sender (target 4) and globally (target 32) | C/D | reassembly flood |
| R8 | TTL accepted only in 1..16; deliver locally, rebroadcast once with `ttl-1`; TTL 0 never delivered/relayed | D | TTL mutation tests |
| R9 | Relay work is rate-limited per neighbour and globally; queue overflow drops explicitly, never blocks the UI | D | flood test, SEC-004 |
| R10 | Identity private key is generated in hardware-backed Keystore where available; software fallback is Keystore-wrapped and excluded from backups | E/F | device inspection, SEC-006 |
| R11 | Channel key is never logged, never sent on the wire, and QR export requires explicit user action; screen-capture protection where available | E/F | code review, SEC-010 |
| R12 | Relay queue stores sealed packets only, expires after 24 h default, and is capped (target 50 MB) | D/F | storage inspection, SEC-014 |
| R13 | Sender IDs rotate every 15 min via the documented HMAC and cannot be linked across epochs without the channel key | E | metadata test, SEC-005 |
| R14 | Malformed input never crashes the app; a 1-hour fuzz run against a live build stays up | C/D/G | `fuzz_packets.py`, SEC-003/012 |
| R15 | UI binds an alias to the roster identity and shows a stable fingerprint/safety number; unknown senders are marked | F | UI review, SEC-013 |
| R16 | Receipts/retransmit requests are authenticated or rate-limited so they cannot amplify traffic | C | design review, SEC-009 |

---

## 7. Privacy analysis

The MVP protects **content** against outsiders, not **who is talking to whom**.
Document this in the README; do not market it as anonymous.

| Leak | Detail | Mitigation | Residual |
|---|---|---|---|
| BLE address | Public/static MAC or long-lived random static address lets a sniffer follow a device | OS/controller address rotation, no bonding for mesh (C) | OS-dependent; some vendors expose identity addresses |
| Advertisement payload | Device name, service UUID, channel name, manufacturer data can fingerprint the app/channel | Advertise only the app service UUID; no name/channel/alias; rotate payload (C/F) | App presence itself is detectable |
| Public `channel_id` | Stable 8-byte HMAC appears in every header; lets any sniffer group packets by channel | Accept (needed for relay filtering); document | Channel-level traffic volume/timing visible without the key |
| Sender ID | 8-byte ID rotates per 15-min epoch and is derived with the channel key | Random-looking 8 bytes; roster resolution only for members | Packets from one sender in the same epoch are linkable; epoch boundaries correlate with timing |
| Clip timing/size | PTT timing reveals conversation rhythm; sizes reveal duration | Size bucketing/padding (stretch), batching (stretch) | Not solved in MVP |
| Counter | Monotonic per identity; linkable across epochs if an observer knows the identity | Counter is inside the signed header, not displayed | A member/relay can correlate with roster knowledge |
| Relay graph | Relays see which packets pass through them and when; store-and-forward reveals store/handoff times | TTL flooding hides the immediate source; jitter (D) | A relay can infer local topology |
| Retention | Queued clips can outlive the conversation | 24 h default expiry, storage cap, UI control (D/F) | Receiver history kept until deleted |
| QR invite | Bearer secret in a screenshot/photo | Fingerprint confirmation, explicit share, no auto-join (F/E) | Anyone who sees the QR can join |

---

## 8. Resource limits (v1 targets)

Values from `docs/packet-format.md` plus Agent H's recommendations for the
parts the docs leave to Phase 5. They are deliberately generous versus a 15 s /
~22 KB clip.

| Limit | Value | Rationale |
|---|---|---|
| Frame size | 107..512 B | Wire format: 107 B header + ≤405 B payload |
| Chunk payload | 0..405 B | `sealed[405*i ..]` |
| `total_chunks` | 1..162 | 162 × 405 B ≈ 64 KiB |
| Reassembled message | ≤64 KiB | Bound memory/storage per message |
| Partial messages | 4 per sender, 32 global (target) | Stop reassembly-table exhaustion |
| Reassembly timeout | 120 s | BLE transfers are seconds; late chunks are not useful |
| TTL | 1..16; default 5; 0 rejected | Bound flooding; relays decrement once |
| Dedup cache | `(channel_id, msg_id, chunk_idx)` for ≥120 s; `msg_id` for retention | Match protocol; bound memory |
| Replay/counter cache | retention window (24 h), bounded LRU | Counter reuse detection without unbounded growth |
| Relay rate | 20 frames/s per neighbour (burst 40), 100 frames/s global (target) | Usable voice, bounded amplification |
| Verify rate | 20 signatures/s per claimed sender; cheapest checks first | Ed25519 is CPU-expensive on low-end phones |
| Relay retention | 24 h default, configurable | Store-and-forward without indefinite retention |
| Relay storage | 50 MB global, 20 MB per channel; evict oldest (target) | No disk exhaustion |
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
| Metadata leaks: stable IDs, adv fingerprint, MAC rotation | `test_metadata.py` | SEC-005, SEC-011 |
| Fuzzing: chunk overflow, huge `total_chunks`, truncated headers | `fuzz_packets.py` | SEC-003, SEC-012 |
| Malicious relay: drop/modify, detection via signature | `test_malicious_relay.py` | SEC-002, SEC-009 |
| Threat model, STRIDE, findings | this document, `findings.md` | — |

Execution status is tracked at the top of [`findings.md`](findings.md). Live
runs are blocked until the contract is reconciled (SEC-016), a CI APK exists,
and Agent C's GATT characteristic/notify contract is known.

---

## 10. Accepted risks and non-goals

1. **No anonymity.** A global or well-placed observer can tell that BLE mesh
   traffic is happening, can group it by public `channel_id`, and relays learn
   local topology and timing.
2. **No forward secrecy.** The channel key is static for the MVP. Compromise
   exposes stored and future clips until members rotate by creating a new
   channel. Documented, not fixed (SEC-007).
3. **Member trust is binary.** Any channel-key holder can send content and
   participate as a relay. Encryption does not make a malicious member honest
   (SEC-015).
4. **Metadata is visible.** `channel_id`, epoch sender ID, timestamps, counters,
   sizes and message IDs are authenticated but not hidden from relays (SEC-011).
5. **Compromised endpoint.** Malware with app-process access, an unlocked stolen
   phone, or a rooted device defeats all of the above.
6. **No legal non-repudiation.** Ed25519 proves channel membership at send time,
   not human intent.
7. **BLE stack flaws.** OEM BLE bugs can crash/hang the transport; the app must
   fail soft and reconnect, but cannot fix the stack.
8. **DoS cannot be fully prevented on a shared medium.** Rate limits reduce
   amplification and battery impact; a local jammer can always deny radio.
9. **In-path relay testing is deferred.** The Python harness injects frames via
   a GATT characteristic. A true on-path malicious relay (ESP32 or second
   adapter) is planned after Agent C publishes the GATT layout; corruption and
   drop behaviour is still covered by injection tests.
10. **8-byte IDs.** `channel_id`/`sender_id` truncation gives 64-bit identifiers;
    collisions are possible but not attacker-controllable at practical cost.
    Monitor roster collisions.

---

## 11. Open questions for Agent A

1. **Contract reconciliation (SEC-016, blocking).** Which is canonical: the
   `docs/packet-format.md` derivations/transcript, or the current
   `:crypto` implementation? Fix before Phase 2; publish byte-exact vectors.
2. **Roster acquisition.** How does the first roster arrive (QR payload, manual
   add, TOFU)? "Established at join" is not enough to stop a race where a
   spoofer is added first. `MEMBER_ANNOUNCE` needs authentication and replay
   protection when it lands in Phase 2.
3. **Counter/replay trade-off.** The docs accept late messages with a new
   `msg_id` and cache `(channel, identity, counter) -> msg_id` for 24 h. Confirm
   the cache bound, restart persistence and behavior across reinstall (counter
   starts at 1 again with the same identity key?).
4. **Receipts/retransmit (Phase 2).** Will `DELIVERY_RECEIPT` and chunk requests
   be signed? SEC-009 needs the payload layout before a test can be written.
5. **GATT notify contract.** `capture.py` assumes one mesh frame per
   characteristic notification on `tx_char_uuid`. If the app fragments at the
   GATT layer, capture/replay needs the transport reassembler.
6. **Store-and-forward resend.** Packets are replayed with original timestamp,
   counter and signature after hours. Confirm receivers keep dedup/replay state
   for the full retention window and accept old-but-inside-retention packets.
7. **Keystore fallback.** Confirm the software-key wrapping approach and
   backup exclusion once `AndroidKeystoreSecretStore` is reviewed on device.
