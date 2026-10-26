# Security Findings — Mesh Voice Notes

Owner: Agent H (Security)
Last updated: 2026-10-26
Target: `main` + `agent-h/phase-2` at the CI run referenced below.
`docs/packet-format.md` and `docs/interfaces.md` are authoritative.

The JVM attack suite now runs the **real** `:mesh` and `:crypto` code on
`FakeNetwork` in CI (`MeshAttackTest`, `ContractVectorTest`, `PacketDecodeFuzzTest`).
Findings below are therefore implementation findings with a green/red CI signal,
not design-review guesses. What is still missing is a device/radio test (BLE
metadata, Keystore behaviour) and an APK on two owned phones.

Overall status: **parser, spoofing, replay, TTL, reassembly and relay-tampering
properties verified in CI**; one High finding remains open in the app-wired
`MeshNode` (SEC-001), plus SEC-017 (counter=0) and the node-side rate limit in
SEC-004. SEC-016 is resolved: docs v1 and `:crypto` now agree and a committed
byte-exact vector verifies in CI.

## CI verification

All evidence below comes from the `build` workflow on `agent-h/phase-2`:

| Run | Commit | Result |
|---|---|---|
| [`40208211416`](https://github.com/solar23040/bit-audio/actions/runs/40208211416) | `65d511b` | green: `security-harness`, `security-fuzz`, `Test, lint, build APK` |

Jobs:

- `security-harness` — `contract_vector.py --check`, `selfcheck.py`,
  `test_mesh_contract.py`, then `:security-harness:testDebugUnitTest` for
  `MeshAttackTest` + `ContractVectorTest` (init script
  `security/ci/harness.init.gradle`). The harness runs both mesh
  implementations (`MeshEngine` and the `AppGraph`-wired `MeshNode`) with the
  real `:crypto` on `FakeNetwork`.
- `security-fuzz` — the same harness module running `PacketDecodeFuzzTest`
  (`SECURITY_FUZZ_SECONDS=90` per implementation) plus
  `fuzz_packets.py --sink dry --duration 15`.

A red run blocks the branch. Known-open findings are printed to the test output
as `[SEC-xxx][KIND] OPEN: ...` (also in the uploaded test reports); fixed
properties are hard assertions.

## Status summary

| ID | Severity | Area | Status | Owner |
|---|---|---|---|---|
| SEC-001 | High | Dedup/verify ordering | **Open — reproduced in `MeshNode`** (`MeshEngine` fixed) | D + E |
| SEC-002 | High | Header authentication | **Fixed — verified in CI** | E + D |
| SEC-003 | Medium | Reassembly resource bounds | **Fixed — verified in CI** | C + D |
| SEC-004 | High | Relay flood amplification | **Partial — `MeshEngine` rate-limited, `MeshNode` has no ingress limiter** | D |
| SEC-005 | Medium | BLE metadata/linkability | Open (needs device test) | C + F |
| SEC-006 | Medium | Keystore Ed25519 fallback | Mitigated in code — device test pending | E |
| SEC-007 | Medium | No forward secrecy | Accepted + document | E |
| SEC-008 | Medium | Replay window vs store-and-forward | **Fixed — verified in CI** | E + D |
| SEC-009 | Medium | Ack forgery/retransmit amplification | Open (Phase 2 acks not implemented) | C |
| SEC-010 | Medium | QR invite is a bearer secret | Open (app UX) | F + E |
| SEC-011 | Low | Relay/channel metadata exposure | Accepted + document | D + F |
| SEC-012 | Low | Parser fuzzing not in CI | **Fixed — time-boxed fuzz job in CI** | A + G |
| SEC-013 | Low | UI alias/identity binding | Open (design review) | F |
| SEC-014 | Low | Relay storage quota/retention | Open (no hard disk cap yet) | D + F |
| SEC-015 | Info | Malicious member content | Accepted | — |
| SEC-016 | High | Crypto code ≠ packet format v1 | **Fixed — docs v1 + code + vector agree** | A + E |
| SEC-017 | Medium | `MeshNode` accepts `counter = 0` | **Open — reproduced in CI** | D |


Severity rubric:

- **Critical** — breaks confidentiality/integrity for all users with no user
  action, or remote code execution.
- **High** — practical attack on one user/channel, silent message suppression or
  tampering, or trivial DoS of a live mesh.
- **Medium** — needs channel key, a member account, notable effort, or leaks
  limited metadata; meaningful privacy or availability impact.
- **Low** — hardening, limited impact, or process gap.
- **Info** — documented limitation/accepted risk.

Repro steps are written so they can be pasted into a shell once the APK and
config exist. All harness paths are relative to `security/attack-tests/`.

---

## SEC-001 — Dedup cache can be poisoned before authentication

**Severity:** High · **Status:** Open — reproduced in `MeshNode` (`MeshEngine` fixed) · **Owner:** D + E

`docs/packet-format.md` specifies the dedup key as
`(channel_id, msg_id, chunk_idx)` — the sender identity is *not* part of it. If
a frame is inserted into the seen cache as soon as it parses, a nearby attacker
who hears chunk 0 of a real multi-chunk clip can inject a garbage frame with the
same `msg_id`/`chunk_idx` toward nodes that have not received the real chunk.
Those nodes then discard the genuine chunk and the message never reassembles.
The same mechanism lets anyone fill the bounded cache with junk and evict real
entries. Pre-poisoning a future message is infeasible while `msg_id` remains 8
random bytes; the attack requires observing a message in flight.

**Impact:** Silent, selective message suppression without a channel key; cache
churn/availability loss. Gets worse if `msg_id` ever becomes predictable
(timestamp/counter-derived).

**Recommendation:**

1. Authenticate first (signature + sender resolution), then insert into the seen
   cache. The docs already require relays to verify before forwarding/storing.
2. If unauthenticated pre-filtering is needed for CPU DoS, use a separate,
   short-lived, bounded pre-filter that cannot suppress authenticated traffic.
3. Include the resolved identity in the dedup key, e.g.
   `(channel_id, sender_identity, msg_id, chunk_idx)`, even though the wire key
   is only 8 bytes.
4. Count per-sender verification rate and drop above it rather than trusting
   unverified IDs.

**Verification:** `test_spoofing.py --case poison`: sends a forged frame with
the victim's sender ID and the baseline's `msg_id` first, then the valid
baseline. Exactly one valid clip may arrive.

**CI result (run `40208211416`):** partially fixed.
`MeshAttackTest > spoofed sender is dropped and never relayed` proves both
implementations verify the signature **before** inserting into the seen cache,
so the pre-authentication poisoning path is closed. `MeshAttackTest > known open
findings are reproduced and reported` still prints
`[SEC-001][NODE] OPEN: dedup key (channel,msg_id,chunk) suppressed a different
sender's valid chunk` for `MeshNode` (`MeshPacket.packetKey` has no identity);
`MeshEngine` keys the seen cache on
`(channel_id, resolved identity, msg_id, chunk_idx)` and delivers both senders.
`MeshNode` is the class wired into `AppGraph`.

---

## SEC-002 — Every authenticated field must be signed, TTL is the only exception

**Severity:** High · **Status:** Fixed — verified in CI · **Owner:** E + D

The format signs `header[ttl=0, sig=0] || payload`. That deliberately excludes
`ttl` (relays decrement it) and must include **everything else**: `version`,
`type`, `msg_id`, `channel_id`, `sender_id`, `chunk_idx`, `total_chunks`,
`timestamp_ms`, `counter`. The AEAD AAD is
`channel_id || msg_id || timestamp_ms || counter`.

If any of those fields is omitted from the signature or the AAD, an attacker can
rewrite chunk indexes, splice chunks between messages, change timestamps to
bypass freshness, or move packets between channels.

**Impact:** Integrity bypass; corrupted playback, replay-window bypass,
cross-channel confusion, misattribution.

**Recommendation:**

1. Implement the exact transcript from `docs/packet-format.md` and publish
   byte-exact test vectors (one fixed key/timestamp/message) in `docs/`.
2. Verify signature **before** acting on any header field, including
   `chunk_idx` and `total_chunks`.
3. Keep `ttl` out of the signature but clamp it to 1..16 on ingress, decrement
   once, and rely on dedup/rate limits to stop inflation (SEC-004).
4. Note: `:crypto` currently uses a different transcript/AAD — see SEC-016.

**Verification:** `test_malicious_relay.py` (default non-TTL mutations) must
show only the baseline clip; `--include-ttl` must show no amplification/loops.
`fuzz_packets.py` covers the same fields. Harness assumes the docs layout; see
`wire.py`.

**CI result (run `40208211416`):** fixed. `ContractVectorTest > docs v1 contract
vector verifies with production crypto` proves the committed v1 frames verify
and open with `:crypto`, and that rewriting `ttl` (relay) keeps both verifications
valid. `MeshAttackTest > malicious relay mutations are rejected` asserts that
sender, channel, `msg_id`, timestamp, counter, signature, nonce, ciphertext,
length/oversize, type, version and TTL mutations are all dropped without
delivery or relay, and that a spliced second chunk with a different timestamp is
not reassembled.

---

## SEC-003 — Reassembly limits must be enforced before allocation

**Severity:** Medium · **Status:** Fixed — verified in CI · **Owner:** C + D

`docs/packet-format.md` specifies the bounds: frame ≤ 512 B, payload ≤ 405 B,
`total_chunks` 1..256, `chunk_idx < total_chunks`, reassembled ≤ 64 KiB,
reassembly timeout 120 s, bounded partials per sender. The risk is an
implementation that parses and allocates first, or that trusts `total_chunks`
from the wire. A single frame can otherwise claim 65,535 chunks, and many
`msg_id`s can allocate unbounded buffers.

**Impact:** OOM/crash, storage exhaustion, battery drain, BLE stack instability.

**Recommendation:** enforce all documented limits before allocation; cap
partial messages (4 per sender, 32 global); reject duplicate
`(msg_id, chunk_idx)` with different bytes; keep the parser fuzz corpus in CI.
Raise this to High if implementation review or the fuzz run shows a missing
bound.

**Verification:** `test_flood.py --mode reassembly --pps 20 --duration 10`,
then `fuzz_packets.py --duration 60`. Phase 5 acceptance: 1-hour fuzz run
without a crash.

**CI result (run `40208211416`):** fixed. `MeshAttackTest > flood and reassembly
claims stay bounded and do not block delivery` pushes 2,000 random frames plus
300 validly signed frames that each claim 256 chunks; both implementations keep
the partial cache bounded, never relay the hostile traffic, and still deliver a
final valid clip. `PacketDecodeFuzzTest` runs 250k+ mutated/truncated/oversized
frames per implementation for 90 s each without a crash or a lost follow-up
delivery. The remaining Phase 5 item is the 1-hour nightly run, not a code fix.

---

## SEC-004 — Relay flood amplification and airtime exhaustion

**Severity:** High · **Status:** Partial — `MeshEngine` rate-limited, `MeshNode` has no ingress limiter · **Owner:** D

TTL flooding rebroadcasts valid packets; a member or a nearby non-member can
send high-rate frames. Even when invalid frames are dropped after verification,
the radio and CPU work is real, and honest transmissions collide. The docs
mention per-sender/per-neighbour rate limits as Phase 5 work but do not specify
values or the drop policy.

**Impact:** Mesh unusable for the duration of a flood; battery drain; triggerable
from outside the channel (garbage) or by a rogue member (valid high-TTL).

**Recommendation:**

1. Token bucket per BLE neighbour: 20 frames/s, burst 40; global 100 frames/s.
2. Clamp ingress TTL to 5 (accept 1..16, forward `ttl-1`); drop TTL 0.
3. Bounded relay queue; explicit drop policy (oldest first) instead of blocking.
4. Verify-rate limit per claimed sender and globally (signature verification is
   the expensive step).
5. Log counters locally for diagnostics, not per-frame logs.

**Verification:** `test_flood.py --mode random --pps 50 --duration 20` with
`--probe-uuid`. Compare valid clip delivery before/during/after; document
achieved pps vs dropped.

**CI result (run `40208211416`):** partial. `MeshEngine` applies
`RateLimiter` token buckets per neighbour (before decode/crypto) and per
resolved identity (after verification), configured by `MeshConfig`
(`perNeighbourRate`, `perSenderRate`). `MeshNode` parses and verifies every
frame from a neighbour with no bucket at all, so a nearby sender can still burn
CPU/airtime up to the BLE layer. The attack suite raises both engine limits to
1e6 so the functional cases are not self-throttled; a focused test that asserts
the bucket values and drops is still a follow-up. Both implementations drop the
hostile traffic and keep delivering valid clips (see SEC-003 evidence).

---

## SEC-005 — BLE identifiers and advertisement payload enable tracking

**Severity:** Medium · **Status:** Open (needs device test) · **Owner:** C + F

Sender IDs rotate every 15 minutes via
`HMAC(channel_key, "bit-audio/sender-id/v1" || pubkey || epoch)`; outsiders
without the channel key cannot link epochs. That is defeated if the BLE address
is public/static, the advertisement carries a stable device name, or the adv
payload is otherwise constant. `channel_id` is also public metadata in every
packet by design (see SEC-011), so channel-level traffic grouping is expected.

**Impact:** Presence/location tracking, membership inference, linkability of a
device across conversations.

**Recommendation:**

1. Advertise only the app service UUID; no device name, alias, channel name or
   stable service data.
2. Rely on controller/host MAC rotation where available; document OEM
   differences. Do not bond for mesh traffic.
3. Rotate advertisements/payload at the same cadence as sender IDs.
4. Duty-cycle scanning and advertising; avoid constant discoverable mode.

**Verification:** `test_metadata.py --duration 900 --json-out meta.json` near an
idle phone. Success: address changes or payload is constant-free; no stable
fingerprint across the window. Field test; a human confirms the OS policy.

---

## SEC-006 — Ed25519 is not available in Android Keystore on all devices

**Severity:** Medium · **Status:** Mitigated in code — device test pending · **Owner:** E

Android Keystore EdDSA support starts at API 33 and is not uniform across OEMs.
The current implementation already avoids the obvious footgun:

- `IdentityManager` stores a 32-byte Ed25519 **seed** in the injected
  `SecretStore`, never a Keystore "Ed25519" key.
- `AndroidKeystoreSecretStore` encrypts secrets with a non-exportable AES-256-GCM
  key in AndroidKeyStore (randomized IV, 16-byte tag) and writes them to
  `noBackupFilesDir`, so the seed is not plaintext on disk and is excluded from
  backup transports.

Residual risk: on API <33 the signing itself happens in app memory, so code
execution in the app process (root/malware) can read the seed. On API 33+ we
should use a hardware Ed25519 key when the OEM supports it, rather than always
falling back to the wrapped seed.

**Impact:** On devices without hardware EdDSA, identity-key extraction requires
app-process compromise; at-rest/backup extraction is blocked by Keystore
wrapping.

**Recommendation:**

1. Feature-detect `KeyPairGenerator("Ed25519", "AndroidKeyStore")`; if it signs
   correctly, use the non-exportable key directly on API 33+.
2. Keep the wrapped-seed fallback for older/OEM-broken devices.
3. Confirm `android:allowBackup="false"` in the app manifest and no key files in
   backup rules (Agent F).
4. Surface the security level in Settings (`hardware`/`wrapped`) for debugging.

**Verification:** install on API 30/31 and API 33+ devices; inspect
`adb shell run-as <pkg>` files for plaintext seeds; attempt signing after key
invalidation (e.g. lock-screen change) and confirm graceful re-onboarding.

---

## SEC-007 — No forward secrecy; static channel key

**Severity:** Medium · **Status:** Accepted for MVP, must be documented · **Owner:** E

All clips are encrypted under one long-lived channel key. Anyone who obtains the
key later (stolen device, QR leak, member leaves) can decrypt every stored clip
they captured and forge new ones until the channel is re-keyed. Store-and-forward
queues make old ciphertext plentiful.

**Impact:** Retrospective disclosure after key compromise; no post-compromise
security.

**Recommendation (MVP):** state the limitation in README and onboarding; offer a
"rotate channel" action that creates a new channel/key and re-invites members
(existing clips stay under the old key). Store-and-forward retention (24 h)
limits exposure. Post-MVP: epoch keys / sender keys with ratcheting.

**Verification:** design review; confirm documentation and that Settings exposes
channel rotation (Agent F's "rotate identity" is not the same thing).

---

## SEC-008 — Replay window vs store-and-forward and ID rotation

**Severity:** Medium · **Status:** Fixed — verified in CI · **Owner:** E + D

The docs reject timestamps older than 24 h or >5 min in the future, cache
completed `msg_id`s, and cache `(channel_id, identity, counter) -> msg_id`.
They explicitly allow late messages with a new `msg_id` to keep
store-and-forward working. The residual risk is implementation:

- counter state must be persisted and keyed by the **stable identity**, not the
  rotating `sender_id`;
- the counter cache must be checked after signature verification;
- sender resolution tries current and previous epoch only, so a queue held
  across an epoch boundary is fine, but a clock jump or long offline relay could
  make old packets unresolvable;
- reusing a counter with a different `msg_id` must be rejected, not overwritten.

**Impact:** Replayed clips re-delivered/played, or legitimate offline clips
dropped; counter-cache growth if unbounded.

**Recommendation:** persist counters and message-ID cache with expiry; cap the
cache; verify before cache updates; unit-test restart/clock-jump/epoch-boundary
cases.

**Verification:** `test_replay.py --mode replay` (immediate and delayed) and
`--mode rewrite-ts`; sent message must be delivered exactly once. Unit tests:
restart persistence, epoch rotation, clock jump forward/back, counter reuse.

**CI result (run `40208211416`):** fixed. `MeshAttackTest > replayed frame is
delivered once and relayed once` sends the identical frame twice and asserts
exactly one delivery at the first hop, one relayed copy and one delivery at the
far node, for both implementations. Counter state in both is keyed by
`(channel_id, resolved identity, counter) -> msg_id` and checked after signature
verification; a counter mapped to a different `msg_id` is rejected by the
`malicious relay mutations` case. `MeshNode` still accepts `counter = 0`, which
is tracked separately as SEC-017.

---

## SEC-009 — Acks/retransmit requests are an unauthenticated amplification path

**Severity:** Medium · **Status:** Open — Phase 2 acks not implemented · **Owner:** C

`DELIVERY_RECEIPT` and retransmit are reserved for Phase 2. If requests are
unauthenticated, any device in range can repeatedly request chunks, forcing
retransmissions (airtime/battery) and potentially pinning a transfer forever.

**Impact:** Targeted DoS of a sender; airtime amplification; battery drain.

**Recommendation:**

1. Authenticate receipt/retransmit packets with the channel key and sign with
   the requester's identity; bind them to `msg_id` and a bounded chunk list.
2. Rate-limit per requester (e.g. one request set per message per 5 s).
3. Cap retries (e.g. 3 rounds), then abandon and let the user resend.
4. Ignore requests for messages the sender does not have or that are older than
   the active window.

**Verification:** `test_malicious_relay.py --mode` plus a repeated-ack script
(to be added with Agent C's ack format); confirm bounded retries.

---

## SEC-010 — QR channel invite is a bearer secret

**Severity:** Medium · **Status:** Open — app UX/QR screens · **Owner:** F + E

The QR contains the channel key (`ChannelKeys.fromQrSecret`, 32 bytes). A photo,
screenshot or shoulder-surf can leak it. A malicious QR can also trick a user
into joining an attacker-controlled channel where the attacker reads everything.
Nothing verifies that the QR belongs to the intended group.

**Impact:** Channel confidentiality loss; impersonation within a fake channel.

**Recommendation:**

1. QR includes channel name, a short key fingerprint (e.g. 4 words or 6 hex
   chars), and an expiry/version; never auto-join without showing the name and
   fingerprint and asking for confirmation.
2. Out-of-band verification instructions in the join screen.
3. Do not include identity private keys or aliases the user did not choose.
4. `FLAG_SECURE` on the QR screen; no automatic screenshots/backups.
5. Log join events locally with channel fingerprint, never the key.

**Verification:** manual UX review plus `test_metadata.py` to confirm the channel
key/name are not advertised. Rotate/expiry unit tests in `:app`.

---

## SEC-011 — Relays see metadata; channel_id is public by design

**Severity:** Low · **Status:** Accepted for MVP, must be documented · **Owner:** D + F

Encryption protects audio, not existence. Every header carries a **stable,
public `channel_id`** (HMAC of the channel key), so any sniffer can group
packets by channel and observe volume/timing even without the key. Relays also
see `sender_id`, `msg_id`, timestamp, counter, size and chunk count; store-and-
forward retains that for up to 24 h. Sender IDs rotate per 15-minute epoch, but
packets from one sender within an epoch are linkable (documented in
`RotatingSenderId`).

**Impact:** Channel-level traffic analysis, conversation timing, rough
size/duration inference, per-epoch linkability.

**Recommendation (MVP):** document clearly; keep retention short; avoid logging
metadata to system log; consider size bucketing and batching post-MVP. The
`channel_id` trade-off (relay filtering vs. linkability) should be stated in the
README.

**Verification:** review logs (`adb logcat`) for frames/keys; inspect stored
queue schema. No fix expected for MVP beyond documentation.

---

## SEC-012 — No continuous parser fuzzing in CI

**Severity:** Low · **Status:** Fixed — time-boxed fuzz job in CI · **Owner:** A + G

The attack harness can fuzz a live device, but nothing yet keeps malformed-input
coverage running on every push. Parser regressions would only be found by manual
field tests. Phase 5 acceptance requires a 1-hour fuzz run without a crash.

**Impact:** Regressions slip in; DoS bugs reach devices.

**Recommendation:**

1. Add a JVM property/fuzz test (jqwik or Kotlin fuzz) for packet parsing,
   fragment reassembly and header validation with a committed corpus.
2. Keep the corpus in `:mesh`/`:transport` tests and grow it from
   `fuzz-artifacts/` failures.
3. CI nightly: `fuzz_packets.py --duration 3600` against the `:sim` sink.

**Verification:** CI workflow contains the job and a failure blocks merge.

**CI result (run `40208211416`):** fixed for the JVM parser. The `security-fuzz`
job runs `PacketDecodeFuzzTest` (90 s per mesh implementation,
`SECURITY_FUZZ_SECONDS`) plus the structure-aware Python fuzzer against a dry
sink, on every push. The 1-hour nightly soak remains a Phase 5 acceptance item;
the job timeout is 15 minutes, so raise it there rather than silently extending
the per-push budget.

---

## SEC-013 — UI alias is not bound to cryptographic identity

**Severity:** Low · **Status:** Open — UI copy/identity binding · **Owner:** F

The channel view shows sender alias, hop count and delivery state. If aliases
come from unauthenticated advertisements or first-seen names, anyone can claim
"Alice". Signatures are valid but users trust the wrong identity.

**Impact:** Social-engineering/impersonation inside a channel.

**Recommendation:** derive display identity from the roster entry bound to the
signing key; show a stable safety number/fingerprint on tap; mark unknown
senders explicitly; never update an alias from network input after enrollment.

**Verification:** UI review; inject a packet signed by a new key claiming an
existing alias and confirm it is shown as unknown.

---

## SEC-014 — Relay/history storage needs hard quotas and expiry

**Severity:** Low · **Status:** Open — no global disk quota implemented · **Owner:** D + F

The docs specify 24 h retention and 64 KiB per message, but no global disk cap.
Without one, a flood or a long offline period can fill storage; without expiry,
clips outlive their usefulness. History retention also needs user-visible
delete.

**Impact:** Storage exhaustion, battery churn, privacy over-retention.

**Recommendation:** 50 MB global / 20 MB per channel, evict oldest; 24 h default
queue expiry; Room cleanup on start and periodically; UI to clear history and
relay queue; never store plaintext after playback unless the user saves it.

**Verification:** instrumentation test fills the queue to the cap; inspect DB
size; confirm expiry job.

---

## SEC-015 — A channel member can send malicious content

**Severity:** Info · **Status:** Accepted · **Owner:** —

Cryptography authenticates members, not intent. A rogue member can send
harassment, misleading clips, or large valid clips within the rate limits. This
is inherent to a key-based group with no moderation server. UI identity binding
(SEC-013) and the ability to leave/rotate the channel are the only controls.
Document it; do not claim content safety.

---

## SEC-016 — `:crypto` does not implement the packet-format v1 transcript

**Severity:** High · **Status:** Fixed — docs v1, code and vector agree · **Owner:** A + E
**Found:** 2026-10-25 (contract review) · **Resolved:** 2026-10-25 (docs v1 + `:crypto` rework)

The original finding: `docs/packet-format.md` and the Kotlin crypto code
disagreed on every wire-defining derivation, so a frame built to the docs could
not verify/open with `:crypto`. Agent A kept the shipped design and revised
`docs/packet-format.md` to v1; `:crypto` and the harness now implement exactly
that text:

| Item | `docs/packet-format.md` v1 = `:crypto` |
|---|---|
| `channel_id` | `SHA-256("bit-audio/channel-id/v1" || channel_key)[0..8]` |
| `sender_id` | `id_key = HMAC-SHA256(key, "bit-audio/sender-id-key/v1")`, then `HMAC-SHA256(id_key, "bit-audio/sender-id/v1" || pubkey || epoch_u64)[0..8]` |
| Epoch input | `timestamp_ms / 900_000` (15 minutes) |
| Signature transcript | `"bit-audio/packet-sign/v1" || u32be(len(canonical_header)) || canonical_header || sealed_payload` |
| AEAD AAD | `"bit-audio/packet-seal/v1" || canonical_header` |
| `canonical_header` | header prefix (43 bytes) with `ttl` (byte 26) forced to `0x00` |
| Argon2 salt | at least 16 bytes (`ChannelKeys.MIN_SALT_SIZE = 16`) |

TTL stays outside both the signature and the AAD, so a relay can decrement it
without re-signing; everything else (`version`, `type`, `msg_id`, `channel_id`,
`sender_id`, `chunk_idx`, `total_chunks`, `timestamp_ms`, `counter`) is bound.

**Evidence (run `40208211416`):**

- `security/ci` Python steps: `contract_vector.py --check`, `selfcheck.py` and
  `test_mesh_contract.py` pass against `security/contract-vectors.json`.
- `ContractVectorTest > docs v1 contract vector verifies with production crypto`
  reads the same committed vector and proves with the real `:crypto` that the
  documented `channel_id`/`sender_id` derivations match, both 512 B/294 B frames
  verify and open, the reassembled plaintext matches, and a relayed `ttl = 4`
  copy still verifies and opens.
- `MeshAttackTest` builds every attack frame byte-for-byte from the docs, so a
  future transcript drift turns the suite red instead of passing silently.

---

## SEC-017 — `MeshNode` accepts `counter = 0`

**Severity:** Medium · **Status:** Open — reproduced in CI · **Owner:** D
**Found:** 2026-10-25 (attack harness)

`docs/packet-format.md` requires `counter` to start at **1** and be shared by all
chunks of a message. `MeshEngine` rejects `counter <= 0` before signature
verification, but `MeshNode` (`MeshNode.processFrame` →
`acceptCounter(channel, identity, counter)`) only checks that an existing
`counter -> msg_id` mapping does not change. A frame with `counter = 0` is
therefore accepted, delivered and relayed by the class wired into `AppGraph`.

**Impact:** Low on its own — the value is only used as a replay key and never
reused for a different `msg_id` in the current cache. It does break the
documented invariant and would let a peer occupy the `0` key, so a future
implementation that assumes `1..2^32-1` (persisted counters, epoch windows)
would behave inconsistently between the two implementations.

**Recommendation:** add `require(counter >= 1)` / drop `counter == 0` in
`MeshNode.processFrame` before the counter cache, matching `MeshEngine` and the
docs; add a unit test next to the existing counter-reuse test.

**Verification:** `MeshAttackTest > known open findings are reproduced and
reported` prints `[SEC-017][NODE] OPEN: counter=0 accepted (docs require
1..2^32-1)` for `MeshNode` and asserts `MeshEngine` rejects it. The test becomes
green for both implementations once the node check lands.

---

## How results will be recorded

1. Every push runs the `build` workflow; `security-harness` and `security-fuzz`
   must be green before merge. Attach the run ID to new/updated findings.
2. Use one of: `Open — reproduced`, `Fixed — verified`, `Partial`,
   `Not reproducible`, `Accepted`, and name the test (or harness command) that
   proves it.
3. Device/radio work (SEC-005, SEC-006) still needs the CI APK on two owned
   phones (see `attack-tests/README.md`); do not paste channel keys or identity
   seeds into this file.
4. Any new finding gets the next ID and the same severity rubric. High/Critical
   blocks Phase 5 acceptance until fixed or explicitly accepted by Agent A.
