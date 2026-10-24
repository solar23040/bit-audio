# Security Findings — Mesh Voice Notes

Owner: Agent H (Security)
Last updated: 2026-10-25
Target: design v0.1 (pre-implementation). No code or APK exists yet, so every
finding below is a **design-review finding**: a property the implementation must
guarantee, with a test that will prove or disprove it once Phase 1/2 lands.

Overall status: **not yet testable on hardware** — Phase 0 interfaces and a CI
APK are still required. Findings marked *Accepted* are documented limitations,
not implementation bugs.

## Status summary

| ID | Severity | Area | Status | Owner |
|---|---|---|---|---|
| SEC-001 | High | Dedup/verify ordering | Open (design review) | D + E |
| SEC-002 | High | Header authentication | Open (design review) | E + D |
| SEC-003 | High | Reassembly resource bounds | Open (design review) | C + D |
| SEC-004 | High | Relay flood amplification | Open (design review) | D |
| SEC-005 | Medium | BLE metadata/linkability | Open (needs device test) | C + F |
| SEC-006 | Medium | Keystore Ed25519 fallback | Open (needs device test) | E |
| SEC-007 | Medium | No forward secrecy | Accepted + document | E |
| SEC-008 | Medium | Replay window vs store-and-forward | Open (design review) | E + D |
| SEC-009 | Medium | Ack forgery/retransmit amplification | Open (design review) | C |
| SEC-010 | Medium | QR invite is a bearer secret | Open (design review) | F + E |
| SEC-011 | Low | Relay metadata exposure | Accepted + document | D + F |
| SEC-012 | Low | Parser fuzzing not in CI | Open (process) | A + G |
| SEC-013 | Low | UI alias/identity binding | Open (design review) | F |
| SEC-014 | Low | Relay storage quota/retention | Open (design review) | D + F |
| SEC-015 | Info | Malicious member content | Accepted | — |

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

**Severity:** High · **Status:** Open (design review) · **Owner:** D + E

If the mesh inserts `msg_id` into the seen/dedup cache as soon as a frame is
parsed, an attacker (no channel key required) can send a garbage frame carrying
a victim's `msg_id` and suppress the real clip. The real frame arrives later,
looks "already seen", and is dropped before signature verification.

**Impact:** Silent, selective message suppression anywhere in range; no key
needed. Also lets an attacker pin memory in the dedup cache.

**Recommendation:**

1. Authenticate first (signature + AEAD), then insert into the seen cache.
2. If unauthenticated pre-filtering is needed for CPU DoS, use a separate,
   short-lived, bounded pre-filter that cannot suppress authenticated traffic.
3. Key the cache by `(sender_id, msg_id)` so two senders cannot collide, and
   bound it (4096 entries / 10 min).
4. Count per-sender verification rate and drop above it, rather than trusting
   unverified IDs.

**Verification:** `test_spoofing.py --case forged-id` followed by the baseline
frame with the same `msg_id`; baseline must still be delivered. Also unit-test
in `:mesh`: insert garbage with a future legitimate msg ID, then deliver the
legitimate signed frame, assert delivery.

---

## SEC-002 — Routing header must be signed and used as AEAD AAD

**Severity:** High · **Status:** Open (design review) · **Owner:** E + D

The plan's header (`version, type, msg_id, sender_id, ttl, chunk_idx,
total_chunks, ts, sig`) is the routing and reassembly input. If `sig` only
covers the payload, an attacker can rewrite `chunk_idx`, `total_chunks`, `ttl`,
`ts` or `sender_id` without invalidating the signature. Consequences include
chunk confusion/splicing, TTL manipulation, replay-window bypass by fresh
timestamps, and misattribution.

**Impact:** Integrity bypass; can corrupt reassembly, suppress clips, extend
floods, or defeat replay timestamp checks.

**Recommendation:**

1. Define a canonical signing input: all header fields with `sig` excluded,
   plus the payload. Sign it with Ed25519.
2. Use the same canonical header as the XChaCha20-Poly1305 AAD.
3. Reject frames whose header is not the one that was authenticated (verify
   before acting on `ttl`/`chunk_idx`).
4. Pin the exact layout in `docs/packet-format.md`; publish test vectors.

**Verification:** `test_malicious_relay.py --mutation all` and the
`fuzz_packets.py` header mutations. Every mutated header must fail closed.
Harness currently assumes 1+1+8+8+1+2+2+8+64 = 95-byte header and
header+payload signing input; update `wire.py` if Agent A/E choose differently.

---

## SEC-003 — Unbounded reassembly and chunk metadata

**Severity:** High · **Status:** Open (design review) · **Owner:** C + D

`total_chunks` is a 16-bit field. Without caps, a single frame can declare
65,535 chunks, and a stream of frames with distinct `msg_id`s can allocate
unbounded buffers. Truncated headers and `chunk_idx >= total_chunks` exercise
the same path. This is a cheap remote memory/CPU DoS from outside the channel.

**Impact:** OOM/crash, storage exhaustion, battery drain, BLE stack instability.

**Recommendation:**

1. Validate before allocation: `1 ≤ total_chunks ≤ 256`,
   `0 ≤ chunk_idx < total_chunks`, frame ≤ 300 B, payload ≤ 240 B,
   reassembled ≤ 32 KB.
2. Cap partial buffers: 4 per sender, 32 globally, 30 s timeout.
3. Reject duplicate `(msg_id, chunk_idx)` with different bytes.
4. Run the parser fuzz corpus in CI on every push.

**Verification:** `test_flood.py --mode reassembly --pps 20 --duration 10`,
then `fuzz_packets.py --duration 60`. Assert app stays connected/responsive.
Acceptance for Phase 5 is a 1-hour fuzz run without a crash.

---

## SEC-004 — Relay flood amplification and airtime exhaustion

**Severity:** High · **Status:** Open (design review) · **Owner:** D

TTL flooding rebroadcasts every authenticated-looking frame. A flooder can send
many high-TTL frames with random IDs; even if each is dropped after verification,
the mesh spends airtime, CPU and battery on them, and honest nodes' transmissions
collide. No per-neighbor or global relay budget is specified.

**Impact:** Mesh unusable for the duration of the flood; battery drain; can be
triggered from outside the channel.

**Recommendation:**

1. Token bucket per BLE neighbor: 20 frames/s, burst 40; global 100 frames/s.
2. Clamp ingress TTL to 5; drop TTL 0 after local delivery.
3. Bounded relay queue; explicit drop policy (oldest first) instead of blocking.
4. Verify rate limit per claimed sender and globally (signature verification is
   the expensive step).
5. Log counters locally for diagnostics, not per-frame logs.

**Verification:** `test_flood.py --mode random --pps 50 --duration 20` with
liveness probe. Compare delivery of a valid clip injected before/during/after the
flood. Document achieved pps vs dropped.

---

## SEC-005 — BLE identifiers and advertisement payload enable tracking

**Severity:** Medium · **Status:** Open (needs device test) · **Owner:** C + F

Rotating ephemeral `sender_id`s do not help if the BLE address is public/static,
the advertisement includes a stable device name or channel identifier, or the adv
payload is otherwise constant. A passive sniffer can then track a device across
time and correlate it with mesh traffic, defeating sender-ID rotation.

**Impact:** Presence/location tracking, membership and conversation-graph
inference, linkability of clips to a device.

**Recommendation:**

1. Advertise only the app service UUID; no device name, alias, channel name or
   stable service data.
2. Rely on controller/host MAC rotation where available; document OEM
   differences. Do not bond for mesh traffic.
3. Rotate advertisements/payload at the same cadence as sender IDs.
4. Duty-cycle scanning and advertising; avoid constant discoverable mode.

**Verification:** `test_metadata.py --duration 900 --json-out meta.json` near an
idle phone. Success: address changes or advertisement payload is constant-free;
no stable fingerprint across the observation window. This is a field test; the
harness reports flags, a human confirms against the device's actual address
policy.

---

## SEC-006 — Ed25519 is not available in Android Keystore on all devices

**Severity:** Medium · **Status:** Open (needs device test) · **Owner:** E

Android Keystore EdDSA support starts at API 33 and is not uniform across OEMs.
The plan says "Ed25519 identity keypair per install (Android Keystore where
possible)"; on older devices a software key is the fallback. If that fallback is
stored as raw bytes in SharedPreferences/files, any app-data read or backup
extraction exposes the identity key.

**Impact:** Sender impersonation on affected devices; silent downgrade of the
security model.

**Recommendation:**

1. Feature-detect: if `KeyPairGenerator("Ed25519", "AndroidKeyStore")` works and
   signs correctly, use it (non-exportable).
2. Otherwise generate the seed in software but wrap it with a Keystore AES-GCM
   key (`setUserAuthenticationRequired(false)`, `setRandomizedEncryptionRequired(true)`).
3. Set `android:allowBackup="false"` and
   `android:fullBackupContent="false"`; exclude key material from any backup rules.
4. Surface the security level in Settings for debugging (`hardware`/`wrapped`).

**Verification:** install on API 30/31 and API 33+ devices; inspect `adb shell
run-as <pkg>` storage for plaintext seeds; attempt signing after key invalidation
(e.g., lock-screen change) and confirm graceful re-onboarding.

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
(existing clips stay under the old key). Store-and-forward retention (24 h) limits
exposure. Post-MVP: epoch keys / sender keys with ratcheting.

**Verification:** design review; confirm documentation and that Settings exposes
channel rotation (Agent F's "rotate identity" is not the same thing).

---

## SEC-008 — Replay window conflicts with store-and-forward and ID rotation

**Severity:** Medium · **Status:** Open (design review) · **Owner:** E + D

A timestamp-only replay window must accept clips delayed by store-and-forward
(hours), yet reject immediate replays. A tight window breaks legitimate offline
delivery; a loose window enables replay. Separately, if the per-sender monotonic
counter resets whenever the ephemeral sender ID rotates (or on restart), replays
across epochs/reboots pass.

**Impact:** Replayed clips re-delivered/replayed to the user; or legitimate
offline clips dropped.

**Recommendation:**

1. Primary defense: per-long-term-identity monotonic message counter, persisted
   across restarts, checked before delivery; accept out-of-order chunk indexes
   within one message.
2. Timestamp is a coarse sanity bound only (e.g., ±24 h, matching retention).
3. Persist counter state keyed by identity key, not ephemeral sender ID; carry
   an epoch in the authenticated header so old epochs are still checked.
4. Cache recently seen `(sender, msg_id)` for late duplicates.

**Verification:** `test_replay.py --mode replay` (immediate and delayed) and
`--mode rewrite-ts`; sent message must be delivered exactly once. Unit tests:
restart persistence, epoch rotation, clock jump forward/back.

---

## SEC-009 — Acks/retransmit requests are an unauthenticated amplification path

**Severity:** Medium · **Status:** Open (design review) · **Owner:** C

Selective ack/retransmit means a receiver can ask a sender to resend chunks. If
requests are unauthenticated, any device in range can repeatedly request the same
chunks, forcing retransmissions (airtime/battery) and potentially pinning a
transfer forever. Forged "missing chunk" lists can also waste the sender's time.

**Impact:** Targeted DoS of a sender; airtime amplification; battery drain.

**Recommendation:**

1. Authenticate ack/retransmit requests with the channel key and sign with the
   requester's identity; bind them to `msg_id` and a bounded chunk list.
2. Rate-limit per requester (e.g., one request set per message per 5 s).
3. Cap retries (e.g., 3 rounds), then abandon and let the user resend.
4. Ignore requests for messages the sender does not have or that are older than
   the active window.

**Verification:** `test_malicious_relay.py --mode drop` plus a repeated-ack
script (to be added with Agent C's ack format); confirm bounded retries.

---

## SEC-010 — QR channel invite is a bearer secret

**Severity:** Medium · **Status:** Open (design review) · **Owner:** F + E

The QR contains the channel key. A photo, screenshot or shoulder-surf can leak it.
A malicious QR can also trick a user into joining an attacker-controlled channel
where the attacker reads everything. There is no built-in way to verify that the
QR belongs to the intended group.

**Impact:** Channel confidentiality loss; impersonation within a fake channel.

**Recommendation:**

1. QR includes channel name, a short key fingerprint (e.g., 4 words or 6 hex
   chars), and an expiry/version; never auto-join without showing the name and
   fingerprint and asking for confirmation.
2. Out-of-band verification instructions in the join screen ("compare the words
   with the person next to you").
3. Do not include identity private keys or aliases the user did not choose.
4. `FLAG_SECURE` on the QR screen and no automatic screenshots/backups.
5. Log join events locally with channel fingerprint, never the key.

**Verification:** manual UX review plus `test_metadata.py` to confirm the channel
key/name are not advertised. Rotate/expiry unit tests in `:app`.

---

## SEC-011 — Relays and sniffers see message metadata

**Severity:** Low · **Status:** Accepted for MVP, must be documented · **Owner:** D + F

Encryption protects audio, not the fact that a message exists. Relays see
`sender_id`, `msg_id`, timestamp, size and chunk count; sniffers see timing and
volume. Store-and-forward retains that metadata for up to 24 h.

**Impact:** Traffic analysis, conversation timing, rough size/duration inference.

**Recommendation (MVP):** document clearly; keep retention short; avoid logging
metadata to system log; consider size bucketing and batching post-MVP.

**Verification:** review logs (`adb logcat`) for frames/keys; inspect stored
queue schema. No fix expected for MVP beyond documentation.

---

## SEC-012 — No continuous parser fuzzing in CI

**Severity:** Low · **Status:** Open (process) · **Owner:** A + G

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

---

## SEC-013 — UI alias is not bound to cryptographic identity

**Severity:** Low · **Status:** Open (design review) · **Owner:** F

The channel view shows "sender alias, hop count, delivery state". If aliases come
from unauthenticated advertisements or first-seen names, anyone can claim
"Alice". Users then trust the wrong identity even though signatures are valid.

**Impact:** Social-engineering/impersonation inside a channel.

**Recommendation:** derive display identity from the roster entry bound to the
signing key; show a stable safety number/fingerprint on tap; mark unknown senders
explicitly; never update an alias from network input after enrollment.

**Verification:** UI review; inject a packet signed by a new key claiming an
existing alias and confirm it is shown as unknown, not as the existing contact.

---

## SEC-014 — Relay/history storage needs hard quotas and expiry

**Severity:** Low · **Status:** Open (design review) · **Owner:** D + F

Store-and-forward requires persistence. Without a global quota and per-channel
caps, a flood or a long offline period can fill the disk; without expiry, clips
outlive their usefulness. History retention also needs a user-visible delete.

**Impact:** Storage exhaustion, battery churn, privacy over-retention.

**Recommendation:** 50 MB global / 20 MB per channel, evict oldest; 24 h default
queue expiry; Room schema with cleanup on app start and periodically; UI to clear
history and relay queue; never store plaintext after playback unless the user
saves it.

**Verification:** instrumentation test fills the queue to the cap; inspect DB
size; confirm expiry job. `adb shell dumpsys diskstats` before/after.

---

## SEC-015 — A channel member can send malicious content

**Severity:** Info · **Status:** Accepted · **Owner:** —

Cryptography authenticates members, not intent. A rogue member can send
harassment, misleading clips, or large valid clips within the rate limits. This
is inherent to a key-based group with no moderation server. UI identity binding
(SEC-013) and the ability to leave/rotate the channel are the only controls.
Document it; do not claim content safety.

---

## How results will be recorded

When code and hardware are available:

1. Run the harness against the CI APK on two owned phones (see
   `attack-tests/README.md`).
2. For each finding, replace "Open (design review)" with one of:
   `Open — reproduced`, `Fixed — verified`, `Not reproducible`, `Accepted`.
3. Attach the seed/capture path and the exact command to the finding. Do not
   paste channel keys or identity seeds into this file.
4. Any new finding gets the next ID and the same severity rubric. High/Critical
   blocks the Phase 5 acceptance until fixed or explicitly accepted by Agent A.
