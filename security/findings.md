# Security Findings — Mesh Voice Notes

Owner: Agent H (Security)
Last updated: 2026-10-25
Target: design v0.1 (pre-implementation). `docs/packet-format.md` and
`docs/interfaces.md` are authoritative. No APK exists yet, so findings are
**design/implementation-review findings**: properties the code must guarantee,
with a harness that proves or disproves them once Phase 1/2 lands.

Overall status: **not yet testable on hardware** — a CI APK and a dedicated
test channel are required. Findings marked *Accepted* are documented
limitations, not implementation bugs. **SEC-016 is a contract mismatch that
needs Agent A's decision before wire code is merged.**

## Status summary

| ID | Severity | Area | Status | Owner |
|---|---|---|---|---|
| SEC-001 | High | Dedup/verify ordering | Open (design review) | D + E |
| SEC-002 | High | Header authentication | Open (design review) | E + D |
| SEC-003 | Medium | Reassembly resource bounds | Open (verify implementation) | C + D |
| SEC-004 | High | Relay flood amplification | Open (design review) | D |
| SEC-005 | Medium | BLE metadata/linkability | Open (needs device test) | C + F |
| SEC-006 | Medium | Keystore Ed25519 fallback | Mitigated in code — device test pending | E |
| SEC-007 | Medium | No forward secrecy | Accepted + document | E |
| SEC-008 | Medium | Replay window vs store-and-forward | Open (design review) | E + D |
| SEC-009 | Medium | Ack forgery/retransmit amplification | Open (design review) | C |
| SEC-010 | Medium | QR invite is a bearer secret | Open (design review) | F + E |
| SEC-011 | Low | Relay/channel metadata exposure | Accepted + document | D + F |
| SEC-012 | Low | Parser fuzzing not in CI | Open (process) | A + G |
| SEC-013 | Low | UI alias/identity binding | Open (design review) | F |
| SEC-014 | Low | Relay storage quota/retention | Open (design review) | D + F |
| SEC-015 | Info | Malicious member content | Accepted | — |
| SEC-016 | High | Crypto code ≠ packet format v1 | Open — Agent A decision | A + E |

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
baseline. Exactly one valid clip may arrive. Unit test in `:mesh`: insert
garbage with a future legitimate msg ID, then deliver the legitimate signed
frame, assert delivery.

---

## SEC-002 — Every authenticated field must be signed, TTL is the only exception

**Severity:** High · **Status:** Open (design review) · **Owner:** E + D

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

---

## SEC-003 — Reassembly limits must be enforced before allocation

**Severity:** Medium · **Status:** Open (verify implementation) · **Owner:** C + D

`docs/packet-format.md` now specifies the bounds: frame ≤ 512 B, payload ≤ 405 B,
`total_chunks` 1..162, `chunk_idx < total_chunks`, reassembled ≤ 64 KiB,
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

---

## SEC-004 — Relay flood amplification and airtime exhaustion

**Severity:** High · **Status:** Open (design review) · **Owner:** D

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

**Severity:** Medium · **Status:** Open (design review) · **Owner:** E + D

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

---

## SEC-009 — Acks/retransmit requests are an unauthenticated amplification path

**Severity:** Medium · **Status:** Open (design review) · **Owner:** C

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

**Severity:** Medium · **Status:** Open (design review) · **Owner:** F + E

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

**Severity:** Low · **Status:** Open (design review) · **Owner:** D + F

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

**Severity:** High · **Status:** Open — needs Agent A decision · **Owner:** A + E
**Found:** 2026-10-25 (contract review)

The Kotlin crypto code and `docs/packet-format.md` disagree on four
wire-defining derivations. `docs/` is authoritative per `AGENTS.md`; the code
must change (or the docs must be deliberately revised by Agent A) before Phase 2
wires them together.

| Item | `docs/packet-format.md` v1 | Current Kotlin |
|---|---|---|
| `channel_id` | `HMAC-SHA256(key, "bit-audio/channel-id/v1")[0..8]` | `SHA-256("bit-audio/channel-id/v1" || key)[0..8]` (`ChannelKeys.channelId`) |
| `sender_id` | `HMAC-SHA256(key, "bit-audio/sender-id/v1" || pubkey || epoch_be64)[0..8]` | `HMAC-SHA256(HMAC-SHA256(key,"bit-audio/sender-id-key/v1"), "bit-audio/sender-id/v1" || pubkey || epoch)[0..8]` (`RotatingSenderId`) |
| Epoch input | `timestamp_ms / 900000` | `timestamp_seconds / 900` (`epochFor` takes seconds) |
| Signature transcript | `header[ttl=0, sig=0] || payload`, no domain/length prefix | `"bit-audio/packet-sign/v1" || u32(header_len) || header_without_sig || payload` (`PacketCrypto`); TTL handling depends on the caller |
| AEAD AAD | `channel_id || msg_id || timestamp_ms || counter` | `"bit-audio/packet-seal/v1" || header_without_signature` (`PacketCrypto`) |
| Argon2 salt | at least 16 bytes (`interfaces.md`) | minimum 8 bytes (`ChannelKeys.MIN_SALT_SIZE = 8`) |

Consequences:

- A frame built to the docs does not verify/open with the current crypto code
  (and vice versa), so the mesh cannot interoperate with the documented format.
- The security properties differ: the code's AAD covers the whole
  `headerWithoutSignature`, while the docs bind only four fields. **If that
  header includes `ttl`, decrementing TTL at a relay breaks the AEAD and/or
  signature** — every multi-hop packet would fail at the receiver. This alone
  is a functional blocker for Phase 2.
- The code's signature domain-separates and length-prefixes, so signature bytes
  are not portable to the documented wire format.
- Test vectors do not exist in `docs/`, so both sides only test self-consistency.
  The attack harness is pinned to the docs and cannot test the current code.

**Recommendation:**

1. Agent A decides which side is canonical and updates the other in the same PR
   (docs are authoritative unless A explicitly changes them).
2. If docs win: change `ChannelKeys.channelId`, `RotatingSenderId`
   (single HMAC, ms epoch), `PacketCrypto` transcript/AAD, and the Argon2 salt
   minimum; add byte-exact vectors to `docs/packet-format.md`.
3. If code wins: update the docs, then update this harness (`wire.py`) before
   any live test. Do not leave both variants in flight.
4. Add a cross-module test in CI that verifies one fixed vector in both Python
   (this harness) and Kotlin (`:crypto`).

**Verification:** after the decision, `python selfcheck.py` plus a new Kotlin
test using the same vector must pass. Until then, no spoofing/replay result
against the APK is meaningful.

---

## How results will be recorded

When code and hardware are available:

1. Run the harness against the CI APK on two owned phones (see
   `attack-tests/README.md`).
2. For each finding, replace the status with one of:
   `Open — reproduced`, `Fixed — verified`, `Not reproducible`, `Accepted`.
3. Attach the seed/capture path and the exact command to the finding. Do not
   paste channel keys or identity seeds into this file.
4. Any new finding gets the next ID and the same severity rubric. High/Critical
   blocks Phase 5 acceptance until fixed or explicitly accepted by Agent A.
