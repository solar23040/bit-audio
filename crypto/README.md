# `:crypto` — Agent E (Phase 1)

Crypto module for Mesh Voice Notes. Pure-Kotlin API over BouncyCastle
primitives; no Android dependencies except the optional Keystore-backed secret
store, so all logic runs in JVM unit tests.

Status: **source + tests written, not compiled locally** (plan rule: no local
builds). There is no Phase 0 project or CI workflow in this workspace yet, so
nothing has run on CI either. First CI run should be
`./gradlew :crypto:test`.

## What is implemented

| Plan item | Where |
|---|---|
| Ed25519 identity per install + Keystore-protected storage | `Ed25519.kt`, `Identity.kt`, `IdentityStore.kt`, `AndroidKeystoreSecretStore.kt` |
| Packet signing / verification | `Crypto.kt`, `PacketCrypto.kt` |
| Argon2id channel key, XChaCha20-Poly1305 AEAD | `ChannelKeys.kt`, `XChaCha20Poly1305.kt`, `HChaCha20.kt` |
| Anti-replay: timestamp window + ID cache + sliding counter | `ReplayGuard.kt` |
| Rotating ephemeral sender IDs | `RotatingSenderId.kt`, `PeerDirectory` |

Public API is exactly the four `Crypto` methods from the plan:

```kotlin
interface Crypto {
    fun sign(data: ByteArray): ByteArray
    fun verify(senderPublicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean
    fun seal(channelKey: ByteArray, plaintext: ByteArray, associatedData: ByteArray): ByteArray
    fun open(channelKey: ByteArray, sealed: ByteArray, associatedData: ByteArray): ByteArray?
}
```

`DefaultCrypto` wires it to an `IdentityManager`:

```kotlin
val identities = IdentityManager(AndroidKeystoreSecretStore(context))
val crypto = DefaultCrypto(identities)
```

## Dependency

One: `org.bouncycastle:bcprov-jdk18on:1.86` (see `build.gradle.kts`). It is used
through its low-level API only; it is never installed as a JCA provider, so it
cannot collide with Android's built-in `BC` provider. Package namespace is
`com.bitaudio.crypto` — rename once Agent A fixes module namespaces.

If the Phase 0 root build uses a version catalog, move the dependency there and
delete `crypto/build.gradle.kts`; nothing else in the module names build
versions.

## Wire formats

- **Sealed payload:** `nonce(24) || ciphertext || tag(16)`, XChaCha20-Poly1305
  (`draft-irtf-cfrg-xchacha-03`). Random 24-byte nonce per seal; no nonce state
  to persist.
- **Channel key:** 32 bytes, random for QR channels, Argon2id for passphrases.
- **Signing input:** `"bit-audio/packet-sign/v1" || u32be(headerLen) || header || payload`,
  where `header` excludes the trailing `sig` field. Use
  `PacketCrypto.signingBytes(...)` rather than rebuilding this by hand.
- **AEAD associated data:** `"bit-audio/packet-seal/v1" || header` (same header,
  no `sig`). This binds `sender_id`, `msg_id`, `ttl`, `chunk_idx`, `ts`, etc. to
  the ciphertext, so a relay cannot rewrite routing fields undetected.
- **Rotating sender ID:** 8 bytes,
  `trunc8(HMAC-SHA256(HMAC-SHA256(channelKey, "bit-audio/sender-id-key/v1"),
  "bit-audio/sender-id/v1" || pubkey || u64be(epoch)))`.
  Default epoch is 15 min. Receivers resolve IDs with `PeerDirectory.resolve()`
  over known channel members and ±1 epoch of clock skew, so no extra packet
  field is needed.

## Key / identity storage

- Ed25519 is implemented in software (BouncyCastle) so it works below API 33,
  where AndroidKeyStore has no Ed25519 support.
- `AndroidKeystoreSecretStore` encrypts the 32-byte seed with AES-256-GCM under
  a non-exportable AndroidKeyStore key and stores it in `noBackupFilesDir`.
  It is not included in cloud backup and cannot be restored onto another phone.
- `IdentityManager.rotate()` creates and persists a new identity; wire it to
  Settings ("rotate identity").
- `InMemorySecretStore` is for tests/previews only.

## Replay protection — packet-format request for Agent A

`ReplayGuard.check(senderId, messageId, timestampSeconds, counter?)` returns
`ACCEPT` / `REPLAY` / `STALE` / `FUTURE`.

- Window is ±120 s by default. Store-and-forward must therefore expire or
  re-timestamp old clips before delivery, or they will be rejected.
- The packet header in `docs/packet-format.md` has **no replay counter**, so
  `counter` stays null for now. Timestamp + `msg_id` cache already rejects
  captured-packet replays.
- Recommendation: add `replay_counter: u32` (or `u64`) to the header and set it
  strictly increasing per sender. `ReplayGuard` then uses a 64-bit sliding
  window, which tolerates mesh reordering. This is the one cross-module change
  Agent E needs from Agent A.
- Sender IDs rotate every 15 min, so replay state is keyed by the rotating ID.
  This is safe because the timestamp window (±2 min) is much shorter than an
  epoch.

## Integration sketch (`:mesh`, Agent D)

Send:

```kotlin
val header = encodeHeaderWithoutSignature(...)        // :mesh owns encoding
val sealed = PacketCrypto.sealPayload(crypto, channelKey, header, opusBytes)
val signature = PacketCrypto.signPacket(crypto, header, sealed)
transport.send(peer, encodePacket(header, sealed, signature))
```

Receive (drop silently on any failure):

```kotlin
val sender = directory.resolve(channelKey, header.senderId, header.ts) ?: return DROP
if (!PacketCrypto.verifyPacket(crypto, sender, header, sealed, signature)) return DROP
if (replayGuard.check(header.senderId, header.msgId, header.ts) != ACCEPT) return DROP
val plaintext = PacketCrypto.openPayload(crypto, channelKey, header, sealed) ?: return DROP
```

Do the timestamp check before signature work if you want cheap early drops.

Note on cost: one Ed25519 signature + 16-byte tag + 24-byte nonce per
*packet* is expensive if you fragment a 15 KB clip into 240-byte chunks
(~25% signature overhead). Preferred: seal the whole message once, fragment the
sealed blob, sign a small manifest (`msg_id`, `total_chunks`, `ts`, payload
hash). If the spec insists on per-fragment `sig`, budget for the overhead and
measure on phones in Phase 4.

## Tests

Run on CI: `./gradlew :crypto:test`.

- `Ed25519Test` — RFC 8032 §7.1 vectors 1–3, tampering, malformed sizes.
- `XChaCha20Poly1305Test` — HChaCha20 vector §2.2.1, AEAD vector A.3.1,
  round-trip, wrong key/AAD/ciphertext, truncation, nonce freshness.
- `Argon2Test` — RFC 9106 Argon2id vector, salt dependence, output length,
  input validation, QR key copies.
- `ReplayGuardTest` — timestamps, duplicate IDs, reordering within counter
  window, old counters, per-sender isolation, eviction bound.
- `RotatingSenderIdTest` — epoch stability/rotation, channel scoping, resolver
  with skew, directory dedup/copy safety.
- `IdentityManagerTest` — persistence, caching, rotation, corrupt seed.
- `CryptoTest` / `PacketCryptoTest` — facade sign/verify/seal/open, header
  binding, domain separation.

## Known limitations (documented, not hidden)

- Static channel key: no forward secrecy, no ratchet, no rekeying or member
  revocation in this phase.
- Same-epoch packets from one sender are linkable (needed for routing).
  Cross-epoch linkage is prevented for outsiders; BLE MAC rotation is the
  transport layer's job.
- Ed25519 seed is software-held, wrapped by a hardware Keystore AES key.
- Argon2 defaults (t=3, 32 MiB, p=2) are above OWASP minimums but not yet
  benchmarked on the target phones.
- Replay cache is bounded; evicted IDs can be replayed only inside the
  timestamp window, which is the accepted MVP trade-off.
