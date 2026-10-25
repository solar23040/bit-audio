# `:crypto` — Agent E (Phase 1)

Crypto module for Mesh Voice Notes. Pure-Kotlin API over BouncyCastle
primitives; no Android dependencies except the Keystore-backed secret store, so
all logic runs in JVM unit tests.

Status: **source + tests written, not compiled locally** (project rule: no local
Gradle). The workspace now has the Phase 0 project and CI workflow; this module
still needs its first green GitHub Actions run (`./gradlew :crypto:test`).

## Implemented (Phase 1 checklist)

| Plan item | Where |
|---|---|
| Ed25519 identity per install + Keystore-protected seed | `Ed25519.kt`, `Identity.kt`, `IdentityStore.kt`, `AndroidKeystoreSecretStore.kt` |
| Packet signing / verification | `Crypto.kt`, `PacketCrypto.kt` |
| Argon2id channel key, XChaCha20-Poly1305 AEAD | `ChannelKeys.kt`, `XChaCha20Poly1305.kt`, `HChaCha20.kt` |
| Anti-replay: freshness, message IDs, counter reuse | `ReplayGuard.kt` |
| Rotating ephemeral sender IDs | `RotatingSenderId.kt`, `PeerDirectory` |

The public interface matches `docs/interfaces.md`:

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

One: `org.bouncycastle:bcprov-jdk18on` via `libs.bouncycastle` (version in
`gradle/libs.versions.toml`). It is used through the low-level API only and is
never installed as a JCA provider, so it cannot collide with Android's built-in
`BC` provider.

## Wire formats (from `docs/packet-format.md`)

- **Packet header:** 107 bytes; the first 43 bytes are the header prefix.
- **Signing input:**
  `"bit-audio/packet-sign/v1" || u32be(43) || canonical_header || sealed_chunk`,
  where `canonical_header` is the prefix with `ttl` (offset 26) zeroed.
  `PacketCrypto.signingBytes()` is the only implementation.
- **AEAD associated data:**
  `"bit-audio/packet-seal/v1" || canonical_header`.
- **Sealed chunk:** `nonce(24) || ciphertext || tag(16)`, XChaCha20-Poly1305,
  fresh random nonce per chunk. Max plaintext chunk is 365 bytes so the sealed
  chunk fits the 405-byte payload limit.
- **Channel ID:** `SHA-256("bit-audio/channel-id/v1" || channel_key)[0..8]`.
- **Sender ID:**
  `id_key = HMAC-SHA256(channel_key, "bit-audio/sender-id-key/v1")`;
  `epoch = floor(timestamp_ms / 900000)`;
  `sender_id = HMAC-SHA256(id_key, "bit-audio/sender-id/v1" || pubkey || epoch_u64)[0..8]`.
  `PeerDirectory.resolve()` checks the packet's epoch and +/- one epoch.

`ChannelKeys.generate()` creates a random 32-byte key for QR invites;
`ChannelKeys.fromPassphrase()` uses Argon2id (32 MiB, 3 passes, 2 lanes) with a
salt of at least 16 bytes.

## Key / identity storage

- Ed25519 is software (BouncyCastle) so it works below API 33, where
  AndroidKeyStore has no Ed25519 support.
- `AndroidKeystoreSecretStore` encrypts the 32-byte seed with AES-256-GCM under
  a non-exportable AndroidKeyStore key and stores it in `noBackupFilesDir`.
  The seed is not backed up or restorable onto another phone.
- `IdentityManager.rotate()` creates and persists a new identity; wire it to the
  Settings screen.
- `InMemorySecretStore` is for tests/previews only.

## Replay protection

`ReplayGuard.check(channelId, identityPublicKey, messageId, counter, timestampMs)`
implements the packet-format rules:

- future timestamps beyond 120 s are rejected;
- timestamps older than retention (default 24 h) are rejected;
- completed `(channel_id, identity, msg_id)` are cached; repeats return `REPLAY`;
- `(channel_id, identity, counter) -> msg_id` is cached; reuse for another
  message returns `COUNTER_REUSED`;
- late counters are accepted when their message ID is new (store-and-forward and
  mesh reordering), so there is no monotonic-counter rule;
- `isStale()` marks packets older than 120 s for "deliver locally, do not
  rebroadcast"; it is not a rejection.

Key the guard by the **resolved Ed25519 identity**, not by the rotating
`sender_id`, otherwise each epoch resets the cache. The guard is bounded and
mesh owns persistence and its own per-chunk dedup keys.

Note: `docs/interfaces.md` still says "optional 64-bit sliding counter window".
That sentence is stale; `docs/packet-format.md` explicitly forbids a monotonic
window. `ReplayGuard` follows the packet format. Agent A should update the
summary sentence.

## Integration sketch (`:mesh`, Agent D)

Send one chunk:

```kotlin
val headerPrefix = encodeHeaderPrefixWithoutSignature(...)   // exactly 43 bytes, real ttl
val sealedChunk = PacketCrypto.sealPayload(crypto, channelKey, headerPrefix, plaintextChunk)
val signature = PacketCrypto.signPacket(crypto, headerPrefix, sealedChunk)
transport.send(peer, encodePacket(headerPrefix, signature, sealedChunk))
```

Receive (drop silently on any failure):

```kotlin
if (frame.size !in 107..512) return DROP
val headerPrefix = frame.copyOfRange(0, 43)
val sealedChunk = frame.copyOfRange(107, frame.size)
val signature = frame.copyOfRange(43, 107)

val sender = directory.resolve(channelKey, header.senderId, header.timestampMs) ?: return DROP
if (!PacketCrypto.verifyPacket(crypto, sender, headerPrefix, sealedChunk, signature)) return DROP
if (replayGuard.check(channelId, sender, header.msgId, header.counter, header.timestampMs) != ACCEPT) return DROP
val plaintext = PacketCrypto.openPayload(crypto, channelKey, headerPrefix, sealedChunk) ?: return DROP
```

Do the cheap length/version/TTL checks and timestamp check before signature
work. `ttl` is not signed; relays may change it without invalidating the
signature or AAD.

## Tests

Run on CI: `./gradlew :crypto:test`.

- `Ed25519Test` — RFC 8032 §7.1 vectors 1–3, tampering, malformed sizes.
- `XChaCha20Poly1305Test` — HChaCha20 vector §2.2.1, AEAD vector A.3.1,
  round-trip, wrong key/AAD/ciphertext, truncation, nonce freshness.
- `Argon2Test` — RFC 9106 Argon2id vector, salt dependence, output length,
  input validation, QR key copy, channel-ID known-answer vector.
- `PacketCryptoTest` — pinned transcript/AAD SHA-256, TTL canonicalisation,
  every non-TTL header byte covered, per-chunk size budget, signature/AAD
  tampering, malformed header rejection.
- `ReplayGuardTest` — duplicates, counter reuse, late counters, future/expired
  windows, malformed input, channel/identity isolation, stale helper, bounded
  cache.
- `RotatingSenderIdTest` — sender-ID known-answer vector, epoch rotation,
  channel scoping, roster resolution with skew.
- `IdentityManagerTest` / `CryptoTest` — identity persistence/rotation and the
  facade sign/verify/seal/open path.

## Known limitations

- Static channel key: no forward secrecy, no ratchet, no rekeying or member
  revocation in this phase.
- Same-epoch packets from one sender are linkable (needed for routing).
- Ed25519 seed is software-held, wrapped at rest by a hardware Keystore AES key.
- Argon2 defaults are above OWASP minimums but not benchmarked on target phones;
  run the benchmark before lowering them.
- The replay cache is bounded; evicted IDs can be replayed until their timestamp
  leaves retention. This is the documented MVP trade-off.

## Contract notes for Agent A

- `docs/interfaces.md` intro says the Kotlin source is authoritative. The
  authoritative module package is `com.bitaudio.crypto` per `AGENTS.md`.
- The stale "sliding counter window" sentence in `docs/interfaces.md` should be
  replaced with the counter→message-ID mapping from `docs/packet-format.md`.
- `security/contract-vectors.json` and `security/attack-tests/wire.py` still
  encode the pre-revision transcript/AAD, HMAC channel ID and one-level sender
  ID. Agent H should regenerate them from the current packet format before
  integration tests.
- `security/findings.md` SEC-016 and its "minimum 8 bytes" salt row describe
  the old code; both are stale.
- `app/README.md` still mentions `Crypto.channelId(ChannelKey)` and app
  `ChannelIdCodec` uses SHA-256, which matches the current packet format. No
  crypto change needed.
