# Interfaces (Phase 0 contract)

These are the only cross-module APIs. The Kotlin source is authoritative; this
document records ownership and semantics. Modules must not depend on another
module's implementation classes.

| Module | Package | Contract |
|---|---|---|
| `:audio` | `com.meshvoice.audio` | `AudioCodec`, `AudioConfig`, `OpusClipCodec`, `EncodedAudioClip` |
| `:transport` | `com.meshvoice.transport` | `Transport`, `Peer`, `BleTransport`, `FakeNetwork` |
| `:mesh` | `com.solar23040.bitaudio.mesh` | `Mesh`, `ChannelId`, `MeshMessage` |
| `:crypto` | `com.bitaudio.crypto` | `Crypto`, `DefaultCrypto`, `ChannelKeys`, `RotatingSenderId`, `PacketCrypto` |
| `:app` | `com.solar23040.bitaudio` | app shell only, no new cross-module APIs |
| `:sim` | `com.solar23040.bitaudio.sim` | tests/simulator only |

Dependency graph:

```
:app  ->  :audio  :transport  :mesh  :crypto
:mesh ->  :transport  :crypto
:sim  ->  :transport  :mesh  :crypto
:audio, :transport, :crypto -> no project dependencies
```

The package prefixes differ because agents picked them before Phase 0 was
merged. They are frozen for Phase 0/1; a single-root rename is a Phase 2 task.

## Audio

```kotlin
interface AudioCodec : AutoCloseable {
    fun encode(pcm: ShortArray): ByteArray
    fun decode(packet: ByteArray): ShortArray
}

class OpusClipCodec {
    fun encode(pcm: ShortArray): EncodedAudioClip
    fun decode(clip: EncodedAudioClip): ShortArray
    fun payloadFor(pcm: ShortArray): ByteArray
    fun decodePayload(payload: ByteArray): ShortArray
}

class VoiceRecorder : AutoCloseable { fun start(); fun stop(): Recording?; fun cancel() }
class ClipPlayer : AutoCloseable { fun play(clip: EncodedAudioClip); fun stop() }
```

- PCM is 16 kHz, mono, signed 16-bit. One `AudioCodec.encode` call consumes
  exactly one 20 ms frame (`AudioConfig.FRAME_SAMPLES`); one `decode` call
  consumes one Opus packet. Codec instances are stateful and not shared between
  encoder and decoder streams.
- `OpusClipCodec` splits a whole clip into frames, zero-pads only the last frame,
  and records the exact `sampleCount` so playback trims the padding.
- Hard cap: 15 s (`AudioConfig.MAX_CLIP_SAMPLES`). Target bitrate 12 kbps.
- `EncodedAudioClip.toPayload()` is the opaque plaintext handed to `Mesh`:
  little-endian `version(1) | codec(1) | frameCount(2) | sampleCount(4) |
  (frameLength(2) | opusPacket)*`. `fromPayload` validates every length and
  rejects trailing bytes.
- Capture/playback block on worker threads. Android-specific classes throw
  `AudioException`; malformed payloads throw `IllegalArgumentException`.
- Ownership: `EncodedAudioClip` copies its frames; payload arrays are fresh.

`FakeNetwork` is not used by audio. Audio tests use the real desktop libopus via
LWJGL on the JVM.

## Transport

```kotlin
data class Peer(
    val id: String,
    val address: String? = null,
    val rssi: Int? = null,
)

data class ReceivedFrame(val from: Peer, val bytes: ByteArray)

class TransportException(message: String, cause: Throwable? = null) : Exception(message, cause)

interface Transport {
    suspend fun send(peer: Peer, bytes: ByteArray)
    fun onReceive(callback: (ReceivedFrame) -> Unit): AutoCloseable
    fun peers(): Flow<List<Peer>>
}
```

- `Peer.id` identifies the direct link for as long as it exists. It is not a
  mesh identity. `address` is the BLE MAC when known (Android may rotate it) and
  may be null for simulated peers.
- `send` hands one complete frame to one neighbour and suspends while the link
  is established. It throws `TransportException` when the transport is stopped,
  the payload exceeds the link limit, or the connection cannot be made. The
  caller keeps ownership of `bytes`. One frame is delivered whole or not at
  all; link fragmentation is internal.
- `onReceive` registers a callback and returns a handle; close it to
  unsubscribe. Callbacks run on a transport-owned coroutine context and must
  not block. The callback receives the neighbour and the complete reassembled
  frame.
- `peers()` emits the current neighbour set on subscription and after every
  topology change. It is only a link view: entries can disappear or fail, so
  callers must tolerate a failed `send`.
- `BleTransport` owns advertising, scanning, GATT server/client, MTU 247,
  write-without-response, selective acks, retransmission, and reconnect. The
  app calls `start()` after permissions and `close()` when its service stops.

### FakeNetwork / FakeTransport

Same package, used by tests and the simulator:

```kotlin
val network = FakeNetwork(
    defaultLink = LinkConfig(lossRate = 0.10, latencyMs = 20L..200L),
    seed = 42,
    externalScope = backgroundScope,   // in runTest; keeps virtual time deterministic
)
val a = network.addNode("a")
val b = network.addNode("b")
network.connect(a, b)
a.send(Peer("b"), bytes)               // suspends for the sampled latency
val handle = b.onReceive { frame -> /* frame.from.id, frame.bytes */ }
handle.close()
network.snapshot("a")                  // current neighbours, sorted
network.disconnect("a", "b")
network.removeNode("b")
network.close()                       // only cancels a scope it created
```

- `send` suspends for the sampled latency and then delivers to every registered
  receiver. Loss is a silent drop. Each delivery gets a copied byte array.
- `peers()` is a `StateFlow<List<Peer>>` of the current neighbours, so the list
  is always the live topology. `FakeNetwork.snapshot(node)` returns the same set
  as a list for non-suspending assertions.
- `onReceive` supports multiple independent callbacks; each handle removes only
  its own callback. Callback exceptions are contained so one bad consumer
  cannot stop the network.
- The topology is symmetric and thread-safe. A node or link can be removed at
  any time.

## Mesh

```kotlin
@JvmInline
value class ChannelId private constructor(val hex: String) {
    fun toBytes(): ByteArray
    companion object {
        fun fromHex(value: String): ChannelId
        fun fromBytes(bytes: ByteArray): ChannelId
    }
}

data class MeshMessage(
    val channel: ChannelId,
    val messageId: String,    // 16 lowercase hex chars
    val senderId: String,     // 16 lowercase hex chars, rotates
    val timestampMs: Long,
    val hopCount: Int,
    val payload: ByteArray,   // EncodedAudioClip.toPayload()
    val senderFingerprint: String = "", // 6 hex chars, empty if unknown
)

data class NearbyPeer(
    val fingerprint: String,
    val nickname: String,
    val rssi: Int?,
    val hopCount: Int,
    val lastSeenMs: Long,
    val capabilities: Int,
) {
    val isDirect: Boolean
}

interface Mesh {
    suspend fun publish(channel: ChannelId, payload: ByteArray)
    fun onMessage(callback: (MeshMessage) -> Unit): AutoCloseable
}

class MeshEngine(...) : Mesh {
    fun peers(): StateFlow<List<NearbyPeer>>  // nearby discovery
}
```

- `publish` takes one plaintext audio payload (the `EncodedAudioClip` blob) and
  returns after the first hop is queued. It seals each chunk, signs every packet,
  stores the message for retry, and floods it with a TTL.
- `onMessage` emits plaintext only after reassembly, signature verification, and
  AEAD open succeed. Callbacks may run concurrently and must not block. Close the
  handle to unsubscribe.
- The mesh implementation owns TTL, seen-ID caches, jitter, reassembly,
  store-and-forward persistence, and retry policy. It is constructed with a
  `Transport`, a `Crypto`, and per-channel key/roster state.
- Invalid, unauthenticated, expired, or wrong-channel packets are dropped
  silently. `MeshException` is only for local failures (unknown channel, storage
  full).
- `MeshEngine` always adds the public `NearbyChannel`. Discoverable nodes send
  `MEMBER_ANNOUNCE` (nickname + identity key) on peer connect and every
  `announceIntervalMs`; `peers()` exposes live peers sorted direct-first, with
  `hopCount = 1` for a neighbour and `2` for one relay. Muted/blocked policy is
  app-local and never changes the mesh.
- `MeshMessage.senderFingerprint` is `SHA-256(sender identity key)[0..3]` as
  lowercase hex, empty only when no stable identity could be resolved.
- Wire format and limits: [`packet-format.md`](packet-format.md).

## Crypto

```kotlin
interface Crypto {
    fun sign(data: ByteArray): ByteArray
    fun verify(senderPublicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean
    fun seal(channelKey: ByteArray, plaintext: ByteArray, associatedData: ByteArray): ByteArray
    fun open(channelKey: ByteArray, sealed: ByteArray, associatedData: ByteArray): ByteArray?
}

class DefaultCrypto(identityManager: IdentityManager) : Crypto {
    val publicKey: ByteArray
    val fingerprint: String
}

object Ed25519
object XChaCha20Poly1305
object ChannelKeys
object RotatingSenderId
object NearbyChannel
object IdentityFingerprint
class PeerDirectory
class ReplayGuard
class IdentityManager(store: SecretStore)
interface SecretStore
class AndroidKeystoreSecretStore(context: Context) : SecretStore
class InMemorySecretStore : SecretStore
object PacketCrypto
```

- Identity is a per-install Ed25519 keypair stored as a 32-byte seed. Android
  uses an AES-GCM key in AndroidKeyStore to encrypt the seed file; the Ed25519
  operations themselves are software (BouncyCastle). `DefaultCrypto.publicKey`
  is the stable 32-byte identity key.
- `sign` returns 64 bytes. `verify` returns false for malformed keys or
  signatures and never throws on attacker input.
- `seal` uses XChaCha20-Poly1305 with a fresh 24-byte nonce and returns
  `nonce(24) || ciphertext || tag(16)`. `open` returns null on any failure.
- `ChannelKeys.generate()` creates a random 32-byte channel key for QR invites.
  `ChannelKeys.fromPassphrase` uses Argon2id (32 MiB, 3 iterations, 2 lanes by
  default) and a 16-byte salt. `ChannelKeys.channelId` returns the 8-byte public
  channel ID. Keys are byte arrays; never log them.
- `RotatingSenderId` derives the 8-byte `sender_id` per 15-minute epoch.
  `PeerDirectory` holds the channel roster and resolves an ID back to a stable
  Ed25519 key, checking adjacent epochs. The nearby channel has no roster:
  members resolve senders from verified `MEMBER_ANNOUNCE` records instead.
- `NearbyChannel` exposes the well-known public key and channel ID. Its payloads
  are signed, not secret.
- `IdentityFingerprint.of(publicKey)` returns the first 3 bytes of
  `SHA-256(publicKey)` as 6 lowercase hex characters; never treat it as a
  secret.
- `ReplayGuard` checks timestamp, message ID, and an optional 64-bit sliding
  counter window. Mesh owns the actual cache retention (see packet format).
- `PacketCrypto` is the single definition of the signing transcript and AEAD
  AAD. Mesh must use it rather than building byte arrays itself.

## Ownership and integration rules

1. A module owns its public types and implementation. Cross-module changes go
   through Agent A.
2. Byte arrays are caller-owned at call boundaries. Implementations that retain
   input copy it; callers may reuse buffers after the call returns.
3. On-wire integers are big-endian unless a layout explicitly says otherwise
   (the audio payload header is little-endian).
4. Long operations run off the main thread. Public callbacks must be safe on a
   background dispatcher and must not block.
5. All peer input is untrusted. Validate sizes and ranges before allocating.
   Never crash on malformed packets, frames, payloads, or QR data.
6. Interface changes are made by Agent A, documented here, and announced before
   dependent modules update.

## Phase 0 acceptance

- [x] Six Gradle modules are included in the root build.
- [x] Audio, transport, mesh, and crypto contracts exist and are implemented in
      their own modules.
- [x] `FakeNetwork` / `FakeTransport` support loss, latency, topology changes,
      and node removal.
- [x] CI workflow runs unit tests, lint, `assembleDebug`, and uploads the APK.
- [x] First green CI run on GitHub Actions: run `40125690964` passed unit
      tests, lint, and `assembleDebug` on `agent-a/phase0` (see README badge).
