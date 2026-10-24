# Interfaces (Phase 0 contract)

These interfaces are the only cross-module API. Modules must not reach into
another module's implementation classes. The Kotlin source files are the source
of truth; this document explains the semantics.

| Module | Contract file |
|---|---|
| `:audio` | `audio/src/main/java/com/solar23040/bitaudio/audio/AudioCodec.kt` |
| `:transport` | `transport/src/main/java/com/solar23040/bitaudio/transport/Transport.kt` |
| `:transport` (fake) | `transport/src/main/java/com/solar23040/bitaudio/transport/FakeTransport.kt` |
| `:mesh` | `mesh/src/main/java/com/solar23040/bitaudio/mesh/Mesh.kt` |
| `:crypto` | `crypto/src/main/java/com/solar23040/bitaudio/crypto/Crypto.kt` |

Module graph:

```
:app  ->  :audio  :transport  :mesh  :crypto
:mesh ->  :transport  :crypto
:sim  ->  :transport  :mesh  :crypto
```

`:audio`, `:transport`, and `:crypto` have no project dependencies. `:mesh`
depends on `:transport` and `:crypto`. `:sim` is test-only until Phase 1.

## Audio

```kotlin
interface AudioCodec {
    fun encode(pcm: ShortArray): ByteArray
    fun decode(encoded: ByteArray): ShortArray
}
```

- PCM is 16 kHz, mono, signed 16-bit.
- One `encode` call produces one self-contained packet or frame sequence that
  `decode` accepts. 20 ms frames, 12 kbps target.
- Clips are capped at 15 s (`AudioConfig.MAX_CLIP_SAMPLES`).
- Encoding/decoding runs on a background audio thread. A codec instance is not
  required to be thread-safe unless its implementation says so.
- Malformed input throws `IllegalArgumentException`; codec failures throw
  `AudioCodecException`.

## Transport

```kotlin
data class Peer(val id: String, val address: String? = null, val rssi: Int? = null)
data class ReceivedFrame(val from: Peer, val bytes: ByteArray)

interface Transport {
    suspend fun send(peer: Peer, bytes: ByteArray)
    fun onReceive(callback: (ReceivedFrame) -> Unit): AutoCloseable
    fun peers(): Flow<List<Peer>>
}
```

- A `Peer.id` identifies a directly connected BLE neighbour. It is not a mesh
  sender ID and has no meaning after the link is gone.
- `send` delivers one complete frame or throws `TransportException`. BLE MTU
  negotiation and link fragmentation happen inside the implementation.
- `onReceive` callbacks run on a transport-owned context, must not block, and
  may be invoked for every valid frame. Closing the handle unregisters it.
- `peers()` emits the current neighbour set on subscription and after changes.
- The transport does not guarantee delivery, ordering, or deduplication.

### FakeNetwork / FakeTransport

`FakeNetwork` is an in-memory implementation for tests and the simulator:

```kotlin
val network = FakeNetwork(
    defaultLink = LinkConfig(lossRate = 0.10, latencyMs = 20L..200L),
    seed = 42,
)
val a = network.addNode("a")
val b = network.addNode("b")
network.connect(a, b)          // or a.connectTo(b, LinkConfig(...))
a.send(Peer("b"), bytes)
network.disconnect("a", "b")
network.removeNode("b")        // node killed
```

- Latency suspends the sender; loss silently drops the frame.
- Callback exceptions are contained so one bad test consumer cannot kill the
  simulated network.
- The topology is symmetric and the network is thread-safe.
- Use `runTest` in unit tests; latency uses virtual time.

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
    val messageId: String,
    val senderId: String,
    val timestampMs: Long,
    val hopCount: Int,
    val payload: ByteArray,
)

interface Mesh {
    suspend fun publish(channel: ChannelId, payload: ByteArray)
    fun onMessage(callback: (MeshMessage) -> Unit): AutoCloseable
}
```

- `publish` takes plaintext Opus bytes. The mesh implementation seals, signs,
  chunks, and floods them; `onMessage` emits plaintext only after reassembly,
  signature verification, and successful decryption.
- `messageId` and `senderId` are 16 lowercase hex characters.
- `onMessage` callbacks run on a mesh-owned context, must not block, and may run
  concurrently. Close the handle to unsubscribe.
- The mesh implementation owns TTL, dedup, jitter, reassembly, and the
  store-and-forward queue. It is constructed with a `Transport`, a `Crypto`,
  and a channel/signing-key store.
- Unknown channel, invalid packet, or failed authentication: drop silently.
  `MeshException` is only for local operational failures (for example storage
  full).

Wire format: [`packet-format.md`](packet-format.md).

## Crypto

```kotlin
class ChannelKey(bytes: ByteArray)          // 32 bytes, redacted toString
data class SealedPayload(val nonce: ByteArray, val ciphertext: ByteArray)

fun interface SignerResolver {
    fun resolve(channelId: ByteArray, senderId: ByteArray, timestampMs: Long): ByteArray?
}

interface Crypto {
    fun identityPublicKey(): ByteArray
    fun sign(payload: ByteArray): ByteArray
    fun verify(payload: ByteArray, signature: ByteArray, signerPublicKey: ByteArray): Boolean
    fun seal(channelKey: ChannelKey, plaintext: ByteArray, aad: ByteArray = ByteArray(0)): SealedPayload
    fun open(channelKey: ChannelKey, sealed: SealedPayload, aad: ByteArray = ByteArray(0)): ByteArray?
    fun deriveChannelKey(passphrase: CharArray, salt: ByteArray): ChannelKey
    fun channelId(channelKey: ChannelKey): ByteArray
    fun senderId(channelKey: ChannelKey, timestampMs: Long): ByteArray
}
```

- Identity is a per-install Ed25519 keypair. The private key stays in Android
  Keystore when the device supports it. `identityPublicKey()` returns 32 bytes.
- `sign` uses Ed25519 and returns 64 bytes. `verify` returns `false` for bad
  input; it never throws for attacker-controlled data.
- `seal` uses XChaCha20-Poly1305 with a fresh 24-byte nonce and returns the
  24-byte nonce plus ciphertext-with-16-byte-tag. `open` returns `null` on any
  authentication failure.
- `deriveChannelKey` uses Argon2id over the UTF-8 passphrase and a caller-held
  salt (at least 16 bytes). A QR invite may carry an already-random 32-byte key
  instead; construct `ChannelKey` directly in that case.
- `channelId` and `senderId` implement the derivations in the packet format
  document. `senderId` rotates every 15 minutes, but the Ed25519 signing key is
  stable.
- `SignerResolver` is the bridge between an 8-byte `sender_id` and the stable
  Ed25519 public key. It is backed by the channel roster and must check the
  current and previous epoch. Receivers must not accept packets from keys that
  are absent from the roster.
- Do not log keys, plaintext, passphrases, or `SealedPayload` contents.

## Ownership and integration rules

1. A module owns its public types and implementation. Cross-module needs go
   through the interfaces above or through Agent A.
2. Byte arrays are caller-owned at call boundaries. Implementations that retain
   input must copy it; callers may reuse buffers after the call returns.
3. IDs on the wire are big-endian. Kotlin `ByteArray` values are treated as
   unsigned bytes.
4. Long operations run off the main thread. Public callbacks must be safe to
   invoke from a background dispatcher and must not block.
5. Expected peer input (packets, frames, QR payloads) is untrusted. Validate
   sizes and ranges before allocating buffers. Never crash on bad input.
6. Any interface change is made by Agent A, documented here, and announced
   before dependent modules update.

## Phase 0 acceptance

- [x] Six Gradle modules exist and compile in CI.
- [x] Audio, transport, mesh, and crypto contracts are present.
- [x] `FakeNetwork` / `FakeTransport` support loss, latency, topology changes,
      and node removal.
- [x] CI runs unit tests, lint, `assembleDebug`, and uploads the APK.
- [ ] First green CI run on GitHub Actions (see README).
