# Packet format v1

Wire format used by `:mesh`. One voice note is split into chunks; each chunk is
sealed with XChaCha20-Poly1305, signed with Ed25519, and flooded as one packet.
BLE link fragmentation happens below this format and is invisible to the mesh.

All multi-byte integers are **big-endian** and unsigned. IDs are byte strings,
displayed as lowercase hex.

## Header (107 bytes)

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 1 | `version` | `0x01` |
| 1 | 1 | `type` | see packet types |
| 2 | 8 | `msg_id` | random, unique per message |
| 10 | 8 | `channel_id` | public channel identifier |
| 18 | 8 | `sender_id` | rotating pseudonym |
| 26 | 1 | `ttl` | remaining relays; mutable and not signed |
| 27 | 2 | `chunk_idx` | 0-based |
| 29 | 2 | `total_chunks` | number of chunks in this message |
| 31 | 8 | `timestamp_ms` | Unix time in milliseconds |
| 39 | 4 | `counter` | per-message counter, shared by all chunks |
| 43 | 64 | `signature` | Ed25519 over the canonical transcript |
| 107 | 1..405 | `payload` | one sealed chunk (`nonce || ciphertext || tag`) |

The first 43 bytes (everything before the signature) are the **header prefix**.
`canonical_header` is a copy of that prefix with `ttl` (byte 26) set to `0x00`.

Maximum packet size is **512 bytes** (`107 + 405`). The frame boundary is the
packet boundary; there is no length field. Frames shorter than 107 or longer
than 512 bytes are discarded.

## Packet types

| Value | Name | Status |
|---:|---|---|
| `0x01` | `VOICE_DATA` | payload is one sealed chunk of an audio payload |
| `0x02` | `DELIVERY_RECEIPT` | reserved, Phase 2 |
| `0x03` | `MEMBER_ANNOUNCE` | reserved for roster sync, Phase 2 |
| `0x04` | `KEY_ROTATE` | reserved, Phase 5/6 |
| `0x05..0x7F` | control | reserved |
| `0x80..0xFF` | private | never emitted by production code |

Receipts and control messages use the same header, signing, counter, and TTL
rules. Their payload layouts are defined with Phase 2.

## IDs

Channel ID (`ChannelKeys.channelId`):

```
channel_id = SHA-256("bit-audio/channel-id/v1" || channel_key)[0..8]
```

It is public metadata used for filtering and display; it is not a secret.

Rotating sender ID (`RotatingSenderId.derive`):

```
id_key    = HMAC-SHA256(channel_key, "bit-audio/sender-id-key/v1")
epoch     = floor(timestamp_ms / 1000 / 900)                    // 15 minutes
sender_id = HMAC-SHA256(
                id_key,
                "bit-audio/sender-id/v1" || identity_pubkey(32) || epoch_u64
            )[0..8]
```

- The signature uses the stable install identity key; only `sender_id` rotates.
- A receiver resolves `sender_id` against the channel roster
  (`PeerDirectory.resolve`) for the packet's epoch +/- 1, then verifies the
  signature with that public key. Unknown keys are dropped.
- Relays must be channel members and must resolve the signer before forwarding.
- The app must key replay/dedup caches by the **resolved identity**, not by the
  rotating `sender_id`, or a new epoch resets the cache.

## Signing

`PacketCrypto` is the only implementation of this transcript:

```
canonical_header = header_prefix with ttl = 0x00
signing_input    = "bit-audio/packet-sign/v1"
                   || u32be(canonical_header.size)        // 43
                   || canonical_header
                   || sealed_chunk
signature        = Ed25519_sign(identity_key, signing_input)
```

- The wire `header_prefix` has the real `ttl`; zero it before building the
  transcript. All other header bytes are covered, including `channel_id`,
  `chunk_idx`, `total_chunks`, `timestamp_ms`, and `counter`.
- `ttl` is deliberately excluded because relays decrement it. Deduplication and
  the TTL bound contain a malicious node that raises it.
- Relays never re-sign or modify signed fields. They only decrement `ttl`.
- A bad signature is dropped silently before dedup, storage, or forwarding.

## Encryption and chunking

Each chunk is sealed independently (`PacketCrypto.sealPayload`):

```
associated_data = "bit-audio/packet-seal/v1" || canonical_header
sealed_chunk    = nonce(24) || XChaCha20-Poly1305(plaintext_chunk, aad)
```

- The nonce is 24 fresh random bytes per chunk; the tag is 16 bytes. A sealed
  chunk is at least 40 bytes.
- Plaintext chunk size is at most **365 bytes**, so the sealed chunk fits the
  405-byte payload limit.
- All chunks share `msg_id`, `channel_id`, `sender_id`, `timestamp_ms`,
  `counter`, and `total_chunks`. `chunk_idx` and the ciphertext differ.
- The plaintext is the `EncodedAudioClip.toPayload()` blob from `:audio`.
- On receive: verify every chunk, open every chunk with its own header as AAD,
  concatenate plaintext in `chunk_idx` order, then call
  `EncodedAudioClip.fromPayload`. Any mismatch or AEAD failure drops the whole
  message.
- Limits: `total_chunks` must be `1..256`, `chunk_idx < total_chunks`, and the
  reassembled plaintext must be at most **64 KiB**. Reject before allocating.
- Reassembly timeout is 120 seconds and keeps a bounded number of partial
  messages per identity.

Wire cost for a 10 s clip at 12 kbps: about 15,000 bytes of audio payload,
42 chunks of at most 512 bytes -> **at most 21,504 bytes** on the wire
(typically ~21.2 KB). The 20 KB plan target applies to the encoded audio, not
mesh headers.

## Freshness and replay

- Reject `timestamp_ms` more than **120 s in the future**.
- Reject messages older than the **retention window (default 24 h)**.
- A packet older than 120 s is *stale*: deliver it locally if valid, but do not
  rebroadcast it. This lets store-and-forward finish without letting old
  packets circulate.
- Completed messages are cached by `(channel_id, resolved identity, msg_id)` for
  retention. A second delivery is dropped.
- `counter` starts at 1, increments once per published message, and is shared by
  all chunks of that message. It is persisted and never reused for a different
  `msg_id` by the same identity on the same channel.
- Keep `(channel_id, identity, counter) -> msg_id` for retention. A counter that
  maps to a different `msg_id` is a replay and is rejected. Do not apply a hard
  "must be greater than the last counter" rule: store-and-forward and reordering
  legitimately deliver older counters. `highest_counter` is for diagnostics and
  rate limiting only.
- `msg_id` uniqueness plus the retention bound is the primary replay defense.
  A replay to a receiver that never saw the original is indistinguishable from a
  legitimately stored message; Phase 5 documents this trade-off.
- Packet dedup key is `(channel_id, msg_id, chunk_idx)`. Insert it only after
  signature verification (see SEC-001), and expire it with the reassembly
  window.
- `ReplayGuard` is a helper for live traffic. If used, configure its timestamp
  window to match retention and key it by resolved identity; its default
  +/-120 s window must not be applied to stored messages.

## TTL, deduplication, jitter

- Default `ttl = 5`. Accept only `1..8`; `0` or larger values are dropped.
- On a valid packet: deliver locally, then if `ttl > 1` and the packet is not
  stale, rebroadcast a copy with `ttl - 1`. Do not send it back to the ingress
  peer when that peer is known.
- Verify the signature and resolve the channel before inserting into any dedup
  cache.
- Rebroadcast after a random **20..200 ms** jitter to avoid lock-step flooding.
- Rate-limit per neighbour and per resolved sender; drop when the relay queue is
  full instead of blocking the radio.

## Store-and-forward

Persist sealed packets plus minimal routing metadata, never plaintext. Expire
entries after retention (default 24 h), including entries that were never
delivered. On new peer/channel discovery, replay stored packets with their
original signatures, `msg_id`, `counter`, and timestamp; decrement `ttl`
normally and mark them stale so receivers do not re-flood them. Validate the
signature again on dequeue.

## Validation checklist (fuzzing targets)

Reject without crashing or unbounded allocation:

- frame length < 107 or > 512
- `version != 1` or unknown type
- `ttl == 0` or `ttl > 8`
- `total_chunks == 0` or `> 256`
- `chunk_idx >= total_chunks`
- reassembled plaintext > 64 KiB
- signature length != 64 or verification failure
- unknown `channel_id`, unresolved `sender_id`, or signer not in roster
- AEAD failure, AAD mismatch, or sealed chunk < 40 bytes
- duplicate `(channel_id, msg_id, chunk_idx)`
- counter mapped to a different `msg_id`
- timestamp outside the future/retention window

## Versioning

`version` is bumped for any incompatible header change. New packet types may be
added without a version bump; unknown types are ignored. A receiver must never
interpret a later version's packet using v1 rules.
