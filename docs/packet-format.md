# Packet format v1

Wire format used by `:mesh`. It is deliberately small: one voice note is
encrypted once, split into independently signed chunks, and flooded as packets.
Transport-level BLE fragmentation happens below this format and is invisible to
the mesh.

All multi-byte integers are **big-endian** and unsigned. IDs are byte strings,
displayed as lowercase hex.

## Header (107 bytes)

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 1 | `version` | `0x01` |
| 1 | 1 | `type` | see packet types |
| 2 | 8 | `msg_id` | random, unique per message |
| 10 | 8 | `channel_id` | derived from channel key, see below |
| 18 | 8 | `sender_id` | rotating pseudonym, see below |
| 26 | 1 | `ttl` | remaining relays, mutable |
| 27 | 2 | `chunk_idx` | 0-based |
| 29 | 2 | `total_chunks` | number of chunks in this message |
| 31 | 8 | `timestamp_ms` | Unix time in milliseconds |
| 39 | 4 | `counter` | per-identity message counter |
| 43 | 64 | `signature` | Ed25519 over the message |
| 107 | 0..405 | `payload` | sealed-message fragment |

Maximum packet size is **512 bytes** (`107 + 405`). The frame boundary is the
packet boundary; there is no length field. A received frame shorter than 107
bytes, or longer than 512, is discarded.

## Packet types

| Value | Name | Status |
|---:|---|---|
| `0x01` | `VOICE_DATA` | payload is a fragment of a sealed voice message |
| `0x02` | `DELIVERY_RECEIPT` | reserved, Phase 2 |
| `0x03` | `MEMBER_ANNOUNCE` | reserved for roster sync, Phase 2 |
| `0x04` | `KEY_ROTATE` | reserved, Phase 5/6 |
| `0x05..0x7F` | control | reserved |
| `0x80..0xFF` | private | never emitted by production code |

Receipts and control messages use the same header, signing, counter, and TTL
rules. Their payload layout is defined with Phase 2.

## Channel ID

```
channel_id = HMAC-SHA256(channel_key, "bit-audio/channel-id/v1")[0..8]
```

`channel_id` is public metadata. It lets relays filter channels and lets the app
show a stable channel identifier without exposing the key. It is not a secret.

## Sender ID (rotating pseudonym)

```
epoch       = floor(timestamp_ms / 900000)          // 15 minutes
sender_id   = HMAC-SHA256(
                  channel_key,
                  "bit-audio/sender-id/v1" || identity_pubkey(32) || epoch_be64
              )[0..8]
```

- `identity_pubkey` is the install's stable 32-byte Ed25519 public key.
- The signature is made with that stable identity key; only the displayed
  `sender_id` rotates. A passive sniffer cannot link two epochs without the
  channel key.
- A receiver resolves `sender_id` to a roster public key by computing the ID for
  the packet's epoch and the previous epoch (handles rotation boundaries and
  clock skew). Unknown keys are dropped.
- Channel membership and the roster are established when joining; roster sync
  uses `MEMBER_ANNOUNCE` in Phase 2. A relay must be a channel member and must
  resolve the signer before forwarding.

## Signing

Each packet is signed independently so relays can verify before forwarding or
storing:

```
transcript = header[0..106] with ttl (byte 26) and signature (bytes 43..106)
             set to 0x00, followed by payload
signature  = Ed25519_sign(identity_private_key, transcript)
```

- `ttl` is excluded because every relay decrements it. Deduplication and the
  maximum TTL bound contain a malicious node that raises it.
- `signature` is excluded because it is the output.
- Verification must use the roster key resolved from `sender_id` and
  `timestamp_ms`. A signature that does not verify causes a silent drop.
- Relays never re-sign or modify signed fields. They only decrement `ttl` and
  rebroadcast the packet unchanged.

## Encryption and chunking

A voice payload is sealed **once per message**:

```
sealed = nonce(24) || XChaCha20-Poly1305_ciphertext_and_tag(opus_plaintext)
aad    = channel_id(8) || msg_id(8) || timestamp_ms_u64(8) || counter_u32(4)

packet_payload[i] = sealed[i * 405 .. min((i + 1) * 405, sealed.size)]
total_chunks      = ceil(sealed.size / 405)
chunk_idx         = 0 .. total_chunks - 1
```

- Nonce is 24 random bytes. Tag is 16 bytes. `sealed.size` is at least 40.
- All chunks of a message share `msg_id`, `channel_id`, `sender_id`,
  `timestamp_ms`, `counter`, and `total_chunks`.
- The receiver concatenates payloads in `chunk_idx` order, then calls `open`
  with the same AAD.
- If any chunk has a mismatched shared field, drop the whole message.
- Limits: `total_chunks` must be `1..162`, `chunk_idx < total_chunks`, and the
  reassembled sealed blob must be at most 64 KiB. Reject before allocating.
- Reassembly times out after 120 seconds and keeps at most a bounded number of
  partial messages per sender.

Wire cost for a 10 s clip at 12 kbps: about 15,000 bytes of Opus, 15,040 bytes
sealed, 38 chunks, 38 x 107 header bytes -> **19,106 bytes** total, under 20 KB.

## Anti-replay and freshness

- Sender timestamps more than **5 minutes in the future** are rejected.
- Sender timestamps older than the **retention window (default 24 h)** are
  rejected. Store-and-forward must not hold packets longer than retention.
- `msg_id` is unique per message. Completed messages are cached per channel for
  the retention window; a second delivery is dropped.
- `counter` starts at 1 on first install and increments once per published
  message (voice, receipt, or control), across channels. It is persisted and
  never reused for a different `msg_id`.
- Receivers cache `(channel_id, resolved identity, counter) -> msg_id` for the
  retention window. Reusing a counter for a different message is rejected.
  `highest_counter` is tracked for diagnostics and rate limiting.
- A hard "counter must be greater than the last seen" rule would break
  store-and-forward and reordered packets. Late messages are therefore accepted
  if their `msg_id` was never delivered and their timestamp is inside retention.
  Phase 5 reviews this trade-off; duplicate delivery is still prevented.
- Per-sender and per-neighbour rate limits belong to the transport/mesh and are
  part of the Phase 5 hardening.

## TTL, deduplication, jitter

- Default `ttl = 5`. Accept only `1..16`; `0` or larger values are dropped.
- On receiving a valid packet: deliver locally, then if `ttl > 1` rebroadcast a
  copy with `ttl - 1`. Never forward back to the ingress peer when that peer is
  known.
- Packet dedup key: `(channel_id, msg_id, chunk_idx)`. Keep it for at least the
  reassembly timeout; `msg_id` message dedup is kept for retention.
- Rebroadcast after a random **20..200 ms** jitter to avoid lock-step flooding.
- Relays verify signature and channel membership before forwarding. Invalid
  packets are dropped silently and never stored.

## Store-and-forward

Undelivered, verified messages may be persisted. Persist the sealed bytes and
packet metadata, not plaintext, so a stolen database does not expose voice
notes. Expire entries after retention (default 24 h). On a new peer or channel
member appearing, replay the stored packets with their original signatures,
`msg_id`, `counter`, and timestamp; decrement `ttl` normally. Expired entries
must be deleted even if never delivered.

## Validation checklist (fuzzing targets)

Reject, without crashing or unbounded allocation:

- frame length < 107 or > 512
- `version != 1` or unknown type
- `ttl == 0` or `ttl > 16`
- `total_chunks == 0` or `> 162`
- `chunk_idx >= total_chunks`
- reassembled size > 64 KiB
- signature length != 64 or verification failure
- unknown `channel_id`, unknown `sender_id`, or unresolved roster key
- AEAD failure, AAD mismatch, or malformed sealed blob (< 40 bytes)
- duplicate `(channel_id, msg_id, chunk_idx)`
- counter reuse with a different `msg_id`
- timestamp outside the future-skew or retention window

## Versioning

`version` is bumped for any incompatible header change. New packet types may be
added without a version bump; unknown types are ignored. A receiver must never
interpret a later version's packet using v1 rules.
