#!/usr/bin/env python3
"""Print deterministic docs-v1 contract vectors for Agent A/E.

The seeds in the output are **test-only** and intentionally public. They must
never be used for a real identity or channel.

  python contract_vector.py > ../contract-vectors.json
"""

from __future__ import annotations

import json

from nacl.signing import SigningKey

from wire import (
    EPOCH_MS,
    build_voice_message,
    channel_id_for_key,
    parse_packet,
    reassemble,
    sender_id_for_pubkey,
    verify_packet,
)

CHANNEL_KEY = bytes(range(32))
IDENTITY_SEED = bytes(range(32, 64))
TIMESTAMP_MS = 1_700_000_000_000
MSG_ID = bytes.fromhex("0102030405060708")
COUNTER = 42
NONCE = bytes.fromhex("a0" * 24)
PLAINTEXT = (b"bit-audio contract vector v1. " * 20)[:512]


def main() -> int:
    signing_key = SigningKey(IDENTITY_SEED)
    pubkey = signing_key.verify_key.encode()
    _, frames = build_voice_message(
        channel_key=CHANNEL_KEY,
        signing_key=signing_key,
        plaintext=PLAINTEXT,
        timestamp_ms=TIMESTAMP_MS,
        msg_id=MSG_ID,
        counter=COUNTER,
        nonce=NONCE,
    )
    assert reassemble(frames, CHANNEL_KEY) == PLAINTEXT
    first = parse_packet(frames[0])
    assert verify_packet(first, pubkey)

    vector = {
        "note": (
            "Test-only vectors for docs/packet-format.md v1. Seeds are public and "
            "must never be used outside tests. See SEC-016 in security/findings.md."
        ),
        "channel_key_hex": CHANNEL_KEY.hex(),
        "identity_seed_hex": IDENTITY_SEED.hex(),
        "identity_pubkey_hex": pubkey.hex(),
        "message": {
            "timestamp_ms": TIMESTAMP_MS,
            "msg_id_hex": MSG_ID.hex(),
            "counter": COUNTER,
            "nonce_hex": NONCE.hex(),
            "plaintext_hex": PLAINTEXT.hex(),
            "channel_id_hex": channel_id_for_key(CHANNEL_KEY).hex(),
            "sender_id_hex": first.sender_id.hex(),
            "sender_id_next_epoch_hex": sender_id_for_pubkey(
                CHANNEL_KEY, pubkey, TIMESTAMP_MS + EPOCH_MS
            ).hex(),
            "aad_hex": first.aad.hex(),
            "total_chunks": first.total_chunks,
            "ttl": first.ttl,
            "type": first.type,
            "version": first.version,
        },
        "frames": [
            {
                "chunk_idx": packet.chunk_idx,
                "payload_hex": packet.payload.hex(),
                "signing_input_hex": packet.signing_input.hex(),
                "signature_hex": packet.signature.hex(),
                "frame_hex": packet.to_bytes().hex(),
            }
            for packet in (parse_packet(frame) for frame in frames)
        ],
    }
    print(json.dumps(vector, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
