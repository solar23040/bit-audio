#!/usr/bin/env python3
"""Deterministic contract vectors for ``docs/packet-format.md`` v1.

The seeds below are **test-only and public**. Never use them for a real
identity or channel.

  python contract_vector.py            # print the vector JSON
  python contract_vector.py --check    # rebuild and compare to the committed file
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from nacl.signing import SigningKey

from wire import (
    MAX_PLAINTEXT_CHUNK,
    TYPE_VOICE_DATA,
    PROTOCOL_VERSION,
    build_voice_message,
    channel_id_for_key,
    epoch_for,
    parse_packet,
    reassemble,
    sender_id_for_pubkey,
    verify_packet,
)

VECTOR_PATH = Path(__file__).resolve().parent.parent / "contract-vectors.json"

CHANNEL_KEY = bytes(range(32))
IDENTITY_SEED = bytes(range(32, 64))
TIMESTAMP_MS = 1_700_000_000_000
MSG_ID = bytes.fromhex("0102030405060708")
COUNTER = 42
TTL = 5
PLAINTEXT = (b"bit-audio contract vector v1. " * 20)[:512]
NONCES = [bytes([0xA0 + index]) * 24 for index in range(2)]


def build_vector() -> dict[str, object]:
    signing_key = SigningKey(IDENTITY_SEED)
    pubkey = signing_key.verify_key.encode()
    _, frames = build_voice_message(
        channel_key=CHANNEL_KEY,
        signing_key=signing_key,
        plaintext=PLAINTEXT,
        chunk_size=MAX_PLAINTEXT_CHUNK,
        ttl=TTL,
        timestamp_ms=TIMESTAMP_MS,
        msg_id=MSG_ID,
        counter=COUNTER,
        nonces=NONCES,
    )
    assert reassemble(frames, CHANNEL_KEY, signer_public_key=pubkey) == PLAINTEXT
    packets = [parse_packet(frame) for frame in frames]
    assert all(verify_packet(packet, pubkey) for packet in packets)

    return {
        "note": (
            "Test-only vectors for docs/packet-format.md v1. Seeds are public and "
            "must never be used outside tests. See SEC-016 in security/findings.md."
        ),
        "protocol_version": PROTOCOL_VERSION,
        "channel_key_hex": CHANNEL_KEY.hex(),
        "identity_seed_hex": IDENTITY_SEED.hex(),
        "identity_pubkey_hex": pubkey.hex(),
        "message": {
            "timestamp_ms": TIMESTAMP_MS,
            "epoch": epoch_for(TIMESTAMP_MS),
            "msg_id_hex": MSG_ID.hex(),
            "counter": COUNTER,
            "plaintext_hex": PLAINTEXT.hex(),
            "channel_id_hex": channel_id_for_key(CHANNEL_KEY).hex(),
            "sender_id_hex": packets[0].sender_id.hex(),
            "sender_id_next_epoch_hex": sender_id_for_pubkey(
                CHANNEL_KEY, pubkey, TIMESTAMP_MS + 15 * 60 * 1000
            ).hex(),
            "total_chunks": packets[0].total_chunks,
            "ttl": TTL,
            "type": TYPE_VOICE_DATA,
            "version": PROTOCOL_VERSION,
        },
        "frames": [
            {
                "chunk_idx": packet.chunk_idx,
                "canonical_header_hex": packet.canonical_header.hex(),
                "aad_hex": packet.aad.hex(),
                "signing_input_hex": packet.signing_input.hex(),
                "sealed_payload_hex": packet.payload.hex(),
                "signature_hex": packet.signature.hex(),
                "frame_hex": packet.to_bytes().hex(),
                "frame_len": len(packet.to_bytes()),
            }
            for packet in packets
        ],
    }


def dumps(vector: dict[str, object]) -> str:
    return json.dumps(vector, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare the generated vector with security/contract-vectors.json",
    )
    args = parser.parse_args()

    rendered = dumps(build_vector())
    if args.check:
        if not VECTOR_PATH.exists():
            print(f"FAIL: {VECTOR_PATH} is missing; run contract_vector.py", file=sys.stderr)
            return 1
        committed = VECTOR_PATH.read_text(encoding="utf-8")
        if committed != rendered:
            print(
                "FAIL: contract vectors drifted from docs/packet-format.md v1 "
                f"({VECTOR_PATH})",
                file=sys.stderr,
            )
            return 1
        print(f"PASS contract vectors: {VECTOR_PATH.name} matches docs v1")
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
