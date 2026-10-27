#!/usr/bin/env python3
"""Harness self-check: v1 wire round-trip, crypto, mutations, no hardware.

Run locally or in CI to prove the attack tooling itself matches
``docs/packet-format.md`` v1:

  python selfcheck.py
"""

from __future__ import annotations

import secrets
import sys

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from mutations import MUTATIONS, TTL_ONLY_MUTATIONS, apply_all
from wire import (
    MAX_PLAINTEXT_CHUNK,
    PacketError,
    build_voice_message,
    now_ms,
    open_sealed,
    parse_packet,
    reassemble,
    validate_frame,
    verify_packet,
)


def main() -> int:
    channel_key = secrets.token_bytes(32)
    signing_key = SigningKey.generate()
    pubkey = signing_key.verify_key.encode()
    timestamp_ms = now_ms()
    plaintext = b"mesh voice note self-check " * 40

    msg_id, frames = build_voice_message(
        channel_key=channel_key,
        signing_key=signing_key,
        plaintext=plaintext,
        chunk_size=200,
        timestamp_ms=timestamp_ms,
    )
    assert len(frames) > 1, "expected a multi-frame message"
    assert all(len(frame) <= 512 for frame in frames), "frame exceeds 512 bytes"

    rebuilt = bytearray()
    for frame in frames:
        reason = validate_frame(frame, now=timestamp_ms)
        assert reason is None, f"valid frame rejected: {reason}"
        packet = parse_packet(frame)
        assert packet.msg_id == msg_id
        assert verify_packet(packet, pubkey), "valid signature rejected"
        rebuilt.extend(open_sealed(channel_key, packet.payload, packet.aad))
    assert bytes(rebuilt) == plaintext, "reassembled plaintext mismatch"
    assert (
        reassemble(frames, channel_key, signer_public_key=pubkey, now=timestamp_ms)
        == plaintext
    ), "reassemble() mismatch"

    # Wrong channel key must fail to open.
    try:
        open_sealed(secrets.token_bytes(32), parse_packet(frames[0]).payload, parse_packet(frames[0]).aad)
    except PacketError:
        pass
    else:
        raise AssertionError("wrong key opened the payload")

    # Every non-TTL mutation must change the frame and then fail parsing or
    # signature verification. TTL is deliberately outside the signature, so TTL
    # mutations must still verify; only the 1..8 bound rejects them.
    for name, mutated in apply_all(frames[0]):
        assert mutated != frames[0], f"{name} did not change the frame"
        try:
            packet = parse_packet(mutated)
        except PacketError:
            continue
        if name in TTL_ONLY_MUTATIONS:
            assert verify_packet(packet, pubkey), f"{name}: TTL mutation broke the signature"
            if name == "bump_ttl":
                assert packet.ttl == 6 and validate_frame(mutated) is None, (
                    "bump_ttl must stay valid (TTL 1..8 is accepted)"
                )
            else:
                assert validate_frame(mutated) is not None, f"{name}: invalid TTL accepted"
            continue
        if verify_packet(packet, pubkey):
            raise AssertionError(f"{name}: mutated frame still verifies")

    try:
        parse_packet(frames[0][:106])
    except PacketError:
        pass
    else:
        raise AssertionError("truncated frame parsed")

    print(
        f"PASS harness self-check: {len(frames)} frames, {len(plaintext)} B round-trip, "
        f"{len(MUTATIONS)} mutations, chunk={MAX_PLAINTEXT_CHUNK} B"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
