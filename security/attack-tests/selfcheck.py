#!/usr/bin/env python3
"""Harness self-check: wire round-trip, crypto, mutations, no hardware needed.

Run this locally or in CI to make sure the attack tooling itself is correct:

  python selfcheck.py
"""

from __future__ import annotations

import secrets
import sys

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from mutations import MUTATIONS, apply, apply_all
from wire import (
    PacketError,
    build_voice_message,
    open_sealed,
    parse_packet,
    validate_frame,
)


def main() -> int:
    channel_key = secrets.token_bytes(32)
    signing_key = SigningKey.generate()
    sender_id = secrets.token_bytes(8)
    plaintext = b"mesh voice note self-check " * 40

    msg_id, frames = build_voice_message(
        channel_key=channel_key,
        signing_key=signing_key,
        sender_id=sender_id,
        plaintext=plaintext,
        chunk_size=96,
    )
    assert len(frames) > 1, "expected a multi-frame message"

    rebuilt = bytearray()
    for frame in frames:
        reason = validate_frame(frame)
        assert reason is None, f"valid frame rejected: {reason}"
        packet = parse_packet(frame)
        assert packet.msg_id == msg_id
        signing_key.verify_key.verify(packet.signing_input, packet.sig)
        header = frame[:31]
        rebuilt.extend(open_sealed(channel_key, packet.payload, header))
    assert bytes(rebuilt) == plaintext, "reassembled plaintext mismatch"

    # Wrong channel key must fail to open.
    try:
        open_sealed(secrets.token_bytes(32), parse_packet(frames[0]).payload, frames[0][:31])
    except PacketError:
        pass
    else:
        raise AssertionError("wrong key opened the payload")

    # Every mutation must produce a changed frame, and parseable ones must fail
    # signature verification.
    for name, mutated in apply_all(frames[0]):
        assert mutated != frames[0], f"{name} did not change the frame"
        try:
            packet = parse_packet(mutated)
        except PacketError:
            continue
        try:
            signing_key.verify_key.verify(packet.signing_input, packet.sig)
        except (BadSignatureError, ValueError):
            continue
        raise AssertionError(f"{name}: mutated frame still verifies")

    try:
        parse_packet(frames[0][:30])
    except PacketError:
        pass
    else:
        raise AssertionError("truncated frame parsed")

    print(
        f"PASS harness self-check: {len(frames)} frames, "
        f"{len(plaintext)} B round-trip, {len(MUTATIONS)} mutations"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
