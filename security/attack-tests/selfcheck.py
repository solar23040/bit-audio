#!/usr/bin/env python3
"""Harness self-check: wire round-trip, crypto, derivations, mutations.

No hardware or attack config needed:

  python selfcheck.py
"""

from __future__ import annotations

import secrets
import sys

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from mutations import MUTATIONS, TTL_MUTATIONS, apply_all
from wire import (
    EPOCH_MS,
    MAX_FRAME,
    PacketError,
    build_voice_message,
    channel_id_for_key,
    parse_packet,
    reassemble,
    sender_id_for_pubkey,
    validate_frame,
    verify_packet,
)


def main() -> int:
    channel_key = secrets.token_bytes(32)
    signing_key = SigningKey.generate()
    pubkey = signing_key.verify_key.encode()
    plaintext = b"mesh voice note self-check " * 40
    timestamp = 1_700_000_000_000

    msg_id, frames = build_voice_message(
        channel_key=channel_key,
        signing_key=signing_key,
        plaintext=plaintext,
        timestamp_ms=timestamp,
    )
    assert len(frames) > 1, "expected a multi-frame message"
    assert len(frames) == (len(plaintext) + 40 + 404) // 405  # sealed once, 405 B chunks

    first = parse_packet(frames[0])
    assert first.channel_id == channel_id_for_key(channel_key)
    assert first.sender_id == sender_id_for_pubkey(channel_key, pubkey, timestamp)
    assert first.total_chunks == len(frames)
    assert first.timestamp_ms == timestamp

    for frame in frames:
        reason = validate_frame(frame)
        assert reason is None, f"valid frame rejected: {reason}"
        assert len(frame) <= MAX_FRAME
        packet = parse_packet(frame)
        assert packet.msg_id == msg_id
        assert verify_packet(packet, pubkey), "signature did not verify"
        assert packet.aad == (
            first.channel_id
            + first.msg_id
            + first.timestamp_ms.to_bytes(8, "big")
            + first.counter.to_bytes(4, "big")
        )

    assert reassemble(frames, channel_key) == plaintext, "reassembled plaintext mismatch"

    try:
        reassemble(frames, secrets.token_bytes(32))
    except PacketError:
        pass
    else:
        raise AssertionError("wrong channel key opened the message")

    # Sender ID rotates per 15-minute epoch and is channel-scoped.
    later = sender_id_for_pubkey(channel_key, pubkey, timestamp + EPOCH_MS)
    other_channel = sender_id_for_pubkey(secrets.token_bytes(32), pubkey, timestamp)
    assert later != first.sender_id
    assert other_channel != first.sender_id

    # Every mutation must change the frame. Non-TTL mutations must fail the
    # signature; TTL mutations keep it valid by design but must be clamped.
    for name, mutated in apply_all(frames[0]):
        assert mutated != frames[0], f"{name} did not change the frame"
        try:
            packet = parse_packet(mutated)
        except PacketError:
            assert name not in TTL_MUTATIONS
            continue
        if name in TTL_MUTATIONS:
            assert verify_packet(packet, pubkey), f"{name}: ttl must not be signed"
            if name in {"bump_ttl", "ttl_16"}:
                assert validate_frame(mutated) is None, f"{name}: expected structurally valid"
            else:
                assert validate_frame(mutated) is not None, f"{name}: expected ttl clamp"
        else:
            assert not verify_packet(packet, pubkey), f"{name}: mutated frame still verifies"

    try:
        parse_packet(frames[0][:106])
    except PacketError:
        pass
    else:
        raise AssertionError("truncated frame parsed")

    try:
        signing_key.verify_key.verify(
            parse_packet(frames[0]).signing_input, bytes(64)
        )
    except (BadSignatureError, ValueError):
        pass
    else:
        raise AssertionError("zero signature verified")

    print(
        f"PASS harness self-check: {len(frames)} frames, "
        f"{len(plaintext)} B round-trip, {len(MUTATIONS)} mutations, "
        f"{len(TTL_MUTATIONS)} TTL cases"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
