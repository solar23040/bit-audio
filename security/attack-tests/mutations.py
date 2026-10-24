"""Frame mutations used by the malicious-relay and fuzz tests.

Every mutation is expected to be rejected or silently dropped by the target.
A mutation that still gets delivered after authentication is a finding.
"""

from __future__ import annotations

import random
from dataclasses import replace
from typing import Callable

from wire import Packet, PacketError, parse_packet


def _with(frame: bytes, **changes: object) -> bytes:
    packet = parse_packet(frame)
    return replace(packet, **changes).to_bytes()


def flip_payload_bit(frame: bytes, rng: random.Random) -> bytes:
    if len(frame) <= 95:
        return frame + bytes([rng.randrange(256)])
    index = rng.randrange(95, len(frame))
    data = bytearray(frame)
    data[index] ^= 1 << rng.randrange(8)
    return bytes(data)


def flip_sig_bit(frame: bytes, rng: random.Random) -> bytes:
    data = bytearray(frame)
    index = rng.randrange(31, 95)
    data[index] ^= 1 << rng.randrange(8)
    return bytes(data)


def flip_sender_bit(frame: bytes, rng: random.Random) -> bytes:
    data = bytearray(frame)
    index = rng.randrange(10, 18)
    data[index] ^= 1 << rng.randrange(8)
    return bytes(data)


def flip_msgid_bit(frame: bytes, rng: random.Random) -> bytes:
    data = bytearray(frame)
    index = rng.randrange(2, 10)
    data[index] ^= 1 << rng.randrange(8)
    return bytes(data)


def flip_nonce_bit(frame: bytes, rng: random.Random) -> bytes:
    if len(frame) <= 95:
        return frame
    data = bytearray(frame)
    index = rng.randrange(95, min(119, len(frame)))
    data[index] ^= 1 << rng.randrange(8)
    return bytes(data)


def bump_ttl(frame: bytes, _rng: random.Random) -> bytes:
    packet = parse_packet(frame)
    return _with(frame, ttl=min(255, packet.ttl + 1))


def zero_ttl(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, ttl=0)


def max_ttl(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, ttl=255)


def chunk_idx_oob(frame: bytes, _rng: random.Random) -> bytes:
    packet = parse_packet(frame)
    return _with(frame, chunk_idx=packet.total_chunks)


def chunk_idx_wrap(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, chunk_idx=0xFFFF)


def total_zero(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, total_chunks=0)


def total_huge(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, total_chunks=0xFFFF)


def version_zero(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, version=0)


def version_255(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, version=255)


def type_random(frame: bytes, rng: random.Random) -> bytes:
    return _with(frame, type=rng.randrange(256))


def ts_zero(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, ts_ms=0)


def ts_future(frame: bytes, _rng: random.Random) -> bytes:
    packet = parse_packet(frame)
    return _with(frame, ts_ms=packet.ts_ms + 365 * 24 * 3600 * 1000)


def clear_sig(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, sig=bytes(64))


def truncate_header(frame: bytes, _rng: random.Random) -> bytes:
    return frame[:31]


def truncate_mid_header(frame: bytes, _rng: random.Random) -> bytes:
    return frame[:20]


def truncate_below_min(frame: bytes, _rng: random.Random) -> bytes:
    return frame[:94]


def empty_payload(frame: bytes, _rng: random.Random) -> bytes:
    return frame[:95]


def append_garbage(frame: bytes, rng: random.Random) -> bytes:
    return frame + bytes(rng.randrange(256) for _ in range(32))


def oversize(frame: bytes, rng: random.Random) -> bytes:
    return frame + bytes(rng.randrange(256) for _ in range(1200))


def corrupt_tag(frame: bytes, rng: random.Random) -> bytes:
    if len(frame) <= 95:
        return frame
    data = bytearray(frame)
    data[-1] ^= 1 << rng.randrange(8)
    return bytes(data)


MUTATIONS: dict[str, Callable[[bytes, random.Random], bytes]] = {
    "flip_payload_bit": flip_payload_bit,
    "flip_sig_bit": flip_sig_bit,
    "flip_sender_bit": flip_sender_bit,
    "flip_msgid_bit": flip_msgid_bit,
    "flip_nonce_bit": flip_nonce_bit,
    "bump_ttl": bump_ttl,
    "zero_ttl": zero_ttl,
    "max_ttl": max_ttl,
    "chunk_idx_oob": chunk_idx_oob,
    "chunk_idx_wrap": chunk_idx_wrap,
    "total_zero": total_zero,
    "total_huge": total_huge,
    "version_zero": version_zero,
    "version_255": version_255,
    "type_random": type_random,
    "ts_zero": ts_zero,
    "ts_future": ts_future,
    "clear_sig": clear_sig,
    "truncate_header": truncate_header,
    "truncate_mid_header": truncate_mid_header,
    "truncate_below_min": truncate_below_min,
    "empty_payload": empty_payload,
    "append_garbage": append_garbage,
    "oversize": oversize,
    "corrupt_tag": corrupt_tag,
}

EXPECTATIONS: dict[str, str] = {
    "flip_payload_bit": "AEAD + signature reject",
    "flip_sig_bit": "signature reject",
    "flip_sender_bit": "signature/identity reject",
    "flip_msgid_bit": "signature reject (msg_id is signed)",
    "flip_nonce_bit": "AEAD reject",
    "bump_ttl": "signature reject (ttl is signed)",
    "zero_ttl": "signature reject; if unsigned path exists, no relay",
    "max_ttl": "signature reject; ttl clamp if unsigned path exists",
    "chunk_idx_oob": "signature reject + structural reject",
    "chunk_idx_wrap": "signature reject + structural reject",
    "total_zero": "signature/structural reject",
    "total_huge": "signature reject + chunk cap",
    "version_zero": "structural reject",
    "version_255": "structural reject",
    "type_random": "signature reject",
    "ts_zero": "signature reject; replay window reject",
    "ts_future": "signature reject; replay window reject",
    "clear_sig": "signature reject",
    "truncate_header": "structural reject",
    "truncate_mid_header": "structural reject",
    "truncate_below_min": "structural reject",
    "empty_payload": "AEAD reject",
    "append_garbage": "signature/AEAD reject or ignore trailing bytes",
    "oversize": "frame-size cap",
    "corrupt_tag": "AEAD reject",
}


def apply(name: str, frame: bytes, rng: random.Random) -> bytes:
    try:
        return MUTATIONS[name](frame, rng)
    except PacketError as exc:
        raise ValueError(f"mutation {name!r} needs a parseable source frame: {exc}") from exc


def apply_all(frame: bytes, seed: int = 1) -> list[tuple[str, bytes]]:
    rng = random.Random(seed)
    result: list[tuple[str, bytes]] = []
    for name in MUTATIONS:
        result.append((name, apply(name, frame, rng)))
    return result


def packet_fields(frame: bytes) -> Packet:
    return parse_packet(frame)
