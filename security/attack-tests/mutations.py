"""Frame mutations used by the malicious-relay and fuzz tests.

Offsets and limits follow ``docs/packet-format.md`` v1. TTL is deliberately
outside the signature (relays decrement it); TTL-only mutations are listed in
[TTL_MUTATIONS] and must be evaluated by the receiver's 1..16 clamp and dedup
instead of signature rejection.
"""

from __future__ import annotations

import random
from dataclasses import replace
from typing import Callable

from wire import (
    HEADER_LEN,
    MAX_TTL,
    Packet,
    PacketError,
    parse_packet,
)

TTL_MUTATIONS = frozenset({"bump_ttl", "zero_ttl", "max_ttl", "ttl_16", "ttl_17"})


def _with(frame: bytes, **changes: object) -> bytes:
    packet = parse_packet(frame)
    return replace(packet, **changes).to_bytes()


def flip_payload_bit(frame: bytes, rng: random.Random) -> bytes:
    if len(frame) <= HEADER_LEN:
        return frame + bytes([rng.randrange(256)])
    index = rng.randrange(HEADER_LEN, len(frame))
    data = bytearray(frame)
    data[index] ^= 1 << rng.randrange(8)
    return bytes(data)


def flip_sig_bit(frame: bytes, rng: random.Random) -> bytes:
    data = bytearray(frame)
    index = rng.randrange(43, 107)
    data[index] ^= 1 << rng.randrange(8)
    return bytes(data)


def flip_sender_bit(frame: bytes, rng: random.Random) -> bytes:
    data = bytearray(frame)
    index = rng.randrange(18, 26)
    data[index] ^= 1 << rng.randrange(8)
    return bytes(data)


def flip_channel_bit(frame: bytes, rng: random.Random) -> bytes:
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
    if len(frame) <= HEADER_LEN:
        return frame
    data = bytearray(frame)
    index = rng.randrange(HEADER_LEN, min(HEADER_LEN + 24, len(frame)))
    data[index] ^= 1 << rng.randrange(8)
    return bytes(data)


def bump_ttl(frame: bytes, _rng: random.Random) -> bytes:
    packet = parse_packet(frame)
    return _with(frame, ttl=min(255, packet.ttl + 1))


def zero_ttl(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, ttl=0)


def max_ttl(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, ttl=255)


def ttl_16(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, ttl=MAX_TTL)


def ttl_17(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, ttl=MAX_TTL + 1)


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
    return _with(frame, type=rng.choice([0, 2, 3, 4, 5, 0x7F, 0x80, 0xFF]))


def ts_zero(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, timestamp_ms=0)


def ts_future(frame: bytes, _rng: random.Random) -> bytes:
    packet = parse_packet(frame)
    return _with(frame, timestamp_ms=packet.timestamp_ms + 365 * 24 * 3600 * 1000)


def counter_zero(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, counter=0)


def counter_max(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, counter=0xFFFFFFFF)


def clear_sig(frame: bytes, _rng: random.Random) -> bytes:
    return _with(frame, signature=bytes(64))


def truncate_header(frame: bytes, _rng: random.Random) -> bytes:
    return frame[:43]


def truncate_mid_header(frame: bytes, _rng: random.Random) -> bytes:
    return frame[:60]


def truncate_below_min(frame: bytes, _rng: random.Random) -> bytes:
    return frame[:106]


def empty_payload(frame: bytes, _rng: random.Random) -> bytes:
    return frame[:HEADER_LEN]


def append_garbage(frame: bytes, rng: random.Random) -> bytes:
    return frame + bytes(rng.randrange(256) for _ in range(32))


def oversize(frame: bytes, rng: random.Random) -> bytes:
    return frame + bytes(rng.randrange(256) for _ in range(1200))


def corrupt_tag(frame: bytes, rng: random.Random) -> bytes:
    if len(frame) <= HEADER_LEN:
        return frame
    data = bytearray(frame)
    data[-1] ^= 1 << rng.randrange(8)
    return bytes(data)


MUTATIONS: dict[str, Callable[[bytes, random.Random], bytes]] = {
    "flip_payload_bit": flip_payload_bit,
    "flip_sig_bit": flip_sig_bit,
    "flip_sender_bit": flip_sender_bit,
    "flip_channel_bit": flip_channel_bit,
    "flip_msgid_bit": flip_msgid_bit,
    "flip_nonce_bit": flip_nonce_bit,
    "bump_ttl": bump_ttl,
    "zero_ttl": zero_ttl,
    "max_ttl": max_ttl,
    "ttl_16": ttl_16,
    "ttl_17": ttl_17,
    "chunk_idx_oob": chunk_idx_oob,
    "chunk_idx_wrap": chunk_idx_wrap,
    "total_zero": total_zero,
    "total_huge": total_huge,
    "version_zero": version_zero,
    "version_255": version_255,
    "type_random": type_random,
    "ts_zero": ts_zero,
    "ts_future": ts_future,
    "counter_zero": counter_zero,
    "counter_max": counter_max,
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
    "flip_payload_bit": "AEAD reject at reassembly",
    "flip_sig_bit": "signature reject",
    "flip_sender_bit": "sender resolution/signature reject",
    "flip_channel_bit": "unknown channel / signature reject",
    "flip_msgid_bit": "signature reject (msg_id is signed and in AAD)",
    "flip_nonce_bit": "AEAD reject",
    "bump_ttl": "accepted by design (ttl unsigned): relay once, no amplification",
    "zero_ttl": "drop; ttl 0 is never delivered or relayed",
    "max_ttl": "drop; ttl > 16",
    "ttl_16": "accepted at ingress; dedup stops loops",
    "ttl_17": "drop; ttl > 16",
    "chunk_idx_oob": "structural reject + signature reject",
    "chunk_idx_wrap": "structural reject + signature reject",
    "total_zero": "structural reject + signature reject",
    "total_huge": "structural reject (>162) + signature reject",
    "version_zero": "structural reject",
    "version_255": "structural reject",
    "type_random": "unknown type ignored; signature reject",
    "ts_zero": "signature reject; freshness/retention reject",
    "ts_future": "signature reject; future-skew reject",
    "counter_zero": "signature reject; counter 0 reject",
    "counter_max": "signature reject; counter-cache check",
    "clear_sig": "signature reject",
    "truncate_header": "structural reject",
    "truncate_mid_header": "structural reject",
    "truncate_below_min": "structural reject",
    "empty_payload": "signature reject / AEAD reject",
    "append_garbage": "signature reject or frame-size cap",
    "oversize": "frame-size cap (>512)",
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
