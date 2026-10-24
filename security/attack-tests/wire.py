"""Wire format and crypto helpers for the Agent H attack harness.

The layout below is the harness's working assumption for
``docs/packet-format.md`` (not written yet by Agent A):

    offset  size  field
    0       1     version
    1       1     type
    2       8     msg_id
    10      8     sender_id
    18      1     ttl
    19      2     chunk_idx      (big endian)
    21      2     total_chunks   (big endian)
    23      8     ts_ms          (big endian, Unix ms)
    31      64    sig            Ed25519 over header || payload
    95      ...   payload        XChaCha20-Poly1305: nonce(24) || ciphertext+tag

The signature input is the 31-byte header followed by the wire payload; the
signature field itself is not signed. The header is also the AEAD AAD for each
chunk. Both assumptions are flagged in ``threat-model.md`` §11 and must be
reconciled with Agent A/E once the interfaces land.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
import time
from dataclasses import dataclass

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.exceptions import CryptoError
from nacl.signing import SigningKey

PROTOCOL_VERSION = 1
TYPE_VOICE = 0x01

HEADER_STRUCT = struct.Struct(">BB8s8sBHHQ")
HEADER_LEN = HEADER_STRUCT.size  # 31
SIG_LEN = 64
BASE_LEN = HEADER_LEN + SIG_LEN  # 95

# Security limits recommended in threat-model.md §8. The app must enforce these;
# the harness uses them to decide whether a frame is plausibly valid.
DEFAULT_LIMITS = {
    "max_frame": 300,
    "max_chunk_plaintext": 128,
    "max_total_chunks": 256,
    "max_reassembled": 32 * 1024,
    "max_ttl": 5,
}


class PacketError(ValueError):
    """A frame cannot be parsed or fails a structural limit."""


@dataclass(frozen=True)
class Packet:
    version: int
    type: int
    msg_id: bytes
    sender_id: bytes
    ttl: int
    chunk_idx: int
    total_chunks: int
    ts_ms: int
    sig: bytes
    payload: bytes

    def to_bytes(self) -> bytes:
        return (
            HEADER_STRUCT.pack(
                self.version,
                self.type,
                self.msg_id,
                self.sender_id,
                self.ttl,
                self.chunk_idx,
                self.total_chunks,
                self.ts_ms,
            )
            + self.sig
            + self.payload
        )

    @property
    def signing_input(self) -> bytes:
        return self.to_bytes()[:HEADER_LEN] + self.payload


def header_bytes(
    *,
    version: int,
    type_: int,
    msg_id: bytes,
    sender_id: bytes,
    ttl: int,
    chunk_idx: int,
    total_chunks: int,
    ts_ms: int,
) -> bytes:
    if len(msg_id) != 8:
        raise ValueError("msg_id must be 8 bytes")
    if len(sender_id) != 8:
        raise ValueError("sender_id must be 8 bytes")
    return HEADER_STRUCT.pack(
        version, type_, msg_id, sender_id, ttl, chunk_idx, total_chunks, ts_ms
    )


def parse_packet(data: bytes) -> Packet:
    if len(data) < BASE_LEN:
        raise PacketError(f"truncated frame: {len(data)} < {BASE_LEN} bytes")
    header = HEADER_STRUCT.unpack(data[:HEADER_LEN])
    return Packet(
        version=header[0],
        type=header[1],
        msg_id=header[2],
        sender_id=header[3],
        ttl=header[4],
        chunk_idx=header[5],
        total_chunks=header[6],
        ts_ms=header[7],
        sig=data[HEADER_LEN:BASE_LEN],
        payload=data[BASE_LEN:],
    )


def build_packet(
    *,
    sender_id: bytes,
    payload: bytes,
    signing_key: SigningKey | None = None,
    sig: bytes | None = None,
    version: int = PROTOCOL_VERSION,
    type_: int = TYPE_VOICE,
    msg_id: bytes | None = None,
    ttl: int = 5,
    chunk_idx: int = 0,
    total_chunks: int = 1,
    ts_ms: int | None = None,
) -> bytes:
    """Build one wire frame. Frames are unsigned when no key/sig is given."""
    msg_id = msg_id if msg_id is not None else random_id()
    ts_ms = ts_ms if ts_ms is not None else now_ms()
    header = header_bytes(
        version=version,
        type_=type_,
        msg_id=msg_id,
        sender_id=sender_id,
        ttl=ttl,
        chunk_idx=chunk_idx,
        total_chunks=total_chunks,
        ts_ms=ts_ms,
    )
    if sig is None:
        sig = signing_key.sign(header + payload).signature if signing_key else bytes(SIG_LEN)
    if len(sig) != SIG_LEN:
        raise ValueError("signature must be 64 bytes")
    return header + sig + payload


def seal(key: bytes, plaintext: bytes, aad: bytes, *, nonce: bytes | None = None) -> bytes:
    if len(key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES:
        raise ValueError("channel key must be 32 bytes")
    nonce = nonce if nonce is not None else secrets.token_bytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    if len(nonce) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:
        raise ValueError("nonce must be 24 bytes")
    return nonce + crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


def open_sealed(key: bytes, payload: bytes, aad: bytes) -> bytes:
    if len(payload) < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 16:
        raise PacketError("sealed payload too short")
    nonce = payload[:crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]
    ct = payload[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:]
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce, key)
    except CryptoError as exc:
        raise PacketError("AEAD open failed") from exc


def build_voice_message(
    *,
    channel_key: bytes,
    signing_key: SigningKey,
    sender_id: bytes,
    plaintext: bytes,
    chunk_size: int = 96,
    ttl: int = 5,
    ts_ms: int | None = None,
    msg_id: bytes | None = None,
) -> tuple[bytes, list[bytes]]:
    """Build a sealed, signed, multi-chunk message.

    Each chunk is sealed separately with the 31-byte header as AAD and signed
    over header||sealed payload, so one corrupted chunk cannot be hidden until
    the end of reassembly.
    """
    if not 1 <= chunk_size <= DEFAULT_LIMITS["max_chunk_plaintext"]:
        raise ValueError(f"chunk_size must be 1..{DEFAULT_LIMITS['max_chunk_plaintext']}")
    chunks = [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)]
    if not chunks:
        chunks = [b""]
    if len(chunks) > DEFAULT_LIMITS["max_total_chunks"]:
        raise ValueError(
            f"{len(chunks)} chunks exceeds the recommended cap "
            f"({DEFAULT_LIMITS['max_total_chunks']}); use a larger chunk size"
        )
    msg_id = msg_id if msg_id is not None else random_id()
    ts_ms = ts_ms if ts_ms is not None else now_ms()
    frames: list[bytes] = []
    for idx, chunk in enumerate(chunks):
        header = header_bytes(
            version=PROTOCOL_VERSION,
            type_=TYPE_VOICE,
            msg_id=msg_id,
            sender_id=sender_id,
            ttl=ttl,
            chunk_idx=idx,
            total_chunks=len(chunks),
            ts_ms=ts_ms,
        )
        sealed = seal(channel_key, chunk, header)
        sig = signing_key.sign(header + sealed).signature
        frames.append(header + sig + sealed)
    return msg_id, frames


def validate_frame(frame: bytes) -> str | None:
    """Return a rejection reason if the frame violates structural limits."""
    try:
        packet = parse_packet(frame)
    except PacketError as exc:
        return str(exc)
    limits = DEFAULT_LIMITS
    if packet.version != PROTOCOL_VERSION:
        return f"bad version {packet.version}"
    if len(frame) > limits["max_frame"]:
        return f"frame too large ({len(frame)} > {limits['max_frame']})"
    if packet.total_chunks < 1:
        return "total_chunks == 0"
    if packet.total_chunks > limits["max_total_chunks"]:
        return f"total_chunks {packet.total_chunks} > {limits['max_total_chunks']}"
    if packet.chunk_idx >= packet.total_chunks:
        return f"chunk_idx {packet.chunk_idx} >= total_chunks {packet.total_chunks}"
    if not packet.sender_id or packet.sender_id == bytes(8):
        return "empty sender_id"
    return None


def sender_id_for_pubkey(pubkey: bytes) -> bytes:
    """Ephemeral-ID stand-in: 8-byte BLAKE2b of the public key."""
    return hashlib.blake2b(pubkey, digest_size=8).digest()


def random_id() -> bytes:
    return secrets.token_bytes(8)


def now_ms() -> int:
    return int(time.time() * 1000)


def hexs(data: bytes) -> str:
    return data.hex()


def from_hex(text: str) -> bytes:
    cleaned = "".join(text.split()).removeprefix("0x")
    return bytes.fromhex(cleaned)


def frame_summary(frame: bytes) -> str:
    try:
        p = parse_packet(frame)
    except PacketError as exc:
        return f"{len(frame)}B unparseable ({exc})"
    return (
        f"{len(frame)}B msg={p.msg_id.hex()} sender={p.sender_id.hex()} "
        f"ttl={p.ttl} chunk={p.chunk_idx}/{p.total_chunks} ts={p.ts_ms}"
    )
