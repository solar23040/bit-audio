"""Wire format and crypto helpers pinned to ``docs/packet-format.md`` v1.

Header prefix (43 bytes, big-endian), followed by the signature and one sealed
chunk:

    0   1   version
    1   1   type
    2   8   msg_id
    10  8   channel_id
    18  8   sender_id
    26  1   ttl                 (excluded from the signature by design)
    27  2   chunk_idx
    29  2   total_chunks
    31  8   timestamp_ms
    39  4   counter
    43  64  signature           Ed25519 over the canonical transcript
    107 ... payload             one sealed chunk (nonce || ciphertext || tag)

Each chunk is sealed independently. The canonical header is the 43-byte prefix
with ``ttl`` zeroed; it is used for both the signature and the AEAD AAD:

    signing_input = "bit-audio/packet-sign/v1"
                    || u32be(len(canonical_header))
                    || canonical_header
                    || sealed_chunk
    aad           = "bit-audio/packet-seal/v1" || canonical_header

Relays decrement ``ttl`` on the wire without touching the signature. The 1..8
bound and the dedup cache contain a malicious node that raises it.

Keep this module in lockstep with the docs. It is the Python side of the
contract vectors in ``security/contract-vectors.json``; the Kotlin side is
``mesh/src/test/.../MeshContractSecurityTest.kt``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import threading
import time
from dataclasses import dataclass, replace

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.signing import SigningKey, VerifyKey

PROTOCOL_VERSION = 1

TYPE_VOICE_DATA = 0x01
TYPE_DELIVERY_RECEIPT = 0x02
TYPE_MEMBER_ANNOUNCE = 0x03
TYPE_KEY_ROTATE = 0x04

HEADER_STRUCT = struct.Struct(">BB8s8s8sBHHQI")  # 43 bytes
HEADER_PREFIX_LEN = HEADER_STRUCT.size
SIG_OFFSET = HEADER_PREFIX_LEN
SIG_LEN = 64
HEADER_LEN = HEADER_PREFIX_LEN + SIG_LEN  # 107
TTL_OFFSET = 26

MAX_FRAME = 512
MAX_PAYLOAD = 405
MIN_SEALED_PAYLOAD = 40
MAX_PLAINTEXT_CHUNK = 365
MIN_TOTAL_CHUNKS = 1
MAX_TOTAL_CHUNKS = 256
MAX_REASSEMBLED = 64 * 1024

MIN_TTL = 1
MAX_TTL = 8
DEFAULT_TTL = 5
FUTURE_SKEW_MS = 120_000
RETENTION_MS = 24 * 60 * 60 * 1000
EPOCH_MS = 15 * 60 * 1000

CHANNEL_ID_SIZE = 8
SENDER_ID_SIZE = 8
IDENTITY_PUBKEY_SIZE = 32

CHANNEL_ID_DOMAIN = b"bit-audio/channel-id/v1"
SENDER_ID_KEY_DOMAIN = b"bit-audio/sender-id-key/v1"
SENDER_ID_DOMAIN = b"bit-audio/sender-id/v1"
SIGNING_DOMAIN = b"bit-audio/packet-sign/v1"
SEAL_DOMAIN = b"bit-audio/packet-seal/v1"


class PacketError(ValueError):
    """A frame cannot be parsed or violates a protocol limit."""


_counter_lock = threading.Lock()
_next_counter = secrets.randbelow(0xFFFFFFFF - 1) + 1


def next_counter() -> int:
    """Process-wide monotonic counter; the docs forbid reusing one per message."""
    global _next_counter
    with _counter_lock:
        value = _next_counter
        _next_counter = value % 0xFFFFFFFF + 1
        return value


@dataclass(frozen=True)
class Packet:
    version: int
    type: int
    msg_id: bytes
    channel_id: bytes
    sender_id: bytes
    ttl: int
    chunk_idx: int
    total_chunks: int
    timestamp_ms: int
    counter: int
    signature: bytes
    payload: bytes

    @property
    def header(self) -> bytes:
        """The 43-byte wire prefix, including the real TTL."""
        return HEADER_STRUCT.pack(
            self.version,
            self.type,
            self.msg_id,
            self.channel_id,
            self.sender_id,
            self.ttl,
            self.chunk_idx,
            self.total_chunks,
            self.timestamp_ms,
            self.counter,
        )

    @property
    def canonical_header(self) -> bytes:
        """The header prefix with TTL zeroed; signed and used as AEAD AAD."""
        header = bytearray(self.header)
        header[TTL_OFFSET] = 0
        return bytes(header)

    @property
    def signing_input(self) -> bytes:
        canonical = self.canonical_header
        return (
            SIGNING_DOMAIN
            + struct.pack(">I", len(canonical))
            + canonical
            + self.payload
        )

    @property
    def aad(self) -> bytes:
        return SEAL_DOMAIN + self.canonical_header

    def to_bytes(self) -> bytes:
        return self.header + self.signature + self.payload


def parse_packet(data: bytes) -> Packet:
    if len(data) < HEADER_LEN:
        raise PacketError(f"truncated frame: {len(data)} < {HEADER_LEN} bytes")
    body = HEADER_STRUCT.unpack(data[:HEADER_PREFIX_LEN])
    return Packet(
        version=body[0],
        type=body[1],
        msg_id=body[2],
        channel_id=body[3],
        sender_id=body[4],
        ttl=body[5],
        chunk_idx=body[6],
        total_chunks=body[7],
        timestamp_ms=body[8],
        counter=body[9],
        signature=data[SIG_OFFSET:HEADER_LEN],
        payload=data[HEADER_LEN:],
    )


def header_bytes(
    *,
    version: int = PROTOCOL_VERSION,
    type_: int = TYPE_VOICE_DATA,
    msg_id: bytes,
    channel_id: bytes,
    sender_id: bytes,
    ttl: int = DEFAULT_TTL,
    chunk_idx: int = 0,
    total_chunks: int = 1,
    timestamp_ms: int | None = None,
    counter: int = 1,
) -> bytes:
    """Pack the 43-byte header prefix. For fuzzers and malformed frames."""
    if len(msg_id) != 8:
        raise ValueError("msg_id must be 8 bytes")
    if len(channel_id) != CHANNEL_ID_SIZE:
        raise ValueError("channel_id must be 8 bytes")
    if len(sender_id) != SENDER_ID_SIZE:
        raise ValueError("sender_id must be 8 bytes")
    if timestamp_ms is None:
        timestamp_ms = now_ms()
    return HEADER_STRUCT.pack(
        version,
        type_,
        msg_id,
        channel_id,
        sender_id,
        ttl,
        chunk_idx,
        total_chunks,
        timestamp_ms,
        counter,
    )


def build_packet(
    *,
    channel_id: bytes,
    sender_id: bytes,
    payload: bytes,
    signing_key: SigningKey | None = None,
    signature: bytes | None = None,
    version: int = PROTOCOL_VERSION,
    type_: int = TYPE_VOICE_DATA,
    msg_id: bytes | None = None,
    ttl: int = DEFAULT_TTL,
    chunk_idx: int = 0,
    total_chunks: int = 1,
    timestamp_ms: int | None = None,
    counter: int = 1,
) -> bytes:
    """Build one wire frame. Unsigned (zero signature) when no key is given."""
    if len(channel_id) != CHANNEL_ID_SIZE:
        raise ValueError("channel_id must be 8 bytes")
    if len(sender_id) != SENDER_ID_SIZE:
        raise ValueError("sender_id must be 8 bytes")
    if not 0 <= ttl <= 0xFF:
        raise ValueError("ttl must fit in u8")
    if not 0 <= chunk_idx <= 0xFFFF:
        raise ValueError("chunk_idx must fit in u16")
    if not 0 <= total_chunks <= 0xFFFF:
        raise ValueError("total_chunks must fit in u16")
    if not 0 <= counter <= 0xFFFFFFFF:
        raise ValueError("counter must fit in u32")

    msg_id = msg_id if msg_id is not None else random_id()
    timestamp_ms = timestamp_ms if timestamp_ms is not None else now_ms()
    packet = Packet(
        version=version,
        type=type_,
        msg_id=msg_id,
        channel_id=channel_id,
        sender_id=sender_id,
        ttl=ttl,
        chunk_idx=chunk_idx,
        total_chunks=total_chunks,
        timestamp_ms=timestamp_ms,
        counter=counter,
        signature=bytes(SIG_LEN),
        payload=payload,
    )
    if signature is not None:
        sig = signature
    elif signing_key is not None:
        sig = signing_key.sign(packet.signing_input).signature
    else:
        sig = bytes(SIG_LEN)
    if len(sig) != SIG_LEN:
        raise ValueError("signature must be 64 bytes")
    return packet.header + sig + payload


def seal(key: bytes, plaintext: bytes, aad: bytes, *, nonce: bytes | None = None) -> bytes:
    if len(key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES:
        raise ValueError("channel key must be 32 bytes")
    nonce = (
        nonce
        if nonce is not None
        else secrets.token_bytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    )
    if len(nonce) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:
        raise ValueError("nonce must be 24 bytes")
    return nonce + crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


def open_sealed(key: bytes, payload: bytes, aad: bytes) -> bytes:
    if len(payload) < MIN_SEALED_PAYLOAD:
        raise PacketError("sealed payload too short")
    nonce = payload[: crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]
    ciphertext = payload[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES :]
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)
    except CryptoError as exc:
        raise PacketError("AEAD open failed") from exc


def channel_id_for_key(channel_key: bytes) -> bytes:
    if len(channel_key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES:
        raise ValueError("channel key must be 32 bytes")
    return hashlib.sha256(CHANNEL_ID_DOMAIN + channel_key).digest()[:CHANNEL_ID_SIZE]


def epoch_for(timestamp_ms: int) -> int:
    return timestamp_ms // EPOCH_MS


def sender_id_for_pubkey(channel_key: bytes, pubkey: bytes, timestamp_ms: int) -> bytes:
    """Rotating ID per docs v1: HMAC(id_key, domain || pubkey || epoch_u64be)."""
    if len(channel_key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES:
        raise ValueError("channel key must be 32 bytes")
    if len(pubkey) != IDENTITY_PUBKEY_SIZE:
        raise ValueError("identity pubkey must be 32 bytes")
    id_key = hmac.new(channel_key, SENDER_ID_KEY_DOMAIN, hashlib.sha256).digest()
    transcript = SENDER_ID_DOMAIN + pubkey + struct.pack(">Q", epoch_for(timestamp_ms))
    return hmac.new(id_key, transcript, hashlib.sha256).digest()[:SENDER_ID_SIZE]


def build_voice_message(
    *,
    channel_key: bytes,
    signing_key: SigningKey,
    plaintext: bytes,
    sender_id: bytes | None = None,
    chunk_size: int = MAX_PLAINTEXT_CHUNK,
    ttl: int = DEFAULT_TTL,
    timestamp_ms: int | None = None,
    msg_id: bytes | None = None,
    counter: int | None = None,
    nonces: list[bytes] | None = None,
) -> tuple[bytes, list[bytes]]:
    """Build a sealed, signed, chunked voice message per the v1 format.

    ``nonces`` is only for deterministic contract vectors/self-checks. Omit it
    in tests that emulate a real sender.
    """
    if not 1 <= chunk_size <= MAX_PLAINTEXT_CHUNK:
        raise ValueError(f"chunk_size must be 1..{MAX_PLAINTEXT_CHUNK}")
    channel_id = channel_id_for_key(channel_key)
    msg_id = msg_id if msg_id is not None else random_id()
    timestamp_ms = timestamp_ms if timestamp_ms is not None else now_ms()
    counter = counter if counter is not None else next_counter()
    pubkey = signing_key.verify_key.encode()
    sender_id = (
        sender_id
        if sender_id is not None
        else sender_id_for_pubkey(channel_key, pubkey, timestamp_ms)
    )
    if len(sender_id) != SENDER_ID_SIZE:
        raise ValueError("sender_id must be 8 bytes")

    chunks = [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)]
    if not chunks:
        chunks = [b""]
    if not MIN_TOTAL_CHUNKS <= len(chunks) <= MAX_TOTAL_CHUNKS:
        raise ValueError(f"total_chunks {len(chunks)} outside 1..{MAX_TOTAL_CHUNKS}")
    if nonces is not None and len(nonces) != len(chunks):
        raise ValueError("nonces must match the chunk count")

    frames: list[bytes] = []
    for index, chunk in enumerate(chunks):
        packet = Packet(
            version=PROTOCOL_VERSION,
            type=TYPE_VOICE_DATA,
            msg_id=msg_id,
            channel_id=channel_id,
            sender_id=sender_id,
            ttl=ttl,
            chunk_idx=index,
            total_chunks=len(chunks),
            timestamp_ms=timestamp_ms,
            counter=counter,
            signature=bytes(SIG_LEN),
            payload=b"",
        )
        sealed = seal(
            channel_key,
            chunk,
            packet.aad,
            nonce=nonces[index] if nonces is not None else None,
        )
        if len(sealed) > MAX_PAYLOAD:
            raise ValueError(f"sealed chunk {len(sealed)} > {MAX_PAYLOAD} bytes")
        signature = signing_key.sign(replace(packet, payload=sealed).signing_input).signature
        frames.append(packet.header + signature + sealed)
    return msg_id, frames


def verify_packet(packet: Packet, pubkey: bytes) -> bool:
    try:
        VerifyKey(pubkey).verify(packet.signing_input, packet.signature)
        return True
    except (BadSignatureError, ValueError):
        return False


def validate_frame(frame: bytes, *, now: int | None = None) -> str | None:
    """Return a rejection reason if the frame violates the v1 limits.

    Structural checks only; roster resolution, signature verification, replay
    and dedup are stateful and belong to the caller.
    """
    if len(frame) < HEADER_LEN:
        return f"frame too short ({len(frame)} < {HEADER_LEN})"
    if len(frame) > MAX_FRAME:
        return f"frame too large ({len(frame)} > {MAX_FRAME})"
    packet = parse_packet(frame)
    if packet.version != PROTOCOL_VERSION:
        return f"bad version {packet.version}"
    if not MIN_TTL <= packet.ttl <= MAX_TTL:
        return f"ttl {packet.ttl} outside {MIN_TTL}..{MAX_TTL}"
    if not MIN_TOTAL_CHUNKS <= packet.total_chunks <= MAX_TOTAL_CHUNKS:
        return f"total_chunks {packet.total_chunks} outside {MIN_TOTAL_CHUNKS}..{MAX_TOTAL_CHUNKS}"
    if not 0 <= packet.chunk_idx < packet.total_chunks:
        return f"chunk_idx {packet.chunk_idx} >= total_chunks {packet.total_chunks}"
    if len(packet.payload) > MAX_PAYLOAD:
        return f"chunk payload {len(packet.payload)} > {MAX_PAYLOAD}"
    if len(packet.payload) < MIN_SEALED_PAYLOAD:
        return f"sealed chunk {len(packet.payload)} < {MIN_SEALED_PAYLOAD}"
    if packet.counter < 1:
        return "counter == 0"
    if now is not None:
        if packet.timestamp_ms > now + FUTURE_SKEW_MS:
            return "timestamp too far in the future"
        if packet.timestamp_ms < now - RETENTION_MS:
            return "timestamp older than retention"
    return None


def reassemble(
    frames: list[bytes],
    channel_key: bytes,
    *,
    signer_public_key: bytes | None = None,
    now: int | None = None,
) -> bytes:
    """Validate, verify, decrypt and join all chunks of one message."""
    if not frames:
        raise PacketError("no frames")
    packets: list[Packet] = []
    for frame in frames:
        reason = validate_frame(frame, now=now)
        if reason is not None:
            raise PacketError(reason)
        packets.append(parse_packet(frame))
    first = packets[0]
    for packet in packets[1:]:
        if (
            packet.version != first.version
            or packet.type != first.type
            or packet.channel_id != first.channel_id
            or packet.msg_id != first.msg_id
            or packet.sender_id != first.sender_id
            or packet.timestamp_ms != first.timestamp_ms
            or packet.counter != first.counter
            or packet.total_chunks != first.total_chunks
        ):
            raise PacketError("mismatched shared header fields")
    indexes = sorted(packet.chunk_idx for packet in packets)
    if indexes != list(range(first.total_chunks)):
        raise PacketError("incomplete or duplicate chunks")
    if sum(len(packet.payload) for packet in packets) > MAX_REASSEMBLED:
        raise PacketError("reassembled message too large")

    plaintext = bytearray()
    for packet in sorted(packets, key=lambda item: item.chunk_idx):
        if signer_public_key is not None and not verify_packet(packet, signer_public_key):
            raise PacketError("signature verification failed")
        plaintext.extend(open_sealed(channel_key, packet.payload, packet.aad))
        if len(plaintext) > MAX_REASSEMBLED:
            raise PacketError("reassembled message too large")
    return bytes(plaintext)


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
        packet = parse_packet(frame)
    except PacketError as exc:
        return f"{len(frame)}B unparseable ({exc})"
    return (
        f"{len(frame)}B channel={packet.channel_id.hex()} msg={packet.msg_id.hex()} "
        f"sender={packet.sender_id.hex()} ttl={packet.ttl} "
        f"chunk={packet.chunk_idx}/{packet.total_chunks} "
        f"ts={packet.timestamp_ms} counter={packet.counter}"
    )
