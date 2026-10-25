"""Wire format and crypto helpers pinned to ``docs/packet-format.md`` v1.

Header (107 bytes, big-endian):

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
    43  64  signature           Ed25519 over header[ttl=0, sig=0] || payload
    107 ... payload             fragment of the single sealed message (0..405 B)

A message is sealed once (nonce || ciphertext+tag, AAD =
channel_id || msg_id || timestamp_ms || counter) and fragmented into 405-byte
payloads. Every packet is signed independently. Relays decrement `ttl`, so it
is deliberately outside the signature; the 1..16 bound and dedup cache contain
malicious TTL inflation.

Keep this module in lockstep with the docs. The Kotlin crypto implementation
currently derives IDs with different domains/AAD; that drift is tracked as
SEC-016 in ``security/findings.md``.
"""

from __future__ import annotations

import hashlib
import hmac
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
from nacl.signing import SigningKey, VerifyKey

PROTOCOL_VERSION = 1
TYPE_VOICE_DATA = 0x01
TYPE_DELIVERY_RECEIPT = 0x02
TYPE_MEMBER_ANNOUNCE = 0x03
TYPE_KEY_ROTATE = 0x04

HEADER_BODY = struct.Struct(">BB8s8s8sBHHQI")  # 43 bytes
HEADER_LEN = 107
SIG_OFFSET = 43
SIG_LEN = 64
TTL_OFFSET = 26
MAX_FRAME = 512
MAX_PAYLOAD = 405
MAX_TOTAL_CHUNKS = 162
MAX_REASSEMBLED = 64 * 1024
MAX_TTL = 16
DEFAULT_TTL = 5
REASSEMBLY_TIMEOUT_MS = 120_000
RETENTION_MS = 24 * 3600 * 1000
FUTURE_SKEW_MS = 5 * 60 * 1000
EPOCH_MS = 15 * 60 * 1000

CHANNEL_ID_SIZE = 8
SENDER_ID_SIZE = 8
IDENTITY_PUBKEY_SIZE = 32
COUNTER_MIN = 1
COUNTER_MAX = 0xFFFFFFFF

CHANNEL_ID_DOMAIN = b"bit-audio/channel-id/v1"
SENDER_ID_DOMAIN = b"bit-audio/sender-id/v1"


class PacketError(ValueError):
    """A frame cannot be parsed or fails a structural/protocol limit."""


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
        return HEADER_BODY.pack(
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

    def to_bytes(self) -> bytes:
        return self.header + self.signature + self.payload

    @property
    def signing_input(self) -> bytes:
        transcript = bytearray(self.header + bytes(SIG_LEN) + self.payload)
        transcript[TTL_OFFSET] = 0
        return bytes(transcript)

    @property
    def aad(self) -> bytes:
        return (
            self.channel_id
            + self.msg_id
            + struct.pack(">Q", self.timestamp_ms)
            + struct.pack(">I", self.counter)
        )


def parse_packet(data: bytes) -> Packet:
    if len(data) < HEADER_LEN:
        raise PacketError(f"truncated frame: {len(data)} < {HEADER_LEN} bytes")
    body = HEADER_BODY.unpack(data[:HEADER_BODY.size])
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


def signing_input(
    *,
    version: int,
    type_: int,
    msg_id: bytes,
    channel_id: bytes,
    sender_id: bytes,
    ttl: int,
    chunk_idx: int,
    total_chunks: int,
    timestamp_ms: int,
    counter: int,
    payload: bytes,
) -> bytes:
    header = HEADER_BODY.pack(
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
    transcript = bytearray(header + bytes(SIG_LEN) + payload)
    transcript[TTL_OFFSET] = 0
    return bytes(transcript)


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
    msg_id = msg_id if msg_id is not None else random_id()
    timestamp_ms = timestamp_ms if timestamp_ms is not None else now_ms()
    if not 0 <= counter <= COUNTER_MAX:
        raise ValueError("counter must fit in u32")
    transcript = signing_input(
        version=version,
        type_=type_,
        msg_id=msg_id,
        channel_id=channel_id,
        sender_id=sender_id,
        ttl=ttl,
        chunk_idx=chunk_idx,
        total_chunks=total_chunks,
        timestamp_ms=timestamp_ms,
        counter=counter,
        payload=payload,
    )
    if signature is not None:
        sig = signature
    elif signing_key is not None:
        sig = signing_key.sign(transcript).signature
    else:
        sig = bytes(SIG_LEN)
    if len(sig) != SIG_LEN:
        raise ValueError("signature must be 64 bytes")
    header = HEADER_BODY.pack(
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


def channel_id_for_key(channel_key: bytes) -> bytes:
    if len(channel_key) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES:
        raise ValueError("channel key must be 32 bytes")
    return hmac.new(channel_key, CHANNEL_ID_DOMAIN, hashlib.sha256).digest()[:CHANNEL_ID_SIZE]


def sender_id_for_pubkey(channel_key: bytes, pubkey: bytes, timestamp_ms: int) -> bytes:
    """Rotating ID per docs/packet-format.md: HMAC(key, domain||pubkey||epoch)."""
    if len(pubkey) != IDENTITY_PUBKEY_SIZE:
        raise ValueError("identity pubkey must be 32 bytes")
    epoch = timestamp_ms // EPOCH_MS
    transcript = SENDER_ID_DOMAIN + pubkey + struct.pack(">Q", epoch)
    return hmac.new(channel_key, transcript, hashlib.sha256).digest()[:SENDER_ID_SIZE]


def build_voice_message(
    *,
    channel_key: bytes,
    signing_key: SigningKey,
    plaintext: bytes,
    ttl: int = DEFAULT_TTL,
    timestamp_ms: int | None = None,
    msg_id: bytes | None = None,
    counter: int | None = None,
    sender_id: bytes | None = None,
    nonce: bytes | None = None,
) -> tuple[bytes, list[bytes]]:
    """Build a sealed, signed, fragmented voice message per the v1 format.

    ``nonce`` is only for deterministic contract vectors/self-checks; omit it in
    tests that emulate a real sender.
    """
    channel_id = channel_id_for_key(channel_key)
    msg_id = msg_id if msg_id is not None else random_id()
    timestamp_ms = timestamp_ms if timestamp_ms is not None else now_ms()
    counter = counter if counter is not None else secrets.randbelow(COUNTER_MAX - 1) + COUNTER_MIN
    pubkey = signing_key.verify_key.encode()
    sender_id = sender_id if sender_id is not None else sender_id_for_pubkey(
        channel_key, pubkey, timestamp_ms
    )
    aad = channel_id + msg_id + struct.pack(">Q", timestamp_ms) + struct.pack(">I", counter)
    sealed = seal(channel_key, plaintext, aad, nonce=nonce)
    if len(sealed) > MAX_REASSEMBLED:
        raise ValueError(f"sealed message {len(sealed)} B exceeds {MAX_REASSEMBLED} B")
    chunks = [sealed[i : i + MAX_PAYLOAD] for i in range(0, len(sealed), MAX_PAYLOAD)]
    total = len(chunks)
    if not 1 <= total <= MAX_TOTAL_CHUNKS:
        raise ValueError(f"total_chunks {total} outside 1..{MAX_TOTAL_CHUNKS}")
    frames = [
        build_packet(
            channel_id=channel_id,
            sender_id=sender_id,
            payload=chunk,
            signing_key=signing_key,
            msg_id=msg_id,
            ttl=ttl,
            chunk_idx=index,
            total_chunks=total,
            timestamp_ms=timestamp_ms,
            counter=counter,
        )
        for index, chunk in enumerate(chunks)
    ]
    return msg_id, frames


def verify_packet(packet: Packet, pubkey: bytes) -> bool:
    try:
        VerifyKey(pubkey).verify(packet.signing_input, packet.signature)
        return True
    except Exception:
        return False


def reassemble(frames: list[bytes], channel_key: bytes) -> bytes:
    """Verify structure and decrypt a complete message. Signature check is separate."""
    if not frames:
        raise PacketError("no frames")
    packets: list[Packet] = []
    for frame in frames:
        reason = validate_frame(frame)
        if reason is not None:
            raise PacketError(reason)
        packets.append(parse_packet(frame))
    first = packets[0]
    for packet in packets[1:]:
        if (
            packet.channel_id != first.channel_id
            or packet.msg_id != first.msg_id
            or packet.sender_id != first.sender_id
            or packet.timestamp_ms != first.timestamp_ms
            or packet.counter != first.counter
            or packet.total_chunks != first.total_chunks
        ):
            raise PacketError("mismatched shared header fields")
    indexes = [packet.chunk_idx for packet in packets]
    if sorted(indexes) != list(range(first.total_chunks)):
        raise PacketError("incomplete or duplicate chunks")
    sealed = b"".join(packet.payload for packet in sorted(packets, key=lambda p: p.chunk_idx))
    if len(sealed) > MAX_REASSEMBLED:
        raise PacketError("reassembled message too large")
    return open_sealed(channel_key, sealed, first.aad)


def validate_frame(frame: bytes) -> str | None:
    """Return a rejection reason if the frame violates the v1 limits."""
    if len(frame) < HEADER_LEN:
        return f"frame too short ({len(frame)} < {HEADER_LEN})"
    if len(frame) > MAX_FRAME:
        return f"frame too large ({len(frame)} > {MAX_FRAME})"
    try:
        packet = parse_packet(frame)
    except PacketError as exc:
        return str(exc)
    if packet.version != PROTOCOL_VERSION:
        return f"bad version {packet.version}"
    if not 1 <= packet.ttl <= MAX_TTL:
        return f"ttl {packet.ttl} outside 1..{MAX_TTL}"
    if not 1 <= packet.total_chunks <= MAX_TOTAL_CHUNKS:
        return f"total_chunks {packet.total_chunks} outside 1..{MAX_TOTAL_CHUNKS}"
    if not 0 <= packet.chunk_idx < packet.total_chunks:
        return f"chunk_idx {packet.chunk_idx} >= total_chunks {packet.total_chunks}"
    if len(packet.payload) > MAX_PAYLOAD:
        return f"chunk payload {len(packet.payload)} > {MAX_PAYLOAD}"
    if packet.counter < COUNTER_MIN:
        return "counter == 0"
    return None


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
        f"{len(frame)}B channel={p.channel_id.hex()} msg={p.msg_id.hex()} "
        f"sender={p.sender_id.hex()} ttl={p.ttl} chunk={p.chunk_idx}/{p.total_chunks} "
        f"ts={p.timestamp_ms} counter={p.counter}"
    )
