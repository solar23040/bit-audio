#!/usr/bin/env python3
"""Mesh attack cases over an in-memory ``FakeNetwork``. No hardware needed.

Cases mirror the Phase 5 checklist (``pllan.md``):

  forged-sender      a member signs with their own key but claims a victim's
                     rotating sender ID -> unresolved/signature failure, dropped
  replayed-packet    the same frame arrives twice -> delivered once, not relayed
                     a second time
  malformed-header   huge total_chunks, chunk_idx overflow, truncated and
                     oversized frames -> rejected before allocation, no crash
  ttl-zero-relay     ttl=0 is dropped; ttl=1 is delivered without rebroadcast;
                     ttl=2 is relayed once with ttl decremented

The node below is a **reference implementation of the documented rules**, not
production code. ``:mesh`` is still interface-only on main (see SEC-017), so
this suite gives Agent D an executable specification and runs in CI today.
Retarget the node to the real ``Mesh`` when it lands.

  python test_mesh_contract.py
"""

from __future__ import annotations

import secrets
import struct
import sys
from collections import deque
from dataclasses import dataclass, field

from nacl.signing import SigningKey

from wire import (
    HEADER_LEN,
    MAX_FRAME,
    TTL_OFFSET,
    PacketError,
    build_voice_message,
    channel_id_for_key,
    open_sealed,
    parse_packet,
    sender_id_for_pubkey,
    validate_frame,
    verify_packet,
)

NOW_MS = 1_700_000_000_000
CHANNEL_KEY = bytes(range(32))
ALICE_SEED = bytes(range(32, 64))
BOB_SEED = bytes(range(64, 96))


class FakeNetwork:
    """Synchronous in-memory mesh links; one queue entry per transmission."""

    def __init__(self) -> None:
        self._links: dict[str, set[str]] = {}
        self._nodes: dict[str, "MeshNode"] = {}
        self._queue: deque[tuple[str, str, bytes]] = deque()
        self.transmissions: list[tuple[str, str, bytes]] = []

    def add_node(self, node: "MeshNode") -> None:
        self._nodes[node.name] = node
        self._links.setdefault(node.name, set())
        node.attach(self)

    def connect(self, left: str, right: str) -> None:
        self._links.setdefault(left, set()).add(right)
        self._links.setdefault(right, set()).add(left)

    def neighbours(self, name: str) -> set[str]:
        return set(self._links.get(name, set()))

    def send(self, src: str, dst: str, frame: bytes) -> None:
        if dst in self._links.get(src, set()):
            self._queue.append((src, dst, frame))

    def run(self) -> int:
        """Deliver until quiet. Returns the number of transmissions."""
        count = 0
        while self._queue:
            src, dst, frame = self._queue.popleft()
            self.transmissions.append((src, dst, frame))
            node = self._nodes.get(dst)
            if node is not None:
                node.receive(src, frame)
            count += 1
        return count


@dataclass
class MeshNode:
    name: str
    channel_key: bytes
    roster: dict[bytes, bytes]  # public key -> display alias
    now_ms: int = NOW_MS
    delivered: list[tuple[bytes, bytes, int]] = field(default_factory=list)  # msg_id, plaintext, ttl
    dropped: list[tuple[str, bytes]] = field(default_factory=list)
    relayed_ttls: list[int] = field(default_factory=list)
    crashes: list[str] = field(default_factory=list)

    def attach(self, network: FakeNetwork) -> None:
        self.network = network
        self._seen: set[tuple[bytes, bytes, int]] = set()
        self._counters: dict[bytes, dict[int, bytes]] = {}
        self._partials: dict[bytes, dict[int, object]] = {}

    def _resolve(self, sender_id: bytes, timestamp_ms: int) -> bytes | None:
        epoch = timestamp_ms // (15 * 60 * 1000)
        for pubkey in self.roster:
            for candidate in (epoch - 1, epoch, epoch + 1):
                expected = sender_id_for_pubkey(
                    self.channel_key, pubkey, candidate * 15 * 60 * 1000
                )
                if secrets.compare_digest(expected, sender_id):
                    return pubkey
        return None

    def receive(self, src: str, frame: bytes) -> None:
        try:
            self._handle(src, frame)
        except Exception as exc:  # noqa: BLE001 - any parser crash is a finding
            self.crashes.append(f"{type(exc).__name__}: {exc}")

    def _handle(self, src: str, frame: bytes) -> None:
        reason = validate_frame(frame, now=self.now_ms)
        if reason is not None:
            self.dropped.append((reason, frame))
            return

        packet = parse_packet(frame)
        if packet.channel_id != channel_id_for_key(self.channel_key):
            self.dropped.append(("unknown channel", frame))
            return

        identity = self._resolve(packet.sender_id, packet.timestamp_ms)
        if identity is None:
            self.dropped.append(("unresolved sender", frame))
            return
        if not verify_packet(packet, identity):
            self.dropped.append(("bad signature", frame))
            return

        # Replay defense: one counter value maps to one msg_id per identity.
        counters = self._counters.setdefault(identity, {})
        mapped = counters.setdefault(packet.counter, packet.msg_id)
        if mapped != packet.msg_id:
            self.dropped.append(("counter replay", frame))
            return

        # Dedup only after authentication.
        dedup_key = (identity, packet.msg_id, packet.chunk_idx)
        if dedup_key in self._seen:
            self.dropped.append(("duplicate chunk", frame))
            return
        self._seen.add(dedup_key)

        partial = self._partials.setdefault(packet.msg_id, {})
        partial[packet.chunk_idx] = packet
        if len(partial) != packet.total_chunks:
            return

        message = self._complete(packet, partial)
        if message is None:
            return
        self._partials.pop(packet.msg_id, None)
        self.delivered.append((packet.msg_id, message, packet.ttl))

        # Relay unchanged bytes except the deliberately unsigned TTL.
        if packet.ttl > 1 and self.now_ms - packet.timestamp_ms <= 120_000:
            relayed = bytearray(frame)
            relayed[TTL_OFFSET] = packet.ttl - 1
            for peer in sorted(self.network.neighbours(self.name)):
                if peer != src:
                    self.network.send(self.name, peer, bytes(relayed))
            self.relayed_ttls.append(packet.ttl - 1)

    def _complete(self, first: object, partial: dict[int, object]) -> bytes | None:
        ordered = [partial[index] for index in sorted(partial)]
        plaintext = bytearray()
        for packet in ordered:
            if (
                packet.channel_id != first.channel_id
                or packet.sender_id != first.sender_id
                or packet.timestamp_ms != first.timestamp_ms
                or packet.counter != first.counter
                or packet.total_chunks != first.total_chunks
            ):
                self.dropped.append(("mismatched shared header", b""))
                return None
            try:
                plaintext.extend(open_sealed(self.channel_key, packet.payload, packet.aad))
            except PacketError:
                self.dropped.append(("AEAD failure", b""))
                return None
        return bytes(plaintext)


@dataclass
class Harness:
    network: FakeNetwork
    alice: SigningKey
    bob: SigningKey

    @property
    def alice_pub(self) -> bytes:
        return self.alice.verify_key.encode()

    @property
    def bob_pub(self) -> bytes:
        return self.bob.verify_key.encode()

    def roster(self) -> dict[bytes, bytes]:
        return {self.alice_pub: b"alice", self.bob_pub: b"bob"}

    def node(self, name: str) -> MeshNode:
        node = MeshNode(name=name, channel_key=CHANNEL_KEY, roster=self.roster())
        self.network.add_node(node)
        return node

    def message(
        self,
        signing_key: SigningKey,
        *,
        sender_id: bytes | None = None,
        plaintext: bytes = b"voice note",
        ttl: int = 5,
        msg_id: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        return build_voice_message(
            channel_key=CHANNEL_KEY,
            signing_key=signing_key,
            plaintext=plaintext,
            sender_id=sender_id,
            ttl=ttl,
            timestamp_ms=NOW_MS,
            msg_id=msg_id or secrets.token_bytes(8),
        )


def _rewrite_u16(frame: bytes, offset: int, value: int) -> bytes:
    data = bytearray(frame)
    data[offset : offset + 2] = struct.pack(">H", value)
    return bytes(data)


def case_forged_sender(harness: Harness) -> None:
    receiver = harness.node("bob")
    harness.network.connect("alice", "bob")
    alice_id = sender_id_for_pubkey(CHANNEL_KEY, harness.alice_pub, NOW_MS)

    # Bob signs a clip that claims Alice's rotating ID.
    msg_id, frames = harness.message(harness.bob, sender_id=alice_id)
    harness.network.send("alice", "bob", frames[0])
    harness.network.run()

    assert not receiver.delivered, "forged sender was delivered"
    assert not receiver.relayed_ttls, "forged sender was relayed"
    assert any(reason == "bad signature" for reason, _ in receiver.dropped), (
        f"expected bad-signature drop, got {[reason for reason, _ in receiver.dropped]}"
    )
    assert not receiver.crashes, receiver.crashes

    # Unknown sender ID must be dropped before verification.
    _, unknown = harness.message(harness.bob, sender_id=secrets.token_bytes(8), msg_id=msg_id)
    harness.network.send("alice", "bob", unknown[0])
    harness.network.run()
    assert any(reason == "unresolved sender" for reason, _ in receiver.dropped)


def case_replayed_packet(harness: Harness) -> None:
    receiver = harness.node("bob")
    _, frames = harness.message(harness.alice)
    harness.network.connect("alice", "bob")

    harness.network.send("alice", "bob", frames[0])
    harness.network.send("alice", "bob", frames[0])
    harness.network.run()

    assert len(receiver.delivered) == 1, f"replay delivered {len(receiver.delivered)} times"
    assert any(reason == "duplicate chunk" for reason, _ in receiver.dropped), (
        "replay was not detected by the dedup cache"
    )
    assert len(receiver.relayed_ttls) == 1, "replay caused a second relay"


def case_malformed_header(harness: Harness) -> None:
    receiver = harness.node("bob")
    harness.network.connect("alice", "bob")
    _, frames = harness.message(harness.alice)
    valid = frames[0]

    cases = {
        "huge total_chunks": _rewrite_u16(valid, 29, 0xFFFF),
        "chunk_idx overflow": _rewrite_u16(valid, 27, 0xFFFF),
        "truncated header": valid[: HEADER_LEN - 1],
        "truncated mid-header": valid[:20],
        "oversize frame": valid + bytes(MAX_FRAME),
        "empty payload": valid[:HEADER_LEN],
        "ttl overflow": valid[:TTL_OFFSET] + b"\xff" + valid[TTL_OFFSET + 1 :],
    }

    for name, frame in cases.items():
        before = len(receiver.dropped)
        harness.network.send("alice", "bob", frame)
        harness.network.run()
        assert len(receiver.dropped) > before, f"{name} was not rejected"
        assert not receiver.delivered, f"{name} was delivered"
        assert not receiver.relayed_ttls, f"{name} was relayed"

    assert not receiver.crashes, f"parser crashed on malformed input: {receiver.crashes}"


def case_ttl_zero_relay(harness: Harness) -> None:
    middle = harness.node("b")
    far = harness.node("c")
    harness.network.connect("a", "b")
    harness.network.connect("b", "c")

    # ttl=0: reject at ingress, no delivery, no relay.
    _, zero = harness.message(harness.alice, ttl=0)
    harness.network.send("a", "b", zero[0])
    harness.network.run()
    assert not middle.delivered, "ttl=0 was delivered"
    assert not middle.relayed_ttls, "ttl=0 was relayed"
    assert any("ttl 0" in reason for reason, _ in middle.dropped)

    # ttl=1: deliver locally, never rebroadcast.
    _, one = harness.message(harness.alice, ttl=1, plaintext=b"ttl one")
    harness.network.send("a", "b", one[0])
    harness.network.run()
    assert [payload for _, payload, _ in middle.delivered] == [b"ttl one"]
    assert not middle.relayed_ttls, "ttl=1 was relayed"
    assert not far.delivered, "ttl=1 reached the far node"

    # ttl=2: relay once with ttl decremented; the far node must not rebroadcast.
    _, two = harness.message(harness.alice, ttl=2, plaintext=b"ttl two")
    harness.network.send("a", "b", two[0])
    harness.network.run()
    assert [payload for _, payload, _ in middle.delivered] == [b"ttl one", b"ttl two"]
    assert [payload for _, payload, _ in far.delivered] == [b"ttl two"]
    assert middle.relayed_ttls == [1], middle.relayed_ttls
    assert not far.relayed_ttls, "ttl=1 copy was rebroadcast by the far node"
    relayed_to_far = [frame for src, dst, frame in harness.network.transmissions if src == "b" and dst == "c"]
    assert relayed_to_far and relayed_to_far[-1][TTL_OFFSET] == 1, "relay did not decrement ttl"
    assert not any(src == "c" for src, _, _ in harness.network.transmissions), "far node transmitted"


def main() -> int:
    alice = SigningKey(ALICE_SEED)
    bob = SigningKey(BOB_SEED)
    cases = (
        ("forged-sender", case_forged_sender),
        ("replayed-packet", case_replayed_packet),
        ("malformed-header", case_malformed_header),
        ("ttl-zero-relay", case_ttl_zero_relay),
    )
    failures = 0
    for name, case in cases:
        harness = Harness(network=FakeNetwork(), alice=alice, bob=bob)
        try:
            case(harness)
        except AssertionError as exc:
            print(f"FAIL {name}: {exc}", file=sys.stderr)
            failures += 1
        else:
            print(f"PASS {name}")
    if failures:
        return 1
    print(f"PASS mesh contract attacks: {len(cases)} cases over FakeNetwork")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
