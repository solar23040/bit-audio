#!/usr/bin/env python3
"""Spoofing tests: forged sender ID, header rewrite, and cache poisoning.

Expected observations:
  baseline        -> delivered and playable
  forged-id       -> dropped silently (signature does not match victim key)
  modified-sender -> dropped silently (sender_id is signed and resolved via roster)
  poison          -> forged frame first, then the valid baseline with the SAME
                     msg_id; exactly one valid clip may be delivered. Any loss or
                     duplicate points at SEC-001.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
from dataclasses import replace

from config import (
    RateLimiter,
    add_sink_args,
    check_frame_size,
    effective_rate,
    identity_from_config,
    resolve_config,
    setup_logging,
)
from sinks import SinkError, make_sink
from wire import (
    build_voice_message,
    frame_summary,
    from_hex,
    hexs,
    now_ms,
    parse_packet,
    sender_id_for_pubkey,
    verify_packet,
)


async def run(args: argparse.Namespace) -> int:
    cfg = resolve_config(args)
    signing_key, pubkey = identity_from_config(cfg)
    own_sender_id = from_hex(args.sender_id_hex) if args.sender_id_hex else None
    if own_sender_id is not None and len(own_sender_id) != 8:
        raise SystemExit("--sender-id-hex must be 8 bytes")

    if cfg.victim_pubkey is None and cfg.victim_sender_id is None:
        raise SystemExit(
            "spoofing tests need victim.pubkey_hex (preferred) or "
            "victim.sender_id_hex in the config"
        )

    cases = [args.case] if args.case != "all" else [
        "baseline",
        "forged-id",
        "modified-sender",
        "poison",
    ]

    def victim_id(timestamp_ms: int) -> bytes:
        if cfg.victim_sender_id is not None:
            return cfg.victim_sender_id
        assert cfg.victim_pubkey is not None
        return sender_id_for_pubkey(cfg.channel_key, cfg.victim_pubkey, timestamp_ms)

    token = secrets.token_hex(4)
    sink = make_sink(args, cfg)
    limiter = RateLimiter(effective_rate(args, cfg))
    rows: list[tuple[str, str, str]] = []
    failures = 0

    await sink.open()
    try:
        for case in cases:
            text = f"Agent H spoof {case} {token}".encode()
            timestamp = now_ms()
            if case == "baseline":
                msg_id, frames = build_voice_message(
                    channel_key=cfg.channel_key,
                    signing_key=signing_key,
                    plaintext=text,
                    timestamp_ms=timestamp,
                    sender_id=own_sender_id,
                )
                rows.append((case, hexs(msg_id), "delivered"))
            elif case == "forged-id":
                forged_id = victim_id(timestamp)
                msg_id, frames = build_voice_message(
                    channel_key=cfg.channel_key,
                    signing_key=signing_key,
                    plaintext=text,
                    timestamp_ms=timestamp,
                    sender_id=forged_id,
                )
                rows.append((case, hexs(msg_id), "dropped"))
            elif case == "modified-sender":
                _, baseline = build_voice_message(
                    channel_key=cfg.channel_key,
                    signing_key=signing_key,
                    plaintext=text,
                    timestamp_ms=timestamp,
                    sender_id=own_sender_id,
                )
                packet = parse_packet(baseline[0])
                frames = [
                    replace(packet, sender_id=victim_id(packet.timestamp_ms)).to_bytes()
                ]
                msg_id = packet.msg_id
                rows.append((case, hexs(msg_id), "dropped"))
            elif case == "poison":
                base_id, baseline = build_voice_message(
                    channel_key=cfg.channel_key,
                    signing_key=signing_key,
                    plaintext=text,
                    timestamp_ms=timestamp,
                    sender_id=own_sender_id,
                )
                _, forged = build_voice_message(
                    channel_key=cfg.channel_key,
                    signing_key=signing_key,
                    plaintext=b"garbage " + text,
                    timestamp_ms=timestamp,
                    msg_id=base_id,
                    sender_id=victim_id(timestamp),
                )
                frames = forged[:1] + baseline
                msg_id = base_id
                rows.append((case, hexs(msg_id), "only valid baseline delivered, once"))
            else:
                raise SystemExit(f"unknown case {case}")

            check_frame_size(frames)
            for index, frame in enumerate(frames):
                await limiter.wait()
                try:
                    await sink.send(frame)
                except SinkError as exc:
                    print(f"FAIL {case}: {exc}", file=sys.stderr)
                    return 2
                if args.verbose:
                    print(f"  {case} frame {index + 1}/{len(frames)}: {frame_summary(frame)}")
                if not sink.healthy():
                    print(f"FAIL {case}: sink became unhealthy after frame {index + 1}", file=sys.stderr)
                    failures += 1
                    break

            # Local prechecks: signed header fields must reject the fakes.
            if case in {"forged-id", "modified-sender"} and cfg.victim_pubkey is not None:
                if verify_packet(parse_packet(frames[0]), cfg.victim_pubkey):
                    print(f"WARN {case}: forged frame verifies under the victim key; test is invalid")
                    failures += 1
                else:
                    print(f"  precheck {case}: signature rejected under victim key (expected)")
            elif case == "baseline":
                if not verify_packet(parse_packet(frames[0]), pubkey):
                    print("WARN baseline: own signature does not verify; harness bug")
                    failures += 1
    finally:
        await sink.close()

    print()
    print(f"{'case':<18} {'msg_id':<18} expected on target")
    print("-" * 70)
    for case, msg_id, expected in rows:
        print(f"{case:<18} {msg_id:<18} {expected}")
    print()
    print("Record the result in security/findings.md:")
    print("  baseline playable, forged/modified absent, exactly one poison clip.")
    print(f"target: {sink.describe()}  |  test token: {token}")
    if failures:
        print(f"{failures} local harness problem(s); do not file target findings yet.", file=sys.stderr)
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_sink_args(parser)
    parser.add_argument(
        "--case",
        choices=("all", "baseline", "forged-id", "modified-sender", "poison"),
        default="all",
    )
    parser.add_argument(
        "--sender-id-hex",
        help="override the baseline sender ID (default: derived from the test identity)",
    )
    args = parser.parse_args()
    setup_logging(args.verbose)
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
