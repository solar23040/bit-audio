#!/usr/bin/env python3
"""Malicious-relay tamper tests: modify one frame of an otherwise valid message.

Prerequisite: the harness identity must be a member of a dedicated test channel
(its pubkey enrolled in the app). Then the baseline must be accepted; every
non-TTL mutation must be dropped, because the signed header and payload cannot
be changed without the sender's key.

TTL is deliberately outside the signature, so TTL-only mutations are skipped
unless --include-ttl is given; they test the 1..16 clamp and dedup instead.

Modes:
  generated (default)  fresh sealed+signed messages using the harness identity
  --capture-file PATH  mutate a message captured from a real sender (may be
                       rejected by anti-replay before the parser sees it)

The test only proves auth coverage if the baseline is delivered. If the
baseline is missing, enroll the harness identity or use --capture-file.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import secrets
import sys
from pathlib import Path

from captured import group_messages, load_capture, pick_message
from config import (
    RateLimiter,
    add_sink_args,
    check_frame_size,
    effective_rate,
    identity_from_config,
    resolve_config,
    setup_logging,
)
from mutations import EXPECTATIONS, MUTATIONS, TTL_MUTATIONS, apply
from sinks import SinkError, make_sink
from wire import (
    build_voice_message,
    frame_summary,
    from_hex,
    hexs,
    parse_packet,
    verify_packet,
)


def _selected_indexes(option: str, frame_count: int) -> list[int]:
    if option == "all":
        return list(range(frame_count))
    try:
        index = int(option)
    except ValueError as exc:
        raise SystemExit("--frame-index must be an integer or 'all'") from exc
    if not 0 <= index < frame_count:
        raise SystemExit(f"--frame-index {index} out of range (message has {frame_count} frames)")
    return [index]


async def run(args: argparse.Namespace) -> int:
    cfg = resolve_config(args)
    rate = effective_rate(args, cfg)
    if args.payload_file:
        plaintext = args.payload_file.read_bytes()
        if not plaintext:
            raise SystemExit("--payload-file is empty")
    else:
        plaintext = b"Agent H relay " + secrets.token_hex(4).encode() + b" " + secrets.token_bytes(args.size)

    signing_key = None
    pubkey = None
    sender_id = None
    if args.capture_file:
        captured = pick_message(group_messages(load_capture(args.capture_file)), args.msg_id, 0)
        base_frames = [item.frame for item in captured]
        msg_id = parse_packet(base_frames[0]).msg_id
        baseline_expected = "unclear (captured replay; depends on anti-replay)"
    else:
        signing_key, pubkey = identity_from_config(cfg)
        sender_id = from_hex(args.sender_id_hex) if args.sender_id_hex else None
        if sender_id is not None and len(sender_id) != 8:
            raise SystemExit("--sender-id-hex must be 8 bytes")
        msg_id, base_frames = build_voice_message(
            channel_key=cfg.channel_key,
            signing_key=signing_key,
            plaintext=plaintext,
            sender_id=sender_id,
        )
        baseline_expected = "delivered (proves the harness identity is accepted)"

    selected = _selected_indexes(args.frame_index, len(base_frames))
    mutations = list(MUTATIONS) if args.mutation is None else args.mutation
    if not args.include_ttl:
        mutations = [name for name in mutations if name not in TTL_MUTATIONS]
    check_frame_size(base_frames)

    sink = make_sink(args, cfg)
    limiter = RateLimiter(rate)
    sent = 0
    failures = 0
    rows: list[tuple[str, str]] = []
    frames_budget = cfg.limits.max_frames - (len(base_frames) if args.baseline else 0)
    budget_cases = len(mutations) if frames_budget <= 0 else frames_budget // len(base_frames)
    if budget_cases < len(mutations):
        print(
            f"warning: frame cap allows {max(0, budget_cases)} mutation case(s); "
            f"narrow --mutation or raise limits.max_frames",
            file=sys.stderr,
        )
        mutations = mutations[: max(0, budget_cases)]

    await sink.open()
    try:
        if args.baseline:
            print(f"[relay] baseline msg={hexs(msg_id)} expected: {baseline_expected}")
            for frame in base_frames:
                await limiter.wait()
                try:
                    await sink.send(frame)
                except SinkError as exc:
                    print(f"FAIL baseline: {exc}", file=sys.stderr)
                    return 2
                sent += 1
                if args.verbose:
                    print(f"  baseline {frame_summary(frame)}")

        for case_index, mutation in enumerate(mutations):
            if args.capture_file:
                frames = list(base_frames)
                case_msg = msg_id
            else:
                assert signing_key is not None
                case_msg, frames = build_voice_message(
                    channel_key=cfg.channel_key,
                    signing_key=signing_key,
                    plaintext=plaintext,
                    sender_id=sender_id,
                )
            rng = random.Random(args.seed + case_index)
            for index in selected:
                frames[index] = apply(mutation, frames[index], rng)
            if pubkey is not None and mutation not in TTL_MUTATIONS:
                for index in selected:
                    try:
                        packet = parse_packet(frames[index])
                    except ValueError:
                        continue
                    if verify_packet(packet, pubkey):
                        print(f"WARN {mutation}: mutated frame still verifies; harness bug", file=sys.stderr)
                        failures += 1

            print(
                f"[relay] {mutation:<20} msg={hexs(case_msg)} "
                f"frames={len(frames)} expect: {EXPECTATIONS[mutation]}"
            )
            for frame in frames:
                await limiter.wait()
                try:
                    await sink.send(frame)
                except SinkError as exc:
                    print(f"FAIL {mutation} after {sent} frame(s): {exc}", file=sys.stderr)
                    return 2
                sent += 1
                if args.verbose:
                    print(f"  {mutation} {frame_summary(frame)}")
            rows.append((mutation, EXPECTATIONS[mutation]))
    finally:
        await sink.close()

    print()
    print(f"sent {sent} frame(s) to {sink.describe()}")
    print(f"baseline: {baseline_expected}")
    print(f"mutations tested: {len(rows)}")
    if args.include_ttl:
        print(
            "EXPECT: non-TTL mutations absent; ttl=6/16 may deliver once (valid by "
            "design), ttl=0/17/255 absent, and no repeated playback or relay storm."
        )
    else:
        print("EXPECT: only the baseline clip appears; no corrupted/partial playback.")
    print("Record results in security/findings.md (SEC-001/002/009/016).")
    return 0 if failures == 0 else 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_sink_args(parser)
    parser.add_argument(
        "--mutation",
        action="append",
        choices=sorted(MUTATIONS),
        help="repeatable; default is all non-TTL mutations",
    )
    parser.add_argument(
        "--include-ttl",
        action="store_true",
        help="also run signature-preserving TTL mutations (clamp/dedup tests)",
    )
    parser.add_argument(
        "--frame-index",
        default="0",
        help="which frame to mutate (integer or 'all', default 0)",
    )
    parser.add_argument("--size", type=int, default=512, help="random payload size for generated messages")
    parser.add_argument("--payload-file", type=Path, help="use a real Opus/audio payload fixture")
    parser.add_argument(
        "--no-baseline",
        dest="baseline",
        action="store_false",
        default=True,
        help="skip the unmodified control message",
    )
    parser.add_argument("--seed", type=int, default=1, help="deterministic mutation RNG")
    parser.add_argument("--capture-file", type=Path, help="mutate a captured message instead of generating")
    parser.add_argument("--msg-id", help="with --capture-file, pick this message")
    parser.add_argument("--sender-id-hex", help="8-byte harness sender ID override")
    args = parser.parse_args()
    setup_logging(args.verbose)
    if args.size <= 0:
        raise SystemExit("--size must be positive")
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
