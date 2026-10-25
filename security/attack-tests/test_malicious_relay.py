#!/usr/bin/env python3
"""Malicious-relay tamper tests: modify one frame of an otherwise valid message.

Prerequisite: the harness identity must be a member of a dedicated test channel
(its pubkey/sender_id enrolled in the app). Then the baseline must be accepted;
every mutation must be dropped, because an authenticated header/payload cannot
be changed without the sender's key.

Modes:
  generated (default)  fresh sealed+signed messages using the harness identity
  --capture-file PATH  mutate a message captured from a real sender (may be
                       rejected by anti-replay before the parser sees it)

The mutation only proves auth coverage if the baseline is delivered. If the
baseline is missing, enroll the harness identity or use --capture-file.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import secrets
import sys
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

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
from mutations import EXPECTATIONS, MUTATIONS, apply
from sinks import SinkError, make_sink
from wire import (
    build_voice_message,
    frame_summary,
    from_hex,
    hexs,
    now_ms,
    parse_packet,
    sender_id_for_pubkey,
)


def _verifies(frame: bytes, pubkey: bytes) -> bool:
    try:
        packet = parse_packet(frame)
        VerifyKey(pubkey).verify(packet.signing_input, packet.signature)
        return True
    except (BadSignatureError, ValueError):
        return False


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

    if args.capture_file:
        captured = pick_message(group_messages(load_capture(args.capture_file)), args.msg_id, 0)
        base_frames = [item.frame for item in captured]
        msg_id = parse_packet(base_frames[0]).msg_id
        baseline_expected = "unclear (captured replay; depends on anti-replay)"
    else:
        signing_key, pubkey = identity_from_config(cfg)
        sender_id = (
            from_hex(args.sender_id_hex)
            if args.sender_id_hex
            else sender_id_for_pubkey(cfg.channel_key, pubkey, now_ms())
        )
        if len(sender_id) != 8:
            raise SystemExit("--sender-id-hex must be 8 bytes")
        msg_id, base_frames = build_voice_message(
            channel_key=cfg.channel_key,
            signing_key=signing_key,
            sender_id=sender_id,
            plaintext=plaintext,
            chunk_size=args.chunk_size,
        )
        baseline_expected = "delivered (proves the harness identity is accepted)"

    selected = _selected_indexes(args.frame_index, len(base_frames))
    mutations = list(MUTATIONS) if args.mutation is None else args.mutation
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
                case_msg, frames = build_voice_message(
                    channel_key=cfg.channel_key,
                    signing_key=signing_key,
                    sender_id=sender_id,
                    plaintext=plaintext,
                    chunk_size=args.chunk_size,
                )
            rng = random.Random(args.seed + case_index)
            for index in selected:
                frames[index] = apply(mutation, frames[index], rng)
            if not args.capture_file and any(_verifies(frames[index], pubkey) for index in selected):
                print(f"WARN {mutation}: mutated frame still verifies; harness bug", file=sys.stderr)
                failures += 1

            print(
                f"[relay] {mutation:<20} msg={hexs(case_msg)} "
                f"frames={len(frames)} expect: dropped ({EXPECTATIONS[mutation]})"
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
    print("EXPECT: only the baseline clip appears; no corrupted/partial playback.")
    print("Record results in security/findings.md (SEC-002, SEC-009).")
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
        help="repeatable; default is all mutations",
    )
    parser.add_argument(
        "--frame-index",
        default="0",
        help="which frame to mutate (integer or 'all', default 0)",
    )
    parser.add_argument("--chunk-size", type=int, default=96, help="plaintext bytes per frame")
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
