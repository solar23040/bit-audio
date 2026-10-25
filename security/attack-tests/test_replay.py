#!/usr/bin/env python3
"""Replay tests: same bytes later, fresh timestamp, and chunk swapping.

Prepare a capture with capture.py while a peer sends a clip that the target
actually receives. Then:

  replay        resend the exact frames (must not play twice)
  rewrite-ts    change ts_ms to now (signature must fail; replay window bypass)
  swap-chunks   swap chunk_idx of two frames (signature/AEAD must fail)
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import replace
from pathlib import Path

from captured import group_messages, load_capture, pick_message
from config import (
    RateLimiter,
    add_sink_args,
    effective_rate,
    identity_from_config,
    resolve_config,
    setup_logging,
)
from sinks import SinkError, make_sink
from wire import frame_summary, now_ms, parse_packet


async def send_frames(args: argparse.Namespace, frames: list[bytes], repeat: int, interval: float) -> int:
    cfg = resolve_config(args)
    sink = make_sink(args, cfg)
    limiter = RateLimiter(effective_rate(args, cfg))
    sent = 0
    await sink.open()
    try:
        for round_index in range(repeat):
            if round_index and interval:
                print(f"[replay] waiting {interval:.1f}s before repeat {round_index + 1}")
                await asyncio.sleep(interval)
            for frame in frames:
                await limiter.wait()
                try:
                    await sink.send(frame)
                except SinkError as exc:
                    print(f"FAIL after {sent} frame(s): {exc}", file=sys.stderr)
                    return 2
                sent += 1
                if args.verbose:
                    print(f"  {frame_summary(frame)}")
                if not sink.healthy():
                    print(f"FAIL sink unhealthy after {sent} frame(s)", file=sys.stderr)
                    return 2
    finally:
        await sink.close()
    print(f"[replay] sent {sent} frame(s) to {sink.describe()}")
    return 0


async def run(args: argparse.Namespace) -> int:
    frames = load_capture(args.capture_file)
    groups = group_messages(frames)
    message = pick_message(groups, args.msg_id, args.message)
    print(
        f"[replay] capture has {len(groups)} message(s); selected "
        f"{len(message)} frame(s) from {parse_packet(message[0].frame).msg_id.hex()}"
    )

    if args.mode == "replay":
        outgoing = [item.frame for item in message]
        print("EXPECT: target must not play this clip a second time (SEC-008).")
        return await send_frames(args, outgoing, args.repeat, args.interval)

    if args.mode == "rewrite-ts":
        outgoing = []
        signing_key = None
        if args.resign_as_attacker:
            cfg = resolve_config(args)
            signing_key, _ = identity_from_config(cfg)
        for item in message:
            packet = replace(parse_packet(item.frame), timestamp_ms=now_ms())
            if signing_key is not None:
                packet = replace(packet, sig=signing_key.sign(packet.signing_input).signature)
            outgoing.append(packet.to_bytes())
        print(
            "EXPECT: frames dropped (signature / replay window). "
            + ("Re-signed with the attacker key while keeping the victim sender_id." if signing_key else "Original signature kept.")
        )
        return await send_frames(args, outgoing, args.repeat, args.interval)

    if args.mode == "swap-chunks":
        packets = [parse_packet(item.frame) for item in message]
        if len(packets) < 2:
            raise SystemExit("swap-chunks needs a message with at least two chunks")
        first, second = packets[0], packets[1]
        outgoing = [
            replace(first, chunk_idx=second.chunk_idx).to_bytes(),
            replace(second, chunk_idx=first.chunk_idx).to_bytes(),
        ]
        print("EXPECT: both chunks dropped; no corrupted playback (SEC-002).")
        return await send_frames(args, outgoing, args.repeat, args.interval)

    raise SystemExit(f"unknown mode {args.mode}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_sink_args(parser)
    parser.add_argument(
        "--mode",
        choices=("replay", "rewrite-ts", "swap-chunks"),
        default="replay",
    )
    parser.add_argument("--capture-file", type=Path, required=True)
    parser.add_argument("--msg-id", help="8-byte hex msg_id to replay (default: newest)")
    parser.add_argument("--message", type=int, default=0, help="message index, newest first")
    parser.add_argument("--repeat", type=int, default=1, help="how many times to send the frames")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between repeats")
    parser.add_argument(
        "--resign-as-attacker",
        action="store_true",
        help="rewrite-ts only: re-sign with our key, keeping the captured sender_id",
    )
    args = parser.parse_args()
    setup_logging(args.verbose)
    if args.repeat < 1:
        raise SystemExit("--repeat must be >= 1")
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
