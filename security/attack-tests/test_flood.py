#!/usr/bin/env python3
"""Flood/DoS test: high-rate garbage, oversized reassembly claims, bad headers.

Safety: frame count and pps are capped by the config (default 50 pps / 2000
frames) and this script refuses to touch hardware without --i-own-this-device.
Run it only against a phone you own, ideally in airplane mode except BLE.

Observations:
  - link stays up (no crash/reboot of the app or BLE stack)
  - probe characteristic still readable before/after (if --probe-uuid)
  - valid clips still get through during/after the flood (manual check)
  - after the flood, the app's counters show drops, not unbounded queues
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from pathlib import Path

from config import (
    RateLimiter,
    add_sink_args,
    effective_rate,
    resolve_config,
    setup_logging,
)
from sinks import BleSink, SinkError, make_sink
from wire import now_ms

MAX_SENT_FRAME = 1500


def _header(
    rng: random.Random,
    *,
    version: int = 1,
    type_: int = 1,
    msg_id: bytes,
    sender_id: bytes,
    ttl: int = 5,
    chunk_idx: int = 0,
    total_chunks: int = 1,
    ts_ms: int | None = None,
) -> bytes:
    from wire import header_bytes

    return header_bytes(
        version=version,
        type_=type_,
        msg_id=msg_id,
        channel_id=rng.randbytes(8),
        sender_id=sender_id,
        ttl=ttl,
        chunk_idx=chunk_idx,
        total_chunks=total_chunks,
        timestamp_ms=ts_ms if ts_ms is not None else now_ms(),
    )


def gen_random(rng: random.Random) -> bytes:
    sender = rng.randbytes(8)
    total = rng.choice([1, 1, 4, 16, 255, 65535])
    header = _header(
        rng,
        type_=rng.randrange(256),
        msg_id=rng.randbytes(8),
        sender_id=sender,
        ttl=rng.choice([0, 1, 5, 5, 255]),
        chunk_idx=rng.randrange(0, min(total, 65535) + 1),
        total_chunks=total,
        ts_ms=rng.choice([0, now_ms(), now_ms() + 10**9]),
    )
    body = rng.randbytes(rng.randrange(1, 400))
    return header + rng.randbytes(64) + body


def gen_reassembly(rng: random.Random, counter: int) -> bytes:
    # 8 parallel "messages" declaring 65,535 chunks each; indexes keep growing
    msg_id = bytes([counter % 8]) * 8
    sender = bytes([1 + counter % 4]) * 8
    return (
        _header(
            rng,
            msg_id=msg_id,
            sender_id=sender,
            ttl=5,
            chunk_idx=counter % 65535,
            total_chunks=65535,
        )
        + rng.randbytes(64)
        + rng.randbytes(200)
    )


def gen_header(rng: random.Random, counter: int) -> bytes:
    cases = [
        dict(total_chunks=0, chunk_idx=0),
        dict(total_chunks=65535, chunk_idx=65534),
        dict(total_chunks=1, chunk_idx=65535),
        dict(total_chunks=65535, chunk_idx=65535),
        dict(ttl=0),
        dict(ttl=255),
        dict(version=0),
        dict(version=255),
        dict(ts_ms=0),
        dict(ts_ms=2**64 - 1),
    ]
    case = cases[counter % len(cases)]
    return (
        _header(
            rng,
            msg_id=rng.randbytes(8),
            sender_id=rng.randbytes(8),
            ttl=case.get("ttl", 5),
            chunk_idx=case.get("chunk_idx", 0),
            total_chunks=case.get("total_chunks", 1),
            version=case.get("version", 1),
            ts_ms=case.get("ts_ms", now_ms()),
        )
        + rng.randbytes(64)
        + rng.randbytes(rng.choice([0, 16, 128, 400]))
    )


def make_frame(mode: str, rng: random.Random, counter: int) -> bytes:
    if mode == "random":
        return gen_random(rng)
    if mode == "reassembly":
        return gen_reassembly(rng, counter)
    if mode == "header":
        return gen_header(rng, counter)
    return [gen_random, gen_reassembly, gen_header][counter % 3](rng, counter)


async def probe(sink, uuid: str | None) -> tuple[bool, float | None]:
    if not uuid or not isinstance(sink, BleSink):
        return True, None
    start = time.perf_counter()
    try:
        await sink.read_char(uuid)
    except SinkError as exc:
        print(f"  probe failed: {exc}", file=sys.stderr)
        return False, None
    return True, (time.perf_counter() - start) * 1000


async def run(args: argparse.Namespace) -> int:
    cfg = resolve_config(args)
    rate = effective_rate(args, cfg)

    max_frames = cfg.limits.max_frames
    if args.max_frames is not None:
        max_frames = min(max_frames, args.max_frames)
    planned = min(max_frames, int(rate * args.duration))
    if planned <= 0:
        raise SystemExit("nothing to send; check --duration/--rate/limits")

    rng = random.Random(args.seed)
    sink = make_sink(args, cfg)
    limiter = RateLimiter(rate)
    sent = 0
    failures = 0
    link_lost_at: int | None = None
    started = time.monotonic()
    probe_before = (True, None)

    await sink.open()
    try:
        probe_before = await probe(sink, args.probe_uuid)
        print(
            f"[flood] mode={args.mode} target={sink.describe()} rate={rate:g}pps "
            f"planned={planned} frame(s) for {args.duration:g}s"
        )
        for counter in range(planned):
            await limiter.wait()
            frame = make_frame(args.mode, rng, counter)
            frame = frame[:MAX_SENT_FRAME]  # never send absurd payloads
            try:
                await sink.send(frame)
            except SinkError as exc:
                failures += 1
                link_lost_at = sent + 1
                print(f"FAIL after {sent} frame(s): {exc}", file=sys.stderr)
                break
            sent += 1
            if not sink.healthy():
                link_lost_at = sent
                print(f"FAIL link down after {sent} frame(s)", file=sys.stderr)
                break
            if sent % 100 == 0:
                print(f"  {sent}/{planned} frames, {(time.monotonic() - started):.1f}s")
    finally:
        probe_after = await probe(sink, args.probe_uuid)
        await sink.close()

    elapsed = time.monotonic() - started
    achieved = sent / elapsed if elapsed > 0 else 0.0
    report = {
        "mode": args.mode,
        "target": sink.describe(),
        "planned": planned,
        "sent": sent,
        "failures": failures,
        "link_lost_at": link_lost_at,
        "elapsed_s": round(elapsed, 2),
        "achieved_pps": round(achieved, 2),
        "probe_before_ok": probe_before[0],
        "probe_after_ok": probe_after[0],
        "probe_before_ms": None if probe_before[1] is None else round(probe_before[1], 1),
        "probe_after_ms": None if probe_after[1] is None else round(probe_after[1], 1),
        "seed": args.seed,
    }
    print()
    print(
        f"sent={sent}/{planned} failures={failures} elapsed={elapsed:.1f}s "
        f"achieved={achieved:.1f}pps"
    )
    if probe_before[1] is not None or probe_after[1] is not None:
        print(f"probe before={probe_before[1]}ms after={probe_after[1]}ms")
    print("EXPECT: link up, probe readable, app responsive; record drops from logcat.")
    print("If the link died, note it in SEC-003/SEC-004 and retry with --rate 10.")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"report: {args.json_out}")

    return 0 if failures == 0 and link_lost_at is None else 3


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_sink_args(parser)
    parser.add_argument("--mode", choices=("random", "reassembly", "header", "mixed"), default="mixed")
    parser.add_argument("--duration", type=float, default=10.0, help="seconds")
    parser.add_argument("--max-frames", type=int, default=None, help="lower the config cap")
    parser.add_argument("--seed", type=int, default=int(time.time()), help="deterministic frame stream")
    parser.add_argument("--probe-uuid", help="read this characteristic before/after as a liveness check")
    parser.add_argument("--json-out", type=Path, help="write the report as JSON")
    args = parser.parse_args()
    setup_logging(args.verbose)
    if args.duration <= 0:
        raise SystemExit("--duration must be positive")
    if args.max_frames is not None and args.max_frames <= 0:
        raise SystemExit("--max-frames must be positive")
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
