#!/usr/bin/env python3
"""Structure-aware packet fuzzer for the live app or the simulator.

Strategies:
  mutate     apply one of the 25 targeted mutations to a valid corpus frame
  random     random length/bytes, half with a plausible header
  boundary   field edge cases (ttl, chunk_idx, total_chunks, ts, version)
  crypto     valid frame with a corrupted sig/nonce/tag/payload

Self-check (no hardware, no config):

  python fuzz_packets.py --self-check

Live run (1-hour Phase 5 acceptance), against a device you own:

  python fuzz_packets.py --sink ble --duration 3600 --rate 20 --i-own-this-device

A disconnect or SinkError saves a reproducible artifact and exits 3. Any crash
of the app is a finding; attach the artifact seed/hex to SEC-003/SEC-012.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import secrets
import sys
import time
from collections import Counter
from pathlib import Path

from nacl.signing import SigningKey

from config import (
    DEFAULT_ARTIFACT_DIR,
    Limits,
    RateLimiter,
    add_sink_args,
    effective_rate,
    resolve_config,
    setup_logging,
)
from mutations import MUTATIONS, apply
from sinks import DryRunSink, SinkError, make_sink
from wire import (
    HEADER_LEN,
    build_packet,
    build_voice_message,
    header_bytes,
    now_ms,
    parse_packet,
    random_id,
    validate_frame,
)

STRATEGIES = ("mutate", "random", "boundary", "crypto")


def make_corpus(channel_key: bytes, count: int = 8) -> list[bytes]:
    key = SigningKey.generate()
    sender = random_id()
    frames: list[bytes] = []
    for index in range(count):
        _, message = build_voice_message(
            channel_key=channel_key,
            signing_key=key,
            sender_id=sender,
            plaintext=secrets.token_bytes(300 + index * 40),
            chunk_size=96,
        )
        frames.extend(message)
    return frames[:count]


def gen_random(rng: random.Random) -> bytes:
    length = rng.choice([0, 1, 15, 30, 42, 63, 106, 107, 120, 147, 300, 405, 512, 900, 1500])
    if rng.random() < 0.5 and length >= HEADER_LEN:
        header = header_bytes(
            version=rng.choice([1, 1, 0, 255]),
            type_=rng.randrange(256),
            msg_id=rng.randbytes(8),
            channel_id=rng.randbytes(8),
            sender_id=rng.randbytes(8),
            ttl=rng.randrange(256),
            chunk_idx=rng.randrange(65536),
            total_chunks=rng.choice([0, 1, 2, 255, 256, 257, 65535]),
            timestamp_ms=rng.choice([0, now_ms(), 2**64 - 1]),
        )
        return (header + rng.randbytes(max(0, length - HEADER_LEN)))[:length]
    return rng.randbytes(length)


def gen_boundary(rng: random.Random) -> bytes:
    total = rng.choice([0, 1, 2, 255, 256, 257, 65535])
    return (
        header_bytes(
            version=rng.choice([1, 0, 2, 255]),
            type_=rng.choice([0, 1, 255]),
            msg_id=rng.randbytes(8),
            channel_id=rng.randbytes(8),
            sender_id=rng.randbytes(8) if rng.random() < 0.9 else bytes(8),
            ttl=rng.choice([0, 1, 5, 6, 8, 9, 255]),
            chunk_idx=rng.choice([0, 1, 255, 256, 65534, 65535]),
            total_chunks=total,
            timestamp_ms=rng.choice([0, 1, now_ms(), 2**63, 2**64 - 1]),
        )
        + rng.randbytes(64)
        + rng.randbytes(rng.choice([0, 1, 16, 40, 200, 405]))
    )


def gen_crypto(rng: random.Random, corpus: list[bytes]) -> bytes:
    frame = bytearray(rng.choice(corpus))
    if len(frame) <= HEADER_LEN:
        return bytes(frame)
    target = rng.choice(["sig", "nonce", "tag", "payload", "truncate"])
    if target == "sig":
        index = rng.randrange(43, 107)
    elif target == "nonce":
        index = rng.randrange(107, min(131, len(frame)))
    elif target == "tag":
        index = len(frame) - 1
    elif target == "payload":
        index = rng.randrange(107, len(frame))
    else:
        return bytes(frame[: rng.randrange(0, len(frame))])
    frame[index] ^= 1 << rng.randrange(8)
    return bytes(frame)


def gen_mutate(rng: random.Random, corpus: list[bytes]) -> bytes:
    name = rng.choice(list(MUTATIONS))
    try:
        return apply(name, rng.choice(corpus), rng)
    except ValueError:
        return gen_random(rng)


def generate(strategy: str, rng: random.Random, corpus: list[bytes]) -> bytes:
    if strategy == "random":
        return gen_random(rng)
    if strategy == "boundary":
        return gen_boundary(rng)
    if strategy == "crypto":
        return gen_crypto(rng, corpus)
    return gen_mutate(rng, corpus)


def self_check(iterations: int) -> int:
    rng = random.Random(20261025)
    corpus = make_corpus(secrets.token_bytes(32))
    if not corpus:
        print("self-check FAIL: empty corpus", file=sys.stderr)
        return 2
    counts: Counter[str] = Counter()
    structurally_valid = 0
    for index in range(iterations):
        strategy = STRATEGIES[index % len(STRATEGIES)]
        frame = generate(strategy, rng, corpus)
        counts[strategy] += 1
        try:
            parse_packet(frame)
        except ValueError:
            continue
        if validate_frame(frame) is None:
            structurally_valid += 1

    # Every mutation must produce a different frame.
    changed = 0
    for name in MUTATIONS:
        source = corpus[0]
        mutated = apply(name, source, random.Random(7))
        if mutated != source:
            changed += 1
        if mutated == source:
            print(f"self-check FAIL: mutation {name} did not change the frame", file=sys.stderr)
            return 2

    print(f"self-check ok: {iterations} generated frames, strategies={dict(counts)}")
    print(f"  structurally valid: {structurally_valid}")
    print(f"  mutations that changed the frame: {changed}/{len(MUTATIONS)}")
    print("  parser raised no unexpected exceptions")
    return 0


def _artifact(report: dict[str, object], case: dict[str, object], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"failure-{int(time.time())}.json"
    path.write_text(json.dumps({"report": report, "case": case}, indent=2) + "\n", encoding="utf-8")
    return path


async def run(args: argparse.Namespace) -> int:
    if args.sink == "dry":
        cfg = None
        limits = Limits(max_pps=args.rate or 20, max_frames=2000)
        sink = DryRunSink(verbose=args.verbose, max_print=0)
        rate = float(args.rate or 20)
    else:
        cfg = resolve_config(args)
        limits = cfg.limits
        sink = make_sink(args, cfg)
        rate = effective_rate(args, cfg)
    if args.rate:
        rate = min(float(args.rate), limits.max_pps)
    max_frames = limits.max_frames if args.max_frames is None else min(limits.max_frames, args.max_frames)
    if max_frames <= 0:
        raise SystemExit("--max-frames must be positive")

    channel_key = cfg.channel_key if cfg else secrets.token_bytes(32)
    corpus = make_corpus(channel_key)
    rng = random.Random(args.seed)
    limiter = RateLimiter(rate)
    counts: Counter[str] = Counter()
    parseable = 0
    eligible = 0
    sent = 0
    started = time.monotonic()
    last_cases: list[dict[str, object]] = []
    if args.save_all is not None:
        args.save_all.parent.mkdir(parents=True, exist_ok=True)
        save_all_fh = args.save_all.open("w", encoding="utf-8")
    else:
        save_all_fh = None
    failed = False
    failure_case: dict[str, object] | None = None
    failure_reason = ""

    print(
        f"[fuzz] seed={args.seed} rate={rate:g}pps max={max_frames} "
        f"target={sink.describe() if args.sink != 'dry' else 'dry-run'}"
    )
    await sink.open()
    try:
        while sent < max_frames:
            if args.duration > 0 and time.monotonic() - started >= args.duration:
                break
            if args.iterations is not None and eligible >= args.iterations:
                break
            strategy = STRATEGIES[eligible % len(STRATEGIES)]
            frame = generate(strategy, rng, corpus)
            eligible += 1
            counts[strategy] += 1
            case = {
                "iteration": eligible,
                "strategy": strategy,
                "frame_hex": frame.hex(),
                "length": len(frame),
            }
            if validate_frame(frame) is None:
                parseable += 1
            if save_all_fh is not None:
                save_all_fh.write(json.dumps(case) + "\n")
            last_cases.append(case)
            last_cases = last_cases[-20:]
            await limiter.wait()
            try:
                await sink.send(frame)
            except SinkError as exc:
                failed = True
                failure_case = case
                failure_reason = str(exc)
                break
            sent += 1
            if sent % 250 == 0:
                print(f"  {sent}/{max_frames} frames, {time.monotonic() - started:.1f}s")
            if not sink.healthy():
                failed = True
                failure_case = case
                failure_reason = "link became unhealthy"
                break
    finally:
        await sink.close()
        if save_all_fh is not None:
            save_all_fh.close()

    elapsed = time.monotonic() - started
    report = {
        "seed": args.seed,
        "target": sink.describe() if args.sink != "dry" else "dry-run",
        "sent": sent,
        "eligible": eligible,
        "parseable_by_harness_limits": parseable,
        "strategies": dict(counts),
        "elapsed_s": round(elapsed, 1),
        "achieved_pps": round(sent / elapsed, 1) if elapsed > 0 else 0,
        "rate": rate,
        "failed": failed,
        "failure_reason": failure_reason,
    }
    print()
    print(json.dumps(report, indent=2))
    if failed:
        out_dir = args.artifact_dir or (DEFAULT_ARTIFACT_DIR / "fuzz")
        path = _artifact(
            report,
            {"failure": failure_case, "recent": last_cases},
            out_dir,
        )
        print(f"FAIL: {failure_reason}; artifact saved to {path}", file=sys.stderr)
        print("Attach the seed/artifact to SEC-003/SEC-012; do not paste keys.", file=sys.stderr)
        return 3
    print("no crash/disconnect observed in this window")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_sink_args(parser)
    parser.add_argument("--self-check", action="store_true", help="generate/parse locally, no hardware")
    parser.add_argument("--iterations", type=int, default=None, help="stop after N cases")
    parser.add_argument("--duration", type=float, default=60.0, help="seconds; 0 = until max frames")
    parser.add_argument("--max-frames", type=int, default=None, help="lower the config cap")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--save-all", type=Path, help="JSONL of every case (large)")
    parser.add_argument("--artifact-dir", type=Path, help="where failure artifacts go")
    args = parser.parse_args()
    setup_logging(args.verbose)
    if args.self_check:
        return self_check(10000)
    if args.duration < 0:
        raise SystemExit("--duration must be >= 0")
    if args.iterations is not None and args.iterations <= 0:
        raise SystemExit("--iterations must be positive")
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
