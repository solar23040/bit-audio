#!/usr/bin/env python3
"""Capture mesh frames from a test device's GATT notify characteristic.

One BLE notification is assumed to contain exactly one complete mesh frame
(the app's notify contract is owned by Agent C; revisit when it lands).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from collections import Counter
from pathlib import Path

from config import DEFAULT_ARTIFACT_DIR, add_sink_args, load_config, setup_logging
from wire import frame_summary, parse_packet


async def capture_notifications(
    *,
    config_path: Path | None,
    address: str | None,
    tx_uuid: str | None,
    duration: float,
    out: Path,
    verbose: bool = False,
) -> Path:
    from bleak import BleakClient

    cfg = load_config(config_path)
    if cfg.ble is None:
        raise SystemExit("capture needs a ble section in the config")
    target = address or cfg.ble.address
    char = tx_uuid or cfg.ble.tx_char_uuid
    if not char:
        raise SystemExit("capture needs --tx-uuid or ble.tx_char_uuid in the config")

    out.parent.mkdir(parents=True, exist_ok=True)
    received = 0

    def on_notify(_characteristic, data: bytearray) -> None:
        nonlocal received
        frame = bytes(data)
        received += 1
        with out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t_ms": int(time.time() * 1000), "frame_hex": frame.hex()}) + "\n")
        if verbose:
            print(f"  #{received} {frame_summary(frame)}")

    print(f"[capture] {target} notify={char} for {duration:.0f}s -> {out}")
    client = BleakClient(target, timeout=15.0)
    try:
        await client.connect()
        await client.start_notify(char, on_notify)
        try:
            await asyncio.sleep(duration)
        finally:
            await client.stop_notify(char)
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
    print(f"[capture] {received} notification(s) saved")
    return out


def _summarize(path: Path) -> None:
    entries: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    if not entries:
        print("no frames captured; check tx_char_uuid and that the app is sending")
        return
    sizes: list[int] = []
    senders: Counter[str] = Counter()
    messages: set[bytes] = set()
    bad = 0
    for entry in entries:
        hex_frame = entry.get("frame_hex")
        if not isinstance(hex_frame, str):
            continue
        try:
            frame = bytes.fromhex(hex_frame)
            packet = parse_packet(frame)
        except ValueError:
            bad += 1
            continue
        sizes.append(len(frame))
        senders[packet.sender_id.hex()] += 1
        messages.add(packet.msg_id)
    if sizes:
        print(
            f"frames={len(sizes)} messages={len(messages)} senders={len(senders)} "
            f"size={min(sizes)}..{max(sizes)}B bad={bad}"
        )
        for sender, count in senders.most_common(8):
            print(f"  sender {sender}: {count} frame(s)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_sink_args(parser)
    parser.add_argument("--duration", type=float, default=60.0, help="seconds to listen")
    parser.add_argument("--out", type=Path, default=None, help="JSONL capture file")
    parser.add_argument("--address", help="override ble.address")
    parser.add_argument("--tx-uuid", help="override ble.tx_char_uuid")
    parser.add_argument("--summarize-only", type=Path, help="just summarize an existing capture")
    args = parser.parse_args()
    setup_logging(args.verbose)
    if args.summarize_only:
        _summarize(args.summarize_only)
        return 0
    if not args.i_own_this_device:
        raise SystemExit(
            "capture connects to real hardware; pass --i-own-this-device to confirm"
        )
    out = args.out or (DEFAULT_ARTIFACT_DIR / f"capture-{int(time.time())}.jsonl")
    if args.sink != "dry":
        print("note: capture ignores --sink; it always talks to BLE")
    try:
        asyncio.run(
            capture_notifications(
                config_path=args.config,
                address=args.address,
                tx_uuid=args.tx_uuid,
                duration=args.duration,
                out=out,
                verbose=args.verbose,
            )
        )
    except KeyboardInterrupt:
        return 130
    _summarize(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
