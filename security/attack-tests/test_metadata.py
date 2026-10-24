#!/usr/bin/env python3
"""Passive BLE metadata survey for SEC-005 (tracking / advertisement fingerprinting).

Scan near the test phone for a while and report:
  - device name, service UUIDs, manufacturer/service data (stable = fingerprint)
  - observed address lifetimes and rough advertisement intervals
  - whether addresses look static/resolvable/non-resolvable random
  - payloads that stay identical across address rotations (still linkable)

This does not inject anything. Only scan devices you own or have permission to
observe; RSSI-only survey in a private space is the intended use.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from config import DEFAULT_ARTIFACT_DIR, add_sink_args, setup_logging


@dataclass(frozen=True)
class Advert:
    t: float
    address: str
    name: str | None
    rssi: int
    service_uuids: tuple[str, ...]
    manufacturer_hex: str
    service_data_hex: str
    tx_power: int | None


def _hex_map(values: dict) -> str:
    if not values:
        return ""
    parts = []
    for key in sorted(values, key=str):
        raw = values[key]
        if isinstance(raw, (bytes, bytearray)):
            parts.append(f"{key}={bytes(raw).hex()}")
        else:
            parts.append(f"{key}={raw}")
    return ";".join(parts)


def fingerprint(advert: Advert) -> str:
    return "|".join(
        [
            advert.name or "",
            ",".join(sorted(advert.service_uuids)),
            advert.manufacturer_hex,
            advert.service_data_hex,
            "" if advert.tx_power is None else str(advert.tx_power),
        ]
    )


def address_kind(address: str) -> str:
    raw = address.replace(":", "").replace("-", "").replace(".", "")
    if len(raw) < 2:
        return "unknown"
    try:
        first = int(raw[:2], 16)
    except ValueError:
        return "unknown"
    if first & 0xC0 == 0xC0:
        return "random-static"
    if first & 0xC0 == 0x40:
        return "resolvable-private"
    return "public-or-nonresolvable"


async def scan(duration: float, raw_out: Path | None, verbose: bool) -> list[Advert]:
    from bleak import BleakScanner

    adverts: list[Advert] = []

    def callback(device, advertisement_data) -> None:
        record = Advert(
            t=time.time(),
            address=str(device.address),
            name=advertisement_data.local_name or device.name,
            rssi=advertisement_data.rssi,
            service_uuids=tuple(str(u) for u in advertisement_data.service_uuids),
            manufacturer_hex=_hex_map(advertisement_data.manufacturer_data),
            service_data_hex=_hex_map(advertisement_data.service_data),
            tx_power=advertisement_data.tx_power,
        )
        adverts.append(record)
        if verbose:
            print(f"  {record.address} rssi={record.rssi} name={record.name!r}")

    print(f"[metadata] scanning for {duration:g}s (passive)")
    scanner = BleakScanner(detection_callback=callback)
    await scanner.start()
    try:
        await asyncio.sleep(duration)
    finally:
        await scanner.stop()

    if raw_out is not None:
        raw_out.parent.mkdir(parents=True, exist_ok=True)
        with raw_out.open("w", encoding="utf-8") as fh:
            for advert in adverts:
                fh.write(json.dumps(asdict(advert)) + "\n")
        print(f"[metadata] raw adverts: {raw_out}")
    return adverts


def analyze(
    adverts: list[Advert],
    *,
    duration: float,
    uuid_filter: str | None,
    name_filter: str | None,
    rotation_threshold: float,
) -> dict[str, object]:
    if uuid_filter:
        wanted = uuid_filter.lower()
        adverts = [a for a in adverts if any(wanted == u.lower() for u in a.service_uuids)]
    if name_filter:
        pattern = re.compile(name_filter, re.IGNORECASE)
        adverts = [a for a in adverts if a.name and pattern.search(a.name)]
    if not adverts:
        return {
            "adverts": 0,
            "addresses": 0,
            "flags": [{"severity": "info", "text": "no matching adverts; move closer or widen --duration/--uuid"}],
        }

    by_address: dict[str, list[Advert]] = defaultdict(list)
    for advert in adverts:
        by_address[advert.address].append(advert)

    address_info = []
    for address, items in by_address.items():
        items.sort(key=lambda a: a.t)
        times = [a.t for a in items]
        gaps = [b - a for a, b in zip(times, times[1:])]
        address_info.append(
            {
                "address": address,
                "kind": address_kind(address),
                "adverts": len(items),
                "first_s": round(times[0] - times[0], 1),
                "span_s": round(times[-1] - times[0], 1),
                "median_gap_s": round(statistics.median(gaps), 2) if gaps else None,
                "names": sorted({a.name for a in items if a.name}),
                "fingerprint": fingerprint(items[0]),
            }
        )
    address_info.sort(key=lambda item: (-item["adverts"], item["address"]))

    fingerprints: dict[str, set[str]] = defaultdict(set)
    for advert in adverts:
        fingerprints[fingerprint(advert)].add(advert.address)
    shared = {fp: addrs for fp, addrs in fingerprints.items() if len(addrs) > 1}

    flags: list[dict[str, str]] = []
    names = Counter(a.name for a in adverts if a.name)
    if names:
        flags.append(
            {
                "severity": "medium",
                "text": f"advertises device name(s) {dict(names)}; a constant name is a tracking handle (SEC-005)",
            }
        )
    if any(a.manufacturer_hex for a in adverts):
        flags.append(
            {
                "severity": "medium",
                "text": "manufacturer data present; verify it does not contain a stable app/channel ID (SEC-005)",
            }
        )
    if any(a.service_data_hex for a in adverts):
        flags.append(
            {
                "severity": "medium",
                "text": "service data present; stable bytes are fingerprintable (SEC-005)",
            }
        )
    if uuid_filter and any(uuid_filter.lower() in [u.lower() for u in a.service_uuids] for a in adverts):
        flags.append(
            {
                "severity": "low",
                "text": "the app's mesh service UUID is advertised; expected, but identifies the app",
            }
        )
    for item in address_info:
        if item["span_s"] >= rotation_threshold:
            flags.append(
                {
                    "severity": "medium",
                    "text": (
                        f"address {item['address']} ({item['kind']}) observed for "
                        f"{item['span_s']:.0f}s; confirm controller MAC rotation (SEC-005)"
                    ),
                }
            )
    for fp, addresses in shared.items():
        if fp.strip("|"):
            flags.append(
                {
                    "severity": "medium",
                    "text": (
                        f"identical advertisement payload seen from {len(addresses)} addresses "
                        f"({', '.join(sorted(addresses)[:4])}); payload itself is linkable"
                    ),
                }
            )
    kinds = Counter(item["kind"] for item in address_info)
    if kinds.get("random-static"):
        flags.append(
            {
                "severity": "low",
                "text": "random-static address observed; static random addresses do not rotate per connection",
            }
        )

    return {
        "duration_s": duration,
        "adverts": len(adverts),
        "addresses": len(address_info),
        "address_kinds": dict(kinds),
        "names": dict(names),
        "address_info": address_info[:20],
        "shared_fingerprints": [
            {"fingerprint": fp, "addresses": sorted(addrs)} for fp, addrs in shared.items()
        ][:10],
        "flags": flags,
    }


def print_summary(report: dict[str, object]) -> None:
    print()
    print("== BLE metadata summary ==")
    print(f"adverts={report.get('adverts', 0)} addresses={report.get('addresses', 0)} "
          f"duration={report.get('duration_s', 0)}s")
    for item in report.get("address_info", []):
        print(
            f"  {item['address']:<20} {item['kind']:<24} n={item['adverts']:<4} "
            f"span={item['span_s']}s gap={item['median_gap_s']}s "
            f"name={','.join(item['names']) or '-'}"
        )
    flags = report.get("flags", [])
    if flags:
        print("flags:")
        for flag in flags:
            print(f"  [{flag['severity']}] {flag['text']}")
    else:
        print("flags: none observed in this window (not proof of absence)")
    print("Compare against SEC-005; keep this report with the field-test notes.")


async def run(args: argparse.Namespace) -> int:
    try:
        adverts = await scan(args.duration, args.raw_out, args.verbose)
    except Exception as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        print("Linux: check `bluetoothctl show`, that the adapter supports LE, and "
              "that your user may access BlueZ (bluetooth group/polkit).", file=sys.stderr)
        return 2
    report = analyze(
        adverts,
        duration=args.duration,
        uuid_filter=args.uuid,
        name_filter=args.name,
        rotation_threshold=args.rotation_threshold,
    )
    print_summary(report)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"report: {args.json_out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_sink_args(parser)
    parser.add_argument("--duration", type=float, default=300.0, help="seconds to scan")
    parser.add_argument("--uuid", help="only adverts containing this service UUID")
    parser.add_argument("--name", help="only adverts whose local name matches this regex")
    parser.add_argument(
        "--rotation-threshold",
        type=float,
        default=900.0,
        help="flag addresses observed longer than this many seconds",
    )
    parser.add_argument("--raw-out", type=Path, default=DEFAULT_ARTIFACT_DIR / "ble-adverts.jsonl")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()
    setup_logging(args.verbose)
    if args.duration <= 0:
        raise SystemExit("--duration must be positive")
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
