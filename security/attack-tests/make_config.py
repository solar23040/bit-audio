#!/usr/bin/env python3
"""Generate a local attack config with fresh secrets.

The file is written with mode 0600 and is gitignored. It never prints the
channel key; copy it from the app's debug export when testing a real channel.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
from pathlib import Path

from nacl.signing import SigningKey

from config import DEFAULT_CONFIG_PATH
from wire import sender_id_for_pubkey


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--force", action="store_true", help="overwrite an existing config")
    parser.add_argument("--address", help="target phone BLE address (for --sink ble)")
    parser.add_argument("--rx-uuid", help="GATT characteristic the app reads frames from")
    parser.add_argument("--tx-uuid", help="GATT characteristic the app notifies frames on")
    parser.add_argument("--service-uuid", help="app's mesh service UUID")
    parser.add_argument("--sim-out", type=Path, help="default JSONL path for --sink sim")
    args = parser.parse_args()

    if args.out.exists() and not args.force:
        raise SystemExit(f"{args.out} exists; use --force to overwrite")

    identity = SigningKey.generate()
    pubkey = identity.verify_key.encode()
    data: dict[str, object] = {
        "channel_key_hex": secrets.token_bytes(32).hex(),
        "identity_seed_hex": identity.encode().hex(),
        "victim": {"sender_id_hex": None, "pubkey_hex": None},
        "ble": None,
        "sim_out": str(args.sim_out) if args.sim_out else None,
        "limits": {"max_pps": 50, "max_frames": 2000},
    }
    if args.address or args.rx_uuid:
        if not (args.address and args.rx_uuid):
            raise SystemExit("--address and --rx-uuid must be given together")
        data["ble"] = {
            "address": args.address,
            "rx_char_uuid": args.rx_uuid,
            "tx_char_uuid": args.tx_uuid,
            "service_uuid": args.service_uuid,
            "mtu": 247,
        }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(args.out, 0o600)

    print(f"wrote {args.out} (mode 0600)")
    print(f"test identity pubkey: {pubkey.hex()}")
    print(f"test identity sender_id: {sender_id_for_pubkey(pubkey).hex()}")
    print("next: paste the channel key from the app debug export and, for spoofing,")
    print("      fill victim.sender_id_hex / victim.pubkey_hex from the target roster.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
