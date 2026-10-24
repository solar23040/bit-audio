"""Config loading, CLI defaults and safety helpers for the attack harness."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass, replace
from pathlib import Path

from nacl.signing import SigningKey

from wire import from_hex

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = HERE / "config.json"
DEFAULT_ARTIFACT_DIR = HERE / "captures"
ENV_CONFIG = "MESH_SECURITY_CONFIG"

log = logging.getLogger("meshattack")


class ConfigError(ValueError):
    """The attack config is missing or malformed."""


@dataclass(frozen=True)
class BleConfig:
    address: str
    rx_char_uuid: str
    tx_char_uuid: str | None = None
    service_uuid: str | None = None
    mtu: int = 247


@dataclass(frozen=True)
class Limits:
    max_pps: float = 50.0
    max_frames: int = 2000


@dataclass(frozen=True)
class Config:
    channel_key: bytes
    identity_seed: bytes | None
    victim_sender_id: bytes | None
    victim_pubkey: bytes | None
    ble: BleConfig | None
    sim_out: Path | None
    limits: Limits
    path: Path | None

    def with_limits(self, **changes: object) -> "Config":
        return replace(self, limits=replace(self.limits, **changes))


def _hex_field(value: object, length: int, name: str, *, optional: bool = False) -> bytes | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a hex string")
    try:
        raw = from_hex(value)
    except ValueError as exc:
        raise ConfigError(f"{name} is not valid hex: {exc}") from exc
    if len(raw) != length:
        raise ConfigError(f"{name} must be {length} bytes ({length * 2} hex chars), got {len(raw)}")
    return raw


def load_config(path: Path | None = None, *, required: bool = True) -> Config:
    resolved = path or Path(os.environ.get(ENV_CONFIG, DEFAULT_CONFIG_PATH))
    if not resolved.exists():
        if not required:
            raise ConfigError(f"config not found: {resolved}")
        raise ConfigError(
            f"config not found: {resolved}\n"
            "Run `python make_config.py --out config.json` and fill in the BLE "
            "address/characteristics, or pass --config. See README.md."
        )
    try:
        data = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read {resolved}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("config root must be a JSON object")

    name = resolved.name
    channel_key = _hex_field(data.get("channel_key_hex"), 32, f"{name}: channel_key_hex")
    assert isinstance(channel_key, bytes)
    if channel_key == bytes(32):
        raise ConfigError(
            f"{name}: channel_key_hex is all zeros (example placeholder). "
            "Fill in the real channel key from the app's debug QR export."
        )

    identity_seed = _hex_field(
        data.get("identity_seed_hex"), 32, f"{name}: identity_seed_hex", optional=True
    )

    victim = data.get("victim") or {}
    if not isinstance(victim, dict):
        raise ConfigError(f"{name}: victim must be an object")
    victim_id = _hex_field(victim.get("sender_id_hex"), 8, f"{name}: victim.sender_id_hex", optional=True)
    victim_pub = _hex_field(victim.get("pubkey_hex"), 32, f"{name}: victim.pubkey_hex", optional=True)

    ble_raw = data.get("ble")
    ble: BleConfig | None = None
    if ble_raw is not None:
        if not isinstance(ble_raw, dict):
            raise ConfigError(f"{name}: ble must be an object")
        address = ble_raw.get("address")
        rx = ble_raw.get("rx_char_uuid")
        if not isinstance(address, str) or not address:
            raise ConfigError(f"{name}: ble.address is required")
        if not isinstance(rx, str) or not rx:
            raise ConfigError(f"{name}: ble.rx_char_uuid is required")
        tx = ble_raw.get("tx_char_uuid")
        service = ble_raw.get("service_uuid")
        mtu = ble_raw.get("mtu", 247)
        if not isinstance(mtu, int) or not 23 <= mtu <= 517:
            raise ConfigError(f"{name}: ble.mtu must be 23..517")
        ble = BleConfig(
            address=address,
            rx_char_uuid=rx,
            tx_char_uuid=tx if isinstance(tx, str) and tx else None,
            service_uuid=service if isinstance(service, str) and service else None,
            mtu=mtu,
        )

    sim_out_raw = data.get("sim_out")
    sim_out = Path(sim_out_raw).expanduser() if isinstance(sim_out_raw, str) else None

    limits_raw = data.get("limits") or {}
    if not isinstance(limits_raw, dict):
        raise ConfigError(f"{name}: limits must be an object")
    limits = Limits(
        max_pps=float(limits_raw.get("max_pps", 50)),
        max_frames=int(limits_raw.get("max_frames", 2000)),
    )
    if limits.max_pps <= 0 or limits.max_frames <= 0:
        raise ConfigError(f"{name}: limits must be positive")

    return Config(
        channel_key=channel_key,
        identity_seed=identity_seed,
        victim_sender_id=victim_id,
        victim_pubkey=victim_pub,
        ble=ble,
        sim_out=sim_out,
        limits=limits,
        path=resolved,
    )


def identity_from_config(cfg: Config) -> tuple[SigningKey, bytes]:
    """Return the test identity. An ephemeral key is generated when unset."""
    if cfg.identity_seed is None:
        log.warning("identity_seed_hex not set; using a throwaway identity for this run")
        key = SigningKey.generate()
    else:
        key = SigningKey(cfg.identity_seed)
    return key, key.verify_key.encode()


def effective_rate(args: argparse.Namespace, cfg: Config) -> float:
    requested = getattr(args, "rate", None)
    pps = float(requested) if requested is not None else cfg.limits.max_pps
    if pps <= 0:
        raise SystemExit("--rate must be positive")
    if pps > cfg.limits.max_pps:
        log.warning(
            "capping --rate %.1f to config limit %.1f (raise limits.max_pps to override)",
            pps,
            cfg.limits.max_pps,
        )
        pps = cfg.limits.max_pps
    return pps


def add_sink_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help=f"attack config JSON (default: ${ENV_CONFIG} or {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--sink",
        choices=("dry", "sim", "ble"),
        default="dry",
        help="dry = print only; sim = JSONL for Agent G's :sim; ble = write to a real device",
    )
    parser.add_argument(
        "--sim-out",
        type=Path,
        default=None,
        help="JSONL output for --sink sim (overrides config sim_out)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=None,
        help="max frames per second (capped by limits.max_pps, default 50)",
    )
    parser.add_argument(
        "--i-own-this-device",
        action="store_true",
        help="required for any transmission to real hardware; confirms you own the target device",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="print every frame/case")


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )


def require_live_consent(args: argparse.Namespace) -> None:
    if args.sink == "ble" and not args.i_own_this_device:
        raise SystemExit(
            "Refusing to transmit to real hardware. Re-run with "
            "--i-own-this-device to confirm the target is your test device."
        )


def resolve_config(args: argparse.Namespace) -> Config:
    try:
        return load_config(args.config)
    except ConfigError as exc:
        raise SystemExit(str(exc)) from exc


def artifact_dir() -> Path:
    path = DEFAULT_ARTIFACT_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def check_frame_size(frames: list[bytes]) -> None:
    too_big = [len(f) for f in frames if len(f) > 300]
    if too_big:
        print(
            f"warning: {len(too_big)} frame(s) exceed the 300 B target "
            f"(max {max(too_big)} B); the transport layer will fragment them",
            file=sys.stderr,
        )


class RateLimiter:
    """Simple monotonic frames-per-second limiter."""

    def __init__(self, pps: float) -> None:
        self._interval = 1.0 / pps if pps > 0 else 0.0
        self._next = 0.0

    async def wait(self) -> None:
        if self._interval <= 0:
            return
        loop = asyncio.get_running_loop()
        now = loop.time()
        delay = self._next - now
        if delay > 0:
            await asyncio.sleep(delay)
            now = loop.time()
        self._next = max(now, self._next) + self._interval
