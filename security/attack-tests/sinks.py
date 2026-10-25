"""Packet sinks: dry-run, simulator JSONL, and real BLE GATT writes."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Protocol

from config import BleConfig, Config
from wire import frame_summary, now_ms

log = logging.getLogger("meshattack.sink")


class SinkError(RuntimeError):
    """A frame could not be delivered to the target."""


class Sink(Protocol):
    async def open(self) -> None: ...
    async def send(self, frame: bytes) -> None: ...
    async def close(self) -> None: ...
    def healthy(self) -> bool: ...
    def describe(self) -> str: ...


class DryRunSink:
    def __init__(self, *, verbose: bool = False, max_print: int = 3) -> None:
        self._verbose = verbose
        self._max_print = max_print
        self._count = 0
        self._bytes = 0

    async def open(self) -> None:
        print("[dry] no hardware touched; frames are printed, not sent")

    async def send(self, frame: bytes) -> None:
        self._count += 1
        self._bytes += len(frame)
        if self._verbose or self._count <= self._max_print:
            print(f"[dry] #{self._count} {frame_summary(frame)}")
            print(f"[dry]     {frame.hex()}")

    async def close(self) -> None:
        print(f"[dry] {self._count} frame(s), {self._bytes} bytes")

    def healthy(self) -> bool:
        return True

    def describe(self) -> str:
        return "dry-run"


class SimSink:
    """Writes frames as JSONL for Agent G's simulator.

    Contract: one JSON object per line, ``{"t_ms": <int>, "frame_hex": "<hex>"}``.
    The simulator is expected to feed these into the mesh as if they arrived
    from a fake peer, preserving order. No BLE retries or fragments are implied.
    """

    def __init__(self, path: Path, *, verbose: bool = False) -> None:
        self._path = path
        self._verbose = verbose
        self._fh = None
        self._count = 0

    async def open(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self._path.open("a", encoding="utf-8")
        print(f"[sim] appending frames to {self._path}")

    async def send(self, frame: bytes) -> None:
        if self._fh is None:
            raise SinkError("sim sink not opened")
        self._fh.write(json.dumps({"t_ms": now_ms(), "frame_hex": frame.hex()}) + "\n")
        self._fh.flush()
        self._count += 1
        if self._verbose:
            print(f"[sim] #{self._count} {frame_summary(frame)}")

    async def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        print(f"[sim] {self._count} frame(s) written to {self._path}")

    def healthy(self) -> bool:
        return True

    def describe(self) -> str:
        return f"sim:{self._path}"


class BleSink:
    """Writes raw frames to a device's GATT RX characteristic with bleak.

    Each frame is written with write-without-response. Frames larger than
    MTU-3 are split into consecutive writes; the app's transport layer is
    expected to reassemble at the characteristic/fragment layer. Keep test
    frames <= MTU-3 until Agent C publishes the GATT contract.
    """

    def __init__(self, ble: BleConfig, *, verbose: bool = False) -> None:
        self._ble = ble
        self._verbose = verbose
        self._client = None
        self._mtu = ble.mtu
        self._warned_split = False
        self._count = 0

    async def open(self) -> None:
        from bleak import BleakClient

        self._client = BleakClient(self._ble.address, timeout=15.0)
        await self._client.connect()
        try:
            self._mtu = self._client.mtu_size or self._ble.mtu
        except Exception:  # pragma: no cover - backend dependent
            self._mtu = self._ble.mtu
        print(
            f"[ble] connected to {self._ble.address} "
            f"(mtu={self._mtu}, rx={self._ble.rx_char_uuid})"
        )

    async def send(self, frame: bytes) -> None:
        if self._client is None or not self._client.is_connected:
            raise SinkError("BLE link is down")
        chunk_size = max(20, self._mtu - 3)
        if len(frame) > chunk_size and not self._warned_split:
            log.warning(
                "frame %d B > MTU-3 (%d B); splitting into %d writes",
                len(frame),
                chunk_size,
                (len(frame) + chunk_size - 1) // chunk_size,
            )
            self._warned_split = True
        try:
            for offset in range(0, len(frame), chunk_size):
                await self._client.write_gatt_char(
                    self._ble.rx_char_uuid,
                    frame[offset : offset + chunk_size],
                    response=False,
                )
        except Exception as exc:  # bleak raises backend-specific exceptions
            raise SinkError(f"GATT write failed after {self._count} frames: {exc}") from exc
        self._count += 1
        if self._verbose:
            print(f"[ble] #{self._count} {frame_summary(frame)}")

    async def read_char(self, uuid: str) -> bytes:
        if self._client is None or not self._client.is_connected:
            raise SinkError("BLE link is down")
        try:
            return bytes(await self._client.read_gatt_char(uuid))
        except Exception as exc:
            raise SinkError(f"GATT read failed: {exc}") from exc

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception as exc:  # pragma: no cover
                log.warning("disconnect failed: %s", exc)
            self._client = None
        print(f"[ble] {self._count} frame(s) sent")

    def healthy(self) -> bool:
        return self._client is not None and self._client.is_connected

    def describe(self) -> str:
        return f"ble:{self._ble.address}"


def make_sink(args, cfg: Config) -> Sink:
    if args.sink == "dry":
        return DryRunSink(verbose=args.verbose)
    if args.sink == "sim":
        path = args.sim_out or cfg.sim_out
        if path is None:
            raise SystemExit("--sink sim needs --sim-out PATH or sim_out in the config")
        return SimSink(path, verbose=args.verbose)
    if args.sink == "ble":
        if not args.i_own_this_device:
            raise SystemExit(
                "Refusing to transmit to real hardware. Re-run with "
                "--i-own-this-device to confirm the target is your test device."
            )
        if cfg.ble is None:
            raise SystemExit("--sink ble needs a ble section in the config")
        return BleSink(cfg.ble, verbose=args.verbose)
    raise SystemExit(f"unknown sink {args.sink}")
