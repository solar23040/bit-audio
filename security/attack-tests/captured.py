"""Loading, grouping and selecting frames from capture.py JSONL files."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from wire import Packet, from_hex, parse_packet


@dataclass(frozen=True)
class CapturedFrame:
    t_ms: int
    frame: bytes


def load_capture(path: Path) -> list[CapturedFrame]:
    if not path.exists():
        raise SystemExit(f"capture not found: {path}")
    frames: list[CapturedFrame] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
            frame = bytes.fromhex(entry["frame_hex"])
            parse_packet(frame)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
        frames.append(CapturedFrame(t_ms=int(entry.get("t_ms", 0)), frame=frame))
    if not frames:
        raise SystemExit(f"no parseable frames in {path}")
    return frames


def group_messages(frames: list[CapturedFrame]) -> list[list[CapturedFrame]]:
    groups: dict[tuple[bytes, bytes], list[CapturedFrame]] = {}
    for entry in frames:
        packet = parse_packet(entry.frame)
        groups.setdefault((packet.sender_id, packet.msg_id), []).append(entry)
    result = []
    for group in groups.values():
        group.sort(key=lambda item: parse_packet(item.frame).chunk_idx)
        result.append(group)
    result.sort(key=lambda group: max(item.t_ms for item in group), reverse=True)
    return result


def pick_message(
    groups: list[list[CapturedFrame]], msg_id_hex: str | None, index: int
) -> list[CapturedFrame]:
    if msg_id_hex:
        wanted = from_hex(msg_id_hex)
        for group in groups:
            if parse_packet(group[0].frame).msg_id == wanted:
                return group
        raise SystemExit(f"msg_id {msg_id_hex} not found in the capture")
    if index >= len(groups):
        raise SystemExit(f"--message {index} out of range ({len(groups)} messages)")
    return groups[index]


def packets(group: list[CapturedFrame]) -> list[Packet]:
    return [parse_packet(item.frame) for item in group]
