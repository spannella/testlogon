#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "docker-compose.broadcast-local.yml"
ARTIFACT_DIR = ROOT / "tmp" / "broadcast-e2e-artifacts"
HLS_ROOT = ROOT / "tmp" / "broadcast-hls" / "devstream"
ARCHIVE_ROOT = ROOT / "tmp" / "broadcast-archive" / "devstream"


def run(cmd: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, capture_output=capture)


def wait_for_file(path: Path, *, timeout_seconds: int = 90) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if path.exists() and path.stat().st_size > 0:
            return True
        time.sleep(1)
    return False


def start_stack() -> None:
    run(["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"], capture=False)


def push_synthetic_rtmp(*, seconds: int = 20) -> None:
    cmd = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "warning",
        "-re",
        "-f",
        "lavfi",
        "-i",
        "color=c=blue:s=1280x720:r=30",
        "-f",
        "lavfi",
        "-i",
        "sine=frequency=1000:sample_rate=48000",
        "-t",
        str(seconds),
        "-c:v",
        "libx264",
        "-preset",
        "veryfast",
        "-c:a",
        "aac",
        "-f",
        "flv",
        "rtmp://localhost:1935/live/devstream",
    ]
    run(cmd, capture=False)


def _stddev(raw_rgb: bytes) -> float:
    if not raw_rgb:
        return 0.0
    values = list(raw_rgb)
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return var ** 0.5


def assert_watermark_present(segment_file: Path) -> dict:
    corner_file = ARTIFACT_DIR / "corner.rgb"
    center_file = ARTIFACT_DIR / "center.rgb"
    run(["ffmpeg", "-y", "-hide_banner", "-loglevel", "error", "-i", str(segment_file), "-frames:v", "1", "-vf", "crop=120:120:W-140:H-140", "-f", "rawvideo", "-pix_fmt", "rgb24", str(corner_file)])
    run(["ffmpeg", "-y", "-hide_banner", "-loglevel", "error", "-i", str(segment_file), "-frames:v", "1", "-vf", "crop=120:120:(W-120)/2:(H-120)/2", "-f", "rawvideo", "-pix_fmt", "rgb24", str(center_file)])
    corner_std = _stddev(corner_file.read_bytes())
    center_std = _stddev(center_file.read_bytes())
    if corner_std <= center_std + 2.0:
        raise RuntimeError(f"watermark assertion failed: corner_std={corner_std:.2f} center_std={center_std:.2f}")
    return {"corner_stddev": round(corner_std, 3), "center_stddev": round(center_std, 3)}


def assert_encrypted_hls() -> None:
    variants = sorted(HLS_ROOT.glob("v*.m3u8"))
    if not variants:
        raise RuntimeError("no variant playlists found")
    any_key = False
    for p in variants:
        text = p.read_text(encoding="utf-8", errors="replace")
        if "#EXT-X-KEY:" in text:
            any_key = True
            break
    if not any_key:
        raise RuntimeError("encrypted hls assertion failed: #EXT-X-KEY marker not found")


def assert_archive_persistence() -> None:
    files = list(ARCHIVE_ROOT.glob("*.m3u8")) + list(ARCHIVE_ROOT.glob("*.ts"))
    if not files:
        raise RuntimeError("archive persistence assertion failed: archive output files missing")


def collect_artifacts() -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    for src, name in [
        (HLS_ROOT / "master.m3u8", "master.m3u8"),
        (HLS_ROOT / "v0.m3u8", "v0.m3u8"),
    ]:
        if src.exists():
            shutil.copy2(src, ARTIFACT_DIR / name)


def main() -> int:
    parser = argparse.ArgumentParser(description="Broadcast local E2E harness")
    parser.add_argument("--no-stack", action="store_true", help="skip docker compose up")
    args = parser.parse_args()

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    report: dict[str, object] = {"ok": False, "checks": {}}
    try:
        if not args.no_stack:
            start_stack()
        push_synthetic_rtmp()
        master = HLS_ROOT / "master.m3u8"
        if not wait_for_file(master, timeout_seconds=120):
            raise RuntimeError("master playlist not generated in time")
        report["checks"]["master_playlist"] = "ok"
        segment = next(iter(sorted(HLS_ROOT.glob("v0-seg-*.ts"))), None)
        if not segment:
            raise RuntimeError("segment file missing for watermark validation")
        report["checks"]["watermark"] = assert_watermark_present(segment)
        assert_encrypted_hls()
        report["checks"]["encrypted_hls"] = "ok"
        assert_archive_persistence()
        report["checks"]["archive_persistence"] = "ok"
        report["ok"] = True
    except Exception as exc:
        report["error"] = str(exc)
        return_code = 2
    else:
        return_code = 0
    finally:
        collect_artifacts()
        (ARTIFACT_DIR / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        if not args.no_stack:
            run(["docker", "compose", "-f", str(COMPOSE_FILE), "logs", "--no-color"], check=False, capture=True)
    print(json.dumps(report, indent=2))
    return return_code


if __name__ == "__main__":
    sys.exit(main())
