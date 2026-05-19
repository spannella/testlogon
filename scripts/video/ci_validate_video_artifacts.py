#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REQUIRED_RENDITIONS = ("1080p", "720p", "540p", "360p")
SEGMENT_RE = re.compile(r"(\d+)(?=\.[^.]+$)")


class ValidationFailure(RuntimeError):
    pass


def _read_text(path: Path) -> str:
    if not path.exists():
        raise ValidationFailure(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def validate_manifests(root: Path) -> None:
    hls_master = root / "hls" / "master.m3u8"
    dash_manifest = root / "dash" / "manifest.mpd"

    master_text = _read_text(hls_master)
    dash_text = _read_text(dash_manifest)
    if "#EXTM3U" not in master_text:
        raise ValidationFailure("invalid HLS master manifest header")
    if "<MPD" not in dash_text:
        raise ValidationFailure("invalid DASH manifest header")

    for rendition in REQUIRED_RENDITIONS:
        variant_ref = f"{rendition}/index.m3u8"
        if variant_ref not in master_text:
            raise ValidationFailure(f"missing rendition in HLS master: {variant_ref}")

        representation_id = f"v_{rendition}"
        if representation_id not in dash_text:
            raise ValidationFailure(f"missing representation in DASH manifest: {representation_id}")

        validate_variant_playlist(root / "hls" / rendition / "index.m3u8", rendition=rendition)


def validate_variant_playlist(path: Path, *, rendition: str) -> None:
    text = _read_text(path)
    if "#EXTM3U" not in text:
        raise ValidationFailure(f"invalid HLS variant header for {rendition}")

    segments = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    if not segments:
        raise ValidationFailure(f"no segments present in variant playlist: {rendition}")

    numbers: list[int] = []
    for segment in segments:
        match = SEGMENT_RE.search(segment)
        if not match:
            raise ValidationFailure(f"non-numeric segment sequence in {rendition}: {segment}")
        numbers.append(int(match.group(1)))

    expected = list(range(numbers[0], numbers[0] + len(numbers)))
    if numbers != expected:
        raise ValidationFailure(
            f"segment continuity check failed for {rendition}: expected consecutive sequence {expected}, found {numbers}"
        )


def validate_watermark_snapshot(snapshot_path: Path) -> None:
    if not snapshot_path.exists():
        raise ValidationFailure(f"watermark snapshot missing: {snapshot_path}")
    data = snapshot_path.read_bytes()
    if not data:
        raise ValidationFailure(f"watermark snapshot is empty: {snapshot_path}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate local video artifacts for CI.")
    parser.add_argument("--root", default="video-data", help="artifact root containing hls/ and dash/")
    parser.add_argument(
        "--watermark-snapshot",
        default="",
        help="path to extracted frame snapshot used for basic watermark presence assertion",
    )
    args = parser.parse_args(argv)

    root = Path(args.root)
    validate_manifests(root)
    if args.watermark_snapshot:
        validate_watermark_snapshot(Path(args.watermark_snapshot))

    print("video artifact CI validation passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ValidationFailure as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
