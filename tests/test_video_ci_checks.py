from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _write_valid_artifacts(root: Path) -> None:
    hls = root / "hls"
    dash = root / "dash"
    for rendition in ("1080p", "720p", "540p", "360p"):
        variant = hls / rendition
        variant.mkdir(parents=True, exist_ok=True)
        (variant / "index.m3u8").write_text(
            "\n".join(
                [
                    "#EXTM3U",
                    "#EXT-X-TARGETDURATION:2",
                    "#EXTINF:2.0,",
                    "seg_00001.ts",
                    "#EXTINF:2.0,",
                    "seg_00002.ts",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    (hls / "master.m3u8").write_text(
        "\n".join(
            [
                "#EXTM3U",
                "1080p/index.m3u8",
                "720p/index.m3u8",
                "540p/index.m3u8",
                "360p/index.m3u8",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    dash.mkdir(parents=True, exist_ok=True)
    (dash / "manifest.mpd").write_text("<MPD>v_1080p v_720p v_540p v_360p</MPD>", encoding="utf-8")


def test_ci_validation_script_passes_for_valid_artifacts(tmp_path: Path) -> None:
    _write_valid_artifacts(tmp_path)
    snapshot = tmp_path / "frame_with_watermark.jpg"
    snapshot.write_bytes(b"fake-image-bytes")

    subprocess.run(
        [
            sys.executable,
            "scripts/video/ci_validate_video_artifacts.py",
            "--root",
            str(tmp_path),
            "--watermark-snapshot",
            str(snapshot),
        ],
        check=True,
    )


def test_ci_validation_script_fails_on_missing_rendition(tmp_path: Path) -> None:
    _write_valid_artifacts(tmp_path)
    master = tmp_path / "hls" / "master.m3u8"
    master.write_text("#EXTM3U\n1080p/index.m3u8\n720p/index.m3u8\n540p/index.m3u8\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "scripts/video/ci_validate_video_artifacts.py", "--root", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "missing rendition" in result.stderr


def test_ci_validation_script_fails_on_segment_continuity(tmp_path: Path) -> None:
    _write_valid_artifacts(tmp_path)
    broken = tmp_path / "hls" / "720p" / "index.m3u8"
    broken.write_text("#EXTM3U\nseg_00001.ts\nseg_00003.ts\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "scripts/video/ci_validate_video_artifacts.py", "--root", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "continuity" in result.stderr


def test_ci_validation_script_fails_on_missing_watermark_snapshot(tmp_path: Path) -> None:
    _write_valid_artifacts(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "scripts/video/ci_validate_video_artifacts.py",
            "--root",
            str(tmp_path),
            "--watermark-snapshot",
            str(tmp_path / "missing.jpg"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "watermark snapshot missing" in result.stderr
