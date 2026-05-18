from __future__ import annotations

import subprocess
from pathlib import Path


def test_shell_scripts_are_syntax_valid() -> None:
    for script in (
        "scripts/video/push_sample_stream.sh",
        "scripts/video/package_vod.sh",
        "scripts/video/validate_manifests.sh",
        "scripts/video/ci_validate_video_artifacts.sh",
        "scripts/video/preprod_reliability_checks.sh",
    ):
        subprocess.run(["bash", "-n", script], check=True)


def test_validate_manifests_script_passes_for_expected_structure(tmp_path: Path) -> None:
    hls = tmp_path / "hls"
    dash = tmp_path / "dash"
    for rendition in ("1080p", "720p", "540p", "360p"):
        path = hls / rendition
        path.mkdir(parents=True, exist_ok=True)
        (path / "index.m3u8").write_text("#EXTM3U\n")

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
        + "\n"
    )
    dash.mkdir(parents=True, exist_ok=True)
    (dash / "manifest.mpd").write_text("v_1080p v_720p v_540p v_360p")

    subprocess.run(["bash", "scripts/video/validate_manifests.sh", str(tmp_path)], check=True)
