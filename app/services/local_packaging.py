from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.contracts.video_rendition_profiles import CANONICAL_ABR_LADDER


def build_hls_master_manifest() -> str:
    lines = ["#EXTM3U", "#EXT-X-VERSION:3"]
    for r in CANONICAL_ABR_LADDER:
        bw = int(r["video_bitrate_kbps"]) * 1000
        lines.append(f"#EXT-X-STREAM-INF:BANDWIDTH={bw},RESOLUTION={r['width']}x{r['height']}")
        lines.append(f"{r['name']}/index.m3u8")
    return "\n".join(lines) + "\n"


def build_dash_manifest() -> str:
    reps = []
    for r in CANONICAL_ABR_LADDER:
        reps.append(
            f'<Representation id="v_{r["name"]}" bandwidth="{int(r["video_bitrate_kbps"])*1000}" '
            f'width="{r["width"]}" height="{r["height"]}" frameRate="{r["fps"]}" />'
        )
    joined = "\n      ".join(reps)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="dynamic" minBufferTime="PT1.5S">\n'
        '  <Period>\n'
        '    <AdaptationSet mimeType="video/mp4">\n'
        f'      {joined}\n'
        '    </AdaptationSet>\n'
        '  </Period>\n'
        '</MPD>\n'
    )


def shaka_packager_config(output_root: str = "/workspace/video-data") -> dict[str, Any]:
    streams = []
    for r in CANONICAL_ABR_LADDER:
        name = r["name"]
        streams.append(
            {
                "name": name,
                "input": f"{output_root}/hls/{name}/index.m3u8",
                "dash_output": f"{output_root}/dash/{name}.mp4",
                "hls_output": f"{output_root}/hls/{name}/index.m3u8",
                "dash_representation_id": f"v_{name}",
            }
        )
    return {
        "tool": "shaka-packager",
        "streams": streams,
        "dash_manifest_output": f"{output_root}/dash/manifest.mpd",
        "hls_master_playlist_output": f"{output_root}/hls/master.m3u8",
        "path_convention": {
            "hls_variant": "hls/<rendition>/index.m3u8",
            "dash_manifest": "dash/manifest.mpd",
            "dash_representation_id": "v_<rendition>",
        },
    }


def write_local_manifests(output_root: Path) -> None:
    hls_dir = output_root / "hls"
    dash_dir = output_root / "dash"
    hls_dir.mkdir(parents=True, exist_ok=True)
    dash_dir.mkdir(parents=True, exist_ok=True)
    (hls_dir / "master.m3u8").write_text(build_hls_master_manifest())
    (dash_dir / "manifest.mpd").write_text(build_dash_manifest())


def write_shaka_packager_config(path: Path, output_root: str = "/workspace/video-data") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(shaka_packager_config(output_root=output_root), indent=2) + "\n")
