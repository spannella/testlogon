from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.contracts.video_rendition_profiles import CANONICAL_ABR_LADDER
from app.contracts.watermark_policy import (
    TenantWatermarkSettings,
    WatermarkPolicy,
    interpolate_template_variables,
)


def _overlay_xy(position: str, margin_x: int, margin_y: int) -> str:
    if position == "top_left":
        return f"{margin_x}:{margin_y}"
    if position == "top_right":
        return f"W-w-{margin_x}:{margin_y}"
    if position == "bottom_left":
        return f"{margin_x}:H-h-{margin_y}"
    return f"W-w-{margin_x}:H-h-{margin_y}"


def _resolve_asset_uri(policy: WatermarkPolicy, tenant_settings: TenantWatermarkSettings | None) -> str | None:
    if policy.asset_uri:
        return policy.asset_uri
    if tenant_settings and tenant_settings.branding_asset_uri:
        return tenant_settings.branding_asset_uri
    return None


def _default_template_values(
    *,
    tenant_settings: TenantWatermarkSettings | None,
    watermark_template_values: dict[str, str] | None,
) -> dict[str, str]:
    values = {
        "tenant_id": tenant_settings.tenant_id if tenant_settings else "",
        "session_id": "",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if watermark_template_values:
        values.update({k: str(v) for k, v in watermark_template_values.items()})
    return values


def build_rendition_ffmpeg_args(
    *,
    input_url: str,
    output_dir: Path,
    rendition: dict[str, Any],
    watermark_policy: WatermarkPolicy,
    tenant_settings: TenantWatermarkSettings | None = None,
    watermark_template_values: dict[str, str] | None = None,
) -> list[str]:
    name = rendition["name"]
    width = rendition["width"]
    height = rendition["height"]
    video_bitrate_kbps = rendition["video_bitrate_kbps"]
    audio_bitrate_kbps = rendition["audio_bitrate_kbps"]

    out_dir = output_dir / name
    out_dir.mkdir(parents=True, exist_ok=True)
    output_playlist = out_dir / "index.m3u8"
    output_segment = out_dir / "seg_%05d.ts"

    args = ["ffmpeg", "-hide_banner", "-loglevel", "warning", "-y", "-rw_timeout", "5000000", "-i", input_url]

    if watermark_policy.mode == "dynamic_text":
        text = interpolate_template_variables(
            watermark_policy.text_template or "tenant={{tenant_id}}",
            _default_template_values(
                tenant_settings=tenant_settings,
                watermark_template_values=watermark_template_values,
            ),
        ).replace("'", r"\'")
        x_y = _overlay_xy(watermark_policy.position, watermark_policy.margin_x, watermark_policy.margin_y)
        drawtext = (
            f"scale={width}:{height},"
            f"drawtext=text='{text}':x={x_y.split(':')[0]}:y={x_y.split(':')[1]}:"
            f"fontcolor=white@{watermark_policy.opacity}:fontsize=24"
        )
        args += ["-vf", drawtext]
    elif watermark_policy.mode == "static_image":
        asset = _resolve_asset_uri(watermark_policy, tenant_settings)
        if asset:
            x_y = _overlay_xy(watermark_policy.position, watermark_policy.margin_x, watermark_policy.margin_y)
            filter_complex = (
                f"[0:v]scale={width}:{height}[base];"
                f"[1:v]format=rgba,colorchannelmixer=aa={watermark_policy.opacity}[wm];"
                f"[base][wm]overlay={x_y}[vout]"
            )
            args += ["-i", asset, "-filter_complex", filter_complex, "-map", "[vout]", "-map", "0:a?"]
        else:
            args += ["-vf", f"scale={width}:{height}"]
    else:
        args += ["-vf", f"scale={width}:{height}"]

    args += [
        "-c:v",
        "libx264",
        "-preset",
        "veryfast",
        "-g",
        "60",
        "-sc_threshold",
        "0",
        "-b:v",
        f"{video_bitrate_kbps}k",
        "-c:a",
        "aac",
        "-b:a",
        f"{audio_bitrate_kbps}k",
        "-f",
        "hls",
        "-hls_time",
        "2",
        "-hls_list_size",
        "6",
        "-hls_flags",
        "delete_segments+append_list",
        "-hls_segment_filename",
        str(output_segment),
        str(output_playlist),
    ]

    return args


def write_master_playlist(output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    master = output_dir / "master.m3u8"
    lines = ["#EXTM3U", "#EXT-X-VERSION:3"]
    for r in CANONICAL_ABR_LADDER:
        bw = int(r["video_bitrate_kbps"]) * 1000
        lines.append(f"#EXT-X-STREAM-INF:BANDWIDTH={bw},RESOLUTION={r['width']}x{r['height']}")
        lines.append(f"{r['name']}/index.m3u8")
    master.write_text("\n".join(lines) + "\n")
    return master
