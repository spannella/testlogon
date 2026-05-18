from __future__ import annotations

from pathlib import Path

import pytest

from app.contracts.video_rendition_profiles import CANONICAL_ABR_LADDER
from app.contracts.watermark_policy import TenantWatermarkSettings, WatermarkPolicy
from app.services.ffmpeg_abr_pipeline import build_rendition_ffmpeg_args, write_master_playlist


def test_build_rendition_args_for_dynamic_text_interpolates_variables(tmp_path: Path) -> None:
    policy = WatermarkPolicy(mode="dynamic_text", text_template="tenant={{tenant_id}} session={{session_id}}", position="top_right", opacity=0.7)
    args = build_rendition_ffmpeg_args(
        input_url="rtmp://ingest/live/localdemo",
        output_dir=tmp_path,
        rendition=CANONICAL_ABR_LADDER[0],
        watermark_policy=policy,
        tenant_settings=TenantWatermarkSettings(tenant_id="tenant-x"),
        watermark_template_values={"session_id": "sess-99"},
    )

    joined = " ".join(args)
    assert "drawtext=text='tenant=tenant-x session=sess-99'" in joined
    assert "scale=1920:1080" in joined
    assert str(tmp_path / "1080p" / "index.m3u8") in joined


def test_build_rendition_args_fails_for_unsupported_dynamic_variable_before_job_start(tmp_path: Path) -> None:
    policy = WatermarkPolicy.model_construct(
        mode="dynamic_text",
        position="top_right",
        opacity=0.7,
        margin_x=24,
        margin_y=24,
        text_template="tenant={{tenant_id}} bad={{unsupported_var}}",
        asset_uri=None,
    )

    with pytest.raises(ValueError) as exc:
        build_rendition_ffmpeg_args(
            input_url="rtmp://ingest/live/localdemo",
            output_dir=tmp_path,
            rendition=CANONICAL_ABR_LADDER[0],
            watermark_policy=policy,
        )

    assert "unsupported watermark template variable" in str(exc.value)


def test_build_rendition_args_for_static_image_includes_overlay(tmp_path: Path) -> None:
    policy = WatermarkPolicy(mode="static_image", asset_uri="/tmp/logo.png", position="bottom_right", opacity=0.8)
    args = build_rendition_ffmpeg_args(
        input_url="rtmp://ingest/live/localdemo",
        output_dir=tmp_path,
        rendition=CANONICAL_ABR_LADDER[1],
        watermark_policy=policy,
    )

    joined = " ".join(args)
    assert "-filter_complex" in joined
    assert "overlay=" in joined
    assert "/tmp/logo.png" in joined


def test_write_master_playlist_contains_all_expected_renditions(tmp_path: Path) -> None:
    master = write_master_playlist(tmp_path)
    text = master.read_text()
    for rendition in ("1080p/index.m3u8", "720p/index.m3u8", "540p/index.m3u8", "360p/index.m3u8"):
        assert rendition in text
