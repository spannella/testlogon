from __future__ import annotations

from app.contracts.video_pipeline_contract import VideoPipelineJobRequest
from app.contracts.video_rendition_profiles import (
    CANONICAL_ABR_LADDER,
    CANONICAL_RENDITION_NAMES,
    dash_representation_id,
    manifest_variant_path,
)


def test_canonical_ladder_names_and_order_are_stable() -> None:
    assert CANONICAL_RENDITION_NAMES == ("1080p", "720p", "540p", "360p")
    assert tuple(item["name"] for item in CANONICAL_ABR_LADDER) == CANONICAL_RENDITION_NAMES


def test_manifest_and_dash_naming_conventions() -> None:
    assert manifest_variant_path(tenant_id="t1", asset_id="a1", rendition="720p") == "tenants/t1/assets/a1/hls/720p/index.m3u8"
    assert dash_representation_id("540p") == "v_540p"


def test_video_contract_accepts_canonical_rendition_names() -> None:
    payload = {
        "contract_version": "2026-03-video-pipeline-v1",
        "asset": {
            "asset_id": "asset_1",
            "tenant_id": "tenant_1",
            "source_uri": "rtmp://ingest/live/demo",
            "input_codec": "h264",
            "input_fps": 30,
            "input_width": 1920,
            "input_height": 1080,
            "audio_layout": "stereo",
        },
        "renditions": [
            {
                "name": "720p",
                "width": 1280,
                "height": 720,
                "video_bitrate_kbps": 3500,
                "audio_bitrate_kbps": 128,
                "fps": 30,
            }
        ],
        "watermark": {"mode": "none", "position": "top_right", "opacity": 0.7, "margin_x": 24, "margin_y": 24},
        "drm": {"profile": "none", "key_rotation_seconds": None, "offline_allowed": False},
        "retention_days": 30,
    }

    parsed = VideoPipelineJobRequest.model_validate(payload)
    assert parsed.renditions[0].name == "720p"
