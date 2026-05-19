from __future__ import annotations

import pytest

from app.services.video_pipeline_contract_service import (
    contract_capabilities_snapshot,
    validate_video_pipeline_event,
    validate_video_pipeline_job,
)


def _payload() -> dict:
    return {
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
                "name": "1080p",
                "width": 1920,
                "height": 1080,
                "video_bitrate_kbps": 6000,
                "audio_bitrate_kbps": 192,
                "fps": 30,
            }
        ],
        "watermark": {
            "mode": "dynamic_text",
            "position": "top_right",
            "opacity": 0.7,
            "margin_x": 24,
            "margin_y": 24,
            "text_template": "tenant={{tenant_id}}",
            "asset_uri": None,
        },
        "drm": {"profile": "none", "key_rotation_seconds": None, "offline_allowed": False},
        "retention_days": 30,
    }


def test_validate_video_pipeline_job_accepts_valid_payload() -> None:
    parsed = validate_video_pipeline_job(_payload())
    assert parsed.contract_version == "2026-03-video-pipeline-v1"


def test_validate_video_pipeline_job_returns_deterministic_error() -> None:
    bad_payload = _payload()
    bad_payload["contract_version"] = "v2"
    bad_payload["renditions"] = []

    with pytest.raises(ValueError) as exc:
        validate_video_pipeline_job(bad_payload)

    message = str(exc.value)
    assert message.startswith("invalid video pipeline contract payload:")
    assert "contract_version" in message
    assert "renditions" in message


def test_contract_capabilities_snapshot_contains_versions_and_policy() -> None:
    snapshot = contract_capabilities_snapshot()

    assert snapshot["active_contract_version"] == "2026-03-video-pipeline-v1"
    assert "2026-03-video-pipeline-v1" in snapshot["supported_contract_versions"]
    assert "minor_additive_fields" in snapshot["backward_compatibility_policy"]
    assert snapshot["canonical_rendition_names"] == ["1080p", "720p", "540p", "360p"]
    assert snapshot["watermark_modes"] == ["none", "static_image", "dynamic_text"]
    assert snapshot["watermark_positions"] == ["top_left", "top_right", "bottom_left", "bottom_right"]
    assert snapshot["drm_profiles"] == ["widevine", "fairplay", "playready", "multi_drm"]
    assert snapshot["drm_policy_defaults"] == {"key_rotation_seconds": 300, "per_content_key": True}


def _event_payload() -> dict:
    return {
        "contract_version": "2026-03-video-pipeline-v1",
        "event_type": "job.running",
        "job_id": "job_1",
        "asset_id": "asset_1",
        "tenant_id": "tenant_1",
        "status": "running",
    }


def test_validate_video_pipeline_event_accepts_valid_payload() -> None:
    parsed = validate_video_pipeline_event(_event_payload())
    assert parsed.event_type == "job.running"


def test_validate_video_pipeline_event_returns_deterministic_error() -> None:
    bad_event = _event_payload()
    bad_event["event_type"] = "job.unknown"

    with pytest.raises(ValueError) as exc:
        validate_video_pipeline_event(bad_event)

    message = str(exc.value)
    assert message.startswith("invalid video pipeline event payload:")
    assert "event_type" in message
