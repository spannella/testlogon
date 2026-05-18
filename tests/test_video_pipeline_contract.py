from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.contracts.video_pipeline_contract import (
    VIDEO_PIPELINE_CONTRACT_VERSION,
    VideoPipelineJobEvent,
    VideoPipelineJobRequest,
)

CONTRACT_SCHEMA_PATH = Path("docs/video-pipeline-contract-v1.json")
EVENT_CONTRACT_SCHEMA_PATH = Path("docs/video-pipeline-event-contract-v1.json")


def _valid_payload() -> dict:
    return {
        "contract_version": VIDEO_PIPELINE_CONTRACT_VERSION,
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
        "drm": {
            "profile": "none",
            "key_rotation_seconds": None,
            "offline_allowed": False,
        },
        "retention_days": 7,
    }


def test_contract_schema_version_is_stable() -> None:
    assert CONTRACT_SCHEMA_PATH.exists()
    schema = json.loads(CONTRACT_SCHEMA_PATH.read_text())
    assert schema["properties"]["contract_version"]["const"] == VIDEO_PIPELINE_CONTRACT_VERSION


def test_video_pipeline_request_accepts_valid_payload() -> None:
    parsed = VideoPipelineJobRequest.model_validate(_valid_payload())
    assert parsed.contract_version == VIDEO_PIPELINE_CONTRACT_VERSION
    assert parsed.asset.asset_id == "asset_1"
    assert parsed.renditions[0].name == "1080p"


def test_video_pipeline_request_rejects_invalid_contract_version() -> None:
    payload = _valid_payload()
    payload["contract_version"] = "2027-01-video-pipeline-v2"

    with pytest.raises(ValidationError) as exc:
        VideoPipelineJobRequest.model_validate(payload)

    assert "contract_version" in str(exc.value)


def test_video_pipeline_request_rejects_empty_renditions() -> None:
    payload = _valid_payload()
    payload["renditions"] = []

    with pytest.raises(ValidationError) as exc:
        VideoPipelineJobRequest.model_validate(payload)

    assert "renditions" in str(exc.value)


def test_event_contract_schema_version_is_stable() -> None:
    assert EVENT_CONTRACT_SCHEMA_PATH.exists()
    schema = json.loads(EVENT_CONTRACT_SCHEMA_PATH.read_text())
    assert schema["properties"]["contract_version"]["const"] == VIDEO_PIPELINE_CONTRACT_VERSION


def test_video_pipeline_event_accepts_valid_payload() -> None:
    event = VideoPipelineJobEvent.model_validate(
        {
            "contract_version": VIDEO_PIPELINE_CONTRACT_VERSION,
            "event_type": "job.completed",
            "job_id": "job_1",
            "asset_id": "asset_1",
            "tenant_id": "tenant_1",
            "status": "completed",
            "output_hls_manifest_uri": "s3://bucket/master.m3u8",
            "output_dash_manifest_uri": "s3://bucket/manifest.mpd",
            "error_code": None,
            "error_message": None,
        }
    )

    assert event.event_type == "job.completed"
    assert event.status == "completed"
