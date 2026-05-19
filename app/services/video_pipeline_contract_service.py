from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from app.contracts.video_pipeline_contract import (
    SUPPORTED_VIDEO_PIPELINE_CONTRACT_VERSIONS,
    VIDEO_PIPELINE_CONTRACT_VERSION,
    VideoPipelineJobEvent,
    VideoPipelineJobRequest,
)
from app.contracts.video_rendition_profiles import CANONICAL_ABR_LADDER, CANONICAL_RENDITION_NAMES
from app.contracts.watermark_policy import ALLOWED_WATERMARK_TEMPLATE_VARIABLES


def validate_video_pipeline_job(payload: dict[str, Any]) -> VideoPipelineJobRequest:
    try:
        return VideoPipelineJobRequest.model_validate(payload)
    except ValidationError as exc:
        normalized_errors = sorted(
            f"{'.'.join(str(part) for part in e['loc'])}: {e['msg']}" for e in exc.errors(include_url=False)
        )
        raise ValueError(f"invalid video pipeline contract payload: {' | '.join(normalized_errors)}") from exc



def validate_video_pipeline_event(payload: dict[str, Any]) -> VideoPipelineJobEvent:
    try:
        return VideoPipelineJobEvent.model_validate(payload)
    except ValidationError as exc:
        normalized_errors = sorted(
            f"{'.'.join(str(part) for part in e['loc'])}: {e['msg']}" for e in exc.errors(include_url=False)
        )
        raise ValueError(f"invalid video pipeline event payload: {' | '.join(normalized_errors)}") from exc


def contract_capabilities_snapshot() -> dict[str, Any]:
    return {
        "active_contract_version": VIDEO_PIPELINE_CONTRACT_VERSION,
        "event_contract_version": VIDEO_PIPELINE_CONTRACT_VERSION,
        "supported_contract_versions": sorted(SUPPORTED_VIDEO_PIPELINE_CONTRACT_VERSIONS),
        "backward_compatibility_policy": {
            "minor_additive_fields": "accepted for 90 days before becoming required",
            "new_major_version": "published in parallel and old major remains accepted for at least 180 days",
            "breaking_enum_changes": "require new contract_version",
        },
        "canonical_rendition_names": list(CANONICAL_RENDITION_NAMES),
        "canonical_abr_ladder": list(CANONICAL_ABR_LADDER),
        "watermark_template_variables": list(ALLOWED_WATERMARK_TEMPLATE_VARIABLES),
        "watermark_modes": ["none", "static_image", "dynamic_text"],
        "watermark_positions": ["top_left", "top_right", "bottom_left", "bottom_right"],
        "drm_profiles": ["widevine", "fairplay", "playready", "multi_drm"],
        "drm_policy_defaults": {"key_rotation_seconds": 300, "per_content_key": True},
    }
