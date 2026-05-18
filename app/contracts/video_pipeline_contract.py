from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.contracts.video_rendition_profiles import RenditionName
from app.contracts.watermark_policy import WatermarkPolicy

VIDEO_PIPELINE_CONTRACT_VERSION = "2026-03-video-pipeline-v1"
SUPPORTED_VIDEO_PIPELINE_CONTRACT_VERSIONS = {VIDEO_PIPELINE_CONTRACT_VERSION}


class VideoRenditionProfile(BaseModel):
    name: RenditionName
    width: int = Field(ge=1)
    height: int = Field(ge=1)
    video_bitrate_kbps: int = Field(ge=1)
    audio_bitrate_kbps: int = Field(ge=1)
    fps: int = Field(ge=1)


class DrmPolicy(BaseModel):
    profile: Literal["none", "widevine", "fairplay", "playready", "multi_drm"] = "none"
    key_rotation_seconds: int | None = Field(default=300, ge=60)
    per_content_key: bool = True
    offline_allowed: bool = False


class VideoAssetSpec(BaseModel):
    asset_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    source_uri: str = Field(min_length=1)
    input_codec: Literal["h264", "hevc", "av1"]
    input_fps: int = Field(ge=1)
    input_width: int = Field(ge=1)
    input_height: int = Field(ge=1)
    audio_layout: Literal["mono", "stereo", "5.1"] = "stereo"


class VideoPipelineJobRequest(BaseModel):
    contract_version: Literal["2026-03-video-pipeline-v1"] = VIDEO_PIPELINE_CONTRACT_VERSION
    asset: VideoAssetSpec
    renditions: list[VideoRenditionProfile] = Field(default_factory=list, min_length=1)
    watermark: WatermarkPolicy = Field(default_factory=WatermarkPolicy)
    drm: DrmPolicy = Field(default_factory=DrmPolicy)
    retention_days: int = Field(default=30, ge=1)


class VideoPipelineJobAccepted(BaseModel):
    contract_version: Literal["2026-03-video-pipeline-v1"] = VIDEO_PIPELINE_CONTRACT_VERSION
    job_id: str = Field(min_length=1)
    status: Literal["accepted"] = "accepted"


class VideoPipelineJobEvent(BaseModel):
    contract_version: Literal["2026-03-video-pipeline-v1"] = VIDEO_PIPELINE_CONTRACT_VERSION
    event_type: Literal["job.accepted", "job.running", "job.failed", "job.completed"]
    job_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    status: Literal["accepted", "running", "failed", "completed"]
    error_code: str | None = None
    error_message: str | None = None
    output_hls_manifest_uri: str | None = None
    output_dash_manifest_uri: str | None = None

