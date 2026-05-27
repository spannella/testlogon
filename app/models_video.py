from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

VideoStatus = Literal[
    "created",
    "probing",
    "probe_failed",
    "pending_encoding",
    "encoding",
    "encoding_failed",
    "pending_review",
    "approved",
    "rejected",
    "published",
    "archived",
    "deleted",
]

VideoSourceType = Literal["upload", "broadcast_archive", "api"]
VideoVisibility = Literal["private", "unlisted", "public"]
VideoReviewStatus = Literal["pending_review", "approved", "rejected"]


class VideoRendition(BaseModel):
    """Per-rendition output metadata stored on completed videos."""

    label: str = Field(min_length=1, max_length=32)
    width: int = Field(ge=1)
    height: int = Field(ge=1)
    bitrate_kbps: int = Field(ge=1)


class VideoMetadataModel(BaseModel):
    id: str = Field(min_length=1)
    owner_user_id: str = Field(min_length=1)
    title: str = Field(min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
    status: VideoStatus = "created"
    created_at: int = 0
    updated_at: int = 0

    # Source
    source_type: VideoSourceType = "upload"
    source_file_node_id: Optional[str] = None
    source_broadcast_session_id: Optional[str] = None
    source_s3_key: Optional[str] = None

    # Technical properties
    duration_seconds: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None
    frame_rate: Optional[float] = None
    video_codec: Optional[str] = None
    audio_codec: Optional[str] = None
    audio_channels: Optional[int] = None
    bitrate_kbps: Optional[int] = None
    container_format: Optional[str] = None
    file_size_bytes: Optional[int] = None

    # Encoding
    encoding_profile_id: Optional[str] = None
    encoding_job_id: Optional[str] = None
    encoding_started_at: Optional[int] = None
    encoding_completed_at: Optional[int] = None
    encoding_error_message: Optional[str] = None

    # Outputs
    thumbnail_s3_key: Optional[str] = None
    thumbnail_url: Optional[str] = None
    hls_manifest_s3_key: Optional[str] = None
    hls_manifest_url: Optional[str] = None
    dash_manifest_s3_key: Optional[str] = None
    renditions: List[VideoRendition] = Field(default_factory=list)

    # Review
    review_status: Optional[VideoReviewStatus] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[int] = None
    review_notes: Optional[str] = None

    # DRM
    drm_enabled: bool = False
    drm_policy_id: Optional[str] = None
    drm_key_id: Optional[str] = None

    # Entitlement
    entitlement_sku: Optional[str] = None

    # Pricing / Pay-Per-View (MON-001)
    price_cents: Optional[int] = None
    access_mode: Optional[str] = None  # "free", "ppv", "subscriber_only", "subscriber_free"
    purchase_count: int = 0
    revenue_cents: int = 0

    # Visibility
    visibility: VideoVisibility = "private"
    published_at: Optional[int] = None
    deleted_at: Optional[int] = None

    # Download (VOD-012)
    allow_download: bool = False
    download_mp4_key: str = ""
    download_mp4_size_bytes: int = 0
    download_mp4_status: str = ""  # "", "generating", "ready", "failed"
    download_count: int = 0


class CreateVideoIn(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
    source_type: VideoSourceType = "upload"
    source_file_node_id: Optional[str] = None
    source_broadcast_session_id: Optional[str] = None
    source_s3_key: Optional[str] = None
    encoding_profile_id: Optional[str] = None
    visibility: VideoVisibility = "private"
    drm_enabled: bool = False
    drm_policy_id: Optional[str] = None
    entitlement_sku: Optional[str] = None


class UpdateVideoIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
    visibility: Optional[VideoVisibility] = None
    encoding_profile_id: Optional[str] = None
    drm_enabled: Optional[bool] = None
    drm_policy_id: Optional[str] = None
    entitlement_sku: Optional[str] = None
    allow_download: Optional[bool] = None


class VideoOut(BaseModel):
    video_id: str
    owner_user_id: str
    title: str
    description: Optional[str] = None
    status: VideoStatus
    created_at: int
    updated_at: int
    source_type: VideoSourceType
    duration_seconds: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None
    thumbnail_url: Optional[str] = None
    hls_manifest_url: Optional[str] = None
    renditions: List[VideoRendition] = Field(default_factory=list)
    review_status: Optional[VideoReviewStatus] = None
    visibility: VideoVisibility = "private"
    published_at: Optional[int] = None
    file_size_bytes: Optional[int] = None
    drm_enabled: bool = False
    drm_key_uri: Optional[str] = None

    # Download (VOD-012)
    allow_download: bool = False
    download_available: bool = False
    download_mp4_size_bytes: Optional[int] = None
