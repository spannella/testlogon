from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


BroadcastSessionStatus = Literal[
    "draft",
    "provisioning",
    "ready",
    "live",
    "stopping",
    "stopped",
    "error",
]


class BroadcastProfileModel(BaseModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1, max_length=120)
    region: str = Field(min_length=1, max_length=32)
    rendition_preset: str = Field(min_length=1, max_length=64)
    watermark_asset: Optional[str] = None
    drm_policy_id: Optional[str] = None
    drm_credentials_ref: Optional[str] = None
    drm_credentials_last_rotated_at: Optional[str] = None
    drm_credentials_rotation_interval_seconds: int = 86400
    created_by: str = Field(min_length=1)
    created_at: str = ""
    updated_at: str = ""


class BroadcastSessionModel(BaseModel):
    id: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    status: BroadcastSessionStatus = "draft"
    ingest_url: Optional[str] = None
    stream_key_ref: Optional[str] = None
    stream_key_last_rotated_at: Optional[str] = None
    stream_key_rotation_interval_seconds: int = 86400
    started_at: Optional[str] = None
    stopped_at: Optional[str] = None
    created_by: str = Field(min_length=1)
    created_at: str = ""
    updated_at: str = ""


class BroadcastOutputModel(BaseModel):
    session_id: str = Field(min_length=1)
    mediapackage_endpoint: Optional[str] = None
    cloudfront_playback_url: Optional[str] = None
    s3_archive_prefix: Optional[str] = None
    aws_input_arn: Optional[str] = None
    aws_channel_arn: Optional[str] = None
    provider_state_snapshot: dict = Field(default_factory=dict)
    updated_at: str = ""


class BroadcastSessionTransitionAuditModel(BaseModel):
    transition_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    from_status: BroadcastSessionStatus
    to_status: BroadcastSessionStatus
    reason: str = Field(min_length=1, max_length=512)
    actor: str = Field(min_length=1)
    created_at: str
    error_code: str = Field(default="BROADCAST_INVALID_STATE_TRANSITION")


class BroadcastSecretReferenceModel(BaseModel):
    secret_ref: str = Field(min_length=1, max_length=2048)
    purpose: Literal["stream_key", "drm_credentials"]
    backend: Literal["secrets_manager", "ssm"] = "secrets_manager"
    last_rotated_at: Optional[str] = None
    rotation_interval_seconds: int = 86400


class BroadcastActionAuditEventModel(BaseModel):
    audit_id: str = Field(min_length=1)
    action: Literal["create_profile", "create_session", "start_session", "stop_session", "delete_session"]
    actor: str = Field(min_length=1)
    correlation_id: str = Field(min_length=1)
    resource_type: Literal["profile", "session"]
    resource_id: str = Field(min_length=1)
    created_at: str
    metadata: dict = Field(default_factory=dict)
