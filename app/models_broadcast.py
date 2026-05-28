from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


BroadcastSessionStatus = Literal[
    "draft",
    "scheduled",
    "provisioning",
    "ready",
    "live",
    "private",
    "stopping",
    "stopped",
    "cancelled",
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

    # Scheduling (BCAST-009)
    scheduled_at: Optional[int] = None
    schedule_status: Optional[str] = None  # "scheduled", "launched", "cancelled"
    name: Optional[str] = None
    description: Optional[str] = None
    thumbnail_url: Optional[str] = None
    cancelled_at: Optional[str] = None
    announcement_post_id: Optional[str] = None

    # Go-Private (BCAST-011)
    private_session_id: Optional[str] = None
    private_behavior: Optional[str] = None  # "pause", "end"
    private_min_rate_cents: Optional[int] = None

    # Private Chat (BCAST-012)
    private_chat_enabled: bool = False
    private_chat_tiers: Optional[list] = None  # [{minutes, price_cents}, ...]
    private_chat_voyeur_enabled: bool = False
    private_chat_voyeur_price_cents: Optional[int] = None

    # Live Tipping (BCAST-013)
    tip_total_cents: int = 0
    tip_count: int = 0
    tip_enabled: bool = True
    tip_min_cents: int = 100
    tip_max_cents: int = 100000

    # Multi-input / Co-streaming (BCAST-016)
    max_inputs: int = Field(default=4, ge=1, le=8)
    active_layout: Optional[str] = None       # "single" | "side_by_side" | "pip" | "grid"
    active_input_ids: Optional[list] = None   # List of input_ids currently on-screen
    primary_input_id: Optional[str] = None    # Main input in PiP mode
    guest_invite_enabled: bool = False


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
    action: Literal[
        "create_profile", "create_session", "start_session", "stop_session", "delete_session",
        "schedule_session", "cancel_scheduled_session", "reschedule_session",
        "go_private", "end_private", "private_chat_start", "private_chat_end",
    ]
    actor: str = Field(min_length=1)
    correlation_id: str = Field(min_length=1)
    resource_type: Literal["profile", "session"]
    resource_id: str = Field(min_length=1)
    created_at: str
    metadata: dict = Field(default_factory=dict)


# ─── Multi-Input / Co-streaming Models (BCAST-016) ────────────────────

class BroadcastInputModel(BaseModel):
    """A single video input attached to a broadcast session."""
    input_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=64)
    input_type: Literal["primary", "guest", "screen"] = "primary"
    label: str = Field(default="", max_length=100)
    ingest_url: Optional[str] = Field(default=None, max_length=1024)
    stream_key_ref: Optional[str] = Field(default=None, max_length=2048)
    aws_input_arn: Optional[str] = Field(default=None, max_length=512)
    aws_input_id: Optional[str] = Field(default=None, max_length=64)
    is_live: bool = False
    connected_at: Optional[int] = None
    disconnected_at: Optional[int] = None
    position: int = Field(default=0, ge=0, le=7)
    created_by: str = Field(min_length=1)
    created_at: str = ""
    updated_at: str = ""
    relay_mode: Optional[Literal["rtmp", "webrtc_relay"]] = None
    relay_process_id: Optional[str] = None


class BroadcastGuestInvite(BaseModel):
    """Guest co-streamer invite."""
    invite_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=64)
    input_id: str = Field(min_length=1, max_length=64)
    created_by: str = Field(min_length=1)
    status: Literal["pending", "accepted", "expired", "revoked"] = "pending"
    guest_user_id: Optional[str] = None
    guest_display_name: Optional[str] = Field(default=None, max_length=100)
    join_mode: Literal["rtmp", "browser"] = "browser"
    ingest_url: Optional[str] = Field(default=None, max_length=1024)
    stream_key: Optional[str] = None
    stream_key_ref: Optional[str] = Field(default=None, max_length=2048)
    expires_at: int = 0
    accepted_at: Optional[int] = None
    created_at: str = ""
    updated_at: str = ""


class LayoutPosition(BaseModel):
    """Position of a single input in the composed output."""
    input_id: str = Field(min_length=1, max_length=64)
    x: float = Field(ge=0.0, le=1.0)
    y: float = Field(ge=0.0, le=1.0)
    width: float = Field(gt=0.0, le=1.0)
    height: float = Field(gt=0.0, le=1.0)
    z_index: int = Field(default=0, ge=0, le=10)


class BroadcastLayoutConfig(BaseModel):
    """Full layout configuration for a broadcast session."""
    mode: Literal["single", "side_by_side", "pip", "grid"]
    positions: list[LayoutPosition] = Field(default_factory=list)
    primary_input_id: Optional[str] = None
    input_ids: list[str] = Field(default_factory=list)
    updated_at: str = ""
