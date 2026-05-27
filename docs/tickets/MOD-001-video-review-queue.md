# MOD-001: Admin Video Review Queue

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: High  
**Estimated effort**: 5-7 days  
**Blocked by**: VOD-001 (video metadata table), MEDIA-001 (shared player)  
**Blocks**: MOD-004 (automated content scanning), MOD-005 (review SLA dashboard)

---

## 1. Overview & Motivation

### The Gap

The VOD pipeline (`app/services/video_state_machine.py`, line 15) defines a clear state transition from `encoding` to `pending_review`, and from `pending_review` to either `approved` or `rejected`. The `VideoMetadataModel` (`app/models_video.py`, lines 79-82) already carries `review_status`, `reviewed_by`, `reviewed_at`, and `review_notes` fields. The `video_metadata` DynamoDB table has a `ByStatusCreatedAt` GSI (`scripts/local-ddb-init.py`, line 655) that can efficiently query all videos in `pending_review` status.

However, **no admin endpoint exists to list pending videos, preview them, or record approve/reject decisions**. The existing `list_videos_by_status` function in `app/services/video_metadata_store.py` (lines 363-404) is a service-layer building block but is not exposed through any admin-authenticated HTTP route. Note that the existing function uses `ScanIndexForward=False` (newest first), so the review queue wrapper will need to override this to `ScanIndexForward=True` for oldest-first ordering. Videos that complete encoding sit in `pending_review` indefinitely with no way for admins to act on them.

### Why This Is Needed

1. **Content safety**: Videos uploaded by users must be reviewed before public visibility. Without a review queue, the only path to `published` requires manual DynamoDB edits or direct API calls with fabricated status transitions.

2. **Operational efficiency**: Admins need a paginated, filterable queue showing pending videos with metadata (title, duration, thumbnail, uploader) and the ability to preview content without leaving the admin dashboard.

3. **Audit compliance**: Every approve/reject decision must be recorded in the moderation audit log (`app/services/moderation_audit_log.py`) with the admin's identity, timestamp, and reason -- the same audit pattern used by the content moderation system.

4. **Batch operations**: When a backlog accumulates, admins need batch approve/reject to process multiple safe videos quickly without clicking through each one individually.

### Architecture After This Change

```
Admin Browser                      Backend                           DynamoDB
     |                                |                                 |
     |-- GET /admin/videos/           |                                 |
     |   review-queue?limit=20 ------>|                                 |
     |                                |-- Query ByStatusCreatedAt ----->|
     |                                |   PK="pending_review"           |
     |                                |<-- Items[] --------------------|
     |<-- { items[], next_cursor } ---|                                 |
     |                                |                                 |
     |-- POST /admin/videos/          |                                 |
     |   {video_id}/approve --------->|                                 |
     |                                |-- get_video(video_id) --------->|
     |                                |<-- VideoMetadataModel ---------|
     |                                |-- validate_transition() ------->|
     |                                |   pending_review -> approved    |
     |                                |-- put_item(updated) ----------->|
     |                                |-- transition approved->published|
     |                                |-- put_item(updated) ----------->|
     |                                |-- write_moderation_audit ------>|
     |                                |-- write_alert (creator) ------->|
     |<-- { video, decision } --------|                                 |
     |                                |                                 |
     |-- POST /admin/videos/          |                                 |
     |   {video_id}/reject ---------->|                                 |
     |                                |-- get_video(video_id) --------->|
     |                                |-- validate_transition() ------->|
     |                                |   pending_review -> rejected    |
     |                                |-- put_item(updated) ----------->|
     |                                |-- write_moderation_audit ------>|
     |                                |-- write_alert (creator) ------->|
     |<-- { video, decision } --------|                                 |
     |                                |                                 |
     |-- POST /admin/videos/          |                                 |
     |   batch-review --------------->|                                 |
     |   { decisions: [{id,action}] } |-- for each decision:           |
     |                                |   validate + transition + audit |
     |<-- { results: [{id,ok}] } -----|                                 |
```

---

## 2. Current State Analysis

### 2.1 Video State Machine (`app/services/video_state_machine.py`)

The state machine (40 lines) defines all legal transitions. The relevant ones for this ticket:

- `"encoding"` -> `{"pending_review", "encoding_failed", "deleted"}` (line 15)
- `"pending_review"` -> `{"approved", "rejected", "deleted"}` (line 17)
- `"approved"` -> `{"published", "archived", "deleted"}` (line 18)
- `"rejected"` -> `{"pending_review", "deleted"}` (line 19)

The `validate_transition()` function (lines 32-39) returns a `TransitionValidationResult` with `legal: bool` and optional `error_code`. This is already used by `transition_video_status()` in `video_metadata_store.py` (line 267).

### 2.2 Video Metadata Model (`app/models_video.py`)

`VideoMetadataModel` (lines 36-103) has review-specific fields that are currently write-only:

- `review_status: Optional[VideoReviewStatus]` (line 79) -- `Literal["pending_review", "approved", "rejected"]`
- `reviewed_by: Optional[str]` (line 80) -- admin user ID
- `reviewed_at: Optional[int]` (line 81) -- Unix timestamp
- `review_notes: Optional[str]` (line 82) -- reason text

These fields are serialized/deserialized by `video_to_item()` (line 51, optional string fields list; line 74, optional numeric fields list for `reviewed_at`) and `video_from_item()` (lines 165-168), but no endpoint populates them.

### 2.3 Existing List-by-Status Function (`app/services/video_metadata_store.py`, lines 363-404)

`list_videos_by_status(status, *, limit, cursor)` already queries the `ByStatusCreatedAt` GSI with the given status as partition key. It pages through up to 10 DynamoDB pages, collects results, and filters to items whose `video_id` begins with `v_` (excluding any non-video items stored in the same table). Note: the existing function uses `ScanIndexForward=False` (newest first) and a default `limit=50`, so the review queue wrapper will override to `ScanIndexForward=True` (oldest first) and `limit=25`. The function is production-ready as a building block for the new admin endpoint.

### 2.4 DynamoDB Table Schema (`scripts/local-ddb-init.py`, lines 646-665)

The `VideoMetadata` table (resolved via `S.video_metadata_table_name`):
- **PK**: `video_id` (String)
- **GSI `ByOwnerCreatedAt`**: PK=`owner_user_id`, SK=`created_at` (Number)
- **GSI `ByStatusCreatedAt`**: PK=`status`, SK=`created_at` (Number)
- **GSI `BySourceBroadcast`**: PK=`source_broadcast_session_id`

The `ByStatusCreatedAt` GSI supports querying `status="pending_review"` ordered by `created_at`, which is exactly what the review queue needs. Oldest-first (ScanIndexForward=True) is the default for review queues so the longest-waiting videos surface first.

### 2.5 Admin Auth Pattern (`app/auth/policy.py`, line 84)

`require_admin_scope(scope)` (lines 84-131) returns a FastAPI dependency that verifies the user is an admin with the specified scope. ROOT users bypass scope checks entirely (line 94: `if role is Role.ROOT: return user`). The content moderation admin dependency is used in `app/routers/admin_moderation.py` (line 36):

```python
require_content_moderation_admin = require_admin_scope(AdminScope.CONTENT_MODERATION)
```

Video review should use the same scope since reviewing uploaded videos is a content moderation responsibility.

### 2.6 Moderation Audit Log (`app/services/moderation_audit_log.py`)

`write_moderation_audit_event()` (lines 10-38) writes to `T.moderation_audit_log` with fields: `audit_id`, `entity_type`, `action`, `actor_user_id`, `ticket_id`, `report_id`, `content_type`, `content_id`, `target_user_id`, `created_at`, `metadata`. Note: `created_at` is stored as a **string** (`str(int(time.time()))`) even though the `ByActionCreatedAt` GSI sort key treats it as String type (no `attr_types={"created_at": "N"}` in the table definition). The `action` field is indexed by the `ByActionCreatedAt` GSI (lines 417-421 of `local-ddb-init.py`) for audit queries. This is the standard audit trail mechanism for all moderation actions.

### 2.7 Alert Notifications (`app/services/alerts.py`, line 261)

`write_alert(user_sub, *, event, outcome, title, details)` (defined at line 261 of `alerts.py`, file is 680 lines total) writes a notification to the user's alert feed. Used by the moderation policy engine (`app/services/moderation_policy_engine.py`) to notify offenders of warnings, bans, and content removal. The same pattern applies here -- creators should be notified when their videos are approved or rejected.

### 2.8 Frontend Admin Pages (`frontend/src/pages/admin/`)

The admin section currently has:
- `ModerationBoardPage.tsx` -- content moderation ticket queue (imports from `@/api/endpoints/moderation`)
- `PaymentIncidentQueuePage.tsx` -- payment incident management
- `RootRoleManagementPage.tsx` -- role grant/revoke

The video review queue will follow the same page structure as `ModerationBoardPage.tsx`: a paginated list with filters, detail panel, and action buttons.

---

## 3. Technical Design

### 3.1 New Router: `app/routers/admin_video_review.py`

A dedicated router keeps video review logic separate from the existing moderation board. Prefix: `/v1/admin/videos`.

Auth: `require_admin_scope(AdminScope.CONTENT_MODERATION)` -- same scope as moderation board access.

### 3.2 Endpoint Specifications

#### `GET /v1/admin/videos/review-queue`

Returns a paginated list of videos in `pending_review` status, ordered oldest-first (longest-waiting surfaces first).

**Query Parameters**:
- `limit` (int, default=25, min=1, max=100): Page size
- `cursor` (string, optional): Base64-encoded DynamoDB `LastEvaluatedKey`
- `owner_user_id` (string, optional): Filter to a specific uploader

**Response**: `VideoReviewQueueOut`

#### `GET /v1/admin/videos/{video_id}/review-detail`

Returns full video metadata plus owner profile summary for review context.

**Response**: `VideoReviewDetailOut`

#### `POST /v1/admin/videos/{video_id}/approve`

Transitions video from `pending_review` -> `approved` -> `published`. Sets `review_status`, `reviewed_by`, `reviewed_at`, `review_notes`. Writes audit log entry. Notifies creator.

**Request**: `VideoApproveIn`  
**Response**: `VideoReviewDecisionOut`

#### `POST /v1/admin/videos/{video_id}/reject`

Transitions video from `pending_review` -> `rejected`. Sets `review_status`, `reviewed_by`, `reviewed_at`, `review_notes`. Writes audit log entry. Notifies creator with rejection reason.

**Request**: `VideoRejectIn`  
**Response**: `VideoReviewDecisionOut`

#### `POST /v1/admin/videos/batch-review`

Batch approve/reject up to 25 videos in a single request. Each decision is processed independently -- partial failures are reported per-item.

**Request**: `VideoBatchReviewIn`  
**Response**: `VideoBatchReviewOut`

### 3.3 Request/Response Models

```python
from __future__ import annotations

import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from app.models_video import VideoOut, VideoStatus


class VideoReviewQueueItemOut(BaseModel):
    """Single item in the review queue list. Contains enough metadata for
    the admin to triage without opening the detail view."""

    video_id: str = Field(description="Unique video identifier (v_{hex})")
    owner_user_id: str = Field(description="User ID of the uploader")
    title: str = Field(description="Video title set by uploader")
    description: Optional[str] = Field(
        default=None, description="Optional description text"
    )
    status: VideoStatus = Field(description="Current video status (always pending_review in queue)")
    created_at: int = Field(description="Unix timestamp when video was created")
    updated_at: int = Field(description="Unix timestamp of last update")
    duration_seconds: Optional[float] = Field(
        default=None, description="Video duration in seconds (from probe)"
    )
    width: Optional[int] = Field(default=None, description="Video width in pixels")
    height: Optional[int] = Field(default=None, description="Video height in pixels")
    thumbnail_url: Optional[str] = Field(
        default=None, description="URL to thumbnail image (S3 pre-signed or mock)"
    )
    hls_manifest_url: Optional[str] = Field(
        default=None, description="URL to HLS manifest for preview playback"
    )
    file_size_bytes: Optional[int] = Field(
        default=None, description="Original file size in bytes"
    )
    source_type: str = Field(description="upload | broadcast_archive | api")
    visibility: str = Field(description="private | unlisted | public")
    owner_display_name: Optional[str] = Field(
        default=None, description="Uploader display name from profile table"
    )
    owner_profile_photo_url: Optional[str] = Field(
        default=None, description="Uploader avatar URL from profile table"
    )

    @field_validator("video_id")
    @classmethod
    def _validate_video_id(cls, v: str) -> str:
        if not v.startswith("v_"):
            raise ValueError("video_id must start with v_")
        return v


class VideoReviewQueueOut(BaseModel):
    """Paginated response for the review queue listing."""

    items: list[VideoReviewQueueItemOut] = Field(
        description="List of pending videos, ordered oldest-first"
    )
    total_pending: int = Field(
        description="Total count of videos in pending_review status"
    )
    next_cursor: Optional[str] = Field(
        default=None,
        description="Base64-encoded DynamoDB LastEvaluatedKey for next page",
    )


class VideoReviewDetailOut(BaseModel):
    """Full detail view for a single video under review. Includes owner
    profile and prior review history for context."""

    video: VideoReviewQueueItemOut
    owner_profile: dict[str, Any] = Field(
        default_factory=dict,
        description="Owner profile data (display_name, bio, profile_photo_url, created_at)",
    )
    prior_review_history: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Previous review audit events for this owner",
    )
    prior_rejections_count: int = Field(
        default=0, description="Count of prior video rejections for this owner"
    )
    prior_approvals_count: int = Field(
        default=0, description="Count of prior video approvals for this owner"
    )


class VideoApproveIn(BaseModel):
    """Request body for approving a video."""

    review_notes: str = Field(
        default="",
        max_length=2000,
        description="Optional admin notes for the approval",
    )
    auto_publish: bool = Field(
        default=True,
        description="If True, immediately transition approved -> published",
    )

    @field_validator("review_notes")
    @classmethod
    def _sanitize_notes(cls, v: str) -> str:
        # Strip HTML tags to prevent stored XSS in admin dashboard
        return re.sub(r"<[^>]+>", "", v)


class VideoRejectIn(BaseModel):
    """Request body for rejecting a video."""

    rejection_reason: str = Field(
        min_length=5,
        max_length=2000,
        description="Required explanation shown to the creator",
    )
    notify_creator: bool = Field(
        default=True,
        description="Whether to send an alert notification to the video creator",
    )

    @field_validator("rejection_reason")
    @classmethod
    def _sanitize_reason(cls, v: str) -> str:
        return re.sub(r"<[^>]+>", "", v)


class VideoReviewDecisionOut(BaseModel):
    """Response after a single approve/reject decision."""

    ok: bool
    video_id: str
    decision: Literal["approved", "rejected"]
    new_status: VideoStatus
    reviewed_by: str
    reviewed_at: int
    audit_id: str
    auto_publish_failed: bool = Field(
        default=False,
        description="True when auto_publish was requested but the second transition failed",
    )


class VideoBatchReviewDecisionIn(BaseModel):
    """Single decision within a batch review request."""

    video_id: str = Field(min_length=1, description="Target video ID")
    action: Literal["approve", "reject"] = Field(description="Action to take")
    reason: str = Field(
        default="",
        max_length=2000,
        description="Reason text (required for reject, optional for approve)",
    )

    @field_validator("reason")
    @classmethod
    def _sanitize_reason(cls, v: str) -> str:
        return re.sub(r"<[^>]+>", "", v)


class VideoBatchReviewIn(BaseModel):
    """Request body for batch review operations. Maximum 25 decisions per request."""

    decisions: list[VideoBatchReviewDecisionIn] = Field(
        min_length=1,
        max_length=25,
        description="List of individual review decisions",
    )


class VideoBatchReviewResultOut(BaseModel):
    """Result for a single decision within a batch."""

    video_id: str
    ok: bool
    decision: Optional[str] = None
    new_status: Optional[str] = None
    error: Optional[str] = None
    audit_id: Optional[str] = None


class VideoBatchReviewOut(BaseModel):
    """Aggregate result of a batch review operation."""

    results: list[VideoBatchReviewResultOut]
    total: int = Field(description="Total decisions submitted")
    succeeded: int = Field(description="Count of successful decisions")
    failed: int = Field(description="Count of failed decisions")
```

### 3.4 Service Layer Functions

New file: `app/services/video_review.py`

```python
from __future__ import annotations

import logging
from typing import Any, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert
from app.services.moderation_audit_log import write_moderation_audit_event
from app.services.video_metadata_store import (
    get_video,
    transition_video_status,
    video_from_item,
    video_to_item,
)
from app.services.video_state_machine import validate_transition

logger = logging.getLogger(__name__)


def list_pending_review_videos(
    *,
    limit: int = 25,
    cursor: dict | None = None,
    owner_filter: str | None = None,
) -> dict[str, Any]:
    """Query ByStatusCreatedAt GSI with PK='pending_review', oldest first.

    Args:
        limit: Maximum number of items to return (1-100).
        cursor: DynamoDB LastEvaluatedKey from previous page.
        owner_filter: Optional owner_user_id to restrict results.

    Returns:
        Dict with 'items' (list of VideoMetadataModel), 'cursor' (next page key or None),
        and 'total_pending' (count of all pending videos).
    """
    collected: list = []
    current_cursor = cursor
    max_pages = 10

    for _ in range(max_pages):
        kwargs: dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status").eq("pending_review"),
            "Limit": limit * 3,
            "ScanIndexForward": True,  # oldest first
        }
        if current_cursor:
            kwargs["ExclusiveStartKey"] = current_cursor

        filter_conditions = Attr("video_id").begins_with("v_")
        if owner_filter:
            filter_conditions = filter_conditions & Attr("owner_user_id").eq(owner_filter)
        kwargs["FilterExpression"] = filter_conditions

        resp = T.video_metadata.query(**kwargs)
        for item in resp.get("Items", []):
            collected.append(video_from_item(item))
            if len(collected) >= limit:
                break

        current_cursor = resp.get("LastEvaluatedKey")
        if len(collected) >= limit or not current_cursor:
            break

    total = count_pending_review()
    return {
        "items": collected[:limit],
        "cursor": current_cursor,
        "total_pending": total,
    }


def approve_video(
    *,
    video_id: str,
    admin_user_id: str,
    review_notes: str = "",
    auto_publish: bool = True,
) -> tuple[Any, str]:
    """Approve a video currently in pending_review status.

    Steps:
        1. get_video() -> verify status == pending_review
        2. transition pending_review -> approved (sets review fields)
        3. If auto_publish: transition approved -> published
        4. write_moderation_audit_event(action="video_approved")
        5. write_alert to creator

    Returns:
        Tuple of (updated VideoMetadataModel, audit_id string).

    Raises:
        HTTPException 404: Video not found.
        HTTPException 409: Video not in pending_review status.
    """
    video = get_video(video_id)
    if video is None:
        raise HTTPException(status_code=404, detail="video not found")
    if video.status != "pending_review":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "VIDEO_INVALID_STATE_TRANSITION",
                "from_status": video.status,
                "to_status": "approved",
            },
        )

    ts = now_ts()
    video.status = "approved"
    video.review_status = "approved"
    video.reviewed_by = admin_user_id
    video.reviewed_at = ts
    video.review_notes = review_notes
    video.updated_at = ts

    item = video_to_item(video)
    T.video_metadata.put_item(Item=item)

    auto_publish_failed = False
    if auto_publish:
        result = validate_transition("approved", "published")
        if result.legal:
            video.status = "published"
            video.published_at = ts
            video.updated_at = ts
            T.video_metadata.put_item(Item=video_to_item(video))
        else:
            auto_publish_failed = True
            logger.warning(
                "Auto-publish failed for video %s: approved->published not legal",
                video_id,
            )

    audit_id = write_moderation_audit_event(
        action="video_approved",
        actor_user_id=admin_user_id,
        content_type="video",
        content_id=video_id,
        target_user_id=video.owner_user_id,
        metadata={
            "review_notes": review_notes,
            "auto_publish": auto_publish,
            "auto_publish_failed": auto_publish_failed,
            "new_status": video.status,
        },
    )

    write_alert(
        video.owner_user_id,
        event="video_review_approved",
        outcome="success",
        title="Video approved",
        details={"video_id": video_id, "title": video.title},
    )

    return video, audit_id


def reject_video(
    *,
    video_id: str,
    admin_user_id: str,
    rejection_reason: str,
    notify_creator: bool = True,
) -> tuple[Any, str]:
    """Reject a video currently in pending_review status.

    Steps:
        1. get_video() -> verify status == pending_review
        2. transition pending_review -> rejected (sets review fields)
        3. write_moderation_audit_event(action="video_rejected")
        4. If notify_creator: write_alert to creator with rejection_reason

    Returns:
        Tuple of (updated VideoMetadataModel, audit_id string).

    Raises:
        HTTPException 404: Video not found.
        HTTPException 409: Video not in pending_review status.
    """
    video = get_video(video_id)
    if video is None:
        raise HTTPException(status_code=404, detail="video not found")
    if video.status != "pending_review":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "VIDEO_INVALID_STATE_TRANSITION",
                "from_status": video.status,
                "to_status": "rejected",
            },
        )

    ts = now_ts()
    video.status = "rejected"
    video.review_status = "rejected"
    video.reviewed_by = admin_user_id
    video.reviewed_at = ts
    video.review_notes = rejection_reason
    video.updated_at = ts

    T.video_metadata.put_item(Item=video_to_item(video))

    audit_id = write_moderation_audit_event(
        action="video_rejected",
        actor_user_id=admin_user_id,
        content_type="video",
        content_id=video_id,
        target_user_id=video.owner_user_id,
        metadata={
            "rejection_reason": rejection_reason,
            "notify_creator": notify_creator,
        },
    )

    if notify_creator:
        write_alert(
            video.owner_user_id,
            event="video_review_rejected",
            outcome="warning",
            title="Video not approved",
            details={
                "video_id": video_id,
                "title": video.title,
                "rejection_reason": rejection_reason,
            },
        )

    return video, audit_id


def count_pending_review() -> int:
    """Count videos in pending_review status (for queue badge).

    Uses Select='COUNT' to avoid transferring full items, which is efficient
    for DynamoDB GSI queries. Paginates through up to 10 pages for accuracy.
    """
    total = 0
    last_key: Optional[dict] = None
    for _ in range(10):
        kwargs: dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status").eq("pending_review"),
            "Select": "COUNT",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.video_metadata.query(**kwargs)
        total += resp.get("Count", 0)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return total


def get_owner_review_history(owner_user_id: str) -> dict[str, Any]:
    """Query ModerationAuditLog for video_approved/video_rejected actions by owner.

    Returns dict with 'events' list, 'approvals_count', and 'rejections_count'.
    """
    events: list[dict] = []
    approvals = 0
    rejections = 0

    for action_type in ("video_approved", "video_rejected"):
        resp = T.moderation_audit_log.query(
            IndexName="ByActionCreatedAt",
            KeyConditionExpression=Key("action").eq(action_type),
            FilterExpression=Attr("target_user_id").eq(owner_user_id),
            Limit=50,
            ScanIndexForward=False,
        )
        for item in resp.get("Items", []):
            events.append(item)
            if action_type == "video_approved":
                approvals += 1
            else:
                rejections += 1

    events.sort(key=lambda e: int(str(e.get("created_at", "0"))), reverse=True)
    return {
        "events": events[:20],
        "approvals_count": approvals,
        "rejections_count": rejections,
    }
```

### 3.5 DDB Schema Changes

No new tables are required. The existing `VideoMetadata` table's `ByStatusCreatedAt` GSI is sufficient. Review metadata (`review_status`, `reviewed_by`, `reviewed_at`, `review_notes`) is already part of the `VideoMetadataModel` schema and is serialized/deserialized by `video_to_item()`/`video_from_item()`.

The moderation audit log entries will use the existing `ModerationAuditLog` table with new action values:
- `action="video_approved"` -- logged on approval
- `action="video_rejected"` -- logged on rejection
- `action="video_batch_reviewed"` -- logged on batch operations

Audit entries use `content_type="video"`, `content_id=video_id`, `target_user_id=owner_user_id`.

### 3.6 Error Handling

| Condition | HTTP Status | Detail |
|-----------|-------------|--------|
| Video not found | 404 | `"video not found"` |
| Video not in `pending_review` | 409 | `{"code": "VIDEO_INVALID_STATE_TRANSITION", "from_status": "...", "to_status": "approved"}` |
| Rejection reason too short | 422 | Pydantic validation error |
| Admin lacks `content_moderation` scope | 403 | `"admin scope not authorized"` |
| Batch size > 25 | 422 | Pydantic validation error |
| State machine error during auto-publish | 409 | `{"code": "VIDEO_INVALID_STATE_TRANSITION", ...}` -- approval still recorded, publish deferred |

### 3.7 Notification Design

On **approve**: Creator receives an alert via `write_alert()`:
```python
write_alert(
    owner_user_id,
    event="video_review_approved",
    outcome="success",
    title="Video approved",
    details={"video_id": video_id, "title": video_title},
)
```

On **reject**: Creator receives an alert with the rejection reason:
```python
write_alert(
    owner_user_id,
    event="video_review_rejected",
    outcome="warning",
    title="Video not approved",
    details={
        "video_id": video_id,
        "title": video_title,
        "rejection_reason": rejection_reason,
    },
)
```

### 3.8 Auto-Publish Behavior

When `auto_publish=True` (default) on approve, the endpoint performs two transitions atomically:
1. `pending_review` -> `approved` (sets `review_status="approved"`, `reviewed_by`, `reviewed_at`)
2. `approved` -> `published` (sets `published_at`, `visibility` unchanged -- admin may have set it to `public`/`unlisted`/`private` before review)

If the second transition fails (e.g., `approved` -> `published` not allowed due to concurrent state change), the video remains in `approved` status and the response indicates `new_status="approved"`. The admin can manually publish later.

---

## 4. Implementation Plan

### Step 1: Create Service Layer (`app/services/video_review.py`)

**New file**: `app/services/video_review.py` (~150 lines)

Functions:
- `list_pending_review_videos()` -- wraps `list_videos_by_status("pending_review")` with `ScanIndexForward=True` for oldest-first ordering, enriches with owner profile data
- `approve_video()` -- validates state, applies transitions, sets review fields, writes audit + alert
- `reject_video()` -- validates state, applies transition, sets review fields, writes audit + alert
- `count_pending_review()` -- count query on `ByStatusCreatedAt` with `Select="COUNT"`
- `get_owner_review_history()` -- queries audit log for prior video decisions

**Line-by-line change description**:
- Lines 1-10: Imports from `boto3.dynamodb.conditions`, `app.core.tables`, `app.core.time`, `app.services.alerts`, `app.services.moderation_audit_log`, `app.services.video_metadata_store`, `app.services.video_state_machine`
- Lines 12-50: `list_pending_review_videos()` implementation -- builds GSI query kwargs, iterates up to 10 DDB pages, applies optional `owner_filter` via `FilterExpression`, returns dict with items/cursor/total_pending
- Lines 52-110: `approve_video()` implementation -- get_video, status check, set review fields, put_item, optional auto-publish transition, audit write, alert write
- Lines 112-155: `reject_video()` implementation -- get_video, status check, set review fields, put_item, audit write, conditional alert write
- Lines 157-175: `count_pending_review()` implementation -- paginated COUNT query
- Lines 177-200: `get_owner_review_history()` implementation -- queries ByActionCreatedAt GSI for video_approved and video_rejected actions, filters by target_user_id

### Step 2: Create Router (`app/routers/admin_video_review.py`)

**New file**: `app/routers/admin_video_review.py` (~250 lines)

Contains all Pydantic models and 5 endpoint handlers. Auth dependency: `require_admin_scope(AdminScope.CONTENT_MODERATION)`.

**Line-by-line change description**:
- Lines 1-20: Imports: FastAPI (`APIRouter`, `Depends`, `HTTPException`, `Query`), Pydantic models, auth dependency, service functions
- Lines 22-30: Router creation: `router = APIRouter(prefix="/v1/admin/videos", tags=["admin-video-review"])`, `require_review_admin = require_admin_scope(AdminScope.CONTENT_MODERATION)`
- Lines 32-100: Pydantic model definitions (as specified in section 3.3)
- Lines 102-130: `GET /review-queue` handler -- parses query params, calls `list_pending_review_videos()`, enriches items with owner profile data via `BatchGetItem` on `T.profile`, returns `VideoReviewQueueOut`
- Lines 132-165: `GET /{video_id}/review-detail` handler -- calls `get_video()`, `get_owner_review_history()`, fetches owner profile, assembles `VideoReviewDetailOut`
- Lines 167-195: `POST /{video_id}/approve` handler -- parses `VideoApproveIn`, calls `approve_video()`, returns `VideoReviewDecisionOut`
- Lines 197-220: `POST /{video_id}/reject` handler -- parses `VideoRejectIn`, calls `reject_video()`, returns `VideoReviewDecisionOut`
- Lines 222-270: `POST /batch-review` handler -- iterates `VideoBatchReviewIn.decisions`, calls approve/reject for each, collects results, returns `VideoBatchReviewOut`

### Step 3: Register Router in `app/main.py`

**File**: `app/main.py`

Add import (after line 85, alongside the existing `admin_moderation_router` import):
```python
from app.routers.admin_video_review import router as admin_video_review_router
```

Add registration (after line 279, alongside the existing `admin_moderation_router` registration):
```python
app.include_router(admin_video_review_router)
```

### Step 4: Add Frontend API Endpoints

**New file**: `frontend/src/api/endpoints/adminVideoReview.ts` (~80 lines)

```typescript
import client from "../client";

export interface VideoReviewQueueItem {
  video_id: string;
  owner_user_id: string;
  title: string;
  description?: string;
  status: string;
  created_at: number;
  thumbnail_url?: string;
  hls_manifest_url?: string;
  duration_seconds?: number;
  width?: number;
  height?: number;
  file_size_bytes?: number;
  source_type: string;
  owner_display_name?: string;
  owner_profile_photo_url?: string;
}

export interface VideoReviewQueue {
  items: VideoReviewQueueItem[];
  total_pending: number;
  next_cursor?: string;
}

export interface VideoReviewDecision {
  ok: boolean;
  video_id: string;
  decision: "approved" | "rejected";
  new_status: string;
  reviewed_by: string;
  reviewed_at: number;
  audit_id: string;
  auto_publish_failed?: boolean;
}

export interface BatchReviewResult {
  results: Array<{
    video_id: string;
    ok: boolean;
    decision?: string;
    new_status?: string;
    error?: string;
    audit_id?: string;
  }>;
  total: number;
  succeeded: number;
  failed: number;
}

export interface VideoReviewDetail {
  video: VideoReviewQueueItem;
  owner_profile: Record<string, unknown>;
  prior_review_history: Array<Record<string, unknown>>;
  prior_rejections_count: number;
  prior_approvals_count: number;
}

export async function fetchVideoReviewQueue(params?: {
  limit?: number;
  cursor?: string;
  owner_user_id?: string;
}): Promise<VideoReviewQueue> {
  const { data } = await client.get("/v1/admin/videos/review-queue", { params });
  return data;
}

export async function fetchVideoReviewDetail(
  videoId: string
): Promise<VideoReviewDetail> {
  const { data } = await client.get(`/v1/admin/videos/${videoId}/review-detail`);
  return data;
}

export async function approveVideo(
  videoId: string,
  data: { review_notes?: string; auto_publish?: boolean }
): Promise<VideoReviewDecision> {
  const resp = await client.post(`/v1/admin/videos/${videoId}/approve`, data);
  return resp.data;
}

export async function rejectVideo(
  videoId: string,
  data: { rejection_reason: string; notify_creator?: boolean }
): Promise<VideoReviewDecision> {
  const resp = await client.post(`/v1/admin/videos/${videoId}/reject`, data);
  return resp.data;
}

export async function batchReviewVideos(
  decisions: Array<{ video_id: string; action: "approve" | "reject"; reason?: string }>
): Promise<BatchReviewResult> {
  const resp = await client.post("/v1/admin/videos/batch-review", { decisions });
  return resp.data;
}
```

### Step 5: Add Frontend Page

**New file**: `frontend/src/pages/admin/VideoReviewQueuePage.tsx` (~350 lines)

Components:
- `VideoReviewQueuePage` -- main page with queue list and detail panel
- `VideoReviewCard` -- card for each pending video showing thumbnail, title, uploader, duration
- `VideoPreviewPanel` -- HLS player (reuses `SharedVideoPlayer` from MEDIA-001) with metadata display
- `RejectionReasonDialog` -- shadcn Dialog with textarea for rejection reason
- `BatchReviewToolbar` -- checkbox selection + bulk approve/reject buttons

### Step 6: Add Route to App.tsx

**File**: `frontend/src/App.tsx`

Add lazy import:
```typescript
const VideoReviewQueuePage = lazy(() => import("@/pages/admin/VideoReviewQueuePage"));
```

Add route under the admin section:
```typescript
<Route path="/admin/video-review" element={<VideoReviewQueuePage />} />
```

### Step 7: Add Sidebar Navigation

**File**: `frontend/src/components/layout/Sidebar.tsx`

Add "Video Review" link under the Admin group with a `Video` icon. Show a badge with `total_pending` count (fetched via React Query).

### Summary of Files Modified/Created

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/services/video_review.py` | **New** | ~150 |
| `app/routers/admin_video_review.py` | **New** | ~250 |
| `app/main.py` | Modified (2 lines) | ~2 |
| `frontend/src/api/endpoints/adminVideoReview.ts` | **New** | ~80 |
| `frontend/src/pages/admin/VideoReviewQueuePage.tsx` | **New** | ~350 |
| `frontend/src/App.tsx` | Modified (2 lines) | ~2 |
| `frontend/src/components/layout/Sidebar.tsx` | Modified (~5 lines) | ~5 |
| `frontend/e2e/video-review-queue.spec.ts` | **New** | ~400 |
| **Total** | | **~1240** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_video_review.py`)

**New file**, ~250 lines. Tests the service layer using moto-mocked DynamoDB.

**Fixtures**:

```python
import pytest
from moto import mock_dynamodb
from app.core.tables import T
from app.services.video_review import (
    approve_video,
    count_pending_review,
    get_owner_review_history,
    list_pending_review_videos,
    reject_video,
)
from app.services.video_metadata_store import create_video, video_to_item


@pytest.fixture
def ddb_tables(moto_ddb):
    """Create video_metadata and ModerationAuditLog tables in moto.
    
    moto_ddb is a session-scoped fixture from conftest that sets up
    DDB_ENDPOINT_URL and creates the base resource.
    """
    # Create video_metadata table with GSIs
    T.video_metadata.meta.client.create_table(
        TableName=T.video_metadata.name,
        KeySchema=[{"AttributeName": "video_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "video_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "owner_user_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByStatusCreatedAt",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByOwnerCreatedAt",
                "KeySchema": [
                    {"AttributeName": "owner_user_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    yield


def _seed_pending_video(owner: str, title: str, created_at: int) -> str:
    """Helper to create a video in pending_review status."""
    from uuid import uuid4
    video_id = f"v_{uuid4().hex}"
    T.video_metadata.put_item(Item={
        "video_id": video_id,
        "owner_user_id": owner,
        "title": title,
        "status": "pending_review",
        "created_at": created_at,
        "updated_at": created_at,
        "source_type": "upload",
        "visibility": "public",
        "drm_enabled": False,
    })
    return video_id
```

**Test cases**:

1. **`test_list_pending_review_empty`** -- No pending videos returns empty list with `total_pending=0`.
   ```python
   def test_list_pending_review_empty(ddb_tables):
       """Verify empty queue returns zero items and zero total."""
       result = list_pending_review_videos(limit=25)
       assert result["items"] == []
       assert result["total_pending"] == 0
       assert result["cursor"] is None
   ```

2. **`test_list_pending_review_returns_oldest_first`** -- Create 5 videos in `pending_review` with different `created_at`, verify list order is oldest-first.
   ```python
   def test_list_pending_review_returns_oldest_first(ddb_tables):
       """Verify ScanIndexForward=True produces oldest-first ordering."""
       ids = [_seed_pending_video("user1", f"vid{i}", 1000 + i) for i in range(5)]
       result = list_pending_review_videos(limit=25)
       assert len(result["items"]) == 5
       assert [v.created_at for v in result["items"]] == [1000, 1001, 1002, 1003, 1004]
   ```

3. **`test_list_pending_review_excludes_other_statuses`** -- Create videos in `created`, `encoding`, `published`, and `pending_review` statuses. Only `pending_review` videos appear in the queue.

4. **`test_list_pending_review_pagination`** -- Create 30 pending videos, request with limit=10. Verify 10 items returned, `next_cursor` is present. Request again with cursor, verify next 10 items.

5. **`test_list_pending_review_owner_filter`** -- Create pending videos from two owners. Filter by `owner_user_id` returns only that owner's videos.

6. **`test_approve_video_success`** -- Create video in `pending_review`, approve it. Verify status transitions to `published` (auto_publish=True), `review_status="approved"`, `reviewed_by` set, `reviewed_at` set, `published_at` set.
   ```python
   def test_approve_video_success(ddb_tables):
       """Verify approve transitions to published with auto_publish=True."""
       vid = _seed_pending_video("creator1", "Test Video", 1000)
       video, audit_id = approve_video(
           video_id=vid,
           admin_user_id="admin1",
           review_notes="Looks good",
           auto_publish=True,
       )
       assert video.status == "published"
       assert video.review_status == "approved"
       assert video.reviewed_by == "admin1"
       assert video.reviewed_at > 0
       assert video.published_at > 0
       assert audit_id.startswith("modaudit_")
   ```

7. **`test_approve_video_no_auto_publish`** -- Approve with `auto_publish=False`. Verify status is `approved` (not `published`), `published_at` is None.

8. **`test_approve_video_wrong_status_409`** -- Try to approve a video in `encoding` status. Expect 409.

9. **`test_approve_video_sets_review_notes`** -- Approve with `review_notes="Looks good"`. Verify notes are persisted on the video record.

10. **`test_approve_video_writes_audit_log`** -- Approve a video, query the moderation audit log. Verify `action="video_approved"`, `actor_user_id` matches admin, `content_id` matches video ID.

11. **`test_approve_video_notifies_creator`** -- Approve a video, query the alerts table for the owner. Verify alert with `event="video_review_approved"`.

12. **`test_reject_video_success`** -- Create video in `pending_review`, reject it. Verify status is `rejected`, `review_status="rejected"`, `review_notes` contains rejection reason.

13. **`test_reject_video_requires_reason`** -- Try to reject with empty `rejection_reason`. Expect 422 validation error.

14. **`test_reject_video_wrong_status_409`** -- Try to reject a video in `published` status. Expect 409.

15. **`test_reject_video_writes_audit_log`** -- Reject a video, query audit log. Verify `action="video_rejected"`.

16. **`test_reject_video_notifies_creator`** -- Reject a video, query alerts for owner. Verify alert with `event="video_review_rejected"` containing `rejection_reason`.

17. **`test_reject_video_no_notification`** -- Reject with `notify_creator=False`. Verify no alert written.

18. **`test_batch_approve_multiple`** -- Create 5 pending videos, batch approve all. Verify all transition to `published`.

19. **`test_batch_mixed_approve_reject`** -- Create 4 pending videos, batch: 2 approve + 2 reject. Verify correct statuses on each.

20. **`test_batch_partial_failure`** -- Create 3 pending videos, manually transition one to `deleted` before batch. Batch should report 2 successes and 1 failure.

21. **`test_batch_max_size_exceeded`** -- Send batch with 26 decisions. Expect 422 validation error.

22. **`test_count_pending_review`** -- Create 7 pending videos. Call `count_pending_review()`, verify returns 7.

### 5.2 E2E Tests (`frontend/e2e/video-review-queue.spec.ts`)

**New file**, ~400 lines. Tests the full admin video review workflow.

**Setup (`beforeAll`)**:
- Seed admin session via `e2e_admin_session_setup.py` (uses root identity for content_moderation scope)
- Create 3 test videos via the VOD upload API, transition them to `pending_review` status using `POST /v1/videos/{id}/transition` (or direct DDB writes)

**Section 90: Review Queue API (8 tests)**:

1. `GET /review-queue returns pending videos oldest first` -- verify order matches creation time ascending
2. `GET /review-queue respects limit parameter` -- set limit=1, verify 1 item + next_cursor
3. `GET /review-queue pagination with cursor` -- fetch page 1, use cursor for page 2, verify non-overlapping sets
4. `GET /review-queue owner_user_id filter` -- create videos from two users, filter by one, verify only their videos appear
5. `POST /approve transitions to published` -- approve one video, verify 200 + new_status="published"
6. `POST /reject with reason` -- reject one video with reason, verify 200 + new_status="rejected" + reason persisted
7. `POST /reject without reason returns 422` -- send empty rejection_reason, verify 422
8. `POST /approve on already-approved returns 409` -- approve the same video twice, verify 409 on second attempt

**Section 91: Batch Review API (5 tests)**:

1. `Batch approve 3 videos` -- all succeed, verify all new_status="published"
2. `Batch mixed approve+reject` -- 2 approve + 1 reject, verify correct statuses
3. `Batch with invalid video_id` -- include non-existent ID, verify partial success
4. `Batch empty list returns 422` -- send empty decisions array
5. `Batch exceeding max size returns 422` -- send 26 decisions

**Section 92: Audit Log Verification (3 tests)**:

1. `Approve writes audit event` -- approve video, query `/v1/admin/moderation/users/{admin_id}/history` or audit log endpoint, verify entry
2. `Reject writes audit event with rejection reason` -- reject video, verify audit entry contains reason
3. `Batch review writes individual audit events` -- batch 3 decisions, verify 3 audit entries

**Section 93: Creator Notifications (3 tests)**:

1. `Creator receives approval notification` -- approve video, query alerts API as creator, verify alert
2. `Creator receives rejection notification with reason` -- reject video, query alerts, verify reason in details
3. `Rejection with notify_creator=false skips notification` -- reject with flag off, verify no alert

**Section 94: Video Review Queue UI (6 tests)**:

1. `Page renders pending videos list` -- navigate to `/admin/video-review`, verify video cards visible
2. `Video card shows thumbnail and metadata` -- verify title, duration, uploader name displayed
3. `Click Approve button approves video` -- click approve on first video, verify success toast + video removed from list
4. `Click Reject opens reason dialog` -- click reject, verify dialog appears with textarea
5. `Submit rejection with reason` -- fill in reason, submit, verify success toast + video removed from list
6. `Batch select and approve` -- check 2 videos, click "Approve Selected", verify both removed from list

### 5.3 Edge Cases to Cover

1. **Concurrent approval race**: Two admins approve the same video simultaneously. The first succeeds; the second gets 409 because `pending_review` -> `approved` already happened.

2. **Video deleted while in review queue**: Admin tries to approve a video that was just deleted by its owner. The state machine rejects `pending_review` -> `approved` if the video is now in `deleted` status. The endpoint should return 409 with a clear message.

3. **Auto-publish failure**: Approve succeeds (pending_review -> approved) but the auto-publish (approved -> published) fails due to concurrent state change. The response should indicate `new_status="approved"` and `auto_publish_failed=true` so the admin knows manual publishing is needed.

4. **Large queue performance**: The `ByStatusCreatedAt` GSI may contain thousands of pending videos. The query uses `Limit` and pagination to avoid loading all items. The `count_pending_review()` function uses `Select="COUNT"` to avoid transferring full items.

5. **Rejected video re-submission**: When a creator re-uploads and the video re-enters `pending_review`, the admin should see the prior rejection history via `prior_rejections_count` in the detail view.

6. **Owner profile enrichment**: `owner_display_name` and `owner_profile_photo_url` are fetched from `T.profile` for each queue item. For large queues, this adds N profile lookups. Mitigate by batching profile lookups using `BatchGetItem` (up to 100 keys per request).

7. **Batch review atomicity**: Each decision in a batch is processed independently. A failure on one video does not roll back others. The response reports per-item success/failure.

### 5.4 Performance Notes

- **Queue list**: Single GSI query per page. Expected p50 latency: ~15ms for 25 items.
- **Owner enrichment**: Up to 25 profile lookups per page. Use `BatchGetItem` to reduce to 1 round-trip (~20ms for 25 keys).
- **Approve/reject**: 1 get_video + 1-2 put_item + 1 audit write + 1 alert write = 4-5 DDB operations. Expected p50: ~50ms.
- **Batch review**: Up to 25 * 5 = 125 DDB operations. Expected p50 for 25 items: ~500ms. Consider parallelizing with `asyncio.gather()` if latency is a concern.
- **Count query**: `Select="COUNT"` on GSI. Expected p50: ~10ms.

---

## 6. Security Considerations

### 6.1 Admin Authentication and Authorization

All endpoints require `require_admin_scope(AdminScope.CONTENT_MODERATION)`, enforced by the `_require_admin_scope` inner dependency in `app/auth/policy.py` (lines 84-131). This verifies:

1. The user has `role >= ADMIN` (extracted from the `ui_access_token` JWT cookie)
2. The admin profile has the `CONTENT_MODERATION` scope (checked via `admin_profile_has_scope()` at line 100)
3. ROOT users bypass scope checks entirely (line 94: `if role is Role.ROOT: return user`)

**Privilege escalation prevention**: The scope check happens at the dependency injection level before any business logic executes. A regular USER cannot bypass this even by crafting requests directly because the `ui_access_token` JWT is signed with `UI_ACCESS_TOKEN_SECRET` (HS256) and the role/admin_profile claims are set at session creation time, not by the client.

### 6.2 CSRF Protection

All POST endpoints (approve, reject, batch-review) require CSRF validation because they are accessed via cookie-based session auth. The `require_ui_session` dependency in `app/auth/deps.py` validates that the `x-csrf-token` header matches both the session's stored `csrf_token` and the `ui_csrf` cookie value. This prevents cross-site request forgery attacks where a malicious page could trigger video approvals.

### 6.3 Input Sanitization

- **`review_notes`** and **`rejection_reason`** fields are stripped of HTML tags via `@field_validator` using `re.sub(r"<[^>]+>", "", v)` to prevent stored XSS. These strings are rendered in the admin dashboard (VideoReviewDetailOut) and in creator notification alerts.
- **`video_id`** path parameters are validated by the `@field_validator` on `VideoReviewQueueItemOut` to ensure they start with `v_`, preventing path traversal or injection through crafted IDs.
- Field length limits (`max_length=2000` on reason/notes) prevent excessively large payloads that could consume DDB write capacity.

### 6.4 Audit Trail Integrity

Every approve/reject action writes an immutable audit record to `ModerationAuditLog` via `write_moderation_audit_event()`. The audit record includes:
- `actor_user_id`: The admin who made the decision (extracted from JWT, not user-supplied)
- `created_at`: Server-side timestamp from `now_ts()` (not client-supplied)
- `metadata`: Full decision context including review_notes and video state

Audit records are append-only (no update or delete API exists). The `ByActorCreatedAt` GSI allows querying all actions by a specific admin for accountability reviews. The `ByActionCreatedAt` GSI allows filtering by action type for aggregate analysis.

### 6.5 Rate Limiting

The batch-review endpoint is limited to 25 decisions per request via Pydantic validation (`max_length=25` on the decisions list). Without this limit, a compromised admin account could approve thousands of videos in a single request. Additional rate limiting (e.g., max 100 decisions per minute per admin) should be implemented at the API gateway layer.

---

## 7. Migration & Rollback Plan

### 7.1 DDB Table Changes

No new DynamoDB tables are required. The existing `video_metadata` table and `ModerationAuditLog` table are sufficient. The review metadata fields (`review_status`, `reviewed_by`, `reviewed_at`, `review_notes`) are already part of the `VideoMetadataModel` schema and do not require table modifications.

### 7.2 Feature Flag Rollout

Add a new feature flag to `app/core/settings.py`:

```python
video_review_queue_enabled: bool = os.environ.get("VIDEO_REVIEW_QUEUE_ENABLED", "0") not in ("0", "false", "False")
```

**Phase 1: Backend only (dark launch)**
- Deploy the new router and service layer with the feature flag defaulting to `False`
- The router returns 404 for all endpoints when the flag is off
- Verify DDB queries work correctly in production by running unit tests against the production table schema

**Phase 2: Admin access**
- Enable the flag for internal testing (`VIDEO_REVIEW_QUEUE_ENABLED=1` in staging)
- QA team exercises all endpoints and verifies audit trail
- Monitor DDB read/write capacity metrics for the `ByStatusCreatedAt` GSI

**Phase 3: General availability**
- Enable the flag in production
- Add the sidebar navigation link (gated by the same flag)
- Monitor queue depth and review throughput metrics

### 7.3 Rollback Steps

1. Set `VIDEO_REVIEW_QUEUE_ENABLED=0` in environment variables
2. Restart the backend (the router will immediately return 404)
3. The sidebar link disappears (frontend checks the flag via a settings endpoint)
4. No data cleanup needed -- approved/rejected videos retain their status, audit records remain
5. Videos stuck in `pending_review` can still be managed via direct DDB access or the existing video management endpoints

### 7.4 Zero-Downtime Deployment

The deployment is additive only:
- New service file: no impact on existing code paths
- New router: only handles new URL paths, does not modify existing endpoints
- `app/main.py` change: adds one import and one `include_router()` call, no disruption to existing routes
- No DDB schema changes: no table migrations or GSI backfills needed

---

## 8. Operational Runbook

### 8.1 Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `video_review_queue_depth` | Count of videos in `pending_review` status | > 100 (warning), > 500 (critical) |
| `video_review_avg_wait_minutes` | Average age of oldest pending video | > 60 min (warning), > 240 min (critical) |
| `video_review_decisions_per_hour` | Approve + reject decisions in the last hour | < 5 when queue_depth > 50 (warning) |
| `video_review_approval_rate` | Percentage of reviews resulting in approval | < 50% (info -- may indicate upload quality issue) |
| `video_review_batch_size_avg` | Average batch size for batch-review calls | Informational |
| `video_review_p50_latency_ms` | p50 latency for approve/reject endpoints | > 200ms (warning) |

### 8.2 Queue Depth Monitoring

The `count_pending_review()` function is called on every queue list request and returns the current queue depth. This value is included in the `VideoReviewQueueOut` response as `total_pending`.

For proactive monitoring, add a background task that runs every 5 minutes:

```python
async def _emit_review_queue_metrics():
    """Emit Prometheus-style metrics for the review queue."""
    total = count_pending_review()
    metrics.gauge("video_review_queue_depth", total)
    
    # Check oldest item age
    result = list_pending_review_videos(limit=1)
    if result["items"]:
        oldest_created = result["items"][0].created_at
        age_minutes = (now_ts() - oldest_created) // 60
        metrics.gauge("video_review_oldest_age_minutes", age_minutes)
```

### 8.3 Common Debugging Scenarios

**Scenario: Video stuck in pending_review**
1. Check `video_metadata` table for the video: `T.video_metadata.get_item(Key={"video_id": "v_xxx"})`
2. Verify `status` is `pending_review` (not `encoding` or `deleted`)
3. Check if the video appears in the GSI: query `ByStatusCreatedAt` with PK=`pending_review`
4. If missing from GSI: check `created_at` is a Number (not String) -- string values break the GSI sort key

**Scenario: Approve returns 409 unexpectedly**
1. The video's status changed between page load and the approve action (race condition)
2. Check the current status via `get_video()`
3. If status is `approved` or `published`, another admin already approved it
4. If status is `deleted`, the creator deleted the video

**Scenario: Batch review has high failure rate**
1. Check if many videos were deleted or already reviewed between page load and batch submission
2. The batch-review response includes per-item error messages -- inspect the `error` field
3. Consider reducing the time between queue list refresh and batch submission in the frontend

### 8.4 Escalation Procedures

| Situation | Action |
|-----------|--------|
| Queue depth > 500 and growing | Page on-call content moderation team. Consider enabling auto-approve for trusted uploaders. |
| Admin account compromise suspected | Immediately revoke the admin session. Query `ByActorCreatedAt` GSI for the admin's recent actions. Manually review all videos approved in the suspected timeframe. |
| DDB throttling on ByStatusCreatedAt | Increase provisioned capacity on the GSI. The GSI has hot partition `pending_review` -- consider adding a scatter key. |

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput

| Scenario | Requests/sec | DDB Operations/sec |
|----------|-------------|-------------------|
| Normal operations (1-2 admins) | 0.1 list + 0.5 approve/reject | ~5 |
| Peak review session (5 admins) | 0.5 list + 2.0 approve/reject | ~25 |
| Batch review (25 items) | 0.02 batch | ~125 (burst) |

### 9.2 DDB Capacity

The `ByStatusCreatedAt` GSI has a hot partition key (`pending_review`). In on-demand mode, DDB auto-scales to handle the load. In provisioned mode, size the GSI for:
- Read: 25 RCU (covers 25-item list queries at ~1 RCU each for eventually consistent reads)
- Write: 10 WCU (covers approve/reject which update the status field, moving items between GSI partitions)

### 9.3 Queue Depth Projections

| Daily uploads | Review rate (items/hour) | Steady-state queue depth |
|--------------|------------------------|--------------------------|
| 50 | 10 | ~25 (5 business hours of review) |
| 200 | 40 | ~25 (with batch review) |
| 1000 | 40 | ~600 (requires additional reviewers or auto-approve) |

For high-volume scenarios (>500 uploads/day), consider:
- Auto-approve for creators with >10 prior approvals and 0 rejections
- ML-based pre-screening to flag only high-risk videos for manual review
- Increasing the batch-review limit from 25 to 100

### 9.4 Admin Dashboard Pagination Performance

Each page load performs:
1. GSI query for `pending_review` items (1 DDB read, ~15ms)
2. `BatchGetItem` for owner profiles (1 DDB read for up to 25 keys, ~20ms)
3. COUNT query for total_pending (1 DDB read, ~10ms)

Total p50 latency: ~45ms. Well within the 200ms target for admin dashboard responsiveness.

---

## 10. Dependency Analysis

### 10.1 Dependencies (This Ticket Requires)

| Dependency | Status | Impact |
|------------|--------|--------|
| VOD-001: Video metadata table + state machine | Complete | Provides `video_metadata` table, `VideoMetadataModel`, `validate_transition()` |
| MEDIA-001: Shared video player component | Complete | Provides `SharedVideoPlayer` React component for preview panel |
| Moderation audit log infrastructure | Complete | Provides `write_moderation_audit_event()` and `ModerationAuditLog` table |
| Alert notification system | Complete | Provides `write_alert()` for creator notifications |
| Admin auth scope system | Complete | Provides `require_admin_scope(AdminScope.CONTENT_MODERATION)` |

### 10.2 Dependents (Blocked by This Ticket)

| Dependent | Description |
|-----------|-------------|
| MOD-004: Automated content scanning | Requires the review queue to exist so auto-scanned videos can be routed to manual review when confidence is low |
| MOD-005: Review SLA dashboard | Requires review queue metrics (queue depth, wait time, throughput) |
| VOD-015: Creator video management | Needs the rejection reason to be displayed in the creator's video list |

### 10.3 Integration with Existing Moderation Pipeline

The video review queue is a parallel workflow to the existing content moderation ticket system (`app/routers/admin_moderation.py`). Key integration points:

- **Shared admin scope**: Both use `AdminScope.CONTENT_MODERATION`
- **Shared audit log**: Both write to `ModerationAuditLog` table via `write_moderation_audit_event()`
- **Shared alert system**: Both use `write_alert()` for user notifications
- **No direct coupling**: Video review does not create moderation tickets. A separate ticket (MOD-006) will add the ability to escalate a video review to a full moderation investigation.

---

## 11. Acceptance Criteria

### 11.1 Functional Requirements

- [ ] Admin with `CONTENT_MODERATION` scope can view a paginated list of pending videos ordered oldest-first
- [ ] Admin can filter the queue by uploader ID
- [ ] Admin can approve a pending video, which transitions it to `published` (with auto_publish) or `approved` (without)
- [ ] Admin can reject a pending video with a required reason (min 5 chars)
- [ ] Admin can batch approve/reject up to 25 videos in a single request
- [ ] Creator receives an alert notification on approval with video title
- [ ] Creator receives an alert notification on rejection with reason text
- [ ] Rejection notification can be suppressed via `notify_creator=false`
- [ ] Every decision writes an audit log entry with admin identity, timestamp, and reason
- [ ] Detail view shows owner profile and prior review history (approval/rejection counts)
- [ ] Queue badge shows total pending count in the admin sidebar

### 11.2 Non-Functional Requirements

- [ ] Queue list endpoint responds in < 200ms p99 for 25 items
- [ ] Approve/reject endpoint responds in < 100ms p99
- [ ] Batch review of 25 items responds in < 2000ms p99
- [ ] All endpoints return appropriate error codes (404, 409, 422, 403)
- [ ] No XSS vectors in stored review notes or rejection reasons

### 11.3 Testing Requirements

- [ ] 22 unit tests pass (service layer with moto-mocked DDB)
- [ ] 25 E2E tests pass (API + UI)
- [ ] Edge cases covered: concurrent approval, deleted video, auto-publish failure, empty queue

---

## 12. Error Handling Matrix

| Error | HTTP Status | Error Code | Admin Message | User (Creator) Message | Recovery |
|-------|-------------|------------|---------------|----------------------|----------|
| Video not found | 404 | `video_not_found` | "Video not found -- it may have been deleted" | N/A (admin-only endpoint) | Admin refreshes queue |
| Video not in pending_review | 409 | `VIDEO_INVALID_STATE_TRANSITION` | "This video has already been reviewed or is no longer pending" | N/A | Admin refreshes queue |
| Rejection reason too short (<5 chars) | 422 | `validation_error` | "Rejection reason must be at least 5 characters" | N/A | Admin enters longer reason |
| Rejection reason too long (>2000 chars) | 422 | `validation_error` | "Rejection reason must be at most 2000 characters" | N/A | Admin shortens reason |
| Admin lacks CONTENT_MODERATION scope | 403 | `role_required_scope` | "You do not have permission to review videos" | N/A | Admin requests scope from root |
| Batch size exceeds 25 | 422 | `validation_error` | "Maximum 25 decisions per batch" | N/A | Admin reduces batch size |
| Batch item failure (individual) | 200 (partial) | Per-item `error` field | "Failed: {video_id}: {reason}" | N/A | Admin retries failed items |
| Auto-publish failed after approve | 200 | `auto_publish_failed=true` | "Video approved but auto-publish failed -- publish manually" | N/A | Admin manually publishes |
| DDB throttling | 500 | `internal_server_error` | "Service temporarily unavailable" | N/A | Retry after backoff |
| Profile enrichment failure | 200 (degraded) | N/A | Queue renders without owner names | N/A | Graceful degradation |

---

## 13. Frontend Component Specifications

### 13.1 VideoReviewQueuePage Layout

```
+---------------------------------------------------------------+
| Video Review Queue                      [25 pending] [Refresh] |
+---------------------------------------------------------------+
| Filters: [Owner ID: ___________] [Apply]                       |
+---------------------------------------------------------------+
| [x] Select All    [Approve Selected (3)] [Reject Selected (3)] |
+----+-----------------------------------------------------+----+
| [] | [thumb] "Beach Sunset Timelapse"                     | [] |
|    | @john_creator | 2:34 | 1920x1080 | 45MB             |    |
|    | Uploaded 2h ago                                       |    |
|    |           [Preview] [Approve] [Reject]               |    |
+----+-----------------------------------------------------+----+
| [] | [thumb] "Product Demo v3"                            | [] |
|    | @acme_corp | 0:58 | 1280x720 | 12MB                 |    |
|    | Uploaded 4h ago                                       |    |
|    |           [Preview] [Approve] [Reject]               |    |
+----+-----------------------------------------------------+----+
|                     [Load More]                                |
+---------------------------------------------------------------+
```

### 13.2 VideoPreviewPanel (Side Panel)

```
+----------------------------------------------+
| Video Preview                           [X]  |
+----------------------------------------------+
| +------------------------------------------+ |
| |                                          | |
| |        [HLS Video Player]               | |
| |        SharedVideoPlayer component       | |
| |                                          | |
| +------------------------------------------+ |
| Title: Beach Sunset Timelapse                |
| Owner: @john_creator (John Smith)            |
| Duration: 2:34                               |
| Resolution: 1920x1080                        |
| File size: 45 MB                             |
| Source: upload                                |
| Visibility: public                           |
| Uploaded: 2026-05-26 14:23 UTC               |
|                                              |
| --- Prior Review History ---                 |
| Approvals: 12 | Rejections: 1               |
| Last rejection: 2026-05-20 "Copyrighted      |
|   music detected in background"              |
|                                              |
| [Approve]  [Reject]                          |
+----------------------------------------------+
```

### 13.3 RejectionReasonDialog

```
+----------------------------------------------+
| Reject Video                            [X]  |
+----------------------------------------------+
| Please provide a reason for rejection.       |
| This will be shown to the video creator.     |
|                                              |
| +------------------------------------------+ |
| |                                          | |
| | [textarea, min 5 chars, max 2000]        | |
| |                                          | |
| +------------------------------------------+ |
| 0 / 2000 characters                         |
|                                              |
| [x] Notify creator                          |
|                                              |
|              [Cancel]  [Reject Video]        |
+----------------------------------------------+
```

### 13.4 TypeScript Component Interfaces

```typescript
interface VideoReviewQueuePageProps {}

interface VideoReviewCardProps {
  video: VideoReviewQueueItem;
  isSelected: boolean;
  onSelect: (videoId: string, selected: boolean) => void;
  onPreview: (videoId: string) => void;
  onApprove: (videoId: string) => void;
  onReject: (videoId: string) => void;
}

interface VideoPreviewPanelProps {
  videoId: string;
  onClose: () => void;
  onApprove: (videoId: string, notes: string) => void;
  onReject: (videoId: string, reason: string, notify: boolean) => void;
}

interface RejectionReasonDialogProps {
  open: boolean;
  videoId: string;
  videoTitle: string;
  onConfirm: (reason: string, notifyCreator: boolean) => void;
  onCancel: () => void;
}

interface BatchReviewToolbarProps {
  selectedCount: number;
  onBatchApprove: () => void;
  onBatchReject: () => void;
  onSelectAll: () => void;
  onDeselectAll: () => void;
}
```

### 13.5 Keyboard Shortcuts for Efficient Review

| Shortcut | Action |
|----------|--------|
| `a` | Approve currently previewed video |
| `r` | Open rejection reason dialog for current video |
| `j` / `Arrow Down` | Move to next video in queue |
| `k` / `Arrow Up` | Move to previous video in queue |
| `Space` | Toggle selection of current video |
| `Enter` | Open preview panel for current video |
| `Escape` | Close preview panel or rejection dialog |
| `Ctrl+Shift+A` | Batch approve all selected videos |

### 13.6 Accessibility

- All interactive elements have `aria-label` attributes
- Video preview panel is a focus trap when open
- Rejection dialog is announced via `aria-live="polite"`
- Queue items are navigable via keyboard (Tab / Shift+Tab)
- Color-coded status badges have text labels (not color-only)
- Batch action buttons are disabled with `aria-disabled="true"` when no items selected

---

## 14. Workflow Diagrams

### 14.1 Complete Video Review State Machine

```
                    +---------+
                    | created |
                    +----+----+
                         |
                         v
                    +---------+
              +---->| probing |------+
              |     +----+----+      |
              |          |           v
              |          v      +-----------+
              |   +-----------+ |probe_failed|
              |   |pending_   | +-----+-----+
              |   | encoding  |       |
              |   +-----+-----+      |
              |         |             |
              |         v             |
              |   +---------+         |
              |   |encoding |<--------+
              |   +----+----+
              |        |
              |   +----+------+
              |   |           |
              |   v           v
       +------+---+    +----------+
       |pending_   |   |encoding_ |
       | review    |   | failed   |
       +----+------+   +----------+
            |
     +------+------+
     |      |      |
     v      v      v
+--------+ +--------+ +-------+
|approved| |rejected| |deleted|
+---+----+ +---+----+ +-------+
    |          |
    v          v (re-submit)
+---------+   pending_review
|published|
+----+----+
     |
     v
+---------+
|archived |
+---------+
```

Guard conditions for review transitions:
- `pending_review -> approved`: Requires `role >= ADMIN` with `CONTENT_MODERATION` scope
- `pending_review -> rejected`: Requires `role >= ADMIN` with `CONTENT_MODERATION` scope, `rejection_reason.length >= 5`
- `approved -> published`: Automatic when `auto_publish=True`, or manual admin action
- `rejected -> pending_review`: Creator re-submits (future ticket, out of scope)
- Any state -> `deleted`: Creator or admin action

### 14.2 Admin Review Workflow Sequence Diagram

```
Admin                   Frontend                 Backend                  DynamoDB
  |                        |                        |                        |
  |-- Navigate to          |                        |                        |
  |   /admin/video-review  |                        |                        |
  |                        |                        |                        |
  |                        |-- GET /review-queue --->|                        |
  |                        |                        |-- Query GSI ---------->|
  |                        |                        |<-- Items[] ------------|
  |                        |                        |-- BatchGetItem ------->|
  |                        |                        |   (profiles)           |
  |                        |                        |<-- Profiles[] ---------|
  |                        |                        |-- COUNT query -------->|
  |                        |                        |<-- 25 ------------------|
  |                        |<-- {items, total} -----|                        |
  |<-- Renders queue list  |                        |                        |
  |                        |                        |                        |
  |-- Click "Preview"      |                        |                        |
  |                        |-- GET /review-detail -->|                        |
  |                        |                        |-- get_video() -------->|
  |                        |                        |-- get_owner_profile() ->|
  |                        |                        |-- get_review_history() ->|
  |                        |<-- {detail} ------------|                        |
  |<-- Shows video player  |                        |                        |
  |   + metadata + history |                        |                        |
  |                        |                        |                        |
  |-- Click "Approve"      |                        |                        |
  |                        |-- POST /approve ------->|                        |
  |                        |                        |-- get_video() -------->|
  |                        |                        |-- validate_transition ->|
  |                        |                        |-- put_item(approved) -->|
  |                        |                        |-- put_item(published) ->|
  |                        |                        |-- write_audit() ------->|
  |                        |                        |-- write_alert() ------->|
  |                        |<-- {ok, published} -----|                        |
  |<-- Toast: "Approved"   |                        |                        |
  |   Video removed from   |                        |                        |
  |   queue list           |                        |                        |
```

### 14.3 Notification Flow Diagram

```
                  Approve/Reject Decision
                         |
                         v
              +---------------------+
              | write_alert()       |
              | app/services/       |
              | alerts.py:261       |
              +----------+----------+
                         |
              +----------+----------+
              |                     |
              v                     v
     +--------+--------+   +-------+--------+
     | T.alerts table  |   | SSE publish    |
     | PK=user_sub     |   | sse_publish_   |
     | SK=alert_id     |   | alert()        |
     +--------+--------+   +-------+--------+
              |                     |
              v                     v
     +--------+--------+   +-------+--------+
     | User views      |   | Real-time      |
     | /alerts page    |   | browser toast  |
     +-----------------+   +----------------+
```

---

## 15. Abuse Prevention

### 15.1 Admin Abuse Vectors

| Vector | Mitigation |
|--------|------------|
| Admin approves unsafe content | Audit trail + periodic review of approval decisions by senior moderators |
| Admin rejects content maliciously | Rejection reason is logged and visible to the creator; appeal system (MOD-003) allows creators to contest |
| Admin batch-approves without reviewing | Monitor approval rate per admin; alert if an admin approves >50 videos in 10 minutes without opening detail views |
| Compromised admin account | Immediate session revocation; audit trail allows identifying all affected decisions |

### 15.2 Queue Manipulation

| Vector | Mitigation |
|--------|------------|
| User floods queue with trivial uploads to overwhelm reviewers | Rate-limit video uploads per user (existing VOD pipeline limit) |
| User re-submits rejected video repeatedly | Track `prior_rejections_count` in detail view; after 3 rejections, auto-escalate to senior moderator |
| User uploads content that passes review then replaces the file | Videos are immutable after encoding -- the S3 key is locked once encoding completes; any "replacement" is a new upload that enters the queue independently |
