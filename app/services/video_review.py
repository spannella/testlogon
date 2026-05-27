"""Video review queue service layer.

Provides functions for admin video review operations:
- list_pending_review_videos: paginated queue of pending videos (oldest first)
- approve_video: transition pending_review -> approved -> published
- reject_video: transition pending_review -> rejected
- count_pending_review: count videos awaiting review
- get_owner_review_history: prior review decisions for a video owner
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert
from app.services.moderation_audit_log import write_moderation_audit_event
from app.services.video_metadata_store import (
    get_video,
    video_from_item,
    video_to_item,
)
from app.services.video_state_machine import validate_transition

logger = logging.getLogger(__name__)


def _sanitize_cursor(cursor: dict | None) -> dict | None:
    """Convert Decimal values in a DDB LastEvaluatedKey to int/float
    so that ``encode_cursor`` (which uses ``json.dumps``) doesn't fail."""
    if cursor is None:
        return None
    out: dict[str, Any] = {}
    for k, v in cursor.items():
        if isinstance(v, Decimal):
            out[k] = int(v) if v == int(v) else float(v)
        else:
            out[k] = v
    return out


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
        Dict with 'items' (list of VideoMetadataModel), 'cursor' (next page
        key or None), and 'total_pending' (count of all pending videos).
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
            filter_conditions = filter_conditions & Attr("owner_user_id").eq(
                owner_filter
            )
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

    # Sanitize cursor: DynamoDB returns Decimal values in LastEvaluatedKey
    # which are not JSON-serializable for encode_cursor().
    safe_cursor = _sanitize_cursor(current_cursor)

    return {
        "items": collected[:limit],
        "cursor": safe_cursor,
        "total_pending": total,
    }


def approve_video(
    *,
    video_id: str,
    admin_user_id: str,
    review_notes: str = "",
    auto_publish: bool = True,
) -> tuple[Any, str, bool]:
    """Approve a video currently in pending_review status.

    Returns:
        Tuple of (updated VideoMetadataModel, audit_id string,
        auto_publish_failed bool).

    Raises:
        HTTPException 404: Video not found.
        HTTPException 409: Video not in pending_review status.
    """
    video = get_video(video_id)
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
    video = video.model_copy(
        update={
            "status": "approved",
            "review_status": "approved",
            "reviewed_by": admin_user_id,
            "reviewed_at": ts,
            "review_notes": review_notes,
            "updated_at": ts,
        }
    )
    T.video_metadata.put_item(Item=video_to_item(video))

    auto_publish_failed = False
    if auto_publish:
        result = validate_transition("approved", "published")
        if result.legal:
            video = video.model_copy(
                update={
                    "status": "published",
                    "published_at": ts,
                    "updated_at": ts,
                }
            )
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

    return video, audit_id, auto_publish_failed


def reject_video(
    *,
    video_id: str,
    admin_user_id: str,
    rejection_reason: str,
    notify_creator: bool = True,
) -> tuple[Any, str]:
    """Reject a video currently in pending_review status.

    Returns:
        Tuple of (updated VideoMetadataModel, audit_id string).

    Raises:
        HTTPException 404: Video not found.
        HTTPException 409: Video not in pending_review status.
    """
    video = get_video(video_id)
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
    video = video.model_copy(
        update={
            "status": "rejected",
            "review_status": "rejected",
            "reviewed_by": admin_user_id,
            "reviewed_at": ts,
            "review_notes": rejection_reason,
            "updated_at": ts,
        }
    )
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
    """Count videos in pending_review status using SELECT COUNT."""
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
    """Query ModerationAuditLog for video_approved/video_rejected actions
    by owner. Returns dict with 'events', 'approvals_count', 'rejections_count'.
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

    events.sort(
        key=lambda e: int(str(e.get("created_at", "0"))), reverse=True
    )
    return {
        "events": events[:20],
        "approvals_count": approvals,
        "rejections_count": rejections,
    }
