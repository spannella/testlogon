"""Activity feed router — unified activity stream endpoints."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.sessions import require_ui_session
from app.services import activity_feed as activity_feed_service
from app.core.time import now_ts

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/activity", tags=["activity-feed"])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ActivityOut(BaseModel):
    activity_id: str
    actor_id: str
    activity_type: str
    target_type: str = ""
    target_id: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: int = 0
    read: bool = False


class ActivityFeedResponse(BaseModel):
    items: List[ActivityOut]
    next_cursor: Optional[str] = None
    total_unread: int = 0


class MarkReadIn(BaseModel):
    up_to_ts: Optional[int] = None


class UnreadCountResponse(BaseModel):
    count: int


class RecordActivityIn(BaseModel):
    """Input for recording an activity (dev/test endpoint)."""
    user_id: str = Field(..., min_length=1, max_length=256)
    actor_id: str = Field(..., min_length=1, max_length=256)
    activity_type: str = Field(..., min_length=1, max_length=64)
    target_type: str = Field(default="", max_length=64)
    target_id: str = Field(default="", max_length=256)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper: convert DDB item to ActivityOut
# ---------------------------------------------------------------------------


def _to_activity_out(item: Dict[str, Any]) -> ActivityOut:
    return ActivityOut(
        activity_id=item.get("activity_id", ""),
        actor_id=item.get("actor_id", ""),
        activity_type=item.get("activity_type", ""),
        target_type=item.get("target_type", ""),
        target_id=item.get("target_id", ""),
        metadata=item.get("metadata", {}),
        created_at=int(item.get("created_at", 0)),
        read=bool(item.get("read", False)),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/feed", response_model=ActivityFeedResponse)
def get_activity_feed(
    session=Depends(require_ui_session),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
):
    """Get paginated activity feed for the current user."""
    user_id = session["user_sub"]
    items, next_cursor = activity_feed_service.get_activity_feed(
        user_id, cursor=cursor, limit=limit,
    )
    unread = activity_feed_service.get_unread_count(user_id)
    return ActivityFeedResponse(
        items=[_to_activity_out(it) for it in items],
        next_cursor=next_cursor,
        total_unread=unread,
    )


@router.get("/feed/unread-count", response_model=UnreadCountResponse)
def get_unread_count(session=Depends(require_ui_session)):
    """Get count of unread activity items."""
    user_id = session["user_sub"]
    count = activity_feed_service.get_unread_count(user_id)
    return UnreadCountResponse(count=count)


@router.post("/feed/mark-read")
def mark_activities_read(
    body: MarkReadIn,
    session=Depends(require_ui_session),
):
    """Mark activities as read up to a timestamp.

    If up_to_ts is not provided, marks all activities as read (uses current time).
    """
    user_id = session["user_sub"]
    up_to = body.up_to_ts if body.up_to_ts is not None else now_ts()
    marked = activity_feed_service.mark_activities_read(user_id, up_to)
    return {"ok": True, "marked_count": marked}


@router.get("/feed/filter", response_model=ActivityFeedResponse)
def filter_activity_feed(
    activity_type: str = Query(..., min_length=1, max_length=64),
    session=Depends(require_ui_session),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
):
    """Get activity feed filtered by activity type."""
    user_id = session["user_sub"]
    items, next_cursor = activity_feed_service.get_activity_feed_filtered(
        user_id,
        activity_type=activity_type,
        cursor=cursor,
        limit=limit,
    )
    unread = activity_feed_service.get_unread_count(user_id)
    return ActivityFeedResponse(
        items=[_to_activity_out(it) for it in items],
        next_cursor=next_cursor,
        total_unread=unread,
    )


@router.post("/feed/record")
def record_activity(
    body: RecordActivityIn,
    session=Depends(require_ui_session),
):
    """Record an activity item (for testing/internal use).

    In production, activities are created by service-layer hooks
    when social events occur (follow, like, comment, etc.).
    """
    item = activity_feed_service.record_activity(
        user_id=body.user_id,
        actor_id=body.actor_id,
        activity_type=body.activity_type,
        target_type=body.target_type,
        target_id=body.target_id,
        metadata=body.metadata,
    )
    return {
        "ok": True,
        "activity_id": item["activity_id"],
        "created_at": item["created_at"],
    }
