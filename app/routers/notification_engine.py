"""Notification engine router — social notification endpoints (SOC-004).

Prefix: /ui/notifications
All endpoints require session auth via require_ui_session.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    MarkNotificationsReadIn,
    NotificationListResponse,
    NotificationOut,
    SendNotificationIn,
)
from app.services import notification_engine as engine
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/notifications", tags=["notification-engine"])


# ---------------------------------------------------------------------------
# Helper: convert DDB item to NotificationOut
# ---------------------------------------------------------------------------


def _to_notification_out(item: dict) -> NotificationOut:
    return NotificationOut(
        notification_id=item.get("notification_id", ""),
        notification_type=item.get("notification_type", ""),
        title=item.get("title", ""),
        body=item.get("body", ""),
        data=item.get("data", {}),
        read=bool(item.get("read", False)),
        created_at=int(item.get("created_at", 0)),
        batch_key=item.get("batch_key") or None,
        batch_count=int(item.get("batch_count", 1)),
        batch_actors=list(item.get("batch_actors", [])),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=NotificationListResponse)
def list_notifications(
    session=Depends(require_ui_session),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
):
    """Get paginated notifications for the current user."""
    user_id = session["user_sub"]
    items, next_cursor = engine.list_notifications(
        user_id, cursor=cursor, limit=limit,
    )
    unread = engine.get_unread_count(user_id)
    return NotificationListResponse(
        items=[_to_notification_out(it) for it in items],
        next_cursor=next_cursor,
        unread_count=unread,
    )


@router.get("/unread-count")
def get_unread_count(session=Depends(require_ui_session)):
    """Get count of unread notifications."""
    user_id = session["user_sub"]
    count = engine.get_unread_count(user_id)
    return {"count": count}


@router.post("/mark-read")
def mark_read(
    body: MarkNotificationsReadIn,
    session=Depends(require_ui_session),
):
    """Mark specific notifications as read by their IDs."""
    user_id = session["user_sub"]
    if not body.notification_ids:
        raise HTTPException(status_code=400, detail="notification_ids must not be empty")
    marked = engine.mark_read(user_id, body.notification_ids)
    return {"ok": True, "marked_count": marked}


@router.post("/mark-all-read")
def mark_all_read(session=Depends(require_ui_session)):
    """Mark all notifications as read for the current user."""
    user_id = session["user_sub"]
    marked = engine.mark_all_read(user_id)
    return {"ok": True, "marked_count": marked}


@router.post("/send")
def send_notification(
    body: SendNotificationIn,
    session=Depends(require_ui_session),
):
    """Send a notification (internal/test endpoint).

    In production, notifications are created by service-layer hooks
    when social events occur (follow, like, comment, etc.).
    """
    if body.notification_type not in engine.NOTIFICATION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid notification_type. Must be one of: {engine.NOTIFICATION_TYPES}",
        )

    item = engine.send_notification(
        user_id=body.user_id,
        notification_type=body.notification_type,
        title=body.title,
        body=body.body,
        data=body.data,
        batch_key=body.batch_key,
    )
    return {
        "ok": True,
        "notification_id": item["notification_id"],
        "created_at": item["created_at"],
        "batch_count": item.get("batch_count", 1),
    }
