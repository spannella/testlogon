"""Content calendar router.

Provides unified read/write access to scheduled content items
across posts, broadcasts, and VOD releases.

Registered in app/main.py with prefix="/ui/content-calendar".
"""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, Query

from app.services.sessions import require_ui_session
from app.services.content_calendar import (
    get_content_calendar,
    get_today_agenda,
    reschedule_item,
    cancel_item,
    ContentType,
)

router = APIRouter(prefix="/ui/content-calendar", tags=["content-calendar"])


@router.get("")
def content_calendar(
    from_ts: int = Query(..., description="Start of time range (Unix seconds)"),
    to_ts: int = Query(..., description="End of time range (Unix seconds)"),
    types: Optional[str] = Query(
        default=None,
        description="Comma-separated content types: post,broadcast,vod",
    ),
    session=Depends(require_ui_session),
):
    """Get all scheduled content for the authenticated creator in a time range."""
    user_id = session["user_sub"]

    type_filter = None
    if types:
        raw = {t.strip().lower() for t in types.split(",")}
        valid: set[str] = set()
        for t in raw:
            if t in ("post", "broadcast", "vod"):
                valid.add(t)
        if valid:
            type_filter = valid

    return get_content_calendar(user_id, from_ts, to_ts, type_filter=type_filter)


@router.get("/today")
def content_calendar_today(
    session=Depends(require_ui_session),
):
    """Get today's and tomorrow's scheduled items."""
    return get_today_agenda(session["user_sub"])


@router.get("/conflicts")
def content_calendar_conflicts(
    from_ts: int = Query(..., description="Start of time range (Unix seconds)"),
    to_ts: int = Query(..., description="End of time range (Unix seconds)"),
    session=Depends(require_ui_session),
):
    """Detect scheduling conflicts in a time range."""
    result = get_content_calendar(session["user_sub"], from_ts, to_ts)
    return {"conflicts": result["conflicts"], "count": len(result["conflicts"])}


@router.post("/reschedule")
def content_calendar_reschedule(
    item_id: str = Query(...),
    item_type: Literal["post", "broadcast", "vod"] = Query(...),
    new_scheduled_at: int = Query(..., description="New scheduled time (Unix seconds)"),
    session=Depends(require_ui_session),
):
    """Reschedule a content item to a new time."""
    return reschedule_item(
        user_id=session["user_sub"],
        item_id=item_id,
        item_type=item_type,
        new_scheduled_at=new_scheduled_at,
    )


@router.post("/cancel")
def content_calendar_cancel(
    item_id: str = Query(...),
    item_type: Literal["post", "broadcast", "vod"] = Query(...),
    session=Depends(require_ui_session),
):
    """Cancel a scheduled content item."""
    return cancel_item(
        user_id=session["user_sub"],
        item_id=item_id,
        item_type=item_type,
    )
