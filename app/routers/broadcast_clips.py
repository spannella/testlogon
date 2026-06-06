"""Broadcast clips router -- viewer-initiated clipping (ENGAGE-005)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from fastapi import HTTPException, status as http_status
from pydantic import BaseModel

from app.models import CreateClipIn, ClipOut, ClipListOut, PublicClipOut
from app.services.sessions import require_ui_session
from app.services.broadcast_clip import (
    create_broadcast_clip,
    get_clip,
    get_public_clip,
    list_clips_for_session,
    list_my_clips,
    list_gallery,
    delete_clip,
    record_view,
    record_share,
)
from app.services.broadcast_store import get_session, update_session_fields

router = APIRouter(tags=["broadcast-clips"])

# Public router -- no auth, for shareable clip pages (ENGAGE-005 §4.5)
public_clips_router = APIRouter(prefix="/broadcast/public", tags=["broadcast-clips-public"])


def _ctx(ctx=Depends(require_ui_session)):
    return ctx


# --- Clip creation ---

@router.post("/broadcast/sessions/{session_id}/clips", response_model=ClipOut)
def create_clip_route(
    session_id: str,
    body: CreateClipIn,
    ctx: dict = Depends(_ctx),
):
    """Create a clip from a broadcast session."""
    display_name = ctx.get("display_name") or ctx.get("user_sub", "Viewer")
    return create_broadcast_clip(
        session_id=session_id,
        creator_user_id=ctx["user_sub"],
        creator_display_name=display_name,
        start_seconds=body.start_seconds,
        end_seconds=body.end_seconds,
        title=body.title,
    )


# --- Clip retrieval ---

@router.get("/broadcast/clips/{clip_id}", response_model=ClipOut)
def get_clip_route(clip_id: str, ctx: dict = Depends(_ctx)):
    """Get clip details."""
    return get_clip(clip_id)


@router.get("/broadcast/sessions/{session_id}/clips", response_model=ClipListOut)
def list_session_clips_route(session_id: str, ctx: dict = Depends(_ctx)):
    """List clips for a broadcast session."""
    clips = list_clips_for_session(session_id)
    return ClipListOut(clips=clips)


@router.get("/ui/clips", response_model=ClipListOut)
def gallery_route(
    sort: str = Query(default="popular", regex="^(popular|recent)$"),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    ctx: dict = Depends(_ctx),
):
    """Public clip gallery."""
    clips, next_cursor = list_gallery(limit=limit, sort=sort, cursor=cursor)
    return ClipListOut(clips=clips, next_cursor=next_cursor)


@router.get("/ui/clips/mine", response_model=ClipListOut)
def my_clips_route(ctx: dict = Depends(_ctx)):
    """List clips created by the current user."""
    clips = list_my_clips(ctx["user_sub"])
    return ClipListOut(clips=clips)


# --- Clip management ---

@router.delete("/broadcast/clips/{clip_id}")
def delete_clip_route(clip_id: str, ctx: dict = Depends(_ctx)):
    """Delete a clip (creator, broadcaster, or platform admin/root)."""
    return delete_clip(clip_id, actor=ctx["user_sub"], role=ctx.get("role"))


@router.post("/broadcast/clips/{clip_id}/view")
def record_view_route(clip_id: str, ctx: dict = Depends(_ctx)):
    """Record a view on a clip."""
    return record_view(clip_id)


@router.post("/broadcast/clips/{clip_id}/share")
def record_share_route(clip_id: str, ctx: dict = Depends(_ctx)):
    """Record a share and get share URL."""
    return record_share(clip_id)


# --- Clips config ---

class ClipsConfigIn(BaseModel):
    clips_enabled: bool


@router.patch("/broadcast/sessions/{session_id}/clips/config")
def update_clips_config_route(
    session_id: str,
    body: ClipsConfigIn,
    ctx: dict = Depends(_ctx),
):
    """Toggle clip creation on/off for a broadcast session (broadcaster only)."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_BROADCASTER", "message": "Only the broadcaster can update clips config."},
        )
    updated = update_session_fields(session_id, {"clips_enabled": body.clips_enabled})
    return {"ok": True, "clips_enabled": updated.clips_enabled}


# --- Public (no-auth) shareable clip endpoints ---

@public_clips_router.get("/clips/{clip_id}", response_model=PublicClipOut)
def public_clip_route(clip_id: str):
    """Public shareable clip view with broadcaster attribution. No auth required."""
    return get_public_clip(clip_id)


@public_clips_router.post("/clips/{clip_id}/view")
def public_record_view_route(clip_id: str):
    """Record a view from the public clip page. No auth required."""
    # Ensure the clip exists / is not deleted before counting the view.
    get_public_clip(clip_id)
    return record_view(clip_id)


@public_clips_router.post("/clips/{clip_id}/share")
def public_record_share_route(clip_id: str):
    """Record a share from the public clip page. No auth required."""
    get_public_clip(clip_id)
    return record_share(clip_id)
