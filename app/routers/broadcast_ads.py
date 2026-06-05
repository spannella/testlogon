"""Broadcast ad-break endpoints (ADS-006).

Adds advertising surfaces to live broadcasts:
  * pre-roll ads delivered in the viewer join response
  * broadcaster-triggered mid-roll ad breaks (SSE fan-out to all viewers)
  * subscriber ad-free skip (server-authoritative)
  * ad config on the broadcast session (pre-roll on/off, mid-roll duration/skip)
  * ad event tracking (impression / skip / complete / click)

A dedicated router (registered once in app/main.py) keeps the large existing
broadcast router untouched. All routes live under the same ``/broadcast`` prefix
as the core broadcast router. ADS-002/ADS-004 do not exist yet; ad selection is
stubbed inline in ``app.services.broadcast_ads``.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from app.core.settings import S
from app.services.broadcast_store import get_session, update_session_fields
from app.services.broadcast_ads import (
    ALLOWED_MIDROLL_DURATIONS,
    build_pre_roll,
    end_ad_break,
    record_ad_event,
    schedule_ad_break_end,
    start_ad_break,
)
from app.services.sessions import require_ui_session
from app.auth.roles import Role

router = APIRouter(prefix="/broadcast", tags=["broadcast-ads"])


def _ctx(ctx=Depends(require_ui_session)):
    return ctx


# ─── Models ──────────────────────────────────────────────────────────


class BroadcastAdConfigIn(BaseModel):
    pre_roll_enabled: Optional[bool] = None
    mid_roll_ad_break_duration_seconds: Optional[int] = Field(default=None, ge=15, le=60)
    mid_roll_skip_after_seconds: Optional[int] = Field(default=None, ge=5, le=30)

    @field_validator("mid_roll_ad_break_duration_seconds")
    @classmethod
    def _validate_duration(cls, v):
        if v is not None and v not in ALLOWED_MIDROLL_DURATIONS:
            raise ValueError("mid_roll_ad_break_duration_seconds must be 15, 30, or 60")
        return v


class BroadcastAdConfigOut(BaseModel):
    session_id: str
    pre_roll_enabled: bool
    mid_roll_ad_break_duration_seconds: int
    mid_roll_skip_after_seconds: int
    ad_break_active: bool
    ad_break_started_at: Optional[int] = None
    total_ad_breaks: int


class PreRollOut(BaseModel):
    creative_id: str
    format: str
    video_url: Optional[str] = None
    image_url: Optional[str] = None
    cta_url: Optional[str] = None
    skip_after_seconds: int = 5
    impression_url: str
    click_url: str
    skip_url: str


class BroadcastJoinOut(BaseModel):
    session_id: str
    stream_url: Optional[str] = None
    pre_roll: Optional[PreRollOut] = None
    ad_free: bool = False
    mid_roll_skip_after_seconds: int = 15


class AdBreakOut(BaseModel):
    ok: bool = True
    duration_seconds: int
    started_at: int
    skip_after_seconds: int


class AdEventOut(BaseModel):
    ok: bool = True
    event_id: str
    event_type: str


def _config_out(session) -> BroadcastAdConfigOut:
    return BroadcastAdConfigOut(
        session_id=session.id,
        pre_roll_enabled=session.pre_roll_enabled,
        mid_roll_ad_break_duration_seconds=session.mid_roll_ad_break_duration_seconds,
        mid_roll_skip_after_seconds=session.mid_roll_skip_after_seconds,
        ad_break_active=session.ad_break_active,
        ad_break_started_at=session.ad_break_started_at,
        total_ad_breaks=session.total_ad_breaks,
    )


# ─── Ad config (broadcaster) ─────────────────────────────────────────


@router.get("/sessions/{session_id}/ad-config", response_model=BroadcastAdConfigOut)
def get_ad_config_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Get the ad configuration + current ad-break state for a session."""
    _ = ctx
    session = get_session(session_id)
    return _config_out(session)


@router.patch("/sessions/{session_id}/ad-config", response_model=BroadcastAdConfigOut)
def update_ad_config_route(session_id: str, body: BroadcastAdConfigIn, ctx: dict = Depends(_ctx)):
    """Update ad configuration (broadcaster only)."""
    session = get_session(session_id)
    if session.created_by != ctx["user_sub"] and ctx.get("role") not in {Role.ADMIN, Role.ROOT}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_BROADCASTER", "detail": "Only the broadcaster can update ad config"},
        )
    if body.pre_roll_enabled is True and not S.broadcast_preroll_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "PREROLL_DISABLED", "detail": "Pre-roll ads are not enabled on this platform"},
        )
    updates = {}
    if body.pre_roll_enabled is not None:
        updates["pre_roll_enabled"] = body.pre_roll_enabled
    if body.mid_roll_ad_break_duration_seconds is not None:
        updates["mid_roll_ad_break_duration_seconds"] = body.mid_roll_ad_break_duration_seconds
    if body.mid_roll_skip_after_seconds is not None:
        updates["mid_roll_skip_after_seconds"] = body.mid_roll_skip_after_seconds
    if updates:
        session = update_session_fields(session_id, updates)
    return _config_out(session)


# ─── Viewer join (with pre-roll) ─────────────────────────────────────


@router.post("/sessions/{session_id}/ad-join", response_model=BroadcastJoinOut)
def ad_join_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Viewer join that returns ad info (pre-roll + ad-free flag).

    Kept separate from the core viewer-count join so the existing endpoint's
    response shape is unchanged. Returns the pre-roll creative (if any) and
    whether the viewer is ad-free (subscriber or broadcaster).
    """
    session = get_session(session_id)
    viewer_id = ctx["user_sub"]

    result = build_pre_roll(session, viewer_id)
    pre_roll = result["pre_roll"]

    # Resolve a best-effort stream URL (mirrors broadcast output wiring).
    stream_url = None
    try:
        from app.services.broadcast_store import get_output

        output = get_output(session_id)
        if output:
            stream_url = output.cloudfront_playback_url or output.mediapackage_endpoint
    except Exception:
        stream_url = None

    return BroadcastJoinOut(
        session_id=session.id,
        stream_url=stream_url,
        pre_roll=PreRollOut(**pre_roll) if pre_roll else None,
        ad_free=result["ad_free"],
        mid_roll_skip_after_seconds=session.mid_roll_skip_after_seconds,
    )


# ─── Mid-roll ad break (broadcaster) ─────────────────────────────────


@router.post("/sessions/{session_id}/ad-break", response_model=AdBreakOut)
async def trigger_ad_break_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Broadcaster triggers a mid-roll ad break for all viewers."""
    session = get_session(session_id)
    if session.created_by != ctx["user_sub"] and ctx.get("role") not in {Role.ADMIN, Role.ROOT}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_BROADCASTER", "detail": "Only the broadcaster can trigger ad breaks"},
        )

    # Global platform kill-switch for mid-roll (BROADCAST_MIDROLL_ENABLED).
    if not S.broadcast_midroll_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "MIDROLL_DISABLED", "detail": "Mid-roll ad breaks are not enabled on this platform"},
        )
    if session.status != "live":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "SESSION_NOT_LIVE", "detail": "Session must be live to trigger ad break"},
        )
    if session.ad_break_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AD_BREAK_ACTIVE", "detail": "Ad break already active"},
        )

    payload = start_ad_break(session)

    # Schedule auto-end after the configured duration.
    import asyncio

    asyncio.get_event_loop().create_task(
        schedule_ad_break_end(session_id, payload["duration_seconds"])
    )

    return AdBreakOut(
        ok=True,
        duration_seconds=payload["duration_seconds"],
        started_at=payload["started_at"],
        skip_after_seconds=payload["skip_after_seconds"],
    )


@router.post("/sessions/{session_id}/ad-break/end")
def end_ad_break_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Broadcaster manually ends an ad break early."""
    session = get_session(session_id)
    if session.created_by != ctx["user_sub"] and ctx.get("role") not in {Role.ADMIN, Role.ROOT}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_BROADCASTER", "detail": "Only the broadcaster can end ad breaks"},
        )
    end_ad_break(session_id, ended_by="manual")
    return {"ok": True}


# ─── Ad event tracking ───────────────────────────────────────────────


@router.post("/sessions/{session_id}/ads/{creative_id}/track", response_model=AdEventOut)
def track_ad_event_route(
    session_id: str,
    creative_id: str,
    event: str = Query(default="impression"),
    slot_type: str = Query(default=""),
    ctx: dict = Depends(_ctx),
):
    """Record an ad event (impression/skip/complete/click) for a broadcast creative."""
    result = record_ad_event(
        session_id=session_id,
        creative_id=creative_id,
        user_id=ctx["user_sub"],
        event_type=event,
        slot_type=slot_type,
    )
    return AdEventOut(**result)
