from __future__ import annotations

import asyncio
import json
import time
from typing import Annotated, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.services.broadcast_store import (
    create_profile,
    create_session,
    get_session,
    get_output,
    list_profiles_by_creator,
    list_sessions_by_creator,
    list_sessions_by_status,
    transition_session_status,
    list_scheduled_sessions_by_creator,
    list_upcoming_sessions,
    update_session_fields,
)
from app.services.broadcast_recording import (
    get_recording_by_session,
    mint_recording_playback_url,
    mint_recording_thumbnail_url,
    mint_recording_download_url,
)
from app.services.broadcast_audit import query_broadcast_actions, record_broadcast_action
from app.services.broadcast_orchestrator import (
    delete_session_with_provider,
    start_session_with_provider,
    stop_session_with_provider,
)
from app.services.broadcast_cloudfront import validate_cloudfront_token
from app.services.broadcast_playback import mint_local_playback_url
from app.services.broadcast_sse import broadcast_sse_subscribe, broadcast_sse_unsubscribe, broadcast_sse_publish
from app.services.broadcast_qa import (
    submit_question as _qa_submit_question,
    feature_question as _qa_feature_question,
    answer_question as _qa_answer_question,
    dismiss_question as _qa_dismiss_question,
    remove_question as _qa_remove_question,
    upvote_question as _qa_upvote_question,
    remove_upvote as _qa_remove_upvote,
    list_questions as _qa_list_questions,
    get_featured_question as _qa_get_featured_question,
    get_qa_stats as _qa_get_qa_stats,
)
from app.services.broadcast_chat_store import (
    send_chat_message as _store_send_chat,
    get_chat_history as _store_get_history,
    fetch_chat_messages_after as _store_fetch_after,
    delete_chat_message as _store_delete_msg,
    get_mute_status as _store_get_mute,
    set_mute as _store_set_mute,
    _chat_msg_out,
)
from app.services.broadcast_viewers import (
    register_viewer,
    touch_viewer,
    unregister_viewer,
    get_viewer_count as _get_viewer_count,
)
from app.services.broadcast_health import (
    store_health_snapshot,
    get_latest_health,
    get_health_history,
)
from app.services.sessions import require_ui_session
from app.models import BroadcastPriceSetIn, BroadcastPriceOut
from app.metrics import record_broadcast_output_error

router = APIRouter(prefix="/broadcast", tags=["broadcast"])


class BroadcastProfileCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    region: str = Field(..., min_length=1, max_length=32)
    rendition_preset: str = Field(..., min_length=1, max_length=64)
    watermark_asset: Optional[str] = Field(default=None, max_length=512)
    drm_policy_id: Optional[str] = Field(default=None, max_length=256)
    drm_credentials_ref: Optional[str] = Field(default=None, max_length=2048)
    drm_credentials_last_rotated_at: Optional[str] = None
    drm_credentials_rotation_interval_seconds: int = Field(default=86400, ge=60)


class BroadcastProfileOut(BaseModel):
    id: str
    name: str
    region: str
    rendition_preset: str
    watermark_asset: Optional[str] = None
    drm_policy_id: Optional[str] = None
    drm_credentials_ref: Optional[str] = None
    drm_credentials_last_rotated_at: Optional[str] = None
    drm_credentials_rotation_interval_seconds: int = 86400
    created_by: str
    created_at: str
    updated_at: str


class BroadcastSessionCreateIn(BaseModel):
    profile_id: str = Field(..., min_length=1)
    ingest_url: Optional[str] = Field(default=None, max_length=1024)
    stream_key_ref: Optional[str] = Field(default=None, max_length=512)
    stream_key_last_rotated_at: Optional[str] = None
    stream_key_rotation_interval_seconds: int = Field(default=86400, ge=60)


class BroadcastSessionActionIn(BaseModel):
    reason: str = Field(default="operator-request", min_length=1, max_length=512)


class BroadcastSessionOut(BaseModel):
    id: str
    profile_id: str
    status: str
    ingest_url: Optional[str] = None
    stream_key_ref: Optional[str] = None
    stream_key_last_rotated_at: Optional[str] = None
    stream_key_rotation_interval_seconds: int = 86400
    started_at: Optional[str] = None
    stopped_at: Optional[str] = None
    created_by: str
    created_at: str
    updated_at: str
    mediapackage_endpoint: Optional[str] = None
    cloudfront_playback_url: Optional[str] = None
    s3_archive_prefix: Optional[str] = None
    aws_input_arn: Optional[str] = None
    aws_channel_arn: Optional[str] = None
    provider_state_snapshot: dict = Field(default_factory=dict)
    # Scheduling fields (BCAST-009)
    scheduled_at: Optional[int] = None
    schedule_status: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    thumbnail_url: Optional[str] = None
    cancelled_at: Optional[str] = None
    announcement_post_id: Optional[str] = None
    # Tipping fields (BCAST-013)
    tip_total_cents: int = 0
    tip_count: int = 0
    tip_enabled: bool = True
    tip_min_cents: int = 100
    tip_max_cents: int = 100000
    # Viewer Clip Creation (ENGAGE-005)
    clips_enabled: bool = True


class BroadcastScheduleIn(BaseModel):
    scheduled_at: int = Field(..., description="Unix timestamp >= min lead time from now")
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)


class BroadcastRescheduleIn(BaseModel):
    scheduled_at: int = Field(..., description="New Unix timestamp, >= min lead time from now")


class BroadcastScheduledListOut(BaseModel):
    items: List[BroadcastSessionOut] = Field(default_factory=list)
    count: int = 0


class BroadcastDeleteOut(BaseModel):
    ok: bool


class BroadcastPlaybackUrlOut(BaseModel):
    session_id: str
    playback_url: str
    expires_at: int


class BroadcastAuditOut(BaseModel):
    audit_id: str
    action: str
    actor: str
    correlation_id: str
    resource_type: str
    resource_id: str
    created_at: str
    metadata: dict = Field(default_factory=dict)


class BroadcastAuditListOut(BaseModel):
    items: List[BroadcastAuditOut] = Field(default_factory=list)


class BroadcastPlaybackTokenVerifyOut(BaseModel):
    valid: bool


class BroadcastSessionListOut(BaseModel):
    items: List[BroadcastSessionOut] = Field(default_factory=list)
    has_more: bool = False


class BroadcastProfileListOut(BaseModel):
    items: List[BroadcastProfileOut] = Field(default_factory=list)


def _ctx(ctx=Depends(require_ui_session)):
    return ctx


def _require_operator_role(ctx: dict) -> None:
    if ctx.get("role") not in {"admin", "root"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "BROADCAST_ROLE_FORBIDDEN", "detail": "admin or root role required"},
        )


def _correlation_id(request: Request) -> str:
    cid = request.headers.get("x-correlation-id", "").strip()
    return cid or str(uuid4())


def _to_session_out(session) -> BroadcastSessionOut:
    output = get_output(session.id)
    payload = session.model_dump()
    if output:
        payload.update(
            {
                "mediapackage_endpoint": output.mediapackage_endpoint,
                "cloudfront_playback_url": output.cloudfront_playback_url,
                "s3_archive_prefix": output.s3_archive_prefix,
                "aws_input_arn": output.aws_input_arn,
                "aws_channel_arn": output.aws_channel_arn,
                "provider_state_snapshot": output.provider_state_snapshot or {},
            }
        )
    return BroadcastSessionOut(**payload)


@router.post("/profiles", response_model=BroadcastProfileOut, status_code=status.HTTP_201_CREATED)
def create_profile_route(body: BroadcastProfileCreateIn, request: Request, ctx: dict = Depends(_ctx)):
    profile = create_profile(
        name=body.name,
        region=body.region,
        rendition_preset=body.rendition_preset,
        created_by=ctx["user_sub"],
        watermark_asset=body.watermark_asset,
        drm_policy_id=body.drm_policy_id,
        drm_credentials_ref=body.drm_credentials_ref,
        drm_credentials_last_rotated_at=body.drm_credentials_last_rotated_at,
        drm_credentials_rotation_interval_seconds=body.drm_credentials_rotation_interval_seconds,
    )
    record_broadcast_action(
        action="create_profile",
        actor=ctx["user_sub"],
        correlation_id=_correlation_id(request),
        resource_type="profile",
        resource_id=profile.id,
        metadata={"drm_credentials_ref": profile.drm_credentials_ref},
    )
    return BroadcastProfileOut(**profile.model_dump())


@router.post("/sessions", response_model=BroadcastSessionOut, status_code=status.HTTP_201_CREATED)
def create_session_route(body: BroadcastSessionCreateIn, request: Request, ctx: dict = Depends(_ctx)):
    session = create_session(
        profile_id=body.profile_id,
        created_by=ctx["user_sub"],
        ingest_url=body.ingest_url,
        stream_key_ref=body.stream_key_ref,
        stream_key_last_rotated_at=body.stream_key_last_rotated_at,
        stream_key_rotation_interval_seconds=body.stream_key_rotation_interval_seconds,
    )
    record_broadcast_action(
        action="create_session",
        actor=ctx["user_sub"],
        correlation_id=_correlation_id(request),
        resource_type="session",
        resource_id=session.id,
        metadata={"stream_key_ref": session.stream_key_ref},
    )
    return _to_session_out(session)


@router.get("/sessions", response_model=BroadcastSessionListOut)
def list_sessions_route(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: dict = Depends(_ctx),
):
    if status_filter:
        result = list_sessions_by_status(status_filter, limit=limit)
    else:
        result = list_sessions_by_creator(ctx["user_sub"], limit=limit)
    items = [_to_session_out(s) for s in result["items"]]
    return BroadcastSessionListOut(items=items, has_more=bool(result.get("cursor")))


@router.get("/sessions/scheduled", response_model=BroadcastScheduledListOut)
def list_scheduled_sessions_route(
    limit: int = Query(default=50, ge=1, le=200),
    ctx: dict = Depends(_ctx),
):
    """List the caller's scheduled broadcasts."""
    items = list_scheduled_sessions_by_creator(ctx["user_sub"], limit=limit)
    out_items = [_to_session_out(s) for s in items]
    return BroadcastScheduledListOut(items=out_items, count=len(out_items))


@router.get("/sessions/upcoming", response_model=BroadcastScheduledListOut)
def list_upcoming_sessions_route(
    limit: int = Query(default=50, ge=1, le=200),
    ctx: dict = Depends(_ctx),
):
    """List all upcoming scheduled broadcasts (global viewer-discovery feed).

    Returns sessions across all creators whose scheduled_at is still in the
    future, soonest-first. Visible to any authenticated user.
    """
    _ = ctx
    from app.core.time import now_ts
    items = list_upcoming_sessions(now=now_ts(), limit=limit)
    out_items = [_to_session_out(s) for s in items]
    return BroadcastScheduledListOut(items=out_items, count=len(out_items))


@router.get("/profiles", response_model=BroadcastProfileListOut)
def list_profiles_route(
    limit: int = Query(default=200, ge=1, le=200),
    ctx: dict = Depends(_ctx),
):
    profiles = list_profiles_by_creator(ctx["user_sub"], limit=limit)
    return BroadcastProfileListOut(items=[BroadcastProfileOut(**p.model_dump()) for p in profiles])


@router.post("/sessions/{session_id}/start", response_model=BroadcastSessionOut, status_code=status.HTTP_202_ACCEPTED)
def start_session_route(
    session_id: str,
    body: BroadcastSessionActionIn,
    request: Request,
    x_correlation_id: Annotated[Optional[str], Header(alias="x-correlation-id")] = None,
    x_idempotency_key: Annotated[Optional[str], Header(alias="x-idempotency-key")] = None,
    ctx: dict = Depends(_ctx),
):
    _require_operator_role(ctx)
    cid = (x_correlation_id or "").strip() or _correlation_id(request)
    idem = (x_idempotency_key or "").strip() or request.headers.get("x-idempotency-key", "").strip()
    try:
        current = start_session_with_provider(
            session_id=session_id,
            actor=ctx["user_sub"],
            reason=body.reason,
            correlation_id=cid,
            idempotency_key=idem,
        )
    except Exception as exc:
        record_broadcast_action(
            action="start_session_failed",
            actor=ctx["user_sub"],
            correlation_id=cid,
            resource_type="session",
            resource_id=session_id,
            metadata={"reason": body.reason, "error": type(exc).__name__},
        )
        raise

    record_broadcast_action(
        action="start_session",
        actor=ctx["user_sub"],
        correlation_id=cid,
        resource_type="session",
        resource_id=session_id,
        metadata={"reason": body.reason},
    )
    return _to_session_out(current)


@router.post("/sessions/{session_id}/stop", response_model=BroadcastSessionOut, status_code=status.HTTP_202_ACCEPTED)
def stop_session_route(
    session_id: str,
    body: BroadcastSessionActionIn,
    request: Request,
    x_correlation_id: Annotated[Optional[str], Header(alias="x-correlation-id")] = None,
    x_idempotency_key: Annotated[Optional[str], Header(alias="x-idempotency-key")] = None,
    ctx: dict = Depends(_ctx),
):
    _require_operator_role(ctx)
    cid = (x_correlation_id or "").strip() or _correlation_id(request)
    idem = (x_idempotency_key or "").strip() or request.headers.get("x-idempotency-key", "").strip()
    try:
        current = stop_session_with_provider(
            session_id=session_id,
            actor=ctx["user_sub"],
            reason=body.reason,
            correlation_id=cid,
            idempotency_key=idem,
        )
    except Exception as exc:
        record_broadcast_action(
            action="stop_session_failed",
            actor=ctx["user_sub"],
            correlation_id=cid,
            resource_type="session",
            resource_id=session_id,
            metadata={"reason": body.reason, "error": type(exc).__name__},
        )
        raise
    record_broadcast_action(
        action="stop_session",
        actor=ctx["user_sub"],
        correlation_id=cid,
        resource_type="session",
        resource_id=session_id,
        metadata={"reason": body.reason},
    )
    # Auto-sync any promoted newsfeed post to the now-ended status (best-effort).
    try:
        from app.services import broadcast_newsfeed_promo as _promo
        if _promo.get_link(session_id) is not None:
            _promo.sync(session_id)
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "promo auto-sync on stop failed for %s", session_id, exc_info=True
        )
    return _to_session_out(current)


@router.delete("/sessions/{session_id}", response_model=BroadcastDeleteOut)
def delete_session_route(session_id: str, request: Request, ctx: dict = Depends(_ctx)):
    _require_operator_role(ctx)
    cid = _correlation_id(request)
    try:
        out = delete_session_with_provider(session_id=session_id)
    except Exception as exc:
        record_broadcast_action(
            action="delete_session_failed",
            actor=ctx["user_sub"],
            correlation_id=cid,
            resource_type="session",
            resource_id=session_id,
            metadata={"error": type(exc).__name__},
        )
        raise
    record_broadcast_action(
        action="delete_session",
        actor=ctx["user_sub"],
        correlation_id=cid,
        resource_type="session",
        resource_id=session_id,
        metadata={},
    )
    return BroadcastDeleteOut(**out)


@router.get("/sessions/{session_id}", response_model=BroadcastSessionOut)
def get_session_route(session_id: str, request: Request, ctx: dict = Depends(_ctx)):
    session = get_session(session_id)
    # Geo-check: non-owners are subject to geo-blocking
    if session.created_by != ctx["user_sub"]:
        from app.services.geo_check import check_geo_access
        from app.core.tables import T as _T
        raw = _T.broadcast_sessions.get_item(Key={"session_id": session_id}).get("Item", {})
        check_geo_access(request, raw.get("geo_mode"), raw.get("geo_countries"))
    return _to_session_out(session)


@router.post("/sessions/{session_id}/playback-url", response_model=BroadcastPlaybackUrlOut)
def mint_playback_url_route(
    session_id: str,
    invite_token: Optional[str] = Query(default=None),
    ctx: dict = Depends(_ctx),
):
    session = get_session(session_id)
    # Go-Private playback gating (BCAST-011)
    from app.services.broadcast_privacy import check_viewer_access
    check_viewer_access(
        session_id,
        ctx["user_sub"],
        creator_id=session.created_by,
        visibility=session.broadcast_privacy_visibility,
        invite_token=invite_token,
    )
    existing = get_output(session_id)
    try:
        minted = mint_local_playback_url(session.id)
    except ValueError as exc:
        record_broadcast_output_error(provider="local", reason="invalid_stream_key")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "BROADCAST_INVALID_STREAM_KEY", "detail": str(exc)},
        ) from exc
    playback_url = existing.cloudfront_playback_url if existing and existing.cloudfront_playback_url else minted.url
    return BroadcastPlaybackUrlOut(session_id=session.id, playback_url=playback_url, expires_at=minted.expires_at)


@router.get("/playback/verify", response_model=BroadcastPlaybackTokenVerifyOut)
def verify_playback_token_route(path: str, cf_token: str, cf_expires: int, ctx: dict = Depends(_ctx)):
    _ = ctx
    valid = validate_cloudfront_token(path=path, token=cf_token, expires_at=cf_expires)
    if not valid:
        record_broadcast_output_error(provider="aws", reason="invalid_playback_token")
        raise HTTPException(status_code=403, detail={"code": "BROADCAST_PLAYBACK_TOKEN_INVALID", "detail": "invalid playback token"})
    return BroadcastPlaybackTokenVerifyOut(valid=True)


@router.get("/admin/audit", response_model=BroadcastAuditListOut)
def query_audit_route(
    actor: Optional[str] = Query(default=None),
    created_from: Optional[str] = Query(default=None),
    created_to: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: dict = Depends(_ctx),
):
    _require_operator_role(ctx)
    items = query_broadcast_actions(
        actor=actor,
        created_from=created_from,
        created_to=created_to,
        limit=limit,
    )
    return BroadcastAuditListOut(items=[BroadcastAuditOut(**i.model_dump()) for i in items])


# ─── Viewer Count Endpoints ─────────────────────────────────────────


class ViewerJoinOut(BaseModel):
    viewer_id: str
    session_id: str
    viewer_count: int


class ViewerHeartbeatOut(BaseModel):
    ok: bool
    viewer_count: int


class ViewerCountOut(BaseModel):
    session_id: str
    viewer_count: int


@router.post("/sessions/{session_id}/viewers/join", response_model=ViewerJoinOut)
def viewer_join_route(
    session_id: str,
    request: Request,
    invite_token: Optional[str] = Query(default=None),
    ctx: dict = Depends(_ctx),
):
    """Register as a viewer. Called when playback begins."""
    from app.core.tables import T as _T
    session = get_session(session_id)  # 404 if session doesn't exist
    # Geo-check for viewers
    if session.created_by != ctx["user_sub"]:
        from app.services.geo_check import check_geo_access
        raw = _T.broadcast_sessions.get_item(Key={"session_id": session_id}).get("Item", {})
        check_geo_access(request, raw.get("geo_mode"), raw.get("geo_countries"))
    # Go-Private access gating (BCAST-011)
    from app.services.broadcast_privacy import check_viewer_access
    check_viewer_access(
        session_id,
        ctx["user_sub"],
        creator_id=session.created_by,
        visibility=session.broadcast_privacy_visibility,
        invite_token=invite_token,
    )
    result = register_viewer(session_id, ctx["user_sub"])
    return ViewerJoinOut(**result)


@router.post("/sessions/{session_id}/viewers/heartbeat", response_model=ViewerHeartbeatOut)
def viewer_heartbeat_route(
    session_id: str,
    viewer_id: str = Query(...),
    ctx: dict = Depends(_ctx),
):
    """Heartbeat to keep viewer session alive. Call every 30s."""
    _ = ctx
    count = touch_viewer(session_id, viewer_id)
    return ViewerHeartbeatOut(ok=True, viewer_count=count)


@router.post("/sessions/{session_id}/viewers/leave")
def viewer_leave_route(
    session_id: str,
    viewer_id: str = Query(...),
    ctx: dict = Depends(_ctx),
):
    """Explicit leave signal. Called on page unload via sendBeacon."""
    _ = ctx
    count = unregister_viewer(session_id, viewer_id)
    return {"ok": True, "viewer_count": count}


@router.get("/sessions/{session_id}/viewers/count", response_model=ViewerCountOut)
def viewer_count_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Get current viewer count for a session."""
    _ = ctx
    count = _get_viewer_count(session_id)
    return ViewerCountOut(session_id=session_id, viewer_count=count)


# ─── Health Metrics Endpoints ────────────────────────────────────────


class BroadcastHealthReportIn(BaseModel):
    ingest_bitrate_kbps: int = Field(ge=0, le=100_000)
    ingest_framerate: float = Field(ge=0, le=240)
    dropped_frames: int = Field(ge=0)
    dropped_frames_pct: float = Field(ge=0, le=100)
    output_errors: int = Field(ge=0, default=0)
    input_loss_seconds: float = Field(ge=0, default=0)


class BroadcastHealthOut(BaseModel):
    session_id: str
    viewer_count: int
    ingest_bitrate_kbps: int
    ingest_framerate: float
    dropped_frames: int
    dropped_frames_pct: float
    connection_quality: str
    output_errors: int
    input_loss_seconds: float
    updated_at: int


class BroadcastHealthHistoryOut(BaseModel):
    session_id: str
    snapshots: List[BroadcastHealthOut] = Field(default_factory=list)


@router.post("/sessions/{session_id}/health/report", response_model=BroadcastHealthOut)
def report_session_health_route(
    session_id: str,
    body: BroadcastHealthReportIn,
    ctx: dict = Depends(_ctx),
):
    """Accept health metrics from the broadcaster client or ingest probe."""
    _ = ctx
    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "BROADCAST_NOT_LIVE", "detail": "session is not live"},
        )
    result = store_health_snapshot(
        session_id,
        ingest_bitrate_kbps=body.ingest_bitrate_kbps,
        ingest_framerate=body.ingest_framerate,
        dropped_frames=body.dropped_frames,
        dropped_frames_pct=body.dropped_frames_pct,
        output_errors=body.output_errors,
        input_loss_seconds=body.input_loss_seconds,
    )
    return BroadcastHealthOut(**result)


@router.get("/sessions/{session_id}/health", response_model=BroadcastHealthOut)
def get_session_health_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Get current health metrics for a live session."""
    _ = ctx
    latest = get_latest_health(session_id)
    if latest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "BROADCAST_NO_HEALTH_DATA", "detail": "no health data for session"},
        )
    return BroadcastHealthOut(**latest)


@router.get("/sessions/{session_id}/health/history", response_model=BroadcastHealthHistoryOut)
def get_session_health_history_route(
    session_id: str,
    from_ts: Optional[int] = Query(default=None),
    to_ts: Optional[int] = Query(default=None),
    limit: int = Query(default=60, ge=1, le=360),
    ctx: dict = Depends(_ctx),
):
    """Get health metric history (for charts)."""
    _ = ctx
    snapshots = get_health_history(session_id, from_ts=from_ts, to_ts=to_ts, limit=limit)
    return BroadcastHealthHistoryOut(
        session_id=session_id,
        snapshots=[BroadcastHealthOut(**s) for s in snapshots],
    )


# ─── SSE Stream Endpoint ────────────────────────────────────────────


@router.get("/sessions/{session_id}/stream")
async def broadcast_event_stream_route(session_id: str, ctx: dict = Depends(_ctx)):
    """SSE stream for real-time broadcast events (viewer count, health updates)."""
    _ = ctx
    _ = get_session(session_id)  # 404 if session doesn't exist
    q = broadcast_sse_subscribe(session_id)

    async def gen():
        try:
            yield "event: hello\ndata: {}\n\n"
            while True:
                try:
                    item = await asyncio.wait_for(q.get(), timeout=15.0)
                    event_type = item.pop("_type", "update")
                    yield f"event: {event_type}\ndata: {json.dumps(item, separators=(',', ':'), default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            broadcast_sse_unsubscribe(session_id, q)

    return StreamingResponse(gen(), media_type="text/event-stream")


# ─── Recording Endpoint (BCAST-006) ─────────────────────────────


class BroadcastRecordingOut(BaseModel):
    recording_id: str
    session_id: str
    status: str
    duration_seconds: Optional[float] = None
    playback_url: Optional[str] = None
    playback_expires_at: Optional[int] = None
    thumbnail_url: Optional[str] = None
    segment_count: Optional[int] = None
    total_bytes: Optional[int] = None
    renditions: list = Field(default_factory=list)
    created_at: int
    completed_at: Optional[int] = None
    expires_at: Optional[int] = None
    # Download fields (BCAST-008)
    allow_download: bool = True
    allow_viewer_download: bool = False
    download_available: bool = False
    mp4_size_bytes: Optional[int] = None


class BroadcastRecordingDownloadOut(BaseModel):
    download_url: str
    download_expires_at: int
    file_size_bytes: int
    filename: str
    content_type: str = "video/mp4"


class BroadcastRecordingDownloadSettingsIn(BaseModel):
    allow_viewer_download: bool


@router.get("/sessions/{session_id}/recording", response_model=BroadcastRecordingOut)
def get_recording_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Get the recording for a broadcast session."""
    _ = ctx
    recording = get_recording_by_session(session_id)
    if not recording:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "BROADCAST_RECORDING_NOT_FOUND", "detail": "No recording found for this session"},
        )
    if recording.status == "expired":
        raise HTTPException(
            status_code=410,
            detail={"code": "BROADCAST_RECORDING_EXPIRED", "detail": "Recording has expired"},
        )
    if recording.status not in ("ready",):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=202,
            content={
                "code": "BROADCAST_RECORDING_PROCESSING",
                "detail": "Recording is still being processed",
                "recording_id": recording.recording_id,
                "session_id": recording.session_id,
                "status": recording.status,
                "created_at": recording.created_at,
            },
        )
    # Mint signed playback URL
    playback = mint_recording_playback_url(recording)
    thumbnail_url = mint_recording_thumbnail_url(recording)
    return BroadcastRecordingOut(
        recording_id=recording.recording_id,
        session_id=recording.session_id,
        status=recording.status,
        duration_seconds=recording.duration_seconds,
        playback_url=playback["playback_url"],
        playback_expires_at=playback["playback_expires_at"],
        thumbnail_url=thumbnail_url,
        segment_count=recording.segment_count,
        total_bytes=recording.total_bytes,
        renditions=recording.renditions,
        created_at=recording.created_at,
        completed_at=recording.completed_at if recording.completed_at else None,
        expires_at=recording.expires_at if recording.expires_at else None,
        # Download fields (BCAST-008)
        allow_download=recording.allow_download,
        allow_viewer_download=recording.allow_viewer_download,
        download_available=bool(recording.mp4_s3_key and recording.status == "ready"),
        mp4_size_bytes=recording.mp4_size_bytes if recording.mp4_s3_key else None,
    )


# ─── Recording Download Endpoints (BCAST-008) ────────────────────


@router.get("/sessions/{session_id}/recording/download", response_model=BroadcastRecordingDownloadOut)
def download_recording_route(
    session_id: str,
    viewer: bool = False,
    ctx: dict = Depends(_ctx),
):
    """Generate a presigned download URL for the recording MP4."""
    from app.core.settings import S as _S
    if not _S.broadcast_recording_download_enabled:
        raise HTTPException(
            status_code=503,
            detail={"code": "BROADCAST_RECORDING_DOWNLOAD_DISABLED", "detail": "Download feature is disabled"},
        )

    recording = get_recording_by_session(session_id)
    if not recording:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "BROADCAST_RECORDING_NOT_FOUND", "detail": "No recording found for this session"},
        )
    if recording.status == "expired":
        raise HTTPException(
            status_code=410,
            detail={"code": "BROADCAST_RECORDING_EXPIRED", "detail": "Recording has expired"},
        )
    if recording.status != "ready":
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=202,
            content={"code": "BROADCAST_RECORDING_PROCESSING", "detail": "Recording is still being processed"},
        )
    if not recording.mp4_s3_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "BROADCAST_RECORDING_MP4_NOT_AVAILABLE", "detail": "MP4 file has not been generated for this recording"},
        )

    # Permission check
    user_sub = ctx["user_sub"]
    if viewer:
        if not recording.allow_viewer_download:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "BROADCAST_RECORDING_DOWNLOAD_FORBIDDEN", "detail": "Broadcaster has not enabled viewer downloads"},
            )
    else:
        # Broadcaster download: verify the requester is the owner
        if user_sub != recording.created_by:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "BROADCAST_RECORDING_DOWNLOAD_FORBIDDEN", "detail": "Only the broadcaster can download this recording"},
            )

    # Mint presigned URL
    download = mint_recording_download_url(recording)
    return BroadcastRecordingDownloadOut(**download)


@router.patch("/sessions/{session_id}/recording/download-settings")
def update_download_settings_route(
    session_id: str,
    body: BroadcastRecordingDownloadSettingsIn,
    ctx: dict = Depends(_ctx),
):
    """Toggle viewer download permission for a recording."""
    from app.services.broadcast_recording import update_recording_status
    recording = get_recording_by_session(session_id)
    if not recording:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "BROADCAST_RECORDING_NOT_FOUND", "detail": "No recording found for this session"},
        )
    if ctx["user_sub"] != recording.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "FORBIDDEN", "detail": "Only the broadcaster can modify settings"},
        )

    update_recording_status(
        recording.recording_id,
        recording.status,
        allow_viewer_download=body.allow_viewer_download,
    )
    return {"ok": True, "allow_viewer_download": body.allow_viewer_download}


# ─── Go-Private Endpoints (BCAST-011) ───────────────────────────


class PrivateRequestIn(BaseModel):
    rate_per_minute_cents: int = Field(..., ge=100, le=10000)
    payment_method_id: str = Field(..., min_length=1, max_length=128)
    max_duration_minutes: int = Field(default=60, ge=5, le=120)


class PrivateRequestOut(BaseModel):
    request_id: str
    private_session_id: str
    session_id: str
    viewer_id: str
    viewer_display_name: str = ""
    rate_per_minute_cents: int
    status: str
    behavior: Optional[str] = None
    call_id: Optional[str] = None
    max_duration_minutes: int = 60
    requested_at: int
    accepted_at: Optional[int] = None
    started_at: Optional[int] = None
    ended_at: Optional[int] = None
    ended_by: Optional[str] = None
    total_billed_cents: int = 0


class PrivateRequestListOut(BaseModel):
    requests: List[PrivateRequestOut] = Field(default_factory=list)


class PrivateRequestAcceptIn(BaseModel):
    behavior: str = Field(..., pattern="^(pause|end|continue)$")


class PrivateAcceptOut(BaseModel):
    private_session_id: str
    session_id: str
    status: str
    behavior: str
    call_id: str
    rate_per_minute_cents: int


class PrivateSessionEndOut(BaseModel):
    private_session_id: str
    session_id: str
    status: str
    duration_seconds: int
    total_billed_cents: int
    ended_by: str


@router.post(
    "/sessions/{session_id}/private/request",
    response_model=PrivateRequestOut,
    status_code=status.HTTP_201_CREATED,
)
def submit_private_request_route(
    session_id: str,
    body: PrivateRequestIn,
    ctx: dict = Depends(_ctx),
):
    """Viewer requests a private 1-on-1 session with the broadcaster."""
    from app.services.broadcast_private import create_private_request
    from app.core.tables import T as _T

    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(
            status_code=403,
            detail="Private requests are only available during live broadcasts.",
        )

    viewer_id = ctx["user_sub"]
    if viewer_id == session.created_by:
        raise HTTPException(
            status_code=403,
            detail="Cannot request a private session on your own broadcast.",
        )

    # Validate payment method
    pm_item = _T.billing.get_item(
        Key={"pk": f"USER#{viewer_id}", "sk": f"PM#{body.payment_method_id}"}
    ).get("Item")
    if not pm_item:
        raise HTTPException(status_code=400, detail="Payment method not found.")

    # Resolve display name
    display_name = viewer_id
    try:
        profile_item = _T.profile.get_item(Key={"user_sub": viewer_id}).get("Item")
        if profile_item and profile_item.get("display_name"):
            display_name = profile_item["display_name"]
    except Exception:
        pass

    min_rate = session.private_min_rate_cents or 100

    result = create_private_request(
        session_id=session_id,
        viewer_id=viewer_id,
        viewer_display_name=display_name,
        rate_per_minute_cents=body.rate_per_minute_cents,
        payment_method_id=body.payment_method_id,
        max_duration_minutes=body.max_duration_minutes,
        min_rate_cents=min_rate,
    )

    # SSE: notify creator
    broadcast_sse_publish(session_id, {
        "_type": "private:request",
        "viewer_id": viewer_id,
        "viewer_display_name": display_name,
        "rate_per_minute_cents": body.rate_per_minute_cents,
        "request_id": result["private_session_id"],
    })

    return PrivateRequestOut(**result)


@router.get(
    "/sessions/{session_id}/private/requests",
    response_model=PrivateRequestListOut,
)
def list_private_requests_route(
    session_id: str,
    ctx: dict = Depends(_ctx),
):
    """List pending private requests (operator/creator only)."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        _require_operator_role(ctx)

    from app.services.broadcast_private import list_pending_requests
    requests = list_pending_requests(session_id)
    return PrivateRequestListOut(requests=[PrivateRequestOut(**r) for r in requests])


@router.post(
    "/sessions/{session_id}/private/{request_id}/accept",
    response_model=PrivateAcceptOut,
)
def accept_private_request_route(
    session_id: str,
    request_id: str,
    body: PrivateRequestAcceptIn,
    request: Request,
    ctx: dict = Depends(_ctx),
):
    """Creator accepts a private session request."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can accept private requests.")

    from app.services.broadcast_private import accept_private_request, get_private_session
    from app.services.messaging_call_sessions import create_call_session

    # Fetch the request to get viewer info
    priv_item = get_private_session(session_id, request_id)
    if not priv_item:
        raise HTTPException(status_code=404, detail="Private request not found.")

    viewer_id = priv_item.get("viewer_id", "")

    # Create WebRTC call record linked to broadcast
    call_id = f"bcast_call_{uuid4().hex}"
    create_call_session(
        call_id=call_id,
        conversation_id=f"bcast_private_{session_id}",
        caller_user_id=session.created_by,
        callee_user_id=viewer_id,
        initial_mode="video",
        state="invited",
        broadcast_session_id=session_id,
    )

    # Accept the private request in DDB
    result = accept_private_request(session_id, request_id, body.behavior, call_id)

    # Transition broadcast to private status
    transition_session_status(
        session_id=session_id,
        to_status="private",
        reason="go_private",
        actor=ctx["user_sub"],
        extra_fields={
            "private_session_id": request_id,
            "private_behavior": body.behavior,
        },
    )

    # Record audit event
    record_broadcast_action(
        action="go_private",
        actor=ctx["user_sub"],
        correlation_id=_correlation_id(request),
        resource_type="session",
        resource_id=session_id,
        metadata={"private_session_id": request_id, "behavior": body.behavior, "viewer_id": viewer_id},
    )

    # SSE events
    broadcast_sse_publish(session_id, {
        "_type": "private:accepted",
        "private_session_id": request_id,
        "behavior": body.behavior,
        "call_id": call_id,
        "viewer_id": viewer_id,
    })
    if body.behavior == "pause":
        broadcast_sse_publish(session_id, {
            "_type": "private:broadcast_paused",
            "session_id": session_id,
            "message": "Creator is in a private session",
        })

    return PrivateAcceptOut(
        private_session_id=request_id,
        session_id=session_id,
        status="accepted",
        behavior=body.behavior,
        call_id=call_id,
        rate_per_minute_cents=result["rate_per_minute_cents"],
    )


@router.post("/sessions/{session_id}/private/{request_id}/decline")
def decline_private_request_route(
    session_id: str,
    request_id: str,
    ctx: dict = Depends(_ctx),
):
    """Creator declines a private session request."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can decline private requests.")

    from app.services.broadcast_private import decline_private_request

    declined = decline_private_request(session_id, request_id)
    if not declined:
        raise HTTPException(status_code=404, detail="Private request not found or not pending.")

    broadcast_sse_publish(session_id, {
        "_type": "private:declined",
        "request_id": request_id,
    })

    return {"ok": True, "request_id": request_id}


@router.post("/sessions/{session_id}/private/{request_id}/cancel")
def cancel_private_request_route(
    session_id: str,
    request_id: str,
    ctx: dict = Depends(_ctx),
):
    """Viewer cancels their own pending private request."""
    from app.services.broadcast_private import cancel_private_request

    cancelled = cancel_private_request(session_id, request_id, ctx["user_sub"])
    if not cancelled:
        raise HTTPException(status_code=404, detail="Request not found, not pending, or not yours.")

    broadcast_sse_publish(session_id, {
        "_type": "private:cancelled",
        "request_id": request_id,
    })

    return {"ok": True, "request_id": request_id}


@router.post(
    "/sessions/{session_id}/private/{private_id}/end",
    response_model=PrivateSessionEndOut,
)
def end_private_session_route(
    session_id: str,
    private_id: str,
    request: Request,
    ctx: dict = Depends(_ctx),
):
    """End an active private session (either party can end)."""
    from app.services.broadcast_private import end_private_session, get_private_session as _get_priv

    session = get_session(session_id)
    priv_item = _get_priv(session_id, private_id)
    if not priv_item:
        raise HTTPException(status_code=404, detail="Private session not found.")

    viewer_id = priv_item.get("viewer_id", "")
    if ctx["user_sub"] not in (session.created_by, viewer_id):
        raise HTTPException(status_code=403, detail="Only the broadcaster or viewer can end the private session.")

    ended_by = "creator" if ctx["user_sub"] == session.created_by else "viewer"

    result = end_private_session(session_id, private_id, ended_by)

    # Clear private_session_id from broadcast session
    update_session_fields(session_id, {"private_session_id": None, "private_behavior": None})

    # Record audit
    record_broadcast_action(
        action="end_private",
        actor=ctx["user_sub"],
        correlation_id=_correlation_id(request),
        resource_type="session",
        resource_id=session_id,
        metadata={"private_session_id": private_id, "ended_by": ended_by, "total_billed_cents": result["total_billed_cents"]},
    )

    # SSE
    broadcast_sse_publish(session_id, {
        "_type": "private:ended",
        "private_session_id": private_id,
        "duration_seconds": result["duration_seconds"],
        "total_billed_cents": result["total_billed_cents"],
    })

    return PrivateSessionEndOut(**result)


@router.get("/sessions/{session_id}/private/status")
def get_private_status_route(
    session_id: str,
    ctx: dict = Depends(_ctx),
):
    """Get current private session status for a broadcast."""
    _ = ctx
    from app.services.broadcast_private import get_private_status
    result = get_private_status(session_id)
    if not result:
        return {"status": "none"}
    return result


@router.post("/sessions/{session_id}/resume", response_model=BroadcastSessionOut)
def resume_broadcast_route(
    session_id: str,
    request: Request,
    ctx: dict = Depends(_ctx),
):
    """Resume broadcast from private mode back to live."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can resume the broadcast.")

    if session.status != "private":
        raise HTTPException(status_code=409, detail="Broadcast is not in private mode.")

    # Check no active private session remains
    from app.services.broadcast_private import get_private_status
    priv_status = get_private_status(session_id)
    if priv_status and priv_status.get("status") in ("active", "accepted"):
        raise HTTPException(status_code=409, detail="Private session is still active. End it first.")

    updated = transition_session_status(
        session_id=session_id,
        to_status="live",
        reason="resume_from_private",
        actor=ctx["user_sub"],
        extra_fields={"private_session_id": None, "private_behavior": None},
    )

    broadcast_sse_publish(session_id, {
        "_type": "private:broadcast_resumed",
        "session_id": session_id,
    })

    return _to_session_out(updated)


# ─── Go-Private Visibility + Allowlist Endpoints (BCAST-011) ─────────


class BroadcastPrivacyVisibilityIn(BaseModel):
    visibility: str = Field(..., pattern="^(public|unlisted|private)$")


class BroadcastPrivacyStateOut(BaseModel):
    session_id: str
    visibility: str
    updated_at: Optional[str] = None
    allowlist_count: int = 0


class BroadcastPrivacyAllowlistEntryIn(BaseModel):
    viewer_id: str = Field(..., min_length=1, max_length=256)


class BroadcastPrivacyAllowlistEntryOut(BaseModel):
    viewer_id: str
    added_by: str = ""
    created_at: int = 0


class BroadcastPrivacyAllowlistOut(BaseModel):
    session_id: str
    entries: List[BroadcastPrivacyAllowlistEntryOut] = Field(default_factory=list)


class BroadcastPrivacyInviteTokenIn(BaseModel):
    max_uses: int = Field(default=1, ge=1, le=10000)


class BroadcastPrivacyInviteTokenOut(BaseModel):
    token: str
    session_id: str
    max_uses: int
    use_count: int = 0
    created_at: int = 0


class BroadcastPrivacyInviteTokenListOut(BaseModel):
    session_id: str
    tokens: List[BroadcastPrivacyInviteTokenOut] = Field(default_factory=list)


def _require_session_owner(session_id: str, ctx: dict):
    """Return the session; raise 403 unless caller is the broadcaster (or operator)."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by and ctx.get("role") not in {"admin", "root"}:
        raise HTTPException(
            status_code=403,
            detail={"code": "BROADCAST_PRIVACY_FORBIDDEN", "detail": "Only the broadcaster can manage privacy."},
        )
    return session


@router.get("/sessions/{session_id}/privacy", response_model=BroadcastPrivacyStateOut)
def get_privacy_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Get current visibility + allowlist size for a session (any authenticated user)."""
    _ = ctx
    from app.services.broadcast_privacy import get_privacy_state
    return BroadcastPrivacyStateOut(**get_privacy_state(session_id))


@router.put("/sessions/{session_id}/privacy", response_model=BroadcastPrivacyStateOut)
def set_privacy_route(
    session_id: str,
    body: BroadcastPrivacyVisibilityIn,
    request: Request,
    ctx: dict = Depends(_ctx),
):
    """Toggle session visibility public/unlisted/private (broadcaster only)."""
    _require_session_owner(session_id, ctx)
    from app.services.broadcast_privacy import set_visibility
    state = set_visibility(session_id, body.visibility)
    record_broadcast_action(
        action="set_visibility",
        actor=ctx["user_sub"],
        correlation_id=_correlation_id(request),
        resource_type="session",
        resource_id=session_id,
        metadata={"visibility": body.visibility},
    )
    broadcast_sse_publish(session_id, {
        "_type": "privacy:visibility_changed",
        "session_id": session_id,
        "visibility": body.visibility,
    })
    return BroadcastPrivacyStateOut(**state)


@router.get("/sessions/{session_id}/privacy/allowlist", response_model=BroadcastPrivacyAllowlistOut)
def list_allowlist_route(session_id: str, ctx: dict = Depends(_ctx)):
    """List allowlisted viewers (broadcaster only)."""
    _require_session_owner(session_id, ctx)
    from app.services.broadcast_privacy import list_allowlist
    entries = list_allowlist(session_id)
    return BroadcastPrivacyAllowlistOut(
        session_id=session_id,
        entries=[BroadcastPrivacyAllowlistEntryOut(**e) for e in entries],
    )


@router.post(
    "/sessions/{session_id}/privacy/allowlist",
    response_model=BroadcastPrivacyAllowlistEntryOut,
    status_code=status.HTTP_201_CREATED,
)
def add_allowlist_route(
    session_id: str,
    body: BroadcastPrivacyAllowlistEntryIn,
    ctx: dict = Depends(_ctx),
):
    """Add a viewer to the allowlist (broadcaster only)."""
    _require_session_owner(session_id, ctx)
    from app.services.broadcast_privacy import add_to_allowlist
    result = add_to_allowlist(session_id, body.viewer_id, added_by=ctx["user_sub"])
    return BroadcastPrivacyAllowlistEntryOut(
        viewer_id=result["viewer_id"], added_by=ctx["user_sub"], created_at=result["created_at"]
    )


@router.delete("/sessions/{session_id}/privacy/allowlist/{viewer_id}")
def remove_allowlist_route(session_id: str, viewer_id: str, ctx: dict = Depends(_ctx)):
    """Remove a viewer from the allowlist (broadcaster only)."""
    _require_session_owner(session_id, ctx)
    from app.services.broadcast_privacy import remove_from_allowlist
    removed = remove_from_allowlist(session_id, viewer_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Viewer not on allowlist.")
    return {"ok": True, "viewer_id": viewer_id}


@router.get("/sessions/{session_id}/privacy/tokens", response_model=BroadcastPrivacyInviteTokenListOut)
def list_invite_tokens_route(session_id: str, ctx: dict = Depends(_ctx)):
    """List invite tokens (broadcaster only)."""
    _require_session_owner(session_id, ctx)
    from app.services.broadcast_privacy import list_invite_tokens
    tokens = list_invite_tokens(session_id)
    return BroadcastPrivacyInviteTokenListOut(
        session_id=session_id,
        tokens=[BroadcastPrivacyInviteTokenOut(session_id=session_id, **t) for t in tokens],
    )


@router.post(
    "/sessions/{session_id}/privacy/tokens",
    response_model=BroadcastPrivacyInviteTokenOut,
    status_code=status.HTTP_201_CREATED,
)
def create_invite_token_route(
    session_id: str,
    body: BroadcastPrivacyInviteTokenIn,
    ctx: dict = Depends(_ctx),
):
    """Mint an invite token granting private access (broadcaster only)."""
    _require_session_owner(session_id, ctx)
    from app.services.broadcast_privacy import create_invite_token
    result = create_invite_token(session_id, created_by=ctx["user_sub"], max_uses=body.max_uses)
    return BroadcastPrivacyInviteTokenOut(**result)


@router.delete("/sessions/{session_id}/privacy/tokens/{token}")
def revoke_invite_token_route(session_id: str, token: str, ctx: dict = Depends(_ctx)):
    """Revoke an invite token (broadcaster only)."""
    _require_session_owner(session_id, ctx)
    from app.services.broadcast_privacy import revoke_invite_token
    revoked = revoke_invite_token(session_id, token)
    if not revoked:
        raise HTTPException(status_code=404, detail="Invite token not found.")
    return {"ok": True, "token": token}


# ─── Live Chat Endpoints (BCAST-005) ─────────────────────────────


class BroadcastChatSendIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=280)
    # Phase B — Replies
    reply_to_message_id: Optional[str] = Field(default=None, max_length=128)
    # Phase C — Expiry (broadcaster-only)
    expires_in_seconds: Optional[int] = Field(default=None, ge=10, le=86400)
    # Phase D — Locked messages (broadcaster-only)
    lock_price_cents: Optional[int] = Field(default=None, ge=1, le=100_000)
    lock_description: Optional[str] = Field(default=None, max_length=200)


class BroadcastChatProductLinkOut(BaseModel):
    item_id: str
    category_id: str
    name: str
    description: Optional[str] = None
    price_cents: int
    currency: str = "USD"
    image_url: Optional[str] = None


class BroadcastChatReactIn(BaseModel):
    emoji: str = Field(min_length=1, max_length=32)
    action: str = Field(default="add", pattern=r"^(add|remove)$")


class BroadcastChatUnlockIn(BaseModel):
    payment_method_id: str = Field(..., min_length=1, max_length=200)


class BroadcastChatMessageOut(BaseModel):
    message_id: str
    session_id: str
    sender_id: str
    sender_display_name: str
    text: Optional[str] = None
    kind: str = "text"
    product_link: Optional[BroadcastChatProductLinkOut] = None
    created_at: int
    deleted: bool = False
    # Tip fields (BCAST-013)
    tip_amount_cents: Optional[int] = None
    tip_currency: Optional[str] = None
    tip_payment_id: Optional[str] = None
    # Phase A — Reactions (BCAST-015)
    reactions_counts: Optional[dict] = None
    my_reactions: Optional[list] = None
    # Phase B — Replies (BCAST-015)
    reply_to_message_id: Optional[str] = None
    reply_to_preview: Optional[dict] = None
    # Phase C — Expiry (BCAST-015)
    expires_at: Optional[int] = None
    expired: bool = False
    # Phase D — Locked (BCAST-015)
    lock_price_cents: Optional[int] = None
    lock_description: Optional[str] = None
    is_unlocked: Optional[bool] = None
    tip_total_cents: Optional[int] = None
    # Lottery field (BCAST-014)
    lottery_id: Optional[str] = None


class BroadcastChatHistoryOut(BaseModel):
    messages: List[BroadcastChatMessageOut] = Field(default_factory=list)
    has_more: bool = False
    oldest_sort_key: Optional[str] = None


class BroadcastChatMuteIn(BaseModel):
    target_user_id: str = Field(..., min_length=1)
    duration_seconds: int = Field(default=300, ge=30, le=86400)


class BroadcastChatMuteOut(BaseModel):
    target_user_id: str
    muted_until: int
    session_id: str


@router.post(
    "/sessions/{session_id}/chat",
    response_model=BroadcastChatMessageOut,
    status_code=status.HTTP_201_CREATED,
)
def send_chat_message_route(session_id: str, body: BroadcastChatSendIn, ctx: dict = Depends(_ctx)):
    """Send a chat message to a live broadcast session."""
    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "BROADCAST_NOT_LIVE", "message": "Chat is only available while the broadcast is live"},
        )

    user_id = ctx["user_sub"]

    # Broadcaster-only features (BCAST-015 Phase C + D)
    if body.expires_in_seconds is not None or body.lock_price_cents is not None:
        if user_id != session.created_by:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "NOT_BROADCASTER", "message": "Only the broadcaster can send special messages"},
            )

    # Resolve display name: use profile display_name if available, otherwise user_sub
    display_name = user_id
    try:
        from app.core.tables import T as _T
        profile_resp = _T.profile.get_item(Key={"user_sub": user_id})
        profile_item = profile_resp.get("Item")
        if profile_item and profile_item.get("display_name"):
            display_name = profile_item["display_name"]
    except Exception:
        pass

    result = _store_send_chat(
        session_id=session_id,
        user_id=user_id,
        display_name=display_name,
        text=body.text,
        reply_to_message_id=body.reply_to_message_id,
        expires_in_seconds=body.expires_in_seconds,
        lock_price_cents=body.lock_price_cents,
        lock_description=body.lock_description,
    )
    return BroadcastChatMessageOut(**{k: v for k, v in result.items() if k != "sort_key"})


@router.get("/sessions/{session_id}/chat", response_model=BroadcastChatHistoryOut)
def get_chat_history_route(
    session_id: str,
    limit: int = Query(default=100, ge=1, le=200),
    before: Optional[str] = Query(default=None),
    ctx: dict = Depends(_ctx),
):
    """Load recent chat history for a broadcast session."""
    _ = get_session(session_id)  # 404 if session doesn't exist
    result = _store_get_history(
        session_id, limit=limit, before_sort_key=before,
        viewer_user_id=ctx["user_sub"],
    )
    return BroadcastChatHistoryOut(
        messages=[BroadcastChatMessageOut(**m) for m in result["messages"]],
        has_more=result["has_more"],
        oldest_sort_key=result["oldest_sort_key"],
    )


@router.delete("/sessions/{session_id}/chat/{message_id}")
def delete_chat_message_route(session_id: str, message_id: str, ctx: dict = Depends(_ctx)):
    """Delete a chat message (broadcaster or admin only)."""
    session = get_session(session_id)
    # Only session creator (broadcaster) or admin/root can delete
    if ctx["user_sub"] != session.created_by:
        _require_operator_role(ctx)

    deleted = _store_delete_msg(session_id, message_id, ctx["user_sub"])
    if not deleted:
        raise HTTPException(status_code=404, detail={"code": "CHAT_MESSAGE_NOT_FOUND", "message": "Message not found"})
    return {"ok": True, "message_id": message_id}


@router.post("/sessions/{session_id}/chat/mute", response_model=BroadcastChatMuteOut)
def mute_chat_user_route(session_id: str, body: BroadcastChatMuteIn, ctx: dict = Depends(_ctx)):
    """Mute a user in broadcast chat (broadcaster or admin only)."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        _require_operator_role(ctx)

    result = _store_set_mute(
        session_id=session_id,
        user_id=body.target_user_id,
        duration_seconds=body.duration_seconds,
        actor=ctx["user_sub"],
    )
    return BroadcastChatMuteOut(**result)


# ─── BCAST-015: Rich Chat Endpoints ────────────────────────────────


@router.post("/sessions/{session_id}/chat/{message_id}/react")
def react_to_chat_message_route(
    session_id: str,
    message_id: str,
    body: BroadcastChatReactIn,
    ctx: dict = Depends(_ctx),
):
    """Add or remove a reaction on a broadcast chat message."""
    _ = get_session(session_id)  # 404 if session doesn't exist
    from app.services.broadcast_chat_rich import react_to_chat_message
    result = react_to_chat_message(
        session_id=session_id,
        message_id=message_id,
        user_id=ctx["user_sub"],
        emoji=body.emoji,
        action=body.action,
    )
    return result


@router.post("/sessions/{session_id}/chat/{message_id}/unlock")
def unlock_chat_message_route(
    session_id: str,
    message_id: str,
    body: BroadcastChatUnlockIn,
    ctx: dict = Depends(_ctx),
):
    """Unlock a locked broadcast chat message by paying the lock price."""
    session = get_session(session_id)
    from app.services.broadcast_chat_rich import unlock_chat_message
    result = unlock_chat_message(
        session_id=session_id,
        message_id=message_id,
        user_id=ctx["user_sub"],
        payment_method_id=body.payment_method_id,
        broadcaster_id=session.created_by,
    )
    return result


class BroadcastChatProductLinkIn(BaseModel):
    item_id: str = Field(..., min_length=1, max_length=128)


@router.post(
    "/sessions/{session_id}/chat/product",
    response_model=BroadcastChatMessageOut,
    status_code=status.HTTP_201_CREATED,
)
def send_chat_product_link_route(
    session_id: str,
    body: BroadcastChatProductLinkIn,
    ctx: dict = Depends(_ctx),
):
    """Share a product link card in broadcast chat (broadcaster only)."""
    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "BROADCAST_NOT_LIVE", "message": "Chat is only available while the broadcast is live"},
        )

    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_SESSION_CREATOR", "message": "Only the broadcaster can share product links"},
        )

    from app.services.broadcast_product_shelf import get_shelf_product_raw, resolve_effective_price
    shelf_item_raw = get_shelf_product_raw(session_id, body.item_id)
    if not shelf_item_raw:
        raise HTTPException(status_code=404, detail="Product not on shelf. Add it to the shelf first.")

    # Resolve current effective price for the product link snapshot (LCOM-004)
    pricing = resolve_effective_price(shelf_item_raw, session.status)
    shelf_item = shelf_item_raw

    user_id = ctx["user_sub"]
    display_name = user_id
    try:
        from app.core.tables import T as _T
        profile_resp = _T.profile.get_item(Key={"user_sub": user_id})
        profile_item = profile_resp.get("Item")
        if profile_item and profile_item.get("display_name"):
            display_name = profile_item["display_name"]
    except Exception:
        pass

    product_link_data = {
        "item_id": shelf_item["item_id"],
        "category_id": shelf_item["category_id"],
        "name": shelf_item["name"],
        "description": shelf_item.get("description", ""),
        "price_cents": int(shelf_item.get("price_cents", 0)),
        "currency": shelf_item.get("currency", "USD"),
        "image_url": shelf_item.get("image_url", ""),
        # Broadcast pricing snapshot (LCOM-004)
        "broadcast_price_cents": int(shelf_item["broadcast_price_cents"]) if shelf_item.get("broadcast_price_cents") is not None else None,
        "broadcast_price_expires_at": int(shelf_item["broadcast_price_expires_at"]) if shelf_item.get("broadcast_price_expires_at") else None,
        "effective_price_cents": pricing["effective_price_cents"],
        "is_broadcast_price": pricing["is_broadcast_price"],
        "discount_pct": pricing["discount_pct"],
    }

    from app.services.broadcast_chat_store import send_product_link_message
    result = send_product_link_message(
        session_id=session_id,
        user_id=user_id,
        display_name=display_name,
        product_link=product_link_data,
    )
    return BroadcastChatMessageOut(**result)


@router.get("/sessions/{session_id}/chat/stream")
async def broadcast_chat_stream_route(
    session_id: str,
    after: Optional[str] = Query(default=None),
    poll_ms: int = Query(default=500, ge=200, le=3000),
    ctx: dict = Depends(_ctx),
):
    """SSE stream for real-time broadcast chat messages."""
    _ = ctx
    session = get_session(session_id)
    if session.status not in ("live", "ready"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "BROADCAST_NOT_LIVE", "message": "Chat stream is only available for live broadcasts"},
        )

    import anyio

    async def gen():
        cursor = after
        last_ping = time.time()
        yield ": stream-open\n\n"

        while True:
            now = time.time()
            if now - last_ping > 15:
                yield ": ping\n\n"
                last_ping = now

            messages = await anyio.to_thread.run_sync(
                lambda: _store_fetch_after(session_id, cursor, 50)
            )
            if messages:
                for msg in messages:
                    sk = msg.get("sort_key", "")
                    cursor = sk
                    # Skip LOTTERY#/LENTRY# config/entry items (BCAST-014)
                    if sk.startswith("LOTTERY#") or sk.startswith("LENTRY#"):
                        continue
                    if msg.get("deleted"):
                        payload = json.dumps({"message_id": msg["message_id"]}, separators=(",", ":"))
                        yield f"event: chat:delete\ndata: {payload}\n\n"
                    else:
                        out = _chat_msg_out(msg)
                        payload = json.dumps(out, separators=(",", ":"), default=str)
                        if out.get("kind") == "product_link":
                            event_type = "chat:product_link"
                        elif out.get("kind") == "tip":
                            event_type = "chat:tip"
                        elif out.get("kind") == "lottery":
                            event_type = "chat:lottery"
                        else:
                            event_type = "chat:message"
                        yield f"event: {event_type}\ndata: {payload}\n\n"
                last_ping = time.time()
                continue

            await asyncio.sleep(poll_ms / 1000.0)

    return StreamingResponse(gen(), media_type="text/event-stream")


# ─── Broadcast Tipping Endpoints (BCAST-013) ──────────────────


class BroadcastChatTipIn(BaseModel):
    """Request body for sending a tip in broadcast chat."""
    amount_cents: int = Field(..., ge=100, le=100000, description="Tip amount in cents.")
    text: str = Field(default="", max_length=280, description="Optional message text.")
    payment_method_id: str = Field(..., min_length=1, max_length=200)
    currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")


class BroadcastTipGoalCreateIn(BaseModel):
    """Request body for creating a tip goal."""
    label: str = Field(..., min_length=1, max_length=200)
    target_cents: int = Field(..., ge=100, le=10000000)
    sort_order: int = Field(default=0, ge=0, le=4)


class BroadcastTipGoalOut(BaseModel):
    """Response model for a tip goal."""
    goal_id: str
    session_id: str
    label: str
    target_cents: int
    current_cents: int = 0
    reached: bool = False
    reached_at: Optional[int] = None
    sort_order: int = 0
    created_at: int


class BroadcastTipGoalsListOut(BaseModel):
    """Response model for listing all goals for a session."""
    goals: List[BroadcastTipGoalOut] = Field(default_factory=list)
    session_id: str


class BroadcastTopTipperItem(BaseModel):
    user_id: str
    display_name: str
    total_cents: int
    tip_count: int


class BroadcastRecentTipItem(BaseModel):
    message_id: str
    sender_id: str
    sender_display_name: str
    amount_cents: int
    text: str
    created_at: int


class BroadcastTipSummaryOut(BaseModel):
    """Tip summary for a broadcast session."""
    session_id: str
    total_cents: int = 0
    tip_count: int = 0
    currency: str = "USD"
    top_tippers: List[BroadcastTopTipperItem] = Field(default_factory=list)
    recent_tips: List[BroadcastRecentTipItem] = Field(default_factory=list)


class BroadcastTipConfigIn(BaseModel):
    """Request body for updating tip configuration."""
    tip_enabled: Optional[bool] = None
    tip_min_cents: Optional[int] = Field(default=None, ge=100, le=100000)
    tip_max_cents: Optional[int] = Field(default=None, ge=100, le=100000)


@router.post(
    "/sessions/{session_id}/chat/tip",
    response_model=BroadcastChatMessageOut,
    status_code=status.HTTP_201_CREATED,
)
def send_tip_message_route(session_id: str, body: BroadcastChatTipIn, ctx: dict = Depends(_ctx)):
    """Send a tip in broadcast chat."""
    from app.services.broadcast_tip_store import send_tip_message

    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "BROADCAST_NOT_LIVE", "message": "Tips are only accepted while the broadcast is live."},
        )
    if not session.tip_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "TIPPING_DISABLED", "message": "Tipping is disabled for this broadcast."},
        )

    user_id = ctx["user_sub"]

    # Resolve display name
    display_name = user_id
    try:
        from app.core.tables import T as _T
        profile_resp = _T.profile.get_item(Key={"user_sub": user_id})
        profile_item = profile_resp.get("Item")
        if profile_item and profile_item.get("display_name"):
            display_name = profile_item["display_name"]
    except Exception:
        pass

    result = send_tip_message(
        session_id=session_id,
        user_id=user_id,
        display_name=display_name,
        amount_cents=body.amount_cents,
        currency=body.currency,
        payment_method_id=body.payment_method_id,
        text=body.text,
        broadcaster_id=session.created_by,
    )
    return BroadcastChatMessageOut(**{k: v for k, v in result.items() if k != "session_tip_total_cents"})


@router.get("/sessions/{session_id}/tips/summary", response_model=BroadcastTipSummaryOut)
def get_tip_summary_route(
    session_id: str,
    top_limit: int = Query(default=10, ge=1, le=50),
    recent_limit: int = Query(default=10, ge=1, le=50),
    ctx: dict = Depends(_ctx),
):
    """Get tip summary for a broadcast session."""
    from app.services.broadcast_tip_store import get_tip_summary

    _ = ctx
    _ = get_session(session_id)  # 404 if not found
    summary = get_tip_summary(session_id, limit=max(top_limit, recent_limit))
    return BroadcastTipSummaryOut(
        session_id=summary["session_id"],
        total_cents=summary["total_cents"],
        tip_count=summary["tip_count"],
        currency=summary["currency"],
        top_tippers=[BroadcastTopTipperItem(**t) for t in summary["top_tippers"][:top_limit]],
        recent_tips=[BroadcastRecentTipItem(**t) for t in summary["recent_tips"][:recent_limit]],
    )


@router.patch("/sessions/{session_id}/tips/config", response_model=BroadcastSessionOut)
def update_tip_config_route(session_id: str, body: BroadcastTipConfigIn, ctx: dict = Depends(_ctx)):
    """Update tipping configuration for a broadcast session (broadcaster only)."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_BROADCASTER", "message": "Only the broadcaster can update tip config."},
        )

    fields = {}
    if body.tip_enabled is not None:
        fields["tip_enabled"] = body.tip_enabled
    if body.tip_min_cents is not None:
        fields["tip_min_cents"] = body.tip_min_cents
    if body.tip_max_cents is not None:
        fields["tip_max_cents"] = body.tip_max_cents

    if not fields:
        return _to_session_out(session)

    # Validate min <= max
    new_min = fields.get("tip_min_cents", session.tip_min_cents)
    new_max = fields.get("tip_max_cents", session.tip_max_cents)
    if new_min > new_max:
        raise HTTPException(400, {"code": "INVALID_TIP_RANGE", "message": "tip_min_cents must be <= tip_max_cents."})

    updated = update_session_fields(session_id, fields)
    return _to_session_out(updated)


@router.post(
    "/sessions/{session_id}/goals",
    response_model=BroadcastTipGoalOut,
    status_code=status.HTTP_201_CREATED,
)
def create_tip_goal_route(session_id: str, body: BroadcastTipGoalCreateIn, ctx: dict = Depends(_ctx)):
    """Create a tip goal for a broadcast session (broadcaster only)."""
    from app.services.broadcast_tip_goals import create_goal

    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_BROADCASTER", "message": "Only the broadcaster can create goals."},
        )
    if session.status not in ("draft", "scheduled", "ready", "live"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "SESSION_NOT_ACTIVE", "message": "Goals can only be set for active sessions."},
        )

    result = create_goal(
        session_id=session_id,
        label=body.label,
        target_cents=body.target_cents,
        sort_order=body.sort_order,
        actor=ctx["user_sub"],
    )
    return BroadcastTipGoalOut(**result)


@router.get("/sessions/{session_id}/goals", response_model=BroadcastTipGoalsListOut)
def list_tip_goals_route(session_id: str, ctx: dict = Depends(_ctx)):
    """List all tip goals for a broadcast session."""
    from app.services.broadcast_tip_goals import list_goals

    _ = ctx
    _ = get_session(session_id)  # 404 if not found
    goals = list_goals(session_id)
    return BroadcastTipGoalsListOut(
        goals=[BroadcastTipGoalOut(**g) for g in goals],
        session_id=session_id,
    )


@router.delete("/sessions/{session_id}/goals/{goal_id}")
def delete_tip_goal_route(session_id: str, goal_id: str, ctx: dict = Depends(_ctx)):
    """Delete a tip goal (broadcaster only)."""
    from app.services.broadcast_tip_goals import delete_goal

    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_BROADCASTER", "message": "Only the broadcaster can delete goals."},
        )

    delete_goal(session_id, goal_id)
    return {"ok": True, "goal_id": goal_id}


# ─── Product Shelf Endpoints (LCOM-001) ────────────────────────


class BroadcastShelfAddIn(BaseModel):
    """Request body for adding a product to the broadcast shelf."""
    item_id: str = Field(..., min_length=1, max_length=128)
    category_id: str = Field(..., min_length=1, max_length=128)
    display_order: int = Field(default=0, ge=0, le=999)


class BroadcastShelfItemOut(BaseModel):
    """A single product on the broadcast shelf (extended with LCOM-004 pricing)."""
    session_id: str
    item_id: str
    category_id: str
    name: str
    description: Optional[str] = None
    price_cents: int
    currency: str = "USD"
    image_url: Optional[str] = None
    display_order: int = 0
    added_by: str
    added_at: int
    # Broadcast pricing fields (LCOM-004)
    broadcast_price_cents: Optional[int] = None
    broadcast_price_expires_at: Optional[int] = None
    broadcast_price_set_at: Optional[int] = None
    effective_price_cents: Optional[int] = None
    is_broadcast_price: bool = False
    discount_pct: int = 0
    original_price_cents: Optional[int] = None


class BroadcastShelfListOut(BaseModel):
    """Response for listing all products on a broadcast shelf."""
    session_id: str
    items: List[BroadcastShelfItemOut] = Field(default_factory=list)
    count: int = 0


class BroadcastShelfReorderIn(BaseModel):
    """Request body for reordering the shelf."""
    item_order: List[str] = Field(..., min_length=1, max_length=50)


@router.post(
    "/sessions/{session_id}/products",
    response_model=BroadcastShelfItemOut,
    status_code=status.HTTP_201_CREATED,
)
def add_shelf_product_route(
    session_id: str,
    body: BroadcastShelfAddIn,
    ctx: dict = Depends(_ctx),
):
    """Add a catalog product to the broadcast product shelf."""
    session = get_session(session_id)

    # Only the broadcaster (session creator) can manage the shelf
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_SESSION_CREATOR", "message": "Only the broadcaster can manage the product shelf"},
        )

    # Session must be in an addable state
    if session.status not in ("draft", "ready", "live"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "SESSION_NOT_ADDABLE", "message": f"Cannot add products when session is {session.status}"},
        )

    # Look up the catalog item to denormalize its data
    from app.routers.catalog import cat_pk, item_sk
    from app.core.tables import T as _T
    cat_item = _T.catalog.get_item(
        Key={"PK": cat_pk(body.category_id), "SK": item_sk(body.item_id)}
    ).get("Item")
    if not cat_item or cat_item.get("entity") != "item":
        raise HTTPException(status_code=404, detail="Catalog item not found.")

    from app.services.broadcast_product_shelf import add_product_to_shelf
    result = add_product_to_shelf(
        session_id=session_id,
        item_id=body.item_id,
        category_id=body.category_id,
        catalog_item=cat_item,
        added_by=ctx["user_sub"],
        display_order=body.display_order,
        is_live=(session.status == "live"),
    )
    return BroadcastShelfItemOut(**result)


@router.delete("/sessions/{session_id}/products/{item_id}")
def remove_shelf_product_route(
    session_id: str,
    item_id: str,
    ctx: dict = Depends(_ctx),
):
    """Remove a product from the broadcast product shelf."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_SESSION_CREATOR", "message": "Only the broadcaster can manage the product shelf"},
        )

    from app.services.broadcast_product_shelf import remove_product_from_shelf
    removed = remove_product_from_shelf(
        session_id=session_id,
        item_id=item_id,
        is_live=(session.status == "live"),
    )
    if not removed:
        raise HTTPException(status_code=404, detail="Product not on shelf.")
    return {"ok": True, "item_id": item_id}


@router.get(
    "/sessions/{session_id}/products",
    response_model=BroadcastShelfListOut,
)
def list_shelf_products_route(
    session_id: str,
    ctx: dict = Depends(_ctx),
):
    """List all products on the broadcast product shelf with resolved pricing."""
    _ = ctx  # any authenticated user can view
    session = get_session(session_id)  # 404 if session doesn't exist

    from app.services.broadcast_product_shelf import list_shelf_products_with_pricing
    items = list_shelf_products_with_pricing(session_id, session.status)
    return BroadcastShelfListOut(
        session_id=session_id,
        items=[BroadcastShelfItemOut(**i) for i in items],
        count=len(items),
    )


@router.patch("/sessions/{session_id}/products/reorder")
def reorder_shelf_products_route(
    session_id: str,
    body: BroadcastShelfReorderIn,
    ctx: dict = Depends(_ctx),
):
    """Reorder products on the broadcast product shelf."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_SESSION_CREATOR", "message": "Only the broadcaster can reorder the shelf"},
        )

    from app.services.broadcast_product_shelf import reorder_shelf
    reorder_shelf(
        session_id=session_id,
        item_order=body.item_order,
        is_live=(session.status == "live"),
    )
    return {"ok": True}


# ─── Broadcast-Exclusive Pricing Endpoints (LCOM-004) ──────────


@router.patch(
    "/sessions/{session_id}/products/{item_id}/price",
    response_model=BroadcastPriceOut,
)
def set_broadcast_price_route(
    session_id: str,
    item_id: str,
    body: BroadcastPriceSetIn,
    ctx: dict = Depends(_ctx),
):
    """Set a broadcast-exclusive price on a shelf product.

    Only the session creator (broadcaster) can set prices.
    The broadcast price must be strictly less than the catalog price.
    If expires_in_seconds is provided, the price reverts after that duration.
    When the session is live, a shelf:price_update SSE event is published.
    """
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the broadcaster can set broadcast prices.",
        )
    if session.status in ("stopping", "stopped", "error"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot set price on a session in terminal state.",
        )

    from app.services.broadcast_product_shelf import set_broadcast_price
    result = set_broadcast_price(
        session_id=session_id,
        item_id=item_id,
        broadcast_price_cents=body.broadcast_price_cents,
        set_by=ctx["user_sub"],
        expires_in_seconds=body.expires_in_seconds,
        is_live=(session.status == "live"),
    )
    return BroadcastPriceOut(
        session_id=session_id,
        item_id=item_id,
        original_price_cents=result["original_price_cents"],
        broadcast_price_cents=result["broadcast_price_cents"],
        broadcast_price_expires_at=result.get("broadcast_price_expires_at"),
        discount_pct=result["discount_pct"],
        set_by=ctx["user_sub"],
        set_at=result["broadcast_price_set_at"],
    )


@router.delete("/sessions/{session_id}/products/{item_id}/price")
def clear_broadcast_price_route(
    session_id: str,
    item_id: str,
    ctx: dict = Depends(_ctx),
):
    """Remove broadcast-exclusive pricing from a shelf product.

    The catalog price is restored as the effective price.
    If the session is live, publishes shelf:price_update SSE event.
    """
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the broadcaster can clear broadcast prices.",
        )

    from app.services.broadcast_product_shelf import clear_broadcast_price
    cleared = clear_broadcast_price(
        session_id=session_id,
        item_id=item_id,
        is_live=(session.status == "live"),
    )
    if not cleared:
        raise HTTPException(status_code=404, detail="Product not on shelf.")
    return {"ok": True, "item_id": item_id}


# ─── Broadcast Scheduling Endpoints (BCAST-009) ───────────────────────


@router.post("/sessions/{session_id}/schedule", response_model=BroadcastSessionOut)
def schedule_session_route(
    session_id: str,
    body: BroadcastScheduleIn,
    request: Request,
    ctx: dict = Depends(_ctx),
):
    """Schedule a draft broadcast session for a future time."""
    from app.core.settings import S as _S
    from app.core.time import now_ts

    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the session creator can schedule.")

    if session.status not in ("draft",):
        raise HTTPException(
            status_code=409,
            detail={"code": "BROADCAST_INVALID_STATE", "detail": "Session must be in draft status to schedule."},
        )

    now = now_ts()
    min_lead = _S.broadcast_schedule_min_lead_time_seconds
    if body.scheduled_at < now + min_lead:
        raise HTTPException(
            status_code=400,
            detail={"code": "SCHEDULE_TOO_SOON", "detail": f"scheduled_at must be at least {min_lead} seconds in the future"},
        )

    # Transition draft -> scheduled and set scheduling fields
    updated = transition_session_status(
        session_id=session_id,
        to_status="scheduled",
        reason="schedule-requested",
        actor=ctx["user_sub"],
        extra_fields={
            "scheduled_at": body.scheduled_at,
            "schedule_status": "scheduled",
            "name": body.name or session.name,
            "description": body.description or session.description,
        },
    )

    # BCAST-010: Create announcement post in newsfeed
    try:
        from app.services.broadcast_newsfeed import create_announcement_post
        announcement_post_id = create_announcement_post(
            session_id=session_id,
            creator_id=ctx["user_sub"],
            session_name=body.name or session.name,
            session_description=body.description or session.description,
            scheduled_at=body.scheduled_at,
        )
        if announcement_post_id:
            update_session_fields(session_id, {"announcement_post_id": announcement_post_id})
            updated = get_session(session_id)
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Announcement post creation failed for session %s (non-fatal)", session_id)

    record_broadcast_action(
        action="schedule_session",
        actor=ctx["user_sub"],
        correlation_id=_correlation_id(request),
        resource_type="session",
        resource_id=session_id,
        metadata={"scheduled_at": body.scheduled_at},
    )
    return _to_session_out(updated)


@router.post("/sessions/{session_id}/reschedule", response_model=BroadcastSessionOut)
def reschedule_session_route(
    session_id: str,
    body: BroadcastRescheduleIn,
    request: Request,
    ctx: dict = Depends(_ctx),
):
    """Reschedule an already-scheduled broadcast session."""
    from app.core.settings import S as _S
    from app.core.time import now_ts

    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the session creator can reschedule.")

    if session.schedule_status != "scheduled":
        raise HTTPException(
            status_code=409,
            detail={"code": "BROADCAST_NOT_SCHEDULED", "detail": "Session is not currently scheduled."},
        )

    now = now_ts()
    min_lead = _S.broadcast_schedule_min_lead_time_seconds
    if body.scheduled_at < now + min_lead:
        raise HTTPException(
            status_code=400,
            detail={"code": "SCHEDULE_TOO_SOON", "detail": f"scheduled_at must be at least {min_lead} seconds in the future"},
        )

    # Cancel old reminders, update scheduled_at
    from app.services.broadcast_reminders import cancel_reminders_for_session
    cancel_reminders_for_session(session_id)

    updated = update_session_fields(session_id, {"scheduled_at": body.scheduled_at})

    record_broadcast_action(
        action="reschedule_session",
        actor=ctx["user_sub"],
        correlation_id=_correlation_id(request),
        resource_type="session",
        resource_id=session_id,
        metadata={"scheduled_at": body.scheduled_at},
    )
    return _to_session_out(updated)


@router.post("/sessions/{session_id}/cancel-schedule", response_model=BroadcastSessionOut)
def cancel_schedule_route(
    session_id: str,
    request: Request,
    ctx: dict = Depends(_ctx),
):
    """Cancel a scheduled broadcast, transitioning it to cancelled."""
    from app.services.broadcast_store import now_iso
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the session creator can cancel the schedule.")

    if session.schedule_status != "scheduled":
        raise HTTPException(
            status_code=409,
            detail={"code": "BROADCAST_NOT_SCHEDULED", "detail": "Session is not currently scheduled."},
        )

    # Cancel reminders
    from app.services.broadcast_reminders import cancel_reminders_for_session
    cancel_reminders_for_session(session_id)

    # BCAST-010: Delete announcement post if it exists
    if session.announcement_post_id:
        try:
            from app.services.broadcast_newsfeed import delete_broadcast_post
            delete_broadcast_post(post_id=session.announcement_post_id, user_id=ctx["user_sub"])
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Announcement post deletion failed for session %s (non-fatal)", session_id)

    # Transition scheduled -> cancelled
    updated = transition_session_status(
        session_id=session_id,
        to_status="cancelled",
        reason="schedule-cancelled",
        actor=ctx["user_sub"],
        extra_fields={
            "schedule_status": "cancelled",
            "cancelled_at": now_iso(),
            "announcement_post_id": None,
        },
    )

    record_broadcast_action(
        action="cancel_scheduled_session",
        actor=ctx["user_sub"],
        correlation_id=_correlation_id(request),
        resource_type="session",
        resource_id=session_id,
        metadata={},
    )
    return _to_session_out(updated)


@router.post("/sessions/{session_id}/remind-me")
def register_reminder_route(
    session_id: str,
    ctx: dict = Depends(_ctx),
):
    """Register a reminder for the current user at T-30m before the broadcast."""
    session = get_session(session_id)
    if not session.scheduled_at or session.schedule_status != "scheduled":
        raise HTTPException(
            status_code=409,
            detail={"code": "BROADCAST_NOT_SCHEDULED", "detail": "Session is not scheduled."},
        )

    remind_at = session.scheduled_at - 1800  # 30 minutes before
    from app.core.time import now_ts
    if remind_at <= now_ts():
        raise HTTPException(
            status_code=400,
            detail={"code": "REMINDER_TOO_LATE", "detail": "Reminder time has already passed."},
        )

    from app.services.broadcast_reminders import register_reminder
    result = register_reminder(
        session_id=session_id,
        user_id=ctx["user_sub"],
        remind_at_ts=remind_at,
        session_name=session.name or "Broadcast",
        interval=1800,
    )
    return result


@router.delete("/sessions/{session_id}/remind-me")
def cancel_reminder_route(
    session_id: str,
    ctx: dict = Depends(_ctx),
):
    """Cancel the current user's reminder for a broadcast."""
    from app.services.broadcast_reminders import cancel_reminder
    return cancel_reminder(session_id, ctx["user_sub"])


@router.get("/sessions/{session_id}/ical")
def download_ical_route(
    session_id: str,
    ctx: dict = Depends(_ctx),
):
    """Download iCal invite for a scheduled broadcast."""
    from fastapi.responses import Response
    session = get_session(session_id)
    if not session.scheduled_at:
        raise HTTPException(
            status_code=409,
            detail={"code": "NOT_SCHEDULED", "detail": "Session has no scheduled time."},
        )

    from app.services.broadcast_reminders import generate_ical
    ical_content = generate_ical(
        session_id=session_id,
        name=session.name or "Broadcast",
        description=session.description or "",
        scheduled_at=session.scheduled_at,
        frontend_base_url="http://localhost:3000",
    )
    return Response(
        content=ical_content,
        media_type="text/calendar",
        headers={"Content-Disposition": 'attachment; filename="broadcast.ics"'},
    )


class BroadcastPromoteDueOut(BaseModel):
    processed: int = 0
    failed: int = 0
    session_ids: List[str] = Field(default_factory=list)


@router.post("/scheduler/run-due", response_model=BroadcastPromoteDueOut)
def run_due_scheduler_route(
    now: Optional[int] = Query(default=None, description="Override 'now' (Unix seconds) — testing only"),
    ctx: dict = Depends(_ctx),
):
    """Manually promote all due scheduled broadcasts to live.

    Mirrors the background scheduler loop but runs synchronously, making the
    auto-start path deterministically testable. Operator/admin role required.
    The optional ``now`` override lets tests trigger promotion of sessions
    scheduled in the near future without waiting for wall-clock time.
    """
    _require_operator_role(ctx)
    from app.services.broadcast_scheduler import promote_due_sessions
    summary = promote_due_sessions(now=now, limit=10)
    return BroadcastPromoteDueOut(**summary)


# ═══════════════════════════════════════════════════════════════════
#  BCAST-012 — Private Chat Tiers (Paid 1-on-1 Text Chat + Voyeur)
# ═══════════════════════════════════════════════════════════════════

from app.services.broadcast_private_chat import (
    purchase_private_chat as _pchat_purchase,
    send_private_chat_message as _pchat_send_msg,
    get_private_chat_history as _pchat_get_history,
    end_private_chat as _pchat_end,
    extend_private_chat as _pchat_extend,
    list_active_chats as _pchat_list_active,
    update_chat_settings as _pchat_update_settings,
    get_chat_status as _pchat_get_status,
    get_private_chat as _pchat_get_chat,
    get_voyeur_item as _pchat_get_voyeur,
)


# ─── Request / Response Models ────────────────────────────────────


class PrivateChatPurchaseIn(BaseModel):
    tier: int = Field(..., ge=1, le=2, description="1 = participant, 2 = voyeur")
    duration_minutes: int = Field(..., ge=5, le=60, description="Duration in minutes")
    payment_method_id: str = Field(..., min_length=1, max_length=128)
    chat_id: Optional[str] = Field(default=None, description="Required for tier 2 (voyeur)")


class PrivateChatPurchaseOut(BaseModel):
    chat_id: str
    session_id: str
    tier: int
    duration_minutes: int
    total_paid_cents: int
    rate_per_minute_cents: int
    expires_at: int
    status: str


class PrivateChatMessageIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=500)


class PrivateChatMessageOut(BaseModel):
    message_id: str
    session_id: str
    sender_id: str
    sender_display_name: str = ""
    text: str = ""
    kind: str = "private_chat"
    private_chat_id: Optional[str] = None
    created_at: int = 0
    deleted: bool = False
    filtered: bool = False


class PrivateChatHistoryOut(BaseModel):
    messages: List[PrivateChatMessageOut] = Field(default_factory=list)
    has_more: bool = False
    oldest_sort_key: Optional[str] = None


class PrivateChatExtendIn(BaseModel):
    duration_minutes: int = Field(..., ge=5, le=60)
    payment_method_id: str = Field(..., min_length=1, max_length=128)


class PrivateChatExtendOut(BaseModel):
    chat_id: str
    session_id: str
    expires_at: int
    purchased_minutes: int
    total_paid_cents: int
    status: str


class PrivateChatStatusOut(BaseModel):
    chat_id: str
    session_id: str
    viewer_id: str = ""
    viewer_display_name: str = ""
    status: str = ""
    tier: int = 1
    rate_per_minute_cents: int = 0
    purchased_minutes: int = 0
    remaining_seconds: int = 0
    started_at: int = 0
    expires_at: int = 0
    voyeur_count: int = 0


class PrivateChatSummaryOut(BaseModel):
    chat_id: str
    viewer_id: str
    viewer_display_name: str = ""
    tier: int = 1
    rate_per_minute_cents: int = 0
    purchased_minutes: int = 0
    remaining_seconds: int = 0
    status: str = ""
    started_at: int = 0
    expires_at: int = 0
    voyeur_count: int = 0
    total_revenue_cents: int = 0


class PrivateChatListOut(BaseModel):
    chats: List[PrivateChatSummaryOut] = Field(default_factory=list)


class PrivateChatSettingsIn(BaseModel):
    private_chat_enabled: Optional[bool] = None
    private_chat_rate_per_minute_cents: Optional[int] = Field(default=None, ge=100, le=10000)
    voyeur_rate_per_minute_cents: Optional[int] = Field(default=None, ge=50, le=5000)
    private_chat_time_blocks: Optional[List[int]] = None
    private_chat_max_concurrent: Optional[int] = Field(default=None, ge=1, le=20)


class PrivateChatTiersOut(BaseModel):
    private_chat_enabled: bool = False
    private_chat_rate_per_minute_cents: int = 500
    voyeur_rate_per_minute_cents: int = 100
    private_chat_time_blocks: List[int] = Field(default_factory=lambda: [5, 15, 30, 60])
    private_chat_max_concurrent: int = 5
    private_chat_voyeur_enabled: bool = False


# ─── Endpoints ────────────────────────────────────────────────────


def _ensure_private_chat_enabled():
    from app.core.settings import S
    if not S.broadcast_private_chat_enabled:
        raise HTTPException(
            status_code=403,
            detail="Private chat feature is disabled.",
        )


@router.put(
    "/sessions/{session_id}/chat-tiers",
    response_model=PrivateChatTiersOut,
)
def configure_chat_tiers_route(
    session_id: str,
    body: PrivateChatSettingsIn,
    ctx: dict = Depends(_ctx),
):
    """Configure private chat tier pricing (operator/creator only)."""
    _ensure_private_chat_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        _require_operator_role(ctx)

    settings_dict = body.model_dump(exclude_none=True)
    _pchat_update_settings(session_id, settings_dict)

    # Also update the BroadcastSessionModel fields via update_session_fields
    # so they survive put_item transitions
    model_fields: dict = {}
    if body.private_chat_enabled is not None:
        model_fields["private_chat_enabled"] = body.private_chat_enabled
    if body.private_chat_time_blocks is not None:
        tiers_list = [
            {"minutes": m, "price_cents": (body.private_chat_rate_per_minute_cents or 500) * m}
            for m in body.private_chat_time_blocks
        ]
        model_fields["private_chat_tiers"] = tiers_list
    if model_fields:
        update_session_fields(session_id, model_fields)

    # Re-fetch to return current state
    updated = get_session(session_id)
    time_blocks = body.private_chat_time_blocks or [5, 15, 30, 60]
    return PrivateChatTiersOut(
        private_chat_enabled=updated.private_chat_enabled,
        private_chat_rate_per_minute_cents=body.private_chat_rate_per_minute_cents or 500,
        voyeur_rate_per_minute_cents=body.voyeur_rate_per_minute_cents or 100,
        private_chat_time_blocks=time_blocks,
        private_chat_max_concurrent=body.private_chat_max_concurrent or 5,
        private_chat_voyeur_enabled=updated.private_chat_voyeur_enabled,
    )


@router.get(
    "/sessions/{session_id}/chat-tiers",
    response_model=PrivateChatTiersOut,
)
def get_chat_tiers_route(
    session_id: str,
    ctx: dict = Depends(_ctx),
):
    """Get private chat tier pricing for a broadcast session."""
    session = get_session(session_id)

    # Extract time blocks from tiers list or default
    time_blocks = [5, 15, 30, 60]
    rate = 500
    voyeur_rate = 100
    max_concurrent = 5

    if session.private_chat_tiers:
        time_blocks = [t.get("minutes", 5) if isinstance(t, dict) else int(t) for t in session.private_chat_tiers]
        if session.private_chat_tiers and isinstance(session.private_chat_tiers[0], dict):
            first = session.private_chat_tiers[0]
            mins = first.get("minutes", 5)
            price = first.get("price_cents", 500 * mins)
            rate = price // mins if mins else 500

    return PrivateChatTiersOut(
        private_chat_enabled=session.private_chat_enabled,
        private_chat_rate_per_minute_cents=rate,
        voyeur_rate_per_minute_cents=int(session.private_chat_voyeur_price_cents or voyeur_rate),
        private_chat_time_blocks=time_blocks,
        private_chat_max_concurrent=max_concurrent,
        private_chat_voyeur_enabled=session.private_chat_voyeur_enabled,
    )


@router.post(
    "/sessions/{session_id}/private-chat/purchase",
    response_model=PrivateChatPurchaseOut,
    status_code=status.HTTP_201_CREATED,
)
def purchase_private_chat_route(
    session_id: str,
    body: PrivateChatPurchaseIn,
    ctx: dict = Depends(_ctx),
):
    """Purchase a private chat session (tier 1) or voyeur access (tier 2)."""
    _ensure_private_chat_enabled()
    from app.core.tables import T as _T

    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(
            status_code=403,
            detail="Private chat is only available during live broadcasts.",
        )

    if not session.private_chat_enabled:
        raise HTTPException(
            status_code=403,
            detail="Private chat is not enabled for this broadcast.",
        )

    viewer_id = ctx["user_sub"]
    if viewer_id == session.created_by:
        raise HTTPException(
            status_code=403,
            detail="Cannot purchase a private chat on your own broadcast.",
        )

    # Validate tier 2 requires chat_id
    if body.tier == 2 and not body.chat_id:
        raise HTTPException(status_code=400, detail="chat_id is required for tier 2 (voyeur).")
    if body.tier == 1 and body.chat_id:
        raise HTTPException(status_code=400, detail="chat_id must not be provided for tier 1.")

    # Validate voyeur enabled for tier 2
    if body.tier == 2:
        from app.core.settings import S
        if not S.broadcast_private_chat_voyeur_enabled and not session.private_chat_voyeur_enabled:
            raise HTTPException(status_code=403, detail="Voyeur mode is not enabled for this broadcast.")

    # Validate payment method
    pm_item = _T.billing.get_item(
        Key={"pk": f"USER#{viewer_id}", "sk": f"PM#{body.payment_method_id}"}
    ).get("Item")
    if not pm_item:
        raise HTTPException(status_code=400, detail="Payment method not found.")

    # Resolve display name
    display_name = viewer_id
    try:
        profile_item = _T.profile.get_item(Key={"user_sub": viewer_id}).get("Item")
        if profile_item and profile_item.get("display_name"):
            display_name = profile_item["display_name"]
    except Exception:
        pass

    # Determine rate
    if body.tier == 1:
        rate = 500  # default
        if session.private_chat_tiers and isinstance(session.private_chat_tiers[0], dict):
            first = session.private_chat_tiers[0]
            mins = first.get("minutes", 5)
            price = first.get("price_cents", 500 * mins)
            rate = price // mins if mins else 500
    else:
        rate = int(session.private_chat_voyeur_price_cents or 100)

    # Get max concurrent from session or default
    max_concurrent = 5

    result = _pchat_purchase(
        session_id=session_id,
        viewer_id=viewer_id,
        viewer_display_name=display_name,
        tier=body.tier,
        duration_minutes=body.duration_minutes,
        payment_method_id=body.payment_method_id,
        rate_per_minute_cents=rate,
        chat_id=body.chat_id,
        creator_id=session.created_by,
        max_concurrent=max_concurrent,
    )

    return PrivateChatPurchaseOut(**result)


@router.post(
    "/sessions/{session_id}/private-chat/{chat_id}/message",
    response_model=PrivateChatMessageOut,
    status_code=status.HTTP_201_CREATED,
)
def send_private_chat_message_route(
    session_id: str,
    chat_id: str,
    body: PrivateChatMessageIn,
    ctx: dict = Depends(_ctx),
):
    """Send a message in a private chat. Only tier 1 participant and creator can send."""
    _ensure_private_chat_enabled()
    from app.core.tables import T as _T

    session = get_session(session_id)
    chat = _pchat_get_chat(session_id, chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Private chat not found.")

    if chat.get("status") not in ("active", "expiring"):
        raise HTTPException(status_code=409, detail="Private chat has ended or expired.")

    sender_id = ctx["user_sub"]

    # Only tier 1 viewer or creator can send
    if sender_id != chat.get("viewer_id") and sender_id != session.created_by:
        raise HTTPException(status_code=403, detail="Only the participant or creator can send messages.")

    # Resolve display name
    display_name = sender_id
    try:
        profile_item = _T.profile.get_item(Key={"user_sub": sender_id}).get("Item")
        if profile_item and profile_item.get("display_name"):
            display_name = profile_item["display_name"]
    except Exception:
        pass

    result = _pchat_send_msg(
        session_id=session_id,
        chat_id=chat_id,
        sender_id=sender_id,
        sender_display_name=display_name,
        text=body.text,
    )

    return PrivateChatMessageOut(**result)


@router.get(
    "/sessions/{session_id}/private-chat/{chat_id}/messages",
    response_model=PrivateChatHistoryOut,
)
def get_private_chat_messages_route(
    session_id: str,
    chat_id: str,
    limit: int = Query(default=100, ge=1, le=200),
    before: Optional[str] = Query(default=None),
    ctx: dict = Depends(_ctx),
):
    """Get message history for a private chat."""
    _ensure_private_chat_enabled()

    session = get_session(session_id)
    user_id = ctx["user_sub"]

    # Validate access: tier 1 viewer, active voyeur, or creator
    chat = _pchat_get_chat(session_id, chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Private chat not found.")

    is_viewer = user_id == chat.get("viewer_id")
    is_creator = user_id == session.created_by
    is_voyeur = False
    if not is_viewer and not is_creator:
        voyeur = _pchat_get_voyeur(session_id, chat_id, user_id)
        if voyeur and voyeur.get("status") in ("active", "expiring"):
            is_voyeur = True

    if not (is_viewer or is_creator or is_voyeur):
        raise HTTPException(status_code=403, detail="You do not have access to this chat.")

    result = _pchat_get_history(session_id, chat_id, limit=limit, before_sort_key=before)
    return PrivateChatHistoryOut(
        messages=[PrivateChatMessageOut(**m) for m in result["messages"]],
        has_more=result["has_more"],
        oldest_sort_key=result.get("oldest_sort_key"),
    )


@router.post(
    "/sessions/{session_id}/private-chat/{chat_id}/end",
)
def end_private_chat_route(
    session_id: str,
    chat_id: str,
    ctx: dict = Depends(_ctx),
):
    """End a private chat. Tier 1 viewer or creator can end."""
    _ensure_private_chat_enabled()

    session = get_session(session_id)
    user_id = ctx["user_sub"]

    chat = _pchat_get_chat(session_id, chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Private chat not found.")

    is_viewer = user_id == chat.get("viewer_id")
    is_creator = user_id == session.created_by

    if not (is_viewer or is_creator):
        raise HTTPException(status_code=403, detail="Only the participant or creator can end the chat.")

    ended_reason = "creator_ended" if is_creator else "viewer_ended"
    _pchat_end(session_id, chat_id, ended_reason)

    return {"ok": True, "chat_id": chat_id, "ended_reason": ended_reason}


@router.post(
    "/sessions/{session_id}/private-chat/{chat_id}/voyeur",
    response_model=PrivateChatPurchaseOut,
    status_code=status.HTTP_201_CREATED,
)
def join_voyeur_route(
    session_id: str,
    chat_id: str,
    body: PrivateChatExtendIn,
    ctx: dict = Depends(_ctx),
):
    """Join as a voyeur on an active private chat."""
    _ensure_private_chat_enabled()
    from app.core.tables import T as _T
    from app.core.settings import S

    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(status_code=403, detail="Private chat is only available during live broadcasts.")

    if not S.broadcast_private_chat_voyeur_enabled and not session.private_chat_voyeur_enabled:
        raise HTTPException(status_code=403, detail="Voyeur mode is not enabled for this broadcast.")

    viewer_id = ctx["user_sub"]
    if viewer_id == session.created_by:
        raise HTTPException(status_code=403, detail="Cannot voyeur your own broadcast.")

    # Validate payment method
    pm_item = _T.billing.get_item(
        Key={"pk": f"USER#{viewer_id}", "sk": f"PM#{body.payment_method_id}"}
    ).get("Item")
    if not pm_item:
        raise HTTPException(status_code=400, detail="Payment method not found.")

    display_name = viewer_id
    try:
        profile_item = _T.profile.get_item(Key={"user_sub": viewer_id}).get("Item")
        if profile_item and profile_item.get("display_name"):
            display_name = profile_item["display_name"]
    except Exception:
        pass

    voyeur_rate = int(session.private_chat_voyeur_price_cents or 100)

    result = _pchat_purchase(
        session_id=session_id,
        viewer_id=viewer_id,
        viewer_display_name=display_name,
        tier=2,
        duration_minutes=body.duration_minutes,
        payment_method_id=body.payment_method_id,
        rate_per_minute_cents=voyeur_rate,
        chat_id=chat_id,
        creator_id=session.created_by,
    )

    return PrivateChatPurchaseOut(**result)


@router.get(
    "/sessions/{session_id}/private-chat/{chat_id}/status",
    response_model=PrivateChatStatusOut,
)
def get_private_chat_status_route(
    session_id: str,
    chat_id: str,
    ctx: dict = Depends(_ctx),
):
    """Get private chat status including time remaining and voyeur count."""
    _ensure_private_chat_enabled()

    result = _pchat_get_status(session_id, chat_id)
    if not result:
        raise HTTPException(status_code=404, detail="Private chat not found.")

    return PrivateChatStatusOut(**result)


@router.get(
    "/sessions/{session_id}/private-chats",
    response_model=PrivateChatListOut,
)
def list_private_chats_route(
    session_id: str,
    ctx: dict = Depends(_ctx),
):
    """List all active private chats for a broadcast (creator only)."""
    _ensure_private_chat_enabled()

    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        _require_operator_role(ctx)

    chats = _pchat_list_active(session_id)
    return PrivateChatListOut(chats=[PrivateChatSummaryOut(**c) for c in chats])


@router.post(
    "/sessions/{session_id}/private-chat/{chat_id}/extend",
    response_model=PrivateChatExtendOut,
)
def extend_private_chat_route(
    session_id: str,
    chat_id: str,
    body: PrivateChatExtendIn,
    ctx: dict = Depends(_ctx),
):
    """Extend a private chat by purchasing additional time."""
    _ensure_private_chat_enabled()
    from app.core.tables import T as _T

    session = get_session(session_id)
    user_id = ctx["user_sub"]

    chat = _pchat_get_chat(session_id, chat_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Private chat not found.")

    is_viewer = user_id == chat.get("viewer_id")
    is_voyeur = False
    if not is_viewer:
        voyeur = _pchat_get_voyeur(session_id, chat_id, user_id)
        if voyeur and voyeur.get("status") in ("active", "expiring"):
            is_voyeur = True

    if not (is_viewer or is_voyeur):
        raise HTTPException(status_code=403, detail="Only the participant or their voyeur can extend.")

    # Validate payment method
    pm_item = _T.billing.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"PM#{body.payment_method_id}"}
    ).get("Item")
    if not pm_item:
        raise HTTPException(status_code=400, detail="Payment method not found.")

    if is_viewer:
        rate = int(chat.get("rate_per_minute_cents", 500))
    else:
        rate = int(session.private_chat_voyeur_price_cents or 100)

    result = _pchat_extend(
        session_id=session_id,
        chat_id=chat_id,
        viewer_id=user_id,
        additional_minutes=body.duration_minutes,
        payment_method_id=body.payment_method_id,
        rate_per_minute_cents=rate,
        platform_fee_pct=20,
        creator_id=session.created_by,
        is_voyeur=is_voyeur,
    )

    return PrivateChatExtendOut(**result)


# ─── Broadcast Lottery Endpoints (BCAST-014) ─────────────────────────


class BroadcastLotteryOutcomeIn(BaseModel):
    """One outcome in a broadcast lottery configuration."""
    display_label: Optional[str] = Field(default=None, max_length=80)
    weight_bps: int = Field(ge=1, le=10_000)
    payload_type: str = Field(default="text", pattern=r"^(text|image|video)$")
    text_content: Optional[str] = Field(default=None, max_length=4000)
    media_asset_id: Optional[str] = Field(default=None, min_length=1, max_length=256)


class BroadcastLotteryCreateIn(BaseModel):
    """Request body for creating a lottery in broadcast chat."""
    title: str = Field(..., min_length=1, max_length=120)
    outcomes: List[BroadcastLotteryOutcomeIn] = Field(..., min_length=2, max_length=10)
    max_entries: Optional[int] = Field(default=None, ge=1, le=10_000)
    entry_fee_cents: int = Field(default=0, ge=0, le=100_000)
    duration_seconds: Optional[int] = Field(default=None, ge=10, le=3600)


class BroadcastLotteryEntryIn(BaseModel):
    """Request body for entering a broadcast lottery."""
    payment_method_id: Optional[str] = Field(default=None, max_length=128)


class BroadcastLotteryOutcomeOut(BaseModel):
    outcome_id: str
    display_label: Optional[str] = None
    weight_bps: int
    payload_type: str
    text_content: Optional[str] = None
    media_asset_id: Optional[str] = None


class BroadcastLotteryConfigOut(BaseModel):
    lottery_id: str
    message_id: str
    title: str
    status: str
    outcomes: List[BroadcastLotteryOutcomeOut] = Field(default_factory=list)
    entry_count: int = 0
    max_entries: Optional[int] = None
    entry_fee_cents: int = 0
    currency: str = "USD"
    duration_seconds: Optional[int] = None
    closes_at: Optional[int] = None
    created_at: int = 0
    drawn_at: Optional[int] = None


class BroadcastLotteryResultEntryOut(BaseModel):
    user_id: str
    display_name: str = ""
    outcome_id: str
    display_label: Optional[str] = None
    payload_type: str = "text"
    text_content: Optional[str] = None
    media_asset_id: Optional[str] = None
    rng_roll: int


class BroadcastLotteryDrawOut(BaseModel):
    lottery_id: str
    status: str = "drawn"
    results: List[BroadcastLotteryResultEntryOut] = Field(default_factory=list)
    idempotent: bool = False


class BroadcastLotteryEntryOut(BaseModel):
    lottery_id: str
    user_id: str
    entered_at: int
    already_entered: bool = False
    entry_fee_cents: int = 0


class BroadcastLotteryViewerStatusOut(BaseModel):
    lottery_id: str
    title: str
    status: str
    entry_count: int = 0
    max_entries: Optional[int] = None
    entry_fee_cents: int = 0
    closes_at: Optional[int] = None
    created_at: int = 0
    drawn_at: Optional[int] = None
    has_entered: bool = False
    viewer_outcome: Optional[BroadcastLotteryResultEntryOut] = None


def _require_broadcast_lottery_enabled() -> None:
    from app.core.settings import S as _S
    if not _S.broadcast_lottery_enabled:
        raise HTTPException(
            status_code=403,
            detail={"code": "BROADCAST_LOTTERY_DISABLED", "message": "Lottery feature is not enabled"},
        )


@router.post(
    "/sessions/{session_id}/chat/lottery",
    response_model=BroadcastLotteryConfigOut,
    status_code=status.HTTP_201_CREATED,
)
def create_lottery_route(
    session_id: str,
    body: BroadcastLotteryCreateIn,
    ctx: dict = Depends(_ctx),
):
    """Create a lottery in a live broadcast chat session (broadcaster only)."""
    _require_broadcast_lottery_enabled()

    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "BROADCAST_NOT_LIVE", "message": "Chat is only available while the broadcast is live"},
        )

    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_SESSION_CREATOR", "message": "Only the broadcaster can create lotteries"},
        )

    user_id = ctx["user_sub"]
    display_name = user_id
    try:
        from app.core.tables import T as _T
        profile_resp = _T.profile.get_item(Key={"user_sub": user_id})
        profile_item = profile_resp.get("Item")
        if profile_item and profile_item.get("display_name"):
            display_name = profile_item["display_name"]
    except Exception:
        pass

    # Convert outcomes with generated outcome_ids
    outcome_dicts = []
    for oc in body.outcomes:
        outcome_dicts.append({
            "outcome_id": "oc_" + uuid4().hex[:8],
            "display_label": oc.display_label,
            "weight_bps": oc.weight_bps,
            "payload_type": oc.payload_type,
            "text_content": oc.text_content,
            "media_asset_id": oc.media_asset_id,
        })

    from app.services.broadcast_lottery import create_lottery
    from app.services.messaging_lottery_store import LotteryConfigValidationError

    try:
        config = create_lottery(
            session_id=session_id,
            broadcaster_id=user_id,
            display_name=display_name,
            title=body.title,
            outcomes=outcome_dicts,
            max_entries=body.max_entries,
            entry_fee_cents=body.entry_fee_cents,
            duration_seconds=body.duration_seconds,
        )
    except LotteryConfigValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return BroadcastLotteryConfigOut(
        lottery_id=config["lottery_id"],
        message_id=config["message_id"],
        title=config["title"],
        status=config["status"],
        outcomes=[BroadcastLotteryOutcomeOut(**o) for o in config["outcomes"]],
        entry_count=int(config.get("entry_count", 0)),
        max_entries=int(config["max_entries"]) if config.get("max_entries") is not None else None,
        entry_fee_cents=int(config.get("entry_fee_cents", 0)),
        currency=config.get("currency", "USD"),
        duration_seconds=int(config["duration_seconds"]) if config.get("duration_seconds") is not None else None,
        closes_at=int(config["closes_at"]) if config.get("closes_at") is not None else None,
        created_at=int(config.get("created_at", 0)),
        drawn_at=int(config["drawn_at"]) if config.get("drawn_at") is not None else None,
    )


@router.post(
    "/sessions/{session_id}/chat/lottery/{lottery_id}/enter",
    response_model=BroadcastLotteryEntryOut,
)
def enter_lottery_route(
    session_id: str,
    lottery_id: str,
    body: BroadcastLotteryEntryIn,
    ctx: dict = Depends(_ctx),
):
    """Enter a broadcast lottery."""
    _require_broadcast_lottery_enabled()

    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "BROADCAST_NOT_LIVE", "message": "Chat is only available while the broadcast is live"},
        )

    user_id = ctx["user_sub"]
    display_name = user_id
    try:
        from app.core.tables import T as _T
        profile_resp = _T.profile.get_item(Key={"user_sub": user_id})
        profile_item = profile_resp.get("Item")
        if profile_item and profile_item.get("display_name"):
            display_name = profile_item["display_name"]
    except Exception:
        pass

    from app.services.broadcast_lottery import enter_lottery
    result = enter_lottery(
        session_id=session_id,
        lottery_id=lottery_id,
        user_id=user_id,
        display_name=display_name,
        payment_method_id=body.payment_method_id,
    )

    entry = result["entry"]
    return BroadcastLotteryEntryOut(
        lottery_id=entry.get("lottery_id", lottery_id),
        user_id=entry.get("user_id", user_id),
        entered_at=int(entry.get("entered_at", 0)),
        already_entered=result["already_entered"],
        entry_fee_cents=int(entry.get("entry_fee_cents", 0)),
    )


@router.post(
    "/sessions/{session_id}/chat/lottery/{lottery_id}/close",
    response_model=BroadcastLotteryConfigOut,
)
def close_lottery_route(
    session_id: str,
    lottery_id: str,
    ctx: dict = Depends(_ctx),
):
    """Close entries for a broadcast lottery (broadcaster only)."""
    _require_broadcast_lottery_enabled()

    _ = get_session(session_id)  # 404 if not found

    from app.services.broadcast_lottery import close_lottery_entries
    config = close_lottery_entries(
        session_id=session_id,
        lottery_id=lottery_id,
        actor_id=ctx["user_sub"],
    )

    return BroadcastLotteryConfigOut(
        lottery_id=config["lottery_id"],
        message_id=config.get("message_id", ""),
        title=config["title"],
        status=config["status"],
        outcomes=[BroadcastLotteryOutcomeOut(**o) for o in (config.get("outcomes") or [])],
        entry_count=int(config.get("entry_count", 0)),
        max_entries=int(config["max_entries"]) if config.get("max_entries") is not None else None,
        entry_fee_cents=int(config.get("entry_fee_cents", 0)),
        currency=config.get("currency", "USD"),
        duration_seconds=int(config["duration_seconds"]) if config.get("duration_seconds") is not None else None,
        closes_at=int(config["closes_at"]) if config.get("closes_at") is not None else None,
        created_at=int(config.get("created_at", 0)),
        drawn_at=int(config["drawn_at"]) if config.get("drawn_at") is not None else None,
    )


@router.post(
    "/sessions/{session_id}/chat/lottery/{lottery_id}/draw",
    response_model=BroadcastLotteryDrawOut,
)
def draw_lottery_route(
    session_id: str,
    lottery_id: str,
    ctx: dict = Depends(_ctx),
):
    """Execute the lottery draw (broadcaster only)."""
    _require_broadcast_lottery_enabled()

    _ = get_session(session_id)  # 404 if not found

    from app.services.broadcast_lottery import draw_lottery
    result = draw_lottery(
        session_id=session_id,
        lottery_id=lottery_id,
        actor_id=ctx["user_sub"],
    )

    return BroadcastLotteryDrawOut(
        lottery_id=result["lottery_id"],
        status=result["status"],
        results=[BroadcastLotteryResultEntryOut(**r) for r in result["results"]],
        idempotent=result.get("idempotent", False),
    )


@router.get(
    "/sessions/{session_id}/chat/lottery/{lottery_id}",
    response_model=BroadcastLotteryViewerStatusOut,
)
def get_lottery_status_route(
    session_id: str,
    lottery_id: str,
    ctx: dict = Depends(_ctx),
):
    """Get lottery state from the requesting viewer's perspective."""
    _require_broadcast_lottery_enabled()

    _ = get_session(session_id)  # 404 if not found

    from app.services.broadcast_lottery import get_lottery_status_for_viewer
    result = get_lottery_status_for_viewer(session_id, lottery_id, ctx["user_sub"])
    if not result:
        raise HTTPException(status_code=404, detail={"code": "LOTTERY_NOT_FOUND", "message": "Lottery not found"})

    viewer_outcome = None
    if result.get("viewer_outcome"):
        vo = result["viewer_outcome"]
        viewer_outcome = BroadcastLotteryResultEntryOut(
            user_id=ctx["user_sub"],
            display_name="",
            outcome_id=vo["outcome_id"],
            display_label=vo.get("display_label"),
            payload_type=vo.get("payload_type", "text"),
            text_content=vo.get("text_content"),
            media_asset_id=vo.get("media_asset_id"),
            rng_roll=int(vo.get("rng_roll", 0)),
        )

    return BroadcastLotteryViewerStatusOut(
        lottery_id=result["lottery_id"],
        title=result["title"],
        status=result["status"],
        entry_count=result["entry_count"],
        max_entries=result.get("max_entries"),
        entry_fee_cents=result["entry_fee_cents"],
        closes_at=result.get("closes_at"),
        created_at=result["created_at"],
        drawn_at=result.get("drawn_at"),
        has_entered=result["has_entered"],
        viewer_outcome=viewer_outcome,
    )


@router.get(
    "/sessions/{session_id}/chat/lottery/{lottery_id}/results",
    response_model=BroadcastLotteryDrawOut,
)
def get_lottery_results_route(
    session_id: str,
    lottery_id: str,
    ctx: dict = Depends(_ctx),
):
    """Get full draw results (broadcaster only)."""
    _require_broadcast_lottery_enabled()

    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_SESSION_CREATOR", "message": "Only the broadcaster can view full results"},
        )

    from app.services.broadcast_lottery import get_lottery_config, _get_draw_results
    config = get_lottery_config(session_id, lottery_id)
    if not config:
        raise HTTPException(status_code=404, detail={"code": "LOTTERY_NOT_FOUND", "message": "Lottery not found"})

    if config["status"] != "drawn":
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_NOT_DRAWN", "message": "Lottery has not been drawn yet"},
        )

    results = _get_draw_results(session_id, lottery_id)
    return BroadcastLotteryDrawOut(
        lottery_id=lottery_id,
        status="drawn",
        results=[BroadcastLotteryResultEntryOut(**r) for r in results],
        idempotent=True,
    )


# ─── Multi-Input / Co-Streaming Endpoints (BCAST-016) ────────────


class BroadcastInputCreateIn(BaseModel):
    input_type: str = Field(default="guest", pattern=r"^(primary|guest|screen)$")
    label: str = Field(default="", max_length=100)


class BroadcastInputOut(BaseModel):
    input_id: str
    session_id: str
    input_type: str
    label: str
    ingest_url: Optional[str] = None
    stream_key_ref: Optional[str] = None
    aws_input_arn: Optional[str] = None
    is_live: bool = False
    connected_at: Optional[int] = None
    disconnected_at: Optional[int] = None
    position: int = 0
    created_by: str
    created_at: str
    updated_at: str
    relay_mode: Optional[str] = None


class BroadcastInputListOut(BaseModel):
    session_id: str
    inputs: List[BroadcastInputOut] = Field(default_factory=list)
    count: int = 0
    max_inputs: int = 4


class BroadcastInputCreateOut(BaseModel):
    input_id: str
    session_id: str
    input_type: str
    label: str
    ingest_url: str
    stream_key: str
    aws_input_arn: Optional[str] = None
    position: int


class BroadcastLayoutSwitchIn(BaseModel):
    mode: str = Field(..., pattern=r"^(single|side_by_side|pip|grid)$")
    primary_input_id: Optional[str] = None
    input_ids: Optional[List[str]] = None


class BroadcastLayoutOut(BaseModel):
    mode: str
    positions: List[dict] = Field(default_factory=list)
    primary_input_id: Optional[str] = None
    input_ids: List[str] = Field(default_factory=list)


class BroadcastGuestInviteCreateIn(BaseModel):
    join_mode: str = Field(default="browser", pattern=r"^(rtmp|browser)$")
    label: str = Field(default="Guest", max_length=100)
    expiry_minutes: int = Field(default=60, ge=5, le=1440)


class BroadcastGuestInviteOut(BaseModel):
    invite_id: str
    session_id: str
    input_id: str
    invite_url: Optional[str] = None
    ingest_url: Optional[str] = None
    stream_key: Optional[str] = None
    join_mode: str
    status: str
    guest_user_id: Optional[str] = None
    guest_display_name: Optional[str] = None
    expires_at: int
    accepted_at: Optional[int] = None
    created_at: str


class BroadcastGuestInviteListOut(BaseModel):
    session_id: str
    invites: List[BroadcastGuestInviteOut] = Field(default_factory=list)
    count: int = 0


class BroadcastGuestAcceptIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=100)


class BroadcastGuestAcceptOut(BaseModel):
    invite_id: str
    input_id: str
    ingest_url: Optional[str] = None
    join_mode: str
    session_id: str


class BroadcastWebRTCOfferIn(BaseModel):
    sdp_offer: str = Field(min_length=1, max_length=65536)


class BroadcastWebRTCOfferOut(BaseModel):
    sdp_answer: str
    session_id: str
    input_id: str


class BroadcastGuestMuteIn(BaseModel):
    muted: bool = True


def _ensure_multi_input_enabled() -> None:
    from app.core.settings import S as _S
    if not _S.broadcast_multi_input_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "MULTI_INPUT_DISABLED", "detail": "Multi-input feature is disabled"},
        )


@router.get("/sessions/{session_id}/inputs", response_model=BroadcastInputListOut)
def list_inputs_route(session_id: str, ctx: dict = Depends(_ctx)):
    """List all inputs for a broadcast session."""
    _ensure_multi_input_enabled()
    _ = get_session(session_id)  # 404 if not found
    from app.services.broadcast_input_store import list_inputs as _list_inputs
    inputs = _list_inputs(session_id)
    from app.core.settings import S as _S
    return BroadcastInputListOut(
        session_id=session_id,
        inputs=[BroadcastInputOut(**inp.model_dump()) for inp in inputs],
        count=len(inputs),
        max_inputs=_S.broadcast_max_inputs_per_session,
    )


@router.post("/sessions/{session_id}/inputs", response_model=BroadcastInputCreateOut, status_code=201)
def add_input_route(session_id: str, body: BroadcastInputCreateIn, request: Request, ctx: dict = Depends(_ctx)):
    """Add a new input to a broadcast session."""
    _ensure_multi_input_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can add inputs.")
    if session.status in ("stopped", "error", "cancelled"):
        raise HTTPException(status_code=409, detail=f"Cannot add inputs when session is {session.status}.")

    from app.services.broadcast_input_store import count_inputs, create_input
    from app.core.settings import S as _S
    current_count = count_inputs(session_id)
    if current_count >= _S.broadcast_max_inputs_per_session:
        raise HTTPException(status_code=400, detail=f"Maximum {_S.broadcast_max_inputs_per_session} inputs per session.")

    from app.services.broadcast_multi_input import create_additional_input
    provision = create_additional_input(
        session_id=session_id,
        input_index=current_count,
        correlation_id=_correlation_id(request),
    )

    inp = create_input(
        session_id=session_id,
        input_type=body.input_type,
        label=body.label,
        ingest_url=provision.ingest_url,
        stream_key_ref=f"ref:{provision.stream_key[:8]}",
        aws_input_arn=provision.input_arn,
        aws_input_id=provision.input_id,
        position=current_count,
        created_by=ctx["user_sub"],
    )

    broadcast_sse_publish(session_id, {
        "_type": "input:added",
        "input_id": inp.input_id,
        "input_type": body.input_type,
        "label": body.label,
        "position": current_count,
    })

    return BroadcastInputCreateOut(
        input_id=inp.input_id,
        session_id=session_id,
        input_type=inp.input_type,
        label=inp.label,
        ingest_url=provision.ingest_url,
        stream_key=provision.stream_key,
        aws_input_arn=provision.input_arn,
        position=inp.position,
    )


@router.delete("/sessions/{session_id}/inputs/{input_id}")
def remove_input_route(session_id: str, input_id: str, ctx: dict = Depends(_ctx)):
    """Remove an input from a broadcast session."""
    _ensure_multi_input_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can remove inputs.")

    from app.services.broadcast_input_store import get_input, delete_input
    inp = get_input(session_id, input_id)

    delete_input(session_id, input_id)

    broadcast_sse_publish(session_id, {
        "_type": "input:removed",
        "input_id": input_id,
    })

    return {"ok": True, "input_id": input_id}


@router.post("/sessions/{session_id}/layout", response_model=BroadcastLayoutOut)
def switch_layout_route(session_id: str, body: BroadcastLayoutSwitchIn, ctx: dict = Depends(_ctx)):
    """Switch layout mode for a live broadcast session."""
    _ensure_multi_input_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can switch layout.")

    from app.services.broadcast_layout import switch_layout
    result = switch_layout(
        session_id=session_id,
        mode=body.mode,
        primary_input_id=body.primary_input_id,
        input_ids=body.input_ids,
    )

    broadcast_sse_publish(session_id, {
        "_type": "layout:switched",
        "mode": result["mode"],
        "input_ids": result["input_ids"],
        "primary_input_id": result.get("primary_input_id"),
    })

    return BroadcastLayoutOut(**result)


@router.get("/sessions/{session_id}/layout", response_model=BroadcastLayoutOut)
def get_layout_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Get current layout configuration."""
    _ensure_multi_input_enabled()
    _ = get_session(session_id)
    from app.services.broadcast_input_store import get_layout
    layout = get_layout(session_id)
    if not layout:
        return BroadcastLayoutOut(mode="single", positions=[], input_ids=[])
    return BroadcastLayoutOut(
        mode=layout.mode,
        positions=[p.model_dump() for p in layout.positions],
        primary_input_id=layout.primary_input_id,
        input_ids=layout.input_ids,
    )


@router.post("/sessions/{session_id}/inputs/{input_id}/activate")
def activate_input_route(session_id: str, input_id: str, ctx: dict = Depends(_ctx)):
    """Bring an input on-screen (mark as live)."""
    _ensure_multi_input_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can activate inputs.")

    from app.services.broadcast_input_store import mark_input_live
    inp = mark_input_live(session_id, input_id, is_live=True)

    broadcast_sse_publish(session_id, {
        "_type": "input:connected",
        "input_id": input_id,
        "is_live": True,
    })

    return {"ok": True, "input_id": input_id, "is_live": True}


@router.post("/sessions/{session_id}/inputs/{input_id}/deactivate")
def deactivate_input_route(session_id: str, input_id: str, ctx: dict = Depends(_ctx)):
    """Remove an input from the layout (mark as not live)."""
    _ensure_multi_input_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can deactivate inputs.")

    from app.services.broadcast_input_store import mark_input_live
    inp = mark_input_live(session_id, input_id, is_live=False)

    broadcast_sse_publish(session_id, {
        "_type": "input:disconnected",
        "input_id": input_id,
        "is_live": False,
    })

    return {"ok": True, "input_id": input_id, "is_live": False}


@router.post("/sessions/{session_id}/guest-invites", response_model=BroadcastGuestInviteOut, status_code=201)
def create_guest_invite_route(session_id: str, body: BroadcastGuestInviteCreateIn, request: Request, ctx: dict = Depends(_ctx)):
    """Create a guest invite link for co-streaming."""
    _ensure_multi_input_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can create guest invites.")

    from app.services.broadcast_input_store import count_inputs, create_input, create_guest_invite
    from app.services.broadcast_multi_input import create_additional_input
    from app.core.settings import S as _S
    from app.core.time import now_ts as _now_ts

    current_count = count_inputs(session_id)
    if current_count >= _S.broadcast_max_inputs_per_session:
        raise HTTPException(status_code=400, detail=f"Maximum {_S.broadcast_max_inputs_per_session} inputs per session.")

    # Provision a new input for the guest
    provision = create_additional_input(
        session_id=session_id,
        input_index=current_count,
        correlation_id=_correlation_id(request),
    )
    inp = create_input(
        session_id=session_id,
        input_type="guest",
        label=body.label,
        ingest_url=provision.ingest_url,
        stream_key_ref=f"ref:{provision.stream_key[:8]}",
        aws_input_arn=provision.input_arn,
        aws_input_id=provision.input_id,
        position=current_count,
        created_by=ctx["user_sub"],
        relay_mode="webrtc_relay" if body.join_mode == "browser" else "rtmp",
    )

    expires_at = _now_ts() + body.expiry_minutes * 60
    invite = create_guest_invite(
        session_id=session_id,
        input_id=inp.input_id,
        created_by=ctx["user_sub"],
        join_mode=body.join_mode,
        ingest_url=provision.ingest_url,
        stream_key_ref=f"ref:{provision.stream_key[:8]}",
        expires_at=expires_at,
    )

    broadcast_sse_publish(session_id, {
        "_type": "guest:invited",
        "invite_id": invite.invite_id,
        "input_id": inp.input_id,
        "join_mode": body.join_mode,
    })

    return BroadcastGuestInviteOut(
        invite_id=invite.invite_id,
        session_id=session_id,
        input_id=inp.input_id,
        invite_url=f"/broadcast/guest/{session_id}/{invite.invite_id}",
        ingest_url=provision.ingest_url,
        stream_key=provision.stream_key,
        join_mode=body.join_mode,
        status="pending",
        expires_at=expires_at,
        created_at=invite.created_at,
    )


@router.get("/sessions/{session_id}/guest-invites", response_model=BroadcastGuestInviteListOut)
def list_guest_invites_route(session_id: str, ctx: dict = Depends(_ctx)):
    """List guest invites for a broadcast session."""
    _ensure_multi_input_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can list guest invites.")

    from app.services.broadcast_input_store import list_guest_invites
    invites = list_guest_invites(session_id)
    return BroadcastGuestInviteListOut(
        session_id=session_id,
        invites=[BroadcastGuestInviteOut(
            invite_id=inv.invite_id,
            session_id=inv.session_id,
            input_id=inv.input_id,
            invite_url=f"/broadcast/guest/{session_id}/{inv.invite_id}",
            ingest_url=inv.ingest_url,
            join_mode=inv.join_mode,
            status=inv.status,
            guest_user_id=inv.guest_user_id,
            guest_display_name=inv.guest_display_name,
            expires_at=inv.expires_at,
            accepted_at=inv.accepted_at,
            created_at=inv.created_at,
        ) for inv in invites],
        count=len(invites),
    )


@router.post("/sessions/{session_id}/guest-invites/{invite_id}/accept", response_model=BroadcastGuestAcceptOut)
def accept_guest_invite_route(session_id: str, invite_id: str, body: BroadcastGuestAcceptIn, ctx: dict = Depends(_ctx)):
    """Guest accepts an invite to co-stream."""
    _ensure_multi_input_enabled()
    _ = get_session(session_id)

    from app.services.broadcast_input_store import accept_guest_invite, get_guest_invite
    invite = accept_guest_invite(
        session_id,
        invite_id,
        guest_user_id=ctx["user_sub"],
        guest_display_name=body.display_name,
    )

    broadcast_sse_publish(session_id, {
        "_type": "guest:accepted",
        "invite_id": invite_id,
        "input_id": invite.input_id,
        "guest_user_id": ctx["user_sub"],
        "guest_display_name": body.display_name,
    })

    return BroadcastGuestAcceptOut(
        invite_id=invite_id,
        input_id=invite.input_id,
        ingest_url=invite.ingest_url,
        join_mode=invite.join_mode,
        session_id=session_id,
    )


@router.post("/sessions/{session_id}/guest-invites/{invite_id}/revoke")
def revoke_guest_invite_route(session_id: str, invite_id: str, ctx: dict = Depends(_ctx)):
    """Revoke a guest invite."""
    _ensure_multi_input_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can revoke invites.")

    from app.services.broadcast_input_store import revoke_guest_invite
    invite = revoke_guest_invite(session_id, invite_id)

    broadcast_sse_publish(session_id, {
        "_type": "guest:revoked",
        "invite_id": invite_id,
    })

    return {"ok": True, "invite_id": invite_id, "status": "revoked"}


@router.post("/sessions/{session_id}/guests/{input_id}/remove")
def remove_guest_route(session_id: str, input_id: str, ctx: dict = Depends(_ctx)):
    """Remove a guest from the broadcast."""
    _ensure_multi_input_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can remove guests.")

    from app.services.broadcast_input_store import mark_input_live
    mark_input_live(session_id, input_id, is_live=False)

    from app.services.broadcast_webrtc_relay import stop_relay
    stop_relay(session_id, input_id)

    broadcast_sse_publish(session_id, {
        "_type": "guest:removed",
        "input_id": input_id,
    })

    return {"ok": True, "input_id": input_id}


@router.post("/sessions/{session_id}/guests/{input_id}/mute")
def mute_guest_route(session_id: str, input_id: str, body: BroadcastGuestMuteIn, ctx: dict = Depends(_ctx)):
    """Mute or unmute a guest."""
    _ensure_multi_input_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can mute guests.")

    from app.services.broadcast_input_store import get_input
    _ = get_input(session_id, input_id)  # 404 if not found

    broadcast_sse_publish(session_id, {
        "_type": "guest:muted",
        "input_id": input_id,
        "muted": body.muted,
    })

    return {"ok": True, "input_id": input_id, "muted": body.muted}


@router.post("/sessions/{session_id}/guests/{input_id}/promote")
def promote_guest_route(session_id: str, input_id: str, ctx: dict = Depends(_ctx)):
    """Promote a guest to primary input."""
    _ensure_multi_input_enabled()
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can promote guests.")

    from app.services.broadcast_input_store import get_input
    _ = get_input(session_id, input_id)  # 404 if not found

    update_session_fields(session_id, {"primary_input_id": input_id})

    broadcast_sse_publish(session_id, {
        "_type": "guest:promoted",
        "input_id": input_id,
    })

    return {"ok": True, "input_id": input_id, "promoted": True}


@router.post("/sessions/{session_id}/inputs/{input_id}/webrtc-offer", response_model=BroadcastWebRTCOfferOut)
def webrtc_offer_route(session_id: str, input_id: str, body: BroadcastWebRTCOfferIn, ctx: dict = Depends(_ctx)):
    """Submit a WebRTC SDP offer for browser-based guest streaming."""
    _ensure_multi_input_enabled()
    _ = get_session(session_id)

    from app.services.broadcast_input_store import get_input
    inp = get_input(session_id, input_id)

    from app.services.broadcast_webrtc_relay import start_relay
    result = start_relay(
        session_id=session_id,
        input_id=input_id,
        rtmp_target_url=inp.ingest_url or "",
        sdp_offer=body.sdp_offer,
    )

    return BroadcastWebRTCOfferOut(
        sdp_answer=result.get("sdp_answer", ""),
        session_id=session_id,
        input_id=input_id,
    )


# ─── Live Q&A Mode Endpoints (ENGAGE-003) ────────────────────────


class QAModeToggleIn(BaseModel):
    enabled: bool


class QAQuestionSubmitIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=500)


def _is_session_owner_or_moderator(session, user_sub: str) -> bool:
    """Check if user is the session owner or a moderator."""
    created_by = session.created_by if hasattr(session, "created_by") else session.get("created_by")
    if created_by == user_sub:
        return True
    moderators = session.moderators if hasattr(session, "moderators") else session.get("moderators")
    if moderators and user_sub in moderators:
        return True
    return False


@router.post("/sessions/{session_id}/qa-mode")
def toggle_qa_mode(
    session_id: str,
    body: QAModeToggleIn,
    ctx: dict = Depends(_ctx),
):
    """Toggle Q&A mode on a broadcast session. Owner only."""
    session = get_session(session_id)
    if session.created_by != ctx["user_sub"]:
        raise HTTPException(403, "Only the session owner can toggle Q&A mode")

    update_session_fields(session_id, {"qa_mode_enabled": body.enabled})
    broadcast_sse_publish(session_id, {
        "_type": "qa:mode_toggle",
        "enabled": body.enabled,
    })
    return {"ok": True, "qa_mode_enabled": body.enabled}


@router.post("/sessions/{session_id}/qa/questions")
def submit_qa_question(
    session_id: str,
    body: QAQuestionSubmitIn,
    ctx: dict = Depends(_ctx),
):
    """Submit a question to the Q&A queue."""
    display_name = ctx.get("display_name", ctx["user_sub"])
    return _qa_submit_question(
        session_id=session_id,
        user_id=ctx["user_sub"],
        display_name=display_name,
        text=body.text,
    )


@router.get("/sessions/{session_id}/qa/questions")
def list_qa_questions(
    session_id: str,
    status_filter: str = Query(default="pending", alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: dict = Depends(_ctx),
):
    """List questions in the Q&A queue."""
    session = get_session(session_id)
    is_owner_or_mod = _is_session_owner_or_moderator(session, ctx["user_sub"])

    # Regular viewers can only see featured and answered
    if not is_owner_or_mod and status_filter == "pending":
        raise HTTPException(403, "Only the broadcaster can view pending questions")

    questions = _qa_list_questions(session_id, status=status_filter, limit=limit)
    return {"questions": questions, "has_more": len(questions) >= limit}


@router.post("/sessions/{session_id}/qa/questions/{question_id}/feature")
def feature_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(_ctx),
):
    """Feature a question (broadcaster/moderator only)."""
    session = get_session(session_id)
    if not _is_session_owner_or_moderator(session, ctx["user_sub"]):
        raise HTTPException(403, "Only broadcaster/moderator can feature questions")
    return _qa_feature_question(session_id, question_id, ctx["user_sub"])


@router.post("/sessions/{session_id}/qa/questions/{question_id}/answer")
def answer_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(_ctx),
):
    """Mark a featured question as answered."""
    session = get_session(session_id)
    if not _is_session_owner_or_moderator(session, ctx["user_sub"]):
        raise HTTPException(403, "Only broadcaster/moderator can answer questions")
    return _qa_answer_question(session_id, question_id, ctx["user_sub"])


@router.post("/sessions/{session_id}/qa/questions/{question_id}/dismiss")
def dismiss_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(_ctx),
):
    """Dismiss a question."""
    session = get_session(session_id)
    if not _is_session_owner_or_moderator(session, ctx["user_sub"]):
        raise HTTPException(403, "Only broadcaster/moderator can dismiss questions")
    return _qa_dismiss_question(session_id, question_id, ctx["user_sub"])


@router.post("/sessions/{session_id}/qa/questions/{question_id}/remove")
def remove_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(_ctx),
):
    """Remove a question (moderator action)."""
    session = get_session(session_id)
    if not _is_session_owner_or_moderator(session, ctx["user_sub"]):
        raise HTTPException(403, "Only broadcaster/moderator can remove questions")
    return _qa_remove_question(session_id, question_id, ctx["user_sub"])


@router.post("/sessions/{session_id}/qa/questions/{question_id}/upvote")
def upvote_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(_ctx),
):
    """Upvote a question."""
    return _qa_upvote_question(session_id, question_id, ctx["user_sub"])


@router.delete("/sessions/{session_id}/qa/questions/{question_id}/upvote")
def remove_upvote_qa_question(
    session_id: str,
    question_id: str,
    ctx: dict = Depends(_ctx),
):
    """Remove upvote from a question."""
    return _qa_remove_upvote(session_id, question_id, ctx["user_sub"])


@router.get("/sessions/{session_id}/qa/featured")
def get_featured_qa_question(
    session_id: str,
    ctx: dict = Depends(_ctx),
):
    """Get the currently featured question, or 204 if none."""
    from fastapi.responses import Response
    featured = _qa_get_featured_question(session_id)
    if not featured:
        return Response(status_code=204)
    return featured


@router.get("/sessions/{session_id}/qa/stats")
def get_qa_stats_endpoint(
    session_id: str,
    ctx: dict = Depends(_ctx),
):
    """Get Q&A engagement statistics for a session."""
    session = get_session(session_id)
    if not _is_session_owner_or_moderator(session, ctx["user_sub"]):
        raise HTTPException(403, "Only broadcaster/moderator can view stats")
    return _qa_get_qa_stats(session_id)
