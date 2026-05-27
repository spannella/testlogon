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
        raw = T.broadcast_sessions.get_item(Key={"session_id": session_id}).get("Item", {})
        check_geo_access(request, raw.get("geo_mode"), raw.get("geo_countries"))
    return _to_session_out(session)


@router.post("/sessions/{session_id}/playback-url", response_model=BroadcastPlaybackUrlOut)
def mint_playback_url_route(session_id: str, ctx: dict = Depends(_ctx)):
    _ = ctx
    session = get_session(session_id)
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
def viewer_join_route(session_id: str, request: Request, ctx: dict = Depends(_ctx)):
    """Register as a viewer. Called when playback begins."""
    session = get_session(session_id)  # 404 if session doesn't exist
    # Geo-check for viewers
    if session.created_by != ctx["user_sub"]:
        from app.services.geo_check import check_geo_access
        raw = T.broadcast_sessions.get_item(Key={"session_id": session_id}).get("Item", {})
        check_geo_access(request, raw.get("geo_mode"), raw.get("geo_countries"))
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


# ─── Live Chat Endpoints (BCAST-005) ─────────────────────────────


class BroadcastChatSendIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=280)


class BroadcastChatProductLinkOut(BaseModel):
    item_id: str
    category_id: str
    name: str
    description: Optional[str] = None
    price_cents: int
    currency: str = "USD"
    image_url: Optional[str] = None


class BroadcastChatMessageOut(BaseModel):
    message_id: str
    session_id: str
    sender_id: str
    sender_display_name: str
    text: str
    kind: str = "text"
    product_link: Optional[BroadcastChatProductLinkOut] = None
    created_at: int
    deleted: bool = False


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
    )
    return BroadcastChatMessageOut(
        message_id=result["message_id"],
        session_id=result["session_id"],
        sender_id=result["sender_id"],
        sender_display_name=result["sender_display_name"],
        text=result["text"],
        created_at=result["created_at"],
        deleted=result["deleted"],
    )


@router.get("/sessions/{session_id}/chat", response_model=BroadcastChatHistoryOut)
def get_chat_history_route(
    session_id: str,
    limit: int = Query(default=100, ge=1, le=200),
    before: Optional[str] = Query(default=None),
    ctx: dict = Depends(_ctx),
):
    """Load recent chat history for a broadcast session."""
    _ = ctx
    _ = get_session(session_id)  # 404 if session doesn't exist
    result = _store_get_history(session_id, limit=limit, before_sort_key=before)
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
                    cursor = msg["sort_key"]
                    if msg.get("deleted"):
                        payload = json.dumps({"message_id": msg["message_id"]}, separators=(",", ":"))
                        yield f"event: chat:delete\ndata: {payload}\n\n"
                    else:
                        out = _chat_msg_out(msg)
                        payload = json.dumps(out, separators=(",", ":"), default=str)
                        event_type = "chat:product_link" if out.get("kind") == "product_link" else "chat:message"
                        yield f"event: {event_type}\ndata: {payload}\n\n"
                last_ping = time.time()
                continue

            await asyncio.sleep(poll_ms / 1000.0)

    return StreamingResponse(gen(), media_type="text/event-stream")


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
