from __future__ import annotations

import asyncio
import json
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
)
from app.services.broadcast_audit import query_broadcast_actions, record_broadcast_action
from app.services.broadcast_orchestrator import (
    delete_session_with_provider,
    start_session_with_provider,
    stop_session_with_provider,
)
from app.services.broadcast_cloudfront import validate_cloudfront_token
from app.services.broadcast_playback import mint_local_playback_url
from app.services.broadcast_sse import broadcast_sse_subscribe, broadcast_sse_unsubscribe
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
def get_session_route(session_id: str, ctx: dict = Depends(_ctx)):
    _ = ctx
    session = get_session(session_id)
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
def viewer_join_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Register as a viewer. Called when playback begins."""
    _ = get_session(session_id)  # 404 if session doesn't exist
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
