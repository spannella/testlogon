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
)
from app.services.broadcast_recording import (
    get_recording_by_session,
    mint_recording_playback_url,
    mint_recording_thumbnail_url,
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
    )


# ─── Live Chat Endpoints (BCAST-005) ─────────────────────────────


class BroadcastChatSendIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=280)


class BroadcastChatMessageOut(BaseModel):
    message_id: str
    session_id: str
    sender_id: str
    sender_display_name: str
    text: str
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
                        payload = json.dumps(_chat_msg_out(msg), separators=(",", ":"), default=str)
                        yield f"event: chat:message\ndata: {payload}\n\n"
                last_ping = time.time()
                continue

            await asyncio.sleep(poll_ms / 1000.0)

    return StreamingResponse(gen(), media_type="text/event-stream")
