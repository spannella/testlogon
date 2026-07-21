"""Group Video Call endpoints (CALL-012).

REST API for group call lifecycle: create, join, leave, end, status,
participants, signaling relay, and media state updates.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy

from app.core.settings import S
from app.models import (
    GroupCallCreateIn,
    GroupCallEndOut,
    GroupCallJoinOut,
    GroupCallLeaveOut,
    GroupCallMediaStatus,
    GroupCallMediaUpdateIn,
    GroupCallMediaUpdateOut,
    GroupCallOut,
    GroupCallParticipantOut,
    GroupCallParticipantsOut,
    GroupCallSignalIn,
    GroupCallSignalOut,
    GroupCallSignalingInfo,
)
from app.services.group_call_service import (
    GroupCallError,
    create_group_call,
    end_call,
    get_active_call_for_conversation,
    get_call,
    join_call,
    leave_call,
    list_call_history,
    list_participants,
    relay_signal,
    update_media_state,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/calls/group", tags=["group-calls"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])


# ---------------------------------------------------------------------------
# Auth dependency — reuse from messaging router
# ---------------------------------------------------------------------------


async def _get_user(request: Request) -> dict:
    """Extract user info from session (cookie auth + CSRF)."""
    from app.routers.messaging import get_messaging_user_id

    authorization = request.headers.get("authorization")
    x_session_id = request.headers.get("x-session-id")
    user_id = await get_messaging_user_id(request, authorization=authorization, x_session_id=x_session_id)

    # Extract role from session context if available
    role = "USER"
    ctx = getattr(request.state, "session_context", None)
    if isinstance(ctx, dict):
        role = str(ctx.get("role") or "USER")

    return {"user_id": user_id, "role": role}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _participant_out(p: dict) -> GroupCallParticipantOut:
    ms = p.get("media_status") or {}
    return GroupCallParticipantOut(
        user_id=str(p.get("user_id") or ""),
        display_name=str(p.get("display_name") or p.get("user_id") or ""),
        joined_at=int(p.get("joined_at") or 0),
        left_at=int(p.get("left_at") or 0),
        media_status=GroupCallMediaStatus(
            audio=bool(ms.get("audio", True)),
            video=bool(ms.get("video", True)),
            screen=bool(ms.get("screen", False)),
        ),
        connection_quality=str(p.get("connection_quality") or "good"),
        state=str(p.get("state") or "active"),
    )


def _call_out(meta: dict, participants: Optional[list[dict]] = None) -> GroupCallOut:
    parts = participants or []
    start_ts = int(meta.get("start_ts") or 0)
    end_ts = int(meta.get("end_ts") or 0)
    duration = max(0, end_ts - start_ts) if start_ts > 0 and end_ts > 0 else 0

    return GroupCallOut(
        call_id=str(meta.get("call_id") or ""),
        conversation_id=str(meta.get("conversation_id") or ""),
        creator_user_id=str(meta.get("creator_user_id") or ""),
        state=str(meta.get("state") or "created"),
        mode=str(meta.get("mode") or "video"),
        max_participants=int(meta.get("max_participants") or S.group_call_max_participants),
        current_participant_count=int(meta.get("current_participant_count") or 0),
        participants=[_participant_out(p) for p in parts],
        created_at=int(meta.get("created_at") or 0),
        started_at=start_ts,
        end_ts=end_ts,
        end_reason=str(meta.get("end_reason") or ""),
        duration_seconds=duration,
    )


def _livekit_group_call_configured() -> bool:
    """LiveKit SFU is usable for group calls when the shared LiveKit creds
    are set and the provider is selected. Reuses the SAME LiveKit deployment
    the audio rooms use (real selective forwarding + simulcast)."""
    return bool(
        getattr(S, "group_call_sfu_provider", "") == "livekit"
        and getattr(S, "livekit_url", "")
        and getattr(S, "livekit_api_key", "")
        and getattr(S, "livekit_api_secret", "")
    )


def _group_call_room_name(call_id: str) -> str:
    """LiveKit room name for a group call. Namespaced to avoid colliding with
    audio-room (broadcast) sessions on the same LiveKit server."""
    return f"groupcall:{call_id}"


def _signaling_info(call_id: str = "") -> GroupCallSignalingInfo:
    if _livekit_group_call_configured():
        # Route through the existing LiveKit SFU. The client fetches a join
        # token from /livekit-token and connects with the LiveKit client SDK.
        return GroupCallSignalingInfo(
            mode="sfu",
            sfu_provider="livekit",
            livekit_url=getattr(S, "livekit_url", "") or None,
            room_name=_group_call_room_name(call_id) if call_id else None,
            ice_servers=[],
        )
    # A bare (non-LiveKit) SFU endpoint is not implemented as a media path;
    # fall back to the hand-rolled mesh transport, which IS implemented.
    return GroupCallSignalingInfo(
        mode="mesh",
        ice_servers=[{"urls": "stun:stun.l.google.com:19302"}],
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/create", status_code=201)
async def create_call_endpoint(body: GroupCallCreateIn, request: Request, user: dict = Depends(_get_user)):
    try:
        meta = create_group_call(
            conversation_id=body.conversation_id,
            creator_user_id=user["user_id"],
            mode=body.mode,
            max_participants=body.max_participants,
        )
    except GroupCallError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    return _call_out(meta, [])


@router.post("/{call_id}/join")
async def join_call_endpoint(call_id: str, request: Request, user: dict = Depends(_get_user)):
    try:
        meta = join_call(call_id, user["user_id"], display_name=user["user_id"])
    except GroupCallError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    parts = list_participants(call_id)
    active_parts = [p for p in parts if p.get("state") == "active"]

    return GroupCallJoinOut(
        call_id=str(meta.get("call_id") or call_id),
        state=str(meta.get("state") or "active"),
        mode=str(meta.get("mode") or "video"),
        current_participant_count=len(active_parts),
        participants=[_participant_out(p) for p in active_parts],
        signaling=_signaling_info(call_id),
    )


@router.post("/{call_id}/leave")
async def leave_call_endpoint(call_id: str, request: Request, user: dict = Depends(_get_user)):
    try:
        result = leave_call(call_id, user["user_id"])
    except GroupCallError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    return GroupCallLeaveOut(
        ok=True,
        call_ended=bool(result.get("call_ended", False)),
        remaining_participants=int(result.get("remaining_participants", 0)),
    )


@router.post("/{call_id}/end")
async def end_call_endpoint(call_id: str, request: Request, user: dict = Depends(_get_user)):
    try:
        result = end_call(call_id, user["user_id"], role=user.get("role", "USER"))
    except GroupCallError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    return GroupCallEndOut(
        ok=True,
        call_id=str(result.get("call_id") or call_id),
        duration_seconds=int(result.get("duration_seconds") or 0),
        total_participants=int(result.get("total_participants") or 0),
    )


@router.get("/{call_id}")
async def get_call_endpoint(call_id: str, request: Request, user: dict = Depends(_get_user)):
    meta = get_call(call_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Call not found")

    parts = list_participants(call_id)
    return _call_out(meta, parts)


@router.get("/{call_id}/participants")
async def get_participants_endpoint(call_id: str, request: Request, user: dict = Depends(_get_user)):
    meta = get_call(call_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Call not found")

    parts = list_participants(call_id)
    active_count = sum(1 for p in parts if p.get("state") == "active")
    total_joined = sum(1 for p in parts if int(p.get("joined_at") or 0) > 0)

    return GroupCallParticipantsOut(
        participants=[_participant_out(p) for p in parts],
        total_active=active_count,
        total_joined=total_joined,
    )


@router.get("/active/{conversation_id}")
async def get_active_call_endpoint(conversation_id: str, request: Request, user: dict = Depends(_get_user)):
    meta = get_active_call_for_conversation(conversation_id)
    if not meta:
        return {"active": False, "call_id": None}

    parts = list_participants(str(meta.get("call_id") or ""))
    return {"active": True, **_call_out(meta, parts).model_dump()}


@router.get("/history/{conversation_id}")
async def get_call_history_endpoint(conversation_id: str, request: Request, user: dict = Depends(_get_user)):
    calls = list_call_history(conversation_id)
    result = []
    for meta in calls:
        call_id = str(meta.get("call_id") or "")
        parts = list_participants(call_id)
        result.append(_call_out(meta, parts))
    return {"calls": result}


@router.post("/{call_id}/signal")
async def signal_endpoint(call_id: str, body: GroupCallSignalIn, request: Request, user: dict = Depends(_get_user)):
    try:
        result = relay_signal(
            call_id,
            sender_user_id=user["user_id"],
            target_user_id=body.target_user_id,
            signal_type=body.type,
            payload=body.payload,
        )
    except GroupCallError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    return GroupCallSignalOut(ok=True, relayed_to=str(result.get("relayed_to") or ""))


@router.patch("/{call_id}/media")
async def update_media_endpoint(call_id: str, body: GroupCallMediaUpdateIn, request: Request, user: dict = Depends(_get_user)):
    try:
        media = update_media_state(
            call_id,
            user["user_id"],
            audio=body.audio,
            video=body.video,
            screen=body.screen,
        )
    except GroupCallError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    return GroupCallMediaUpdateOut(
        ok=True,
        media_status=GroupCallMediaStatus(
            audio=bool(media.get("audio", True)),
            video=bool(media.get("video", True)),
            screen=bool(media.get("screen", False)),
        ),
    )


# ---------------------------------------------------------------------------
# LiveKit SFU token seam (GAP-0017-sfu)
# ---------------------------------------------------------------------------
#
# Group video calls can route through the SAME LiveKit SFU the audio rooms use
# (real selective forwarding + simulcast — we do NOT hand-roll an SFU). When
# LiveKit is configured (livekit_url/api_key/api_secret + group_call_sfu_provider
# =="livekit"), the join response advertises mode="sfu"/sfu_provider="livekit"
# and the client calls this endpoint to obtain a per-participant join token, then
# connects to livekit_url with the LiveKit client SDK.
#
# Honest degradation: unconfigured -> 503 LIVEKIT_NOT_CONFIGURED (the client
# falls back to mesh, which IS a real media path). SDK missing -> 503. No token
# is ever fabricated.


@router.get("/{call_id}/livekit-token")
async def group_call_livekit_token_endpoint(
    call_id: str, request: Request, user: dict = Depends(_get_user)
):
    """Mint a LiveKit join token for the caller's group call.

    Requires the caller to be an *active* participant of the call (the roster is
    the source of truth; LiveKit enforces the grant). Publish + subscribe are
    granted for both mic and camera (group video call). Screen-share source is
    also allowed so an active participant can present.
    """
    if not _livekit_group_call_configured():
        raise HTTPException(
            status_code=503,
            detail={
                "code": "LIVEKIT_NOT_CONFIGURED",
                "detail": "group-call SFU (LiveKit) not configured; client should use mesh",
            },
        )

    meta = get_call(call_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Call not found")
    if str(meta.get("state") or "") in ("ended", "cancelled"):
        raise HTTPException(status_code=409, detail={"code": "CALL_ENDED", "detail": "call is not active"})

    uid = user["user_id"]
    parts = list_participants(call_id)
    is_active = any(
        str(p.get("user_id")) == str(uid) and p.get("state") == "active" for p in parts
    )
    if not is_active:
        raise HTTPException(
            status_code=403,
            detail={"code": "NOT_IN_CALL", "detail": "join the call before requesting a token"},
        )

    try:
        import livekit.api as lkapi  # provided by livekit-api (same dep as audio rooms)
    except Exception:  # noqa: BLE001 - SDK not installed in this environment
        logger.warning("livekit-api SDK not importable; group-call token unavailable")
        raise HTTPException(
            status_code=503,
            detail={
                "code": "LIVEKIT_SDK_UNAVAILABLE",
                "detail": "livekit-api not installed on server; client should use mesh",
            },
        )

    room = _group_call_room_name(call_id)
    grants = lkapi.VideoGrants(
        room_join=True,
        room=room,
        can_subscribe=True,
        can_publish=True,
        can_publish_data=True,
        can_publish_sources=["microphone", "camera", "screen_share", "screen_share_audio"],
    )
    token = (
        lkapi.AccessToken(S.livekit_api_key, S.livekit_api_secret)
        .with_identity(str(uid))
        .with_grants(grants)
        .to_jwt()
    )
    return {
        "token": token,
        "url": getattr(S, "livekit_url", "") or "",
        "room_name": room,
        "identity": str(uid),
        "provider": "livekit",
    }
