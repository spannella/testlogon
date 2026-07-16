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


def _signaling_info() -> GroupCallSignalingInfo:
    return GroupCallSignalingInfo(
        mode="sfu" if S.group_call_sfu_endpoint else "mesh",
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
        signaling=_signaling_info(),
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
