"""Broadcast delegation router (DELEGATE-004).

Endpoints for delegated broadcast chat moderation (pin, delete, mute, ban,
announce) and broadcast control (start, stop, schedule).
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Query

from app.models import (
    BroadcastMuteIn,
    BroadcastBanIn,
    BroadcastAnnouncementIn,
    BroadcastScheduleIn,
    BroadcastModeratorOut,
    BroadcastBanOut,
    BroadcastModerationLogEntry,
)
from app.services import delegate_broadcast as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/broadcast/delegate", tags=["broadcast-delegation"])


# ---------------------------------------------------------------------------
# Chat moderation
# ---------------------------------------------------------------------------


@router.post("/{creator_id}/sessions/{sid}/chat/{mid}/pin")
async def pin_message(
    creator_id: str,
    sid: str,
    mid: str,
    user=Depends(require_ui_session),
):
    """Pin a chat message in a broadcast session."""
    return svc.pin_chat_message(
        session_id=sid,
        message_id=mid,
        moderator_id=user["user_sub"],
        creator_id=creator_id,
    )


@router.delete("/{creator_id}/sessions/{sid}/chat/{mid}/pin")
async def unpin_message(
    creator_id: str,
    sid: str,
    mid: str,
    user=Depends(require_ui_session),
):
    """Unpin a chat message in a broadcast session."""
    return svc.unpin_chat_message(
        session_id=sid,
        message_id=mid,
        moderator_id=user["user_sub"],
        creator_id=creator_id,
    )


@router.delete("/{creator_id}/sessions/{sid}/chat/{mid}")
async def delete_message(
    creator_id: str,
    sid: str,
    mid: str,
    user=Depends(require_ui_session),
):
    """Delete a chat message from a broadcast session."""
    return svc.delete_moderated_message(
        session_id=sid,
        message_id=mid,
        moderator_id=user["user_sub"],
        creator_id=creator_id,
    )


@router.post("/{creator_id}/sessions/{sid}/mute")
async def mute_viewer(
    creator_id: str,
    sid: str,
    body: BroadcastMuteIn,
    user=Depends(require_ui_session),
):
    """Mute a viewer in broadcast chat."""
    return svc.mute_viewer(
        session_id=sid,
        user_id=body.user_id,
        moderator_id=user["user_sub"],
        creator_id=creator_id,
        duration_seconds=body.duration_seconds,
    )


@router.post("/{creator_id}/sessions/{sid}/ban")
async def ban_viewer(
    creator_id: str,
    sid: str,
    body: BroadcastBanIn,
    user=Depends(require_ui_session),
):
    """Ban a viewer from broadcast chat."""
    return svc.ban_viewer(
        session_id=sid,
        user_id=body.user_id,
        moderator_id=user["user_sub"],
        creator_id=creator_id,
        reason=body.reason,
    )


@router.delete("/{creator_id}/sessions/{sid}/ban/{uid}")
async def unban_viewer(
    creator_id: str,
    sid: str,
    uid: str,
    user=Depends(require_ui_session),
):
    """Unban a viewer from broadcast chat."""
    return svc.unban_viewer(
        session_id=sid,
        user_id=uid,
        moderator_id=user["user_sub"],
        creator_id=creator_id,
    )


@router.post("/{creator_id}/sessions/{sid}/announcement")
async def post_announcement(
    creator_id: str,
    sid: str,
    body: BroadcastAnnouncementIn,
    user=Depends(require_ui_session),
):
    """Post an announcement in broadcast chat."""
    return svc.post_announcement(
        session_id=sid,
        moderator_id=user["user_sub"],
        creator_id=creator_id,
        text=body.text,
    )


# ---------------------------------------------------------------------------
# Broadcast control
# ---------------------------------------------------------------------------


@router.post("/{creator_id}/sessions/{sid}/start")
async def start_broadcast(
    creator_id: str,
    sid: str,
    user=Depends(require_ui_session),
):
    """Start a broadcast on behalf of the creator."""
    return svc.start_broadcast_as_delegate(
        session_id=sid,
        delegate_id=user["user_sub"],
        creator_id=creator_id,
    )


@router.post("/{creator_id}/sessions/{sid}/stop")
async def stop_broadcast(
    creator_id: str,
    sid: str,
    user=Depends(require_ui_session),
):
    """Stop a broadcast on behalf of the creator."""
    return svc.stop_broadcast_as_delegate(
        session_id=sid,
        delegate_id=user["user_sub"],
        creator_id=creator_id,
    )


@router.post("/{creator_id}/sessions/schedule")
async def schedule_broadcast(
    creator_id: str,
    body: BroadcastScheduleIn,
    user=Depends(require_ui_session),
):
    """Schedule a broadcast on behalf of the creator."""
    return svc.schedule_broadcast_as_delegate(
        delegate_id=user["user_sub"],
        creator_id=creator_id,
        title=body.title,
        scheduled_at=body.scheduled_at,
        profile_id=body.profile_id,
    )


# ---------------------------------------------------------------------------
# Moderator management
# ---------------------------------------------------------------------------


@router.post("/{creator_id}/sessions/{sid}/moderator/register")
async def register_moderator(
    creator_id: str,
    sid: str,
    user=Depends(require_ui_session),
):
    """Register the caller as an active moderator for a broadcast session."""
    return svc.register_moderator(
        session_id=sid,
        moderator_id=user["user_sub"],
        creator_id=creator_id,
    )


@router.get(
    "/{creator_id}/sessions/{sid}/moderators",
    response_model=List[BroadcastModeratorOut],
)
async def list_moderators(
    creator_id: str,
    sid: str,
    user=Depends(require_ui_session),
):
    """List active moderators for a broadcast session."""
    return svc.list_active_moderators(sid)


@router.get(
    "/{creator_id}/sessions/{sid}/bans",
    response_model=List[BroadcastBanOut],
)
async def list_bans(
    creator_id: str,
    sid: str,
    user=Depends(require_ui_session),
):
    """List banned viewers for a broadcast session."""
    return svc.list_banned_viewers(sid)


@router.get(
    "/{creator_id}/sessions/{sid}/moderation-log",
    response_model=List[BroadcastModerationLogEntry],
)
async def get_moderation_log(
    creator_id: str,
    sid: str,
    limit: int = Query(default=100, ge=1, le=500),
    user=Depends(require_ui_session),
):
    """Get moderation action log for a broadcast session."""
    return svc.get_broadcast_moderation_log(sid, limit=limit)
