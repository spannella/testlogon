"""Watch Party router (ENGAGE-004).

Prefix: /ui/watch-parties
"""

from __future__ import annotations

import asyncio
import json
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from app.services.sessions import require_ui_session
from app.models import (
    CreatePartyIn,
    GrantCoHostIn,
    InviteResolveOut,
    ParticipantOut,
    PartyOut,
    PlaybackControlIn,
)
from app.services.broadcast_sse import (
    broadcast_sse_publish,
    broadcast_sse_subscribe,
    broadcast_sse_unsubscribe,
)
from app.services.watch_party import (
    control_playback,
    create_party,
    end_party,
    get_party,
    get_playback_url,
    grant_co_host,
    heartbeat,
    join_party,
    kick_participant,
    leave_party,
    list_host_parties,
    list_participants,
    resolve_invite,
)

router = APIRouter(prefix="/ui/watch-parties", tags=["watch-parties"])


def _user_sub(session: dict) -> str:
    return session["user_sub"]


def _party_out(item: dict) -> PartyOut:
    return PartyOut(
        party_id=item["party_id"],
        host_user_sub=item["host_user_sub"],
        video_id=item["video_id"],
        video_title=item.get("video_title", ""),
        video_duration_seconds=int(item.get("video_duration_seconds", 0)),
        title=item.get("title", ""),
        invite_code=item.get("invite_code", ""),
        status=item.get("status", "waiting"),
        max_participants=int(item.get("max_participants", 50)),
        participant_count=int(item.get("participant_count", 0)),
        position=float(item.get("position", 0)),
        position_updated_at=int(item.get("position_updated_at", 0)),
        created_at=int(item.get("created_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
        ended_at=int(item["ended_at"]) if item.get("ended_at") else None,
    )


def _participant_out(item: dict) -> ParticipantOut:
    return ParticipantOut(
        party_id=item["party_id"],
        user_sub=item["user_sub"],
        role=item.get("role", "member"),
        status=item.get("status", "active"),
        joined_at=int(item.get("joined_at", 0)),
        last_seen=int(item["last_seen"]) if item.get("last_seen") else None,
    )


# ─── Static routes first (before /{party_id}) ──────────────────────────────


@router.get("/join/{invite_code}", response_model=InviteResolveOut)
def resolve_invite_route(invite_code: str, session: dict = Depends(require_ui_session)):
    """Resolve an invite code to party details."""
    item = resolve_invite(invite_code)
    return InviteResolveOut(
        party_id=item["party_id"],
        title=item.get("title", ""),
        host_user_sub=item["host_user_sub"],
        video_title=item.get("video_title", ""),
        status=item.get("status", "waiting"),
        participant_count=int(item.get("participant_count", 0)),
        max_participants=int(item.get("max_participants", 50)),
    )


# ─── CRUD ──────────────────────────────────────────────────────────


@router.post("/", response_model=PartyOut)
def create_party_route(inp: CreatePartyIn, session: dict = Depends(require_ui_session)):
    """Create a new watch party."""
    user_sub = _user_sub(session)

    # Validate video exists and is published
    try:
        from app.services.video_metadata_store import get_video
        video = get_video(inp.video_id)
        if video.status != "published":
            raise HTTPException(status_code=404, detail="video not found or not published")
        video_title = video.title
        video_duration = float(video.duration_seconds or 300)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail="video not found")

    item = create_party(
        host_user_sub=user_sub,
        video_id=inp.video_id,
        video_title=video_title,
        video_duration_seconds=video_duration,
        max_participants=inp.max_participants,
        title=inp.title,
    )
    return _party_out(item)


@router.get("/", response_model=List[PartyOut])
def list_parties_route(session: dict = Depends(require_ui_session)):
    """List the current user's parties (as host)."""
    user_sub = _user_sub(session)
    items = list_host_parties(user_sub)
    return [_party_out(i) for i in items]


@router.get("/{party_id}", response_model=PartyOut)
def get_party_route(party_id: str, session: dict = Depends(require_ui_session)):
    """Get party details by ID."""
    item = get_party(party_id)
    return _party_out(item)


# ─── Join / Leave ──────────────────────────────────────────────────


@router.post("/{party_id}/join", response_model=ParticipantOut)
def join_party_route(party_id: str, session: dict = Depends(require_ui_session)):
    """Join a watch party."""
    user_sub = _user_sub(session)
    item = join_party(party_id, user_sub)
    return _participant_out(item)


@router.post("/{party_id}/leave")
def leave_party_route(party_id: str, session: dict = Depends(require_ui_session)):
    """Leave a watch party."""
    user_sub = _user_sub(session)
    leave_party(party_id, user_sub)
    return {"ok": True}


# ─── End ────────────────────────────────────────────────────────────


@router.post("/{party_id}/end", response_model=PartyOut)
def end_party_route(party_id: str, session: dict = Depends(require_ui_session)):
    """End a watch party (host only)."""
    user_sub = _user_sub(session)
    item = end_party(party_id, user_sub)
    return _party_out(item)


# ─── Playback Control ──────────────────────────────────────────────


@router.post("/{party_id}/control", response_model=PartyOut)
def control_playback_route(
    party_id: str,
    inp: PlaybackControlIn,
    session: dict = Depends(require_ui_session),
):
    """Control playback (host or co-host)."""
    user_sub = _user_sub(session)
    item = control_playback(
        party_id,
        user_sub,
        action=inp.action,
        position=inp.position,
    )
    return _party_out(item)


# ─── Participants ──────────────────────────────────────────────────


@router.get("/{party_id}/participants", response_model=List[ParticipantOut])
def list_participants_route(party_id: str, session: dict = Depends(require_ui_session)):
    """List participants in a party."""
    items = list_participants(party_id)
    return [_participant_out(i) for i in items]


# ─── Co-host ───────────────────────────────────────────────────────


@router.post("/{party_id}/co-host")
def grant_co_host_route(
    party_id: str,
    inp: GrantCoHostIn,
    session: dict = Depends(require_ui_session),
):
    """Grant co-host role to a participant."""
    user_sub = _user_sub(session)
    grant_co_host(party_id, user_sub, inp.user_sub)
    return {"ok": True}


# ─── Kick ──────────────────────────────────────────────────────────


@router.post("/{party_id}/kick/{target_user_sub}")
def kick_participant_route(
    party_id: str,
    target_user_sub: str,
    session: dict = Depends(require_ui_session),
):
    """Kick a participant from the party."""
    user_sub = _user_sub(session)
    kick_participant(party_id, user_sub, target_user_sub)
    return {"ok": True}


# ─── Heartbeat ─────────────────────────────────────────────────────


@router.post("/{party_id}/heartbeat")
def heartbeat_route(party_id: str, session: dict = Depends(require_ui_session)):
    """Send a heartbeat (updates last_seen)."""
    user_sub = _user_sub(session)
    party = heartbeat(party_id, user_sub)
    return _party_out(party)


# ─── Playback URL ──────────────────────────────────────────────────


@router.get("/{party_id}/playback-url")
def playback_url_route(party_id: str, session: dict = Depends(require_ui_session)):
    """Get a playback URL for the party's video."""
    user_sub = _user_sub(session)
    return get_playback_url(party_id, user_sub)


# ─── SSE Stream ────────────────────────────────────────────────────


@router.get("/{party_id}/stream")
async def party_stream_route(party_id: str, session: dict = Depends(require_ui_session)):
    """SSE stream for real-time party events."""
    _ = get_party(party_id)  # 404 if not exists
    q = broadcast_sse_subscribe(party_id)

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
            broadcast_sse_unsubscribe(party_id, q)

    return StreamingResponse(gen(), media_type="text/event-stream")
