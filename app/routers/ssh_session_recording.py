"""SSH Session Recording & Playback API router (INFRA-010).

Prefix: ``/ui/compute/ssh-recordings``

Builds on the existing SSH browser-terminal infra (``browser_ssh_terminal.py`` /
``ssh_key_manager.py``) — it does NOT recreate the SSH bridge. Recordings capture
an SSH session as a timed asciicast-style event stream that can be listed and
played back.

All endpoints use cookie-based session auth (``require_ui_session``). Recordings
are owner-scoped: a user can only see/append/playback/delete their own. A separate
admin endpoint (``require_admin_or_root``) lets oversight roles list any user's
recordings, with an audit event.
"""

from __future__ import annotations

import logging
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.models import (
    AppendSshRecordingEventsIn,
    SshRecordingListOut,
    SshRecordingOut,
    SshRecordingPlaybackOut,
    StartSshRecordingIn,
)
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session
from app.services.ssh_session_recording import (
    InvalidEvent,
    RecordingClosed,
    RecordingLimitExceeded,
    RecordingNotFound,
    append_events,
    delete_recording,
    get_playback,
    get_recording,
    list_recordings,
    start_recording,
    stop_recording,
)

logger = logging.getLogger(__name__)

ssh_session_recording_router = APIRouter(
    prefix="/ui/compute/ssh-recordings", tags=["ssh-session-recording"]
)


def _require_enabled() -> None:
    if not S.ssh_session_recording_enabled:
        raise HTTPException(status_code=503, detail="Session recording is disabled")


# ─── Start ───────────────────────────────────────────────────────

@ssh_session_recording_router.post("", status_code=201, response_model=SshRecordingOut)
async def start_ssh_recording(
    body: StartSshRecordingIn,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_sub = session["user_sub"]
    rec = start_recording(
        user_sub,
        hostname=body.hostname,
        port=body.port,
        username=body.username,
        terminal_cols=body.terminal_cols,
        terminal_rows=body.terminal_rows,
        host_id=body.host_id,
        session_id=body.session_id,
    )
    audit_event(
        "compute.ssh_recording_started", user_sub, request,
        recording_id=rec["recording_id"], host_key=rec["host_key"],
    )
    return SshRecordingOut(**rec)


# ─── List ────────────────────────────────────────────────────────

@ssh_session_recording_router.get("", response_model=SshRecordingListOut)
async def list_ssh_recordings(
    hostname: str = "",
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_sub = session["user_sub"]
    recs = list_recordings(user_sub, hostname=hostname or None)
    return SshRecordingListOut(
        recordings=[SshRecordingOut(**r) for r in recs],
        count=len(recs),
    )


# ─── Get detail ──────────────────────────────────────────────────

@ssh_session_recording_router.get("/{recording_id}", response_model=SshRecordingOut)
async def get_ssh_recording(
    recording_id: str, session: Dict = Depends(require_ui_session)
):
    _require_enabled()
    user_sub = session["user_sub"]
    rec = get_recording(user_sub, recording_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Recording not found")
    return SshRecordingOut(**rec)


# ─── Append events ───────────────────────────────────────────────

@ssh_session_recording_router.post(
    "/{recording_id}/events", response_model=SshRecordingOut
)
async def append_ssh_recording_events(
    recording_id: str,
    body: AppendSshRecordingEventsIn,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_sub = session["user_sub"]
    events = [[e.offset, e.type, e.data] for e in body.events]
    try:
        rec = append_events(user_sub, recording_id, events)
    except RecordingNotFound:
        raise HTTPException(status_code=404, detail="Recording not found")
    except RecordingClosed:
        raise HTTPException(status_code=409, detail="Recording is not active")
    except RecordingLimitExceeded as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except InvalidEvent as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return SshRecordingOut(**rec)


# ─── Stop ────────────────────────────────────────────────────────

@ssh_session_recording_router.post(
    "/{recording_id}/stop", response_model=SshRecordingOut
)
async def stop_ssh_recording(
    recording_id: str,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_sub = session["user_sub"]
    try:
        rec = stop_recording(user_sub, recording_id)
    except RecordingNotFound:
        raise HTTPException(status_code=404, detail="Recording not found")
    audit_event(
        "compute.ssh_recording_stopped", user_sub, request,
        recording_id=recording_id,
        event_count=rec["event_count"], duration_seconds=rec["duration_seconds"],
    )
    return SshRecordingOut(**rec)


# ─── Playback ────────────────────────────────────────────────────

@ssh_session_recording_router.get(
    "/{recording_id}/playback", response_model=SshRecordingPlaybackOut
)
async def playback_ssh_recording(
    recording_id: str, session: Dict = Depends(require_ui_session)
):
    _require_enabled()
    user_sub = session["user_sub"]
    try:
        playback = get_playback(user_sub, recording_id)
    except RecordingNotFound:
        raise HTTPException(status_code=404, detail="Recording not found")
    return SshRecordingPlaybackOut(**playback)


# ─── Delete ──────────────────────────────────────────────────────

@ssh_session_recording_router.delete("/{recording_id}")
async def delete_ssh_recording(
    recording_id: str,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_sub = session["user_sub"]
    if not delete_recording(user_sub, recording_id):
        raise HTTPException(status_code=404, detail="Recording not found")
    audit_event(
        "compute.ssh_recording_deleted", user_sub, request,
        recording_id=recording_id,
    )
    return {"ok": True}


# ─── Admin oversight ─────────────────────────────────────────────

@ssh_session_recording_router.get(
    "/admin/users/{target_user_sub}", response_model=SshRecordingListOut
)
async def admin_list_user_ssh_recordings(
    target_user_sub: str,
    request: Request,
    user=Depends(require_admin_or_root),
):
    _require_enabled()
    audit_event(
        "compute.ssh_recording_admin_view", user.sub, request,
        target_user_sub=target_user_sub,
    )
    recs = list_recordings(target_user_sub)
    return SshRecordingListOut(
        recordings=[SshRecordingOut(**r) for r in recs],
        count=len(recs),
    )
