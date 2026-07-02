

# =====================================================================
# AUDIO ROOM (LiveKit) — broadcast stage endpoints (mode="audio_room")
# Transport-neutral roster/roles in broadcast_stage_store; token + server-
# authoritative controls via LiveKit. All LiveKit control is best-effort:
# the stage store is the source of truth for the roster, LiveKit enforces.
# =====================================================================
import logging as _ar_logging
from app.services import broadcast_stage_store as _stage

_ar_log = _ar_logging.getLogger("broadcast.audioroom")


class StageUserIn(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=256)


def _livekit_cfg():
    from app.core.settings import S
    return (
        getattr(S, "livekit_url", "") or "",
        getattr(S, "livekit_api_key", "") or "",
        getattr(S, "livekit_api_secret", "") or "",
        getattr(S, "livekit_control_url", "") or "http://127.0.0.1:7880",
    )


def _is_host(session, ctx: dict) -> bool:
    return ctx.get("user_sub") == session.created_by or ctx.get("role") == "root"


def _require_audio_room(session):
    if getattr(session, "mode", "video") != "audio_room":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "BROADCAST_NOT_AUDIO_ROOM", "detail": "session is not an audio_room"},
        )


def _mint_livekit_token(session_id: str, uid: str, is_speaker: bool) -> str:
    import livekit.api as lkapi
    url, key, secret, _ctrl = _livekit_cfg()
    if not key or not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "LIVEKIT_NOT_CONFIGURED", "detail": "LIVEKIT_API_KEY/SECRET not set"},
        )
    grants = lkapi.VideoGrants(
        room_join=True,
        room=session_id,
        can_subscribe=True,
        can_publish=bool(is_speaker),
        can_publish_data=True,
        can_publish_sources=["microphone"] if is_speaker else [],
    )
    return lkapi.AccessToken(key, secret).with_identity(uid).with_grants(grants).to_jwt()


def _livekit_run(coro):
    import asyncio
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


async def _lk_set_can_publish(session_id: str, uid: str, can_publish: bool):
    import livekit.api as lkapi
    _url, key, secret, ctrl = _livekit_cfg()
    lk = lkapi.LiveKitAPI(ctrl, key, secret)
    try:
        req = lkapi.UpdateParticipantRequest(
            room=session_id,
            identity=uid,
            permission=lkapi.ParticipantPermission(
                can_subscribe=True,
                can_publish=bool(can_publish),
                can_publish_data=True,
            ),
        )
        return await lk.room.update_participant(req)
    finally:
        await lk.aclose()


async def _lk_mute(session_id: str, uid: str, muted: bool):
    import livekit.api as lkapi
    _url, key, secret, ctrl = _livekit_cfg()
    lk = lkapi.LiveKitAPI(ctrl, key, secret)
    try:
        pi = await lk.room.get_participant(
            lkapi.RoomParticipantIdentity(room=session_id, identity=uid)
        )
        track_sid = None
        for t in getattr(pi, "tracks", []):
            # AUDIO track type == 1 in the LiveKit proto; source MICROPHONE == 2
            if int(getattr(t, "type", -1)) == 1 or int(getattr(t, "source", -1)) == 2:
                track_sid = t.sid
                break
        if not track_sid:
            return {"ok": False, "reason": "no_published_audio_track"}
        await lk.room.mute_published_track(
            lkapi.MuteRoomTrackRequest(room=session_id, identity=uid, track_sid=track_sid, muted=bool(muted))
        )
        return {"ok": True, "track_sid": track_sid}
    finally:
        await lk.aclose()


def _lk_control(coro):
    """Run a LiveKit control coroutine best-effort; never raise to the caller."""
    try:
        return {"applied": True, "result": str(_livekit_run(coro))[:200]}
    except Exception as exc:  # noqa: BLE001
        _ar_log.warning("livekit control best-effort failure: %s", exc)
        return {"applied": False, "error": str(exc)[:200]}


def _fanout_stage_event(target_user_id: str, event_type: str, session_id: str, payload: dict) -> None:
    """Fan a stage.* event to a user's /messaging/events/poll queue (best-effort)."""
    try:
        from app.routers.messaging import tbl_events, now_ts as _mnow, _event_id
        ts = _mnow()
        body = {"session_id": session_id}
        body.update(payload or {})
        tbl_events.put_item(Item={
            "user_id": target_user_id,
            "event_id": _event_id(),
            "type": event_type,
            "created_at": ts,
            "conversation_id": "broadcast:" + session_id,
            "payload": body,
            "ttl": ts + 7 * 24 * 3600,
        })
    except Exception as exc:  # noqa: BLE001
        _ar_log.warning("stage event fanout failed (%s -> %s): %s", event_type, target_user_id, exc)


def _stage_roster_payload(session) -> dict:
    r = _stage.roster(session.id)
    spk = len(r["speakers"])
    try:
        viewers = _get_viewer_count(session.id)
    except Exception:
        viewers = 0
    listener_count = max(0, int(viewers) - spk)
    return {
        "speakers": r["speakers"],
        "hands": r["hands"],
        "speaker_count": spk,
        "listener_count": listener_count,
        "stage_max_slots": int(getattr(session, "stage_max_slots", 20) or 20),
    }


@router.post("/sessions/{session_id}/stage/request")
def stage_request_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Listener raises a hand to request the stage."""
    session = get_session(session_id)
    _require_audio_room(session)
    uid = ctx["user_sub"]
    if _is_host(session, ctx):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail={"code": "STAGE_HOST_CANNOT_REQUEST", "detail": "host is already on stage"})
    rec = _stage.raise_hand(session_id, uid)
    # notify the host to refresh the roster
    _fanout_stage_event(session.created_by, "stage.hand", session_id,
                        {"user_id": uid, "hand_raised": True})
    return {"ok": True, "record": rec}


@router.get("/sessions/{session_id}/stage")
def stage_roster_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Roster: {speakers[], hands[], speaker_count, listener_count, stage_max_slots}."""
    session = get_session(session_id)
    _require_audio_room(session)
    if _is_host(session, ctx):
        _stage.ensure_host(session_id, ctx["user_sub"])  # lazily seat the host
    return _stage_roster_payload(session)


@router.post("/sessions/{session_id}/stage/promote")
def stage_promote_route(session_id: str, body: StageUserIn, ctx: dict = Depends(_ctx)):
    """Host/root promotes a listener to speaker (slot-clamped + LiveKit can_publish=true)."""
    session = get_session(session_id)
    _require_audio_room(session)
    if not _is_host(session, ctx):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail={"code": "STAGE_HOST_ONLY", "detail": "host or root required"})
    target = body.user_id
    max_slots = int(getattr(session, "stage_max_slots", 20) or 20)
    existing = _stage.get_record(session_id, target)
    already_on_stage = bool(existing and existing["role"] in _stage.STAGE_ROLES_ON_STAGE)
    if not already_on_stage and _stage.speaker_count(session_id) >= max_slots:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"code": "STAGE_FULL", "detail": "stage_max_slots=" + str(max_slots) + " reached"})
    rec = _stage.promote(session_id, target)
    lk = _lk_control(_lk_set_can_publish(session_id, target, True))
    _fanout_stage_event(target, "stage.promote", session_id, {"user_id": target, "role": "speaker"})
    return {"ok": True, "record": rec, "livekit": lk, "roster": _stage_roster_payload(session)}


@router.post("/sessions/{session_id}/stage/demote")
def stage_demote_route(session_id: str, body: StageUserIn, ctx: dict = Depends(_ctx)):
    """Host/root demotes a speaker back to listener (LiveKit can_publish=false)."""
    session = get_session(session_id)
    _require_audio_room(session)
    if not _is_host(session, ctx):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail={"code": "STAGE_HOST_ONLY", "detail": "host or root required"})
    target = body.user_id
    _stage.remove(session_id, target)
    lk = _lk_control(_lk_set_can_publish(session_id, target, False))
    _fanout_stage_event(target, "stage.demote", session_id, {"user_id": target, "role": "listener"})
    return {"ok": True, "livekit": lk, "roster": _stage_roster_payload(session)}


@router.post("/sessions/{session_id}/stage/mute")
def stage_mute_route(session_id: str, body: StageUserIn, ctx: dict = Depends(_ctx)):
    """Host/root force-mutes a speaker's mic via LiveKit."""
    session = get_session(session_id)
    _require_audio_room(session)
    if not _is_host(session, ctx):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail={"code": "STAGE_HOST_ONLY", "detail": "host or root required"})
    target = body.user_id
    _stage.set_mic_muted(session_id, target, True)
    lk = _lk_control(_lk_mute(session_id, target, True))
    _fanout_stage_event(target, "stage.mute", session_id, {"user_id": target, "mic_muted": True})
    return {"ok": True, "livekit": lk}


@router.post("/sessions/{session_id}/stage/unmute")
def stage_unmute_route(session_id: str, body: StageUserIn, ctx: dict = Depends(_ctx)):
    """Host/root unmutes a speaker's mic via LiveKit (the speaker may still self-mute)."""
    session = get_session(session_id)
    _require_audio_room(session)
    if not _is_host(session, ctx):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail={"code": "STAGE_HOST_ONLY", "detail": "host or root required"})
    target = body.user_id
    _stage.set_mic_muted(session_id, target, False)
    lk = _lk_control(_lk_mute(session_id, target, False))
    _fanout_stage_event(target, "stage.unmute", session_id, {"user_id": target, "mic_muted": False})
    return {"ok": True, "livekit": lk}


@router.post("/sessions/{session_id}/stage/leave")
def stage_leave_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Caller steps down off the stage (self-demote)."""
    session = get_session(session_id)
    _require_audio_room(session)
    uid = ctx["user_sub"]
    _stage.remove(session_id, uid)
    lk = _lk_control(_lk_set_can_publish(session_id, uid, False))
    return {"ok": True, "livekit": lk}


@router.get("/sessions/{session_id}/livekit-token")
def stage_livekit_token_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Mint a LiveKit join token for the caller per their current stage role.

    Speaker (host or on-stage speaker) => can_publish; otherwise listener.
    """
    session = get_session(session_id)
    _require_audio_room(session)
    uid = ctx["user_sub"]
    url, _key, _secret, _ctrl = _livekit_cfg()
    if _is_host(session, ctx):
        _stage.ensure_host(session_id, uid)
        is_speaker = True
        role = "host"
    else:
        rec = _stage.get_record(session_id, uid)
        is_speaker = bool(rec and rec["role"] in _stage.STAGE_ROLES_ON_STAGE)
        role = rec["role"] if rec else "listener"
    token = _mint_livekit_token(session_id, uid, is_speaker)
    return {
        "token": token,
        "url": url,
        "room": session_id,
        "identity": uid,
        "role": role,
        "can_publish": is_speaker,
    }
