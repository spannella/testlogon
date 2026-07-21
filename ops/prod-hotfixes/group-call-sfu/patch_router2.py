p = "app/routers/group_calls.py"
s = open(p).read()
assert "group_call_livekit_token_endpoint" not in s, "token endpoint already present"
addition = '''

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
'''
s = s.rstrip("\n") + "\n" + addition
open(p, "w").write(s)
print("token endpoint appended")
