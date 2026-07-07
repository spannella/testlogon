set -e
cd /home/ubuntu/testlogon
TS=$(date +%s)
cp app/routers/messaging.py app/routers/messaging.py.bak_delegrest_$TS
cp app/services/delegates.py app/services/delegates.py.bak_delegrest_$TS
echo "BAK_TS=$TS"
cat > /tmp/newblock.txt <<'NEWBLOCK'
# ─────────────────────────────────────────────────────────────────────────────
# DELEGATE FULL-PARITY — REMAINING KINDS/ACTIONS + REALTIME (DELEGATE-REST)
# Extends the delegate wrapper to voice / voicemail / gif / sticker / arbitrary
# poll (+ vote / write-in / close) / calendar-event / calendar-share /
# find-datetime (+ availability / close) and the message ACTIONS
# read(receipts) / delete / pin / unpin / hide / unhide / typing, PLUS the
# delegate conversation REALTIME (events/poll projected for the creator).
# Same contract as the shipped block: reuse the exact normal handler with
# user_id=creator, attribute to the CREATOR, [via @delegate] where a body
# applies, and audit. TIPS are money-OUT (creator's wallet) so they are gated
# behind a per-delegate can_tip permission (default FALSE) — see
# _delegate_guard_tip, wired into every tip-capable delegate send.
# ─────────────────────────────────────────────────────────────────────────────


class DelegateArbPollVoteIn(BaseModel):
    option_id: str = Field(min_length=1, max_length=64)
    question_id: Optional[str] = Field(default=None, max_length=64)


class DelegateArbPollWriteInIn(BaseModel):
    text: str = Field(min_length=1, max_length=200)
    question_id: Optional[str] = Field(default=None, max_length=64)


def _delegate_guard_tip(creator_id: str, delegate_id: str, inp) -> None:
    """Block a money-OUT tip sent AS the creator unless the delegate holds
    can_tip (default off). A tip debits the CREATOR's wallet, so it is opt-in
    per delegate — parity with every other send stays enabled, tips do not."""
    if not getattr(inp, "tip_amount_cents", None):
        return
    from app.services.delegates import get_delegate
    item = get_delegate(creator_id, delegate_id) or {}
    if "can_tip" not in (item.get("permissions") or []):
        raise HTTPException(
            403,
            "delegate_tip_forbidden: tipping as the creator spends the "
            "creator's money; grant the can_tip delegate permission to allow it",
        )


def _delegate_preview(inp) -> str:
    for f in ("text", "caption", "title", "question"):
        v = getattr(inp, f, None)
        if v:
            return str(v)
    return ""


# ── voice message (presign + create) ────────────────────────────────────────
@router.post("/delegate/{creator_id}/conversations/{conversation_id}/voice-message/presign")
def delegate_presign_voice_message(
    creator_id: str,
    conversation_id: str,
    body: PresignVoiceMessageRequest,
    user_id: str = Depends(get_messaging_user_id),
):
    """Presign a voice-message upload for a delegated (as-creator) send."""
    _delegate_authorize(creator_id, user_id, conversation_id)
    return presign_voice_message(conversation_id=conversation_id, body=body, user_id=creator_id)


@router.post("/delegate/{creator_id}/conversations/{conversation_id}/voice-message", response_model=MessageOut)
def delegate_create_voice_message(
    creator_id: str,
    conversation_id: str,
    body: CreateVoiceMessageRequest,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """VOICE message AS the creator via delegation."""
    tag, hide, dname = _delegate_authorize(creator_id, user_id, conversation_id)
    _delegate_guard_tip(creator_id, user_id, body)
    out = create_voice_message(conversation_id=conversation_id, body=body, req=req, user_id=creator_id)
    _delegate_stamp_and_audit(
        creator_id, user_id, conversation_id, _delegate_mid(out), dname, tag,
        "chat_message_sent", _delegate_preview(body),
    )
    return out


# ── voicemail (presign + create) ─────────────────────────────────────────────
@router.post("/delegate/{creator_id}/conversations/{conversation_id}/voicemail/presign")
def delegate_presign_voicemail(
    creator_id: str,
    conversation_id: str,
    body: PresignVoicemailRequest,
    user_id: str = Depends(get_messaging_user_id),
):
    """Presign a voicemail upload for a delegated (as-creator) send."""
    _delegate_authorize(creator_id, user_id, conversation_id)
    return presign_voicemail(conversation_id=conversation_id, body=body, user_id=creator_id)


@router.post("/delegate/{creator_id}/conversations/{conversation_id}/voicemail", response_model=MessageOut)
def delegate_create_voicemail(
    creator_id: str,
    conversation_id: str,
    body: CreateVoicemailRequest,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """VOICEMAIL (post-call) AS the creator via delegation. Note the handler
    still enforces that the creator is the call's caller."""
    tag, hide, dname = _delegate_authorize(creator_id, user_id, conversation_id)
    out = create_voicemail(conversation_id=conversation_id, body=body, req=req, user_id=creator_id)
    _delegate_stamp_and_audit(
        creator_id, user_id, conversation_id, _delegate_mid(out), dname, tag,
        "chat_message_sent", _delegate_preview(body),
    )
    return out


# ── gif / sticker ────────────────────────────────────────────────────────────
@router.post("/delegate/{creator_id}/conversations/{conversation_id}/messages/gif", response_model=MessageOut, status_code=201)
def delegate_send_gif_message(
    creator_id: str,
    conversation_id: str,
    inp: SendGifMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """GIF message AS the creator via delegation."""
    tag, hide, dname = _delegate_authorize(creator_id, user_id, conversation_id)
    _delegate_tag_input(inp, tag, hide)
    out = send_gif_message(conversation_id=conversation_id, inp=inp, req=req, user_id=creator_id)
    _delegate_stamp_and_audit(
        creator_id, user_id, conversation_id, _delegate_mid(out), dname, tag,
        "chat_message_sent", _delegate_preview(inp),
    )
    return out


@router.post("/delegate/{creator_id}/conversations/{conversation_id}/messages/sticker", response_model=MessageOut, status_code=201)
def delegate_send_sticker_message(
    creator_id: str,
    conversation_id: str,
    inp: SendStickerMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """STICKER message AS the creator via delegation."""
    tag, hide, dname = _delegate_authorize(creator_id, user_id, conversation_id)
    _delegate_tag_input(inp, tag, hide)
    out = send_sticker_message(conversation_id=conversation_id, inp=inp, req=req, user_id=creator_id)
    _delegate_stamp_and_audit(
        creator_id, user_id, conversation_id, _delegate_mid(out), dname, tag,
        "chat_message_sent", _delegate_preview(inp),
    )
    return out


# ── arbitrary poll message (create) ──────────────────────────────────────────
@router.post("/delegate/{creator_id}/conversations/{conversation_id}/messages/poll", response_model=MessageOut, status_code=201)
def delegate_create_poll_message(
    creator_id: str,
    conversation_id: str,
    inp: CreatePollMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """ARBITRARY poll message (question + options + write-in) AS the creator."""
    tag, hide, dname = _delegate_authorize(creator_id, user_id, conversation_id)
    _delegate_tag_input(inp, tag, hide)
    out = create_poll_message(conversation_id=conversation_id, inp=inp, req=req, user_id=creator_id)
    _delegate_stamp_and_audit(
        creator_id, user_id, conversation_id, _delegate_mid(out), dname, tag,
        "chat_message_sent", _delegate_preview(inp),
    )
    return out


def _delegate_msg_poll_conversation(poll_id: str, viewer: str) -> str:
    """Resolve + require a messaging arbitrary-poll and return its conversation."""
    from app.services import arbitrary_polls as _apolls
    snap = _apolls.get_snapshot(poll_id, viewer)
    if not snap:
        raise HTTPException(404, "Poll not found")
    if snap.get("surface") != "messaging" or not snap.get("ref_id"):
        raise HTTPException(400, "Not a messaging poll")
    return snap["ref_id"]


@router.post("/delegate/{creator_id}/polls/{poll_id}/vote")
def delegate_vote_arbitrary_poll(
    creator_id: str,
    poll_id: str,
    body: DelegateArbPollVoteIn,
    user_id: str = Depends(get_messaging_user_id),
):
    """VOTE on a messaging arbitrary poll AS the creator via delegation."""
    conv = _delegate_msg_poll_conversation(poll_id, creator_id)
    _delegate_authorize(creator_id, user_id, conv)
    from app.services import arbitrary_polls as _apolls
    from app.services.delegates import _write_audit
    result = _apolls.vote(poll_id, creator_id, body.option_id, body.question_id)
    try:
        _write_audit(creator_id, user_id, "delegate", "chat_poll_voted", conv,
                     {"poll_id": poll_id, "option_id": body.option_id})
    except Exception:
        logger.warning("delegate: failed to audit poll vote %s", poll_id)
    return result


@router.post("/delegate/{creator_id}/polls/{poll_id}/write-in")
def delegate_write_in_arbitrary_poll(
    creator_id: str,
    poll_id: str,
    body: DelegateArbPollWriteInIn,
    user_id: str = Depends(get_messaging_user_id),
):
    """WRITE-IN answer on a messaging arbitrary poll AS the creator."""
    conv = _delegate_msg_poll_conversation(poll_id, creator_id)
    _delegate_authorize(creator_id, user_id, conv)
    from app.services import arbitrary_polls as _apolls
    from app.services.delegates import _write_audit
    result = _apolls.write_in(poll_id, creator_id, body.text, body.question_id)
    try:
        _write_audit(creator_id, user_id, "delegate", "chat_poll_write_in", conv,
                     {"poll_id": poll_id, "text_preview": (body.text or "")[:100]})
    except Exception:
        logger.warning("delegate: failed to audit poll write-in %s", poll_id)
    return result


@router.post("/delegate/{creator_id}/polls/{poll_id}/close")
def delegate_close_arbitrary_poll(
    creator_id: str,
    poll_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    """CLOSE a messaging arbitrary poll AS the creator via delegation."""
    conv = _delegate_msg_poll_conversation(poll_id, creator_id)
    _delegate_authorize(creator_id, user_id, conv)
    from app.services import arbitrary_polls as _apolls
    from app.services.delegates import _write_audit
    result = _apolls.close(poll_id, creator_id)
    try:
        _write_audit(creator_id, user_id, "delegate", "chat_poll_closed", conv,
                     {"poll_id": poll_id})
    except Exception:
        logger.warning("delegate: failed to audit poll close %s", poll_id)
    return result


# ── calendar-event / calendar-share ──────────────────────────────────────────
@router.post("/delegate/{creator_id}/conversations/{conversation_id}/messages/calendar-event", response_model=MessageOut)
def delegate_create_calendar_event_message(
    creator_id: str,
    conversation_id: str,
    inp: CreateCalendarEventMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """CALENDAR-EVENT share AS the creator (the calendar must be the creator's)."""
    tag, hide, dname = _delegate_authorize(creator_id, user_id, conversation_id)
    _delegate_tag_input(inp, tag, hide)
    out = create_calendar_event_message(conversation_id=conversation_id, inp=inp, req=req, user_id=creator_id)
    _delegate_stamp_and_audit(
        creator_id, user_id, conversation_id, _delegate_mid(out), dname, tag,
        "chat_message_sent", _delegate_preview(inp),
    )
    return out


@router.post("/delegate/{creator_id}/conversations/{conversation_id}/messages/calendar-share", response_model=MessageOut)
def delegate_create_calendar_share_message(
    creator_id: str,
    conversation_id: str,
    inp: CreateCalendarShareMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """CALENDAR-SHARE AS the creator (the calendar must be the creator's)."""
    tag, hide, dname = _delegate_authorize(creator_id, user_id, conversation_id)
    _delegate_tag_input(inp, tag, hide)
    out = create_calendar_share_message(conversation_id=conversation_id, inp=inp, req=req, user_id=creator_id)
    _delegate_stamp_and_audit(
        creator_id, user_id, conversation_id, _delegate_mid(out), dname, tag,
        "chat_message_sent", _delegate_preview(inp),
    )
    return out


# ── find-a-datetime (create + availability + close) ──────────────────────────
@router.post("/delegate/{creator_id}/conversations/{conversation_id}/messages/find-datetime", response_model=MessageOut, status_code=201)
def delegate_create_find_datetime_message(
    creator_id: str,
    conversation_id: str,
    inp: CreateFindDateTimeMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """FIND-A-DATETIME poll message AS the creator via delegation."""
    tag, hide, dname = _delegate_authorize(creator_id, user_id, conversation_id)
    _delegate_tag_input(inp, tag, hide)
    out = create_find_datetime_message(conversation_id=conversation_id, inp=inp, req=req, user_id=creator_id)
    _delegate_stamp_and_audit(
        creator_id, user_id, conversation_id, _delegate_mid(out), dname, tag,
        "chat_message_sent", _delegate_preview(inp),
    )
    return out


@router.post("/delegate/{creator_id}/messages/find-datetime/{poll_id}/availability")
def delegate_submit_find_datetime_availability(
    creator_id: str,
    poll_id: str,
    inp: SubmitAvailabilityIn,
    user_id: str = Depends(get_messaging_user_id),
):
    """Submit availability on a Find-a-DateTime poll AS the creator."""
    meta = _fadt_meta_or_404(poll_id)
    conv = meta.get("conversation_id")
    _delegate_authorize(creator_id, user_id, conv)
    from app.services.delegates import _write_audit
    result = submit_find_datetime_availability(poll_id=poll_id, inp=inp, user_id=creator_id)
    try:
        _write_audit(creator_id, user_id, "delegate", "chat_find_datetime_availability", conv,
                     {"poll_id": poll_id})
    except Exception:
        logger.warning("delegate: failed to audit fadt availability %s", poll_id)
    return result


@router.post("/delegate/{creator_id}/messages/find-datetime/{poll_id}/close")
def delegate_close_find_datetime(
    creator_id: str,
    poll_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    """Close a Find-a-DateTime poll AS the creator (creator must own the poll)."""
    meta = _fadt_meta_or_404(poll_id)
    conv = meta.get("conversation_id")
    _delegate_authorize(creator_id, user_id, conv)
    from app.services.delegates import _write_audit
    result = close_find_datetime(poll_id=poll_id, user_id=creator_id)
    try:
        _write_audit(creator_id, user_id, "delegate", "chat_find_datetime_closed", conv,
                     {"poll_id": poll_id})
    except Exception:
        logger.warning("delegate: failed to audit fadt close %s", poll_id)
    return result


# ── message ACTIONS: read / delete / pin / unpin / hide / unhide / typing ────
@router.post("/delegate/{creator_id}/conversations/{conversation_id}/read")
def delegate_mark_read(
    creator_id: str,
    conversation_id: str,
    inp: MarkReadIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """MARK-READ (receipts) AS the creator via delegation."""
    _delegate_authorize(creator_id, user_id, conversation_id)
    from app.services.delegates import _write_audit
    result = mark_read(conversation_id=conversation_id, inp=inp, req=req, user_id=creator_id)
    try:
        _write_audit(creator_id, user_id, "delegate", "chat_marked_read", conversation_id, {})
    except Exception:
        logger.warning("delegate: failed to audit mark_read on %s", conversation_id)
    return result


@router.delete("/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}")
def delegate_delete_message(
    creator_id: str,
    conversation_id: str,
    message_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """DELETE-for-me AS the creator via delegation."""
    _delegate_authorize(creator_id, user_id, conversation_id)
    from app.services.delegates import _write_audit
    result = delete_message_for_me(conversation_id=conversation_id, message_id=message_id, req=req, user_id=creator_id)
    try:
        _write_audit(creator_id, user_id, "delegate", "chat_message_deleted", conversation_id,
                     {"message_id": message_id})
    except Exception:
        logger.warning("delegate: failed to audit delete on %s", message_id)
    return result


@router.post("/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}/pin")
def delegate_pin_message(
    creator_id: str,
    conversation_id: str,
    message_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """PIN a message AS the creator via delegation."""
    _delegate_authorize(creator_id, user_id, conversation_id)
    from app.services.delegates import _write_audit
    result = pin_message(conversation_id=conversation_id, message_id=message_id, req=req, user_id=creator_id)
    try:
        _write_audit(creator_id, user_id, "delegate", "chat_message_pinned", conversation_id,
                     {"message_id": message_id})
    except Exception:
        logger.warning("delegate: failed to audit pin on %s", message_id)
    return result


@router.delete("/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}/pin")
def delegate_unpin_message(
    creator_id: str,
    conversation_id: str,
    message_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """UNPIN a message AS the creator via delegation."""
    _delegate_authorize(creator_id, user_id, conversation_id)
    from app.services.delegates import _write_audit
    result = unpin_message(conversation_id=conversation_id, message_id=message_id, req=req, user_id=creator_id)
    try:
        _write_audit(creator_id, user_id, "delegate", "chat_message_unpinned", conversation_id,
                     {"message_id": message_id})
    except Exception:
        logger.warning("delegate: failed to audit unpin on %s", message_id)
    return result


@router.post("/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}/hide")
def delegate_hide_message(
    creator_id: str,
    conversation_id: str,
    message_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    """HIDE-for-me AS the creator via delegation."""
    _delegate_authorize(creator_id, user_id, conversation_id)
    from app.services.delegates import _write_audit
    result = hide_message_for_me(conversation_id=conversation_id, message_id=message_id, user_id=creator_id)
    try:
        _write_audit(creator_id, user_id, "delegate", "chat_message_hidden", conversation_id,
                     {"message_id": message_id})
    except Exception:
        logger.warning("delegate: failed to audit hide on %s", message_id)
    return result


@router.delete("/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}/hide")
def delegate_unhide_message(
    creator_id: str,
    conversation_id: str,
    message_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    """UNHIDE-for-me AS the creator via delegation."""
    _delegate_authorize(creator_id, user_id, conversation_id)
    from app.services.delegates import _write_audit
    result = unhide_message_for_me(conversation_id=conversation_id, message_id=message_id, user_id=creator_id)
    try:
        _write_audit(creator_id, user_id, "delegate", "chat_message_unhidden", conversation_id,
                     {"message_id": message_id})
    except Exception:
        logger.warning("delegate: failed to audit unhide on %s", message_id)
    return result


@router.post("/delegate/{creator_id}/conversations/{conversation_id}/typing")
def delegate_set_typing(
    creator_id: str,
    conversation_id: str,
    inp: TypingIn,
    user_id: str = Depends(get_messaging_user_id),
):
    """TYPING indicator AS the creator via delegation (not audited — high volume)."""
    _delegate_authorize(creator_id, user_id, conversation_id)
    return set_typing(conversation_id=conversation_id, inp=inp, user_id=creator_id)


# ── delegate conversation REALTIME (inbound arrives live in delegate context) ─
@router.get("/delegate/{creator_id}/events/poll")
def delegate_events_poll(
    creator_id: str,
    after: Optional[str] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    request: Request = None,
    x_request_id: Optional[str] = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Realtime backstop for delegate context: returns the CREATOR's per-user
    event queue (inbound message:new, receipts, typing, poll/call events)
    projected exactly as /events/poll, so a helper managing a creator sees
    inbound messages arrive live instead of only on send/reopen. Requires
    chat_respond on the creator (same gate as the delegate sends)."""
    _delegate_authorize(creator_id, user_id, None)
    return events_poll(
        after=after, limit=limit, request=request,
        x_request_id=x_request_id, user_id=creator_id,
    )
NEWBLOCK
python3 - <<'PY'
msg='app/routers/messaging.py'
s=open(msg).read()
nb=open('/tmp/newblock.txt').read()
anchor='        "chat_message_edited", inp.text or "",\n    )\n    return out\n'
assert s.count(anchor)==1, ('edit anchor count', s.count(anchor))
s=s.replace(anchor, anchor+'\n\n'+nb, 1)
for h in ['send_text_message','create_image_message','create_gallery_message','create_video_share_message','create_file_message']:
    a='    out = %s(\n'%h
    assert s.count(a)==1, (h, s.count(a))
    s=s.replace(a, '    _delegate_guard_tip(creator_id, user_id, inp)\n'+a, 1)
open(msg,'w').write(s)
dp='app/services/delegates.py'
d=open(dp).read()
va='    "broadcast_control",\n}'
assert d.count(va)==1, ('valid_perms anchor', d.count(va))
d=d.replace(va, '    "broadcast_control",\n    "can_tip",\n}', 1)
open(dp,'w').write(d)
import py_compile
py_compile.compile(msg, doraise=True)
py_compile.compile(dp, doraise=True)
print("PATCH_OK new_routes=%d" % s.count('/delegate/{creator_id}'))
PY
echo "=== OFFLINE import + openapi build check ==="
set -a; . /home/ubuntu/testlogon/.env.local; set +a
.venv/bin/python -c "import app.main as m; spec=m.app.openapi(); print('OPENAPI_OK paths=%d' % len(spec['paths']))"
