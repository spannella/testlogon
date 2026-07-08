#!/usr/bin/env python3
"""TIP-B4 pay-to-message gate + tip-free allowlist. Idempotent in-place patch of
app/routers/messaging.py. Usage: python apply_tipb4.py /path/to/messaging.py"""
import sys, io

path = sys.argv[1]
with io.open(path, 'r', encoding='utf-8') as f:
    src = f.read()
orig = src

MARK = 'TIP-B4 pay-to-message'
if MARK in src:
    print('ALREADY_PATCHED')
    sys.exit(0)

# ---------------------------------------------------------------------------
# 1) Pydantic models: after FindOrCreateDmIn
# ---------------------------------------------------------------------------
anchor_dto = "class FindOrCreateDmIn(BaseModel):\n    user_id: str  # target user's sub\n"
models = anchor_dto + '''

# --- TIP-B4 pay-to-message: MessagePrivacy (TIP-401) ---
class MessagePrivacyOut(BaseModel):
    require_tip_to_message: bool = False
    min_tip_cents: int = 0
    tip_free_allowlist: List[str] = []


class MessagePrivacyUpdateIn(BaseModel):
    require_tip_to_message: Optional[bool] = None
    min_tip_cents: Optional[int] = Field(default=None, ge=0, le=100_000)
    tip_free_allowlist: Optional[List[str]] = None


class MessagePrivacyAllowlistEntryIn(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=200)
'''
assert anchor_dto in src, 'DTO anchor missing'
src = src.replace(anchor_dto, models, 1)

# ---------------------------------------------------------------------------
# 2) Helpers + endpoints: before the find_or_create_dm route decorator
# ---------------------------------------------------------------------------
anchor_route = '@router.post("/conversations/dm/find-or-create", response_model=ConversationOut)\n'
helpers = '''# --- TIP-B4 pay-to-message gate helpers (TIP-401/402) ---
def _get_message_privacy(user_sub: str) -> Dict[str, Any]:
    """Read the MessagePrivacy record off the user profile settings row."""
    try:
        item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    except Exception:
        item = {}
    mp = item.get("message_privacy") or {}
    return {
        "require_tip_to_message": bool(mp.get("require_tip_to_message", False)),
        "min_tip_cents": int(mp.get("min_tip_cents", 0) or 0),
        "tip_free_allowlist": [str(x) for x in (mp.get("tip_free_allowlist") or [])],
    }


def _put_message_privacy(user_sub: str, priv: Dict[str, Any]) -> None:
    seen: List[str] = []
    for x in (priv.get("tip_free_allowlist") or []):
        sx = str(x)
        if sx and sx not in seen:
            seen.append(sx)
    T.profile.update_item(
        Key={"user_sub": user_sub},
        UpdateExpression="SET message_privacy = :mp",
        ExpressionAttributeValues={":mp": {
            "require_tip_to_message": bool(priv.get("require_tip_to_message", False)),
            "min_tip_cents": int(priv.get("min_tip_cents", 0) or 0),
            "tip_free_allowlist": seen,
        }},
    )


def _conversation_has_messages(conversation_id: str) -> bool:
    """True if the conversation already has >=1 message (established/not first contact)."""
    try:
        resp = tbl_msgs.query(
            KeyConditionExpression=Key("conversation_id").eq(conversation_id),
            Limit=1,
        )
        return bool(resp.get("Items"))
    except Exception:
        return False


def _dm_tip_gate_required(
    sender_id: str,
    recipient_id: str,
    conversation_id: Optional[str],
    attached_tip_cents: Optional[int],
) -> Optional[int]:
    """TIP-402: pay-to-message gate. Return min_tip_cents when a tip is REQUIRED for
    sender_id to message the gated recipient_id and is not (sufficiently) provided;
    otherwise None (bypass or satisfied).

    Bypasses: recipient not gating / sender in tip_free_allowlist / mutual-follow /
    an established conversation (any prior message = not first contact, which also
    covers the recipient-messaged-first case). If none apply, an attached tip
    >= min_tip_cents satisfies the gate."""
    priv = _get_message_privacy(recipient_id)
    if not priv["require_tip_to_message"]:
        return None
    if sender_id in priv["tip_free_allowlist"]:
        return None
    try:
        from app.services import social as _social
        if _social.is_following(sender_id, recipient_id) and _social.is_following(recipient_id, sender_id):
            return None
    except Exception:
        pass
    if conversation_id and _conversation_has_messages(conversation_id):
        return None
    min_cents = int(priv["min_tip_cents"] or 0)
    if attached_tip_cents is not None and int(attached_tip_cents) >= min_cents:
        return None
    return min_cents


@router.get("/privacy/message", response_model=MessagePrivacyOut)
def get_message_privacy(user_id: str = Depends(get_messaging_user_id)):
    """TIP-401: read the caller's pay-to-message privacy settings."""
    return MessagePrivacyOut(**_get_message_privacy(user_id))


@router.put("/privacy/message", response_model=MessagePrivacyOut)
def update_message_privacy(inp: MessagePrivacyUpdateIn, user_id: str = Depends(get_messaging_user_id)):
    """TIP-401: set require_tip_to_message / min_tip_cents / allowlist (partial)."""
    cur = _get_message_privacy(user_id)
    if inp.require_tip_to_message is not None:
        cur["require_tip_to_message"] = bool(inp.require_tip_to_message)
    if inp.min_tip_cents is not None:
        cur["min_tip_cents"] = int(inp.min_tip_cents)
    if inp.tip_free_allowlist is not None:
        cur["tip_free_allowlist"] = [str(x) for x in inp.tip_free_allowlist]
    _put_message_privacy(user_id, cur)
    return MessagePrivacyOut(**_get_message_privacy(user_id))


@router.post("/privacy/message/allowlist", response_model=MessagePrivacyOut)
def add_message_privacy_allowlist(inp: MessagePrivacyAllowlistEntryIn, user_id: str = Depends(get_messaging_user_id)):
    """TIP-401: add a user to the tip-free allowlist."""
    cur = _get_message_privacy(user_id)
    if inp.user_id not in cur["tip_free_allowlist"]:
        cur["tip_free_allowlist"].append(inp.user_id)
    _put_message_privacy(user_id, cur)
    return MessagePrivacyOut(**_get_message_privacy(user_id))


@router.delete("/privacy/message/allowlist/{allow_user_id}", response_model=MessagePrivacyOut)
def remove_message_privacy_allowlist(allow_user_id: str, user_id: str = Depends(get_messaging_user_id)):
    """TIP-401: remove a user from the tip-free allowlist."""
    cur = _get_message_privacy(user_id)
    cur["tip_free_allowlist"] = [x for x in cur["tip_free_allowlist"] if x != allow_user_id]
    _put_message_privacy(user_id, cur)
    return MessagePrivacyOut(**_get_message_privacy(user_id))


'''
assert anchor_route in src, 'route anchor missing'
src = src.replace(anchor_route, helpers + anchor_route, 1)

# ---------------------------------------------------------------------------
# 3) find_or_create_dm gate: existing-DM branch + new-DM branch
# ---------------------------------------------------------------------------
ex_old = (
    "            out.participants = _get_conversation_participants_enriched(existing_id, profile_cache)\n"
    "            return out\n"
)
ex_new = (
    "            out.participants = _get_conversation_participants_enriched(existing_id, profile_cache)\n"
    "            # TIP-402 pay-to-message gate on an existing-but-empty DM.\n"
    "            _min_c = _dm_tip_gate_required(user_id, target_sub, existing_id, None)\n"
    "            if _min_c is not None:\n"
    "                raise HTTPException(402, {\"code\": \"tip_required\", \"min_tip_cents\": _min_c, \"recipient\": target_sub, \"conversation_id\": existing_id})\n"
    "            return out\n"
)
assert ex_old in src, 'find_or_create existing-branch anchor missing'
src = src.replace(ex_old, ex_new, 1)

cr_old = (
    "    # No existing DM — create one using the same logic as start_conversation\n"
    "    return start_conversation(\n"
    "        StartConversationIn(participant_ids=[target_sub], type=\"dm\"),\n"
    "        req=req,\n"
    "        user_id=user_id,\n"
    "    )\n"
)
cr_new = (
    "    # No existing DM — create one using the same logic as start_conversation\n"
    "    _new_convo = start_conversation(\n"
    "        StartConversationIn(participant_ids=[target_sub], type=\"dm\"),\n"
    "        req=req,\n"
    "        user_id=user_id,\n"
    "    )\n"
    "    # TIP-402: pay-to-message gate. A brand-new DM to a gated recipient requires a\n"
    "    # tip on the first message; surface 402 WITH the conversation_id so the client\n"
    "    # can send the first message carrying the tip (TIP-403).\n"
    "    _min_c = _dm_tip_gate_required(user_id, target_sub, _new_convo.conversation_id, None)\n"
    "    if _min_c is not None:\n"
    "        raise HTTPException(402, {\"code\": \"tip_required\", \"min_tip_cents\": _min_c, \"recipient\": target_sub, \"conversation_id\": _new_convo.conversation_id})\n"
    "    return _new_convo\n"
)
assert cr_old in src, 'find_or_create create-branch anchor missing'
src = src.replace(cr_old, cr_new, 1)

# ---------------------------------------------------------------------------
# 4) send_text_message first-message gate (TIP-402/403)
# ---------------------------------------------------------------------------
send_old = (
    "    _validate_reply_target(conversation_id, inp.reply_to_message_id)\n"
    "\n"
    "    # Validate send_at: must be in the future (at least 5 seconds from now)\n"
)
send_new = (
    "    _validate_reply_target(conversation_id, inp.reply_to_message_id)\n"
    "\n"
    "    # TIP-B4 pay-to-message gate (TIP-402/403): the FIRST message to a gated DM\n"
    "    # recipient must carry a tip >= min_tip_cents. Bypassed for allowlist /\n"
    "    # mutual-follow / established conversation (any prior message, incl. the\n"
    "    # recipient-messaged-first case). When a tip is attached and >= min, the\n"
    "    # attached-tip path below routes it through charge_tip(content_type=\"message\",\n"
    "    # recipient=the gated user) as non-refundable creator earnings.\n"
    "    if convo.get(\"type\") == \"dm\":\n"
    "        _tip_recipient = _resolve_tip_recipient(conversation_id, user_id)\n"
    "        if _tip_recipient:\n"
    "            _min_c = _dm_tip_gate_required(user_id, _tip_recipient, conversation_id, inp.tip_amount_cents)\n"
    "            if _min_c is not None:\n"
    "                raise HTTPException(402, {\"code\": \"tip_required\", \"min_tip_cents\": _min_c, \"recipient\": _tip_recipient})\n"
    "\n"
    "    # Validate send_at: must be in the future (at least 5 seconds from now)\n"
)
assert send_old in src, 'send_text gate anchor missing'
src = src.replace(send_old, send_new, 1)

assert src != orig, 'no changes made'
with io.open(path, 'w', encoding='utf-8') as f:
    f.write(src)
print('PATCH_OK')
