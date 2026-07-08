#!/usr/bin/env python3
"""TIP-B2 patch: tip-reaction (money-reaction) endpoints for a MESSAGE and a POST,
distinct from the free emoji reactions, both routed through the single charge_tip
money-path.

- TIP-201  app/routers/messaging.py  POST /conversations/{cid}/messages/{mid}/reactions/tip
           -> charge_tip(content_type="message_react", recipient=message author)
           -> money-reaction badge on the message + realtime "reaction:tip" event.
- TIP-202  app/routers/newsfeed.py    POST /posts/{pid}/reactions/tip
           -> charge_tip(content_type="post_react", recipient=post author)
           -> money-reaction badge on the post + bump tip_total_cents + social alert.
- TIP-201/202 allowlist: add message_react + post_react to tips.py TIP_CONTENT_TYPES,
           tip_ledger.py content_type set + reason map.
- TIP-205  app/services/creator_earnings.py classify_entry -> message_react/post_react/
           video/video_comment classified under "tips".

Money-path rule: charge_tip is the ONLY charge/ledger. A self-tip (400) or a failed
charge (402) raises BEFORE any badge/event side effect -> no badge, no ledger row.

Idempotent-ish: refuses to double-apply (asserts each anchor's occurrence count) and
py_compiles each patched file.
Usage: apply_tip_b2.py <repo_root>
"""
import io, sys, py_compile

ROOT = sys.argv[1].rstrip('/')


def patch(path, edits):
    full = ROOT + '/' + path
    with io.open(full, 'r', encoding='utf-8') as f:
        src = f.read()
    for label, old, new, count in edits:
        n = src.count(old)
        assert n == count, f'{path}: anchor [{label}] found {n} times, expected {count}'
        src = src.replace(old, new)
    with io.open(full, 'w', encoding='utf-8') as f:
        f.write(src)
    py_compile.compile(full, doraise=True)
    print('PATCHED+COMPILED', path)


# ---------------- FILE 1: app/services/tip_ledger.py ----------------
patch('app/services/tip_ledger.py', [
    (
        'ledger_content_type_set',
        'if content_type not in ("message", "post", "comment", "broadcast", "video"):',
        'if content_type not in ("message", "post", "comment", "broadcast", "video", "message_react", "post_react"):',
        1,
    ),
    (
        'ledger_reason_map',
        '        "video": "Tip: video",\n    }.get(content_type, f"Tip: {content_type}")',
        '        "video": "Tip: video",\n        "message_react": "Tip: message reaction",\n        "post_react": "Tip: post reaction",\n    }.get(content_type, f"Tip: {content_type}")',
        1,
    ),
])

# ---------------- FILE 2: app/services/tips.py ----------------
patch('app/services/tips.py', [
    (
        'tips_content_types',
        'TIP_CONTENT_TYPES = ("message", "post", "comment", "broadcast", "video")',
        'TIP_CONTENT_TYPES = ("message", "post", "comment", "broadcast", "video", "message_react", "post_react")',
        1,
    ),
])

# ---------------- FILE 3: app/services/creator_earnings.py (TIP-205) ----------------
patch('app/services/creator_earnings.py', [
    (
        'earnings_classify',
        '    if content_type in ("message", "post", "comment"):\n        return "tips"',
        '    if content_type in ("message", "post", "comment", "message_react", "post_react", "video", "video_comment"):\n        return "tips"',
        1,
    ),
])

# ---------------- FILE 4: app/routers/messaging.py (TIP-201) ----------------
MSG_ENDPOINT = '''# TIP-201: money-reaction (tip-react) on a MESSAGE -- DISTINCT from the free emoji
# react_to_message above. Routes through the single charge_tip money-path
# (content_type="message_react"), crediting the MESSAGE AUTHOR (group-safe: the
# message sender), rejecting a self-tip, and -- only AFTER a successful charge --
# recording a money-reaction badge on the message + fanning a realtime event.
class TipReactIn(BaseModel):
    amount_cents: int = Field(..., ge=1)
    emoji: Optional[str] = Field(default=None, max_length=64)
    payment_method_id: Optional[str] = Field(default=None, max_length=200)


@router.post("/conversations/{conversation_id}/messages/{message_id}/reactions/tip")
def tip_react_to_message(
    conversation_id: str,
    message_id: str,
    inp: TipReactIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    msg = _get_message_or_404(conversation_id, message_id)
    if isinstance(msg, dict) and msg.get("revoked_at"):
        raise HTTPException(400, "Cannot tip a revoked message")
    author_id = msg.get("sender_id")
    if not author_id:
        raise HTTPException(400, "Message has no author to tip")
    if author_id == user_id:
        raise HTTPException(400, {"code": "cannot_tip_self", "message": "Cannot tip your own message."})

    emoji = (inp.emoji or "\\U0001F4B8").strip() or "\\U0001F4B8"

    # Money-path via the single funnel. A self-tip (400) or a failed charge (402)
    # raises BEFORE any badge/event side effect -> no badge, no ledger on failure.
    from app.services.tips import charge_tip
    receipt = charge_tip(
        tipper_id=user_id,
        recipient_id=author_id,
        amount_cents=inp.amount_cents,
        currency="USD",
        payment_method_id=inp.payment_method_id,
        content_type="message_react",
        content_id=message_id,
        meta={"conversation_id": conversation_id, "emoji": emoji},
        idempotency_key=f"msgreacttip:{message_id}:{uuid.uuid4().hex}",
    )

    ts = now_ts()
    badge = {
        "tipper_id": user_id,
        "emoji": emoji,
        "amount_cents": int(inp.amount_cents),
        "tip_payment_id": receipt.tip_payment_id,
        "created_at": ts,
    }
    try:
        tbl_msgs.update_item(
            Key={"conversation_id": conversation_id, "message_id": message_id},
            UpdateExpression="SET tip_reactions = list_append(if_not_exists(tip_reactions, :empty), :new) ADD tip_amount_cents :amt",
            ExpressionAttributeValues={":empty": [], ":new": [badge], ":amt": int(inp.amount_cents)},
            ConditionExpression="attribute_exists(message_id)",
        )
    except ClientError as e:
        # The money already moved (ledger written); a badge-write failure must not
        # 500 the charged tip. Log + continue so the realtime event still fires.
        logger.warning("tip-react badge write failed: %s", e)

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="reaction:tip",
        payload={
            "message_id": message_id,
            "emoji": emoji,
            "amount_cents": int(inp.amount_cents),
            "tipper_id": user_id,
            "recipient_id": author_id,
            "tip_payment_id": receipt.tip_payment_id,
            "updated_at": ts,
        },
        respect_mute=False,
    )
    audit_event(
        "messaging_message_tip_reaction",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
        emoji=emoji,
        amount_cents=int(inp.amount_cents),
    )
    return {
        "ok": True,
        "tip_payment_id": receipt.tip_payment_id,
        "charged_cents": receipt.charged_cents,
        "net_cents": receipt.net_cents,
        "recipient_id": author_id,
        "emoji": emoji,
    }


'''

patch('app/routers/messaging.py', [
    (
        'msg_insert_before_reaction_details',
        '# MSG-011: Reaction detail — who reacted with what (avatars + display names).\n@router.get(',
        MSG_ENDPOINT + '# MSG-011: Reaction detail — who reacted with what (avatars + display names).\n@router.get(',
        1,
    ),
])

# ---------------- FILE 5: app/routers/newsfeed.py (TIP-202) ----------------
NF_ENDPOINT = '''class PostTipReactRequest(BaseModel):
    amount_cents: int = Field(..., ge=1)
    currency: str = "usd"
    emoji: Optional[str] = None
    payment_method_id: Optional[str] = None


@router.post("/posts/{post_id}/reactions/tip")
def tip_react_to_post(post_id: str, req: PostTipReactRequest, user_id: UserIdDep, _kyc: object = Depends(require_kyc_tier(2))):  # GAP-0268 (inert unless enforcement flag on)
    """TIP-202: money-reaction (tip-react) on a POST -- DISTINCT from the free emoji
    add_reaction. Routes through the single charge_tip money-path
    (content_type="post_react"), crediting the POST AUTHOR, rejecting a self-tip,
    and -- only AFTER a successful charge -- recording a money-reaction badge +
    bumping tip_total_cents + emitting a social alert."""
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    author = post.get("user_id")
    if not author:
        raise HTTPException(status_code=400, detail="Post has no author to tip")
    if author == user_id:
        raise HTTPException(status_code=400, detail="Cannot tip your own post")

    emoji = (req.emoji or "\\U0001F4B8").strip() or "\\U0001F4B8"

    # Money-path via the single funnel. A self-tip (400) or a failed charge (402)
    # raises BEFORE any badge/ledger side effect -> no badge, no ledger on failure.
    from app.services.tips import charge_tip
    receipt = charge_tip(
        tipper_id=user_id,
        recipient_id=author,
        amount_cents=req.amount_cents,
        currency=req.currency,
        payment_method_id=req.payment_method_id,
        content_type="post_react",
        content_id=post_id,
        meta={"post_id": post_id, "emoji": emoji},
        idempotency_key=new_id("postreacttip"),
    )

    # Only reached on a successful charge. Record the money-reaction badge + running
    # tip total on the post (distinct from the free emoji `reactions` map).
    badge = {
        "tipper_id": user_id,
        "emoji": emoji,
        "amount_cents": int(req.amount_cents),
        "tip_payment_id": receipt.tip_payment_id,
        "created_at": now_iso(),
    }
    updated = ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr="SET tip_reactions = list_append(if_not_exists(tip_reactions, :empty), :new), tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",
        expr_vals={":empty": [], ":new": [badge], ":z": 0, ":amt": int(req.amount_cents)},
    )

    # GAP-0355: social alert to the post author (best-effort; never break the tip).
    try:
        actor_name = _post_fadt_display_name(user_id)
        emit_social_alert(
            recipient_user_id=author,
            alert_type="post_tip",
            actor_user_id=user_id,
            actor_display_name=actor_name,
            batch_key=BATCH_KEY_PATTERNS["post_tip"].format(post_id=post_id),
            title=f"{actor_name} sent you a tip reaction {emoji}",
            details={"post_id": post_id, "amount_cents": int(req.amount_cents), "emoji": emoji},
            action_url=f"/feed/posts/{post_id}",
        )
    except Exception:
        logger.warning("post tip-react social alert failed post_id=%s", post_id, exc_info=True)

    return {
        "ok": True,
        "tip_payment_id": receipt.tip_payment_id,
        "charged_cents": receipt.charged_cents,
        "net_cents": receipt.net_cents,
        "recipient_id": author,
        "emoji": emoji,
        "tip_total_cents": int(updated.get("tip_total_cents", 0)),
    }


'''

patch('app/routers/newsfeed.py', [
    (
        'nf_insert_before_unreact',
        '@router.post("/posts/{post_id}/unreact")\ndef remove_reaction(post_id: str, req: ReactionRequest, user_id: UserIdDep):',
        NF_ENDPOINT + '@router.post("/posts/{post_id}/unreact")\ndef remove_reaction(post_id: str, req: ReactionRequest, user_id: UserIdDep):',
        1,
    ),
])

print('TIP-B2 ALL PATCHED OK')
