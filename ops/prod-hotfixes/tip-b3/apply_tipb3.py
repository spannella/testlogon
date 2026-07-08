#!/usr/bin/env python3
"""TIP-B3 backend patcher (TIP-301/302/303). Idempotent-guarded, backs up .bak_tipb3_<ts>.
Usage: apply_tipb3.py <APP_ROOT> <TS>"""
import sys, os

ROOT = sys.argv[1].rstrip("/")
TS = sys.argv[2]

def patch(relpath, edits):
    fp = os.path.join(ROOT, relpath)
    with open(fp, "r", encoding="utf-8") as f:
        src = f.read()
    orig = src
    for old, new, n in edits:
        if new in src and old not in src:
            print(f"  SKIP (already applied): {relpath} :: {new[:48]!r}")
            continue
        c = src.count(old)
        assert c == n, f"{relpath}: expected {n} of {old[:60]!r}, found {c}"
        src = src.replace(old, new)
    if src != orig:
        with open(fp + f".bak_tipb3_{TS}", "w", encoding="utf-8") as f:
            f.write(orig)
        with open(fp, "w", encoding="utf-8") as f:
            f.write(src)
        print(f"  PATCHED {relpath} (backup .bak_tipb3_{TS})")
    else:
        print(f"  NOCHANGE {relpath}")

# ---- tips.py : add video_comment to the charge_tip allowlist (TIP-303) ----
patch("app/services/tips.py", [(
    'TIP_CONTENT_TYPES = ("message", "post", "comment", "broadcast", "video", "message_react", "post_react")',
    'TIP_CONTENT_TYPES = ("message", "post", "comment", "broadcast", "video", "message_react", "post_react", "video_comment")',
    1,
)])

# ---- tip_ledger.py : allowlist + reason map (TIP-303) ----
patch("app/services/tip_ledger.py", [
    (
        'if content_type not in ("message", "post", "comment", "broadcast", "video", "message_react", "post_react"):',
        'if content_type not in ("message", "post", "comment", "broadcast", "video", "message_react", "post_react", "video_comment"):',
        1,
    ),
    (
        '        "post_react": "Tip: post reaction",\n    }.get(content_type, f"Tip: {content_type}")',
        '        "post_react": "Tip: post reaction",\n        "video_comment": "Tip: video comment",\n    }.get(content_type, f"Tip: {content_type}")',
        1,
    ),
])

# ---- newsfeed.py : TIP-301 (comment TipRequest PM) + TIP-302 (carrying tip) ----
patch("app/routers/newsfeed.py", [
    # TIP-301: payment_method_id on comment TipRequest
    (
        'class TipRequest(BaseModel):\n    amount_cents: int = Field(..., ge=1)\n    currency: str = "usd"\n',
        'class TipRequest(BaseModel):\n    amount_cents: int = Field(..., ge=1)\n    currency: str = "usd"\n'
        '    # TIP-301: name an explicit / tip-default payment method for the comment\n'
        '    # tip so charge_tip can resolve the tipper\'s saved PM (falls back to\n'
        '    # tip-default -> default when None).\n'
        '    payment_method_id: Optional[str] = None\n',
        1,
    ),
    # TIP-302: carrying-tip fields on CreateCommentRequest
    (
        'class CreateCommentRequest(ContentFieldsMixin):\n    parent_comment_id: Optional[str] = None\n',
        'class CreateCommentRequest(ContentFieldsMixin):\n    parent_comment_id: Optional[str] = None\n'
        '    # TIP-302: a comment can CARRY a tip. When tip_amount_cents is present the\n'
        '    # create-comment handler charges it (recipient = the POST author) via\n'
        '    # charge_tip BEFORE the comment row is written, then stamps tip_total_cents.\n'
        '    tip_amount_cents: Optional[int] = Field(default=None, ge=1)\n'
        '    tip_currency: str = "usd"\n'
        '    tip_payment_method_id: Optional[str] = None\n',
        1,
    ),
    # TIP-302: charge before writing the comment row
    (
        '    comment_id = new_id("cmt")\n    created_at = now_iso()\n    parent = req.parent_comment_id\n',
        '    comment_id = new_id("cmt")\n    created_at = now_iso()\n    parent = req.parent_comment_id\n\n'
        '    # TIP-302: comment-CARRYING tip. Charge FIRST (recipient = the POST author)\n'
        '    # so a declined/failed charge raises BEFORE any comment row is written --\n'
        '    # no orphan comment, no orphan stamp, no ledger. A tip on your OWN post\n'
        '    # self-tips -> charge_tip raises 400 cannot_tip_self.\n'
        '    comment_tip_total = 0\n'
        '    if getattr(req, "tip_amount_cents", None):\n'
        '        from app.services.tips import charge_tip\n'
        '        charge_tip(\n'
        '            tipper_id=user_id,\n'
        '            recipient_id=post_author,\n'
        '            amount_cents=int(req.tip_amount_cents),\n'
        '            currency=(getattr(req, "tip_currency", "usd") or "usd"),\n'
        '            payment_method_id=getattr(req, "tip_payment_method_id", None),\n'
        '            content_type="comment",\n'
        '            content_id=comment_id,\n'
        '            meta={"post_id": post_id, "comment_id": comment_id, "carried": True},\n'
        '            idempotency_key=new_id("cmtcarry"),\n'
        '        )\n'
        '        comment_tip_total = int(req.tip_amount_cents)\n',
        1,
    ),
    # TIP-302: stamp tip_total on the item row
    (
        '        "version": 1,\n        "tip_total_cents": 0,\n        "GSI2PK": pk_post_comments(post_id),',
        '        "version": 1,\n        "tip_total_cents": comment_tip_total,\n        "GSI2PK": pk_post_comments(post_id),',
        1,
    ),
    # TIP-302: reflect tip_total in the response
    (
        '        version=1,\n        tip_total_cents=0,\n        kind=req.kind,',
        '        version=1,\n        tip_total_cents=comment_tip_total,\n        kind=req.kind,',
        1,
    ),
    # TIP-301: reorder tip_comment so charge precedes the tip_total stamp
    (
        '    pi = {"provider": "stub", "payment_intent_id": None, "status": "succeeded"}\n\n'
        '    key = {"pk": target["pk"], "sk": target["sk"]}\n'
        '    updated = ddb_update_item(\n'
        '        key=key,\n'
        '        update_expr="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",\n'
        '        expr_vals={":z": 0, ":amt": req.amount_cents},\n'
        '    )\n\n'
        '    comment_author = updated.get("user_id")\n\n'
        '    # Write billing ledger debit + credit entries for comment tip (best-effort)\n'
        '    if comment_author and comment_author != tipper_id:\n'
        '        from app.services.tips import charge_tip\n'
        '        _ct = charge_tip(\n'
        '            tipper_id=tipper_id,\n'
        '            recipient_id=comment_author,\n'
        '            amount_cents=req.amount_cents,\n'
        '            currency=req.currency,\n'
        '            payment_method_id=getattr(req, "payment_method_id", None),\n'
        '            content_type="comment",\n'
        '            content_id=comment_id,\n'
        '            meta={"post_id": post_id, "comment_id": comment_id},\n'
        '            idempotency_key=new_id("cmttip"),\n'
        '        )\n'
        '        pi["payment_intent_id"] = _ct.tip_payment_id\n',
        '    pi = {"provider": "stub", "payment_intent_id": None, "status": "succeeded"}\n\n'
        '    comment_author = target.get("user_id")\n\n'
        '    # TIP-301: charge via the centralized charge_tip seam BEFORE stamping the\n'
        '    # comment, so a declined/failed charge (402) leaves NO tip_total bump and\n'
        '    # NO ledger. payment_method_id now flows from TipRequest (explicit ->\n'
        '    # tip-default -> default fallback inside charge_tip).\n'
        '    if comment_author and comment_author != tipper_id:\n'
        '        from app.services.tips import charge_tip\n'
        '        _ct = charge_tip(\n'
        '            tipper_id=tipper_id,\n'
        '            recipient_id=comment_author,\n'
        '            amount_cents=req.amount_cents,\n'
        '            currency=req.currency,\n'
        '            payment_method_id=getattr(req, "payment_method_id", None),\n'
        '            content_type="comment",\n'
        '            content_id=comment_id,\n'
        '            meta={"post_id": post_id, "comment_id": comment_id},\n'
        '            idempotency_key=new_id("cmttip"),\n'
        '        )\n'
        '        pi["payment_intent_id"] = _ct.tip_payment_id\n\n'
        '    key = {"pk": target["pk"], "sk": target["sk"]}\n'
        '    updated = ddb_update_item(\n'
        '        key=key,\n'
        '        update_expr="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",\n'
        '        expr_vals={":z": 0, ":amt": req.amount_cents},\n'
        '    )\n',
        1,
    ),
])

# ---- video_comments.py : get_comment + bump helper (TIP-303) ----
patch("app/services/video_comments.py", [(
    'def delete_comment(',
    'def get_comment(*, video_id: str, comment_id: str) -> Optional[Dict[str, Any]]:\n'
    '    """Fetch a single comment\'s raw item by id (the SK embeds a timestamp so a\n'
    '    direct GetItem is impossible; page the partition like delete_comment).\n'
    '    Returns None if not found."""\n'
    '    last_key = None\n'
    '    while True:\n'
    '        kwargs: Dict[str, Any] = {\n'
    '            "KeyConditionExpression": Key("pk").eq(f"VIDEO#{video_id}"),\n'
    '            "FilterExpression": "comment_id = :cid",\n'
    '            "ExpressionAttributeValues": {":cid": comment_id},\n'
    '        }\n'
    '        if last_key:\n'
    '            kwargs["ExclusiveStartKey"] = last_key\n'
    '        resp = T.video_comments.query(**kwargs)\n'
    '        items = resp.get("Items", [])\n'
    '        if items:\n'
    '            return items[0]\n'
    '        last_key = resp.get("LastEvaluatedKey")\n'
    '        if not last_key:\n'
    '            return None\n\n\n'
    'def bump_comment_tip_total(*, video_id: str, comment: Dict[str, Any], amount_cents: int) -> int:\n'
    '    """Additively bump tip_total_cents on a video comment row; returns new total."""\n'
    '    upd = T.video_comments.update_item(\n'
    '        Key={"pk": comment["pk"], "sk": comment["sk"]},\n'
    '        UpdateExpression="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",\n'
    '        ExpressionAttributeValues={":z": 0, ":amt": amount_cents},\n'
    '        ReturnValues="UPDATED_NEW",\n'
    '    )\n'
    '    return int(upd.get("Attributes", {}).get("tip_total_cents", amount_cents))\n\n\n'
    'def delete_comment(',
    1,
)])

# ---- video_listing.py : video-comment tip endpoint (TIP-303) ----
patch("app/routers/video_listing.py", [(
    '@router.get("/{video_id}", response_model=VideoDetailOut)\ndef get_video_detail(',
    'class VideoCommentTipIn(BaseModel):\n'
    '    amount_cents: int = Field(..., ge=1)\n'
    '    currency: str = "usd"\n'
    '    payment_method_id: Optional[str] = None\n\n\n'
    'class VideoCommentTipOut(BaseModel):\n'
    '    ok: bool\n'
    '    video_id: str\n'
    '    comment_id: str\n'
    '    amount_cents: int\n'
    '    currency: str\n'
    '    tip_total_cents: int\n\n\n'
    '@router.post("/{video_id}/comments/{comment_id}/tip", response_model=VideoCommentTipOut)\n'
    'def tip_video_comment_endpoint(\n'
    '    video_id: str,\n'
    '    comment_id: str,\n'
    '    body: VideoCommentTipIn,\n'
    '    user=Depends(require_ui_session),\n'
    '):\n'
    '    """TIP-303: tip a VIDEO COMMENT. Recipient = the comment\'s author (mirrors\n'
    '    the newsfeed comment tip). Charge BEFORE stamping tip_total_cents so a\n'
    '    failed charge leaves no orphan total; own-comment tips self-tip ->\n'
    '    charge_tip raises 400 cannot_tip_self."""\n'
    '    if not S.video_gallery_enabled:\n'
    '        raise HTTPException(status_code=404, detail="gallery not enabled")\n\n'
    '    from app.services.video_comments import get_comment, bump_comment_tip_total\n'
    '    comment = get_comment(video_id=video_id, comment_id=comment_id)\n'
    '    if not comment:\n'
    '        raise HTTPException(status_code=404, detail="Comment not found")\n\n'
    '    user_sub = user["user_sub"]\n'
    '    comment_author = comment.get("user_id")\n\n'
    '    from app.services.tips import charge_tip\n'
    '    charge_tip(\n'
    '        tipper_id=user_sub,\n'
    '        recipient_id=comment_author,\n'
    '        amount_cents=body.amount_cents,\n'
    '        currency=body.currency,\n'
    '        payment_method_id=body.payment_method_id,\n'
    '        content_type="video_comment",\n'
    '        content_id=comment_id,\n'
    '        meta={"video_id": video_id, "comment_id": comment_id},\n'
    '        idempotency_key="vidcmttip:" + uuid.uuid4().hex,\n'
    '    )\n\n'
    '    new_total = bump_comment_tip_total(\n'
    '        video_id=video_id, comment=comment, amount_cents=body.amount_cents\n'
    '    )\n\n'
    '    # Notify the comment author (best-effort).\n'
    '    try:\n'
    '        from app.services.activity_feed import record_social_interaction\n'
    '        record_social_interaction(\n'
    '            recipient_id=comment_author, actor_id=user_sub, kind="tip",\n'
    '            target_type="video_comment", target_id=comment_id,\n'
    '            extra={"amount_cents": body.amount_cents, "currency": body.currency,\n'
    '                   "video_id": video_id},\n'
    '        )\n'
    '    except Exception:\n'
    '        logger.debug("social hook: tip_video_comment", exc_info=True)\n\n'
    '    return VideoCommentTipOut(\n'
    '        ok=True, video_id=video_id, comment_id=comment_id,\n'
    '        amount_cents=body.amount_cents, currency=body.currency,\n'
    '        tip_total_cents=new_total,\n'
    '    )\n\n\n'
    '@router.get("/{video_id}", response_model=VideoDetailOut)\ndef get_video_detail(',
    1,
)])

print("ALL PATCHES APPLIED OK")
