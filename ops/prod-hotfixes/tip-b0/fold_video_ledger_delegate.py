import sys, io
ROOT = sys.argv[1].rstrip("/")

def patch(rel, edits):
    path = ROOT + "/" + rel
    with io.open(path, "r", encoding="utf-8") as f:
        data = f.read()
    for old, new, count in edits:
        n = data.count(old)
        if n != count:
            print("FAIL", rel, "expected", count, "got", n, "for", repr(old[:50])); sys.exit(3)
        data = data.replace(old, new)
    with io.open(path, "w", encoding="utf-8") as f:
        f.write(data)
    print("OK", rel, len(edits))

# ---- tip_ledger.py: add "video" to the content_type allowlist + reason map ----
patch("app/services/tip_ledger.py", [
('''        if content_type not in ("message", "post", "comment", "broadcast"):''',
 '''        if content_type not in ("message", "post", "comment", "broadcast", "video"):''', 1),
('''        "message": "Tip: message",
        "post": "Tip: post",
        "comment": "Tip: comment",
        "broadcast": "Tip: broadcast",
    }.get(content_type, f"Tip: {content_type}")''',
 '''        "message": "Tip: message",
        "post": "Tip: post",
        "comment": "Tip: comment",
        "broadcast": "Tip: broadcast",
        "video": "Tip: video",
    }.get(content_type, f"Tip: {content_type}")''', 1),
])

# ---- delegates.py: fold prod-only can_tip permission (TIP-012) ----
patch("app/services/delegates.py", [
('''VALID_PERMISSIONS = {
    "chat_read",
    "chat_respond",
    "feed_read",
    "feed_post",
    "feed_moderate",
    "broadcast_moderate",
    "broadcast_control",
}''',
 '''VALID_PERMISSIONS = {
    "chat_read",
    "chat_respond",
    "feed_read",
    "feed_post",
    "feed_moderate",
    "broadcast_moderate",
    "broadcast_control",
    # TIP-012: money-OUT tip guard. A delegate may tip AS the creator (which
    # debits the creator's wallet) only when granted this opt-in permission.
    # charge_tip._guard_delegate_can_tip enforces default-DENY.
    "can_tip",
}''', 1),
])

# ---- video_listing.py: fold the prod-only video-tip endpoint (migrated to charge_tip) ----
VIDEO_ENDPOINT = '''class VideoTipIn(BaseModel):
    amount_cents: int = Field(..., ge=1)
    currency: str = "usd"
    payment_method_id: Optional[str] = None


class VideoTipOut(BaseModel):
    ok: bool
    video_id: str
    amount_cents: int
    currency: str
    tip_total_cents: int


@router.post("/{video_id}/tip", response_model=VideoTipOut)
def tip_video_endpoint(
    video_id: str,
    body: VideoTipIn,
    user=Depends(require_ui_session),
):
    """B-VIDSOCIAL2 (#2): tip a video's creator. Mirrors newsfeed POST /posts/{id}/tip
    so VOD posts reach full social parity (reactions + comments + tips)."""
    user_sub = user["user_sub"]
    video = get_video(video_id)
    if video.owner_user_id == user_sub:
        raise HTTPException(status_code=400, detail="Cannot tip your own video")
    # Non-owner may only tip a published, viewable video.
    if video.status != "published" or video.visibility not in ("public", "unlisted"):
        raise HTTPException(status_code=403, detail="video not available for tipping")

    # TIP-011: charge + credit via the centralized charge_tip seam (replaces the
    # mock PaymentProvider stub + direct write_tip_ledger). Charge BEFORE bumping
    # tip_total_cents so a failed charge does not leave an orphan total.
    from app.services.tips import charge_tip
    charge_tip(
        tipper_id=user_sub,
        recipient_id=video.owner_user_id,
        amount_cents=body.amount_cents,
        currency=body.currency,
        payment_method_id=body.payment_method_id,
        content_type="video",
        content_id=video_id,
        meta={"video_id": video_id},
        idempotency_key="videotip:" + uuid.uuid4().hex,
    )

    # Accumulate tip_total_cents on the video metadata row (best-effort additive).
    new_total = body.amount_cents
    try:
        upd = T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",
            ExpressionAttributeValues={":z": 0, ":amt": body.amount_cents},
            ReturnValues="UPDATED_NEW",
        )
        new_total = int(upd.get("Attributes", {}).get("tip_total_cents", body.amount_cents))
    except Exception:
        logger.warning("failed to accumulate tip_total_cents on video %s", video_id)

    # Social activity + notification hooks (best-effort).
    try:
        from app.services.activity_feed import record_social_interaction
        record_social_interaction(
            recipient_id=video.owner_user_id, actor_id=user_sub, kind="tip",
            target_type="video", target_id=video_id,
            extra={"amount_cents": body.amount_cents, "currency": body.currency},
        )
    except Exception:
        logger.debug("social hook: tip_video", exc_info=True)

    return VideoTipOut(
        ok=True, video_id=video_id, amount_cents=body.amount_cents,
        currency=body.currency, tip_total_cents=new_total,
    )


'''

patch("app/routers/video_listing.py", [
('''import logging
''', '''import logging
import uuid
''', 1),
('''@router.get("/{video_id}", response_model=VideoDetailOut)
def get_video_detail(''',
 VIDEO_ENDPOINT + '''@router.get("/{video_id}", response_model=VideoDetailOut)
def get_video_detail(''', 1),
])

print("DEV_FOLD_DONE")
