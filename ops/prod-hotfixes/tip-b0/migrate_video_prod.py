import sys, io
ROOT = sys.argv[1].rstrip("/")
path = ROOT + "/app/routers/video_listing.py"
with io.open(path, "r", encoding="utf-8") as f:
    data = f.read()

EDITS = []

# add `import uuid`
EDITS.append((
'''import logging
''',
'''import logging
import uuid
''', 1))

# migrate tip_video_endpoint: stub + accumulate + ledger -> charge_tip (charge first) + accumulate
EDITS.append((
'''    from app.routers.newsfeed import payments as _payments
    pi = _payments.create_payment_intent(
        user_id=user_sub,
        amount_cents=body.amount_cents,
        currency=body.currency,
        metadata={"type": "tip_video", "video_id": video_id},
    )
    conf = _payments.confirm_payment_intent(payment_intent_id=pi["payment_intent_id"])
    if conf.get("status") != "succeeded":
        raise HTTPException(status_code=402, detail="Payment failed")

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

    # Billing ledger debit/credit (best-effort), mirroring tip_post.
    try:
        from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
        write_tip_ledger(TipLedgerEntry(
            tipper_user_id=user_sub,
            recipient_user_id=video.owner_user_id,
            amount_cents=body.amount_cents,
            currency=body.currency,
            content_type="video",
            content_id=video_id,
            payment_method_id=body.payment_method_id,
            extra_meta={"video_id": video_id},
        ))
    except Exception:
        logger.warning("tip ledger write failed for video tip %s", video_id)
''',
'''    # TIP-011: charge + credit via the centralized charge_tip seam (replaces the
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
''', 1))

for old, new, count in EDITS:
    n = data.count(old)
    if n != count:
        print("FAIL video expected", count, "got", n, "for", repr(old[:50])); sys.exit(3)
    data = data.replace(old, new)
with io.open(path, "w", encoding="utf-8") as f:
    f.write(data)
print("VIDEO_PROD_OK edits", len(EDITS))
