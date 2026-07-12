import sys, io
ROOT = sys.argv[1].rstrip("/")

EDITS = []
def E(rel, old, new, count=1):
    EDITS.append((rel, old, new, count))

# ---------------- app/services/tips.py : optional tip_payment_id param ----------------
E("app/services/tips.py",
'''    idempotency_key: str,
    acting_delegate_id: Optional[str] = None,
) -> TipResult:''',
'''    idempotency_key: str,
    acting_delegate_id: Optional[str] = None,
    tip_payment_id: Optional[str] = None,
) -> TipResult:''')

E("app/services/tips.py",
'''    # 5. Mock charge (B0). The real stripe-mock PaymentIntent is B1/TIP-101.
    tip_payment_id = "tip_" + uuid.uuid4().hex
    payment_intent_id: Optional[str] = None''',
'''    # 5. Mock charge (B0). The real stripe-mock PaymentIntent is B1/TIP-101.
    # Callers that already minted a tip id (and stored it on their content row)
    # pass it through so the ledger row + content row stay linked; else mint one.
    tip_payment_id = tip_payment_id or ("tip_" + uuid.uuid4().hex)
    payment_intent_id: Optional[str] = None''')

# ---------------- messaging.py TEXT: move lock+tip check up (orphan fix) ----------------
E("app/routers/messaging.py",
'''    # Process tip
    tip_amount_cents: Optional[int] = None
    tip_currency: Optional[str] = None
    tip_payment_id: Optional[str] = None
    if inp.tip_amount_cents:''',
'''    # Process tip
    # TIP-005 orphan-credit fix: validate the tip+lock mutual-exclusion BEFORE any
    # ledger write. Previously this 400 lived AFTER write_tip_ledger, so a lock+tip
    # text send settled a credit and THEN 400d (orphan credit). The image/gallery
    # paths already validate first; this aligns the text path with them.
    if inp.lock_price_cents and inp.tip_amount_cents:
        raise HTTPException(400, "Cannot combine lock_price_cents with tip_amount_cents")
    tip_amount_cents: Optional[int] = None
    tip_currency: Optional[str] = None
    tip_payment_id: Optional[str] = None
    if inp.tip_amount_cents:''')

# ---------------- messaging.py TEXT: swap ledger -> charge_tip + drop moved check ----------------
E("app/routers/messaging.py",
'''            recipient_id = _resolve_tip_recipient(conversation_id, user_id)
            if recipient_id:
                from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
                write_tip_ledger(TipLedgerEntry(
                    tipper_user_id=user_id,
                    recipient_user_id=recipient_id,
                    amount_cents=tip_amount_cents,
                    currency="USD",
                    content_type="message",
                    content_id=mid,
                    payment_method_id=inp.tip_payment_method_id,
                    tip_payment_id=tip_payment_id,
                    extra_meta={"conversation_id": conversation_id},
                ))

    # Validate: lock_price_cents and tip_amount_cents cannot both be set
    if inp.lock_price_cents and inp.tip_amount_cents:
        raise HTTPException(400, "Cannot combine lock_price_cents with tip_amount_cents")''',
'''            recipient_id = _resolve_tip_recipient(conversation_id, user_id)
            if recipient_id:
                from app.services.tips import charge_tip
                charge_tip(
                    tipper_id=user_id,
                    recipient_id=recipient_id,
                    amount_cents=tip_amount_cents,
                    currency="USD",
                    payment_method_id=inp.tip_payment_method_id,
                    content_type="message",
                    content_id=mid,
                    meta={"conversation_id": conversation_id},
                    idempotency_key=f"msgtip:{mid}",
                    tip_payment_id=tip_payment_id,
                )

    # (tip+lock mutual-exclusion is validated above, before any ledger write)''')

# ---------------- messaging.py IMAGE ----------------
E("app/routers/messaging.py",
'''                from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
                write_tip_ledger(TipLedgerEntry(
                    tipper_user_id=user_id,
                    recipient_user_id=recipient_id,
                    amount_cents=tip_amount_cents,
                    currency="USD",
                    content_type="message",
                    content_id=mid,
                    payment_method_id=inp.tip_payment_method_id,
                    tip_payment_id=_img_tip_payment_id,
                    extra_meta={"conversation_id": conversation_id},
                ))''',
'''                from app.services.tips import charge_tip
                charge_tip(
                    tipper_id=user_id,
                    recipient_id=recipient_id,
                    amount_cents=tip_amount_cents,
                    currency="USD",
                    payment_method_id=inp.tip_payment_method_id,
                    content_type="message",
                    content_id=mid,
                    meta={"conversation_id": conversation_id},
                    idempotency_key=f"msgtip:{mid}",
                    tip_payment_id=_img_tip_payment_id,
                )''')

# ---------------- messaging.py GALLERY ----------------
E("app/routers/messaging.py",
'''                from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
                write_tip_ledger(TipLedgerEntry(
                    tipper_user_id=user_id,
                    recipient_user_id=recipient_id,
                    amount_cents=gal_tip_amount_cents,
                    currency="USD",
                    content_type="message",
                    content_id=mid,
                    payment_method_id=inp.tip_payment_method_id,
                    tip_payment_id=_gal_tip_payment_id,
                    extra_meta={"conversation_id": conversation_id},
                ))''',
'''                from app.services.tips import charge_tip
                charge_tip(
                    tipper_id=user_id,
                    recipient_id=recipient_id,
                    amount_cents=gal_tip_amount_cents,
                    currency="USD",
                    payment_method_id=inp.tip_payment_method_id,
                    content_type="message",
                    content_id=mid,
                    meta={"conversation_id": conversation_id},
                    idempotency_key=f"msgtip:{mid}",
                    tip_payment_id=_gal_tip_payment_id,
                )''')

# ---------------- messaging.py SCHEDULED DELIVER ----------------
E("app/routers/messaging.py",
'''            from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
            write_tip_ledger(TipLedgerEntry(
                tipper_user_id=user_id,
                recipient_user_id=recipient_id,
                amount_cents=int(item["tip_amount_cents"]),
                currency=item.get("tip_currency", "USD"),
                content_type="message",
                content_id=message_id,
                payment_method_id=item.get("tip_payment_method_id"),
                tip_payment_id=item.get("tip_payment_id"),
                extra_meta={"conversation_id": conversation_id},
            ))''',
'''            from app.services.tips import charge_tip
            charge_tip(
                tipper_id=user_id,
                recipient_id=recipient_id,
                amount_cents=int(item["tip_amount_cents"]),
                currency=item.get("tip_currency", "USD"),
                payment_method_id=item.get("tip_payment_method_id"),
                content_type="message",
                content_id=message_id,
                meta={"conversation_id": conversation_id},
                idempotency_key=f"msgtip:{message_id}",
                tip_payment_id=item.get("tip_payment_id"),
            )''')

# ---------------- messaging.py send_message_tip (post-hoc) ----------------
E("app/routers/messaging.py",
'''        from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
        write_tip_ledger(TipLedgerEntry(
            tipper_user_id=user_id,
            recipient_user_id=msg_author,
            amount_cents=inp.amount_cents,
            currency=inp.currency,
            content_type="message",
            content_id=message_id,
            payment_method_id=inp.payment_method_id,
            tip_payment_id=tip_payment_id,
            extra_meta={"conversation_id": conversation_id},
        ))''',
'''        from app.services.tips import charge_tip
        charge_tip(
            tipper_id=user_id,
            recipient_id=msg_author,
            amount_cents=inp.amount_cents,
            currency=inp.currency,
            payment_method_id=inp.payment_method_id,
            content_type="message",
            content_id=message_id,
            meta={"conversation_id": conversation_id},
            idempotency_key="msgtip:" + new_id(),
            tip_payment_id=tip_payment_id,
        )''')

# ---------------- newsfeed.py tip_post : drop stub ----------------
E("app/routers/newsfeed.py",
'''    pi = payments.create_payment_intent(
        user_id=user_id,
        amount_cents=req.amount_cents,
        currency=req.currency,
        metadata={"type": "tip_post", "post_id": post_id},
    )
    conf = payments.confirm_payment_intent(payment_intent_id=pi["payment_intent_id"])
    if conf.get("status") != "succeeded":
        raise HTTPException(status_code=402, detail="Payment failed")

    updated = ddb_update_item(''',
'''    # TIP-007: the mock PaymentProvider stub is replaced by the centralized
    # charge_tip seam (called below, after the tip_total bump). The stub always
    # "succeeded", so removing it changes no behavior.
    updated = ddb_update_item(''')

# ---------------- newsfeed.py tip_post : ledger -> charge_tip ----------------
E("app/routers/newsfeed.py",
'''    # Write billing ledger debit + credit entries (best-effort)
    post_author = post.get("user_id")
    if post_author and post_author != user_id:
        from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
        write_tip_ledger(TipLedgerEntry(
            tipper_user_id=user_id,
            recipient_user_id=post_author,
            amount_cents=req.amount_cents,
            currency=req.currency,
            content_type="post",
            content_id=post_id,
            payment_method_id=req.payment_method_id,
            extra_meta={"post_id": post_id},
        ))''',
'''    # Write billing ledger debit + credit entries via the centralized charge_tip seam.
    post_author = post.get("user_id")
    _tip_txn_id = ""
    if post_author and post_author != user_id:
        from app.services.tips import charge_tip
        _tp = charge_tip(
            tipper_id=user_id,
            recipient_id=post_author,
            amount_cents=req.amount_cents,
            currency=req.currency,
            payment_method_id=req.payment_method_id,
            content_type="post",
            content_id=post_id,
            meta={"post_id": post_id},
            idempotency_key=new_id("posttip"),
        )
        _tip_txn_id = _tp.tip_payment_id''')

# tip_post license split source_txn_id (pi no longer exists)
E("app/routers/newsfeed.py",
'''            source_type="post_tip",
            source_amount_cents=req.amount_cents,
            source_txn_id=pi["payment_intent_id"],''',
'''            source_type="post_tip",
            source_amount_cents=req.amount_cents,
            source_txn_id=_tip_txn_id or post_id,''')

# ---------------- newsfeed.py tip_comment : drop stub, keep pi-shaped receipt ----------------
E("app/routers/newsfeed.py",
'''    pi = payments.create_payment_intent(
        user_id=tipper_id,
        amount_cents=req.amount_cents,
        currency=req.currency,
        metadata={"type": "tip", "post_id": post_id, "comment_id": comment_id},
    )
    conf = payments.confirm_payment_intent(payment_intent_id=pi["payment_intent_id"])
    if conf.get("status") != "succeeded":
        raise HTTPException(status_code=402, detail="Payment failed")

    key = {"pk": target["pk"], "sk": target["sk"]}''',
'''    # TIP-008: the mock PaymentProvider stub is replaced by the centralized
    # charge_tip seam (called below). Keep a stub-shaped receipt for the response.
    pi = {"provider": "stub", "payment_intent_id": None, "status": "succeeded"}

    key = {"pk": target["pk"], "sk": target["sk"]}''')

E("app/routers/newsfeed.py",
'''    if comment_author and comment_author != tipper_id:
        from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
        write_tip_ledger(TipLedgerEntry(
            tipper_user_id=tipper_id,
            recipient_user_id=comment_author,
            amount_cents=req.amount_cents,
            currency=req.currency,
            content_type="comment",
            content_id=comment_id,
            payment_method_id=getattr(req, "payment_method_id", None),
            extra_meta={"post_id": post_id, "comment_id": comment_id},
        ))''',
'''    if comment_author and comment_author != tipper_id:
        from app.services.tips import charge_tip
        _ct = charge_tip(
            tipper_id=tipper_id,
            recipient_id=comment_author,
            amount_cents=req.amount_cents,
            currency=req.currency,
            payment_method_id=getattr(req, "payment_method_id", None),
            content_type="comment",
            content_id=comment_id,
            meta={"post_id": post_id, "comment_id": comment_id},
            idempotency_key=new_id("cmttip"),
        )
        pi["payment_intent_id"] = _ct.tip_payment_id''')

# ---------------- broadcast_tip_store.py ----------------
E("app/services/broadcast_tip_store.py",
'''    # 7. Write billing ledger entries
    ledger_entry = TipLedgerEntry(
        tipper_user_id=user_id,
        recipient_user_id=broadcaster_id,
        amount_cents=amount_cents,
        currency=currency,
        content_type="broadcast",
        content_id=f"{session_id}#{msg_id}",
        payment_method_id=payment_method_id,
        tip_payment_id=tip_payment_id,
        extra_meta={
            "session_id": session_id,
            "message_id": msg_id,
            "display_name": display_name,
        },
    )
    write_tip_ledger(ledger_entry)''',
'''    # 7. Charge + write billing ledger via the centralized charge_tip seam.
    #    PM ownership, amount bounds and self-tip were validated above; charge_tip
    #    re-validates PM + self-tip and writes the same net-credit ledger. The
    #    minted tip id is threaded through so the chat row and ledger stay linked.
    from app.services.tips import charge_tip
    charge_tip(
        tipper_id=user_id,
        recipient_id=broadcaster_id,
        amount_cents=amount_cents,
        currency=currency,
        payment_method_id=payment_method_id,
        content_type="broadcast",
        content_id=f"{session_id}#{msg_id}",
        meta={
            "session_id": session_id,
            "message_id": msg_id,
            "display_name": display_name,
        },
        idempotency_key=f"bctip:{msg_id}",
        tip_payment_id=tip_payment_id,
    )''')

# apply
report = []
for rel, old, new, count in EDITS:
    path = ROOT + "/" + rel
    with io.open(path, "r", encoding="utf-8") as f:
        data = f.read()
    n = data.count(old)
    if n != count:
        print("FAIL", rel, "expected", count, "got", n, "for old-block starting:", repr(old[:60]))
        sys.exit(3)
    data = data.replace(old, new)
    with io.open(path, "w", encoding="utf-8") as f:
        f.write(data)
    report.append((rel, count))
for rel, count in report:
    print("OK", rel, count)
print("TOTAL EDITS", len(EDITS))
