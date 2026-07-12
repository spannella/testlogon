#!/usr/bin/env python3
"""SUB-E2 PART 2 — gifting + cancel/refund (idempotent anchored patcher).

Edits 3 files:
  app/routers/subscription_server.py  (models + reversal helpers + cancel-refund + gift/refund endpoints)
  app/services/subscription_access.py (keep access on 'canceling' until period end)

Idempotent: each edit is skipped when its marker is already present. Fails loudly
if an anchor is missing (so we never silently mis-apply on a drifted file).
"""
import io, sys, os

ROOT = os.environ.get("REPO_ROOT", ".")
SERVER = os.path.join(ROOT, "app/routers/subscription_server.py")
ACCESS = os.path.join(ROOT, "app/services/subscription_access.py")
RENEWAL = os.path.join(ROOT, "app/services/subscription_renewal.py")


def _read(p):
    with io.open(p, "r", encoding="utf-8") as f:
        return f.read()


def _write(p, s):
    with io.open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)


def edit(text, old, new, marker, label):
    if marker in text:
        print("SKIP  (already applied): %s" % label)
        return text
    if old not in text:
        raise SystemExit("ANCHOR MISSING for %s" % label)
    if text.count(old) != 1:
        raise SystemExit("ANCHOR NOT UNIQUE (%d) for %s" % (text.count(old), label))
    print("APPLY: %s" % label)
    return text.replace(old, new)


# ---------------------------------------------------------------------------
# subscription_server.py
# ---------------------------------------------------------------------------
s = _read(SERVER)

# ---- E1: models (cancel refund flag + gift/refund input models) ----
s = edit(
    s,
    '''class SubscriptionCancelIn(BaseModel):
    cancel_at_period_end: bool = True
    reason: Optional[str] = None''',
    '''class SubscriptionCancelIn(BaseModel):
    cancel_at_period_end: bool = True
    # SUB-E2 PART 2 (SUB-25): on an IMMEDIATE cancel (cancel_at_period_end=False)
    # refund the unused prorated portion by DEFAULT (locked decision). Pass
    # refund=False to force an immediate cancel with NO refund. Ignored when
    # cancelling at period end (that path never refunds).
    refund: Optional[bool] = None
    reason: Optional[str] = None


class SubscriptionGiftIn(BaseModel):
    # SUB-E2 PART 2 (SUB-23): the GIFTER (X-User-Id) pays ONE cycle for recipient_id.
    recipient_id: str
    interval: Optional[Literal["month", "year"]] = None
    payment_method_id: Optional[str] = None
    message: Optional[str] = Field(default=None, max_length=500)
    client_request_id: Optional[str] = Field(default=None, max_length=128)


class SubscriptionRefundIn(BaseModel):
    # SUB-E2 PART 2 (SUB-25): general/dispute refund path. fraction defaults to the
    # remaining unused prorated portion; pass 1.0 to fully refund the current cycle.
    fraction: Optional[float] = None
    reason: Optional[str] = "refund"''',
    "class SubscriptionGiftIn(BaseModel):",
    "models: cancel.refund + SubscriptionGiftIn + SubscriptionRefundIn",
)

# ---- E2: reversal helpers (tips.reverse_tip / ADV-502 pattern) ----
s = edit(
    s,
    '''# -----------------------------
# SUB-E0 — real subscribe charge (funds-guarded stripe-mock rail, tips pattern)
# -----------------------------''',
    '''# -----------------------------
# SUB-E2 PART 2 — cancel/refund reversal (tips.reverse_tip / ADV-502 pattern)
# -----------------------------

def _sub_reversal_sk(marker_key: str) -> str:
    return f"SUBREVERSAL#{marker_key}"


def _find_subscription_credit_row(creator_id: str, subscription_id: str) -> Optional[Dict[str, Any]]:
    """Locate the latest NON-reversed creator mirror-credit row for a subscription
    (the current cycle's credit written by _mirror_creator_credit_to_billing).
    Returns the raw T.billing item or None."""
    try:
        rows = billing_query_pk(T.billing, user_pk(creator_id))
    except Exception:
        return None
    best = None
    for it in rows:
        if not str(it.get("sk", "")).startswith("LEDGER#"):
            continue
        if it.get("type") != "credit" or it.get("subscription_id") != subscription_id:
            continue
        if (it.get("state") or "") == "reversed":
            continue
        if best is None or int(it.get("ts") or 0) > int(best.get("ts") or 0):
            best = it
    return best


def _latest_paid_invoice_pi(subscription_id: str) -> Optional[str]:
    try:
        items = ddb_query(pk_subscription(subscription_id))
    except Exception:
        return None
    invs = [it for it in items if str(it.get("sk", "")).startswith("INV#") and (it.get("status") or "").lower() == "paid"]
    invs.sort(key=lambda x: int(x.get("created_at") or 0), reverse=True)
    for inv in invs:
        if inv.get("payment_intent_id"):
            return inv.get("payment_intent_id")
    return None


def _reverse_subscription_charge(
    sub: Dict[str, Any],
    *,
    now: int,
    refund_fraction: float,
    reason: str,
    payer_id: Optional[str] = None,
    actor: Optional[str] = None,
) -> Dict[str, Any]:
    """SUB-E2 PART 2 (SUB-25): idempotently refund the payer the prorated unused
    portion of the current cycle AND claw back the creator's prorated NET credit --
    via the tips.reverse_tip / ADV-502 reversal pattern.

    Money-safety invariants (mirror reverse_tip):
      * the payer REFUND entry (type="refund") and the creator CLAWBACK entry
        (type="reversal") are NOT type="credit", so a reversal never INFLATES
        creator earnings (creator_earnings / get_available_balance only sum
        type=="credit").
      * the ORIGINAL creator mirror-credit row is flipped to state="reversed" so it
        drops out of get_available_balance + creator_earnings; on a PARTIAL
        (mid-cycle) refund the KEPT (used) fraction is re-credited so the creator
        retains exactly the used portion.
      * a SUBREVERSAL#{subscription_id}#{period_end} marker (conditional put) makes
        it idempotent + guards double-refund; a real Stripe partial refund is
        issued best-effort against the original PaymentIntent.
    For a GIFT the refund goes to the GIFTER (gifter_id), never the recipient.
    """
    subscription_id = sub["subscription_id"]
    creator_id = sub["creator_id"]
    payer = payer_id or sub.get("gifter_id") or sub["subscriber_id"]
    currency = sub.get("currency", "usd")
    period_gross = int(sub.get("price_cents") or 0)
    period_end = int(sub.get("current_period_end") or now)
    marker_key = f"{subscription_id}#{period_end}"

    prior = billing_get(T.billing, user_pk(payer), _sub_reversal_sk(marker_key))
    if prior and prior.get("subscription_id"):
        return {**prior, "idempotent_replay": True}

    frac = max(0.0, min(1.0, float(refund_fraction)))
    credit_row = _find_subscription_credit_row(creator_id, subscription_id)
    if credit_row:
        net_full = int(credit_row.get("amount_cents") or 0)
    else:
        # No live (non-reversed) credit -> the cycle was already reversed; refund 0
        # (the collected funds have already been returned) to prevent a double-refund.
        net_full = 0
        period_gross = 0
    refund_gross = int(round(period_gross * frac))
    clawback_net = int(round(net_full * frac))
    ts = int(now)

    reversal_id = new_id("subrev")
    refund_id = new_id("subref")
    base_meta = {
        "content_type": "subscription",
        "subscription_id": subscription_id,
        "creator_id": creator_id,
        "payer_user_id": payer,
        "subscriber_user_id": sub["subscriber_id"],
        "reversal_reason": reason,
        "refund_fraction": round(frac, 6),
        "period_end": period_end,
    }
    if actor:
        base_meta["reversal_actor"] = actor

    receipt = {
        "subscription_id": subscription_id,
        "marker_key": marker_key,
        "refunded_cents": refund_gross,
        "clawback_cents": clawback_net,
        "refund_entry_id": refund_id,
        "reversal_entry_id": reversal_id,
        "reason": reason,
        "created_at": ts,
        "idempotent_replay": False,
    }
    # CLAIM the reversal (idempotency guard) BEFORE writing money entries.
    try:
        billing_put(
            T.billing,
            {"pk": user_pk(payer), "sk": _sub_reversal_sk(marker_key), "ts": ts, **receipt},
            condition_expression="attribute_not_exists(sk)",
        )
    except Exception:
        winner = billing_get(T.billing, user_pk(payer), _sub_reversal_sk(marker_key))
        if winner and winner.get("subscription_id"):
            return {**winner, "idempotent_replay": True}
        raise

    # Payer REFUND entry (type != credit).
    if refund_gross > 0:
        T.billing.put_item(Item={
            "pk": user_pk(payer),
            "sk": f"LEDGER#{ts}#{refund_id}",
            "entry_id": refund_id,
            "ts": ts,
            "type": "refund",
            "amount_cents": int(refund_gross),
            "currency": currency,
            "state": "settled",
            "reason": "subscription_refund",
            "meta": base_meta,
        })
    # Creator CLAWBACK entry (type != credit -> earnings NOT inflated).
    if clawback_net > 0:
        T.billing.put_item(Item={
            "pk": user_pk(creator_id),
            "sk": f"LEDGER#{ts}#{reversal_id}",
            "entry_id": reversal_id,
            "ts": ts,
            "type": "reversal",
            "amount_cents": int(clawback_net),
            "currency": currency,
            "state": "settled",
            "reason": "subscription_reversal",
            "meta": base_meta,
        })
        # Flip the ORIGINAL credit out of the creator's spendable balance; re-credit
        # the KEPT (used) fraction on a partial refund.
        if credit_row:
            try:
                T.billing.update_item(
                    Key={"pk": credit_row["pk"], "sk": credit_row["sk"]},
                    UpdateExpression="SET #s = :r",
                    ConditionExpression="attribute_exists(sk)",
                    ExpressionAttributeNames={"#s": "state"},
                    ExpressionAttributeValues={":r": "reversed"},
                )
            except Exception:
                logger.warning("subscription credit flip skipped sub=%s", subscription_id, exc_info=True)
            retained = int(net_full) - int(clawback_net)
            if retained > 0:
                keep_id = new_id("biled")
                T.billing.put_item(Item={
                    "pk": user_pk(creator_id),
                    "sk": f"LEDGER#{ts}#{keep_id}",
                    "type": "credit",
                    "amount_cents": int(retained),
                    "currency": currency,
                    "reason": "subscription_charge",
                    "ts": ts,
                    "created_at": ts,
                    "entry_id": keep_id,
                    "subscription_id": subscription_id,
                    "subscriber_id": sub["subscriber_id"],
                    "meta": {"content_type": "subscription", "retained_after_refund": True},
                })
    # Mark the underlying paid invoice refunded (bookkeeping) + best-effort Stripe.
    try:
        mark_invoice_refunded(subscription_id, reason)
    except Exception:
        logger.warning("mark_invoice_refunded skipped sub=%s", subscription_id, exc_info=True)
    pi_id = _latest_paid_invoice_pi(subscription_id) or sub.get("payment_intent_id")
    if pi_id and refund_gross > 0 and getattr(S, "stripe_secret_key", ""):
        try:
            from app.routers.billing import ensure_stripe_configured
            import stripe

            ensure_stripe_configured()
            stripe.Refund.create(payment_intent=pi_id, amount=int(refund_gross), idempotency_key=f"subrev:{marker_key}")
            receipt["stripe_refund"] = True
        except Exception:
            logger.warning("subscription stripe refund skipped sub=%s", subscription_id, exc_info=True)
    logger.info(
        "subscription_reversed sub=%s payer=%s refund=%s clawback=%s frac=%s reason=%s",
        subscription_id, payer, refund_gross, clawback_net, frac, reason,
    )
    return receipt


# -----------------------------
# SUB-E0 — real subscribe charge (funds-guarded stripe-mock rail, tips pattern)
# -----------------------------''',
    "_reverse_subscription_charge(",
    "helpers: reversal (find-credit + reverse_subscription_charge)",
)

# ---- E3: cancel endpoint -> refund on immediate cancel ----
s = edit(
    s,
    '''    sub["cancel_at_period_end"] = body.cancel_at_period_end
    sub["auto_renew"] = False
    sub["renewal_policy"] = "cancel_at_period_end" if body.cancel_at_period_end else "manual"
    if body.cancel_at_period_end:
        sub["status"] = "canceling"
    else:
        sub["status"] = "canceled"
        sub["current_period_end"] = now_ts()
    sub["updated_at"] = now_ts()
    save_subscription(sub)
    record_billing_subscription(sub)''',
    '''    sub["cancel_at_period_end"] = body.cancel_at_period_end
    sub["auto_renew"] = False
    sub["renewal_policy"] = "cancel_at_period_end" if body.cancel_at_period_end else "manual"
    now = now_ts()
    refund_receipt = None
    if body.cancel_at_period_end:
        # DEFAULT: keep access until current_period_end, then the E1 sweeper flips
        # to 'canceled'. NO refund. has_active_subscription treats 'canceling' as
        # active-until-period_end (SUB-25 access fix).
        sub["status"] = "canceling"
    else:
        # IMMEDIATE cancel: revoke access NOW + refund the unused prorated portion by
        # default (locked decision) + claw back the creator credit (state=reversed,
        # not inflating), idempotent -- unless refund=False was explicitly passed. A
        # fully-elapsed period yields fraction 0 -> no refund (also makes a repeat
        # immediate-cancel a no-op).
        do_refund = body.refund if body.refund is not None else True
        if do_refund:
            frac = _proration_fraction(now, int(sub.get("start_at") or now), int(sub.get("current_period_end") or now))
            if frac > 0:
                refund_receipt = _reverse_subscription_charge(
                    sub, now=now, refund_fraction=frac, reason="immediate_cancel", actor=user_id,
                )
        sub["status"] = "canceled"
        sub["canceled_at"] = now
        sub["current_period_end"] = now
    sub["updated_at"] = now
    save_subscription(sub)
    record_billing_subscription(sub)
    if refund_receipt:
        audit_event(
            "subscription_refunded",
            sub["subscriber_id"],
            request,
            outcome="success",
            subscription_id=subscription_id,
            creator_id=sub["creator_id"],
            refunded_cents=refund_receipt.get("refunded_cents"),
            clawback_cents=refund_receipt.get("clawback_cents"),
        )''',
    "refund_receipt = None",
    "cancel endpoint: immediate-cancel refund + clawback",
)

# ---- E4: gift + general refund endpoints (inserted before list_subscriptions) ----
s = edit(
    s,
    '''    refresh_subscription_calendar_events(sub, plan)
    return attach_subscription_profiles(sub)


@router.get("/api/subscriptions", response_model=List[SubscriptionOut])
async def list_subscriptions(''',
    '''    refresh_subscription_calendar_events(sub, plan)
    return attach_subscription_profiles(sub)


@router.post("/api/plans/{plan_id}/gift", response_model=SubscriptionOut)
async def gift_subscription(
    plan_id: str,
    body: SubscriptionGiftIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    """SUB-E2 PART 2 (SUB-23): the GIFTER pays for ONE cycle for a recipient.

    Charge the gifter's PM ONCE for one period (real E0 rail, funds-guarded), grant
    the RECIPIENT a subscription for that period with auto_renew=False (it LAPSES at
    period end via the E1 sweeper unless the recipient subscribes themselves -- the
    recipient is NEVER charged), and credit the creator NET (10% fee) exactly like a
    normal charge. A gift is NOT a renewal.
    """
    gifter_id = require_user(x_user_id)
    recipient_id = (body.recipient_id or "").strip()
    if not recipient_id:
        raise HTTPException(status_code=400, detail="recipient_id is required")
    if recipient_id == gifter_id:
        raise HTTPException(status_code=400, detail="Cannot gift a subscription to yourself")
    plan = ddb_get_item(pk_plan(plan_id), "META")
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    if plan.get("status") != "active":
        raise HTTPException(status_code=400, detail="Plan is not active")
    if plan["creator_id"] in (recipient_id, gifter_id):
        raise HTTPException(status_code=400, detail="Creator cannot gift/receive their own plan")

    # idempotent replay (namespaced gift key): a retry returns the created gift sub.
    idem_raw = (body.client_request_id or "").strip()
    idem_key = f"gift:{idem_raw}" if idem_raw else ""
    if idem_key:
        prior_sub_id = _load_subscribe_idem(gifter_id, idem_key)
        if prior_sub_id:
            prior = ddb_get_item(pk_subscription(prior_sub_id), "META")
            if prior:
                return attach_subscription_profiles(normalize_subscription(prior))

    ts = now_ts()
    subscription_id = new_id("sub")
    provider_subscription_id = new_id("stub_sub")
    interval = _plan_interval(plan, body.interval)
    period_end = ts + interval_seconds(interval)
    price_cents = _select_plan_price(plan, interval)
    if int(price_cents) <= 0:
        raise HTTPException(status_code=400, detail="Plan price must be positive to gift")

    # CHARGE THE GIFTER ONCE (real funds-guarded rail). 402 -> nothing written.
    payment_method_id = resolve_subscription_payment_method(gifter_id, body.payment_method_id)
    payment_intent_id = _charge_subscription_payment_intent(
        subscriber_id=gifter_id,
        amount_cents=int(price_cents),
        currency=plan["currency"],
        payment_method_id=payment_method_id,
        plan_id=plan_id,
        subscription_id=subscription_id,
        idempotency_key=(idem_key or f"{subscription_id}:gift:{ts}"),
    )

    # GRANT THE RECIPIENT a one-cycle, NON-renewing subscription (never charged).
    sub = {
        "subscription_id": subscription_id,
        "plan_id": plan_id,
        "creator_id": plan["creator_id"],
        "subscriber_id": recipient_id,
        "interval": interval,
        "provider": "stripe" if payment_intent_id else "stub",
        "provider_subscription_id": provider_subscription_id,
        "status": "active",
        "start_at": ts,
        "current_period_end": period_end,
        "next_billing_date": period_end,
        # the recipient has NO PM on this sub -> nothing to charge even if a renewal
        # were attempted; auto_renew=False makes it lapse cleanly at period end.
        "payment_method_id": None,
        "payment_intent_id": payment_intent_id,
        "cancel_at_period_end": False,
        "price_cents": int(price_cents),
        "currency": plan["currency"],
        "auto_renew": False,
        "trial_start": None,
        "trial_end": None,
        "proration_policy": "none",
        "renewal_policy": "manual",
        "is_gift": True,
        "gifter_id": gifter_id,
        "gift_message": body.message or "",
        "created_at": ts,
        "updated_at": ts,
    }
    save_subscription(sub)
    record_billing_subscription(sub)

    # invoice + ledger + creator NET credit (gross paid by the gifter).
    invoice_id = new_id("inv")
    invoice = {
        "invoice_id": invoice_id,
        "subscription_id": subscription_id,
        "subscriber_id": recipient_id,
        "payer_id": gifter_id,
        "provider": "stripe" if payment_intent_id else "stub",
        "provider_invoice_id": payment_intent_id or new_id("stub_inv"),
        "payment_intent_id": payment_intent_id,
        "payment_method_id": payment_method_id,
        "amount_cents": int(price_cents),
        "currency": plan["currency"],
        "status": "paid",
        "period_start": ts,
        "period_end": period_end,
        "created_at": ts,
        "billing_reason": "subscription_gift",
        "is_gift": True,
    }
    recurring = emit_subscription_cycle_order_and_reconcile(subscription=sub, plan=plan, invoice=invoice)
    invoice["recurring_order_id"] = recurring["order_id"]
    save_invoice(invoice)
    # the PAYMENT record sits under the GIFTER (the payer), never the recipient, so
    # the recipient carries NO charge record (recipient is never charged).
    record_billing_payment({**invoice, "subscriber_id": gifter_id}, subscription_id)
    record_billing_transaction(
        user_sub=gifter_id,
        amount_cents=int(price_cents),
        currency=plan["currency"],
        description=f"Gift subscription {plan_id} to {recipient_id}",
        status="COMPLETED",
        external_ref=invoice_id,
        metadata={"subscription_id": subscription_id, "creator_id": plan["creator_id"], "recipient_id": recipient_id, "billing_reason": "gift"},
    )
    fee_cents = int(int(price_cents) * FEE_BPS / 10000)
    _base = {
        "subscription_id": subscription_id,
        "subscriber_id": recipient_id,
        "currency": plan["currency"],
        "created_at": ts,
        "metadata": {"invoice_id": invoice_id, "billing_reason": "gift", "gifter_id": gifter_id},
    }
    save_ledger_entry(plan["creator_id"], {**_base, "entry_id": new_id("led"), "entry_type": "charge", "amount_cents": int(price_cents)})
    save_ledger_entry(plan["creator_id"], {**_base, "entry_id": new_id("led"), "entry_type": "fee", "amount_cents": fee_cents})
    _mirror_creator_credit_to_billing(
        plan["creator_id"],
        int(price_cents) - fee_cents,
        currency=plan["currency"],
        created_at=ts,
        subscription_id=subscription_id,
        subscriber_id=recipient_id,
        invoice_id=invoice_id,
    )

    if idem_key:
        _store_subscribe_idem(gifter_id, idem_key, subscription_id)

    put_notification(
        recipient_user_id=recipient_id,
        notif_type="subscription_gifted",
        payload={"subscription_id": subscription_id, "plan_id": plan_id, "gifter_id": gifter_id, "creator_id": plan["creator_id"], "message": body.message or ""},
    )
    put_notification(
        recipient_user_id=plan["creator_id"],
        notif_type="subscription_created",
        payload={"subscription_id": subscription_id, "plan_id": plan_id, "subscriber_id": recipient_id, "gift": True},
    )
    put_notification(
        recipient_user_id=gifter_id,
        notif_type="subscription_gift_sent",
        payload={"subscription_id": subscription_id, "plan_id": plan_id, "recipient_id": recipient_id},
    )
    try:
        from app.services.social_alerts import emit_social_alert
        from app.services.profile import get_profile_identity
        gifter_name = get_profile_identity(gifter_id).get("display_name") or gifter_id
        emit_social_alert(
            recipient_user_id=recipient_id,
            alert_type="subscription_gifted",
            actor_user_id=gifter_id,
            actor_display_name=gifter_name,
            title=f"{gifter_name} gifted you a subscription",
            details={"plan_id": plan_id, "subscription_id": subscription_id, "creator_id": plan["creator_id"]},
            action_url="/subscriptions",
        )
    except Exception:
        logger.warning("gift social alert failed recipient=%s", recipient_id, exc_info=True)
    audit_event("subscription_gifted", gifter_id, request, outcome="success", subscription_id=subscription_id, plan_id=plan_id, recipient_id=recipient_id, price_cents=int(price_cents))
    audit_event("subscription_gift_received", recipient_id, request, outcome="success", subscription_id=subscription_id, plan_id=plan_id, gifter_id=gifter_id)
    try:
        from app.services.milestones import check_milestone
        check_milestone(plan["creator_id"], "subscribers", count_active_subscribers(plan["creator_id"]))
    except Exception:
        logger.warning("check_milestone failed on gift", exc_info=True)
    refresh_subscription_calendar_events(sub, plan)
    return attach_subscription_profiles(sub)


@router.post("/api/subscriptions/{subscription_id}/refund")
async def refund_subscription(
    subscription_id: str,
    body: SubscriptionRefundIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    """SUB-E2 PART 2 (SUB-25): general/dispute refund path. Refund the current cycle
    (default = remaining unused prorated portion; pass fraction=1.0 to fully refund)
    + claw back the creator credit (state=reversed, not inflating), idempotent.
    Authorized for the subscriber, the creator, or (for a gift) the gifter."""
    sub = ddb_get_item(pk_subscription(subscription_id), "META")
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub = normalize_subscription(sub)
    user_id = require_user(x_user_id)
    if user_id not in (sub["subscriber_id"], sub["creator_id"], sub.get("gifter_id")):
        raise HTTPException(status_code=403, detail="Not authorized to refund this subscription")
    now = now_ts()
    if body.fraction is not None:
        frac = max(0.0, min(1.0, float(body.fraction)))
    else:
        frac = _proration_fraction(now, int(sub.get("start_at") or now), int(sub.get("current_period_end") or now))
    if frac <= 0:
        raise HTTPException(status_code=400, detail="Nothing to refund for the current period")
    receipt = _reverse_subscription_charge(sub, now=now, refund_fraction=frac, reason=(body.reason or "refund"), actor=user_id)
    audit_event(
        "subscription_refunded",
        sub["subscriber_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        creator_id=sub["creator_id"],
        refunded_cents=receipt.get("refunded_cents"),
        clawback_cents=receipt.get("clawback_cents"),
    )
    return {
        "subscription_id": subscription_id,
        "status": sub.get("status"),
        "refunded_cents": receipt.get("refunded_cents"),
        "clawback_cents": receipt.get("clawback_cents"),
        "idempotent_replay": receipt.get("idempotent_replay", False),
        "reason": receipt.get("reason"),
    }


@router.get("/api/subscriptions", response_model=List[SubscriptionOut])
async def list_subscriptions(''',
    "async def gift_subscription(",
    "endpoints: gift_subscription + refund_subscription",
)

_write(SERVER, s)

# ---------------------------------------------------------------------------
# subscription_access.py -- keep access on 'canceling' until period end
# ---------------------------------------------------------------------------
a = _read(ACCESS)
a = edit(
    a,
    '''        status = (item.get("status") or "").lower()
        # SUB-E1: expired/canceled subs never grant access.
        if status not in {"active", "past_due", "trialing"}:
            continue''',
    '''        status = (item.get("status") or "").lower()
        # SUB-E1: expired/canceled subs never grant access.
        # SUB-E2 PART 2 (SUB-25): 'canceling' = cancel-at-period-end; KEEP access
        # until current_period_end (the effective_end check below bounds it); the
        # E1 sweeper flips it to 'canceled' (excluded) at period end.
        if status not in {"active", "past_due", "trialing", "canceling"}:
            continue''',
    '"trialing", "canceling"}',
    "access: keep 'canceling' access until period end",
)
_write(ACCESS, a)

# ---------------------------------------------------------------------------
# subscription_renewal.py -- make 'canceling' terminal at period end (never charged)
# ---------------------------------------------------------------------------
r = _read(RENEWAL)
r = edit(
    r,
    '''        if trial_end and trial_end <= now:
            _attempt_renewal(sub, now, summary, trial_conversion=True)
        return
    if status not in ("active", "past_due"):
        return''',
    '''        if trial_end and trial_end <= now:
            _attempt_renewal(sub, now, summary, trial_conversion=True)
        return
    # SUB-E2 PART 2 (SUB-25): a 'canceling' sub (cancel-at-period-end) KEEPS access
    # until current_period_end (subscription_access grants it) then becomes terminal
    # 'canceled' here. It is NEVER charged / renewed / dunned.
    if status == "canceling":
        cpe = int(sub.get("current_period_end") or 0)
        if cpe and cpe <= now:
            sub["status"] = "canceled"
            sub["canceled_at"] = sub.get("canceled_at") or now
            sub["updated_at"] = now
            _save(sub)
            summary["canceled"].append(sub["subscription_id"])
            logger.info("subscription_canceled_at_period_end id=%s", sub["subscription_id"])
        return
    if status not in ("active", "past_due"):
        return''',
    'if status == "canceling":',
    "renewal sweeper: 'canceling' -> terminal 'canceled' at period end",
)
_write(RENEWAL, r)

print("PATCH OK")
