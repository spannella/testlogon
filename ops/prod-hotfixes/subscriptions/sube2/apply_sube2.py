#!/usr/bin/env python3
"""SUB-E2 anchored idempotent patch: proration/upgrade-downgrade + trial card-up-front + sweeper auto-convert.

Patches:
  app/routers/subscription_server.py
    P1  subscribe(): TRIAL captures + VALIDATES a PM up front (no charge)
    P2a change_subscription_plan(): route by price -> upgrade(immediate delta charge) / downgrade(pending_change)
    P2b change_subscription_plan(): switch plan NOW + real proration invoice/ledger + creator delta-net credit
  app/services/subscription_renewal.py
    P3a run_renewal_sweep(): summary buckets trial_converted / plan_changed
    P3b _process(): AUTO-CONVERT a trial at trial_end
    P3c _attempt_renewal(): apply due pending_change + trial_conversion flag
    P3d _renewal_success(): trial_conversion param (billing_reason/trial_converted_at/bucket)

Run:  ROOT=<repo-root> python3 sube2_apply.py
Idempotent: re-running is a no-op (each edit detects its NEW marker).
"""
import io, os, sys, py_compile

ROOT = os.environ.get("ROOT") or (sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/dev/testlogon"))
SS = os.path.join(ROOT, "app/routers/subscription_server.py")
SR = os.path.join(ROOT, "app/services/subscription_renewal.py")

results = []

def _read(p):
    with io.open(p, "r", encoding="utf-8") as f:
        return f.read()

def _write(p, s):
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(s)

def patch(path, name, old, new, marker):
    src = _read(path)
    if marker in src:
        results.append((name, "SKIP_ALREADY"))
        return src
    n = src.count(old)
    if n != 1:
        raise SystemExit(f"ANCHOR FAIL {name}: expected 1 occurrence, found {n} in {path}")
    src = src.replace(old, new, 1)
    _write(path, src)
    results.append((name, "APPLIED"))
    return src

# ---------------------------------------------------------------------------
# P0 — SubscriptionChangePlanIn: optional explicit PM for the upgrade delta charge
# ---------------------------------------------------------------------------
patch(
    SS, "P0_changeplan_pm",
    '''    proration_amount_cents: Optional[int] = None
    provider_invoice_id: Optional[str] = None
    reason: Optional[str] = None''',
    '''    proration_amount_cents: Optional[int] = None
    # SUB-E2: optional explicit PM to charge the upgrade delta against (falls back
    # to the subscription's stored payment_method_id).
    payment_method_id: Optional[str] = None
    provider_invoice_id: Optional[str] = None
    reason: Optional[str] = None''',
    "SUB-E2: optional explicit PM to charge the upgrade delta",
)

# ---------------------------------------------------------------------------
# P1 — subscribe(): trial card-up-front (capture + validate PM, no charge)
# ---------------------------------------------------------------------------
P1_OLD = '''            idempotency_key=(idempotency_key or f"{subscription_id}:{ts}"),
        )

    sub = {'''
P1_NEW = '''            idempotency_key=(idempotency_key or f"{subscription_id}:{ts}"),
        )
    elif status == "trialing":
        # SUB-E2: TRIAL requires a CARD UP FRONT. Capture + VALIDATE a real owned
        # PM at trial start (NO charge now); store it so the E1 sweeper can
        # AUTO-CONVERT (charge the stored PM) at trial_end. A trial with no
        # resolvable/owned PM is rejected 402 here -> no phantom trialing sub.
        payment_method_id = resolve_subscription_payment_method(subscriber_id, body.payment_method_id)

    sub = {'''
patch(SS, "P1_trial_pm", P1_OLD, P1_NEW, 'SUB-E2: TRIAL requires a CARD UP FRONT')

# ---------------------------------------------------------------------------
# P2a — change_subscription_plan(): route by price
# ---------------------------------------------------------------------------
P2A_OLD = '''    if body.effective == "period_end":
        sub["pending_plan_id"] = body.plan_id
        sub["pending_interval"] = interval
        sub["pending_price_cents"] = new_price
        sub["pending_apply_at"] = sub.get("current_period_end")
        sub["updated_at"] = ts
        save_subscription(sub)
        record_billing_subscription(sub)
        audit_event(
            "subscription_plan_change_scheduled",
            sub["subscriber_id"],
            request,
            outcome="success",
            subscription_id=subscription_id,
            plan_id=body.plan_id,
            effective=body.effective,
        )
        refresh_subscription_calendar_events(sub, plan)
        return attach_subscription_profiles(sub)

    proration_amount = 0
    if body.proration_amount_cents is not None:
        proration_amount = int(body.proration_amount_cents)
    elif body.proration_policy != "none":
        proration_amount = calculate_proration(
            current_price=int(sub["price_cents"]),
            new_price=int(new_price),
            now=ts,
            period_start=int(sub.get("start_at") or ts),
            period_end=int(sub.get("current_period_end") or ts),
        )
    if body.proration_policy == "none":
        proration_amount = 0
    elif proration_amount > 0 and body.proration_policy == "credit":
        proration_amount = 0
    elif proration_amount < 0 and body.proration_policy == "charge":
        proration_amount = 0

    sub["plan_id"] = body.plan_id
    sub["interval"] = interval
    sub["price_cents"] = int(new_price)
    sub["proration_policy"] = body.proration_policy
    sub["updated_at"] = ts
    save_subscription(sub)
    record_billing_subscription(sub)

    if proration_amount != 0:
        invoice_id = body.provider_invoice_id or new_id("inv")
        proration_status = "paid" if proration_amount > 0 else "credited"
        invoice = {
            "invoice_id": invoice_id,
            "subscription_id": subscription_id,
            "subscriber_id": sub["subscriber_id"],
            "provider_invoice_id": body.provider_invoice_id or new_id("stub_inv"),
            "amount_cents": abs(int(proration_amount)),
            "currency": sub["currency"],
            "status": proration_status,
            "period_start": ts,
            "period_end": sub.get("current_period_end"),
            "created_at": ts,
            "is_proration": True,
            "proration_amount_cents": int(proration_amount),
            "proration_period_start": sub.get("start_at"),
            "proration_period_end": sub.get("current_period_end"),
        }
        recurring = emit_subscription_cycle_order_and_reconcile(subscription=sub, plan=plan, invoice=invoice)
        invoice["recurring_order_id"] = recurring["order_id"]
        save_invoice(invoice)
        record_billing_payment(invoice, subscription_id)
        record_billing_transaction(
            user_sub=sub["subscriber_id"],
            amount_cents=int(proration_amount),
            currency=sub["currency"],
            description=f"Subscription proration {subscription_id}",
            status="COMPLETED",
            external_ref=invoice_id,
            metadata={"subscription_id": subscription_id, "creator_id": sub["creator_id"]},
        )

        entry_type = "proration_charge" if proration_amount > 0 else "proration_credit"
        entry = {
            "entry_id": new_id("led"),
            "subscription_id": subscription_id,
            "subscriber_id": sub["subscriber_id"],
            "entry_type": entry_type,
            "amount_cents": abs(int(proration_amount)),
            "currency": sub["currency"],
            "created_at": ts,
            "metadata": {"invoice_id": invoice_id, "proration_amount_cents": proration_amount},
        }
        save_ledger_entry(sub["creator_id"], entry)

    audit_event(
        "subscription_plan_changed",
        sub["subscriber_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        plan_id=body.plan_id,
        proration_amount_cents=proration_amount,
    )
    refresh_subscription_calendar_events(sub, plan)
    return attach_subscription_profiles(sub)'''

P2A_NEW = '''    # SUB-E2 LOCKED ROUTING: an UPGRADE (target price strictly higher) applies
    # IMMEDIATELY and charges the PRORATED DELTA for the remaining period now (real
    # E0 rail + creator credited the delta NET). A DOWNGRADE (target price <=
    # current) is SCHEDULED as a pending_change that the E1 sweeper applies at
    # period end (no immediate money). An explicit effective="period_end" also
    # schedules.
    old_price = int(sub["price_cents"])
    is_upgrade = int(new_price) > old_price
    schedule_at_period_end = (not is_upgrade) or (body.effective == "period_end")

    if schedule_at_period_end:
        apply_at = int(sub.get("current_period_end") or ts)
        sub["pending_change"] = {
            "plan_id": body.plan_id,
            "interval": interval,
            "price_cents": int(new_price),
            "apply_at": apply_at,
            "scheduled_at": ts,
            "direction": "upgrade" if is_upgrade else "downgrade",
        }
        # legacy mirror fields (kept for any back-compat reader)
        sub["pending_plan_id"] = body.plan_id
        sub["pending_interval"] = interval
        sub["pending_price_cents"] = int(new_price)
        sub["pending_apply_at"] = apply_at
        sub["updated_at"] = ts
        save_subscription(sub)
        record_billing_subscription(sub)
        audit_event(
            "subscription_plan_change_scheduled",
            sub["subscriber_id"],
            request,
            outcome="success",
            subscription_id=subscription_id,
            plan_id=body.plan_id,
            effective="period_end",
        )
        refresh_subscription_calendar_events(sub, plan)
        return attach_subscription_profiles(sub)

    # ---- UPGRADE: immediate, prorated DELTA charge via the E0 rail ----
    # delta = (new_price - old_price) * remaining_fraction (>=0 for an upgrade with
    # time left; a fully-elapsed period yields 0 -> switch plan with no charge).
    proration_amount = calculate_proration(
        current_price=old_price,
        new_price=int(new_price),
        now=ts,
        period_start=int(sub.get("start_at") or ts),
        period_end=int(sub.get("current_period_end") or ts),
    )
    if proration_amount < 0:
        proration_amount = 0
    upgrade_pm = None
    upgrade_pi = None
    if proration_amount > 0:
        upgrade_pm = resolve_subscription_payment_method(
            sub["subscriber_id"], body.payment_method_id or sub.get("payment_method_id")
        )
        upgrade_pi = _charge_subscription_payment_intent(
            subscriber_id=sub["subscriber_id"],
            amount_cents=int(proration_amount),
            currency=sub["currency"],
            payment_method_id=upgrade_pm,
            plan_id=body.plan_id,
            subscription_id=subscription_id,
            idempotency_key=f"{subscription_id}:upgrade:{int(sub.get('current_period_end') or ts)}:{body.plan_id}",
        )

    # switch the plan NOW; the cycle they already paid keeps its period end (they
    # only owe the upgrade delta for the remaining time).
    sub["plan_id"] = body.plan_id
    sub["interval"] = interval
    sub["price_cents"] = int(new_price)
    sub["proration_policy"] = body.proration_policy
    if upgrade_pm:
        sub["payment_method_id"] = upgrade_pm
    for _k in ("pending_change", "pending_plan_id", "pending_interval", "pending_price_cents", "pending_apply_at"):
        sub.pop(_k, None)
    sub["updated_at"] = ts
    save_subscription(sub)
    record_billing_subscription(sub)

    if proration_amount > 0:
        invoice_id = body.provider_invoice_id or new_id("inv")
        invoice = {
            "invoice_id": invoice_id,
            "subscription_id": subscription_id,
            "subscriber_id": sub["subscriber_id"],
            "provider": "stripe" if upgrade_pi else "stub",
            "provider_invoice_id": upgrade_pi or body.provider_invoice_id or new_id("stub_inv"),
            "payment_intent_id": upgrade_pi,
            "payment_method_id": upgrade_pm,
            "amount_cents": int(proration_amount),
            "currency": sub["currency"],
            "status": "paid",
            "period_start": ts,
            "period_end": sub.get("current_period_end"),
            "created_at": ts,
            "billing_reason": "subscription_upgrade_proration",
            "is_proration": True,
            "proration_amount_cents": int(proration_amount),
            "proration_period_start": sub.get("start_at"),
            "proration_period_end": sub.get("current_period_end"),
        }
        recurring = emit_subscription_cycle_order_and_reconcile(subscription=sub, plan=plan, invoice=invoice)
        invoice["recurring_order_id"] = recurring["order_id"]
        save_invoice(invoice)
        record_billing_payment(invoice, subscription_id)
        record_billing_transaction(
            user_sub=sub["subscriber_id"],
            amount_cents=int(proration_amount),
            currency=sub["currency"],
            description=f"Subscription upgrade proration {subscription_id}",
            status="COMPLETED",
            external_ref=invoice_id,
            metadata={"subscription_id": subscription_id, "creator_id": sub["creator_id"], "billing_reason": "upgrade_proration"},
        )
        # creator credited the DELTA NET (10% fee) -> withdrawable via the mirror
        fee_cents = int(proration_amount * FEE_BPS / 10000)
        _base = {
            "subscription_id": subscription_id,
            "subscriber_id": sub["subscriber_id"],
            "currency": sub["currency"],
            "created_at": ts,
            "metadata": {"invoice_id": invoice_id, "billing_reason": "upgrade_proration"},
        }
        save_ledger_entry(sub["creator_id"], {**_base, "entry_id": new_id("led"), "entry_type": "charge", "amount_cents": int(proration_amount)})
        save_ledger_entry(sub["creator_id"], {**_base, "entry_id": new_id("led"), "entry_type": "fee", "amount_cents": fee_cents})
        _mirror_creator_credit_to_billing(
            sub["creator_id"],
            int(proration_amount) - fee_cents,
            currency=sub["currency"],
            created_at=ts,
            subscription_id=subscription_id,
            subscriber_id=sub["subscriber_id"],
            invoice_id=invoice_id,
        )

    audit_event(
        "subscription_plan_changed",
        sub["subscriber_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        plan_id=body.plan_id,
        proration_amount_cents=proration_amount,
    )
    refresh_subscription_calendar_events(sub, plan)
    return attach_subscription_profiles(sub)'''
patch(SS, "P2_change_plan", P2A_OLD, P2A_NEW, "SUB-E2 LOCKED ROUTING")

# ---------------------------------------------------------------------------
# P3a — sweep summary buckets
# ---------------------------------------------------------------------------
P3A_OLD = '''        "idempotent_skips": [],
        "grandfather_skips": [],
    }'''
P3A_NEW = '''        "idempotent_skips": [],
        "grandfather_skips": [],
        "trial_converted": [],
        "plan_changed": [],
    }'''
patch(SR, "P3a_summary", P3A_OLD, P3A_NEW, '"trial_converted": [],')

# ---------------------------------------------------------------------------
# P3b — _process(): auto-convert trials at trial_end
# ---------------------------------------------------------------------------
P3B_OLD = '''def _process(sub: Dict[str, Any], now: int, summary: Dict[str, Any]) -> None:
    status = (sub.get("status") or "").lower()
    if status not in ("active", "past_due"):
        return'''
P3B_NEW = '''def _process(sub: Dict[str, Any], now: int, summary: Dict[str, Any]) -> None:
    status = (sub.get("status") or "").lower()
    # SUB-E2: AUTO-CONVERT a trial at trial_end -> charge the card captured up front
    # at trial start (via the same real rail). Success -> active + creator credited;
    # decline / no-PM -> dunning (past_due). Trials are otherwise not "due".
    if status == "trialing":
        trial_end = int(sub.get("trial_end") or sub.get("current_period_end") or 0)
        if trial_end and trial_end <= now:
            _attempt_renewal(sub, now, summary, trial_conversion=True)
        return
    if status not in ("active", "past_due"):
        return'''
patch(SR, "P3b_process_trial", P3B_OLD, P3B_NEW, "AUTO-CONVERT a trial at trial_end")

# ---------------------------------------------------------------------------
# P3c — _attempt_renewal(): apply pending_change + trial flag
# ---------------------------------------------------------------------------
P3C_OLD = '''def _attempt_renewal(sub: Dict[str, Any], now: int, summary: Dict[str, Any]) -> None:
    from app.routers.subscription_server import _charge_subscription_payment_intent

    subscription_id = sub["subscription_id"]
    amount = _renewal_amount(sub)
    if amount <= 0:
        _renewal_success(sub, now, None, 0, summary)
        return
    pm = sub.get("payment_method_id")
    if not pm:
        _decline(sub, now, "no_payment_method", summary)
        return
    cpe = int(sub.get("current_period_end") or now)
    try:
        pi_id = _charge_subscription_payment_intent(
            subscriber_id=sub["subscriber_id"],
            amount_cents=int(amount),
            currency=sub.get("currency", "usd"),
            payment_method_id=pm,
            plan_id=sub.get("plan_id", ""),
            subscription_id=subscription_id,
            idempotency_key=f"{subscription_id}:{cpe}",
        )
    except HTTPException as exc:
        if exc.status_code == 402:
            _decline(sub, now, "charge_declined", summary)
            return
        raise
    _renewal_success(sub, now, pi_id, amount, summary)'''
P3C_NEW = '''def _apply_pending_change(sub: Dict[str, Any], now: int) -> bool:
    """SUB-E2: apply a SCHEDULED plan change (downgrade / period-end change) once its
    apply_at has arrived. Mutates plan_id/interval/price_cents so the renewal that
    follows charges the NEW plan for the NEW period. Returns True if applied."""
    pending = sub.get("pending_change") or {}
    if not pending and sub.get("pending_plan_id"):
        pending = {
            "plan_id": sub.get("pending_plan_id"),
            "interval": sub.get("pending_interval"),
            "price_cents": sub.get("pending_price_cents"),
            "apply_at": sub.get("pending_apply_at"),
        }
    if not pending or not pending.get("plan_id"):
        return False
    apply_at = int(pending.get("apply_at") or sub.get("current_period_end") or 0)
    if apply_at and apply_at > now:
        return False
    sub["plan_id"] = pending["plan_id"]
    if pending.get("interval"):
        sub["interval"] = pending["interval"]
    if pending.get("price_cents") is not None:
        sub["price_cents"] = int(pending["price_cents"])
    sub["plan_change_applied_at"] = now
    # a plan change resets any old-plan discount
    sub.pop("discount", None)
    sub.pop("discount_remaining_months", None)
    for k in ("pending_change", "pending_plan_id", "pending_interval", "pending_price_cents", "pending_apply_at"):
        sub.pop(k, None)
    return True


def _attempt_renewal(sub: Dict[str, Any], now: int, summary: Dict[str, Any], *, trial_conversion: bool = False) -> None:
    from app.routers.subscription_server import _charge_subscription_payment_intent

    subscription_id = sub["subscription_id"]
    # SUB-E2: apply any DUE scheduled (downgrade / period-end) plan change BEFORE
    # computing the amount so this cycle charges the new plan/price.
    if not trial_conversion and _apply_pending_change(sub, now):
        summary["plan_changed"].append(subscription_id)
    amount = _renewal_amount(sub)
    if amount <= 0:
        _renewal_success(sub, now, None, 0, summary, trial_conversion=trial_conversion)
        return
    pm = sub.get("payment_method_id")
    if not pm:
        _decline(sub, now, "no_payment_method", summary)
        return
    cpe = int(sub.get("current_period_end") or now)
    idem_suffix = "convert" if trial_conversion else str(cpe)
    try:
        pi_id = _charge_subscription_payment_intent(
            subscriber_id=sub["subscriber_id"],
            amount_cents=int(amount),
            currency=sub.get("currency", "usd"),
            payment_method_id=pm,
            plan_id=sub.get("plan_id", ""),
            subscription_id=subscription_id,
            idempotency_key=f"{subscription_id}:{idem_suffix}",
        )
    except HTTPException as exc:
        if exc.status_code == 402:
            _decline(sub, now, "charge_declined", summary)
            return
        raise
    _renewal_success(sub, now, pi_id, amount, summary, trial_conversion=trial_conversion)'''
patch(SR, "P3c_attempt_renewal", P3C_OLD, P3C_NEW, "def _apply_pending_change")

# ---------------------------------------------------------------------------
# P3d — _renewal_success(): trial_conversion param
# ---------------------------------------------------------------------------
patch(
    SR, "P3d_success_sig",
    "def _renewal_success(sub: Dict[str, Any], now: int, pi_id: Optional[str], amount: int, summary: Dict[str, Any]) -> None:",
    "def _renewal_success(sub: Dict[str, Any], now: int, pi_id: Optional[str], amount: int, summary: Dict[str, Any], *, trial_conversion: bool = False) -> None:",
    "amount: int, summary: Dict[str, Any], *, trial_conversion: bool = False)",
)
patch(
    SR, "P3d_success_billing_reason",
    '''        "created_at": now,
        "billing_reason": "subscription_renewal",
    }''',
    '''        "created_at": now,
        "billing_reason": ("trial_conversion" if trial_conversion else "subscription_renewal"),
    }''',
    '("trial_conversion" if trial_conversion else "subscription_renewal"),',
)
patch(
    SR, "P3d_success_status",
    '''    sub["status"] = "active"
    sub["last_renewed_at"] = now''',
    '''    sub["status"] = "active"
    if trial_conversion:
        sub["trial_converted_at"] = now
    sub["last_renewed_at"] = now''',
    "if trial_conversion:\n        sub[\"trial_converted_at\"] = now",
)
patch(
    SR, "P3d_success_bucket",
    '''    summary["renewed"].append({"subscription_id": subscription_id, "amount_cents": int(amount), "new_period_end": new_cpe, "pi": pi_id})
    logger.info("subscription_renewed id=%s amount=%s new_cpe=%s pi=%s", subscription_id, amount, new_cpe, pi_id)''',
    '''    _bucket = "trial_converted" if trial_conversion else "renewed"
    summary[_bucket].append({"subscription_id": subscription_id, "amount_cents": int(amount), "new_period_end": new_cpe, "pi": pi_id})
    logger.info("subscription_%s id=%s amount=%s new_cpe=%s pi=%s", _bucket, subscription_id, amount, new_cpe, pi_id)''',
    '_bucket = "trial_converted" if trial_conversion else "renewed"',
)

# ---------------------------------------------------------------------------
py_compile.compile(SS, doraise=True)
py_compile.compile(SR, doraise=True)
print("ROOT=", ROOT)
for n, s in results:
    print(f"  {s:16} {n}")
print("PY_COMPILE_OK")
