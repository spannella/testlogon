from __future__ import annotations

"""SUB-E1: recurring RENEWAL + DUNNING sweeper + expiry lifecycle.

A periodic asyncio sweep (pattern: moderation_lifecycle.start_hold_sweep_task /
billing_dunning) that scans T.subscriptions base META rows and drives the money +
lifecycle state machine:

  * DUE renewal (active, auto_renew, not cancel_at_period_end, next_billing_date<=now)
    -> REAL funds-guarded charge via subscription_server._charge_subscription_payment_intent
       (idempotency_key = sub_id:current_period_end, ONE charge per cycle) ->
       on success: advance current_period_end += interval + next_billing_date,
       credit the creator NET (10% fee) each cycle, write a paid invoice, clear
       dunning, emit 'subscription_renewed'.
  * DECLINE / no-stored-PM -> DUNNING: status past_due + retry at day 1/3/5/7
    (SUBSCRIPTION_DUNNING_RETRY_DAYS), emit 'subscription_renewal_failed'; after
    the last retry -> GRACE (SUBSCRIPTION_GRACE_DAYS=7) -> status 'expired' +
    'subscription_expired'.
  * cancel_at_period_end / auto_renew off at period end -> terminal (canceled/expired).

Idempotency: the stripe-mock PaymentIntent idempotency_key (sub_id:period_end) makes
the processor charge at most once per cycle even across overlapping ticks; a
conditional RENEWCYCLE# marker makes the creator credit + invoice + period-advance
fire at most once per cycle. A declined renewal writes NO credit.

All charge/credit/invoice primitives are reused verbatim from subscription_server
(lazy-imported to avoid an import cycle: main -> this -> router).
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def _retry_days() -> List[int]:
    raw = getattr(S, "subscription_dunning_retry_days", "1,3,5,7")
    try:
        days = [int(x.strip()) for x in str(raw).split(",") if x.strip()]
    except Exception:
        days = [1, 3, 5, 7]
    return days or [1, 3, 5, 7]


def _grace_days() -> int:
    try:
        return int(getattr(S, "subscription_grace_days", 7))
    except Exception:
        return 7


# ---------------------------------------------------------------------------
# per-cycle idempotency claim
# ---------------------------------------------------------------------------

def _claim_renewal_cycle(subscription_id: str, cycle_key: str) -> bool:
    """Conditionally claim (subscription_id, cycle_key). Returns True for the FIRST
    claimer only -> guarantees the creator credit + invoice + period-advance run at
    most once per billing cycle even under overlapping sweeps."""
    from app.routers.subscription_server import pk_subscription

    try:
        T.subscriptions.put_item(
            Item={
                "pk": pk_subscription(subscription_id),
                "sk": f"RENEWCYCLE#{cycle_key}",
                "entity": "renewal_cycle",
                "created_at": now_ts(),
            },
            ConditionExpression="attribute_not_exists(sk)",
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


# ---------------------------------------------------------------------------
# notifications (default-on push; alerts.DEFAULT_PUSH_EVENT_TYPES)
# ---------------------------------------------------------------------------

def _display_name(user_id: str) -> str:
    try:
        from app.services.profile import get_profile_identity

        return get_profile_identity(user_id).get("display_name") or user_id
    except Exception:
        return user_id


def _emit(alert_type: str, *, recipient: str, actor: str, title: str, details: Dict[str, Any]) -> None:
    try:
        from app.services.social_alerts import emit_social_alert

        emit_social_alert(
            recipient_user_id=recipient,
            alert_type=alert_type,
            actor_user_id=actor,
            actor_display_name=_display_name(actor),
            title=title,
            details=details,
            action_url="/subscriptions",
        )
    except Exception:
        logger.warning("subscription alert %s failed recipient=%s", alert_type, recipient, exc_info=True)


# ---------------------------------------------------------------------------
# amount
# ---------------------------------------------------------------------------

def _renewal_amount(sub: Dict[str, Any]) -> int:
    from app.routers.subscription_server import _apply_discount

    amount = int(sub.get("price_cents") or 0)
    discount = sub.get("discount") or {}
    if discount and int(sub.get("discount_remaining_months") or 0) > 0:
        try:
            amount = _apply_discount(amount, discount)
        except Exception:
            pass
    return max(0, amount)


# ---------------------------------------------------------------------------
# terminal / dunning transitions
# ---------------------------------------------------------------------------

def _save(sub: Dict[str, Any]) -> None:
    from app.routers.subscription_server import save_subscription

    save_subscription(sub)


def _expire(sub: Dict[str, Any], now: int, reason: str, summary: Dict[str, Any]) -> None:
    sub["status"] = "expired"
    sub["auto_renew"] = False
    sub["dunning_state"] = "expired"
    sub["expired_at"] = now
    sub["expired_reason"] = reason
    sub["updated_at"] = now
    _save(sub)
    _emit(
        "subscription_expired",
        recipient=sub["subscriber_id"],
        actor=sub["creator_id"],
        title="Your subscription has expired",
        details={"subscription_id": sub["subscription_id"], "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "reason": reason},
    )
    summary["expired"].append(sub["subscription_id"])
    logger.info("subscription_expired id=%s reason=%s", sub["subscription_id"], reason)


def _decline(sub: Dict[str, Any], now: int, reason: str, summary: Dict[str, Any]) -> None:
    attempts = int(sub.get("dunning_attempts") or 0) + 1
    retry_days = _retry_days()
    sub["status"] = "past_due"
    sub["dunning_attempts"] = attempts
    sub["dunning_last_at"] = now
    sub["dunning_last_reason"] = reason
    sub["updated_at"] = now
    # SUB-E1: establish the ACCESS horizon on the FIRST decline so content access
    # CONTINUES through the entire dunning + grace window (has_active_subscription
    # reads grace_until as the grace-extended end). Horizon = last-retry day + grace
    # days; the period itself (current_period_end) has already elapsed by now.
    if attempts == 1:
        horizon_days = (max(retry_days) if retry_days else 0) + _grace_days()
        sub["grace_until"] = now + horizon_days * 86400
    entered_grace = False
    if attempts <= len(retry_days):
        gap_days = retry_days[attempts - 1]
        sub["dunning_state"] = "retrying"
        sub["dunning_next_retry_at"] = now + gap_days * 86400
    else:
        entered_grace = True
        sub["dunning_state"] = "grace"
        sub["dunning_next_retry_at"] = 0
    _save(sub)
    _emit(
        "subscription_renewal_failed",
        recipient=sub["subscriber_id"],
        actor=sub["creator_id"],
        title="Your subscription payment failed",
        details={"subscription_id": sub["subscription_id"], "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "attempt": attempts, "reason": reason},
    )
    if entered_grace:
        _emit(
            "subscription_expiring",
            recipient=sub["subscriber_id"],
            actor=sub["creator_id"],
            title="Your subscription is about to expire",
            details={"subscription_id": sub["subscription_id"], "grace_until": sub["grace_until"], "creator_id": sub["creator_id"]},
        )
    summary["dunning"].append({"subscription_id": sub["subscription_id"], "attempt": attempts, "grace": entered_grace})
    logger.info("subscription_dunning id=%s attempt=%s grace=%s reason=%s", sub["subscription_id"], attempts, entered_grace, reason)


# ---------------------------------------------------------------------------
# renewal success
# ---------------------------------------------------------------------------

def _renewal_success(sub: Dict[str, Any], now: int, pi_id: Optional[str], amount: int, summary: Dict[str, Any]) -> None:
    from app.routers.subscription_server import (
        FEE_BPS,
        _mirror_creator_credit_to_billing,
        ddb_get_item,
        emit_subscription_cycle_order_and_reconcile,
        interval_seconds,
        new_id,
        pk_plan,
        record_billing_payment,
        record_billing_transaction,
        save_invoice,
        save_ledger_entry,
    )

    subscription_id = sub["subscription_id"]
    old_cpe = int(sub.get("current_period_end") or now)
    cycle_key = str(old_cpe)

    # ONE credit/invoice/advance per cycle (charge itself already idempotent at processor)
    if not _claim_renewal_cycle(subscription_id, cycle_key):
        summary["idempotent_skips"].append(subscription_id)
        logger.info("renewal cycle already claimed id=%s cycle=%s (idempotent skip)", subscription_id, cycle_key)
        return

    interval = sub.get("interval", "month")
    new_cpe = old_cpe + interval_seconds(interval)
    currency = sub.get("currency", "usd")
    plan = ddb_get_item(pk_plan(sub["plan_id"]), "META")

    invoice_id = new_id("inv")
    invoice = {
        "invoice_id": invoice_id,
        "subscription_id": subscription_id,
        "subscriber_id": sub["subscriber_id"],
        "provider": "stripe" if pi_id else "stub",
        "provider_invoice_id": pi_id or new_id("stub_inv"),
        "payment_intent_id": pi_id,
        "payment_method_id": sub.get("payment_method_id"),
        "amount_cents": int(amount),
        "currency": currency,
        "status": "paid",
        "period_start": old_cpe,
        "period_end": new_cpe,
        "created_at": now,
        "billing_reason": "subscription_renewal",
    }
    # advance the record BEFORE reconcile so the recurring order carries the new period
    sub["current_period_end"] = new_cpe
    sub["next_billing_date"] = new_cpe
    sub["status"] = "active"
    sub["last_renewed_at"] = now
    sub["renewal_count"] = int(sub.get("renewal_count") or 0) + 1
    # clear dunning
    for k in ("dunning_state", "dunning_attempts", "dunning_next_retry_at", "grace_until", "dunning_last_at", "dunning_last_reason"):
        sub.pop(k, None)
    if int(sub.get("discount_remaining_months") or 0) > 0:
        sub["discount_remaining_months"] = int(sub["discount_remaining_months"]) - 1
    sub["updated_at"] = now
    _save(sub)

    if plan:
        try:
            recurring = emit_subscription_cycle_order_and_reconcile(subscription=sub, plan=plan, invoice=invoice)
            invoice["recurring_order_id"] = recurring["order_id"]
        except Exception:
            logger.warning("renewal recurring reconcile failed id=%s", subscription_id, exc_info=True)
    save_invoice(invoice)
    record_billing_payment(invoice, subscription_id)
    if amount > 0:
        try:
            record_billing_transaction(
                user_sub=sub["subscriber_id"],
                amount_cents=int(amount),
                currency=currency,
                description=f"Subscription renewal {sub.get('plan_id')}",
                status="COMPLETED",
                external_ref=invoice_id,
                metadata={"subscription_id": subscription_id, "creator_id": sub["creator_id"], "billing_reason": "renewal"},
            )
        except Exception:
            logger.warning("renewal record_billing_transaction failed id=%s", subscription_id, exc_info=True)

        fee_cents = int(amount * FEE_BPS / 10000)
        base = {"subscription_id": subscription_id, "subscriber_id": sub["subscriber_id"], "currency": currency, "created_at": now, "metadata": {"invoice_id": invoice_id, "billing_reason": "renewal"}}
        save_ledger_entry(sub["creator_id"], {**base, "entry_id": new_id("led"), "entry_type": "charge", "amount_cents": int(amount)})
        save_ledger_entry(sub["creator_id"], {**base, "entry_id": new_id("led"), "entry_type": "fee", "amount_cents": fee_cents})
        _mirror_creator_credit_to_billing(
            sub["creator_id"],
            int(amount) - fee_cents,
            currency=currency,
            created_at=now,
            subscription_id=subscription_id,
            subscriber_id=sub["subscriber_id"],
            invoice_id=invoice_id,
        )

    _emit(
        "subscription_renewed",
        recipient=sub["subscriber_id"],
        actor=sub["creator_id"],
        title="Your subscription renewed",
        details={"subscription_id": subscription_id, "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "amount_cents": int(amount), "period_end": new_cpe},
    )
    _emit(
        "subscription_renewed",
        recipient=sub["creator_id"],
        actor=sub["subscriber_id"],
        title="A subscription renewed",
        details={"subscription_id": subscription_id, "plan_id": sub.get("plan_id"), "subscriber_id": sub["subscriber_id"], "amount_cents": int(amount)},
    )
    summary["renewed"].append({"subscription_id": subscription_id, "amount_cents": int(amount), "new_period_end": new_cpe, "pi": pi_id})
    logger.info("subscription_renewed id=%s amount=%s new_cpe=%s pi=%s", subscription_id, amount, new_cpe, pi_id)


def _attempt_renewal(sub: Dict[str, Any], now: int, summary: Dict[str, Any]) -> None:
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
    _renewal_success(sub, now, pi_id, amount, summary)


# ---------------------------------------------------------------------------
# per-subscription dispatch
# ---------------------------------------------------------------------------

def _process(sub: Dict[str, Any], now: int, summary: Dict[str, Any]) -> None:
    status = (sub.get("status") or "").lower()
    if status not in ("active", "past_due"):
        return
    auto_renew = bool(sub.get("auto_renew", True))
    cancel_ape = bool(sub.get("cancel_at_period_end", False))
    cpe = int(sub.get("current_period_end") or 0)
    nbd = int(sub.get("next_billing_date") or cpe or 0)
    grace_until = int(sub.get("grace_until") or 0)
    dunning_state = (sub.get("dunning_state") or "")
    next_retry = int(sub.get("dunning_next_retry_at") or 0)

    # (1) grace exhausted -> expired
    if status == "past_due" and dunning_state == "grace":
        if grace_until and grace_until <= now:
            _expire(sub, now, "dunning_exhausted", summary)
        return

    # (2) cancel-at-period-end / auto_renew-off lapse at period end
    if cpe and cpe <= now and (cancel_ape or not auto_renew):
        if cancel_ape:
            sub["status"] = "canceled"
            sub["canceled_at"] = sub.get("canceled_at") or now
            sub["updated_at"] = now
            _save(sub)
            summary["canceled"].append(sub["subscription_id"])
            logger.info("subscription_canceled_at_period_end id=%s", sub["subscription_id"])
        else:
            _expire(sub, now, "auto_renew_off", summary)
        return

    # (3) due?
    if status == "active":
        grandfathered = not sub.get("next_billing_date") and not sub.get("payment_method_id")
        if grandfathered:
            summary["grandfather_skips"].append(sub["subscription_id"])
            return
        due = (nbd and nbd <= now) or (cpe and cpe <= now)
        if not due:
            return
    else:  # past_due
        if next_retry and next_retry > now:
            return

    # (4) attempt renewal / retry
    _attempt_renewal(sub, now, summary)


# ---------------------------------------------------------------------------
# sweep
# ---------------------------------------------------------------------------

def run_renewal_sweep(*, now: Optional[int] = None, limit: int = 1000) -> Dict[str, Any]:
    """Scan T.subscriptions base META rows and drive one lifecycle tick each.
    In-process callable (verify) + driven by the periodic task and the admin
    endpoint. Returns an action summary."""
    ts = int(now or now_ts())
    summary: Dict[str, Any] = {
        "now": ts,
        "scanned": 0,
        "renewed": [],
        "dunning": [],
        "expired": [],
        "canceled": [],
        "idempotent_skips": [],
        "grandfather_skips": [],
    }
    filter_expr = Attr("entity").eq("subscription") & Attr("sk").eq("META")
    last_key: Optional[Dict[str, Any]] = None
    while summary["scanned"] < limit:
        kwargs: Dict[str, Any] = {"FilterExpression": filter_expr, "Limit": min(200, limit - summary["scanned"])}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.subscriptions.scan(**kwargs)
        for item in resp.get("Items", []):
            summary["scanned"] += 1
            try:
                _process(item, ts, summary)
            except Exception:
                logger.exception("renewal sweep: failed subscription=%s", item.get("subscription_id"))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return summary


# ---------------------------------------------------------------------------
# periodic task
# ---------------------------------------------------------------------------

async def _renewal_loop() -> None:
    from app.services.job_registry import register_task, report_error, report_poll

    interval = max(60, int(getattr(S, "subscription_renewal_interval_seconds", 900)))
    register_task("subscription_renewal", interval, enabled=True, description="Recurring subscription renewal + dunning + expiry sweep")
    logger.info("subscription renewal sweep started (interval=%ds)", interval)
    while True:
        _start = time.perf_counter()
        try:
            run_renewal_sweep()
            report_poll("subscription_renewal", duration_ms=(time.perf_counter() - _start) * 1000)
        except Exception as exc:
            try:
                report_error("subscription_renewal", str(exc))
            except Exception:
                pass
            logger.exception("subscription renewal loop failed")
        await asyncio.sleep(interval)


def start_subscription_renewal_task() -> None:
    if not getattr(S, "subscription_renewal_enabled", True):
        try:
            from app.services.job_registry import register_task

            register_task("subscription_renewal", 900, enabled=False, description="Recurring subscription renewal + dunning + expiry sweep")
        except Exception:
            pass
        logger.info("subscription renewal sweep disabled")
        return
    try:
        asyncio.get_event_loop().create_task(_renewal_loop())
    except RuntimeError:
        asyncio.ensure_future(_renewal_loop())
