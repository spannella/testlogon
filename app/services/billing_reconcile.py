from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_ccbill import (
    apply_balance_delta as ccbill_apply_balance_delta,
    settle_or_reverse_ledger as ccbill_settle_or_reverse_ledger,
    update_payment_status as ccbill_update_payment_status,
)
from app.services.billing_shared import apply_balance_delta, settle_or_reverse_ledger, user_pk

logger = logging.getLogger(__name__)

PENDING_STATUSES = {
    "pending",
    "processing",
    "requires_action",
    "requires_payment_method",
    "requires_confirmation",
    "requires_capture",
}

STRIPE_FAILURE_STATUSES = {"canceled", "payment_failed", "requires_payment_method"}
PAYPAL_FAILURE_STATUSES = {"VOIDED", "CANCELLED", "CANCELED", "EXPIRED"}
PAYPAL_PENDING_STATUSES = {"CREATED", "SAVED", "APPROVED", "PAYER_ACTION_REQUIRED"}


def _pending_cutoff_ts() -> int:
    return now_ts() - int(S.billing_reconcile_pending_age_seconds)


def _age_ts(item: Dict[str, Any]) -> int:
    return int(item.get("updated_at") or item.get("created_at") or 0)


def _scan_pending_payments(limit: int) -> List[Dict[str, Any]]:
    if limit <= 0:
        return []
    items: List[Dict[str, Any]] = []
    last_key: Optional[Dict[str, Any]] = None
    filter_expr = Attr("sk").begins_with("PAY#") & Attr("status").is_in(list(PENDING_STATUSES))
    while len(items) < limit:
        scan_kwargs: Dict[str, Any] = {
            "FilterExpression": filter_expr,
            "Limit": min(200, limit - len(items)),
        }
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        resp = T.billing.scan(**scan_kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


def _user_id_from_pk(pk: str) -> Optional[str]:
    if not pk or not pk.startswith("USER#"):
        return None
    return pk.split("USER#", 1)[1]


def _reconcile_stripe_payment(item: Dict[str, Any]) -> Optional[str]:
    from app.routers import billing as stripe_router

    stripe_router.ensure_stripe_configured()
    if not stripe_router.stripe:
        return None

    pi_id = item.get("payment_intent_id")
    if not pi_id:
        return None

    pk = item.get("pk")
    user_id = _user_id_from_pk(pk) if isinstance(pk, str) else None
    if not user_id:
        return None

    pi = stripe_router.stripe.PaymentIntent.retrieve(pi_id)
    status = pi.get("status")
    prior_status = item.get("status")
    amount = int(item.get("amount_cents", 0))
    ledger_sk = item.get("ledger_sk")
    purchase_txn_id = item.get("purchase_txn_id")

    charge_id = None
    try:
        charges = (pi.get("charges") or {}).get("data") or []
        if charges:
            charge_id = charges[0].get("id")
    except Exception:
        charge_id = None

    if status == "succeeded":
        stripe_router.update_payment_status(user_id, pi_id, "succeeded", charge_id=charge_id)
        stripe_router._sync_purchase_history_status(
            user_id=user_id,
            purchase_txn_id=purchase_txn_id,
            status="succeeded",
            charge_id=charge_id,
        )
        if prior_status in PENDING_STATUSES:
            apply_balance_delta(T.billing, pk, {"payments_pending_cents": -amount, "payments_settled_cents": amount}, currency=item.get("currency", "usd"))
        if ledger_sk:
            settle_or_reverse_ledger(T.billing, "pk", pk, ledger_sk, "settled")
        return "succeeded"

    if status in STRIPE_FAILURE_STATUSES:
        stripe_router.update_payment_status(
            user_id,
            pi_id,
            status,
            charge_id=charge_id,
            last_error=pi.get("last_payment_error"),
        )
        stripe_router._sync_purchase_history_status(
            user_id=user_id,
            purchase_txn_id=purchase_txn_id,
            status=status,
            charge_id=charge_id,
            last_error=pi.get("last_payment_error"),
        )
        if prior_status in PENDING_STATUSES:
            apply_balance_delta(T.billing, pk, {"payments_pending_cents": -amount}, currency=item.get("currency", "usd"))
        if ledger_sk:
            settle_or_reverse_ledger(T.billing, "pk", pk, ledger_sk, "reversed")
        return status

    stripe_router.update_payment_status(user_id, pi_id, status, charge_id=charge_id)
    return status


def _paypal_get_order_status(order_id: str) -> Optional[str]:
    from app.routers import paypal as paypal_router

    access = paypal_router.paypal_oauth()
    url = f"{paypal_router.PAYPAL_BASE_URL}/v2/checkout/orders/{order_id}"
    headers = {"Authorization": f"Bearer {access}", "Content-Type": "application/json"}
    resp = paypal_router.requests.get(url, headers=headers, timeout=20)
    if resp.status_code != 200:
        logger.warning("PayPal order lookup failed", extra={"order_id": order_id, "status_code": resp.status_code})
        return None
    data = resp.json()
    return data.get("status")


def _reconcile_paypal_payment(item: Dict[str, Any]) -> Optional[str]:
    from app.routers import paypal as paypal_router

    external_id = item.get("external_id")
    if not external_id:
        return None

    pk = item.get("pk")
    user_id = _user_id_from_pk(pk) if isinstance(pk, str) else None
    if not user_id:
        return None

    status = _paypal_get_order_status(str(external_id))
    if not status:
        return None

    prior_status = item.get("status")
    amount = int(item.get("amount_cents", 0))
    ledger_sk = item.get("ledger_sk")

    if status == "COMPLETED":
        paypal_router.update_payment_status(user_id, str(external_id), "succeeded", raw={"order_status": status})
        if prior_status in PENDING_STATUSES:
            apply_balance_delta(T.billing, pk, {"payments_pending_cents": -amount, "payments_settled_cents": amount}, currency=item.get("currency", "usd"))
        if ledger_sk:
            settle_or_reverse_ledger(T.billing, "pk", pk, ledger_sk, "settled")
        return "succeeded"

    if status in PAYPAL_FAILURE_STATUSES:
        paypal_router.update_payment_status(user_id, str(external_id), "failed", raw={"order_status": status})
        if prior_status in PENDING_STATUSES:
            apply_balance_delta(T.billing, pk, {"payments_pending_cents": -amount}, currency=item.get("currency", "usd"))
        if ledger_sk:
            settle_or_reverse_ledger(T.billing, "pk", pk, ledger_sk, "reversed")
        return "failed"

    if status in PAYPAL_PENDING_STATUSES:
        paypal_router.update_payment_status(user_id, str(external_id), "pending", raw={"order_status": status})
    return status


def _reconcile_ccbill_payment(item: Dict[str, Any]) -> Optional[str]:
    user_sub = item.get("user_sub")
    if not user_sub:
        return None

    if item.get("status") not in PENDING_STATUSES:
        return None

    amount = int(item.get("amount_cents", 0))
    ledger_sk = item.get("ledger_sk")
    transaction_id = item.get("transaction_id")

    ccbill_update_payment_status(str(user_sub), str(transaction_id), "stale", raw={"reason": "reconcile_timeout"})
    ccbill_apply_balance_delta(str(user_sub), {"payments_pending_cents": -amount})
    if ledger_sk:
        ccbill_settle_or_reverse_ledger(str(user_sub), ledger_sk, "reversed")
    return "stale"


def reconcile_pending_payments() -> Dict[str, int]:
    cutoff = _pending_cutoff_ts()
    items = _scan_pending_payments(int(S.billing_reconcile_scan_limit))
    results = {"processed": 0, "stripe": 0, "paypal": 0, "ccbill": 0}
    for item in items:
        if _age_ts(item) > cutoff:
            continue
        try:
            provider = None
            if "payment_intent_id" in item:
                provider = "stripe"
                _reconcile_stripe_payment(item)
                results["stripe"] += 1
            elif "external_id" in item:
                provider = "paypal"
                _reconcile_paypal_payment(item)
                results["paypal"] += 1
            elif "user_sub" in item:
                provider = "ccbill"
                _reconcile_ccbill_payment(item)
                results["ccbill"] += 1
            else:
                provider = "unknown"
            if provider:
                results["processed"] += 1
        except Exception:
            logger.exception("Pending payment reconcile failed", extra={"provider": provider, "sk": item.get("sk")})
    return results


async def billing_reconcile_loop() -> None:
    import time as _time
    from app.services.job_registry import register_task, report_error, report_poll

    interval = max(60, int(S.billing_reconcile_interval_seconds))
    register_task("billing_reconcile", interval, enabled=True,
                   description="Reconciles pending Stripe/PayPal/CCBill payment statuses")

    while True:
        _start = _time.perf_counter()
        try:
            reconcile_pending_payments()
            _dur = (_time.perf_counter() - _start) * 1000
            report_poll("billing_reconcile", duration_ms=_dur)
        except Exception as exc:
            report_error("billing_reconcile", str(exc))
            logger.exception("Billing reconciliation loop failed")
        await asyncio.sleep(interval)


def start_billing_reconcile_task() -> None:
    from app.services.job_registry import register_task

    if not S.billing_reconcile_enabled:
        register_task("billing_reconcile", 60, enabled=False,
                       description="Reconciles pending Stripe/PayPal/CCBill payment statuses")
        logger.info("Billing reconciliation disabled")
        return
    asyncio.create_task(billing_reconcile_loop())
