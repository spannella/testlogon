from __future__ import annotations

import hashlib
from pathlib import Path
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    AddChargeIn,
    OneTimeChargeIn,
    PayBalanceIn,
    PaymentMethodOut,
    RefundIn,
    SavePaymentTokenIn,
    SetAutopayIn,
    SetDefaultIn,
    SetPriorityIn,
    SubscribeMonthlyIn,
)
from app.services.billing_ccbill import (
    apply_balance_delta,
    ccbill_frontend_oauth,
    charge_once,
    compute_due,
    ensure_balance_row,
    list_payment_methods,
    mark_webhook_processed,
    new_ledger_entry,
    pay_balance,
    settle_or_reverse_ledger,
    sanitize_ccbill_payload,
    subscribe_monthly,
    update_payment_status,
    upsert_subscription,
    verify_ccbill_webhook_signature,
    webhook_remote_ip_allowed,
    put_payment_record,
)
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session
from app.services.purchase_history import mark_reverted
from app.services.billing_dunning import (
    bump_dunning_after_payment_method_update,
    schedule_ccbill_autopay_disabled_notice,
    schedule_ccbill_dunning,
)

router = APIRouter(tags=["billing"])


def _pm_sk(payment_token_id: str) -> str:
    return f"PM#{payment_token_id}"


def _pay_sk(transaction_id: str) -> str:
    return f"PAY#{transaction_id}"


def _sub_sk(subscription_id: str) -> str:
    return f"SUB#{subscription_id}"


def _ledger_items(user_sub: str, prefix: str) -> List[Dict[str, Any]]:
    resp = T.billing.query(
        KeyConditionExpression="user_sub = :u AND begins_with(sk, :p)",
        ExpressionAttributeValues={":u": user_sub, ":p": prefix},
    )
    return resp.get("Items", [])


def _safe_webhook_payload(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    sanitized = sanitize_ccbill_payload(payload)
    return sanitized if isinstance(sanitized, dict) else {}


def _webhook_meta(event_type: str, payload: Any, q: Any) -> Dict[str, Any]:
    return {
        "eventType": event_type,
        "payload": _safe_webhook_payload(payload),
        "q": _safe_webhook_payload(q),
    }


def _dollars_str_to_cents(s: Optional[str]) -> Optional[int]:
    if not s:
        return None
    try:
        d = Decimal(str(s)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        return int(d * 100)
    except Exception:
        return None


@router.get("/billing", response_class=HTMLResponse)
def billing_index():
    static_dir = Path(__file__).resolve().parents[1] / "static"
    return FileResponse(static_dir / "index.html")


@router.get("/api/billing/config")
def billing_config():
    return {
        "ccbill_base_url": S.ccbill_base_url,
        "ccbill_accept": S.ccbill_accept,
        "clientAccnum": S.ccbill_client_accnum,
        "clientSubacc": S.ccbill_client_subacc,
        "default_currency": S.default_currency,
        "default_currency_code": S.default_currency_code,
        "default_monthly_price_cents": S.default_monthly_price_cents,
    }


@router.post("/api/billing/ccbill/frontend-oauth")
def get_frontend_oauth(ctx=Depends(require_ui_session)):
    _ = ctx["user_sub"]
    return {"access_token": ccbill_frontend_oauth()}


@router.get("/api/billing/settings")
def get_settings(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    it = T.billing.get_item(Key={"user_sub": user_sub, "sk": "BILLING"}).get("Item")
    return it or {"autopay_enabled": False, "currency": S.default_currency, "default_payment_token_id": None}


@router.post("/api/billing/autopay")
def set_autopay(body: SetAutopayIn, req: Request = None, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    existing = T.billing.get_item(Key={"user_sub": user_sub, "sk": "BILLING"}).get("Item")
    if not existing:
        T.billing.put_item(Item={
            "user_sub": user_sub,
            "sk": "BILLING",
            "autopay_enabled": False,
            "currency": S.default_currency,
            "default_payment_token_id": None,
        })
    T.billing.update_item(
        Key={"user_sub": user_sub, "sk": "BILLING"},
        UpdateExpression="SET autopay_enabled = :e",
        ExpressionAttributeValues={":e": bool(body.enabled)},
    )
    audit_event("billing_autopay_set", user_sub, req, outcome="success", provider="ccbill", enabled=bool(body.enabled))
    if not body.enabled:
        schedule_ccbill_autopay_disabled_notice(user_sub)
    return {"ok": True}


@router.get("/api/billing/balance")
def get_balance(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    ensure_balance_row(user_sub)
    bal = T.billing.get_item(Key={"user_sub": user_sub, "sk": "BALANCE"}).get("Item") or {}
    due = compute_due(bal)
    return {
        "currency": bal.get("currency", S.default_currency),
        "owed_pending_cents": int(bal.get("owed_pending_cents", 0)),
        "owed_settled_cents": int(bal.get("owed_settled_cents", 0)),
        "payments_pending_cents": int(bal.get("payments_pending_cents", 0)),
        "payments_settled_cents": int(bal.get("payments_settled_cents", 0)),
        **due,
        "updated_at": bal.get("updated_at"),
    }


@router.post("/api/billing/payment-methods/ccbill-token")
def save_payment_token(body: SavePaymentTokenIn, req: Request = None, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    existing = list_payment_methods(user_sub)
    next_priority = 0 if not existing else (max(int(x.get("priority", 0)) for x in existing) + 1)

    T.billing.put_item(Item={
        "user_sub": user_sub,
        "sk": _pm_sk(body.payment_token_id),
        "payment_token_id": body.payment_token_id,
        "provider": "ccbill",
        "provider_method_id": body.payment_token_id,
        "label": body.label,
        "priority": next_priority,
        "created_at": now_ts(),
    })

    if body.make_default or not _current_default_pm(user_sub):
        _set_default_pm(user_sub, body.payment_token_id)
    bump_dunning_after_payment_method_update(user_sub, "ccbill")

    audit_event(
        "billing_payment_method_added",
        user_sub,
        req,
        outcome="success",
        provider="ccbill",
        payment_token_id=body.payment_token_id,
        make_default=bool(body.make_default),
    )
    return {"ok": True}


@router.get("/api/billing/payment-methods", response_model=List[PaymentMethodOut])
def list_payment_methods_endpoint(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    default_token = _current_default_pm(user_sub)
    pms = list_payment_methods(user_sub)
    out: List[PaymentMethodOut] = [
        PaymentMethodOut(
            payment_token_id=it["payment_token_id"],
            label=it.get("label"),
            priority=int(it.get("priority", 0)),
            provider=it.get("provider") or "ccbill",
            provider_method_id=it.get("provider_method_id") or it.get("payment_token_id"),
            is_default=it.get("payment_token_id") == default_token,
        )
        for it in pms
    ]
    out.sort(key=lambda x: x.priority)
    return out


@router.post("/api/billing/payment-methods/priority")
def set_priority(body: SetPriorityIn, req: Request = None, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    sk = _pm_sk(body.payment_token_id)
    if not T.billing.get_item(Key={"user_sub": user_sub, "sk": sk}).get("Item"):
        raise HTTPException(404, "Payment method not found")
    T.billing.update_item(
        Key={"user_sub": user_sub, "sk": sk},
        UpdateExpression="SET priority = :p",
        ExpressionAttributeValues={":p": int(body.priority)},
    )
    audit_event(
        "billing_payment_method_priority",
        user_sub,
        req,
        outcome="success",
        provider="ccbill",
        payment_token_id=body.payment_token_id,
        priority=int(body.priority),
    )
    return {"ok": True}


@router.post("/api/billing/payment-methods/default")
def set_default(body: SetDefaultIn, req: Request = None, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    if not T.billing.get_item(Key={"user_sub": user_sub, "sk": _pm_sk(body.payment_token_id)}).get("Item"):
        raise HTTPException(404, "Payment method not found")
    _set_default_pm(user_sub, body.payment_token_id)
    audit_event(
        "billing_payment_method_default",
        user_sub,
        req,
        outcome="success",
        provider="ccbill",
        payment_token_id=body.payment_token_id,
    )
    bump_dunning_after_payment_method_update(user_sub, "ccbill")
    return {"ok": True}


@router.delete("/api/billing/payment-methods/{payment_token_id}")
def remove_payment_method(payment_token_id: str, req: Request = None, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    sk = _pm_sk(payment_token_id)
    if not T.billing.get_item(Key={"user_sub": user_sub, "sk": sk}).get("Item"):
        raise HTTPException(404, "Payment method not found")

    T.billing.delete_item(Key={"user_sub": user_sub, "sk": sk})

    if _current_default_pm(user_sub) == payment_token_id:
        remaining = list_payment_methods(user_sub)
        remaining.sort(key=lambda x: int(x.get("priority", 0)))
        new_default = remaining[0]["payment_token_id"] if remaining else None
        _set_default_pm(user_sub, new_default)
        audit_event(
            "billing_payment_method_removed",
            user_sub,
            req,
            outcome="success",
            provider="ccbill",
            payment_token_id=payment_token_id,
            new_default_payment_token_id=new_default,
        )
    else:
        audit_event(
            "billing_payment_method_removed",
            user_sub,
            req,
            outcome="success",
            provider="ccbill",
            payment_token_id=payment_token_id,
        )

    return {"ok": True}


@router.post("/api/billing/charge-once")
async def charge_once_endpoint(body: OneTimeChargeIn, request: Request, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    resp = charge_once(
        user_sub=user_sub,
        amount_cents=body.amount_cents,
        payment_token_id=body.payment_token_id,
        reason=body.reason,
        idempotency_key=body.idempotency_key,
        request=request,
    )
    audit_event(
        "billing_charge_once",
        user_sub,
        request,
        outcome="success" if resp.get("approved") else "failure",
        provider="ccbill",
        amount_cents=int(body.amount_cents),
        payment_token_id=body.payment_token_id,
        reason=body.reason,
        transaction_id=resp.get("transaction_id"),
    )
    if not resp.get("approved"):
        schedule_ccbill_dunning(
            user_sub=user_sub,
            amount_cents=int(body.amount_cents),
            reason="charge_failed",
            payment_ref=resp.get("transaction_id"),
        )
    return resp


@router.post("/api/billing/pay-balance")
async def pay_balance_endpoint(body: PayBalanceIn, request: Request, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    resp = pay_balance(
        user_sub=user_sub,
        amount_cents=body.amount_cents,
        idempotency_key=body.idempotency_key,
        request=request,
    )
    outcome = "success" if resp.get("status") not in ("failed", "no_settled_balance_due") else "failure"
    audit_event(
        "billing_pay_balance",
        user_sub,
        request,
        outcome=outcome,
        provider="ccbill",
        amount_cents=body.amount_cents,
        status=resp.get("status"),
    )
    return resp


@router.post("/api/billing/subscribe-monthly")
async def subscribe_monthly_endpoint(body: SubscribeMonthlyIn, request: Request, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    resp = subscribe_monthly(
        user_sub=user_sub,
        plan_id=body.plan_id,
        monthly_price_cents=body.monthly_price_cents,
        payment_token_id=body.payment_token_id,
        idempotency_key=body.idempotency_key,
        request=request,
    )
    audit_event(
        "billing_subscribe_monthly",
        user_sub,
        request,
        outcome="success" if resp.get("approved") else "failure",
        provider="ccbill",
        plan_id=body.plan_id,
        monthly_price_cents=body.monthly_price_cents,
        payment_token_id=body.payment_token_id,
        transaction_id=resp.get("transaction_id"),
        subscription_id=resp.get("subscription_id"),
    )
    if not resp.get("approved"):
        schedule_ccbill_dunning(
            user_sub=user_sub,
            amount_cents=int(body.monthly_price_cents or 0),
            reason="subscription_failed",
            payment_ref=resp.get("transaction_id"),
        )
    return resp


@router.post("/api/billing/refund")
def refund_payment(body: RefundIn, req: Request = None, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    pay = T.billing.get_item(Key={"user_sub": user_sub, "sk": _pay_sk(body.transaction_id)}).get("Item")
    if not pay:
        raise HTTPException(404, "Payment record not found")

    amount = int(body.amount_cents or pay.get("amount_cents", 0))
    if amount <= 0:
        raise HTTPException(400, "amount_cents must be greater than zero")

    led_sk_value, led_item = new_ledger_entry(
        user_sub=user_sub,
        entry_type="adjustment",
        amount_cents=amount,
        state="settled",
        reason="refund",
        ccbill_transaction_id=str(body.transaction_id),
        meta={"reason": body.reason},
    )
    T.billing.put_item(Item=led_item)

    if pay.get("status") in ("pending", "processing", "requires_action"):
        apply_balance_delta(user_sub, {"payments_pending_cents": -amount})
    else:
        apply_balance_delta(user_sub, {"payments_settled_cents": -amount})

    if pay.get("ledger_sk"):
        settle_or_reverse_ledger(user_sub, str(pay["ledger_sk"]), "reversed")

    update_payment_status(
        user_sub,
        str(body.transaction_id),
        "refunded",
        raw={"reason": body.reason},
    )

    purchase_txn_id = pay.get("purchase_txn_id")
    if purchase_txn_id:
        mark_reverted(user_sub, purchase_txn_id, body.reason or "refund")

    audit_event(
        "billing_refund",
        user_sub,
        req,
        outcome="success",
        provider="ccbill",
        transaction_id=str(body.transaction_id),
        amount_cents=amount,
        reason=body.reason,
    )

    return {"ok": True, "transaction_id": str(body.transaction_id), "ledger_sk": led_sk_value}


@router.post("/api/billing/_dev/add-charge")
def dev_add_charge(body: AddChargeIn, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    ensure_balance_row(user_sub)

    led_sk_value, led_item = new_ledger_entry(
        user_sub=user_sub,
        entry_type="debit",
        amount_cents=int(body.amount_cents),
        state=body.state,
        reason=body.reason,
    )
    T.billing.put_item(Item=led_item)

    if body.state == "pending":
        apply_balance_delta(user_sub, {"owed_pending_cents": int(body.amount_cents)})
    else:
        apply_balance_delta(user_sub, {"owed_settled_cents": int(body.amount_cents)})

    return {"ok": True, "ledger_sk": led_sk_value}


@router.get("/api/billing/ledger")
def list_ledger(ctx=Depends(require_ui_session), limit: int = 50):
    user_sub = ctx["user_sub"]
    led = _ledger_items(user_sub, "LEDGER#")
    led.sort(key=lambda x: x.get("ts", 0), reverse=True)
    return {"items": led[: max(1, min(limit, 200))]}


@router.get("/api/billing/payments")
def list_payments(ctx=Depends(require_ui_session), limit: int = 50):
    user_sub = ctx["user_sub"]
    pays = _ledger_items(user_sub, "PAY#")
    pays.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return {"items": pays[: max(1, min(limit, 200))]}


@router.get("/api/billing/subscriptions")
def list_subscriptions(ctx=Depends(require_ui_session), limit: int = 50):
    user_sub = ctx["user_sub"]
    subs = _ledger_items(user_sub, "SUB#")
    subs.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return {"items": subs[: max(1, min(limit, 200))]}


@router.post("/api/ccbill/webhook")
async def ccbill_webhook(req: Request):
    remote_ip = client_ip_from_request(req)
    q = dict(req.query_params)
    event_type = q.get("eventType", "")

    raw_body = await req.body()
    ct = (req.headers.get("content-type") or "").lower()
    payload: Dict[str, Any] = {}
    if "application/json" in ct:
        try:
            payload = await req.json()
        except Exception:
            payload = {}
    else:
        form = await req.form()
        payload = dict(form)

    if not webhook_remote_ip_allowed(remote_ip):
        _log_ccbill_webhook_rejection(
            reason="ip_not_allowed",
            remote_ip=remote_ip,
            event_type=event_type,
            q=q,
            payload=payload,
            req=req,
            raw_body=raw_body,
        )
        raise HTTPException(403, "Forbidden")

    signature_header = req.headers.get(S.ccbill_webhook_signature_header, "")
    if not verify_ccbill_webhook_signature(raw_body, signature_header):
        _log_ccbill_webhook_rejection(
            reason="invalid_signature",
            remote_ip=remote_ip,
            event_type=event_type,
            q=q,
            payload=payload,
            req=req,
            raw_body=raw_body,
        )
        raise HTTPException(403, "Invalid webhook signature")

    dedupe_key = hashlib.sha256((event_type + "|").encode("utf-8") + raw_body).hexdigest()
    if not mark_webhook_processed(dedupe_key):
        _log_ccbill_webhook_rejection(
            reason="replay",
            remote_ip=remote_ip,
            event_type=event_type,
            q=q,
            payload=payload,
            req=req,
            raw_body=raw_body,
            dedupe_key=dedupe_key,
        )
        return {"received": True, "deduped": True}

    user_sub = payload.get("X-app_user_id") or payload.get("X_app_user_id") or payload.get("X-user-id") or payload.get("X_user_id")
    transaction_id = payload.get("transactionId") or payload.get("transaction_id")
    subscription_id = payload.get("subscriptionId") or payload.get("subscription_id")
    plan_id = payload.get("X-plan_id") or payload.get("X_plan_id") or "monthly"
    ledger_sk_hint = payload.get("X-ledger_sk") or payload.get("X_ledger_sk")

    if not user_sub:
        safe_meta = _webhook_meta(event_type, payload, q)
        T.billing.put_item(Item={
            "user_sub": "CCBILL_WEBHOOK_UNMATCHED",
            "sk": f"{now_ts()}#{dedupe_key}",
            "eventType": event_type,
            "q": safe_meta["q"],
            "payload": safe_meta["payload"],
            "created_at": now_ts(),
        })
        return {"received": True, "unmatched": True}

    user_sub = str(user_sub)
    ensure_balance_row(user_sub)

    def _try_find_pay_and_ledger(tid: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        if not tid:
            return None, None
        pay = T.billing.get_item(Key={"user_sub": user_sub, "sk": _pay_sk(str(tid))}).get("Item")
        return pay, (pay.get("ledger_sk") if pay else None)

    if event_type == "NewSaleSuccess":
        pay, led_sk_value = _try_find_pay_and_ledger(transaction_id)
        amount = int(pay["amount_cents"]) if pay else (_dollars_str_to_cents(payload.get("initialPrice")) or S.default_monthly_price_cents)
        safe_meta = _webhook_meta(event_type, payload, q)

        led_sk_to_settle = led_sk_value
        if not led_sk_to_settle and ledger_sk_hint:
            if T.billing.get_item(Key={"user_sub": user_sub, "sk": str(ledger_sk_hint)}).get("Item"):
                led_sk_to_settle = str(ledger_sk_hint)

            if led_sk_to_settle:
                if pay and pay.get("status") in ("pending", "processing", "requires_action"):
                    apply_balance_delta(user_sub, {"payments_pending_cents": -amount, "payments_settled_cents": amount})
                settle_or_reverse_ledger(user_sub, led_sk_to_settle, "settled")
                if transaction_id:
                    update_payment_status(user_sub, str(transaction_id), "succeeded", raw=safe_meta)
        else:
            led_sk_value2, led_item = new_ledger_entry(
                user_sub=user_sub,
                entry_type="credit",
                amount_cents=amount,
                state="settled",
                reason="subscription_signup_webhook",
                ccbill_transaction_id=str(transaction_id) if transaction_id else None,
                ccbill_subscription_id=str(subscription_id) if subscription_id else None,
                meta=safe_meta,
            )
            T.billing.put_item(Item=led_item)
            apply_balance_delta(user_sub, {"payments_settled_cents": amount})
            if transaction_id:
                put_payment_record(
                    user_sub=user_sub,
                    transaction_id=str(transaction_id),
                    amount_cents=amount,
                    kind="subscription_signup",
                    status="succeeded",
                    ledger_sk_value=led_sk_value2,
                    subscription_id=str(subscription_id) if subscription_id else None,
                    raw=safe_meta,
                )

        if subscription_id:
            upsert_subscription(
                user_sub=user_sub,
                subscription_id=str(subscription_id),
                status="active",
                plan_id=plan_id,
                next_renewal_date=payload.get("nextRenewalDate"),
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw=safe_meta,
            )

    elif event_type == "NewSaleFailure":
        pay, led_sk_value = _try_find_pay_and_ledger(transaction_id)
        safe_meta = _webhook_meta(event_type, payload, q)
        if pay and led_sk_value:
            amount = int(pay.get("amount_cents", 0))
            if pay.get("status") in ("pending", "processing", "requires_action"):
                apply_balance_delta(user_sub, {"payments_pending_cents": -amount})
            settle_or_reverse_ledger(user_sub, led_sk_value, "reversed")
            update_payment_status(user_sub, str(transaction_id), "failed", raw=safe_meta)
        if subscription_id:
            upsert_subscription(user_sub=user_sub, subscription_id=str(subscription_id), status="failed", plan_id=plan_id, raw=safe_meta)
        if pay:
            schedule_ccbill_dunning(
                user_sub=user_sub,
                amount_cents=int(pay.get("amount_cents", 0)),
                reason="webhook_new_sale_failure",
                payment_ref=str(transaction_id) if transaction_id else None,
            )

    elif event_type == "RenewalSuccess":
        billed_cents = _dollars_str_to_cents(payload.get("billedAmount")) or S.default_monthly_price_cents
        safe_meta = _webhook_meta(event_type, payload, q)
        led_sk_value2, led_item = new_ledger_entry(
            user_sub=user_sub,
            entry_type="credit",
            amount_cents=billed_cents,
            state="settled",
            reason="subscription_rebill",
            ccbill_transaction_id=str(transaction_id) if transaction_id else None,
            ccbill_subscription_id=str(subscription_id) if subscription_id else None,
            meta=safe_meta,
        )
        T.billing.put_item(Item=led_item)
        apply_balance_delta(user_sub, {"payments_settled_cents": billed_cents})

        if transaction_id:
            put_payment_record(
                user_sub=user_sub,
                transaction_id=str(transaction_id),
                amount_cents=billed_cents,
                kind="subscription_rebill",
                status="succeeded",
                ledger_sk_value=led_sk_value2,
                subscription_id=str(subscription_id) if subscription_id else None,
                raw=safe_meta,
            )

        if subscription_id:
            upsert_subscription(
                user_sub=user_sub,
                subscription_id=str(subscription_id),
                status="active",
                plan_id=plan_id,
                next_renewal_date=payload.get("nextRenewalDate"),
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw=safe_meta,
            )

    elif event_type == "RenewalFailure":
        safe_meta = _webhook_meta(event_type, payload, q)
        if subscription_id:
            upsert_subscription(
                user_sub=user_sub,
                subscription_id=str(subscription_id),
                status="past_due",
                plan_id=plan_id,
                next_renewal_date=payload.get("nextRenewalDate"),
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw=safe_meta,
            )
        if transaction_id:
            schedule_ccbill_dunning(
                user_sub=user_sub,
                amount_cents=_dollars_str_to_cents(payload.get("billedAmount")) or 0,
                reason="webhook_renewal_failure",
                payment_ref=str(transaction_id),
            )

    elif event_type == "Cancellation":
        safe_meta = _webhook_meta(event_type, payload, q)
        if subscription_id:
            upsert_subscription(
                user_sub=user_sub,
                subscription_id=str(subscription_id),
                status="canceled",
                plan_id=plan_id,
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw=safe_meta,
            )

    elif event_type in ("Chargeback", "Refund", "Void", "Return"):
        amount = _dollars_str_to_cents(payload.get("billedAmount")) or 0
        safe_meta = _webhook_meta(event_type, payload, q)
        led_sk_value2, led_item = new_ledger_entry(
            user_sub=user_sub,
            entry_type="adjustment",
            amount_cents=amount,
            state="settled",
            reason=event_type.lower(),
            ccbill_transaction_id=str(transaction_id) if transaction_id else None,
            ccbill_subscription_id=str(subscription_id) if subscription_id else None,
            meta=safe_meta,
        )
        T.billing.put_item(Item=led_item)
        if amount:
            apply_balance_delta(user_sub, {"owed_settled_cents": amount})

        if transaction_id:
            pay = T.billing.get_item(Key={"user_sub": user_sub, "sk": _pay_sk(str(transaction_id))}).get("Item")
        else:
            pay = None

        if pay and pay.get("ledger_sk"):
            settle_or_reverse_ledger(user_sub, str(pay["ledger_sk"]), "reversed")
            apply_balance_delta(user_sub, {"payments_settled_cents": -amount})

        if transaction_id:
            update_payment_status(user_sub, str(transaction_id), "chargeback" if event_type == "Chargeback" else "refunded", raw=safe_meta)

        if pay and pay.get("purchase_txn_id"):
            mark_reverted(user_sub, pay["purchase_txn_id"], event_type.lower())

    else:
        safe_meta = _webhook_meta(event_type, payload, q)
        T.billing.put_item(Item={
            "user_sub": "CCBILL_WEBHOOK_OTHER",
            "sk": f"{now_ts()}#{dedupe_key}",
            "eventType": event_type,
            "q": safe_meta["q"],
            "payload": safe_meta["payload"],
            "created_at": now_ts(),
        })

    return {"received": True}


def _log_ccbill_webhook_rejection(
    *,
    reason: str,
    remote_ip: str,
    event_type: str,
    q: Dict[str, Any],
    payload: Dict[str, Any],
    req: Request,
    raw_body: bytes,
    dedupe_key: Optional[str] = None,
) -> None:
    safe_headers = {}
    for key in ("content-type", "user-agent", S.ccbill_webhook_signature_header):
        val = req.headers.get(key)
        if val:
            safe_headers[key] = "[REDACTED]" if key == S.ccbill_webhook_signature_header else val
    T.billing.put_item(Item={
        "user_sub": "CCBILL_WEBHOOK_REJECTED",
        "sk": f"{now_ts()}#{dedupe_key or hashlib.sha256(raw_body).hexdigest()}",
        "reason": reason,
        "remote_ip": remote_ip,
        "eventType": event_type,
        "q": sanitize_ccbill_payload(q),
        "payload": sanitize_ccbill_payload(payload),
        "headers": safe_headers,
        "body_sha256": hashlib.sha256(raw_body).hexdigest(),
        "created_at": now_ts(),
    })


def _current_default_pm(user_sub: str) -> Optional[str]:
    billing = T.billing.get_item(Key={"user_sub": user_sub, "sk": "BILLING"}).get("Item") or {}
    return billing.get("default_payment_token_id")


def _set_default_pm(user_sub: str, token_id: Optional[str]) -> None:
    existing = T.billing.get_item(Key={"user_sub": user_sub, "sk": "BILLING"}).get("Item")
    if not existing:
        T.billing.put_item(Item={
            "user_sub": user_sub,
            "sk": "BILLING",
            "autopay_enabled": False,
            "currency": S.default_currency,
            "default_payment_token_id": token_id,
        })
    else:
        T.billing.update_item(
            Key={"user_sub": user_sub, "sk": "BILLING"},
            UpdateExpression="SET default_payment_token_id = :t",
            ExpressionAttributeValues={":t": token_id},
        )
