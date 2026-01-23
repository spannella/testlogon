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
    subscribe_monthly,
    update_payment_status,
    upsert_subscription,
    webhook_remote_ip_allowed,
    put_payment_record,
)
from app.services.sessions import require_ui_session

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
def set_autopay(body: SetAutopayIn, ctx=Depends(require_ui_session)):
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
def save_payment_token(body: SavePaymentTokenIn, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    existing = list_payment_methods(user_sub)
    next_priority = 0 if not existing else (max(int(x.get("priority", 0)) for x in existing) + 1)

    T.billing.put_item(Item={
        "user_sub": user_sub,
        "sk": _pm_sk(body.payment_token_id),
        "payment_token_id": body.payment_token_id,
        "label": body.label,
        "priority": next_priority,
        "created_at": now_ts(),
    })

    if body.make_default or not _current_default_pm(user_sub):
        _set_default_pm(user_sub, body.payment_token_id)

    return {"ok": True}


@router.get("/api/billing/payment-methods", response_model=List[PaymentMethodOut])
def list_payment_methods_endpoint(ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    pms = list_payment_methods(user_sub)
    out: List[PaymentMethodOut] = [
        PaymentMethodOut(
            payment_token_id=it["payment_token_id"],
            label=it.get("label"),
            priority=int(it.get("priority", 0)),
        )
        for it in pms
    ]
    out.sort(key=lambda x: x.priority)
    return out


@router.post("/api/billing/payment-methods/priority")
def set_priority(body: SetPriorityIn, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    sk = _pm_sk(body.payment_token_id)
    if not T.billing.get_item(Key={"user_sub": user_sub, "sk": sk}).get("Item"):
        raise HTTPException(404, "Payment method not found")
    T.billing.update_item(
        Key={"user_sub": user_sub, "sk": sk},
        UpdateExpression="SET priority = :p",
        ExpressionAttributeValues={":p": int(body.priority)},
    )
    return {"ok": True}


@router.post("/api/billing/payment-methods/default")
def set_default(body: SetDefaultIn, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    if not T.billing.get_item(Key={"user_sub": user_sub, "sk": _pm_sk(body.payment_token_id)}).get("Item"):
        raise HTTPException(404, "Payment method not found")
    _set_default_pm(user_sub, body.payment_token_id)
    return {"ok": True}


@router.delete("/api/billing/payment-methods/{payment_token_id}")
def remove_payment_method(payment_token_id: str, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    sk = _pm_sk(payment_token_id)
    if not T.billing.get_item(Key={"user_sub": user_sub, "sk": sk}).get("Item"):
        raise HTTPException(404, "Payment method not found")

    T.billing.delete_item(Key={"user_sub": user_sub, "sk": sk})

    if _current_default_pm(user_sub) == payment_token_id:
        remaining = list_payment_methods(user_sub)
        remaining.sort(key=lambda x: int(x.get("priority", 0)))
        _set_default_pm(user_sub, remaining[0]["payment_token_id"] if remaining else None)

    return {"ok": True}


@router.post("/api/billing/charge-once")
async def charge_once_endpoint(body: OneTimeChargeIn, request: Request, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    return charge_once(
        user_sub=user_sub,
        amount_cents=body.amount_cents,
        payment_token_id=body.payment_token_id,
        reason=body.reason,
        idempotency_key=body.idempotency_key,
        request=request,
    )


@router.post("/api/billing/pay-balance")
async def pay_balance_endpoint(body: PayBalanceIn, request: Request, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    return pay_balance(
        user_sub=user_sub,
        amount_cents=body.amount_cents,
        idempotency_key=body.idempotency_key,
        request=request,
    )


@router.post("/api/billing/subscribe-monthly")
async def subscribe_monthly_endpoint(body: SubscribeMonthlyIn, request: Request, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    return subscribe_monthly(
        user_sub=user_sub,
        plan_id=body.plan_id,
        monthly_price_cents=body.monthly_price_cents,
        payment_token_id=body.payment_token_id,
        idempotency_key=body.idempotency_key,
        request=request,
    )


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
    if not webhook_remote_ip_allowed(remote_ip):
        raise HTTPException(403, "Forbidden")

    q = dict(req.query_params)
    event_type = q.get("eventType", "")

    raw_body = await req.body()
    dedupe_key = hashlib.sha256((event_type + "|").encode("utf-8") + raw_body).hexdigest()
    if not mark_webhook_processed(dedupe_key):
        return {"received": True, "deduped": True}

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

    user_sub = payload.get("X-app_user_id") or payload.get("X_app_user_id") or payload.get("X-user-id") or payload.get("X_user_id")
    transaction_id = payload.get("transactionId") or payload.get("transaction_id")
    subscription_id = payload.get("subscriptionId") or payload.get("subscription_id")
    plan_id = payload.get("X-plan_id") or payload.get("X_plan_id") or "monthly"
    ledger_sk_hint = payload.get("X-ledger_sk") or payload.get("X_ledger_sk")

    if not user_sub:
        T.billing.put_item(Item={
            "user_sub": "CCBILL_WEBHOOK_UNMATCHED",
            "sk": f"{now_ts()}#{dedupe_key}",
            "eventType": event_type,
            "q": q,
            "payload": payload,
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

        led_sk_to_settle = led_sk_value
        if not led_sk_to_settle and ledger_sk_hint:
            if T.billing.get_item(Key={"user_sub": user_sub, "sk": str(ledger_sk_hint)}).get("Item"):
                led_sk_to_settle = str(ledger_sk_hint)

        if led_sk_to_settle:
            if pay and pay.get("status") in ("pending", "processing", "requires_action"):
                apply_balance_delta(user_sub, {"payments_pending_cents": -amount, "payments_settled_cents": amount})
            settle_or_reverse_ledger(user_sub, led_sk_to_settle, "settled")
            if transaction_id:
                update_payment_status(user_sub, str(transaction_id), "succeeded", raw={"eventType": event_type, "payload": payload, "q": q})
        else:
            led_sk_value2, led_item = new_ledger_entry(
                user_sub=user_sub,
                entry_type="credit",
                amount_cents=amount,
                state="settled",
                reason="subscription_signup_webhook",
                ccbill_transaction_id=str(transaction_id) if transaction_id else None,
                ccbill_subscription_id=str(subscription_id) if subscription_id else None,
                meta={"eventType": event_type, "q": q, "payload": payload},
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
                    raw={"eventType": event_type, "payload": payload, "q": q},
                )

        if subscription_id:
            upsert_subscription(
                user_sub=user_sub,
                subscription_id=str(subscription_id),
                status="active",
                plan_id=plan_id,
                next_renewal_date=payload.get("nextRenewalDate"),
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw={"eventType": event_type, "payload": payload, "q": q},
            )

    elif event_type == "NewSaleFailure":
        pay, led_sk_value = _try_find_pay_and_ledger(transaction_id)
        if pay and led_sk_value:
            amount = int(pay.get("amount_cents", 0))
            if pay.get("status") in ("pending", "processing", "requires_action"):
                apply_balance_delta(user_sub, {"payments_pending_cents": -amount})
            settle_or_reverse_ledger(user_sub, led_sk_value, "reversed")
            update_payment_status(user_sub, str(transaction_id), "failed", raw={"eventType": event_type, "payload": payload, "q": q})
        if subscription_id:
            upsert_subscription(user_sub=user_sub, subscription_id=str(subscription_id), status="failed", plan_id=plan_id, raw={"eventType": event_type, "payload": payload, "q": q})

    elif event_type == "RenewalSuccess":
        billed_cents = _dollars_str_to_cents(payload.get("billedAmount")) or S.default_monthly_price_cents
        led_sk_value2, led_item = new_ledger_entry(
            user_sub=user_sub,
            entry_type="credit",
            amount_cents=billed_cents,
            state="settled",
            reason="subscription_rebill",
            ccbill_transaction_id=str(transaction_id) if transaction_id else None,
            ccbill_subscription_id=str(subscription_id) if subscription_id else None,
            meta={"eventType": event_type, "q": q, "payload": payload},
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
                raw={"eventType": event_type, "payload": payload, "q": q},
            )

        if subscription_id:
            upsert_subscription(
                user_sub=user_sub,
                subscription_id=str(subscription_id),
                status="active",
                plan_id=plan_id,
                next_renewal_date=payload.get("nextRenewalDate"),
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw={"eventType": event_type, "payload": payload, "q": q},
            )

    elif event_type == "RenewalFailure":
        if subscription_id:
            upsert_subscription(
                user_sub=user_sub,
                subscription_id=str(subscription_id),
                status="past_due",
                plan_id=plan_id,
                next_renewal_date=payload.get("nextRenewalDate"),
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw={"eventType": event_type, "payload": payload, "q": q},
            )

    elif event_type == "Cancellation":
        if subscription_id:
            upsert_subscription(
                user_sub=user_sub,
                subscription_id=str(subscription_id),
                status="canceled",
                plan_id=plan_id,
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw={"eventType": event_type, "payload": payload, "q": q},
            )

    elif event_type in ("Chargeback", "Refund", "Void", "Return"):
        amount = _dollars_str_to_cents(payload.get("billedAmount")) or 0
        led_sk_value2, led_item = new_ledger_entry(
            user_sub=user_sub,
            entry_type="adjustment",
            amount_cents=amount,
            state="settled",
            reason=event_type.lower(),
            ccbill_transaction_id=str(transaction_id) if transaction_id else None,
            ccbill_subscription_id=str(subscription_id) if subscription_id else None,
            meta={"eventType": event_type, "q": q, "payload": payload},
        )
        T.billing.put_item(Item=led_item)
        if amount:
            apply_balance_delta(user_sub, {"owed_settled_cents": amount})

    else:
        T.billing.put_item(Item={
            "user_sub": "CCBILL_WEBHOOK_OTHER",
            "sk": f"{now_ts()}#{dedupe_key}",
            "eventType": event_type,
            "q": q,
            "payload": payload,
            "created_at": now_ts(),
        })

    return {"received": True}


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
