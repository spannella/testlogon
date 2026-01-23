from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import stripe
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    AddChargeReq,
    BillingCheckoutReq,
    PaymentMethodOut,
    PayBalanceReq,
    SetAutopayReq,
    SetDefaultReq,
    SetPriorityReq,
    VerifyMicrodepositsReq,
)
from app.services.sessions import require_ui_session
from app.services.ttl import with_ttl

router = APIRouter(tags=["billing"])


def ensure_stripe_configured() -> None:
    if not S.stripe_secret_key:
        raise HTTPException(501, "Stripe is not configured")
    stripe.api_key = S.stripe_secret_key


def build_return_url(req: Request, fallback_query: str) -> str:
    if fallback_query.startswith("/"):
        return urljoin(str(req.base_url), fallback_query.lstrip("/"))
    return urljoin(str(req.base_url), fallback_query)


def user_pk(user_id: str) -> str:
    return f"USER#{user_id}"


def ulidish() -> str:
    return f"{int(now_ts() * 1000)}_{secrets.token_hex(8)}"


def ddb_get(pk: str, sk: str) -> Optional[Dict[str, Any]]:
    resp = T.billing.get_item(Key={"pk": pk, "sk": sk})
    return resp.get("Item")


def ddb_put(item: Dict[str, Any], *, condition_expression: Optional[str] = None) -> None:
    kwargs: Dict[str, Any] = {"Item": item}
    if condition_expression:
        kwargs["ConditionExpression"] = condition_expression
    T.billing.put_item(**kwargs)


def ddb_del(pk: str, sk: str) -> None:
    T.billing.delete_item(Key={"pk": pk, "sk": sk})


def ddb_query_pk(pk: str) -> List[Dict[str, Any]]:
    resp = T.billing.query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": pk},
    )
    return resp.get("Items", [])


def ddb_update(pk: str, sk: str, expr: str, values: Dict[str, Any], names: Optional[Dict[str, str]] = None) -> None:
    kwargs: Dict[str, Any] = {
        "Key": {"pk": pk, "sk": sk},
        "UpdateExpression": expr,
        "ExpressionAttributeValues": values,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    T.billing.update_item(**kwargs)


def get_or_create_customer(user_id: str) -> str:
    pk = user_pk(user_id)
    prof = ddb_get(pk, "PROFILE")
    if prof and prof.get("stripe_customer_id"):
        return prof["stripe_customer_id"]

    cust = stripe.Customer.create(metadata={"app_user_id": user_id})
    ddb_put({"pk": pk, "sk": "PROFILE", "stripe_customer_id": cust["id"], "created_at": now_ts()})
    return cust["id"]


def user_id_from_customer(customer_id: str) -> Optional[str]:
    try:
        cust = stripe.Customer.retrieve(customer_id)
        return cust.get("metadata", {}).get("app_user_id")
    except Exception:
        return None


BAL_FIELDS = [
    "owed_pending_cents",
    "owed_settled_cents",
    "payments_pending_cents",
    "payments_settled_cents",
]


def ensure_balance_row(pk: str) -> None:
    if not ddb_get(pk, "BALANCE"):
        ddb_put({
            "pk": pk,
            "sk": "BALANCE",
            "currency": "usd",
            **{k: 0 for k in BAL_FIELDS},
            "updated_at": now_ts(),
        })


def apply_balance_delta(pk: str, delta: Dict[str, int]) -> None:
    ensure_balance_row(pk)

    sets = []
    values: Dict[str, Any] = {":z": 0, ":t": now_ts()}
    names: Dict[str, str] = {}

    i = 0
    for key, value in delta.items():
        if value == 0:
            continue
        i += 1
        nk = f"#k{i}"
        dv = f":d{i}"
        names[nk] = key
        values[dv] = int(value)
        sets.append(f"{nk} = if_not_exists({nk}, :z) + {dv}")

    names["#u"] = "updated_at"
    sets.append("#u = :t")

    expr = "SET " + ", ".join(sets)
    ddb_update(pk, "BALANCE", expr, values, names=names)


def compute_due(balance_item: Dict[str, Any]) -> Dict[str, int]:
    owed_settled = int(balance_item.get("owed_settled_cents", 0))
    owed_pending = int(balance_item.get("owed_pending_cents", 0))
    pay_settled = int(balance_item.get("payments_settled_cents", 0))
    pay_pending = int(balance_item.get("payments_pending_cents", 0))

    due_settled = owed_settled - pay_settled
    due_if_all_settles = (owed_settled + owed_pending) - (pay_settled + pay_pending)

    return {
        "due_settled_cents": due_settled,
        "due_if_all_settles_cents": due_if_all_settles,
    }


def ledger_sk(ts: int, entry_id: str) -> str:
    return f"LEDGER#{ts}#{entry_id}"


def new_ledger_entry(
    user_id: str,
    entry_type: str,
    amount_cents: int,
    state: str,
    reason: str,
    stripe_payment_intent_id: Optional[str] = None,
    stripe_charge_id: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Dict[str, Any]]:
    ts = now_ts()
    entry_id = ulidish()
    sk = ledger_sk(ts, entry_id)
    item = {
        "pk": user_pk(user_id),
        "sk": sk,
        "entry_id": entry_id,
        "ts": ts,
        "type": entry_type,
        "amount_cents": int(amount_cents),
        "state": state,
        "reason": reason,
    }
    if stripe_payment_intent_id:
        item["stripe_payment_intent_id"] = stripe_payment_intent_id
    if stripe_charge_id:
        item["stripe_charge_id"] = stripe_charge_id
    if meta:
        item["meta"] = meta
    return sk, item


def settle_or_reverse_ledger(user_id: str, ledger_sk_value: str, new_state: str) -> None:
    pk = user_pk(user_id)
    ddb_update(pk, ledger_sk_value, "SET #s = :s", {":s": new_state}, names={"#s": "state"})


def pay_sk(payment_intent_id: str) -> str:
    return f"PAY#{payment_intent_id}"


def put_payment_record(
    user_id: str,
    pi: Dict[str, Any],
    ledger_sk_value: str,
    payment_method_type: str,
) -> None:
    pk = user_pk(user_id)
    item = {
        "pk": pk,
        "sk": pay_sk(pi["id"]),
        "payment_intent_id": pi["id"],
        "status": pi.get("status"),
        "amount_cents": int(pi.get("amount", 0)),
        "currency": pi.get("currency", "usd"),
        "customer_id": pi.get("customer"),
        "payment_method_id": pi.get("payment_method"),
        "payment_method_type": payment_method_type,
        "ledger_sk": ledger_sk_value,
        "created_at": now_ts(),
        "updated_at": now_ts(),
    }
    ddb_put(item)


def update_payment_status(
    user_id: str,
    pi_id: str,
    status: str,
    charge_id: Optional[str] = None,
    last_error: Optional[Dict[str, Any]] = None,
) -> None:
    pk = user_pk(user_id)
    names = {"#st": "status", "#u": "updated_at"}
    values: Dict[str, Any] = {":st": status, ":u": now_ts()}
    sets = ["#st = :st", "#u = :u"]

    if charge_id is not None:
        names["#ch"] = "charge_id"
        values[":ch"] = charge_id
        sets.append("#ch = :ch")

    if last_error is not None:
        names["#le"] = "last_error"
        values[":le"] = last_error
        sets.append("#le = :le")

    ddb_update(pk, pay_sk(pi_id), "SET " + ", ".join(sets), values, names=names)


def pm_sk(payment_method_id: str) -> str:
    return f"PM#{payment_method_id}"


def list_payment_methods_ddb(user_id: str) -> List[Dict[str, Any]]:
    items = ddb_query_pk(user_pk(user_id))
    return [it for it in items if it["sk"].startswith("PM#")]


def current_default_pm(user_id: str) -> Optional[str]:
    billing = ddb_get(user_pk(user_id), "BILLING") or {}
    return billing.get("default_payment_method_id")


def set_default_pm(user_id: str, pm_id: Optional[str]) -> None:
    pk = user_pk(user_id)
    if not ddb_get(pk, "BILLING"):
        ddb_put({"pk": pk, "sk": "BILLING", "autopay_enabled": False, "currency": "usd", "default_payment_method_id": pm_id})
    else:
        ddb_update(pk, "BILLING", "SET default_payment_method_id = :pm", {":pm": pm_id})


def mark_event_processed(event_id: str) -> bool:
    try:
        ddb_put(
            with_ttl(
                {"pk": "STRIPE_EVENT", "sk": event_id, "ts": now_ts()},
                ttl_epoch=now_ts() + 60 * 60 * 24 * 7,
            ),
            condition_expression="attribute_not_exists(pk)",
        )
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


@router.get("/api/billing/config")
@router.get("/ui/billing/config")
def billing_config() -> Dict[str, str]:
    if not S.stripe_publishable_key:
        raise HTTPException(500, "Missing STRIPE_PUBLISHABLE_KEY")
    return {
        "publishable_key": S.stripe_publishable_key,
        "currency": S.stripe_default_currency,
    }


@router.get("/api/billing/settings")
@router.get("/ui/billing/settings")
def get_settings(ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    user_id = ctx["user_sub"]
    pk = user_pk(user_id)
    settings = ddb_get(pk, "BILLING") or {"autopay_enabled": False, "currency": "usd", "default_payment_method_id": None}
    return settings


@router.post("/api/billing/autopay")
@router.post("/ui/billing/autopay")
def set_autopay(body: SetAutopayReq, ctx=Depends(require_ui_session)) -> Dict[str, bool]:
    user_id = ctx["user_sub"]
    pk = user_pk(user_id)
    if not ddb_get(pk, "BILLING"):
        ddb_put({"pk": pk, "sk": "BILLING", "autopay_enabled": False, "currency": "usd", "default_payment_method_id": None})
    ddb_update(pk, "BILLING", "SET autopay_enabled = :e", {":e": bool(body.enabled)})
    return {"ok": True}


@router.get("/api/billing/balance")
@router.get("/ui/billing/balance")
def get_balance(ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    user_id = ctx["user_sub"]
    pk = user_pk(user_id)
    ensure_balance_row(pk)
    bal = ddb_get(pk, "BALANCE") or {}
    due = compute_due(bal)
    return {
        "currency": bal.get("currency", "usd"),
        "owed_pending_cents": int(bal.get("owed_pending_cents", 0)),
        "owed_settled_cents": int(bal.get("owed_settled_cents", 0)),
        "payments_pending_cents": int(bal.get("payments_pending_cents", 0)),
        "payments_settled_cents": int(bal.get("payments_settled_cents", 0)),
        **due,
        "updated_at": bal.get("updated_at"),
    }


@router.post("/api/billing/setup-intent/card")
@router.post("/ui/billing/setup-intent/card")
def create_card_setup_intent(ctx=Depends(require_ui_session)) -> Dict[str, str]:
    ensure_stripe_configured()
    user_id = ctx["user_sub"]
    customer_id = get_or_create_customer(user_id)
    si = stripe.SetupIntent.create(
        customer=customer_id,
        payment_method_types=["card"],
        usage="off_session",
    )
    return {"client_secret": si["client_secret"]}


@router.post("/api/billing/setup-intent/us-bank")
@router.post("/ui/billing/setup-intent/us-bank")
def create_us_bank_setup_intent(ctx=Depends(require_ui_session)) -> Dict[str, str]:
    ensure_stripe_configured()
    user_id = ctx["user_sub"]
    customer_id = get_or_create_customer(user_id)
    si = stripe.SetupIntent.create(
        customer=customer_id,
        payment_method_types=["us_bank_account"],
        usage="off_session",
    )
    return {"client_secret": si["client_secret"]}


@router.post("/api/billing/us-bank/verify-microdeposits")
@router.post("/ui/billing/us-bank/verify-microdeposits")
def verify_microdeposits(body: VerifyMicrodepositsReq, ctx=Depends(require_ui_session)) -> Dict[str, str]:
    ensure_stripe_configured()
    if not body.amounts and not body.descriptor_code:
        raise HTTPException(400, "Provide amounts or descriptor_code")
    si = stripe.SetupIntent.verify_microdeposits(
        body.setup_intent_id,
        amounts=body.amounts,
        descriptor_code=body.descriptor_code,
    )
    return {"status": si["status"]}


@router.get("/api/billing/payment-methods", response_model=List[PaymentMethodOut])
@router.get("/ui/billing/payment-methods", response_model=List[PaymentMethodOut])
def list_payment_methods(ctx=Depends(require_ui_session)) -> List[PaymentMethodOut]:
    user_id = ctx["user_sub"]
    pms = list_payment_methods_ddb(user_id)

    out: List[PaymentMethodOut] = []
    for it in pms:
        out.append(PaymentMethodOut(
            payment_method_id=it["payment_method_id"],
            method_type=it.get("method_type", "unknown"),
            label=it.get("label"),
            brand=it.get("brand"),
            last4=it.get("last4"),
            exp_month=it.get("exp_month"),
            exp_year=it.get("exp_year"),
            priority=int(it.get("priority", 0)),
        ))
    out.sort(key=lambda x: x.priority)
    return out


@router.post("/api/billing/payment-methods/priority")
@router.post("/ui/billing/payment-methods/priority")
def set_priority(body: SetPriorityReq, ctx=Depends(require_ui_session)) -> Dict[str, bool]:
    user_id = ctx["user_sub"]
    pk = user_pk(user_id)
    sk = pm_sk(body.payment_method_id)
    if not ddb_get(pk, sk):
        raise HTTPException(404, "Payment method not found")
    ddb_update(pk, sk, "SET priority = :p", {":p": int(body.priority)})
    return {"ok": True}


@router.post("/api/billing/payment-methods/default")
@router.post("/ui/billing/payment-methods/default")
def set_default(body: SetDefaultReq, ctx=Depends(require_ui_session)) -> Dict[str, bool]:
    ensure_stripe_configured()
    user_id = ctx["user_sub"]
    pk = user_pk(user_id)
    if not ddb_get(pk, pm_sk(body.payment_method_id)):
        raise HTTPException(404, "Payment method not found")

    customer_id = get_or_create_customer(user_id)
    set_default_pm(user_id, body.payment_method_id)
    stripe.Customer.modify(customer_id, invoice_settings={"default_payment_method": body.payment_method_id})
    return {"ok": True}


@router.delete("/api/billing/payment-methods/{payment_method_id}")
@router.delete("/ui/billing/payment-methods/{payment_method_id}")
def remove_payment_method(payment_method_id: str, ctx=Depends(require_ui_session)) -> Dict[str, bool]:
    ensure_stripe_configured()
    user_id = ctx["user_sub"]
    pk = user_pk(user_id)
    sk = pm_sk(payment_method_id)
    if not ddb_get(pk, sk):
        raise HTTPException(404, "Payment method not found")

    try:
        stripe.PaymentMethod.detach(payment_method_id)
    except Exception:
        pass

    ddb_del(pk, sk)

    if current_default_pm(user_id) == payment_method_id:
        remaining = list_payment_methods_ddb(user_id)
        remaining.sort(key=lambda x: int(x.get("priority", 0)))
        new_default = remaining[0]["payment_method_id"] if remaining else None
        set_default_pm(user_id, new_default)

        customer_id = get_or_create_customer(user_id)
        stripe.Customer.modify(customer_id, invoice_settings={"default_payment_method": new_default})

    return {"ok": True}


@router.post("/api/billing/pay-balance")
@router.post("/ui/billing/pay-balance")
def pay_balance(body: PayBalanceReq, ctx=Depends(require_ui_session)) -> Dict[str, str]:
    ensure_stripe_configured()
    user_id = ctx["user_sub"]
    pk = user_pk(user_id)

    ensure_balance_row(pk)
    bal = ddb_get(pk, "BALANCE") or {}
    due = compute_due(bal)["due_settled_cents"]
    if due <= 0:
        return {"status": "no_settled_balance_due"}

    amount = due if body.amount_cents is None else min(int(body.amount_cents), due)
    if amount <= 0:
        return {"status": "no_settled_balance_due"}

    billing = ddb_get(pk, "BILLING") or {"currency": "usd", "default_payment_method_id": None}
    default_pm = billing.get("default_payment_method_id")
    if not default_pm:
        raise HTTPException(400, "No default payment method set")

    customer_id = get_or_create_customer(user_id)
    idem = body.idempotency_key or f"paybalance:{user_id}:{amount}:{int(now_ts()/30)}"
    try:
        pi = stripe.PaymentIntent.create(
            amount=amount,
            currency=billing.get("currency", "usd"),
            customer=customer_id,
            payment_method=default_pm,
            off_session=True,
            confirm=True,
            description=f"Pay settled balance for {user_id}",
            metadata={"app_user_id": user_id, "purpose": "pay_balance"},
            idempotency_key=idem,
        )
    except stripe.error.CardError as exc:
        return {"status": "failed", "reason": str(exc)}

    pm_type = "unknown"
    try:
        pm_obj = stripe.PaymentMethod.retrieve(default_pm)
        pm_type = pm_obj.get("type", "unknown")
    except Exception:
        pass

    led_sk, led_item = new_ledger_entry(
        user_id=user_id,
        entry_type="credit",
        amount_cents=amount,
        state="pending" if pi.get("status") in ("processing", "requires_action") else ("settled" if pi.get("status") == "succeeded" else "pending"),
        reason="payment",
        stripe_payment_intent_id=pi["id"],
        meta={"idempotency_key": idem},
    )
    ddb_put(led_item)

    if pi.get("status") == "succeeded":
        apply_balance_delta(pk, {"payments_settled_cents": amount})
        settle_or_reverse_ledger(user_id, led_sk, "settled")
    else:
        apply_balance_delta(pk, {"payments_pending_cents": amount})

    put_payment_record(user_id, pi, led_sk, payment_method_type=pm_type)

    return {"status": pi.get("status"), "payment_intent_id": pi["id"]}


@router.post("/api/billing/checkout_session")
@router.post("/ui/billing/checkout_session")
def create_checkout_session(body: BillingCheckoutReq, req: Request, ctx=Depends(require_ui_session)) -> Dict[str, str]:
    ensure_stripe_configured()
    if body.amount_cents <= 0:
        raise HTTPException(400, "amount_cents must be greater than zero")
    currency = (body.currency or S.stripe_default_currency or "usd").lower()
    description = body.description or "Security Control Panel charge"

    success_url = S.stripe_success_url or build_return_url(req, "?stripe=success")
    cancel_url = S.stripe_cancel_url or build_return_url(req, "?stripe=cancel")

    session = stripe.checkout.Session.create(
        mode="payment",
        success_url=success_url,
        cancel_url=cancel_url,
        client_reference_id=ctx["user_sub"],
        line_items=[
            {
                "quantity": 1,
                "price_data": {
                    "currency": currency,
                    "unit_amount": body.amount_cents,
                    "product_data": {"name": description},
                },
            }
        ],
        metadata={"user_sub": ctx["user_sub"]},
    )
    return {"session_id": session.id, "url": session.url}


@router.post("/api/stripe/webhook")
async def stripe_webhook(req: Request) -> Dict[str, Any]:
    ensure_stripe_configured()
    if not S.stripe_webhook_secret:
        raise HTTPException(501, "Stripe webhook secret not configured")

    payload = await req.body()
    sig = req.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig, secret=S.stripe_webhook_secret)
    except Exception as exc:
        raise HTTPException(400, f"Webhook error: {exc}") from exc

    if not mark_event_processed(event["id"]):
        return {"received": True, "deduped": True}

    event_type = event["type"]

    if event_type == "setup_intent.succeeded":
        si = event["data"]["object"]
        customer_id = si.get("customer")
        pm_id = si.get("payment_method")
        if not customer_id or not pm_id:
            return {"received": True}

        user_id = user_id_from_customer(customer_id)
        if not user_id:
            return {"received": True}

        try:
            stripe.PaymentMethod.attach(pm_id, customer=customer_id)
        except Exception:
            pass

        pm = stripe.PaymentMethod.retrieve(pm_id)
        pm_type = pm.get("type", "unknown")

        brand = last4 = None
        exp_month = exp_year = None
        label = None

        if pm_type == "card":
            card = pm.get("card", {}) or {}
            brand = card.get("brand")
            last4 = card.get("last4")
            exp_month = card.get("exp_month")
            exp_year = card.get("exp_year")
            label = f"{brand} ****{last4}"
        elif pm_type == "us_bank_account":
            uba = pm.get("us_bank_account", {}) or {}
            last4 = uba.get("last4")
            bank_name = uba.get("bank_name")
            label = f"{bank_name or 'Bank'} ****{last4}"

        pk = user_pk(user_id)
        existing = list_payment_methods_ddb(user_id)
        next_priority = 0 if not existing else (max(int(x.get("priority", 0)) for x in existing) + 1)

        ddb_put({
            "pk": pk,
            "sk": pm_sk(pm_id),
            "payment_method_id": pm_id,
            "method_type": pm_type,
            "label": label,
            "brand": brand,
            "last4": last4,
            "exp_month": exp_month,
            "exp_year": exp_year,
            "priority": next_priority,
            "created_at": now_ts(),
        })

        if not current_default_pm(user_id):
            set_default_pm(user_id, pm_id)
            stripe.Customer.modify(customer_id, invoice_settings={"default_payment_method": pm_id})

    elif event_type.startswith("payment_intent."):
        pi = event["data"]["object"]
        pi_id = pi["id"]
        status = pi.get("status")

        user_id = None
        md = pi.get("metadata", {}) or {}
        if md.get("app_user_id"):
            user_id = md["app_user_id"]
        elif pi.get("customer"):
            user_id = user_id_from_customer(pi["customer"])

        if not user_id:
            return {"received": True}

        pk = user_pk(user_id)
        pay = ddb_get(pk, pay_sk(pi_id))
        if not pay:
            return {"received": True}

        amount = int(pay.get("amount_cents", 0))
        led_sk_value = pay.get("ledger_sk")

        charge_id = None
        try:
            charges = (pi.get("charges") or {}).get("data") or []
            if charges:
                charge_id = charges[0].get("id")
        except Exception:
            pass

        if status == "processing":
            update_payment_status(user_id, pi_id, "processing", charge_id=charge_id)

        elif status == "succeeded":
            update_payment_status(user_id, pi_id, "succeeded", charge_id=charge_id)
            if pay.get("status") in ("processing", "requires_action"):
                apply_balance_delta(pk, {"payments_pending_cents": -amount, "payments_settled_cents": amount})
            if led_sk_value:
                settle_or_reverse_ledger(user_id, led_sk_value, "settled")

        elif status in ("requires_payment_method", "canceled"):
            update_payment_status(user_id, pi_id, status, charge_id=charge_id, last_error=pi.get("last_payment_error"))
            if pay.get("status") in ("processing", "requires_action"):
                apply_balance_delta(pk, {"payments_pending_cents": -amount})
            elif pay.get("status") == "succeeded":
                apply_balance_delta(pk, {"payments_settled_cents": -amount})
            if led_sk_value:
                settle_or_reverse_ledger(user_id, led_sk_value, "reversed")

        elif status == "payment_failed":
            update_payment_status(user_id, pi_id, "payment_failed", charge_id=charge_id, last_error=pi.get("last_payment_error"))
            if pay.get("status") in ("processing", "requires_action"):
                apply_balance_delta(pk, {"payments_pending_cents": -amount})
            elif pay.get("status") == "succeeded":
                apply_balance_delta(pk, {"payments_settled_cents": -amount})
            if led_sk_value:
                settle_or_reverse_ledger(user_id, led_sk_value, "reversed")

        else:
            update_payment_status(user_id, pi_id, status, charge_id=charge_id)

    elif event_type.startswith("charge.dispute."):
        dispute = event["data"]["object"]
        charge_id = dispute.get("charge")
        amount = int(dispute.get("amount", 0))
        currency = dispute.get("currency", "usd")

        pi_id = None
        user_id = None
        try:
            ch = stripe.Charge.retrieve(charge_id)
            pi_id = ch.get("payment_intent")
            customer_id = ch.get("customer")
            if customer_id:
                user_id = user_id_from_customer(customer_id)
            if not user_id and pi_id:
                pi = stripe.PaymentIntent.retrieve(pi_id)
                user_id = (pi.get("metadata") or {}).get("app_user_id") or user_id
        except Exception:
            pass

        if not user_id:
            return {"received": True}

        pk = user_pk(user_id)
        ensure_balance_row(pk)

        if event_type == "charge.dispute.funds_withdrawn":
            led_sk_value, led_item = new_ledger_entry(
                user_id=user_id,
                entry_type="adjustment",
                amount_cents=amount,
                state="settled",
                reason="dispute_funds_withdrawn",
                stripe_charge_id=charge_id,
                stripe_payment_intent_id=pi_id,
                meta={"currency": currency, "dispute_id": dispute.get("id")},
            )
            ddb_put(led_item)
            apply_balance_delta(pk, {"owed_settled_cents": amount})

        elif event_type == "charge.dispute.funds_reinstated":
            led_sk_value, led_item = new_ledger_entry(
                user_id=user_id,
                entry_type="adjustment",
                amount_cents=amount,
                state="settled",
                reason="dispute_funds_reinstated",
                stripe_charge_id=charge_id,
                stripe_payment_intent_id=pi_id,
                meta={"currency": currency, "dispute_id": dispute.get("id")},
            )
            ddb_put(led_item)
            apply_balance_delta(pk, {"owed_settled_cents": -amount})

    return {"received": True}


@router.post("/api/billing/_dev/add-charge")
@router.post("/ui/billing/_dev/add-charge")
def dev_add_charge(body: AddChargeReq, ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    user_id = ctx["user_sub"]
    pk = user_pk(user_id)
    ensure_balance_row(pk)

    led_sk_value, led_item = new_ledger_entry(
        user_id=user_id,
        entry_type="debit",
        amount_cents=int(body.amount_cents),
        state=body.state,
        reason=body.reason,
    )
    ddb_put(led_item)

    if body.state == "pending":
        apply_balance_delta(pk, {"owed_pending_cents": int(body.amount_cents)})
    else:
        apply_balance_delta(pk, {"owed_settled_cents": int(body.amount_cents)})

    return {"ok": True, "ledger_sk": led_sk_value}


@router.get("/api/billing/ledger")
@router.get("/ui/billing/ledger")
def list_ledger(ctx=Depends(require_ui_session), limit: int = 50) -> Dict[str, Any]:
    user_id = ctx["user_sub"]
    items = ddb_query_pk(user_pk(user_id))
    led = [it for it in items if it["sk"].startswith("LEDGER#")]
    led.sort(key=lambda x: x.get("ts", 0), reverse=True)
    return {"items": led[: max(1, min(limit, 200))]}
