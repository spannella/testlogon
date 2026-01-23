from __future__ import annotations

import hashlib
import json
import secrets
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Tuple

import requests
from botocore.exceptions import ClientError
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import (
    apply_balance_delta as apply_balance_delta_shared,
    compute_due,
    ddb_del as ddb_del_shared,
    ddb_get as ddb_get_shared,
    ddb_put as ddb_put_shared,
    ddb_query_pk as ddb_query_pk_shared,
    ddb_update as ddb_update_shared,
    ensure_balance_row as ensure_balance_row_shared,
    user_pk,
)

router = APIRouter(tags=["billing"])

DEFAULT_MONTHLY_PRICE_CENTS = S.default_monthly_price_cents
DEFAULT_CURRENCY = S.default_currency
DEFAULT_CURRENCY_CODE = DEFAULT_CURRENCY.upper()

PUBLIC_BASE_URL = (S.public_base_url or "http://localhost:8000").rstrip("/")
PAYPAL_ENV = (S.paypal_env or "sandbox").lower()
PAYPAL_BASE_URL = "https://api-m.sandbox.paypal.com" if PAYPAL_ENV == "sandbox" else "https://api-m.paypal.com"

PAYPAL_PLAN_MAP: Dict[str, str] = {}
if S.paypal_plan_map.strip():
    for part in S.paypal_plan_map.split(","):
        if ":" in part:
            key, value = part.split(":", 1)
            PAYPAL_PLAN_MAP[key.strip()] = value.strip()


# ============================================================
# Helpers
# ============================================================

def _billing_table():
    billing_table_name = getattr(S, "billing_table_name", None)
    if billing_table_name is None:
        return T.billing
    if not billing_table_name:
        raise HTTPException(500, "Billing table not configured (set BILLING_TABLE_NAME)")
    return T.billing


def _require_paypal_config() -> None:
    if not S.paypal_client_id or not S.paypal_client_secret:
        raise HTTPException(500, "PayPal not configured (set PAYPAL_CLIENT_ID/PAYPAL_CLIENT_SECRET)")


def ulidish() -> str:
    return f"{int(now_ts() * 1000)}_{secrets.token_hex(8)}"


def _money_value_from_cents(cents: int) -> str:
    d = (Decimal(int(cents)) / Decimal(100)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return f"{d:.2f}"


# ---------- DynamoDB wrappers ----------

def ddb_get(pk: str, sk: str) -> Optional[Dict[str, Any]]:
    return ddb_get_shared(_billing_table(), pk, sk)


def ddb_put(item: Dict[str, Any], *, condition_expression: Optional[str] = None) -> None:
    ddb_put_shared(_billing_table(), item, condition_expression=condition_expression)


def ddb_del(pk: str, sk: str) -> None:
    ddb_del_shared(_billing_table(), pk, sk)


def ddb_query_pk(pk: str) -> List[Dict[str, Any]]:
    return ddb_query_pk_shared(_billing_table(), pk)


def ddb_update(pk: str, sk: str, expr: str, values: Dict[str, Any], names: Optional[Dict[str, str]] = None) -> None:
    ddb_update_shared(_billing_table(), pk, sk, expr, values, names=names)


def ensure_balance_row(pk: str) -> None:
    ensure_balance_row_shared(_billing_table(), pk, DEFAULT_CURRENCY)


def apply_balance_delta(pk: str, delta: Dict[str, int]) -> None:
    apply_balance_delta_shared(_billing_table(), pk, delta, currency=DEFAULT_CURRENCY)

# ---------- Auth assumption ----------

def require_user(x_user_id: Optional[str]) -> str:
    if not x_user_id:
        raise HTTPException(401, "Missing X-User-Id (login assumed handled)")
    return x_user_id


# ============================================================
# Ledger
# ============================================================

def ledger_sk(ts: int, entry_id: str) -> str:
    return f"LEDGER#{ts}#{entry_id}"


def new_ledger_entry(
    user_id: str,
    entry_type: str,
    amount_cents: int,
    state: str,
    reason: str,
    paypal_payment_token_id: Optional[str] = None,
    paypal_order_id: Optional[str] = None,
    paypal_capture_id: Optional[str] = None,
    paypal_subscription_id: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Dict[str, Any]]:
    ts = now_ts()
    eid = ulidish()
    sk = ledger_sk(ts, eid)
    item = {
        "pk": user_pk(user_id),
        "sk": sk,
        "entry_id": eid,
        "ts": ts,
        "type": entry_type,
        "amount_cents": int(amount_cents),
        "state": state,
        "reason": reason,
    }
    if paypal_payment_token_id:
        item["paypal_payment_token_id"] = paypal_payment_token_id
    if paypal_order_id:
        item["paypal_order_id"] = paypal_order_id
    if paypal_capture_id:
        item["paypal_capture_id"] = paypal_capture_id
    if paypal_subscription_id:
        item["paypal_subscription_id"] = paypal_subscription_id
    if meta:
        item["meta"] = meta
    return sk, item


def settle_or_reverse_ledger(user_id: str, ledger_sk_value: str, new_state: str) -> None:
    ddb_update(user_pk(user_id), ledger_sk_value, "SET #s = :s", {":s": new_state}, names={"#s": "state"})


# ============================================================
# Payment + Subscription records
# ============================================================

def pay_sk(external_id: str) -> str:
    return f"PAY#{external_id}"


def sub_sk(subscription_id: str) -> str:
    return f"SUB#{subscription_id}"


def put_payment_record(
    user_id: str,
    external_id: str,
    amount_cents: int,
    kind: str,
    status: str,
    ledger_sk_value: Optional[str],
    payment_token_id: Optional[str] = None,
    subscription_id: Optional[str] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> None:
    pk = user_pk(user_id)
    item = {
        "pk": pk,
        "sk": pay_sk(external_id),
        "external_id": external_id,
        "kind": kind,
        "status": status,
        "amount_cents": int(amount_cents),
        "currency": DEFAULT_CURRENCY,
        "payment_token_id": payment_token_id,
        "subscription_id": subscription_id,
        "ledger_sk": ledger_sk_value,
        "created_at": now_ts(),
        "updated_at": now_ts(),
    }
    if raw:
        item["raw"] = raw
    ddb_put(item)


def update_payment_status(user_id: str, external_id: str, status: str, raw: Optional[Dict[str, Any]] = None) -> None:
    pk = user_pk(user_id)
    names = {"#st": "status", "#u": "updated_at"}
    values: Dict[str, Any] = {":st": status, ":u": now_ts()}
    sets = ["#st = :st", "#u = :u"]
    if raw is not None:
        names["#r"] = "raw"
        values[":r"] = raw
        sets.append("#r = :r")
    ddb_update(pk, pay_sk(external_id), "SET " + ", ".join(sets), values, names=names)


def upsert_subscription(
    user_id: str,
    subscription_id: str,
    *,
    status: str,
    plan_id: str,
    payment_token_id: Optional[str] = None,
    next_renewal_time: Optional[str] = None,
    last_external_id: Optional[str] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> None:
    pk = user_pk(user_id)
    sk = sub_sk(subscription_id)
    existing = ddb_get(pk, sk)
    item = existing or {
        "pk": pk,
        "sk": sk,
        "subscription_id": subscription_id,
        "created_at": now_ts(),
    }
    item["status"] = status
    item["plan_id"] = plan_id
    item["updated_at"] = now_ts()
    if payment_token_id:
        item["payment_token_id"] = payment_token_id
    if next_renewal_time:
        item["next_renewal_time"] = next_renewal_time
    if last_external_id:
        item["last_external_id"] = last_external_id
    if raw:
        item["raw"] = raw
    ddb_put(item)


# ============================================================
# Payment methods (store PayPal payment token IDs)
# ============================================================

def pm_sk(payment_token_id: str) -> str:
    return f"PM#{payment_token_id}"


def list_payment_methods_ddb(user_id: str) -> List[Dict[str, Any]]:
    items = ddb_query_pk(user_pk(user_id))
    return [it for it in items if it["sk"].startswith("PM#")]


def current_default_pm(user_id: str) -> Optional[str]:
    billing = ddb_get(user_pk(user_id), "BILLING") or {}
    return billing.get("default_payment_token_id")


def set_default_pm(user_id: str, token_id: Optional[str]) -> None:
    pk = user_pk(user_id)
    if not ddb_get(pk, "BILLING"):
        ddb_put(
            {
                "pk": pk,
                "sk": "BILLING",
                "autopay_enabled": False,
                "currency": DEFAULT_CURRENCY,
                "default_payment_token_id": token_id,
            }
        )
    else:
        ddb_update(pk, "BILLING", "SET default_payment_token_id = :t", {":t": token_id})


# ============================================================
# PayPal OAuth (simple in-memory cache)
# ============================================================
_PAYPAL_OAUTH_CACHE: Tuple[str, int] = ("", 0)


def paypal_oauth() -> str:
    _require_paypal_config()
    tok, exp = _PAYPAL_OAUTH_CACHE
    if tok and exp > now_ts() + 30:
        return tok

    url = f"{PAYPAL_BASE_URL}/v1/oauth2/token"
    r = requests.post(
        url,
        auth=(S.paypal_client_id, S.paypal_client_secret),
        headers={"Accept": "application/json"},
        data={"grant_type": "client_credentials"},
        timeout=15,
    )
    if r.status_code != 200:
        raise HTTPException(502, f"PayPal OAuth failed: {r.status_code} {r.text}")
    data = r.json()
    access = data["access_token"]
    expires_in = int(data.get("expires_in", 300))
    globals()["_PAYPAL_OAUTH_CACHE"] = (access, now_ts() + expires_in)
    return access


# ============================================================
# PayPal: Vault (setup token -> payment token)
# ============================================================

def paypal_create_setup_token(
    *,
    user_id: str,
    usage_type: str,
    pm_kind: str,
    return_url: str,
    cancel_url: str,
    idempotency_key: str,
) -> Dict[str, Any]:
    access = paypal_oauth()
    url = f"{PAYPAL_BASE_URL}/v3/vault/setup-tokens"
    headers = {
        "Authorization": f"Bearer {access}",
        "Content-Type": "application/json",
        "PayPal-Request-Id": idempotency_key,
    }

    if pm_kind == "paypal":
        payment_source = {"paypal": {"experience_context": {"return_url": return_url, "cancel_url": cancel_url}}}
    else:
        payment_source = {"card": {"experience_context": {"return_url": return_url, "cancel_url": cancel_url}}}

    payload = {
        "usage_type": usage_type,
        "customer_type": "CONSUMER",
        "payment_source": payment_source,
        "metadata": {
            "brand_name": "Your App",
            "locale": "en-US",
        },
        "custom_id": user_id,
    }

    r = requests.post(url, headers=headers, json=payload, timeout=20)
    if r.status_code not in (200, 201):
        raise HTTPException(502, f"PayPal setup-token failed: {r.status_code} {r.text}")
    return r.json()


def paypal_exchange_setup_for_payment_token(
    *,
    setup_token_id: str,
    idempotency_key: str,
) -> Dict[str, Any]:
    access = paypal_oauth()
    url = f"{PAYPAL_BASE_URL}/v3/vault/payment-tokens"
    headers = {
        "Authorization": f"Bearer {access}",
        "Content-Type": "application/json",
        "PayPal-Request-Id": idempotency_key,
    }
    payload = {
        "payment_source": {
            "token": {
                "id": setup_token_id,
                "type": "SETUP_TOKEN",
            }
        }
    }
    r = requests.post(url, headers=headers, json=payload, timeout=20)
    if r.status_code not in (200, 201):
        raise HTTPException(502, f"PayPal payment-token exchange failed: {r.status_code} {r.text}")
    return r.json()


def paypal_delete_payment_token(payment_token_id: str) -> None:
    access = paypal_oauth()
    url = f"{PAYPAL_BASE_URL}/v3/vault/payment-tokens/{payment_token_id}"
    headers = {"Authorization": f"Bearer {access}"}
    r = requests.delete(url, headers=headers, timeout=20)
    if r.status_code not in (204, 200):
        raise HTTPException(502, f"PayPal delete payment token failed: {r.status_code} {r.text}")


# ============================================================
# PayPal: Orders (create + capture)
# ============================================================

def paypal_create_order(
    *,
    user_id: str,
    amount_cents: int,
    currency: str,
    idempotency_key: str,
    return_url: str,
    cancel_url: str,
    payment_token_id: Optional[str] = None,
    custom_id: Optional[str] = None,
) -> Dict[str, Any]:
    access = paypal_oauth()
    url = f"{PAYPAL_BASE_URL}/v2/checkout/orders"
    headers = {
        "Authorization": f"Bearer {access}",
        "Content-Type": "application/json",
        "PayPal-Request-Id": idempotency_key,
    }

    purchase_unit = {
        "amount": {"currency_code": currency.upper(), "value": _money_value_from_cents(amount_cents)},
        "custom_id": custom_id or user_id,
    }

    payload: Dict[str, Any] = {
        "intent": "CAPTURE",
        "purchase_units": [purchase_unit],
        "application_context": {
            "return_url": return_url,
            "cancel_url": cancel_url,
        },
    }

    if payment_token_id:
        payload["payment_source"] = {
            "token": {
                "id": payment_token_id,
                "type": "PAYMENT_METHOD_TOKEN",
            }
        }

    r = requests.post(url, headers=headers, json=payload, timeout=20)
    if r.status_code not in (200, 201):
        raise HTTPException(502, f"PayPal create order failed: {r.status_code} {r.text}")
    return r.json()


def paypal_capture_order(*, order_id: str, idempotency_key: str) -> Dict[str, Any]:
    access = paypal_oauth()
    url = f"{PAYPAL_BASE_URL}/v2/checkout/orders/{order_id}/capture"
    headers = {
        "Authorization": f"Bearer {access}",
        "Content-Type": "application/json",
        "PayPal-Request-Id": idempotency_key,
    }
    r = requests.post(url, headers=headers, timeout=20)
    if r.status_code not in (200, 201):
        raise HTTPException(502, f"PayPal capture failed: {r.status_code} {r.text}")
    return r.json()


def _find_link(data: Dict[str, Any], rel: str) -> Optional[str]:
    for ln in data.get("links") or []:
        if ln.get("rel") == rel and ln.get("href"):
            return ln["href"]
    return None


# ============================================================
# PayPal: Subscriptions
# ============================================================

def paypal_create_subscription(
    *,
    plan_id: str,
    user_id: str,
    idempotency_key: str,
    return_url: str,
    cancel_url: str,
    custom_id: str,
) -> Dict[str, Any]:
    access = paypal_oauth()
    url = f"{PAYPAL_BASE_URL}/v1/billing/subscriptions"
    headers = {
        "Authorization": f"Bearer {access}",
        "Content-Type": "application/json",
        "PayPal-Request-Id": idempotency_key,
    }
    payload = {
        "plan_id": plan_id,
        "custom_id": custom_id,
        "application_context": {
            "return_url": return_url,
            "cancel_url": cancel_url,
        },
    }
    r = requests.post(url, headers=headers, json=payload, timeout=20)
    if r.status_code not in (200, 201):
        raise HTTPException(502, f"PayPal create subscription failed: {r.status_code} {r.text}")
    return r.json()


def paypal_cancel_subscription(*, subscription_id: str, reason: str, idempotency_key: str) -> None:
    access = paypal_oauth()
    url = f"{PAYPAL_BASE_URL}/v1/billing/subscriptions/{subscription_id}/cancel"
    headers = {
        "Authorization": f"Bearer {access}",
        "Content-Type": "application/json",
        "PayPal-Request-Id": idempotency_key,
    }
    payload = {"reason": reason}
    r = requests.post(url, headers=headers, json=payload, timeout=20)
    if r.status_code not in (204, 200):
        raise HTTPException(502, f"PayPal cancel subscription failed: {r.status_code} {r.text}")


# ============================================================
# Webhook security + dedupe
# ============================================================

def mark_webhook_processed(dedupe_key: str) -> bool:
    try:
        ddb_put(
            {
                "pk": "PAYPAL_WEBHOOK",
                "sk": dedupe_key,
                "ts": now_ts(),
                S.ddb_ttl_attr: now_ts() + 60 * 60 * 24 * 7,
            },
            condition_expression="attribute_not_exists(pk)",
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def paypal_verify_webhook_signature(
    *,
    transmission_id: str,
    transmission_time: str,
    transmission_sig: str,
    cert_url: str,
    auth_algo: str,
    webhook_id: str,
    raw_body: bytes,
) -> bool:
    access = paypal_oauth()
    url = f"{PAYPAL_BASE_URL}/v1/notifications/verify-webhook-signature"
    headers = {"Authorization": f"Bearer {access}", "Content-Type": "application/json"}
    payload = {
        "transmission_id": transmission_id,
        "transmission_time": transmission_time,
        "cert_url": cert_url,
        "auth_algo": auth_algo,
        "transmission_sig": transmission_sig,
        "webhook_id": webhook_id,
        "webhook_event": json.loads(raw_body.decode("utf-8") or "{}"),
    }
    r = requests.post(url, headers=headers, json=payload, timeout=20)
    if r.status_code != 200:
        raise HTTPException(502, f"PayPal verify webhook failed: {r.status_code} {r.text}")
    data = r.json()
    return data.get("verification_status") == "SUCCESS"


# ============================================================
# Models
# ============================================================
class PaymentMethodOut(BaseModel):
    payment_token_id: str
    label: Optional[str] = None
    priority: int
    pm_type: Optional[str] = None


class SetAutopayIn(BaseModel):
    enabled: bool


class PayBalanceIn(BaseModel):
    amount_cents: Optional[int] = Field(default=None, ge=1)
    idempotency_key: Optional[str] = None


class OneTimeChargeIn(BaseModel):
    amount_cents: int = Field(ge=1)
    payment_token_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    reason: str = "one_time_charge"


class CaptureOrderIn(BaseModel):
    order_id: str
    idempotency_key: Optional[str] = None


class SetupTokenIn(BaseModel):
    pm_kind: str = Field(pattern="^(paypal|card)$")
    label: Optional[str] = None
    make_default: bool = True


class ExchangeTokenIn(BaseModel):
    setup_token_id: str
    label: Optional[str] = None
    make_default: bool = True


class SetPriorityIn(BaseModel):
    payment_token_id: str
    priority: int = Field(ge=0, le=100000)


class SetDefaultIn(BaseModel):
    payment_token_id: str


class SubscribeMonthlyIn(BaseModel):
    plan_id: str = "monthly"
    paypal_plan_id: Optional[str] = None
    idempotency_key: Optional[str] = None


class CancelSubscriptionIn(BaseModel):
    subscription_id: str
    reason: str = "user_requested"
    idempotency_key: Optional[str] = None


class AddChargeIn(BaseModel):
    amount_cents: int = Field(ge=1)
    state: str = Field(pattern="^(pending|settled)$")
    reason: str = "usage"


# ============================================================
# Config + settings + balances
# ============================================================
@router.get("/api/billing/config")
def billing_config():
    return {
        "paypal_env": PAYPAL_ENV,
        "paypal_base_url": PAYPAL_BASE_URL,
        "default_currency": DEFAULT_CURRENCY,
        "default_monthly_price_cents": DEFAULT_MONTHLY_PRICE_CENTS,
        "public_base_url": PUBLIC_BASE_URL,
        "plan_map": PAYPAL_PLAN_MAP,
    }


@router.get("/api/billing/settings")
def get_settings(x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)
    return ddb_get(pk, "BILLING") or {
        "autopay_enabled": False,
        "currency": DEFAULT_CURRENCY,
        "default_payment_token_id": None,
    }


@router.post("/api/billing/autopay")
def set_autopay(body: SetAutopayIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)
    if not ddb_get(pk, "BILLING"):
        ddb_put(
            {
                "pk": pk,
                "sk": "BILLING",
                "autopay_enabled": False,
                "currency": DEFAULT_CURRENCY,
                "default_payment_token_id": None,
            }
        )
    ddb_update(pk, "BILLING", "SET autopay_enabled = :e", {":e": bool(body.enabled)})
    return {"ok": True}


@router.get("/api/billing/balance")
def get_balance(x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)
    ensure_balance_row(pk)
    bal = ddb_get(pk, "BALANCE") or {}
    due = compute_due(bal)
    return {
        "currency": bal.get("currency", DEFAULT_CURRENCY),
        "owed_pending_cents": int(bal.get("owed_pending_cents", 0)),
        "owed_settled_cents": int(bal.get("owed_settled_cents", 0)),
        "payments_pending_cents": int(bal.get("payments_pending_cents", 0)),
        "payments_settled_cents": int(bal.get("payments_settled_cents", 0)),
        **due,
        "updated_at": bal.get("updated_at"),
    }


# ============================================================
# Payment methods (PayPal Vault tokens)
# ============================================================

def _get_default_token_or_400(user_id: str) -> str:
    pk = user_pk(user_id)
    billing = ddb_get(pk, "BILLING") or {}
    token = billing.get("default_payment_token_id")
    if not token:
        raise HTTPException(400, "No default payment method set")
    return token


@router.post("/api/billing/payment-methods/paypal/setup-token")
def create_setup_token(body: SetupTokenIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    idem = f"setup:{user_id}:{body.pm_kind}:{int(now_ts()/300)}:{secrets.token_hex(4)}"
    ret = f"{PUBLIC_BASE_URL}/billing/paypal/vault/return"
    can = f"{PUBLIC_BASE_URL}/billing/paypal/vault/cancel"

    resp = paypal_create_setup_token(
        user_id=user_id,
        usage_type="MERCHANT",
        pm_kind=body.pm_kind,
        return_url=ret,
        cancel_url=can,
        idempotency_key=idem,
    )
    approve = _find_link(resp, "approve") or _find_link(resp, "payer-action") or _find_link(resp, "payer_action")
    return {"setup_token": resp.get("id"), "approve_url": approve, "raw": resp}


@router.post("/api/billing/payment-methods/paypal/exchange-token")
def exchange_setup_token(body: ExchangeTokenIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)

    idem = f"exchange:{user_id}:{body.setup_token_id}:{int(now_ts()/300)}"
    resp = paypal_exchange_setup_for_payment_token(setup_token_id=body.setup_token_id, idempotency_key=idem)

    payment_token_id = resp.get("id")
    if not payment_token_id:
        raise HTTPException(502, "PayPal exchange did not return payment token id")

    existing = list_payment_methods_ddb(user_id)
    next_priority = 0 if not existing else (max(int(x.get("priority", 0)) for x in existing) + 1)

    pm_type = None
    if isinstance(resp.get("payment_source"), dict) and resp.get("payment_source"):
        pm_type = next(iter(resp["payment_source"].keys()))

    ddb_put(
        {
            "pk": pk,
            "sk": pm_sk(payment_token_id),
            "payment_token_id": payment_token_id,
            "label": body.label,
            "pm_type": pm_type,
            "priority": next_priority,
            "created_at": now_ts(),
            "raw": resp,
        }
    )

    if body.make_default or not current_default_pm(user_id):
        set_default_pm(user_id, payment_token_id)

    return {"ok": True, "payment_token_id": payment_token_id, "raw": resp}


@router.get("/api/billing/payment-methods", response_model=List[PaymentMethodOut])
def list_payment_methods(x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pms = list_payment_methods_ddb(user_id)
    out: List[PaymentMethodOut] = [
        PaymentMethodOut(
            payment_token_id=it["payment_token_id"],
            label=it.get("label"),
            priority=int(it.get("priority", 0)),
            pm_type=it.get("pm_type"),
        )
        for it in pms
    ]
    out.sort(key=lambda x: x.priority)
    return out


@router.post("/api/billing/payment-methods/priority")
def set_priority(body: SetPriorityIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)
    sk = pm_sk(body.payment_token_id)
    if not ddb_get(pk, sk):
        raise HTTPException(404, "Payment method not found")
    ddb_update(pk, sk, "SET priority = :p", {":p": int(body.priority)})
    return {"ok": True}


@router.post("/api/billing/payment-methods/default")
def set_default(body: SetDefaultIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)
    if not ddb_get(pk, pm_sk(body.payment_token_id)):
        raise HTTPException(404, "Payment method not found")
    set_default_pm(user_id, body.payment_token_id)
    return {"ok": True}


@router.delete("/api/billing/payment-methods/{payment_token_id}")
def remove_payment_method(
    payment_token_id: str,
    x_user_id: Optional[str] = Header(default=None),
    delete_from_paypal: bool = False,
):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)
    sk = pm_sk(payment_token_id)
    if not ddb_get(pk, sk):
        raise HTTPException(404, "Payment method not found")

    if delete_from_paypal:
        paypal_delete_payment_token(payment_token_id)

    ddb_del(pk, sk)

    if current_default_pm(user_id) == payment_token_id:
        remaining = list_payment_methods_ddb(user_id)
        remaining.sort(key=lambda x: int(x.get("priority", 0)))
        set_default_pm(user_id, remaining[0]["payment_token_id"] if remaining else None)

    return {"ok": True}


# ============================================================
# One-time charges + Pay Balance (ledger-first)
# ============================================================
@router.post("/api/billing/charge-once")
async def charge_once(body: OneTimeChargeIn, request: Request, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)

    token = body.payment_token_id or _get_default_token_or_400(user_id)
    amount = int(body.amount_cents)

    idem = body.idempotency_key or f"order:{user_id}:{token}:{amount}:{int(now_ts()/30)}"
    return_url = f"{PUBLIC_BASE_URL}/billing/paypal/checkout/return"
    cancel_url = f"{PUBLIC_BASE_URL}/billing/paypal/checkout/cancel"

    led_sk_value, led_item = new_ledger_entry(
        user_id=user_id,
        entry_type="credit",
        amount_cents=amount,
        state="pending",
        reason=body.reason,
        paypal_payment_token_id=token,
        meta={"idempotency_key": idem, "mode": "one_time"},
    )
    ddb_put(led_item)
    apply_balance_delta(pk, {"payments_pending_cents": amount})

    custom_id = f"{user_id}|{led_sk_value}"
    order = paypal_create_order(
        user_id=user_id,
        amount_cents=amount,
        currency=DEFAULT_CURRENCY_CODE,
        idempotency_key=idem,
        return_url=return_url,
        cancel_url=cancel_url,
        payment_token_id=token,
        custom_id=custom_id,
    )

    order_id = order.get("id")
    approve = _find_link(order, "approve") or _find_link(order, "payer-action") or _find_link(order, "payer_action")

    if order_id:
        put_payment_record(
            user_id=user_id,
            external_id=str(order_id),
            amount_cents=amount,
            kind="one_time",
            status="pending",
            ledger_sk_value=led_sk_value,
            payment_token_id=token,
            raw={"order": order},
        )

    return {"order_id": order_id, "approve_url": approve, "status": "created", "ledger_sk": led_sk_value, "raw": order}


@router.post("/api/billing/paypal/capture-order")
async def capture_order(body: CaptureOrderIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)

    order_id = body.order_id
    idem = body.idempotency_key or f"capture:{user_id}:{order_id}:{int(now_ts()/30)}"

    pay = ddb_get(pk, pay_sk(order_id))
    if not pay or not pay.get("ledger_sk"):
        raise HTTPException(404, "Unknown order_id (no internal record)")

    amount = int(pay.get("amount_cents", 0))
    led_sk_value = pay["ledger_sk"]

    cap = paypal_capture_order(order_id=order_id, idempotency_key=idem)

    status = (cap.get("status") or "").upper()
    ok = status in ("COMPLETED",)

    if ok:
        apply_balance_delta(pk, {"payments_pending_cents": -amount, "payments_settled_cents": amount})
        settle_or_reverse_ledger(user_id, led_sk_value, "settled")
        update_payment_status(user_id, order_id, "succeeded", raw={"capture": cap})
    else:
        apply_balance_delta(pk, {"payments_pending_cents": -amount})
        settle_or_reverse_ledger(user_id, led_sk_value, "reversed")
        update_payment_status(user_id, order_id, "failed", raw={"capture": cap})

    return {"ok": ok, "order_id": order_id, "capture": cap}


@router.post("/api/billing/pay-balance")
async def pay_balance(body: PayBalanceIn, request: Request, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)

    ensure_balance_row(pk)
    bal = ddb_get(pk, "BALANCE") or {}
    due = compute_due(bal)["due_settled_cents"]
    if due <= 0:
        return {"status": "no_settled_balance_due"}

    amount = due if body.amount_cents is None else min(int(body.amount_cents), due)
    if amount <= 0:
        return {"status": "no_settled_balance_due"}

    token = _get_default_token_or_400(user_id)
    idem = body.idempotency_key or f"paybalance:{user_id}:{token}:{amount}:{int(now_ts()/30)}"

    ot = OneTimeChargeIn(amount_cents=amount, payment_token_id=token, idempotency_key=idem, reason="pay_balance")
    return await charge_once(ot, request, x_user_id=x_user_id)


# ============================================================
# Monthly subscription start (PayPal Subscriptions)
# ============================================================
@router.post("/api/billing/subscribe-monthly")
async def subscribe_monthly(body: SubscribeMonthlyIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)

    paypal_plan_id = body.paypal_plan_id or PAYPAL_PLAN_MAP.get(body.plan_id)
    if not paypal_plan_id:
        raise HTTPException(400, "Missing paypal_plan_id (or PAYPAL_PLAN_MAP does not contain this plan_id)")

    idem = body.idempotency_key or f"subcreate:{user_id}:{paypal_plan_id}:{int(now_ts()/300)}"
    return_url = f"{PUBLIC_BASE_URL}/billing/paypal/subscription/return"
    cancel_url = f"{PUBLIC_BASE_URL}/billing/paypal/subscription/cancel"

    custom_id = f"{user_id}|plan={body.plan_id}"
    resp = paypal_create_subscription(
        plan_id=paypal_plan_id,
        user_id=user_id,
        idempotency_key=idem,
        return_url=return_url,
        cancel_url=cancel_url,
        custom_id=custom_id,
    )
    sub_id = resp.get("id")
    approve = _find_link(resp, "approve") or _find_link(resp, "payer-action") or _find_link(resp, "payer_action")

    if sub_id:
        upsert_subscription(
            user_id=user_id,
            subscription_id=str(sub_id),
            status=(resp.get("status") or "created").lower(),
            plan_id=body.plan_id,
            raw={"create_subscription": resp},
        )

    return {"subscription_id": sub_id, "approve_url": approve, "raw": resp}


@router.post("/api/billing/subscriptions/cancel")
def cancel_subscription(body: CancelSubscriptionIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    idem = body.idempotency_key or f"subcancel:{user_id}:{body.subscription_id}:{int(now_ts()/300)}"
    paypal_cancel_subscription(subscription_id=body.subscription_id, reason=body.reason, idempotency_key=idem)
    upsert_subscription(user_id, body.subscription_id, status="canceled", plan_id="unknown", raw={"cancel_reason": body.reason})
    return {"ok": True}


# ============================================================
# OPTIONAL: add charges to user's balance (your app debits)
# ============================================================
@router.post("/api/billing/_dev/add-charge")
def dev_add_charge(body: AddChargeIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
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


# ============================================================
# OPTIONAL: list ledger / payments / subscriptions for UI
# ============================================================
@router.get("/api/billing/ledger")
def list_ledger(x_user_id: Optional[str] = Header(default=None), limit: int = 50):
    user_id = require_user(x_user_id)
    items = ddb_query_pk(user_pk(user_id))
    led = [it for it in items if it["sk"].startswith("LEDGER#")]
    led.sort(key=lambda x: x.get("ts", 0), reverse=True)
    return {"items": led[: max(1, min(limit, 200))]}


@router.get("/api/billing/payments")
def list_payments(x_user_id: Optional[str] = Header(default=None), limit: int = 50):
    user_id = require_user(x_user_id)
    items = ddb_query_pk(user_pk(user_id))
    pays = [it for it in items if it["sk"].startswith("PAY#")]
    pays.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return {"items": pays[: max(1, min(limit, 200))]}


@router.get("/api/billing/subscriptions")
def list_subscriptions(x_user_id: Optional[str] = Header(default=None), limit: int = 50):
    user_id = require_user(x_user_id)
    items = ddb_query_pk(user_pk(user_id))
    subs = [it for it in items if it["sk"].startswith("SUB#")]
    subs.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return {"items": subs[: max(1, min(limit, 200))]}


# ============================================================
# PayPal Webhook handler (verify + dedupe)
# ============================================================
@router.post("/api/paypal/webhook")
async def paypal_webhook(req: Request):
    raw_body = await req.body()
    dedupe_key = hashlib.sha256(raw_body).hexdigest()
    if not mark_webhook_processed(dedupe_key):
        return {"received": True, "deduped": True}

    if not S.paypal_webhook_id:
        raise HTTPException(500, "PAYPAL_WEBHOOK_ID not set; cannot verify webhook signatures")

    transmission_id = req.headers.get("paypal-transmission-id", "")
    transmission_time = req.headers.get("paypal-transmission-time", "")
    transmission_sig = req.headers.get("paypal-transmission-sig", "")
    cert_url = req.headers.get("paypal-cert-url", "")
    auth_algo = req.headers.get("paypal-auth-algo", "")

    if not (transmission_id and transmission_time and transmission_sig and cert_url and auth_algo):
        raise HTTPException(400, "Missing PayPal webhook verification headers")

    verified = paypal_verify_webhook_signature(
        transmission_id=transmission_id,
        transmission_time=transmission_time,
        transmission_sig=transmission_sig,
        cert_url=cert_url,
        auth_algo=auth_algo,
        webhook_id=S.paypal_webhook_id,
        raw_body=raw_body,
    )
    if not verified:
        raise HTTPException(403, "Invalid webhook signature")

    event = json.loads(raw_body.decode("utf-8") or "{}")
    event_type = event.get("event_type", "")
    resource = event.get("resource") or {}

    user_id = None
    ledger_sk_hint = None

    def _split_custom_id(s: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        if not s or "|" not in s:
            return None, None
        a, b = s.split("|", 1)
        if b.startswith("LEDGER#"):
            return a, b
        return a, None

    try:
        purchase_units = resource.get("purchase_units") or []
        if purchase_units:
            cid = purchase_units[0].get("custom_id")
            user_id, ledger_sk_hint = _split_custom_id(cid)
    except Exception:
        pass

    if not user_id:
        try:
            cid = resource.get("custom_id")
            if isinstance(cid, str) and "|" in cid:
                user_id = cid.split("|", 1)[0]
        except Exception:
            pass

    if not user_id:
        ddb_put(
            {
                "pk": "PAYPAL_WEBHOOK_UNMATCHED",
                "sk": f"{now_ts()}#{dedupe_key}",
                "eventType": event_type,
                "event": event,
                "created_at": now_ts(),
            }
        )
        return {"received": True, "unmatched": True}

    user_id = str(user_id)
    pk = user_pk(user_id)
    ensure_balance_row(pk)

    if event_type in ("PAYMENT.CAPTURE.COMPLETED", "CHECKOUT.ORDER.APPROVED"):
        if event_type == "PAYMENT.CAPTURE.COMPLETED":
            order_id = None
            try:
                order_id = (resource.get("supplementary_data") or {}).get("related_ids", {}).get("order_id")
            except Exception:
                order_id = None

            if order_id:
                pay = ddb_get(pk, pay_sk(str(order_id)))
                if pay and pay.get("ledger_sk"):
                    amount = int(pay.get("amount_cents", 0))
                    apply_balance_delta(pk, {"payments_pending_cents": -amount, "payments_settled_cents": amount})
                    settle_or_reverse_ledger(user_id, pay["ledger_sk"], "settled")
                    update_payment_status(user_id, str(order_id), "succeeded", raw={"event": event})
                else:
                    amount_cents = 0
                    try:
                        amt = resource.get("amount") or {}
                        amount_cents = int(Decimal(str(amt.get("value"))) * 100)
                    except Exception:
                        amount_cents = 0
                    led_sk_value2, led_item = new_ledger_entry(
                        user_id=user_id,
                        entry_type="credit",
                        amount_cents=amount_cents,
                        state="settled",
                        reason="paypal_capture_webhook",
                        paypal_order_id=str(order_id),
                        paypal_capture_id=str(resource.get("id") or ""),
                        meta={"event": event},
                    )
                    ddb_put(led_item)
                    if amount_cents:
                        apply_balance_delta(pk, {"payments_settled_cents": amount_cents})

    elif event_type in ("PAYMENT.CAPTURE.DENIED", "PAYMENT.CAPTURE.DECLINED", "PAYMENT.CAPTURE.REFUNDED"):
        amount_cents = 0
        try:
            amt = resource.get("amount") or {}
            amount_cents = int(Decimal(str(amt.get("value"))) * 100)
        except Exception:
            amount_cents = 0
        led_sk_value2, led_item = new_ledger_entry(
            user_id=user_id,
            entry_type="adjustment",
            amount_cents=amount_cents,
            state="settled",
            reason=event_type.lower(),
            paypal_capture_id=str(resource.get("id") or ""),
            meta={"event": event},
        )
        ddb_put(led_item)
        if amount_cents:
            apply_balance_delta(pk, {"owed_settled_cents": amount_cents})

    elif event_type == "BILLING.SUBSCRIPTION.ACTIVATED":
        sub_id = str(resource.get("id") or "")
        if sub_id:
            upsert_subscription(user_id, sub_id, status="active", plan_id="monthly", raw={"event": event})

    elif event_type in ("BILLING.SUBSCRIPTION.CANCELLED", "BILLING.SUBSCRIPTION.SUSPENDED", "BILLING.SUBSCRIPTION.EXPIRED"):
        sub_id = str(resource.get("id") or "")
        if sub_id:
            upsert_subscription(
                user_id,
                sub_id,
                status=event_type.split(".")[-1].lower(),
                plan_id="monthly",
                raw={"event": event},
            )

    elif event_type in ("BILLING.SUBSCRIPTION.PAYMENT.FAILED",):
        sub_id = str(resource.get("billing_agreement_id") or resource.get("id") or "")
        if sub_id:
            upsert_subscription(user_id, sub_id, status="past_due", plan_id="monthly", raw={"event": event})

    else:
        ddb_put(
            {
                "pk": "PAYPAL_WEBHOOK_OTHER",
                "sk": f"{now_ts()}#{dedupe_key}",
                "eventType": event_type,
                "event": event,
                "created_at": now_ts(),
            }
        )

    return {"received": True}
