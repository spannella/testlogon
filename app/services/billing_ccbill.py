from __future__ import annotations

import ipaddress
import json
import secrets
import time
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Tuple

import requests
from botocore.exceptions import ClientError
from fastapi import HTTPException, Request

from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

BAL_FIELDS = [
    "owed_pending_cents",
    "owed_settled_cents",
    "payments_pending_cents",
    "payments_settled_cents",
]

CCBILL_WEBHOOK_IP_RANGES = [
    ("64.38.212.0", "64.38.212.255"),
    ("64.38.215.0", "64.38.215.255"),
    ("64.38.240.0", "64.38.240.255"),
    ("64.38.241.0", "64.38.241.255"),
]

_OAUTH_CACHE: Dict[str, Tuple[str, int]] = {}


def _ulidish() -> str:
    return f"{int(time.time() * 1000)}_{secrets.token_hex(8)}"


def _billing_sk(kind: str, identifier: str) -> str:
    return f"{kind}#{identifier}"


def ensure_balance_row(user_sub: str) -> None:
    it = T.billing.get_item(Key={"user_sub": user_sub, "sk": "BALANCE"}).get("Item")
    if not it:
        T.billing.put_item(Item={
            "user_sub": user_sub,
            "sk": "BALANCE",
            "currency": S.default_currency,
            **{k: 0 for k in BAL_FIELDS},
            "updated_at": now_ts(),
        })


def apply_balance_delta(user_sub: str, delta: Dict[str, int]) -> None:
    ensure_balance_row(user_sub)
    sets = []
    values: Dict[str, Any] = {":z": 0, ":t": now_ts()}
    names: Dict[str, str] = {}

    i = 0
    for k, v in delta.items():
        if v == 0:
            continue
        i += 1
        nk = f"#k{i}"
        dv = f":d{i}"
        names[nk] = k
        values[dv] = int(v)
        sets.append(f"{nk} = if_not_exists({nk}, :z) + {dv}")

    names["#u"] = "updated_at"
    sets.append("#u = :t")
    expr = "SET " + ", ".join(sets)
    T.billing.update_item(
        Key={"user_sub": user_sub, "sk": "BALANCE"},
        UpdateExpression=expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


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
    user_sub: str,
    entry_type: str,
    amount_cents: int,
    state: str,
    reason: str,
    ccbill_payment_token_id: Optional[str] = None,
    ccbill_transaction_id: Optional[str] = None,
    ccbill_subscription_id: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Dict[str, Any]]:
    ts = now_ts()
    eid = _ulidish()
    sk = ledger_sk(ts, eid)
    item = {
        "user_sub": user_sub,
        "sk": sk,
        "entry_id": eid,
        "ts": ts,
        "type": entry_type,
        "amount_cents": int(amount_cents),
        "state": state,
        "reason": reason,
    }
    if ccbill_payment_token_id:
        item["ccbill_payment_token_id"] = ccbill_payment_token_id
    if ccbill_transaction_id:
        item["ccbill_transaction_id"] = ccbill_transaction_id
    if ccbill_subscription_id:
        item["ccbill_subscription_id"] = ccbill_subscription_id
    if meta:
        item["meta"] = meta
    return sk, item


def settle_or_reverse_ledger(user_sub: str, ledger_sk_value: str, new_state: str) -> None:
    T.billing.update_item(
        Key={"user_sub": user_sub, "sk": ledger_sk_value},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "state"},
        ExpressionAttributeValues={":s": new_state},
    )


def put_payment_record(
    user_sub: str,
    transaction_id: str,
    amount_cents: int,
    kind: str,
    status: str,
    ledger_sk_value: Optional[str],
    payment_token_id: Optional[str] = None,
    subscription_id: Optional[str] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> None:
    item = {
        "user_sub": user_sub,
        "sk": _billing_sk("PAY", transaction_id),
        "transaction_id": transaction_id,
        "kind": kind,
        "status": status,
        "amount_cents": int(amount_cents),
        "currency": S.default_currency,
        "payment_token_id": payment_token_id,
        "subscription_id": subscription_id,
        "ledger_sk": ledger_sk_value,
        "created_at": now_ts(),
        "updated_at": now_ts(),
    }
    if raw:
        item["raw"] = raw
    T.billing.put_item(Item=item)


def update_payment_status(user_sub: str, transaction_id: str, status: str, raw: Optional[Dict[str, Any]] = None) -> None:
    names = {"#st": "status", "#u": "updated_at"}
    values: Dict[str, Any] = {":st": status, ":u": now_ts()}
    sets = ["#st = :st", "#u = :u"]
    if raw is not None:
        names["#r"] = "raw"
        values[":r"] = raw
        sets.append("#r = :r")
    T.billing.update_item(
        Key={"user_sub": user_sub, "sk": _billing_sk("PAY", transaction_id)},
        UpdateExpression="SET " + ", ".join(sets),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def upsert_subscription(
    user_sub: str,
    subscription_id: str,
    *,
    status: str,
    plan_id: str,
    payment_token_id: Optional[str] = None,
    next_renewal_date: Optional[str] = None,
    last_transaction_id: Optional[str] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> None:
    existing = T.billing.get_item(Key={"user_sub": user_sub, "sk": _billing_sk("SUB", subscription_id)}).get("Item")
    item = existing or {
        "user_sub": user_sub,
        "sk": _billing_sk("SUB", subscription_id),
        "subscription_id": subscription_id,
        "created_at": now_ts(),
    }
    item["status"] = status
    item["plan_id"] = plan_id
    item["updated_at"] = now_ts()
    if payment_token_id:
        item["payment_token_id"] = payment_token_id
    if next_renewal_date:
        item["next_renewal_date"] = next_renewal_date
    if last_transaction_id:
        item["last_transaction_id"] = last_transaction_id
    if raw:
        item["raw"] = raw
    T.billing.put_item(Item=item)


def list_payment_methods(user_sub: str) -> List[Dict[str, Any]]:
    resp = T.billing.query(
        KeyConditionExpression="user_sub = :u AND begins_with(sk, :p)",
        ExpressionAttributeValues={":u": user_sub, ":p": "PM#"},
    )
    return resp.get("Items", [])


def current_default_pm(user_sub: str) -> Optional[str]:
    billing = T.billing.get_item(Key={"user_sub": user_sub, "sk": "BILLING"}).get("Item") or {}
    return billing.get("default_payment_token_id")


def set_default_pm(user_sub: str, token_id: Optional[str]) -> None:
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


def _oauth_token(client_id: str, client_secret: str, cache_key: str) -> str:
    tok, exp = _OAUTH_CACHE.get(cache_key, ("", 0))
    if tok and exp > now_ts() + 30:
        return tok

    if not client_id or not client_secret:
        raise HTTPException(500, "Missing CCBill OAuth credentials")

    url = f"{S.ccbill_base_url}/ccbill-auth/oauth/token?grant_type=client_credentials"
    r = requests.post(
        url,
        auth=(client_id, client_secret),
        headers={
            "Accept": S.ccbill_accept,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=15,
    )
    if r.status_code != 200:
        raise HTTPException(502, f"CCBill OAuth failed: {r.status_code} {r.text}")

    data = r.json()
    access = data["access_token"]
    expires_in = int(data.get("expires_in", 600))
    _OAUTH_CACHE[cache_key] = (access, now_ts() + expires_in)
    return access


def ccbill_frontend_oauth() -> str:
    return _oauth_token(S.ccbill_frontend_client_id, S.ccbill_frontend_client_secret, "frontend")


def ccbill_backend_oauth() -> str:
    return _oauth_token(S.ccbill_backend_client_id, S.ccbill_backend_client_secret, "backend")


def _cents_to_dollars(cents: int) -> float:
    d = (Decimal(cents) / Decimal(100)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return float(d)


def ccbill_charge_payment_token(
    *,
    payment_token_id: str,
    origin_ip: str,
    initial_price_cents: int,
    initial_period_days: int,
    recurring_price_cents: Optional[int] = None,
    recurring_period_days: Optional[int] = None,
    currency_code: int = S.default_currency_code,
    extra: Optional[Dict[str, Any]] = None,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    access = ccbill_backend_oauth()
    url = f"{S.ccbill_base_url}/transactions/payment-tokens/{payment_token_id}"

    payload: Dict[str, Any] = {
        "clientAccnum": S.ccbill_client_accnum,
        "clientSubacc": S.ccbill_client_subacc,
        "initialPrice": _cents_to_dollars(int(initial_price_cents)),
        "initialPeriod": int(initial_period_days),
        "currencyCode": int(currency_code),
        "ipAddress": origin_ip,
    }
    if recurring_price_cents is not None and recurring_period_days is not None:
        payload["recurringPrice"] = _cents_to_dollars(int(recurring_price_cents))
        payload["recurringPeriod"] = int(recurring_period_days)

    if extra:
        payload.update(extra)

    headers = {
        "Authorization": f"Bearer {access}",
        "Accept": S.ccbill_accept,
        "Content-Type": "application/json",
        "X-Origin-IP": origin_ip,
    }
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=20)
    if r.status_code != 200:
        raise HTTPException(502, f"CCBill charge failed: {r.status_code} {r.text}")
    return r.json()


def mark_webhook_processed(dedupe_key: str) -> bool:
    try:
        T.billing.put_item(
            Item={
                "user_sub": "CCBILL_WEBHOOK",
                "sk": dedupe_key,
                "ts": now_ts(),
                "ttl": now_ts() + 60 * 60 * 24 * 7,
            },
            ConditionExpression="attribute_not_exists(user_sub)",
        )
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def webhook_remote_ip_allowed(ip_str: str) -> bool:
    if not S.ccbill_webhook_ip_enforce:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    for a, b in CCBILL_WEBHOOK_IP_RANGES:
        if ipaddress.ip_address(a) <= ip <= ipaddress.ip_address(b):
            return True
    return False


def charge_once(
    *,
    user_sub: str,
    amount_cents: int,
    payment_token_id: Optional[str],
    reason: str,
    idempotency_key: Optional[str],
    request: Request,
) -> Dict[str, Any]:
    token = payment_token_id or _get_default_token_or_400(user_sub)
    amount = int(amount_cents)
    origin_ip = client_ip_from_request(request)
    idem = idempotency_key or f"chargeonce:{user_sub}:{token}:{amount}:{int(time.time()/30)}"

    led_sk_value, led_item = new_ledger_entry(
        user_sub=user_sub,
        entry_type="credit",
        amount_cents=amount,
        state="pending",
        reason=reason,
        ccbill_payment_token_id=token,
        meta={"idempotency_key": idem, "mode": "one_time"},
    )
    T.billing.put_item(Item=led_item)
    apply_balance_delta(user_sub, {"payments_pending_cents": amount})

    resp = ccbill_charge_payment_token(
        payment_token_id=token,
        origin_ip=origin_ip,
        initial_price_cents=amount,
        initial_period_days=1,
        recurring_price_cents=None,
        recurring_period_days=None,
        idempotency_key=idem,
    )

    approved = bool(resp.get("approved"))
    transaction_id = resp.get("transactionId") or resp.get("paymentUniqueId") or resp.get("transaction_id")

    if approved:
        apply_balance_delta(user_sub, {"payments_pending_cents": -amount, "payments_settled_cents": amount})
        settle_or_reverse_ledger(user_sub, led_sk_value, "settled")
        status = "succeeded"
    else:
        apply_balance_delta(user_sub, {"payments_pending_cents": -amount})
        settle_or_reverse_ledger(user_sub, led_sk_value, "reversed")
        status = "failed"

    if transaction_id:
        put_payment_record(
            user_sub=user_sub,
            transaction_id=str(transaction_id),
            amount_cents=amount,
            kind="one_time",
            status=status,
            ledger_sk_value=led_sk_value,
            payment_token_id=token,
            raw=resp,
        )

    return {"approved": approved, "transaction_id": transaction_id, "response": resp}


def subscribe_monthly(
    *,
    user_sub: str,
    plan_id: str,
    monthly_price_cents: Optional[int],
    payment_token_id: Optional[str],
    idempotency_key: Optional[str],
    request: Request,
) -> Dict[str, Any]:
    token = payment_token_id or _get_default_token_or_400(user_sub)
    monthly_cents = int(monthly_price_cents or S.default_monthly_price_cents)
    origin_ip = client_ip_from_request(request)
    idem = idempotency_key or f"subscribe:{user_sub}:{token}:{monthly_cents}:{int(time.time()/300)}"

    led_sk_value, led_item = new_ledger_entry(
        user_sub=user_sub,
        entry_type="credit",
        amount_cents=monthly_cents,
        state="pending",
        reason="subscription_signup",
        ccbill_payment_token_id=token,
        meta={"idempotency_key": idem, "plan_id": plan_id, "mode": "subscription"},
    )
    T.billing.put_item(Item=led_item)
    apply_balance_delta(user_sub, {"payments_pending_cents": monthly_cents})

    resp = ccbill_charge_payment_token(
        payment_token_id=token,
        origin_ip=origin_ip,
        initial_price_cents=monthly_cents,
        initial_period_days=30,
        recurring_price_cents=monthly_cents,
        recurring_period_days=30,
        idempotency_key=idem,
        extra={
            "X-app_user_id": user_sub,
            "X-ledger_sk": led_sk_value,
            "X-plan_id": plan_id,
        },
    )

    approved = bool(resp.get("approved"))
    transaction_id = resp.get("transactionId") or resp.get("paymentUniqueId") or resp.get("transaction_id")
    subscription_id = resp.get("subscriptionId") or resp.get("subscription_id")

    if approved:
        apply_balance_delta(user_sub, {"payments_pending_cents": -monthly_cents, "payments_settled_cents": monthly_cents})
        settle_or_reverse_ledger(user_sub, led_sk_value, "settled")
        pay_status = "succeeded"
        sub_status = "active"
    else:
        apply_balance_delta(user_sub, {"payments_pending_cents": -monthly_cents})
        settle_or_reverse_ledger(user_sub, led_sk_value, "reversed")
        pay_status = "failed"
        sub_status = "failed"

    if transaction_id:
        put_payment_record(
            user_sub=user_sub,
            transaction_id=str(transaction_id),
            amount_cents=monthly_cents,
            kind="subscription_signup",
            status=pay_status,
            ledger_sk_value=led_sk_value,
            payment_token_id=token,
            subscription_id=str(subscription_id) if subscription_id else None,
            raw=resp,
        )

    if subscription_id:
        upsert_subscription(
            user_sub=user_sub,
            subscription_id=str(subscription_id),
            status=sub_status,
            plan_id=plan_id,
            payment_token_id=token,
            last_transaction_id=str(transaction_id) if transaction_id else None,
            raw=resp,
        )

    return {
        "approved": approved,
        "transaction_id": transaction_id,
        "subscription_id": subscription_id,
        "response": resp,
    }


def pay_balance(
    *,
    user_sub: str,
    amount_cents: Optional[int],
    idempotency_key: Optional[str],
    request: Request,
) -> Dict[str, Any]:
    ensure_balance_row(user_sub)
    bal = T.billing.get_item(Key={"user_sub": user_sub, "sk": "BALANCE"}).get("Item") or {}
    due = compute_due(bal)["due_settled_cents"]
    if due <= 0:
        return {"status": "no_settled_balance_due"}

    amount = due if amount_cents is None else min(int(amount_cents), due)
    if amount <= 0:
        return {"status": "no_settled_balance_due"}

    token = _get_default_token_or_400(user_sub)
    idem = idempotency_key or f"paybalance:{user_sub}:{token}:{amount}:{int(time.time()/30)}"
    return charge_once(
        user_sub=user_sub,
        amount_cents=amount,
        payment_token_id=token,
        reason="pay_balance",
        idempotency_key=idem,
        request=request,
    )


def _get_default_token_or_400(user_sub: str) -> str:
    billing = T.billing.get_item(Key={"user_sub": user_sub, "sk": "BILLING"}).get("Item") or {}
    token = billing.get("default_payment_token_id")
    if not token:
        raise HTTPException(400, "No default payment method set")
    return token

