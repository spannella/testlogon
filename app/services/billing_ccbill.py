from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import time
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Tuple

import requests
from botocore.exceptions import ClientError
from fastapi import HTTPException, Request

from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import (
    apply_balance_delta_for_key,
    compute_due as compute_due_shared,
    ensure_balance_row_for_key,
    new_ledger_entry as new_ledger_entry_shared,
    settle_or_reverse_ledger as settle_or_reverse_ledger_shared,
)
from app.services.purchase_history import record_billing_transaction

_DEFAULT_CCBILL_WEBHOOK_IP_RANGES = [
    ("64.38.212.0", "64.38.212.255"),
    ("64.38.215.0", "64.38.215.255"),
    ("64.38.240.0", "64.38.240.255"),
    ("64.38.241.0", "64.38.241.255"),
]
_CCBILL_IP_RANGE_CACHE: Optional[List[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]]] = None

_OAUTH_CACHE: Dict[str, Tuple[str, int]] = {}
_REDACTED_VALUE = "[REDACTED]"
_ALLOWED_RAW_KEYS = {
    "approved",
    "transactionId",
    "paymentUniqueId",
    "transaction_id",
    "subscriptionId",
    "subscription_id",
    "eventType",
    "responseCode",
    "errorCode",
    "message",
    "reason",
    "status",
    "type",
    "amount",
    "currencyCode",
    "payload",
    "q",
}
_SENSITIVE_KEY_FRAGMENTS = (
    "card",
    "cvv",
    "cvc",
    "security",
    "password",
    "email",
    "address",
    "ip",
    "phone",
    "name",
    "ssn",
    "bank",
    "routing",
    "acct",
)


def _is_sensitive_key(key: str) -> bool:
    key_lower = key.lower()
    return any(fragment in key_lower for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _sanitize_ccbill_raw(raw: Any) -> Any:
    if isinstance(raw, dict):
        sanitized: Dict[str, Any] = {}
        for key, value in raw.items():
            if key not in _ALLOWED_RAW_KEYS:
                continue
            if _is_sensitive_key(key):
                sanitized[key] = _REDACTED_VALUE
            elif key in {"payload", "q"}:
                sanitized[key] = _sanitize_ccbill_raw(value)
            else:
                sanitized[key] = _sanitize_ccbill_raw(value)
        return sanitized
    if isinstance(raw, list):
        return [_sanitize_ccbill_raw(item) for item in raw]
    if isinstance(raw, (str, int, float, bool)) or raw is None:
        return raw
    return str(raw)


def sanitize_ccbill_payload(payload: Any) -> Any:
    return _sanitize_ccbill_raw(payload)


def _parse_ccbill_ip_ranges(raw: str) -> List[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]]:
    tokens = [tok.strip() for tok in raw.split(",") if tok.strip()]
    ranges: List[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]] = []
    for token in tokens:
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                ranges.append((net.network_address, net.broadcast_address))
                continue
            if "-" in token:
                start, end = token.split("-", 1)
                ranges.append((ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())))
                continue
            ip = ipaddress.ip_address(token)
            ranges.append((ip, ip))
        except ValueError:
            continue
    return ranges


def _ccbill_ip_ranges() -> List[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]]:
    global _CCBILL_IP_RANGE_CACHE
    if _CCBILL_IP_RANGE_CACHE is not None:
        return _CCBILL_IP_RANGE_CACHE
    raw = S.ccbill_webhook_ip_ranges.strip()
    if not raw:
        _CCBILL_IP_RANGE_CACHE = [
            (ipaddress.ip_address(a), ipaddress.ip_address(b)) for a, b in _DEFAULT_CCBILL_WEBHOOK_IP_RANGES
        ]
        return _CCBILL_IP_RANGE_CACHE
    parsed = _parse_ccbill_ip_ranges(raw)
    if not parsed:
        _CCBILL_IP_RANGE_CACHE = [
            (ipaddress.ip_address(a), ipaddress.ip_address(b)) for a, b in _DEFAULT_CCBILL_WEBHOOK_IP_RANGES
        ]
        return _CCBILL_IP_RANGE_CACHE
    _CCBILL_IP_RANGE_CACHE = parsed
    return _CCBILL_IP_RANGE_CACHE


def verify_ccbill_webhook_signature(raw_body: bytes, signature_header: str) -> bool:
    secret = _webhook_signature_secret_for_mode(ccbill_webhook_verify_mode())
    if not secret:
        return False
    if not signature_header:
        return False
    sig = signature_header.strip()
    if "=" in sig:
        _, sig = sig.split("=", 1)
        sig = sig.strip()
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, sig)


def ccbill_webhook_verify_mode() -> str:
    raw_mode = (S.ccbill_webhook_verify_mode or "").strip().lower()
    if raw_mode in {"ip+sig", "sig_only", "local"}:
        return raw_mode
    return "local" if S.dev_mode else "ip+sig"


def _webhook_signature_secret_for_mode(mode: str) -> str:
    secret = (S.ccbill_webhook_signature_secret or "").strip()
    if secret:
        return secret
    if mode == "local":
        return "local-ccbill-webhook-secret"
    return ""


def _billing_sk(kind: str, identifier: str) -> str:
    return f"{kind}#{identifier}"


def ensure_balance_row(user_sub: str) -> None:
    ensure_balance_row_for_key(T.billing, "pk", user_sub, S.default_currency)


def apply_balance_delta(user_sub: str, delta: Dict[str, int]) -> None:
    apply_balance_delta_for_key(T.billing, "pk", user_sub, delta, currency=S.default_currency)


def compute_due(balance_item: Dict[str, Any]) -> Dict[str, int]:
    return compute_due_shared(balance_item)


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
    provider: str = "ccbill",
) -> Tuple[str, Dict[str, Any]]:
    # GAP-0203 / FIN-013: persist provider so the platform financial dashboard
    # provider breakdown attributes CCBill ledger entries correctly.
    extra: Dict[str, Any] = {"provider": provider}
    if ccbill_payment_token_id:
        extra["ccbill_payment_token_id"] = ccbill_payment_token_id
    if ccbill_transaction_id:
        extra["ccbill_transaction_id"] = ccbill_transaction_id
    if ccbill_subscription_id:
        extra["ccbill_subscription_id"] = ccbill_subscription_id
    return new_ledger_entry_shared(
        key_name="pk",
        key_value=user_sub,
        entry_type=entry_type,
        amount_cents=amount_cents,
        state=state,
        reason=reason,
        meta=meta,
        extra=extra or None,
    )


def settle_or_reverse_ledger(user_sub: str, ledger_sk_value: str, new_state: str) -> None:
    settle_or_reverse_ledger_shared(T.billing, "pk", user_sub, ledger_sk_value, new_state)


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
    purchase_txn_id: Optional[str] = None,
) -> None:
    item = {
        "pk": user_sub,
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
    if purchase_txn_id:
        item["purchase_txn_id"] = purchase_txn_id
    if raw:
        item["raw"] = _sanitize_ccbill_raw(raw)
    T.billing.put_item(Item=item)


def update_payment_status(user_sub: str, transaction_id: str, status: str, raw: Optional[Dict[str, Any]] = None) -> None:
    names = {"#st": "status", "#u": "updated_at"}
    values: Dict[str, Any] = {":st": status, ":u": now_ts()}
    sets = ["#st = :st", "#u = :u"]
    if raw is not None:
        names["#r"] = "raw"
        values[":r"] = _sanitize_ccbill_raw(raw)
        sets.append("#r = :r")
    T.billing.update_item(
        Key={"pk": user_sub, "sk": _billing_sk("PAY", transaction_id)},
        UpdateExpression="SET " + ", ".join(sets),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def _parse_ccbill_date(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value)
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y%m%d"):
        try:
            parsed = datetime.strptime(text, fmt)
            return int(parsed.replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue
    try:
        if text.endswith("Z"):
            text = text.replace("Z", "+00:00")
        return int(datetime.fromisoformat(text).timestamp())
    except ValueError:
        return None


def renewal_fields(status: str, cancel_at_period_end: Optional[bool] = None) -> Tuple[bool, str, bool]:
    status_lower = (status or "").lower()
    if cancel_at_period_end:
        return False, "cancel_at_period_end", True
    if status_lower in ("canceling",):
        return False, "cancel_at_period_end", True
    if status_lower in ("canceled", "cancelled", "expired", "suspended", "failed"):
        return False, "manual", False
    return True, "auto", False


def upsert_subscription(
    user_sub: str,
    subscription_id: str,
    *,
    status: str,
    plan_id: str,
    payment_token_id: Optional[str] = None,
    next_renewal_date: Optional[str] = None,
    last_transaction_id: Optional[str] = None,
    current_period_end: Optional[int] = None,
    auto_renew: Optional[bool] = None,
    renewal_policy: Optional[str] = None,
    cancel_at_period_end: Optional[bool] = None,
    trial_start: Optional[int] = None,
    trial_end: Optional[int] = None,
    proration_policy: Optional[str] = None,
    price_cents: Optional[int] = None,
    interval: Optional[str] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> None:
    existing = T.billing.get_item(Key={"pk": user_sub, "sk": _billing_sk("SUB", subscription_id)}).get("Item") or {}
    status_lower = (status or "").lower()
    default_cancel_at_period_end = status_lower == "canceling"
    auto_renew_default, renewal_policy_default, cancel_default = renewal_fields(
        status_lower,
        cancel_at_period_end=default_cancel_at_period_end,
    )
    auto_renew_value = auto_renew if auto_renew is not None else existing.get("auto_renew", auto_renew_default)
    renewal_policy_value = renewal_policy or existing.get("renewal_policy") or renewal_policy_default
    cancel_at_period_end_value = (
        cancel_at_period_end
        if cancel_at_period_end is not None
        else existing.get("cancel_at_period_end", cancel_default)
    )
    current_period_end_value = (
        current_period_end
        if current_period_end is not None
        else existing.get("current_period_end") or _parse_ccbill_date(next_renewal_date) or 0
    )
    trial_start_value = trial_start if trial_start is not None else existing.get("trial_start", 0)
    trial_end_value = trial_end if trial_end is not None else existing.get("trial_end", 0)
    proration_policy_value = proration_policy or existing.get("proration_policy") or "full"
    price_cents_value = price_cents if price_cents is not None else existing.get("price_cents", S.default_monthly_price_cents)
    interval_value = interval or existing.get("interval") or "month"
    item = existing or {
        "pk": user_sub,
        "sk": _billing_sk("SUB", subscription_id),
        "subscription_id": subscription_id,
        "created_at": now_ts(),
    }
    item["status"] = status
    item["plan_id"] = plan_id
    item["current_period_end"] = int(current_period_end_value)
    item["auto_renew"] = bool(auto_renew_value)
    item["renewal_policy"] = renewal_policy_value
    item["cancel_at_period_end"] = bool(cancel_at_period_end_value)
    item["trial_start"] = int(trial_start_value)
    item["trial_end"] = int(trial_end_value)
    item["proration_policy"] = proration_policy_value
    item["price_cents"] = int(price_cents_value)
    item["interval"] = interval_value
    item["updated_at"] = now_ts()
    if payment_token_id:
        item["payment_token_id"] = payment_token_id
    if next_renewal_date:
        item["next_renewal_date"] = next_renewal_date
    if last_transaction_id:
        item["last_transaction_id"] = last_transaction_id
    if raw:
        item["raw"] = _sanitize_ccbill_raw(raw)
    T.billing.put_item(Item=item)


def list_payment_methods(user_sub: str) -> List[Dict[str, Any]]:
    resp = T.billing.query(
        KeyConditionExpression="pk = :u AND begins_with(sk, :p)",
        ExpressionAttributeValues={":u": user_sub, ":p": "PM#"},
    )
    return resp.get("Items", [])


def current_default_pm(user_sub: str) -> Optional[str]:
    billing = T.billing.get_item(Key={"pk": user_sub, "sk": "BILLING"}).get("Item") or {}
    return billing.get("default_payment_token_id")


def set_default_pm(user_sub: str, token_id: Optional[str]) -> None:
    existing = T.billing.get_item(Key={"pk": user_sub, "sk": "BILLING"}).get("Item")
    if not existing:
        T.billing.put_item(Item={
            "pk": user_sub,
            "sk": "BILLING",
            "autopay_enabled": False,
            "currency": S.default_currency,
            "default_payment_token_id": token_id,
        })
    else:
        T.billing.update_item(
            Key={"pk": user_sub, "sk": "BILLING"},
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
                "pk": "CCBILL_WEBHOOK",
                "sk": dedupe_key,
                "ts": now_ts(),
                "ttl": now_ts() + 60 * 60 * 24 * 7,
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def webhook_remote_ip_allowed(ip_str: str, *, enforce: bool = False) -> bool:
    if not (enforce or S.ccbill_webhook_ip_enforce):
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    for start, end in _ccbill_ip_ranges():
        if start <= ip <= end:
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
        purchase_txn_id = record_billing_transaction(
            user_sub=user_sub,
            amount_cents=amount,
            currency=S.default_currency,
            description=f"CCBill charge once ({reason})",
            status="COMPLETED",
            external_ref=str(transaction_id or ""),
            metadata={"provider": "ccbill", "payment_token_id": token, "transaction_id": str(transaction_id or "")},
        )
    else:
        apply_balance_delta(user_sub, {"payments_pending_cents": -amount})
        settle_or_reverse_ledger(user_sub, led_sk_value, "reversed")
        status = "failed"
        purchase_txn_id = None

    if transaction_id:
        put_payment_record(
            user_sub=user_sub,
            transaction_id=str(transaction_id),
            amount_cents=amount,
            kind="one_time",
            status=status,
            ledger_sk_value=led_sk_value,
            payment_token_id=token,
            purchase_txn_id=purchase_txn_id,
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
        purchase_txn_id = record_billing_transaction(
            user_sub=user_sub,
            amount_cents=monthly_cents,
            currency=S.default_currency,
            description="CCBill subscription signup",
            status="COMPLETED",
            external_ref=str(transaction_id or ""),
            metadata={
                "provider": "ccbill",
                "payment_token_id": token,
                "transaction_id": str(transaction_id or ""),
                "subscription_id": str(subscription_id or ""),
                "plan_id": plan_id,
            },
        )
    else:
        apply_balance_delta(user_sub, {"payments_pending_cents": -monthly_cents})
        settle_or_reverse_ledger(user_sub, led_sk_value, "reversed")
        pay_status = "failed"
        sub_status = "failed"
        purchase_txn_id = None

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
            purchase_txn_id=purchase_txn_id,
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
    bal = T.billing.get_item(Key={"pk": user_sub, "sk": "BALANCE"}).get("Item") or {}
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
    billing = T.billing.get_item(Key={"pk": user_sub, "sk": "BILLING"}).get("Item") or {}
    token = billing.get("default_payment_token_id")
    if not token:
        raise HTTPException(400, "No default payment method set")
    return token
