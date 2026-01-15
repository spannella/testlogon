import os
import time
import json
import secrets
import hashlib
import ipaddress
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional, List, Dict, Any, Tuple

import boto3
from botocore.exceptions import ClientError
import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

# ============================================================
# Config
# ============================================================
DDB_TABLE = os.environ["DDB_TABLE"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# CCBill RESTful API
CCBILL_BASE_URL = os.environ.get("CCBILL_BASE_URL", "https://api.ccbill.com").rstrip("/")
CCBILL_ACCEPT = os.environ.get(
    "CCBILL_ACCEPT",
    "application/vnd.mcn.transaction-service.api.v.2+json"
)

# OAuth credentials
CCBILL_FRONTEND_CLIENT_ID = os.environ["CCBILL_FRONTEND_CLIENT_ID"]
CCBILL_FRONTEND_CLIENT_SECRET = os.environ["CCBILL_FRONTEND_CLIENT_SECRET"]
CCBILL_BACKEND_CLIENT_ID = os.environ["CCBILL_BACKEND_CLIENT_ID"]
CCBILL_BACKEND_CLIENT_SECRET = os.environ["CCBILL_BACKEND_CLIENT_SECRET"]

# Routing / merchant account
CCBILL_CLIENT_ACCNUM = int(os.environ["CCBILL_CLIENT_ACCNUM"])
CCBILL_CLIENT_SUBACC = int(os.environ.get("CCBILL_CLIENT_SUBACC", "0"))

# Default monthly subscription price (cents) for /subscribe unless overridden per request
DEFAULT_MONTHLY_PRICE_CENTS = int(os.environ.get("DEFAULT_MONTHLY_PRICE_CENTS", "999"))  # $9.99
DEFAULT_CURRENCY_CODE = int(os.environ.get("DEFAULT_CURRENCY_CODE", "840"))  # 840 = USD
DEFAULT_CURRENCY = os.environ.get("DEFAULT_CURRENCY", "usd")

# Webhook security
CCBILL_WEBHOOK_IP_ENFORCE = os.environ.get("CCBILL_WEBHOOK_IP_ENFORCE", "false").lower() == "true"
CCBILL_WEBHOOK_IP_RANGES = [
    # Documented CCBill ranges; you may want to keep these in env/config.
    ("64.38.212.0", "64.38.212.255"),
    ("64.38.215.0", "64.38.215.255"),
    ("64.38.240.0", "64.38.240.255"),
    ("64.38.241.0", "64.38.241.255"),
]

ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
tbl = ddb.Table(DDB_TABLE)

app = FastAPI(title="Billing Backend (Ledger + CCBill Tokens)")

# ============================================================
# Helpers
# ============================================================
def now_ts() -> int:
    return int(time.time())

def ulidish() -> str:
    return f"{int(time.time() * 1000)}_{secrets.token_hex(8)}"

def user_pk(user_id: str) -> str:
    return f"USER#{user_id}"

# ---------- DynamoDB wrappers ----------
def ddb_get(pk: str, sk: str) -> Optional[Dict[str, Any]]:
    resp = tbl.get_item(Key={"pk": pk, "sk": sk})
    return resp.get("Item")

def ddb_put(item: Dict[str, Any], *, condition_expression: Optional[str] = None) -> None:
    kwargs = {"Item": item}
    if condition_expression:
        kwargs["ConditionExpression"] = condition_expression
    tbl.put_item(**kwargs)

def ddb_del(pk: str, sk: str) -> None:
    tbl.delete_item(Key={"pk": pk, "sk": sk})

def ddb_query_pk(pk: str) -> List[Dict[str, Any]]:
    resp = tbl.query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": pk},
    )
    return resp.get("Items", [])

def ddb_update(pk: str, sk: str, expr: str, values: Dict[str, Any], names: Optional[Dict[str, str]] = None) -> None:
    kwargs = {
        "Key": {"pk": pk, "sk": sk},
        "UpdateExpression": expr,
        "ExpressionAttributeValues": values,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    tbl.update_item(**kwargs)

# ---------- Auth assumption ----------
def require_user(x_user_id: Optional[str]) -> str:
    if not x_user_id:
        raise HTTPException(401, "Missing X-User-Id (login assumed handled)")
    return x_user_id

# ============================================================
# Balance snapshot (same semantics as your Stripe server)
# ============================================================
BAL_FIELDS = [
    "owed_pending_cents",
    "owed_settled_cents",
    "payments_pending_cents",
    "payments_settled_cents",
]

def ensure_balance_row(pk: str) -> None:
    if not ddb_get(pk, "BALANCE"):
        ddb_put({
            "pk": pk, "sk": "BALANCE",
            "currency": DEFAULT_CURRENCY,
            **{k: 0 for k in BAL_FIELDS},
            "updated_at": now_ts(),
        })

def apply_balance_delta(pk: str, delta: Dict[str, int]) -> None:
    ensure_balance_row(pk)
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

# ============================================================
# Ledger
# ============================================================
def ledger_sk(ts: int, entry_id: str) -> str:
    return f"LEDGER#{ts}#{entry_id}"

def new_ledger_entry(
    user_id: str,
    entry_type: str,          # "debit" | "credit" | "adjustment"
    amount_cents: int,
    state: str,               # "pending" | "settled" | "reversed"
    reason: str,
    ccbill_payment_token_id: Optional[str] = None,
    ccbill_transaction_id: Optional[str] = None,
    ccbill_subscription_id: Optional[str] = None,
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
    if ccbill_payment_token_id:
        item["ccbill_payment_token_id"] = ccbill_payment_token_id
    if ccbill_transaction_id:
        item["ccbill_transaction_id"] = ccbill_transaction_id
    if ccbill_subscription_id:
        item["ccbill_subscription_id"] = ccbill_subscription_id
    if meta:
        item["meta"] = meta
    return sk, item

def settle_or_reverse_ledger(user_id: str, ledger_sk_value: str, new_state: str) -> None:
    ddb_update(user_pk(user_id), ledger_sk_value, "SET #s = :s", {":s": new_state}, names={"#s": "state"})

# ============================================================
# Payment + Subscription records
# ============================================================
def pay_sk(transaction_id: str) -> str:
    return f"PAY#{transaction_id}"

def sub_sk(subscription_id: str) -> str:
    return f"SUB#{subscription_id}"

def put_payment_record(
    user_id: str,
    transaction_id: str,
    amount_cents: int,
    kind: str,  # "one_time" | "subscription_signup" | "subscription_rebill"
    status: str,
    ledger_sk_value: Optional[str],
    payment_token_id: Optional[str] = None,
    subscription_id: Optional[str] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> None:
    pk = user_pk(user_id)
    item = {
        "pk": pk,
        "sk": pay_sk(transaction_id),
        "transaction_id": transaction_id,
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

def update_payment_status(user_id: str, transaction_id: str, status: str, raw: Optional[Dict[str, Any]] = None) -> None:
    pk = user_pk(user_id)
    names = {"#st": "status", "#u": "updated_at"}
    values: Dict[str, Any] = {":st": status, ":u": now_ts()}
    sets = ["#st = :st", "#u = :u"]
    if raw is not None:
        names["#r"] = "raw"
        values[":r"] = raw
        sets.append("#r = :r")
    ddb_update(pk, pay_sk(transaction_id), "SET " + ", ".join(sets), values, names=names)

def upsert_subscription(
    user_id: str,
    subscription_id: str,
    *,
    status: str,
    plan_id: str,
    payment_token_id: Optional[str] = None,
    next_renewal_date: Optional[str] = None,
    last_transaction_id: Optional[str] = None,
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
    if next_renewal_date:
        item["next_renewal_date"] = next_renewal_date
    if last_transaction_id:
        item["last_transaction_id"] = last_transaction_id
    if raw:
        item["raw"] = raw
    ddb_put(item)

# ============================================================
# Payment methods (store paymentTokenId)
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
        ddb_put({"pk": pk, "sk": "BILLING", "autopay_enabled": False, "currency": DEFAULT_CURRENCY, "default_payment_token_id": token_id})
    else:
        ddb_update(pk, "BILLING", "SET default_payment_token_id = :t", {":t": token_id})

# ============================================================
# CCBill OAuth (simple in-memory cache)
# ============================================================
_OAUTH_CACHE: Dict[str, Tuple[str, int]] = {}

def _oauth_token(client_id: str, client_secret: str, cache_key: str) -> str:
    tok, exp = _OAUTH_CACHE.get(cache_key, ("", 0))
    if tok and exp > now_ts() + 30:
        return tok

    url = f"{CCBILL_BASE_URL}/ccbill-auth/oauth/token?grant_type=client_credentials"
    r = requests.post(
        url,
        auth=(client_id, client_secret),
        headers={
            "Accept": CCBILL_ACCEPT,
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
    return _oauth_token(CCBILL_FRONTEND_CLIENT_ID, CCBILL_FRONTEND_CLIENT_SECRET, "frontend")

def ccbill_backend_oauth() -> str:
    return _oauth_token(CCBILL_BACKEND_CLIENT_ID, CCBILL_BACKEND_CLIENT_SECRET, "backend")

# ============================================================
# CCBill charge helpers
# ============================================================
def _cents_to_dollars(cents: int) -> float:
    # Avoid float surprises by rounding to 2 decimals explicitly
    d = (Decimal(cents) / Decimal(100)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return float(d)

def _get_origin_ip(req: Request) -> str:
    # Prefer first XFF value, else remote addr
    xff = (req.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if xff:
        return xff
    return req.client.host if req.client else "0.0.0.0"

def ccbill_charge_payment_token(
    *,
    payment_token_id: str,
    origin_ip: str,
    initial_price_cents: int,
    initial_period_days: int,
    recurring_price_cents: Optional[int] = None,
    recurring_period_days: Optional[int] = None,
    currency_code: int = DEFAULT_CURRENCY_CODE,
    extra: Optional[Dict[str, Any]] = None,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Charges a payment token. If recurring_* is supplied, creates a subscription (rebills).
    """
    access = ccbill_backend_oauth()
    url = f"{CCBILL_BASE_URL}/transactions/payment-tokens/{payment_token_id}"

    payload: Dict[str, Any] = {
        "clientAccnum": CCBILL_CLIENT_ACCNUM,
        "clientSubacc": CCBILL_CLIENT_SUBACC,
        "initialPrice": _cents_to_dollars(int(initial_price_cents)),
        "initialPeriod": int(initial_period_days),
        "currencyCode": int(currency_code),
        "ipAddress": origin_ip,
    }
    if recurring_price_cents is not None and recurring_period_days is not None:
        payload["recurringPrice"] = _cents_to_dollars(int(recurring_price_cents))
        payload["recurringPeriod"] = int(recurring_period_days)

    if extra:
        # Useful for pass-through fields if your integration supports it; safe to ignore otherwise.
        payload.update(extra)

    headers = {
        "Authorization": f"Bearer {access}",
        "Accept": CCBILL_ACCEPT,
        "Content-Type": "application/json",
        "X-Origin-IP": origin_ip,
    }
    if idempotency_key:
        # Not guaranteed CCBill honors this header, but it's harmless and helps proxies/logging.
        headers["Idempotency-Key"] = idempotency_key

    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=20)
    if r.status_code != 200:
        raise HTTPException(502, f"CCBill charge failed: {r.status_code} {r.text}")
    return r.json()

# ============================================================
# Webhook security + dedupe
# ============================================================
def _ip_in_ranges(ip_str: str, ranges: List[Tuple[str, str]]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    for a, b in ranges:
        if ipaddress.ip_address(a) <= ip <= ipaddress.ip_address(b):
            return True
    return False

def mark_webhook_processed(dedupe_key: str) -> bool:
    """
    Returns True if newly marked, False if already seen.
    """
    try:
        ddb_put(
            {"pk": "CCBILL_WEBHOOK", "sk": dedupe_key, "ts": now_ts(), "ttl": now_ts() + 60 * 60 * 24 * 7},
            condition_expression="attribute_not_exists(pk)",
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise

# ============================================================
# Models
# ============================================================
class PaymentMethodOut(BaseModel):
    payment_token_id: str
    label: Optional[str] = None
    priority: int

class SavePaymentTokenIn(BaseModel):
    payment_token_id: str
    label: Optional[str] = None
    make_default: bool = True

class SetPriorityIn(BaseModel):
    payment_token_id: str
    priority: int = Field(ge=0, le=100000)

class SetDefaultIn(BaseModel):
    payment_token_id: str

class SetAutopayIn(BaseModel):
    enabled: bool

class PayBalanceIn(BaseModel):
    amount_cents: Optional[int] = Field(default=None, ge=1)
    idempotency_key: Optional[str] = None

class OneTimeChargeIn(BaseModel):
    amount_cents: int = Field(ge=1)
    payment_token_id: Optional[str] = None  # if omitted, uses default
    idempotency_key: Optional[str] = None
    reason: str = "one_time_charge"

class SubscribeMonthlyIn(BaseModel):
    plan_id: str = "monthly"
    monthly_price_cents: Optional[int] = Field(default=None, ge=1)
    payment_token_id: Optional[str] = None  # if omitted, uses default
    idempotency_key: Optional[str] = None

class AddChargeIn(BaseModel):
    amount_cents: int = Field(ge=1)
    state: str = Field(pattern="^(pending|settled)$")
    reason: str = "usage"

# ============================================================
# Minimal UI placeholder
# ============================================================
@app.get("/", response_class=HTMLResponse)
def index():
    return """<!doctype html>
<html><head><meta charset="utf-8"/><title>Billing (CCBill)</title></head>
<body style="font-family:system-ui;margin:24px;max-width:900px">
<h2>Billing (CCBill)</h2>
<p>This backend provides ledger + subscription + one-time charging using stored CCBill payment tokens.</p>
</body></html>"""

# ============================================================
# Config + settings + balances
# ============================================================
@app.get("/api/billing/config")
def billing_config():
    return {
        "ccbill_base_url": CCBILL_BASE_URL,
        "ccbill_accept": CCBILL_ACCEPT,
        "clientAccnum": CCBILL_CLIENT_ACCNUM,
        "clientSubacc": CCBILL_CLIENT_SUBACC,
        "default_currency": DEFAULT_CURRENCY,
        "default_currency_code": DEFAULT_CURRENCY_CODE,
        "default_monthly_price_cents": DEFAULT_MONTHLY_PRICE_CENTS,
    }

@app.post("/api/billing/ccbill/frontend-oauth")
def get_frontend_oauth(x_user_id: Optional[str] = Header(default=None)):
    _ = require_user(x_user_id)
    return {"access_token": ccbill_frontend_oauth()}

@app.get("/api/billing/settings")
def get_settings(x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)
    return ddb_get(pk, "BILLING") or {"autopay_enabled": False, "currency": DEFAULT_CURRENCY, "default_payment_token_id": None}

@app.post("/api/billing/autopay")
def set_autopay(body: SetAutopayIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)
    if not ddb_get(pk, "BILLING"):
        ddb_put({"pk": pk, "sk": "BILLING", "autopay_enabled": False, "currency": DEFAULT_CURRENCY, "default_payment_token_id": None})
    ddb_update(pk, "BILLING", "SET autopay_enabled = :e", {":e": bool(body.enabled)})
    return {"ok": True}

@app.get("/api/billing/balance")
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
# Payment methods: store tokens + priority/default/remove
# ============================================================
@app.post("/api/billing/payment-methods/ccbill-token")
def save_payment_token(body: SavePaymentTokenIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)

    existing = list_payment_methods_ddb(user_id)
    next_priority = 0 if not existing else (max(int(x.get("priority", 0)) for x in existing) + 1)

    ddb_put({
        "pk": pk,
        "sk": pm_sk(body.payment_token_id),
        "payment_token_id": body.payment_token_id,
        "label": body.label,
        "priority": next_priority,
        "created_at": now_ts(),
    })

    if body.make_default or not current_default_pm(user_id):
        set_default_pm(user_id, body.payment_token_id)

    return {"ok": True}

@app.get("/api/billing/payment-methods", response_model=List[PaymentMethodOut])
def list_payment_methods(x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pms = list_payment_methods_ddb(user_id)
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

@app.post("/api/billing/payment-methods/priority")
def set_priority(body: SetPriorityIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)
    sk = pm_sk(body.payment_token_id)
    if not ddb_get(pk, sk):
        raise HTTPException(404, "Payment method not found")
    ddb_update(pk, sk, "SET priority = :p", {":p": int(body.priority)})
    return {"ok": True}

@app.post("/api/billing/payment-methods/default")
def set_default(body: SetDefaultIn, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)
    if not ddb_get(pk, pm_sk(body.payment_token_id)):
        raise HTTPException(404, "Payment method not found")
    set_default_pm(user_id, body.payment_token_id)
    return {"ok": True}

@app.delete("/api/billing/payment-methods/{payment_token_id}")
def remove_payment_method(payment_token_id: str, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)
    sk = pm_sk(payment_token_id)
    if not ddb_get(pk, sk):
        raise HTTPException(404, "Payment method not found")

    ddb_del(pk, sk)

    if current_default_pm(user_id) == payment_token_id:
        remaining = list_payment_methods_ddb(user_id)
        remaining.sort(key=lambda x: int(x.get("priority", 0)))
        set_default_pm(user_id, remaining[0]["payment_token_id"] if remaining else None)

    return {"ok": True}

# ============================================================
# One-time charges + Pay Balance (ledger-first)
# ============================================================
def _get_default_token_or_400(user_id: str) -> str:
    pk = user_pk(user_id)
    billing = ddb_get(pk, "BILLING") or {}
    token = billing.get("default_payment_token_id")
    if not token:
        raise HTTPException(400, "No default payment method set")
    return token

@app.post("/api/billing/charge-once")
async def charge_once(body: OneTimeChargeIn, request: Request, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)

    token = body.payment_token_id or _get_default_token_or_400(user_id)
    amount = int(body.amount_cents)
    origin_ip = _get_origin_ip(request)
    idem = body.idempotency_key or f"chargeonce:{user_id}:{token}:{amount}:{int(time.time()/30)}"

    # ledger: pending credit now; settle/reverse based on immediate approval + webhook later
    led_sk_value, led_item = new_ledger_entry(
        user_id=user_id,
        entry_type="credit",
        amount_cents=amount,
        state="pending",
        reason=body.reason,
        ccbill_payment_token_id=token,
        meta={"idempotency_key": idem, "mode": "one_time"},
    )
    ddb_put(led_item)
    apply_balance_delta(pk, {"payments_pending_cents": amount})

    resp = ccbill_charge_payment_token(
        payment_token_id=token,
        origin_ip=origin_ip,
        initial_price_cents=amount,
        initial_period_days=1,     # 1-day "period" for one-time style
        recurring_price_cents=None,
        recurring_period_days=None,
        idempotency_key=idem,
    )

    approved = bool(resp.get("approved"))
    transaction_id = resp.get("transactionId") or resp.get("paymentUniqueId") or resp.get("transaction_id")

    if approved:
        apply_balance_delta(pk, {"payments_pending_cents": -amount, "payments_settled_cents": amount})
        settle_or_reverse_ledger(user_id, led_sk_value, "settled")
        status = "succeeded"
    else:
        apply_balance_delta(pk, {"payments_pending_cents": -amount})
        settle_or_reverse_ledger(user_id, led_sk_value, "reversed")
        status = "failed"

    if transaction_id:
        put_payment_record(
            user_id=user_id,
            transaction_id=str(transaction_id),
            amount_cents=amount,
            kind="one_time",
            status=status,
            ledger_sk_value=led_sk_value,
            payment_token_id=token,
            raw=resp,
        )

    return {"approved": approved, "transaction_id": transaction_id, "response": resp}

@app.post("/api/billing/pay-balance")
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
    origin_ip = _get_origin_ip(request)
    idem = body.idempotency_key or f"paybalance:{user_id}:{token}:{amount}:{int(time.time()/30)}"

    # Just call charge-once semantics
    ot = OneTimeChargeIn(amount_cents=amount, payment_token_id=token, idempotency_key=idem, reason="pay_balance")
    return await charge_once(ot, request, x_user_id=x_user_id)

# ============================================================
# Monthly subscription start
# ============================================================
@app.post("/api/billing/subscribe-monthly")
async def subscribe_monthly(body: SubscribeMonthlyIn, request: Request, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    pk = user_pk(user_id)

    token = body.payment_token_id or _get_default_token_or_400(user_id)
    monthly_cents = int(body.monthly_price_cents or DEFAULT_MONTHLY_PRICE_CENTS)
    origin_ip = _get_origin_ip(request)
    idem = body.idempotency_key or f"subscribe:{user_id}:{token}:{monthly_cents}:{int(time.time()/300)}"

    # Create a pending ledger entry for the signup payment
    led_sk_value, led_item = new_ledger_entry(
        user_id=user_id,
        entry_type="credit",
        amount_cents=monthly_cents,
        state="pending",
        reason="subscription_signup",
        ccbill_payment_token_id=token,
        meta={"idempotency_key": idem, "plan_id": body.plan_id, "mode": "subscription"},
    )
    ddb_put(led_item)
    apply_balance_delta(pk, {"payments_pending_cents": monthly_cents})

    # Create subscription by charging token with recurring terms (30-day month)
    resp = ccbill_charge_payment_token(
        payment_token_id=token,
        origin_ip=origin_ip,
        initial_price_cents=monthly_cents,
        initial_period_days=30,
        recurring_price_cents=monthly_cents,
        recurring_period_days=30,
        idempotency_key=idem,
        extra={
            # If your flow supports pass-through vars that return in webhooks, these help correlate.
            # Some integrations use X- prefixed passthrough keys in hosted flows; harmless here.
            "X-app_user_id": user_id,
            "X-ledger_sk": led_sk_value,
            "X-plan_id": body.plan_id,
        },
    )

    approved = bool(resp.get("approved"))
    transaction_id = resp.get("transactionId") or resp.get("paymentUniqueId") or resp.get("transaction_id")
    subscription_id = resp.get("subscriptionId") or resp.get("subscription_id")

    if approved:
        apply_balance_delta(pk, {"payments_pending_cents": -monthly_cents, "payments_settled_cents": monthly_cents})
        settle_or_reverse_ledger(user_id, led_sk_value, "settled")
        pay_status = "succeeded"
        sub_status = "active"
    else:
        apply_balance_delta(pk, {"payments_pending_cents": -monthly_cents})
        settle_or_reverse_ledger(user_id, led_sk_value, "reversed")
        pay_status = "failed"
        sub_status = "failed"

    if transaction_id:
        put_payment_record(
            user_id=user_id,
            transaction_id=str(transaction_id),
            amount_cents=monthly_cents,
            kind="subscription_signup",
            status=pay_status,
            ledger_sk_value=led_sk_value,
            payment_token_id=token,
            subscription_id=str(subscription_id) if subscription_id else None,
            raw=resp,
        )

    # If subscription_id is known immediately, store it. If not, webhooks will later.
    if subscription_id:
        upsert_subscription(
            user_id=user_id,
            subscription_id=str(subscription_id),
            status=sub_status,
            plan_id=body.plan_id,
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

# ============================================================
# OPTIONAL: add charges to user's balance (your app debits)
# ============================================================
@app.post("/api/billing/_dev/add-charge")
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
@app.get("/api/billing/ledger")
def list_ledger(x_user_id: Optional[str] = Header(default=None), limit: int = 50):
    user_id = require_user(x_user_id)
    items = ddb_query_pk(user_pk(user_id))
    led = [it for it in items if it["sk"].startswith("LEDGER#")]
    led.sort(key=lambda x: x.get("ts", 0), reverse=True)
    return {"items": led[: max(1, min(limit, 200))]}

@app.get("/api/billing/payments")
def list_payments(x_user_id: Optional[str] = Header(default=None), limit: int = 50):
    user_id = require_user(x_user_id)
    items = ddb_query_pk(user_pk(user_id))
    pays = [it for it in items if it["sk"].startswith("PAY#")]
    pays.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return {"items": pays[: max(1, min(limit, 200))]}

@app.get("/api/billing/subscriptions")
def list_subscriptions(x_user_id: Optional[str] = Header(default=None), limit: int = 50):
    user_id = require_user(x_user_id)
    items = ddb_query_pk(user_pk(user_id))
    subs = [it for it in items if it["sk"].startswith("SUB#")]
    subs.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return {"items": subs[: max(1, min(limit, 200))]}

# ============================================================
# CCBill Webhook handler
# ============================================================
@app.post("/api/ccbill/webhook")
async def ccbill_webhook(req: Request):
    # Optional IP enforcement
    if CCBILL_WEBHOOK_IP_ENFORCE:
        remote_ip = _get_origin_ip(req)
        if not _ip_in_ranges(remote_ip, CCBILL_WEBHOOK_IP_RANGES):
            raise HTTPException(403, "Forbidden")

    # eventType is in URL params for CCBill webhooks
    q = dict(req.query_params)
    event_type = q.get("eventType", "")

    raw_body = await req.body()
    dedupe_key = hashlib.sha256((event_type + "|").encode("utf-8") + raw_body).hexdigest()
    if not mark_webhook_processed(dedupe_key):
        return {"received": True, "deduped": True}

    # Parse payload (json or urlencoded form)
    ct = (req.headers.get("content-type") or "").lower()
    payload: Dict[str, Any] = {}
    if "application/json" in ct:
        try:
            payload = json.loads(raw_body.decode("utf-8") or "{}")
        except Exception:
            payload = {}
    else:
        form = await req.form()
        payload = dict(form)

    # Correlate user: prefer explicit pass-through key
    # You should configure your flow so X-app_user_id is present.
    user_id = payload.get("X-app_user_id") or payload.get("X_app_user_id") or payload.get("X-user-id") or payload.get("X_user_id")
    transaction_id = payload.get("transactionId") or payload.get("transaction_id")
    subscription_id = payload.get("subscriptionId") or payload.get("subscription_id")
    plan_id = payload.get("X-plan_id") or payload.get("X_plan_id") or "monthly"
    ledger_sk_hint = payload.get("X-ledger_sk") or payload.get("X_ledger_sk")

    if not user_id:
        # Store unmatched webhook for later reconciliation
        ddb_put({
            "pk": "CCBILL_WEBHOOK_UNMATCHED",
            "sk": f"{now_ts()}#{dedupe_key}",
            "eventType": event_type,
            "q": q,
            "payload": payload,
            "created_at": now_ts(),
        })
        return {"received": True, "unmatched": True}

    user_id = str(user_id)
    pk = user_pk(user_id)
    ensure_balance_row(pk)

    def _try_find_pay_and_ledger(tid: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        if not tid:
            return None, None
        pay = ddb_get(pk, pay_sk(str(tid)))
        return pay, (pay.get("ledger_sk") if pay else None)

    # Amounts for rebills show up as billedAmount (string dollars) in RenewalSuccess; other events vary.
    def _dollars_str_to_cents(s: Optional[str]) -> Optional[int]:
        if not s:
            return None
        try:
            d = Decimal(str(s)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            return int(d * 100)
        except Exception:
            return None

    # --- New sale (subscription signup)
    if event_type == "NewSaleSuccess":
        # If we have a payment record, use its amount/ledger. Else create a fresh settled credit.
        pay, led_sk_value = _try_find_pay_and_ledger(transaction_id)
        amount = int(pay["amount_cents"]) if pay else (_dollars_str_to_cents(payload.get("initialPrice")) or DEFAULT_MONTHLY_PRICE_CENTS)

        if led_sk_value:
            # if our internal record still says "pending", move pending->settled
            if pay and pay.get("status") in ("pending", "processing", "requires_action"):
                apply_balance_delta(pk, {"payments_pending_cents": -amount, "payments_settled_cents": amount})
            settle_or_reverse_ledger(user_id, led_sk_value, "settled")
            if transaction_id:
                update_payment_status(user_id, str(transaction_id), "succeeded", raw={"eventType": event_type, "payload": payload, "q": q})
        else:
            # create a new settled credit (external-only)
            led_sk_value2, led_item = new_ledger_entry(
                user_id=user_id,
                entry_type="credit",
                amount_cents=amount,
                state="settled",
                reason="subscription_signup_webhook",
                ccbill_transaction_id=str(transaction_id) if transaction_id else None,
                ccbill_subscription_id=str(subscription_id) if subscription_id else None,
                meta={"eventType": event_type, "q": q, "payload": payload},
            )
            ddb_put(led_item)
            apply_balance_delta(pk, {"payments_settled_cents": amount})
            if transaction_id:
                put_payment_record(
                    user_id=user_id,
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
                user_id=user_id,
                subscription_id=str(subscription_id),
                status="active",
                plan_id=plan_id,
                next_renewal_date=payload.get("nextRenewalDate"),
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw={"eventType": event_type, "payload": payload, "q": q},
            )

    elif event_type == "NewSaleFailure":
        # Reverse pending if we can find it
        pay, led_sk_value = _try_find_pay_and_ledger(transaction_id)
        if pay and led_sk_value:
            amount = int(pay.get("amount_cents", 0))
            if pay.get("status") in ("pending", "processing", "requires_action"):
                apply_balance_delta(pk, {"payments_pending_cents": -amount})
            settle_or_reverse_ledger(user_id, led_sk_value, "reversed")
            update_payment_status(user_id, str(transaction_id), "failed", raw={"eventType": event_type, "payload": payload, "q": q})
        if subscription_id:
            upsert_subscription(user_id, str(subscription_id), status="failed", plan_id=plan_id, raw={"eventType": event_type, "payload": payload, "q": q})

    # --- Renewal (rebill)
    elif event_type == "RenewalSuccess":
        # billedAmount is a string like "4.95"
        billed_cents = _dollars_str_to_cents(payload.get("billedAmount")) or DEFAULT_MONTHLY_PRICE_CENTS
        # Always record a settled credit for successful rebill
        led_sk_value2, led_item = new_ledger_entry(
            user_id=user_id,
            entry_type="credit",
            amount_cents=billed_cents,
            state="settled",
            reason="subscription_rebill",
            ccbill_transaction_id=str(transaction_id) if transaction_id else None,
            ccbill_subscription_id=str(subscription_id) if subscription_id else None,
            meta={"eventType": event_type, "q": q, "payload": payload},
        )
        ddb_put(led_item)
        apply_balance_delta(pk, {"payments_settled_cents": billed_cents})

        if transaction_id:
            put_payment_record(
                user_id=user_id,
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
                user_id=user_id,
                subscription_id=str(subscription_id),
                status="active",
                plan_id=plan_id,
                next_renewal_date=payload.get("nextRenewalDate"),
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw={"eventType": event_type, "payload": payload, "q": q},
            )

    elif event_type == "RenewalFailure":
        # Mark subscription past_due; you can also notify user to add a new token.
        if subscription_id:
            upsert_subscription(
                user_id=user_id,
                subscription_id=str(subscription_id),
                status="past_due",
                plan_id=plan_id,
                next_renewal_date=payload.get("nextRenewalDate"),
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw={"eventType": event_type, "payload": payload, "q": q},
            )

    # --- Cancellation / lifecycle
    elif event_type == "Cancellation":
        if subscription_id:
            upsert_subscription(
                user_id=user_id,
                subscription_id=str(subscription_id),
                status="canceled",
                plan_id=plan_id,
                last_transaction_id=str(transaction_id) if transaction_id else None,
                raw={"eventType": event_type, "payload": payload, "q": q},
            )

    # --- Risk / reversals
    elif event_type in ("Chargeback", "Refund", "Void", "Return"):
        # Conservative default: create a settled debit adjustment (user owes again)
        # If you want to reverse a specific prior payment instead, add mapping by transactionId here.
        amount = _dollars_str_to_cents(payload.get("billedAmount")) or 0
        led_sk_value2, led_item = new_ledger_entry(
            user_id=user_id,
            entry_type="adjustment",
            amount_cents=amount,
            state="settled",
            reason=event_type.lower(),
            ccbill_transaction_id=str(transaction_id) if transaction_id else None,
            ccbill_subscription_id=str(subscription_id) if subscription_id else None,
            meta={"eventType": event_type, "q": q, "payload": payload},
        )
        ddb_put(led_item)
        if amount:
            apply_balance_delta(pk, {"owed_settled_cents": amount})

    else:
        # Unknown/unhandled event types: store raw
        ddb_put({
            "pk": "CCBILL_WEBHOOK_OTHER",
            "sk": f"{now_ts()}#{dedupe_key}",
            "eventType": event_type,
            "q": q,
            "payload": payload,
            "created_at": now_ts(),
        })

    return {"received": True}

