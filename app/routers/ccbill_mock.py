from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Any, Dict, Optional

import requests
from fastapi import APIRouter, HTTPException, Request

from app.core.settings import S
from app.core.time import now_ts

router = APIRouter(tags=["billing", "mock"])

_TOKEN_CACHE: Dict[str, int] = {}
_SUBSCRIPTIONS: Dict[str, Dict[str, Any]] = {}


def _ensure_mock_enabled() -> None:
    if not S.ccbill_mock_enabled:
        raise HTTPException(404, "Not found")


def _decode_basic_auth(auth_header: str) -> tuple[str, str]:
    if not auth_header.lower().startswith("basic "):
        return "", ""
    raw = auth_header.split(" ", 1)[1].strip()
    try:
        decoded = base64.b64decode(raw).decode("utf-8")
        if ":" not in decoded:
            return "", ""
        return decoded.split(":", 1)
    except Exception:
        return "", ""


def _is_valid_oauth_client(client_id: str, client_secret: str) -> bool:
    pairs = {
        (S.ccbill_frontend_client_id, S.ccbill_frontend_client_secret),
        (S.ccbill_backend_client_id, S.ccbill_backend_client_secret),
    }
    # Accept any non-empty credentials when mock creds are not configured.
    if not any(a and b for a, b in pairs):
        return bool(client_id and client_secret)
    return (client_id, client_secret) in pairs


def _signature_secret() -> str:
    if S.ccbill_webhook_signature_secret:
        return S.ccbill_webhook_signature_secret
    return "local-ccbill-webhook-secret"


@router.post("/mock/ccbill/ccbill-auth/oauth/token")
async def ccbill_mock_oauth(req: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    grant_type = req.query_params.get("grant_type", "")
    if grant_type != "client_credentials":
        raise HTTPException(400, "Unsupported grant_type")

    client_id, client_secret = _decode_basic_auth(req.headers.get("authorization", ""))
    if not _is_valid_oauth_client(client_id, client_secret):
        raise HTTPException(401, "Invalid client credentials")

    token = f"mock_ccbill_{hashlib.sha256(f'{client_id}:{now_ts()}'.encode()).hexdigest()[:20]}"
    expires_in = 3600
    _TOKEN_CACHE[token] = now_ts() + expires_in
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in}


@router.post("/mock/ccbill/transactions/payment-tokens/{payment_token_id}")
async def ccbill_mock_charge(payment_token_id: str, req: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()

    auth = req.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token")
    access_token = auth.split(" ", 1)[1].strip()
    exp = _TOKEN_CACHE.get(access_token, 0)
    if exp <= now_ts():
        raise HTTPException(401, "Invalid or expired token")

    body = await req.json()
    approved = payment_token_id.lower().startswith("tok_") or bool(body.get("approve", True))
    if payment_token_id.lower().startswith("fail"):
        approved = False

    transaction_id = f"txn_{int(time.time() * 1000)}"
    subscription_id: Optional[str] = None
    next_renewal_date: Optional[str] = None

    recurring_price = body.get("recurringPrice")
    recurring_period = body.get("recurringPeriod")
    if recurring_price is not None and recurring_period is not None and approved:
        subscription_id = f"sub_{int(time.time() * 1000)}"
        next_renewal_date = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 30 * 86400))
        _SUBSCRIPTIONS[subscription_id] = {
            "subscriptionId": subscription_id,
            "status": "Active",
            "paymentTokenId": payment_token_id,
            "nextRenewalDate": next_renewal_date,
            "amount": recurring_price,
            "currencyCode": body.get("currencyCode"),
        }

    return {
        "approved": approved,
        "responseCode": "200" if approved else "500",
        "transactionId": transaction_id,
        "paymentUniqueId": transaction_id,
        "subscriptionId": subscription_id,
        "nextRenewalDate": next_renewal_date,
        "message": "Approved" if approved else "Declined",
    }


@router.get("/mock/ccbill/subscriptions/{subscription_id}")
def ccbill_mock_get_subscription(subscription_id: str) -> Dict[str, Any]:
    _ensure_mock_enabled()
    item = _SUBSCRIPTIONS.get(subscription_id)
    if not item:
        raise HTTPException(404, "Subscription not found")
    return item


@router.post("/mock/ccbill/subscriptions/{subscription_id}/cancel")
def ccbill_mock_cancel_subscription(subscription_id: str) -> Dict[str, Any]:
    _ensure_mock_enabled()
    item = _SUBSCRIPTIONS.get(subscription_id)
    if not item:
        raise HTTPException(404, "Subscription not found")
    item["status"] = "Canceled"
    return {"ok": True, "subscriptionId": subscription_id, "status": item["status"]}


@router.post("/emit/ccbill-webhook")
def emit_ccbill_webhook(body: Dict[str, Any]) -> Dict[str, Any]:
    _ensure_mock_enabled()
    event_type = str(body.get("event_type") or body.get("eventType") or "NewSaleSuccess")
    payload = body.get("payload") or {}
    if not isinstance(payload, dict):
        raise HTTPException(400, "payload must be an object")

    target_url = str(body.get("target_url") or f"{S.public_base_url}/api/ccbill/webhook")
    raw = requests.models.complexjson.dumps(payload).encode("utf-8")
    sig = hmac.new(_signature_secret().encode("utf-8"), raw, hashlib.sha256).hexdigest()

    resp = requests.post(
        target_url,
        params={"eventType": event_type},
        headers={
            "content-type": "application/json",
            S.ccbill_webhook_signature_header: sig,
            **({"x-forwarded-for": str(body.get("forwarded_for"))} if body.get("forwarded_for") else {}),
        },
        data=raw,
        timeout=10,
    )

    return {
        "ok": resp.status_code < 400,
        "status_code": resp.status_code,
        "event_type": event_type,
        "target_url": target_url,
        "response": resp.text[:2000],
    }
