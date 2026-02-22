"""
Local mock PayPal API server for dev/test.

Enabled when PAYPAL_MOCK_ENABLED=1.  Set PAYPAL_BASE_URL=http://localhost:8000/mock/paypal
in .env.local so that paypal.py hits this server instead of api-m.sandbox.paypal.com.
"""
from __future__ import annotations

import secrets
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from app.core.settings import S

router = APIRouter(tags=["mock"])

# In-memory stores (reset on backend restart, that's fine for dev)
_SETUP_TOKENS: Dict[str, Dict[str, Any]] = {}
_PAYMENT_TOKENS: Dict[str, Dict[str, Any]] = {}
_ORDERS: Dict[str, Dict[str, Any]] = {}
_SUBSCRIPTIONS: Dict[str, Dict[str, Any]] = {}


def _mock_enabled() -> None:
    if not getattr(S, "paypal_mock_enabled", False):
        raise HTTPException(404, "Not found")


def _tok() -> str:
    return secrets.token_urlsafe(16)


# ─── OAuth ────────────────────────────────────────────────────────────────────

@router.post("/mock/paypal/v1/oauth2/token")
async def mock_oauth(req: Request) -> Dict[str, Any]:
    _mock_enabled()
    return {
        "access_token": f"mock_access_{_tok()}",
        "token_type": "Bearer",
        "expires_in": 32400,
        "scope": "https://uri.paypal.com/services/subscriptions",
    }


# ─── Vault: setup tokens ──────────────────────────────────────────────────────

@router.post("/mock/paypal/v3/vault/setup-tokens")
async def mock_create_setup_token(req: Request) -> Dict[str, Any]:
    _mock_enabled()
    body = await req.json()
    st_id = f"ST-{_tok().upper()[:20]}"
    pm_kind = "card"
    if isinstance(body.get("payment_source"), dict):
        if "paypal" in body["payment_source"]:
            pm_kind = "paypal"
    _SETUP_TOKENS[st_id] = {"id": st_id, "pm_kind": pm_kind, "custom_id": body.get("custom_id")}
    base = (S.public_base_url or "http://localhost:8000").rstrip("/")
    return {
        "id": st_id,
        "status": "PAYER_ACTION_REQUIRED",
        "links": [
            {"rel": "approve", "href": f"{base}/billing/paypal/vault/return?setup_token={st_id}", "method": "GET"},
            {"rel": "self", "href": f"{base}/mock/paypal/v3/vault/setup-tokens/{st_id}", "method": "GET"},
        ],
    }


# ─── Vault: exchange setup token for payment token ────────────────────────────

@router.post("/mock/paypal/v3/vault/payment-tokens")
async def mock_exchange_setup_token(req: Request) -> Dict[str, Any]:
    _mock_enabled()
    body = await req.json()
    src = body.get("payment_source", {})
    token_src = src.get("token", {})
    st_id = token_src.get("id", "")
    st = _SETUP_TOKENS.pop(st_id, {})
    pm_kind = st.get("pm_kind", "card")

    pt_id = f"PT-{_tok().upper()[:20]}"
    _PAYMENT_TOKENS[pt_id] = {"id": pt_id, "pm_kind": pm_kind, "setup_token_id": st_id}

    if pm_kind == "paypal":
        payment_source = {"paypal": {"account_id": "mock_paypal_account", "email_address": "buyer@example.com"}}
    else:
        payment_source = {"card": {"brand": "VISA", "last_digits": "4242", "expiry": "2026-12"}}

    return {
        "id": pt_id,
        "status": "CREATED",
        "payment_source": payment_source,
        "links": [
            {"rel": "self", "href": f"/mock/paypal/v3/vault/payment-tokens/{pt_id}", "method": "GET"},
        ],
    }


@router.delete("/mock/paypal/v3/vault/payment-tokens/{payment_token_id}")
async def mock_delete_payment_token(payment_token_id: str) -> Response:
    _mock_enabled()
    _PAYMENT_TOKENS.pop(payment_token_id, None)
    return Response(status_code=204)


# ─── Orders ───────────────────────────────────────────────────────────────────

@router.post("/mock/paypal/v2/checkout/orders")
async def mock_create_order(req: Request) -> Dict[str, Any]:
    _mock_enabled()
    body = await req.json()
    order_id = f"MOCK-ORDER-{_tok().upper()[:16]}"
    units = body.get("purchase_units", [{}])
    _ORDERS[order_id] = {
        "id": order_id,
        "status": "CREATED",
        "purchase_units": units,
        "custom_id": (units[0].get("custom_id") if units else None),
    }
    base = (S.public_base_url or "http://localhost:8000").rstrip("/")
    return {
        "id": order_id,
        "status": "CREATED",
        "purchase_units": units,
        "links": [
            {"rel": "approve", "href": f"{base}/billing/paypal/checkout/return?token={order_id}", "method": "GET"},
            {"rel": "self", "href": f"{base}/mock/paypal/v2/checkout/orders/{order_id}", "method": "GET"},
            {"rel": "capture", "href": f"{base}/mock/paypal/v2/checkout/orders/{order_id}/capture", "method": "POST"},
        ],
    }


@router.post("/mock/paypal/v2/checkout/orders/{order_id}/capture")
async def mock_capture_order(order_id: str) -> Dict[str, Any]:
    _mock_enabled()
    order = _ORDERS.get(order_id, {})
    units = order.get("purchase_units", [{}])
    amount = (units[0].get("amount", {}) if units else {})
    capture_id = f"CAP-{_tok().upper()[:16]}"
    if order:
        _ORDERS[order_id]["status"] = "COMPLETED"
    return {
        "id": order_id,
        "status": "COMPLETED",
        "purchase_units": [
            {
                **(units[0] if units else {}),
                "payments": {
                    "captures": [
                        {
                            "id": capture_id,
                            "status": "COMPLETED",
                            "amount": amount,
                            "supplementary_data": {"related_ids": {"order_id": order_id}},
                        }
                    ]
                },
            }
        ],
    }


# ─── Subscriptions ────────────────────────────────────────────────────────────

@router.post("/mock/paypal/v1/billing/subscriptions")
async def mock_create_subscription(req: Request) -> Dict[str, Any]:
    _mock_enabled()
    body = await req.json()
    sub_id = f"I-MOCK{_tok().upper()[:16]}"
    next_billing = "2026-03-20T12:00:00Z"
    _SUBSCRIPTIONS[sub_id] = {
        "id": sub_id,
        "status": "APPROVAL_PENDING",
        "plan_id": body.get("plan_id", "monthly"),
        "custom_id": body.get("custom_id"),
        "billing_info": {"next_billing_time": next_billing},
    }
    base = (S.public_base_url or "http://localhost:8000").rstrip("/")
    return {
        "id": sub_id,
        "status": "APPROVAL_PENDING",
        "plan_id": body.get("plan_id", "monthly"),
        "custom_id": body.get("custom_id"),
        "billing_info": {"next_billing_time": next_billing},
        "links": [
            {"rel": "approve", "href": f"{base}/billing/paypal/subscription/return?subscription_id={sub_id}", "method": "GET"},
            {"rel": "self", "href": f"{base}/mock/paypal/v1/billing/subscriptions/{sub_id}", "method": "GET"},
        ],
    }


@router.post("/mock/paypal/v1/billing/subscriptions/{subscription_id}/cancel")
async def mock_cancel_subscription(subscription_id: str) -> Response:
    _mock_enabled()
    if subscription_id in _SUBSCRIPTIONS:
        _SUBSCRIPTIONS[subscription_id]["status"] = "CANCELLED"
    return Response(status_code=204)


# ─── Webhook signature verification ──────────────────────────────────────────

@router.post("/mock/paypal/v1/notifications/verify-webhook-signature")
async def mock_verify_webhook(req: Request) -> Dict[str, Any]:
    _mock_enabled()
    # In mock mode always succeed so webhook handler proceeds
    return {"verification_status": "SUCCESS"}
