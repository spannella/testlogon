from __future__ import annotations

from urllib.parse import urljoin

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.settings import S
from app.models import BillingCheckoutReq
from app.services.sessions import require_ui_session

router = APIRouter(tags=["billing"])


def ensure_stripe_configured() -> None:
    if not S.stripe_secret_key:
        raise HTTPException(501, "Stripe is not configured")
    stripe.api_key = S.stripe_secret_key


def build_return_url(req: Request, fallback_query: str) -> str:
    if fallback_query.startswith("/"):
        return urljoin(str(req.base_url), fallback_query.lstrip("/"))
    return urljoin(str(req.base_url), fallback_query)


@router.get("/ui/billing/config")
async def billing_config() -> dict:
    return {
        "publishable_key": S.stripe_publishable_key,
        "currency": S.stripe_default_currency,
    }


@router.post("/ui/billing/checkout_session")
async def create_checkout_session(body: BillingCheckoutReq, req: Request, ctx=Depends(require_ui_session)) -> dict:
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
async def stripe_webhook(req: Request) -> dict:
    ensure_stripe_configured()
    if not S.stripe_webhook_secret:
        raise HTTPException(501, "Stripe webhook secret not configured")

    payload = await req.body()
    sig_header = req.headers.get("stripe-signature")
    if not sig_header:
        raise HTTPException(400, "Missing Stripe-Signature header")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=S.stripe_webhook_secret,
        )
    except Exception as exc:
        raise HTTPException(400, f"Webhook error: {exc}") from exc

    event_type = event.get("type", "")
    if event_type == "checkout.session.completed":
        session = event.get("data", {}).get("object", {})
        if session:
            print(f"Stripe checkout completed: {session.get('id')}")

    return {"received": True}
