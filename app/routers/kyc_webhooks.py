"""KYC webhooks & notifications router (KYC-011).

Thin glue layer over the existing webhook + alert infrastructure:

* Lists the canonical ``kyc.*`` webhook event types.
* Exposes the user's KYC notification history (in-app alerts) + preferences.
* Admin/root test-emit endpoint that fires a real KYC event through the
  existing webhook dispatcher + alert system (deterministic for E2E).

Webhook ENDPOINT subscriptions themselves are managed by the existing
``app/routers/webhooks.py`` (``/ui/webhooks``); a user simply subscribes one of
their endpoints to a ``kyc.*`` event type there. This router does not duplicate
that — it surfaces KYC-specific listing / history / test-emit / delivery view.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.models import (
    KycWebhookEmitRequest,
    KycWebhookEmitResult,
    KycWebhookEventTypesOut,
    KycWebhookNotificationsOut,
    KycWebhookPrefsOut,
    KycWebhookPrefsUpdateRequest,
)
from app.services.kyc_webhooks import (
    emit_kyc_event,
    get_kyc_webhooks_prefs,
    is_kyc_event_type,
    list_kyc_event_types,
    list_kyc_notifications,
    update_kyc_webhooks_prefs,
)
from app.services.sessions import require_ui_session

kyc_webhooks_router = APIRouter(prefix="/ui/kyc/webhooks", tags=["kyc-webhooks"])


@kyc_webhooks_router.get("/event-types", response_model=KycWebhookEventTypesOut)
def get_kyc_event_types(_ctx: Dict[str, Any] = Depends(require_ui_session)):
    """List the canonical KYC webhook event types users can subscribe to."""
    return KycWebhookEventTypesOut(event_types=list_kyc_event_types())


@kyc_webhooks_router.get("/preferences", response_model=KycWebhookPrefsOut)
def get_kyc_prefs(ctx: Dict[str, Any] = Depends(require_ui_session)):
    prefs = get_kyc_webhooks_prefs(ctx["user_sub"])
    return KycWebhookPrefsOut(**prefs)


@kyc_webhooks_router.patch("/preferences", response_model=KycWebhookPrefsOut)
def patch_kyc_prefs(
    body: KycWebhookPrefsUpdateRequest,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    prefs = update_kyc_webhooks_prefs(
        ctx["user_sub"],
        in_app_enabled=body.in_app_enabled,
        email_enabled=body.email_enabled,
        events=body.events,
    )
    return KycWebhookPrefsOut(**prefs)


@kyc_webhooks_router.get("/notifications", response_model=KycWebhookNotificationsOut)
def get_kyc_notifications(
    limit: int = Query(50, ge=1, le=200),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """User's in-app KYC notification history (alerts with kyc.* events)."""
    items = list_kyc_notifications(ctx["user_sub"], limit=limit)
    return KycWebhookNotificationsOut(items=items, total=len(items))


@kyc_webhooks_router.post("/test-emit", response_model=KycWebhookEmitResult)
def test_emit_kyc_event(
    body: KycWebhookEmitRequest,
    request: Request,
    _admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Admin/root: emit a real KYC event (in-app alert + webhook dispatch).

    Targets the supplied ``user_sub`` so the user's subscribed webhook
    endpoints receive a delivery and an in-app alert is written. Used for
    verification and E2E. Deterministic — no randomness.
    """
    if not is_kyc_event_type(body.event):
        raise HTTPException(status_code=422, detail="unknown_kyc_event_type")
    extra = dict(body.data or {})
    result = emit_kyc_event(
        event=body.event,
        user_sub=body.user_sub,
        case_id=body.case_id,
        request=request,
        **extra,
    )
    return KycWebhookEmitResult(**result)
