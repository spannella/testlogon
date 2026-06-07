"""Advertiser API router (ADS-011).

Programmatic, API-key-authenticated access to the advertiser campaign
lifecycle (accounts, campaigns, creatives, budgets, analytics) exposed at
``/api/v1/ads``.

Authentication uses the mature API-key infrastructure via
``require_api_key_principal`` (Authorization: ApiKey <key> or X-API-Key).
These are programmatic (Bearer/API-key) requests, so CSRF does not apply.

Scope model (added to CANONICAL_API_KEY_CAPABILITIES):
* ``ads:read``    — list/read campaigns, creatives, analytics
* ``ads:manage``  — full CRUD (implies ads:read, ads:serve)
* ``ads:serve``   — ad-serving / sandbox only

This router does NOT reimplement campaign logic — it delegates to the
existing ad services via ``app.services.advertiser_api``.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    AdsApiBudgetUpdate,
    AdsApiBulkAction,
    AdsApiCampaignCreate,
    AdsApiCampaignUpdate,
    AdsApiCreativeCreate,
    AdsApiCreativeUpdate,
    WebhookEndpointCreateReq,
)
from app.services import advertiser_api as svc
from app.services.api_key_auth_dependency import require_api_key_principal

advertiser_api_router = APIRouter(prefix="/api/v1/ads", tags=["Advertiser API"])


# ── Account ──────────────────────────────────────────────────────────

@advertiser_api_router.get("/account")
async def get_my_account(principal: Dict[str, Any] = Depends(require_api_key_principal)):
    svc.require_scope(principal, "ads:read")
    return svc.resolve_account(principal)


# ── Campaigns ────────────────────────────────────────────────────────

@advertiser_api_router.post("/campaigns", status_code=201)
async def create_campaign(
    body: AdsApiCampaignCreate,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:manage")
    account = svc.resolve_account(principal)
    return svc.create_campaign(account["account_id"], body)


@advertiser_api_router.get("/campaigns")
async def list_campaigns(
    status: Optional[str] = Query(default=None),
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:read")
    account = svc.resolve_account(principal)
    items = svc.list_campaigns(account["account_id"], status)
    return {"data": items, "count": len(items)}


@advertiser_api_router.get("/campaigns/{campaign_id}")
async def get_campaign(
    campaign_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:read")
    account = svc.resolve_account(principal)
    return svc.get_campaign(account["account_id"], campaign_id)


@advertiser_api_router.patch("/campaigns/{campaign_id}")
async def update_campaign(
    campaign_id: str,
    body: AdsApiCampaignUpdate,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:manage")
    account = svc.resolve_account(principal)
    return svc.update_campaign(account["account_id"], campaign_id, body)


@advertiser_api_router.delete("/campaigns/{campaign_id}")
async def delete_campaign(
    campaign_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:manage")
    account = svc.resolve_account(principal)
    return svc.archive_campaign(account["account_id"], campaign_id)


@advertiser_api_router.post("/campaigns/bulk-action")
async def bulk_action(
    body: AdsApiBulkAction,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:manage")
    account = svc.resolve_account(principal)
    return svc.bulk_action(account["account_id"], body)


# ── Budget ───────────────────────────────────────────────────────────

@advertiser_api_router.patch("/campaigns/{campaign_id}/budget")
async def update_budget(
    campaign_id: str,
    body: AdsApiBudgetUpdate,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:manage")
    account = svc.resolve_account(principal)
    return svc.update_budget(account["account_id"], campaign_id, body)


# ── Creatives ────────────────────────────────────────────────────────

@advertiser_api_router.post("/creatives", status_code=201)
async def create_creative(
    body: AdsApiCreativeCreate,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:manage")
    account = svc.resolve_account(principal)
    return svc.create_creative(account["account_id"], body)


@advertiser_api_router.get("/creatives")
async def list_creatives(
    campaign_id: str = Query(...),
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:read")
    account = svc.resolve_account(principal)
    items = svc.list_creatives(account["account_id"], campaign_id)
    return {"data": items, "count": len(items)}


@advertiser_api_router.get("/creatives/{creative_id}")
async def get_creative(
    creative_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:read")
    account = svc.resolve_account(principal)
    return svc.get_creative(account["account_id"], creative_id)


@advertiser_api_router.patch("/creatives/{creative_id}")
async def update_creative(
    creative_id: str,
    body: AdsApiCreativeUpdate,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:manage")
    account = svc.resolve_account(principal)
    return svc.update_creative(account["account_id"], creative_id, body)


@advertiser_api_router.delete("/creatives/{creative_id}")
async def delete_creative(
    creative_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:manage")
    account = svc.resolve_account(principal)
    return svc.delete_creative(account["account_id"], creative_id)


# ── Analytics ────────────────────────────────────────────────────────

@advertiser_api_router.get("/analytics/summary")
async def analytics_summary(
    days: int = Query(default=30, ge=1, le=365),
    campaign_id: Optional[str] = Query(default=None),
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:read")
    account = svc.resolve_account(principal)
    return svc.analytics_summary(account["account_id"], campaign_id, days)


@advertiser_api_router.get("/analytics/by-date")
async def analytics_by_date(
    days: int = Query(default=30, ge=1, le=365),
    campaign_id: Optional[str] = Query(default=None),
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:read")
    account = svc.resolve_account(principal)
    points = svc.analytics_by_date(account["account_id"], campaign_id, days)
    return {"data": points, "count": len(points)}


@advertiser_api_router.get("/analytics/breakdown")
async def analytics_breakdown(
    dimension: str = Query(default="creative"),
    days: int = Query(default=30, ge=1, le=365),
    campaign_id: Optional[str] = Query(default=None),
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:read")
    account = svc.resolve_account(principal)
    rows = svc.analytics_breakdown(account["account_id"], campaign_id, dimension, days)
    return {"data": rows, "count": len(rows)}


# ── Webhooks (ADS-011 / GAP-0055) ────────────────────────────────────
#
# Reuse the general-purpose webhook_service for delivery. Advertiser webhook
# endpoints are restricted to ``ad.*`` event types so a key with ads scope can
# only subscribe to ad-platform events. Authentication is API-key only; CSRF
# does not apply to programmatic requests.

@advertiser_api_router.get("/webhooks/event-types")
async def list_ad_webhook_event_types(
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:read")
    from app.services.ad_webhooks import list_ad_event_types
    types = list_ad_event_types()
    return {"data": types, "count": len(types)}


@advertiser_api_router.post("/webhooks", status_code=201)
async def create_ad_webhook(
    body: WebhookEndpointCreateReq,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:manage")
    account = svc.resolve_account(principal)
    from app.services.ad_webhooks import is_ad_event_type
    from app.services.webhook_service import register_endpoint

    # Restrict advertiser webhook subscriptions to ad.* event types only.
    allowed_events = [e for e in (body.event_types or []) if is_ad_event_type(e)]
    if not allowed_events:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "no_ad_event_types",
                "message": "At least one ad.* event type is required",
            },
        )
    try:
        return register_endpoint(
            account["owner_sub"],
            body.url,
            allowed_events,
            body.description or "",
            retry_policy=body.retry_policy,
            signature_version=body.signature_version,
            circuit_failure_threshold=body.circuit_failure_threshold,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OverflowError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@advertiser_api_router.get("/webhooks")
async def list_ad_webhooks(
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:read")
    account = svc.resolve_account(principal)
    from app.services.webhook_service import list_endpoints

    endpoints = list_endpoints(account["owner_sub"])
    ad_endpoints = [
        e
        for e in endpoints
        if any(str(ev).startswith("ad.") for ev in (e.get("event_types") or []))
    ]
    return {"data": ad_endpoints, "count": len(ad_endpoints)}


@advertiser_api_router.delete("/webhooks/{endpoint_id}", status_code=204)
async def delete_ad_webhook(
    endpoint_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:manage")
    account = svc.resolve_account(principal)
    from app.services.webhook_service import delete_endpoint

    if not delete_endpoint(account["owner_sub"], endpoint_id):
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")


@advertiser_api_router.post("/webhooks/{endpoint_id}/test", status_code=200)
async def test_ad_webhook(
    endpoint_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "ads:manage")
    account = svc.resolve_account(principal)
    from app.services.ad_webhooks import emit_ad_event
    from app.services.webhook_service import get_endpoint

    if not get_endpoint(account["owner_sub"], endpoint_id):
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")
    delivery_ids = emit_ad_event(
        "ad.webhook.test",
        account["owner_sub"],
        {"endpoint_id": endpoint_id, "message": "Test event from advertiser API"},
    )
    return {"ok": True, "delivery_ids": delivery_ids}
