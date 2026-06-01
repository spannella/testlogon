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

from fastapi import APIRouter, Depends, Query

from app.models import (
    AdsApiBudgetUpdate,
    AdsApiBulkAction,
    AdsApiCampaignCreate,
    AdsApiCampaignUpdate,
    AdsApiCreativeCreate,
    AdsApiCreativeUpdate,
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
