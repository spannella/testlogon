"""Admin ad-platform management router (ADS-018).

Platform-admin oversight over the existing advertiser ad system: cross-user
listing of advertiser accounts / campaigns / creatives, account + creative
moderation (approve / reject / suspend) with audit, and platform-wide ad
revenue / spend / impression metrics + dashboard data.

Auth:
  * Read + moderation endpoints  → require_admin_or_root (ADMIN or ROOT).
  * Account/creative suspend (destructive) → require_root_session (ROOT only).
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser, require_root_session
from app.auth.policy import require_admin_or_root
from app.models import (
    AdminAdAccountDetailOut,
    AdminAdAccountOut,
    AdminAdCampaignOut,
    AdminAdCreativeOut,
    AdminAdModerationAction,
    AdminAdModerationEventOut,
    AdminAdModerationResult,
    AdminAdPlatformMetricsOut,
    AdminAdRevenuePoint,
    AdminAdTopSpenderOut,
)
from app.services import admin_ad_platform as svc

admin_ad_platform_router = APIRouter(
    prefix="/ui/admin/ad-platform", tags=["admin-ad-platform"]
)


# ── Cross-user listing ──────────────────────────────────────────────────────

@admin_ad_platform_router.get("/accounts", response_model=List[AdminAdAccountOut])
async def list_advertiser_accounts(
    status: Optional[str] = Query(default=None),
    owner_sub: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return svc.list_all_advertiser_accounts(
        status=status, owner_sub=owner_sub, limit=limit
    )


@admin_ad_platform_router.get(
    "/accounts/{account_id}", response_model=AdminAdAccountDetailOut
)
async def get_advertiser_account(
    account_id: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    detail = svc.get_account_detail(account_id)
    if detail is None:
        raise HTTPException(404, "Advertiser account not found")
    return detail


@admin_ad_platform_router.get("/campaigns", response_model=List[AdminAdCampaignOut])
async def list_campaigns(
    status: Optional[str] = Query(default=None),
    account_id: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return svc.list_all_campaigns(status=status, account_id=account_id, limit=limit)


@admin_ad_platform_router.get("/creatives", response_model=List[AdminAdCreativeOut])
async def list_creatives(
    status: Optional[str] = Query(default=None),
    account_id: Optional[str] = Query(default=None),
    campaign_id: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return svc.list_all_creatives(
        status=status, account_id=account_id, campaign_id=campaign_id, limit=limit
    )


# ── Moderation queue ─────────────────────────────────────────────────────────

@admin_ad_platform_router.get(
    "/moderation/queue", response_model=dict
)
async def moderation_queue(
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Items awaiting moderation: pending accounts + pending creatives."""
    accounts = svc.list_all_advertiser_accounts(status="pending_review", limit=500)
    creatives = svc.list_all_creatives(status="pending_review", limit=500)
    return {
        "accounts": accounts,
        "creatives": creatives,
        "account_count": len(accounts),
        "creative_count": len(creatives),
    }


@admin_ad_platform_router.get(
    "/moderation/{item_type}/{item_id}/history",
    response_model=List[AdminAdModerationEventOut],
)
async def moderation_history(
    item_type: str,
    item_id: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    if item_type not in ("account", "creative"):
        raise HTTPException(422, "item_type must be 'account' or 'creative'")
    return svc.get_moderation_history(item_type, item_id)


@admin_ad_platform_router.post(
    "/accounts/{account_id}/moderate", response_model=AdminAdModerationResult
)
async def moderate_account(
    account_id: str,
    body: AdminAdModerationAction,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    if body.action in ("reject", "suspend") and not (body.reason or body.notes):
        raise HTTPException(422, "reason is required for reject/suspend")
    result = svc.moderate_account(
        account_id=account_id, action=body.action, admin_sub=user.sub,
        reason=body.reason, notes=body.notes, request=request,
    )
    if result is None:
        raise HTTPException(404, "Advertiser account not found")
    return AdminAdModerationResult(
        item_type="account", item_id=account_id, status=result["status"]
    )


@admin_ad_platform_router.post(
    "/creatives/{creative_id}/moderate", response_model=AdminAdModerationResult
)
async def moderate_creative(
    creative_id: str,
    body: AdminAdModerationAction,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    if body.action in ("reject", "suspend") and not (body.reason or body.notes):
        raise HTTPException(422, "reason is required for reject/suspend")
    result = svc.moderate_creative(
        creative_id=creative_id, action=body.action, admin_sub=user.sub,
        reason=body.reason, notes=body.notes, request=request,
    )
    if result is None:
        raise HTTPException(404, "Creative not found")
    return AdminAdModerationResult(
        item_type="creative", item_id=creative_id, status=result["status"]
    )


# ── Platform metrics ─────────────────────────────────────────────────────────

@admin_ad_platform_router.get("/metrics", response_model=AdminAdPlatformMetricsOut)
async def platform_metrics(
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return svc.get_platform_metrics()


@admin_ad_platform_router.get(
    "/metrics/revenue-series", response_model=List[AdminAdRevenuePoint]
)
async def revenue_series(
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return svc.get_monthly_revenue_series()


@admin_ad_platform_router.get(
    "/metrics/top-spenders", response_model=List[AdminAdTopSpenderOut]
)
async def top_spenders(
    limit: int = Query(default=10, ge=1, le=100),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    return svc.get_top_spenders(limit=limit)
