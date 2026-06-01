"""Advertiser API orchestration (ADS-011).

Thin orchestration layer over the existing ad services
(`ad_accounts`, `ad_campaigns`, `ad_creatives`, `ad_analytics`) for the
programmatic, API-key-authenticated advertiser API exposed at
``/api/v1/ads``.

Authentication is handled by ``require_api_key_principal`` in the router;
this module provides:

* scope enforcement helpers (``ads:read`` / ``ads:manage`` / ``ads:serve``)
* advertiser-account resolution from the API key's owning user
* CRUD/lifecycle wrappers that delegate to the existing ad services

It deliberately does NOT reimplement campaign/creative/analytics logic.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.models import (
    AdsApiBudgetUpdate,
    AdsApiBulkAction,
    AdsApiCampaignCreate,
    AdsApiCampaignUpdate,
    AdsApiCreativeCreate,
    AdsApiCreativeUpdate,
    CampaignCreateIn,
    CampaignUpdateIn,
    CreativeCreateIn,
    CreativeUpdateIn,
)
from app.services import ad_accounts, ad_analytics, ad_campaigns, ad_creatives
from app.services.api_key_capabilities import expand_api_key_capabilities

# Map a bulk action verb to the target campaign status.
_BULK_ACTION_STATUS = {
    "pause": "paused",
    "resume": "active",
    "archive": "archived",
}


# ── Scope enforcement ────────────────────────────────────────────────

def require_scope(principal: Dict[str, Any], scope: str) -> None:
    """Raise 403 if the API key principal lacks ``scope``.

    Capability implications are honored here (``ads:manage`` implies
    ``ads:read`` and ``ads:serve``).
    """
    caps = expand_api_key_capabilities(principal.get("capabilities") or [])
    if scope not in caps:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "api_key_scope_missing",
                "message": f"API key missing required scope: {scope}",
                "required_scope": scope,
            },
        )


# ── Account resolution ───────────────────────────────────────────────

def resolve_account(principal: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve the advertiser account owned by the API key's user.

    Returns the first (most recent) account owned by the principal's
    ``user_sub``. Raises 403 if the user has no advertiser account.
    """
    user_sub = str(principal.get("user_sub") or "")
    if not user_sub:
        raise HTTPException(status_code=401, detail="Invalid API key principal")
    accounts = ad_accounts.list_accounts_by_owner(user_sub)
    if not accounts:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "no_advertiser_account",
                "message": "No advertiser account found for this API key",
            },
        )
    return accounts[0]


def _owned_campaign_or_404(account_id: str, campaign_id: str) -> Dict[str, Any]:
    camp = ad_campaigns.get_campaign(account_id, campaign_id)
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return camp


# ── Campaign lifecycle ───────────────────────────────────────────────

def create_campaign(account_id: str, body: AdsApiCampaignCreate) -> Dict[str, Any]:
    payload = CampaignCreateIn(
        name=body.name,
        objective=body.objective,
        budget_cents=body.budget_cents,
        budget_type=body.budget_type,
        start_date=body.start_date,
        end_date=body.end_date,
    )
    return ad_campaigns.create_campaign(account_id, payload)


def list_campaigns(account_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
    items = ad_campaigns.list_campaigns(account_id)
    if status:
        items = [c for c in items if c.get("status") == status]
    return items


def get_campaign(account_id: str, campaign_id: str) -> Dict[str, Any]:
    return _owned_campaign_or_404(account_id, campaign_id)


def update_campaign(account_id: str, campaign_id: str, body: AdsApiCampaignUpdate) -> Dict[str, Any]:
    _owned_campaign_or_404(account_id, campaign_id)
    payload = CampaignUpdateIn(**body.model_dump(exclude_none=True))
    try:
        ad_campaigns.update_campaign(account_id, campaign_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _owned_campaign_or_404(account_id, campaign_id)


def archive_campaign(account_id: str, campaign_id: str) -> Dict[str, Any]:
    """Soft-delete a campaign by transitioning it to archived."""
    _owned_campaign_or_404(account_id, campaign_id)
    payload = CampaignUpdateIn(status="archived")
    try:
        ad_campaigns.update_campaign(account_id, campaign_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"ok": True, "campaign_id": campaign_id, "status": "archived"}


def update_budget(account_id: str, campaign_id: str, body: AdsApiBudgetUpdate) -> Dict[str, Any]:
    _owned_campaign_or_404(account_id, campaign_id)
    update_fields: Dict[str, Any] = {"budget_cents": body.budget_cents}
    if body.budget_type is not None:
        update_fields["budget_type"] = body.budget_type
    payload = CampaignUpdateIn(**update_fields)
    try:
        ad_campaigns.update_campaign(account_id, campaign_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _owned_campaign_or_404(account_id, campaign_id)


def bulk_action(account_id: str, body: AdsApiBulkAction) -> Dict[str, Any]:
    """Apply a pause/resume/archive action to up to 100 campaigns.

    Returns a per-campaign results list with partial-failure handling.
    """
    target_status = _BULK_ACTION_STATUS[body.action]
    results: List[Dict[str, Any]] = []
    success = 0
    for campaign_id in body.campaign_ids:
        camp = ad_campaigns.get_campaign(account_id, campaign_id)
        if not camp:
            results.append({"campaign_id": campaign_id, "ok": False, "error": "campaign not found"})
            continue
        try:
            ad_campaigns.update_campaign(account_id, campaign_id, CampaignUpdateIn(status=target_status))
        except ValueError as exc:
            results.append({"campaign_id": campaign_id, "ok": False, "error": str(exc)})
            continue
        results.append({"campaign_id": campaign_id, "ok": True, "status": target_status})
        success += 1
    return {
        "results": results,
        "success_count": success,
        "error_count": len(results) - success,
    }


# ── Creatives ────────────────────────────────────────────────────────

def create_creative(account_id: str, body: AdsApiCreativeCreate) -> Dict[str, Any]:
    _owned_campaign_or_404(account_id, body.campaign_id)
    payload = CreativeCreateIn(
        format=body.format,
        title=body.title,
        headline=body.headline,
        body_text=body.body_text,
        cta_text=body.cta_text,
        cta_url=body.cta_url,
        alt_text=body.alt_text,
        rotation_weight=body.rotation_weight,
    )
    return ad_creatives.create_creative(body.campaign_id, account_id, payload)


def _owned_creative_or_404(account_id: str, creative_id: str) -> Dict[str, Any]:
    creative = ad_creatives.get_creative_by_id(creative_id)
    if not creative or creative.get("account_id") != account_id:
        raise HTTPException(status_code=404, detail="Creative not found")
    return creative


def list_creatives(account_id: str, campaign_id: str) -> List[Dict[str, Any]]:
    _owned_campaign_or_404(account_id, campaign_id)
    return ad_creatives.list_creatives(campaign_id)


def get_creative(account_id: str, creative_id: str) -> Dict[str, Any]:
    return _owned_creative_or_404(account_id, creative_id)


def update_creative(account_id: str, creative_id: str, body: AdsApiCreativeUpdate) -> Dict[str, Any]:
    creative = _owned_creative_or_404(account_id, creative_id)
    payload = CreativeUpdateIn(**body.model_dump(exclude_none=True))
    ad_creatives.update_creative(creative["campaign_id"], creative_id, payload)
    return _owned_creative_or_404(account_id, creative_id)


def delete_creative(account_id: str, creative_id: str) -> Dict[str, Any]:
    creative = _owned_creative_or_404(account_id, creative_id)
    ad_creatives.delete_creative(creative["campaign_id"], creative_id)
    return {"ok": True, "creative_id": creative_id}


# ── Analytics ────────────────────────────────────────────────────────

def analytics_summary(account_id: str, campaign_id: Optional[str], days: int) -> Dict[str, Any]:
    return ad_analytics.get_summary(account_id, campaign_id, days)


def analytics_by_date(account_id: str, campaign_id: Optional[str], days: int) -> List[Dict[str, Any]]:
    return ad_analytics.get_timeseries(account_id, campaign_id, days, "daily")


def analytics_breakdown(account_id: str, campaign_id: Optional[str], dimension: str, days: int) -> List[Dict[str, Any]]:
    return ad_analytics.get_breakdown(account_id, campaign_id, dimension, days)
