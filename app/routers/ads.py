"""Advertiser account, campaign, and billing endpoints (ADS-001/007)."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query

from app.services.sessions import require_ui_session
from app.models import (
    AdAccountCreateIn,
    AdDepositIn,
)
from app.services.ad_accounts import (
    create_ad_account,
    get_ad_account,
    list_accounts_by_owner,
)
from app.services.ad_campaigns import (
    create_campaign,
    get_campaign,
    list_campaigns,
)
from app.services.ad_billing import (
    deposit_funds,
    get_billing_history,
    get_campaign_spending,
    generate_invoice,
    charge_impression,
    charge_click,
    charge_conversion,
)

router = APIRouter(prefix="/ui/ads", tags=["ads"])


# ── Helpers ────────────────────────────────────────────────────────

def _require_account_owner(account_id: str, user_sub: str) -> dict:
    acct = get_ad_account(account_id)
    if not acct or acct["owner_sub"] != user_sub:
        raise HTTPException(status_code=404, detail="Account not found")
    return acct


# ── Advertiser Accounts ────────────────────────────────────────────

@router.post("/accounts", status_code=201)
async def create_account_endpoint(body: AdAccountCreateIn, ctx=Depends(require_ui_session)):
    return create_ad_account(ctx["user_sub"], body)


@router.get("/accounts")
async def list_my_accounts(ctx=Depends(require_ui_session)):
    return list_accounts_by_owner(ctx["user_sub"])


@router.get("/accounts/{account_id}")
async def get_account_endpoint(account_id: str, ctx=Depends(require_ui_session)):
    acct = get_ad_account(account_id)
    if not acct or acct["owner_sub"] != ctx["user_sub"]:
        raise HTTPException(status_code=404, detail="Account not found")
    return acct


# ── Campaigns ──────────────────────────────────────────────────────

@router.post("/accounts/{account_id}/campaigns", status_code=201)
async def create_campaign_endpoint(
    account_id: str, body: dict, ctx=Depends(require_ui_session)
):
    from app.models import CampaignCreateIn
    acct = _require_account_owner(account_id, ctx["user_sub"])
    data = CampaignCreateIn(**body)
    return create_campaign(account_id, data)


@router.get("/accounts/{account_id}/campaigns")
async def list_campaigns_endpoint(account_id: str, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    return list_campaigns(account_id)


@router.get("/accounts/{account_id}/campaigns/{campaign_id}")
async def get_campaign_endpoint(
    account_id: str, campaign_id: str, ctx=Depends(require_ui_session)
):
    _require_account_owner(account_id, ctx["user_sub"])
    campaign = get_campaign(account_id, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


# ── Ad Billing (ADS-007) ──────────────────────────────────────────

@router.post("/accounts/{account_id}/deposit")
async def deposit_endpoint(account_id: str, body: AdDepositIn, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    try:
        return deposit_funds(account_id, body.amount_cents, body.payment_method_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/accounts/{account_id}/billing")
async def billing_history_endpoint(
    account_id: str,
    limit: int = Query(default=50, ge=1, le=500),
    ctx=Depends(require_ui_session),
):
    _require_account_owner(account_id, ctx["user_sub"])
    entries = get_billing_history(account_id, limit)
    return entries


@router.get("/accounts/{account_id}/billing/campaigns/{campaign_id}")
async def campaign_spending_endpoint(
    account_id: str,
    campaign_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    ctx=Depends(require_ui_session),
):
    _require_account_owner(account_id, ctx["user_sub"])
    return get_campaign_spending(campaign_id, limit)


@router.get("/accounts/{account_id}/invoices/{month}")
async def invoice_endpoint(account_id: str, month: str, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    if not re.match(r"^\d{4}-\d{2}$", month):
        raise HTTPException(status_code=400, detail="Invalid month format, use YYYY-MM")
    return generate_invoice(account_id, month)


# ── Internal charge endpoints (called by ad serving) ──────────────

@router.post("/internal/charge-impression")
async def internal_charge_impression(body: dict, ctx=Depends(require_ui_session)):
    """Charge for an ad impression. Used internally by ad serving engine."""
    return charge_impression(
        account_id=body["account_id"],
        campaign_id=body["campaign_id"],
        creative_id=body.get("creative_id", ""),
        creator_id=body.get("creator_id", ""),
        content_id=body.get("content_id", ""),
        bid_cpm_cents=body.get("bid_cpm_cents", 500),
    )


@router.post("/internal/charge-click")
async def internal_charge_click(body: dict, ctx=Depends(require_ui_session)):
    """Charge for an ad click."""
    return charge_click(
        account_id=body["account_id"],
        campaign_id=body["campaign_id"],
        creative_id=body.get("creative_id", ""),
        creator_id=body.get("creator_id", ""),
        content_id=body.get("content_id", ""),
        bid_cpc_cents=body.get("bid_cpc_cents", 50),
    )


@router.post("/internal/charge-conversion")
async def internal_charge_conversion(body: dict, ctx=Depends(require_ui_session)):
    """Charge for an ad conversion."""
    return charge_conversion(
        account_id=body["account_id"],
        campaign_id=body["campaign_id"],
        creative_id=body.get("creative_id", ""),
        creator_id=body.get("creator_id", ""),
        content_id=body.get("content_id", ""),
        bid_cpa_cents=body.get("bid_cpa_cents", 500),
    )
