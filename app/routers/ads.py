"""Advertiser account + campaign endpoints, plus admin review (ADS-001)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.services.sessions import require_ui_session
from app.models import (
    AdAccountCreateIn,
    AdAccountReviewIn,
    CampaignCreateIn,
    CampaignReviewIn,
    CampaignUpdateIn,
)
from app.services.ad_accounts import (
    create_ad_account,
    get_ad_account,
    list_accounts_by_owner,
    list_accounts_by_status,
    review_ad_account,
)
from app.services.ad_campaigns import (
    create_campaign,
    get_campaign,
    list_campaigns,
    list_campaigns_by_status,
    review_campaign,
    submit_campaign_for_review,
    update_campaign,
)

router = APIRouter(prefix="/ui/ads", tags=["ads"])
admin_router = APIRouter(prefix="/ui/admin/ads", tags=["ads-admin"])


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
    account_id: str, body: CampaignCreateIn, ctx=Depends(require_ui_session)
):
    acct = _require_account_owner(account_id, ctx["user_sub"])
    if acct.get("status") != "active":
        raise HTTPException(status_code=403, detail="Account is not active")
    return create_campaign(account_id, body)


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


@router.patch("/accounts/{account_id}/campaigns/{campaign_id}")
async def update_campaign_endpoint(
    account_id: str,
    campaign_id: str,
    body: CampaignUpdateIn,
    ctx=Depends(require_ui_session),
):
    _require_account_owner(account_id, ctx["user_sub"])
    try:
        return update_campaign(account_id, campaign_id, body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/accounts/{account_id}/campaigns/{campaign_id}/submit")
async def submit_for_review_endpoint(
    account_id: str, campaign_id: str, ctx=Depends(require_ui_session)
):
    _require_account_owner(account_id, ctx["user_sub"])
    try:
        return submit_campaign_for_review(account_id, campaign_id)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Campaign must be in draft status to submit for review",
        )


# ── Admin endpoints ────────────────────────────────────────────────

@admin_router.get("/accounts/pending")
async def list_pending_accounts(user: AuthenticatedUser = Depends(require_admin_or_root)):
    return list_accounts_by_status("pending_review")


@admin_router.post("/accounts/{account_id}/review")
async def review_account_endpoint(
    account_id: str,
    body: AdAccountReviewIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    result = review_ad_account(
        account_id, user.sub, body.decision, body.notes or ""
    )
    if not result:
        raise HTTPException(status_code=404, detail="Account not found")
    return result


@admin_router.get("/campaigns/pending")
async def list_pending_campaigns(user: AuthenticatedUser = Depends(require_admin_or_root)):
    return list_campaigns_by_status("pending_review")


@admin_router.post("/campaigns/{campaign_id}/review")
async def review_campaign_endpoint(
    campaign_id: str,
    body: CampaignReviewIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    result = review_campaign(
        campaign_id, user.sub, body.decision, body.notes or ""
    )
    if not result:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return result
