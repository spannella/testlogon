"""Advertiser account + campaign + creative endpoints, plus ad serving (ADS-001/002/004)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.services.sessions import require_ui_session
from app.models import (
    AdAccountCreateIn,
    AdAccountReviewIn,
    AdServeRequestIn,
    AdTrackEventIn,
    CampaignCreateIn,
    CampaignReviewIn,
    CampaignUpdateIn,
    CreativeCreateIn,
    CreativeReviewIn,
    CreativeUpdateIn,
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
from app.services.ad_creatives import (
    create_creative,
    delete_creative,
    get_creative,
    list_creatives,
    list_creatives_by_status,
    review_creative,
    submit_creative_for_review,
    update_creative,
)
from app.services.ad_serving import serve_ad, track_ad_event, get_serving_stats

router = APIRouter(prefix="/ui/ads", tags=["ads"])
admin_router = APIRouter(prefix="/ui/admin/ads", tags=["ads-admin"])


# ── Helpers ────────────────────────────────────────────────────────

def _require_account_owner(account_id: str, user_sub: str) -> dict:
    acct = get_ad_account(account_id)
    if not acct or acct["owner_sub"] != user_sub:
        raise HTTPException(status_code=404, detail="Account not found")
    return acct


def _require_campaign_owner(campaign_id: str, user_sub: str) -> dict:
    """Verify user owns the campaign (via its account). Returns campaign dict."""
    from app.core.tables import T
    from boto3.dynamodb.conditions import Key as DKey

    resp = T.ad_campaigns.query(
        IndexName="ByCampaignId",
        KeyConditionExpression=DKey("campaign_id").eq(campaign_id),
    )
    items = resp.get("Items", [])
    if not items:
        raise HTTPException(status_code=404, detail="Campaign not found")
    camp = items[0]
    acct = get_ad_account(camp["account_id"])
    if not acct or acct["owner_sub"] != user_sub:
        raise HTTPException(status_code=403, detail="You do not own this campaign")
    return camp


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


# ── Creatives (ADS-002) ──────────────────────────────────────────────

@router.post("/campaigns/{campaign_id}/creatives", status_code=201)
async def create_creative_endpoint(
    campaign_id: str, body: CreativeCreateIn, ctx=Depends(require_ui_session)
):
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    return create_creative(campaign_id, camp["account_id"], body)


@router.get("/campaigns/{campaign_id}/creatives")
async def list_creatives_endpoint(campaign_id: str, ctx=Depends(require_ui_session)):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return list_creatives(campaign_id)


@router.get("/campaigns/{campaign_id}/creatives/{creative_id}")
async def get_creative_endpoint(
    campaign_id: str, creative_id: str, ctx=Depends(require_ui_session)
):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    cr = get_creative(campaign_id, creative_id)
    if not cr:
        raise HTTPException(status_code=404, detail="Creative not found")
    return cr


@router.patch("/campaigns/{campaign_id}/creatives/{creative_id}")
async def update_creative_endpoint(
    campaign_id: str,
    creative_id: str,
    body: CreativeUpdateIn,
    ctx=Depends(require_ui_session),
):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    cr = get_creative(campaign_id, creative_id)
    if not cr:
        raise HTTPException(status_code=404, detail="Creative not found")
    return update_creative(campaign_id, creative_id, body)


@router.delete("/campaigns/{campaign_id}/creatives/{creative_id}")
async def delete_creative_endpoint(
    campaign_id: str, creative_id: str, ctx=Depends(require_ui_session)
):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    cr = get_creative(campaign_id, creative_id)
    if not cr:
        raise HTTPException(status_code=404, detail="Creative not found")
    return delete_creative(campaign_id, creative_id)


@router.post("/campaigns/{campaign_id}/creatives/{creative_id}/submit")
async def submit_creative_endpoint(
    campaign_id: str, creative_id: str, ctx=Depends(require_ui_session)
):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    try:
        return submit_creative_for_review(campaign_id, creative_id)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Creative must be in draft status to submit for review",
        )


# ── Admin Creative Review (ADS-002) ──────────────────────────────────

@admin_router.get("/creatives/pending")
async def list_pending_creatives(user: AuthenticatedUser = Depends(require_admin_or_root)):
    return list_creatives_by_status("pending_review")


@admin_router.post("/creatives/{creative_id}/review")
async def review_creative_endpoint(
    creative_id: str,
    body: CreativeReviewIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    result = review_creative(
        creative_id, user.sub, body.decision, body.notes or ""
    )
    if not result:
        raise HTTPException(status_code=404, detail="Creative not found")
    return result


# ── Ad Serving (ADS-004) ──────────────────────────────────────────────

@router.post("/serve")
async def serve_ad_endpoint(body: AdServeRequestIn, ctx=Depends(require_ui_session)):
    """Request an ad for the given surface and context."""
    result = serve_ad(
        surface=body.surface,
        content_type=body.content_type or body.surface,
        creator_id=body.creator_id,
        content_id=body.content_id,
        slot_type=body.slot_type,
        user_id=ctx["user_sub"],
        user_context=body.user_context,
    )
    return result


@router.post("/track")
async def track_ad_event_endpoint(
    body: AdTrackEventIn,
    ctx=Depends(require_ui_session),
):
    """Track an ad event (impression, click, skip, complete)."""
    return track_ad_event(
        event=body.event,
        creative_id=body.creative_id,
        campaign_id=body.campaign_id,
        account_id=body.account_id,
        surface=body.surface,
        slot_type=body.slot_type,
        content_id=body.content_id,
        creator_id=body.creator_id,
        user_id=ctx["user_sub"],
    )


@router.get("/stats/{campaign_id}")
async def serving_stats_endpoint(campaign_id: str, ctx=Depends(require_ui_session)):
    """Get serving stats for a campaign (owner only)."""
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return get_serving_stats(campaign_id)
