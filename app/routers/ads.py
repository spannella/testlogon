"""Advertiser account + campaign + creative endpoints, ad serving, billing, plus admin review (ADS-001/002/004/007)."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, Form

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.services.sessions import require_ui_session
from app.models import (
    AdAccountCreateIn,
    AdDepositIn,
    AdAccountReviewIn,
    AdFeedbackIn,
    AdServeRequestIn,
    AdTrackEventIn,
    CampaignCreateIn,
    CampaignReviewIn,
    CampaignUpdateIn,
    CreativeCreateIn,
    CreativeReviewIn,
    CreativeUpdateIn,
)
from app.services.ad_serving import serve_ad, track_ad_event, get_serving_stats
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
    upload_creative_asset,
)

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
    # Verify ownership via account
    acct = get_ad_account(camp["account_id"])
    if not acct or acct["owner_sub"] != user_sub:
        raise HTTPException(status_code=403, detail="You do not own this campaign")
    return camp


def _validate_asset(data: bytes, content_type: str | None, asset_type: str) -> None:
    if asset_type == "image":
        if content_type not in ("image/jpeg", "image/png", "image/webp"):
            raise HTTPException(400, "Image must be JPEG, PNG, or WebP")
        if len(data) > 5 * 1024 * 1024:
            raise HTTPException(400, "Image must be under 5 MB")
    elif asset_type == "video":
        if content_type != "video/mp4":
            raise HTTPException(400, "Video must be MP4")
        if len(data) > 50 * 1024 * 1024:
            raise HTTPException(400, "Video must be under 50 MB")
    elif asset_type == "thumbnail":
        if content_type not in ("image/jpeg", "image/png"):
            raise HTTPException(400, "Thumbnail must be JPEG or PNG")
        if len(data) > 2 * 1024 * 1024:
            raise HTTPException(400, "Thumbnail must be under 2 MB")


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


@router.post("/campaigns/{campaign_id}/creatives/{creative_id}/upload")
async def upload_asset_endpoint(
    campaign_id: str,
    creative_id: str,
    file: UploadFile = File(...),
    asset_type: str = Form("image"),
    ctx=Depends(require_ui_session),
):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    cr = get_creative(campaign_id, creative_id)
    if not cr:
        raise HTTPException(status_code=404, detail="Creative not found")
    data = await file.read()
    _validate_asset(data, file.content_type, asset_type)
    url = upload_creative_asset(creative_id, campaign_id, data, file.content_type or "", asset_type)
    return {"url": url}


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
    result = serve_ad(
        surface=body.surface,
        content_type=getattr(body, "content_type", None) or body.surface,
        creator_id=body.creator_id,
        content_id=body.content_id,
        slot_type=body.slot_type,
        user_id=ctx["user_sub"],
        user_context=getattr(body, "user_context", None),
    )
    return result


@router.post("/track")
async def track_ad_event_endpoint(body: AdTrackEventIn, request: Request, ctx=Depends(require_ui_session)):
    ip_address = request.client.host if request.client else ""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        ip_address = fwd.split(",")[0].strip()
    return track_ad_event(
        event=body.event,
        creative_id=body.creative_id,
        campaign_id=body.campaign_id,
        account_id=body.account_id,
        surface=body.surface,
        slot_type=getattr(body, "slot_type", ""),
        content_id=getattr(body, "content_id", ""),
        creator_id=getattr(body, "creator_id", ""),
        user_id=ctx["user_sub"],
        ip_address=ip_address,
        user_agent=body.user_agent or request.headers.get("user-agent", ""),
        view_time_ms=body.view_time_ms,
        geo_country=body.geo_country,
    )


@router.get("/stats/{campaign_id}")
async def serving_stats_endpoint(campaign_id: str, ctx=Depends(require_ui_session)):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return get_serving_stats(campaign_id)


# ── Ad Feedback & Sponsored Posts (ADS-005) ──────────────────────────────


@router.post("/feedback")
async def ad_feedback_endpoint(body: AdFeedbackIn, ctx=Depends(require_ui_session)):
    """Record user feedback on a sponsored post (hide, not_relevant, repetitive, offensive)."""
    from app.services.ad_feedback import record_ad_feedback
    try:
        return record_ad_feedback(
            user_id=ctx["user_sub"],
            creative_id=body.creative_id,
            campaign_id=body.campaign_id,
            feedback_type=body.feedback_type,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/why/{creative_id}")
async def why_this_ad(creative_id: str, ctx=Depends(require_ui_session)):
    """Return a vague targeting category for the ad (never exposes specific targeting)."""
    return {
        "reason": "Based on your activity on the platform",
        "categories": ["general"],
        "note": "Ads are selected based on the content you view and your platform activity.",
    }


# ── Ad Billing (ADS-007) ──────────────────────────────────────────

@router.post("/accounts/{account_id}/deposit")
async def deposit_endpoint(account_id: str, body: AdDepositIn, ctx=Depends(require_ui_session)):
    from app.services.ad_billing import deposit_funds
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
    from app.services.ad_billing import get_billing_history
    _require_account_owner(account_id, ctx["user_sub"])
    return get_billing_history(account_id, limit)


@router.get("/accounts/{account_id}/billing/campaigns/{campaign_id}")
async def campaign_spending_endpoint(
    account_id: str,
    campaign_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    ctx=Depends(require_ui_session),
):
    from app.services.ad_billing import get_campaign_spending
    _require_account_owner(account_id, ctx["user_sub"])
    return get_campaign_spending(campaign_id, limit)


@router.get("/accounts/{account_id}/invoices/{month}")
async def invoice_endpoint(account_id: str, month: str, ctx=Depends(require_ui_session)):
    from app.services.ad_billing import generate_invoice
    _require_account_owner(account_id, ctx["user_sub"])
    if not re.match(r"^\d{4}-\d{2}$", month):
        raise HTTPException(status_code=400, detail="Invalid month format, use YYYY-MM")
    return generate_invoice(account_id, month)


@router.post("/internal/charge-impression")
async def internal_charge_impression(body: dict, ctx=Depends(require_ui_session)):
    from app.services.ad_billing import charge_impression
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
    from app.services.ad_billing import charge_click
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
    from app.services.ad_billing import charge_conversion
    return charge_conversion(
        account_id=body["account_id"],
        campaign_id=body["campaign_id"],
        creative_id=body.get("creative_id", ""),
        creator_id=body.get("creator_id", ""),
        content_id=body.get("content_id", ""),
        bid_cpa_cents=body.get("bid_cpa_cents", 500),
    )


# ── Ad Analytics (ADS-008) ──────────────────────────────────────────

_VALID_GRANULARITIES = {"hourly", "daily", "weekly", "monthly"}
_VALID_DIMENSIONS = {"creative", "surface", "targeting"}


@router.get("/analytics/summary")
async def analytics_summary_endpoint(
    account_id: str = Query(...),
    campaign_id: str | None = Query(default=None),
    days: int = Query(default=30, ge=1, le=365),
    ctx=Depends(require_ui_session),
):
    from app.services.ad_analytics import get_summary
    _require_account_owner(account_id, ctx["user_sub"])
    return get_summary(account_id, campaign_id, days)


@router.get("/analytics/timeseries")
async def analytics_timeseries_endpoint(
    account_id: str = Query(...),
    campaign_id: str | None = Query(default=None),
    days: int = Query(default=30, ge=1, le=365),
    granularity: str = Query(default="daily"),
    ctx=Depends(require_ui_session),
):
    from app.services.ad_analytics import get_timeseries
    _require_account_owner(account_id, ctx["user_sub"])
    if granularity not in _VALID_GRANULARITIES:
        raise HTTPException(400, "Granularity must be hourly, daily, weekly, or monthly")
    return get_timeseries(account_id, campaign_id, days, granularity)


@router.get("/analytics/breakdown")
async def analytics_breakdown_endpoint(
    account_id: str = Query(...),
    campaign_id: str | None = Query(default=None),
    dimension: str = Query(default="creative"),
    days: int = Query(default=30, ge=1, le=365),
    ctx=Depends(require_ui_session),
):
    from app.services.ad_analytics import get_breakdown
    _require_account_owner(account_id, ctx["user_sub"])
    if dimension not in _VALID_DIMENSIONS:
        raise HTTPException(400, "Dimension must be creative, surface, or targeting")
    return get_breakdown(account_id, campaign_id, dimension, days)


@router.get("/analytics/export")
async def analytics_export_endpoint(
    account_id: str = Query(...),
    campaign_id: str | None = Query(default=None),
    days: int = Query(default=30, ge=1, le=365),
    ctx=Depends(require_ui_session),
):
    from app.services.ad_analytics import export_csv
    from fastapi.responses import Response as FastAPIResponse
    _require_account_owner(account_id, ctx["user_sub"])
    csv_data = export_csv(account_id, campaign_id, days)
    return FastAPIResponse(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ad_analytics.csv"},
    )
