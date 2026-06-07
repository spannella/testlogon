"""Ad Performance Optimization endpoints (ADS-017).

Advertiser-facing optimization API scoped to the campaign owner (mirrors the
ownership pattern in ``app/routers/ads.py`` / ``ad_dayparting.py``). Builds on
the existing analytics (``ad_analytics``) and campaign/creative records.

Recommendation generation is deterministic and triggered explicitly via the
``generate`` endpoint so E2E tests don't depend on a background timer.
"""

from __future__ import annotations

from typing import Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.tables import T
from app.models import (
    ABTestRequest,
    OptimizationConfigUpdate,
)
from app.services import ad_optimization
from app.services.ad_accounts import get_ad_account
from app.services.sessions import require_ui_session

ad_optimization_router = APIRouter(
    prefix="/ui/ads/optimization", tags=["ad-optimization"]
)


# ── Ownership helper ─────────────────────────────────────────────────


def _require_campaign_owner(campaign_id: str, user_sub: str) -> dict:
    """Verify the user owns the campaign (via its account). Returns the campaign."""
    resp = T.ad_campaigns.query(
        IndexName="ByCampaignId",
        KeyConditionExpression=Key("campaign_id").eq(campaign_id),
    )
    items = resp.get("Items", [])
    if not items:
        raise HTTPException(status_code=404, detail="Campaign not found")
    camp = items[0]
    acct = get_ad_account(camp["account_id"])
    if not acct or acct["owner_sub"] != user_sub:
        raise HTTPException(status_code=403, detail="You do not own this campaign")
    return camp


# ── Recommendations: generate / list / history ───────────────────────


@ad_optimization_router.post("/campaigns/{campaign_id}/generate")
async def generate_recommendations_endpoint(
    campaign_id: str,
    days: int = Query(default=7, ge=1, le=90),
    ctx=Depends(require_ui_session),
):
    """Run a deterministic optimization pass and persist recommendations."""
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    return ad_optimization.generate_recommendations(
        account_id=camp["account_id"], campaign=camp, days=days
    )


@ad_optimization_router.get("/campaigns/{campaign_id}/recommendations")
async def list_recommendations_endpoint(
    campaign_id: str,
    status: Optional[str] = Query(default=None),
    ctx=Depends(require_ui_session),
):
    """List recommendation history for a campaign (newest first)."""
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return {
        "recommendations": ad_optimization.list_recommendations(campaign_id, status)
    }


@ad_optimization_router.post(
    "/campaigns/{campaign_id}/recommendations/{recommendation_id}/apply"
)
async def apply_recommendation_endpoint(
    campaign_id: str,
    recommendation_id: str,
    ctx=Depends(require_ui_session),
):
    """Apply a recommendation (mutates the underlying campaign/creative)."""
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    try:
        return ad_optimization.apply_recommendation(
            account_id=camp["account_id"],
            campaign=camp,
            recommendation_id=recommendation_id,
        )
    except ValueError as exc:
        msg = str(exc)
        status = 404 if "not found" in msg.lower() else 400
        raise HTTPException(status_code=status, detail=msg)


@ad_optimization_router.post(
    "/campaigns/{campaign_id}/recommendations/{recommendation_id}/dismiss"
)
async def dismiss_recommendation_endpoint(
    campaign_id: str,
    recommendation_id: str,
    ctx=Depends(require_ui_session),
):
    """Dismiss a recommendation without applying it."""
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    try:
        return ad_optimization.dismiss_recommendation(
            campaign_id=campaign_id, recommendation_id=recommendation_id
        )
    except ValueError as exc:
        msg = str(exc)
        status = 404 if "not found" in msg.lower() else 400
        raise HTTPException(status_code=status, detail=msg)


# ── A/B test / suggested bid / budget recommendation ──────────────────


@ad_optimization_router.get("/campaigns/{campaign_id}/ab-test")
async def ab_test_endpoint(
    campaign_id: str,
    creative_a_id: str = Query(...),
    creative_b_id: str = Query(...),
    confidence_level: float = Query(default=0.95, ge=0.80, le=0.99),
    days: int = Query(default=30, ge=1, le=90),
    ctx=Depends(require_ui_session),
):
    """Two-proportion Z-test between two creatives in the campaign."""
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    # Validate the request shape (also surfaces 422 on bad confidence levels).
    ABTestRequest(
        creative_a_id=creative_a_id,
        creative_b_id=creative_b_id,
        confidence_level=confidence_level,
    )
    stats = {
        s["creative_id"]: s
        for s in ad_optimization.get_creative_stats(
            camp["account_id"], campaign_id, days=days
        )
    }
    a = stats.get(creative_a_id, {"impressions": 0, "clicks": 0})
    b = stats.get(creative_b_id, {"impressions": 0, "clicks": 0})
    return ad_optimization.ab_test_significance(
        variant_a={"impressions": a.get("impressions", 0), "clicks": a.get("clicks", 0)},
        variant_b={"impressions": b.get("impressions", 0), "clicks": b.get("clicks", 0)},
        confidence_level=confidence_level,
    )


@ad_optimization_router.get("/campaigns/{campaign_id}/suggested-bid")
async def suggested_bid_endpoint(
    campaign_id: str, ctx=Depends(require_ui_session)
):
    """Suggested bid range based on campaign targeting specificity."""
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    targeting = camp.get("targeting") if isinstance(camp.get("targeting"), dict) else None
    return ad_optimization.calculate_suggested_bid(targeting=targeting)


@ad_optimization_router.get("/campaigns/{campaign_id}/budget-recommendation")
async def budget_recommendation_endpoint(
    campaign_id: str,
    desired_daily_reach: int = Query(default=1000, ge=1),
    ctx=Depends(require_ui_session),
):
    """Recommended daily budget that scales with desired reach."""
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    targeting = camp.get("targeting") if isinstance(camp.get("targeting"), dict) else None
    return ad_optimization.recommend_daily_budget(
        targeting=targeting, desired_daily_reach=desired_daily_reach
    )


# ── ROAS (Return on Ad Spend) ──────────────────────────────────────────


@ad_optimization_router.get("/campaigns/{campaign_id}/roas")
async def campaign_roas_endpoint(
    campaign_id: str,
    days: int = Query(default=30, ge=1, le=365),
    ctx=Depends(require_ui_session),
):
    """Return ROAS metrics (conversion revenue / spend) for a campaign.

    Sources conversion revenue from affiliate redemption rows and spend from
    the analytics rollups. Advertiser must own the campaign (GAP-0062).
    """
    from app.services.ad_roas import calculate_campaign_roas

    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    return calculate_campaign_roas(
        account_id=camp["account_id"],
        campaign_id=campaign_id,
        days=days,
    )


# ── Optimization config ───────────────────────────────────────────────


@ad_optimization_router.patch("/campaigns/{campaign_id}/optimization-config")
async def update_optimization_config_endpoint(
    campaign_id: str,
    body: OptimizationConfigUpdate,
    ctx=Depends(require_ui_session),
):
    """Update auto-optimize toggle + threshold configuration on a campaign."""
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    return ad_optimization.update_optimization_config(camp, body.model_dump())
