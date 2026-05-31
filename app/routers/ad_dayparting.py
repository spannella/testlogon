"""Ad scheduling & dayparting endpoints (ADS-016).

Extends the existing ads system with per-campaign dayparting schedules
(days-of-week + active hours, optional timezone) and flight scheduling.
The schedule is stored on the existing campaign record (no new table).

All endpoints are advertiser-facing and scoped to the campaign owner via
``_require_campaign_owner`` (mirrors the pattern in ``app/routers/ads.py``).
"""

from __future__ import annotations

from typing import Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.tables import T
from app.models import CampaignScheduleUpdate
from app.services import ad_dayparting
from app.services.ad_accounts import get_ad_account
from app.services.ad_campaigns import get_campaign
from app.services.sessions import require_ui_session

ad_dayparting_router = APIRouter(prefix="/ui/ads/scheduling", tags=["ad-dayparting"])


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


# ── Templates ────────────────────────────────────────────────────────


@ad_dayparting_router.get("/templates")
async def list_schedule_templates(ctx=Depends(require_ui_session)):
    """List predefined dayparting schedule templates."""
    return {"templates": ad_dayparting.SCHEDULE_TEMPLATES}


# ── Schedule get/set ─────────────────────────────────────────────────


@ad_dayparting_router.get("/campaigns/{campaign_id}/schedule")
async def get_campaign_schedule_endpoint(
    campaign_id: str, ctx=Depends(require_ui_session)
):
    """Get the current dayparting / flight schedule for a campaign."""
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    return ad_dayparting.get_campaign_schedule(camp)


@ad_dayparting_router.patch("/campaigns/{campaign_id}/schedule")
async def update_campaign_schedule_endpoint(
    campaign_id: str,
    body: CampaignScheduleUpdate,
    ctx=Depends(require_ui_session),
):
    """Update dayparting and/or flights and/or timezone on a campaign."""
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    provided = body.model_fields_set

    dayparting = (
        body.dayparting.model_dump() if body.dayparting is not None else None
    )
    flights = (
        [f.model_dump() for f in body.flights] if body.flights is not None else None
    )

    try:
        return ad_dayparting.update_campaign_schedule(
            account_id=camp["account_id"],
            campaign_id=campaign_id,
            dayparting=dayparting,
            flights=flights,
            campaign_timezone=body.campaign_timezone,
            set_dayparting="dayparting" in provided,
            set_flights="flights" in provided,
            campaign=camp,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Eligibility & pacing ─────────────────────────────────────────────


@ad_dayparting_router.get("/campaigns/{campaign_id}/schedule/eligibility")
async def schedule_eligibility_endpoint(
    campaign_id: str,
    now: Optional[int] = Query(default=None, description="Override 'now' (Unix ts) for deterministic checks"),
    ctx=Depends(require_ui_session),
):
    """Check whether the campaign is eligible to serve right now."""
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    eligible, debug = ad_dayparting.is_campaign_eligible_now(
        dayparting=camp.get("dayparting"),
        campaign_timezone=camp.get("campaign_timezone", "UTC"),
        now=now,
    )
    active_flight = ad_dayparting.get_active_flight(
        flights=camp.get("flights"), now=now
    )
    return {**debug, "eligible": eligible, "active_flight": active_flight}


@ad_dayparting_router.get("/campaigns/{campaign_id}/schedule/pacing")
async def schedule_pacing_endpoint(
    campaign_id: str,
    now: Optional[int] = Query(default=None),
    ctx=Depends(require_ui_session),
):
    """Get dayparting-aware budget pacing for the campaign."""
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    daily = int(camp.get("daily_budget_cents") or camp.get("budget_cents") or 0)
    return ad_dayparting.calculate_dayparted_budget(
        daily_budget_cents=daily,
        dayparting=camp.get("dayparting"),
        campaign_timezone=camp.get("campaign_timezone", "UTC"),
        now=now,
    )
