"""Syndicate advertising campaign router (SYND-006).

A syndicate runs advertising as a unit: the syndicate admin creates/manages ad
campaigns funded from the syndicate treasury; all members can view campaigns and
analytics. Orchestrates the ``syndicate_advertising`` service which reuses the
treasury debit/refund path and syndicate admin/role checks.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.models import (
    SyndicateCampaignAnalyticsOut,
    SyndicateCampaignBudgetAddIn,
    SyndicateCampaignCreateIn,
    SyndicateCampaignDailyStatsOut,
    SyndicateCampaignImpressionIn,
    SyndicateCampaignOut,
    SyndicateCampaignStatusUpdateIn,
)
from app.services import syndicate_advertising as svc
from app.services import syndicates as syndicate_svc
from app.services.sessions import require_ui_session

syndicate_advertising_router = APIRouter(
    prefix="/ui/syndicates/advertising", tags=["syndicate-advertising"]
)


def _campaign_out(c: dict) -> SyndicateCampaignOut:
    return SyndicateCampaignOut(
        campaign_id=c.get("campaign_id", ""),
        syndicate_id=c.get("syndicate_id", ""),
        name=c.get("name", ""),
        description=c.get("description", ""),
        status=c.get("status", ""),
        budget_cents=int(c.get("budget_cents", 0)),
        spent_cents=int(c.get("spent_cents", 0)),
        remaining_cents=int(c.get("remaining_cents", 0)),
        creative=dict(c.get("creative", {}) or {}),
        targeting=dict(c.get("targeting", {}) or {}),
        start_date=c.get("start_date", "") or "",
        end_date=c.get("end_date", "") or "",
        created_by=c.get("created_by", ""),
        created_at=int(c.get("created_at", 0)),
        updated_at=int(c.get("updated_at", 0)),
        stats_summary=dict(c.get("stats_summary", {}) or {}),
    )


@syndicate_advertising_router.post(
    "/{syndicate_id}/campaigns", response_model=SyndicateCampaignOut
)
def create_campaign(
    syndicate_id: str,
    body: SyndicateCampaignCreateIn,
    session=Depends(require_ui_session),
):
    """Create an ad campaign funded by the treasury (admin only)."""
    campaign = svc.create_campaign(
        syndicate_id=syndicate_id,
        admin_sub=session["user_sub"],
        name=body.name,
        description=body.description,
        budget_cents=body.budget_cents,
        creative=body.creative.model_dump(),
        targeting=body.targeting.model_dump() if body.targeting else None,
        start_date=body.start_date,
        end_date=body.end_date,
    )
    return _campaign_out(campaign)


@syndicate_advertising_router.get(
    "/{syndicate_id}/campaigns", response_model=list[SyndicateCampaignOut]
)
def list_campaigns(
    syndicate_id: str,
    status: str | None = Query(default=None),
    session=Depends(require_ui_session),
):
    """List all syndicate campaigns (members only)."""
    syndicate_svc._require_is_member(syndicate_id, session["user_sub"])
    campaigns = svc.list_campaigns(syndicate_id, status=status)
    return [_campaign_out(c) for c in campaigns]


@syndicate_advertising_router.get(
    "/{syndicate_id}/campaigns/{campaign_id}", response_model=SyndicateCampaignOut
)
def get_campaign(
    syndicate_id: str,
    campaign_id: str,
    session=Depends(require_ui_session),
):
    """Get campaign details (members only)."""
    syndicate_svc._require_is_member(syndicate_id, session["user_sub"])
    return _campaign_out(svc.get_campaign(syndicate_id, campaign_id))


@syndicate_advertising_router.post(
    "/{syndicate_id}/campaigns/{campaign_id}/status",
    response_model=SyndicateCampaignOut,
)
def update_status(
    syndicate_id: str,
    campaign_id: str,
    body: SyndicateCampaignStatusUpdateIn,
    session=Depends(require_ui_session),
):
    """Pause / resume / cancel a campaign (admin only)."""
    campaign = svc.update_campaign_status(
        syndicate_id=syndicate_id,
        campaign_id=campaign_id,
        admin_sub=session["user_sub"],
        new_status=body.status,
    )
    return _campaign_out(campaign)


@syndicate_advertising_router.post(
    "/{syndicate_id}/campaigns/{campaign_id}/add-budget",
    response_model=SyndicateCampaignOut,
)
def add_budget(
    syndicate_id: str,
    campaign_id: str,
    body: SyndicateCampaignBudgetAddIn,
    session=Depends(require_ui_session),
):
    """Add more budget from the treasury (admin only)."""
    campaign = svc.add_campaign_budget(
        syndicate_id=syndicate_id,
        campaign_id=campaign_id,
        admin_sub=session["user_sub"],
        additional_cents=body.additional_cents,
    )
    return _campaign_out(campaign)


@syndicate_advertising_router.post(
    "/{syndicate_id}/campaigns/{campaign_id}/impression"
)
def record_impression(
    syndicate_id: str,
    campaign_id: str,
    body: SyndicateCampaignImpressionIn,
    session=Depends(require_ui_session),
):
    """Record an ad impression/click; draws spend from the campaign budget."""
    syndicate_svc._require_is_member(syndicate_id, session["user_sub"])
    return svc.record_campaign_impression(
        syndicate_id=syndicate_id,
        campaign_id=campaign_id,
        viewer_user_id=body.viewer_user_id or session["user_sub"],
        clicked=body.clicked,
    )


@syndicate_advertising_router.get(
    "/{syndicate_id}/campaigns/{campaign_id}/analytics",
    response_model=SyndicateCampaignAnalyticsOut,
)
def get_analytics(
    syndicate_id: str,
    campaign_id: str,
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    session=Depends(require_ui_session),
):
    """Daily analytics + totals (members only)."""
    syndicate_svc._require_is_member(syndicate_id, session["user_sub"])
    result = svc.get_campaign_analytics(
        syndicate_id, campaign_id, from_date=from_date, to_date=to_date
    )
    return SyndicateCampaignAnalyticsOut(
        campaign_id=result["campaign_id"],
        daily=[SyndicateCampaignDailyStatsOut(**d) for d in result["daily"]],
        totals=result["totals"],
    )
