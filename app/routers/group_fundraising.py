"""Group advertising & fundraising REST endpoints (GROUP-003).

Authenticated admin/member endpoints live under ``/ui/groups/fundraising``;
public donor-facing endpoints live under ``/public`` (no auth).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.models import (
    GroupCampaignListOut,
    GroupCampaignOut,
    GroupCampaignStatsOut,
    GroupCreateCampaignIn,
    GroupCreateFundraiserIn,
    GroupDonateIn,
    GroupDonationListOut,
    GroupDonationOut,
    GroupDonationReceiptOut,
    GroupFundraiserListOut,
    GroupFundraiserOut,
    GroupPublicFundraiserOut,
    GroupUpdateCampaignIn,
    GroupUpdateFundraiserIn,
)
from app.services import group_fundraising as svc
from app.services import user_groups
from app.services.sessions import require_ui_session

group_fundraising_router = APIRouter(prefix="/ui/groups/fundraising", tags=["group-fundraising"])
public_group_fundraising_router = APIRouter(prefix="/public", tags=["group-fundraising-public"])


def _check_enabled() -> None:
    if not S.group_fundraising_enabled:
        raise HTTPException(status_code=404, detail="Group fundraising is not enabled")


# ---------------------------------------------------------------------------
# Advertising campaigns (admin)
# ---------------------------------------------------------------------------


@group_fundraising_router.post("/{group_id}/campaigns")
def create_campaign(
    group_id: str,
    body: GroupCreateCampaignIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> GroupCampaignOut:
    _check_enabled()
    result = svc.create_campaign(
        group_id=group_id,
        admin_id=ctx["user_sub"],
        name=body.name,
        daily_budget_cents=body.daily_budget_cents,
        lifetime_budget_cents=body.lifetime_budget_cents,
        creative_text=body.creative_text,
        creative_image_url=body.creative_image_url,
    )
    return GroupCampaignOut(**result)


@group_fundraising_router.get("/{group_id}/campaigns")
def list_campaigns(
    group_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> GroupCampaignListOut:
    _check_enabled()
    user_groups.require_membership(group_id, ctx["user_sub"])
    return GroupCampaignListOut(campaigns=svc.list_campaigns(group_id))


@group_fundraising_router.get("/{group_id}/campaigns/{campaign_id}/stats")
def campaign_stats(
    group_id: str,
    campaign_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> GroupCampaignStatsOut:
    _check_enabled()
    user_groups.require_membership(group_id, ctx["user_sub"])
    return GroupCampaignStatsOut(**svc.get_campaign_stats(group_id, campaign_id))


@group_fundraising_router.patch("/{group_id}/campaigns/{campaign_id}")
def update_campaign(
    group_id: str,
    campaign_id: str,
    body: GroupUpdateCampaignIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> GroupCampaignOut:
    _check_enabled()
    result = svc.update_campaign(
        group_id=group_id,
        admin_id=ctx["user_sub"],
        campaign_id=campaign_id,
        status=body.status,
        daily_budget_cents=body.daily_budget_cents,
    )
    return GroupCampaignOut(**result)


# ---------------------------------------------------------------------------
# Fundraisers (admin/member)
# ---------------------------------------------------------------------------


@group_fundraising_router.post("/{group_id}/fundraisers")
def create_fundraiser(
    group_id: str,
    body: GroupCreateFundraiserIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> GroupFundraiserOut:
    _check_enabled()
    result = svc.create_fundraiser(
        group_id=group_id,
        admin_id=ctx["user_sub"],
        title=body.title,
        description=body.description,
        goal_cents=body.goal_cents,
        cover_image_url=body.cover_image_url,
        ends_at=body.ends_at,
    )
    return GroupFundraiserOut(**result)


@group_fundraising_router.get("/{group_id}/fundraisers")
def list_fundraisers(
    group_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> GroupFundraiserListOut:
    _check_enabled()
    user_groups.require_membership(group_id, ctx["user_sub"])
    return GroupFundraiserListOut(fundraisers=svc.list_fundraisers(group_id))


@group_fundraising_router.get("/{group_id}/fundraisers/{fundraiser_id}")
def get_fundraiser(
    group_id: str,
    fundraiser_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> GroupFundraiserOut:
    _check_enabled()
    user_groups.require_membership(group_id, ctx["user_sub"])
    return GroupFundraiserOut(**svc.get_fundraiser(group_id, fundraiser_id))


@group_fundraising_router.patch("/{group_id}/fundraisers/{fundraiser_id}")
def update_fundraiser(
    group_id: str,
    fundraiser_id: str,
    body: GroupUpdateFundraiserIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> GroupFundraiserOut:
    _check_enabled()
    result = svc.update_fundraiser(
        group_id=group_id,
        admin_id=ctx["user_sub"],
        fundraiser_id=fundraiser_id,
        title=body.title,
        description=body.description,
        goal_cents=body.goal_cents,
        status=body.status,
        ends_at=body.ends_at,
    )
    return GroupFundraiserOut(**result)


@group_fundraising_router.get("/{group_id}/fundraisers/{fundraiser_id}/donations")
def list_donations(
    group_id: str,
    fundraiser_id: str,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> GroupDonationListOut:
    _check_enabled()
    # Admin-only: only the group admin may see the donor list.
    user_groups.require_admin(group_id, ctx["user_sub"])
    result = svc.list_donations(fundraiser_id, cursor=cursor, limit=limit)
    return GroupDonationListOut(**result)


# ---------------------------------------------------------------------------
# Public donor-facing endpoints (no auth)
# ---------------------------------------------------------------------------


@public_group_fundraising_router.get("/fundraisers/{fundraiser_id}")
def public_fundraiser(fundraiser_id: str) -> GroupPublicFundraiserOut:
    _check_enabled()
    return GroupPublicFundraiserOut(**svc.get_public_fundraiser(fundraiser_id))


@public_group_fundraising_router.post("/fundraisers/{fundraiser_id}/donate", status_code=201)
def public_donate(fundraiser_id: str, body: GroupDonateIn) -> GroupDonationOut:
    _check_enabled()
    result = svc.create_donation(
        fundraiser_id=fundraiser_id,
        amount_cents=body.amount_cents,
        donor_name=body.donor_name,
        donor_email=body.donor_email,
    )
    return GroupDonationOut(**result)


@public_group_fundraising_router.get("/fundraisers/{fundraiser_id}/donations/{donation_id}/receipt")
def public_receipt(fundraiser_id: str, donation_id: str) -> GroupDonationReceiptOut:
    _check_enabled()
    return GroupDonationReceiptOut(**svc.get_donation_receipt(donation_id, fundraiser_id))
