"""Group advertising & fundraising REST endpoints (GROUP-003).

Authenticated admin/member endpoints live under ``/ui/groups/fundraising``;
public donor-facing endpoints live under ``/public`` (no auth).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy

from app.auth.deps import AuthenticatedUser, require_root_session
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

group_fundraising_router = APIRouter(prefix="/ui/groups/fundraising", tags=["group-fundraising"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])
public_group_fundraising_router = APIRouter(prefix="/public", tags=["group-fundraising-public"])
# GAP-0218: production donation-confirmation surface (Stripe webhook + ROOT
# break-glass). In dev/test donations auto-confirm; in prod the treasury is only
# credited once a real Stripe ``payment_intent.succeeded`` event proves the
# charge cleared.
fundraising_internal_router = APIRouter(prefix="/internal", tags=["group-fundraising-internal"])


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


# ---------------------------------------------------------------------------
# Production donation confirmation (GAP-0218)
#
# In dev/test donations auto-confirm synchronously (stripe-mock cannot complete
# off-session payments). In production the auto-confirm path is disabled, so a
# donation stays ``pending`` until either:
#   1. A real Stripe ``payment_intent.succeeded`` webhook fires (the normal
#      path), or
#   2. A ROOT operator manually confirms it (break-glass for a missed webhook).
# Only then is the group treasury credited.
# ---------------------------------------------------------------------------


@fundraising_internal_router.post("/fundraisers/stripe/webhook")
async def fundraising_stripe_webhook(req: Request) -> Dict[str, Any]:
    """Stripe webhook for fundraising donations (``payment_intent.succeeded``).

    Verifies the Stripe signature, then confirms the matching pending donation
    (credits the treasury, increments ``raised_cents``). The PaymentIntent must
    carry ``metadata.fundraiser_id`` and ``metadata.donation_id``. Idempotent:
    ``confirm_donation`` returns ``already_confirmed`` for completed donations,
    so Stripe retries are safe.
    """
    _check_enabled()
    if not S.stripe_webhook_secret:
        raise HTTPException(status_code=501, detail="Stripe webhook secret not configured")

    payload = await req.body()
    sig = req.headers.get("stripe-signature")
    try:
        import stripe  # local import: stripe SDK is optional in some envs

        event = stripe.Webhook.construct_event(
            payload=payload, sig_header=sig, secret=S.stripe_webhook_secret
        )
    except Exception as exc:  # invalid signature / malformed payload
        raise HTTPException(status_code=400, detail=f"Webhook error: {exc}") from exc

    event_type = event["type"]
    if event_type != "payment_intent.succeeded":
        return {"received": True, "ignored": event_type}

    pi = event["data"]["object"]
    pi_id = pi.get("id")
    metadata = pi.get("metadata", {}) or {}
    fundraiser_id = metadata.get("fundraiser_id")
    donation_id = metadata.get("donation_id")
    if not fundraiser_id or not donation_id:
        # Not a fundraising PaymentIntent — nothing for us to do.
        return {"received": True, "ignored": "missing_fundraising_metadata"}

    result = svc.confirm_donation_by_payment_intent(
        fundraiser_id=fundraiser_id,
        donation_id=donation_id,
        stripe_pi_id=pi_id,
    )
    return {"received": True, "confirmed": True, **result}


@group_fundraising_router.post("/{group_id}/fundraisers/{fundraiser_id}/donations/{donation_id}/confirm")
def root_confirm_donation(
    group_id: str,
    fundraiser_id: str,
    donation_id: str,
    user: AuthenticatedUser = Depends(require_root_session),
) -> Dict[str, Any]:
    """ROOT-only break-glass: manually confirm a pending donation.

    Used when a Stripe ``payment_intent.succeeded`` webhook was missed (endpoint
    downtime, network failure). Credits the treasury for the donation. Idempotent.
    """
    _check_enabled()
    return svc.confirm_donation(fundraiser_id, donation_id)
