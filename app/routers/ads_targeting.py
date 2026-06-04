"""Ad Targeting + Creator Ad Preferences (ADS-003).

Extends the ads platform with targeting sets, audience estimation,
creator ad settings, and advertiser block lists.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.services.sessions import require_ui_session
from app.models import (
    AudienceEstimateOut,
    CreatorAdSettingsIn,
    TargetingCreateIn,
    TargetingOut,
)


# Local request model for advertiser blocks. Defined here rather than
# imported from app.models because app.models contains a duplicate
# ``AdBlockIn`` definition with a spurious required ``startup_seconds``
# field that incorrectly rejects valid block requests with HTTP 422.
class AdBlockIn(BaseModel):
    account_id: str
    reason: str = ""


router = APIRouter(prefix="/ui/ads", tags=["ads"])


# ── Helpers ────────────────────────────────────────────────────────


def _require_campaign_owner(campaign_id: str, user_sub: str) -> dict:
    """Verify user owns the campaign (via its account). Returns campaign dict.

    When ADS-001 services are available, use them; otherwise use a lightweight
    lookup via the ad_campaigns table directly.
    """
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
    try:
        from app.services.ad_accounts import get_ad_account
        acct = get_ad_account(camp["account_id"])
        if not acct or acct["owner_sub"] != user_sub:
            raise HTTPException(status_code=403, detail="You do not own this campaign")
    except ImportError:
        # Fallback if ADS-001 services not available
        if camp.get("owner_id") != user_sub:
            raise HTTPException(status_code=403, detail="You do not own this campaign")
    return camp


# ── Targeting (ADS-003) ──────────────────────────────────────────────


@router.post("/campaigns/{campaign_id}/targeting", status_code=201)
def create_targeting_endpoint(
    campaign_id: str, body: TargetingCreateIn, ctx=Depends(require_ui_session)
):
    from app.services.ad_targeting import create_targeting

    campaign = _require_campaign_owner(campaign_id, ctx["user_sub"])
    return create_targeting(campaign_id, campaign["account_id"], body)


@router.get("/campaigns/{campaign_id}/targeting")
def list_targeting_endpoint(campaign_id: str, ctx=Depends(require_ui_session)):
    from app.services.ad_targeting import list_targeting_sets

    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return list_targeting_sets(campaign_id)


@router.get("/campaigns/{campaign_id}/targeting/{target_set_id}")
def get_targeting_endpoint(
    campaign_id: str, target_set_id: str, ctx=Depends(require_ui_session)
):
    from app.services.ad_targeting import get_targeting

    _require_campaign_owner(campaign_id, ctx["user_sub"])
    item = get_targeting(campaign_id, target_set_id)
    if not item:
        raise HTTPException(status_code=404, detail="Targeting set not found")
    return item


@router.put("/campaigns/{campaign_id}/targeting/{target_set_id}")
def update_targeting_endpoint(
    campaign_id: str,
    target_set_id: str,
    body: TargetingCreateIn,
    ctx=Depends(require_ui_session),
):
    from app.services.ad_targeting import update_targeting

    _require_campaign_owner(campaign_id, ctx["user_sub"])
    result = update_targeting(campaign_id, target_set_id, body)
    if result is None:
        raise HTTPException(status_code=404, detail="Targeting set not found")
    return result


@router.delete("/campaigns/{campaign_id}/targeting/{target_set_id}")
def delete_targeting_endpoint(
    campaign_id: str, target_set_id: str, ctx=Depends(require_ui_session)
):
    from app.services.ad_targeting import delete_targeting

    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return delete_targeting(campaign_id, target_set_id)


@router.post("/campaigns/{campaign_id}/targeting/estimate")
def estimate_audience_endpoint(
    campaign_id: str, body: TargetingCreateIn, ctx=Depends(require_ui_session)
):
    from app.services.ad_targeting import estimate_audience

    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return estimate_audience(body)


# ── Creator Ad Preferences (ADS-003) ─────────────────────────────────


@router.get("/creator/ad-settings")
def get_ad_settings(ctx=Depends(require_ui_session)):
    from app.services.creator_ad_prefs import get_creator_ad_settings

    return get_creator_ad_settings(ctx["user_sub"])


@router.patch("/creator/ad-settings")
def update_ad_settings(body: CreatorAdSettingsIn, ctx=Depends(require_ui_session)):
    from app.services.creator_ad_prefs import update_creator_ad_settings

    return update_creator_ad_settings(ctx["user_sub"], body)


@router.post("/creator/ad-blocks")
def block_advertiser_endpoint(body: AdBlockIn, ctx=Depends(require_ui_session)):
    from app.services.creator_ad_prefs import block_advertiser

    return block_advertiser(ctx["user_sub"], body.account_id, body.reason)


@router.delete("/creator/ad-blocks/{account_id}")
def unblock_advertiser_endpoint(account_id: str, ctx=Depends(require_ui_session)):
    from app.services.creator_ad_prefs import unblock_advertiser

    return unblock_advertiser(ctx["user_sub"], account_id)


@router.get("/creator/ad-blocks")
def list_blocked_advertisers_endpoint(ctx=Depends(require_ui_session)):
    from app.services.creator_ad_prefs import list_blocked_advertisers

    return list_blocked_advertisers(ctx["user_sub"])
