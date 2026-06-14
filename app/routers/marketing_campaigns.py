"""Marketing campaigns HTTP surface (MKT-011)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse

from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.services.sessions import require_ui_session
from app.models import (
    MarketingCampaignCreateIn,
    MarketingCampaignUpdateIn,
    CampaignTransitionIn,
    ContactListCreateIn,
    ContactListUpdateIn,
    ContactListMemberIn,
    PartySegmentCreateIn,
    PartySegmentUpdateIn,
    TrackingCodeCreateIn,
)

router = APIRouter(prefix="/ui/marketing", tags=["marketing"])
admin_router = APIRouter(prefix="/ui/admin/marketing", tags=["marketing-admin"])
public_router = APIRouter(tags=["marketing-public"])


def _require_enabled() -> None:
    """Raise 404 when the marketing campaigns module is disabled."""
    if not S.marketing_campaigns_enabled:
        raise HTTPException(status_code=404, detail="Marketing campaigns are not enabled")


def _require_campaign_owner(campaign_id: str, user_sub: str) -> dict:
    """Return the campaign item or raise 404 (never 403, to prevent enumeration)."""
    from app.services.marketing_campaigns import get_campaign_by_id
    item = get_campaign_by_id(campaign_id)
    if not item or item.get("owner_id") != user_sub:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return item


# ---------------------------------------------------------------------------
# Campaign endpoints
# ---------------------------------------------------------------------------


@router.post("/campaigns")
async def create_campaign_endpoint(
    data: MarketingCampaignCreateIn,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.marketing_campaigns import create_campaign
    return create_campaign(session["user_sub"], data)


@router.get("/campaigns")
async def list_campaigns_endpoint(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    from app.services.marketing_campaigns import list_campaigns
    return list_campaigns(session["user_sub"], limit=limit, cursor=cursor)


@router.get("/campaigns/{campaign_id}")
async def get_campaign_endpoint(
    campaign_id: str,
    session: dict = Depends(require_ui_session),
):
    from app.services.marketing_campaigns import get_campaign
    item = get_campaign(session["user_sub"], campaign_id)
    if not item:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return item


@router.patch("/campaigns/{campaign_id}")
async def update_campaign_endpoint(
    campaign_id: str,
    data: MarketingCampaignUpdateIn,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    _require_campaign_owner(campaign_id, session["user_sub"])
    from app.services.marketing_campaigns import update_campaign
    return update_campaign(session["user_sub"], campaign_id, data)


@router.post("/campaigns/{campaign_id}/transition")
async def transition_campaign_endpoint(
    campaign_id: str,
    data: CampaignTransitionIn,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    _require_campaign_owner(campaign_id, session["user_sub"])
    from app.services.marketing_campaigns import transition_campaign
    return transition_campaign(session["user_sub"], campaign_id, data.target_status)


@router.get("/campaigns/{campaign_id}/attribution")
async def get_attribution_endpoint(
    campaign_id: str,
    session: dict = Depends(require_ui_session),
):
    _require_campaign_owner(campaign_id, session["user_sub"])
    from app.services.marketing_campaigns import compute_attribution
    return compute_attribution(session["user_sub"], campaign_id)


@router.post("/campaigns/{campaign_id}/send")
async def send_campaign_endpoint(
    campaign_id: str,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    _require_campaign_owner(campaign_id, session["user_sub"])
    from app.services.marketing_campaigns import send_campaign
    return send_campaign(campaign_id, session["user_sub"])


@router.post("/campaigns/{campaign_id}/ad-campaign")
async def attach_ad_campaign_endpoint(
    campaign_id: str,
    ad_campaign_id: str = Query(...),
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    _require_campaign_owner(campaign_id, session["user_sub"])
    from app.services.marketing_campaigns import attach_ad_campaign
    return attach_ad_campaign(session["user_sub"], campaign_id, ad_campaign_id)


@router.delete("/campaigns/{campaign_id}/ad-campaign")
async def detach_ad_campaign_endpoint(
    campaign_id: str,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    _require_campaign_owner(campaign_id, session["user_sub"])
    from app.services.marketing_campaigns import detach_ad_campaign
    return detach_ad_campaign(session["user_sub"], campaign_id)


@router.post("/campaigns/{campaign_id}/promo-codes/{code_id}")
async def attach_promo_code_endpoint(
    campaign_id: str,
    code_id: str,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    _require_campaign_owner(campaign_id, session["user_sub"])
    from app.services.marketing_campaigns import attach_promo_code
    return attach_promo_code(session["user_sub"], campaign_id, code_id)


@router.delete("/campaigns/{campaign_id}/promo-codes/{code_id}")
async def detach_promo_code_endpoint(
    campaign_id: str,
    code_id: str,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    _require_campaign_owner(campaign_id, session["user_sub"])
    from app.services.marketing_campaigns import detach_promo_code
    return detach_promo_code(session["user_sub"], campaign_id, code_id)


# ---------------------------------------------------------------------------
# Contact-list endpoints
# ---------------------------------------------------------------------------


@router.post("/lists")
async def create_list_endpoint(
    data: ContactListCreateIn,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.marketing_lists import create_list
    return create_list(session["user_sub"], data)


@router.get("/lists")
async def list_lists_endpoint(
    session: dict = Depends(require_ui_session),
):
    from app.services.marketing_lists import list_lists
    return list_lists(session["user_sub"])


@router.get("/lists/{list_id}")
async def get_list_endpoint(
    list_id: str,
    session: dict = Depends(require_ui_session),
):
    from app.services.marketing_lists import get_list
    item = get_list(session["user_sub"], list_id)
    if not item:
        raise HTTPException(status_code=404, detail="List not found")
    return item


@router.patch("/lists/{list_id}")
async def update_list_endpoint(
    list_id: str,
    data: ContactListUpdateIn,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.marketing_lists import update_list
    return update_list(session["user_sub"], list_id, data)


@router.delete("/lists/{list_id}")
async def delete_list_endpoint(
    list_id: str,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.marketing_lists import delete_list
    delete_list(session["user_sub"], list_id)
    return {"ok": True}


@router.post("/lists/{list_id}/members")
async def add_member_endpoint(
    list_id: str,
    data: ContactListMemberIn,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.marketing_lists import add_member
    return add_member(session["user_sub"], list_id, data)


@router.delete("/lists/{list_id}/members/{party_id}")
async def remove_member_endpoint(
    list_id: str,
    party_id: str,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.marketing_lists import remove_member
    remove_member(session["user_sub"], list_id, party_id)
    return {"ok": True}


@router.get("/lists/{list_id}/members")
async def list_members_endpoint(
    list_id: str,
    include_suppressed: bool = Query(default=True),
    session: dict = Depends(require_ui_session),
):
    from app.services.marketing_lists import list_members
    return list_members(list_id, include_suppressed=include_suppressed)


@router.post("/lists/{list_id}/seed-from-contacts")
async def seed_from_contacts_endpoint(
    list_id: str,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.marketing_lists import seed_from_contacts
    return seed_from_contacts(session["user_sub"], list_id)


# ---------------------------------------------------------------------------
# Segment endpoints
# ---------------------------------------------------------------------------


@router.post("/segments")
async def create_segment_endpoint(
    data: PartySegmentCreateIn,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.party_segments import create_segment
    return create_segment(session["user_sub"], data)


@router.get("/segments")
async def list_segments_endpoint(
    session: dict = Depends(require_ui_session),
):
    from app.services.party_segments import list_segments
    return list_segments(session["user_sub"])


@router.get("/segments/{segment_id}")
async def get_segment_endpoint(
    segment_id: str,
    session: dict = Depends(require_ui_session),
):
    from app.services.party_segments import get_segment
    item = get_segment(session["user_sub"], segment_id)
    if not item:
        raise HTTPException(status_code=404, detail="Segment not found")
    return item


@router.patch("/segments/{segment_id}")
async def update_segment_endpoint(
    segment_id: str,
    data: PartySegmentUpdateIn,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.party_segments import update_segment
    return update_segment(session["user_sub"], segment_id, data)


@router.delete("/segments/{segment_id}")
async def delete_segment_endpoint(
    segment_id: str,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.party_segments import delete_segment
    delete_segment(session["user_sub"], segment_id)
    return {"ok": True}


@router.get("/segments/{segment_id}/evaluate")
async def evaluate_segment_endpoint(
    segment_id: str,
    session: dict = Depends(require_ui_session),
):
    from app.services.party_segments import evaluate_segment
    return evaluate_segment(segment_id, session["user_sub"])


@router.post("/segments/{segment_id}/snapshot")
async def snapshot_segment_endpoint(
    segment_id: str,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.party_segments import snapshot_segment
    return snapshot_segment(session["user_sub"], segment_id)


@router.get("/segments/{segment_id}/snapshots")
async def list_snapshots_endpoint(
    segment_id: str,
    limit: int = Query(default=10, ge=1, le=50),
    session: dict = Depends(require_ui_session),
):
    from app.services.party_segments import list_snapshots
    return list_snapshots(segment_id, session["user_sub"], limit=limit)


@router.get("/segments/{segment_id}/snapshots/{snap_id}/members")
async def list_snapshot_members_endpoint(
    segment_id: str,
    snap_id: str,
    include_opted_out: bool = Query(default=True),
    session: dict = Depends(require_ui_session),
):
    from app.services.party_segments import list_snapshot_members
    return list_snapshot_members(
        segment_id, snap_id, session["user_sub"], include_opted_out=include_opted_out
    )


# ---------------------------------------------------------------------------
# Tracking-code endpoints
# ---------------------------------------------------------------------------


@router.post("/tracking-codes")
async def create_tracking_code_endpoint(
    data: TrackingCodeCreateIn,
    session: dict = Depends(require_ui_session),
):
    _require_enabled()
    from app.services.tracking_codes import create_tracking_code
    return create_tracking_code(session["user_sub"], data)


@router.get("/tracking-codes/{code_slug}")
async def get_tracking_code_endpoint(
    code_slug: str,
    session: dict = Depends(require_ui_session),
):
    from app.services.tracking_codes import get_tracking_code
    item = get_tracking_code(code_slug)
    if not item:
        raise HTTPException(status_code=404, detail="Tracking code not found")
    return item


# Public tracking visit redirect (no auth) — declared first to avoid being
# captured by a dynamic /{campaign_id} route.
@public_router.get("/ui/marketing/t/{code_slug}")
async def tracking_visit_redirect(
    code_slug: str,
    request: Request,
    redirect_to: Optional[str] = Query(default=None),
):
    """Public: record a visit and redirect. No auth required."""
    from app.services.tracking_codes import record_visit, get_tracking_code

    # Extract optional party_id from query param (anon otherwise)
    party_id: Optional[str] = request.query_params.get("pid")
    referrer: Optional[str] = request.headers.get("referer")

    record_visit(code_slug, party_id=party_id, referrer=referrer)

    # Build redirect URL with open-redirect guard
    base = S.public_base_url
    target = base + "/"
    if redirect_to and redirect_to.startswith(base):
        target = redirect_to

    return RedirectResponse(url=target, status_code=302)


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------


@admin_router.get("/campaigns")
async def admin_list_campaigns_endpoint(
    status: str = Query(default="draft"),
    limit: int = Query(default=50, ge=1, le=200),
    session: dict = Depends(require_admin_or_root),
):
    from app.services.marketing_campaigns import list_campaigns_by_status
    return list_campaigns_by_status(status, limit=limit)


@admin_router.patch("/campaigns/{campaign_id}/review")
async def admin_review_campaign_endpoint(
    campaign_id: str,
    data: CampaignTransitionIn,
    session: dict = Depends(require_admin_or_root),
):
    """Admin: force-transition a campaign (approve/reject)."""
    from app.services.marketing_campaigns import get_campaign_by_id, transition_campaign
    item = get_campaign_by_id(campaign_id)
    if not item:
        raise HTTPException(status_code=404, detail="Campaign not found")
    owner_id = item["owner_id"]
    return transition_campaign(owner_id, campaign_id, data.target_status)
