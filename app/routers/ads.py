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
    CtaClickIn,
    CampaignCreateIn,
    CampaignReviewIn,
    CampaignUpdateIn,
    CreativeCreateIn,
    CreativeReviewIn,
    CreativeUpdateIn,
)
from app.services.ad_serving import serve_ad, track_ad_event, get_serving_stats, record_cta_click
from app.services.ad_accounts import (
    create_ad_account,
    create_syndicate_ad_account,
    list_syndicate_ad_accounts,
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


# Magic-byte signatures: mime_type → list of allowed byte prefixes.
# WebP is handled specially in _check_magic_bytes (RIFF at 0–3 + WEBP at 8–11).
_ASSET_MAGIC_BYTES: dict[str, list[bytes]] = {
    "image/jpeg": [b"\xff\xd8\xff"],            # JPEG SOI marker
    "image/png": [b"\x89PNG\r\n\x1a\n"],        # PNG signature (8 bytes)
    "image/webp": [b"RIFF"],                     # checked further below
    "video/mp4": [
        b"\x00\x00\x00\x18ftyp",
        b"\x00\x00\x00\x1cftyp",
        b"\x00\x00\x00\x20ftyp",
        b"ftyp",
    ],
}

_MIN_MAGIC_BYTES = 12  # longest signature window we inspect


def _check_magic_bytes(data: bytes, content_type: str) -> bool:
    """Return True if the file header matches the declared content_type."""
    if len(data) < _MIN_MAGIC_BYTES:
        return False
    head = data[:_MIN_MAGIC_BYTES]
    if content_type == "image/webp":
        # WebP: RIFF at bytes 0–3 and WEBP fourcc at bytes 8–11.
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    sigs = _ASSET_MAGIC_BYTES.get(content_type)
    if not sigs:
        return False
    return any(head.startswith(sig) for sig in sigs)


def _validate_asset(data: bytes, content_type: str | None, asset_type: str) -> None:
    if asset_type == "image":
        if content_type not in ("image/jpeg", "image/png", "image/webp"):
            raise HTTPException(400, "Image must be JPEG, PNG, or WebP")
        if len(data) > 5 * 1024 * 1024:
            raise HTTPException(400, "Image must be under 5 MB")
        if not _check_magic_bytes(data, content_type):
            raise HTTPException(400, "File content does not match declared image type")
    elif asset_type == "video":
        if content_type != "video/mp4":
            raise HTTPException(400, "Video must be MP4")
        if len(data) > 50 * 1024 * 1024:
            raise HTTPException(400, "Video must be under 50 MB")
        if not _check_magic_bytes(data, content_type):
            raise HTTPException(400, "File content does not match declared video type")
    elif asset_type == "thumbnail":
        if content_type not in ("image/jpeg", "image/png"):
            raise HTTPException(400, "Thumbnail must be JPEG or PNG")
        if len(data) > 2 * 1024 * 1024:
            raise HTTPException(400, "Thumbnail must be under 2 MB")
        if not _check_magic_bytes(data, content_type):
            raise HTTPException(400, "File content does not match declared thumbnail type")


# ── Advertiser Accounts ────────────────────────────────────────────

@router.post("/accounts", status_code=201)
async def create_account_endpoint(body: AdAccountCreateIn, ctx=Depends(require_ui_session)):
    try:
        return create_ad_account(ctx["user_sub"], body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


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
    # ADV2-301 (F3): a free self-promo campaign needs no funded/active ad account
    # (the creator promotes their OWN content for free); paid campaigns still
    # require an active account.
    if not getattr(body, "is_self_promo", False) and acct.get("status") != "active":
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
        content_owner_id=getattr(body, "content_owner_id", "") or "",
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
        ad_click_id=getattr(body, "ad_click_id", "") or "",
    )


@router.post("/cta-click")
async def cta_click_endpoint(body: CtaClickIn, request: Request, ctx=Depends(require_ui_session)):
    """ADV2-201/E2: a structured CTA tap. Charges CPC to the advertiser
    (funds-guarded, idempotent per ad_click_id+cta_type) EXCEPT tip (no
    advertiser charge; a tip credits the creator only). Records the tap for
    last-click attribution so a resulting purchase/subscribe fires CPA via the
    existing conversion path."""
    ip_address = request.client.host if request.client else ""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        ip_address = fwd.split(",")[0].strip()
    return record_cta_click(
        ad_click_id=body.ad_click_id,
        cta_type=body.cta_type,
        target_id=body.target_id,
        viewer_sub=ctx["user_sub"],
        ip_address=ip_address,
        user_agent=request.headers.get("user-agent", ""),
    )


# --- Sponsored-as-creator posts (ADV2-E4 / F4) ---------------------
from typing import Optional as _SPCPOptional, List as _SPCPList
from pydantic import BaseModel as _SPCPBase, Field as _SPCPField
from app.services import sponsored_creator_posts as _spcp


class SponsoredPostProposalIn(_SPCPBase):
    creator_sub: str = _SPCPField(..., min_length=1, max_length=128)
    body: str = _SPCPField("", max_length=20000)
    body_format: str = _SPCPField("plain", max_length=16)
    image_urls: _SPCPList[str] = _SPCPField(default_factory=list)
    video_id: _SPCPOptional[str] = None
    account_id: str = _SPCPField("", max_length=128)
    campaign_id: str = _SPCPField("", max_length=128)
    creative_id: str = _SPCPField("", max_length=128)
    sponsor_label: str = _SPCPField("", max_length=200)
    disclosure: str = _SPCPField("", max_length=500)


class SponsoredPostRejectIn(_SPCPBase):
    reason: str = _SPCPField("", max_length=500)


def _spcp_http(exc):
    return HTTPException(status_code=getattr(exc, "status_code", 400), detail=getattr(exc, "detail", str(exc)))


@router.post("/sponsored-posts/proposals", status_code=201)
async def create_sponsored_proposal_endpoint(body: SponsoredPostProposalIn, ctx=Depends(require_ui_session)):
    """ADV2-401: an advertiser drafts a sponsored post and PROPOSES it to a
    target creator. Does NOT publish until the creator approves."""
    if body.account_id:
        _require_account_owner(body.account_id, ctx["user_sub"])
    try:
        return _spcp.create_proposal(
            advertiser_sub=ctx["user_sub"],
            advertiser_account_id=body.account_id,
            creator_sub=body.creator_sub,
            body=body.body, body_format=body.body_format,
            image_urls=body.image_urls, video_id=body.video_id,
            campaign_id=body.campaign_id, creative_id=body.creative_id,
            sponsor_account_id=body.account_id,
            sponsor_label=body.sponsor_label, disclosure=body.disclosure,
        )
    except _spcp.SponsoredPostError as exc:
        raise _spcp_http(exc)


@router.get("/sponsored-posts/proposals/inbox")
async def sponsored_proposals_inbox_endpoint(ctx=Depends(require_ui_session)):
    """ADV2-403: the targeted creator's review queue (pending proposals)."""
    return {"proposals": _spcp.list_pending_for_creator(ctx["user_sub"])}


@router.get("/sponsored-posts/proposals/outbox")
async def sponsored_proposals_outbox_endpoint(ctx=Depends(require_ui_session)):
    return {"proposals": _spcp.list_for_advertiser(ctx["user_sub"])}


@router.post("/sponsored-posts/proposals/{proposal_id}/approve")
async def approve_sponsored_proposal_endpoint(proposal_id: str, ctx=Depends(require_ui_session)):
    """ADV2-402: only the TARGETED creator may approve -> publishes a post
    authored-by-creator carrying paid_partnership (NOT is_sponsored)."""
    try:
        return _spcp.approve_and_publish(proposal_id=proposal_id, creator_sub=ctx["user_sub"])
    except _spcp.SponsoredPostError as exc:
        raise _spcp_http(exc)


@router.post("/sponsored-posts/proposals/{proposal_id}/reject")
async def reject_sponsored_proposal_endpoint(proposal_id: str, body: _SPCPOptional[SponsoredPostRejectIn] = None, ctx=Depends(require_ui_session)):
    try:
        return _spcp.reject_proposal(proposal_id=proposal_id, creator_sub=ctx["user_sub"], reason=(body.reason if body else ""))
    except _spcp.SponsoredPostError as exc:
        raise _spcp_http(exc)


@router.get("/sponsored-posts/{post_id}/placement")
async def sponsored_post_placement_endpoint(post_id: str, ctx=Depends(require_ui_session)):
    """ADV2-404: lazy-mint the per-viewer ad-click for a published
    paid_partnership post and return impression/click tracking handles so the
    client can fire /ui/ads/track (advertiser billed, creator placement share).
    Returns {billable:false} for an organic post or a self-view."""
    from app.routers.newsfeed import ddb_get_item, pk_post, sk_post
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    handle = _spcp.mint_post_ad_click(viewer_sub=ctx["user_sub"], post=post)
    if not handle:
        return {"billable": False}
    out = {"billable": True}
    out.update(handle)
    return out


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


@admin_router.post("/internal/charge-impression")
async def internal_charge_impression(
    body: dict,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    from app.services.ad_billing import charge_impression
    return charge_impression(
        account_id=body["account_id"],
        campaign_id=body["campaign_id"],
        creative_id=body.get("creative_id", ""),
        creator_id=body.get("creator_id", ""),
        content_id=body.get("content_id", ""),
        bid_cpm_cents=body.get("bid_cpm_cents", 500),
    )


@admin_router.post("/internal/charge-click")
async def internal_charge_click(
    body: dict,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    from app.services.ad_billing import charge_click
    return charge_click(
        account_id=body["account_id"],
        campaign_id=body["campaign_id"],
        creative_id=body.get("creative_id", ""),
        creator_id=body.get("creator_id", ""),
        content_id=body.get("content_id", ""),
        bid_cpc_cents=body.get("bid_cpc_cents", 50),
    )


@admin_router.post("/internal/charge-conversion")
async def internal_charge_conversion(
    body: dict,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    from app.services.ad_billing import charge_conversion
    return charge_conversion(
        account_id=body["account_id"],
        campaign_id=body["campaign_id"],
        creative_id=body.get("creative_id", ""),
        creator_id=body.get("creator_id", ""),
        content_id=body.get("content_id", ""),
        bid_cpa_cents=body.get("bid_cpa_cents", 500),
    )


@admin_router.post("/charges/reverse")
async def internal_reverse_charge(
    body: dict,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """ADV-502: idempotently reverse an ad charge (fraud clawback / dispute)."""
    from app.services.ad_billing import reverse_ad_charge
    actor = getattr(user, "sub", "") or getattr(user, "user_id", "") or ""
    return reverse_ad_charge(
        account_id=body["account_id"],
        entry_id=body["entry_id"],
        reason=body.get("reason", "admin_reversal"),
        actor=actor,
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


@router.get("/roas")
async def roas_report_endpoint(
    account_id: str = Query(...),
    campaign_id: str | None = Query(default=None),
    days: int = Query(default=30, ge=1, le=365),
    ctx=Depends(require_ui_session),
):
    """ADV-501: per-account + per-campaign ROAS (spend / impressions / clicks /
    CTR / conversions / CPA / ROAS) sourced from the ad_billing ledger."""
    from app.services.ad_roas import roas_report
    _require_account_owner(account_id, ctx["user_sub"])
    return roas_report(account_id, campaign_id, days)


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


# ── Ad-messaging: shared engine + F5 sponsored mass-messaging (ADV2-E5) ─────
from typing import Optional as _AMOptional
from pydantic import BaseModel as _AMBase, Field as _AMField
from app.services import ad_messaging as _admsg


class SponsoredMessageOfferIn(_AMBase):
    creator_sub: str = _AMField(..., min_length=1, max_length=128)
    body: str = _AMField(..., min_length=1, max_length=20000)
    cta_url: str = _AMField("", max_length=2000)
    image_url: str = _AMField("", max_length=2000)
    account_id: str = _AMField("", max_length=128)
    campaign_id: str = _AMField("", max_length=128)
    creative_id: str = _AMField("", max_length=128)
    sponsor_label: str = _AMField("", max_length=200)
    segment: str = _AMField("followers", max_length=32)


class SponsoredMessageApproveIn(_AMBase):
    body: str = _AMField("", max_length=20000)  # optional creator wording override (D3)


class SponsoredMessageRejectIn(_AMBase):
    reason: str = _AMField("", max_length=500)


class AdMessagePrefsIn(_AMBase):
    allow_ad_messages: bool = True


def _admsg_http(exc):
    return HTTPException(status_code=getattr(exc, "status_code", 400),
                         detail=getattr(exc, "detail", str(exc)))


@router.post("/sponsored-messages/offers", status_code=201)
async def create_sponsored_message_offer_endpoint(body: SponsoredMessageOfferIn, ctx=Depends(require_ui_session)):
    """ADV2-501: an advertiser drafts a sponsored MESSAGE and offers it to a
    creator. Does NOT send until the creator approves (D3)."""
    if body.account_id:
        _require_account_owner(body.account_id, ctx["user_sub"])
    try:
        return _admsg.create_offer(
            advertiser_sub=ctx["user_sub"], advertiser_account_id=body.account_id,
            creator_sub=body.creator_sub, body=body.body, cta_url=body.cta_url,
            image_url=body.image_url, campaign_id=body.campaign_id, creative_id=body.creative_id,
            sponsor_account_id=body.account_id, sponsor_label=body.sponsor_label, segment=body.segment,
        )
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.get("/sponsored-messages/offers/inbox")
async def sponsored_message_inbox_endpoint(ctx=Depends(require_ui_session)):
    """ADV2-507: the targeted creator's review queue (pending offers)."""
    return {"offers": _admsg.list_pending_for_creator(ctx["user_sub"])}


@router.get("/sponsored-messages/offers/outbox")
async def sponsored_message_outbox_endpoint(ctx=Depends(require_ui_session)):
    return {"offers": _admsg.list_for_advertiser(ctx["user_sub"])}


@router.post("/sponsored-messages/offers/{offer_id}/approve")
async def approve_sponsored_message_endpoint(offer_id: str, body: _AMOptional[SponsoredMessageApproveIn] = None, ctx=Depends(require_ui_session)):
    """ADV2-501/503: ONLY the targeted creator may approve -> the message is sent
    to the creator's audience AS the creator; advertiser billed hybrid (delivered
    2c), creator credited the 70% placement share."""
    try:
        return _admsg.approve_and_send(
            offer_id=offer_id, creator_sub=ctx["user_sub"],
            body_override=(body.body if body else None),
        )
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.post("/sponsored-messages/offers/{offer_id}/reject")
async def reject_sponsored_message_endpoint(offer_id: str, body: _AMOptional[SponsoredMessageRejectIn] = None, ctx=Depends(require_ui_session)):
    try:
        return _admsg.reject_offer(offer_id=offer_id, creator_sub=ctx["user_sub"], reason=(body.reason if body else ""))
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.get("/sponsored-messages/sends/{send_id}")
async def sponsored_message_send_endpoint(send_id: str, ctx=Depends(require_ui_session)):
    """ADV2-509: campaign progress -- delivered/opened/clicked + spend."""
    send = _admsg.get_send(send_id)
    if not send:
        raise HTTPException(status_code=404, detail="Send not found")
    if ctx["user_sub"] not in (str(send.get("advertiser_sub") or ""), str(send.get("creator_sub") or "")):
        raise HTTPException(status_code=403, detail="Not authorized for this send")
    return send


@router.post("/messages/{ad_click_id}/open")
async def ad_message_open_endpoint(ad_click_id: str, ctx=Depends(require_ui_session)):
    """ADV2-504/605: recipient opened/read the ad message -> +open surcharge
    (once, idempotent)."""
    try:
        return _admsg.record_open(ad_click_id=ad_click_id, actor_sub=ctx["user_sub"])
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.post("/messages/{ad_click_id}/click")
async def ad_message_click_endpoint(ad_click_id: str, ctx=Depends(require_ui_session)):
    """ADV2-504/605: recipient tapped the CTA/link -> +click surcharge (once,
    idempotent)."""
    try:
        return _admsg.record_click(ad_click_id=ad_click_id, actor_sub=ctx["user_sub"])
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.get("/messages/ad-preferences")
async def get_ad_message_prefs_endpoint(ctx=Depends(require_ui_session)):
    """ADV2-511/601: per-user ad-messages opt-out state."""
    return {"allow_ad_messages": _admsg.user_accepts_ad_messages(ctx["user_sub"])}


@router.put("/messages/ad-preferences")
async def set_ad_message_prefs_endpoint(body: AdMessagePrefsIn, ctx=Depends(require_ui_session)):
    """ADV2-511/601: set the per-user ad-messages opt-out. A user with a
    relationship receives ad DMs UNLESS they opt out here."""
    return _admsg.set_ad_messages_optout(ctx["user_sub"], bool(body.allow_ad_messages))


# ── Ad-messaging: F6 advertiser direct mass-DM (ADV2-E5 / ADV2-601..610) ────
# Reuses the shared ad_messaging engine (PLATFORM-100%, no content owner) via
# app.services.ad_dm_audience. The per-user ad opt-out endpoints + the
# open/click surcharge endpoints are SHARED with F5 (already defined above).
from app.services import ad_dm_audience as _addm


class AdMassDmCreateIn(_AMBase):
    account_id: str = _AMField(..., min_length=1, max_length=128)
    campaign_id: str = _AMField(..., min_length=1, max_length=128)
    body: str = _AMField(..., min_length=1, max_length=20000)
    cta_url: str = _AMField("", max_length=2000)
    image_url: str = _AMField("", max_length=2000)
    creative_id: str = _AMField("", max_length=128)
    sponsor_label: str = _AMField("", max_length=200)


def _addm_http(exc):
    return HTTPException(status_code=getattr(exc, "status_code", 400),
                         detail=getattr(exc, "detail", str(exc)))


@router.get("/mass-dm/audience/preview")
async def ad_mass_dm_audience_preview_endpoint(ctx=Depends(require_ui_session)):
    """ADV2-602/607: preview the advertiser's eligible mass-DM audience (existing
    relationships minus ad opt-outs) before composing/sending."""
    return _addm.resolve_advertiser_audience(ctx["user_sub"])


@router.post("/mass-dm/campaigns", status_code=201)
async def ad_mass_dm_create_endpoint(body: AdMassDmCreateIn, ctx=Depends(require_ui_session)):
    """ADV2-603/604/605/606: advertiser composes + sends a direct mass-DM AS the
    advertiser to ONLY eligible relationships (followers/subscribers) minus ad
    opt-outs. Billed the hybrid stack (delivered 2c / open +5c / click +10c),
    PLATFORM-100% (no content owner). Funds-guarded: an empty balance stops the
    send."""
    _require_account_owner(body.account_id, ctx["user_sub"])
    try:
        return _addm.send_mass_dm(
            advertiser_sub=ctx["user_sub"], account_id=body.account_id,
            campaign_id=body.campaign_id, body=body.body, cta_url=body.cta_url,
            image_url=body.image_url, creative_id=body.creative_id,
            sponsor_label=body.sponsor_label,
        )
    except _addm.AdDmError as exc:
        raise _addm_http(exc)
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.get("/mass-dm/campaigns")
async def ad_mass_dm_list_endpoint(ctx=Depends(require_ui_session)):
    """ADV2-608: the advertiser's F6 mass-DM sends (delivered/opened/clicked +
    spend counters)."""
    return {"sends": _addm.list_advertiser_sends(ctx["user_sub"])}


@router.get("/mass-dm/campaigns/{send_id}")
async def ad_mass_dm_detail_endpoint(send_id: str, ctx=Depends(require_ui_session)):
    """ADV2-608: F6 mass-DM campaign detail (advertiser-scoped)."""
    send = _addm.get_send(send_id)
    if not send:
        raise HTTPException(status_code=404, detail="Send not found")
    if str(send.get("advertiser_sub") or "") != ctx["user_sub"]:
        raise HTTPException(status_code=403, detail="Not authorized for this send")
    return send


@router.post("/mass-dm/campaigns/{send_id}/cancel")
async def ad_mass_dm_cancel_endpoint(send_id: str, ctx=Depends(require_ui_session)):
    """ADV2-603: cancel a mass-DM send (synchronous -> a fully-sent campaign is
    final and returns 409)."""
    try:
        return _addm.cancel_send(send_id=send_id, advertiser_sub=ctx["user_sub"])
    except _addm.AdDmError as exc:
        raise _addm_http(exc)


# ── Syndicate-owned advertiser accounts (ADV2-701) ─────────────────────────
# A syndicate-level advertiser: an ad account owned by a syndicate, managed by
# its admin. Reuses the campaign/creative/funding endpoints above (owner_sub is
# the admin). Gated by syndicates._require_admin.

@router.post("/syndicates/{syndicate_id}/accounts", status_code=201)
async def create_syndicate_ad_account_endpoint(
    syndicate_id: str, body: AdAccountCreateIn, ctx=Depends(require_ui_session)
):
    from app.services.syndicates import _require_admin
    _require_admin(syndicate_id, ctx["user_sub"])  # raises 403/404
    try:
        return create_syndicate_ad_account(syndicate_id, ctx["user_sub"], body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/syndicates/{syndicate_id}/accounts")
async def list_syndicate_ad_accounts_endpoint(
    syndicate_id: str, ctx=Depends(require_ui_session)
):
    from app.services.syndicates import _require_admin
    _require_admin(syndicate_id, ctx["user_sub"])
    return list_syndicate_ad_accounts(syndicate_id, ctx["user_sub"])
