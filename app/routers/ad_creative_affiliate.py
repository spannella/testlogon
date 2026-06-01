"""
Ad Creative Affiliate Discounts router (ADS-015).

Lets an advertiser attach an affiliate tracking code + promo discount code to
an ad creative, tracks clicks/redemptions, and validates the discount at
checkout. Reuses promo_codes (discounts) and affiliate_links (attribution).

Auth: require_ui_session (cookie-based) for all endpoints. The advertiser must
own the ad account that owns the creative. Click + redeem are viewer-scoped
(any authenticated user may click an ad / redeem at checkout).

Prefix: /ui/ads/affiliate
"""
from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from app.core.settings import S
from app.models import (
    AdAffiliateClickResult,
    AdAffiliateDiscountAttachIn,
    AdAffiliateDiscountListOut,
    AdAffiliateDiscountOut,
    AdAffiliateDiscountUpdateIn,
    AdAffiliateRedeemIn,
    AdAffiliateRedeemOut,
    AdAffiliateStatsOut,
)
from app.services import ad_creative_affiliate as svc
from app.services.sessions import require_ui_session

ad_creative_affiliate_router = APIRouter(prefix="/ui/ads/affiliate", tags=["ad-creative-affiliate"])


def _require_enabled() -> None:
    if not S.ad_creative_affiliate_enabled:
        raise HTTPException(404, "Ad creative affiliate discounts are not enabled")


# ─── Discount config CRUD ─────────────────────────────────────────


@ad_creative_affiliate_router.post(
    "/creatives/{creative_id}/discount",
    response_model=AdAffiliateDiscountOut,
    status_code=201,
)
async def attach_discount(
    creative_id: str,
    body: AdAffiliateDiscountAttachIn,
    session: Dict = Depends(require_ui_session),
) -> AdAffiliateDiscountOut:
    _require_enabled()
    config, err = svc.attach_discount(
        creative_id=creative_id,
        campaign_id=body.campaign_id,
        advertiser_id=session["user_sub"],
        affiliate_code=body.affiliate_code,
        promo_code=body.promo_code,
        promo_value_display=body.promo_value_display,
        click_through_url=body.click_through_url,
    )
    if err:
        raise HTTPException(err[0], err[1])
    return AdAffiliateDiscountOut(**config)


@ad_creative_affiliate_router.get(
    "/creatives/{creative_id}/discount",
    response_model=AdAffiliateDiscountOut,
)
async def get_discount(
    creative_id: str,
    session: Dict = Depends(require_ui_session),
) -> AdAffiliateDiscountOut:
    _require_enabled()
    config = svc.get_config(creative_id)
    if not config:
        raise HTTPException(404, "No affiliate discount attached to this creative")
    if config.get("owner_sub") != session["user_sub"]:
        raise HTTPException(403, "You do not own this creative")
    return AdAffiliateDiscountOut(**config)


@ad_creative_affiliate_router.get(
    "/discounts",
    response_model=AdAffiliateDiscountListOut,
)
async def list_discounts(
    session: Dict = Depends(require_ui_session),
) -> AdAffiliateDiscountListOut:
    _require_enabled()
    items = svc.list_configs(session["user_sub"])
    return AdAffiliateDiscountListOut(items=[AdAffiliateDiscountOut(**i) for i in items])


@ad_creative_affiliate_router.patch(
    "/creatives/{creative_id}/discount",
    response_model=AdAffiliateDiscountOut,
)
async def update_discount(
    creative_id: str,
    body: AdAffiliateDiscountUpdateIn,
    session: Dict = Depends(require_ui_session),
) -> AdAffiliateDiscountOut:
    _require_enabled()
    config, err = svc.update_discount(
        creative_id=creative_id,
        advertiser_id=session["user_sub"],
        affiliate_code=body.affiliate_code,
        promo_code=body.promo_code,
        promo_value_display=body.promo_value_display,
        click_through_url=body.click_through_url,
        clear_affiliate_code=body.clear_affiliate_code,
        clear_promo_code=body.clear_promo_code,
    )
    if err:
        raise HTTPException(err[0], err[1])
    return AdAffiliateDiscountOut(**config)


@ad_creative_affiliate_router.delete("/creatives/{creative_id}/discount")
async def remove_discount(
    creative_id: str,
    session: Dict = Depends(require_ui_session),
) -> Dict[str, bool]:
    _require_enabled()
    err = svc.remove_discount(creative_id=creative_id, advertiser_id=session["user_sub"])
    if err:
        raise HTTPException(err[0], err[1])
    return {"ok": True}


@ad_creative_affiliate_router.get(
    "/creatives/{creative_id}/stats",
    response_model=AdAffiliateStatsOut,
)
async def get_discount_stats(
    creative_id: str,
    session: Dict = Depends(require_ui_session),
) -> AdAffiliateStatsOut:
    _require_enabled()
    stats, err = svc.get_stats(creative_id, session["user_sub"])
    if err:
        raise HTTPException(err[0], err[1])
    return AdAffiliateStatsOut(**stats)


# ─── Click redirect (viewer-scoped) ───────────────────────────────


@ad_creative_affiliate_router.get("/click/{creative_id}")
async def click_redirect(
    creative_id: str,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    """Process an ad click: record attribution, set the promo auto-apply
    cookie, and 302-redirect to the click-through URL with ``?ref=``."""
    _require_enabled()
    result, err = svc.handle_click(
        creative_id=creative_id,
        user_id=session["user_sub"],
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
    )
    if err:
        raise HTTPException(err[0], err[1])

    response = RedirectResponse(url=result["redirect_url"], status_code=302)
    promo_code = result.get("promo_code")
    if promo_code:
        response.set_cookie(
            "ad_promo_code",
            promo_code,
            max_age=S.ad_creative_affiliate_promo_cookie_max_age,
            path="/",
            httponly=False,
            samesite="lax",
        )
    return response


@ad_creative_affiliate_router.get(
    "/click/{creative_id}/preview",
    response_model=AdAffiliateClickResult,
)
async def click_preview(
    creative_id: str,
    request: Request,
    session: Dict = Depends(require_ui_session),
) -> AdAffiliateClickResult:
    """Same attribution as the redirect, but returns JSON (for SPA clients
    that prefer to navigate client-side / read the result)."""
    _require_enabled()
    result, err = svc.handle_click(
        creative_id=creative_id,
        user_id=session["user_sub"],
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
    )
    if err:
        raise HTTPException(err[0], err[1])
    return AdAffiliateClickResult(**result)


# ─── Redemption / checkout validation (viewer-scoped) ─────────────


@ad_creative_affiliate_router.post(
    "/redeem",
    response_model=AdAffiliateRedeemOut,
)
async def redeem_discount(
    body: AdAffiliateRedeemIn,
    session: Dict = Depends(require_ui_session),
) -> AdAffiliateRedeemOut:
    """Validate the creative's promo code at checkout and record the
    redemption + affiliate conversion when valid."""
    _require_enabled()
    result, err = svc.redeem(
        creative_id=body.creative_id,
        user_id=session["user_sub"],
        checkout_type=body.checkout_type,
        item_price_cents=body.item_price_cents,
        creator_user_id=body.creator_user_id,
        order_id=body.order_id,
    )
    if err:
        raise HTTPException(err[0], err[1])
    return AdAffiliateRedeemOut(**result)
