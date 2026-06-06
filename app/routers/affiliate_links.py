"""
Affiliate Links router (CREATOR-004).

Creator management endpoints + public redirect endpoint.
Auth: require_ui_session (cookie-based) for management; public redirect has no auth.
"""
from __future__ import annotations

from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.responses import RedirectResponse

from app.core.settings import S
from app.models import (
    AffiliateClickTimeSeriesOut,
    AffiliateEarningsBreakdownOut,
    AffiliateSummaryOut,
    AffiliateTopProductsOut,
)
from app.services.affiliate_links import (
    create_affiliate_link,
    delete_link,
    get_click_timeseries,
    get_creator_summary,
    get_earnings_breakdown,
    get_link,
    get_link_by_code,
    get_link_stats,
    get_top_products,
    list_creator_links,
    record_click,
    record_conversion,
)
from app.services.sessions import require_ui_session

router = APIRouter(tags=["affiliate-links"])


def _require_enabled() -> None:
    if not S.affiliate_links_enabled:
        raise HTTPException(status_code=404, detail="Affiliate links are not enabled")


def _link_to_out(item: dict) -> dict:
    """Convert a DDB item to the API response shape."""
    click_count = int(item.get("click_count", 0))
    unique_clicks = int(item.get("unique_click_count", 0))
    conversions = int(item.get("conversion_count", 0))
    return {
        "link_id": item["link_id"],
        "affiliate_user_id": item.get("affiliate_user_id", ""),
        "product_owner_id": item.get("product_owner_id", ""),
        "target_type": item.get("target_type", ""),
        "target_id": item.get("target_id", ""),
        "target_name": item.get("target_name", ""),
        "tracking_code": item.get("tracking_code", ""),
        "short_url": item.get("short_url", ""),
        "destination_url": item.get("destination_url", ""),
        "commission_percent": int(item.get("commission_percent", S.affiliate_default_commission_percent)),
        "status": item.get("status", "active"),
        "click_count": click_count,
        "unique_click_count": unique_clicks,
        "conversion_count": conversions,
        "revenue_cents": int(item.get("revenue_cents", 0)),
        "commission_earned_cents": int(item.get("commission_earned_cents", 0)),
        "conversion_rate_pct": round(conversions / unique_clicks * 100, 2) if unique_clicks > 0 else 0.0,
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


# ─── Creator aggregate analytics (FIN-010 / GAP-0197) ─────────────


@router.get("/ui/affiliates/summary", response_model=AffiliateSummaryOut)
async def creator_summary(ctx: Dict = Depends(require_ui_session)):
    _require_enabled()
    return get_creator_summary(ctx["user_sub"])


@router.get("/ui/affiliates/timeseries", response_model=AffiliateClickTimeSeriesOut)
async def click_timeseries(
    interval: str = Query("day", pattern="^(day|week)$"),
    from_ts: Optional[int] = Query(None, ge=0),
    to_ts: Optional[int] = Query(None, ge=0),
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    items = get_click_timeseries(
        ctx["user_sub"],
        interval=interval,
        from_ts=from_ts or 0,
        to_ts=to_ts or 0,
    )
    return {"items": items, "interval": interval}


@router.get("/ui/affiliates/earnings", response_model=AffiliateEarningsBreakdownOut)
async def earnings_breakdown(
    from_ts: Optional[int] = Query(None, ge=0),
    to_ts: Optional[int] = Query(None, ge=0),
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    return get_earnings_breakdown(ctx["user_sub"], from_ts or 0, to_ts or 0)


@router.get("/ui/affiliates/top-products", response_model=AffiliateTopProductsOut)
async def top_products(
    limit: int = Query(10, ge=1, le=50),
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    items = get_top_products(ctx["user_sub"], limit=limit)
    return {"items": items}


# ─── CRUD ─────────────────────────────────────────────────────────


@router.post("/ui/affiliates/links", status_code=201)
async def create_link(
    body: dict,
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    creator_id = ctx["user_sub"]
    target_type = body.get("target_type", "catalog_item")
    target_id = body.get("target_id", "")
    commission_percent = body.get("commission_percent")
    custom_code = body.get("custom_code")

    if not target_id:
        raise HTTPException(status_code=400, detail="target_id is required")

    item, err = create_affiliate_link(
        creator_id=creator_id,
        target_type=target_type,
        target_id=target_id,
        commission_percent=commission_percent,
        custom_code=custom_code,
    )
    if err:
        status = 409 if "already exists" in err else 400
        if "not found" in err.lower():
            status = 404
        raise HTTPException(status_code=status, detail=err)
    return _link_to_out(item)


@router.get("/ui/affiliates/links")
async def list_links(
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    creator_id = ctx["user_sub"]
    items = list_creator_links(creator_id)
    return {"links": [_link_to_out(i) for i in items]}


@router.get("/ui/affiliates/links/{link_id}")
async def get_link_detail(
    link_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    item = get_link(link_id)
    if not item:
        raise HTTPException(status_code=404, detail="Link not found")
    if item["affiliate_user_id"] != ctx["user_sub"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    return _link_to_out(item)


@router.delete("/ui/affiliates/links/{link_id}")
async def revoke_link(
    link_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    ok, err = delete_link(ctx["user_sub"], link_id)
    if not ok:
        status = 404 if err == "Link not found" else 403
        raise HTTPException(status_code=status, detail=err)
    return {"ok": True, "link_id": link_id}


@router.get("/ui/affiliates/links/{link_id}/stats")
async def link_stats(
    link_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    item = get_link(link_id)
    if not item:
        raise HTTPException(status_code=404, detail="Link not found")
    if item["affiliate_user_id"] != ctx["user_sub"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    stats = get_link_stats(link_id)
    return stats


@router.post("/ui/affiliates/links/{link_id}/conversions")
async def create_conversion(
    link_id: str,
    body: dict,
    ctx: Dict = Depends(require_ui_session),
):
    """Record a conversion for an affiliate link (for testing/manual attribution)."""
    _require_enabled()
    order_id = body.get("order_id", "")
    amount_cents = body.get("amount_cents", 0)
    if not order_id or not amount_cents:
        raise HTTPException(status_code=400, detail="order_id and amount_cents required")

    result = record_conversion(
        link_id=link_id,
        order_id=order_id,
        amount_cents=int(amount_cents),
    )
    if not result:
        raise HTTPException(status_code=404, detail="Link not found or not active")
    return result


# ─── Public redirect ─────────────────────────────────────────────


@router.get("/r/{tracking_code}")
async def affiliate_redirect(
    tracking_code: str,
    request: Request,
):
    """Public redirect endpoint: record click, set cookie, redirect to destination."""
    link = get_link_by_code(tracking_code)
    if not link:
        return RedirectResponse(url="/", status_code=302)

    if link.get("status") != "active":
        return RedirectResponse(url=link.get("destination_url", "/"), status_code=302)

    # Record click
    ip = request.client.host if request.client else "0.0.0.0"
    ua = request.headers.get("user-agent", "")
    referrer = request.headers.get("referer")

    record_click(
        link_id=link["link_id"],
        tracking_code=tracking_code,
        ip_address=ip,
        user_agent=ua,
        referrer=referrer,
        creator_id=link.get("affiliate_user_id", ""),
    )

    destination = link.get("destination_url", "/")
    response = RedirectResponse(url=destination, status_code=302)

    # Set attribution cookie
    response.set_cookie(
        key="afl_ref",
        value=tracking_code,
        max_age=S.affiliate_cookie_duration_days * 86400,
        httponly=True,
        samesite="lax",
        path="/",
        secure=S.ui_cookie_secure,
    )

    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"

    return response
