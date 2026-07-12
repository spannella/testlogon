"""Ad x Ecommerce integration — shop sponsored products + seller boost.

B2 SPONSORED PRODUCTS IN SHOP: ``serve_shop_sponsored`` serves product-linked
sponsored units into the shop search/browse surfaces. Each unit is a STANDALONE
placement (no third-party content owner) so the money-path books platform-100%
on the CPC/impression charge (``ad_billing._split_revenue`` with empty
creator_id). Billing itself is the EXISTING funds-guarded, idempotent
``track_ad_event`` path fired via ``POST /ui/ads/track`` (surface shop_search /
shop_browse is NOT in the completion-charge skip set, so impression + click bill
normally). Sponsored products are NOT tippable (a product ad is a creative/serve
unit, never a tippable post).

B4 SELLER BOOST-THIS-PRODUCT: ``boost_listing`` turns a catalog LISTING into a
product ad campaign in one call — owner-checked, create/reuse the seller ad
account, a campaign, and a product creative prefilled from the listing (image /
name / price / product link + buy_product CTA). The seller pays the PLATFORM for
the ad (advertiser ledger); the underlying ecom payout is unchanged (a buyer
still pays the seller normally on purchase).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

SHOP_SURFACES = ("shop_search", "shop_browse")


# ── Catalog product resolution ──────────────────────────────────────


def resolve_product(item_id: str, category_id: str = "") -> Optional[Dict[str, Any]]:
    """Resolve a catalog item by item_id via the ByItemId GSI (owner-scoped
    fields carried: creator_id / name / price_cents / image_urls / category_id)."""
    if not item_id:
        return None
    try:
        resp = T.catalog.query(
            IndexName="ByItemId",
            KeyConditionExpression=Key("item_id").eq(item_id),
            FilterExpression="entity = :ent",
            ExpressionAttributeValues={":ent": "item"},
        )
        items = resp.get("Items", [])
    except Exception:
        logger.warning("shop_ads.resolve_product_failed item=%s", item_id)
        items = []
    if not items:
        return None
    return items[0]


def _product_card_fields(product_id: str, category_id: str) -> Dict[str, Any]:
    """Enrich a sponsored unit with live catalog product details so the shop
    card renders name/price/image even when the creative omits them."""
    prod = resolve_product(product_id, category_id)
    if not prod:
        return {}
    imgs = prod.get("image_urls") or []
    try:
        price = int(prod.get("price_cents") or 0)
    except (TypeError, ValueError):
        price = 0
    return {
        "product_name": prod.get("name", ""),
        "product_price_cents": price,
        "product_currency": prod.get("currency", "USD"),
        "product_category_id": prod.get("category_id", "") or category_id or "",
        "product_image_url": imgs[0] if imgs else "",
        "product_creator_id": prod.get("creator_id", "") or "",
    }


# ── B2: serve sponsored products into the shop ──────────────────────


def serve_shop_sponsored(
    *,
    viewer_id: str,
    query: str = "",
    category_id: str = "",
    limit: int = 3,
    surface: str = "shop_search",
) -> List[Dict[str, Any]]:
    """Serve up to ``limit`` STANDALONE product-linked sponsored units for the
    shop search/browse surface. Each carries the product_id + a buy_product CTA
    (reuse E2) + impression/click track URLs; the app fires impression on render
    and click on tap-through -> the EXISTING /ui/ads/track charges the advertiser
    CPC/impression (funds-guarded, idempotent, standalone -> platform 100%)."""
    if not viewer_id:
        return []
    surface = surface if surface in SHOP_SURFACES else "shop_search"
    limit = max(1, min(int(limit or 1), 10))

    from app.services.ad_serving import serve_ad

    units: List[Dict[str, Any]] = []
    seen: set = set()
    ctx = {}
    if query:
        ctx["query"] = query
    if category_id:
        ctx["category_id"] = category_id

    # serve_ad returns ONE winner per call; loop to gather distinct product ads.
    for i in range(limit * 3):
        if len(units) >= limit:
            break
        try:
            ad = serve_ad(
                surface=surface,
                content_type="product",
                creator_id="platform",
                content_id=f"{surface}_slot_{i}",
                slot_type="sponsored_post",
                user_id=viewer_id,
                user_context=ctx or None,
                content_owner_id="",       # STANDALONE -> platform 100% (no creator)
                require_product=True,       # shop serves ONLY product ads
            )
        except Exception:
            logger.debug("shop_ads.serve_error surface=%s", surface, exc_info=True)
            break
        if not ad.get("filled") or ad.get("is_house_ad"):
            break
        creative_id = ad.get("creative_id", "")
        product_id = ad.get("product_id", "") or ""
        if not product_id:
            continue
        if creative_id in seen:
            continue
        seen.add(creative_id)

        card = {
            "unit_id": f"sponsored_{surface}_{creative_id}",
            "is_sponsored": True,
            "sponsor_label": ad.get("title", "Sponsored"),
            "headline": ad.get("headline"),
            "body": ad.get("body_text", ""),
            "cta_text": ad.get("cta_text") or "Shop now",
            "ctas": ad.get("ctas") or [],
            "product_id": product_id,
            "image_url": ad.get("image_url") or "",
            "creative_id": creative_id,
            "campaign_id": ad.get("campaign_id", ""),
            "account_id": ad.get("account_id", ""),
            "ad_click_id": ad.get("ad_click_id", ""),
            "content_owner_id": "",           # standalone shop placement
            "impression_url": ad.get("impression_url"),
            "click_url": ad.get("click_url"),
            "surface": surface,
            "tippable": False,                # sponsored products are NOT tippable
        }
        card.update(_product_card_fields(product_id, category_id))
        units.append(card)
    return units


# ── B4: seller boost-this-product ───────────────────────────────────


def _reuse_or_create_ad_account(owner_sub: str, company_name: str) -> Dict[str, Any]:
    """Reuse the seller's first ACTIVE user-owned ad account, else create one and
    auto-activate it (self-serve boost skips the manual review queue)."""
    from app.services.ad_accounts import create_ad_account, list_accounts_by_owner
    from app.models import AdAccountCreateIn

    for acct in list_accounts_by_owner(owner_sub):
        if acct.get("status") == "active" and str(acct.get("owner_type", "user")) == "user":
            return acct

    acct = create_ad_account(
        owner_sub,
        AdAccountCreateIn(
            company_name=(company_name or "My Store")[:200],
            billing_email=f"{owner_sub[:300]}@boost.testlogon",
        ),
    )
    # Auto-activate the boost ad account (self-serve).
    account_id = acct["account_id"]
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": "META"},
        UpdateExpression="SET #s = :a, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":a": "active", ":u": now_ts()},
    )
    acct["status"] = "active"
    return acct


def boost_listing(
    *,
    owner_sub: str,
    item_id: str,
    category_id: str = "",
    budget_cents: int = 5000,
    bid_cpc_cents: int = 50,
    bid_cpm_cents: int = 500,
    bid_cpa_cents: int = 500,
    duration_days: int = 7,
    objective: str = "traffic",
) -> Dict[str, Any]:
    """Create a product ad from a catalog LISTING in one call. OWNER-CHECKED: the
    caller MUST own the listing (item.creator_id == owner_sub) else PermissionError.

    Creates/reuses the seller ad account, a campaign (auto-active), and a product
    creative prefilled from the listing (image / name / price / product link +
    buy_product CTA, auto-approved) so the boost serves immediately."""
    prod = resolve_product(item_id, category_id)
    if not prod:
        raise ValueError("listing_not_found")

    listing_owner = str(prod.get("creator_id", "") or "")
    if listing_owner and listing_owner != owner_sub:
        raise PermissionError("not_owner")

    resolved_category = str(prod.get("category_id", "") or category_id or "")
    name = str(prod.get("name", "") or "Product")
    imgs = prod.get("image_urls") or []
    try:
        price_cents = int(prod.get("price_cents") or 0)
    except (TypeError, ValueError):
        price_cents = 0

    # 1. seller ad account (reuse active / create + auto-activate)
    acct = _reuse_or_create_ad_account(owner_sub, name)
    account_id = acct["account_id"]

    # 2. campaign (draft -> auto-active for self-serve boost)
    from app.services.ad_campaigns import create_campaign
    from app.models import CampaignCreateIn

    obj = objective if objective in ("awareness", "traffic", "conversions") else "traffic"
    now = now_ts()
    campaign = create_campaign(
        account_id,
        CampaignCreateIn(
            name=f"Boost: {name}"[:200],
            objective=obj,
            budget_cents=max(100, int(budget_cents or 100)),
            budget_type="lifetime",
            bid_cpm_cents=int(bid_cpm_cents or 500),
            bid_cpc_cents=int(bid_cpc_cents or 50),
            bid_cpa_cents=int(bid_cpa_cents or 500),
            start_date=now,
            end_date=now + max(1, int(duration_days or 7)) * 86400,
            category="general",
        ),
    )
    campaign_id = campaign["campaign_id"]
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET #s = :a, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":a": "active", ":u": now},
    )

    # 3. product creative prefilled from the listing (auto-approved so it serves)
    from app.services.ad_creatives import create_product_creative

    creative = create_product_creative(
        campaign_id,
        account_id,
        product_id=item_id,
        product_category_id=resolved_category,
        title=name,
        headline=f"{name} — Shop now",
        body_text=str(prod.get("description", "") or ""),
        image_url=(imgs[0] if imgs else ""),
        price_cents=price_cents,
        cta_text="Shop now",
        status="approved",
    )

    return {
        "ok": True,
        "account_id": account_id,
        "campaign_id": campaign_id,
        "creative_id": creative["creative_id"],
        "product_id": item_id,
        "product_category_id": resolved_category,
        "product_name": name,
        "product_price_cents": price_cents,
        "budget_cents": campaign["budget_cents"],
        "bid_cpc_cents": campaign.get("bid_cpc_cents"),
        "bid_cpm_cents": campaign.get("bid_cpm_cents"),
        "status": "active",
    }
