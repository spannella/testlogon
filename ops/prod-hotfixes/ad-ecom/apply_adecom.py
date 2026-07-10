#!/usr/bin/env python3
"""ADV x ECOM integration — anchored, idempotent hotfix.

B1 product-linked creative + B2 shop serve surface + B4 seller boost endpoints.
Runs on the divergent dev clone AND prod (anchor-matched, not line#). Re-run =
SKIP where already applied. ROOT env var selects the repo root (default cwd).
"""
import os
import sys

ROOT = os.environ.get("ROOT", os.getcwd())


def _patch(path, edits, marker):
    full = os.path.join(ROOT, path)
    with open(full, "r", encoding="utf-8") as f:
        src = f.read()
    if marker in src:
        print(f"SKIP {path} (marker present)")
        return
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            print(f"FAIL {path}: anchor count={n} (expected 1) for:\n{old[:80]}...")
            sys.exit(2)
        src = src.replace(old, new)
    with open(full, "w", encoding="utf-8") as f:
        f.write(src)
    print(f"PATCHED {path}")


# ── ad_serving.py: require_product param + carry product_id ──────────
_patch(
    "app/services/ad_serving.py",
    [
        (
            '    content_owner_id: str = "",\n) -> Dict[str, Any]:',
            '    content_owner_id: str = "",\n    require_product: bool = False,\n) -> Dict[str, Any]:',
        ),
        (
            "        # Get approved creatives\n"
            "        creatives = list_approved_creatives(campaign[\"campaign_id\"])\n"
            "        if not creatives:\n"
            "            continue",
            "        # Get approved creatives\n"
            "        creatives = list_approved_creatives(campaign[\"campaign_id\"])\n"
            "        # B2: shop surfaces serve only PRODUCT-LINKED creatives (a product ad).\n"
            "        if require_product:\n"
            "            creatives = [c for c in creatives if c.get(\"product_id\")]\n"
            "        if not creatives:\n"
            "            continue",
        ),
        (
            '            "creative_id": creative["creative_id"],\n'
            '            "content_owner_sub": content_owner_id or "",',
            '            "creative_id": creative["creative_id"],\n'
            '            "product_id": creative.get("product_id", "") or "",\n'
            '            "content_owner_sub": content_owner_id or "",',
        ),
        (
            '        "ctas": creative.get("ctas") or [],\n'
            '        "image_url": creative.get("image_url"),',
            '        "ctas": creative.get("ctas") or [],\n'
            '        "product_id": creative.get("product_id", "") or "",\n'
            '        "product_category_id": creative.get("product_category_id", "") or "",\n'
            '        "product_price_cents": int(creative.get("product_price_cents", 0) or 0),\n'
            '        "image_url": creative.get("image_url"),',
        ),
    ],
    marker="B2: shop surfaces serve only PRODUCT-LINKED",
)


# ── ad_creatives.py: append create_product_creative ─────────────────
def _append(path, block, marker):
    full = os.path.join(ROOT, path)
    with open(full, "r", encoding="utf-8") as f:
        src = f.read()
    if marker in src:
        print(f"SKIP {path} (marker present)")
        return
    if not src.endswith("\n"):
        src += "\n"
    src += block
    with open(full, "w", encoding="utf-8") as f:
        f.write(src)
    print(f"APPENDED {path}")


_CREATIVE_BLOCK = '''

# ── B1: product-linked creative ─────────────────────────────────────


def create_product_creative(
    campaign_id: str,
    account_id: str,
    *,
    product_id: str,
    product_category_id: str = "",
    title: str,
    headline: str = "",
    body_text: str = "",
    image_url: str = "",
    price_cents: int = 0,
    cta_text: str = "Shop now",
    status: str = "draft",
    rotation_weight: int = 50,
) -> dict:
    """B1: create a PRODUCT-LINKED creative whose subject is a catalog product.

    Carries product_id + a buy_product CTA (reuse E2) so a tap deep-links to the
    real product page and a resulting cart purchase attributes CPA. Used by the
    seller-boost flow (auto-approved) and the advertiser product-creative
    endpoint (draft)."""
    creative_id = f"cr_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    item = {
        "pk": f"CAMP#{campaign_id}",
        "sk": f"CREATIVE#{creative_id}",
        "creative_id": creative_id,
        "campaign_id": campaign_id,
        "account_id": account_id,
        "format": "image",
        "title": title,
        "status": status,
        "rotation_weight": int(rotation_weight),
        "skip_after_seconds": 5,
        "product_id": product_id,
        "product_category_id": product_category_id or "",
        "product_price_cents": int(price_cents or 0),
        "cta_text": cta_text,
        "ctas": [{"cta_type": "buy_product", "target_id": product_id, "label": cta_text}],
        "created_at": ts,
        "updated_at": ts,
    }
    if headline:
        item["headline"] = headline
    if body_text:
        item["body_text"] = body_text
    if image_url:
        item["image_url"] = image_url
    T.ad_creatives.put_item(Item=item)
    logger.info(
        "product_creative_created creative_id=%s campaign_id=%s product_id=%s status=%s",
        creative_id, campaign_id, product_id, status,
    )
    return item
'''

_append("app/services/ad_creatives.py", _CREATIVE_BLOCK, marker="B1: product-linked creative")


# ── ads.py router: shop serve + product creative + seller boost ─────
_ADS_BLOCK = '''

# ── ADV x ECOM: product creative (B1) + shop serve (B2) + boost (B4) ─
from pydantic import BaseModel as _AEBase, Field as _AEField


class _ProductCreativeIn(_AEBase):
    product_id: str = _AEField(..., min_length=1, max_length=200)
    category_id: str = _AEField(default="", max_length=200)
    title: str = _AEField(default="", max_length=200)
    headline: str = _AEField(default="", max_length=200)
    cta_text: str = _AEField(default="Shop now", max_length=40)


class _ShopServeIn(_AEBase):
    surface: str = _AEField(default="shop_search", pattern="^(shop_search|shop_browse)$")
    query: str = _AEField(default="", max_length=200)
    category_id: str = _AEField(default="", max_length=200)
    limit: int = _AEField(default=3, ge=1, le=10)


class _ProductBoostIn(_AEBase):
    item_id: str = _AEField(..., min_length=1, max_length=200)
    category_id: str = _AEField(default="", max_length=200)
    budget_cents: int = _AEField(default=5000, ge=100, le=100_000_000)
    bid_cpc_cents: int = _AEField(default=50, ge=1, le=10_000)
    bid_cpm_cents: int = _AEField(default=500, ge=50, le=20_000)
    bid_cpa_cents: int = _AEField(default=500, ge=1, le=100_000)
    duration_days: int = _AEField(default=7, ge=1, le=365)
    objective: str = _AEField(default="traffic", pattern="^(awareness|traffic|conversions)$")


@router.post("/campaigns/{campaign_id}/product-creatives", status_code=201)
async def create_product_creative_endpoint(
    campaign_id: str, body: _ProductCreativeIn, ctx=Depends(require_ui_session)
):
    """B1: create a product-linked creative (references a catalog product +
    buy_product CTA). Owner-checked via the campaign's ad account."""
    camp = _require_campaign_owner(campaign_id, ctx["user_sub"])
    from app.services.shop_ads import resolve_product
    from app.services.ad_creatives import create_product_creative

    prod = resolve_product(body.product_id, body.category_id)
    if not prod:
        raise HTTPException(status_code=404, detail="Product not found")
    imgs = prod.get("image_urls") or []
    try:
        price = int(prod.get("price_cents") or 0)
    except (TypeError, ValueError):
        price = 0
    return create_product_creative(
        campaign_id,
        camp["account_id"],
        product_id=str(prod.get("item_id") or body.product_id),
        product_category_id=str(prod.get("category_id", "") or body.category_id or ""),
        title=(body.title or prod.get("name", "") or "Product"),
        headline=body.headline or "",
        body_text=str(prod.get("description", "") or ""),
        image_url=(imgs[0] if imgs else ""),
        price_cents=price,
        cta_text=body.cta_text or "Shop now",
        status="draft",
    )


@router.post("/shop/serve")
async def shop_serve_endpoint(body: _ShopServeIn, ctx=Depends(require_ui_session)):
    """B2: serve STANDALONE product-linked sponsored units into the shop
    search/browse results (platform-100%, no-tip). The app fires impression on
    render + click on tap via /ui/ads/track (funds-guarded, idempotent)."""
    from app.services.shop_ads import serve_shop_sponsored

    units = serve_shop_sponsored(
        viewer_id=ctx["user_sub"],
        query=body.query,
        category_id=body.category_id,
        limit=body.limit,
        surface=body.surface,
    )
    return {"sponsored": units, "count": len(units)}


@router.post("/boost/product", status_code=201)
async def boost_product_endpoint(body: _ProductBoostIn, ctx=Depends(require_ui_session)):
    """B4: seller BOOST-this-product. From a catalog LISTING, create/reuse the
    seller ad account + a campaign + a product creative prefilled from the
    listing. OWNER-CHECKED: a non-owner cannot boost the listing (403)."""
    from app.services.shop_ads import boost_listing

    try:
        return boost_listing(
            owner_sub=ctx["user_sub"],
            item_id=body.item_id,
            category_id=body.category_id,
            budget_cents=body.budget_cents,
            bid_cpc_cents=body.bid_cpc_cents,
            bid_cpm_cents=body.bid_cpm_cents,
            bid_cpa_cents=body.bid_cpa_cents,
            duration_days=body.duration_days,
            objective=body.objective,
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="You do not own this listing")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
'''

_append("app/routers/ads.py", _ADS_BLOCK, marker="ADV x ECOM: product creative (B1)")

print("APPLY_DONE")
