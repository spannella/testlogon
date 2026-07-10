# ADV x ECOM integration (B1–B5) — LIVE PROD HOTFIX

Product ads across the shop + feed/video, CPA-attributed on real ecom purchases.

## What shipped (backend)
- **B1 product-linked creative** — `ad_creatives.create_product_creative`: a creative
  whose subject is a catalog product (`product_id` + `product_category_id` +
  `product_price_cents`) carrying a `buy_product` CTA (reuse E2). Serve carries the
  product_id onto the AdClicks row + the serve response.
- **B2 sponsored products in shop** — new `app/services/shop_ads.py::serve_shop_sponsored`
  + `POST /ui/ads/shop/serve` (surface `shop_search`/`shop_browse`). `serve_ad` gained
  `require_product=True` so the shop serves ONLY product ads. STANDALONE placement (no
  content owner) → platform-100%. Billing = the EXISTING funds-guarded, idempotent
  `track_ad_event` via `POST /ui/ads/track` (shop surfaces are billable, not in the
  completion-charge skip set). Sponsored products are NOT tippable (a serve unit, not a post).
- **B3 shoppable product ads** — reuse the ADV-B4 cart path: a product ad's `buy_product`
  CTA → product page → cart → `ui_purchase_cart` threads `ad_click_id` →
  `ad_attribution.attribute_conversion` → `charge_conversion` (CPA), last-click, idempotent.
- **B4 seller boost-this-product** — `shop_ads.boost_listing` + `POST /ui/ads/boost/product`:
  owner-checked (`item.creator_id == caller`, else 403); create/reuse the seller ad account
  (auto-active), a campaign (auto-active), and a product creative prefilled from the listing
  (auto-approved) so it serves immediately.
- **B5 ROAS** — no code change: `ad_roas.roas_report` is ledger-sourced, so product-ad
  impression/click/conversion charges + attributed `conversion_value_cents` flow in.
- **B1 advertiser endpoint** — `POST /ui/ads/campaigns/{campaign_id}/product-creatives`
  (owner-checked) to author a product creative referencing any catalog product.

## Money-path rules honored
- Sponsored-product CPC/impression + CPA via the funds-guarded ad ledger, idempotent per
  `{ad_click_id}#{event}` / `{ad_click_id}#conversion`.
- Shop placement = standalone → platform 100% (no third-party content owner). A product ad
  in front of a creator video/live still credits that creator (existing `_split_revenue`).
- Underlying ecom payout unchanged: the buyer still pays the seller; the ad charge is the
  advertiser (seller, for a boost) paying the platform.

## Apply / files
- `apply_adecom.py` — anchored, idempotent (ROOT env). Patches `ad_serving.py` (4 anchors),
  appends `create_product_creative` to `ad_creatives.py`, appends the router block to
  `ads.py`. Re-run = SKIP.
- `shop_ads.py` — new service (copy to `app/services/shop_ads.py`).
- `verify_adecom.py` — in-process prod-DDB verify (run via `ssm_run.py`).

## Prod deploy
`.bak_adecom_1783717785` on ad_serving.py / ad_creatives.py / ads.py. Restart openapi 200,
routes registered. Probe: all 4 ad_serving anchors count=1, markers absent, shop_ads absent.

## Verify (in-process on prod DDB) — OVERALL ALL_PASS 21/21
Seller boosts a listing → product ad account+campaign+creative (owner-checked; non-owner
→ PermissionError/403). `serve_shop_sponsored` returns the sponsored product (standalone,
not tippable). impression billed CPM (funds-guarded) + idempotent repeat=0; click CPC=137 +
idempotent; advertiser balance debited by imp+click; placement = platform-100%
(creator_share=0, platform_share==charge); drained account → insufficient_funds, balance≥0.
Buyer (who was served the ad) runs a REAL cart purchase (order created→approved, total 2599)
→ CPA=456 charged, AdClicks converted + value stamped, retry no-op (already_converted). ROAS
spend=1592 / value=2599 / roas=1.6325.
