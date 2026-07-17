# ECOMX EPIC E5 — COVERAGE / MEASUREMENT / NOTIFICATIONS

Earnings attribution, seller analytics, notification completeness, review
integrity, wishlist restock/price-drop watcher, and live-commerce per-stream
summary. Verified 65/65 over real HTTP on BOTH the live dev-clone AND the live
prod uvicorn (never an in-process TestClient).

## Tickets
- **ECOMX-50 (earnings attribution)** — `creator_earnings.classify_entry` now maps
  shop credits (`meta.content_type=="shop"` / reason "Shop sale") -> `shop_sales`
  and live-commerce credits (`content_type=="livecom"` / "Live-stream …") ->
  `live_commerce`, instead of collapsing both into `other`. New `EarningsBreakdown`
  fields `shop_sales` / `live_commerce`. Reconciles to the ledger (bucket == sum of
  seller_net on the credits); no double-count vs tips/subs/ads (they key off
  different content_types).
- **ECOMX-51 (seller analytics)** — new `GET /ui/seller/analytics` (own ship groups
  only): GMV, units, order_count, AOV, open-fulfilment count, shipped/delivered/
  cancelled-or-returned counts, top item. `seller_ship_groups.seller_analytics()`.
- **ECOMX-52 (notifications)** — registered + default-on-push + categorized
  (commerce) + url_map deep-links for `review_received`, `order_refunded`,
  `refund_approved`, `refund_denied`, `wishlist_restock`, `wishlist_price_drop`.
  `order_refunded` is now emitted (alert+push) from the owner self-cancel-refund
  branch (`order_lifecycle._maybe_refund`); `refund_approved`/`refund_denied` now
  fire an actual FCM push (were alert-only); `review_received` fires to the seller
  from `add_review`.
- **ECOMX-53 (review integrity)** — `catalog.add_review` now requires a VERIFIED
  PURCHASE (`purchase_history.has_purchased_item`), forces the author identity from
  the session `user_sub` (spoofed `reviewer` is a display label only), clamps rating
  1..5, blocks self-review, one review per (item, author). `delete_review` is
  author-or-admin scoped. New owner/admin `POST /items/{id}/reviews/{rid}/response`
  (seller reply). NOTE: also fixed a latent pre-existing bug — the review flow used
  `_get_item_meta` (queries the review partition, always returned `{}` for real
  items, silently no-op'ing the subscription gate); swapped to `_find_item_by_id`
  (the ByItemId GSI).
- **ECOMX-54 (wishlist watcher)** — new `wishlist_watch.notify_item_changed`, hooked
  into `catalog.update_item` (price/stock) + `adjust_stock`. Diffs the new
  stock/price vs each wishlister's saved snapshot -> `wishlist_restock` /
  `wishlist_price_drop` alert+push, refreshes the snapshot (notify-once).
- **ECOMX-55 (conversion + livecom summary)** — conversion attribution
  (`ad_click_id` sponsored-card->cart->purchase->`attribute_conversion`) was ALREADY
  wired (advertising v2); this epic adds the per-stream livecom summary
  `GET /ui/live-commerce/sessions/{id}/summary` (host-scoped) aggregating settled
  order-settlement markers -> GMV / host_commission / seller_net / platform_fee /
  order_count (`live_commerce_split.session_summary`).

## Files (dev clone == repo)
- NEW `app/services/wishlist_watch.py`
- `app/models.py` (EarningsBreakdown +shop_sales/+live_commerce; review models
  +verified_purchase/+seller_response + `CatalogReviewSellerResponseIn`)
- `app/services/creator_earnings.py` (classify_entry + canonical buckets)
- `app/services/seller_ship_groups.py` (seller_analytics) + `app/routers/seller_ship_groups.py` (analytics_router)
- `app/services/alerts.py` (registrations/url_map/default-push/category)
- `app/services/order_lifecycle.py` (order_refunded emit)
- `app/services/refund_requests.py` (refund push)
- `app/services/purchase_history.py` (has_purchased_item)
- `app/services/live_commerce_split.py` (session_summary) + `app/routers/live_commerce.py` (summary route)
- `app/routers/catalog.py` (review integrity + wishlist hooks + logger + find_item swap)
- `app/services/api_key_route_scope_registry.py` (register the new review-response route -> #118 parity)
- `app/main.py` (mount seller analytics router)

## Deploy (prod)
- 10 files were byte-identical dev==prod (md5): overwritten in place
  (`prod_deploy_chunked.sh`, chunked base64 over SSM).
- 4 files diverged on prod (models/alerts/main/catalog carry prior prod-only
  hotfix lines): anchor-patched on prod via the `patch_*.py` / `prod_patch_*.py`
  scripts here (functionally equivalent; not byte-identical to dev — expected,
  same as E3's main/settings). Prod .bak: `.bak_ecomx_e5_<ts>`.
- Restarted (pkill root uvicorn first, then `restart_backend.sh`); single healthy
  worker; local + public openapi 200; +8 paths (2981->2989) incl. the 3 new routes.

## Verify
`verify_ecomx5.py` = 65/65 PASS on live dev AND live prod (real HTTP, live
DDB-Local, NOT TestClient). Covers the full E2E buy->fulfil->ship->track->deliver
->review(purchase-gated)->refund loop + every E5 ticket. 0 residue. Regression:
E1 29/29 + E2 33/33 re-run GREEN on prod; tips/ads/catalog/earnings/seller/wishlist
routes intact + 401-gated.
