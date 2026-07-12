# ADV-B4 — CPA conversion attribution + placement-aware revenue split (LIVE PROD HOTFIX)

Applied to prod i-08f937fc705ebea75 via SSM; backups `.bak_advb4_1783491889` on the 5 pre-existing files.
Apply with: `python3 apply_advb4.py <repo_root>` (idempotent, two-phase: validates every
string anchor BEFORE writing; SKIPs already-applied edits). Works on both the dev clone
and the divergent prod tree (anchor-matched, not line-numbered).

## Changes
- **ADV-401** NEW `app/services/ad_attribution.py`:
  - `find_last_click(viewer_sub)` — most-recent UNEXPIRED, UNCONVERTED AdClicks row via GSI
    `ByViewer` (viewer_sub HASH + created_at RANGE), 7d window (`ATTRIBUTION_WINDOW_SECONDS`).
  - `attribute_conversion(viewer_sub, conversion_type, conversion_value_cents, ad_click_id="")`:
    explicit `ad_click_id` resolves STRICTLY (`_classify_click`: unknown/foreign/expired/
    already-converted -> hard no-op, NEVER swapped for a different last-click so a retried
    purchase can't double-attribute); no explicit id -> last-click fallback. Atomically claims
    the row (`ConditionExpression="attribute_not_exists(converted_at) AND #s <> converted"`),
    then `ad_billing.charge_conversion` (CPA bid, funds-guarded) with idempotency_key
    `{ad_click_id}#conversion`, placement-aware via `content_owner_sub`.
- **ADV-402** `subscription_server.py`: `SubscribeIn.ad_click_id`; on a real (non-trial) charge,
  `attribute_conversion(..., "subscription", price_cents)`. Best-effort, never breaks signup.
- **ADV-403** `models.CartPurchaseIn.ad_click_id`; `shoppingcart.ui_purchase_cart` attributes
  `"purchase"` with the order total after `purchase_cart`. Retried purchase = already-converted no-op.
- **ADV-404** `newsfeed.UnlockPostRequest.ad_click_id`; `unlock_post` attributes `"unlock"` with
  the unlock price after `_finalize_unlock_attempt_success`.
- **ADV-406** `ad_billing._split_revenue` creator credit `entry_type` -> `"credit"` (was
  `"ad_revenue_credit"` on the DEV CLONE) so ad-revenue share shows in creator earnings/payouts
  (`creator_earnings._query_credit_entries` filters `type=="credit"`), Bug#3-safe. PROD already
  had `"credit"` (SKIP) — this aligns dev<->prod. The platform-100%-when-no-owner split
  (standalone books the FULL charge, not 30%) already shipped in ADV-B3 and is asserted here.

## Idempotency (money-path)
Two guards: (1) the AdClicks conditional converted-claim = at most ONE successful claim per
ad_click_id; (2) `charge_conversion` IDEMP# marker keyed `{ad_click_id}#conversion`. Budget can
never overspend (`_process_charge` funds-guard).

## Prod verification (verify_advb4.py, in-process, prod DDB) — 16/16 ALL_PASS
- ADV-401 last-click returns newest unexpired click; expired click not attributable.
- ADV-402 REAL subscribe endpoint (ad_click_id) -> advertiser debited CPA 500 + AdClicks converted.
- ADV-404 REAL unlock endpoint (ad_click_id) -> advertiser debited CPA 500 + AdClicks converted.
- ADV-406 STANDALONE (no owner) -> platform books FULL 500 (== charge, the 70%-drop fix), NO creator row.
- ADV-406 VIDEO (owner=poster) -> poster credited 350 (70%) type="credit" + platform 150 (30%).
- IDEMP repeat conversion same ad_click_id -> already_converted no-op, 0 additional debit.
- ADV-403 CartPurchaseIn accepts ad_click_id; purchase attribution charges CPA + converts.
