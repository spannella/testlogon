# ADV-B3 — real newsfeed impression/click charging + 2nd-price auction (LIVE PROD HOTFIX)

Applied to prod i-08f937fc705ebea75 via SSM; backups `.bak_advb3_1783483355` on the 5 files.
Apply with: `python3 apply_advb3_1.py <repo_root> && python3 apply_advb3_2.py <repo_root>` (transactional, asserts exact anchors).

## Changes
- ADV-301 models.py/ad_campaigns.py: bid_cpc_cents (default 50, 1..10000) + bid_cpa_cents (default 500, 1..100000) on CampaignCreateIn/UpdateIn/Out; persisted in create_campaign. AdTrackEventIn gains ad_click_id.
- ADV-302 ad_serving.serve_ad: second-price auction. Winner (highest bid_cpm x relevance) clears at runner_up_cpm+1 capped at own bid; lone bidder clears at reserve floor (50c). ad_clicks now stores effective_price_cents (cleared CPM) + effective_cpm_cents + bid_cpc_cents + bid_cpa_cents + gross_bid_cpm_cents.
- ADV-303 ad_serving.track_ad_event: after the fraud gate, a NEWSFEED impression/click actually charges via ad_billing.charge_impression (cleared CPM) / charge_click (campaign CPC) through the funds-guarded _process_charge. Surface-gated (skips preroll/midroll/postroll — those charge on completion in broadcast_ads). Credits revenue via _split_revenue with the ad_clicks content_owner_sub.
- ADV-304 ad_billing.charge_click/charge_conversion gain idempotency_key; track passes {ad_click_id}#{event} so a repeat track never double-charges (IDEMP# conditional marker).
- ADV-303/406 ad_billing._split_revenue: a standalone unit (no content owner) now books platform-100% instead of dropping ~70%.
- ADV-305: verified _check_budget_and_alert auto-completes at 100% and _has_budget excludes the depleted campaign from serve_ad (no code change).

## Prod verification (verify_advb3.py, in-process, prod DDB)
auction winner cleared 15001 (runnerup 15000 +1); impression debit 15c + repeat 0; click debit 30c + repeat 0; preroll track debit 0; PLATFORM_REVENUE booked full 15c/30c ownerless; budget $1.00 -> spent 105 -> status completed -> serve excludes it. ALL_ASSERTIONS_PASSED.
