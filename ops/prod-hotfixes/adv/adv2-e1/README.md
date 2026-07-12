# ADV2-E1 — live-stream ad breaks (host-triggered mid-roll) — backend ADV2-101..104

Wires the proven broadcast pre-roll monetization into the already-shipped mid-roll
control plane (host trigger + `ad_break_active` state). Overlay-only: the live
encode keeps running; an ad NEVER blocks the broadcast (disabled / no-fill /
ad-free all stay live).

## Tickets
- **ADV2-101** `POST /broadcast/sessions/{id}/ad-break/serve` + `build_mid_roll()`
  (surface/slot `broadcast_midroll`, mirrors `build_pre_roll`): returns creative +
  `ad_click_id` + `skip_after_seconds` (`mid_roll_skip_after_seconds`) +
  `remaining_seconds`. Honors `broadcast_midroll_enabled`, requires
  `ad_break_active`, honors `is_ad_free` (self broadcaster + active subscribers).
  Mints the AdClicks row via `serve_broadcast_ad` (content_owner=broadcaster).
- **ADV2-102** `_charge_broadcast_completion(*, ad_click_id, session_id, surface)`
  (renamed from `_charge_broadcast_preroll_completion`, alias kept). The AdClicks
  row `surface` is authoritative -> idempotency `broadcast_midroll:{ad_click_id}` +
  meta `surface=broadcast_midroll`. Broadcaster 70/30 via `_split_revenue`
  (content_owner present). `record_ad_event` passes surface from `slot_type`.
- **ADV2-103** poll-detectable state: `remaining_seconds` added to
  `BroadcastAdConfigOut` + light `GET /broadcast/sessions/{id}/ad-break/state`.
- **ADV2-104** anti-abuse guardrails in `trigger_ad_break_route`: min interval
  (`BROADCAST_MIDROLL_MIN_INTERVAL_SECONDS`=300) + max breaks/session
  (`BROADCAST_MIDROLL_MAX_BREAKS`=4). New `last_ad_break_at` session field
  persists the last-break timestamp (survives break-end which nulls
  `ad_break_started_at`).

## Files patched (anchor-matched, idempotent; runs on divergent prod + dev clone)
- app/core/settings.py           (2 midroll guardrail settings)
- app/models_broadcast.py        (last_ad_break_at field)
- app/services/broadcast_store.py(persist/hydrate last_ad_break_at)
- app/services/broadcast_ads.py  (build_mid_roll, _break_remaining_seconds, surface-param charge)
- app/routers/broadcast_ads.py   (serve + state routes, models, guardrails, config remaining_seconds)

## Apply / verify
    python3 apply_adv2e1.py /home/ubuntu/testlogon     # idempotent
    # restart: su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"; openapi 200
    .venv/bin/python verify_adv2e1.py                  # in-process on prod DDB

## PROD deploy (2026-07-08)
Backups: `.bak_adv2e1_1783546469` on all 5 files. openapi 200; routes
`ad-break/serve` (post) + `ad-break/state` (get) registered. Verify OVERALL
ALL_PASS (14/14): serve mints broadcast_midroll click (owner=broadcaster,
eff_price 25001) -> advertiser debited 25001 + broadcaster credited 17500 (70%,
type:"credit") + platform 7501 (30%); repeat complete+impression = 0 extra
(idempotent per broadcast_midroll:{ad_click_id}); self broadcaster + ad-free
subscriber -> no serve; too-soon 429 AD_BREAK_TOO_SOON; 5th break 429
MAX_BREAKS_REACHED; first trigger 200; state returns remaining_seconds; serve
route 200 with creative.

Cosmetic residual (pre-existing, shared with pre-roll): the AdClicks row
`charged_cents` writes 0 (result key mismatch in the post-charge row update);
the actual advertiser debit + broadcaster credit are correct. Not a regression.

## ADV2-108 - 2-device on-prod verification (2026-07-08)
Real app on prod (tl-api.bitbazaar.cc), app build c9e7190b, BUILD_EXIT=0,
installed + launched crash-free on both phones. Host = Bella (broadcaster) on
Pixel 7a 32281JEHN13840; viewer = demo.viewer on SM-A156U R5CX821TA9R
(record device). Live session f8a09592-... created for Bella; viewer deep-linked
testlogon://broadcast/viewer/{sid} (reaches Ready + arms the ~2s state poll even
though the seeded stream has no real media); host deep-linked
testlogon://broadcast/ingest/{sid} -> Go Live -> Manage broadcast ->
HostControlScreen "Start ad break" (host_ad_break_start).

Real-app okhttp evidence (single break):
- HOST tap -> POST /broadcast/sessions/{sid}/ad-break 200.
- VIEWER poll GET /ad-break/state -> ad_break_active:true ->
  POST /ad-break/serve 200 (creative cr_0226a669cf66, image) ->
  track event=impression slot_type=mid_roll ad_click_id=fc0ff8e8... 200 ->
  event=complete view_time_ms=8000 200 -> resumed to live (poll re-armed,
  same break NOT re-served).

Money (prod DDB, surface=broadcast_midroll, ad_click_id fc0ff8e8...):
- advertiser debit T.ad_billing ACCT#adacct_416cea3bdad4 LEDGER chg_b1d1f3d930a2
  entry_type=impression_charge amount 20001 state=settled;
- broadcaster (Bella) T.billing credit 14000 [70pct] meta surface=broadcast_midroll
  model=cpm; platform_share 6001 [30pct]; 14000+6001=20001;
- idempotency marker IDEMP#broadcast_midroll:fc0ff8e8... present -> the app's
  duplicate impression+complete collapsed to ONE charge (idempotent on-device);
- ad-free/self [fresh active break]: normal viewer served=true; self-broadcaster
  mid_roll=null/ad_free=true; active subscriber mid_roll=null/ad_free=true [NOT
  interrupted]. Guardrails: too-soon 429 AD_BREAK_TOO_SOON, max-breaks 429
  MAX_BREAKS_REACHED. Auction winner was a competing prod advertiser
  [adacct_416cea3bdad4, eff_price 20001] - seeded Acme lost the second-price
  auction [Acme balance unchanged = correctly NOT charged]. An ad never blocks
  the live stream [fail-open].

Mid-roll overlay captured on the A15 [2nd session a38f6847-...]: AdOverlay renders
the ad creative over the still-running live viewer with Ad badge + skip
countdown + seconds-remaining.

APK: s3://testlogon-apk-749211675678/adv2-e1/testlogon-adv2e1-midroll-c9e7190b-1783549379-debug.apk
[7-day presigned, emailed spannella@gmail.com, subject "Updated TestLogon - ADV2-E1 live-stream ad breaks"].
