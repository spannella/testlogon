# ADV3 EPIC E4 — Measurement/analytics reconciliation (ADV3-8, ADV3-9)

Prod hotfix bundle. Backend = LIVE PROD HOTFIX via SSM (EC2 `i-08f937fc705ebea75`,
DynamoDB Local at `localhost:8001`). Dev clone `android-impl`; prod diverges only on
`ad_billing.py` (applied as a targeted patch, not a full-file mirror).

## What changed (ticket -> fix)

ADV3-8 (D1..D4) — reconcile the KPI dashboard to the money ledger:
- D1: `/ui/ads/analytics/{summary,timeseries,breakdown}` now accept `from`/`to`
  (YYYY-MM-DD) in addition to `days`; the Android range control (which already
  sent from/to) is no longer a no-op. `resolve_days()` folds a from/to window to
  an inclusive day count.
- D2/D3: `get_summary` is now sourced from the **ad_billing ledger** via
  `ad_roas.ledger_metrics` — the SAME money path as the /roas card — so the KPI
  strip and the ROAS card reconcile exactly and a currently-spending campaign
  shows today's activity (no dependence on the once-a-day rollup write).
- D4: `cpc_cents` (spend/clicks) is the true CPC that was mislabeled `cpa_cents`;
  `cpa_cents` is now the true cost-per-conversion; `roas`/`conversions`/
  `conversion_revenue_cents`/`unique_users` are surfaced. Web gets a real ROAS
  panel calling `/ui/ads/roas`. All `*_cents` summary fields are integer cents.

ADV3-9 (D5..D11) — kill fake/empty rollup metrics + engine dedupe:
- D5: `complete`/`skip` counted from the ad_impressions event log (was hardcoded 0).
- D6: impression/click charges stamp `surface`/`slot_type`/`geo_country` on the
  ledger meta; `compute_hourly_rollup` attributes REAL spend into
  `by_surface`/`by_targeting` (was spend=0). Android breakdown gets a dimension picker.
- D7: one ROAS source of truth — `ledger_metrics` (ledger `conversion_value_cents`).
  `get_summary`, `roas_report`, and `calculate_campaign_roas` (optimizer endpoint)
  all agree; the affiliate-REDEEM engine is retired from the ROAS path.
- D8: timeseries weekly/monthly -> 422 (only hourly/daily are materialized).
- D9: the rollup loop rolls up active/paused/completed campaigns (was active-only),
  so a campaign that auto-paused at 100% budget still gets its final period.
- D10: fabricated `revenue_cents = spend*0.7` removed from rollup rows.
- D11: `unique_users` is real reach (distinct impression viewers) from the event log.

## Files (mirror dev clone byte-for-byte, except ad_billing)
- `ad_analytics.py`, `ad_roas.py`, `ad_serving.py`, `ads.py` — full-file mirror
  (prod baseline was byte-identical to dev HEAD; verified md5-equal after deploy).
- `ad_billing_meta_patch.py` — targeted patch applied to prod's divergent
  `app/services/ad_billing.py` (adds surface/slot_type/geo_country to charge meta).

## Apply (prod)
1. Probe: confirm prod `ad_analytics/ad_roas/ad_serving/ads.py` md5 == dev HEAD.
2. `cp <file> <file>.bak_adv3e4_<ts>`; decode the mirror files into place; `chown ubuntu:ubuntu`.
3. `python3 ad_billing_meta_patch.py app/services/ad_billing.py` (with .bak).
4. Restart: `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`; wait `openapi.json` 200.

## Verify (prod DDB, self-cleaning, 0 residue)
- `verify_reconcile.py` — seeds a synthetic advertiser, charges via the real money
  path, writes complete/skip/impression events; asserts summary == roas_report ==
  ledger == calculate_campaign_roas, correct CPC/CPA, real completion/reach, today
  not lost, no fabricated revenue_cents. Run under the app env (inject
  `/proc/<uvicorn pid>/environ` so DDB_ENDPOINT_URL=localhost:8001).
- `verify_rollup.py` — asserts by_surface/by_targeting carry real spend, real
  complete/unique counts, no revenue_cents in the rollup row.
- Result: ALL RECONCILE CHECKS PASSED; RESIDUE ledger_rows=0.

## Prod .bak files created
- app/routers/ads.py.bak_adv3e4_1784135799
- app/services/ad_analytics.py.bak_adv3e4_1784135791 (+.bak_adv3e4b_1784136141/1784136635)
- app/services/ad_roas.py.bak_adv3e4_1784135794 (+.bak_adv3e4b_1784136144)
- app/services/ad_billing.py.bak_adv3e4_1784135836
- app/services/ad_serving.py.bak_adv3e4_1784135796

## On-device (A15 SM-A156U) spot-check
Ad analytics dashboard renders real data; KPI strip (Impr 11 / Clk 2 / Spend $20.45)
reconciles exactly with the ROAS card totals; CPC correctly labeled; CPA shown only
with conversions; completion-rate tile suppressed (no fake 0%); switching to
"Last 7 days" re-scopes BOTH the KPIs and the ROAS card together (range no longer a
no-op). assembleDebug green.
