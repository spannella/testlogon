# ADV-B5 — advertising hardening (ROAS + reversal + money-path tests)

Final epic of the ad program. LIVE PROD HOTFIX applied to i-08f937fc705ebea75 via SSM.

## Tickets
- **ADV-501** ROAS reporting surface. `ad_roas.roas_report(account_id, campaign_id=None, days=30)`
  aggregates impression/click/conversion CHARGES (spend) + attributed conversion
  VALUE (recorded on conversion_charge rows as meta.conversion_value_cents) from
  the ad_billing ledger and derives impressions/clicks/CTR/conversions/CPA/ROAS,
  per-account totals + per-campaign breakdown. Endpoint `GET /ui/ads/roas`.
- **ADV-502** Idempotent ad-charge reversal. `ad_billing.reverse_ad_charge(...)`
  refunds the advertiser balance, backs the charge out of campaign spend, writes a
  `charge_reversal` ledger row, and reverses the split: creator clawback with
  entry_type `ad_revenue_reversal` (!= "credit", so it never inflates earnings —
  creator_earnings/get_available_balance only sum type=="credit") + flips the
  original credit to state="reversed"; platform revenue reversed too. A
  `REVERSAL#{entry_id}` marker (attribute_not_exists) makes it idempotent +
  double-reversal guarded. Endpoint `POST /ui/admin/ads/charges/reverse`
  (admin/root). Mirrors the TIP-502 pattern.
- **ADV-504** money-path tests: `test_adv_b5_money_paths.py` (16 tests) — 2nd-price
  clearing, charge amounts, funds-guard, idempotency, placement split (video->poster
  70/30 vs standalone->platform full), budget/balance no-overspend, reversal
  net-zero + earnings-not-inflated + idempotent, ROAS aggregation.

## Files patched (5)
app/services/ad_billing.py, app/services/ad_roas.py, app/services/ad_attribution.py,
app/services/ad_serving.py (extracted `clear_second_price` helper, behaviour-identical),
app/routers/ads.py.

## Apply (idempotent, anchor-based; runs on dev clone AND prod)
    .venv/bin/python apply_advb5.py <repo_root>
Backups on prod: `<file>.bak_advb5_<TS>` (TS=1783500024).

## Prod verify (in-process on real prod DDB, throwaway ids)
    .venv/bin/python verify_advb5.py
All assertions passed: charges 5c/50c/500c, idempotent repeat=0, ROAS
{imp,clk,conv,spend,value,ctr,cpa,roas} correct, creator credit 350 (70%),
reverse refunds 500 (net-zero) + clawback 350 (non-credit) + original credit
state=reversed + EARNINGS_NOT_INFLATED + idempotent double-reversal replay.
