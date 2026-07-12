# BUG #3 — Digital-goods seller credits invisible to earnings/payouts (LIVE PROD HOTFIX)

**Applied to prod (i-08f937fc705ebea75, /home/ubuntu/testlogon) 2026-07-04.**
Backups on prod: `<file>.bak_ecom2_1783143629`.

## Root cause
`billing_shared.new_ledger_entry` persists `type = entry_type`.
`creator_earnings._query_credit_entries`, `creator_earnings.get_earnings_transactions`
and `creator_payouts.get_available_balance` all filter `Attr("type").eq("credit")`.
The revenue **category** is decided from `reason` (`creator_earnings.classify_entry`),
NOT from the type. But the digital-delivery SELLER-credit writers wrote non-`"credit"`
entry_types, so their rows were filtered out before counting → seller VOD/rental/
license/ad earnings never appeared in the earnings summary or payout balance.

## Fix (per-writer entry_type -> "credit"; reason unchanged so bucketing is preserved)
- app/services/vod_purchase.py      seller credit  vod_purchase_credit  -> credit  (reason "VOD sale")
- app/services/vod_rental.py        seller credit  vod_rental_credit    -> credit  (reason "VOD {tier} sale")
- app/services/license_revenue.py   licensor credit license_revenue_credit  -> credit (reason "License revenue share from ...")
- app/services/license_revenue.py   licensor credit license_fixed_fee_credit -> credit (reason "License fixed fee")
- app/services/ad_billing.py        creator credit ad_revenue_credit    -> credit  (reason "Ad revenue share")
- app/services/ad_placement.py      creator credit ad_revenue_credit    -> credit  (reason "Ad revenue")

DEBIT counterparts (vod_purchase_debit, vod_rental_debit, license_*_debit) are
UNCHANGED. refund_credit / affiliate_withdrawal_credit / sponsorship_payout are
UNCHANGED (must NOT be swept into seller earnings). Sign map unaffected: all these
types and "credit" are +1 in LEDGER_ENTRY_SIGN, so signed_amount_cents is identical.

## Consumer compatibility (only ad_revenue_credit had consumers)
`ad_revenue_credit` was the only old type read by a consumer. Two consumers were made
forward+backward compatible (identify ad-revenue rows by reason, still match legacy type):
- app/services/content_ad_controls.py     get_ad_revenue_breakdown filter
- app/services/platform_financial_dashboard.py  _aggregate revenue attribution
(vod_purchase_credit / vod_rental_credit / license_revenue_credit / license_fixed_fee_credit
had NO consumers reading the literal string.)

## End-to-end verification (real purchases on prod)
Seller = admin crash1782189692@testlogon.example. Fresh buyer registered via API.
- PRE-FIX real VOD purchase (1500c): seller earnings total 26200->26200, vod_purchases 0,
  payout total_earned 26200->26200  => credit INVISIBLE (bug reproduced).
- POST-FIX: VOD purchase (2500c) + license revenue split (2000c):
  earnings total 26200 -> 30700 (+4500); vod_purchases 0 -> 2500; other +2000;
  txn_count 8 -> 10; payout total_earned 26200 -> 30700 (+4500).
  Earnings transactions show "VOD sale"/vod_purchases and "License revenue share.../other".
Ad path not seeded E2E (needs ad-serving pipeline); ad-consumer compat unit-verified
(_aggregate net_revenue counts new "credit"+reason "Ad revenue" and legacy rows, excludes VOD).
available_cents stayed 0 because all credits are within the payout hold window
(hold_cents == total_earned_cents); total_earned_cents is the authoritative moved number.

See bug3_seller_credit_visibility.patch for the exact diffs.
