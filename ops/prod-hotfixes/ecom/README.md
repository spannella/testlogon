# E-commerce backend hotfixes (2026-07-03)

Applied live to prod (SSM) and folded into the branch source. Three bugs found while
verifying the full buyer+seller e-commerce matrix on-device against prod
(https://tl-api.bitbazaar.cc). The affected service files (shoppingcart.py,
refund_requests.py) were NOT part of the big prod<->android-impl divergence, so the
real fix is folded directly into the branch; the .patch files here are the
prod-apply record.

## BUG A — shop sales never credited the seller (PRIMARY)
`app/services/shoppingcart.py::purchase_cart` recorded only a BUYER billing-ledger
debit (via `record_cart_purchase`) and never credited the creator/seller. Both
`creator_earnings._query_credit_entries` (earnings summary/transactions) and
`creator_payouts.get_available_balance` (payout balance) sum `T.billing` entries with
`type == "credit"` under `pk = USER#<seller>`. No such entry was written, so
`/ui/earnings/*` and `/ui/payouts/balance` stayed at 0 after a completed purchase.
FIX: after a successful purchase, write a per-creator `type="credit"` ledger entry
(reason "Shop sale", meta.content_type "shop") sized to the creator's share of the
post-discount total. Self-purchases (buyer == creator) are skipped.
NOTE: `vod_purchase` writes `entry_type="vod_purchase_credit"`, which those same
queries do NOT match — VOD/other-content seller credit is likely also affected
(separate latent bug, not fixed here).

## BUG B — physical stock never decremented
`app/services/shoppingcart.py::add_catalog_item` built the cart-item payload WITHOUT
`category_id`/`item_id`. `add_item` only persists those when present, so catalog cart
items were stored without them, and the `purchase_cart` stock-decrement loop
(`if not cat_id or not ci_item_id: continue`) skipped every item. Stock stayed
constant through purchases. FIX: include `category_id` and `item_id` in the payload.

## BUG C — shop purchases were never refundable
`app/services/refund_requests.py::create_refund_request` rejected any ledger entry
with `amount_cents <= 0` as "not eligible for refund". Cart-purchase buyer debits are
stored with a NEGATIVE `amount_cents` (signed debit, e.g. -7830), so EVERY shop
purchase was un-refundable. FIX: use `abs(...)` to derive the refundable amount.

## Verified (prod, real sessions + on-device)
- Purchase via `POST /ui/shoppingcart/carts/{id}/purchase` (+X-Idempotency-Key, promo):
  order+txn created, idempotent replay = same ids.
- Stock 50 -> 48 after buying qty 2.
- Seller `/ui/earnings/summary` total 6200, `/ui/earnings/transactions` shows "Shop sale",
  `/ui/payouts/balance` total_earned 6200 (held per 7-day PAYOUT_HOLD_PERIOD_SECONDS).
- On-device: seller Earnings screen shows "Other $62.00 100%".
- Refund request 201 -> admin approve 200.
