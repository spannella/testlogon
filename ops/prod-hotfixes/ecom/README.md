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

## BUG D — app-driven shop purchases still did not credit the seller (2026-07-04)
Follow-up found while verifying the in-app buyer checkout end-to-end. BUG A credits
each cart item's creator via `_ci.get("creator_user_id")`, but that field is only
populated by `add_catalog_item` (POST /carts/{id}/items/catalog). The Android app
adds via `add_item` (POST /carts/{id}/items) and its `CartItemInDto` carries no
creator field, so app-added cart items had no `creator_user_id` -> the BUG-A credit
loop skipped them and the seller earned nothing from an in-app purchase (stock still
decremented, buyer ledger still written). FIX: in `add_item`, when `creator_user_id`
is absent but `item_id`+`category_id` are present, enrich `creator_user_id` from the
catalog item's `creator_id` (same source add_catalog_item uses). Client-agnostic; fixes
web + app uniformly. See shoppingcart_add_item_creator.py.patch.
Verified (prod, on-device, real sessions): full app flow browse->product->add-to-cart->
cart->checkout->Place Order created order fb8d2b4e..., stock 47->46, seller
/ui/earnings/summary 6200->8700 (+2500 "Shop sale" attributed to buyer), payouts
total_earned 6200->8700.

## Related app fix (residual #1 — the in-app checkout now completes)
android/ CheckoutSessionViewModel.placeOrder() previously routed "Place order" through
the never-authorizing BillingAuthorizer stub (PaymentsUnavailable) / an external
redirect that 404s on stripe-mock, so no in-app purchase could complete. It now calls
the reliable one-shot endpoint POST /ui/shoppingcart/carts/{cart_id}/purchase
(X-Idempotency-Key) via CartRepository.purchase(); on success it routes to the order
confirmation (tracking) screen. Files: data/cart/{CartApi,CartDtos,CartDomain,
CartRepository}.kt, feature/checkout/{CheckoutSessionViewModel,OrderReviewScreen}.kt,
navigation/CartNavigation.kt.

## BUG E — shop purchases not refundable from the app order-detail (entry_id unreachable)

**Symptom:** on-device "Request a refund" from the order-detail screen returned
`404 Transaction not found`; refunding a cart purchase via the app was impossible.

**Root cause:** `record_cart_purchase` (app/services/purchase_history.py) writes the
buyer purchase-debit billing ledger entry via `new_ledger_entry`, which auto-assigns
a random `entry_id` (ulidish). `refund_requests.create_refund_request` matches the
refund target by that ledger `entry_id`, but the client never receives it — the
purchase-history transaction only exposes `txn_id` (and `external_ref`=order_id).
The Android order-detail passes `txn_id` (PurchasesDomain `id = txnId`) as
`transaction_entry_id`, which never matches the ledger entry_id → "Transaction not found".

**Fix:** after building the buyer purchase-debit ledger item, set
`led_item["entry_id"] = txn_id` so the debit is addressable by the same txn_id the
client already holds. Backend-only; the app already passes the correct id (no rebuild).
Approve path also matches on the `entry_id` field, so approval works too.

**Verified:** API refund request via txn_id → 201; admin approve → 200 (approved, 2500).
On-device: fresh purchase → order-detail → Request a refund → "Refund request / Pending"
(previously "Transaction not found"), crash-free.

Prod-applied to the ACTIVE serving path /home/ubuntu/testlogon/app/services/purchase_history.py
(`.bak_ecom_1783125555`) + restart; openapi 200.

## BUG F — digital-goods seller credits invisible to earnings/payouts (2026-07-04)

Sibling of BUG A, for the DIGITAL delivery paths. `billing_shared.new_ledger_entry`
persists `"type": entry_type`, and the earnings/payout consumers
(`creator_earnings._query_credit_entries` / `get_earnings_transactions` and
`creator_payouts.get_available_balance`) hard-filter `Attr("type").eq("credit")`.
The seller-earning credit writers for VOD/license/ad used NON-`credit` entry_types, so
those rows were filtered out before counting and the seller earned nothing on-paper from
a digital sale (buyer txn / stock / credit-row all otherwise correct). The earnings
CATEGORY is derived from `reason` (`creator_earnings.classify_entry`), not from type, and
`LEDGER_ENTRY_SIGN` maps every one of these types AND `credit` to +1, so `signed_amount_cents`
is unchanged by the flip.

FIX (per-writer entry_type flip to `credit`; debits + refund/affiliate/sponsorship
credits left untouched so they are NOT swept into seller earnings):
- `vod_purchase.py`         `vod_purchase_credit`      -> `credit`  (reason "VOD sale" -> vod_purchases)
- `vod_rental.py`           `vod_rental_credit`        -> `credit`  (reason "VOD {tier} sale" -> vod_purchases)
- `license_revenue.py`      `license_revenue_credit`   -> `credit`  (reason "License revenue share from ..." -> other)
- `license_revenue.py`      `license_fixed_fee_credit` -> `credit`  (reason "License fixed fee" -> other)
- `ad_billing.py`           `ad_revenue_credit`        -> `credit`  (reason "Ad revenue share")
- `ad_placement.py`         `ad_revenue_credit`        -> `credit`  (reason "Ad revenue")

Consumer-string check (verify-before-change): only `ad_revenue_credit` was read by any
consumer. Both made forward+backward compatible (identify ad-revenue by `reason`, still
match the legacy type): `content_ad_controls.get_ad_revenue_breakdown` and
`platform_financial_dashboard._aggregate`. The vod/license type strings had no consumers.
The earnings/payout QUERY was deliberately NOT broadened.

Verified (prod, real sessions; seller crash1782189692@testlogon.example; fresh buyer):
- Pre-fix real VOD purchase (1500c): earnings total 26200->26200, vod_purchases 0, payout
  total_earned 26200->26200 -> credit invisible (bug reproduced).
- Post-fix VOD purchase (2500c) + license split (2000c): earnings total 26200->30700 (+4500),
  vod_purchases 0->2500, other 26200->28200 (+2000), transaction_count 8->10; payout
  total_earned 26200->30700 (+4500). `/ui/earnings/transactions` shows "VOD sale"->vod_purchases,
  "License revenue share from content_sale"->other.
- `available_cents` stayed 0 (all credits inside the payout hold window; total_earned is the
  authoritative moved figure).
- Ad path NOT seeded E2E (needs the ad-serving pipeline); ad-consumer compat unit-verified
  (`platform_financial_dashboard._aggregate` net_revenue counts new `credit`+reason "Ad revenue"
  and legacy rows, excludes a `credit`/"VOD sale" row).

Prod .bak: `<file>.bak_ecom2_1783143629` (all 7 files) on /home/ubuntu/testlogon; restart_backend.sh;
openapi 200. See bug3_seller_credit_visibility.patch + README_bug3_seller_credit_visibility.md.

## BUG G — shop order stuck at pending_payment after a completed cart purchase (2026-07-04)

`commerce_order_service.create_order` seeds the /ui/orders header at
`lifecycle_status="created"` (legacy mirror `status="pending_payment"`; prod has
`ORDER_LIFECYCLE_ENABLED=1`). `shoppingcart.purchase_cart` captures payment synchronously
(buyer txn COMPLETED, stock decremented, seller credited) but never called the
`order_lifecycle` state machine, so the header was orphaned in `created`/`pending_payment`
forever.

FIX: after `_ecm_commit`, advance the header `created -> approved` (legacy
`pending_payment -> approved`) via the existing `order_lifecycle.transition_order`.
`approved` is the ONLY forward edge out of `created` (created -> {approved, held, cancelled})
and legacy-mirrors to payment-approved/paid — no new states invented. Deliberately NOT
`completed` (a post-shipment terminal state that would require falsely asserting
allocate/pick/pack/ship events). Safe + idempotent: guarded on `lifecycle_status=="created"`,
CAS/version-gated with the canonical cart idempotency key, best-effort (never blocks/reverses
a purchase), fires only on the first successful purchase (replays return earlier). The
checkout-session/redirect path is untouched.

Verified (prod, real sessions, https://tl-api.bitbazaar.cc; buyer ecbuyer1783123620@…, physical
widget @2500c):
- BEFORE: 8 pre-fix orders all `status=pending_payment / lifecycle_status=created`.
- AFTER: new order c9d4e9d32a2808741d1db9030c3352bf -> `status=approved / lifecycle_status=approved`;
  history = None->created (order_created) then created->approved (actor=buyer, "Cart purchase paid").
  Older orders remain pending_payment.
- No regression: purchase-history txn `status=COMPLETED`, external_ref=order_id (linkage intact).
- Idempotent replay: re-POST same cart -> same order_id, stays approved, history still exactly 2 rows.

Prod-only file (order_lifecycle router/service + the diverged purchase_cart do NOT exist in the
android-impl dev clone), so this is a prod-apply record, not a runnable branch fold. Prod .bak:
`app/services/shoppingcart.py.bak_ecom2_1783144144`; restart_backend.sh; openapi 200. See
bug2_order_lifecycle_advance.patch + README_bug2_order_lifecycle.md.
