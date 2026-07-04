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
