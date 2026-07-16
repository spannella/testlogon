# ECOMX E4 — Buyer-flow / UX (app + backend)

LIVE-verified against the running uvicorn (real HTTP + live openapi + real ship-group table),
NOT an in-process TestClient. `verify_ecomx4.py` = 19/19 PASS on the dev live server; the new routes
are live (200/401) on prod; E1 29/29, E2 33/33, E3 all-pass (no regression).

## Tickets

- **ECOMX-40 (B3 / A7)** — reachable shipping-address step + shipping/tax on the charge.
  `CartPurchaseIn` gained `address_id` + `shipping_method`. `purchase_cart` now, for a PHYSICAL order
  (>=1 line from a seller != buyer) WITH a selected address, computes a shipping fee (rate engine when
  enabled+seeded, else `CHECKOUT_FLAT_SHIPPING_CENTS`) + sales tax (`CHECKOUT_TAX_BPS` on the
  post-discount merchandise subtotal) and adds them to `final_total` BEFORE the ECOMX-10 charge, so the
  quoted total == the amount charged. Components are stamped on the order header (shipping_cents /
  tax_cents / merchandise_cents / grand_total_cents / ship_to), the txn refund_meta and the purchase
  response. The chosen address is threaded into `populate_on_approval(ship_to=...)` so the seller ships
  to it. Seller-credit proration switched to the merchandise subtotal (sellers are NOT credited a share
  of shipping/tax; the platform keeps those). Digital/self-purchase carts collect neither.
  APP: the orphaned `AddressShippingDest` is wired into OrderReview → address step (result passed back
  via SavedStateHandle); Place order is disabled until an address is chosen; `address_id` is threaded
  into `cartRepository.purchase(...)`.

- **ECOMX-41 (B4)** — ONE checkout CTA. The dual "Choose payment method" redirect button is removed from
  OrderReview; only "Place order" remains (which really charges via ECOMX-10). No double-charge, no
  redirect dead-end.

- **ECOMX-42 (B2 / B6 / B8)** — realistic post-purchase status + confirm-delivery.
  `record_cart_purchase` now seeds the txn **PENDING** (not COMPLETED at t=0, no `completed_at`). A
  digital/self order (no ship groups) completes instantly; a physical order stays PENDING and is driven
  to COMPLETED only on delivery: `order_fulfillment_bridge.reconcile_order` calls the new
  `complete_txn_on_delivery` when the header reaches `completed`. `get_transaction_info` surfaces
  `order_status` + `fulfillment_status` from the header. New buyer endpoint
  `POST /ui/purchase-history/transactions/{txn_id}/confirm-received` (owner-scoped; added to the
  API-key route-scope exemption so #118 parity holds) forces delivery + completes the txn. The orphan
  self-heal sweep now treats PENDING-or-COMPLETED as "paid" (it no longer requires COMPLETED).
  APP: OrderDetail shows a fulfilment chip, a "Confirm delivery" card (visible once shipped, gone once
  completed), and confirmation routes off `orderId`-derived txn (the nullable fallback lands on the
  purchase-history list which always identifies the order).

- **ECOMX-43 (B5)** — digital-goods access surface. New `data/entitlements` layer over
  `GET /v1/entitlements` (already live); OrderDetail renders a "Digital items" card with Open/Download
  per granted entitlement (gated on active status; deep-links the in-app library viewer).

- **ECOMX-44 (B7)** — PDP quantity stepper. AddToCartBar gained a 1..maxQty stepper (maxQty = stock when
  finite, else 99); `addToCart(quantity)` was already backend-capable. Variants are a separate authoring
  feature (PRD-007) not surfaced on the shopper PDP → documented single-SKU on the PDP.

## E0-gap closed to enable E4 fulfilment verification on dev

`seller_ship_groups` was a PROD-ONLY table (declared/bound in prod `tables.py`/`settings.py` but absent
from the dev clone + `local-ddb-init`). Reconciled into the dev clone: `settings.seller_ship_groups_table_name`,
`Tables.seller_ship_groups` binding, and a `local-ddb-init` TableDef (PK seller_id / SK ship_group_id /
GSI_ORDER). Prod already had it (no prod change needed for the table wiring).

## Backend files (dev==prod, mirrored byte-for-byte + prod-patched for the 2 divergent files)

app/services/shoppingcart.py, app/services/purchase_history.py, app/services/order_fulfillment_bridge.py,
app/services/seller_ship_groups.py, app/routers/shoppingcart.py, app/routers/purchase_history.py,
app/services/api_key_route_scope_registry.py, app/models.py, app/core/settings.py, app/core/tables.py
(dev-only), scripts/local-ddb-init.py (dev-only).

## Settings (defaults; env-overridable)
CHECKOUT_SHIPPING_TAX_ENABLED=true, CHECKOUT_FLAT_SHIPPING_CENTS=599, CHECKOUT_TAX_BPS=725.

## LIVE verify matrix — 19/19 (dev live server, real HTTP)
B3 merchandise=5000 / shipping>0 / tax>0 ; A7 total==merch+ship+tax ; A7 seller net from merch only (4250) ;
B2 fresh order PENDING (not COMPLETED, no completed_at) ; B2 order_status surfaced ;
B3 seller ship_to == checkout address ; B6 confirm-received → COMPLETED + completed_at ;
B3 self/digital: no shipping/no tax ; B2 instant(no-ship) → COMPLETED. Regression: E1 29/29, E2 33/33, E3 all-pass.

## Residuals (non-blocking, pre-existing — NOT E4)
- `ShopSponsoredUnitDtoJsonAdapter` crashes on a sponsored ad with a null `body` (`$.sponsored[0].body`
  non-null violation). Pre-existing shopads DTO strictness; not touched by E4.
