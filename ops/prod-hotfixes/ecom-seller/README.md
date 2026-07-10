# ECOM-SELLER (G1–G4) — seller fulfilment: per-seller ship-groups + notify + scoped queue

Backend LIVE PROD HOTFIX (via SSM) fixing the 4 seller-fulfilment gaps found while
filming the V3 e-commerce demo. **Prod-only subsystem**: the ORD-008/009/011 order
lifecycle (`app/routers/order_lifecycle.py`, `app/routers/orders.py`,
`app/services/order_lifecycle.py`, `order_ship_groups.py`, `order_store.py`,
`shipping.py`, `T.orders`/`T.order_items`) exists ONLY on prod EC2
`i-08f937fc705ebea75` — the `android-impl` dev clone does NOT have it. So this is a
prod re-apply artifact (like the rest of `ops/prod-hotfixes/`), not a dev-clone code
change.

## The 4 gaps → fixes

- **G1 "you sold it" notification** — on order APPROVAL (payment captured), each
  distinct seller in the cart now gets an in-app alert (`write_alert`, event
  `shop_item_sold`) + FCM push (`send_push_for_alert`) summarising the item(s) +
  buyer + ship-to, deep-linking to their sale (`action_url=/seller/orders?sale={ship_group_id}`).
- **G2 buyer address + full details on the seller screen** — each seller ship-group
  carries the buyer shipping address (`ship_to`, from `purchase.buyer.mailing_address`
  → profile `mailing_address`, fallback `/ui/addresses` primary), buyer name/email, and
  that seller's real line items (name + qty + unit price + line total + subtotal).
- **G3 seller-scoped orders (non-admin)** — new `/ui/seller/sales` endpoints let a
  NORMAL seller list + fetch + fulfil ONLY their own ship-groups. A seller never sees
  another seller's items nor the buyer's payment internals. (The pre-existing
  `/ui/orders` list is buyer-scoped for normal users; `/ui/orders/{id}/transition` is
  admin-only — that admin path is untouched.)
- **G4 real line-item name** — the cart→order line was rendered as the internal
  `internal_api_package` product_type (no `name` on the row). On approval we backfill
  each `order_items` row's real catalog `name` (+ `seller_id`) so the order line shows
  the real product name for BOTH the buyer order detail and the seller sale.

## What changed (prod)

New files:
- `app/services/seller_ship_groups.py` — populate-on-approval, seller-scoped reads,
  scoped lifecycle transition, G1 notify, G4 backfill.
- `app/routers/seller_ship_groups.py` — `/ui/seller/sales` (prefix), `require_ui_session`
  (non-admin), gated by `S.order_lifecycle_enabled`.

Edited (anchored, idempotent) — `.bak_ecomsell_1783650821`:
- `app/services/shoppingcart.py` — after the created→approved transition in
  `purchase_cart`, call `seller_ship_groups.populate_on_approval(...)` (best-effort,
  never blocks the purchase).
- `app/main.py` — import + `include_router(seller_sales_router)`.
- `app/core/settings.py` — `seller_ship_groups_table_name` (`SELLER_SHIP_GROUPS_TABLE_NAME`, default `seller_ship_groups`).
- `app/core/tables.py` — `seller_ship_groups` field + `_safe_table` registration.
- `scripts/local-ddb-init.py` — `TableDef(seller_ship_groups, hash=seller_id, range=ship_group_id, gsi=GSI_ORDER)`.

New DDB table (created on prod via `T.order_items.meta.client.create_table`):
- **`seller_ship_groups`** — PK `seller_id` (S) / SK `ship_group_id` (S);
  GSI **`GSI_ORDER`** (HASH `order_id`, RANGE `ship_group_id`, projection ALL);
  PAY_PER_REQUEST.

## Contracts (`/ui/seller/sales`, non-admin, `require_ui_session`)

- `GET  /ui/seller/sales?limit=&cursor=` → `SellerSaleListOut{ sales:[SellerSaleOut], next_cursor }`
- `GET  /ui/seller/sales/{ship_group_id}` → `SellerSaleOut` (404 if not the caller's)
- `POST /ui/seller/sales/{ship_group_id}/transition` → `SellerSaleOut`
  body `{ target_status, reason?, tracking_number?, carrier?, idempotency_key? }`

`SellerSaleOut = { ship_group_id, order_id, status, allowed_transitions[], buyer_name,
buyer_email, ship_to{}, line_items:[{item_id, sku, name, quantity, unit_price_cents,
line_total_cents}], item_count, subtotal_cents, currency, tracking_number, carrier,
created_at, updated_at }` — **no buyer payment internals by construction.**

Lifecycle: a group is born `approved` and follows the canonical
`order_lifecycle.TRANSITIONS` state machine, scoped to the seller's own group:
`approved → allocated → picking → packed → shipped` (→ completed/returned). Illegal
transitions → 409; another seller's group → 404.

## Prod verify — 32/32 OVERALL ALL_PASS

`verify_ecomsell.py` (in-process FastAPI TestClient + service layer on prod DDB via SSM):
G1 seller `shop_item_sold` alert + deep-link; G2 buyer ship_to (Columbus) + real names
on the list/detail; G3 non-admin list 200 / sellerA sees own / sellerB does NOT see or
transition it (404) / no payment field in payload; G4 order line name == "Handmade Blue
Mug"; fulfil approved→…→shipped; multi-seller cart → 2 groups each seeing only their own;
idempotent replay = no dup groups.

## Re-apply

```
ROOT=/home/ubuntu/testlogon python3 apply_ecomsell.py   # idempotent, anchored, creates table
# restart: bash /home/ubuntu/restart_backend.sh ; curl openapi.json -> 200
```
Set `PROBE=1` + `ROOT=/tmp/probe_...` to dry-run anchors + pycompile without creating the table.

## Residuals

- App slice (separate task): a Seller Sale-detail screen that renders the buyer address +
  real line names from `/ui/seller/sales`, a non-admin sales queue, mark-shipped action,
  and handling the `shop_item_sold` alert deep-link. No app code changed here.
- Dev clone (`android-impl`) is NOT registered (settings/tables/ddb-init) because it lacks
  the whole order-lifecycle subsystem; prod IS registered. Fold is the record of record.
- FCM push is gated by the seller's `push_event_types` prefs (correct product behavior);
  the in-app alert always writes. Pre-existing unrelated noise during purchase:
  `store_integration.reserve(reservation_id=…)` TypeError + `commerce_entitlement_orchestration_failed`
  — neither affects the ship-group flow.
