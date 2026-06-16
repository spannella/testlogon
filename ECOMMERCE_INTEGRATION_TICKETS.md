# eCommerce Store Integration — Implementation Tickets

This backlog wires the new OFBiz ERP depth — product variants/categories (PRD), live inventory & soft reservations (FAC/OFB), the pricing-rules engine (OFBiz M5), and the sales-order lifecycle/fulfillment state machine (ORD/FAC/SHP) — into the **existing storefront** (`app/services/shoppingcart.py`, `frontend/src/pages/shop/*`) so the customer browse/cart/checkout/post-order experience reflects variants, real availability, applied pricing rules, and fulfillment status. It is the **integration layer (Phase 8, J)** of the full OFBiz buildout: it consumes the other modules rather than reimplementing them. Everything is additive behind a single default-off `STORE_INTEGRATION_ENABLED` flag — with it off, the current shop/cart/orders/billing/inventory paths are byte-for-byte unchanged. New read/write paths use single-table DynamoDB modeling (PK/SK + GSIs, numeric GSI sort keys declared with `attr_types` in `scripts/local-ddb-init.py`), deterministic-id idempotency, SECOPS-007 dev/prod parity, and hermetic offline tests. Money never forks billing: any money-out reuses `refund_payment` / `settle_or_reverse_ledger`.

## Milestone 1 — Scoping & Scaffolding

### ECM-001: Store-integration scoping spike & integration-surface map
**Type:** Spike  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Map every storefront touchpoint that must change to surface the new ERP depth, grounded in the current store: catalog browse (`frontend/src/pages/shop/Catalog.tsx:180` flat `stock_status`/`stock_count` badges), product detail + add-to-cart (`frontend/src/pages/shop/ProductDetail.tsx:83` `addToCartMutation`, sends scalar `sku`/`item_id`), cart (`app/services/shoppingcart.py:311` `add_item`, `:474` `purchase_cart`, stock decrement at `:515`), cart total (`app/routers/shoppingcart.py:169` `ui_cart_total` → `cart_total_cents`), and checkout (`frontend/src/pages/shop/Checkout.tsx:135` `purchaseCart`).
- Define how each upstream module is consumed read-only at the storefront: PRD variants/categories (`CATALOG_DEPTH_TICKETS.md` PRD-007/PRD-004), FAC/OFB live availability + reservations (`FACILITY_FULFILLMENT_TICKETS.md` FAC-004, `OFBIZ_COMMERCE_TICKETS.md` OFB-003/OFB-004), OFB pricing rules (OFB-019/OFB-020), ORD order lifecycle + SHP tracking (`ORDER_LIFECYCLE_TICKETS.md` ORD-005/ORD-012, `SHIPPING_LOGISTICS_TICKETS.md` SHP-012/SHP-014).
- Decide the flag-gating contract: when `STORE_INTEGRATION_ENABLED` is off OR a given upstream flag (`PRODUCT_DEPTH_ENABLED`, `INVENTORY_RESERVATIONS_ENABLED`, `PRICING_RULES_ENABLED`, `ORDER_LIFECYCLE_ENABLED`, `SHIPPING_ENABLED`) is off, the storefront falls back to the current scalar behavior with zero regressions.
- Document the read-merge points (variant selection → inventory SKU → reservation → priced line → order line → fulfillment status) and the deterministic-id reuse (cart purchase already keys on `cart_purchase:{user_sub}:{cart_id}`, `shoppingcart.py:195`).

**Acceptance Criteria**
- A written design note (`docs/ecommerce-integration-plan.md`) enumerates every storefront touchpoint, the upstream module/ticket it consumes, and the off-flag fallback for each.
- A dependency matrix maps each ECM ticket to the upstream module flags it reads.
- Reviewer signs off that integration is read-only against upstream services (no forked pricing/inventory/order logic) and that all five upstream flags being off leaves the store byte-for-byte unchanged.

**Dependencies**
- None.

---

### ECM-002: Feature flag, settings & graceful-degrade helper
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add `STORE_INTEGRATION_ENABLED` (default `false`) plus per-surface sub-flags (`STORE_SHOW_LIVE_AVAILABILITY`, `STORE_APPLY_PRICING_RULES`, `STORE_SHOW_FULFILLMENT_STATUS`, `STORE_VARIANT_SELECTION_ENABLED`, all default `false`) to `app/core/settings.py`, read through the `S` singleton (mirroring the existing `cart_ttl_days` / `cart_abandonment_*` settings).
- Add an `app/services/store_integration.py` module with a `_integration_enabled(sub_flag)` gate helper and a `_safe_upstream(call, default)` wrapper that swallows upstream errors and returns the legacy default (so an upstream module being unavailable never breaks browse/cart/checkout).
- No behavior change yet — only scaffolding consumed by later tickets.

**Acceptance Criteria**
- New flags default to disabled and read through `S`.
- `_safe_upstream` returns the supplied default on any raised upstream exception (unit-tested).
- A smoke pytest imports `app.services.store_integration` and asserts the gate returns `False` with flags off.

**Dependencies**
- ECM-001.

---

### ECM-003: Storefront integration Pydantic models
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add additive response models to `app/models.py` (alongside the existing `CatalogItemOut` / `ShoppingCartItemOut` / `ShoppingCartTotalOut`): `StorefrontVariantOut` (variant SKU, option selections, per-variant price + availability), `StorefrontAvailabilityOut` (`available`, `on_hand`, `reserved`, `low_stock`, derived from FAC/OFB inventory), `CartPricingBreakdownOut` (subtotal, applied rule lines, discount_cents, final_total_cents), and `OrderFulfillmentStatusOut` (lifecycle status, ship groups, tracking numbers).
- Make every new field optional / additive so existing serializers and the current `_catalog_item_out` (`app/routers/catalog.py:107`) keep validating unchanged when the integration is off.

**Acceptance Criteria**
- New models import cleanly and existing `app/models.py` shapes are unchanged.
- Each new model has explicit optional defaults so an off-flag response (no variant/availability/pricing/fulfillment data) validates.
- pytest round-trips each model with both populated and empty payloads.

**Dependencies**
- ECM-001, ECM-002.

---

## Milestone 2 — Catalog browse: variants & live availability

### ECM-004: Variant-aware catalog read service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- In `app/services/store_integration.py`, add `enrich_catalog_item(item, *, viewer)` that, when `STORE_VARIANT_SELECTION_ENABLED` is on, calls the PRD virtual↔variant service (`CATALOG_DEPTH_TICKETS.md` PRD-007) to attach a `variants: [StorefrontVariantOut]` list and feature/option groups to the scalar catalog item read at `app/routers/catalog.py:107` `_catalog_item_out`.
- When the flag is off OR the product has no variants, return the item unchanged (legacy scalar item), so `frontend/src/pages/shop/Catalog.tsx`/`ProductDetail.tsx` keep working.
- Resolve each variant's inventory SKU mapping (per PRD-001 variant→SKU) but do NOT query stock here (ECM-005 owns availability) — keep this read pure topology.

**Acceptance Criteria**
- A virtual product returns its variant list with option selections; a flat product returns unchanged.
- With `STORE_VARIANT_SELECTION_ENABLED` off, output equals the legacy `_catalog_item_out`.
- Upstream PRD-service failure degrades to the legacy flat item (via `_safe_upstream`).
- pytest covers virtual-with-variants, flat-product, flag-off, and upstream-error paths.

**Dependencies**
- ECM-003, PRD-007 (CATALOG_DEPTH).

---

### ECM-005: Live availability projection from inventory/reservations
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Add `availability_for_skus(skus)` to `app/services/store_integration.py` that reads on-hand/reserved from the FAC facility service (`FACILITY_FULFILLMENT_TICKETS.md` FAC-004) / OFB inventory (`OFBIZ_COMMERCE_TICKETS.md` OFB-003) and computes `available = on_hand − reserved` per SKU, returning `StorefrontAvailabilityOut`.
- Wire it into the catalog read path so `stock_status`/`stock_count` on the browse grid (`Catalog.tsx:180`) and product detail (`ProductDetail.tsx:209`) reflect **live reservation-adjusted availability** instead of the static `stock_count` scalar — when `STORE_SHOW_LIVE_AVAILABILITY` is on.
- With the flag off, fall through to the existing `_compute_stock_status` (`app/routers/catalog.py:94`) so the current badge logic is untouched.

**Acceptance Criteria**
- An item with active reservations shows reduced `available` vs `on_hand`; an item at/below reorder point reports `low_stock`.
- Flag off → response uses the legacy `stock_count`/`_compute_stock_status` exactly.
- Inventory-service unavailable degrades to the scalar `stock_count` (no 500).
- pytest covers reserved-reduces-available, low-stock threshold, flag-off, and degrade paths.

**Dependencies**
- ECM-003, FAC-004 (FACILITY), OFB-003/OFB-004 (OFBIZ_COMMERCE).

---

### ECM-006: Catalog router — surface variants & availability (flag-gated)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Extend the catalog read endpoints (`app/routers/catalog.py:394` `list_items`, `:465` `search_items`, and the per-item read used by ProductDetail) to run responses through `enrich_catalog_item` + `availability_for_skus` when `STORE_INTEGRATION_ENABLED` is on, returning the additive `variants`/availability fields.
- Keep the endpoints registered as-is in `app/main.py`; no new router. Preserve all existing query params, pagination (`encode_next_token`/`decode_next_token`), and geo-block behavior (`_item_geo_blocked`, `:130`).

**Acceptance Criteria**
- With the integration on, list/search/detail responses carry variant + live-availability fields; with it off, responses are byte-for-byte the current shape.
- Pagination, geo-block, and search tokenization are unchanged.
- pytest asserts the enriched vs legacy response shapes against both flag states.

**Dependencies**
- ECM-004, ECM-005.

---

### ECM-007: Storefront variant picker & live-availability UI
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Update `frontend/src/pages/shop/ProductDetail.tsx` to render a variant/option picker (driven by the new `variants` field) that resolves to a selected variant SKU + price; the add-to-cart mutation (`ProductDetail.tsx:83`) sends the chosen variant SKU instead of the bare `item.item_id`.
- Update browse badges in `Catalog.tsx:180` and the detail stock badge (`ProductDetail.tsx:209`) to bind to the live `available`/`low_stock` projection; disable Add-to-Cart at zero availability (reuse the existing `out_of_stock` disable at `ProductDetail.tsx:267`).
- All new UI is conditional on the integration flag exposed via a config/feature endpoint; with it off, the page renders exactly as today.

**Acceptance Criteria**
- Selecting a variant updates price + availability + the SKU sent to the cart.
- Live availability badges reflect reservations; zero-availability disables Add-to-Cart.
- With the integration flag off, the page is visually + behaviorally unchanged (no variant picker).

**Dependencies**
- ECM-006, ECM-013 (types/endpoints).

---

## Milestone 3 — Cart: reservations & pricing rules

### ECM-008: Reserve stock on add-to-cart / checkout-begin
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Hook `app/services/shoppingcart.py:311` `add_item` (and the catalog add at `:370` `add_catalog_item`) to place a **soft reservation** via the OFB/FAC reservation service (`OFBIZ_COMMERCE_TICKETS.md` OFB-004) when `STORE_SHOW_LIVE_AVAILABILITY`/reservations are on, keyed deterministically per `{cart_id}#{sku}` so re-adds don't double-reserve.
- Release/adjust the reservation on quantity change (`set_item_quantity`, `:400`; `decrement_item`, `:424`) and on cart delete (`delete_cart`, `:448`); let the reservation TTL/expiry (OFB-004) + the existing cart-abandonment expiry (`expire_abandoned_carts`, `:912`) free stranded reservations.
- When reservations are off, `add_item` behaves exactly as today (no reservation calls).

**Acceptance Criteria**
- Adding an item reserves available stock; reducing/removing quantity releases the delta; deleting the cart releases all.
- Re-adding the same SKU is idempotent (single reservation, not doubled).
- Reservation-service failure does not block adding to cart (degrades to legacy add) — covered by test.
- pytest covers reserve-on-add, release-on-decrement/delete, idempotent re-add, and degrade.

**Dependencies**
- ECM-005, OFB-004 (OFBIZ_COMMERCE).

---

### ECM-009: Apply pricing rules at cart total & checkout
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Replace the naive `cart_total_cents` summation (`app/services/shoppingcart.py:301`, used by `ui_cart_total` at `app/routers/shoppingcart.py:169`) with a pricing-aware total: when `STORE_APPLY_PRICING_RULES` is on, run cart line items through the OFB pricing-rules engine (`OFBIZ_COMMERCE_TICKETS.md` OFB-019/OFB-020) to produce `CartPricingBreakdownOut` (subtotal, applied rule lines, discount, final total), while preserving the existing flat promo-code path in `purchase_cart` (`:545` `validate_promo_code`).
- Make `purchase_cart` (`:474`) authoritative: the rule-discounted total computed at checkout must match the cart-total preview (no client/server drift), and applied rule references persist onto the order line items via `commerce_order_service.create_order_from_line_items` (`:581` `metadata`).
- Keep promo-code stacking/precedence per OFB-020 (rule + code interaction); with pricing rules off, totals equal today's behavior.

**Acceptance Criteria**
- Cart total preview and final purchase amount reflect the same applied rules (no drift); rule lines + discount are stored on the order metadata.
- Existing flat promo codes still validate and redeem unchanged (`redeem_promo_code`, `:657`).
- With `STORE_APPLY_PRICING_RULES` off, totals equal the legacy summation.
- pytest covers a tiered rule through total→purchase, rule+promo interaction, and flag-off parity.

**Dependencies**
- ECM-003, OFB-019/OFB-020 (OFBIZ_COMMERCE).

---

### ECM-010: Convert reservations → committed inventory on purchase
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Make `purchase_cart` (`app/services/shoppingcart.py:474`) reservation-aware: on a successful, idempotent purchase (the existing `ConditionExpression="#status = :open"` CAS at `:626` already guarantees single-commit), convert each cart reservation into an on-hand decrement via OFB-004's commit path instead of the current direct `stock_count` decrement (`:515`).
- Preserve the current `stock_count` mirror write as a denormalized read-through (so the legacy `Catalog.tsx` badge keeps working) and keep the existing out-of-stock 409 path (`:534`) as the fallback when reservations are off.
- Release any leftover reservation if order creation fails before the CAS commit.

**Acceptance Criteria**
- A purchase commits exactly the reserved quantity to on-hand once (idempotent on replay — the CAS already returns the prior result at `:631`).
- With reservations off, the legacy conditional `stock_count` decrement + rollback path runs unchanged.
- A pre-commit failure releases the reservation (no leaked reserved stock).
- pytest covers reserve→commit-once, replay idempotency, off-flag legacy decrement, and pre-commit release.

**Dependencies**
- ECM-008, ECM-009.

---

### ECM-011: Cart UI — reservation & pricing-breakdown surfacing
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Update `frontend/src/pages/shop/Cart.tsx` and `Checkout.tsx` to bind the cart total to the new `CartPricingBreakdownOut` (subtotal, per-rule discount lines, final total) returned by the total endpoint (`Cart.tsx:71` `getCartTotal`, `Checkout.tsx:68`), showing applied rule names + savings.
- Surface a soft "reserved for you" indicator and a low-availability warning when a cart line's live availability drops, reusing the availability projection from ECM-005.
- All additions are flag-gated; with the integration off, the cart/checkout render exactly as today.

**Acceptance Criteria**
- Cart/checkout show the rule breakdown and reservation/availability indicators when on.
- With the flag off, the pages are visually + behaviorally unchanged.
- The displayed final total matches the server `purchaseCart` result (no drift).

**Dependencies**
- ECM-009, ECM-010, ECM-013.

---

## Milestone 4 — Post-checkout: order lifecycle & fulfillment status

### ECM-012: Order fulfillment-status read service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add `order_fulfillment_status(order_id, *, user_sub)` to `app/services/store_integration.py` that projects the ORD lifecycle state (`ORDER_LIFECYCLE_TICKETS.md` ORD-005/ORD-012), FAC ship groups + pick/pack/ship state (`FACILITY_FULFILLMENT_TICKETS.md` FAC-010), and SHP tracking numbers (`SHIPPING_LOGISTICS_TICKETS.md` SHP-012/SHP-014) into `OrderFulfillmentStatusOut`, ownership-checked against the requesting `user_sub`.
- Reconcile with the existing post-purchase data: the cart purchase already returns `order_id` + `purchase_txn_id` (`app/services/shoppingcart.py:722`) and writes purchase history (`record_cart_purchase`, `:668`); this read joins those to the lifecycle/fulfillment state without forking order creation.
- When `STORE_SHOW_FULFILLMENT_STATUS` is off (or ORD/SHP flags off), return only the legacy order summary status.

**Acceptance Criteria**
- A buyer sees their order's lifecycle status + ship-group tracking; a foreign order_id → 403/404.
- Flag off → only the legacy order summary status is returned.
- Missing/unavailable ORD/SHP data degrades gracefully (no 500).
- pytest covers populated status, ownership rejection, flag-off, and degrade.

**Dependencies**
- ECM-003, ORD-005/ORD-012 (ORDER_LIFECYCLE), FAC-010 (FACILITY), SHP-012/SHP-014 (SHIPPING).

---

### ECM-013: Frontend types & endpoint wrappers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add TS interfaces to `frontend/src/api/types.ts` mirroring ECM-003 (`StorefrontVariant`, `StorefrontAvailability`, `CartPricingBreakdown`, `OrderFulfillmentStatus`) and extend the existing `CatalogItem`/`CartTotal`/`CartPurchase` types with the additive optional fields.
- Add endpoint wrappers to `frontend/src/api/endpoints/cart.ts` (and a small `orders.ts` if needed) for the fulfillment-status read and any new config/feature-flag read, following the existing `getCartTotal`/`purchaseCart` patterns (`cart.ts`).

**Acceptance Criteria**
- New types compile and the existing `cart.ts` wrappers are unchanged in signature.
- A `getOrderFulfillmentStatus(orderId)` wrapper calls the ECM-012 endpoint and is typed to `OrderFulfillmentStatus`.
- `tsc` passes with no errors.

**Dependencies**
- ECM-003, ECM-012.

---

### ECM-014: Order fulfillment endpoint + order detail/tracking page
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Add a `GET` fulfillment-status endpoint (under the cart/orders router, registered in `app/main.py`) backed by `order_fulfillment_status` (ECM-012), `require_ui_session`, ownership-enforced.
- Update the post-purchase success view (`frontend/src/pages/shop/Checkout.tsx:140`, which already captures `order_id`) and add an order-detail/tracking page under `frontend/src/pages/shop/` showing lifecycle timeline + ship-group tracking links, with a route in `frontend/src/App.tsx` (alongside `cart/checkout` at `App.tsx:363`) and a nav entry, all flag-gated.

**Acceptance Criteria**
- A buyer can open their order and see lifecycle status + tracking; non-owners are denied.
- The checkout success screen links to the order/tracking page when the integration is on.
- Route + nav are flag-gated; with the integration off, no new nav/route surface is added.

**Dependencies**
- ECM-012, ECM-013.

---

## Milestone 5 — Tests

### ECM-015: Hermetic offline pytest + storefront E2E suite
**Type:** Chore  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Add hermetic offline pytest (`tests/test_ecm_store_integration.py`) covering: variant-aware catalog read (ECM-004), live availability projection incl. reservation reduction + degrade (ECM-005), reserve-on-add/release idempotency (ECM-008), pricing-rule total↔purchase parity + flag-off parity (ECM-009), reserve→commit-once on purchase (ECM-010), and fulfillment-status ownership + degrade (ECM-012). Bind moto to the frozen `T` handles (per the CLAUDE.md hermetic-test pattern), stub upstream PRD/FAC/OFB/ORD/SHP services, and assert **flag-off byte-for-byte parity** with the legacy `shoppingcart`/`catalog` responses.
- Add `frontend/e2e/store-integration.spec.ts` covering: select a variant → live availability → add to cart (reserves) → pricing rule applied at total → checkout → order tracking page, using the seeded-session + CSRF + `X-Idempotency-Key` patterns from CLAUDE.md/MEMORY.md; plus a flag-off smoke that the legacy store path is unchanged.

**Acceptance Criteria**
- pytest suite passes offline with no real AWS and asserts flag-off parity for every integrated surface.
- E2E covers the full variant→reserve→price→checkout→track happy path and the flag-off legacy path under the standard 1-worker Playwright config.
- CI green for both suites.

**Dependencies**
- ECM-007, ECM-011, ECM-014.

---
