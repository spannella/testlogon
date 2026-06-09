# Shipping / Logistics — Implementation Tickets

This backlog adds OFBiz Shipping/Logistics (Phase 8, module H) to the testlogon commerce stack: a carrier/ship-method model, shipping-rate estimation, first-class SHIPMENTS with ship groups and package contents, tracking numbers/status, and shipment↔order-fulfillment linkage. It is **additive + flag-gated** (default-off `SHIPPING_ENABLED` group) and reuses — never forks — the existing carrier infrastructure already in the repo (`app/services/carrier_tracking.py` URL/detect/status helpers, the `purchase_transactions` shipping sub-record, the `carrier_tracking_poller`, and the order/line-item model in `app/services/commerce_order_service.py`). With every flag off, existing shop/cart/orders/billing/tracking behavior is byte-for-byte unchanged. All money-out (refunds of paid shipping) reuses `refund_payment`; new write paths use deterministic-id idempotency; tests are hermetic + offline; dev/prod parity (SECOPS-007) holds throughout.

## Milestone 1 — Scaffolding & data model

### SHP-001: Shipping module scoping & data-model delta
**Type:** Spike  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Map OFBiz Shipping/Logistics entities (Carrier party-role + ShipmentMethodType, CarrierShipmentMethod, ProductStoreShipmentMeth/quote, Shipment, ShipmentItem, ShipmentPackage, ShipmentPackageContent, ShipmentRouteSegment + tracking, ShipGroup on OrderHeader) onto the current state: existing carrier helpers (`app/services/carrier_tracking.py:10` `CARRIER_TRACKING_URLS`, `:33` `build_tracking_url`, `:46` `detect_carrier`, `:84` `map_carrier_status`, `:138` `apply_tracking_result`), the order/line model (`app/services/commerce_order_service.py:39` `create_order`, line rows at `:88`, statuses only `pending_payment`), the transaction shipping sub-record + tracking endpoint (`app/services/purchase_history.py:398` `update_shipping`, `:595` `find_transaction_by_tracking`; `app/routers/purchase_history.py:118` `GET .../tracking`), and the mock carrier surface (`app/routers/carrier_tracking_mock.py`).
- Document the gaps: no carrier/ship-method catalog, no rate model/estimation, no Shipment entity (shipping is a flat sub-map on a transaction), no ship groups (one ship-to per order), no package/contents model, no shipment↔order-line link.
- Decide the cherry-picked scope (defer multi-warehouse routing, label-printing/manifest generation, customs/international docs, freight/LTL) and lock the new tables + GSIs (with `attr_types` for numeric keys), settings keys, and the `SHIPPING_ENABLED` flag group, all reconciling to the `orders`/`order_items`/`purchase_transactions` tables.

**Acceptance Criteria**
- A short design note (in this file's header or `docs/ofbiz-shipping-plan.md`) enumerates each OFBiz shipping entity, the in/out decision, and the testlogon mapping.
- The data-model delta lists every new table (PK/SK/GSIs, `attr_types` for numeric keys), every new `app/models.py` shape, and every new `app/core/settings.py` key + flag.
- The plan explicitly states that existing `carrier_tracking.py` helpers and the transaction shipping sub-record are reused (not replaced) and remain the source for tracking-URL/status.

**Dependencies**
- None.

---

### SHP-002: Shipping tables, settings & feature flags scaffolding
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Land the table definitions agreed in SHP-001 into `scripts/local-ddb-init.py` following the `TableDef(_resolve_table_name(S.<name>, "<default>"), "PK", "SK", gsi=[...], attr_types={...})` pattern used for `orders` at `scripts/local-ddb-init.py:287` and `order_items` at `:295`. New tables: `shipping_carriers` (carrier/ship-method catalog, PK `carrier_id` / SK `sk` for `CARRIER#`/`METHOD#` rows), `shipments` (PK `shipment_id`, GSIs by `order_id`+`created_at` and `status`+`created_at`), `shipment_items` (PK `shipment_id` / SK `item_id`), `shipment_packages` (PK `shipment_id` / SK `package_seq`). Declare numeric GSI sort keys (`created_at`) with `attr_types={"created_at": "N"}` per the CLAUDE.md gotcha.
- Add settings to `app/core/settings.py` near the existing carrier block (`app/core/settings.py:343` "Carrier tracking (SHOP-004)"): the master flag `shipping_enabled` (`SHIPPING_ENABLED`, default `false`), `shipping_rate_estimation_enabled`, table-name keys (`shipping_carriers_table_name`, `shipments_table_name`, `shipment_items_table_name`, `shipment_packages_table_name`), and `shipping_default_currency`.
- Wire table handles in `app/core/tables.py` (`T.shipping_carriers`, `T.shipments`, `T.shipment_items`, `T.shipment_packages`).

**Acceptance Criteria**
- `just restart` recreates all new tables locally with no `ValidationException` (numeric GSI keys correctly typed).
- New flags read through the `S` singleton and default to disabled; `shipping_enabled` off leaves all new routers/paths inert.
- A smoke pytest imports `app.core.tables.T` and asserts each new handle resolves.

**Dependencies**
- SHP-001.

---

### SHP-003: Shipping Pydantic models
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add the request/response shapes to `app/models.py` (alongside the existing commerce/order models): `CarrierIn`/`CarrierOut`, `ShipmentMethodIn`/`ShipmentMethodOut`, `ShippingRateRequest`/`ShippingRateQuote`/`ShippingRateOption`, `ShipGroupIn`/`ShipGroupOut`, `ShipmentIn`/`ShipmentOut`, `ShipmentItemOut`, `ShipmentPackageIn`/`ShipmentPackageOut`, `ShipmentPackageContentIn`, and `ShipmentTrackingUpdateIn`.
- Reuse existing value conventions: integer cents for money (mirroring `amount_cents` on order rows, `app/services/commerce_order_service.py:99`), ISO timestamps for created/updated, and the internal shipment-status enum aligned with the carrier statuses already mapped in `carrier_tracking.py` (`label_created`, `picked_up`, `in_transit`, `out_for_delivery`, `delivered`, `exception`, `returned`).
- Keep carrier codes consistent with the supported set in `app/services/carrier_tracking.py:10` (`ups`/`fedex`/`usps`/`dhl`) plus a generic `manual` carrier for ship methods without online tracking.

**Acceptance Criteria**
- Models validate weight/dimension/cents fields as non-negative and reject unknown carrier codes against the supported set.
- Shipment-status enum matches the internal statuses in `carrier_tracking.py` so a tracking update can drive a shipment state with no translation.
- A pytest round-trips each model (`model_validate` → `model_dump`) with representative payloads.

**Dependencies**
- SHP-002.

---

## Milestone 2 — Carrier & ship-method catalog

### SHP-004: Carrier & ship-method service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/services/shipping_carriers.py` with CRUD over `shipping_carriers`: `create_carrier`, `list_carriers`, `get_carrier`, `update_carrier`, `disable_carrier`, and per-carrier ship-method ops (`add_method`, `list_methods`, `update_method`) where a method captures `method_code` (e.g. `ground`/`express`/`overnight`/`economy`), display label, default rate inputs, and an `online_tracking: bool` flag tying back to the supported carriers in `app/services/carrier_tracking.py:10`.
- Seed a default carrier/method set idempotently (deterministic `carrier_id` derived from carrier code) covering UPS/FedEx/USPS/DHL + a `manual` carrier, so rate estimation and shipment creation have data to bind to out of the box.
- Emit audit events via `app/services/alerts.audit_event` (mirroring `commerce_order_service.py:106`) on every mutation.

**Acceptance Criteria**
- Default carriers/methods seed idempotently (re-seeding does not duplicate rows); each carrier carries its supported-tracking flag.
- Disabling a carrier hides it from rate estimation and shipment-method selection but leaves historical shipments intact.
- pytest covers seed idempotency, method CRUD, and the disable→hidden-from-estimation behavior.

**Dependencies**
- SHP-003.

---

### SHP-005: Carrier/ship-method admin router
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Create `app/routers/shipping_carriers.py` exposing admin CRUD (`require_admin_session`) for carriers + ship methods, plus a public/authenticated `GET` list of enabled methods for the storefront. Gate every handler on `S.shipping_enabled` (503/404 when off, mirroring the mock-enabled gate in `app/routers/carrier_tracking_mock.py:19`).
- Register the router in `app/main.py` alongside the existing carrier routers (`app/main.py:80` `carrier_tracking_poller_router`), preserving import + `include_router` ordering conventions.

**Acceptance Criteria**
- Admin can create/list/update/disable carriers and methods; non-admin is denied (403); flag-off returns the gated error.
- The enabled-methods list endpoint returns only active methods and is consumable by the storefront.
- Router is registered in `app/main.py` and appears in `GET /openapi.json` only behind the flag's runtime gate.

**Dependencies**
- SHP-004.

---

## Milestone 3 — Rate estimation

### SHP-006: Shipping-rate estimation engine
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Add `app/services/shipping_rates.py` computing rate quotes from a destination + a set of cart/order line items: per-method estimation using weight/dimensional-weight breakpoints and flat/zone modifiers defined on the ship method (SHP-004), returning one `ShippingRateOption` per enabled method (carrier, method_code, amount_cents, currency, estimated transit days).
- Make the engine pluggable: a deterministic built-in estimator in dev/test, with a clean seam for a real carrier-rate call (UPS rating) gated by config — but the **same** code path/shape both ways (SECOPS-007 parity), no `dev_mode` branch in the result shape. Reuse `S.ups_base_url` / `S.ups_client_id` settings (`app/core/settings.py:334`) for the live seam only.
- Derive total billable weight from line-item quantities and per-SKU shipping weight (read from the catalog item; default weight when unset) so a cart with N units estimates realistically.

**Acceptance Criteria**
- A given (destination, line-items) yields a deterministic, ordered set of options across all enabled methods in the built-in estimator.
- Dimensional vs actual weight is resolved per method and unit-tested at the breakpoints.
- Unknown/disabled methods are excluded; an empty enabled-method set yields an empty-but-valid quote (not an error).
- pytest covers weight aggregation, breakpoint selection, and the empty-method case.

**Dependencies**
- SHP-004.

---

### SHP-007: Rate-estimation router + cart/checkout estimate endpoint
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Create `app/routers/shipping_rates.py` with `POST /ui/shop/shipping/estimate` (`require_ui_session`) accepting a destination + cart/line-item reference and returning the `ShippingRateQuote` from SHP-006. Gate on `S.shipping_enabled` AND `S.shipping_rate_estimation_enabled`.
- Provide a cart-bound variant that resolves the caller's active cart line items (reusing the cart-read path used by `app/services/shoppingcart.py:474` `purchase_cart`) so the storefront can show live shipping options before checkout — **read-only**, no mutation of cart/order with the flag off.
- Register in `app/main.py`.

**Acceptance Criteria**
- The estimate endpoint returns ordered options for a valid destination + cart; flag-off returns the gated error and never touches cart state.
- CSRF + session auth enforced per the repo convention (cookie non-GET needs `x-csrf-token`).
- pytest invokes the handler directly (hermetic) and asserts the quote shape + flag gating.

**Dependencies**
- SHP-006.

---

## Milestone 4 — Shipments, ship groups & package contents

### SHP-008: Shipment & ship-group service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/shipments.py` creating a first-class Shipment from an order: `create_shipment(order_id, ship_group, method, items)` writing a `shipments` row (deterministic `shipment_id = sha256("shipment:{order_id}:{ship_group_seq}")[:32]` for idempotency, mirroring the order-id derivation at `app/services/commerce_order_service.py:67`), `shipment_items` rows linked to the originating order-line `item_id`s (from `order_items`, written at `commerce_order_service.py:88`), and a default single package.
- Support **ship groups**: multiple shipments per order, each with its own ship-to + method (OFBiz OrderItemShipGroup), validating that the summed shipped quantity per order line never exceeds the ordered quantity.
- Provide `get_shipment`, `list_shipments_for_order`, and `list_shipments_by_status` (via the GSIs from SHP-002). Audit every creation/transition via `audit_event`.

**Acceptance Criteria**
- Creating a shipment twice for the same `(order_id, ship_group)` is idempotent (same `shipment_id`, no duplicate rows).
- Ship-group quantities are validated against ordered quantities; over-ship is rejected.
- Shipment items correctly reference their source order-line `item_id`; `list_shipments_for_order` returns all groups.
- pytest covers single-group create, multi-group split, idempotent replay, and over-ship rejection.

**Dependencies**
- SHP-003, SHP-004.

---

### SHP-009: Package contents & packing
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Extend `app/services/shipments.py` with package management over `shipment_packages`: `add_package`, `assign_item_to_package` (ShipmentPackageContent), and per-package weight/dimension capture, validating that packed quantities per shipment item never exceed the shipment item's quantity.
- Compute and store a billed package weight per package (reusing the weight aggregation from SHP-006) so the rate at ship time can reconcile against the estimate.

**Acceptance Criteria**
- Items can be split across multiple packages; total packed qty per item equals the shipment-item qty before the shipment can advance to `packed`.
- Package weight/dimensions persist and are returned in `ShipmentPackageOut`.
- pytest covers multi-package packing, the over-pack guard, and the pack-complete invariant.

**Dependencies**
- SHP-008.

---

### SHP-010: Shipment lifecycle state machine
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add a shipment status machine to `app/services/shipments.py`: `created → packed → label_created → shipped → in_transit → out_for_delivery → delivered`, with side-states `exception`/`returned`/`cancelled`. Enforce legal transitions (illegal → 409) with version-guarded conditional updates (mirroring the optimistic-concurrency pattern in `app/services/purchase_history.py:420`).
- On the `shipped` transition, require/attach a tracking number + carrier, auto-detecting carrier via `app/services/carrier_tracking.py:46` `detect_carrier` when only a number is given, and compute the tracking URL via `:33` `build_tracking_url` (computed, never stored — same approach as `purchase_history.get_transaction_info` at `:389`).

**Acceptance Criteria**
- Only legal transitions succeed; illegal transitions return 409 and leave state unchanged.
- Advancing to `shipped` without a tracking number/carrier is rejected; auto-detection fills carrier from a recognizable number.
- Concurrent transitions are serialized by the version guard (single-writer wins).
- pytest covers the happy path, an illegal transition, auto-detect-on-ship, and the version race.

**Dependencies**
- SHP-008.

---

### SHP-011: Shipments + ship-groups router
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/routers/shipments.py`: admin endpoints (`require_admin_session`) to create shipments/ship-groups, manage packages, and drive lifecycle transitions; plus an authenticated read view for the buyer to see their order's shipments/tracking. Gate on `S.shipping_enabled`.
- Reuse the shipment→order linkage so a shipment can resolve its order/buyer; validate ownership on the buyer read path (foreign order → 404, mirroring `purchase_history` ownership enforcement).
- Register in `app/main.py`.

**Acceptance Criteria**
- Admin can create a shipment, pack it, and walk it through the lifecycle; buyer can read only their own order's shipments.
- Flag-off returns the gated error; CSRF + role gating enforced.
- pytest drives the router handlers directly (hermetic) for create → pack → ship → buyer-read.

**Dependencies**
- SHP-008, SHP-009, SHP-010.

---

## Milestone 5 — Tracking & order-fulfillment linkage

### SHP-012: Tracking-number/status on shipments (reuse carrier_tracking)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Wire shipment tracking through the **existing** carrier layer rather than a new one: store `tracking_number`/`carrier` on the shipment route segment and feed carrier status results into the shipment status machine via the normalization in `app/services/carrier_tracking.py:84` `map_carrier_status` and the apply helper at `:138` `apply_tracking_result` (refactored/parameterized so it can target a shipment record, not only a `purchase_transactions` item — keep the transaction path working unchanged).
- Add a `find_shipment_by_tracking(tracking_number)` lookup (GSI-backed; avoid the scan-loop fallback used at `app/services/purchase_history.py:595` by indexing `tracking_number`) so the existing webhook/poller can resolve a shipment.
- Reuse the active-status set `ACTIVE_TRACKING_STATUSES` (`carrier_tracking.py:129`) to decide which shipments are worth polling.

**Acceptance Criteria**
- A carrier status update advances the shipment via the shared `map_carrier_status` path; the transition to `delivered` fires the existing delivery alert exactly once (idempotent re-apply is a no-op, matching `apply_tracking_result`'s old==new short-circuit).
- `find_shipment_by_tracking` resolves via GSI (not a full scan).
- The pre-existing `purchase_transactions` tracking path is unchanged (regression test asserts both paths share the carrier helpers).
- pytest covers status-advance, idempotent re-apply, and delivered-alert-once.

**Dependencies**
- SHP-010.

---

### SHP-013: Carrier-tracking poller integration for shipments
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Extend the existing poller (`app/routers/carrier_tracking_poller.py`, `app/services/carrier_tracking_poller.py`, gated by `S.carrier_tracking_poll_enabled` at `app/core/settings.py:344`) to also poll active shipments (status in `ACTIVE_TRACKING_STATUSES`) and apply results through SHP-012 — reusing the same poll cadence/batch settings (`carrier_tracking_poll_interval_minutes` / `carrier_tracking_poll_batch_size`), not a new loop.
- Add a `POST /ui/shop/tracking/shipments/{shipment_id}/poll` admin endpoint mirroring the existing per-transaction poll at `app/routers/carrier_tracking_poller.py` so a shipment can be refreshed on demand.

**Acceptance Criteria**
- With `carrier_tracking_poll_enabled` on, active shipments are refreshed on the existing interval; with both shipping + poll flags off the poller behaves exactly as today.
- The per-shipment poll endpoint returns the refreshed shipment tracking view.
- pytest covers a poll that advances an active shipment and one that no-ops on a delivered/terminal shipment.

**Dependencies**
- SHP-012.

---

### SHP-014: Link shipments to order fulfillment + purchase-history tracking
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Bridge shipments back into the buyer-facing order/transaction view: when a shipment is created/shipped for an order, denormalize a shipment summary (carrier, method, tracking_number, status, tracking_url) onto the matching `purchase_transactions` record via the existing `app/services/purchase_history.py:398` `update_shipping` (so the existing `GET .../transactions/{txn_id}/tracking` endpoint at `app/routers/purchase_history.py:118` surfaces the shipment with no FE change), resolving the transaction by the order's `external_ref`/`order_id` linkage written at `purchase_history.py:270`.
- Reflect a fulfillment status on the order itself (`orders` table, `app/services/commerce_order_service.py`): advance an order-level `fulfillment_status` (`unfulfilled → partially_shipped → shipped → delivered`) as ship groups progress, **without** mutating the existing `status` field (preserve the `pending_payment` semantics; add `fulfillment_status` additively, flag-gated).
- Keep idempotency: re-shipping/re-linking a shipment does not double-write the transaction shipping sub-record (compare status before update, like `apply_tracking_result`).

**Acceptance Criteria**
- A shipped shipment shows up under the buyer's existing transaction tracking view with carrier/tracking_url populated; no frontend change required for that surface.
- Order `fulfillment_status` derives from its ship groups (partial when some groups shipped); the legacy `status` field is untouched with the flag off.
- Re-linking is idempotent (no duplicate alerts, no churn on the transaction record).
- pytest covers create→ship→link, partial-vs-full fulfillment derivation, and link idempotency.

**Dependencies**
- SHP-011, SHP-012.

---

### SHP-015: Refund of paid shipping via existing billing
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- When a shipment is cancelled/returned and shipping was charged, issue any shipping refund **only** through the existing money-out path — `refund_payment` / `settle_or_reverse_ledger` (`app/routers/billing.py`) with a `new_ledger_entry` reason like `shipping_refund` — never a parallel mechanism, preserving provider attribution (FIN-013) and the platform financial dashboard. The GL derives from this ledger entry; do not post shipping refunds directly to any GL.
- Make the refund idempotent per shipment (deterministic correlation/idempotency key) so a replayed cancel does not double-refund.

**Acceptance Criteria**
- A shipping refund produces exactly one reversed/refund ledger entry tied to the original payment + provider; no new refund code path is introduced.
- Double-cancel of the same shipment refunds at most once (idempotent).
- pytest covers single refund, idempotent replay, and the no-charge (nothing to refund) case.

**Dependencies**
- SHP-010, SHP-014.

---

## Milestone 6 — Frontend & tests

### SHP-016: Shipping TypeScript types & API endpoints
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add TS interfaces to `frontend/src/api/types.ts` mirroring the SHP-003 models (Carrier, ShipMethod, RateQuote/RateOption, Shipment, ShipGroup, ShipmentPackage, tracking views).
- Add endpoint wrappers under `frontend/src/api/endpoints/` (e.g. `shipping.ts`) for carriers/methods, rate estimate, shipments lifecycle, and shipment tracking — consistent with the existing `carrierTracking.ts`/`purchases.ts` endpoint style, using the shared axios client.

**Acceptance Criteria**
- Types compile and mirror the backend response shapes 1:1.
- Endpoint wrappers cover carrier admin, rate estimate, shipment CRUD/lifecycle, and tracking read.
- No runtime behavior changes when the shipping flag is off (endpoints simply unused).

**Dependencies**
- SHP-005, SHP-007, SHP-011.

---

### SHP-017: Shipping admin UI (carriers, rates, shipments)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Add admin pages under `frontend/src/pages/shop/admin/` (alongside `InventoryAdmin`, registered at `frontend/src/App.tsx:45`): a carrier/ship-method manager, a shipment queue (create from order, pack, advance lifecycle, enter tracking), and a rate-rule editor.
- Add routes to `frontend/src/App.tsx` (mirroring the `shop/admin/...` route pattern around `:360`) and a sidebar/nav entry, all gated on the shipping flag (hidden when off).

**Acceptance Criteria**
- Admin can manage carriers/methods, create + pack + ship a shipment, and enter a tracking number, seeing the computed tracking URL.
- Pages are admin/root-gated and flag-gated (hidden + backend-denied when off).
- Shipment status transitions reflect in the UI without a full reload.

**Dependencies**
- SHP-016.

---

### SHP-018: Buyer shipping/tracking UI integration
**Type:** Feature  
**Priority:** P2  
**Estimate:** 2 days

**Description**
- Surface shipments + rate options on the buyer side: show live shipping options at checkout (SHP-007 estimate) and per-order shipment tracking on the purchases view (`frontend/src/pages/purchases/PurchasesPage.tsx` / `TransactionDetail.tsx`), reusing the existing transaction tracking surface fed by SHP-014 so most of this is read-only display.
- Flag-gate the checkout shipping-options block so the existing checkout (`frontend/src/pages/shop/Checkout.tsx`) is unchanged with the flag off.

**Acceptance Criteria**
- Checkout shows shipping options for a valid destination when the flag is on; unchanged when off.
- The purchases/transaction detail view shows shipment status + tracking link sourced from the SHP-014 linkage.
- Buyer sees only their own shipments.

**Dependencies**
- SHP-014, SHP-016.

---

### SHP-019: Shipping/logistics tests (hermetic pytest + e2e)
**Type:** Chore  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add hermetic offline pytest suites (`tests/test_shp_*.py`) following the repo pattern (moto-bound frozen `T` via `object.__setattr__`, frozen `S` flags toggled, handlers/services called directly, no real AWS/network): carrier/method CRUD + seed idempotency, rate estimation math + breakpoints, shipment create/idempotency/ship-group split + over-ship, package packing invariants, lifecycle transitions + version race, tracking apply (reusing `carrier_tracking` helpers) + delivered-alert-once, order-fulfillment linkage + idempotency, and shipping-refund-via-billing idempotency.
- Add `frontend/e2e/shipping.spec.ts` covering: carrier/method admin, a rate estimate at checkout, create→pack→ship a shipment, tracking surfacing on the buyer transaction view, and flag-off invisibility — using seeded sessions + admin identity (`e2e_admin_session_setup.py`) and the CSRF/session patterns in CLAUDE.md/MEMORY.md.
- Include a regression test asserting that with `shipping_enabled` off, the existing carrier-tracking + purchase-history + checkout paths are byte-for-byte unchanged.

**Acceptance Criteria**
- pytest suites cover carrier CRUD, rate math, shipment idempotency/ship-groups/over-ship, packing, lifecycle/version race, tracking apply + delivered-once, fulfillment linkage, and refund idempotency — all offline.
- E2E covers the admin shipment lifecycle, checkout estimate, buyer tracking, and flag-off invisibility under the standard 1-worker Playwright config.
- A flag-off parity test confirms existing tracking/checkout behavior is unchanged.

**Dependencies**
- SHP-015, SHP-017, SHP-018.

---
