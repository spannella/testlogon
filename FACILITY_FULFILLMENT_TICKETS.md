# Facility / Fulfillment — Implementation Tickets

This backlog extends the existing OFBiz-inspired inventory foundation (`app/services/inventory.py` — first-class SKU on-hand/reserved/available records + soft reservations, on `T.inventory`/`T.reservations`) into the full OFBiz **Facility** application: warehouses/facilities + locations, stock **transfers** between locations, **receiving** (against purchase orders), and **pick / pack / ship** fulfillment with optional lot/serial tracking. Everything is additive, gated behind a default-off `FACILITY_FULFILLMENT_ENABLED` flag, single-table-modeled in DynamoDB, and reconciles money-out (write-offs / damaged stock) and refunds through the existing ledger — never forking billing. With the flag off, the existing inventory, shop, cart, orders, and billing paths are byte-for-byte unchanged.

## Milestone 1 — Facility scaffolding (model, tables, flags)

### FAC-001: Facility/fulfillment scoping spike & data-model delta
**Type:** Spike  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Map the OFBiz Facility application (facilities, facility locations, inventory-item-per-location, inventory transfers, shipment receipts against POs, picklists, packages, shipments) onto the existing foundation: the SKU-level inventory record keyed `sku`/`location_sk=LOC#{location_id}` with a single hard-coded `DEFAULT_LOCATION = "warehouse"` (`app/services/inventory.py:43`, `:118`, `:131`), the reservation lifecycle (`reserve`/`commit_reservation`/`release_reservation`, `app/services/inventory.py:339`, `:456`, `:492`), the existing `inventory`/`reservations`/`returns` tables (`scripts/local-ddb-init.py:2452`-`2492`), and the cart→order purchase path (`app/services/shoppingcart.py:474` `purchase_cart`, decrement at `:515`, order creation via `commerce_order_service.create_order_from_line_items` at `:581`).
- Document the gaps the foundation does NOT cover: no facility/warehouse entity (location is a bare string), no facility-location bins, no inter-location transfers, no receiving (PO inbound is owned by the Purchasing module — define the receipt contract this module consumes), and no pick/pack/ship fulfillment off an order.
- Define every new DynamoDB table (PK/SK/GSIs with `attr_types` for numeric keys), new `app/models.py` shapes, new `app/core/settings.py` keys, the `FACILITY_FULFILLMENT_ENABLED` flag, and the cross-module contracts: how a facility `location_id` maps onto the existing `inventory.location_sk` dimension (forward-compatible per `app/services/inventory.py:57` `_location_sk`), how receiving calls `inventory.adjust(...+qty)` (`app/services/inventory.py:209`), how shipping consumes order/reservation rows, and how the Purchasing module (`PUR`) hands off received POs.

**Acceptance Criteria**
- A written design doc (`docs/facility-fulfillment-plan.md`) enumerates each Facility sub-domain, the in/out decision (lot/serial = optional/stretch), and rationale.
- Data-model delta lists each new table with PK/SK/GSIs (numeric `attr_types` noted), new Pydantic shapes, and new settings/flag keys.
- Cross-module dependency graph records the contracts with Order-lifecycle (`ORD`) and Purchasing (`PUR`); every downstream FAC ticket references a doc section.
- Reviewer confirms the multi-location model is additive to the existing single-`warehouse` inventory rows (existing rows remain valid; `DEFAULT_LOCATION` stays the implicit default).

**Dependencies**
- None.

---

### FAC-002: Facility tables, settings & feature flag
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Land the table definitions from FAC-001 into `scripts/local-ddb-init.py` alongside the existing inventory/reservations block (`scripts/local-ddb-init.py:2452`-`2492`), each via the `_resolve_table_name(S.<name>, "<default>")` pattern with numeric GSI sort keys declared in `attr_types` (per the CLAUDE.md gotcha and the existing `attr_types={"available": "N"}` / `{"created_at": "N", "expires_at": "N"}` examples at `:2463`/`:2477`): `facilities` (PK=`facility_id`, SK=`META`|`LOC#{location_id}`; GSI by owner/status), `transfers` (PK=`transfer_id`, SK=`META`|`ITEM#{n}`; GSI by status + numeric `created_at`), `picklists` (PK=`picklist_id`, SK=`META`|`LINE#{n}`; GSI by `order_id` + by status), `shipments` (PK=`shipment_id`, SK=`META`|`PKG#{n}`; GSI by `order_id` + by status), and an optional `lot_serial` table (PK=`sku`, SK=`LOT#{lot_id}`|`SERIAL#{serial}`).
- Add settings keys + the `FACILITY_FULFILLMENT_ENABLED` flag to `app/core/settings.py` next to the existing inventory keys (`app/core/settings.py:839`-`847`: `inventory_reservations_enabled`, `inventory_table_name`, `reservations_table_name`, `returns_table_name`), all defaulting off/empty so nothing activates until its milestone ships.
- Wire table handles in `app/core/tables.py` next to the existing `T.inventory`/`T.reservations`/`T.returns` declarations (`app/core/tables.py:317`-`319`, init at `:569`-`571`): `T.facilities`, `T.transfers`, `T.picklists`, `T.shipments`, (optional) `T.lot_serial`.

**Acceptance Criteria**
- `just restart` recreates all new tables locally with no `ValidationException` (numeric keys correctly typed `N`).
- `FACILITY_FULFILLMENT_ENABLED` reads through the `S` singleton and defaults to disabled; new table-name settings default to the literal table names.
- A smoke pytest imports `app.core.tables.T` and asserts each new handle resolves.

**Dependencies**
- FAC-001.

---

### FAC-003: Facility/fulfillment Pydantic models
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add the request/response Pydantic shapes to `app/models.py` (mirroring the existing `InventoryRecordOut`/`ReservationOut` shapes referenced by `app/routers/inventory.py:36`,`:89`): `FacilityIn`/`FacilityOut`, `FacilityLocationIn`/`FacilityLocationOut`, `TransferIn`/`TransferOut` (with line items + qty), `ReceiveIn`/`ReceiptOut`, `PicklistOut`/`PickLineOut`, `PackageIn`, `ShipmentIn`/`ShipmentOut` (carrier, tracking, packages), and (optional) `LotSerialOut`.
- Coerce DynamoDB `Decimal` → `int` on numeric quantity/qty fields with a `@model_validator(mode="before")`, following the project pattern used elsewhere for DDB Decimal coercion.

**Acceptance Criteria**
- All new models import cleanly and round-trip representative dicts (DDB `Decimal` quantities coerce to `int`).
- Models are referenced as `response_model=` by the FAC-005/006/007/008 endpoints with no schema-generation errors.

**Dependencies**
- FAC-002.

---

## Milestone 2 — Facilities & locations

### FAC-004: Facility & location service (CRUD + location dimension)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/services/facilities.py` with a flag gate mirroring `app/services/inventory.py:50`-`56` (`_flag_on()` reading `S.facility_fulfillment_enabled`, `_require_enabled()` → 404 when off) so the module is dormant when disabled.
- Implement facility CRUD (`create_facility`, `get_facility`, `list_facilities`, `update_facility`, `archive_facility`) and per-facility location/bin CRUD (`create_location`, `list_locations`), keyed `facility_id`/`META` and `facility_id`/`LOC#{location_id}` on `T.facilities`.
- Map a facility `location_id` onto the existing inventory location dimension: `inventory._location_sk(location_id)` (`app/services/inventory.py:57`) already keys stock per location, so a facility location is the addressable unit `inventory.set_on_hand(...)`/`adjust(...)` write against (`app/services/inventory.py:176`,`:209`). Keep `DEFAULT_LOCATION = "warehouse"` (`app/services/inventory.py:43`) as the implicit default so existing single-location rows belong to an auto-seeded default facility.
- Emit `alerts.audit_event` on every mutation via a best-effort `_audit()` wrapper (copy the pattern at `app/services/inventory.py:92`-`98`). Use deterministic ids (`facility_id = sha256(owner_sub|name)`-style) for idempotent create.

**Acceptance Criteria**
- Creating/listing/updating/archiving facilities and locations works; each mutation writes an audit event.
- A facility location resolves to an `inventory.location_sk`; setting on-hand at that location reads back via `inventory.get_inventory(sku, location_id)` (`app/services/inventory.py:150`).
- A default `warehouse` facility is auto-provisioned so pre-existing inventory rows are attributable.
- With the flag off, every service entrypoint raises 404 (`_require_enabled`).
- pytest covers facility/location CRUD, idempotent create, and the default-facility back-compat.

**Dependencies**
- FAC-003.

---

### FAC-005: Facility router (registered in main.py)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Create `app/routers/facilities.py` with `facilities_router = APIRouter(prefix="/ui/facilities", tags=["facilities"])`, mirroring the existing inventory router (`app/routers/inventory.py:29`). Read endpoints use `require_ui_session`; mutating endpoints (create/update/archive facility + location) use `require_admin_or_root_csrf` (the same split as `app/routers/inventory.py:9`-`11`,`:46`,`:63`).
- Each handler calls `facilities._require_enabled()` first so mounting the router is a no-op with the flag off (matches `app/routers/inventory.py:32` and the foundation's `_require_enabled` 404 contract).
- Register `facilities_router` in `app/main.py` next to the existing `inventory_router` import/include (`app/main.py:311` import, and the `app.include_router(...)` block near `:549`).

**Acceptance Criteria**
- `GET /ui/facilities`, `POST/PUT/DELETE /ui/facilities`, and `/ui/facilities/{id}/locations` behave per role gating; non-admin mutations → 403.
- All endpoints 404 with `FACILITY_FULFILLMENT_ENABLED` off.
- Router is registered in `app/main.py` and appears in `GET /openapi.json`.

**Dependencies**
- FAC-004.

---

## Milestone 3 — Transfers & receiving

### FAC-006: Stock transfers between locations
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/transfers.py` implementing a transfer lifecycle (`requested`→`in_transit`→`completed`/`cancelled`) that moves stock between two facility locations on `T.transfers` (header `META` + per-SKU `ITEM#{n}` rows).
- On `complete_transfer`, atomically `inventory.adjust(sku, -qty, reason="transfer_out", location_id=from_loc)` then `inventory.adjust(sku, +qty, reason="transfer_in", location_id=to_loc)` (`app/services/inventory.py:209`), reusing the existing conditional single-writer guard (so a transfer can't drop `available` below reserved — `app/services/inventory.py:256`) and the create-on-adjust path for a SKU that doesn't yet exist at the destination (`app/services/inventory.py:225`-`251`).
- Make `complete_transfer` idempotent: flip the transfer header `status` with a `status = in_transit` conditional guard (copy the terminal-status guard pattern in `app/services/inventory.py:434`-`453` `_close_reservation`) so replays after completion are no-ops and the dual adjust runs exactly once.
- Emit `alerts.audit_event` per transition.

**Acceptance Criteria**
- A completed transfer decrements the source location and increments the destination by the same qty; net on-hand across locations is unchanged.
- An in-transit transfer can be cancelled (no stock moved); a completed transfer cannot be re-completed (idempotent — exactly one adjust pair).
- A transfer that would overdraw the source location's available stock is rejected (409 from `inventory.adjust`).
- pytest covers requested→in_transit→completed, cancel, the overdraw 409, and completion-replay idempotency.

**Dependencies**
- FAC-004.

---

### FAC-007: Receiving (inbound goods → on-hand)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/receiving.py` implementing inbound receipts that land goods into a facility location: `receive_shipment(facility_id, location_id, lines, *, po_id=None, correlation_id)` writes a receipt row and, per line, `inventory.adjust(sku, +qty, reason="receipt", location_id=...)` (`app/services/inventory.py:209`) — using the create-on-adjust branch (`app/services/inventory.py:225`) for first-time SKUs at that location.
- Support receiving **against a purchase order**: accept an optional `po_id` and reconcile received-vs-ordered quantities, exposing partial/over/short-receipt status. The PO entity itself is owned by the Purchasing module (`PUR`) — this ticket defines and consumes the receipt contract (a `received_qty` callback the PUR module can read) but does not create POs.
- Deterministic-id idempotency: `receipt_id = sha256(correlation_id)` (reuse the `commerce_order_service` pattern at `app/services/commerce_order_service.py:67`) so a re-submitted receipt does NOT double-increment on-hand. Emit `alerts.audit_event` per receipt.

**Acceptance Criteria**
- Receiving N units of a SKU increments on-hand at the target location by exactly N (verified via `inventory.get_inventory`).
- Re-submitting the same `correlation_id` is a no-op (idempotent — on-hand unchanged on replay).
- A PO-linked receipt records received-vs-ordered and surfaces short/over/complete status; a standalone (no-PO) receipt also works.
- With the inventory flag off, receiving still records the receipt header but skips the on-hand adjust (mirrors the RMA-restock guard in OFB-009).
- pytest covers receipt→on-hand increment, replay idempotency, partial PO receipt, and the inventory-disabled skip.

**Dependencies**
- FAC-004, FAC-006.

---

## Milestone 4 — Pick / pack / ship

### FAC-008: Picklist generation & pick confirmation
**Type:** Feature  
**Priority:** P0  
**Estimate:** 5 days

**Description**
- Create `app/services/picking.py` that generates a picklist for an order ready to fulfill: read the order + its line items (`commerce_order_service` order rows, `order_id`/`item_id`/`sku`/`qty` at `app/services/commerce_order_service.py:90`-`92`), allocate each line against an existing reservation where present (`inventory.reserve`/`commit_reservation`, `app/services/inventory.py:339`,`:456`), and write a picklist (`META` + `LINE#{n}` rows) on `T.picklists` with a `from` facility location per line.
- `confirm_pick(picklist_id, line, picked_qty)` marks a line picked; when all lines are picked the picklist flips to `picked`. Use the `status` conditional-guard idempotency pattern (`app/services/inventory.py:434`-`453`) so confirming a line twice is a no-op.
- On full-pick confirmation, `commit_reservation(...)` the reserved units (decrements on-hand, `app/services/inventory.py:456`) — or, when no reservation exists (flag-off inventory or direct sale), `inventory.adjust(sku, -qty, reason="pick")`. Emit `alerts.audit_event` per transition.

**Acceptance Criteria**
- Generating a picklist for an order produces one line per order line with the correct SKU/qty and source location.
- Confirming all picks commits the reservation(s) and decrements on-hand exactly once (idempotent on replay).
- An order with insufficient available stock surfaces a backorder/short-pick state rather than silently overdrawing.
- pytest covers generate→confirm→commit, partial pick, the commit-replay idempotency, and the no-reservation adjust fallback.

**Dependencies**
- FAC-006, FAC-007.

---

### FAC-009: Pack into packages
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add `pack_picklist(picklist_id, packages)` to `app/services/picking.py` (or a sibling `packing.py`): group picked lines into one or more packages (weight/dimensions/contents), creating a draft shipment header on `T.shipments` with `PKG#{n}` rows, and flip the picklist to `packed`.
- Validate that packed quantities reconcile to picked quantities (can't pack more than picked); use the conditional `status = picked` guard for the picklist transition (idempotent).
- Emit `alerts.audit_event` on pack.

**Acceptance Criteria**
- Packing picked lines creates package rows whose contents sum to the picked quantities; over-pack is rejected (409).
- The picklist transitions `picked`→`packed` exactly once (idempotent); a draft shipment header exists with the packages.
- pytest covers pack happy-path, over-pack rejection, and packed-state idempotency.

**Dependencies**
- FAC-008.

---

### FAC-010: Ship shipment (carrier, tracking, order linkage)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/shipping_fulfillment.py` (or extend `packing.py`) with `ship_shipment(shipment_id, *, carrier, tracking_number)` that finalizes the draft shipment to `shipped`, stamps carrier + tracking, and links it to its order. Reuse the existing order-tracking surface noted in the plan (the order tracking endpoint already exists; this writes the tracking the customer reads).
- Drive the order-lifecycle hand-off: emit a fulfillment event the Order-lifecycle module (`ORD`) consumes to advance the order to `shipped`/`completed` (define the event contract; do NOT re-implement the order state machine here).
- Idempotent ship via a `status = packed` conditional guard; emit `alerts.audit_event`. Backorder/cancel path: cancelling a packed-but-unshipped shipment releases any still-active reservations via `inventory.release_reservation` (`app/services/inventory.py:492`).

**Acceptance Criteria**
- Shipping stamps carrier + tracking, sets status `shipped`, and emits the order-lifecycle fulfillment event exactly once (idempotent on replay).
- Cancelling a packed shipment releases reservations and restores available stock.
- Tracking number is readable via the order/shipment read endpoints.
- pytest covers pack→ship→event, ship-replay idempotency, and cancel→release.

**Dependencies**
- FAC-009.

---

### FAC-011: Fulfillment router (registered in main.py)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Create `app/routers/fulfillment.py` exposing transfer, receive, picklist, pack, and ship endpoints under `/ui/fulfillment` (and transfers under `/ui/facilities/transfers` or `/ui/fulfillment/transfers`), mirroring the inventory router's structure and role gating (`app/routers/inventory.py:29`,`:46`,`:89`): warehouse-operator actions (transfer/receive/pick/pack/ship) use `require_admin_or_root_csrf`; read endpoints use `require_ui_session`.
- Every handler calls the relevant service `_require_enabled()` so mounting is a no-op with the flag off.
- Register the router in `app/main.py` next to `inventory_router`/`facilities_router` (`app/main.py:311`, include near `:549`).

**Acceptance Criteria**
- All transfer/receive/pick/pack/ship endpoints are reachable, correctly role-gated, and 404 with the flag off.
- Router registered in `app/main.py` and present in `GET /openapi.json`.
- A short pytest exercises one endpoint per lifecycle stage through the router (auth stubbed).

**Dependencies**
- FAC-005, FAC-006, FAC-007, FAC-008, FAC-009, FAC-010.

---

## Milestone 5 — Frontend & lot/serial (optional)

### FAC-012: Frontend types & endpoint wrappers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add TypeScript interfaces to `frontend/src/api/types.ts` mirroring the FAC-003 Pydantic shapes (Facility, FacilityLocation, Transfer, Receipt, Picklist, Shipment, Package), alongside the existing inventory types.
- Add endpoint wrappers under `frontend/src/api/endpoints/` (e.g. `facilities.ts`, `fulfillment.ts`) using the shared axios instance (`frontend/src/api/client.ts`) with CSRF handling, matching the existing inventory endpoint wrappers added by OFB-006.

**Acceptance Criteria**
- Types compile and match the backend response models (no `any` for the new shapes).
- Endpoint wrappers cover facility CRUD, transfers, receiving, picklist/pack/ship, and read paths.

**Dependencies**
- FAC-005, FAC-011.

---

### FAC-013: Warehouse / fulfillment admin page + route + nav
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Add a warehouse/fulfillment management page under `frontend/src/pages/shop/admin/` (alongside the inventory admin page from OFB-006): facility/location management, a transfers panel, a receiving form, and a pick/pack/ship fulfillment queue for orders ready to fulfill, using React Query (`useQuery`/`useMutation`) + shadcn/ui primitives per the project conventions.
- Add the route to `frontend/src/App.tsx` (lazy-loaded) and a sidebar/nav entry (`frontend/src/components/layout/`), gated on the `FACILITY_FULFILLMENT_ENABLED` flag and admin/root role.

**Acceptance Criteria**
- Admin can create a facility/location, initiate a transfer, receive stock, and progress an order through pick→pack→ship without reload (React Query invalidation).
- The page and nav entry are flag-gated and role-gated; non-admin users cannot reach it.
- Tracking number entered at ship is visible on the shipment view.

**Dependencies**
- FAC-012.

---

### FAC-014: Lot / serial tracking (optional)
**Type:** Feature  
**Priority:** P2  
**Estimate:** 4 days

**Description**
- Add optional lot/serial tracking on `T.lot_serial` (FAC-002): receiving (FAC-007) can stamp a lot id and per-unit serials; picking (FAC-008) and shipping (FAC-010) record which lot/serial fulfilled each line, so a shipment is traceable to its inbound receipt.
- Gate this behind a sub-flag (`FACILITY_LOT_SERIAL_ENABLED`, default off) so the base fulfillment flow is unaffected when disabled; thread lot/serial through receive→pick→ship only when on.

**Acceptance Criteria**
- With lot/serial off, receive/pick/ship behave exactly as in FAC-007/008/010 (no schema or behavior change).
- With it on, a received lot/serial is recorded, carried through pick + pack, and stamped on the shipment; a shipment is traceable back to its receipt.
- pytest covers the on/off branches and the receipt→shipment traceability lookup.

**Dependencies**
- FAC-007, FAC-010.

---

## Milestone 6 — Tests

### FAC-015: Hermetic pytest + E2E test suite
**Type:** Chore  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add hermetic offline pytest suites (`tests/test_fac_facilities.py`, `tests/test_fac_transfers.py`, `tests/test_fac_receiving.py`, `tests/test_fac_pick_pack_ship.py`) using moto-bound frozen `T` handles patched via `object.__setattr__` and frozen `S` flags flipped the same way (the established project pattern from `tests/test_gap_0223_0224_ec2_host_inventory.py` and the inventory foundation tests), with no real AWS/network. Cover: facility/location CRUD + default-facility back-compat; transfer dual-adjust + overdraw 409 + completion idempotency; receiving on-hand increment + replay idempotency + PO partial + inventory-disabled skip; pick→pack→ship lifecycle + commit/ship idempotency + cancel→release.
- Add `frontend/e2e/facility-fulfillment.spec.ts` covering: create facility/location, a stock transfer, receiving stock into a location, and an order driven through pick→pack→ship with a tracking number — following the seeded-session + CSRF + admin-identity patterns in CLAUDE.md / MEMORY.md (`e2e_admin_session_setup.py`).
- Assert flag-off parity: with `FACILITY_FULFILLMENT_ENABLED` off, every FAC endpoint 404s and the existing inventory/shop/cart/order flows are unchanged.

**Acceptance Criteria**
- pytest suites cover each lifecycle (facilities, transfers, receiving, pick/pack/ship) including idempotency and the inventory-disabled skip, and pass offline (no AWS) under the standard runner.
- E2E spec covers facility/location create, transfer, receive, and a full pick→pack→ship with tracking, and passes under the 1-worker Playwright config.
- A flag-off test confirms all FAC endpoints 404 and existing commerce paths are byte-for-byte unchanged.

**Dependencies**
- FAC-011, FAC-013, FAC-014.

---
