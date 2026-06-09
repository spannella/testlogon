# Manufacturing / MRP — Implementation Tickets

This backlog layers OFBiz Manufacturing/MRP onto the existing inventory foundation: Bills of Materials (BOM), routing/work centers, work orders (production runs that **issue component inventory → produce finished-goods inventory**), and a lite MRP that derives net requirements from demand vs. supply and suggests production/purchase. It is additive, **flag-gated** (`MANUFACTURING_MRP_ENABLED`, default OFF), and reuses `app/services/inventory.py` reservation/adjust primitives end-to-end so component issue and finished-goods receipt go through the **one** stock mechanism — no parallel inventory math, no fork of billing/cart/orders. Limited natural fit for a creator platform, but explicitly in scope per the full-OFBiz buildout plan (`docs/ofbiz-full-buildout-plan.md` row K).

## Milestone 1 — Scaffolding & Data Model

### MFG-001: Manufacturing/MRP scoping spike & inventory-integration delta
**Type:** Spike  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Map OFBiz Manufacturing entities (ProductBom / BOM components, RoutingTask / WorkEffort routing, WorkEffort production runs, InventoryItemDetail issue/produce, MrpEvent/requirements) onto the testlogon inventory foundation: SKU-keyed records in `app/services/inventory.py` (`get_inventory`/`adjust`/`reserve`/`commit_reservation`/`release_reservation`), the `inventory` table (PK=`sku`, SK=`LOC#{location_id}`, GSI_AVAILABLE on numeric `available` — `scripts/local-ddb-init.py:2456`), and the `reservations` table (`scripts/local-ddb-init.py:2469`).
- Confirm the integration contract: a production run **issues** components via `inventory.adjust(component_sku, -qty, reason="mfg_issue")` (or reserve→commit for the soft-reservation path) and **produces** finished goods via `inventory.adjust(fg_sku, +qty, reason="mfg_produce")` (`app/services/inventory.py:209` `adjust`, `:339` `reserve`, `:456` `commit_reservation`). No new stock ledger — finished/component quantities live in the existing `inventory` records.
- Decide the new DynamoDB tables (BOMs, work centers/routing, work orders/production runs, MRP runs/requirements), settings keys, and the default-off feature flag. Document the lite-MRP algorithm: net requirement = gross demand (sales orders / explicit forecast) − on-hand `available` − scheduled-receipt supply, exploded through the BOM, producing make/buy suggestions.
- Explicitly defer: multi-level nested BOM phantom assemblies beyond depth N (confirm N), finite-capacity scheduling, backflush variance accounting beyond a simple GL hook, and co-product/by-product yields.

**Acceptance Criteria**
- A short design note (in this file's header or `docs/ofbiz-manufacturing-plan.md`) lists each new table with PK/SK/GSIs (`attr_types` noted for numeric keys), new `app/models.py` shapes, new `app/core/settings.py` keys, and the lite-MRP net-requirement formula.
- The component-issue / finished-goods-produce contract is pinned to specific `app/services/inventory.py` functions with line citations; reviewer confirms no new stock store is introduced.
- A money-out / GL note records that any costed production posting reuses the existing single-entry ledger (`billing_shared.new_ledger_entry`) and never forks billing.

**Dependencies**
- None.

---

### MFG-002: Manufacturing tables, settings & feature flag
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add the four manufacturing tables to `scripts/local-ddb-init.py` next to the existing inventory/reservations/returns `TableDef`s (`scripts/local-ddb-init.py:2452-2492`), each via the `_resolve_table_name(S.<name>, "<default>")` pattern and with numeric GSI sort keys declared in `attr_types` (per the CLAUDE.md numeric-GSI gotcha):
  - `mfg_boms`: PK=`bom_id`, SK=`META` (header) / `COMP#{seq}` (components). GSI_PRODUCT (partition `product_sku`, numeric sort `created_at`) to find the active BOM for a finished-goods SKU.
  - `mfg_work_centers`: PK=`work_center_id`, SK=`META`. GSI_STATUS (partition `status`, numeric sort `created_at`).
  - `mfg_work_orders`: PK=`work_order_id`, SK=`META` (header) / `ISSUE#{n}` / `EVENT#{ts}`. GSI_STATUS (partition `status`, numeric sort `created_at`) for the production queue; GSI_PRODUCT (partition `product_sku`, numeric sort `created_at`).
  - `mfg_mrp`: PK=`mrp_run_id`, SK=`META` (run header) / `REQ#{sku}#{seq}` (requirement rows). GSI_RUN_STATUS (partition `status`, numeric sort `created_at`).
- Add settings + the master flag to `app/core/settings.py` after the inventory block (`app/core/settings.py:836-842`): `manufacturing_mrp_enabled` (env `MANUFACTURING_MRP_ENABLED`, default `false`), plus `mfg_boms_table_name`, `mfg_work_centers_table_name`, `mfg_work_orders_table_name`, `mfg_mrp_table_name`, and `mfg_mrp_default_horizon_days` (default 30).
- Wire table handles in `app/core/tables.py` (`T.mfg_boms`, `T.mfg_work_centers`, `T.mfg_work_orders`, `T.mfg_mrp`).

**Acceptance Criteria**
- `just restart` recreates all four tables locally with no `ValidationException` (numeric sort keys honored).
- `manufacturing_mrp_enabled` reads through the `S` singleton and defaults to `False`; with it off, the inventory/cart/orders/billing tables and behavior are byte-for-byte unchanged.
- A smoke pytest imports `app.core.tables.T` and asserts the four new handles resolve.

**Dependencies**
- MFG-001.

---

### MFG-003: Pydantic models for BOM, routing, work orders & MRP
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add request/response models to `app/models.py` (alongside the existing inventory/catalog shapes referenced in `OFBIZ_COMMERCE_TICKETS.md`):
  - `BomComponentIn`/`BomComponentOut` (`component_sku`, `quantity_per`, `scrap_pct`, `seq`), `BomHeaderIn`/`BomOut` (`bom_id`, `product_sku`, `name`, `output_quantity`, `status`, `components: list`).
  - `WorkCenterIn`/`WorkCenterOut` (`work_center_id`, `name`, `capacity_per_hour`, `cost_per_hour_cents`, `status`).
  - `WorkOrderCreateIn` (`product_sku`, `quantity`, `bom_id?`, `work_center_id?`, `correlation_id?`), `WorkOrderOut` (`work_order_id`, `status`, issued-components list, produced qty), `WorkOrderIssueOut`.
  - `MrpRunIn` (`horizon_days?`, `location_id?`) and `MrpRequirementOut` (`sku`, `gross_requirement`, `on_hand_available`, `scheduled_receipts`, `net_requirement`, `suggested_action` ∈ {`produce`,`purchase`,`none`}, `suggested_quantity`).
- Use integer cents for money and integer quantities throughout, matching the inventory record shapes in `app/services/inventory.py:101` `_record_out`.

**Acceptance Criteria**
- All models import cleanly and round-trip through FastAPI serialization; `quantity_per`/`output_quantity` reject ≤ 0 via validators.
- `suggested_action` is a constrained literal; `MrpRequirementOut.net_requirement` is allowed to be negative (surplus) but `suggested_quantity` is ≥ 0.
- pytest covers model validation (negative qty rejected, status enum bounds).

**Dependencies**
- MFG-002.

---

## Milestone 2 — Bill of Materials & Routing

### MFG-004: BOM service (CRUD + explosion)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/manufacturing_bom.py`: CRUD for BOM headers + components on `T.mfg_boms` (header `SK=META`, components `SK=COMP#{seq}`), with `_require_enabled()` 404-gating mirroring `inventory._require_enabled` (`app/services/inventory.py:54`).
- `get_active_bom(product_sku)` resolves the latest active BOM for a finished-goods SKU via GSI_PRODUCT. `explode_bom(bom_id, build_qty)` returns the flattened component requirement list (`component_sku`, `required_qty = ceil(quantity_per × build_qty × (1 + scrap_pct))`), supporting nested sub-BOMs up to the depth decided in MFG-001 (a component SKU that itself has an active BOM recurses), with cycle detection.
- Validate that `product_sku` and every `component_sku` reference real catalog/inventory SKUs (read-through to `inventory.get_or_zero` — `app/services/inventory.py:158`); emit `alerts.audit_event` on create/update/delete via a best-effort `_audit` wrapper like `inventory._audit` (`app/services/inventory.py:92`).

**Acceptance Criteria**
- Creating a BOM with components persists header + component rows; `get_active_bom` returns it by `product_sku`.
- `explode_bom` computes required quantities with scrap and recurses through sub-BOMs; a cyclic BOM raises a 409 rather than recursing infinitely.
- Deleting/deactivating a BOM referenced by an open work order is blocked (409).
- pytest covers single-level explosion, nested explosion with scrap, and cycle detection.

**Dependencies**
- MFG-003.

---

### MFG-005: Work-center / routing service
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Create `app/services/manufacturing_routing.py`: CRUD for work centers on `T.mfg_work_centers` and an ordered routing-task list (per-BOM or per-work-order) describing the sequence of operations, each referencing a `work_center_id`, `setup_minutes`, `run_minutes_per_unit`, and derived labor cost (`cost_per_hour_cents`).
- `estimate_routing_cost(bom_id_or_tasks, build_qty)` computes total labor minutes and cost in cents for a build quantity — used by MFG-007's optional costed production posting and the MRP lead-time estimate.
- Flag-gated (`_require_enabled`) and audited like the BOM service.

**Acceptance Criteria**
- Work centers CRUD; routing tasks are returned in declared order.
- `estimate_routing_cost` returns deterministic labor minutes + cents for a given build qty; covered by pytest with a two-operation routing.
- Disabling a work center referenced by an open routing is blocked (409).

**Dependencies**
- MFG-003.

---

### MFG-006: BOM & routing admin UI
**Type:** Feature  
**Priority:** P2  
**Estimate:** 3 days

**Description**
- Add a manufacturing admin page under `frontend/src/pages/shop/admin/` (alongside the inventory admin from `OFBIZ_COMMERCE_TICKETS.md` OFB-006): BOM list/editor (header + component grid with qty-per/scrap) and work-center/routing management, with a live "explode" preview for a sample build quantity.
- Add TS types to `frontend/src/api/types.ts`, endpoint wrappers under `frontend/src/api/endpoints/` (`manufacturing.ts`), a route in `frontend/src/App.tsx`, and a nav entry — all gated on the manufacturing flag and `require_admin_session` on the backend.

**Acceptance Criteria**
- Admin can create/edit a BOM and its components and see the exploded component requirements for a sample build qty without reload.
- Work centers and routing tasks are editable; the page is admin/root-gated and flag-gated (hidden/404 when the flag is off).

**Dependencies**
- MFG-004, MFG-005, MFG-011 (router).

---

## Milestone 3 — Work Orders / Production Runs

### MFG-007: Work-order lifecycle service (issue → produce)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 5 days

**Description**
- Create `app/services/manufacturing_work_orders.py` with a production-run state machine: `created → released → in_progress → completed` (+ `cancelled`), persisted on `T.mfg_work_orders` (header `SK=META`, issue rows `SK=ISSUE#{n}`, transition events `SK=EVENT#{ts}`).
- **Issue components**: on release/start, explode the BOM (MFG-004) for the order quantity and issue each component from inventory — reuse `inventory.adjust(component_sku, -required_qty, reason="mfg_issue", user_sub=...)` (`app/services/inventory.py:209`); the negative-adjust guard already prevents driving `available` below reserved (`:256` 409). Record each issue as an `ISSUE#` row for traceability.
- **Produce finished goods**: on completion, receive the produced quantity into inventory via `inventory.adjust(product_sku, +produced_qty, reason="mfg_produce")` (`app/services/inventory.py:209`) — the same primitive that backs RMA restock (OFB-009), so finished goods land in the existing `inventory` record and surface in the catalog stock mirror.
- **Idempotency**: derive `work_order_id = sha256(correlation_id)` (the deterministic-id pattern from the plan / `commerce_order_service.create_order_from_line_items` at `app/services/commerce_order_service.py:132`); issue/produce steps flip a per-step guard flag so a replayed completion never double-issues or double-produces.
- Illegal transitions → 409; every transition emits `alerts.audit_event`.

**Acceptance Criteria**
- Releasing a work order issues exactly the exploded component quantities (one `inventory.adjust` per component) and records `ISSUE#` rows; insufficient component stock blocks release with the existing 409 path.
- Completing a work order produces `+produced_qty` of the finished SKU into inventory exactly once; replaying completion is a no-op (deterministic-id + step guard).
- Cancelling a released order optionally un-issues components (configurable) and never produces finished goods.
- pytest covers release→issue, complete→produce, replay idempotency, insufficient-stock block, and illegal-transition 409 — all against moto-bound inventory.

**Dependencies**
- MFG-004, MFG-002.

---

### MFG-008: Optional costed-production GL hook
**Type:** Feature  
**Priority:** P2  
**Estimate:** 2 days

**Description**
- On work-order completion, optionally post a **costed** production entry deriving component cost + routing labor cost (MFG-005 `estimate_routing_cost`) into the existing single-entry ledger via `billing_shared.new_ledger_entry` (`app/services/billing_shared.py:224`) — e.g. a WIP→finished-goods value move — so the Phase-7 double-entry GL (OFB-014) can pick it up from the `GSI_LEDGER_DATE` day buckets like any other ledger row. **Never** mint a parallel posting path; any money-out reuses the existing refund/settle machinery (none is expected here — production is an internal value transfer).
- Gated behind a sub-flag `manufacturing_cost_posting_enabled` (default off) so the inventory-only path (MFG-007) works with no accounting coupling.

**Acceptance Criteria**
- With the sub-flag on, completing a work order writes exactly one ledger entry carrying `ledger_date` (so it appears in `GSI_LEDGER_DATE`) and a `reason`/`type` mapping cleanly to a manufacturing/WIP account in OFB-013's chart.
- With the sub-flag off, no ledger entry is written and MFG-007 behavior is unchanged.
- pytest asserts the ledger row shape and idempotency (one entry per completed work order).

**Dependencies**
- MFG-007, MFG-005.

---

### MFG-009: Work-order admin UI (production queue)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add a production-queue page under `frontend/src/pages/shop/admin/`: list work orders by status (GSI_STATUS), create a work order (pick finished-goods SKU + qty, auto-resolve active BOM), and drive release/start/complete/cancel actions with a component-availability preview (reads `inventory.get_inventory` per exploded component).
- TS types + endpoint wrappers in `frontend/src/api/endpoints/manufacturing.ts`, route + nav in `App.tsx`, flag- and role-gated.

**Acceptance Criteria**
- Admin can create a work order, see exploded component availability, and complete it; finished-goods on-hand increases in the inventory page without reload.
- A release blocked by insufficient component stock surfaces the 409 reason inline.
- Page is admin/root-gated and flag-gated.

**Dependencies**
- MFG-007, MFG-011 (router).

---

## Milestone 4 — Lite MRP

### MFG-010: Lite MRP engine (requirements explosion → suggestions)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 5 days

**Description**
- Create `app/services/manufacturing_mrp.py` implementing the lite-MRP run decided in MFG-001: gather **gross demand** (open sales-order line quantities from `orders`/`order_items` via `commerce_order_service` + any explicit forecast rows), subtract **supply** (`inventory.get_inventory().available` — `app/services/inventory.py:150` — plus scheduled receipts: open purchase orders from the Purchasing module if present, and open work-order produced quantities), explode finished-goods net requirements through `manufacturing_bom.explode_bom` (MFG-004) to component net requirements, and emit per-SKU suggestions: `produce` (has an active BOM) or `purchase` (no BOM / raw component) with a `suggested_quantity`.
- Persist each run + its requirement rows on `T.mfg_mrp` (`SK=META` + `REQ#{sku}#{seq}`), keyed by `mrp_run_id = sha256(correlation_id)` for idempotent re-runs; expose `run_mrp(horizon_days, location_id)` and `get_mrp_run(run_id)`.
- Flag-gated + audited; read-only against demand/supply (an MRP run never mutates inventory — it only suggests).

**Acceptance Criteria**
- A run over a fixture (demand > supply for a BOM'd finished good) yields a `produce` suggestion for the finished good and `purchase` suggestions for its short components, with quantities = net requirement.
- Net requirement = gross demand − available − scheduled receipts; surplus (negative net) yields `suggested_action="none"`, `suggested_quantity=0`.
- Re-running with the same `correlation_id` overwrites/returns the same run (idempotent); the run never changes any `inventory` record.
- pytest covers the requirement math, BOM explosion into component suggestions, the surplus case, and idempotent re-run — moto-bound.

**Dependencies**
- MFG-004, MFG-007.

---

### MFG-011: Manufacturing router (BOM / routing / work orders / MRP)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/routers/manufacturing.py` exposing the service layer under `/ui/manufacturing/*`, registered in `app/main.py` next to `inventory_router`/`returns_rma_router` (`app/main.py:311-312` imports; `include_router` block at `:549+`):
  - BOM: `POST/GET/PATCH/DELETE /ui/manufacturing/boms`, `GET /ui/manufacturing/boms/{id}/explode`.
  - Work centers/routing: `POST/GET/PATCH /ui/manufacturing/work-centers`, routing CRUD.
  - Work orders: `POST/GET /ui/manufacturing/work-orders`, `POST /ui/manufacturing/work-orders/{id}/release|start|complete|cancel`.
  - MRP: `POST /ui/manufacturing/mrp/run`, `GET /ui/manufacturing/mrp/runs/{id}`.
- Static/literal sub-paths (e.g. `/work-orders/{id}/release`) declared so FastAPI doesn't capture literals as path params (the `/schedules`-before-`/{id}` gotcha from CLAUDE.md). All write endpoints `require_admin_session`; the module is fully 404 when the flag is off (service-level `_require_enabled`).

**Acceptance Criteria**
- Router registered in `app/main.py`; all endpoints 404 when `manufacturing_mrp_enabled` is off and function when on.
- Write endpoints reject non-admin sessions (403); GET endpoints honor `require_admin_session` per OFBiz admin scope.
- `GET /openapi.json` lists the new paths; literal action sub-paths resolve correctly (not captured as `{id}`).

**Dependencies**
- MFG-004, MFG-005, MFG-007, MFG-010.

---

### MFG-012: MRP suggestions admin UI
**Type:** Feature  
**Priority:** P2  
**Estimate:** 3 days

**Description**
- Add an MRP page under `frontend/src/pages/shop/admin/`: trigger a run (horizon picker), view requirement rows grouped by `produce`/`purchase`, and one-click hand-offs — a `produce` suggestion pre-fills a MFG-009 work-order create; a `purchase` suggestion deep-links to the Purchasing module's PO create (if present) or shows the suggested quantity for manual action.
- TS types + endpoint wrappers + route + nav, flag- and role-gated.

**Acceptance Criteria**
- Admin can run MRP and see produce/purchase suggestions with quantities.
- A `produce` suggestion launches a pre-filled work order; the resulting finished-goods production is reflected back in inventory.
- Page is admin/root-gated and flag-gated.

**Dependencies**
- MFG-010, MFG-011, MFG-009.

---

## Milestone 5 — Storefront/Inventory Integration & Tests

### MFG-013: Finished-goods ↔ catalog stock integration
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Ensure produced finished goods (MFG-007) surface in the existing storefront stock view through the same denormalized mirror the inventory foundation already maintains: finished-goods on-hand changes via `inventory.adjust` recompute `available`/`status` on the `inventory` record (`app/services/inventory.py:101` `_record_out`), which the catalog stock mirror reads (per OFB-003's read-through mirror design in `OFBIZ_COMMERCE_TICKETS.md`).
- No new write path into catalog stock — production goes only through `inventory.adjust`; this ticket verifies and, if needed, wires the mirror refresh hook so a completed work order's output is immediately purchasable.

**Acceptance Criteria**
- Completing a work order for a catalog-listed SKU makes the produced quantity available for purchase in the existing shop/cart flow with no separate stock write.
- With the manufacturing flag off, the catalog stock path is byte-for-byte unchanged.
- pytest asserts that post-production `inventory.get_inventory(sku).available` and the catalog stock mirror agree.

**Dependencies**
- MFG-007.

---

### MFG-014: Manufacturing/MRP tests (hermetic pytest + e2e)
**Type:** Chore  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add hermetic offline pytest suites (moto-bound frozen `T` via `object.__setattr__`, no real AWS, flag toggled with `object.__setattr__` — the pattern used across the GAP regression tests in CLAUDE.md):
  - `tests/test_mfg_bom.py`: explosion (single/nested/scrap), cycle detection.
  - `tests/test_mfg_work_orders.py`: release→issue (component decrement via real `inventory.adjust`), complete→produce (finished-goods increment), replay idempotency, insufficient-stock 409, illegal transition.
  - `tests/test_mfg_mrp.py`: net-requirement math, BOM-exploded purchase/produce suggestions, surplus case, idempotent re-run.
  - `tests/test_mfg_cost_posting.py`: ledger entry shape + idempotency for MFG-008 (sub-flag on/off).
- Add `frontend/e2e/manufacturing.spec.ts` covering: create BOM → create work order → release (component stock drops) → complete (finished-goods stock rises) → MRP run shows expected suggestions, using seeded admin sessions + CSRF (per CLAUDE.md / MEMORY.md patterns).

**Acceptance Criteria**
- Unit suites cover BOM explosion, work-order issue/produce + idempotency, MRP math + suggestions, and the costed-posting hook; all run offline with no real AWS.
- E2E walks BOM → work order → production → MRP and asserts inventory deltas, passing under the standard 1-worker Playwright config.
- With the flag off, a regression test asserts the manufacturing endpoints 404 and inventory/cart/orders behavior is unchanged.

**Dependencies**
- MFG-010, MFG-011, MFG-013, MFG-008.

---
