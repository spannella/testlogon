# Purchasing / SCM (OFBiz Application G) — Implementation Tickets

This backlog builds the **buy-side** counterpart of the existing sales-order stack: a supplier/vendor party model, purchase orders with an approval lifecycle, receiving-against-PO that increments inventory through the existing `app/services/inventory.py` primitives, supplier product pricing, and reorder-driven PO suggestions wired to the OFB-005 low-stock signals. Everything is **additive + flag-gated** behind a default-off `PURCHASING_SCM_ENABLED` master switch (mirroring `inventory_reservations_enabled` at `app/core/settings.py:839` and `returns_rma_enabled` at `:846`); with the flag off the new tables are dormant, the router endpoints 404, and existing shop/cart/orders/billing/inventory behavior is byte-for-byte unchanged. Money-out (supplier payment / AP) reuses the existing single-entry ledger (`billing_shared.new_ledger_entry` at `app/services/billing_shared.py:224`) — it never forks billing. New write paths use deterministic-id idempotency (sha256 of a correlation id, per `commerce_order_service.create_order` at `app/services/commerce_order_service.py:67`), SECOPS-007 dev/prod parity, and hermetic offline tests.

## Milestone 1 — Scoping & Scaffolding

### PUR-001: Purchasing/SCM data-model & sequencing spike
**Type:** Spike  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Model purchase orders as the buy-side mirror of the sell-side: study `app/services/commerce_order_service.py:39` (`create_order`, deterministic `order_id = sha256(corr)` at `:67`, header + per-line `order_items` rows at `:85`/`:103`) and the inventory primitives `inventory.adjust(sku, +qty, reason)` (`app/services/inventory.py:209`) and `inventory.set_on_hand` (`:176`) that receiving will increment.
- Map OFBiz purchasing entities onto testlogon: **Supplier** (a vendor party — note we are NOT building full Party Manager here; suppliers are a self-contained party record under this module, forward-compatible with `PARTY_CRM_TICKETS.md`/`PTY`), **SupplierProduct** (supplier↔SKU price/lead-time/MOQ), **PurchaseOrder** (header + lines, approval lifecycle), **Receipt** (a receiving event against PO lines → inventory increment), and **reorder suggestion** (derived from OFB-005 low-stock signals + `reorder_point` at `app/services/inventory.py:104`).
- Decide the PO lifecycle state machine (`draft → submitted → approved → ordered → partially_received → received → closed`, plus `rejected`/`cancelled`) and the receiving model (partial receipts; cumulative received-qty per line). Define every new DynamoDB table (PK/SK/GSIs, `attr_types` for numeric sort keys), `app/models.py` Pydantic shapes, and `app/core/settings.py` flags/keys.
- Decide AP linkage: a received/invoiced PO produces a payable that, when paid, reuses `new_ledger_entry`/`settle_or_reverse_ledger` (never a new refund/payment mechanism) and reconciles to AR/AP in `OFBIZ_COMMERCE_TICKETS.md` OFB-015. Cite the `GSI_LEDGER_DATE` / provider-attribution constraints (CLAUDE.md FIN-013).

**Acceptance Criteria**
- A written design section (append to `docs/ofbiz-commerce-plan.md` or a new `docs/purchasing-scm-plan.md`) enumerates each entity, its table PK/SK/GSIs (with `attr_types` noted for numeric keys), Pydantic shapes, settings keys, and feature flags.
- The PO lifecycle state machine and legal transitions are documented (illegal transition → 409).
- The receiving→inventory and PO→AP/ledger derivation paths are documented and reviewed (eng + finance) to confirm money-out reuses existing billing.
- Every downstream PUR ticket references a section of the doc.

**Dependencies**
- None.

---

### PUR-002: Purchasing/SCM scaffolding (tables, settings, flag, handles)
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add the tables agreed in PUR-001 to `scripts/local-ddb-init.py` next to the existing OFBiz blocks (`inventory` at `:2456`, `reservations` at `:2469`, `returns` at `:2483`), each via the standard `_resolve_table_name(S.<name>, "<default>")` pattern, with numeric GSI sort keys declared via `attr_types` (per the CLAUDE.md DDB-numeric-GSI gotcha and the `attr_types={"created_at": "N"}` example at `:2491`):
  - `suppliers` — PK=`supplier_id`, SK=`META`; `GSI_STATUS` (partition `status`, sort `created_at` N) for the admin list.
  - `supplier_products` — PK=`supplier_id`, SK=`SKU#{sku}`; `GSI_SKU` (partition `sku`, sort `unit_cost_cents` N) to find cheapest supplier per SKU.
  - `purchase_orders` — PK=`po_id`, SK=`META` (header) + `LINE#{n}` (lines); `GSI_SUPPLIER` (partition `supplier_id`, sort `created_at` N) and `GSI_STATUS` (partition `status`, sort `created_at` N) for the approval/receiving queues.
  - `po_receipts` — PK=`po_id`, SK=`RECEIPT#{receipt_id}`; `GSI_RECEIPT` (partition `receipt_id`) for idempotent lookup.
- Add settings keys + the default-off master flag to `app/core/settings.py` after the returns block (`:846`): `purchasing_scm_enabled` (`PURCHASING_SCM_ENABLED`, default false), `suppliers_table_name`, `supplier_products_table_name`, `purchase_orders_table_name`, `po_receipts_table_name`, and `purchase_order_reorder_suggestions_enabled` (default false).
- Wire table handles in `app/core/tables.py` (after `returns` at `:319`): `T.suppliers`, `T.supplier_products`, `T.purchase_orders`, `T.po_receipts`, via `_safe_table(S.<name>)` (mirroring `:569`–`:571`).

**Acceptance Criteria**
- `just restart` recreates all new tables locally with no `ValidationException`.
- `S.purchasing_scm_enabled` and all new keys resolve through the `S` singleton; the flag defaults to disabled.
- A smoke pytest imports `app.core.tables.T` and asserts each new handle resolves.

**Dependencies**
- PUR-001.

---

## Milestone 2 — Supplier & Supplier-Product Model

### PUR-003: Supplier (vendor party) model & CRUD service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/suppliers.py` with a first-class supplier record (`supplier_id`, `name`, `status` = `active`/`inactive`, contact mechs — email/phone/address, `default_currency`, `payment_terms_days`, `created_at`/`updated_at`). Use the deterministic-id pattern (`supplier_id = sha256(f"supplier:{user_sub}:{name}")[:32]`, per `commerce_order_service.py:67`) so re-creating the same supplier is idempotent.
- Provide `create_supplier`, `get_supplier`, `update_supplier`, `set_supplier_status`, and `list_suppliers` (paginated via `GSI_STATUS`, following the `list_low_stock` GSI-paginate loop at `app/services/inventory.py:318`). Emit `alerts.audit_event` on every mutation via a best-effort `_audit` helper (copy the pattern at `app/services/inventory.py:92`).
- Gate all functions behind `purchasing_scm_enabled` via a `_require_enabled()` helper that raises `HTTPException(404)` when off (copy `inventory._require_enabled` at `app/services/inventory.py:54`).

**Acceptance Criteria**
- Creating a supplier with the same name twice is idempotent (same `supplier_id`, no duplicate row).
- `set_supplier_status("inactive")` excludes the supplier from active lists but preserves history.
- Every mutation writes an audit event; with the flag off every function raises 404.
- pytest covers create-idempotency, update, status toggle, and list pagination.

**Dependencies**
- PUR-002.

---

### PUR-004: Supplier-product pricing (supplier↔SKU price / lead-time / MOQ)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add `app/services/supplier_products.py` managing the supplier↔SKU relationship: `unit_cost_cents`, `currency`, `lead_time_days`, `min_order_qty` (MOQ), `supplier_sku` (the vendor's own part number), `preferred` flag.
- Provide `upsert_supplier_product(supplier_id, sku, ...)`, `get_supplier_product`, `list_products_for_supplier(supplier_id)`, and `list_suppliers_for_sku(sku)` (queries `GSI_SKU` sorted by `unit_cost_cents` so the cheapest/lead-time-best supplier surfaces first — this feeds PUR-011 reorder suggestions).
- Validate the SKU exists in the catalog (`shopping_catalog`, cf. `app/routers/catalog.py:122`) or inventory (`inventory.get_inventory` at `app/services/inventory.py:150`); a non-existent SKU → 422.

**Acceptance Criteria**
- `list_suppliers_for_sku` returns suppliers ordered by ascending `unit_cost_cents`.
- Upsert is idempotent on (`supplier_id`, `sku`); re-upsert updates price/lead-time in place.
- MOQ and lead-time persist and are returned; unknown SKU → 422.
- pytest covers upsert, cheapest-supplier ordering, and SKU validation.

**Dependencies**
- PUR-003.

---

### PUR-005: Supplier & supplier-product models + router
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add Pydantic shapes to `app/models.py` near the catalog block (`CatalogItemCreateIn` at `:538`): `SupplierCreateIn`, `SupplierPatchIn`, `SupplierOut`, `SupplierListOut`, `SupplierProductUpsertIn`, `SupplierProductOut`, `SupplierProductListOut`.
- Create `app/routers/purchasing.py` exposing `purchasing_router = APIRouter(prefix="/ui/purchasing", tags=["purchasing"])` (mirror `inventory_router` at `app/routers/inventory.py:29`). Supplier/supplier-product CRUD endpoints are **admin-gated** (`require_admin_session`); a read-only supplier list may use `require_admin_session` too (purchasing is staff-only). Declare any literal sub-paths (e.g. `/suppliers`) BEFORE dynamic `/{supplier_id}` segments (FastAPI declaration-order gotcha, per CLAUDE.md audit-export-schedule note).
- Register the router in `app/main.py`: import alongside `inventory_router` (`app/main.py:311`) and `app.include_router(purchasing_router)` alongside `inventory_router` (`:877`).

**Acceptance Criteria**
- `POST/GET/PATCH /ui/purchasing/suppliers[/{id}]` and `PUT/GET /ui/purchasing/suppliers/{id}/products[/{sku}]` work end-to-end; non-admin → 403.
- With `purchasing_scm_enabled=false` every endpoint returns 404.
- OpenAPI (`/openapi.json`) lists the new endpoints; router registered in `app/main.py`.

**Dependencies**
- PUR-003, PUR-004.

---

## Milestone 3 — Purchase Orders & Approval

### PUR-006: Purchase-order entity & creation
**Type:** Feature  
**Priority:** P0  
**Estimate:** 5 days

**Description**
- Create `app/services/purchase_orders.py` with a PO header (`po_id`, `supplier_id`, `status`, `currency`, `subtotal_cents`, `expected_delivery_date`, `created_by`, `created_at`/`updated_at`) plus per-line rows (`LINE#{n}`: `sku`, `quantity_ordered`, `quantity_received` (starts 0), `unit_cost_cents`, `line_total_cents`). Model it as the buy-side mirror of `commerce_order_service.create_order` (`app/services/commerce_order_service.py:39`): header `put_item` + per-line `put_item` loop (`:85`/`:103`), deterministic `po_id = sha256(corr)[:32]` (`:67`) for idempotency.
- Default each line's `unit_cost_cents` from the supplier-product price (PUR-004) when omitted; compute `subtotal_cents = Σ line_total_cents`. New POs start in `draft`. Emit `audit_event("purchase_order_created", ...)` (mirror `commerce_order_created` at `commerce_order_service.py:106`).
- Provide `create_purchase_order`, `get_purchase_order` (header + lines), and `list_purchase_orders` (by supplier via `GSI_SUPPLIER`, by status via `GSI_STATUS`).

**Acceptance Criteria**
- Creating a PO with the same correlation id twice yields the same `po_id` and does not duplicate lines (idempotent).
- Line totals and header subtotal compute correctly; missing `unit_cost_cents` defaults from supplier-product pricing.
- `get_purchase_order` returns header + ordered lines; `list_purchase_orders` filters by supplier and by status.
- pytest covers creation, idempotency, subtotal math, and price defaulting.

**Dependencies**
- PUR-002, PUR-004.

---

### PUR-007: PO approval lifecycle state machine
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Add a guarded transition function `transition_po(po_id, target_status, actor_sub, ...)` enforcing the PUR-001 state machine: `draft → submitted → approved → ordered → partially_received → received → closed`, plus `submitted/approved → rejected` and `draft/submitted/approved → cancelled`. Use a conditional `update_item` on the header (`ConditionExpression="#status = :expected"`) so transitions are atomic and idempotent under replay — mirror the reservation terminal-state guard at `app/services/inventory.py:441` (`_close_reservation`). Illegal transition → 409.
- `submit` (draft→submitted) and `approve` (submitted→approved) are separate operations; approval is restricted to `require_admin_session`. Record `approved_by`/`approved_at`/`rejected_reason` on the header. Each transition emits an audit event and moves the row across `GSI_STATUS` partitions for the approval queue.
- Cancelling a PO with received quantity is blocked (must close instead); a `received` PO auto-derives from receiving (PUR-008/009), not via manual transition.

**Acceptance Criteria**
- Legal transitions succeed and are audited; illegal transitions return 409 without mutating state.
- Replaying an already-applied transition is a no-op (idempotent), not a 409 storm.
- Approval is admin-only; rejection records a reason; cancel is blocked once any quantity is received.
- pytest covers the full happy path, each illegal transition, replay idempotency, and the cancel-after-receive block.

**Dependencies**
- PUR-006.

---

### PUR-008: Receiving against PO → inventory increment
**Type:** Feature  
**Priority:** P0  
**Estimate:** 5 days

**Description**
- Add `app/services/po_receiving.py` with `receive_po(po_id, lines=[{line_no, quantity}], actor_sub, receipt_correlation_id)` that records a `po_receipts` row (`RECEIPT#{receipt_id}`, deterministic `receipt_id = sha256(receipt_correlation_id)[:32]` for idempotency) and, per received line, increments stock via the existing `inventory.adjust(sku, +qty, reason="po_receipt", user_sub=...)` (`app/services/inventory.py:209`) — never a parallel stock mutation.
- Update each PO line's `quantity_received` (conditional increment; cannot exceed `quantity_ordered` → 422 on over-receive) and recompute the header status: all lines fully received → `received` (and auto-`closed` per PUR-007 policy), some lines received → `partially_received` (drives the GSI_STATUS queue transition from PUR-007).
- Guard the inventory increment behind `inventory_reservations_enabled` (`app/core/settings.py:839`) so PO receiving still records the receipt and updates `quantity_received` even when inventory is disabled (mirrors OFB-009's "RMA still functions minus restock" guard). Receiving requires the PO be in `approved`/`ordered`/`partially_received` (else 409).

**Acceptance Criteria**
- A full receipt increments inventory on-hand by exactly the received qty (idempotent on `receipt_correlation_id`: replay does NOT double-increment) and flips the PO to `received`/`closed`.
- A partial receipt advances `quantity_received` and sets `partially_received`; a subsequent receipt completes it.
- Over-receiving a line (received > ordered) → 422; receiving against a non-approved PO → 409.
- With inventory disabled, the receipt is recorded and `quantity_received` advances but no stock mutation occurs.
- pytest covers full receipt, partial-then-complete, over-receive rejection, replay idempotency, and the inventory-disabled path.

**Dependencies**
- PUR-007, PUR-002, (Inventory OFB-003 — `app/services/inventory.py`).

---

### PUR-009: PO → AP payable / supplier payment via existing ledger
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- On a `received` PO, record a supplier payable and (when paid) post money-out **through the existing billing machinery** — `billing_shared.new_ledger_entry` (`app/services/billing_shared.py:224`) with `entry_type` for AP/purchase, `state`, `reason="supplier_payment"`, and `extra={"provider": ...}` for attribution (FIN-013) — and `settle_or_reverse_ledger` (`:262`) for settlement. Do NOT mint a new payment/refund mechanism (cross-cutting constraint).
- Make the payable balance reconcile to the AP subledger in `OFBIZ_COMMERCE_TICKETS.md` OFB-015 (AP control account): the PO payable is the AP open-item source for purchasing. Use a deterministic ledger correlation (`po_id`) so re-posting is idempotent (one payable per PO).
- Record the payment linkage (`ledger_entry_id`, `paid_at`, `amount_cents`) back onto the PO header.

**Acceptance Criteria**
- A received PO produces exactly one payable ledger entry tied to the supplier and `po_id` (idempotent — re-running does not double-post).
- The payable amount equals the PO `subtotal_cents` (currency-checked); the entry carries provider attribution.
- The payable appears in the AP subledger/aging (OFB-015) and ties out to the AP control account.
- pytest covers payable creation, idempotency, and amount/currency correctness with a stubbed ledger.

**Dependencies**
- PUR-008, OFB-015 (Accounting AR/AP, `OFBIZ_COMMERCE_TICKETS.md`).

---

### PUR-010: Purchase-order models + router endpoints
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add Pydantic shapes to `app/models.py`: `PurchaseOrderCreateIn` (supplier_id + lines), `PurchaseOrderLineIn/Out`, `PurchaseOrderOut` (header + lines + status), `PurchaseOrderListOut`, `PoTransitionIn` (target_status + reason), `PoReceiveIn` (lines + receipt_correlation_id), `PoReceiptOut`.
- Extend `app/routers/purchasing.py` (PUR-005) with admin-gated PO endpoints: `POST /ui/purchasing/purchase-orders`, `GET .../{po_id}`, `GET .../purchase-orders?supplier_id=&status=`, `POST .../{po_id}/submit`, `POST .../{po_id}/approve`, `POST .../{po_id}/reject`, `POST .../{po_id}/cancel`, `POST .../{po_id}/receive`. Approval/reject use `require_admin_session`; keep literal segments before dynamic `/{po_id}`.

**Acceptance Criteria**
- The full PO lifecycle (create → submit → approve → receive) is drivable end-to-end via the router; non-admin approve → 403.
- Receiving via `POST .../{po_id}/receive` increments inventory (PUR-008) and returns the updated PO + receipt.
- With `purchasing_scm_enabled=false` every endpoint returns 404; endpoints appear in OpenAPI.

**Dependencies**
- PUR-006, PUR-007, PUR-008.

---

## Milestone 4 — Reorder-Driven Suggestions

### PUR-011: Reorder-driven PO suggestions from low-stock signals
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Add `app/services/reorder_suggestions.py` that scans for SKUs at/below their reorder point using the existing inventory low-stock query `inventory.list_low_stock(status="low_stock")` (and `out_of_stock`) at `app/services/inventory.py:318` (the OFB-005 low-stock signal source; `reorder_point` lives at `app/services/inventory.py:104`).
- For each low SKU, pick the preferred/cheapest supplier via `supplier_products.list_suppliers_for_sku(sku)` (PUR-004, ordered by `unit_cost_cents`), compute a suggested order quantity (`max(reorder_point - available, MOQ)`, rounded to MOQ multiples), and produce a suggestion grouped by supplier. Suggestions are advisory — `create_purchase_order_from_suggestion(...)` materializes one into a `draft` PO via PUR-006 (deterministic id keyed on the suggestion so repeated generation is idempotent).
- Gate behind `purchase_order_reorder_suggestions_enabled` (PUR-002); skip SKUs with no supplier-product mapping (surface them as "no supplier" warnings).

**Acceptance Criteria**
- Suggestions list every SKU at/below reorder point with the chosen supplier and a quantity ≥ MOQ.
- A SKU with no supplier-product mapping is surfaced as a warning, not silently dropped.
- Converting a suggestion creates a `draft` PO (PUR-006) idempotently; re-converting the same suggestion does not duplicate the PO.
- pytest covers suggestion math (reorder gap vs MOQ rounding), supplier selection, the no-supplier warning, and convert-to-PO idempotency.

**Dependencies**
- PUR-006, PUR-004, OFB-005 (low-stock signals, `app/services/inventory.py`).

---

### PUR-012: Reorder-suggestion endpoints + optional background scan
**Type:** Feature  
**Priority:** P2  
**Estimate:** 3 days

**Description**
- Add admin endpoints to `app/routers/purchasing.py`: `GET /ui/purchasing/reorder-suggestions` (compute on demand) and `POST /ui/purchasing/reorder-suggestions/{supplier_id}/create-po` (materialize a draft PO via PUR-011). Add `ReorderSuggestionOut`/`ReorderSuggestionListOut` models.
- Optionally add a periodic background scan `start_reorder_suggestion_task` (gated by `purchase_order_reorder_suggestions_enabled`) that emits an alert when new low-stock SKUs appear, registered in `app/main.py` next to the other startup tasks (e.g. `start_cart_abandonment_task` import at `app/main.py:71`). Best-effort, non-blocking, dev/prod parity.

**Acceptance Criteria**
- `GET /ui/purchasing/reorder-suggestions` returns the current suggestions; `create-po` materializes a draft PO for one supplier.
- The optional background task is flag-gated, registered in `app/main.py`, and a no-op when disabled.
- With `purchasing_scm_enabled=false` the endpoints 404.

**Dependencies**
- PUR-011, PUR-010.

---

## Milestone 5 — Frontend

### PUR-013: Frontend types + endpoint wrappers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add TypeScript interfaces to `frontend/src/api/types.ts` mirroring the new Pydantic shapes (`Supplier`, `SupplierProduct`, `PurchaseOrder`, `PurchaseOrderLine`, `PoReceipt`, `ReorderSuggestion`).
- Add endpoint wrappers `frontend/src/api/endpoints/purchasing.ts` (suppliers CRUD, supplier-products, purchase-orders CRUD + transitions + receive, reorder-suggestions) using the shared axios instance in `frontend/src/api/client.ts` (CSRF header is attached automatically per CLAUDE.md frontend conventions).

**Acceptance Criteria**
- Types compile (`tsc`) and mirror the backend shapes.
- Endpoint wrappers cover every PUR-005/PUR-010/PUR-012 route and are typed.

**Dependencies**
- PUR-005, PUR-010, PUR-012.

---

### PUR-014: Suppliers admin page
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add a suppliers management page under `frontend/src/pages/shop/admin/` (alongside `AdminCatalog.tsx`/inventory admin from OFB-006) listing suppliers with status, contact info, and per-supplier product pricing (inline upsert of `unit_cost_cents`/`lead_time_days`/MOQ).
- Use React Query (`useQuery`/`useMutation`) + React Hook Form + Zod + shadcn/ui primitives per the frontend conventions; admin/root-gated.

**Acceptance Criteria**
- Admin can create/edit suppliers and manage supplier-product pricing without reload.
- The page is flag-gated (hidden/404 when `purchasing_scm_enabled=false`) and role-gated.

**Dependencies**
- PUR-013.

---

### PUR-015: Purchase-orders admin page (create / approve / receive)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Add a purchase-orders page under `frontend/src/pages/shop/admin/` with a PO list (filter by supplier/status via `GSI_SUPPLIER`/`GSI_STATUS`), a PO builder (pick supplier → add SKU lines with defaulted cost), the approval queue (submit/approve/reject buttons gated to admin), and a receiving panel (enter received quantities → calls `POST .../{po_id}/receive`).
- Surface the reorder-suggestions view with a "Create draft PO" action (PUR-012). Show PO status badges driven by the PUR-007 state machine.

**Acceptance Criteria**
- Admin can create a PO, move it through submit→approve, and receive (full + partial) from the UI; status badges update without reload.
- Receiving reflects the inventory increment (cross-link to the inventory admin page from OFB-006).
- Reorder suggestions render and can be converted to draft POs.

**Dependencies**
- PUR-013, PUR-014.

---

### PUR-016: Route + navigation entries
**Type:** Chore  
**Priority:** P2  
**Estimate:** 1 day

**Description**
- Add lazy-loaded routes for the suppliers and purchase-orders pages to `frontend/src/App.tsx` (mirroring the OFB-006 inventory-admin route), and a "Purchasing" nav entry under the admin/shop section in `frontend/src/components/layout/` (Sidebar), shown only to admins and only when the purchasing flag is on (flag surfaced via an existing config/feature endpoint or the page's own 404 fallback).

**Acceptance Criteria**
- Routes resolve to the new pages; nav entry appears for admins and is hidden when the flag is off.
- Non-admin users cannot reach the pages (route guard + backend 403).

**Dependencies**
- PUR-014, PUR-015.

---

## Milestone 6 — Tests

### PUR-017: Purchasing/SCM hermetic offline + E2E tests
**Type:** Chore  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add hermetic offline pytest suites (moto-bound frozen `T` via `object.__setattr__`, no real AWS — following the CLAUDE.md regression-test patterns, e.g. `tests/test_gap_0223_0224_ec2_host_inventory.py`): `tests/test_pur_suppliers.py` (supplier + supplier-product CRUD, cheapest-supplier ordering, idempotency), `tests/test_pur_purchase_orders.py` (PO creation/subtotal/idempotency, the full lifecycle state machine + illegal-transition 409s + replay idempotency), `tests/test_pur_receiving.py` (full/partial receive, over-receive 422, receipt replay idempotency, inventory-disabled path, AP payable via a stubbed `new_ledger_entry`), and `tests/test_pur_reorder.py` (suggestion math, supplier selection, no-supplier warning, convert-to-PO idempotency).
- Add `frontend/e2e/purchasing-scm.spec.ts` covering create-supplier → create-PO → approve → receive → inventory increment, plus a reorder-suggestion → draft-PO flow, using seeded admin sessions (`e2e_admin_session_setup.py`) + CSRF per CLAUDE.md/MEMORY.md patterns.
- Verify the flag-off contract: with `purchasing_scm_enabled=false`, every endpoint 404s and existing shop/cart/orders/billing/inventory pytest + E2E suites are unaffected.

**Acceptance Criteria**
- Offline pytest suites cover supplier/PO/receiving/reorder happy paths, idempotency, lifecycle guards, and the inventory-disabled + flag-off contracts; all run without real AWS/network.
- E2E covers the full create→approve→receive→increment lifecycle and a reorder→draft-PO flow under the standard 1-worker Playwright config.
- Money-out is asserted to flow through `new_ledger_entry`/`settle_or_reverse_ledger` (no forked billing); receiving reuses `inventory.adjust`.

**Dependencies**
- PUR-010, PUR-012, PUR-016, PUR-009.

---
