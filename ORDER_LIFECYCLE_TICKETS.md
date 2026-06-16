# Order Lifecycle (OFBiz Order Manager) — Implementation Tickets

This backlog turns the platform's flat `pending_payment` order record into a full OFBiz-style sales-order **state machine** (created/approved → allocated → picking → packed → shipped → completed, plus held/backorder/cancelled/returned), with order adjustments (discounts/surcharges/tax/shipping lines), ship groups, and an append-only order status-history/audit trail. It is strictly additive over the existing `app/services/commerce_order_service.py` (`create_order` at `:39`, hard-coded status `pending_payment` at `:75`, deterministic `order_id = sha256(correlation_id)` at `:67`, writing `orders` + `order_items`) and is gated behind a default-off `ORDER_LIFECYCLE_ENABLED` flag so existing shop/cart/orders/billing flows are byte-for-byte unchanged when off. Money-out (cancel/return adjustments) reuses `refund_payment` / `settle_or_reverse_ledger` and never forks billing; the GL continues to derive from the single-entry ledger.

## Milestone 1 — Foundation (flag, data model, tables)

### ORD-001: Order-lifecycle scoping & state-machine design
**Type:** Spike  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Map the OFBiz Order Manager state machine onto the current order record. Today `commerce_order_service.create_order` (`app/services/commerce_order_service.py:39`) writes a single `status="pending_payment"` (`:75`) with no transition logic; `orders`/`order_items` tables are defined at `scripts/local-ddb-init.py:288` / `:295` (PK `order_id`, SK `item_id` for items).
- Define the canonical status set and legal transition graph: `created → approved → allocated → picking → packed → shipped → completed`, plus side states `held`, `backorder`, `cancelled`, `returned`, and their allowed sources/targets (e.g. `held` reachable from any pre-`shipped` state and resumable; `cancelled` reachable from any pre-`shipped` state; `returned` only from `completed`/`shipped`).
- Specify how the new lifecycle status coexists with the legacy `status` field (decision: add `lifecycle_status` additively, keep legacy `status` as a denormalized mirror for back-compat) so existing reads in `app/services/shoppingcart.py:581` (order creation via `create_order_from_line_items`) and any storefront consumers keep working.
- Enumerate the new DDB items (status-history rows, ship-group rows, adjustment rows) as additional SK partitions under the existing `orders` table single-table model, plus required GSIs (status index, ship-date index) with `attr_types` for numeric sort keys.

**Acceptance Criteria**
- A design note (`docs/order-lifecycle-plan.md`) enumerates every status, the full transition matrix (legal/illegal), the additive coexistence with legacy `status`, and the new SK partition layout + GSIs.
- The note cites the exact current-state lines (`commerce_order_service.py:39/67/75`, `local-ddb-init.py:288`) and confirms zero behavior change when `ORDER_LIFECYCLE_ENABLED` is off.
- Reviewer signs off that no money path is forked and that cancel/return defer to `refund_payment`.

**Dependencies**
- None.

---

### ORD-002: Feature flag & settings
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add `ORDER_LIFECYCLE_ENABLED` (default `false`) to `app/core/settings.py` (`Settings` dataclass + `S` singleton), following the existing flag pattern used by the other ERP modules.
- Add supporting settings: `ORDER_LIFECYCLE_AUTO_APPROVE` (default `false` — whether a paid order auto-advances `created → approved`) and `ORDER_BACKORDER_ENABLED` (default `false`).
- Document the flag group in the order-lifecycle plan; ensure no code path activates until a downstream ticket reads the flag.

**Acceptance Criteria**
- `S.order_lifecycle_enabled` and the two supporting settings resolve through the `S` singleton and default off.
- A smoke pytest asserts the defaults and that flipping the env var toggles them.
- With all flags off, no new behavior is reachable.

**Dependencies**
- ORD-001.

---

### ORD-003: DDB single-table items, GSIs, and table handles
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Extend the existing `orders` table single-table model (`scripts/local-ddb-init.py:288`) with new SK partitions rather than new physical tables where natural: status-history (`SK=HIST#{ts:020d}#{event_id}`), ship-group (`SK=SHIPGRP#{ship_group_id}`), and order-adjustment (`SK=ADJ#{adjustment_id}`) rows, all under PK `order_id`. The order header stays `SK=ORDER` (or current convention) and `order_items` (`:295`) is unchanged.
- Add a status GSI (`GSI_ORDER_STATUS`: PK `lifecycle_status`, SK numeric `updated_ts`) and a ship-date GSI (`GSI_ORDER_SHIPDATE`: PK derived ship-day bucket, SK numeric `ship_ts`) to the `orders` table, declaring numeric sort keys via `attr_types={"updated_ts":"N", ...}` per the CLAUDE.md numeric-GSI gotcha.
- Wire any new handle aliases in `app/core/tables.py` (`T.orders` already exists at `:381`); add `attr_types` declarations so `just restart` recreates without `ValidationException`.

**Acceptance Criteria**
- `just restart` recreates the `orders` table with the new GSIs and no `ValidationException`.
- Numeric GSI sort keys are stored as `N` and queryable with integer values.
- A smoke pytest writes a HIST/SHIPGRP/ADJ row + header and reads them back via PK query and the status GSI.

**Dependencies**
- ORD-001, ORD-002.

---

### ORD-004: Pydantic models for lifecycle, history, ship groups, adjustments
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add Pydantic request/response models to `app/models.py`: `OrderLifecycleStatus` (enum), `OrderStatusHistoryEntry` (status, from_status, actor, reason, ts), `ShipGroup` (ship_group_id, ship_method, address ref, line refs, status), `OrderAdjustment` (type ∈ {discount, surcharge, tax, shipping, promotion}, amount_cents, currency, label, taxable, source rule ref), and `OrderTransitionRequest`/`OrderTransitionResult`.
- Mirror the additive `lifecycle_status` + legacy `status` decision from ORD-001 on the order response model so existing consumers see both.
- Reuse existing money/currency conventions (`amount_cents` int) consistent with `commerce_order_service._line_amount_cents` (`:27`) and the line-item rows at `:88`.

**Acceptance Criteria**
- New models validate sample payloads and reject illegal enum values / negative amounts where appropriate.
- The order response model carries `lifecycle_status`, `ship_groups`, `adjustments`, and `status_history` additively without breaking existing serialization.
- pytest covers model validation for each new shape.

**Dependencies**
- ORD-001.

---

## Milestone 2 — State machine & status history

### ORD-005: Order state-machine service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/order_lifecycle.py` defining the transition graph from ORD-001 as data (a `TRANSITIONS: dict[status, set[status]]`) and a `transition_order(order_id, target_status, *, actor, reason, idempotency_key=None)` that validates the current → target edge, performs a conditional `update_item` on the order header guarded on the current `lifecycle_status` (single-writer / optimistic concurrency), and mirrors legacy `status` per ORD-001.
- Illegal transitions raise a typed error → 409 at the router; the service is a pure additive layer over the header written by `commerce_order_service.create_order` (`:72`) and never mutates `order_items` content.
- Use deterministic idempotency: derive the transition `event_id` from `sha256(order_id|from|to|idempotency_key)` (mirroring the `order_id = sha256(correlation_id)` pattern at `commerce_order_service.py:67`) so replays are no-ops.

**Acceptance Criteria**
- Legal transitions succeed and update both `lifecycle_status` and legacy `status`; illegal transitions raise and persist nothing.
- Concurrent transition attempts from the same source resolve to exactly one winner (conditional update); the loser sees the typed conflict error.
- Replaying the same transition with the same idempotency key is a no-op (no duplicate history).
- pytest covers each legal edge, a representative illegal edge, the race, and replay idempotency.

**Dependencies**
- ORD-003, ORD-004.

---

### ORD-006: Order status-history (append-only audit trail)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- On every successful transition in `order_lifecycle.transition_order` (ORD-005), append a `HIST#{ts:020d}#{event_id}` row (from_status, to_status, actor, reason, ts) under the order PK, and emit an `audit_event("order_status_changed", actor, ...)` via `app/services/alerts.audit_event` (mirroring `commerce_order_service.py:106`).
- Provide `list_status_history(order_id)` returning newest-first, and ensure history is written in the same logical operation as the header update is acknowledged (best-effort transactional ordering: header CAS first, then history append; history append failure is logged but does not roll back the state change, matching the platform's best-effort audit convention).

**Acceptance Criteria**
- Every transition produces exactly one history row with correct from/to/actor/reason/ts.
- `list_status_history` returns chronological (newest-first) entries; the initial `created` event is recorded at order creation when the flag is on.
- Both an in-table HIST row and an `alerts` audit event are written; pytest asserts both.

**Dependencies**
- ORD-005.

---

### ORD-007: Lifecycle integration at order creation (flag-gated)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- When `ORDER_LIFECYCLE_ENABLED` is on, have `commerce_order_service.create_order` (`app/services/commerce_order_service.py:39`) stamp `lifecycle_status="created"` on the header (`:72`) and write the initial `created` HIST row (ORD-006). When off, the header is byte-for-byte identical to today (`status="pending_payment"`, no `lifecycle_status`, no HIST rows).
- Optionally auto-advance `created → approved` on payment success when `ORDER_LIFECYCLE_AUTO_APPROVE` is on, hooked from the existing purchase path (`app/services/shoppingcart.py:581` where `create_order_from_line_items` is called) — without duplicating any billing logic.
- Keep the deterministic `order_id` (`:67`) and idempotency behavior unchanged.

**Acceptance Criteria**
- With the flag off, the persisted order record and `order_items` rows are identical to current output (verified by a golden-record pytest).
- With the flag on, new orders carry `lifecycle_status="created"` and an initial HIST row; auto-approve advances to `approved` only when its sub-flag is on.
- No change to `order_id` derivation or line-item serialization.

**Dependencies**
- ORD-005, ORD-006.

---

## Milestone 3 — Adjustments & ship groups

### ORD-008: Order adjustments (discount/surcharge/tax/shipping lines)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add adjustment management to `app/services/order_lifecycle.py` (or a sibling `order_adjustments.py`): `add_adjustment(order_id, adjustment)`, `remove_adjustment`, `list_adjustments`, writing `ADJ#{adjustment_id}` rows (ORD-003) and recomputing an additive `adjusted_amount_cents` = base line total + Σ adjustments on the header.
- Base line total is the existing `amount_cents` computed at `commerce_order_service.py:69`; adjustments are additive and never mutate `order_items` `amount_cents` rows. Discounts are negative, surcharges/tax/shipping positive; each adjustment carries a type, label, currency, and optional source rule reference (forward-compatible with the Pricing module).
- Only allow adjustments in pre-`shipped` states (validated against `lifecycle_status`); record an audit event per change.

**Acceptance Criteria**
- Adding/removing adjustments recomputes `adjusted_amount_cents` correctly (negative discounts subtract, surcharges/tax/shipping add); base `amount_cents` and line rows are untouched.
- Adjustments are rejected on shipped/completed/cancelled orders (409).
- Currency mismatch between an adjustment and the order currency is rejected.
- pytest covers the math, state-gating, and currency validation.

**Dependencies**
- ORD-004, ORD-005.

---

### ORD-009: Ship groups
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add ship-group support: `create_ship_group(order_id, ship_method, address_ref, item_refs)`, `assign_items_to_ship_group`, `list_ship_groups`, writing `SHIPGRP#{ship_group_id}` rows (ORD-003). A ship group references a subset of `order_items` (`app/services/commerce_order_service.py:88` rows by `item_id`) and carries its own fulfillment sub-status.
- Default behavior: a single implicit ship group covering all items when none is created, so single-shipment orders need no extra modeling. The lifecycle transitions `allocated → picking → packed → shipped` operate per ship group, and the order header advances to `shipped`/`completed` only when all ship groups reach that state.
- Validate that each `order_items` line is assigned to at most one ship group and that referenced items exist on the order.

**Acceptance Criteria**
- Items can be partitioned across multiple ship groups; an item cannot be double-assigned; unknown item refs are rejected.
- Per-ship-group fulfillment status advances independently; the order header reaches `shipped`/`completed` only when every ship group has.
- A single-ship-group default works with no explicit ship-group creation.
- pytest covers multi-ship-group fulfillment roll-up and the assignment guards.

**Dependencies**
- ORD-005, ORD-006.

---

### ORD-010: Cancel & return transitions (refund via existing billing)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Wire the `cancelled` and `returned` lifecycle transitions to the existing money-out path: any refund issued on cancel/return goes through `refund_payment` / `settle_or_reverse_ledger` (`app/routers/billing.py:1287`, `:1324`) and `new_ledger_entry` with `reason="refund"` — never a parallel mechanism — preserving provider attribution (`extra={"provider": ...}`, FIN-013).
- `cancel_order(order_id, reason, refund=bool)` validates the source state (pre-`shipped` only), transitions to `cancelled`, and optionally issues a prorated/full refund; `return_order` is the bridge that the Returns/RMA module (OFB-010) can call to drive `completed/shipped → returned`. Refunds account for ORD-008 adjustments (refund the adjusted amount).
- Idempotent: a second cancel/return of the same order is a no-op; a second refund of the same payment is prevented.

**Acceptance Criteria**
- Cancelling a pre-shipped order transitions to `cancelled` and, when `refund=true`, produces exactly one refund ledger entry tied to the original payment + provider.
- Shipped/completed orders cannot be `cancelled` (must go through `returned`); the refund amount honors order adjustments.
- Double-cancel / double-refund of the same order is prevented (idempotent); pytest covers cancel-with-refund, cancel-no-refund, illegal cancel, and refund idempotency with billing patched.

**Dependencies**
- ORD-005, ORD-008.

---

## Milestone 4 — Router & API

### ORD-011: Order-lifecycle router (transitions, history, adjustments, ship groups)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/routers/order_lifecycle.py` and register it in `app/main.py` (per the CLAUDE.md router convention). Endpoints under `require_ui_session` for owner reads and `require_admin_session` for fulfillment actions:
  - `POST /ui/orders/{order_id}/transition` (admin) → `transition_order`,
  - `GET /ui/orders/{order_id}/lifecycle` (owner/admin) → header status + ship groups + adjustments + history,
  - `GET /ui/orders/{order_id}/history` → status history,
  - `POST/DELETE /ui/orders/{order_id}/adjustments` (admin),
  - `POST /ui/orders/{order_id}/ship-groups` + `POST .../ship-groups/{id}/assign` (admin),
  - `POST /ui/orders/{order_id}/cancel` (owner can self-cancel pre-approval; admin otherwise).
- Declare any static path segments before dynamic `/{order_id}` ones (FastAPI matches in declaration order — per the CLAUDE.md `/schedules`-before-`/{export_id}` gotcha). Enforce ownership (the requester's `user_sub` must match the order `user_id` from `commerce_order_service.py:74`) for non-admin reads/cancels. Gate the whole router behind `ORDER_LIFECYCLE_ENABLED` (503 when off).

**Acceptance Criteria**
- All endpoints enforce auth/ownership; foreign-order access → 403/404; illegal transitions → 409; adjustments on shipped orders → 409.
- With `ORDER_LIFECYCLE_ENABLED` off, every endpoint returns 503/404 and no existing route is affected.
- Router registered in `app/main.py`; CSRF enforced on non-GET cookie-auth requests (per CLAUDE.md auth conventions).
- pytest hits each endpoint via the test client for happy-path + auth-failure + flag-off.

**Dependencies**
- ORD-005, ORD-006, ORD-008, ORD-009, ORD-010.

---

### ORD-012: Status & ship-date list/query endpoints
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add admin list endpoints to the ORD-011 router backed by the GSIs from ORD-003: `GET /ui/orders/lifecycle/by-status?status=picking` (queries `GSI_ORDER_STATUS`, paginated via `app/core/cursor.py`) and `GET /ui/orders/lifecycle/by-ship-date?date=YYYY-MM-DD` (queries `GSI_ORDER_SHIPDATE`).
- Paginate using the existing cursor encode/decode (`app/core/cursor.py`) and loop on `LastEvaluatedKey` for any filtered queries (per the CLAUDE.md FilterExpression page-size gotcha) so sparse-status queries don't silently miss items.

**Acceptance Criteria**
- By-status returns only orders in the requested lifecycle state, paginated, newest-first by `updated_ts`.
- By-ship-date returns ship groups/orders for the day bucket; pagination cursors round-trip.
- pytest seeds multiple orders across statuses and asserts correct filtering + pagination.

**Dependencies**
- ORD-003, ORD-011.

---

## Milestone 5 — Frontend

### ORD-013: Frontend types & endpoint wrappers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add TypeScript interfaces to `frontend/src/api/types.ts` mirroring the ORD-004 Pydantic models (`OrderLifecycleStatus`, `OrderStatusHistoryEntry`, `ShipGroup`, `OrderAdjustment`, lifecycle response shape).
- Add endpoint wrappers in a new `frontend/src/api/endpoints/orderLifecycle.ts` using the axios instance in `frontend/src/api/client.ts` (CSRF header auto-attached) for transition, lifecycle fetch, history, adjustments, ship groups, cancel, and the by-status/by-ship-date lists.

**Acceptance Criteria**
- Types compile and match the backend response shapes (no `any`).
- Each endpoint wrapper calls the correct path/method and is consumed by React Query hooks in ORD-014.

**Dependencies**
- ORD-011, ORD-012.

---

### ORD-014: Order-lifecycle admin page, customer view, route & nav
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Add an admin order-fulfillment page under `frontend/src/pages/shop/admin/` (alongside the existing shop admin pages): a status-board / order detail with a transition control (only legal next states enabled), a status-history timeline, adjustments editor, and ship-group management — all using React Query + shadcn/ui per the frontend conventions.
- Add a customer-facing order timeline (read-only lifecycle + history + self-cancel pre-approval) under `frontend/src/pages/shop/` or the existing order/checkout area.
- Add routes to `frontend/src/App.tsx` and a nav entry, all gated on `ORDER_LIFECYCLE_ENABLED` (hide when off) and admin-role-gated for the fulfillment board.

**Acceptance Criteria**
- Admin can drive an order through legal transitions (illegal targets disabled), add/remove adjustments, and manage ship groups, with the timeline updating without reload.
- Customer sees a read-only lifecycle timeline and can self-cancel a pre-approval order.
- Page/route/nav are flag-gated and role-gated; with the flag off they are not reachable.

**Dependencies**
- ORD-013.

---

## Milestone 6 — Tests

### ORD-015: Hermetic backend + E2E tests
**Type:** Chore  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add hermetic offline pytest suites (`tests/test_ord_lifecycle.py`, `tests/test_ord_adjustments_shipgroups.py`, `tests/test_ord_cancel_refund.py`) using moto-bound frozen `T` handles (via `object.__setattr__`, per the CLAUDE.md test-isolation pattern) — no real AWS. Cover: transition matrix (legal/illegal), single-writer race, replay idempotency, status-history append, adjustment math + state-gating, ship-group fulfillment roll-up, and cancel/return refund (with `refund_payment`/`settle_or_reverse_ledger` patched, asserting exactly one refund ledger entry and idempotency).
- Add a golden-record test proving the order record is byte-for-byte identical with `ORDER_LIFECYCLE_ENABLED` off (additive-safety guarantee).
- Add `frontend/e2e/order-lifecycle.spec.ts` covering admin transition through the board, customer timeline, an adjustment, and a self-cancel, using the seeded admin session (`e2e_admin_session_setup.py`) + CSRF patterns from CLAUDE.md / MEMORY.md.

**Acceptance Criteria**
- All pytest suites pass offline with no network/AWS; the golden-record flag-off test confirms zero behavior change.
- E2E suite passes under the standard 1-worker Playwright config and covers transition + adjustment + cancel.
- CI green across unit + E2E for the module.

**Dependencies**
- ORD-007, ORD-010, ORD-011, ORD-012, ORD-014.

---
