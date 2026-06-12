# WOV — Maintenance Work Orders & Vendors (gap analysis §C)

Source gap analysis: `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §C
("Work Orders + Vendors + Policy + Documents"). open-property
([clawnify/open-property](https://github.com/clawnify/open-property)) ships a
property-maintenance **Work Order** entity (title/description/priority/status +
property/unit/vendor links + scheduled date + cost) and a trade-categorized
**Vendor** directory. The gap analysis scores this domain as **~70% reuse**: the
workflow machinery already exists or is fully specced.

- **Work orders** map onto the planned maintenance-work-order spec
  (`docs/ofbiz/specs/FXA-012.md` — `create_work_order`/`transition_work_order` +
  the `open → in_progress → completed (/cancelled)` state machine) and the
  ticket system's board/status-index idiom (`app/services/tickets.py`
  `_DEFAULT_BOARD_COLUMNS` / `_STATUS_TRANSITIONS`). The gap is `priority`, the
  property/unit FKs, and the vendor FK — additive fields on a property-scoped
  variant of FXA-012.
- **Paid maintenance** maps onto the bounty/escrow model
  (`docs/ticket-bounty/specs/TBT-001.md` escrow row + TBT-006 release / TBT-007
  refund) — a work order can carry an escrowed dollar amount paid out to the
  vendor on completion.
- **Vendor directory** is the PUR-003 supplier party model
  (`docs/ofbiz/specs/PUR-003.md` — `create_supplier`/`set_supplier_status` +
  `GSI_STATUS`) plus a trade-category enum and work-order assignment.

These five tickets cover ONLY the work-order entity + CRUD/assignment/scheduling/
cost (WOV-001/002), optional escrowed paid maintenance (WOV-003), the
trade-categorized vendor directory (WOV-004), and the FE + tests (WOV-005). The
rent ledger, lease, tenant, property/unit entities, rent-policy settings, document
links, and portfolio dashboard are out of scope (separate clusters — PROP-*,
TENANTS-*, LEASES-*, and the gap analysis §B rent ledger). This cluster **depends
on PROP** (`docs/open-property/PROPERTY_UNITS_TICKETS.md` — Property + Unit) for
the `property_id` / `unit_id` FK targets.

## Cross-cutting constraints (apply to every WOV ticket)

- **Additive + flag-gated, default OFF.** A new master flag
  `MAINTENANCE_ORDERS_ENABLED` (env, default `false`) gates the whole vertical.
  Mirror the `INVENTORY_RESERVATIONS_ENABLED` contract: a service-level
  `_flag_on()` / `_require_enabled()` raising **404** when off, exactly like
  `app/services/inventory.py:50-56` and the FXA-012 `_require_enabled()`
  (`docs/ofbiz/specs/FXA-012.md` §4.2 — note FXA-012 raises 503; WOV mirrors the
  inventory **404** form for parity with the PROP cluster). Routers are always
  mounted; every handler is a no-op until opt-in. With the flag off the platform
  is byte-for-byte unchanged.
- **Single-table DynamoDB, header row per work order.** Follow the FXA-012
  `maintenance_orders` shape (`docs/ofbiz/specs/FXA-012.md` §3.1) but re-key the
  partition for property scoping: `maintenance_orders` table, PK
  `pk="PROPERTY#{property_id}"`, SK `sk="WO#{work_order_id}"` — one row per work
  order, co-located under the owning property's partition for cheap
  per-property queue scans (same header-per-row idiom as FXA-012, re-anchored on
  property instead of asset).
- **Reuse the ticket lifecycle dict, never fork.** The state machine
  `open → assigned → in_progress → completed (/cancelled)` is a service-level
  `VALID_TRANSITIONS: dict[str, set[str]]` constant mirroring
  `app/services/tickets.py:30-40` (`_STATUS_TRANSITIONS`) and FXA-012 §5.5.
  Illegal transitions raise **409 `illegal_transition`**; the optimistic
  `ConditionExpression="wo_status = :current"` guard maps to **409
  `concurrent_transition`** (FXA-012 §5.4).
- **Reuse the ticket board columns for tabbed status views.** The FE Kanban
  re-skins the work-order statuses using the
  `app/services/tickets.py:61-70` `_DEFAULT_BOARD_COLUMNS` / `default_board_columns()`
  pattern (display-only relabelings over a `status_key`) — no new board engine.
- **`attr_types` for numeric GSI keys.** Numeric GSI sort keys (`created_at`,
  `scheduled_for`) MUST be declared in the `TableDef` `attr_types` map per the
  CLAUDE.md DynamoDB numeric-GSI gotcha (omitting it stores the value as String →
  `ValidationException`). Pattern: `scripts/local-ddb-init.py` `TableDef(...)`
  with `attr_types={"created_at": "N"}` (FXA-012 §3.1 / PUR-003 §2.5).
- **Reuse primitives.** Deterministic ids via
  `hashlib.sha256(corr.encode())[:32]` (`app/services/commerce_order_service.py:64-67`,
  FXA-012 §2.5); `now_ts()` (`app/core/time.py:2`); cursor pagination
  (`app/core/cursor.py:94,103`); `_audit()` best-effort lazy-import wrapper
  (`app/services/inventory.py:92-98`, FXA-012 §2.8); `_to_int` Decimal coercion
  (PUR-003 §2.7 / FXA-012 §5.6); table handles via `T.*` (`app/core/tables.py`).
- **Auth split.** Reads → `require_ui_session` (`app/services/sessions.py`, as
  `app/routers/tickets.py:19` uses); mutations → `require_admin_or_root_csrf`
  (`app/auth/policy.py:100`) — staff-only for create/assign/schedule/transition.
  Same split as `app/routers/inventory.py`.
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business
  logic; the same `T.*` handles in both environments (moto intercepts boto3 in
  dev, real DynamoDB in prod). Mirrors FXA-012 §7.1 and PUR-003 §7.
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via
  `object.__setattr__`), frozen `S` flags toggled via `object.__setattr__`,
  service functions / route coroutines called directly — no `TestClient`, no
  real AWS. Mirrors FXA-012 §9.1 and PUR-003 §9.1.

---

### WOV-001: Work-order entity — model, table, flag, create + read service

**Type**: Feature
**Priority**: P1
**Estimate**: 2d

**Description**

Land the property maintenance work-order data model, its DynamoDB table, the
master feature flag, and the create/read service primitives — the foundation
every other WOV ticket depends on. This is a property-scoped variant of the
planned FXA-012 maintenance-work-order service (`docs/ofbiz/specs/FXA-012.md`):
same lifecycle/idempotency/audit machinery, but re-anchored on `property_id`
(not `asset_id`) and extended with `priority` + `unit_id` + `vendor_id` FKs.

New module `app/services/maintenance_orders.py` (sibling pattern to
`app/services/suppliers.py` and FXA-012's `asset_maintenance.py`). New master flag
`S.maintenance_orders_enabled` (env `MAINTENANCE_ORDERS_ENABLED`, default `false`)
+ setting `S.maintenance_orders_table_name` (default `"maintenance_orders"`) added
to `app/core/settings.py` (mirror the `inventory_reservations_enabled` block, FXA-012
§6). `T.maintenance_orders` handle wired in `app/core/tables.py` via
`_safe_table(S.maintenance_orders_table_name)` (FXA-012 §2.4).

DDB table `maintenance_orders` (PK=`pk`, SK=`sk`), `TableDef` added to
`scripts/local-ddb-init.py` (FXA-012 §3.1 fragment, re-keyed for property scope):

| Attribute | Type | Notes |
|---|---|---|
| `pk` | S | `"PROPERTY#{property_id}"` — partition key (property-scoped, vs FXA-012's `ASSET#`) |
| `sk` | S | `"WO#{work_order_id}"` — sort key |
| `work_order_id` | S | `sha256(corr)[:32]`, `corr = correlation_id or f"wo:{actor_sub}:{uuid4().hex}"` (FXA-012 §2.5) |
| `property_id` | S | Denormalized FK → PROP property (`PROPERTY_UNITS_TICKETS.md` PROP-001) |
| `unit_id` | S | Optional FK → PROP unit (`UNIT#{unit_id}` row, PROP-002); null = property-level WO |
| `vendor_id` | S | Optional FK → WOV-004 vendor (`supplier_id`); set via WOV-002 assignment |
| `title` | S | Short description (1–200 chars) |
| `description` | S | Optional full details (max 2000 chars) |
| `priority` | S | `"urgent"`/`"high"`/`"normal"`/`"low"` (default `"normal"`) — the gap-analysis §C MISSING field |
| `wo_status` | S | `"open"`/`"assigned"`/`"in_progress"`/`"completed"`/`"cancelled"`; `GSI_WO_STATUS` partition key |
| `scheduled_for` | N | Optional Unix timestamp; when maintenance is planned (FXA-012 §3.1) |
| `cost_cents` | N | Optional; recorded on completion (FXA-012 §3.1, reporting only — no GL/ledger write) |
| `assignee_sub` | S | Optional staff sub; `GSI_WO_ASSIGNEE` partition key (sparse) |
| `created_at` | N | `now_ts()`; `GSI_WO_STATUS`/`GSI_WO_ASSIGNEE` sort key |
| `updated_at` | N | set on every mutation |
| `completed_at` | N | null until `completed` |
| `correlation_id` | S | idempotency key, stored for audit |

GSIs (FXA-012 §3.1, both share numeric `created_at` sort key →
`attr_types={"created_at": "N"}` covers both):

| Index | PK | SK | Use |
|---|---|---|---|
| `GSI_WO_STATUS` | `wo_status` (S) | `created_at` (N) | system-wide status queue (drives the Kanban tabs) |
| `GSI_WO_ASSIGNEE` | `assignee_sub` (S) | `created_at` (N) | work orders by assignee |

New Pydantic models in `app/models.py` (FXA-012 §3.2 shapes + `priority` +
property/unit/vendor FKs): `MaintenanceOrderIn` (title, description?, priority?,
property_id, unit_id?, scheduled_for?, correlation_id?), `MaintenanceOrderOut`,
and (for WOV-002) `MaintenanceOrderTransitionIn` / `MaintenanceOrderAssignIn`.

Service functions delivered in this ticket:
- `create_work_order(property_id, body, actor_sub) -> MaintenanceOrderOut` —
  idempotent deterministic-id create with `attribute_not_exists(sk)` conditional
  put → fetch-and-return on `ConditionalCheckFailedException` (FXA-012 §5.1).
  Validates the property exists (lazy-import the PROP property service, raise
  404 `property_not_found`); validates `priority` ∈ the four-value enum (422 on
  bad value). Emits `_audit("maintenance_order.created", ...)`.
- `get_work_order(property_id, work_order_id) -> MaintenanceOrderOut | None`
  (FXA-012 §5.2).
- `_item_to_out(item)` with Decimal coercion on all numeric fields (FXA-012 §5.6).

Helpers `_flag_on()` / `_require_enabled()` (404), `_wo_pk` / `_wo_sk`, `_audit`,
`_to_int` all copied verbatim from the cited precedents.

**Acceptance Criteria**
- With `MAINTENANCE_ORDERS_ENABLED=false` (default), every service function raises
  `HTTPException(404)` at `_require_enabled()`; no DDB I/O; platform byte-for-byte
  unchanged.
- `create_work_order` is idempotent: same `correlation_id` → same `work_order_id`,
  exactly one `WO#` row, second call emits `maintenance_order.create.idempotent`.
- Created WO defaults `wo_status="open"`, `priority="normal"` (when omitted),
  `cost_cents`/`completed_at` absent; `work_order_id` is 32-char hex.
- Bad `priority` → 422; unknown `property_id` → 404 `property_not_found`.
- `get_work_order` round-trips the created item with numeric fields as `int` (not
  `Decimal`); unknown id → `None`.
- Hermetic pytest `tests/test_wov_001_work_orders.py` (moto-bound frozen
  `T.maintenance_orders`, frozen flag, `audit_event` mocked) covers create
  happy-path, idempotency, flag-off, priority/property guards, and get.

**Dependencies**
- PROP-001 / PROP-002 (`docs/open-property/PROPERTY_UNITS_TICKETS.md`) — provides
  the `property_id` / `unit_id` FK targets + the property-lookup service used by
  the create guard.
- Reuses (no new tickets): `tickets.py` lifecycle dict, `commerce_order_service`
  sha256 idempotency, `inventory._audit`, `cursor`, `now_ts`.

---

### WOV-002: Work-order lifecycle — assignment, scheduling, cost, status queue

**Type**: Feature
**Priority**: P1
**Estimate**: 2d

**Description**

Add the mutating lifecycle to `app/services/maintenance_orders.py`: assignment
(to a property/unit and to a vendor + optional staff `assignee_sub`), scheduling
(`scheduled_for`), cost recording (`cost_cents` on completion), the state-machine
transitions, and the paginated status/assignee queues that drive the tabbed
Kanban. Plus the router (`app/routers/maintenance_orders.py`) registered in
`app/main.py`.

State machine (`VALID_TRANSITIONS: dict[str, set[str]]`, mirroring
`app/services/tickets.py:30-40` + FXA-012 §5.5, extended with the `assigned`
state from open-property's WO flow):

```
VALID_TRANSITIONS = {
    "open":        {"assigned", "in_progress", "cancelled"},
    "assigned":    {"in_progress", "open", "cancelled"},
    "in_progress": {"completed", "cancelled"},
    "completed":   set(),   # terminal
    "cancelled":   set(),   # terminal
}
```

Service functions:
- `assign_work_order(property_id, work_order_id, *, vendor_id?, unit_id?, assignee_sub?, actor_sub)`
  — sets the vendor/unit/staff FKs, validates `vendor_id` resolves to an
  **active** vendor (lazy-import WOV-004 `get_vendor`; raise 404 if missing, 422
  if `status=="inactive"` — mirrors PUR-006's active-supplier guard, PUR-003
  §5.6), and (when `wo_status=="open"`) advances to `assigned`. Updates the
  `GSI_WO_ASSIGNEE` key. Emits `maintenance_order.assigned`.
- `schedule_work_order(property_id, work_order_id, scheduled_for, actor_sub)` —
  sets `scheduled_for` (any Unix ts; staff can reschedule freely). Emits
  `maintenance_order.scheduled`.
- `transition_work_order(property_id, work_order_id, body: MaintenanceOrderTransitionIn, actor_sub)`
  — FXA-012 §5.4 verbatim: fetch current, reject `target not in
  VALID_TRANSITIONS[current]` with **409 `illegal_transition`**; `update_item`
  with `ConditionExpression="wo_status = :current"` (→ **409
  `concurrent_transition`** on conflict); set `completed_at` + `cost_cents` on
  `completed`; optional reassignment. Emits `maintenance_order.{target}`.
- `list_work_orders(property_id?, wo_status?, assignee_sub?, cursor?, limit=50)`
  — FXA-012 §5.3 three-mode query: Mode A base table by `property_id` (bounded
  partition, optional `wo_status` FilterExpression), Mode B `GSI_WO_STATUS` queue
  (drives Kanban columns), Mode C `GSI_WO_ASSIGNEE`. Cursor pagination via
  `encode_cursor`/`decode_cursor`. No-filter call → 400 (no full scan).

Router endpoints (FXA-012 §4.3 surface, property-scoped; literal `/work-orders`
queue route declared **before** any `/{property_id}` dynamic capture per the
CLAUDE.md FastAPI declaration-order gotcha):

| Method | Path | Auth | Service |
|---|---|---|---|
| `POST` | `/ui/properties/{property_id}/work-orders` | `require_admin_or_root_csrf` | `create_work_order` (WOV-001) |
| `GET` | `/ui/properties/{property_id}/work-orders` | `require_ui_session` | `list_work_orders(property_id=...)` |
| `GET` | `/ui/maintenance/work-orders` | `require_ui_session` | `list_work_orders(wo_status=...)` (Kanban queue) |
| `PATCH` | `/ui/maintenance/work-orders/{work_order_id}/assign` | `require_admin_or_root_csrf` | `assign_work_order` (`property_id` from body) |
| `PATCH` | `/ui/maintenance/work-orders/{work_order_id}/schedule` | `require_admin_or_root_csrf` | `schedule_work_order` |
| `PATCH` | `/ui/maintenance/work-orders/{work_order_id}` | `require_admin_or_root_csrf` | `transition_work_order` (`property_id` from body, FXA-012 §10.5) |

`MaintenanceOrderTransitionIn` / `MaintenanceOrderAssignIn` carry
`property_id: str` (required) so the PATCH handlers can construct the DDB key
(FXA-012 §10.5 resolution).

**Acceptance Criteria**
- Valid transitions succeed and stamp `updated_at`/`completed_at`/`cost_cents`
  appropriately; illegal transitions → 409 `illegal_transition`; concurrent
  transition → 409 `concurrent_transition`.
- `assign_work_order` to an inactive vendor → 422; to a missing vendor → 404; a
  successful assign on an `open` WO advances it to `assigned` and indexes it on
  `GSI_WO_ASSIGNEE`.
- `schedule_work_order` persists `scheduled_for` and is re-callable (reschedule).
- `list_work_orders` returns reverse-`created_at` order, paginates via `cursor`,
  and supports all three filter modes; no-filter call → 400.
- All mutating endpoints are staff-only (non-admin → 403); reads work for any
  `require_ui_session` caller; CSRF enforced for cookie-auth mutations.
- Hermetic pytest `tests/test_wov_002_lifecycle.py` covers each transition, the
  vendor-active guard, scheduling, cost-on-complete, and the three list modes.

**Dependencies**
- WOV-001 (entity, table, flag, create/get).
- WOV-004 (vendor directory) for the `assign_work_order` active-vendor guard —
  build WOV-004 before the assign path, OR gate the vendor guard behind a
  `try/except ImportError` until WOV-004 lands (assignment to a staff sub still
  works without a vendor).

---

### WOV-003: Optional escrowed paid maintenance (bounty/escrow on a work order)

**Type**: Feature
**Priority**: P2
**Estimate**: 2d

**Description**

Let a work order carry an escrowed dollar amount that is funded when the WO is
posted and paid out to the assigned vendor on completion — reusing the Ticket
Bounty escrow/release model rather than building new money movement.
Sub-flag-gated and entirely additive: with the sub-flag off a work order is a
pure maintenance record (WOV-001/002 unchanged).

New sub-flag `S.maintenance_orders_escrow_enabled` (env
`MAINTENANCE_ORDERS_ESCROW_ENABLED`, default `false`) + bounded settings copied
from the TBT-001 block (`docs/ticket-bounty/specs/TBT-001.md` §1):
`maintenance_escrow_min_cents` (100), `maintenance_escrow_max_cents` (100000_00),
`maintenance_escrow_fee_bps` (0), `maintenance_escrow_payout_hold_seconds` (0).

Storage: reuse the **existing `T.billing` table** single-table escrow sentinel
exactly as TBT-001 §1 decides — escrow row keyed `pk="MAINT_ESCROW#{work_order_id}"`,
`sk="ESCROW"`, co-located with the per-user ledger entries (`pk=USER#{sub}`,
`sk=LEDGER#…`) so funding, refund, release, and audit all stay on one table with
**no new table and no new GSI** (TBT-001 §1 reuse rationale). The escrow row
carries `amount_cents`, `state` (`held`/`released`/`refunded`), `poster_sub`,
`vendor_sub`, `work_order_id`.

Service additions to `app/services/maintenance_orders.py` (thin wrappers over the
escrow primitives — reuse the TBT escrow service rather than reimplement):
- On `create_work_order` (WOV-001) with a non-null `amount_cents`: fund escrow via
  the TBT escrow `post_bounty`-equivalent (TBT-003 escrow service; lazy-import,
  hold from the poster's balance/ledger) and stamp `amount_cents` +
  `escrow_state="held"` on the WO row.
- On `transition_work_order(... target="completed")` (WOV-002): if the WO has a
  held escrow AND an assigned `vendor_id`, **release** escrow → vendor payout
  (TBT-006 release-on-approval flow; `docs/ticket-bounty/specs/TBT-006.md`),
  applying `maintenance_escrow_fee_bps` and `payout_hold_seconds`. Set
  `escrow_state="released"`.
- On `transition_work_order(... target="cancelled")`: if a held escrow exists,
  **refund** → poster (TBT-007 refund flow; `docs/ticket-bounty/specs/TBT-007.md`),
  set `escrow_state="refunded"`.

All escrow money movement delegates to the TBT escrow service primitives (which
own the `T.billing` ledger writes via `billing_shared.new_ledger_entry`) — WOV-003
adds no new ledger math, mirroring how FXA-012 §2.9 deliberately keeps `cost_cents`
as reporting-only metadata while this ticket adds the *optional* real escrow path.

**Acceptance Criteria**
- With `MAINTENANCE_ORDERS_ESCROW_ENABLED=false` (default), no escrow row is
  written and `create_work_order`/`transition_work_order` behave exactly as
  WOV-001/002; `amount_cents` is ignored/rejected.
- With the sub-flag on: posting a WO with `amount_cents` in `[min,max]` writes a
  `MAINT_ESCROW#{wo}` / `ESCROW` `held` row on `T.billing`; out-of-range → 422.
- Completing a WO with a held escrow + assigned vendor releases escrow to the
  vendor (fee_bps applied) and sets `escrow_state="released"`; completing with no
  assigned vendor → 409/422 (cannot pay out an unassigned WO).
- Cancelling a WO with a held escrow refunds the poster and sets
  `escrow_state="refunded"`; double-release/double-refund is prevented by the
  escrow `state` guard (TBT-006/007 conditional update).
- Hermetic pytest `tests/test_wov_003_escrow.py` (moto-bound `T.billing` +
  `T.maintenance_orders`, TBT escrow primitives exercised against moto) covers
  fund-on-post, release-on-complete, refund-on-cancel, and the no-vendor guard.

**Dependencies**
- WOV-001 + WOV-002 (work-order entity + completion/cancellation transitions).
- WOV-004 (vendor directory) — the payout target `vendor_sub` is the assigned
  vendor.
- Ticket Bounty escrow: TBT-001 (flag/settings/escrow-row decision), TBT-003
  (escrow service `post_bounty`), TBT-006 (release→assignee), TBT-007
  (refund→poster) — `docs/ticket-bounty/specs/TBT-00{1,3,6,7}.md`. If the TBT
  cluster is unbuilt, WOV-003 is a no-op behind its sub-flag and ships after TBT.

---

### WOV-004: Trade-categorized vendor directory (on the PUR-003 supplier model)

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

A vendor directory for property maintenance, built directly on the PUR-003
supplier party model (`docs/ofbiz/specs/PUR-003.md`) plus a trade-category enum
and a property-management framing. A "vendor" IS a PUR-003 supplier with a
`trade_category` attribute; we reuse the supplier service idempotency, soft
deactivation, and `GSI_STATUS` listing rather than building a parallel directory.

Decision (recorded here): rather than fork `app/services/suppliers.py`, WOV-004
adds a thin `app/services/maintenance_vendors.py` wrapper that **delegates to the
PUR-003 supplier service** (`create_supplier`/`update_supplier`/
`set_supplier_status`/`get_supplier`/`list_suppliers`, PUR-003 §4.1) and layers a
`trade_category` field + a property-management `source="maintenance_vendor"`
marker onto the supplier `address`/extra map. The vendor's `supplier_id` is the
FK stored on the work order (`vendor_id`, WOV-001/002). Gated by the WOV master
flag `MAINTENANCE_ORDERS_ENABLED` AND the PUR master flag
`purchasing_scm_enabled` (the underlying supplier table lives behind PUR — both
must be on; if PUR is unbuilt, see Dependencies for the standalone-table fallback).

Trade-category enum (gap analysis §C / open-property vendor trades):
`"plumbing"`, `"electrical"`, `"hvac"`, `"handyman"`, `"cleaning"`,
`"landscaping"`, `"general"`. Stored as a `trade_category` attribute on the
supplier row; validated in the service (422 on a non-enum value).

Service functions (delegating to PUR-003):
- `create_vendor(actor_sub, name, trade_category, *, email?, phone?, address?, ...)`
  — validates `trade_category`, then calls supplier `create_supplier` (PUR-003
  §5.1 deterministic idempotency `sha256("supplier:{user_sub}:{name}")[:32]`) and
  stamps `trade_category` + `source`. Idempotent per `(actor_sub, name)`.
- `get_vendor(vendor_id)` → supplier `get_supplier` projection + `trade_category`
  (used by WOV-002 `assign_work_order` active-vendor guard).
- `set_vendor_status(vendor_id, status, actor_sub)` — supplier
  `set_supplier_status` soft deactivation (PUR-003 §5.3); inactive vendors are
  excluded from the active list but remain valid historical FKs.
- `list_vendors(status="active", trade_category?, cursor?, limit?)` — supplier
  `list_suppliers` (PUR-003 §5.4 `GSI_STATUS` pagination) with an optional
  `trade_category` FilterExpression.

Router endpoints in `app/routers/maintenance_orders.py` (or a sibling
`maintenance_vendors` router), staff-only mutations / `require_ui_session` reads,
mirroring PUR-003 §9.2 surface but under `/ui/maintenance/vendors`.

**Acceptance Criteria**
- `create_vendor` validates `trade_category` ∈ the seven-value enum (422
  otherwise) and is idempotent per `(actor_sub, name)` (same `vendor_id`, one
  row) — inheriting PUR-003 §5.1 idempotency.
- `set_vendor_status("inactive")` excludes the vendor from
  `list_vendors(status="active")` but `get_vendor` still resolves it (soft
  deactivation, PUR-003 §5.3).
- `list_vendors(trade_category="plumbing")` returns only plumbing vendors;
  pagination via `cursor` works (PUR-003 §5.4).
- A work order can be assigned to a vendor by `vendor_id` (WOV-002
  `assign_work_order`); assignment to an inactive vendor → 422.
- All mutations staff-only (403 for non-admin); flag-off (master flag) → 404.
- Hermetic pytest `tests/test_wov_004_vendors.py` (moto-bound supplier table +
  frozen flags) covers trade-enum validation, idempotency, soft deactivation,
  and trade-filtered listing.

**Dependencies**
- PUR-003 (`docs/ofbiz/specs/PUR-003.md`) supplier party service + PUR-002 (table,
  `purchasing_scm_enabled` flag, `T.suppliers` handle). If the PUR cluster is
  unbuilt, WOV-004 falls back to a standalone `maintenance_vendors` DDB table
  cloning the PUR-003 `suppliers` schema (PK=`vendor_id`, SK=`META`, `GSI_STATUS`,
  `attr_types={"created_at":"N"}`) + an inlined copy of the supplier CRUD — same
  contract, separate table; the delegating wrapper is preferred when PUR exists.
- WOV-001 (master flag).

---

### WOV-005: Frontend — work-order Kanban board + vendor directory + E2E

**Type**: Feature
**Priority**: P2
**Estimate**: 2.5d

**Description**

The work-order and vendor UIs, wired to the WOV-002/004 endpoints, plus E2E
coverage. All gated by the `MAINTENANCE_ORDERS_ENABLED` surface (nav entries and
routes hidden / 404 when off).

Frontend (under `frontend/src/pages/maintenance/`, following the
`frontend/src/pages/tickets/` and `frontend/src/pages/shop/` conventions per
CLAUDE.md):
- **Work-order Kanban board** — a tabbed/columned status board re-skinning the
  WO statuses (`open`/`assigned`/`in_progress`/`completed`/`cancelled`) using the
  same column model as the ticket board (`app/services/tickets.py:61-70`
  `_DEFAULT_BOARD_COLUMNS` → mirror its display-only relabelings in the FE).
  Columns populated from `GET /ui/maintenance/work-orders?wo_status=…` per
  column. Cards show title, priority badge (urgent/high/normal/low),
  property/unit, assigned vendor, `scheduled_for`, and `cost_cents`. Drag/menu
  actions call the `PATCH .../{id}` transition + `/assign` + `/schedule`
  endpoints.
- **Work-order create/detail** — create dialog (title, description, priority,
  property+unit picker, optional `scheduled_for`, optional escrow `amount_cents`
  when the escrow sub-flag is on); detail drawer with the lifecycle timeline.
- **Vendor directory** — a trade-categorized vendor list (filter by
  `trade_category`), create/edit vendor dialog, and an active/inactive toggle
  (`set_vendor_status`). Vendors are selectable in the work-order assign action.

API wrappers in `frontend/src/api/endpoints/maintenance.ts` + TypeScript types in
`frontend/src/api/types.ts` (mirror `app/models.py` work-order/vendor shapes);
routes added to `frontend/src/App.tsx`; React Query for all server state per the
CLAUDE.md frontend conventions.

Tests:
- Hermetic pytest already covered per WOV-001..004; this ticket adds the
  integration round-trip `tests/test_wov_005_integration.py` (create → assign
  vendor → schedule → in_progress → complete with cost, via the route coroutines
  on a fresh event loop, moto-bound tables) and an escrow round-trip when the
  sub-flag is on.
- E2E spec `frontend/e2e/maintenance.spec.ts` (`injectAuth(page, "charlie_admin")`
  + CSRF header pattern per CLAUDE.md): work-order create, Kanban
  column moves through the lifecycle, vendor create + trade filter + assign,
  schedule, and complete-with-cost. Flag-off → routes 404 / nav hidden.

**Acceptance Criteria**
- Kanban renders one column per WO status with cards showing priority badge,
  property/unit, vendor, scheduled date, and cost; status changes via the UI hit
  the correct PATCH endpoints and re-render via React Query invalidation.
- Create dialog enforces priority/property selection; escrow `amount_cents` field
  appears only when the escrow sub-flag is on.
- Vendor directory lists/filters by trade category, supports create + edit +
  activate/deactivate, and vendors are selectable in the WO assign action.
- With `MAINTENANCE_ORDERS_ENABLED=false`, the maintenance nav + routes are hidden
  and the API returns 404.
- `frontend/e2e/maintenance.spec.ts` passes the full create→assign→schedule→
  in_progress→complete round-trip plus the vendor flows.

**Dependencies**
- WOV-002 (work-order CRUD/assign/schedule/transition endpoints + queue).
- WOV-004 (vendor directory endpoints).
- WOV-003 (escrow) — the escrow `amount_cents` field is conditional on the escrow
  sub-flag; the FE degrades gracefully when WOV-003 is unbuilt (field hidden).
- PROP-005 (`docs/open-property/PROPERTY_UNITS_TICKETS.md`) for the property/unit
  picker components reused in the WO create dialog.

---

## Dependency order

```
WOV-001 (entity + table + flag + create/get)   ← depends on PROP-001/002
   └─ WOV-002 (lifecycle: assign/schedule/cost/transition + queue + router)
        ├─ WOV-004 (vendor directory on PUR-003)   ← used by WOV-002 assign guard
        ├─ WOV-003 (optional escrowed paid maintenance)   ← depends on TBT-001/003/006/007
        └─ WOV-005 (FE Kanban + vendor directory + E2E)   ← depends on WOV-002/003/004, PROP-005
```

Build order: **WOV-001 → WOV-004 → WOV-002 → WOV-003 → WOV-005**. (WOV-004 is
pulled forward ahead of WOV-002's assign path so the active-vendor guard has a
real `get_vendor` to call; WOV-002 can otherwise ship with the vendor guard
behind a `try/except ImportError` and WOV-004 follows.)
