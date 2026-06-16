# Fixed Assets / Maintenance — Implementation Tickets

This backlog implements OFBiz's **FixedAsset** application on the testlogon stack: a fixed-asset register, a straight-line **depreciation** schedule that posts to the double-entry GL, and basic **maintenance work orders** against assets. It is the final (Phase N) module of the full OFBiz buildout (`docs/ofbiz-full-buildout-plan.md` line 50/153) and is entirely additive + flag-gated — with `FIXED_ASSETS_ENABLED` off, the existing shop/cart/orders/billing/inventory/GL paths are byte-for-byte unchanged. Depreciation posts into the GL via the same DERIVE-from-the-ledger contract as Accounting (`OFBIZ_COMMERCE_TICKETS.md` M4 / OFB-013/014); any asset disposal that returns money reuses `refund_payment`/`settle_or_reverse_ledger` — billing is never forked.

## Milestone 1 — Scaffolding & Data Model

### FXA-001: Fixed-assets scoping spike & GL-touchpoint delta
**Type:** Spike  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Confirm the FixedAsset scope per `docs/ofbiz-full-buildout-plan.md` line 50 (Asset Maintenance / FixedAsset = IN, built last): register, straight-line depreciation, basic maintenance work orders. Explicitly DEFER declining-balance/units-of-production depreciation, asset revaluation, lease accounting, and multi-currency.
- Map the accounting touchpoints the module must hook: the single-entry ledger `new_ledger_entry` (`app/services/billing_shared.py:224`) with its `ledger_date` denorm (`app/services/billing_shared.py:253`, `ledger_date_for_ts` at `:10`), and the double-entry GL that derives from it (`OFBIZ_COMMERCE_TICKETS.md` OFB-013 chart of accounts `app/services/gl_accounts.py`, OFB-014 `app/services/gl_posting.py`). Document that depreciation is a **non-cash** internal journal (Dr Depreciation Expense / Cr Accumulated Depreciation) that does NOT flow through `billing_shared` (no money moves), and so must post directly to the GL journal as a non-ledger-derived entry while still balancing (Σdr == Σcr) and being idempotent per period.
- Map asset-acquisition + disposal money flows: acquisition optionally references an existing purchase/payout; disposal-with-proceeds money-out reuses `refund_payment`/`settle_or_reverse_ledger` (`app/routers/billing.py:1287`) — never a parallel mechanism (plan line 108).
- Define the new DynamoDB tables, GSIs (with numeric `attr_types`), settings keys, feature flags, and the new GL accounts the depreciation journal needs.

**Acceptance Criteria**
- A short design note enumerates in/out scope, the depreciation-journal account mapping, and the disposal money-out path, and is referenced by every downstream FXA ticket.
- Data-model delta lists each new table (PK/SK/GSIs, `attr_types` for numeric keys), new `app/models.py` shapes, and new `app/core/settings.py` keys/flags.
- Reviewer (eng + finance) signs off that depreciation posts a balanced non-cash journal and that disposal proceeds reuse the existing refund path.

**Dependencies**
- None.

---

### FXA-002: Settings, feature flags & table handles
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add `FIXED_ASSETS_ENABLED` (master, default off) plus `FIXED_ASSETS_DEPRECIATION_POSTING_ENABLED` (default off) and `FIXED_ASSETS_DEPRECIATION_POLL_INTERVAL` (default 86400s) to `app/core/settings.py`, following the existing flag pattern (e.g. `inventory_reservations_enabled` at `app/core/settings.py:839`). All read through the `S` singleton; all gates default disabled.
- Add table-name settings (`fixed_assets_table_name`, `fixed_asset_schedule_table_name`, `maintenance_orders_table_name`) and wire handles in `app/core/tables.py` (`T.fixed_assets`, `T.fixed_asset_schedule`, `T.maintenance_orders`) using the existing `_safe_table(S.<name>)` pattern (mirrors `inventory=_safe_table(S.inventory_table_name)` at `app/core/tables.py:569`).

**Acceptance Criteria**
- New flags resolve through `S` and default to `False`/disabled.
- `from app.core.tables import T` exposes the three new handles without error.
- A smoke pytest asserts each handle resolves and each flag defaults off.

**Dependencies**
- FXA-001.

---

### FXA-003: DynamoDB tables (assets, depreciation schedule, work orders)
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add three `TableDef` entries to `scripts/local-ddb-init.py` (following the `TableDef`/`_resolve_table_name` convention at `scripts/local-ddb-init.py:29`/`:38`):
  - **fixed_assets**: PK `pk="ASSET#{asset_id}"`, SK `sk="META"`; GSI `GSI_OWNER` (`owner_sub` / `acquired_at` numeric) for per-owner listing; GSI `GSI_STATUS` (`status` / `acquired_at` numeric) for active/disposed filtering. Declare `attr_types={"acquired_at": "N"}` (per the CLAUDE.md numeric-GSI gotcha).
  - **fixed_asset_schedule**: PK `pk="ASSET#{asset_id}"`, SK `sk="PERIOD#{period:07d}"` (one row per depreciation period, sortable); GSI `GSI_DUE` (`schedule_status` / `period_end_ts` numeric) so the poster can find due-but-unposted periods. Declare `attr_types={"period_end_ts": "N"}`.
  - **maintenance_orders**: PK `pk="ASSET#{asset_id}"`, SK `sk="WO#{work_order_id}"`; GSI `GSI_WO_STATUS` (`wo_status` / `created_at` numeric) for the open-work-order queue; GSI `GSI_WO_ASSIGNEE` (`assignee_sub` / `created_at` numeric). Declare `attr_types` for both numeric sort keys.
- All three behind the `FIXED_ASSETS_ENABLED` table set (created at stack init regardless, but unused until flag on — matches the additive convention).

**Acceptance Criteria**
- `just restart` recreates the three tables with no `ValidationException` (numeric GSI sort keys honored).
- Each GSI is queryable with integer sort-key values in a smoke test.
- With `FIXED_ASSETS_ENABLED=false`, no existing table definition changes.

**Dependencies**
- FXA-002.

---

### FXA-004: Pydantic models for assets, schedules & work orders
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add request/response models to `app/models.py` (alongside the existing commerce/inventory shapes, e.g. catalog stock fields near `app/models.py:546`):
  - `FixedAssetIn`/`FixedAssetOut`: `asset_id`, `name`, `asset_class` (e.g. equipment/furniture/software), `acquisition_cost_cents`, `salvage_value_cents`, `useful_life_months`, `acquired_at` (ts), `depreciation_method="straight_line"` (only value for now), `status` (`active`/`fully_depreciated`/`disposed`), `accumulated_depreciation_cents`, `net_book_value_cents` (derived), `gl_asset_account_id`, `gl_accum_depr_account_id`, `gl_depr_expense_account_id`.
  - `DepreciationPeriodOut`: `period`, `period_start_ts`, `period_end_ts`, `amount_cents`, `schedule_status` (`scheduled`/`posted`), `journal_entry_id` (nullable), `posted_at`.
  - `MaintenanceOrderIn`/`MaintenanceOrderOut`: `work_order_id`, `asset_id`, `title`, `description`, `wo_status` (`open`/`in_progress`/`completed`/`cancelled`), `assignee_sub`, `cost_cents` (optional), `scheduled_for` (ts), `created_at`, `completed_at`.
- Use integer-cents money fields and `now_ts()` integer timestamps throughout (consistent with `billing_shared` / `app/core/time.py:2`).

**Acceptance Criteria**
- Models validate required fields and reject negative cost/life values.
- `net_book_value_cents` is computed as `acquisition_cost_cents - accumulated_depreciation_cents` and never below `salvage_value_cents`.
- `depreciation_method` accepts only `straight_line` (others → 422).

**Dependencies**
- FXA-001.

---

## Milestone 2 — Asset Register

### FXA-005: Fixed-asset register service (CRUD)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/services/fixed_assets.py` with `create_asset`, `get_asset`, `list_assets(owner_sub|status, cursor)`, `update_asset`, and `dispose_asset` against `T.fixed_assets`.
- Use deterministic-id idempotency for creation (`asset_id = sha256(correlation_id)` per plan line 110) so a retried create never double-registers an asset.
- Emit audit events on create/update/dispose via `app/services/alerts.audit_event` (`app/services/alerts.py:644`), mirroring the commerce-service audit pattern.
- All writes gated by `FIXED_ASSETS_ENABLED`; with the flag off the service is import-safe but never invoked from any active path.

**Acceptance Criteria**
- Create/get/list/update round-trip; list paginates via the cursor pattern (`app/core/cursor.py`) over `GSI_OWNER`/`GSI_STATUS`.
- Re-issuing a create with the same `correlation_id` returns the existing asset (idempotent), writing no duplicate.
- Every mutating call writes one audit event with before/after where applicable.

**Dependencies**
- FXA-003, FXA-004.

---

### FXA-006: Straight-line depreciation schedule generation
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- In `app/services/fixed_assets.py`, add `generate_schedule(asset_id)` that computes a straight-line schedule from `(acquisition_cost_cents - salvage_value_cents) / useful_life_months`, writing one `fixed_asset_schedule` row per month (`sk="PERIOD#{period:07d}"`) with `schedule_status="scheduled"`, `period_end_ts`, and `amount_cents`.
- Handle integer-cents rounding so the sum of all period amounts exactly equals the depreciable base (last period absorbs the remainder — no fractional-cent drift).
- Re-generating an existing schedule is idempotent: scheduled (un-posted) rows are recomputed in place; already-`posted` periods are never altered.

**Acceptance Criteria**
- For a fixture asset, the schedule has `useful_life_months` rows whose `amount_cents` sum to `cost - salvage` exactly (rounding remainder lands on the final period).
- Regenerating after some periods are posted leaves posted rows untouched and only updates remaining scheduled rows.
- pytest covers even and uneven (remainder) divisions and the salvage floor.

**Dependencies**
- FXA-005.

---

### FXA-007: Asset register router
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Create `app/routers/fixed_assets.py` with `require_admin_session`-gated CRUD (`POST/GET /ui/fixed-assets`, `GET/PATCH /ui/fixed-assets/{asset_id}`, `POST /ui/fixed-assets/{asset_id}/dispose`) and `GET /ui/fixed-assets/{asset_id}/schedule`.
- Register the router in `app/main.py` next to the other commerce/accounting routers (follow the `app.include_router(...)` block near `app/main.py:961`). Guard every handler behind `FIXED_ASSETS_ENABLED` (503 when off).
- Declare any literal sub-paths (e.g. a future `/fixed-assets/classes`) BEFORE `/{asset_id}` so FastAPI's declaration-order matching doesn't capture them as the path param (per the CLAUDE.md `/schedules`-before-`/{id}` gotcha).

**Acceptance Criteria**
- All endpoints return 503 when `FIXED_ASSETS_ENABLED=false` and function when on; non-admin → 403.
- Creating an asset then GETting it returns the persisted record incl. derived `net_book_value_cents`.
- `GET /{asset_id}/schedule` returns the generated periods newest-or-oldest-first per spec.

**Dependencies**
- FXA-005, FXA-006.

---

## Milestone 3 — Depreciation → GL Posting

### FXA-008: Depreciation GL accounts seed
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Extend the OFB-013 chart-of-accounts seed (`app/services/gl_accounts.py`) with the three accounts depreciation needs: **Fixed Assets** (asset, debit-normal), **Accumulated Depreciation** (contra-asset, credit-normal), and **Depreciation Expense** (expense, debit-normal). Seed idempotently alongside the existing default accounts.
- Persist the resolved account ids onto each asset (`gl_asset_account_id`/`gl_accum_depr_account_id`/`gl_depr_expense_account_id`) at registration (default from the seeded accounts, overridable per asset).

**Acceptance Criteria**
- The three accounts seed exactly once (idempotent) with correct class + normal-balance side.
- A newly created asset carries the three resolved GL account ids.
- pytest asserts seed idempotency and account normal-balance sides.

**Dependencies**
- FXA-005, OFB-013 (chart of accounts).

---

### FXA-009: Depreciation journal posting (non-cash, balanced, idempotent)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Add `post_depreciation_period(asset_id, period)` to `app/services/fixed_assets.py` that posts a balanced non-cash journal entry **directly to the GL journal** (the OFB-014 `app/services/gl_posting.py` journal store): **Dr Depreciation Expense / Cr Accumulated Depreciation** for the period's `amount_cents`. This is NOT a money movement, so it does NOT call `billing_shared.new_ledger_entry` — it is a GL-internal entry, distinct from the ledger-DERIVED entries (FXA-001 note), but it MUST balance (Σdr == Σcr) and reuse the same journal shape/validation so trial balance (OFB-016) stays consistent.
- Idempotency: deterministic journal id per `(asset_id, period)` with a conditional put (`attribute_not_exists`) so re-posting a period is a no-op; on success, flip the schedule row to `schedule_status="posted"` and back-write `journal_entry_id`/`posted_at`, and increment the asset's `accumulated_depreciation_cents` via a conditional update.
- When the final period posts (or accumulated == depreciable base), flip asset `status="fully_depreciated"`.

**Acceptance Criteria**
- Each posted period produces exactly one balanced journal entry on the correct three accounts; an unbalanced mapping fails loudly and persists nothing.
- Re-posting the same period writes no second journal entry and does not double-increment accumulated depreciation (idempotent compare-and-set).
- After all periods post, the asset is `fully_depreciated` and `net_book_value_cents == salvage_value_cents`.
- Posted depreciation appears in the OFB-016 trial balance and keeps it balanced.

**Dependencies**
- FXA-006, FXA-008, OFB-014 (journal store).

---

### FXA-010: Depreciation poster background loop
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add `run_depreciation_poster_loop()` + `start_depreciation_poster_task()` (gated on `FIXED_ASSETS_ENABLED && FIXED_ASSETS_DEPRECIATION_POSTING_ENABLED`) and register it in `app/main.py` next to the other background-task startup hooks (mirror `start_compute_billing_timer_task` / `start_k8s_ttl_checker_task` registration).
- The loop queries `fixed_asset_schedule.GSI_DUE` for `schedule_status="scheduled"` rows with `period_end_ts <= now_ts()` and calls `post_depreciation_period` for each, looping over `LastEvaluatedKey` (per the CLAUDE.md "FilterExpression doesn't reduce page size" gotcha) so a busy index never silently drops due periods. Interval = `S.fixed_assets_depreciation_poll_interval` (default 86400s).
- Same DDB code path in dev (moto) and prod (SECOPS-007 parity) — no `dev_mode` branch.

**Acceptance Criteria**
- With both flags on, due periods post within one poll cycle; with either flag off, the loop is not started.
- The poster is idempotent across restarts (re-running posts nothing already posted, via FXA-009's conditional put).
- A period not yet due (`period_end_ts > now`) is skipped until its due time.

**Dependencies**
- FXA-009.

---

### FXA-011: Asset disposal with proceeds via existing refund path
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Extend `dispose_asset` (FXA-005) so disposal posts the closing journal: remove the asset cost and its accumulated depreciation, and book any gain/loss on disposal to a Gain/Loss-on-Disposal account (seed it in FXA-008's extension). When disposal returns money to a counterparty, route the money-out through the existing `refund_payment`/`settle_or_reverse_ledger` path (`app/routers/billing.py:1287`) — never a parallel mechanism (plan line 108) — so provider attribution and the platform financial dashboard stay correct (FIN-013).
- Disposal is idempotent (deterministic disposal-journal id); a disposed asset cannot be re-disposed or further depreciated (remaining scheduled periods are cancelled).

**Acceptance Criteria**
- Disposing a partially-depreciated asset books a balanced closing journal (asset out, accum-depr out, gain/loss plug) and the trial balance stays balanced.
- A disposal with cash proceeds creates exactly one refund/ledger entry via the existing billing path (no forked refund).
- Re-disposing an already-disposed asset is a no-op (idempotent); its remaining scheduled depreciation periods are marked cancelled and never post.

**Dependencies**
- FXA-009, OFB-010 (refund path) / `refund_payment`.

---

## Milestone 4 — Maintenance Work Orders

### FXA-012: Maintenance work-order service & lifecycle
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add work-order CRUD + lifecycle to `app/services/fixed_assets.py` (or a sibling `app/services/asset_maintenance.py`): `create_work_order`, `list_work_orders(asset_id|wo_status|assignee, cursor)`, `transition_work_order(wo_id, target)` enforcing `open → in_progress → completed` (and `→ cancelled` from open/in_progress), against `T.maintenance_orders`.
- Validate the asset exists and is not `disposed`; illegal transitions → 409; deterministic `work_order_id` for idempotent creation. Emit audit events on create/transition (`alerts.audit_event`).
- Optional `cost_cents` on completion is recorded on the work order for reporting (no GL posting in this milestone — maintenance expense capitalization is OUT of scope per FXA-001).

**Acceptance Criteria**
- Create/list/transition round-trip; the open-work-order queue lists via `GSI_WO_STATUS`.
- Illegal transitions (e.g. `completed → open`) return 409; transitions are audited.
- A work order against a disposed asset is rejected.

**Dependencies**
- FXA-005, FXA-003.

---

### FXA-013: Maintenance work-order router
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Add maintenance endpoints to `app/routers/fixed_assets.py` (`require_admin_session`): `POST /ui/fixed-assets/{asset_id}/work-orders`, `GET /ui/fixed-assets/{asset_id}/work-orders`, `PATCH /ui/fixed-assets/work-orders/{work_order_id}` (transition/assign), and a queue endpoint `GET /ui/fixed-assets/work-orders?status=open`.
- Declare the literal `/work-orders` queue route BEFORE any `/{asset_id}`-style dynamic capture to avoid the FastAPI declaration-order capture pitfall (CLAUDE.md). Guard all behind `FIXED_ASSETS_ENABLED`.

**Acceptance Criteria**
- All endpoints 503 when the flag is off; admin-gated when on (non-admin → 403).
- Creating then transitioning a work order reflects the new `wo_status` on GET.
- The queue endpoint returns only open/in-progress orders, paginated.

**Dependencies**
- FXA-012, FXA-007.

---

## Milestone 5 — Frontend

### FXA-014: Frontend types & endpoint wrappers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Add TypeScript interfaces mirroring the FXA-004 models to `frontend/src/api/types.ts` (`FixedAsset`, `DepreciationPeriod`, `MaintenanceOrder`).
- Add `frontend/src/api/endpoints/fixedAssets.ts` wrapping the FXA-007/FXA-013 endpoints via the shared axios instance (`frontend/src/api/client.ts`), with React Query-friendly fetchers.

**Acceptance Criteria**
- Types compile and match the backend response shapes.
- Endpoint wrappers send the CSRF header on non-GET calls (via the shared client) and are covered by a type-check build.

**Dependencies**
- FXA-007, FXA-013.

---

### FXA-015: Fixed-assets admin page (register + depreciation + work orders)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add a fixed-assets admin page under `frontend/src/pages/shop/admin/` (alongside `AdminCatalog.tsx`, where the inventory/returns admin UIs live): an asset register table (name, class, cost, accumulated depreciation, net book value, status) with a create/edit dialog, a per-asset depreciation-schedule drawer (periods + posted/journal-entry drill-through), and a maintenance work-order tab with the open-WO queue and a create/transition dialog.
- Use React Query (`useQuery`/`useMutation`) and shadcn/ui primitives per the frontend conventions; the depreciation drawer reads `GET /{asset_id}/schedule`.

**Acceptance Criteria**
- Admin can register an asset, view its generated depreciation schedule, see posted periods linked to their journal entry, and manage work orders without reload.
- Net book value updates after a depreciation period posts.
- All actions are admin/root-gated.

**Dependencies**
- FXA-014.

---

### FXA-016: Route + navigation (flag-gated)
**Type:** Feature  
**Priority:** P2  
**Estimate:** 1 day

**Description**
- Add the `/fixed-assets` route to `frontend/src/App.tsx` (lazy-loaded) and a nav entry in the admin sidebar (`frontend/src/components/layout/`), both rendered only when the `FIXED_ASSETS_ENABLED` flag is exposed to the frontend (mirror how other flag-gated admin pages are conditionally shown).
- With the flag off, neither the route nor the nav entry appears; existing nav is unchanged.

**Acceptance Criteria**
- Navigating to `/fixed-assets` renders the page when the flag is on; the nav entry is visible only then.
- With the flag off, the route/nav are absent and no existing route/nav changes.

**Dependencies**
- FXA-015.

---

## Milestone 6 — Tests

### FXA-017: Hermetic offline unit + E2E tests
**Type:** Chore  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add hermetic offline pytest suites (moto-bound frozen `T` handles patched via `object.__setattr__`, no real AWS, frozen `S` flags flipped per-test — following the CLAUDE.md regression-test pattern):
  - `tests/test_fxa_register.py`: create/get/list/update/dispose + create idempotency.
  - `tests/test_fxa_depreciation.py`: schedule generation (even/uneven/salvage-floor), balanced journal posting, posting idempotency (no double-increment), fully-depreciated transition, NBV == salvage at end, and trial-balance stays balanced after posting (against an OFB-014/016 in-memory GL).
  - `tests/test_fxa_disposal.py`: balanced closing journal, gain/loss plug, disposal-with-proceeds reuses the patched `refund_payment` (assert no forked refund), and disposal idempotency.
  - `tests/test_fxa_work_orders.py`: lifecycle transitions, illegal-transition 409, disposed-asset rejection.
- Add `frontend/e2e/fixed-assets.spec.ts` (seeded admin session + CSRF per CLAUDE.md/MEMORY.md): register an asset, view its depreciation schedule, post/observe a period, and create + complete a work order.

**Acceptance Criteria**
- Unit suites cover schedule math, balanced + idempotent depreciation posting, disposal (incl. refund-path reuse), and work-order lifecycle; all run offline with no real AWS/network.
- E2E covers register → schedule → post → work-order under the standard 1-worker Playwright config.
- With `FIXED_ASSETS_ENABLED=false`, a regression test asserts the depreciation poster never starts and no FXA endpoint is reachable (existing paths unchanged).

**Dependencies**
- FXA-009, FXA-011, FXA-012, FXA-015.

---
