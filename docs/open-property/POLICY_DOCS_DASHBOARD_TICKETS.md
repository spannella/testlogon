# PMD — Rent-policy settings + document linking + portfolio dashboard (gap analysis §A/§C)

Source gap analysis: `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A
("Properties & Units + Portfolio Dashboard") and §C ("Work Orders + Vendors + Policy
+ Documents"). These five tickets cover the **extension layer** that sits on top of
the real-estate spine (PROP/Unit, TEN, LSE) and the rent-ledger / work-order clusters
(RNT, WOV): (1) a **rent-policy settings** entity — configurable per-landlord defaults
that leases inherit (gap analysis §C "Rent-policy settings … only global currency exists
— net-new entity"); (2) **document linking** — the EVT-011 record-link fields on
file-manager nodes so files attach to a property/unit/lease/tenant (gap analysis §C
"Documents linked to … EVT-011 record-link + EVT-012 revisions"); (3) a **portfolio
dashboard** KPI service + monthly rent snapshot + priority items (gap analysis §A rows
"Portfolio KPIs", "Monthly rent snapshot"); (4) the **frontend** dashboard page; and
(5) **tests + cross-module integration**.

These tickets do NOT (re-)build Property/Unit (PROP-001..005), Tenant (TEN-001..004),
Lease (LSE-001..004), the rent ledger (**RNT** cluster — gap analysis §B "Rent ledger
& collections"), or work orders (**WOV** cluster mirroring `FXA-004/012/013` — gap
analysis §C). PMD **consumes** their query surfaces:
- **PROP** (`app/services/property_mgmt.py`, table `properties`, `list_properties` /
  `compute_property_occupancy`, PROPERTY_UNITS_TICKETS §PROP-001/003) — occupancy +
  unit counts for the KPI dashboard.
- **LSE** (`app/services/leases.py`, table `leases`, `list_leases(status="active")` and
  `list_upcoming_expirations(within_days=…)`, LEASES_TICKETS §LSE-002/003) — active-lease
  count + upcoming-expiration priority items.
- **RNT** (planned rent-ledger cluster, gap analysis §B; rent charges posted via
  `billing_shared.new_ledger_entry` with `ledger_date`, same single-entry ledger as
  `app/services/platform_financial_dashboard.py`) — outstanding/collected/overdue rent
  totals via the ledger query pattern (`_iter_billing_entries`, `compute_due`).
- **WOV** (planned work-order cluster, gap analysis §C, mirrors `FXA-004/012/013`) —
  open-work-order counts. Until WOV lands, the work-order KPI is computed from the
  existing ticket system (`app/services/tickets.py`) filtered to property-linked tickets,
  behind the same flag (degrades to `0` cleanly).

## Cross-cutting constraints (apply to every PMD ticket)

- **Additive + flag-gated, default OFF.** A single master flag
  `PROPERTY_DASHBOARD_ENABLED` (default `false`) gates the policy-settings + dashboard
  surfaces; document linking reuses the EVT-011 flag `CRM_DOCUMENT_LIBRARY_ENABLED`
  (`docs/suitecrm/specs/EVT-011.md` §6, default off) **plus** a property-scoped
  `linked_record_type` extension. Mirror the `INVENTORY_RESERVATIONS_ENABLED` contract:
  `_flag_on()` / `_require_enabled()` raising **404** when off, exactly like
  `app/services/inventory.py:51-58` and `app/routers/inventory.py:32-38`. Routers are
  always mounted; every handler is a 404 no-op until opt-in. With the flags off the
  platform is byte-for-byte unchanged.
- **Reuse, never fork.** Policy-settings storage mirrors the runtime-override config-row
  idiom in `app/services/billing_config.py` (single partition, `sk=CURRENT`, audit rows
  at `sk=AUDIT#{ts}#{event_id}`, in-memory cache invalidated on write,
  `app/services/billing_config.py:9-16,38-58`). Document linking reuses the EVT-011
  service primitives verbatim (`update_crm_metadata` / `search_by_linked_record`,
  `docs/suitecrm/specs/EVT-011.md` §4.1). The dashboard KPI service mirrors the in-memory
  bucketing + ledger-scan strategy of `app/services/platform_financial_dashboard.py`
  (module docstring §"Aggregation strategy") and surfaces as an RPT-006/007 dashlet
  (`docs/suitecrm/specs/RPT-006.md` §3.2 dashlet schema; `docs/suitecrm/specs/RPT-007.md`
  §4.1 provider dispatch).
- **Reuse primitives.** `now_ts()` (`app/core/time.py:2`), cursor pagination
  (`app/core/cursor.py:94,103`), `_audit()` lazy-import wrapper
  (`app/services/inventory.py:92-98`), table handles via `T.*` (`app/core/tables.py`),
  `audit_event` (`app/services/alerts.py:644`). Auth: reads → `require_ui_session`
  (`app/services/sessions.py:330`); mutations → `require_admin_or_root_csrf`
  (`app/auth/policy.py:100`) — identical split to `app/routers/inventory.py:48,65,81`
  and PROP-004 (PROPERTY_UNITS_TICKETS §PROP-004 endpoint table).
- **Single-table DynamoDB + `attr_types` for numeric GSI keys.** The policy entity reuses
  the FAC/billing_config single-partition config-row shape (no new GSI). Any numeric GSI
  sort key (e.g. `created_at`) MUST be declared in the `TableDef` `attr_types` map per the
  CLAUDE.md DynamoDB numeric-GSI gotcha. DDB `FilterExpression` does not reduce page size —
  every cross-user sweep loops on `LastEvaluatedKey` (CLAUDE.md gotcha; mirrors
  `platform_financial_dashboard` scan + `csv_export._iter_billing_entries`).
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business logic; the
  same `T.*` handles in both environments (moto intercepts boto3 in dev, real DynamoDB in
  prod). Mirrors `billing_config.py` and `platform_financial_dashboard.py`.
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via `object.__setattr__`),
  frozen `S` flags, route coroutines called directly on a fresh
  `asyncio.new_event_loop()` — no `TestClient`, no real AWS. Mirrors RPT-006 §9.1 /
  EVT-011 §9.1.

Dependency order: **PMD-001** (policy entity) → **PMD-002** (document linking) →
**PMD-003** (KPI service) → **PMD-004** (FE dashboard page) → **PMD-005** (tests +
cross-module integration).

---

### PMD-001: Rent-policy settings entity — per-landlord configurable defaults + admin CRUD

**Type:** Feature | **Priority:** P1 | **Estimate:** 2d

**Description.**
Greenfield entity holding per-landlord (owner) rent-policy defaults that leases inherit:
`rent_due_day` (1–28), `late_fee_cents`, `grace_period_days`, and `currency`. Today only
a **global** default exists (`S.default_currency` = `"usd"`, `app/core/settings.py:325`;
`S.default_currency_code` = `840`, `:324`) — there is no per-owner policy. Model the
storage on the runtime-override config-row idiom in `app/services/billing_config.py`
(`:9-16` storage-keys docstring) but keyed per owner rather than a single global partition.

DDB — reuse a new `rent_policy` table (PK=`pk`, SK=`sk`), single-partition-per-owner:
- `pk = POLICY#{owner_sub}`, `sk = CURRENT` — the effective policy row.
- `pk = POLICY#{owner_sub}`, `sk = AUDIT#{ts:010d}#{event_id}` — one change-history row per
  mutation (mirrors `billing_config.py` audit-row layout `:11-13`).
- `TableDef(_resolve_table_name(S.rent_policy_table_name, "rent_policy"), "pk", "sk")` in
  `scripts/local-ddb-init.py` (no GSI; per-owner reads are a single `Key={pk,sk}` get or a
  `begins_with(sk, "AUDIT#")` query — no numeric GSI key, so no `attr_types` change).
- Settings (`app/core/settings.py`, after the `default_currency` block `:324-325`):
  `property_dashboard_enabled: bool = os.environ.get("PROPERTY_DASHBOARD_ENABLED","false").lower()=="true"`
  and `rent_policy_table_name: str = os.environ.get("RENT_POLICY_TABLE_NAME","rent_policy")`.
- `app/core/tables.py`: add `rent_policy: Any` field + `rent_policy=_safe_table(S.rent_policy_table_name)`.

Service `app/services/rent_policy.py` (new), modeled on `billing_config.py`:
- `_flag_on()` / `_require_enabled()` (404 when `property_dashboard_enabled` off; mirror
  `inventory.py:51-58`).
- `get_policy(owner_sub) -> dict` — read `sk=CURRENT`; if absent return the **effective
  default** (`rent_due_day=1`, `late_fee_cents=0`, `grace_period_days=0`,
  `currency=S.default_currency`) so leases always inherit a value (override-or-env, the
  `billing_config` "effective value" contract `:3-7`).
- `set_policy(owner_sub, *, rent_due_day, late_fee_cents, grace_period_days, currency, actor_sub) -> dict`
  — validate (`1 <= rent_due_day <= 28`; `late_fee_cents >= 0`; `grace_period_days >= 0`;
  `currency` lower-cased 3-letter code), `put_item` the CURRENT row stamping
  `updated_at=now_ts()`, write an AUDIT row, invalidate the in-memory cache (mirror
  `billing_config.invalidate_cache` `:54-58`), `_audit("rent_policy.updated", actor_sub, …)`.
- `list_policy_audit(owner_sub, *, limit, cursor)` — `begins_with(sk,"AUDIT#")` query,
  `encode_cursor`/`decode_cursor` paginated.
- In-memory per-owner cache with short TTL (`billing_config.py:46-58` pattern), invalidated on write.

Pydantic (`app/models.py`): `RentPolicyOut` (all four fields + `updated_at` + `is_default: bool`),
`RentPolicyUpdateIn` (the four fields), `RentPolicyAuditOut`.

Router `app/routers/rent_policy.py` (new, prefix `/ui/rent-policy`, registered in
`app/main.py`), auth split per cross-cutting constraints:
- `GET /ui/rent-policy` → `require_ui_session` → `get_policy(session["user_sub"])`.
- `PUT /ui/rent-policy` → `require_admin_or_root_csrf` → `set_policy(...)`.
- `GET /ui/rent-policy/audit` → `require_ui_session` → `list_policy_audit`.

**Lease inheritance hook (cross-module, additive):** document that LSE `create_lease`
(LEASES_TICKETS §LSE-001) should default unset `rent_due_day` / `late_fee_cents` /
`grace_period_days` from `rent_policy.get_policy(owner_sub)` at creation time (LSE already
carries those scalar fields — LEASES_TICKETS §LSE-001 `renewal_notice_days`-adjacent
fields). PMD-001 only provides `get_policy`; the call site is a one-line addition LSE
makes when present (best-effort, behind a local import so PMD does not hard-depend on LSE).

**Acceptance Criteria.**
- `GET /ui/rent-policy` for an owner with no saved policy returns the effective defaults
  with `is_default=true`; after `PUT`, returns the saved values with `is_default=false`.
- `PUT` with `rent_due_day=0` or `=29` → 422; `late_fee_cents<0` → 422; invalid currency → 422.
- `PUT` writes exactly one `AUDIT#…` row; a second identical `PUT` writes a second audit
  row and advances `updated_at` (audit is append-only).
- `set_policy` invalidates the cache so the next `get_policy` reflects the new value.
- All three endpoints 404 when `PROPERTY_DASHBOARD_ENABLED=false`; no DDB call is made.
- No `if S.dev_mode` branch in `rent_policy.py`.

**Dependencies.** None hard (greenfield). Reuses `billing_config.py` idiom,
`inventory.py` flag/audit helpers, `app/core/settings.py:324-325`. Soft consumer: **LSE**
(LEASES_TICKETS §LSE-001) inherits these defaults.

---

### PMD-002: Document linking — property/unit/lease/tenant record-link on file-manager nodes (EVT-011 extension)

**Type:** Feature | **Priority:** P1 | **Estimate:** 2d

**Description.**
Implement the EVT-011 record-link fields (`linked_record_type` / `linked_record_id`,
`crm_category`, `crm_description`) on file-manager nodes so files attach to a property,
unit, lease, or tenant. The file-manager node has **no record-link today** — `upload_file`
writes a node item with no `linked_record_*` field (`docs/suitecrm/specs/EVT-011.md` §2
"There is no `crm_category`, … `linked_record_type`, or `linked_record_id` field today").

This ticket does **not** reimplement EVT-011's service — it **extends the allowlist**.
EVT-011 provides `update_crm_metadata` / `search_by_linked_record` writing the four
additive attributes to the existing `NODE#<path>` item via a targeted `update_item`, with
`_LINKED_RECORD_TYPES = frozenset({"contact","ticket","account","party"})`
(`docs/suitecrm/specs/EVT-011.md` §4.1, §3 attribute table). PMD-002:

1. **Extends `_LINKED_RECORD_TYPES`** in `app/services/filemanager.py` to add the four
   property-domain record types: `{"property","unit","lease","tenant"}` (union with the
   existing CRM set; no behavior change for existing types). This keeps the single
   validated enum so the PATCH/search endpoints accept property links.
2. **Reuses the EVT-011 endpoints verbatim** — `PATCH /v1/fs/crm-metadata` and
   `GET /v1/fs/crm-search` (`docs/suitecrm/specs/EVT-011.md` §4.3). A file is linked to a
   lease via `PATCH /v1/fs/crm-metadata?path=/leases/lease-42.pdf` with
   `{"linked_record_type":"lease","linked_record_id":"<lease_id>","crm_category":"Lease"}`.
3. **Adds a property-scoped convenience read** in `app/routers/property_mgmt.py`
   (PROP-004 router) / lease+tenant routers — a thin `GET /ui/properties/{id}/documents`
   (and `…/units/{uid}/documents`, `/ui/leases/{id}/documents`, `/ui/tenants/{id}/documents`)
   that delegates to `search_by_linked_record(user_sub, linked_record_type="property",
   linked_record_id=property_id, …)`. No new storage — pure reuse of the EVT-011 scan
   (`docs/suitecrm/specs/EVT-011.md` §4.1 `search_by_linked_record`, scoped to the caller's PK).

**Gating.** Reuse the EVT-011 flag `CRM_DOCUMENT_LIBRARY_ENABLED`
(`docs/suitecrm/specs/EVT-011.md` §6, default off) for the file-manager endpoints; gate
the new property-scoped `…/documents` convenience reads on
`PROPERTY_DASHBOARD_ENABLED AND CRM_DOCUMENT_LIBRARY_ENABLED` (a 404 no-op when either is off).

**EVT-012 revisions note (informational, no code here):** for lease versions, document
revision history is provided by EVT-012 (`docs/suitecrm/specs/EVT-012.md`): overwriting
`/leases/lease-42.pdf` archives the prior PDF as a `REVISION#{path}#{n:08d}` row and the
`linked_record_type=lease` / `linked_record_id` link is **carried forward** onto the
replacement node (EVT-012 §11 "carry EVT-011 fields forward by copying them from
`existing_node`"). PMD-002 ensures the property record-link survives lease-document
versioning by relying on that EVT-012 carry-forward — no new code, but the integration is
exercised in PMD-005 if EVT-012 is present.

**Acceptance Criteria.**
- `PATCH /v1/fs/crm-metadata` with `linked_record_type` ∈ {`property`,`unit`,`lease`,`tenant`}
  succeeds and writes the link onto the node item; an unknown type still → 400
  `invalid_linked_record_type` (existing EVT-011 guard, now over the widened set).
- `GET /ui/properties/{id}/documents` returns only the caller's nodes linked to that
  property; cross-user isolation holds (scan scoped to `PK=USER#{caller}`, EVT-011 §7).
- The four new record types do not appear in the existing `GET /v1/fs/info` projection
  (EVT-011 additive-only requirement §2).
- `…/documents` reads 404 when `PROPERTY_DASHBOARD_ENABLED` or `CRM_DOCUMENT_LIBRARY_ENABLED`
  is off; the EVT-011 `/v1/fs/*` endpoints retain their own flag behavior.
- No new DynamoDB table or GSI; only `_LINKED_RECORD_TYPES` is widened.

**Dependencies.** **EVT-011** (`docs/suitecrm/specs/EVT-011.md` — provides
`update_crm_metadata` / `search_by_linked_record` + the flag + the enum being extended) —
**hard**. **PROP-004** (PROPERTY_UNITS_TICKETS — the `/ui/properties` router the
convenience reads attach to). Soft: **LSE**, **TEN** (their routers for `…/documents`),
**EVT-012** (revision carry-forward, informational).

---

### PMD-003: Portfolio dashboard KPI service — occupancy/active-leases/outstanding-rent/open-WOs + monthly snapshot + priority items

**Type:** Feature | **Priority:** P1 | **Estimate:** 3d

**Description.**
A read-only KPI aggregation service for the per-landlord portfolio, mirroring the in-memory
bucketing + ledger-scan strategy of `app/services/platform_financial_dashboard.py` (module
docstring §"Aggregation strategy mirrors the cross-user scan pattern … buckets in-memory
by day/type"). The gap analysis flags **Portfolio KPIs** and **Monthly rent snapshot** as
MISSING because `platform_financial_dashboard` is GMV/revenue, not a rent-roll (§A rows
4–5). PMD-003 computes a rent-roll view by **consuming** PROP/LSE/RNT/WOV query surfaces
— it does NOT recreate any ledger or entity.

Service `app/services/portfolio_dashboard.py` (new), all functions read-only and behind
`_require_enabled()` (404 when `PROPERTY_DASHBOARD_ENABLED` off; mirror `inventory.py:51-58`):

1. **`compute_kpis(owner_sub) -> dict`** — the four headline KPIs:
   - `occupancy_rate` + `unit_count` + `occupied_units`: iterate the owner's properties via
     `property_mgmt.list_properties(owner_sub)` and per-property
     `property_mgmt.compute_property_occupancy(property_id)` (PROPERTY_UNITS_TICKETS
     §PROP-003 `GET /ui/properties/{id}/occupancy`); roll up to `occupied/total`.
   - `active_lease_count`: `leases.list_leases(owner_sub, status="active")` count
     (LEASES_TICKETS §LSE-002 status filter; loop `LastEvaluatedKey`).
   - `outstanding_rent_cents`: sum of unpaid rent charges from the billing ledger — query
     the owner's ledger rows (`pk=USER#{owner_sub}`, `begins_with(sk,"LEDGER#")`) filtering
     RNT rent-charge `type` whose `state` is not settled, via the same iteration as
     `csv_export._iter_billing_entries` / `platform_financial_dashboard` (the RNT cluster
     posts charges through `billing_shared.new_ledger_entry` with `ledger_date`,
     gap analysis §B). Reuse `compute_due` (`app/services/billing_shared.py:158`) where a
     per-lease balance item is available.
   - `open_work_order_count`: when WOV is present, count its open work orders for the owner's
     properties; otherwise fall back to `tickets.list_tickets` filtered to property-linked
     tickets (`app/services/tickets.py` owner-GSI query) — degrades to `0` cleanly.

2. **`monthly_rent_snapshot(owner_sub, *, year, month) -> dict`** — `{collected_cents,
   outstanding_cents, overdue_cents, charged_cents}` for the period: filter the owner's
   ledger rows by `ledger_date` prefix `YYYY-MM` (the denormalized `ledger_date` field
   written by `new_ledger_entry`, `platform_financial_dashboard.py` docstring) and bucket
   by `state` (settled→collected, open→outstanding, open+past-due-day→overdue using the
   PMD-001 policy `rent_due_day` + `grace_period_days`). In-memory bucketing, no new writes.

3. **`priority_items(owner_sub, *, limit=20) -> dict`** — `{open_work_orders:[…],
   upcoming_expirations:[…]}`: open WOs (or property-linked tickets) + upcoming lease
   expirations from `leases.list_upcoming_expirations(owner_sub, within_days=60)`
   (LEASES_TICKETS §LSE-003 — "feeds the portfolio dashboard's upcoming lease expirations
   priority items"), newest-due-first.

All cross-module reads use **lazy local imports** (`from app.services import leases` inside
the function, mirroring `ssh_bastion.py:501` / `inventory._audit`) so PMD-003 imports
cleanly even when LSE/RNT/WOV are not yet merged — each consumer is wrapped in a
`try/except`/`getattr` guard returning `0`/`[]` so a missing cluster degrades gracefully
rather than 500-ing.

**RPT-006/007 dashlet surface (gap analysis §A "add a property dashlet"):** register a new
`portfolio_summary` dashlet type. Per `docs/suitecrm/specs/RPT-006.md` §3.2 the dashlet
config schema lives in the `dashlets` list on `T.crm_dashboards`; per
`docs/suitecrm/specs/RPT-007.md` §4.1 a provider is added to `crm_dashlet_data.py`'s
dispatch (`_provider_portfolio_summary(user_sub, config) -> compute_kpis(user_sub)`),
returning the KPI dict under `data`. Add `"portfolio_summary"` to RPT-006's
`VALID_DASHLET_TYPES` / `DashletConfig` pattern (RPT-006 §4.1) and to RPT-007's dispatch
(RPT-007 §5.8 "RPT-008 adds `saved_search` without touching this validation" — same
extension point). Gate the provider additionally on `S.property_dashboard_enabled` so the
dashlet returns 404/`unknown_dashlet_type` when the property vertical is off even if
`CRM_REPORTS_ENABLED` is on.

Router `app/routers/portfolio_dashboard.py` (new, prefix `/ui/portfolio`, registered in
`app/main.py`), all `require_ui_session` reads:
- `GET /ui/portfolio/kpis` → `compute_kpis`.
- `GET /ui/portfolio/rent-snapshot?year=&month=` → `monthly_rent_snapshot`.
- `GET /ui/portfolio/priority-items?limit=` → `priority_items`.

Pydantic (`app/models.py`): `PortfolioKpisOut`, `RentSnapshotOut`, `PriorityItemsOut` +
`PortfolioSummaryData` (the RPT-007 dashlet payload model, additive to the
`DashletDataOut.data` Union, RPT-007 §4.3).

**Acceptance Criteria.**
- `GET /ui/portfolio/kpis` returns `occupancy_rate` (0.0 when no units), `active_lease_count`,
  `outstanding_rent_cents`, `open_work_order_count` — each computed from the consumed cluster,
  or a safe `0`/`0.0` when that cluster (RNT/WOV) is absent.
- `monthly_rent_snapshot` buckets the owner's `YYYY-MM` ledger rows into
  collected/outstanding/overdue using PMD-001's `rent_due_day`+`grace_period_days`; the four
  buckets reconcile (`collected+outstanding == charged`, `overdue <= outstanding`).
- `priority_items` returns upcoming expirations only for `active` leases within the window
  (open-ended leases excluded, LSE-003 contract) and open WOs/tickets, capped at `limit`.
- The `portfolio_summary` dashlet provider returns the same KPI dict and is reachable via
  `GET /ui/crm/dashboard/dashlets/{id}/data` only when both `CRM_REPORTS_ENABLED` and
  `PROPERTY_DASHBOARD_ENABLED` are on (else 404 / `unknown_dashlet_type`).
- All `/ui/portfolio/*` endpoints 404 when `PROPERTY_DASHBOARD_ENABLED=false`.
- No new DynamoDB table/write; cross-user ledger sweeps loop on `LastEvaluatedKey`
  (CLAUDE.md FilterExpression gotcha). No `if S.dev_mode` branch.

**Dependencies.** **PMD-001** (rent-policy `rent_due_day`/`grace_period_days` for the
overdue bucketing) — **hard**. **PROP-003** (occupancy), **LSE-002/003** (active +
expiring leases), **RNT** (rent ledger), **WOV**/`tickets.py` (work orders) — consumed
(soft via lazy import + graceful degradation). **RPT-006/007** (`docs/suitecrm/specs/
RPT-006.md`, `RPT-007.md`) — dashlet registration/dispatch surface — soft (the
`/ui/portfolio/*` endpoints work without the dashlet).

---

### PMD-004: Frontend — portfolio dashboard page (KPI cards + rent snapshot + priority items + property dashlet)

**Type:** Feature | **Priority:** P2 | **Estimate:** 2d

**Description.**
A `PortfolioDashboardPage` rendering the PMD-003 KPIs, monthly rent snapshot, and priority
items, plus the rent-policy settings editor (PMD-001) and a `portfolio_summary` dashlet tile
for the RPT-006 configurable dashboard. Follows the existing dashboard-page conventions
(React Query + shadcn/ui; `frontend/src/pages/earnings/EarningsPage.tsx` recharts usage,
cited by RPT-006 §2.4 as the chart-stub reference — no new package needed).

Frontend (per CLAUDE.md "Adding a new feature" checklist steps 5–8):
- `frontend/src/api/endpoints/portfolio.ts` — wrappers for
  `GET /ui/portfolio/kpis|rent-snapshot|priority-items` and
  `GET|PUT /ui/rent-policy` (axios instance `frontend/src/api/client.ts`, CSRF header on PUT).
- `frontend/src/api/types.ts` — `PortfolioKpis`, `RentSnapshot`, `PriorityItems`,
  `RentPolicy` interfaces mirroring the PMD-001/003 Pydantic models.
- `frontend/src/pages/property/PortfolioDashboardPage.tsx`:
  - KPI cards (occupancy rate %, active leases, outstanding rent $, open work orders).
  - Monthly rent snapshot card with period (year/month) navigation
    (collected/outstanding/overdue/charged), recharts bar/donut like EarningsPage.
  - Priority-items list (upcoming lease expirations + open work orders) with deep links to
    the lease/work-order pages.
  - A `RentPolicyDialog` (admin/root only) editing `rent_due_day` / `late_fee_cents` /
    `grace_period_days` / `currency` via `PUT /ui/rent-policy` (React Hook Form + Zod).
- `frontend/src/pages/reports/dashlets/PortfolioSummaryDashlet.tsx` — the RPT-007 tile
  component for the `portfolio_summary` dashlet type (renders `compute_kpis` payload inside
  the RPT-006 dashboard grid; mirrors the RPT-007 dashlet component pattern §1).
- `frontend/src/App.tsx` — lazy route `/portfolio` → `PortfolioDashboardPage` (gated; the
  nav entry is hidden when the backend 404s, matching the flag-off contract).

**Acceptance Criteria.**
- `/portfolio` renders the four KPI cards from `GET /ui/portfolio/kpis`; an owner with no
  properties shows `0%` occupancy / `0` counts without error.
- Period navigation on the rent-snapshot card re-fetches `rent-snapshot?year=&month=` and
  updates collected/outstanding/overdue figures.
- The rent-policy dialog is visible only to admin/root and PUTs successfully (CSRF header
  sent); a non-admin user does not see the edit control.
- The `PortfolioSummaryDashlet` renders KPI values inside the RPT-006 dashboard grid when
  the `portfolio_summary` dashlet is added.
- With the backend flag off, `/portfolio` and the dashlet degrade (404 → empty/hidden), no
  console crash.

**Dependencies.** **PMD-001** (rent-policy endpoints), **PMD-003** (KPI/snapshot/priority
endpoints + dashlet provider) — **hard**. **RPT-006** (dashboard grid + dashlet component
slot) — soft (the `/portfolio` page works standalone without the configurable dashboard).

---

### PMD-005: Tests + cross-module integration (rent-policy, document linking, dashboard, RPT dashlet)

**Type:** Test | **Priority:** P1 | **Estimate:** 2d

**Description.**
Hermetic pytest + Playwright E2E coverage for PMD-001..004 and the cross-module
integration seams (LSE policy inheritance, EVT-011/012 document linking, RPT-006/007
dashlet dispatch). All Python tests are offline: moto-bound frozen `T` via
`object.__setattr__`, frozen `S` flags toggled per test, route coroutines called directly
on a fresh `asyncio.new_event_loop()` — no `TestClient`, no real AWS (mirrors RPT-006 §9.1,
EVT-011 §9.1, the PROP/LSE test pattern).

Pytest:
- `tests/test_pmd_001_rent_policy.py` — effective-default vs saved policy; validation
  (`rent_due_day` 0/29, negative fees, bad currency → 422); audit row append-only +
  `updated_at` advance; cache invalidation on `set_policy`; flag-off 404 (handler called
  directly with `property_dashboard_enabled=False`).
- `tests/test_pmd_002_document_linking.py` — `_LINKED_RECORD_TYPES` widened set accepts
  `property`/`unit`/`lease`/`tenant`; PATCH writes the link; `search_by_linked_record` /
  `…/documents` returns only the caller's property-linked nodes; cross-user isolation;
  unknown type → 400; new types absent from `GET /v1/fs/info` projection; double-flag 404
  on the property-scoped reads. (Reuses the EVT-011 §9.1 moto file-manager setup.)
- `tests/test_pmd_003_portfolio_dashboard.py` — `compute_kpis` rolls up occupancy + active
  leases + outstanding rent + open WOs from **seeded** PROP/LSE/billing-ledger/ticket rows
  (and the **graceful-degradation** path: with no RNT/WOV data, KPIs are `0`/`0.0`, no
  exception); `monthly_rent_snapshot` bucket reconciliation
  (`collected+outstanding==charged`, overdue derived from PMD-001 policy);
  `priority_items` excludes open-ended/non-active leases; flag-off 404.
- `tests/test_pmd_003_dashlet_provider.py` — the `portfolio_summary` provider dispatch in
  `crm_dashlet_data.get_dashlet_data` returns the KPI dict; double-gated on
  `CRM_REPORTS_ENABLED` + `PROPERTY_DASHBOARD_ENABLED` (off either → 404 /
  `unknown_dashlet_type`). (RPT-007 §9.1 harness.)

Cross-module integration test `tests/test_pmd_integration.py`:
- **LSE inheritance:** seed a rent policy, create a lease with unset due-day/fees (LSE
  `create_lease`), assert the lease inherits PMD-001's `rent_due_day`/`late_fee_cents`/
  `grace_period_days` (skipped with a clear marker if LSE not yet merged — lazy-import guard).
- **EVT-012 carry-forward:** link a lease PDF (`linked_record_type=lease`), overwrite it
  (EVT-012 revision), assert the live node retains the lease link and the prior version is
  in `list_revisions` (skipped if EVT-012 flag/code absent).
- **End-to-end KPI:** property + active lease + an unpaid rent ledger row + an open
  property-ticket → `compute_kpis` reflects all four; `priority_items` surfaces the lease
  expiration and the open ticket.

E2E `frontend/e2e/portfolio-dashboard.spec.ts` (sections):
- Rent-policy API (GET default → PUT → GET saved → audit list; admin-only PUT; 422 cases).
- Document-linking API (upload → PATCH `linked_record_type=property` → `…/documents`
  returns it; Bob isolation).
- Portfolio KPIs/snapshot/priority API (seed via session auth; assert shapes + reconciliation).
- Portfolio dashboard UI (KPI cards, period navigation, rent-policy dialog admin-gating,
  `portfolio_summary` dashlet tile renders).
- Flag-off smoke (all PMD endpoints 404 when `PROPERTY_DASHBOARD_ENABLED=0`).

**Acceptance Criteria.**
- All pytest suites pass offline (no AWS/network); each asserts the flag-off 404 path and a
  graceful-degradation path for absent RNT/WOV/LSE/EVT-012 clusters.
- The integration test exercises LSE policy inheritance, EVT-012 carry-forward, and the
  end-to-end KPI roll-up (cluster-absent seams are explicitly skip-marked, not failed).
- E2E covers rent-policy CRUD, document linking + isolation, KPI/snapshot/priority APIs,
  the dashboard UI, the RPT dashlet, and the flag-off smoke; run after `just restart`
  (state accumulation, CLAUDE.md).

**Dependencies.** **PMD-001..004** — **hard**. Soft (integration seams, skip-marked when
absent): **LSE** (LEASES_TICKETS), **EVT-011/012** (`docs/suitecrm/specs/`),
**RPT-006/007** (`docs/suitecrm/specs/`), **RNT**/**WOV** (planned clusters).
