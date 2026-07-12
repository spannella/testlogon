# Human Resources (HRM) — Implementation Tickets

This backlog delivers **Phase M — Human Resources (OFBiz HR, application M)** of the full OFBiz commerce/ERP buildout (`docs/ofbiz-full-buildout-plan.md`) — the most peripheral module, built last. It is a deliberately **lean** HR-lite: employees modeled as OFBiz-style PERSON party records carrying an `EMPLOYEE` role plus an `EMPLOYMENT` relationship to the platform/org PARTY_GROUP (per the Party model in `PARTY_CRM_TICKETS.md`), positions/job titles, employment periods, and a minimal **payroll-expense hook into the GL** that derives a double-entry journal entry from the existing single-entry ledger rather than forking billing. Everything is **additive + flag-gated** (default-off), single-table DynamoDB (numeric GSI sort keys declared with `attr_types`), deterministic-id idempotent on write paths, SECOPS-007 dev/prod parity, and hermetically tested offline. With the flag off, the shop/cart/orders/billing/inventory and Party surfaces are byte-for-byte unchanged.

## Milestone 1 — Scaffolding & Data Model

### HRM-001: HR feature flag & settings keys
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add a default-off feature flag group to `app/core/settings.py` following the exact boolean-env pattern already used (e.g. `browser_ssh_terminal_enabled` at `app/core/settings.py:124`): `hr_enabled: bool = os.environ.get("HR_ENABLED", "0") not in ("0", "false", "False")`, plus sub-flags `hr_payroll_enabled` and `hr_payroll_gl_posting_enabled`, all defaulting **off**.
- Add the table-name setting key alongside the existing `contacts_table_name` (`app/core/settings.py:498`): `hr_table_name: str = os.environ.get("DDB_HR_TABLE", "hr")`.
- Add a payroll-GL settings key for the expense-account mapping default (so HRM-010 can resolve the chart-of-accounts code without hard-coding): `hr_payroll_expense_account_code: str = os.environ.get("HR_PAYROLL_EXPENSE_ACCOUNT_CODE", "6000")` (Salaries & Wages Expense), defaulting to a conventional expense code that OFB-013's seeded chart can satisfy.
- Document the flags in `.env.local.example` and the feature-flag table in `CLAUDE.md`.

**Acceptance Criteria**
- `S.hr_enabled`, `S.hr_payroll_enabled`, `S.hr_payroll_gl_posting_enabled` read through the `S` singleton and default to `False` with no env set.
- No existing flag value or table name is changed.
- A pytest asserts all three new flags default off and `hr_table_name` defaults to `"hr"`.

**Dependencies**
- None.

---

### HRM-002: HR single-table DynamoDB definition + handle
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add the `hr` single-table `TableDef` to `scripts/local-ddb-init.py` next to the existing `Contacts`/`party` defs (`scripts/local-ddb-init.py:691`), using `_resolve_table_name(S.hr_table_name, "hr")`, `PK`/`SK` keys, and GSIs:
  - `GSI1` (`GSI1PK` / `GSI1SK`) — entity-type/status lookup (e.g. `POSITION#OPEN`, `EMPLOYMENT#ACTIVE`).
  - `GSI2` (`GSI2PK` / `GSI2SK`) — party reverse-lookup so an employee's HR rows resolve from a `party_id` (e.g. `PARTY#{party_id}` → `EMPLOYMENT#{employment_id}`).
  - `GSI_CREATED` (`entity_type` partition / `created_at` sort) for newest-first listing.
- Declare numeric GSI sort keys with `attr_types={"created_at": "N", ...}` per the CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha so `created_at` (and any numeric employment-period `start_date`/`end_date` epoch keys used as GSI sort keys) are stored as `N`.
- Wire the handle `hr=_safe_table(S.hr_table_name)` into `app/core/tables.py` next to `contacts=_safe_table(S.contacts_table_name)` (`app/core/tables.py:354`) and declare `hr: Any` in the table-handles dataclass (next to `contacts: Any` at `app/core/tables.py:102`).

**Acceptance Criteria**
- `just restart` recreates the `hr` table locally with no `ValidationException` (numeric sort keys correct).
- `app.core.tables.T.hr` resolves to a live handle in a smoke pytest.
- Existing tables are unmodified.

**Dependencies**
- HRM-001.

---

### HRM-003: HR Pydantic models (employee / position / employment / payroll)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add OFBiz-shaped Pydantic models to `app/models.py` (mirroring the request/response style already there): `Position` (`position_id`, `title`, `department`, `status` ∈ {`OPEN`, `FILLED`, `CLOSED`}, `created_at`, `updated_at`), `Employment` (`employment_id`, `party_id` — the employee PERSON party, `position_id`, `org_party_id`, `status` ∈ {`ACTIVE`, `TERMINATED`, `ON_LEAVE`}, `start_date`, `end_date` optional, `pay_rate_cents`, `pay_period` ∈ {`MONTHLY`, `BIWEEKLY`, `WEEKLY`, `HOURLY`}, `currency`), and `PayrollRun` / `PayrollLine` (`payroll_run_id`, `period_start`, `period_end`, lines of `employment_id` → `gross_cents`, `status` ∈ {`DRAFT`, `APPROVED`, `POSTED`}).
- Reuse the money/currency conventions already used by the ledger (integer cents + `currency`, mirroring `billing_shared.new_ledger_entry` at `app/services/billing_shared.py:224`) rather than inventing a new money type.
- Add the request/response IO models: `CreatePositionIn`, `PositionOut`, `CreateEmploymentIn`, `EmploymentOut`, `TerminateEmploymentIn`, `CreatePayrollRunIn`, `PayrollRunOut`, `PayrollLineOut`.

**Acceptance Criteria**
- All models validate the enum constraints and reject unknown `status` / `pay_period`.
- Money fields are integer cents with a `currency`; negative `pay_rate_cents`/`gross_cents` are rejected.
- `end_date < start_date` on `Employment` is rejected at the model layer.
- pytest covers model validation success + rejection per field.

**Dependencies**
- HRM-001.

---

## Milestone 2 — Employee & Position Service Core

### HRM-004: Employee party records (PERSON + EMPLOYEE role + EMPLOYMENT rel)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/services/hr.py`. Per the STATE requirement that employees be party records with an employment relationship, an employee is **not** a new entity: `ensure_employee_party(user_sub=None, *, person_fields=None, correlation_id=None) -> party_id` reuses the Party model — it calls `party.ensure_person_party(user_sub)` / `party.create_party("PERSON", ...)` (PTY-010 / PTY-004), then `party.add_role(party_id, "EMPLOYEE")` (the `EMPLOYEE` role already enumerated in `PartyRoleType`, `PARTY_CRM_TICKETS.md` PTY-003) — never re-implementing person storage in the `hr` table.
- Roles are checked against the platform role model only where authorization is needed: HR admin endpoints (HRM-009) are `require_admin_session`-gated per `app/auth/roles.py` (`Role.ADMIN`/`Role.ROOT`, `role_allows_admin_features` at `app/auth/roles.py:60`); the HR record itself is a party/HR-table row, decoupled from the auth `Role` enum.
- Use **deterministic-id idempotency** per the plan ("`order_id = sha256(correlation_id)`"): any new HR write path keys its id off `sha256(correlation_id).hexdigest()[:32]` when `correlation_id` is supplied with a conditional `attribute_not_exists(PK)` put, else a fresh `uuid4().hex`.
- Emit audit events via `app.services.alerts.audit_event` (`app/services/alerts.py:644`) for employee onboarding.

**Acceptance Criteria**
- `ensure_employee_party` provisions (or reuses) a PERSON party carrying the `EMPLOYEE` role; re-calling with the same `correlation_id`/`user_sub` returns the same `party_id` (no duplicate).
- No employee identity/profile data is duplicated into the `hr` table — the PERSON party remains the source of truth.
- Onboarding writes an audit event.
- Hermetic pytest (moto-bound frozen `T.hr` + `T.party`) covers ensure / idempotent replay / EMPLOYEE-role assignment.

**Dependencies**
- HRM-002, HRM-003, PTY-004, PTY-005, PTY-010.

---

### HRM-005: Position / job-title service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Extend `app/services/hr.py` with `create_position(title, department, *, correlation_id=None)`, `get_position(position_id)`, `list_positions(status=None, cursor=None)`, and `update_position_status(position_id, status)`.
- Store as `PK=POSITION#{position_id}`, `SK=META`, plus `GSI1PK=POSITION#{status}` / `GSI1SK=POSITION#{position_id}` for status filtering and `GSI_CREATED` keys (`entity_type=POSITION`, numeric `created_at` via `now_ts()` per `app/core/time.py:2`) for newest-first listing; paginate via `app/core/cursor.py` like other services.
- Validate `status` transitions (`OPEN`→`FILLED`→`CLOSED`, `OPEN`→`CLOSED`); illegal transitions raise the error the router maps to 409.

**Acceptance Criteria**
- Positions are creatable, gettable, and listable by status via `GSI1` (no scan) and newest-first via `GSI_CREATED`.
- Deterministic-id replay is a no-op.
- Illegal status transitions are rejected.
- pytest covers create / get / list-by-status / transition validation / idempotent replay.

**Dependencies**
- HRM-004.

---

### HRM-006: Employment-period service (hire / terminate / list)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add `create_employment(party_id, position_id, org_party_id, pay_rate_cents, pay_period, start_date, *, currency="usd", correlation_id=None)`, `terminate_employment(employment_id, end_date, *, reason=None)`, `get_employment(employment_id)`, `list_employments(party_id=None, status=None, cursor=None)`, and `set_employment_status(employment_id, status)` to `app/services/hr.py`.
- On create, also persist the OFBiz-style **EMPLOYMENT relationship** on the party graph via `party.create_relationship(from_party_id=party_id, to_party_id=org_party_id, relationship_type="EMPLOYMENT", correlation_id=...)` (PTY-006) so the employment is queryable from both the HR table and the party graph (no fork of the relationship store).
- Store as `PK=EMPLOYMENT#{employment_id}`, `SK=META`, with `GSI1PK=EMPLOYMENT#{status}`, `GSI2PK=PARTY#{party_id}` / `GSI2SK=EMPLOYMENT#{employment_id}` (employee reverse-lookup), and numeric epoch `start_date`/`end_date` (declared `attr_types` "N" in HRM-002 where used as GSI sort keys). Mark the position `FILLED` on hire (HRM-005) and back to `OPEN`/`CLOSED` policy on terminate (best-effort, flag-gated; never blocks the employment write).
- Terminating sets `status=TERMINATED` + `end_date`, validates `end_date >= start_date`, and is idempotent (re-terminate is a no-op).

**Acceptance Criteria**
- Hiring creates the employment row + the `EMPLOYMENT` party relationship and flips the position to `FILLED`; both resolve the same employee.
- `list_employments(party_id=...)` resolves an employee's history via `GSI2`; `list_employments(status="ACTIVE")` via `GSI1` (no scan).
- Terminate sets end_date/status idempotently and rejects `end_date < start_date`.
- pytest covers hire / relationship-mirror / list-by-party / list-by-status / terminate / idempotent replay.

**Dependencies**
- HRM-005, PTY-006.

---

## Milestone 3 — Payroll & GL Hook

### HRM-007: Payroll run service (draft / compute / approve)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add `app/services/hr_payroll.py` (gated by `S.hr_payroll_enabled`): `create_payroll_run(period_start, period_end, *, correlation_id=None)` enumerates `ACTIVE` employments (HRM-006) and computes each line's `gross_cents` from `pay_rate_cents` × `pay_period` proration (monthly = rate as-is, biweekly/weekly/hourly prorated against the period), producing `PayrollLine` rows in `DRAFT`.
- `approve_payroll_run(payroll_run_id)` transitions `DRAFT`→`APPROVED` (validation only — no money moves yet; posting is HRM-008/HRM-010).
- Store as `PK=PAYROLL#{payroll_run_id}`, `SK=META` (run) + `SK=LINE#{employment_id}` (lines), with `GSI1PK=PAYROLL#{status}` for status filtering. Deterministic-id idempotency keys the run off `correlation_id` (a re-create for the same period returns the existing run, no duplicate).

**Acceptance Criteria**
- A draft run enumerates exactly the `ACTIVE` employments and computes gross per pay-period proration (covered by a unit table of period/rate cases).
- `approve` validates the `DRAFT`→`APPROVED` transition; re-approve is a no-op; approving a non-draft run is rejected.
- Re-creating a run for the same period (same `correlation_id`) returns the existing run.
- pytest covers compute math, draft/approve transitions, and idempotent replay.

**Dependencies**
- HRM-006.

---

### HRM-008: Payroll disbursement reuses the single billing/ledger path (no fork)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add `post_payroll_run(payroll_run_id)` to `app/services/hr_payroll.py` that, for an `APPROVED` run, records the **money-out** per line through the existing single-entry ledger primitive — `billing_shared.new_ledger_entry(...)` (`app/services/billing_shared.py:224`, which also denorms `ledger_date` at `:253` for the `GSI_LEDGER_DATE` GL-derivation index) — with `reason="payroll"` and an `extra={...}` carrying `employment_id`/`party_id`/`payroll_run_id`. Per the plan's "one refund mechanism / never fork billing" constraint, payroll **must not** mint a parallel money movement; any reversal of a posted run reuses `settle_or_reverse_ledger` (`app/services/billing_shared.py:262`).
- Each ledger write is idempotent per `(payroll_run_id, employment_id)` via a deterministic ledger correlation id (`sha256(f"payroll:{payroll_run_id}:{employment_id}")`), so re-posting a run never double-pays.
- Transition the run `APPROVED`→`POSTED` only after all line ledger entries succeed; emit an audit event per the existing pattern.

**Acceptance Criteria**
- Posting an approved run writes exactly one ledger entry per line via `new_ledger_entry` (carrying `ledger_date` + `reason="payroll"` + `extra`), never a forked path.
- Re-posting the same run is idempotent (no duplicate ledger entries; deterministic correlation id enforced).
- The run only reaches `POSTED` after all lines post; a partial failure leaves it `APPROVED` for safe retry.
- pytest covers post / idempotent re-post / partial-failure-retry, asserting `new_ledger_entry` is the sole money-out path.

**Dependencies**
- HRM-007.

---

### HRM-009: HR + payroll router (registered in app/main.py)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/routers/hr.py` with prefix `/ui/hr` under `Depends(require_admin_session)` (HR is an admin/root function; admin dep per the CLAUDE.md convention and `app/auth/roles.py` `role_allows_admin_features` at `:60`), exposing: `POST/GET /positions`, `GET /positions/{position_id}`, `PATCH /positions/{position_id}` (status); `POST/GET /employments`, `GET /employments/{employment_id}`, `POST /employments/{employment_id}/terminate`; and payroll `POST/GET /payroll`, `GET /payroll/{payroll_run_id}`, `POST /payroll/{payroll_run_id}/approve`, `POST /payroll/{payroll_run_id}/post`.
- Declare static segments (e.g. `/payroll`) **before** any dynamic `/{...}` capture so FastAPI's declaration-order matching doesn't swallow the literal (per the CLAUDE.md `/schedules` before `/{export_id}` gotcha).
- Register it in `app/main.py` next to `contacts_router` (import at `app/main.py:82`, include block at `app/main.py:549+`), but every handler returns **404/disabled** when `S.hr_enabled` is off (payroll routes additionally gated on `S.hr_payroll_enabled`), so the API surface is inert with the flag off.

**Acceptance Criteria**
- All endpoints round-trip against the service layer with cookie auth + CSRF (non-GET requires `x-csrf-token` per CLAUDE.md) and are admin/root-gated.
- With `hr_enabled` off, every `/ui/hr/*` route returns the disabled response and no service code runs; with `hr_enabled` on but `hr_payroll_enabled` off, only the payroll routes are inert.
- Non-admin callers are denied (403).
- pytest exercises each route's success + flag-off + authz path.

**Dependencies**
- HRM-005, HRM-006, HRM-007, HRM-008.

---

### HRM-010: Payroll-expense GL journal hook (derives from the ledger)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Per the STATE "minimal payroll-expense hook into the GL" and the plan's "GL DERIVES from the existing single-entry ledger", extend the GL posting mapper introduced in Accounting Phase 7 (`OFBIZ_COMMERCE_TICKETS.md` OFB-013/OFB-014, `app/services/gl_posting.py`) so a `reason="payroll"` ledger row (HRM-008) maps to a balanced double-entry journal: **Dr Salaries & Wages Expense** (account code `S.hr_payroll_expense_account_code`, HRM-001) **/ Cr Cash** (the same Cash/Bank account other money-out entries credit). HR does **not** post journals itself — it only emits the `reason="payroll"` ledger rows that the existing GL poster consumes, gated by `S.hr_payroll_gl_posting_enabled` AND the GL flag.
- Add the mapping entry + the expense account to OFB-013's seeded chart-of-accounts default set (Salaries & Wages Expense, expense class, debit normal-balance) so the journal balances.

**Acceptance Criteria**
- A posted payroll ledger row derives exactly one balanced journal entry (Σdebits = Σcredits) hitting Salaries & Wages Expense (Dr) and Cash (Cr), with idempotent one-journal-per-`entry_id` semantics inherited from OFB-014.
- With `hr_payroll_gl_posting_enabled` off (or the GL flag off), payroll ledger rows post no journal entries; the ledger itself is unaffected.
- The seeded chart includes the expense account so the trial balance still balances after payroll posting.
- pytest covers the payroll→journal mapping, balance invariant, idempotency, and the flag-off no-op (no journal).

**Dependencies**
- HRM-008, OFB-013, OFB-014.

---

## Milestone 4 — Frontend

### HRM-011: Frontend types + endpoint wrappers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add TypeScript interfaces mirroring the Pydantic models (HRM-003) to `frontend/src/api/types.ts`: `Position`, `Employment`, `PayrollRun`, `PayrollLine`.
- Add `frontend/src/api/endpoints/hr.ts` (the per-domain wrapper convention, alongside `contacts.ts`) using the shared axios instance (`frontend/src/api/client.ts`) for the position / employment / payroll endpoints (HRM-009).

**Acceptance Criteria**
- Endpoint wrappers cover every HRM-009 route and attach CSRF for non-GET (handled by `client.ts`).
- Types compile and match the backend response shapes.
- A vitest unit test asserts the wrapper builds the right URLs/payloads.

**Dependencies**
- HRM-009.

---

### HRM-012: HR admin page, route & nav entry
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add `frontend/src/pages/hr/HrPage.tsx` (a directory under `frontend/src/pages/`, mirroring the admin page conventions in `pages/admin/`) using React Query + shadcn/ui: a Positions tab (list + create + status), an Employees/Employment tab (hire against a position + an employee party, list, terminate), and a Payroll tab (create run → review computed lines → approve → post).
- Lazy-load and route it in `frontend/src/App.tsx` as `/hr` (admin/root-gated, next to other admin routes), and add a flag-gated nav entry to `frontend/src/components/layout/Sidebar.tsx` so the item renders only when an `hr_enabled` capability flag (surfaced via the existing settings/feature endpoint) is on.
- The page + nav entry render only for admin/root AND when `hr_enabled` is on, so the UI is invisible with the flag off or for non-admins.

**Acceptance Criteria**
- Admin/root can create a position, hire an employee against it, list employments, terminate, and run+approve+post a payroll run from the UI.
- With the flag off (or a non-admin user), neither the `/hr` route nor the nav entry is reachable.
- React Query caches invalidate correctly after mutations (no stale list).

**Dependencies**
- HRM-011.

---

## Milestone 5 — Tests

### HRM-013: HR hermetic pytest + E2E suite
**Type:** Chore  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add hermetic offline pytest `tests/test_hr.py` (moto-bound `T.hr` + `T.party` patched onto the frozen handles via `object.__setattr__`, `S` flags toggled via `object.__setattr__`, `new_ledger_entry`/GL collaborators patched at the source module, no real AWS — the project's standard test-isolation pattern) covering: employee party + EMPLOYEE role + idempotency (HRM-004), position CRUD + status (HRM-005), hire/terminate + EMPLOYMENT relationship mirror + reverse lookups (HRM-006), payroll compute/draft/approve + idempotent replay (HRM-007), payroll posting reusing `new_ledger_entry` with idempotent `(run, employment)` correlation ids and no forked money path (HRM-008), and the payroll→GL journal balance + flag-off no-op (HRM-010).
- Add a **flag-off regression test** asserting that with `hr_*` flags off the `/ui/hr/*` router is inert and that no `hr`-related ledger or journal rows are written — proving the billing/ledger/GL surfaces are byte-for-byte unchanged.
- Add `frontend/e2e/hr.spec.ts` (seeded admin/root session + CSRF per CLAUDE.md/MEMORY.md, using `e2e_admin_session_setup.py`) covering: create a position, hire an employee, list employments, terminate, run+approve+post payroll, and a flag-off check that `/hr` is unreachable. Run under the standard 1-worker Playwright config.

**Acceptance Criteria**
- pytest suite covers every service path (employees, positions, employment, payroll, ledger reuse, GL hook, idempotency) and passes offline with no AWS calls.
- The flag-off regression test proves the billing/ledger/GL surfaces are unchanged and the router is inert.
- E2E suite passes under the standard Playwright config and includes the flag-off unreachable-route assertion.

**Dependencies**
- HRM-009, HRM-010, HRM-012.

---
