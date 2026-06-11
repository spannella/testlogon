# CRM Reports & Dashboards — Implementation Tickets

**Area**: Reports & Dashboards (AOR + dashlets)
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T3] Reports & Dashboards (AOR + dashlets) — 8 tickets")

## What SuiteCRM provides in this area

SuiteCRM's Advanced OpenReports (AOR) and Dashlets system provides: a metadata-driven custom report builder where users select any CRM module, choose fields, and add filter conditions; GROUP BY / aggregate functions (SUM, AVG, COUNT, MIN, MAX) on report results; embedded bar/line/pie charts per report; scheduled email delivery of reports on cron cadences; a per-user configurable Home dashboard with drag-and-drop dashlet layout; saved searches pinned as dashboard tiles; a catalogue of pre-built dashlets (Recent Activities, Upcoming Calls/Meetings, My Leads, Pipeline, etc.); and CSV data export from any tabular module. testlogon has several hard-coded domain dashboards (creator, financial, ads, KYC) and charting infrastructure (recharts via `frontend/src/pages/earnings/EarningsPage.tsx:19`, affiliates dashboard) but the structural gap is that the platform's analytics are hard-coded per domain rather than metadata-driven — there is no user-defined report builder, no cross-entity query composer, no per-user configurable home dashlets, no saved searches, and no general-purpose scheduled report emails.

## Cross-cutting constraints

- **Additive only, default-off**: All tickets in this file are gated by `S.crm_reports_enabled` (env `CRM_REPORTS_ENABLED`, default `"0"`). With the flag off, all routes under `/ui/crm/reports/*` and `/ui/crm/dashboard/*` return 404 and all background workers are no-ops. No existing files are modified unless a ticket explicitly says so.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: New tables follow the `TableDef` pattern at `scripts/local-ddb-init.py:29`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` — omitting causes a DynamoDB `ValidationException` at query time (CLAUDE.md gotcha). All code runs identically in dev (moto, `DDB_ENDPOINT_URL=http://localhost:8001`) and prod. No `if dev_mode` branches in business logic.
- **Reuse existing primitives — never fork**:
  - Auth: `app/auth/policy.require_admin_or_root` (`app/auth/policy.py:67`) for admin-scoped endpoints; `app/services/sessions.require_ui_session` for user-scoped endpoints.
  - CSV export: `app/services/csv_export.py` — `generate_csv_rows` generator with `csv.writer`, RFC 4180, UTF-8 BOM; extend the `VALID_SOURCES` set and add new `_iter_*` / `_format_*` pairs rather than forking the file.
  - Streaming CSV response: `app/routers/csv_export.py:108` `StreamingResponse(media_type="text/csv")` pattern.
  - Scheduled jobs: `app/services/audit_export_schedule.py` — GSI-backed cron scheduling with `SCHEDULES#ACTIVE` / `next_run_at` numeric SK, `CADENCE_OFFSETS`, background loop pattern; the report scheduler in RPT-004 mirrors this exactly.
  - Email notifications: `app/services/alerts.send_alert_email` (`app/services/alerts.py:459`) and `audit_event` (`app/services/alerts.py:644`).
  - Rate limiting: `app/services/rate_limit._bucket_limit` (DDB-backed token bucket) — as used in `app/routers/csv_export.py:66`.
  - Cursor pagination: `app/core/cursor.encode_cursor` / `decode_cursor` (`app/core/cursor.py:94`).
  - Recharts charting: already a project dependency; pattern from `frontend/src/pages/earnings/EarningsPage.tsx:19` (`BarChart`, `LineChart`, `PieChart`, `XAxis`, `YAxis`, `Tooltip`, `ResponsiveContainer`).
  - Financial rollup pattern: `app/services/platform_financial_dashboard.py` — daily rollup PK/SK scheme, `compute_daily_rollup`, `_store_daily_rollup`, `_entries_for_range`.
  - Existing table handles in `app/core/tables.py`: `T.tickets`, `T.contacts`, `T.billing`, `T.orders`, `T.subscriptions`, `T.questionnaires` — all accessible from report data-source adapters.
- **Route ordering**: Declare static segments (`/templates`, `/run`, `/schedules`, `/dashlets`, `/saved-searches`) **before** dynamic `{report_id}` / `{dashboard_id}` segments to prevent FastAPI matching literals as path parameters.
- **Hermetic offline tests**: All pytest must use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles (canonical form: `tests/test_gap_0220_0221_ssh_stored_key.py`). No real AWS, network, or external service calls.

---

### RPT-001: Feature flag, settings & DynamoDB scaffolding
**Type:** Chore  **Priority:** P0  **Estimate:** 1d

**Description**

Introduce the top-level `CRM_REPORTS_ENABLED` feature flag, new table-name settings, and the three new DynamoDB tables required by the rest of the RPT tickets. This ticket is pure scaffolding — no user-visible behaviour.

**Settings additions** (`app/core/settings.py`) — follow the bool-env pattern used for `messaging_translation_enabled`:

```python
crm_reports_enabled: bool = _bool_env("CRM_REPORTS_ENABLED", False)
crm_reports_table_name: str = _str_env("CRM_REPORTS_TABLE_NAME", "crm_reports")
crm_dashboards_table_name: str = _str_env("CRM_DASHBOARDS_TABLE_NAME", "crm_dashboards")
crm_saved_searches_table_name: str = _str_env("CRM_SAVED_SEARCHES_TABLE_NAME", "crm_saved_searches")
```

**Table additions** (`scripts/local-ddb-init.py`) — three new `TableDef` entries:

1. `crm_reports` — stores report definitions and their run results:
   - PK `report_id` (S), SK `sk` (S)
   - META row: `sk="META"` holds the full report definition (module, fields, conditions, aggregations, chart config, owner_sub, created_at, updated_at, name, description)
   - RUN row: `sk="RUN#{run_ts:010d}#{run_id}"` holds the last run result (output_rows JSON, row_count, run_at, status)
   - GSI `owner-reports-index`: `GSI1PK=OWNER#{owner_sub}` / `GSI1SK=created_at` (numeric → `attr_types={"GSI1SK": "N"}`)

2. `crm_dashboards` — stores per-user dashboard layout and dashlet config:
   - PK `dashboard_id` (S), SK `sk` (S)
   - `sk="META"` row: owner_sub, name, layout (ordered list of dashlet configs), created_at, updated_at
   - GSI `owner-dashboards-index`: `GSI1PK=OWNER#{owner_sub}` / `GSI1SK=created_at` (numeric → `attr_types={"GSI1SK": "N"}`)

3. `crm_saved_searches` — named saved searches that can be pinned as dashlets:
   - PK `saved_search_id` (S), SK `sk` (S)
   - `sk="META"`: owner_sub, name, module, filters (JSON), created_at
   - GSI `owner-searches-index`: `GSI1PK=OWNER#{owner_sub}` / `GSI1SK=created_at` (numeric → `attr_types={"GSI1SK": "N"}`)

**Table handle additions** (`app/core/tables.py`) — add three new fields to the `Tables` dataclass and wire them in the `T = Tables(...)` initialiser following the existing pattern at `app/core/tables.py:68`.

**Acceptance Criteria**
- `just restart` creates all three tables with correct key schema and GSIs without error.
- Setting `CRM_REPORTS_ENABLED=0` (default) causes no tables to be queried at runtime (flag is checked at the router layer in RPT-002).
- All three table names are configurable via environment variables.
- `app/core/tables.py` exposes `T.crm_reports`, `T.crm_dashboards`, `T.crm_saved_searches`.

**Dependencies**
- None (this is the foundation for all other RPT tickets).

---

### RPT-002: Custom report builder — definition CRUD
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Implement the metadata-driven custom report builder: users define a report by selecting a target module, choosing output fields, and specifying filter conditions. Results are computed on demand and cached as a RUN row on the same `crm_reports` table. This ticket covers the full backend service + router surface and the minimal Pydantic models in `app/models.py`.

**Pydantic models** (add to `app/models.py`):

```python
class ReportCondition(BaseModel):
    field: str          # field name within the module
    operator: str       # eq | neq | contains | gt | lt | gte | lte | is_empty | not_empty
    value: Optional[str] = None

class ReportCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    module: str = Field(..., pattern=r"^(tickets|contacts|billing_ledger|orders|subscriptions|questionnaire_responses)$")
    fields: List[str] = Field(..., min_items=1, max_items=20)
    conditions: List[ReportCondition] = Field(default_factory=list)

class ReportOut(BaseModel):
    report_id: str
    name: str
    description: Optional[str]
    module: str
    fields: List[str]
    conditions: List[ReportCondition]
    owner_sub: str
    created_at: int
    updated_at: int

class ReportRunOut(BaseModel):
    report_id: str
    run_id: str
    run_at: int
    status: str   # ok | error
    row_count: int
    columns: List[str]
    rows: List[List[Any]]   # capped at 2000 rows
```

**Service** (`app/services/crm_reports.py`):
- `create_report(owner_sub, payload)` — generates `report_id = "RPT#{uuid4().hex[:12]}"`, writes META row to `T.crm_reports`.
- `get_report(report_id, owner_sub)` — reads META row; raises `PermissionError` if owner_sub mismatches (ownership enforced at data layer).
- `list_reports(owner_sub, cursor)` — queries `owner-reports-index` GSI on `T.crm_reports`; returns paginated list using `encode_cursor` / `decode_cursor` from `app/core/cursor.py:94`.
- `update_report(report_id, owner_sub, patch)` — conditional update on META row.
- `delete_report(report_id, owner_sub)` — deletes META row and all RUN rows via `batch_writer`.
- `run_report(report_id, owner_sub)` — evaluates the report definition against live DynamoDB data using module-specific data adapters (see below); writes a RUN row; returns `ReportRunOut`. Cap output at 2000 rows. Computation runs in `asyncio.to_thread` to avoid blocking the event loop.

**Module data adapters** (in `app/services/crm_reports.py`) — thin wrappers over existing table queries, reusing the iteration patterns already established in `app/services/csv_export.py:52` (`_iter_billing_entries`), `app/services/csv_export.py:90` (`_iter_contacts`), and `app/services/csv_export.py:113` (`_iter_questionnaire_responses`):
- `tickets` → paginated scan of `T.tickets` (PK per user or admin full scan for admin-owned reports)
- `contacts` → existing `_iter_contacts` pattern from `app/services/csv_export.py:90`
- `billing_ledger` → existing `_iter_billing_entries` pattern from `app/services/csv_export.py:52`
- `orders` → scan `T.orders` for owner_sub
- `subscriptions` → scan `T.subscriptions` for owner_sub
- `questionnaire_responses` → existing `_iter_questionnaire_responses` from `app/services/csv_export.py:113`

**Condition evaluation** — a pure-Python `_eval_condition(item, condition)` function supporting operators: `eq`, `neq`, `contains` (substring), `gt`, `lt`, `gte`, `lte`, `is_empty`, `not_empty`. Applied as a post-scan filter after fetching pages (mirrors DynamoDB FilterExpression semantics but client-side so all operators work on all field types).

**Router** (`app/routers/crm_reports.py`):
```
POST   /ui/crm/reports                    create_report   (require_ui_session)
GET    /ui/crm/reports                    list_reports    (require_ui_session)
GET    /ui/crm/reports/{report_id}        get_report      (require_ui_session)
PATCH  /ui/crm/reports/{report_id}        update_report   (require_ui_session)
DELETE /ui/crm/reports/{report_id}        delete_report   (require_ui_session)
POST   /ui/crm/reports/{report_id}/run    run_report      (require_ui_session)
```
All endpoints check `S.crm_reports_enabled` first (404 if off). Register in `app/main.py`.

**Acceptance Criteria**
- `POST /ui/crm/reports` with a valid `module=tickets`, `fields=["subject","status"]`, `conditions=[{field:"status",operator:"eq",value:"open"}]` returns `ReportOut` with a fresh `report_id`.
- `POST /ui/crm/reports/{id}/run` returns a `ReportRunOut` with `columns=["subject","status"]` and rows matching the filter.
- Only the owning user can read, update, delete, or run a report (ownership enforced in service layer; other users receive 403).
- Condition operators `eq`, `contains`, `is_empty`, `gt` are exercised by the hermetic pytest suite.
- With `CRM_REPORTS_ENABLED=0` all endpoints return 404.

**Dependencies**
- RPT-001 (tables + flag).

---

### RPT-003: Report grouping (GROUP BY) and aggregate functions
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Extend the report definition model and `run_report` execution engine (from RPT-002) to support GROUP BY on a chosen field with aggregate functions (SUM, AVG, COUNT, MIN, MAX) over numeric fields. This is the AOR "Grouped Report" capability.

**Model additions** (`app/models.py`):

```python
class AggregateSpec(BaseModel):
    field: str
    function: str   # SUM | AVG | COUNT | MIN | MAX

class ReportCreateIn(BaseModel):   # extend existing
    ...
    group_by: Optional[str] = None          # field name to group on
    aggregates: List[AggregateSpec] = Field(default_factory=list)
```

**Service additions** (`app/services/crm_reports.py`):
- `_apply_group_by(rows, group_by_field, aggregates)` — pure-Python grouping using `collections.defaultdict`. Groups the raw row dicts by the value of `group_by_field`; for each group computes each aggregate function over the named numeric field (coercing `Decimal` → `float` via the `_to_decimal`-safe pattern in `app/core/tables.py:11`). Returns a list of group dicts `{group_by_field: value, agg_field_FUNC: value, ...}`.
- Wire into `run_report`: after applying conditions filter and before capping at 2000 rows, if `group_by` is set, call `_apply_group_by` and replace the row list with group rows.

**Acceptance Criteria**
- A `tickets` report with `group_by="status"`, `aggregates=[{field:"*",function:"COUNT"}]` returns one row per distinct status value with the correct count.
- A `billing_ledger` report with `group_by="type"`, `aggregates=[{field:"amount_cents",function:"SUM"},{field:"amount_cents",function:"AVG"}]` returns correct totals and averages.
- Reports without `group_by` continue to behave as per RPT-002.
- Hermetic pytest covers COUNT, SUM, AVG, MIN, MAX aggregates with a mocked data set.

**Dependencies**
- RPT-002 (core report CRUD and run engine).

---

### RPT-004: Scheduled report email delivery
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Add recurring scheduled delivery of custom reports by email. A user can attach a schedule (cadence + recipient list) to any report they own; the background runner evaluates the report and emails the output CSV to recipients. This is the AOR "Schedule" capability, and it mirrors the audit export schedule in `app/services/audit_export_schedule.py` exactly.

**Data model**: Schedules reuse the `crm_reports` table (single-table design, same pattern as `audit_export_schedule.py:10` which stores schedules in `audit_exports` alongside export jobs):
- `pk = SCHEDULE#{schedule_id}`, `sk = "META"` on `T.crm_reports`
- Fields: `report_id`, `owner_sub`, `cadence` (daily/weekly/monthly), `recipients` (list of email strings), `format` (csv/json), `enabled`, `created_at`, `next_run_at` (numeric), `last_run_at`, `last_export_id`
- `GSI1PK = "RPT_SCHEDULES#ACTIVE"`, `GSI1SK = next_run_at` (numeric) → requires `attr_types={"GSI1SK": "N"}` in the `crm_reports` TableDef (add in RPT-001 if possible, or amend it here)
- Index name: `rpt-schedules-due-index`

**Service** (`app/services/crm_report_scheduler.py`) — mirror `app/services/audit_export_schedule.py`:
- `create_report_schedule(owner_sub, report_id, cadence, recipients, format)` — validates report ownership, writes SCHEDULE# row.
- `list_report_schedules(owner_sub)` — queries GSI filtered to `owner_sub`.
- `update_report_schedule(schedule_id, owner_sub, ...)` — patch cadence/recipients/enabled; disable moves `GSI1PK` to `RPT_SCHEDULES#DISABLED`.
- `delete_report_schedule(schedule_id, owner_sub)` — deletes the SCHEDULE# row.
- `run_due_report_schedules()` — queries `rpt-schedules-due-index` for `GSI1PK = "RPT_SCHEDULES#ACTIVE"` and `GSI1SK <= now_ts()`; for each due schedule: (1) calls `crm_reports.run_report(report_id, owner_sub)`, (2) serialises result to CSV using the same `generate_csv_rows` pattern in `app/services/csv_export.py:194`, (3) emails the CSV attachment via `app/services/alerts.send_alert_email` (`app/services/alerts.py:459`) — dev logs only, prod SES (SECOPS-007 parity), (4) advances `next_run_at` by one cadence offset (copy `CADENCE_OFFSETS` from `audit_export_schedule.py:40`).
- `start_report_scheduler_task()` — background `asyncio` loop (interval `S.crm_reports_scheduler_poll_interval`, default 300 s), gated by `S.crm_reports_enabled`; registered in `app/main.py` startup.

**Router additions** (`app/routers/crm_reports.py` — add to existing router):
```
POST   /ui/crm/reports/{report_id}/schedules         create schedule (require_ui_session)
GET    /ui/crm/reports/{report_id}/schedules         list schedules  (require_ui_session)
PATCH  /ui/crm/reports/{report_id}/schedules/{sid}   update schedule (require_ui_session)
DELETE /ui/crm/reports/{report_id}/schedules/{sid}   delete schedule (require_ui_session)
```
All routes declared before any `{report_id}` catch-all pattern.

**Settings additions** (`app/core/settings.py`):
```python
crm_reports_scheduler_poll_interval: int = _int_env("CRM_REPORTS_SCHEDULER_POLL_INTERVAL", 300)
```

**Acceptance Criteria**
- `POST /ui/crm/reports/{id}/schedules` with `cadence=daily`, `recipients=["a@b.com"]` returns a schedule with `next_run_at > now`.
- `run_due_report_schedules()` called with a due schedule invokes `run_report`, generates CSV output, and calls `send_alert_email` once per schedule.
- Disabling a schedule (`enabled=false`) moves its `GSI1PK` to `RPT_SCHEDULES#DISABLED` and the runner skips it.
- `start_report_scheduler_task()` is registered in `app/main.py` `on_startup` handlers.
- Hermetic pytest patches `crm_reports.run_report` and `alerts.send_alert_email` and asserts correct dispatch.

**Dependencies**
- RPT-002 (run_report), RPT-001 (flag + tables).

---

### RPT-005: Report charts (bar, line, pie)
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Attach an optional chart definition to a report so that the frontend can render a bar, line, or pie chart alongside the tabular output. This is the AOR "Charts" capability; the gap analysis marks it PARTIAL because recharts is already a dependency (`frontend/src/pages/earnings/EarningsPage.tsx:19` imports `BarChart`, `LineChart`, `PieChart`) but no report builder exists to attach charts to.

**Model additions** (`app/models.py`):

```python
class ChartConfig(BaseModel):
    chart_type: str = Field(..., pattern=r"^(bar|line|pie)$")
    x_field: str       # field name for x-axis / pie labels
    y_field: str       # field name for y-axis / pie values

class ReportCreateIn(BaseModel):   # extend existing
    ...
    chart: Optional[ChartConfig] = None
```

**Backend changes** (`app/services/crm_reports.py`):
- `chart` config is persisted on the META row; `run_report` returns it unchanged in `ReportRunOut` as an optional `chart: Optional[ChartConfig]` field. No server-side chart rendering — the frontend renders.

**Frontend** (`frontend/src/pages/reports/`):
- `ReportsPage.tsx` — lists user's saved reports, with a "New Report" button and run/edit/delete actions per row. Auth via `useAuthStore`.
- `ReportBuilderPage.tsx` — form for creating/editing a report definition: module selector (dropdown), field checkboxer, condition builder (add/remove condition rows with field/operator/value), aggregate builder, group-by picker, chart type picker with x/y field selectors (shown only when chart is enabled). Uses React Hook Form + Zod, shadcn/ui `Select`, `Input`, `Checkbox`, `Button`.
- `ReportRunView.tsx` — renders the last run result: a `DataTable` (shadcn/ui) for tabular rows and a recharts chart component (conditional on `chart_type`):
  - `bar` → `<BarChart>` with `<Bar dataKey={y_field}/>` from `recharts`
  - `line` → `<LineChart>` with `<Line dataKey={y_field}/>`
  - `pie` → `<PieChart>` with `<Pie dataKey={y_field} nameKey={x_field}/>`
  Each wraps in `<ResponsiveContainer width="100%" height={300}>`.
- API endpoint wrappers in `frontend/src/api/endpoints/crmReports.ts` (axios instance from `frontend/src/api/client.ts`; React Query keys `["crm-reports"]`, `["crm-report", id]`, `["crm-report-run", id]`).
- Routes added to `frontend/src/App.tsx`: `/crm/reports`, `/crm/reports/new`, `/crm/reports/:reportId/edit`.

**Acceptance Criteria**
- A report with `chart={chart_type:"bar",x_field:"status",y_field:"count"}` renders a `<BarChart>` in `ReportRunView`.
- A report without a chart renders only the data table.
- Pie chart renders for a grouped report where `x_field` is the group-by field and `y_field` is a COUNT aggregate.
- React Query `["crm-report-run", id]` is invalidated after `POST /run` completes.

**Dependencies**
- RPT-002, RPT-003 (for aggregated/grouped data to chart).

---

### RPT-006: Per-user configurable home dashboard with dashlets
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Implement a per-user configurable home dashboard: users can add, remove, and reorder dashlet tiles; the layout is persisted in `T.crm_dashboards`. This is the SuiteCRM Home Dashboard / DASH-001 capability.

**DynamoDB model** (table created in RPT-001):
`T.crm_dashboards`, PK `dashboard_id`, SK `"META"`:
```
{
  "dashboard_id": "DASH#{user_sub}#default",   # one default dashboard per user
  "sk": "META",
  "GSI1PK": "OWNER#{user_sub}",
  "GSI1SK": <created_at numeric>,
  "owner_sub": user_sub,
  "name": "Home",
  "dashlets": [                     # ordered list; each element is a dashlet config
    {
      "dashlet_id": "dlt_{uuid8}",
      "dashlet_type": "recent_tickets" | "calendar_today" | "my_contacts" | "billing_summary" | "saved_search" | "report",
      "title": str,
      "config": {}                  # type-specific config (e.g. report_id, saved_search_id, row_limit)
    }
  ],
  "created_at": int,
  "updated_at": int
}
```
At most 20 dashlets per dashboard. `dashlet_id` is a stable per-dashlet UUID within the layout list.

**Pydantic models** (`app/models.py`):
```python
class DashletConfig(BaseModel):
    dashlet_type: str
    title: str
    config: Dict[str, Any] = Field(default_factory=dict)

class DashletConfigOut(DashletConfig):
    dashlet_id: str

class DashboardOut(BaseModel):
    dashboard_id: str
    name: str
    owner_sub: str
    dashlets: List[DashletConfigOut]
    created_at: int
    updated_at: int

class DashboardUpdateIn(BaseModel):
    name: Optional[str] = None
    dashlets: Optional[List[DashletConfig]] = None
```

**Service** (`app/services/crm_dashboard.py`):
- `get_or_create_default_dashboard(user_sub)` — reads `DASH#{user_sub}#default` / `META`; creates an empty dashboard on first call.
- `update_dashboard(user_sub, patch)` — writes full `dashlets` list replacement (re-assigns stable `dashlet_id` to each element preserving existing IDs by position) or name update.
- `add_dashlet(user_sub, dashlet_type, title, config)` — appends a new dashlet; enforces ≤ 20 limit.
- `remove_dashlet(user_sub, dashlet_id)` — filters dashlet from list.
- `reorder_dashlets(user_sub, ordered_dashlet_ids)` — replaces `dashlets` in specified order, preserving configs.

**Router** (`app/routers/crm_dashboard.py`):
```
GET    /ui/crm/dashboard           get_or_create_default (require_ui_session)
PATCH  /ui/crm/dashboard           update_dashboard      (require_ui_session)
POST   /ui/crm/dashboard/dashlets  add_dashlet           (require_ui_session)
DELETE /ui/crm/dashboard/dashlets/{dashlet_id}  remove_dashlet  (require_ui_session)
POST   /ui/crm/dashboard/dashlets/reorder       reorder_dashlets (require_ui_session)
```
Static routes (`/dashlets`, `/dashlets/reorder`) declared before `/{dashlet_id}`. Register in `app/main.py`.

**Frontend** (`frontend/src/pages/reports/DashboardPage.tsx`):
- Grid layout (CSS grid / shadcn Card) of dashlets in the stored order.
- "Add Dashlet" button opens a dialog to pick `dashlet_type`; "Remove" (X) button per tile; drag-and-drop reorder (or up/down arrow buttons for simpler implementation) calls `/reorder`.
- Each dashlet tile renders its data (RPT-007 provides the built-in data sources; custom report/saved-search dashlets are stubs until RPT-007/RPT-008 deliver).
- Route: `/crm/dashboard` added to `frontend/src/App.tsx`.

**Acceptance Criteria**
- `GET /ui/crm/dashboard` for a new user creates and returns an empty `DashboardOut`.
- `POST /ui/crm/dashboard/dashlets` with `dashlet_type="recent_tickets"` appends the dashlet and returns the updated dashboard.
- `POST /ui/crm/dashboard/dashlets/reorder` with reordered IDs persists the new order.
- Adding a 21st dashlet returns 422.
- Dashboard layout is per-user (user A's changes do not affect user B).
- Hermetic pytest covers create, add, remove, reorder lifecycle.

**Dependencies**
- RPT-001 (tables + flag).

---

### RPT-007: Pre-built dashlet catalogue
**Type:** Feature  **Priority:** P2  **Estimate:** 3d

**Description**

Implement the backend data providers for the five standard built-in dashlet types and wire them into the dashlet rendering on the frontend. This is the DASH-003 "standard dashlet catalogue" capability. Each dashlet type is a small read-only query returning a capped list of items.

**Dashlet data endpoint** — a single polymorphic endpoint that dispatches to the appropriate data provider based on `dashlet_type`:

```
GET /ui/crm/dashboard/dashlets/{dashlet_id}/data
```
Auth: `require_ui_session`. Reads the dashlet config from the user's dashboard, routes to the appropriate provider, returns JSON.

**Dashlet type providers** (implemented in `app/services/crm_dashlet_data.py`):

1. `recent_tickets` — queries `T.tickets` for the calling user's most recent 10 tickets (or admin: all open tickets); reuses the existing tickets query path from `app/services/tickets.py`. Returns list of `{ticket_id, subject, status, created_at}`.

2. `calendar_today` — queries `T.calendar` for events on today's date for the user; reuses the calendar query pattern from `app/routers/calendar.py`. Returns list of `{event_id, title, start_ts, end_ts}`.

3. `my_contacts` — queries `T.contacts` for the user's contacts sorted by `last_contacted_at` descending (reuses `_iter_contacts` from `app/services/csv_export.py:90`). Returns up to 10 contacts `{contact_id, name, email}`.

4. `billing_summary` — reads the user's billing ledger last-30-days aggregate: total spend, transaction count (reuses `_iter_billing_entries` from `app/services/csv_export.py:52`). Returns `{total_cents, tx_count, period_days: 30}`.

5. `report` — runs (or returns the last cached run of) the `report_id` from the dashlet `config` dict; delegates to `crm_reports.run_report` / reads the last RUN row from `T.crm_reports`. Returns `ReportRunOut` shape. Requires RPT-002.

**Frontend dashlet renderers** (in `frontend/src/pages/reports/dashlets/`):
- `RecentTicketsDashlet.tsx` — table of ticket rows with status badge; links to `/tickets/{id}`.
- `CalendarTodayDashlet.tsx` — list of today's events with time; links to `/calendar`.
- `MyContactsDashlet.tsx` — contact cards; links to `/contacts/{id}`.
- `BillingSummaryDashlet.tsx` — KPI cards (total spend, transaction count).
- `ReportDashlet.tsx` — shows a `DataTable` + optional chart from `ReportRunOut`.

Each dashlet component calls `GET /ui/crm/dashboard/dashlets/{dashlet_id}/data` via React Query key `["dashlet-data", dashlet_id]`.

**Acceptance Criteria**
- `GET /ui/crm/dashboard/dashlets/{id}/data` with a `recent_tickets` dashlet returns up to 10 ticket objects.
- `GET .../data` with an unknown `dashlet_type` returns 422.
- Each of the five dashlet types is exercised in hermetic pytest with mocked DDB responses (no real `T.tickets`/`T.contacts`/`T.calendar`/`T.billing` queries).
- Frontend renders all five dashlet tile types in `DashboardPage`.

**Dependencies**
- RPT-006 (dashboard CRUD to store dashlet configs), RPT-002 (for `report` dashlet type).

---

### RPT-008: Saved searches as dashlets
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Allow users to save a named filter (a module + conditions) as a "Saved Search", and pin it as a `saved_search` dashlet tile on their dashboard. This is the DASH-002 capability.

**Service** (`app/services/crm_saved_searches.py`):
- `create_saved_search(owner_sub, name, module, filters)` — writes `saved_search_id = "SS#{uuid8}"` / `"META"` to `T.crm_saved_searches`; sets `GSI1PK = OWNER#{owner_sub}`, `GSI1SK = created_at` (numeric).
- `list_saved_searches(owner_sub, cursor)` — queries `owner-searches-index` GSI; pagination via `encode_cursor` / `decode_cursor` (`app/core/cursor.py:94`).
- `get_saved_search(saved_search_id, owner_sub)` — ownership-enforced get.
- `delete_saved_search(saved_search_id, owner_sub)` — deletes the row.
- `run_saved_search(saved_search_id, owner_sub)` — reads the saved search, constructs an ephemeral `ReportCreateIn`-equivalent (no persistence) and calls `crm_reports._fetch_and_filter(module, fields=["*"], conditions=filters)` (a shared helper extracted from `run_report` in RPT-002). Returns `{module, columns, rows, row_count}` capped at 500 rows.

**Router** (`app/routers/crm_saved_searches.py`):
```
POST   /ui/crm/saved-searches               create     (require_ui_session)
GET    /ui/crm/saved-searches               list       (require_ui_session)
GET    /ui/crm/saved-searches/{id}          get        (require_ui_session)
DELETE /ui/crm/saved-searches/{id}          delete     (require_ui_session)
POST   /ui/crm/saved-searches/{id}/run      run        (require_ui_session)
```
Register in `app/main.py`.

**Dashlet data extension** (`app/services/crm_dashlet_data.py` from RPT-007):
- Wire `saved_search` dashlet type: reads `saved_search_id` from dashlet config, calls `crm_saved_searches.run_saved_search(...)`, returns the result dict.

**Frontend** (`frontend/src/pages/reports/SavedSearchesPage.tsx`):
- List of saved searches with name, module, condition summary, and "Run" / "Add to Dashboard" / "Delete" actions.
- "New Saved Search" opens a builder dialog (module selector + condition rows — reuses `ReportBuilderPage` condition builder component from RPT-005).
- "Add to Dashboard" calls `POST /ui/crm/dashboard/dashlets` with `dashlet_type="saved_search"` and `config={saved_search_id}`.
- Route `/crm/saved-searches` added to `frontend/src/App.tsx`.

**Acceptance Criteria**
- `POST /ui/crm/saved-searches` with `module="tickets"`, `filters=[{field:"status",operator:"eq",value:"open"}]` returns a `SavedSearchOut` with a stable `saved_search_id`.
- `POST /ui/crm/saved-searches/{id}/run` returns a filtered result list.
- Pinning a saved search as a dashlet and calling `GET /ui/crm/dashboard/dashlets/{dashlet_id}/data` returns the run result.
- Ownership enforced: a different user cannot run or delete another user's saved search (403).
- Hermetic pytest covers create, run, and ownership enforcement.

**Dependencies**
- RPT-001 (tables + flag), RPT-006 (dashboard dashlet add), RPT-007 (saved_search dashlet type in crm_dashlet_data).

---

### RPT-009: Extended CSV export for additional modules
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Extend `GET /ui/export/csv` (currently at `app/routers/csv_export.py:27`) to cover four additional source modules: `tickets`, `subscriptions`, `orders`, and `contacts_crm`. The endpoint, rate-limiting, streaming response, and RFC 4180 formatting are all unchanged — only new iterator+formatter pairs are added to `app/services/csv_export.py`.

The gap analysis marks this capability PARTIAL because `billing_ledger`, `contacts`, and `questionnaire_responses` are already exported; `tickets`, `subscriptions`, `orders`, and a richer contacts export are absent. No new tables or flags are needed — this is a pure extension of existing code.

**Service additions** (`app/services/csv_export.py`):

1. `tickets` source:
   - Columns: `["Ticket ID", "Subject", "Status", "Priority", "Owner", "Assigned Agent", "Created At", "Updated At", "Space"]`
   - `_iter_tickets(user_sub)` — queries `T.tickets` by `OWNER#{user_sub}` partition; if caller is admin (pass `is_admin` flag), scans all tickets. Handles `LastEvaluatedKey` pagination loop (`FilterExpression` on sparse attrs requires looping per CLAUDE.md gotcha).
   - `_format_ticket_row(item)` — extracts fields; sanitizes via `_sanitize_csv_field`.

2. `subscriptions` source:
   - Columns: `["Subscription ID", "Plan ID", "Status", "Start Date", "End Date", "Amount Cents", "Currency", "Provider"]`
   - `_iter_subscriptions(user_sub)` — queries `T.subscriptions` with `pk = USER#{user_sub}`.

3. `orders` source:
   - Columns: `["Order ID", "Status", "Total Cents", "Currency", "Item Count", "Created At"]`
   - `_iter_orders(user_sub)` — queries `T.orders` with pagination.

4. `contacts_crm` source (richer alternative to existing `contacts`):
   - Columns: `["Name", "Email", "Phone", "Company", "Notes", "Tags", "Source", "Created At"]`
   - Reuses `_iter_contacts` but with an extended formatter including `notes` and `source` fields.

**Router changes** (`app/routers/csv_export.py`):
- Extend `VALID_SOURCES` set to include `"tickets"`, `"subscriptions"`, `"orders"`, `"contacts_crm"`.
- Update the `source` query param `pattern` regex to include the four new values.
- Pass `is_admin` (from session `role >= ADMIN`) into `generate_csv_rows` for the `tickets` source so admin users can export all tickets.

**Acceptance Criteria**
- `GET /ui/export/csv?source=tickets` returns a valid CSV with header row `Ticket ID,Subject,...` for the calling user's tickets.
- `GET /ui/export/csv?source=subscriptions` returns user's subscription rows.
- `GET /ui/export/csv?source=orders` returns user's order rows.
- `GET /ui/export/csv?source=contacts_crm` returns contacts with the extended column set.
- Rate limit (5 per 60 s) and existing sources (`billing_ledger`, `contacts`, `questionnaire_responses`) are unchanged.
- Hermetic pytest exercises each new source against moto-backed tables with a small fixture data set.

**Dependencies**
- RPT-001 (flag — check `S.crm_reports_enabled` before serving new sources; existing sources remain ungated).
