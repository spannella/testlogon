# CRM Opportunities Tickets — Opportunities, Sales Pipeline & Forecasts

**Area:** Opportunities, Sales Pipeline & Forecasts (SuiteCRM Tier 1)

**What SuiteCRM provides that testlogon currently lacks:**
SuiteCRM's Opportunities module is the heart of a B2B sales workflow: a named deal record with a configurable stage pipeline (Prospecting → Qualification → Proposal → Negotiation → Closed Won / Lost), a probability and weighted-amount forecast, a contact-role junction (Decision Maker, Evaluator, Influencer), quota management per rep/team, forecast worksheets by period/category, and a funnel report. The testlogon platform has zero of these capabilities today. Two generic subsystems (`app/services/activity_feed.py` and `app/routers/calendar.py`) are partial foundations once a core Opportunity entity exists. The planned PTY-001..PTY-015 Party/CRM buildout (Contacts + Org Accounts) is a prerequisite for linking Opportunities to Contacts and Accounts; that work is unbuilt but fully specced in `docs/ofbiz/specs/`.

**Cross-cutting constraints for all tickets in this file:**
- All changes are **additive and flag-gated default-off**; existing surfaces are byte-for-byte unchanged with the flag off. Master gate: `S.sales_pipeline_enabled` (`SALES_PIPELINE_ENABLED`, default `false`).
- Single-table DynamoDB for the `sales_opportunities` table (`pk`, `sk`); numeric GSI sort keys must carry `attr_types={"created_at": "N", "close_date": "N"}` per the CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha.
- Reuse existing primitives: `app/services/alerts.audit_event` and `send_alert_email`, `app/core/normalize.py`, `app/core/cursor.py` (pagination), `app/core/time.now_ts()`, `app/services/sessions.require_ui_session`, `app/core/tables._safe_table` / `_FloatSafeTable` proxy.
- Never fork existing modules — add new files (`app/services/opportunities.py`, `app/routers/opportunities.py`, etc.) and register in `app/main.py` in the same block as `contacts_router` and `activity_feed_router` (lines 683–685 of `app/main.py`).
- Dev/prod parity (SECOPS-007): no `if S.dev_mode` branches in business logic; same code path in both environments.
- Hermetic offline tests: moto in-memory tables bound to frozen `T.sales_opportunities` (and relevant sibling handles) via `object.__setattr__`, frozen `S.sales_pipeline_enabled` via `object.__setattr__`; no real AWS/network.

---

### OPP-001: Opportunity data model, DynamoDB table, and feature flag
**Type:** Feature  **Priority:** P0  **Estimate:** 2d

**Description**

Lay the data-model and infrastructure foundation that every other OPP ticket depends on. Zero application logic ships in this ticket; it only provides the table, the setting, and the Pydantic models.

**Settings (`app/core/settings.py`)**

Add adjacent to `contacts_table_name` at line 498:

```python
sales_pipeline_enabled: bool = os.environ.get("SALES_PIPELINE_ENABLED", "false").lower() in ("1", "true", "yes", "on")
sales_opportunities_table_name: str = os.environ.get("DDB_SALES_OPPORTUNITIES_TABLE", "sales_opportunities")
sales_quotas_table_name: str = os.environ.get("DDB_SALES_QUOTAS_TABLE", "sales_quotas")
```

**Tables (`scripts/local-ddb-init.py`)**

Add two `TableDef` entries to `_table_defs()`, positioned after the existing `Contacts` `TableDef` at line 691:

```python
# Sales pipeline — Opportunities (OPP-001)
TableDef(
    _resolve_table_name(S.sales_opportunities_table_name, "sales_opportunities"),
    "pk",   # USER#{user_sub} for ownership; OPP#{opp_id} for GSI1 direct-by-id lookup
    "sk",
    gsi=[
        {"index_name": "GSI_BY_USER_CLOSE",   "partition_key": "owner_sub", "sort_key": "close_date"},
        {"index_name": "GSI_BY_STAGE",        "partition_key": "stage",     "sort_key": "close_date"},
        {"index_name": "GSI_DIRECT",          "partition_key": "opp_id"},
    ],
    attr_types={"close_date": "N", "created_at": "N"},
),
# Sales pipeline — Quotas (OPP-001)
TableDef(
    _resolve_table_name(S.sales_quotas_table_name, "sales_quotas"),
    "pk",   # USER#{user_sub}
    "sk",   # QUOTA#{period_key}
),
```

**`T.sales_opportunities` and `T.sales_quotas` (`app/core/tables.py`)**

Add two `Any` fields to the `Tables` dataclass after `contacts` (line 129) and wire them in the `T` singleton factory at the bottom of the file using the `_safe_table(...)` pattern used by every other table handle.

**Pydantic models (`app/models.py`)**

Add to `app/models.py` (near the contacts/ticket models):

```python
OPPORTUNITY_STAGES = (
    "prospecting", "qualification", "needs_analysis", "value_proposition",
    "id_decision_makers", "proposal_price_quote", "negotiation_review",
    "closed_won", "closed_lost",
)
LEAD_SOURCE_CHOICES = (
    "cold_call", "existing_customer", "self_generated", "employee", "partner",
    "public_relations", "direct_mail", "conference", "trade_show", "web_site",
    "word_of_mouth", "email", "campaign", "other",
)

class OpportunityCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    stage: str = Field(..., description="One of OPPORTUNITY_STAGES")
    amount_cents: int = Field(ge=0)
    close_date: int = Field(..., description="Unix timestamp (integer seconds)")
    probability: int = Field(ge=0, le=100, default=0)
    lead_source: Optional[str] = None
    description: Optional[str] = Field(None, max_length=4096)
    account_party_id: Optional[str] = None   # links to PTY PARTY_GROUP once PTY-008 ships
    contact_party_id: Optional[str] = None   # links to PTY PERSON once PTY-004 ships

class OpportunityUpdateIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    stage: Optional[str] = None
    amount_cents: Optional[int] = Field(None, ge=0)
    close_date: Optional[int] = None
    probability: Optional[int] = Field(None, ge=0, le=100)
    lead_source: Optional[str] = None
    description: Optional[str] = Field(None, max_length=4096)
    account_party_id: Optional[str] = None
    contact_party_id: Optional[str] = None

class OpportunityOut(BaseModel):
    opp_id: str
    owner_sub: str
    name: str
    stage: str
    amount_cents: int
    weighted_amount_cents: int   # = amount_cents * probability / 100
    close_date: int
    probability: int
    lead_source: Optional[str]
    description: Optional[str]
    account_party_id: Optional[str]
    contact_party_id: Optional[str]
    created_at: int
    updated_at: int
```

Validate `stage` against `OPPORTUNITY_STAGES` and `lead_source` against `LEAD_SOURCE_CHOICES` (or `None`) with a `@validator` that raises `ValueError` on unknown values.

**Acceptance Criteria**
- `sales_opportunities` and `sales_quotas` DynamoDB tables are created by `scripts/local-ddb-init.py` with the correct GSIs and `attr_types`.
- `T.sales_opportunities` and `T.sales_quotas` are accessible in tests via `from app.core.tables import T`.
- `S.sales_pipeline_enabled` defaults to `False`; setting `SALES_PIPELINE_ENABLED=1` flips it to `True`.
- `OpportunityCreateIn`, `OpportunityUpdateIn`, `OpportunityOut` models pass `pytest` with valid + invalid field values (hermetic, no DDB).
- Unknown `stage` returns `ValueError`; unknown `lead_source` returns `ValueError`.
- No existing table definitions or handles are changed.

**Dependencies**
- None (pure infrastructure; no other OPP ticket required).
- Flag: `SALES_PIPELINE_ENABLED` (introduced here, default false).

---

### OPP-002: Opportunity CRUD service and router
**Type:** Feature  **Priority:** P0  **Estimate:** 3d

**Description**

Implement the full Opportunity CRUD service and REST router, gated by `S.sales_pipeline_enabled`.

**Service (`app/services/opportunities.py`)**

Single-table DDB layout on `T.sales_opportunities`:

| pk | sk | Description |
|---|---|---|
| `USER#{owner_sub}` | `OPP#{opp_id}` | Opportunity META row (all fields) |

Additional denormalized attributes on the META row for GSI projections:
- `opp_id`, `owner_sub`, `stage`, `close_date` (integer), `created_at` (integer), `amount_cents`, `probability`, `weighted_amount_cents`.

Functions:

```python
def _require_flag() -> None:
    if not S.sales_pipeline_enabled:
        raise HTTPException(503, detail={"code": "sales_pipeline_disabled"})

def create_opportunity(owner_sub: str, data: OpportunityCreateIn) -> OpportunityOut: ...
def get_opportunity(owner_sub: str, opp_id: str) -> OpportunityOut: ...   # 404 if not found or not owner
def update_opportunity(owner_sub: str, opp_id: str, data: OpportunityUpdateIn) -> OpportunityOut: ...
def delete_opportunity(owner_sub: str, opp_id: str) -> None: ...
def list_opportunities(
    owner_sub: str,
    stage: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Tuple[List[OpportunityOut], Optional[str]]: ...
```

- `create_opportunity` generates `opp_id = "opp_" + uuid4().hex`, writes to `pk=USER#{owner_sub}`, `sk=OPP#{opp_id}`. Validates `stage` and `lead_source`. Computes `weighted_amount_cents = amount_cents * probability // 100`. Emits `audit_event("opportunity.created", owner_sub, None, {"opp_id": opp_id})` via `app/services/alerts.audit_event`.
- `get_opportunity` uses `T.sales_opportunities.get_item(Key={"pk": f"USER#{owner_sub}", "sk": f"OPP#{opp_id}"})`. Returns 404 if missing.
- `list_opportunities` queries `GSI_BY_USER_CLOSE` (`owner_sub` partition key, `close_date` sort key) with optional `FilterExpression` on `stage`; uses `app/core/cursor.encode_cursor` / `decode_cursor` for pagination. Note: DDB `FilterExpression` does not reduce page size — loop via `LastEvaluatedKey` for sparse stage filters (per CLAUDE.md gotcha on FilterExpression).
- `update_opportunity` uses `update_item` with a dynamic `UpdateExpression` built from non-None fields; recomputes `weighted_amount_cents` whenever `amount_cents` or `probability` changes. Uses optimistic concurrency via `ConditionExpression=Attr("updated_at").eq(current_updated_at)` to prevent lost-update races.
- `delete_opportunity` calls `delete_item`; emits `audit_event("opportunity.deleted", ...)`.
- All DDB writes go through `T.sales_opportunities` which is wrapped in `_safe_table` / `_FloatSafeTable` (handles `float → Decimal` coercion).

**Router (`app/routers/opportunities.py`)**

```python
router = APIRouter(prefix="/ui/sales/opportunities", tags=["sales-pipeline"])

POST   /                          # create; body=OpportunityCreateIn; returns OpportunityOut
GET    /                          # list; query ?stage=&cursor=&limit=; returns {"items": [...], "next_cursor": ...}
GET    /{opp_id}                  # get single; returns OpportunityOut; 404 if not owned
PATCH  /{opp_id}                  # update; body=OpportunityUpdateIn; returns OpportunityOut
DELETE /{opp_id}                  # soft-delete (set deleted_at); 204
```

All endpoints use `Depends(require_ui_session)` from `app/services/sessions`. Each calls `_require_flag()` before any DDB operation.

**`app/main.py` registration**

Import and `app.include_router(opportunities_router)` adjacent to `contacts_router` at line 683.

**Acceptance Criteria**
- `POST /ui/sales/opportunities` with valid payload creates a record; returns `OpportunityOut` with correct `weighted_amount_cents`.
- `GET /ui/sales/opportunities` lists only the caller's opportunities; stage filter works.
- `GET /ui/sales/opportunities/{opp_id}` returns 404 for another user's opportunity.
- `PATCH /ui/sales/opportunities/{opp_id}` updates subset of fields; recomputes `weighted_amount_cents`.
- `DELETE /ui/sales/opportunities/{opp_id}` returns 204; subsequent GET returns 404.
- With `SALES_PIPELINE_ENABLED=false`, all endpoints return 503.
- Hermetic pytest covers CRUD, pagination cursor, stage filter, authz (wrong owner → 404), flag-off (→ 503), audit_event emission.

**Dependencies**
- OPP-001 (table + models + flag).

---

### OPP-003: Sales stage pipeline management and Kanban UI
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Add a configurable stage pipeline and a Kanban board frontend view for opportunities.

**Stage configuration (backend)**

SuiteCRM ships with a default stage list but allows admins to rename and reorder stages. Implement a lightweight stage config stored in `T.sales_opportunities` under `pk="STAGE_CONFIG"`, `sk="META"` as a JSON list `[{stage_key, label, probability_default, order, is_won, is_lost}]`. If the row is absent, fall back to `OPPORTUNITY_STAGES` from OPP-001.

New admin endpoints in `app/routers/opportunities.py`:

```python
GET    /ui/sales/stages                          # list stages (public to sales users); no auth required beyond session
PUT    /ui/admin/sales/stages                    # replace stage list; Depends(require_admin_session)
```

`PUT /ui/admin/sales/stages` validates that exactly one stage has `is_won=True` and exactly one has `is_lost=True`, and no duplicate `stage_key` values. Calls `audit_event("sales_stage_config.updated", admin_sub, None, {...})`.

**Stage transition (`app/services/opportunities.py`)**

`update_opportunity` must validate stage transitions: once an opportunity is in `closed_won` or `closed_lost`, it may only be re-opened to `negotiation_review` (configurable via a `SALES_PIPELINE_ALLOW_REOPEN` env flag, default `true`). On any stage change, emit `audit_event("opportunity.stage_changed", owner_sub, None, {"opp_id": ..., "from_stage": ..., "to_stage": ...})`.

**Frontend Kanban view (`frontend/src/pages/sales/`)**

Create `frontend/src/pages/sales/OpportunitiesPage.tsx` (lazy-loaded):
- Fetches `GET /ui/sales/stages` to build column headers.
- Fetches `GET /ui/sales/opportunities` (all stages) and groups cards by `stage`.
- Renders a horizontal scrollable Kanban board using the same shadcn/ui `Card` primitives used by `frontend/src/pages/tickets/TicketsPage.tsx` (mirror the Kanban column pattern at `app/routers/ticket_boards.py`).
- Each card shows `name`, `amount_cents` (formatted), `close_date`, `probability %`.
- Drag-and-drop (via `@hello-pangea/dnd`, already used in other pages) updates the stage via `PATCH /ui/sales/opportunities/{opp_id}`.
- Add route `/sales/opportunities` to `frontend/src/App.tsx`.

**Frontend API layer (`frontend/src/api/endpoints/sales.ts`)**

Add typed wrappers: `createOpportunity`, `listOpportunities`, `getOpportunity`, `updateOpportunity`, `deleteOpportunity`, `listStages`, using the `axios` instance from `frontend/src/api/client.ts`.

**Acceptance Criteria**
- `GET /ui/sales/stages` returns the default stage list when no config row exists.
- `PUT /ui/admin/sales/stages` by admin replaces the list; non-admin gets 403; invalid list (no `is_won` or duplicate `stage_key`) returns 400.
- Stage transition to `closed_won`/`closed_lost` is tracked via `audit_event`.
- Frontend Kanban loads columns from the stages API, not from a hardcoded enum.
- Drag-and-drop emits `PATCH` and the card moves to the new column.
- With flag off, all endpoints return 503.
- Hermetic pytest: stage config CRUD, transition validation, flag-off.

**Dependencies**
- OPP-001, OPP-002.

---

### OPP-004: Opportunity–Contact role junction
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

SuiteCRM supports multiple contacts per opportunity, each with a role (Decision Maker, Evaluator, Influencer, Champion, etc.). Implement the junction entity in the `sales_opportunities` single-table and expose it via sub-resource endpoints.

**DDB layout (new item types on `T.sales_opportunities`)**

| pk | sk | Description |
|---|---|---|
| `USER#{owner_sub}` | `OPP#{opp_id}#CONTACT#{contact_ref}` | Opportunity–Contact role row |

Fields on the role row: `opp_id`, `contact_ref` (party_id once PTY ships; otherwise a free-text display name or platform `user_sub`), `contact_role` (enum), `created_at`, `owner_sub`.

```python
CONTACT_ROLES = (
    "decision_maker", "evaluator", "influencer", "champion",
    "end_user", "executive_sponsor", "technical_buyer", "other",
)
```

New Pydantic models in `app/models.py`:

```python
class OppContactRoleIn(BaseModel):
    contact_ref: str = Field(..., min_length=1, max_length=255)
    contact_role: str

class OppContactRoleOut(BaseModel):
    opp_id: str
    contact_ref: str
    contact_role: str
    created_at: int
```

**Service functions (`app/services/opportunities.py`)**

```python
def add_contact_role(owner_sub: str, opp_id: str, data: OppContactRoleIn) -> OppContactRoleOut: ...
def list_contact_roles(owner_sub: str, opp_id: str) -> List[OppContactRoleOut]: ...
def remove_contact_role(owner_sub: str, opp_id: str, contact_ref: str) -> None: ...
```

`add_contact_role` uses `put_item` with `ConditionExpression=Attr("sk").not_exists()` to prevent duplicates for the same `contact_ref` on the same opportunity (returns 409 on conflict). Validates that the opportunity exists and belongs to `owner_sub` first (calls `get_opportunity`). Validates `contact_role` against `CONTACT_ROLES`.

`list_contact_roles` queries `pk=USER#{owner_sub}` with `KeyConditionExpression=pk.eq(...) & sk.begins_with(f"OPP#{opp_id}#CONTACT#")`.

**Router endpoints (append to `app/routers/opportunities.py`)**

```python
POST   /ui/sales/opportunities/{opp_id}/contacts          # add contact role
GET    /ui/sales/opportunities/{opp_id}/contacts          # list contact roles
DELETE /ui/sales/opportunities/{opp_id}/contacts/{contact_ref}   # remove
```

All three use `Depends(require_ui_session)` and call `_require_flag()`. The `OpportunityOut` model gains an optional `contact_roles: List[OppContactRoleOut] = []` field populated (lazily) by a `include_contacts=true` query param on the GET single-opportunity endpoint.

**PTY integration note:** Once PTY-004 (party CRUD) and PTY-006 (contact mechanisms) are implemented, `contact_ref` should be resolved to a `CrmPartyOut` using `party.get_party(contact_ref)` and the contact's name/email surfaced in `OppContactRoleOut`. This is a follow-up extension; for now `contact_ref` is stored as-is.

**Acceptance Criteria**
- `POST /ui/sales/opportunities/{opp_id}/contacts` adds a contact role; duplicate `contact_ref` on same opp returns 409.
- `GET /ui/sales/opportunities/{opp_id}/contacts` returns all role rows for the opp.
- `DELETE /ui/sales/opportunities/{opp_id}/contacts/{contact_ref}` removes the row; returns 404 if not present.
- Adding a contact role to another user's opportunity returns 404 (ownership enforced).
- Unknown `contact_role` returns 400.
- With flag off, all sub-resource endpoints return 503.
- Hermetic pytest covers add / list / remove / duplicate-409 / authz / flag-off.

**Dependencies**
- OPP-001, OPP-002.
- Future extension: PTY-004 (party resolution by `contact_ref`).

---

### OPP-005: Sales quota management and forecast worksheets
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Implement two related forecast capabilities: (1) admin-managed sales quotas per rep/period, and (2) per-rep forecast worksheets where a rep categorizes their pipeline amount for a period.

**Quota entity (`T.sales_quotas`)**

DDB layout:

| pk | sk | Description |
|---|---|---|
| `USER#{user_sub}` | `QUOTA#{period_key}` | Rep quota row |
| `TEAM#{team_id}` | `QUOTA#{period_key}` | Team quota row (future; ignored for now) |

Fields: `user_sub`, `period_type` (`monthly`/`quarterly`/`annual`), `period_key` (e.g. `2026-Q2`, `2026-06`), `target_amount_cents`, `created_at`, `updated_at`, `set_by_sub` (admin who set it).

New Pydantic models in `app/models.py`:

```python
class SalesQuotaIn(BaseModel):
    user_sub: str
    period_type: str   # monthly | quarterly | annual
    period_key: str    # e.g. "2026-Q2"
    target_amount_cents: int = Field(ge=0)

class SalesQuotaOut(BaseModel):
    user_sub: str
    period_type: str
    period_key: str
    target_amount_cents: int
    created_at: int
    updated_at: int
    set_by_sub: str
```

**Forecast worksheet entity (also in `T.sales_opportunities`)**

| pk | sk | Description |
|---|---|---|
| `USER#{user_sub}` | `FORECAST#{period_key}` | Forecast worksheet row |

Fields: `user_sub`, `period_key`, `committed_cents`, `best_case_cents`, `pipeline_cents`, `closed_cents` (read-only, auto-computed from `closed_won` opportunities in the period), `notes`, `created_at`, `updated_at`.

```python
class ForecastWorksheetIn(BaseModel):
    period_key: str
    committed_cents: int = Field(ge=0)
    best_case_cents: int = Field(ge=0)
    pipeline_cents: int = Field(ge=0)
    notes: Optional[str] = None

class ForecastWorksheetOut(BaseModel):
    user_sub: str
    period_key: str
    committed_cents: int
    best_case_cents: int
    pipeline_cents: int
    closed_cents: int      # auto-computed sum of closed_won opps in period
    quota_cents: int       # from SalesQuotaOut if one exists for the period, else 0
    attainment_pct: int    # closed_cents * 100 // quota_cents (or 0 if no quota)
    notes: Optional[str]
    created_at: int
    updated_at: int
```

**Service functions**

In `app/services/opportunities.py`:

```python
# Quota
def set_quota(admin_sub: str, data: SalesQuotaIn) -> SalesQuotaOut: ...     # admin only
def get_quota(user_sub: str, period_key: str) -> Optional[SalesQuotaOut]: ...
def list_quotas_for_user(user_sub: str) -> List[SalesQuotaOut]: ...

# Forecast worksheet
def upsert_forecast(user_sub: str, data: ForecastWorksheetIn) -> ForecastWorksheetOut: ...
def get_forecast(user_sub: str, period_key: str) -> ForecastWorksheetOut: ...
```

`upsert_forecast` computes `closed_cents` by scanning `GSI_BY_USER_CLOSE` for `owner_sub=user_sub` filtered on `stage=closed_won` and a `close_date` range corresponding to the `period_key` (month = first/last second of that calendar month; quarter = first/last second of that quarter). Uses `app/core/time.now_ts()` indirectly for the current timestamp. Resolves the quota from `T.sales_quotas` and computes `attainment_pct`.

**Router endpoints (in `app/routers/opportunities.py`)**

```python
# Admin quota management
POST   /ui/admin/sales/quotas                  # set quota; Depends(require_admin_session)
GET    /ui/admin/sales/quotas/{user_sub}       # list quotas for rep; Depends(require_admin_session)

# Rep forecast worksheet (self-service)
PUT    /ui/sales/forecast/{period_key}         # upsert worksheet; Depends(require_ui_session)
GET    /ui/sales/forecast/{period_key}         # get worksheet; Depends(require_ui_session)
```

The `PUT /ui/sales/forecast/{period_key}` route must be declared BEFORE any `/{opp_id}` route in the router to prevent FastAPI capturing the literal `forecast` as an `opp_id` (same issue as the `schedules` / `/{export_id}` ordering in `audit_export.py`).

**Acceptance Criteria**
- `POST /ui/admin/sales/quotas` by admin creates a quota row; non-admin gets 403.
- `GET /ui/admin/sales/quotas/{user_sub}` returns all quotas for a rep.
- `PUT /ui/sales/forecast/2026-Q2` creates/updates a worksheet; `closed_cents` is auto-computed from `closed_won` opportunities whose `close_date` falls in the quarter.
- `quota_cents` is populated from the quota table if a matching quota exists, else 0.
- `attainment_pct` is computed correctly (0 if no quota).
- With flag off, all endpoints return 503.
- Hermetic pytest: quota CRUD, forecast upsert, closed-cents computation from mock opps, attainment calculation, flag-off.

**Dependencies**
- OPP-001, OPP-002 (opportunities needed for `closed_cents` computation).

---

### OPP-006: Pipeline funnel report and frontend dashboard
**Type:** Feature  **Priority:** P2  **Estimate:** 3d

**Description**

Implement a pipeline funnel report endpoint (opportunities grouped by stage with total amount, weighted amount, and count) and a frontend dashboard page that renders this as a funnel/bar chart.

**Report service (`app/services/opportunities.py`)**

```python
class PipelineStageMetric(TypedDict):
    stage: str
    label: str
    count: int
    total_amount_cents: int
    weighted_amount_cents: int
    avg_close_date: Optional[int]

def pipeline_report(
    owner_sub: str,
    close_date_from: Optional[int] = None,
    close_date_to: Optional[int] = None,
) -> List[PipelineStageMetric]: ...
```

`pipeline_report` queries `GSI_BY_USER_CLOSE` for `owner_sub`, applies an optional close_date range filter via `KeyConditionExpression` on the sort key (leverages `between` expression so DDB index scan is bounded), then groups results in Python by `stage`, summing `amount_cents` and `weighted_amount_cents` and counting records. Returns one `PipelineStageMetric` per stage in the configured stage order (reads stage config from the same `STAGE_CONFIG` META row introduced in OPP-003; falls back to `OPPORTUNITY_STAGES`). Stages with no opportunities still appear in the result with zero counts (so the funnel renders correctly).

**Admin cross-user report**

Admin variant: `pipeline_report_all(admin_sub: str, ...)` scans `GSI_BY_STAGE` to aggregate across all users for each stage. Gated by `Depends(require_admin_session)`.

**Router endpoints**

```python
GET /ui/sales/reports/pipeline           # caller's own pipeline; query ?from=&to= (Unix ts); Depends(require_ui_session)
GET /ui/admin/sales/reports/pipeline     # all reps; Depends(require_admin_session)
```

Response model:

```python
class PipelineReportOut(BaseModel):
    stages: List[PipelineStageMetric]
    total_amount_cents: int           # sum across all non-closed stages
    total_weighted_cents: int
    generated_at: int
```

Both endpoints call `_require_flag()`.

**Frontend dashboard (`frontend/src/pages/sales/SalesDashboard.tsx`)**

Create a sales dashboard page with two sections:
1. **Pipeline funnel chart** — a horizontal bar chart (using `recharts` `BarChart`, already a dependency in `package.json`) showing `total_amount_cents` per stage. Bars are colored by stage position (green = closed won, red = closed lost, blue = active stages).
2. **Forecast summary table** — `GET /ui/sales/forecast/{current_period}` showing committed / best case / pipeline vs. quota with an attainment progress bar using the shadcn/ui `Progress` component.

Add route `/sales/dashboard` to `frontend/src/App.tsx`. Add "Sales" entry to the sidebar in `frontend/src/components/layout/Sidebar.tsx` (visible only when `sales_pipeline_enabled` feature is on — read from a new `GET /ui/sales/feature-status` lightweight endpoint that returns `{"enabled": bool}`).

**Frontend API layer additions (`frontend/src/api/endpoints/sales.ts`)**

Add: `getPipelineReport`, `getAdminPipelineReport`, `getForecast`, `listStages`, `getSalesFeatureStatus`.

**Acceptance Criteria**
- `GET /ui/sales/reports/pipeline` returns a metric per stage; stages with zero opps appear with count=0.
- Date range filters correctly bound the `close_date` scan.
- `GET /ui/admin/sales/reports/pipeline` aggregates across all users; non-admin gets 403.
- Frontend dashboard renders a bar chart from the report data.
- Forecast summary shows attainment progress bar.
- With flag off, all report endpoints return 503 and sidebar entry is hidden.
- Hermetic pytest: pipeline grouping, date filter, zero-count stage inclusion, admin vs. user authz, flag-off.

**Dependencies**
- OPP-001, OPP-002 (opportunity data), OPP-003 (stage config), OPP-005 (forecast data).
