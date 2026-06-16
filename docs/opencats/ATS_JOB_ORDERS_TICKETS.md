# ATS Job Orders Tickets — Job Order / Requisition Entity

**Area:** OpenCATS ATS / Recruiting — Tier 1 Core Entity: **Job Order** (gap analysis §B, `docs/opencats/OPENCATS_GAP_ANALYSIS.md:53-61`, :100-102)

**What OpenCATS / SuiteCRM provides that testlogon currently lacks:**
OpenCATS is built around four entities — Companies, Contacts, **Job Orders**, Candidates — joined by a candidate↔job-order pipeline. The **Job Order (requisition)** is the central recruiting record: a client opening with a `title`, an employment `type` (Hire / Contract / Contract-to-Hire / Referral), a 7-state status workflow (Active / On Hold / Full / Closed / Canceled / Lead / Upcoming), `hot` and `public` (career-portal) flags, commercial fields (pay rate, bill rate, duration, openings count), a location (city/state), a free-text description, and links to the **client company**, **client contact**, and one or more **recruiter owners**. It also drives list views (open / hot / mine) and an **openings-remaining-vs-placed** counter that the pipeline later decrements. testlogon has zero of this today: HRM "Positions" model *internal* employee roles and OPP "Opportunities" model *sales* deals — neither is a client recruiting requisition (gap analysis :35-36). This file specs **only** the Job Order entity; the Candidate entity, the candidate↔job-order pipeline (which actually places candidates and decrements the openings counter), the public career portal, and self-apply are separate clusters (CND-*, PIPE-*, PORTAL-* — referenced as future dependencies, not built here).

**Cross-cutting constraints for all tickets in this file:**
- All changes are **additive and flag-gated default-off**; existing surfaces are byte-for-byte unchanged with the flag off. Master gate: `S.ats_enabled` (`ATS_ENABLED`, default `false`) with the job-order sub-gate `S.job_orders_enabled` (`JOB_ORDERS_ENABLED`, default `false`). This mirrors the parent+sub gate pattern in PTY-008 (`S.party_crm_enabled` + `S.party_crm_org_accounts_enabled`, `docs/ofbiz/specs/PTY-008.md` §2.1) — service functions are unconditionally callable from tests; the router checks both flags.
- Single-table DynamoDB for the `job_orders` table (`pk`, `sk`), following the exact `TableDef` + `_resolve_table_name` pattern in `scripts/local-ddb-init.py:42-71`. **Numeric GSI sort keys must carry `attr_types`** (e.g. `attr_types={"created_at": "N", "updated_at": "N"}`) per the CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha and the `users` `TableDef` precedent at `scripts/local-ddb-init.py:49-54`.
- **Reuse existing primitives, never fork:** `app/core/time.now_ts()` (integer Unix seconds); `app/core/cursor.encode_cursor` / `decode_cursor` (HMAC-signed pagination, `app/core/cursor.py`); `app/core/tables._safe_table(...)` proxy (`app/core/tables.py:65`, handles `float→Decimal` coercion); `app/services/alerts.audit_event` (`app/services/alerts.py:644`); `require_ui_session` (`app/services/sessions.py:330`); admin/root enforcement via `app/auth/policy.require_roles(actor, {Role.ROOT})` / the `require_root` dependency (`app/auth/policy.py:49,64`, used in `app/routers/admin_roles.py:277-279`).
- **Reuse OPP-001/002 as the structural template** (`docs/suitecrm/CRM_OPPORTUNITIES_TICKETS.md:18-208`): table+flag+models first, then CRUD service+router, single-table layout, optimistic-concurrency `update_item`, `audit_event` on mutations, cursor pagination, `_require_flag()` → 503 with the flag off.
- **Linkage is by reference id, resolved lazily** (the linked entities are planned, not built): `client_company_id` → PTY B2B org account (PTY-008 `create_org_account`, `docs/ofbiz/specs/PTY-008.md` §1) + CCT-001; `client_contact_id` → PTY PERSON party (PTY-007 contact mechs) + CCT-003 reports-to; `recruiter_subs` (owner-assignment) → the round-robin / `assigned_to` pattern in LED-010 (`docs/suitecrm/specs/...` LED-010 §2, modeled on `app/services/kyc_case_assignment.py`). Until those ship, references are stored as opaque strings and validated only for shape — **do not duplicate that planned work; depend on it.**
- Dev/prod parity (SECOPS-007): no `if S.dev_mode` branches in business logic; same code path in both environments.
- Hermetic offline tests: moto in-memory `job_orders` table bound to the frozen `T.job_orders` handle via `object.__setattr__`, frozen `S.ats_enabled` / `S.job_orders_enabled` via `object.__setattr__`; route handlers invoked directly with stubbed `require_ui_session`; no real AWS/network — same recipe as `tests/test_gap_0265_0266_kyc_risk_scoring.py` and the OPP hermetic pattern.

---

### JOB-001: Job Order data model, DynamoDB table, type/status enums, and feature flags
**Type:** Feature  **Priority:** P0  **Estimate:** 2d

**Description**

Lay the data-model and infrastructure foundation that every other JOB ticket depends on. Zero application logic ships here — only the table, the settings, the enums, and the Pydantic models. Structural template: OPP-001 (`docs/suitecrm/CRM_OPPORTUNITIES_TICKETS.md:18-131`).

**Settings (`app/core/settings.py`)** — add adjacent to `contacts_table_name` (`app/core/settings.py:498`), using the boolean-env idiom at `app/core/settings.py:124` (`browser_ssh_terminal_enabled`):

```python
ats_enabled: bool = os.environ.get("ATS_ENABLED", "0") not in ("0", "false", "False")
job_orders_enabled: bool = os.environ.get("JOB_ORDERS_ENABLED", "0") not in ("0", "false", "False")
job_orders_table_name: str = os.environ.get("DDB_JOB_ORDERS_TABLE", "job_orders")
```

**Table (`scripts/local-ddb-init.py`)** — add one `TableDef` to `_table_defs()` after the `Contacts` def, following `scripts/local-ddb-init.py:49-71`:

```python
# ATS — Job Orders (JOB-001)
TableDef(
    _resolve_table_name(S.job_orders_table_name, "job_orders"),
    "pk",   # COMPANY#{client_company_id} for company-scoped lookup; also holds JOB#{job_id} META under that PK
    "sk",   # JOB#{job_id} (META) ; RECRUITER#{sub} (owner index rows)
    gsi=[
        {"index_name": "GSI_BY_STATUS",     "partition_key": "status",        "sort_key": "created_at"},
        {"index_name": "GSI_BY_RECRUITER",  "partition_key": "recruiter_sub", "sort_key": "created_at"},
        {"index_name": "GSI_HOT",           "partition_key": "hot_flag",      "sort_key": "created_at"},
        {"index_name": "GSI_PUBLIC",        "partition_key": "public_flag",   "sort_key": "created_at"},
        {"index_name": "GSI_DIRECT",        "partition_key": "job_id"},
    ],
    attr_types={"created_at": "N", "updated_at": "N"},
),
```

`status`, `hot_flag` (`"1"` when hot, else **absent** → sparse), and `public_flag` (`"1"` when public, else absent → sparse) are written sparsely so the hot/public GSIs only index matching rows (the sparse-GSI idiom — write the GSI PK attr only when the flag is set; mirrors `_check_restart_policy`'s sparse-index approach noted in CLAUDE.md INFRA-008).

**`T.job_orders` (`app/core/tables.py`)** — add an `Any` field to the `Tables` dataclass after `contacts` (`app/core/tables.py:102`) and wire `job_orders=_safe_table(S.job_orders_table_name)` in the `T` factory next to `contacts=_safe_table(S.contacts_table_name)` (`app/core/tables.py:354`).

**Enums + Pydantic models (`app/models.py`)** — near the contacts/opportunity models:

```python
JOB_ORDER_TYPES = ("hire", "contract", "contract_to_hire", "referral")  # H / C / C2H / Referral
JOB_ORDER_STATUSES = ("active", "on_hold", "full", "closed", "canceled", "lead", "upcoming")
# Terminal statuses cannot transition further (state-machine in JOB-002):
JOB_ORDER_TERMINAL = ("closed", "canceled")

class JobOrderCreateIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., description="One of JOB_ORDER_TYPES")
    status: str = Field(default="active", description="One of JOB_ORDER_STATUSES")
    openings: int = Field(default=1, ge=0, le=10000)
    client_company_id: str = Field(..., min_length=1, max_length=128)  # PTY B2B org (PTY-008) / CCT-001
    client_contact_id: Optional[str] = Field(None, max_length=128)      # PTY PERSON (PTY-007) / CCT-003
    recruiter_subs: List[str] = Field(default_factory=list, max_length=25)  # owner(s); LED-010 pattern
    hot: bool = False
    public: bool = False
    pay_rate_cents: Optional[int] = Field(None, ge=0)
    bill_rate_cents: Optional[int] = Field(None, ge=0)
    duration: Optional[str] = Field(None, max_length=120)   # e.g. "6 months", "permanent"
    city: Optional[str] = Field(None, max_length=120)
    state: Optional[str] = Field(None, max_length=120)
    description: Optional[str] = Field(None, max_length=20000)

class JobOrderUpdateIn(BaseModel):
    # every field Optional; status handled by JOB-002 transition guard, not a blind overwrite
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    type: Optional[str] = None
    status: Optional[str] = None
    openings: Optional[int] = Field(None, ge=0, le=10000)
    client_company_id: Optional[str] = Field(None, max_length=128)
    client_contact_id: Optional[str] = Field(None, max_length=128)
    recruiter_subs: Optional[List[str]] = Field(None, max_length=25)
    hot: Optional[bool] = None
    public: Optional[bool] = None
    pay_rate_cents: Optional[int] = Field(None, ge=0)
    bill_rate_cents: Optional[int] = Field(None, ge=0)
    duration: Optional[str] = Field(None, max_length=120)
    city: Optional[str] = Field(None, max_length=120)
    state: Optional[str] = Field(None, max_length=120)
    description: Optional[str] = Field(None, max_length=20000)

class JobOrderOut(BaseModel):
    job_id: str
    title: str
    type: str
    status: str
    openings: int
    placed_count: int          # # of pipeline placements; 0 until PIPE-* ships (JOB-005 counter)
    openings_remaining: int     # max(openings - placed_count, 0)
    client_company_id: str
    client_contact_id: Optional[str]
    recruiter_subs: List[str]
    hot: bool
    public: bool
    pay_rate_cents: Optional[int]
    bill_rate_cents: Optional[int]
    duration: Optional[str]
    city: Optional[str]
    state: Optional[str]
    description: Optional[str]
    created_by: str
    created_at: int
    updated_at: int
```

Add a `@validator` (or `model_validator`) that raises `ValueError` for unknown `type` (not in `JOB_ORDER_TYPES`) and unknown `status` (not in `JOB_ORDER_STATUSES`).

**Acceptance Criteria**
- `job_orders` table is created by `scripts/local-ddb-init.py` with the five GSIs and `attr_types={"created_at":"N","updated_at":"N"}`.
- `T.job_orders` is importable in tests via `from app.core.tables import T`.
- `S.ats_enabled` and `S.job_orders_enabled` default to `False`; `ATS_ENABLED=1` / `JOB_ORDERS_ENABLED=1` flip them true.
- `JobOrderCreateIn` / `JobOrderUpdateIn` / `JobOrderOut` validate valid + invalid payloads (hermetic, no DDB); unknown `type` → `ValueError`; unknown `status` → `ValueError`.
- No existing table definition, table handle, or setting is changed.

**Dependencies**
- None (pure infrastructure). Flags `ATS_ENABLED` / `JOB_ORDERS_ENABLED` introduced here, default false.

---

### JOB-002: Job Order CRUD service + status state-machine with transition guards
**Type:** Feature  **Priority:** P0  **Estimate:** 3d

**Description**

Implement the Job Order CRUD service plus the 7-state status state-machine. Pure service layer — the router is JOB-003. Template: OPP-002 service (`docs/suitecrm/CRM_OPPORTUNITIES_TICKETS.md:135-208`).

**Service (`app/services/job_orders.py`)** — single-table DDB layout on `T.job_orders`:

| pk | sk | Description |
|---|---|---|
| `COMPANY#{client_company_id}` | `JOB#{job_id}` | Job Order META row (all fields) |
| `COMPANY#{client_company_id}` | `RECRUITER#{sub}#JOB#{job_id}` | per-recruiter index row (sparse; written per `recruiter_sub`) |

Denormalized attributes on the META row for GSI projections: `job_id`, `status`, `created_at`, `updated_at`, `hot_flag` (`"1"` iff `hot`, else absent), `public_flag` (`"1"` iff `public`, else absent). The `GSI_BY_RECRUITER` index is fed by the per-recruiter index rows, each carrying `recruiter_sub` + `created_at` + a projected `job_id` (mine-list path in JOB-004).

```python
def _require_flag() -> None:
    if not (S.ats_enabled and S.job_orders_enabled):
        raise HTTPException(503, detail={"code": "job_orders_disabled"})

def create_job_order(actor_sub: str, data: JobOrderCreateIn) -> JobOrderOut: ...
def get_job_order(job_id: str) -> JobOrderOut: ...                       # via GSI_DIRECT; 404 if missing
def update_job_order(actor_sub: str, job_id: str, data: JobOrderUpdateIn) -> JobOrderOut: ...
def delete_job_order(actor_sub: str, job_id: str) -> None: ...           # soft-delete (set deleted_at), 204
def set_status(actor_sub: str, job_id: str, new_status: str) -> JobOrderOut: ...
```

- `create_job_order` mints `job_id = "job_" + uuid4().hex`, sets `created_by=actor_sub`, `created_at=updated_at=now_ts()`, `placed_count=0`. Validates `type`/`status`. Writes the META row (`pk=COMPANY#{client_company_id}`, `sk=JOB#{job_id}`) and one `RECRUITER#{sub}#JOB#{job_id}` index row per `recruiter_subs` entry. Emits `audit_event("job_order.created", actor_sub, None, {"job_id": job_id, "client_company_id": ...})`.
- `get_job_order` resolves the META row by `job_id` via `GSI_DIRECT` (a `Query` on `job_id` returning the single META item). All numeric attrs round-tripped through `_safe_table` (Decimal-safe).
- `update_job_order` builds a dynamic `UpdateExpression` from non-None fields. **`status` changes are routed through `set_status`'s guard, never a blind overwrite.** When `recruiter_subs` changes, reconcile the `RECRUITER#...` index rows (delete removed, put added). When `hot`/`public` flip, set/remove the sparse `hot_flag`/`public_flag` attrs. Uses optimistic concurrency `ConditionExpression=Attr("updated_at").eq(prev_updated_at)` (OPP-002 lost-update guard). Bumps `updated_at=now_ts()`.
- **`set_status` — the state-machine.** Transition matrix (OpenCATS Job Order statuses): `lead`/`upcoming` → `active`; `active` ⇄ `on_hold`; `active` → `full` (when `openings_remaining == 0`, allowed manually too); `active`/`on_hold`/`full` → `closed` | `canceled`; terminal `closed`/`canceled` (in `JOB_ORDER_TERMINAL`) reject any further transition with **409** `{"code":"invalid_status_transition","from":...,"to":...}` unless `JOB_ORDER_ALLOW_REOPEN` (env, default `true`) permits reopening a `closed` job back to `active` (mirrors OPP-003's `SALES_PIPELINE_ALLOW_REOPEN`). Same-status is a no-op (returns current). Every accepted transition emits `audit_event("job_order.status_changed", actor_sub, None, {"job_id":..., "from_status":..., "to_status":...})`.
- `delete_job_order` writes `deleted_at=now_ts()` (soft delete; list paths filter it out) and removes the recruiter index rows; emits `audit_event("job_order.deleted", ...)`.

**Acceptance Criteria**
- `create_job_order` persists META + one recruiter index row per `recruiter_subs` entry; returns `JobOrderOut` with `placed_count=0`, `openings_remaining=openings`.
- `get_job_order` returns the record by `job_id`; 404 for unknown id.
- `update_job_order` patches a subset of fields; recruiter-set change reconciles index rows; hot/public toggle sets/clears the sparse flag attrs; concurrent stale `updated_at` → conflict.
- `set_status`: `lead`→`active` OK; `active`→`on_hold`→`active` OK; `closed`→`active` allowed only when `JOB_ORDER_ALLOW_REOPEN` true; `closed`→`full` rejected with 409; same-status no-op.
- `delete_job_order` soft-deletes; subsequent list excludes it.
- Every create / status-change / delete emits the corresponding `audit_event`.
- Hermetic pytest covers CRUD, every legal + illegal transition, reopen flag on/off, recruiter index reconciliation, optimistic-concurrency conflict, audit emission.

**Dependencies**
- JOB-001 (table + models + flags). Flag: `ATS_ENABLED` + `JOB_ORDERS_ENABLED`; env `JOB_ORDER_ALLOW_REOPEN`.

---

### JOB-003: Job Order REST router + main.py registration
**Type:** Feature  **Priority:** P0  **Estimate:** 2d

**Description**

Expose the JOB-002 service as a REST router, gated by `_require_flag()`. Template: OPP-002 router (`docs/suitecrm/CRM_OPPORTUNITIES_TICKETS.md:179-195`).

**Router (`app/routers/job_orders.py`)**

```python
router = APIRouter(prefix="/ui/ats/job-orders", tags=["ats-job-orders"])

POST   /                       # create; body=JobOrderCreateIn → JobOrderOut
GET    /{job_id}               # get single → JobOrderOut; 404 if not found
PATCH  /{job_id}               # update; body=JobOrderUpdateIn → JobOrderOut
POST   /{job_id}/status        # set_status; body={"status": "<one of JOB_ORDER_STATUSES>"} → JobOrderOut
DELETE /{job_id}               # soft-delete → 204
```

All endpoints use `Depends(require_ui_session)` (`app/services/sessions.py:330`) and call `_require_flag()` before any DDB op. The `actor_sub` comes from the session dict's `user_sub`. The list endpoints (`GET /` and its filter variants) are specced in JOB-004 and must be declared **before** `/{job_id}` so the literal list segments aren't captured as a `job_id` path param (the `/schedules` before `/{export_id}` ordering rule, CLAUDE.md GAP-0210). The `/{job_id}/status` POST is a sub-resource and is unambiguous.

**`app/main.py` registration** — import `from app.routers.job_orders import router as job_orders_router` near `from app.routers.contacts import router as contacts_router` (`app/main.py:82`) and `app.include_router(job_orders_router)` adjacent to `app.include_router(contacts_router)` (`app/main.py:683`).

**Acceptance Criteria**
- `POST /ui/ats/job-orders` with a valid payload creates a record and returns `JobOrderOut`.
- `GET /ui/ats/job-orders/{job_id}` returns the record; 404 for unknown id.
- `PATCH /ui/ats/job-orders/{job_id}` updates a subset; `POST /{job_id}/status` drives `set_status` (illegal transition → 409).
- `DELETE /ui/ats/job-orders/{job_id}` returns 204.
- With `ATS_ENABLED` or `JOB_ORDERS_ENABLED` false, every endpoint returns 503 `{"code":"job_orders_disabled"}`.
- Router is registered in `app/main.py`; with flags off, no existing route behavior changes.
- Hermetic pytest invokes the handlers directly with a stubbed session and a moto-bound `T.job_orders`, asserting status codes + 503-when-off.

**Dependencies**
- JOB-001, JOB-002.

---

### JOB-004: List & filter endpoints (open / hot / mine) with cursor pagination
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Add the Job Order list views OpenCATS surfaces on its dashboard: **open** (all non-terminal/non-deleted), **hot** (hot-flagged), and **mine** (assigned to the calling recruiter). Service in `app/services/job_orders.py`, endpoints in `app/routers/job_orders.py`.

**Service functions**

```python
def list_open(cursor=None, limit=50, *, company_id=None, status=None) -> Tuple[List[JobOrderOut], Optional[str]]: ...
def list_hot(cursor=None, limit=50) -> Tuple[List[JobOrderOut], Optional[str]]: ...
def list_mine(recruiter_sub, cursor=None, limit=50) -> Tuple[List[JobOrderOut], Optional[str]]: ...
```

- `list_open` queries `GSI_BY_STATUS` per non-terminal status (`active`, `on_hold`, `full`, `lead`, `upcoming`) — or the single `status` when supplied — newest-first on `created_at`, excluding soft-deleted rows. **`FilterExpression` (e.g. excluding `deleted_at`) does not reduce DDB page size** → loop on `LastEvaluatedKey` until `limit` real items are gathered (CLAUDE.md FilterExpression gotcha). Optional `company_id` narrows to a single client. Pagination via `app/core/cursor.encode_cursor` / `decode_cursor`.
- `list_hot` queries the sparse `GSI_HOT` (`hot_flag="1"`), newest-first, soft-deleted excluded.
- `list_mine` queries `GSI_BY_RECRUITER` (`recruiter_sub` = caller), newest-first, resolving each index row's `job_id` to the META row (batch get / per-row get), soft-deleted excluded.

**Router endpoints (declared BEFORE `/{job_id}`)**

```python
GET /ui/ats/job-orders/open    # query ?company_id=&status=&cursor=&limit= → {"items":[...],"next_cursor":...}
GET /ui/ats/job-orders/hot     # query ?cursor=&limit=
GET /ui/ats/job-orders/mine    # caller's own; query ?cursor=&limit=
```

All `Depends(require_ui_session)` + `_require_flag()`. `mine` derives `recruiter_sub` from the session `user_sub`.

**Acceptance Criteria**
- `GET /ui/ats/job-orders/open` returns only non-terminal, non-deleted job orders; `?status=active` narrows correctly; `?company_id=` scopes to one client.
- `GET /ui/ats/job-orders/hot` returns only hot-flagged orders (sparse GSI); flipping `hot` off via PATCH removes it from this list.
- `GET /ui/ats/job-orders/mine` returns only orders where the caller is in `recruiter_subs`; adding/removing the caller via PATCH adds/removes it.
- Cursor pagination round-trips (`next_cursor` from page 1 fetches page 2 with no overlap/gap) even when soft-deleted rows are interleaved (LastEvaluatedKey loop, not a single query).
- The three list routes resolve before `/{job_id}` (literal segments not captured as ids).
- With flags off → 503.
- Hermetic pytest: seed mixed-status + hot + multi-recruiter + soft-deleted rows; assert each list's membership, pagination, and flag-off.

**Dependencies**
- JOB-001, JOB-002, JOB-003.

---

### JOB-005: Openings-remaining-vs-placed counter + placement hooks (forward-compat for pipeline)
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Implement the **openings-remaining-vs-placed** counter OpenCATS shows on every Job Order. `openings` is set at creation (JOB-001); `placed_count` is incremented/decremented when the candidate↔job-order **pipeline** moves a candidate into/out of the `Placed` status. The pipeline (PIPE-*) is a separate cluster, so this ticket ships the **counter primitives + projection** and a guarded hook the pipeline will call — without forking pipeline work.

**Service additions (`app/services/job_orders.py`)**

```python
def adjust_placed_count(job_id: str, delta: int, *, actor_sub: str, candidate_ref: str | None = None) -> JobOrderOut: ...
def get_openings_summary(job_id: str) -> dict: ...   # {"openings", "placed_count", "openings_remaining"}
```

- `adjust_placed_count` does an atomic `update_item` `ADD placed_count :delta` on the META row with `ConditionExpression` clamping `placed_count` ≥ 0 (reject a decrement that would go negative → 409 `{"code":"placed_count_underflow"}`). Recomputes `openings_remaining = max(openings - placed_count, 0)` in the returned projection (not stored, derived). When a placement pushes `openings_remaining` to 0 and `status == "active"`, **auto-advance status to `full` via `set_status`** (the natural OpenCATS behavior; emits the `job_order.status_changed` audit). Emits `audit_event("job_order.placement_adjusted", actor_sub, None, {"job_id":..., "delta":..., "candidate_ref":..., "placed_count":...})`.
- `JobOrderOut.placed_count` / `openings_remaining` (added in JOB-001) are populated by `_item_to_out` from the stored `placed_count` (default 0) for every read path (get / all lists). No schema migration — absent `placed_count` reads as 0.
- **Pipeline hook contract (documented, not wired here):** PIPE-* will call `adjust_placed_count(job_id, +1, ...)` on candidate→Placed and `adjust_placed_count(job_id, -1, ...)` on un-place. This ticket only guarantees the primitive + counter projection exist and are correct; it does not import or depend on pipeline code.

**Router** — read-only summary endpoint:

```python
GET /ui/ats/job-orders/{job_id}/openings   # → {"openings","placed_count","openings_remaining"}
```

`Depends(require_ui_session)` + `_require_flag()`. (No public mutate endpoint — `adjust_placed_count` is invoked internally by the pipeline service, not by clients.)

**Acceptance Criteria**
- New job order: `placed_count=0`, `openings_remaining == openings` on every read path.
- `adjust_placed_count(+1)` increments atomically; `openings_remaining` decrements; reaching 0 on an `active` order auto-advances `status` to `full` and audits the status change.
- `adjust_placed_count(-1)` below 0 is rejected with 409 (`ConditionExpression` clamp).
- `GET /{job_id}/openings` returns the live summary.
- Concurrent increments are atomic (ADD), no lost updates.
- With flags off → 503.
- Hermetic pytest: increment/decrement, underflow-409, auto-`full` transition + audit, summary endpoint, flag-off. No pipeline imports.

**Dependencies**
- JOB-001, JOB-002, JOB-003. Forward-compat consumer: **PIPE-\*** (candidate↔job-order pipeline cluster, future) calls `adjust_placed_count`.

---

### JOB-006: Linkage resolution — client company / contact / recruiter owners (lazy, planned-dependency-aware)
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Resolve the three reference ids on a Job Order — `client_company_id`, `client_contact_id`, `recruiter_subs` — into display objects when the linked entities exist, **without duplicating the planned PTY/CCT/LED work**. Until those ship, references are stored as opaque strings (JOB-001) and validated for shape only; this ticket adds the *resolution layer* behind a `?expand=` query param so the FE detail page can show names.

**Service additions (`app/services/job_orders.py`)**

```python
def resolve_links(out: JobOrderOut) -> dict: ...
# returns {"company": <CompanyRef|None>, "contact": <ContactRef|None>, "recruiters": [<UserRef>...]}
```

- **Company** — when `S.party_crm_org_accounts_enabled` is on AND `client_company_id` resolves via `party.get_party(client_company_id)` (PTY-008 / PTY-004, `docs/ofbiz/specs/PTY-008.md` §1), project `{id, name}`; else `{id, name: None, unresolved: True}`. Local import of `app.services.party` inside the function (avoid hard import coupling to unbuilt code — same lazy-import discipline as `instance_monitoring`'s `_record_timeline`, CLAUDE.md INFRA-008).
- **Contact** — same pattern via `party.get_party(client_contact_id)` (PTY-007 mechs / CCT-003), `{id, name, email}` or unresolved.
- **Recruiters** — resolve each `recruiter_sub` against `T.users` (`get_item`) for `{sub, display_name, email}`; unknown subs returned as `{sub, unresolved: True}`. This is the read side of the LED-010 owner-assignment pattern (the *write* side — round-robin auto-assign — is LED-010 / `kyc_case_assignment.py`; **not duplicated here**, owners are set explicitly via `recruiter_subs` in create/update).

**Router** — extend the existing single-get to support expansion (no new route):

```python
GET /ui/ats/job-orders/{job_id}?expand=links   # → JobOrderOut + {"links": resolve_links(...)}
```

Default (`expand` absent) returns the plain `JobOrderOut` (unchanged from JOB-003). `Depends(require_ui_session)` + `_require_flag()`. All resolution failures degrade gracefully to `unresolved: True` — a missing/unbuilt PTY entity never 500s the read.

**Acceptance Criteria**
- `GET /{job_id}?expand=links` returns a `links` block; `GET /{job_id}` (no expand) is byte-for-byte the JOB-003 response.
- With `party_crm_org_accounts_enabled` off (PTY unbuilt), company/contact resolve to `{id, name: None, unresolved: True}` — no error, no 500.
- Recruiter subs resolve from `T.users`; an unknown sub → `{sub, unresolved: True}`.
- No hard module-level import of `app.services.party` (lazy local import; the file imports cleanly even if `party.py` lacks `get_party`).
- With flags off → 503.
- Hermetic pytest: seed `T.users`; stub/patch `party.get_party` for the resolved-company case and omit it for the unresolved case; assert graceful degradation both ways and plain-get parity.

**Dependencies**
- JOB-001, JOB-002, JOB-003. **Planned (depend, do not duplicate):** PTY-008 (`create_org_account`/`get_party`) + CCT-001 (company fields); PTY-007 + CCT-003 (contact); LED-010 (recruiter owner-assignment write side).

---

### JOB-007: Frontend — Job Orders list, detail, and create/edit pages
**Type:** Feature  **Priority:** P1  **Estimate:** 4d

**Description**

Add the Job Orders UI: a list page (open / hot / mine tabs), a detail page (with openings counter + linked company/contact/recruiters), and a create/edit form. Mirror the existing feature-page conventions (React Query, shadcn/ui, RHF + Zod) and the OPP frontend layering (`docs/suitecrm/CRM_OPPORTUNITIES_TICKETS.md:235-247`).

**API layer (`frontend/src/api/endpoints/jobOrders.ts`)** — typed axios wrappers on `frontend/src/api/client.ts`: `createJobOrder`, `getJobOrder` (with `expand` arg), `updateJobOrder`, `setJobOrderStatus`, `deleteJobOrder`, `listOpenJobOrders`, `listHotJobOrders`, `listMyJobOrders`, `getOpeningsSummary`. Add `JobOrder*` TS interfaces to `frontend/src/api/types.ts` mirroring `app/models.py` (`JobOrderOut`, create/update inputs, the type/status string-literal unions, the `links` block).

**Pages (`frontend/src/pages/ats/`)** — lazy-loaded (`lazy(() => import(...))`, `frontend/src/App.tsx:14-21` pattern):
- `JobOrdersPage.tsx` — tabbed list (Open / Hot / Mine) using shadcn `Tabs`; each tab `useInfiniteQuery` against the matching endpoint; each row shows `title`, `type`, status badge, `city/state`, and an `openings_remaining / openings` chip. "New Job Order" button → create form.
- `JobOrderDetailPage.tsx` — `useQuery(getJobOrder(id, {expand:"links"}))`; renders all commercial fields (pay/bill rate formatted from cents, duration), the openings counter, resolved company/contact/recruiter names (degrading to the raw id when `unresolved`), hot/public badges, and a status dropdown that calls `setJobOrderStatus` (only offering legal transitions; surfacing the 409 message on illegal). Edit + soft-delete buttons.
- `JobOrderForm.tsx` (create/edit) — RHF + Zod; fields for every `JobOrderCreateIn` property; `type`/`status` as selects from the enums; `recruiter_subs` multi-select; `hot`/`public` toggles; pay/bill rate as currency inputs (cents under the hood).

**Routing + nav** — add lazy routes `/ats/job-orders`, `/ats/job-orders/new`, `/ats/job-orders/:jobId`, `/ats/job-orders/:jobId/edit` to `frontend/src/App.tsx`. Add a sidebar "Job Orders" entry to `frontend/src/components/layout/Sidebar.tsx` (`frontend/src/components/layout/Sidebar.tsx:104` item pattern), **visible only when the ATS feature is on** — gate via a lightweight `GET /ui/ats/feature-status` → `{"job_orders_enabled": bool}` endpoint (add to the JOB-003 router; mirrors OPP-006's `feature-status`), so with the flag off the nav entry is hidden and existing UI is unchanged.

**Acceptance Criteria**
- List page tabs load Open / Hot / Mine via their endpoints with infinite-scroll pagination; status + openings chips render.
- Create form submits `JobOrderCreateIn`; validation (required title/type/company) enforced client-side (Zod) and server-side.
- Detail page shows commercial fields, openings counter, resolved links (or raw id when unresolved), and a status dropdown that performs legal transitions and shows the 409 message on an illegal one.
- Edit form round-trips; soft-delete removes the order from the lists.
- Sidebar "Job Orders" entry appears only when `GET /ui/ats/feature-status` reports enabled; hidden + zero existing-UI change when off.
- All API calls go through `frontend/src/api/endpoints/jobOrders.ts`.

**Dependencies**
- JOB-001..JOB-006 (full backend surface incl. the `feature-status` endpoint added to the JOB-003 router).

---

### JOB-008: Hermetic pytest + Playwright E2E for Job Orders
**Type:** Chore  **Priority:** P1  **Estimate:** 3d

**Description**

Lock the Job Order vertical with offline backend tests and a browser E2E spec. Each prior ticket ships its own focused hermetic unit tests; this ticket adds the **integration-level** pytest module and the **E2E** spec, and asserts flag-off invisibility end-to-end.

**Hermetic pytest (`tests/test_job_orders.py`)** — recipe per `tests/test_gap_0265_0266_kyc_risk_scoring.py` and the OPP hermetic pattern: moto in-memory `job_orders` table bound to the frozen `T.job_orders` handle via `object.__setattr__` (restored on teardown); `S.ats_enabled` / `S.job_orders_enabled` toggled via `object.__setattr__`; `require_ui_session` stubbed to a fixed `user_sub`; route handlers invoked directly on a fresh event loop where async. Coverage:
- Full CRUD + soft-delete round-trip.
- Every legal status transition + a representative illegal one (409); reopen flag on/off.
- `open`/`hot`/`mine` list membership + cursor pagination across a soft-deleted-interleaved page (LastEvaluatedKey loop).
- Openings counter: +1/-1, underflow-409, auto-`full` + status-changed audit.
- Linkage resolution: resolved (patched `party.get_party`) vs unresolved (PTY off) graceful degradation; recruiter resolution from seeded `T.users`.
- **Flag-off parity:** with `JOB_ORDERS_ENABLED=0`, every endpoint → 503 and no `job_orders` rows are written.
- `audit_event` emission asserted on create / status-change / delete / placement-adjust (spy the module-level symbol).

**Playwright E2E (`frontend/e2e/ats-job-orders.spec.ts`)** — pattern per the repo E2E conventions (CLAUDE.md "E2E tests"; cookie session via `injectAuth`, CSRF header via `x-csrf-token` for non-GET, `page.request` for session-auth calls). Requires the backend started with `ATS_ENABLED=1 JOB_ORDERS_ENABLED=1`. Coverage:
- Create a job order via the UI form; assert it appears in the **Open** tab with the right status badge + openings chip.
- Toggle `hot` → appears in **Hot** tab; toggle off → leaves it.
- Assign the test user as recruiter → appears in **Mine** tab.
- Detail page: drive a legal status transition (active→on_hold) and assert the badge updates; attempt an illegal one and assert the 409 toast.
- Soft-delete → leaves all lists.
- Feature-flag gate: a separate assertion (or a flag-off project) that with the flags off the sidebar entry is absent and `/ui/ats/job-orders/open` returns 503.

**Acceptance Criteria**
- `tests/test_job_orders.py` passes offline with no real AWS/network (moto + frozen-handle rebind); restores `T`/`S` on teardown.
- All branches above are covered: CRUD, state-machine (legal+illegal+reopen), three lists + pagination, openings counter incl. underflow + auto-full, linkage resolution both ways, flag-off 503/no-write, audit emission.
- `frontend/e2e/ats-job-orders.spec.ts` passes against a stack started with the ATS flags on; the flag-off gate assertion passes.
- Tests are deterministic (unique per-run titles/ids to avoid cross-run collisions, per the repo "test data accumulates" gotcha).

**Dependencies**
- JOB-001..JOB-007 (entire Job Order surface, backend + frontend).
