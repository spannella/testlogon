# CRM Leads, Targets / Prospects & Target Lists — Implementation Tickets

**Area**: Leads, Targets / Prospects & Target Lists  
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T1] Leads, Targets / Prospects & Target Lists — 13 tickets")

## What SuiteCRM provides in this area

SuiteCRM's Lead module is a first-class CRM entity with a status state machine (New → Assigned → In Process → Converted → Recycled → Dead), a lead-source picklist, web-to-lead form embedding, one-click conversion to Account + Contact + Opportunity, lead scoring, bulk CSV import with duplicate detection, round-robin assignment, drip nurturing sequences, and a unified activity log (calls, emails, meetings linked to the record). Target (Prospect) records are a lighter-weight pre-lead that hold an external email only (no platform account required), used as campaign recipients via Target Lists.

## Cross-cutting constraints

- **Additive only, default-off**: Every ticket introduces a feature flag (default `"0"`, off). With the flag off all new routes return 404 and all new background work is a no-op. Existing surfaces (`app/routers/contacts.py`, `app/routers/questionnaires.py`, `app/services/alerts.py`, `app/services/csv_export.py`, `app/services/activity_feed.py`) are byte-for-byte unchanged when the flag is off.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: All new tables use the `TableDef` pattern in `scripts/local-ddb-init.py`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` per the CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha — omitting this causes `ValidationException` at query time.
- **Reuse existing primitives — never fork**: Email via `app/services/alerts.send_alert_email`, audit events via `app/services/alerts.audit_event`, CSV export by extending `app/services/csv_export.generate_csv_rows`, activity timeline via `app/services/activity_feed.record_activity`, assignment pattern from `app/services/kyc_case_assignment.py`, opt-out gate from `app/services/cart_reminders.is_user_opted_out`.
- **Planned upstream dependencies**: PTY-001..PTY-015 (`PARTY_CRM_TICKETS.md`) deliver the party/role/relationship DDB model. MKT-001..MKT-014 (`docs/ofbiz/specs/MKT-*.md`) deliver ContactLists, PartySegments, and campaign-send. LED tickets are layered **on top of** PTY/MKT, not parallel to them. Where a PTY/MKT ticket is not yet built, the LED ticket must declare it as a prerequisite (or provide a minimal inline stub flagged as removable once the upstream ships).
- **Hermetic offline tests**: All pytest must use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles per the project test-isolation pattern (see `tests/test_gap_0220_0221_ssh_stored_key.py` for the canonical form). No real AWS or network calls.

---

### LED-001: Leads feature flag, settings keys & DynamoDB table
**Type:** Chore  **Priority:** P0  **Estimate:** 1d

**Description**

Add the feature flag and new DynamoDB `leads` single-table to scaffold all downstream LED work.

**Settings** (`app/core/settings.py`) — follow the exact bool-env pattern from `cart_reminders_enabled` at `app/core/settings.py:821`:

```python
leads_enabled: bool = os.environ.get("LEADS_ENABLED", "0") not in ("0", "false", "False")
leads_table_name: str = os.environ.get("DDB_LEADS_TABLE", "leads")
```

Also add `leads_scoring_enabled`, `leads_drip_enabled`, `leads_assignment_enabled` (all default off) as sub-flags, following the pattern `party_crm_contacts_migration_enabled` in `PARTY_CRM_TICKETS.md:PTY-001`.

**DynamoDB table** (`scripts/local-ddb-init.py`) — single table PK=`pk` / SK=`sk`:

```
Row type        | PK                      | SK
----------------+-------------------------+------------------
Lead META       | LEAD#{lead_id}          | META
By-owner index  | (GSI1PK) OWNER#{sub}    | (GSI1SK) {created_at}
By-status index | (GSI2PK) STATUS#{status}| (GSI2SK) {created_at}
By-source index | (GSI3PK) SOURCE#{source}| (GSI3SK) {created_at}
Activity row    | LEAD#{lead_id}          | ACTIVITY#{ts}#{id}
```

GSIs: `ByOwner` (PK=`GSI1PK`/SK=`GSI1SK`), `ByStatus` (PK=`GSI2PK`/SK=`GSI2SK`), `BySource` (PK=`GSI3PK`/SK=`GSI3SK`). Declare `attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"}`.

Wire `T.leads = _safe_table(S.leads_table_name)` in `app/core/tables.py` next to `T.contacts` (which is at `app/core/tables.py:354`).

**Acceptance Criteria**
- `S.leads_enabled` defaults to `False`; all sub-flags default to `False`.
- `T.leads` resolves in a smoke pytest.
- `just restart` creates the `leads` table with all three GSIs and no `ValidationException`.
- No existing table or flag is changed.

**Dependencies**
- None (no PTY/MKT prerequisite — scaffolding only).

---

### LED-002: Lead entity Pydantic models
**Type:** Feature  **Priority:** P0  **Estimate:** 1d

**Description**

Add Lead-domain Pydantic models to `app/models.py` after the existing campaign-family models (currently ending around line 4927), following the same insert-point convention used by MKT-003.

**Key model classes**:

```python
LEAD_STATUSES = {"new", "assigned", "in_process", "converted", "recycled", "dead"}
LEAD_SOURCES = {"web_site", "cold_call", "email", "campaign", "trade_show",
                "word_of_mouth", "other", "internal"}

class LeadCreateIn(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=120)
    last_name: str = Field(..., min_length=1, max_length=120)
    email: str = Field(..., min_length=3, max_length=254)
    phone: Optional[str] = None
    company: Optional[str] = Field(default=None, max_length=200)
    title: Optional[str] = Field(default=None, max_length=200)
    lead_source: str = Field("other", pattern=r"^(web_site|cold_call|email|campaign|trade_show|word_of_mouth|other|internal)$")
    description: Optional[str] = Field(default=None, max_length=4000)
    assigned_to: Optional[str] = None  # user_sub of the assignee
    website: Optional[str] = Field(default=None, max_length=500)

class LeadUpdateIn(BaseModel):
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    last_name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    email: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    title: Optional[str] = None
    lead_source: Optional[str] = None
    description: Optional[str] = None
    assigned_to: Optional[str] = None
    status: Optional[str] = None  # transition enforced by service layer
    website: Optional[str] = None

class LeadOut(BaseModel):
    lead_id: str
    first_name: str
    last_name: str
    email: str
    phone: Optional[str] = None
    company: Optional[str] = None
    title: Optional[str] = None
    lead_source: str = "other"
    description: Optional[str] = None
    status: str = "new"
    assigned_to: Optional[str] = None
    score: int = 0
    website: Optional[str] = None
    created_by: str
    created_at: int = 0
    updated_at: int = 0
    converted_at: Optional[int] = None
    converted_party_id: Optional[str] = None   # PERSON party_id post-conversion
    converted_org_id: Optional[str] = None     # PARTY_GROUP party_id post-conversion
```

Email/phone normalization uses `app/core/normalize.normalize_email` and `normalize_phone` (imported in `app/services/profile.py:9`) — apply at the service layer on create/update, not at the model layer, consistent with the contacts pattern in `app/routers/contacts.py:96-100`.

Also add `ProspectCreateIn`, `ProspectOut` (light-weight: only `email`, `first_name`, `last_name`, optional `phone`/`company`) and `LeadConversionIn` / `LeadConversionOut` models for LED-006.

**Acceptance Criteria**
- All models pass `.model_validate(...)` round-trips.
- `lead_source` and `status` (on create) reject unknown values.
- `email` min/max length enforced; `phone` is unrestricted string (normalized server-side).
- No existing `app/models.py` model is modified.

**Dependencies**
- LED-001 (flag must exist; no table required for pure-model ticket).

---

### LED-003: Lead CRUD service
**Type:** Feature  **Priority:** P0  **Estimate:** 2d

**Description**

Create `app/services/leads.py` implementing the single-table DDB access layer for the `leads` table (handle `T.leads` from LED-001):

```python
def create_lead(creator_sub: str, data: LeadCreateIn) -> dict:
    # lead_id = "lead_" + uuid4().hex[:20]
    # Normalize email via normalize_email, phone via normalize_phone (app/core/normalize.py)
    # Duplicate check: query GSI2PK=STATUS#new + FilterExpression email==normalized_email
    # → if duplicate found, return existing lead (idempotent create)
    # Write PK=LEAD#{lead_id}/SK=META with GSI1PK=OWNER#{creator_sub}, GSI1SK=created_at(N),
    #   GSI2PK=STATUS#new, GSI2SK=created_at(N), GSI3PK=SOURCE#{lead_source}, GSI3SK=created_at(N)
    # Emit audit_event("lead.created", ...) via app/services/alerts.audit_event (line 644)

def get_lead(lead_id: str) -> Optional[dict]: ...
def list_leads(*, owner_sub: str, status: Optional[str]=None, lead_source: Optional[str]=None,
               assigned_to: Optional[str]=None, created_after: Optional[int]=None,
               cursor: Optional[str]=None, limit: int=50) -> dict:
    # Route to ByStatus GSI, BySource GSI, or ByOwner GSI depending on supplied filters
    # Pagination via app/core/cursor.encode_cursor/decode_cursor (used in activity_feed.py:18)

def update_lead(lead_id: str, actor_sub: str, data: LeadUpdateIn) -> dict:
    # Status transition validation against LEAD_STATUSES state machine
    # Re-write GSI2PK on status change (GSI key update = delete + re-write)

def delete_lead(lead_id: str, actor_sub: str) -> None:
    # Soft-delete: status="dead", set deleted_at timestamp
```

Reuses `app/core/normalize.normalize_email`, `normalize_phone` (same as `app/routers/contacts.py:96`), `app/core/time.now_ts()`, and `app/core/cursor.encode_cursor/decode_cursor` (see `app/services/activity_feed.py:18`). Audit events via `app/services/alerts.audit_event` (line 644 of `app/services/alerts.py`).

**Acceptance Criteria**
- CRUD round-trips persist and retrieve correct field values.
- `list_leads(status="assigned")` queries the `ByStatus` GSI; `list_leads(lead_source="campaign")` queries `BySource` GSI.
- Status transitions rejected for unknown statuses; `"converted"` status requires `converted_party_id` to be set.
- Duplicate email on create returns the existing lead, no duplicate row written.
- Hermetic pytest (moto `T.leads` via `object.__setattr__`).

**Dependencies**
- LED-001, LED-002.

---

### LED-004: Lead source tracking & attribution field
**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

Extends LED-003 to wire `lead_source` into attribution rollup alongside MKT tracking codes.

Add `attribution_code` (string, optional) and `campaign_id` (string, optional) fields to `LeadCreateIn` and `LeadOut`. When a lead is created with an `attribution_code`, the service calls `app/services/tracking_codes.record_visit(code_slug, party_id=None, referrer="lead_create")` (the service planned in MKT-010) as a best-effort fire-and-forget (never blocks lead creation). If MKT-010 is not yet deployed, the call is wrapped in a `try/except` that silences `ImportError`.

Add a read-only `GET /ui/leads/sources/summary` admin endpoint that returns a count breakdown grouped by `lead_source` using the `BySource` GSI (one `SELECT COUNT` query per source value in `LEAD_SOURCES`). Admin-only via `require_admin_session` (the auth dep used in `app/auth/deps.py`, same pattern as `app/routers/admin_roles.py`).

**Acceptance Criteria**
- `attribution_code` stored on the lead META row; its presence is optional.
- When `attribution_code` is present and MKT-010 is available, `record_visit` is called once per lead create (no blocking).
- `GET /ui/leads/sources/summary` returns `{"sources": [{"lead_source": "campaign", "count": N}, ...]}` for admin users; non-admin gets 403.
- With `leads_enabled=False`, all endpoints return 404.

**Dependencies**
- LED-003. Soft dependency on MKT-010 (tracking codes).

---

### LED-005: Web-to-lead form capture (questionnaire integration)
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Adds a `capture_as_lead` flag to questionnaire publish settings that, on anonymous or authenticated submission, creates a Lead record.

**Changes to `app/routers/questionnaires.py`**:
- Extend `PublishDraftReq` (line 79) with `capture_as_lead: bool = False` and `lead_source_override: Optional[str] = None` (overrides the default `"web_site"` source).
- In the questionnaire submit handler (around line 790, after `_enforce_anonymous_submission_controls`) add a best-effort call to `leads.create_lead_from_submission(version, answers, user_sub=None)` when `version.get("capture_as_lead")` is True and `S.leads_enabled` is True.

**New function `app/services/leads.create_lead_from_submission`**:
```python
def create_lead_from_submission(version: dict, answers: dict, *, user_sub: Optional[str]) -> Optional[dict]:
    # Extract first_name, last_name, email from a standard answer map
    # Field mapping: question_id values "first_name","last_name","email","phone","company"
    # If email is missing → skip (returns None, never raises)
    # Calls create_lead() with lead_source = version.get("lead_source_override", "web_site")
    # Wrapped in try/except so submission never fails due to lead capture error
```

This is a **best-effort, non-blocking** hook — the questionnaire submission always succeeds regardless of lead capture outcome. No new table is created; it writes to the existing `leads` table (LED-001).

**Acceptance Criteria**
- Publishing a questionnaire with `capture_as_lead=True` persists the flag on the version row.
- Anonymous submission containing `email`, `first_name`, `last_name` answers creates a lead with `lead_source="web_site"` (or the override value).
- Questionnaire submission returns 200 even if lead creation fails (try/except swallows errors).
- With `leads_enabled=False` or `capture_as_lead=False`, no lead is created.
- Hermetic pytest: mock `leads.create_lead`, assert called exactly once on submit with correct payload.

**Dependencies**
- LED-003. Questionnaire service at `app/routers/questionnaires.py`.

---

### LED-006: Lead conversion to Party + Opportunity stub
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Implements `POST /ui/leads/{lead_id}/convert` which converts a Lead into a PERSON Party + PARTY_GROUP Party (Account) and marks the lead as `status=converted`.

**Conversion endpoint**:
- `LeadConversionIn`: `{create_account: bool, account_name: Optional[str], create_opportunity: bool, opportunity_name: Optional[str], opportunity_amount_cents: Optional[int]}`.
- Service `leads.convert_lead(lead_id, actor_sub, data: LeadConversionIn) -> LeadConversionOut`.
- When `S.party_crm_enabled` is True (PTY-001 flag): calls `party.ensure_person_party(user_sub=None)` to create/reuse a PERSON party keyed on the lead's email (via `find_party_by_contact(mech_type="EMAIL", value=lead.email)` from PTY-007), and optionally `party.create_org_account(name=data.account_name)` (PTY-008). Stores the returned `party_id` and `org_party_id` on the lead META row (`converted_party_id`, `converted_org_id`, `converted_at`).
- When `S.party_crm_enabled` is False (PTY module not built): creates minimal inline PERSON/ORG stubs stored in the `leads` table as `PERSON#` / `ORG#` child rows — a temporary shim that avoids blocking the LED feature on PTY delivery. The shim is clearly documented as removable once PTY ships.
- Opportunity stub: when `create_opportunity=True`, writes a `LEAD#{lead_id}/OPPORTUNITY#META` sub-row in the leads table capturing `opportunity_name` and `opportunity_amount_cents` — no dedicated Opportunity table required at this stage (the full Opportunity module is SALES-001/002 in a separate backlog).
- Emits `audit_event("lead.converted", actor_sub, ...)`.

**Acceptance Criteria**
- Converting a lead with `create_account=True` creates a PARTY_GROUP (via PTY-008 if flag on, or inline stub if off) and sets `converted_org_id` on the lead.
- A lead with `status=converted` cannot be converted again (409 Conflict).
- `LeadConversionOut` contains `lead_id`, `converted_party_id`, `converted_org_id`, `opportunity_id` (nullable).
- Hermetic pytest covers both the PTY-available and PTY-unavailable code paths.

**Dependencies**
- LED-003. Soft dependency on PTY-004, PTY-007, PTY-008 (graceful fallback when unavailable).

---

### LED-007: Prospect (Target) record — external email-only contact
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Adds a lightweight Prospect (Target) entity for external email-only contacts that have no platform user account. Prospects are stored in the `leads` table as a separate row type (`prospect_type=PROSPECT`) and are the primary target of campaign sends to non-users.

**DDB row**: `PK=PROSPECT#{prospect_id}`, `SK=META`. GSI: reuses LED-001's `ByOwner` and `ByStatus` GSIs with `GSI2PK=STATUS#prospect` so prospects are listable separately from leads. Add a `ByEmail` GSI to the `leads` table: `GSI4PK=EMAIL#{normalized_email}` / `GSI4SK=created_at(N)` for fast duplicate lookup. Declare `attr_types={"GSI4SK": "N"}`.

**Service** `app/services/leads.py` additions:
```python
def create_prospect(owner_sub: str, data: ProspectCreateIn) -> dict:
    # Normalize email; duplicate-check via ByEmail GSI
    # Write PK=PROSPECT#{prospect_id}/SK=META
    # Opt-out check: cart_reminders.is_user_opted_out(email) — returns suppressed=True if opted out

def list_prospects(owner_sub: str, cursor=None, limit=50) -> dict: ...
def get_prospect(prospect_id: str) -> Optional[dict]: ...
def update_prospect(prospect_id: str, actor_sub: str, data: ProspectUpdateIn) -> dict: ...
def delete_prospect(prospect_id: str, actor_sub: str) -> None: ...

def add_prospect_to_contact_list(prospect_id: str, list_id: str) -> None:
    # Calls marketing_lists.add_member() from MKT-007 (soft dep)
    # Writes member row with suppressed flag from opt-out check
```

Reuses `app/services/cart_reminders.is_user_opted_out` (line 95) for opt-out checking, exactly as `app/services/marketing_lists.add_member` does (see MKT-001 §5 "Opt-out signal").

**Acceptance Criteria**
- `create_prospect` with a duplicate email returns the existing prospect (idempotent).
- `is_user_opted_out` check sets `suppressed=True` on the prospect if opted out.
- `GET /ui/leads/prospects` lists only prospects (not leads) for the caller.
- Hermetic pytest covers create/dedup/opt-out/list.

**Dependencies**
- LED-001, LED-002. Soft dependency on MKT-007 (contact-list integration).

---

### LED-008: Bulk CSV import for Leads and Prospects
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Adds `POST /ui/leads/import/csv` (multipart upload) that parses a CSV, validates fields, checks for duplicates, and bulk-creates Lead or Prospect records.

**Service** `app/services/leads_import.py`:
```python
LEAD_CSV_COLUMNS = ["first_name", "last_name", "email", "phone", "company",
                    "title", "lead_source", "description", "website"]

def import_leads_from_csv(
    owner_sub: str,
    csv_bytes: bytes,
    *,
    record_type: str = "lead",   # "lead" or "prospect"
    skip_duplicates: bool = True,
) -> dict:
    # Returns {"imported": N, "skipped": N, "errors": [{"row": R, "reason": "..."}]}
    # Uses csv.DictReader (same pattern as app/services/csv_export.py:211)
    # Duplicate check per row: call find_lead_by_email() (GSI lookup)
    # Row-level errors are collected; import continues on per-row failure
    # Hard cap: MAX_IMPORT_ROWS = 5000
```

Reuses the `csv.DictReader` / `io.StringIO` pattern from `app/services/csv_export.py:211` and the existing CSV injection sanitization `_sanitize_csv_field` from `app/services/csv_export.py:43`. Normalization via `app/core/normalize.normalize_email` / `normalize_phone`.

Router endpoint at `app/routers/leads.py` with `require_ui_session` auth dep (same as `app/routers/contacts.py:14`). Multipart file upload using `UploadFile` (same pattern as `app/routers/files.py`). Request size limited to 10 MB via FastAPI dependency.

**Acceptance Criteria**
- A valid 100-row CSV creates 100 leads; a row with a missing `email` is reported in `errors`.
- Duplicate email rows (same email already in DB) are skipped and counted in `skipped` when `skip_duplicates=True`.
- Import stops at 5000 rows; caller receives a 422 if file exceeds 10 MB.
- `record_type=prospect` creates Prospect rows instead of Lead rows.
- Hermetic pytest uses `io.BytesIO` as the mock upload file.

**Dependencies**
- LED-003, LED-007.

---

### LED-009: Duplicate detection and merge for Leads
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Implements lead duplicate detection (exact email/phone match via GSI lookup) and a merge endpoint that consolidates two lead records into one canonical record.

**Service** `app/services/leads.py` additions:
```python
def find_duplicates(lead_id: str) -> list[dict]:
    # Queries ByEmail GSI (GSI4PK=EMAIL#{normalized}) for all rows with same email
    # Also queries a (new) ByPhone GSI on normalized phone if phone is present
    # Returns list of LeadOut for all matching rows excluding the input lead_id

def merge_leads(primary_lead_id: str, secondary_lead_id: str, actor_sub: str) -> dict:
    # Reads both leads; validates both exist and belong to actor
    # Copies non-null fields from secondary onto primary (primary fields win)
    # Soft-deletes secondary: status="dead", merged_into=primary_lead_id
    # Writes ACTIVITY# row on primary: "merged from {secondary_lead_id}"
    # Emits audit_event("lead.merged", actor_sub, ...)
```

Add `ByPhone` GSI to the `leads` table: `GSI5PK=PHONE#{normalized_e164}` / `GSI5SK=created_at(N)`. Declare `attr_types={"GSI5SK": "N"}` in `scripts/local-ddb-init.py`. Also update LED-001's `TableDef` accordingly.

The merge logic intentionally mirrors the PTY-016 duplicate-detection design in the gap-analysis note for `Accounts, Contacts & Relationships` (see `SUITECRM_GAP_ANALYSIS.md:49`), keeping the approaches consistent.

**Acceptance Criteria**
- `find_duplicates(lead_id)` returns all leads sharing the same normalized email.
- `merge_leads` sets `secondary.status="dead"` and `secondary.merged_into=primary_lead_id`.
- Merging the same pair twice is idempotent (second call is a no-op if secondary already dead).
- Merge is actor-scoped: cannot merge leads the actor does not own.
- Hermetic pytest covers find / merge / idempotent replay / scope guard.

**Dependencies**
- LED-003.

---

### LED-010: Lead assignment and round-robin distribution
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Adds `assigned_to` user management for leads and optional round-robin auto-assignment per a configurable team/queue.

**Service** `app/services/lead_assignment.py` (mirrors `app/services/kyc_case_assignment.py` which delivers the same round-robin pattern for KYC cases):

```python
# Assignment queue config stored in leads table:
#   PK=QUEUE#{queue_id} / SK=CONFIG
# Agent availability:
#   PK=AGENT#{user_sub} / SK=QUEUE#{queue_id}

def assign_lead(lead_id: str, assignee_sub: str, actor_sub: str) -> dict:
    # Writes assigned_to on lead META row; updates GSI2PK to STATUS#assigned
    # Emits alert to assignee via alerts.write_alert("lead_assigned", ...)

def auto_assign_round_robin(lead_id: str, queue_id: str) -> Optional[str]:
    # Reads queue config; lists active agents; selects agent with fewest open leads
    # (count via FilterExpression assigned_to=sub on ByOwner GSI, same COUNT trick
    #  as kyc_case_assignment.py:267 _active_case_count)
    # Falls back to random selection if counts are equal

def configure_queue(queue_id: str, agent_subs: list[str], *, admin_sub: str) -> dict: ...
def list_queues(admin_sub: str) -> list[dict]: ...
```

Reuses the `_active_case_count` pattern from `app/services/kyc_case_assignment.py:267` for counting open leads per agent. Alert delivery uses `app/services/alerts.write_alert` (line 644 region of `app/services/alerts.py`).

Gated by `S.leads_assignment_enabled` (sub-flag from LED-001).

**Acceptance Criteria**
- `assign_lead` sets `assigned_to` and emits an alert to the assignee.
- `auto_assign_round_robin` returns the agent with the fewest open leads.
- Round-robin assignment is idempotent: re-assigning the same lead is allowed and replaces the prior assignment.
- Queue config CRUD is admin-only.
- Hermetic pytest covers assign / round-robin selection / empty-queue fallback.

**Dependencies**
- LED-003. Sub-flag `leads_assignment_enabled`.

---

### LED-011: Lead scoring engine
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Adds a configurable point-based lead scoring engine that computes a numeric `score` on each lead based on profile criteria and behavioral signals.

**Service** `app/services/lead_scoring.py` (mirrors `app/services/kyc_risk_scoring.py` which delivers the same trigger-and-score pattern):

```python
SCORING_RULES_PK = "SCORING_CONFIG"  # stored in leads table

class ScoringRule(TypedDict):
    field: str    # "company", "phone", "lead_source", "has_website"
    condition: str  # "present", "eq", "in"
    value: Any
    points: int   # positive or negative

def compute_score(lead_id: str) -> int:
    # Reads lead META row
    # Loads active scoring rules via T.leads.get_item(PK=SCORING_CONFIG, SK=RULES)
    # Evaluates each rule against the lead's fields
    # Updates score on lead META row via update_item(... ADD score :delta)
    # Returns new score

def save_scoring_rules(rules: list[ScoringRule], actor_sub: str) -> None:
    # Validates rules; stores at PK=SCORING_CONFIG/SK=RULES
    # Admin-only (validated at router layer)

def get_scoring_rules() -> list[ScoringRule]: ...
```

Score recomputation is triggered: (1) on `update_lead` (best-effort call to `compute_score` at the end of the service, never blocking the update), and (2) via `POST /ui/admin/leads/rescore-all` which fans out via a background task using the `asyncio.create_task` pattern (like `app/services/audit_export_worker.py` startup task).

Gated by `S.leads_scoring_enabled` (sub-flag from LED-001).

**Acceptance Criteria**
- A lead with a company name, phone, and lead_source="campaign" scores higher than one with only an email.
- `compute_score` is idempotent: calling it twice on the same unchanged lead returns the same score without writing extra rows.
- Score is persisted as an integer on the lead META row and visible in `LeadOut.score`.
- With `leads_scoring_enabled=False`, score remains `0` and no rule evaluation occurs.
- Hermetic pytest covers rule evaluation / partial match / negative points / flag-off.

**Dependencies**
- LED-003. Sub-flag `leads_scoring_enabled`.

---

### LED-012: Activity log on Lead / Contact
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Extends the existing `app/services/activity_feed.py` to support CRM-entity-scoped queries (by `lead_id` or `party_id`) and adds `lead_activity` / `lead_note` / `lead_call` activity types to the lead entity.

**Changes to `app/services/activity_feed.py`**:
- Add `target_type` options `"lead"`, `"party"` to the existing `ACTIVITY_TYPES` list (line 22 of `app/services/activity_feed.py`).
- Add `get_entity_activity_feed(target_type: str, target_id: str, *, limit=50, cursor=None) -> tuple[list, Optional[str]]` that queries the existing `activity_feed` table using a new sparse GSI: `ByTarget` (`target_type#target_id` partition / `sk` sort). Wire this GSI onto the `activity_feed` table in `scripts/local-ddb-init.py` (add `ByTarget` GSI with `GSI_TARGET_PK=TARGET#{target_type}#{target_id}` / `GSI_TARGET_SK=sk`). The GSI is sparse — only activity rows that carry `target_type` and `target_id` project into it.
- Existing `record_activity` and `get_activity_feed` functions are unchanged (additive-only).

**New router endpoints** in `app/routers/leads.py`:
- `POST /ui/leads/{lead_id}/activities` — log a note or call against a lead (`activity_type` ∈ `{"note", "call", "email", "meeting"}`). Calls `activity_feed.record_activity(user_id=lead_id, actor_id=caller_sub, activity_type=..., target_type="lead", target_id=lead_id, metadata={...})`.
- `GET /ui/leads/{lead_id}/activities` — returns the entity activity feed via `get_entity_activity_feed("lead", lead_id)`.

These endpoints reuse the existing `activity_feed` DDB table (`T.activity_feed`) and `record_activity` function — no new table is needed.

**Acceptance Criteria**
- `POST /ui/leads/{lead_id}/activities` with `type=note` and `body="called"` writes a row and returns it.
- `GET /ui/leads/{lead_id}/activities` returns newest-first ordered activities scoped to that lead.
- The `ByTarget` GSI allows the query without a scan.
- Existing `GET /activity-feed` endpoint behavior is unchanged.
- Hermetic pytest uses moto `activity_feed` table bound to frozen `T.activity_feed`.

**Dependencies**
- LED-003. `app/services/activity_feed.py`.

---

### LED-013: Lead / Prospect search, filter, and router surface
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Delivers the complete `app/routers/leads.py` router, wraps all LED-003..LED-012 services behind `require_ui_session` auth (same as `app/routers/contacts.py:14`), and adds filterable search.

**Router** (`app/routers/leads.py`, prefix `/ui/leads`, tags `["leads"]`):

```
POST   /ui/leads                          → create_lead
GET    /ui/leads                          → list_leads (filter: status, lead_source, assigned_to, created_after, q)
GET    /ui/leads/{lead_id}                → get_lead
PATCH  /ui/leads/{lead_id}                → update_lead
DELETE /ui/leads/{lead_id}                → delete_lead (soft)
POST   /ui/leads/{lead_id}/convert        → convert_lead (LED-006)
GET    /ui/leads/{lead_id}/duplicates     → find_duplicates (LED-009)
POST   /ui/leads/{lead_id}/merge          → merge_leads (LED-009)
POST   /ui/leads/{lead_id}/assign         → assign_lead (LED-010)
GET    /ui/leads/{lead_id}/activities     → entity activity feed (LED-012)
POST   /ui/leads/{lead_id}/activities     → log activity (LED-012)
POST   /ui/leads/import/csv               → bulk import (LED-008)
GET    /ui/leads/prospects                → list_prospects (LED-007, declared BEFORE /{lead_id})
POST   /ui/leads/prospects                → create_prospect (LED-007)
GET    /ui/leads/prospects/{prospect_id}  → get_prospect
PATCH  /ui/leads/prospects/{prospect_id}  → update_prospect
DELETE /ui/leads/prospects/{prospect_id}  → delete_prospect
```

**IMPORTANT**: Declare all static-segment routes (`/import/csv`, `/prospects`, `/sources/summary`) **before** the dynamic `/{lead_id}` route per the CLAUDE.md FastAPI declaration-order gotcha (same rule applied in `app/routers/kyc_cases.py` for `/templates` before `/{case_id}`).

**Search filter** (`GET /ui/leads?q=foo&status=new&lead_source=campaign`): the `q` param triggers a client-side text match over first_name, last_name, email, company fields loaded from the `ByOwner` GSI result set (DDB FilterExpression with `contains` on a small result set). This keeps the implementation DDB-native with no separate search index for MVP.

Register the router in `app/main.py` next to `contacts_router` (imported at `app/main.py:82`). Add CSRF to all non-GET endpoints (enforced automatically by `require_ui_session` in `app/auth/deps.py`).

**Frontend types** (`frontend/src/api/types.ts`) — add `Lead`, `Prospect`, `LeadActivity` TypeScript interfaces mirroring `LeadOut`, `ProspectOut`, `ActivityOut`.

**Frontend API wrappers** (`frontend/src/api/endpoints/leads.ts`) — add endpoint functions for all above routes using the shared axios instance in `frontend/src/api/client.ts`.

**Frontend page** (`frontend/src/pages/leads/LeadsPage.tsx`) — React Query + shadcn/ui list with status badge filters, source pills, a detail drawer (edit form + activity log), and a "Convert" button. Add the lazy-loaded route `/leads` in `frontend/src/App.tsx` and a flag-gated nav item in `frontend/src/components/layout/Sidebar.tsx`.

**Acceptance Criteria**
- All CRUD endpoints round-trip with cookie auth + CSRF.
- `GET /ui/leads?status=in_process` returns only in-process leads.
- Static paths (`/prospects`, `/import/csv`) are not captured as `/{lead_id}`.
- With `leads_enabled=False`, every endpoint returns 404 and the nav item is hidden.
- E2E Playwright spec `frontend/e2e/leads.spec.ts` covers: create lead (API), list/filter, convert, bulk import (10-row CSV), create prospect, flag-off 404 check.
- Hermetic pytest covers the router's auth guard and flag-off no-op.

**Dependencies**
- LED-003, LED-004, LED-005, LED-006, LED-007, LED-008, LED-009, LED-010, LED-011, LED-012. PTY-001 (flag check for PTY integration in LED-006).

---

## Dependency order summary

```
LED-001 (flag + table)
  └─ LED-002 (models)
       └─ LED-003 (CRUD service)
            ├─ LED-004 (lead source attribution)
            ├─ LED-005 (web-to-lead / questionnaire)
            ├─ LED-006 (conversion to party/opp)
            ├─ LED-007 (prospects)
            │    └─ LED-008 (bulk CSV import)
            ├─ LED-009 (duplicate detection & merge)
            ├─ LED-010 (assignment & round-robin)
            ├─ LED-011 (lead scoring)
            ├─ LED-012 (activity log)
            └─ LED-013 (router + frontend + E2E)
```

Soft upstream dependencies (graceful fallback when unavailable):
- PTY-001..PTY-008 (party model) — LED-006 falls back to inline stubs.
- MKT-007 (contact lists) — LED-007 prospect-to-list integration silenced on `ImportError`.
- MKT-010 (tracking codes) — LED-004 attribution silenced on `ImportError`.
