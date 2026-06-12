# ATS Integration Tickets (prefix `ATI`)

These tickets close the **small additive field gaps and cross-module wiring** that the
OpenCATS gap analysis (`docs/opencats/OPENCATS_GAP_ANALYSIS.md`) flagged as **MISSING** or
**PARTIAL** but which are *not* part of the net-new ATS vertical (Job Order / Candidate /
Pipeline = the proposed `JOB`/`CND`/`PIP` clusters). Every ATI ticket is a **thin extension
of an already-planned ticket**: it depends on the owning planned ticket and adds only the
ATS-specific delta. Nothing here forks an existing primitive.

Concretely the five tickets cover:

1. **ATI-001** — company `key_technologies` / `fein` / `billing_contact_party_id` (org-account
   META + PATCH, extending **CCT-001**) and contact `title` / `is_hot` (PERSON party META +
   PATCH, same pattern, extending **PTY-007/PTY-008 + CCT-003**).
2. **ATI-002** — recruiting **report definitions** (submissions / placements /
   recruiter-activity / pipeline-breakdown / candidates-by-source) over the new ATS data,
   registered as report modules in the **RPT-002/RPT-003** report builder.
3. **ATI-003** — calendar **event↔entity linking** (`linked_entity_type` /
   `linked_entity_id` on `EventOut` + a by-entity event query) and the combined
   **log-activity-AND-schedule-next-event** action (one call → **ACT-009** timeline row +
   linked calendar event).
4. **ATI-004** — candidate + job-order result branches in `app/routers/search.py`
   `global_search`.
5. Tests are folded into each ticket (hermetic offline pytest + E2E section).

---

## Cross-cutting constraints (apply to every ATI ticket)

- **Additive + flag-gated, default-off.** No ATI ticket introduces a *new* top-level flag of
  its own where a parent flag already exists; each gates on the owning planned ticket's flag
  (`PARTY_CRM_ORG_ACCOUNTS_ENABLED`, `PARTY_CRM_ENABLED`, `CRM_REPORTS_ENABLED`,
  `CRM_ACTIVITIES_ENABLED`/`CRM_ACTIVITY_TIMELINE_ENABLED`) plus the relevant ATS-vertical
  flag (`ATS_JOB_ORDERS_ENABLED`, `ATS_CANDIDATES_ENABLED`, `ATS_PIPELINE_ENABLED` — owned by
  the JOB/CND/PIP clusters). With every flag off the platform is byte-for-byte unchanged.
- **Depends on the owning planned ticket — never reimplements it.** ATI-001 reuses CCT-001's
  `update_org_account` UpdateExpression/`model_fields_set` partial-update mechanics and PTY-007's
  PERSON-party META row; ATI-002 reuses RPT-002's `_fetch_and_filter` dispatch + RPT-003's
  `_apply_group_by`; ATI-003 reuses ACT-009's `record_crm_activity`; ATI-004 reuses
  `search.py`'s `_make_result_item` / `_search_aggregator` / `_empty_section` contract.
- **SECOPS-007 dev/prod parity.** No `if S.dev_mode:` branch in any new code path. All DDB
  reads/writes go through the existing `T.*` handles (DynamoDB Local in dev, real DynamoDB in
  prod). All money-adjacent fields (none here are money-out) follow existing patterns.
- **`now_ts()` integer Unix seconds** for all numeric timestamps; numeric GSI/SK fields declare
  `attr_types={"...": "N"}` in `scripts/local-ddb-init.py`.
- **`audit_event(event, user_sub, request=None, **fields)`** (`app/services/alerts.py:644`) on
  every successful mutating call.
- **Tests are hermetic + offline** (moto in-memory DDB bound to the frozen `T.*` handle via
  `object.__setattr__`, frozen `S` flags toggled via `object.__setattr__`, async handlers driven
  on a fresh `asyncio.new_event_loop()`, collaborators patched at source). E2E specs require the
  parent flags enabled in the local stack.
- **The ATS-vertical entities (Job Order, Candidate, Pipeline) are owned by the JOB/CND/PIP
  clusters** proposed in the gap analysis (Tier 1, ~15 tickets). ATI tickets that reference ATS
  data (ATI-002, ATI-004) take a **hard dependency** on those clusters and add only the wiring
  delta; they do not define the entities, tables, or services.

---

### ATI-001: Company & contact ATS field gaps — `key_technologies` / `fein` / `billing_contact_party_id` + contact `title` / `is_hot`

**Type:** Feature | **Priority:** P2 | **Estimate:** 2d
**Flags:** `PARTY_CRM_ORG_ACCOUNTS_ENABLED` (org fields), `PARTY_CRM_ENABLED` (contact fields) — both existing, from PTY-001. No new flag.

#### Description — what it extends + reuse citations

The gap matrix rows "Company key-technologies / FEIN / billing-contact pointer" and "Contact
job-title / is-hot flag" are both marked **MISSING** ("small additive gaps not in PTY/CCT").
This ticket closes both by following the **exact** field-extension pattern that **CCT-001**
established for org-account business metadata.

**Part A — Company fields (extends CCT-001 / PTY-008).**
CCT-001 (`docs/suitecrm/specs/CCT-001.md`) already adds five business-metadata fields
(`industry`, `website`, `phone`, `employee_count`, `annual_revenue_cents`) to the
`CrmOrgAccountOut` model + the PARTY_GROUP META row, and introduces
`update_org_account(org_party_id, actor_party_id, *, fields)` (CCT-001 §4.3) + the
`PATCH /ui/party/orgs/{org_party_id}` endpoint (CCT-001 §4.6), with `model_fields_set`-based
partial-update / explicit-REMOVE semantics (CCT-001 §4.2, §5.4) and field allow-listing
(CCT-001 §7). ATI-001 **adds three more additive fields to the same model, META row, and PATCH
allow-list**:

| Attribute | DDB type | Constraint / note |
|---|---|---|
| `key_technologies` | List (L of S) | OpenCATS "Key Technologies" — a tag list; max 50 tags, each ≤ 64 chars, deduped/lower-trimmed; stored as a DDB String Set or List; absent when empty |
| `fein` | String (S) | US Federal Employer Identification Number / tax-id; loose `^\d{2}-?\d{7}$` validation; absent when `None` |
| `billing_contact_party_id` | String (S) | pointer to a PERSON party (the billing contact); validated to exist + be `party_type == "PERSON"` at write time; absent when `None` |

These extend `CrmOrgAccountOut` and `CrmCreateOrgAccountIn` (the CCT-001 §4.2 models) and the
`update_org_account` allow-list set `{"industry","website","phone","employee_count","annual_revenue_cents"}`
→ add the three new keys. `billing_contact_party_id` validation reuses CCT-001's existence-check
ordering (validate org exists → assert ORG_ADMIN → validate referenced party) and `get_party`
(PTY-004). No new endpoint — the existing CCT-001 `PATCH /ui/party/orgs/{org_party_id}` carries
the new fields.

**Part B — Contact fields (extends PTY-007/PTY-008 + CCT-003).**
The PERSON party META row (written by `create_party(party_type="PERSON", ...)` per PTY-004, with
contact mechs from PTY-007) carries no `title` (job-title) or `is_hot` flag. CCT-003
(`docs/suitecrm/specs/CCT-003.md` §4.3) already extends `CrmPartyOut` additively
(`manager_party_id`, `direct_report_count`) and establishes the `/ui/party/parties/{party_id}`
sub-group. ATI-001 adds, in the **same** additive style:

| Attribute | DDB type | Constraint |
|---|---|---|
| `title` | String (S) | contact job-title; max 128 chars; absent when `None` |
| `is_hot` | Bool (BOOL) | OpenCATS "hot candidate/contact" flag; default `False` |

These are appended to `CrmPartyOut` (defaults `None` / `False`, mirroring CCT-003's additive
fields) and persisted on the PERSON META row. A new
`PATCH /ui/party/parties/{party_id}` endpoint (declared in the `/parties/{party_id}` sub-group
**after** static segments to avoid the FastAPI declaration-order capture noted in CCT-001 §4.6
and CCT-003 §4.2) reuses a new `update_person(party_id, actor_party_id, *, fields)` service
helper modelled byte-for-byte on CCT-001 §4.3 `update_org_account` (dynamic UpdateExpression,
`ConditionExpression="attribute_exists(PK)"`, field allow-list `{"title","is_hot"}`, `updated_at`
bump, `audit_event("party_person_updated", ...)`). The `_item_to_party_out` projection (CCT-003
§4.3) is extended to read `item.get("title")` and `bool(item.get("is_hot", False))`.

No new tables, GSIs, or flags. `key_technologies` is **not** indexed in this ticket (skill/tag
search is owned by the proposed skill-tag cluster); it is a plain projected attribute.

#### Acceptance Criteria

- `CrmOrgAccountOut` + `CrmCreateOrgAccountIn` gain `key_technologies: list[str] = []`,
  `fein: Optional[str] = None`, `billing_contact_party_id: Optional[str] = None`; all default-safe
  so existing CCT-001 callers are unaffected.
- `update_org_account` allow-list includes the three new keys; a PATCH with `{"fein": "12-3456789"}`
  updates only `fein` + `updated_at`; `{"key_technologies": ["Python","AWS"]}` stores a deduped
  list; `{"billing_contact_party_id": null}` REMOVEs the attribute.
- Setting `billing_contact_party_id` to a non-existent or non-PERSON party → `HTTPException(400, "billing_contact_must_be_person")`; setting it to a valid PERSON party succeeds.
- `fein` failing `^\d{2}-?\d{7}$` → 422; `key_technologies` with >50 tags or a tag >64 chars → 422.
- `CrmPartyOut` gains `title: Optional[str] = None`, `is_hot: bool = False`; existing CCT-003 callers unaffected.
- `PATCH /ui/party/parties/{party_id}` (auth `require_ui_session`, CSRF) updates `title`/`is_hot` via `update_person`; non-allow-listed keys are ignored; `is_hot=True` then `GET /ui/party/parties/{party_id}` returns `is_hot: true`.
- Both PATCHes emit `audit_event` (`party_org_account_updated` reused for org; `party_person_updated` new for person).
- Flag off (`PARTY_CRM_ORG_ACCOUNTS_ENABLED=0` resp. `PARTY_CRM_ENABLED=0`) → the respective PATCH returns 503; the new fields are never written.
- Hermetic pytest `tests/test_ati_001_ats_field_gaps.py` (moto-backed `T.party`, frozen `S`, handlers driven directly) covers: org three-field create + PATCH + REMOVE; billing-contact-party validation (valid/invalid/non-PERSON); FEIN + key_technologies validation; person `title`/`is_hot` PATCH + projection; flag-off 503; audit emitted. E2E section appended to `frontend/e2e/party-crm.spec.ts`.

#### Dependencies

- **CCT-001** (org-account metadata fields, `update_org_account`, `PATCH /ui/party/orgs/{id}`, partial-update mechanics) — **extended**.
- **PTY-001** (`S.party_crm_enabled`, `S.party_crm_org_accounts_enabled`), **PTY-002** (`T.party`), **PTY-003** (`CrmOrgAccountOut`, `CrmCreateOrgAccountIn`, `CrmPartyOut`), **PTY-004** (`create_party`, `get_party`), **PTY-007** (PERSON contact-mech layer), **PTY-008** (`create_org_account`, `_assert_org_admin`), **PTY-011/PTY-012** (party router scaffold + org-endpoint block), **CCT-003** (`CrmPartyOut` additive extension + `/parties/{party_id}` sub-group + `_item_to_party_out`).

---

### ATI-002: Recruiting report definitions over ATS data (submissions / placements / recruiter-activity / pipeline-breakdown / candidates-by-source)

**Type:** Feature | **Priority:** P2 | **Estimate:** 2d
**Flags:** `CRM_REPORTS_ENABLED` (existing, RPT-001) + `ATS_PIPELINE_ENABLED` / `ATS_CANDIDATES_ENABLED` (owned by PIP/CND clusters). No new flag.

#### Description — what it extends + reuse citations

The gap matrix row "Reports (submissions/placements/recruiter/pipeline/source)" is
**PARTIAL (framework)** — "RPT-002/003/005/007 builder; needs recruiting data source". The
report *engine* already exists; what is missing is **report modules over the ATS data + five
canonical recruiting report definitions**. This ticket adds exactly that wiring on top of the
RPT builder.

**Reuse — RPT-002 module dispatch.** RPT-002 (`docs/suitecrm/specs/RPT-002.md` §2.3, §3) defines
`_fetch_and_filter(module, owner_sub, fields, conditions)` in `app/services/crm_reports.py` with
a per-module dispatch table (RPT-002 §3, line ~230) that iterates a module's DDB table, applies
client-side condition filtering, projects to the requested `fields`, and caps at
`MAX_REPORT_ROWS = 2000`. ATI-002 **adds three new module adapters** to that dispatch table —
keyed on the ATS data owned by the JOB/CND/PIP clusters:

| New module key | Source table (JOB/CND/PIP-owned) | Notable projectable fields |
|---|---|---|
| `ats_pipeline` | pipeline junction table (candidate↔job-order, ranked status) | `candidate_id`, `job_order_id`, `status`, `status_rank`, `recruiter_sub`, `submitted_at`, `placed_at`, `source`, `rating` |
| `ats_candidates` | candidate table | `candidate_id`, `name`, `source`, `owner_sub`, `candidate_status`, `created_at` |
| `ats_job_orders` | job-order table | `job_order_id`, `title`, `client_org_party_id`, `type`, `status`, `openings`, `placed_count` |

Each adapter mirrors the existing RPT-002 adapters' iteration shape (e.g. the `tickets` adapter's
owner-GSI query, RPT-002 §2.3) and the `Decimal→float/int` coercion pattern (RPT-003 §2.2/§2.3).
Owner-scoping uses each ATS table's owner/recruiter GSI (defined by the owning cluster).

**Reuse — RPT-003 GROUP BY.** RPT-003 (`docs/suitecrm/specs/RPT-003.md` §1, §2.1) adds
`_apply_group_by(rows, group_by_field, aggregates)` with COUNT/SUM/AVG/MIN/MAX. ATI-002's report
definitions exercise this engine — no new aggregation logic is written.

**The five canonical recruiting reports** are seeded as `ReportCreateIn` definitions (RPT-002
§2.5 model) — i.e. ordinary report rows in `T.crm_reports`, **not** bespoke code — via an
idempotent seeding helper `seed_recruiting_reports(owner_sub)` (one `RPT#` META row per report,
conditional-put so re-seeding is a no-op):

| Report | Module | group_by | aggregates | Maps to OpenCATS report |
|---|---|---|---|---|
| Submissions | `ats_pipeline` (filter `status_rank >= submitted`) | `recruiter_sub` | COUNT | "Submissions" |
| Placements | `ats_pipeline` (filter `status == placed`) | `recruiter_sub` | COUNT, SUM(`fee_cents`) | "Placements" |
| Recruiter activity | `ats_pipeline` | `recruiter_sub` | COUNT | recruiter productivity |
| Pipeline breakdown | `ats_pipeline` | `status` | COUNT | pipeline-by-status |
| Candidates by source | `ats_candidates` | `source` | COUNT | "Candidates by source" |

No new table (reuses `T.crm_reports`), no new endpoint (reuses RPT-002's
`POST/GET/PATCH/DELETE /ui/crm/reports` + `POST …/{report_id}/run`). The only code additions are
the three module adapters + the seeding helper + their dispatch-table registration.

#### Acceptance Criteria

- `_fetch_and_filter` recognises `ats_pipeline`, `ats_candidates`, `ats_job_orders`; each iterates its source table owner-scoped, applies conditions, projects to `fields`, caps at `MAX_REPORT_ROWS`.
- Unknown/required-condition handling matches RPT-002 (e.g. a missing required owner condition raises `ValueError` → 422 in the router) — no new error shapes.
- `POST /ui/crm/reports/{id}/run` on each seeded report returns grouped rows: pipeline-breakdown returns one row per distinct `status` with a COUNT; placements returns per-recruiter COUNT + SUM(`fee_cents`); candidates-by-source returns per-`source` COUNT.
- `seed_recruiting_reports(owner_sub)` is idempotent (second call writes nothing new; uses a conditional put) and creates exactly the five definitions with the correct `module`/`group_by`/`aggregates`.
- All numeric aggregates Decimal-safe (`fee_cents` summed as int, no float drift), per RPT-003 §2.2/§2.3.
- Flag off (`CRM_REPORTS_ENABLED=0` or the ATS data flag off) → adapters never run / router 404 per RPT-002; no ATS table is read.
- Hermetic pytest `tests/test_ati_002_recruiting_reports.py`: moto-backed `T.crm_reports` + stub ATS tables bound to frozen `T.*`; assert each adapter's projection + each seeded report's grouped output; assert seeding idempotency; assert Decimal-safe SUM. E2E: `frontend/e2e/crm-reports.spec.ts` recruiting-reports section (seed → run → assert group rows).

#### Dependencies

- **RPT-001** (`S.crm_reports_enabled`, `T.crm_reports`), **RPT-002** (`_fetch_and_filter` dispatch, `ReportCreateIn`, report CRUD + run endpoints), **RPT-003** (`_apply_group_by`, `AggregateSpec`, `group_by`/`aggregates` on `ReportCreateIn`) — **extended**.
- **JOB cluster** (job-order entity + table + owner GSI), **CND cluster** (candidate entity + source attribution + owner GSI), **PIP cluster** (pipeline junction + ranked status + recruiter/placement fields) — **hard dependency** (provide the data the new modules read). ATI-002 adds only the adapters + report definitions, not the entities.

---

### ATI-003: Calendar event↔entity linking + combined "log activity AND schedule next event"

**Type:** Feature | **Priority:** P2 | **Estimate:** 2d
**Flags:** `CRM_ACTIVITIES_ENABLED` + `CRM_ACTIVITY_TIMELINE_ENABLED` (existing, ACT-001) for the combined action. Event-link fields gate on the same activities flag. No new flag.

#### Description — what it extends + reuse citations

Two gap-matrix items: **event↔entity link** is flagged **MISSING** ("on `app/models.py` EventOut")
and **Combined "log activity + schedule next event"** is flagged **MISSING**.

**Part A — event↔entity linking (extends `app/routers/calendar.py` + `EventOut`).**
`EventOut` (`app/models.py:1274`) and `EventCreateIn` (`app/models.py:1256`) / `EventUpdateIn`
(`app/models.py:1298`) carry no entity reference. The `calendar` table
(`scripts/local-ddb-init.py:99`, `TableDef(..., "calendar_id", "sk")`) has **no GSI** — events are
stored as `{"calendar_id", "sk": "event#{event_id}", ...}` items (`create_event`,
`app/routers/calendar.py:1550-1588`) and listed via
`Key("calendar_id").eq(...) & Key("sk").begins_with("event#")` (`calendar.py:854`). This ticket
adds two additive optional fields end-to-end:

- `linked_entity_type: Optional[str]` (allow-listed: `"contact"`, `"lead"`, `"account"`,
  `"opportunity"`, `"candidate"`, `"job_order"`) and `linked_entity_id: Optional[str]` — appended
  to `EventCreateIn`, `EventUpdateIn`, and `EventOut` (defaults `None`), persisted on the event
  item in `create_event`/`update_event`, and surfaced by the `_event_out` serializer
  (`calendar.py:979`).
- A **by-entity event query**. Because the calendar table has no GSI, ATI-003 writes a **sparse
  secondary index item** alongside each linked event — a row keyed
  `{"calendar_id": "ENTITY#{linked_entity_type}#{linked_entity_id}", "sk": "event#{event_id}", ...}`
  (a pointer carrying `source_calendar_id` + denormalised `start_utc`/`name`) — and queries it via
  the existing `Key("calendar_id").eq(f"ENTITY#{type}#{id}") & Key("sk").begins_with("event#")`
  pattern (identical mechanics to `calendar.py:854`, no schema change, no GSI). The pointer is
  written/updated/deleted in lockstep with the event in `create_event`/`update_event`/`delete_event`.
  New endpoint `GET /ui/calendar/events/by-entity?entity_type=&entity_id=` returns
  `list[EventOut]` (resolved from the pointer's `source_calendar_id` + `event_id`).

**Part B — combined log-activity-and-schedule (extends ACT-009 + Part A).**
ACT-009 (`docs/suitecrm/specs/ACT-009.md` §1) provides `record_crm_activity(...)` (the central
timeline write primitive) on `crm_activity_timeline`. This ticket adds **one** endpoint
`POST /ui/crm/entities/{entity_type}/{entity_id}/log-and-schedule` whose single call:

1. writes an ACT-009 timeline activity (e.g. `type="call"`/`note` with the logged outcome) via
   `record_crm_activity(entity_type, entity_id, ...)`, then
2. creates a calendar event for the "next step" via the Part-A `create_event` path **with**
   `linked_entity_type`/`linked_entity_id` set to the same entity (so the scheduled follow-up is
   itself discoverable through the by-entity query).

The endpoint is best-effort-ordered (timeline write first; if the event creation fails the
already-written activity is preserved and the response reports `event_created: false` — the
timeline row is never rolled back, mirroring ACT-009's no-op-guard philosophy). The body is a new
`CrmLogAndScheduleIn` model (activity fields + an embedded `EventCreateIn`-shaped `next_event`).

No new flag; both parts gate on the existing activities/timeline flags (event-link fields are
inert no-ops when unset, so Part A's additive fields are safe even with the flag off — they simply
stay `None`).

#### Acceptance Criteria

- `EventCreateIn`/`EventUpdateIn`/`EventOut` gain `linked_entity_type`/`linked_entity_id` (default `None`); existing event create/list/update callers unaffected (fields omitted → `None`).
- `linked_entity_type` outside the allow-list → 422; both fields must be set together (one without the other → 422).
- Creating a linked event writes both the event item and the `ENTITY#{type}#{id}` pointer; deleting/updating the event keeps the pointer in sync (re-pointing on entity change, removing on unlink).
- `GET /ui/calendar/events/by-entity?entity_type=contact&entity_id=X` returns every `EventOut` linked to that entity, resolved from the pointer; empty list (not 404) when none.
- `POST /ui/crm/entities/{type}/{id}/log-and-schedule` writes exactly one ACT-009 timeline row AND one linked calendar event in a single call; response carries the new `activity_id` + `event_id`; the scheduled event is returned by the by-entity query.
- If `next_event` creation raises, the timeline activity is still persisted and the response reports `event_created: false` (no rollback of the activity).
- Flag off → `log-and-schedule` and `by-entity` return 503/404 per the parent flags; `record_crm_activity` no-ops per ACT-009.
- Hermetic pytest `tests/test_ati_003_event_entity_link.py`: moto-backed `T.calendar` + `T.crm_activity_timeline` bound to frozen `T.*`; `record_crm_activity` spied; assert event+pointer write/sync/delete, by-entity query, combined-action both-writes + event-failure-preserves-activity, allow-list/paired-field validation, flag-off. E2E section in `frontend/e2e/calendar-messaging.spec.ts` (or a new `frontend/e2e/crm-calendar-link.spec.ts`).

#### Dependencies

- **ACT-001** (`S.crm_activities_enabled`, `S.crm_activity_timeline_enabled`, `T.crm_activity_timeline`), **ACT-009** (`record_crm_activity` write primitive + timeline service) — **extended (Part B)**.
- `app/routers/calendar.py` `create_event`/`update_event`/`delete_event`/`list_events` + `_event_out` serializer + `EventCreateIn`/`EventUpdateIn`/`EventOut` (`app/models.py:1256-1313`) — **extended (Part A)**; the `calendar` table (`scripts/local-ddb-init.py:99`).
- Entity-type allow-list values `candidate`/`job_order` reference the **CND/JOB clusters** (soft — the link fields are free-string-validated against an allow-list and do not require the ATS tables to exist; the by-entity query works for any entity type).

---

### ATI-004: Candidate + job-order branches in global search

**Type:** Feature | **Priority:** P2 | **Estimate:** 1d
**Flags:** `GLOBAL_SEARCH_EXTENDED_DOMAINS` (existing) + `ATS_CANDIDATES_ENABLED` / `ATS_JOB_ORDERS_ENABLED` (owned by CND/JOB clusters). No new flag.

#### Description — what it extends + reuse citations

The gap matrix row "Global/per-module search" is **HAVE** with the explicit note "(add
candidate/job branches)". `app/routers/search.py` already fans out to nine per-module search
functions (`_search_users`/`_search_posts`/`_search_catalog`/`_search_files`/`_search_messages`/
`_search_tickets`/`_search_contacts`/`_search_videos`/`_search_calendar`) via
`_search_aggregator` (`search.py:645`), with the module set in `ALLOWED_TYPES`
(`search.py:43-45`) and registered in the `_search_aggregator` dispatch (`search.py:656-674`).
Each function returns the standard section shape `{"items", "total_estimate", "has_more"}` built
from `_make_result_item(...)` (`search.py:64`) and `_empty_section()` (`search.py:60`).

ATI-004 adds **two more branches** following that exact contract:

- `_search_candidates(q, user_id, limit)` — owner-scoped query against the candidate table (CND
  cluster) matching `name`/`email`/`title`/skills; emits `_make_result_item(type="candidate", id=candidate_id, title=name, snippet=current_title_or_status, url=f"/ats/candidates/{candidate_id}", meta={...})`.
- `_search_job_orders(q, user_id, limit)` — query against the job-order table (JOB cluster)
  matching `title`/`client`/`description`; emits `_make_result_item(type="job_order", id=job_order_id, title=title, snippet=client_name, url=f"/ats/job-orders/{job_order_id}", meta={...})`.

Wiring (mirrors the existing extended-domain pattern at `search.py:44-45` and the dispatch at
`search.py:656-674`):

- `ALLOWED_TYPES |= {"candidates", "job_orders"}` guarded by the ATS flags (only added when the
  respective cluster flag is on, so flag-off keeps the type-allow-list and the validation
  (`search.py:856-858`) byte-for-byte unchanged).
- `_search_aggregator` registers `search_fns["candidates"]` / `search_fns["job_orders"]` under
  the existing `if "<type>" in types:` blocks; the `ThreadPoolExecutor` fan-out, per-section
  timeout, and `partial` handling are reused unchanged.

No router signature change (`global_search`, `search.py:824` already accepts a `types` CSV defaulting
to `ALLOWED_TYPES`), no new endpoint, no new table.

#### Acceptance Criteria

- `GET /search?q=...&types=candidates,job_orders` returns `results.candidates` and `results.job_orders` sections in the standard `{items, total_estimate, has_more}` shape; each item has `type` `"candidate"`/`"job_order"` and a resolvable `url`.
- Candidate matches surface on `name`/`email`/`title`; job-order matches surface on `title`/`client`/`description`; both owner-scoped (a viewer never sees another recruiter's records beyond the existing ACL).
- Both branches participate in the parallel fan-out and honour `limit`; a slow/failing branch yields `_empty_section()` + `partial: true` (existing aggregator behaviour, `search.py:683-686`).
- With the ATS flags off, `candidates`/`job_orders` are **not** in `ALLOWED_TYPES`; requesting them → `HTTPException(400, "Invalid search types: ...")` (existing validation, `search.py:856-858`) — no new code path for flag-off.
- Default `global_search` (no `types`) includes the new types only when the flags are on.
- Hermetic pytest `tests/test_ati_004_search_ats.py`: moto-backed candidate/job-order tables bound to frozen `T.*`; call `_search_candidates`/`_search_job_orders` directly and assert result shape + matching + owner-scoping; assert flag-off keeps `ALLOWED_TYPES` unchanged. E2E section in `frontend/e2e/search-messaging.spec.ts` (or `search-ats.spec.ts`): seed a candidate + job order, `GET /search` asserts both sections.

#### Dependencies

- `app/routers/search.py` (`_search_aggregator`, `_make_result_item`, `_empty_section`, `ALLOWED_TYPES`, `global_search`) — **extended**.
- **CND cluster** (candidate entity + table + owner GSI) and **JOB cluster** (job-order entity + table + owner GSI) — **hard dependency** (provide the data the new branches read). ATI-004 adds only the two search functions + dispatch wiring.

---

### ATI-005: ATS integration regression test suite + flag-matrix coverage

**Type:** Test | **Priority:** P2 | **Estimate:** 1d
**Flags:** all parent flags above (toggled per case). No new flag.

#### Description — what it extends + reuse citations

ATI-001..ATI-004 each ship their own hermetic unit tests + E2E section. ATI-005 adds the
**cross-ticket integration + flag-matrix** coverage that no single ticket owns, ensuring the four
thin extensions compose correctly and that **every** new surface is inert when its parent flag is
off (the load-bearing SECOPS-007 / additive-default-off guarantee). It reuses the existing
hermetic patterns (moto `T.*` via `object.__setattr__`, frozen `S` toggling, direct async-handler
invocation) — no new test infrastructure.

Coverage:

- **End-to-end ATS thread (flags on):** create org account with `key_technologies`/`fein`/
  `billing_contact_party_id` (ATI-001) → seed + run the pipeline-breakdown and candidates-by-source
  recruiting reports (ATI-002) → `log-and-schedule` a follow-up against a candidate, asserting the
  linked event is found by the by-entity query (ATI-003) → `GET /search` returns the candidate +
  job order (ATI-004). Asserts the four deltas interoperate through shared `T.party`/`T.crm_reports`/
  `T.calendar`/`T.crm_activity_timeline` state.
- **Flag matrix:** for each parent flag (`PARTY_CRM_ORG_ACCOUNTS_ENABLED`, `PARTY_CRM_ENABLED`,
  `CRM_REPORTS_ENABLED`, `CRM_ACTIVITY_TIMELINE_ENABLED`, the ATS cluster flags,
  `GLOBAL_SEARCH_EXTENDED_DOMAINS`) toggled **off**, assert the corresponding ATI surface returns
  503 / 404 / "Invalid search types" / `None`-defaulted fields and performs **zero** writes to its
  table — byte-for-byte parity with pre-ATI behaviour.
- **Additive-projection regression:** assert that the additive model fields (`EventOut`,
  `CrmOrgAccountOut`, `CrmPartyOut`) serialise the new optional fields as `null`/`[]`/`false` for
  legacy rows lacking them, so existing API/E2E consumers don't break.

#### Acceptance Criteria

- `tests/test_ati_005_integration.py` exercises the full on-flags thread and asserts all four ATI deltas interoperate (shared DDB state observed across modules).
- Parametrised flag-off cases assert each ATI surface is inert (correct error/empty/`None` + zero table writes) for every parent flag.
- Legacy-row projection cases assert additive fields default safely (`null`/`[]`/`false`).
- Suite is fully offline/hermetic (no real AWS/network); runs under `just test`.

#### Dependencies

- **ATI-001, ATI-002, ATI-003, ATI-004** (the surfaces under integration test).
- Indirectly all parent tickets those depend on (CCT-001, PTY-001/002/003/004/007/008/011/012, CCT-003, RPT-001/002/003, ACT-001/009, and the JOB/CND/PIP clusters).
