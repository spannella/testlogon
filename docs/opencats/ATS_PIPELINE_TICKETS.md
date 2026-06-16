# ATS Pipeline & Submissions — Ticket Set (prefix `PIP`)

**Area:** OpenCATS gap analysis §C — *Pipeline & Submissions* (candidate ↔ job-order pipeline).
**Source gap doc:** `docs/opencats/OPENCATS_GAP_ANALYSIS.md` §C (rows: pipeline M:N junction, ranked configurable status workflow + Kanban, status-change logging, candidate rating 1–5, submit-to-client, bulk add/remove, placement record).

This set delivers the **candidate↔job-order pipeline** — the join that makes testlogon an ATS rather than a pile of independent candidate and job records. It is modelled directly on the SuiteCRM **OPP** specs (the closest already-specced analogue):

- **OPP-004** (`docs/suitecrm/specs/OPP-004.md`) — the **single-table M:N junction** pattern (`pk=USER#{owner}` / `sk=OPP#{id}#CONTACT#{ref}`, `begins_with` query, `ConditionExpression=Attr("sk").not_exists()` duplicate guard, ownership-by-key authz, additive `OpportunityOut` field, fire-and-forget `audit_event`). PIP reuses this verbatim for the pipeline-entry join.
- **OPP-003** (`docs/suitecrm/specs/OPP-003.md`) — the **admin-configurable ranked stage-config row** (`pk=STAGE_CONFIG`/`sk=META`, JSON-encoded ordered stage list, `GET /…/stages` for everyone + `PUT /ui/admin/…/stages` admin-only, default-fallback when no row, `_reopen_target_stage`, audited writes) **plus the drag Kanban** (`@dnd-kit/core` already in `frontend/package.json:17`, columns fetched from the API never hard-coded, optimistic move + `onError` rollback + `sonner` toast). PIP reuses this for the recruiting status workflow.
- **ACT-003** (`docs/suitecrm/specs/ACT-003.md`) — the **email-with-attachment** pattern (`send_alert_email` at `app/services/alerts.py:459`; the multipart/raw SES path + dev-log fallback added there for ICS) is the template for the *submit-to-client* résumé-attachment email.
- **ACT-009** (`docs/suitecrm/specs/ACT-009.md`) — the **per-entity activity timeline** write primitive `record_crm_activity` (`app/services/crm_activity_timeline.py`, `entity_key="{type}#{id}"`, inverted-ts SK, fire-and-forget lazy-import `try/except`). PIP status changes / submissions / placements are logged through it (with `audit_event` as the always-on secondary sink at `app/services/alerts.py:644`).

---

## Cross-cutting constraints (apply to every PIP ticket)

1. **Master flag, default-off, additive.** All behavior is gated behind a single new setting `S.ats_pipeline_enabled` (`ATS_PIPELINE_ENABLED`, default `false`), introduced in **PIP-001** (positive-set pattern matching OPP-001's `sales_pipeline_enabled` and the `inventory_reservations_enabled` style verified at `app/core/settings.py`). With the flag off: no PIP route is mounted, no DDB writes occur, no sidebar entry appears, and every existing code path is byte-for-byte unchanged. A `_require_flag()` helper (mirroring OPP-002's, `raise HTTPException(503, detail={"code": "ats_pipeline_disabled"})`) runs at the top of every service function. The frontend mirror flag is `VITE_ATS_PIPELINE_ENABLED` (`toBool(env.VITE_ATS_PIPELINE_ENABLED, false)` + `isAtsPipelineEnabled()` in `frontend/src/lib/featureFlags.ts`, per the OPP-003 §6.3 pattern).

2. **Dependencies on sibling ATS tickets (forward deps).** This set depends on the **JOB-*** (job orders / requisitions) and **CND-*** (candidates) ticket sets called for in the gap doc §"Tier 1 — Core ATS entities". Those provide: `T.ats_job_orders` + `get_job_order(owner_sub, job_order_id)` (ownership gate) + `S.ats_job_orders_enabled`; and `T.ats_candidates` + `get_candidate(owner_sub, candidate_id)` + the candidate résumé-attachment linkage (the "primary résumé" S3 pointer). Where a JOB-*/CND-* primitive is not yet merged, PIP code uses a lazy local import inside `try/except` (the ACT-007 → ACT-009 ordering-independence trick described in ACT-009 §2.3) and treats a missing record as 404. PIP **does not** re-implement job-order or candidate CRUD.

3. **Single-table, no new tables where avoidable.** The pipeline junction + its sub-rows (rating, placement) all live in **one** new `ats_pipeline` DynamoDB table (PIP-001). The ranked status-config row reuses that same table (`pk=PIPELINE_STATUS_CONFIG`/`sk=META`), exactly as OPP-003's `STAGE_CONFIG#META` reuses `sales_opportunities`. No GSI is added that requires a numeric sort key unless a `TableDef` `attr_types={…:"N"}` entry is added in `scripts/local-ddb-init.py` (CLAUDE.md numeric-GSI-sort-key gotcha).

4. **DDB write proxy + timestamps.** All writes go through `T.ats_pipeline` (a `_FloatSafeTable`, `app/core/tables.py:29`/`:65-66`) so Python floats coerce to `Decimal`. All timestamps are integer Unix seconds via `now_ts()` (`app/core/time.py:2`). Money is integer cents (`fee_cents`), never float.

5. **Ownership-by-key authz (no role gate on the data plane).** Pipeline entries are partitioned under the recruiter's `pk=USER#{owner_sub}`. An attacker passing another user's id gets a 404 from the keyed lookup (OPP-004 §5 "structural authorization"). The **only** admin-gated surface is `PUT /ui/admin/ats/pipeline/statuses` (status-config write), enforced with `normalize_role(ctx.get("role")) in {Role.ADMIN, Role.ROOT}` (`app/auth/roles.py:48`) exactly as OPP-003 §4.2 does. `require_ui_session` (`app/services/sessions.py:330`) is the auth dependency everywhere and enforces CSRF on non-GET cookie requests automatically.

6. **Audit + timeline on every state change.** Every mutation calls `audit_event(...)` (`app/services/alerts.py:644`, fire-and-forget, writes `T.alerts`) **and**, when the linked entities resolve, `record_crm_activity(...)` (ACT-009) so the change shows on both the candidate's and the job-order's timelines. Both are best-effort (`try/except`, never block the mutation).

7. **Dev/prod parity (SECOPS-007).** No `if S.dev_mode` business-logic branches. The only env-fork is the *delivery substrate* already abstracted by the reused primitives (`send_alert_email` / the ACT-003 raw-SES path log to `S.dev_email_log` in dev and SES in prod; `s3_client()` at `app/core/aws_clients.py:114` hits in-process moto in dev and real S3 in prod). DDB code is identical in both.

8. **Tests.** Each backend ticket ships a hermetic pytest (`tests/test_pip_NNN_*.py`): moto in-memory `ats_pipeline` table bound to the frozen `T` via `object.__setattr__`, `S.ats_pipeline_enabled` toggled via `object.__setattr__`, route handlers called **directly** (no `TestClient` — broken per CLAUDE.md), `audit_event`/`record_crm_activity`/`send_alert_email`/`s3_client` monkeypatched where asserted. E2E lives in one shared `frontend/e2e/ats-pipeline.spec.ts` with section blocks added per ticket (`injectAuth(page, …)` + `x-csrf-token` per the repo E2E conventions). With the flag off, an E2E asserts the sidebar entry is absent and the API returns 503.

---

### PIP-001: Pipeline junction model + table + master flag

**Type:** Feature
**Priority:** P0
**Estimate:** 2 days

**Description**
Introduce the candidate↔job-order pipeline as an M:N junction in a new single-table, plus the master feature flag — the foundation every other PIP ticket builds on. Models the OPP-004 junction verbatim, generalised from "opportunity↔contact" to "job-order↔candidate".

*DDB model* — new table `ats_pipeline` (`T.ats_pipeline` via `_safe_table(S.ats_pipeline_table_name)` in `app/core/tables.py`; `TableDef` in `scripts/local-ddb-init.py`):

| pk | sk | Purpose |
|---|---|---|
| `USER#{owner_sub}` | `PIPE#{job_order_id}#CAND#{candidate_id}` | Pipeline entry (the junction row) |
| `PIPELINE_STATUS_CONFIG` | `META` | Ranked status config (PIP-002) |

Pipeline-entry attributes: `pk`, `sk`, `pipeline_id` (`pe_{uuid4().hex}`, projected for ergonomic reads), `job_order_id`, `candidate_id`, `owner_sub`, `status` (string status key, default `"100_no_contact"`), `status_rank` (int, denormed from the status config for ordering), `rating` (int 0–5, default 0; 0 = unrated — PIP-004 owns writes), `created_at` (N), `updated_at` (N). One numeric GSI **may** be added later (PIP-008 bulk/list) keyed on a `job_order_id`-scoped sort — if so it needs `attr_types={…:"N"}`; PIP-001 itself adds none.

*Pydantic models* (`app/models.py`, near the job-order/candidate models): `PipelineEntryCreateIn { job_order_id, candidate_id, status?: str }`, `PipelineEntryOut { pipeline_id, job_order_id, candidate_id, owner_sub, status, status_rank, rating, created_at, updated_at }`. Add additive `pipeline_entries: List[PipelineEntryOut] = Field(default_factory=list)` to the job-order and candidate `…Out` models (default `[]`, populated only on `include_pipeline=true`), exactly as OPP-004 §3 adds `OpportunityOut.contact_roles`.

*Service* (`app/services/ats_pipeline.py`, new): `_require_flag()`; `add_to_pipeline(owner_sub, data)` — validates both `get_job_order(owner_sub, job_order_id)` and `get_candidate(owner_sub, candidate_id)` as ownership gates (404 if either missing/foreign; lazy-import per cross-cutting #2), then `put_item(..., ConditionExpression=Attr("sk").not_exists())` → 409 `pipeline_entry_exists` on duplicate (OPP-004 §4 duplicate idiom); `get_pipeline_entry(owner_sub, job_order_id, candidate_id)`; `list_pipeline_for_job(owner_sub, job_order_id)` and `list_pipeline_for_candidate(owner_sub, candidate_id)` via `pk=USER#{owner}` + `sk.begins_with(...)`, looping `LastEvaluatedKey` (CLAUDE.md 1MB pagination gotcha); `remove_from_pipeline(...)` (404 `pipeline_entry_not_found`). Each mutation emits `audit_event("pipeline.candidate_added"/"…removed", owner_sub, None, …)`.

*Settings* (`app/core/settings.py`): `ats_pipeline_enabled` (`ATS_PIPELINE_ENABLED`, default `false`) + `ats_pipeline_table_name` (default `"ats_pipeline"`).

**Reuse / citations:** OPP-004 §3/§4 (junction table shape, `begins_with` query, conditional-put duplicate guard, ownership-by-key, additive `…Out` field); `_FloatSafeTable` (`app/core/tables.py:29`/`:65`); `audit_event` (`app/services/alerts.py:644`); `now_ts()` (`app/core/time.py:2`); OPP-001 `sales_pipeline_enabled` flag style.

**Acceptance Criteria**
- `T.ats_pipeline` handle wired; `ats_pipeline` `TableDef` present in `scripts/local-ddb-init.py`; `just restart` recreates it.
- Flag `false` (default): service functions raise 503 `ats_pipeline_disabled`; no router mounted (router lands in PIP-009).
- `add_to_pipeline` writes a row keyed `PIPE#{job}#CAND#{cand}`, returns `PipelineEntryOut` with `status="100_no_contact"`, `rating=0`; duplicate (same job+cand under same owner) → 409 `pipeline_entry_exists`; foreign job or candidate → 404.
- `list_pipeline_for_job` / `list_pipeline_for_candidate` return all entries under the owner's partition, loop-paginated.
- Each add/remove emits the documented `audit_event`.
- Job-order/candidate `…Out` gain `pipeline_entries=[]` by default (wire-compatible).
- `tests/test_pip_001_pipeline_junction.py` hermetic (moto + frozen-T `object.__setattr__`): add/list/remove, duplicate-409, foreign-404, flag-off-503, audit emitted.

**Dependencies:** JOB-* (`T.ats_job_orders`, `get_job_order`), CND-* (`T.ats_candidates`, `get_candidate`). No upstream PIP dep.

---

### PIP-002: Ranked, admin-configurable status workflow (status-config row)

**Type:** Feature
**Priority:** P0
**Estimate:** 2 days

**Description**
Add the OpenCATS ranked recruiting status workflow as an **admin-configurable stored config row**, modelled exactly on OPP-003's stage config. The default ladder is the canonical OpenCATS pipeline:

`100 No-Contact → 200 Contacted → 300 Qualifying → 400 Submitted → 500 Interviewing → 600 Offered → 700 Not-in-Consideration → 800 Client-Declined → 900 Placed`.

*DDB model* — single row on the PIP-001 `ats_pipeline` table: `pk="PIPELINE_STATUS_CONFIG"`, `sk="META"`, `statuses` (JSON-encoded ordered list, stored as a String — OPP-003 §3.1 marshalling), `updated_at` (N), `updated_by_sub` (S). Each list element: `{ status_key, label, rank (int, the OpenCATS 100…900 weight), order (int, column position), is_submitted (bool), is_placed (bool), is_terminal (bool), color? }`. (`rank` drives ordering/forward-progress logic; `is_submitted`/`is_placed` flag the two stages that trigger side effects — PIP-005 submit, PIP-006 placement; `is_terminal` flags 700/800/900-style stops.)

*Pydantic* (`app/models.py`): `PipelineStatusItemIn/Out` + `PipelineStatusConfigIn/Out` (OPP-003 §3.1 shapes). `PipelineStatusConfigIn` root-validator enforces: 1–20 statuses, unique `status_key`, **exactly one** `is_placed`, **at most one** `is_submitted`, ranks distinct. Violations → 422 → service re-raises 400 `invalid_status_config` (OPP-003 §4.1 `_validate…`).

*Service* (`app/services/ats_pipeline.py`): `get_status_config()` → returns stored row, or `_default_status_config()` (the 9-status ladder above, `is_submitted` on `400_submitted`, `is_placed` on `900_placed`, `is_terminal` on 700/800/900) when absent — so reads never error before first admin write (OPP-003 §5.1). `set_status_config(admin_sub, data)` → `_validate…` then unconditional `put_item` (full replacement, idempotent, last-write-wins; OPP-003 §5.3/§7.2) + `audit_event("ats_status_config.updated", admin_sub, None, status_count=…, submitted_key=…, placed_key=…)`. Helper `resolve_status_rank(status_key)` reads the config to denorm `status_rank` onto pipeline entries (used by PIP-003).

**Reuse / citations:** OPP-003 §3.1–§4.1 (config-row marshalling, default fallback, full-replacement put, validation codes, audited write), §6 flag style. Reuses the PIP-001 table + flag (no new table).

**Acceptance Criteria**
- `get_status_config()` with no row returns the 9 default statuses with correct `rank`/`order` and `is_submitted` on `400_submitted`, `is_placed` on `900_placed`.
- `set_status_config` writes `PIPELINE_STATUS_CONFIG#META`; round-trips; two zero-`is_placed` → 400 `invalid_status_config`; two `is_placed` → 400; duplicate `status_key` → 400.
- `set_status_config` emits `ats_status_config.updated` audit with the documented kwargs.
- Flag off → both raise 503.
- `tests/test_pip_002_status_config.py`: default fallback, valid set, each validation rejection, audit emitted, flag-off-503.

**Dependencies:** PIP-001.

---

### PIP-003: Status-change transitions + logging (timeline + audit)

**Type:** Feature
**Priority:** P0
**Estimate:** 2 days

**Description**
Implement the pipeline-entry **status change** operation and wire it to the ACT-009 per-entity timeline + `audit_event`. This is the workhorse the Kanban drag (PIP-009 FE) and the submit/placement actions (PIP-005/006) call.

*Service* (`app/services/ats_pipeline.py`): `change_status(owner_sub, job_order_id, candidate_id, new_status, *, note=None) -> PipelineEntryOut`:
1. `get_pipeline_entry(...)` (ownership gate; 404 if absent).
2. Resolve `get_status_config()`; reject `invalid_status` (400) if `new_status` not in the current config's keys (OPP-003 §5.2 step 4 — validate the *incoming* status against the live config regardless of legacy values).
3. No-op short-circuit if `new_status == current` (idempotent; no log written).
4. `update_item` setting `status`, `status_rank=resolve_status_rank(new_status)`, `updated_at=now_ts()`.
5. `audit_event("pipeline.status_changed", owner_sub, None, pipeline_id=…, job_order_id=…, candidate_id=…, from_status=…, to_status=…, from_rank=…, to_rank=…)`.
6. Best-effort `record_crm_activity(...)` (ACT-009) **twice** — once for `entity_type="candidate"`/`entity_id=candidate_id` and once for `entity_type="job_order"`/`entity_id=job_order_id` — `activity_type="pipeline_status"`, `summary=f"Pipeline status → {label}"`, `metadata={from_status, to_status, note}`. Lazy-import + `try/except` so a missing/absent timeline service never blocks the transition (ACT-009 §2.3 pattern).

Forward-progress is **not** enforced (OpenCATS allows moving backward, e.g. 800 → 300); the config's `rank` is recorded for reporting only. (A future ticket may add an optional `ats_pipeline_block_regression` flag à la OPP-003 `sales_pipeline_allow_reopen`.)

**Reuse / citations:** OPP-003 §4.1 stage-change `audit_event("…stage_changed")` + config-validation; ACT-009 `record_crm_activity` write primitive + fire-and-forget lazy-import guard (§2.3); `audit_event` (`alerts.py:644`); `now_ts()`.

**Acceptance Criteria**
- `change_status` from `100_no_contact` → `300_qualifying` updates `status`+`status_rank`, returns updated `PipelineEntryOut`.
- `new_status` not in config → 400 `invalid_status`; foreign entry → 404; same-status → no-op (no audit/timeline write).
- Emits one `pipeline.status_changed` audit with correct `from_status`/`to_status`/`from_rank`/`to_rank`.
- Calls `record_crm_activity` for **both** the candidate and the job-order entity (assert via monkeypatch capturing 2 calls); a raised exception inside it does **not** propagate.
- Flag off → 503.
- `tests/test_pip_003_status_change.py`: happy path, invalid-status-400, foreign-404, same-status no-op, dual timeline write, timeline-failure-swallowed, audit kwargs.

**Dependencies:** PIP-001, PIP-002; ACT-009 (`record_crm_activity`, soft via lazy import).

---

### PIP-004: Candidate rating (1–5) within a pipeline entry

**Type:** Feature
**Priority:** P1
**Estimate:** 1 day

**Description**
Let a recruiter set a 1–5 star rating on a candidate **within a specific job-order pipeline** (OpenCATS rates the candidate per-pipeline, not globally), stored on the PIP-001 junction row.

*Pydantic* (`app/models.py`): `PipelineRatingIn { rating: int = Field(ge=0, le=5) }` (0 = clear the rating).
*Service*: `set_rating(owner_sub, job_order_id, candidate_id, rating) -> PipelineEntryOut` — `get_pipeline_entry` ownership gate (404), `update_item` setting `rating`+`updated_at`, `audit_event("pipeline.rated", owner_sub, None, pipeline_id=…, rating=…, previous_rating=…)`, best-effort `record_crm_activity` (candidate entity, `activity_type="pipeline_rating"`, `summary=f"Rated {rating}/5"`). Validation is Pydantic-layer (422) for out-of-range; service re-checks `0 ≤ rating ≤ 5` as defence-in-depth (400 `invalid_rating`).

**Reuse / citations:** OPP-004 §4 ownership-by-key + audited mutation; the `rating` attribute defined in PIP-001's junction row; `record_crm_activity` (ACT-009).

**Acceptance Criteria**
- `set_rating(...,4)` persists `rating=4`; returns updated entry.
- `rating=0` clears it; `rating=6` / `-1` → 422 at the model boundary (and 400 if forced past the model).
- Foreign entry → 404; flag off → 503.
- Emits `pipeline.rated` audit with `previous_rating`.
- `tests/test_pip_004_rating.py`: set, clear, out-of-range, foreign-404, flag-off-503, audit.

**Dependencies:** PIP-001 (junction `rating` field); PIP-003 (shares the `update_item` helper).

---

### PIP-005: "Submit candidate to client" action (SES email + résumé attach + advance status + log)

**Type:** Feature
**Priority:** P1
**Estimate:** 3 days

**Description**
The signature ATS action: submit a candidate's résumé to the hiring-company contact by email, **advance the pipeline status to the configured `is_submitted` stage**, and log a typed activity — all atomically from the recruiter's POV. Reuses the ACT-003 email-with-attachment plumbing for the résumé attachment.

*Pydantic* (`app/models.py`): `SubmitToClientIn { to_emails: List[EmailStr] (1–10), subject?: str, message?: str, resume_attachment?: bool = True }`.
*Service* `submit_to_client(owner_sub, job_order_id, candidate_id, data) -> SubmitToClientOut`:
1. `get_pipeline_entry(...)` ownership gate (404).
2. Resolve the candidate's **primary résumé** S3 pointer via the CND-* linkage (lazy import; if `resume_attachment` and no primary résumé exists → 400 `no_primary_resume`). Fetch bytes via `s3_client().get_object(...)` (`app/core/aws_clients.py:114` — in-process moto in dev, real S3 in prod; SECOPS-007 parity).
3. Build subject (`f"Candidate submission: {candidate_name} — {job_order_title}"` default) and a merge body; send via the **ACT-003 multipart/raw-SES path** — i.e. extend or reuse `send_calendar_invite_email`'s raw-MIME builder generalised to `send_email_with_attachment(to_emails, subject, body_text, attachment_bytes, filename, mime_type)` (one `ses.send_raw_email` per recipient in prod; structured `S.dev_email_log` entry in dev — never raises). Fall back to `send_alert_email` (`alerts.py:459`) when `resume_attachment=False` (no attachment).
4. On send success, call `change_status(owner_sub, job_order_id, candidate_id, <is_submitted status_key from get_status_config()>)` (PIP-003) — advancing to `400_submitted` by default. If the entry is already at/past submitted, the status update is a no-op but the email still sends.
5. `audit_event("pipeline.submitted_to_client", owner_sub, None, pipeline_id=…, to_emails=…, with_resume=…)` and best-effort `record_crm_activity` (both candidate + job-order entities, `activity_type="submission"`, `summary=f"Submitted to {', '.join(to_emails)}"`) — the ACT-009 §C "Submitted" typed-activity row.

*Idempotency/best-effort:* the email send is best-effort and the status advance is idempotent; a re-submit re-sends and re-logs (callers wanting once-only semantics gate in the UI).

**Reuse / citations:** ACT-003 §4.2 `send_calendar_invite_email` raw-MIME `ses.send_raw_email` + dev-log fallback (the only multipart-SES path in the app — generalised here to an arbitrary attachment), `send_alert_email` (`alerts.py:459`); `s3_client()` (`app/core/aws_clients.py:114`); PIP-003 `change_status` for the status advance; PIP-002 `is_submitted` config flag; `record_crm_activity` (ACT-009, "Submitted" typed activity per gap §C); `audit_event`.

**Acceptance Criteria**
- `submit_to_client` with `resume_attachment=True` fetches the primary résumé from S3, sends a multipart email carrying it (assert dev-log contains the attachment marker + filename), advances status to the `is_submitted` key, and logs the submission on both timelines.
- `resume_attachment=False` sends a plain `send_alert_email` (no attachment) and still advances + logs.
- No primary résumé + `resume_attachment=True` → 400 `no_primary_resume` (no email, no status change).
- Foreign entry → 404; flag off → 503.
- Email-send failure is swallowed (logged, `EMAIL_FAILED` style) and does **not** roll back / 500 the request, matching ACT-003's best-effort contract; status advance only runs on send success.
- Emits `pipeline.submitted_to_client` audit + `record_crm_activity` ×2.
- `tests/test_pip_005_submit_to_client.py` (hermetic; `s3_client` patched to in-memory fake, the email fn patched/asserted, `change_status`+`record_crm_activity` spied): with-résumé, without-résumé, no-résumé-400, foreign-404, flag-off-503, send-failure-non-fatal, status-advanced-to-submitted.

**Dependencies:** PIP-001, PIP-002, PIP-003; CND-* (primary-résumé S3 linkage); ACT-003 (attachment-email path); ACT-009.

---

### PIP-006: Placement record on transition to Placed (start date, fee_cents)

**Type:** Feature
**Priority:** P1
**Estimate:** 2 days

**Description**
When a pipeline entry transitions to the configured `is_placed` status (`900_placed` by default), write a **placement record** capturing the recruiting outcome: start date and placement fee. This is the ATS revenue artifact OpenCATS calls a "placement".

*DDB model* — sub-row on the PIP-001 `ats_pipeline` table: `pk=USER#{owner_sub}`, `sk=PIPE#{job_order_id}#CAND#{candidate_id}#PLACEMENT`. Attributes: `placement_id` (`pl_{uuid4().hex}`), `job_order_id`, `candidate_id`, `owner_sub`, `start_date` (N, Unix-day or epoch seconds), `fee_cents` (int), `status_at_placement` (the `is_placed` key), `notes?`, `created_at` (N). One placement per pipeline entry (conditional-put `Attr("sk").not_exists()` → 409 `placement_exists` on re-placement; OPP-004 duplicate idiom).

*Pydantic* (`app/models.py`): `PlacementIn { start_date: int, fee_cents: int = Field(ge=0), notes?: str }`, `PlacementOut { placement_id, job_order_id, candidate_id, owner_sub, start_date, fee_cents, status_at_placement, notes, created_at }`.

*Service* `record_placement(owner_sub, job_order_id, candidate_id, data) -> PlacementOut`:
1. `get_pipeline_entry(...)` ownership gate.
2. `change_status(..., <is_placed status_key>)` (PIP-003) — advancing the entry to Placed (idempotent if already there).
3. Conditional `put_item` the placement sub-row (409 on duplicate).
4. `audit_event("pipeline.placed", owner_sub, None, placement_id=…, fee_cents=…, start_date=…)` + best-effort `record_crm_activity` (both entities, `activity_type="placement"`, `summary=f"Placed — fee {fee_cents/100:.2f}, starts {start_date}"`). `get_placement(owner_sub, job_order_id, candidate_id)` reads it back; `include_pipeline=true` job-order/candidate reads may surface placements in a follow-up (out of scope here).

*Hook:* `change_status` (PIP-003) does **not** auto-create a placement (placement requires the fee/start-date payload), but the FE Kanban drag onto the Placed column opens a placement dialog that calls this endpoint (PIP-009).

**Reuse / citations:** PIP-002 `is_placed` config flag; PIP-003 `change_status`; OPP-004 conditional-put duplicate guard; `_FloatSafeTable` (cents/Decimal); `audit_event`; `record_crm_activity` (ACT-009). Cents-as-int money convention (cross-cutting #4).

**Acceptance Criteria**
- `record_placement` advances status to `900_placed`, writes the `…#PLACEMENT` sub-row with `fee_cents`/`start_date`, returns `PlacementOut`.
- Second `record_placement` on the same entry → 409 `placement_exists` (status stays Placed).
- `fee_cents < 0` → 422; foreign entry → 404; flag off → 503.
- Emits `pipeline.placed` audit + `record_crm_activity` ×2.
- `tests/test_pip_006_placement.py`: place, duplicate-409, negative-fee-422, foreign-404, flag-off-503, status-advanced, audit/timeline.

**Dependencies:** PIP-001, PIP-002, PIP-003; ACT-009.

---

### PIP-007: Bulk add/remove candidates to/from a job-order pipeline

**Type:** Feature
**Priority:** P1
**Estimate:** 2 days

**Description**
Bulk operations so a recruiter can drop a multi-select of candidates onto a job order (or clear several at once) — the OpenCATS "add to this job order pipeline" multi-select.

*Pydantic* (`app/models.py`): `BulkPipelineAddIn { job_order_id, candidate_ids: List[str] (1–100), status?: str }`, `BulkPipelineRemoveIn { job_order_id, candidate_ids: List[str] (1–100) }`, `BulkPipelineResultOut { added: List[str], skipped: List[{candidate_id, reason}], removed: List[str] }`.

*Service*:
- `bulk_add_to_pipeline(owner_sub, data)` — validate `get_job_order` **once** (404 if foreign), then loop `candidate_ids` calling `add_to_pipeline` per candidate, collecting `added` vs `skipped` (reason: `not_found` for a foreign/absent candidate, `already_in_pipeline` for the 409). Partial success returns 200 with the breakdown — no all-or-nothing transaction (DynamoDB cross-item txns are avoided; each row is independent). One summary `audit_event("pipeline.bulk_added", owner_sub, None, job_order_id=…, added_count=…, skipped_count=…)`.
- `bulk_remove_from_pipeline(owner_sub, data)` — symmetric; `remove_from_pipeline` per id, 404s collected as skipped, summary audit `pipeline.bulk_removed`.

Loops are capped at 100 ids/call (model `max_length`). Each successful add/remove still emits its own per-row `audit_event` from `add_to_pipeline`/`remove_from_pipeline` **plus** the one summary event.

**Reuse / citations:** PIP-001 `add_to_pipeline`/`remove_from_pipeline` (called in the loop — no duplicated junction logic); ownership-by-key (one `get_job_order` upfront); `audit_event`.

**Acceptance Criteria**
- `bulk_add_to_pipeline` with 3 valid + 1 already-in-pipeline + 1 foreign candidate → `added=[3]`, `skipped=[{already_in_pipeline},{not_found}]`, HTTP 200.
- Foreign `job_order_id` → 404 (fails fast before the loop).
- `bulk_remove_from_pipeline` removes present entries, reports absent ones as skipped.
- `candidate_ids` empty → 422; >100 → 422.
- Emits the summary `pipeline.bulk_added`/`bulk_removed` audit.
- `tests/test_pip_007_bulk.py`: mixed-result add, foreign-job-404, bulk remove, cap/empty validation, flag-off-503.

**Dependencies:** PIP-001 (`add`/`remove`); JOB-*/CND-* (resolution, soft).

---

### PIP-008: Pipeline router (all PIP endpoints + admin status-config) + registration

**Type:** Feature
**Priority:** P0
**Estimate:** 2 days

**Description**
Expose every PIP service through `app/routers/ats_pipeline.py` (mounted at `/ui/ats/pipeline`) + an admin sub-router (`/ui/admin/ats`), registered in `app/main.py` inside an `if _S.ats_pipeline_enabled:` block (OPP-003 §4.3 registration pattern). Every handler depends on `require_ui_session` (`app/services/sessions.py:330`) and calls `_require_flag()`.

**Route table** — *literal segments declared before dynamic `/{…_id}` segments* (CLAUDE.md audit-export `/schedules`-before-`/{export_id}` ordering gotcha; e.g. `statuses` and `bulk` must precede any `/{pipeline_id}` route):

| Method | Path | Service | Auth |
|---|---|---|---|
| `GET` | `/ui/ats/pipeline/statuses` | `get_status_config` | session |
| `PUT` | `/ui/admin/ats/pipeline/statuses` | `set_status_config` | session **+ ADMIN/ROOT** |
| `POST` | `/ui/ats/pipeline/bulk-add` | `bulk_add_to_pipeline` | session |
| `POST` | `/ui/ats/pipeline/bulk-remove` | `bulk_remove_from_pipeline` | session |
| `GET` | `/ui/ats/pipeline/by-job/{job_order_id}` | `list_pipeline_for_job` | session |
| `GET` | `/ui/ats/pipeline/by-candidate/{candidate_id}` | `list_pipeline_for_candidate` | session |
| `POST` | `/ui/ats/pipeline/entries` | `add_to_pipeline` | session |
| `DELETE` | `/ui/ats/pipeline/by-job/{job_order_id}/candidate/{candidate_id}` | `remove_from_pipeline` | session |
| `PATCH` | `/ui/ats/pipeline/by-job/{job_order_id}/candidate/{candidate_id}/status` | `change_status` | session |
| `PUT` | `/ui/ats/pipeline/by-job/{job_order_id}/candidate/{candidate_id}/rating` | `set_rating` | session |
| `POST` | `/ui/ats/pipeline/by-job/{job_order_id}/candidate/{candidate_id}/submit` | `submit_to_client` | session |
| `POST` | `/ui/ats/pipeline/by-job/{job_order_id}/candidate/{candidate_id}/placement` | `record_placement` | session |
| `GET` | `/ui/ats/pipeline/feature-status` | returns `{"enabled": S.ats_pipeline_enabled}` (no `_require_flag`) | session |

The admin `PUT /ui/admin/ats/pipeline/statuses` checks `normalize_role(ctx.get("role")) not in {Role.ADMIN, Role.ROOT}` → 403 `admin_role_required` (OPP-003 §4.2). `feature-status` deliberately skips `_require_flag()` so the FE can hide/show the sidebar with the flag off (OPP-003 §5.8). Add `GET:/ui/ats/pipeline/feature-status` to any API-key route exemptions if needed (mirrors recsys §"API_KEY_ROUTE_EXEMPTIONS").

**Reuse / citations:** OPP-003 §4.2/§4.3 (admin sub-router, `normalize_role` gate, flag-gated `include_router` block, `feature-status` endpoint, route-order gotcha), OPP-004 §4 (sub-resource route shapes); `require_ui_session` (`sessions.py:330`); `normalize_role`/`Role` (`app/auth/roles.py:48`).

**Acceptance Criteria**
- All routes mounted only when `ats_pipeline_enabled`; with flag off, requests 503 (data routes) and `feature-status` returns `{"enabled": false}` (does not 503).
- `PUT /ui/admin/ats/pipeline/statuses` by a USER-role ctx → 403; by ADMIN/ROOT → 200.
- Literal routes (`statuses`, `bulk-*`, `by-job`, `by-candidate`, `feature-status`) are not shadowed by dynamic params (verified by hitting each).
- CSRF enforced on non-GET cookie requests (via `require_ui_session`).
- `tests/test_pip_008_router.py`: handlers called directly — status-config admin 403/200, add/list/remove, change-status, rating, feature-status flag-off, route-order sanity.

**Dependencies:** PIP-001…PIP-007.

---

### PIP-009: Frontend — pipeline Kanban + pipeline panels + submit/placement dialogs

**Type:** Feature
**Priority:** P1
**Estimate:** 4 days

**Description**
The recruiting Kanban + pipeline UI, modelled on the OPP-003 opportunity Kanban (and the existing `TicketKanbanBoard.tsx`/`BoardKanban.tsx` `@dnd-kit/core` boards, `frontend/package.json:17`).

- **Pipeline Kanban** at `/ats/pipeline?jobOrderId=…` (and embedded on the job-order detail page): columns fetched from `GET /ui/ats/pipeline/statuses` (**never hard-coded** — admin labels/order/colors respected; OPP-003 §2.7/§5.6), candidate cards grouped by `status`, sorted by `order` ascending. Card shows candidate name, 1–5 star rating control (PATCH→`set_rating`), and a "Submit"/"Place" affordance. Drag a card to another column → optimistic move in React-Query state, `PATCH …/status`; on non-2xx (`invalid_status` etc.) roll back via `onError` + invalidate `["ats-pipeline", jobOrderId]` + `sonner` toast (OPP-003 §5.5). An "Unknown" overflow column catches entries whose `status` isn't in the live config (OPP-003 Q3).
- **Submit-to-client dialog**: recipient emails + subject/message + "attach résumé" toggle → `POST …/submit`; success toast + auto-refetch (card jumps to the `400_submitted` column).
- **Placement dialog**: opened when a card is dragged onto the Placed column (or via "Place") → start-date + fee inputs → `POST …/placement`; fee formatted as `$${(cents/100).toFixed(2)}` (the `EarningsSummaryCard.tsx:10` convention).
- **Bulk add**: a candidate multi-select → "Add to job order pipeline" → `POST …/bulk-add`, showing the added/skipped breakdown.
- **Admin status-config editor** (admin-only page): reorder/relabel/recolor statuses, set `is_submitted`/`is_placed`/`is_terminal`, `PUT /ui/admin/ats/pipeline/statuses`.
- **Flag gating**: `isAtsPipelineEnabled()` in `frontend/src/lib/featureFlags.ts` (`toBool(env.VITE_ATS_PIPELINE_ENABLED,false)`); sidebar "Recruiting"/"Pipeline" entry + routes in `App.tsx` rendered only when enabled (and/or `GET /ui/ats/pipeline/feature-status`). API wrappers in `frontend/src/api/endpoints/atsPipeline.ts`; TS types in `frontend/src/api/types.ts` mirroring the PIP Pydantic models.

**Reuse / citations:** OPP-003 §2.7/§5.5/§5.6/§6.3 (Kanban-from-API, dnd-kit, optimistic+rollback+toast, FE flag/sidebar gating), `TicketKanbanBoard.tsx`/`BoardKanban.tsx` (`@dnd-kit/core` `^6.3.1`, `frontend/package.json:17`), `EarningsSummaryCard.tsx:10` (cents formatting), `frontend/src/api/client.ts` (CSRF header auto-attach).

**Acceptance Criteria**
- Kanban renders columns from the statuses API (not hard-coded); dragging a card emits `PATCH …/status` and re-renders in the target column; failed transitions roll back + toast.
- Star-rating control persists via the rating endpoint.
- Submit dialog posts to `…/submit` and the card moves to Submitted; placement dialog posts start-date+fee to `…/placement` and the card moves to Placed.
- Bulk-add shows added/skipped counts.
- Admin status editor saves the config; non-admins don't see the editor.
- With `VITE_ATS_PIPELINE_ENABLED=false`, no sidebar entry and routes are absent.

**Dependencies:** PIP-008 (all endpoints).

---

### PIP-010: Tests — hermetic pytest suite + E2E spec

**Type:** Testing
**Priority:** P1
**Estimate:** 2 days

**Description**
Consolidate/complete the test coverage for the PIP set. (Per-ticket unit tests are authored alongside each backend ticket; this ticket guarantees the cross-cutting suite + the end-to-end spec exist and pass green.)

- **Hermetic pytest** (`tests/test_pip_*.py`, one per PIP-001…008): moto in-memory `ats_pipeline` table bound to the frozen `T.ats_pipeline` via `object.__setattr__` (restored on teardown), `S.ats_pipeline_enabled`/config flags toggled via `object.__setattr__`, route handlers called **directly** (no `TestClient`). External collaborators patched at the source module: `audit_event`, `record_crm_activity`, the email send fn, `s3_client` (in-memory fake), and JOB-*/CND-* resolvers (`get_job_order`/`get_candidate`) stubbed so the suite stays offline (no real AWS/SES/S3/network). Each test creates its own table to avoid cross-test contamination (OPP-003 §9.1 / OPP-004 §9 fixtures).
- **E2E** `frontend/e2e/ats-pipeline.spec.ts` (new section block continuing the repo numbering; `SECOPS`-style flag `ATS_PIPELINE_ENABLED=1` + `VITE_ATS_PIPELINE_ENABLED=1` in `.env.local`):
  - **Status-config API** (`GET /ui/ats/pipeline/statuses` default 9 stages; `PUT /ui/admin/ats/pipeline/statuses` as root replaces; as alice → 403; invalid config → 400).
  - **Pipeline API** (add candidate to job order; duplicate → 409; list by-job/by-candidate; `PATCH …/status`; `PUT …/rating`; foreign → 404; bulk-add mixed result).
  - **Submit** (`POST …/submit` advances to Submitted; assert dev-email-log entry + status moved).
  - **Placement** (`POST …/placement` advances to Placed; duplicate → 409).
  - **Kanban UI** (columns from API; drag card across columns emits `PATCH …/status`; rollback toast on a blocked move; submit/placement dialogs; bulk-add).
  - **Flag-off** (sidebar entry absent; `/ui/ats/pipeline/*` data routes → 503; `feature-status` → `{enabled:false}`).
  - Auth via `injectAuth(page,"alice"|"root")` + `x-csrf-token: sessions[id].csrf_token` on non-GET (repo E2E conventions).

**Reuse / citations:** OPP-003 §9 / OPP-004 §9 (hermetic moto + frozen-`T` `object.__setattr__`, direct-handler-call, E2E section pattern); CLAUDE.md test-isolation + `TestClient`-broken + numeric-GSI gotchas.

**Acceptance Criteria**
- `just test` runs all `tests/test_pip_*.py` green, fully offline (no AWS/SES/S3/network).
- `ats-pipeline.spec.ts` passes under `just e2e` with the flag on; the flag-off section passes with it off.
- Coverage spans every service function (add/list/remove, status-change incl. invalid+no-op, rating incl. bounds, submit incl. with/without résumé + send-failure-non-fatal, placement incl. duplicate, bulk mixed-result, status-config admin 403 + validation) and the FE Kanban drag/submit/placement/bulk flows.

**Dependencies:** PIP-001…PIP-009.

---

## Dependency graph (build order)

```
JOB-* (job orders) ─┐
CND-* (candidates) ─┤
ACT-009 (timeline) ─┤  (soft, lazy-import)
ACT-003 (attach email)┘ (PIP-005 only)
        │
        ▼
PIP-001 (junction + table + flag)
        ▼
PIP-002 (ranked status config)
        ▼
PIP-003 (status change + logging)
   ├─► PIP-004 (rating)
   ├─► PIP-005 (submit-to-client)        [+ACT-003, CND résumé]
   ├─► PIP-006 (placement)
   └─► PIP-007 (bulk add/remove)         [needs PIP-001]
        ▼
PIP-008 (router + registration)          [needs PIP-001…007]
        ▼
PIP-009 (frontend Kanban/dialogs)        [needs PIP-008]
        ▼
PIP-010 (tests: pytest + E2E)            [needs PIP-001…009]
```
