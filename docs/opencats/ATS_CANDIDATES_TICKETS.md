# ATS — Candidate Entity Tickets (CND)

**Prefix:** `CND` · **Source gap analysis:** `docs/opencats/OPENCATS_GAP_ANALYSIS.md` §A (Candidates + Résumé / Skills)
**Cluster:** Tier-1 "Candidate" entity from the gap analysis Recommended-Tickets list (line 102).

---

## Headline

OpenCATS' Candidate is, structurally, a **Lead/PERSON with recruiting-specific fields**. The gap
analysis (§A, line 45) is explicit: the existing Lead entity (`LED-002`/`LED-003`) already owns
`first_name`/`last_name`/`email`/`phone`/`company`/`title`/`lead_source`/`assigned_to`/`status`,
and the LED family already specs the **reusable** cross-cutting behaviour — dedupe/merge
(`LED-009`), owner/recruiter assignment (`LED-010`), source attribution (`LED-004`), and the
per-entity activity log (`LED-012`). **CND does NOT re-implement any of those.** It adds only the
ATS-specific delta: current/desired pay, free-text key-skills, date-available, can-relocate,
LinkedIn/web URLs, a candidate-pipeline status, and a postal address — plus résumé/CV attachment
linkage (multiple attachments + a "primary résumé" flag) reusing the **KB-003 S3-attach-on-entity
pattern** and the file manager, and candidate change-history reusing the **LED-012 / ACT-009**
per-entity timeline.

This file delivers the Candidate **entity, CRUD service, résumé attachments, router, frontend, and
tests** as ~7 dependency-ordered tickets. Pipeline (candidate↔job-order junction), skill-tag
registry, résumé text-extraction, public apply, and CSV import are **out of scope** here (they are
separate Tier-1/Tier-2/Tier-3 clusters in the gap analysis).

---

## Cross-cutting constraints (apply to every CND ticket)

1. **Additive + flag-gated, default OFF.** A new master flag `S.candidates_enabled`
   (`CANDIDATES_ENABLED`, default `"0"` → `False`) gates the entire feature, following the
   `cart_reminders_enabled` pattern at `app/core/settings.py:821`. With the flag off every new
   route returns 404 / every service function raises `HTTPException(503, "Candidates module is not
   enabled")`, and no existing file behaves differently. No existing table, router, service, or
   model is modified destructively — every change is an additive new file or an append.

2. **Reuse LED, do NOT fork it.** The Candidate is built as a *specialized record that reuses the
   Lead service primitives and patterns*, not a copy-paste of `app/services/leads.py`. Dedupe/merge
   (`LED-009`), owner assignment (`LED-010`), source attribution (`LED-004`), and the activity
   timeline (`LED-012`) are **dependencies**, not re-implementations. Where CND needs a Lead-family
   capability it calls the LED service or, when LED has not yet shipped, mirrors the LED *pattern*
   in a clearly-labelled shim that LED can later absorb (cited per ticket).

3. **SECOPS-007 dev/prod parity.** No `S.dev_mode` branch except the single `_make_download_url`
   helper for résumé presigned URLs (dev → `/mock/s3/...`, prod → `generate_presigned_url(...,
   ExpiresIn=300)`), copied verbatim from the KB-003 / `app/services/kyc_partner_api.py:630-641`
   pattern. All DDB goes through `T.*` handles (moto in dev, real DDB in prod); all S3 goes through
   `app.core.aws_clients.s3_client()` (`app/core/aws_clients.py:114`), which moto intercepts
   in-process in dev. No mock path, no inline data.

4. **Standard primitives only.** Email/phone normalization via `app/core/normalize.py`
   (`normalize_email`:60, `normalize_phone`:66 — both raise HTTP 400, applied at the **service**
   layer, never in a Pydantic validator); timestamps via `now_ts()` (`app/core/time.py:2`);
   pagination via `encode_cursor`/`decode_cursor` (`app/core/cursor.py:94,103`); audit via
   `audit_event(event, user_sub, request=None, **fields)` (`app/services/alerts.py:644`, DDB-only,
   parity-safe); auth via `require_ui_session` (`app/services/sessions.py:330`) and the
   `_is_admin(user)` role guard mirror from `app/routers/tickets.py:207-208`
   (`normalize_role(user.role) in {Role.ADMIN, Role.ROOT}`, `app/auth/roles.py:8,48`).

5. **DynamoDB numeric GSI sort keys** must declare `attr_types={"field": "N"}` in the `TableDef`
   (CLAUDE.md gotcha; `scripts/local-ddb-init.py` `TableDef` at line 29, `attr_types` at line 35).

6. **Single-table sub-items.** Résumé/attachment metadata and (optional) skill rows live on the
   candidate's OWN table under distinct SK prefixes (`ATTACHMENT#...`), mirroring KB-003's
   `ATTACHMENT#` sub-item on `crm_kb_articles` and the `crm_cases_links` single-table pattern — no
   separate attachments table.

7. **Tests are hermetic.** pytest uses moto in-memory DynamoDB with the exact frozen `T.*` handle
   patched via `object.__setattr__` and frozen `S` flags toggled the same way (pattern:
   `tests/test_gap_0220_0221_ssh_stored_key.py`); S3 is an in-memory `_FakeS3` patched onto
   `app.core.aws_clients` (pattern: `tests/test_gap_0286_0287_kyc_partner_api.py`). No real AWS, no
   network, no `TestClient` for service-layer tests (route handlers called directly on a fresh
   `asyncio.new_event_loop()` per CLAUDE.md).

---

## Ticket index (dependency order)

| Ticket | Title | Depends on |
|--------|-------|-----------|
| CND-001 | Candidate DDB table, flag, settings + Pydantic models | (root) |
| CND-002 | Candidate CRUD service (extends/reuses Lead patterns) | CND-001 |
| CND-003 | Résumé/CV attachment linkage + "primary résumé" flag (KB-003 S3 pattern) | CND-001, CND-002 |
| CND-004 | Candidate change-history feed (reuse LED-012 / ACT-009 timeline) | CND-002 |
| CND-005 | Candidate router (CRUD + résumé + history endpoints) | CND-002, CND-003, CND-004 |
| CND-006 | Frontend — Candidates list page + detail page (with résumé section) | CND-005 |
| CND-007 | Hermetic pytest + Playwright E2E | CND-002..CND-006 |

---

### CND-001: Candidate DDB table, flag, settings + Pydantic models

**Type:** Feature · **Priority:** P0 · **Estimate:** 1.5 days

**Description**

Scaffolds the Candidate entity: feature flag, settings, the `candidates` DynamoDB table with GSIs,
the `T.candidates` handle, and all Pydantic wire models. This is the root ticket; nothing else in
the cluster compiles without it. It is the CND analogue of LED-001 + LED-002 combined (the LED
family split these into two tickets; CND merges them because the Candidate model surface is smaller
and reuses the Lead field set).

**Settings / flag** (`app/core/settings.py`, append next to `cart_reminders_enabled` at line 821):

- `candidates_enabled: bool` — `CANDIDATES_ENABLED`, default `"0"` → `False`.
- `candidates_table_name: str` — `DDB_CANDIDATES_TABLE`, default `"candidates"`.
- `candidate_resume_bucket: str` — `CANDIDATE_RESUME_BUCKET`, default `"local-uploads"`.
- `candidate_resume_s3_prefix: str` — `CANDIDATE_RESUME_S3_PREFIX`, default `"candidate-resumes/"`.
- `candidate_resume_max_bytes: int` — `CANDIDATE_RESUME_MAX_BYTES`, default `20971520` (20 MB),
  using the `int(os.environ.get(...))` pattern at `settings.py:1870` (`voice_message_max_size_bytes`).
- `candidate_resume_max_per_candidate: int` — default `25`.

**Table handle** (`app/core/tables.py`): wire `candidates=_safe_table(S.candidates_table_name)`
into the `Tables` dataclass, mirroring `contacts=_safe_table(S.contacts_table_name)`
(`tables.py:354`) and `tickets=_safe_table(S.tickets_table_name)` (`tables.py:392`).

**DDB model** — `candidates` table, `PK=pk` (S) / `SK=sk` (S), single-table:

Candidate META row (written by CND-002, attachment sub-items by CND-003):

| Attribute | Type | Notes |
|---|---|---|
| `pk` | S | `"CANDIDATE#{candidate_id}"` |
| `sk` | S | `"META"` |
| `candidate_id` | S | `"cand_" + uuid4().hex[:20]` |
| `first_name` / `last_name` | S | reused from Lead field set (LED-002) |
| `email` | S | normalized via `normalize_email` (service layer) |
| `email_raw` | S | original pre-normalization (display fidelity, mirrors LED-003 §5.3) |
| `phone` | S\|null | normalized via `normalize_phone` |
| `company` / `title` | S\|null | current employer / current title (reused Lead fields) |
| `source` | S | candidate source, default `"other"` — **reuses LED-004 source attribution**; do not re-validate against a campaigns table |
| `owner_sub` | S | recruiter — **reuses LED-010 owner assignment**; default = `creator_sub` |
| `status` | S | candidate-pipeline status (closed set §below), default `"active"` |
| **`current_pay`** | S\|null | ATS delta — free-text (e.g. `"$95k"`); free-text per OpenCATS |
| **`desired_pay`** | S\|null | ATS delta |
| **`key_skills`** | S\|null | ATS delta — free-text skills blob (OpenCATS dropped parsing → free-text tags); max 4000 chars |
| **`date_available`** | S\|null | ATS delta — ISO date string `"YYYY-MM-DD"` |
| **`can_relocate`** | BOOL | ATS delta, default `False` |
| **`linkedin_url`** / **`web_url`** | S\|null | ATS delta — URL strings (max 500) |
| **`address` / `city` / `state` / `postal_code` / `country`** | S\|null | ATS delta — postal address |
| `primary_resume_id` | S\|null | attachment_id of the primary résumé (set by CND-003) |
| `created_by` | S | creator_sub |
| `created_at` / `updated_at` | N | `now_ts()` |
| `deleted_at` | N\|null | soft-delete marker |
| `GSI1PK` / `GSI1SK` | S / N | `"OWNER#{owner_sub}"` / `created_at` — **ByOwner** (mirrors LED ByOwner) |
| `GSI2PK` / `GSI2SK` | S / N | `"STATUS#{status}"` / `created_at` — **ByStatus** |
| `GSI3PK` / `GSI3SK` | S / N | `"SOURCE#{source}"` / `created_at` — **BySource** |

Three GSIs (`ByOwner`/`ByStatus`/`BySource`), `ProjectionType: ALL`, declared in
`scripts/local-ddb-init.py` via a `TableDef` (line 29) with
`attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N", "created_at": "N"}` (numeric-GSI gotcha).
The GSI layout is intentionally **identical to the Lead `leads` table** (LED-003 §3.2) so the
CND-002 service can reuse the LED routing logic verbatim.

**Candidate-pipeline status closed set** (ATS-specific; distinct from the Lead state machine):

```python
CANDIDATE_STATUSES = {"active", "qualified", "submitted", "interviewing",
                      "placed", "on_hold", "not_in_search", "archived"}
```

Transitions are permissive (recruiters move candidates freely); only `archived` is treated as a
soft-terminal display state. The full ranked **pipeline** workflow (100 No-Contact → 900 Placed)
belongs to the separate Pipeline cluster (gap analysis §C) and is NOT modelled here — this status
is the candidate's own lifecycle flag, not a job-order pipeline rank.

**Pydantic models** (append to `app/models.py` end-of-file with a `# ── ATS Candidates (CND-001) ──`
section comment, per the LED-002 §2.1 insertion convention): `CANDIDATE_STATUSES`,
`CANDIDATE_SOURCES` (sentinel sets for `pattern=` validation), `CandidateCreateIn`,
`CandidateUpdateIn` (all-optional partial), `CandidateOut` (all stored fields + `candidate_id` +
`resumes: list[CandidateResumeOut]` populated by the router from CND-003). Use the existing
`pydantic` imports (`models.py:11-19`); normalization stays at the service layer (LED-002 §2.3).

**Reuse citations:** LED-001 (flag/table/GSI pattern), LED-002 (model insertion + field set),
LED-004 (`source` field), LED-010 (`owner_sub` field), `cart_reminders_enabled`
(`settings.py:821`), `voice_message_max_size_bytes` int-env (`settings.py:1870`),
`contacts`/`tickets` table wiring (`tables.py:354,392`).

**Acceptance Criteria**
- `S.candidates_enabled` defaults `False`; all six settings present and env-overridable.
- `T.candidates` resolves; `just restart` creates the `candidates` table with three GSIs and the
  numeric `attr_types` declaration.
- `CandidateCreateIn`/`CandidateUpdateIn`/`CandidateOut` import cleanly with the flag off
  (no `ImportError`); ATS-delta fields all present; `status` validates against `CANDIDATE_STATUSES`.
- No existing model, table, or setting is altered; `grep` confirms `Candidate*` / `CANDIDATE_STAT`
  were absent before this ticket.

**Dependencies:** none (root). Pattern-source tickets: LED-001, LED-002, LED-004, LED-010.

---

### CND-002: Candidate CRUD service (extends/reuses Lead patterns)

**Type:** Feature · **Priority:** P0 · **Estimate:** 2 days

**Description**

Creates `app/services/candidates.py` — the DDB data-access + business-logic layer for the
`candidates` table. It is the CND analogue of LED-003, deliberately mirroring LED-003's structure
(same GSI-routing, same soft-delete + `deleted_at` filter, same cursor pagination, same audit
emission) so the two services stay convergent and a future refactor can hoist shared helpers. CND
adds the ATS-delta field handling and the candidate-status set; it does **not** re-implement
dedupe/merge, owner round-robin, or source analytics — those are LED-009 / LED-010 / LED-004 and
are consumed, not copied.

**Public functions** (all sync; called from async routes via `asyncio.to_thread`, per
`app/routers/google_drive_integration.py`):

- `create_candidate(creator_sub, data: CandidateCreateIn) -> dict` — guard on flag (503 if off);
  `normalize_email`/`normalize_phone` at the service layer (store `email_raw`); generate
  `candidate_id = "cand_" + uuid4().hex[:20]`; default `owner_sub=creator_sub` (LED-010 reuse),
  `source=data.source or "other"` (LED-004 reuse), `status="active"`; write META + all three GSI
  pairs; `audit_event("candidate.created", creator_sub, candidate_id=..., email=...)`.
  **Duplicate detection is delegated:** call `leads.find_lead_by_email`-style dedupe is NOT
  reimplemented — instead expose an internal `find_candidate_by_email(email)` (mirroring LED-003
  §4.6 `find_lead_by_email`, querying `ByStatus` GSI + `FilterExpression`) so that **LED-009's
  merge engine can operate on candidates once it ships**; `create_candidate` performs the same
  cheap idempotent same-email-active short-circuit LED-003 uses, then defers true fuzzy
  dedupe/merge to LED-009.
- `get_candidate(candidate_id) -> Optional[dict]`.
- `list_candidates(*, owner_sub, status=None, source=None, created_after=None, cursor=None,
  limit=50) -> {"candidates": [...], "cursor": ...}` — GSI routing identical to LED-003 §4.3
  (`ByStatus` → `BySource` → `ByOwner`), `deleted_at` filter, `encode_cursor`/`decode_cursor`,
  `limit` clamped `[1,200]`.
- `update_candidate(candidate_id, actor_sub, data: CandidateUpdateIn) -> dict` — 404 if missing,
  410 if soft-deleted; normalize updated email/phone; rewrite `GSI2PK`/`GSI3PK` via full
  `put_item` overwrite when `status`/`source` change (LED-003 §5.5 technique); update ATS-delta
  fields; `audit_event("candidate.updated", ...)`. **On any field change, emit a change-history
  row** by calling CND-004's `record_candidate_change` (best-effort `try/except`, fire-and-forget).
- `delete_candidate(candidate_id, actor_sub) -> None` — idempotent soft-delete (`deleted_at`,
  `status="archived"`), `audit_event("candidate.deleted", ...)`.
- `set_owner(candidate_id, owner_sub, actor_sub)` — thin wrapper that **delegates to LED-010's
  assignment primitive when `leads_assignment_enabled` and the LED assignment service is present**;
  otherwise writes `owner_sub` + `GSI1PK` directly (a labelled shim LED-010 can absorb). This is
  the only "owner" logic CND owns; round-robin queues stay entirely in LED-010.

**Reuse citations:** LED-003 (whole service shape: GSI routing, soft-delete, cursor pagination,
audit, status-rewrite-via-put), LED-003 §4.6 (`find_lead_by_email` → `find_candidate_by_email`),
LED-009 (dedupe/merge — depended on, not built), LED-010 (owner/round-robin — delegated),
LED-004 (`source` — stored, not analyzed here), `normalize_email`/`normalize_phone`
(`normalize.py:60,66`), `now_ts` (`time.py:2`), `encode_cursor`/`decode_cursor`
(`cursor.py:94,103`), `audit_event` (`alerts.py:644`), `asyncio.to_thread` router pattern
(`google_drive_integration.py`).

**Acceptance Criteria**
- All six functions raise 503 with the flag off; full CRUD round-trips with the flag on.
- `create_candidate` normalizes email (lowercased, `email_raw` preserved) and phone (E.164);
  emits `candidate.created`.
- `list_candidates` routes to the correct GSI per filter, excludes `deleted_at` rows, paginates.
- `update_candidate` rejects 404/410 correctly, rewrites status/source GSI keys, fires a
  change-history row.
- `set_owner` delegates to LED-010 when available and falls back to the shim otherwise; no
  round-robin queue logic is duplicated in `candidates.py`.
- Zero `S.dev_mode` references in `candidates.py`.

**Dependencies:** CND-001. Reuses LED-003/004/009/010 (patterns/delegation), CND-004 (`record_candidate_change`, soft dep — wrapped in `try/except`).

---

### CND-003: Résumé/CV attachment linkage + "primary résumé" flag

**Type:** Feature · **Priority:** P1 · **Estimate:** 2 days

**Description**

Adds résumé/CV upload, listing, download, delete, and a **"primary résumé"** flag to a candidate —
directly reusing the **KB-003 S3-attach-on-entity pattern**: attachment metadata is stored as
`ATTACHMENT#{attachment_id}` sub-items on the candidate's OWN `candidates` table (no new table,
mirroring KB-003's `ATTACHMENT#` rows on `crm_kb_articles` and the `crm_cases_links` single-table
pattern), and bytes go to S3 under a deterministic key. Multiple résumés per candidate are
supported; exactly one may be flagged primary. This is the "résumé/CV upload + multiple attachments
+ primary resume" PARTIAL gap (analysis §A, line 46).

**File-manager reuse note:** rather than duplicate the S3 upload/presign plumbing, this ticket
follows KB-003's already-proven attach-on-entity service helpers (`add_attachment`,
`list_attachments`, `get_attachment`, `delete_attachment`) and the file-manager S3 conventions
(`app/services/filemanager.py` `put_object`/`s3_key` usage). A recruiter may alternatively attach a
résumé already in their file manager; that path reuses the file manager's existing
`share_node`/node resolution and records only a pointer sub-item (`source="file_manager"`,
`node_path` stored instead of an owned `s3_key`) — no byte copy. The default path is a direct
multipart upload to the candidate résumé prefix.

**DDB sub-item** (`candidates` table, same PK as candidate META):

```
pk: "CANDIDATE#{candidate_id}"      sk: "ATTACHMENT#{attachment_id}"
attachment_id: "att_" + uuid4().hex
candidate_id, filename (sanitized, ≤255), content_type, size_bytes,
s3_key (or node_path for file_manager source), source ("upload"|"file_manager"),
is_primary: bool, uploaded_by, created_at: int, deleted_at: int|absent
```

`re.sub(r"[^A-Za-z0-9._-]", "_", filename)[:255]` sanitization
(`kyc_partner_api.py:489` / KB-003 §5.1). S3 key:
`f"{S.candidate_resume_s3_prefix}{candidate_id}/{attachment_id}/{safe_name}"`.

**Service additions** (`app/services/candidates.py`, mirroring KB-003 §4.1):

- `add_resume(candidate_id, *, uploaded_by, filename, content_type, size_bytes, s3_key,
  source="upload", make_primary=False) -> dict` — verify candidate META exists (404 else); enforce
  `S.candidate_resume_max_per_candidate` active-count cap (400 `candidate_resume_limit_reached`);
  write sub-item; if `make_primary` (or it is the candidate's first résumé) call
  `set_primary_resume`; `audit_event("candidate.resume.uploaded", ...)`.
- `list_resumes(candidate_id) -> list[dict]` — query `SK begins_with "ATTACHMENT#"`, drop
  `deleted_at` rows, sort by `created_at`; primary first.
- `get_resume(candidate_id, attachment_id) -> dict` — 404 if missing/soft-deleted.
- `set_primary_resume(candidate_id, attachment_id, actor_sub)` — clear `is_primary` on all other
  attachment rows, set it on the target, back-write `primary_resume_id` onto the candidate META.
  Exactly-one-primary invariant enforced here.
- `delete_resume(candidate_id, attachment_id, actor_sub)` — soft-delete (`deleted_at`); if it was
  primary, promote the next-newest active résumé to primary (or clear `primary_resume_id`); S3
  object is NOT deleted (lifecycle policy handles it, KB-003 §5.3);
  `audit_event("candidate.resume.deleted", ...)`.
- `_make_download_url(s3_key) -> str` — the single dev/prod branch (dev `/mock/s3/...`, prod
  `generate_presigned_url(..., ExpiresIn=300)`), copied from KB-003 §4.4 /
  `kyc_partner_api.py:630-641`.

**Model:** `CandidateResumeOut` (append `app/models.py`, mirroring `KbAttachmentOut`):
`attachment_id, candidate_id, filename, content_type, size_bytes, url, source, is_primary,
created_at, uploaded_by`. `CandidateOut.resumes: list[CandidateResumeOut]` populated by the router.

**Reuse citations:** KB-003 (entire attach-on-entity service + S3 key + presign + sub-item shape +
count-cap + soft-delete-no-S3-delete), `s3_client()` (`aws_clients.py:114`), file-manager
`put_object`/`s3_key`/`share_node` (`app/services/filemanager.py`), filename sanitize
(`kyc_partner_api.py:489`), `audit_event` (`alerts.py:644`), `crm_cases_links` single-table SK
prefix.

**Acceptance Criteria**
- Multiple résumés attach to one candidate; each gets a distinct `attachment_id` + S3 key.
- Exactly one résumé is primary at any time; first upload auto-promotes to primary; deleting the
  primary promotes the next-newest (or clears `primary_resume_id`).
- `candidate_resume_max_per_candidate` cap enforced (400); soft-deleted résumés free a slot and are
  excluded from `list_resumes`.
- `_make_download_url` returns `/mock/s3/...` in dev and a 300s presigned URL in prod; it is the
  only `S.dev_mode` branch added.
- File-manager-sourced résumé records a pointer (`source="file_manager"`, `node_path`) with no byte
  copy.
- Deleting a résumé never deletes the S3 object.

**Dependencies:** CND-001, CND-002. Reuses KB-003 (S3 attach pattern), file manager.

---

### CND-004: Candidate change-history feed (reuse LED-012 / ACT-009 timeline)

**Type:** Feature · **Priority:** P1 · **Estimate:** 1 day

**Description**

Adds a per-candidate **change-history / activity feed** so recruiters see a chronological audit of
edits, status moves, owner changes, and résumé uploads. This is **not** a new timeline engine — it
**reuses the LED-012 per-entity activity-log pattern** (and, when the broader CRM timeline ships,
the **ACT-009** `record_crm_activity` write primitive with `entity_type="candidate"`). CND owns
only the thin candidate-side adapter; the storage + read model are LED-012's / ACT-009's.

**Design:**

- `record_candidate_change(candidate_id, actor_sub, *, change_type, summary, metadata=None)` — a
  fire-and-forget adapter. It prefers **ACT-009** `crm_activity_timeline.record_crm_activity(
  entity_type="candidate", entity_id=candidate_id, activity_type=change_type, ...)` via a lazy
  local import inside `try/except` (exactly the ACT-007 §2.4 caller pattern). If ACT-009 has not
  shipped, it falls back to the **LED-012** activity-row pattern: write an `ACTIVITY#{inverted_ts}#
  {activity_id}` sub-item on the candidate's own `candidates` table (single-table, same PK as META)
  — the same `ACTIVITY#{ts}#{id}` key shape LED-012 uses on the `leads` table. Never raises.
- `list_candidate_history(candidate_id, *, cursor=None, limit=50) -> {"events": [...], "cursor":
  ...}` — if ACT-009 is present, delegate to `list_entity_activities("candidate", candidate_id,
  ...)`; else query the local `ACTIVITY#` sub-items newest-first (inverted-ts SK, so no
  `ScanIndexForward`) with `encode_cursor`/`decode_cursor`.
- `change_type` values: `created`, `updated`, `status_changed`, `owner_changed`, `resume_added`,
  `resume_removed`, `deleted`. CND-002/CND-003 call `record_candidate_change` at the relevant
  points (already wired as best-effort in those tickets).

**Model:** reuse `CrmActivityOut` (ACT-009) when delegating; otherwise a local `CandidateHistoryOut`
(`event_id, candidate_id, change_type, summary, actor_sub, metadata, created_at`) is returned by the
fallback path.

**Reuse citations:** LED-012 (`ACTIVITY#{ts}#{id}` single-table per-entity activity rows — the
fallback storage), ACT-009 (`record_crm_activity` / `list_entity_activities` / `CrmActivityOut` —
the preferred path; `entity_type="candidate"` extends ACT-009's entity set), ACT-007 §2.4
(lazy-import fire-and-forget caller pattern), `call_history.py:31` inverted-ts `_make_sk` pattern,
`encode_cursor`/`decode_cursor` (`cursor.py`), `audit_event` (`alerts.py:644`).

**Acceptance Criteria**
- `record_candidate_change` never raises (best-effort); writes via ACT-009 when present, else the
  LED-012-style local `ACTIVITY#` row.
- `list_candidate_history` returns newest-first events, paginated; delegates to ACT-009 when
  available.
- CND-002 edits and CND-003 résumé add/remove produce history events of the correct `change_type`.
- No new timeline table is created; the feature is purely a candidate-side adapter over
  LED-012 / ACT-009.

**Dependencies:** CND-002 (caller). Reuses LED-012, ACT-009/ACT-007. (Both LED-012 and ACT-009 are
soft deps via lazy import; the fallback keeps CND self-contained if neither has shipped.)

---

### CND-005: Candidate router (CRUD + résumé + history endpoints)

**Type:** Feature · **Priority:** P0 · **Estimate:** 1.5 days

**Description**

Creates `app/routers/candidates.py`, registered in `app/main.py` with prefix `/ui` (mirroring
`tickets_router`). Every handler gates on `if not S.candidates_enabled: raise HTTPException(404)`
first. Auth via `Depends(require_ui_session)` (`sessions.py:330`); owner/admin enforcement at the
router layer (service stays authz-agnostic, LED-003 §7.4); admin guard via the `_is_admin` mirror
(`tickets.py:207`). Service calls run through `asyncio.to_thread`.

**Endpoints** (literal segments declared BEFORE `/{candidate_id}` so `resumes`/`history` aren't
captured as IDs — KB-003 §4.3 / GAP-0210 ordering gotcha):

```
POST   /ui/candidates                                   create (CandidateOut)
GET    /ui/candidates                                   list (owner/status/source/cursor filters)
GET    /ui/candidates/{candidate_id}                    detail (+ resumes[] populated)
PATCH  /ui/candidates/{candidate_id}                    update
DELETE /ui/candidates/{candidate_id}                    soft-delete (owner/admin)
PUT    /ui/candidates/{candidate_id}/owner              set owner (delegates LED-010)
POST   /ui/candidates/{candidate_id}/resumes            multipart upload (CandidateResumeOut)
GET    /ui/candidates/{candidate_id}/resumes            list résumés (presigned/mock urls)
GET    /ui/candidates/{candidate_id}/resumes/{att_id}   single résumé download url
PUT    /ui/candidates/{candidate_id}/resumes/{att_id}/primary   mark primary
DELETE /ui/candidates/{candidate_id}/resumes/{att_id}   soft-delete résumé
GET    /ui/candidates/{candidate_id}/history            change-history feed (CND-004)
```

Résumé upload handler mirrors KB-003 §4.3: `await file.read()`, 413 if over
`S.candidate_resume_max_bytes`, content-type allowlist (`_validate_content_type` — PDF/DOC/DOCX/RTF/
TXT/ODT for résumés), `s3_client().put_object(...)`, then `add_resume(...)`. `CandidateOut` detail
populates `resumes` from `list_resumes` with `url` from `_make_download_url`.

**Reuse citations:** KB-003 §4.3-4.5 (multipart upload handler + presign + router registration +
route-ordering), `require_ui_session` (`sessions.py:330`), `_is_admin` (`tickets.py:207`),
`get_authenticated_user` (`deps.py:199`), `asyncio.to_thread` (`google_drive_integration.py`),
LED-010 owner delegation (PUT /owner), CND-002/003/004 services.

**Acceptance Criteria**
- All routes 404 with the flag off (no service call, no auth check executed).
- CRUD + résumé + history flows work end-to-end against moto in dev; literal-segment routes are not
  shadowed by `/{candidate_id}`.
- Upload enforces 413 size cap + content-type allowlist; detail returns `resumes[]` with working
  dev `/mock/s3/...` urls.
- Owner endpoint delegates to LED-010 when enabled; non-owner/non-admin gets 403 on delete.

**Dependencies:** CND-002, CND-003, CND-004.

---

### CND-006: Frontend — Candidates list + detail page (with résumé section)

**Type:** Feature · **Priority:** P1 · **Estimate:** 2.5 days

**Description**

Adds the Candidates UI under `frontend/src/pages/candidates/`, following the platform's
list-page + detail-page conventions (React Query + shadcn/ui + React Hook Form + Zod, per
CLAUDE.md frontend conventions). Hidden behind the same flag (the route renders a "module disabled"
state / 404 if `S.candidates_enabled` is off, surfaced via the API returning 404).

- `frontend/src/api/types.ts`: `Candidate`, `CandidateCreateInput`, `CandidateUpdateInput`,
  `CandidateResume`, `CandidateHistoryEvent` (mirror `app/models.py`).
- `frontend/src/api/endpoints/candidates.ts`: wrappers over the CND-005 routes using the axios
  instance in `api/client.ts` (CSRF cookie header handled there).
- `frontend/src/pages/candidates/CandidatesPage.tsx` — **list**: `useQuery` table with filters
  (owner=me / status / source), columns name/email/title/status/owner/date-available, "New
  Candidate" dialog (React Hook Form + Zod), pagination via cursor.
- `frontend/src/pages/candidates/CandidateDetailPage.tsx` — **detail**: candidate fields incl. ATS
  deltas (current/desired pay, key-skills, date-available, can-relocate, LinkedIn/web, address),
  inline edit (`useMutation`), status & owner controls; a **Résumé section** (the §A "résumé
  section" requirement) listing résumés with primary badge, upload control (multipart), "Set
  primary" / delete actions, and download links (open `url` from the API); a **History** tab
  rendering the CND-004 change-history feed.
- `frontend/src/App.tsx`: lazy routes `/candidates` and `/candidates/:candidateId`. Sidebar nav
  entry (`components/layout/Sidebar`) gated on the flag.

**Reuse citations:** existing list/detail page conventions (`pages/tickets`, `pages/contacts`),
`api/client.ts` axios+CSRF, React Query / RHF+Zod / shadcn patterns (CLAUDE.md frontend section),
file-upload UI from the file manager / KB-012-style attachment controls.

**Acceptance Criteria**
- `/candidates` lists candidates with working filters + pagination + create dialog.
- `/candidates/:id` shows all ATS fields, supports inline edit, status/owner changes, and a résumé
  section that uploads, lists (primary badge), sets-primary, deletes, and downloads.
- History tab renders change events newest-first.
- With the module disabled the page shows a graceful disabled state (API 404).

**Dependencies:** CND-005.

---

### CND-007: Hermetic pytest + Playwright E2E

**Type:** Test · **Priority:** P0 · **Estimate:** 2 days

**Description**

Delivers the full test surface for the cluster.

**Hermetic pytest** (`tests/test_cnd_candidates.py`) — moto in-memory `candidates` table bound to
the exact frozen `T.candidates` via `object.__setattr__`, frozen `S` flags toggled the same way,
S3 via in-memory `_FakeS3` patched onto `app.core.aws_clients` (patterns:
`tests/test_gap_0220_0221_ssh_stored_key.py` for frozen T/S,
`tests/test_gap_0286_0287_kyc_partner_api.py` for `_FakeS3`). No real AWS, no network. Service
functions tested directly; async route handlers (CND-005) invoked on a fresh
`asyncio.new_event_loop()` (no `TestClient`). Coverage:

- **Service (CND-002):** create normalizes email/phone + `email_raw`; flag-off → 503; `list` GSI
  routing (owner/status/source) + soft-delete exclusion + pagination cursor; update 404/410 +
  status/source GSI rewrite + history hook fired; delete idempotent; `set_owner` delegates vs shim.
- **Résumé (CND-003):** upload writes `ATTACHMENT#` sub-item + S3 put; first upload auto-primary;
  `set_primary` exactly-one invariant; delete-primary promotes next; count cap → 400; soft-delete
  excludes + frees slot; `_make_download_url` dev vs prod; S3 object never deleted on résumé delete;
  file-manager-source pointer (no byte copy).
- **History (CND-004):** `record_candidate_change` never raises; fallback `ACTIVITY#` row written
  when ACT-009 absent; delegates to ACT-009 when patched present; `list_candidate_history`
  newest-first + paginated.
- **Router (CND-005):** every route 404 with flag off; create/list/detail/update/delete; résumé
  upload 413 + content-type 400; literal-segment routing not shadowed; non-owner delete 403.

**Playwright E2E** (`frontend/e2e/candidates.spec.ts`) — runs with `CANDIDATES_ENABLED=1` seeded
(via `e2e_admin_session_setup.py`), cookie/CSRF auth pattern per CLAUDE.md E2E section. Sections:
candidate CRUD API; list filters/pagination UI; detail edit + ATS fields; **résumé upload / set
primary / download / delete UI**; history tab; flag-off → disabled-state.

**Reuse citations:** `tests/test_gap_0220_0221_ssh_stored_key.py` (frozen T/S),
`tests/test_gap_0286_0287_kyc_partner_api.py` (`_FakeS3`), `tests/test_kb_003_article_attachments.py`
(attachment test shape — analogous), E2E cookie/CSRF + `injectAuth` patterns (CLAUDE.md).

**Acceptance Criteria**
- pytest passes offline (no AWS/network); covers service, résumé, history, and router as above.
- E2E spec passes against the dev stack with the flag on; exercises the résumé section end-to-end.
- All tests are hermetic (frozen-handle isolation; no real S3/DDB).

**Dependencies:** CND-002, CND-003, CND-004, CND-005, CND-006.

---

## Reuse summary (depended-on, NOT re-implemented)

| Reused capability | Source ticket / code | How CND uses it |
|---|---|---|
| Lead field set (name/email/phone/company/title) | LED-002/003 | Candidate META reuses these fields |
| Lead CRUD service shape (GSI routing, soft-delete, cursor, audit) | LED-003 | CND-002 mirrors it; `find_candidate_by_email` ↔ `find_lead_by_email` |
| Duplicate detection + merge | **LED-009** | depended on (merge operates on candidates); NOT rebuilt |
| Owner / recruiter assignment + round-robin | **LED-010** | `set_owner` delegates; queues stay in LED-010 |
| Source attribution | **LED-004** | `source` field stored; analytics not duplicated |
| Per-entity activity log | **LED-012** | CND-004 fallback storage (`ACTIVITY#` rows) |
| CRM activity timeline | **ACT-009** (+ACT-007 caller pattern) | CND-004 preferred path, `entity_type="candidate"` |
| S3 attach-on-entity (sub-item + key + presign + primary-like flag) | **KB-003** | CND-003 résumé attachments |
| File manager S3 + node sharing | `app/services/filemanager.py` | CND-003 `file_manager`-source résumé pointer |
| Flag/settings/table/GSI scaffold | LED-001 / `settings.py:821` / `tables.py:354,392` | CND-001 |

**ATS delta owned by CND (everything else is reuse):** current/desired pay, free-text key-skills,
date-available, can-relocate, LinkedIn/web URLs, candidate-pipeline status set, postal address,
résumé "primary" flag, candidate-side history adapter.
