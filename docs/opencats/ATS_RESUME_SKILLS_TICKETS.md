# ATS — Résumé Parsing, Skill Tags & Import Tickets (prefix **RSK**)

**Source gap analysis:** `docs/opencats/OPENCATS_GAP_ANALYSIS.md` — §A (Candidates + Résumé / Skills)
and §D (Search/Lists/Tags/Import). These tickets implement the *peripheral / depth* recruiting
capabilities (Tier 3 in the gap analysis §"Recommended new tickets") that sit on top of the core
ATS vertical (Candidate + Job Order entities) delivered by the **CND-\*** and **JOB-\*** ticket
families.

This file covers six tickets:

| Ticket | Title | Type | Pri | Est |
|---|---|---|---|---|
| RSK-001 | Cross-module skill-tag registry + assignment store | Feature | P1 | 2 d |
| RSK-002 | Résumé text-extraction service (PDF/DOCX → plain text) | Feature | P1 | 2 d |
| RSK-003 | Full-text résumé keyword-search token index | Feature | P1 | 2 d |
| RSK-004 | Skill-based candidate / job-order search & filter | Feature | P2 | 1.5 d |
| RSK-005 | Candidate / company CSV import (dedupe + merge) | Feature | P2 | 2 d |
| RSK-006 | Candidate hot-lists / named shortlists + quick-add-from-résumé | Feature | P2 | 2 d |

---

## Cross-cutting constraints (apply to every RSK ticket)

These mirror the constraints already enforced across the LED-\*, KB-\*, and GAP-\* specs and
**must hold for every ticket below**:

1. **Additive + flag-gated, default-OFF.** All new behavior is gated behind
   `S.ats_recruiting_enabled` (env `ATS_RECRUITING_ENABLED`, default `"0"`), declared in
   `app/core/settings.py` following the bool-env pattern at `app/core/settings.py:821`
   (`cart_reminders_enabled`). With the flag off the platform is byte-for-byte unchanged: new
   routes return `404`, new service functions are importable but never invoked, no token rows or
   skill rows are ever written. (Same flag-off convention as LED-008 §6 / KB-009 §8.1.)
   The flag is **owned by CND-001** (the candidate entity ticket); these tickets reuse it and do
   not redefine it. RSK-001 (skill registry) optionally adds a finer sub-flag
   `S.ats_skills_enabled` defaulting to *on-when-parent-on* — see RSK-001 §Description.

2. **Single-table DynamoDB.** Reuse existing tables wherever possible. Skill-tag rows and
   résumé-extraction state live on the **candidate** / **job-order** tables owned by CND-\* /
   JOB-\* (single-table, `pk`/`sk`); a dedicated `ats_skills` registry table is the only new
   table (RSK-001). All numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` in
   `scripts/local-ddb-init.py` (CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha — same trap
   hit by LED-009 §3.1 GSI5SK).

3. **SECOPS-007 dev/prod parity — no `if S.dev_mode:` branches.** Every DDB read/write goes
   through the frozen `T.*` handles; every S3 read goes through `app.core.aws_clients.s3_client()`
   (`app/core/aws_clients.py:114`). The same code path runs against DynamoDB Local / in-process
   moto S3 in dev and against real AWS in prod (same structural guarantee as LED-008 §7.1).

4. **Reuse, never fork, existing primitives.** Concretely:
   - **Token-index pattern** — `app/services/filemanager.py` `_token_pk`/`_token_entry`/
     `_put_token_entries`/`_delete_token_entries` (`:1709–:1751`) and `_search_tokens`
     (`:966`, `re.findall(r"[a-z0-9@._-]+", text.lower())`); newsfeed `_write_tag_index`
     batched-put pattern (`app/routers/newsfeed.py:440`). NOTE per gap analysis §A, the existing
     **file search indexes filenames only** (`filemanager.py:1734` `_node_haystack` covers
     `name`/`path`/`type`) — full-text *content* search is net-new (RSK-003).
   - **Full-text index spec** — `docs/suitecrm/specs/KB-009.md` (inverted-token index on a
     single table; `_KB_SEARCH_MAX_PREFIX_LEN = 8` prefix cap matching
     `app/routers/messaging.py:2786` `_MSG_SEARCH_MAX_PREFIX_LEN`; AND-intersection multi-token
     query; per-IP `_bucket_limit` fail-open). RSK-003 adapts this near-verbatim for résumé text.
   - **CSV import** — `docs/suitecrm/specs/LED-008.md` (`import_*_from_csv`,
     `csv.DictReader(io.StringIO(...))`, `_sanitize_csv_field` from
     `app/services/csv_export.py:43`, 10 MB guard from `app/routers/newsfeed.py:3114`,
     `MAX_IMPORT_ROWS`, `asyncio.to_thread`, `audit_event` once per import).
   - **Dedupe / merge** — `docs/suitecrm/specs/LED-009.md` (`find_duplicates` / `merge_leads`,
     `ByEmail`/`ByPhone` GSIs, "primary wins; secondary back-fills null fields; secondary
     soft-deleted with `merged_into`").
   - **Dependency-free PDF** — `app/services/receipts.py:53` `_render_pdf` and
     `app/services/audit_export_pipeline.py:81` `_build_pdf` build PDFs with **no `reportlab` /
     system deps** (CLAUDE.md "Audit export PDF format" / "dependency-free approach as
     `receipts.py`"). RSK-002 mirrors this *philosophy* (stdlib-only) for the inverse direction:
     **extracting** text rather than rendering it.
   - **Auth** — `Depends(require_ui_session)` from `app/services/sessions.py` (cookie + CSRF on
     non-GET), same as `app/routers/contacts.py:12,63`. Admin-scoped actions use
     `require_admin_session`.
   - **Audit** — `audit_event(event, user_sub, request=None, **fields)` at
     `app/services/alerts.py:644`.

5. **FastAPI declaration order.** Static-segment routes (e.g. `/skills`, `/import/csv`,
   `/hotlists`) are declared **before** dynamic `/{candidate_id}` / `/{job_order_id}` routes so a
   literal segment is not captured as a path param (CLAUDE.md "GAP-0210" / KB-009 §4.2 / LED-008
   §2.9).

6. **Hermetic tests.** Pytest uses the canonical offline pattern from
   `tests/test_gap_0220_0221_ssh_stored_key.py`: `@mock_aws` moto tables bound to frozen `T.*`
   handles via `object.__setattr__` (restored on cleanup), `now_ts` patched, S3 via in-memory fake
   or in-process moto, route handlers invoked directly (no `TestClient`), no real AWS / network.
   E2E adds API-level sections to the candidate/job-order Playwright specs owned by CND-\*/JOB-\*.

7. **Dependencies on the core ATS vertical.** Every ticket here depends on the **Candidate**
   entity (**CND-001**: `S.ats_recruiting_enabled`, `T.candidates`, `candidates` table; candidate
   META row with `key_skills`, `resume_attachment_id`, `email`, `phone`) and several depend on the
   **Job Order** entity (**JOB-001**: `T.job_orders`, job-order META with `required_skills`). These
   are forward dependencies (the CND-\*/JOB-\* ticket files are net-new per the gap analysis
   §Headline — "no Candidate entity … no Job Order"); hermetic tests create the moto tables
   manually so RSK tickets are testable before CND/JOB ship (same approach LED-008 §11.1 uses for
   the LED-007 `ByEmail` GSI).

---

### RSK-001: Cross-module skill-tag registry + assignment store

**Type:** Feature  **Priority:** P1  **Estimate:** 2 days

**Description**

OpenCATS dropped résumé *parsing* upstream and replaced it with **skill tagging** as the primary
way to make candidates and job orders searchable (gap analysis §Headline). The gap analysis §A and
§D both flag **"no cross-module tag/skill store"** as MISSING (`OPENCATS_GAP_ANALYSIS.md:51,87`).
This ticket builds that store from scratch as the foundation the rest of the RSK family searches
against.

Two responsibilities:

1. **Skill registry** — a canonical, normalized list of skill names (e.g. `"python"`, `"aws"`,
   `"project management"`) with a usage counter, so the UI can autocomplete and so duplicate
   spellings collapse to one tag. Normalization mirrors `app/core/normalize.py` style: lowercase,
   collapse internal whitespace, strip surrounding punctuation. A skill's canonical id is the
   slugified name (`re.sub(r"[^a-z0-9]+", "-", name).strip("-")`), so `"Project Management"` and
   `"project  management"` both resolve to skill id `project-management`.

2. **Assignment store** — bidirectional M:N links between a skill and an entity
   (`candidate` key-skill, or `job_order` required-skill), each carrying an optional `weight`
   (candidate proficiency 1–5) or `required` flag (job order). Reusable across modules via an
   `entity_type` discriminator so a future module (contact, project) can attach skills with zero
   schema change.

**DDB — new `ats_skills` table** (the one new table in this family; added to
`scripts/local-ddb-init.py` via the `TableDef` pattern at `scripts/local-ddb-init.py:28-35`):

```
pk / sk  (single table, same shape as the leads/kb tables)

Row types:
  Registry META   pk="SKILL#{skill_id}"           sk="META"
                  { skill_id, name, name_lc, usage_count(N), created_at(N) }
  Assignment (fwd)  pk="SKILL#{skill_id}"          sk="ENTITY#{entity_type}#{entity_id}"
                  { skill_id, entity_type, entity_id, weight(N, opt), required(BOOL, opt),
                    created_at(N) }
  Reverse index   pk="ENTITY#{entity_type}#{entity_id}"  sk="SKILL#{skill_id}"
                  { skill_id, name, weight(N, opt), required(BOOL, opt), created_at(N) }

GSI  ByName (GSI1PK="NAME_PREFIX#{name_lc[:1]}" / GSI1SK=name_lc S) — autocomplete by prefix;
     NOTE GSI1SK is a STRING sort key (name_lc), so NO attr_types "N" entry for it.
     created_at numeric attrs are non-key on these rows → no attr_types needed unless a numeric
     GSI sort key is added.
```

The forward row (`SKILL#…` → `ENTITY#…`) powers "who has skill X" (RSK-004 candidate search);
the reverse row (`ENTITY#…` → `SKILL#…`) powers "list skills on candidate Y" (detail view) — the
same dual-row technique LED-009 §3 and the newsfeed tag index use to avoid scans in both
directions.

**Service — `app/services/ats_skills.py`** (new file):
- `normalize_skill(name) -> (skill_id, canonical_name)` — pure, tested directly.
- `upsert_skill(name) -> dict` — idempotent registry create; `ADD usage_count :zero`-style
  no-op on existing (mirrors newsfeed `TAG_STATS` counter at `newsfeed.py:440`).
- `assign_skill(entity_type, entity_id, name, *, weight=None, required=None, actor_sub) -> dict`
  — upserts the registry row, writes both fwd + reverse rows in a `batch_writer()`, increments
  `usage_count`, emits `audit_event("ats.skill.assigned", actor_sub, entity_type=…, skill_id=…)`.
- `unassign_skill(entity_type, entity_id, skill_id, actor_sub)` — deletes both rows, decrements
  counter (floor 0); `audit_event("ats.skill.unassigned", …)`.
- `list_entity_skills(entity_type, entity_id) -> list[dict]` — query reverse rows
  (`pk="ENTITY#{entity_type}#{entity_id}"`, `begins_with(sk, "SKILL#")`).
- `list_skill_entities(skill_id, entity_type=None) -> list[dict]` — query fwd rows; loop via
  `LastEvaluatedKey` (CLAUDE.md "FilterExpression doesn't reduce page size" when `entity_type`
  filter is applied).
- `search_skills(prefix, limit=20)` — query `ByName` GSI for autocomplete.
- `set_candidate_skills(candidate_id, names, actor_sub)` / `set_job_order_skills(...)` — bulk
  replace helpers (diff current vs desired, assign/unassign deltas) consumed by CND-\* / JOB-\*
  detail editors.

**Router — `app/routers/ats_skills.py`** (new, `prefix="/ui/ats/skills"`, declared **before** any
dynamic candidate/job routes per cross-cutting §5):
- `GET  /ui/ats/skills/search?prefix=` — registry autocomplete.
- `GET  /ui/ats/skills/entity/{entity_type}/{entity_id}` — list skills on an entity.
- `POST /ui/ats/skills/entity/{entity_type}/{entity_id}` (body `{name, weight?, required?}`) —
  assign.
- `DELETE /ui/ats/skills/entity/{entity_type}/{entity_id}/{skill_id}` — unassign.
All `Depends(require_ui_session)` (CSRF auto-enforced on non-GET); guarded by
`if not S.ats_recruiting_enabled: raise HTTPException(404)`. Optional finer flag
`S.ats_skills_enabled` (env `ATS_SKILLS_ENABLED`, default `"1"`) lets ops disable skill tagging
while keeping the rest of the ATS on — it is ANDed with the master flag at the router guard, never
a separate code path.

**Models — `app/models.py`** (additive, after the candidate model block from CND-002):
`SkillOut`, `SkillAssignmentIn{name, weight?, required?}`, `EntitySkillsOut{entity_type, entity_id,
skills: List[SkillOut]}`.

**Reuse citations:** newsfeed batched-put + counter (`newsfeed.py:440`); LED-009 dual-row
fwd/reverse index (`LED-009.md §3`); `normalize_*` style (`app/core/normalize.py:60,66`);
`audit_event` (`alerts.py:644`); `TableDef` (`local-ddb-init.py:28-35`); `require_ui_session`
(`contacts.py:12,63`).

**Acceptance Criteria**
- New `ats_skills` table created in `scripts/local-ddb-init.py` with the `ByName` GSI (string SK,
  no spurious `attr_types` "N").
- `normalize_skill("Project  Management")` and `normalize_skill("project-management")` both yield
  skill id `project-management`.
- Assigning a skill writes BOTH the fwd (`SKILL#…`→`ENTITY#…`) and reverse (`ENTITY#…`→`SKILL#…`)
  rows and increments `usage_count`; unassigning deletes both and decrements (never below 0).
- `assign_skill` is idempotent: re-assigning the same skill to the same entity does not double the
  reverse rows nor double-count usage.
- `list_entity_skills` returns weight/required; `list_skill_entities(skill_id, "candidate")`
  returns only candidate entities even across paginated pages.
- `search_skills("pyt")` returns `python` via the `ByName` prefix GSI (no table scan).
- Flag off (`S.ats_recruiting_enabled=False`) → every router endpoint returns 404; service
  functions importable but unused.
- `audit_event("ats.skill.assigned"|"ats.skill.unassigned", …)` emitted on each mutation.
- Hermetic pytest `tests/test_rsk_001_skill_registry.py` (moto `ats_skills` bound to frozen
  `T.ats_skills`; normalization, dual-row write, idempotency, counter floor, prefix search,
  flag-off 404).

**Dependencies:** CND-001 (`S.ats_recruiting_enabled`, candidate entity); JOB-001 (job-order
entity, for `entity_type="job_order"`). No hard dep on other RSK tickets — RSK-001 is the
foundation the rest build on.

---

### RSK-002: Résumé text-extraction service (PDF/DOCX → plain text)

**Type:** Feature  **Priority:** P1  **Estimate:** 2 days

**Description**

Gap analysis §A: **"Résumé parsing / text extraction → full-text résumé search — MISSING — no
parsing anywhere"** (`OPENCATS_GAP_ANALYSIS.md:47`). This ticket extracts plain text from an
uploaded candidate résumé (PDF or DOCX), and **stores the extracted text on the candidate résumé
attachment** so RSK-003 can index it and the UI can preview it.

Per the explicit scope guidance, extraction is **dependency-free / stdlib-only**, mirroring the
dependency-free PDF philosophy already in the codebase (`app/services/receipts.py:53` `_render_pdf`
and `app/services/audit_export_pipeline.py:81` `_build_pdf` build PDFs with no `reportlab`/system
deps; CLAUDE.md "Audit export PDF format"). RSK-002 is the inverse — **reading** text out — using
only the Python standard library:

- **DOCX** — a DOCX is a ZIP of XML. Use `zipfile` (stdlib, already used in
  `app/services/legal_export.py` / `gdpr_service.py` / `filemanager.py`) to open the archive, read
  `word/document.xml`, and strip tags: text lives in `<w:t>` runs. Extraction =
  `re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml, re.S)` joined with spaces, with paragraph breaks from
  `<w:p>`. No `python-docx` dependency.
- **PDF** — extract text from the **uncompressed text-stream PDFs the platform itself produces**
  (the `_render_pdf` family writes `BT … (text) Tj … ET` content streams with `/F1 12 Tf`, no
  Flate compression — see `receipts.py:53`). A small stdlib parser walks the content stream,
  pulls `( … ) Tj` / `[ … ] TJ` operands, and un-escapes PDF string escapes (`\(`, `\)`, `\\`).
  For **Flate-compressed** streams (`/Filter /FlateDecode`, common in third-party PDFs) use
  `zlib.decompress` (stdlib) on the stream bytes before parsing. This covers the common case
  dependency-free; genuinely scanned/image-only PDFs yield empty text and are flagged
  `extraction_status="unsupported"` (no OCR — explicitly out of scope, documented in Open
  Questions, same "best-effort" posture as the platform's other dependency-free document code).

The service is **format-detected by magic bytes**, not trusting the filename: `%PDF` → pdf,
`PK\x03\x04` + a `word/` member → docx, otherwise `text/plain` passthrough (UTF-8 decode with
`errors="replace"`).

**DDB — no new table.** Extracted text is stored on the candidate résumé attachment row owned by
CND-003 (the résumé-attachment ticket), keyed on the candidates table:

```
pk="CANDIDATE#{candidate_id}"  sk="RESUME#{attachment_id}"   (row owned by CND-003)
  + additive attributes written by RSK-002:
      extracted_text       S   — capped at S.ats_resume_extract_max_chars (default 50_000)
      extraction_status    S   — "ok" | "unsupported" | "error"
      extracted_at         N   — now_ts()
      extracted_bytes      N   — source byte length (for observability)
```

Large résumés are truncated at the cap (the full S3 object remains the source of truth; the stored
text is for indexing/preview only). DynamoDB's 400 KB item limit comfortably holds a 50 KB text
field.

**Service — `app/services/resume_extraction.py`** (new file, all sync, dispatched via
`asyncio.to_thread` from the upload handler):
- `_detect_format(data: bytes) -> str` — magic-byte sniff.
- `_extract_docx_text(data: bytes) -> str` — `zipfile` + `<w:t>` regex.
- `_extract_pdf_text(data: bytes) -> str` — content-stream `Tj`/`TJ` parser + optional
  `zlib.decompress`.
- `extract_resume_text(candidate_id, attachment_id, *, s3_key=None, raw_bytes=None,
  actor_sub) -> dict` — fetch bytes (via `app.core.aws_clients.s3_client().get_object` when
  `s3_key` given — CND-003 stores the résumé in S3), dispatch by format, normalize whitespace
  (`re.sub(r"\s+", " ", …)`), truncate to cap, `update_item` the attachment row with the four
  attributes, emit `audit_event("ats.resume.extracted", actor_sub, candidate_id=…,
  status=…, chars=…)`. Best-effort: any exception → `extraction_status="error"`, text left empty,
  never raises into the upload path (mirrors KB-009 `_write_kb_search_index` best-effort posture).
  Returns `{extraction_status, char_count}`.

**Wiring:** CND-003's résumé-upload handler calls `extract_resume_text(...)` (best-effort
`try/except`) immediately after the S3 put — same "register-then-best-effort-enrich" shape as the
EC2 host-inventory hooks (CLAUDE.md GAP-0223). A re-extract endpoint
`POST /ui/ats/candidates/{candidate_id}/resume/{attachment_id}/extract` (admin or owner,
`require_ui_session`) lets the UI retry a failed extraction.

**Settings:** `ats_resume_extract_max_chars: int = int(os.environ.get(
"ATS_RESUME_EXTRACT_MAX_CHARS", "50000"))` and `ats_resume_extract_max_bytes: int` (default
10 MB, reusing the `_MAX_UPLOAD_BYTES` constant value from `newsfeed.py:3114`).

**Reuse citations:** dependency-free PDF philosophy (`receipts.py:53`,
`audit_export_pipeline.py:81`); `zipfile` precedent (`legal_export.py`, `gdpr_service.py`,
`filemanager.py`); `s3_client()` (`aws_clients.py:114`); best-effort enrich-after-write
(CLAUDE.md GAP-0223, KB-009 §4.1); `audit_event` (`alerts.py:644`).

**Acceptance Criteria**
- `_detect_format` correctly classifies a `%PDF` blob, a `PK\x03\x04`+`word/document.xml` blob,
  and a plain-text blob.
- `_extract_docx_text` returns the visible run text from a hand-built minimal DOCX zip (built in
  the test with `zipfile`, no external fixture).
- `_extract_pdf_text` round-trips text produced by `app/services/receipts.py._render_pdf` (build a
  PDF with `_render_pdf(["Senior Python Engineer", "AWS Lambda"])`, extract, assert both lines
  present) — proving the parser reads the platform's own PDFs.
- A `/FlateDecode`-compressed content stream is decompressed via `zlib` and parsed.
- Extraction stores `extracted_text` (≤ cap), `extraction_status="ok"`, `extracted_at`,
  `extracted_bytes` on the `RESUME#{attachment_id}` row.
- Oversized/empty/image-only PDF → `extraction_status="unsupported"`, empty text, **no exception**
  propagated to the caller.
- Truncation: a >50 KB text input is stored truncated to the cap; `char_count` reflects the stored
  length.
- Flag off → re-extract endpoint returns 404; `extract_resume_text` is a no-op guard.
- `audit_event("ats.resume.extracted", …)` emitted with `status`.
- Hermetic pytest `tests/test_rsk_002_resume_extraction.py` (in-memory fake S3 like
  `tests/test_gap_0286_0287_kyc_partner_api.py`, moto `candidates` bound to frozen `T.candidates`,
  PDF/DOCX built in-test with stdlib, `now_ts` patched).

**Dependencies:** CND-001 (candidate entity, flag); CND-003 (résumé attachment row + S3 upload
path that RSK-002 hooks). Feeds RSK-003 (which indexes `extracted_text`).

---

### RSK-003: Full-text résumé keyword-search token index

**Type:** Feature  **Priority:** P1  **Estimate:** 2 days

**Description**

Gap analysis §A: full-text résumé search is **MISSING**, and explicitly notes the existing file
search **"indexes filenames only (`filemanager.py:1734`)"** — so a content index is net-new
(`OPENCATS_GAP_ANALYSIS.md:47`). This ticket builds an **inverted-token index over the
`extracted_text` produced by RSK-002**, adapting the **KB-009 full-text index spec**
(`docs/suitecrm/specs/KB-009.md`) near-verbatim, swapping KB articles for candidate résumés.

**Pattern reused (KB-009 §3.3, §4.1):**
- Tokenize: `re.findall(r"[a-z0-9]+", text.lower())`, drop tokens < 3 chars (stop-word floor),
  generate prefix strings length 3..`min(len(word), _RESUME_SEARCH_MAX_PREFIX_LEN)` where
  `_RESUME_SEARCH_MAX_PREFIX_LEN = 8` — **must** match the messaging prefix cap
  (`messaging.py:2786`) so query prefixes are guaranteed to exist (CLAUDE.md "Message search prefix
  length bug").
- Cap distinct tokens per résumé at `_RESUME_SEARCH_MAX_TOKENS` (default **400** — higher than
  KB-009's 60 because a résumé body is far larger than an article title; this bounds DDB write
  amplification per résumé while keeping recall reasonable).
- Multi-token query = **AND intersection** across per-token result sets (KB-009 §5.5), take first
  3 query tokens to bound read amplification.
- `batch_writer()` for index writes/deletes (newsfeed `_write_tag_index` pattern,
  `newsfeed.py:440`); loop the query via `LastEvaluatedKey` (CLAUDE.md FilterExpression caveat).

**DDB — no new table.** Token rows live on the **candidates** table (single-table, owned by
CND-001), distinct PK prefix from candidate META / résumé / skill-reverse rows:

```
pk="RESUME_TOKEN#{token}"   sk="CANDIDATE#{candidate_id}"
  { candidate_id, name_snippet (first 80 chars of candidate name), updated_at(N) }
```

The `RESUME_TOKEN#` prefix never collides with `CANDIDATE#…` / `ENTITY#…` (RSK-001 reverse rows
live on `ats_skills`, not here). No GSI required — the query is always
`pk = "RESUME_TOKEN#{token}"` on the primary hash key (identical to KB-009 §3.1 reasoning).

**Service — `app/services/resume_search.py`** (new file):
- `_build_resume_tokens(text) -> list[str]` — pure (KB-009 `_build_kb_search_tokens` adapted),
  unit-tested.
- `_write_resume_index(candidate_id, name, text)` — best-effort batched put of token rows.
- `_delete_resume_index(candidate_id, text)` — batched delete on re-extract / candidate delete.
- `search_resumes(q, *, owner_sub=None, limit=25) -> list[dict]` — tokenize query (first 3
  tokens), per-token `query(pk="RESUME_TOKEN#…", Limit=200)` looping `LastEvaluatedKey`,
  AND-intersect candidate-id sets, optional owner-scope filter (only the requesting recruiter's
  candidates when `owner_sub` given), `batch_get_item` the candidate META rows for display,
  return ranked-by-recency dicts. Empty/short query → `[]` with no DDB call (KB-009 §5.6).

**Wiring:** RSK-002's `extract_resume_text` calls `_write_resume_index(candidate_id, name,
extracted_text)` after a successful extraction (delete-old-then-write on re-extract). Candidate
delete (CND-\*) calls `_delete_resume_index` best-effort.

**Router — `app/routers/ats_recruiting.py`** (or the candidate router owned by CND-\*; declared
**before** `/{candidate_id}`):
- `GET /ui/ats/candidates/search/resume?q=&limit=` — full-text résumé search,
  `Depends(require_ui_session)`, owner-scoped to the caller's candidates by default
  (`owner_sub=ctx["user_sub"]`, admin may pass `all=true`), per-user `_bucket_limit`
  (`app/services/rate_limit.py`) at 30/60 s like the global search endpoint (KB-009 §2.9).

**Optional global-search integration (KB-009 §4.3):** add a `_search_candidates_resume` fan-out
branch + `"candidates"` to `ALLOWED_TYPES` in `app/routers/search.py` guarded by
`S.ats_recruiting_enabled`, returning `_empty_section()` when off — exactly the KB-009 mechanism.
Mark this sub-task as a soft follow-up if `app/routers/search.py` churn is undesirable in the same
PR.

**Settings:** `_RESUME_SEARCH_MAX_PREFIX_LEN`, `_RESUME_SEARCH_MAX_TOKENS` are module-level
constants (not env-driven — changing them needs an index rebuild, same rationale as KB-009 §6.2).
A `rebuild_resume_index()` migration helper (scan `RESUME#` attachment rows, re-extract-or-reindex)
mirrors KB-009 §8.2 `rebuild_search_index` for cold-start population; CLI-only, not an endpoint.

**Reuse citations:** KB-009 full-text spec (`docs/suitecrm/specs/KB-009.md` §3.3/§4.1/§5.5/§8.2);
messaging prefix cap (`messaging.py:2786`); filename-only file search it supersedes
(`filemanager.py:1734`); newsfeed batched-put (`newsfeed.py:440`); `_bucket_limit`
(`rate_limit.py`); `search.py` aggregator (`search.py:41,60,64`).

**Acceptance Criteria**
- `_build_resume_tokens` skips <3-char tokens, caps prefixes at 8 chars and total tokens at 400,
  dedupes (KB-009 token tests adapted).
- Indexing a candidate whose résumé text contains "python" + "kubernetes" makes both
  `search_resumes("python")` and `search_resumes("kubernetes")` return that candidate.
- `search_resumes("python kubernetes")` returns a candidate only if the résumé contains **both**
  (AND intersection); a candidate with only "python" is excluded.
- Owner scope: recruiter A's search does not return recruiter B's candidate (when `owner_sub`
  passed); admin `all=true` returns both.
- Re-extraction deletes the old token rows and writes new ones (no stale matches on the old text).
- Empty / sub-3-char query (`"a b"`) returns `[]` with no DDB query issued.
- Flag off → endpoint 404; index writes are no-ops.
- Hermetic pytest `tests/test_rsk_003_resume_search.py` (moto `candidates` bound to frozen
  `T.candidates`, token-build purity tests, write/query/AND/owner-scope/re-extract/flag-off).

**Dependencies:** RSK-002 (produces `extracted_text`); CND-001 (candidates table + flag).
Cross-references KB-009 as the template spec.

---

### RSK-004: Skill-based candidate / job-order search & filter

**Type:** Feature  **Priority:** P2  **Estimate:** 1.5 days

**Description**

Gap analysis §A: **"Skill tagging + skill-based search — MISSING"** (`OPENCATS_GAP_ANALYSIS.md:48`).
RSK-001 built the skill store; this ticket exposes **search/filter by skill** across candidates and
job orders — the recruiter workflow of "find candidates who have skills X and Y" and "find job
orders requiring skill Z". It is pure query composition over RSK-001's forward index — **no new
table, no new index**.

**Service — extend `app/services/ats_skills.py`:**
- `find_candidates_by_skills(skill_ids: list[str], *, match="all", owner_sub=None, limit=50)
  -> list[str]` — for each `skill_id`, `query(pk="SKILL#{skill_id}",
  begins_with(sk, "ENTITY#candidate#"))` looping `LastEvaluatedKey`; intersect (`match="all"`,
  AND) or union (`match="any"`, OR) the candidate-id sets client-side (same AND/OR choice as
  KB-009 §5.5 / `_search_tickets` `all(tok in haystack …)` at `search.py:432`). Optional
  `owner_sub` post-filter. Returns candidate ids; the candidate router (CND-\*) hydrates them to
  `CandidateOut`.
- `find_job_orders_by_skills(skill_ids, *, match="all", limit=50) -> list[str]` — same against
  `begins_with(sk, "ENTITY#job_order#")`; optionally honour the `required` flag
  (`required_only=True` keeps only assignments where `required is True`).
- `match_candidates_to_job_order(job_order_id, *, limit=50) -> list[dict]` — convenience: read the
  job order's required skills (RSK-001 `list_entity_skills("job_order", job_order_id)`), then
  `find_candidates_by_skills(required_skill_ids, match="any")`, returning each candidate with a
  **match score** = (#required skills the candidate has) / (#required skills) — a cheap ranking
  signal for the pipeline UI. Pure set arithmetic over already-fetched rows; no extra DDB reads
  beyond the per-skill queries.

**Router — extend the skills/candidate router (static segments before `/{id}`):**
- `GET /ui/ats/candidates/search/skills?skill_ids=a,b&match=all` — candidate search by skill.
- `GET /ui/ats/job-orders/search/skills?skill_ids=…&match=all&required_only=true` — job search.
- `GET /ui/ats/job-orders/{job_order_id}/matching-candidates` — ranked candidate suggestions.
All `Depends(require_ui_session)`, flag-guarded (`S.ats_recruiting_enabled`).

**Models:** `CandidateMatchOut{candidate_id, name, matched_skill_ids, match_score(float)}`;
reuse `SkillOut` from RSK-001.

**Reuse citations:** RSK-001 forward index; AND/OR semantics (KB-009 §5.5, `search.py:432`);
`LastEvaluatedKey` loop (CLAUDE.md FilterExpression caveat); `require_ui_session`.

**Acceptance Criteria**
- `find_candidates_by_skills(["python","aws"], match="all")` returns only candidates assigned
  **both**; `match="any"` returns candidates with at least one.
- Results are stable across paginated `SKILL#…` query pages (loop covers >1 page).
- `find_job_orders_by_skills(..., required_only=True)` excludes job orders where the skill is
  present but `required` is falsy.
- `match_candidates_to_job_order` returns candidates sorted by descending `match_score`, score in
  `[0,1]`, `1.0` when a candidate has every required skill.
- `owner_sub` filter restricts candidate results to that recruiter.
- Flag off → endpoints 404.
- Hermetic pytest `tests/test_rsk_004_skill_search.py` (moto `ats_skills` bound to frozen handle;
  AND/OR, pagination, required_only, match-score, owner scope, flag-off).

**Dependencies:** RSK-001 (skill store + assignments). Soft-uses CND-\* (candidate hydrate) and
JOB-001 (job-order required-skills). Independent of RSK-002/003.

---

### RSK-005: Candidate / company CSV import (dedupe + merge)

**Type:** Feature  **Priority:** P2  **Estimate:** 2 days

**Description**

Gap analysis §A/§D: **"CSV import (candidates/companies/contacts) — PARTIAL/PLANNED — export HAVE;
lead import LED-008; candidate import missing"** (`OPENCATS_GAP_ANALYSIS.md:89`) and **"Duplicate
detection + merge — PLANNED — LED-009 (reusable if Candidate=Lead)"** (`:49`). This ticket models
the candidate (and company) bulk CSV importer **directly on LED-008**
(`docs/suitecrm/specs/LED-008.md`) and reuses **LED-009** dedupe/merge semantics
(`docs/suitecrm/specs/LED-009.md`).

**Service — `app/services/candidate_import.py`** (new file, structured exactly like LED-008
`leads_import.py`):
- Constants: `CANDIDATE_CSV_COLUMNS = ["first_name","last_name","email","phone","current_title",
  "current_employer","desired_pay","date_available","can_relocate","linkedin_url","key_skills"]`,
  `MAX_IMPORT_ROWS = 5000`, `_MAX_CSV_BYTES = 10*1024*1024` (LED-008 §4.1.1).
- `import_candidates_from_csv(owner_sub, csv_bytes, *, record_type="candidate",
  skip_duplicates=True) -> dict` — flag-guard (`S.ats_recruiting_enabled`), decode
  `utf-8-sig`/`errors="replace"` (LED-008 §5.5 BOM handling), `csv.DictReader(io.StringIO(...))`,
  require an `email` header column (422 if missing), per-row: strip + `_sanitize_csv_field`
  (imported from `app/services/csv_export.py:43`, LED-008 §4.1.3), `normalize_email` pre-validate
  (per-row error on failure, continue), duplicate check via **CND-\*'s
  `find_candidate_by_email`** (the candidate analogue of `find_lead_by_email`; assume CND-001 wires
  a `ByEmail` GSI like LED-007), build `CandidateCreateIn`, `try/except ValidationError` →
  per-row error, then `create_candidate(owner_sub, model)`. **`key_skills`** column is split on
  `;` / `,` and each skill is assigned via RSK-001 `assign_skill(...)` (best-effort per skill) —
  the import is the natural place to populate the skill store. Returns
  `{imported, skipped, errors:[{row,reason}]}`; one `audit_event("candidate_import.completed", …)`
  per call (LED-008 §4.1.2 step 8). Dispatched via `asyncio.to_thread` from the async route.
- `import_companies_from_csv(owner_sub, csv_bytes, ...) -> dict` — same shape, writing companies
  via the PTY/CCT company entity (gap analysis §B; soft-dep — if the company entity is not yet
  present, this function is gated separately and can ship in a follow-up; the candidate path is the
  load-bearing one).

**Dedupe / merge (LED-009 reuse):** RSK-005 reuses LED-009's `find_duplicates` / `merge_leads`
**pattern** for candidates — CND-\* is expected to expose `find_candidate_duplicates(candidate_id)`
and `merge_candidates(primary, secondary, actor_sub)` (the Candidate=Lead analogues; "primary wins;
secondary back-fills null fields; secondary soft-deleted with `merged_into`", LED-009 §1/§4.2). If
CND-\* has not yet delivered them, RSK-005 includes them as candidate-table-scoped copies of the
LED-009 functions (same `MERGEABLE_FIELDS`-style back-fill, `ByEmail`/`ByPhone` GSIs) so import →
dedupe → merge is end-to-end usable. The import itself uses `skip_duplicates=True` to skip on email
match (LED-008 §5.4); explicit merge is a separate post-import recruiter action (LED-009 §10.5
"import does not auto-merge").

**Router — extend the candidate router (`prefix="/ui/ats/candidates"`, static before `/{id}`,
LED-008 §2.9):**
- `POST /ui/ats/candidates/import/csv` (multipart `file` + `record_type` + `skip_duplicates` form
  fields, LED-008 §4.2) — `require_ui_session` (CSRF auto), 10 MB guard (422), flag-guard 404,
  `asyncio.to_thread(import_candidates_from_csv, …)`.
- `GET /ui/ats/candidates/{candidate_id}/duplicates` and `POST /ui/ats/candidates/{candidate_id}/
  merge` (LED-009 §4.3 shape) — surfaced here if CND-\* hasn't already.

**Models:** `CandidateImportRowError{row,reason}`, `CandidateImportResultOut{imported,skipped,
errors}` (LED-008 §4.3 shape).

**Reuse citations:** LED-008 importer (`docs/suitecrm/specs/LED-008.md` §4.1/§4.2/§5.5);
LED-009 dedupe/merge (`docs/suitecrm/specs/LED-009.md` §1/§4.2); `_sanitize_csv_field`
(`csv_export.py:43`); 10 MB guard (`newsfeed.py:3114`); `normalize_email` (`normalize.py:60`);
multipart `UploadFile` (`kyc_partner_api.py:186`); RSK-001 `assign_skill` for the `key_skills`
column.

**Acceptance Criteria**
- Happy path: a 5-row candidate CSV with all columns → `imported=5`, `skipped=0`, `errors=[]`; 5
  `CANDIDATE#` META rows exist.
- `key_skills="python; aws; kubernetes"` on a row creates 3 RSK-001 skill assignments for that
  candidate.
- Missing `email` header → `HTTPException(422)`; row with empty/invalid email → per-row `errors`
  entry, other rows imported (LED-008 §5).
- Duplicate email with `skip_duplicates=True` → `skipped` incremented, no new row; with
  `skip_duplicates=False` → processed (idempotent create) (LED-008 §5.4).
- UTF-8 BOM-prefixed CSV imports correctly (`utf-8-sig`, LED-008 §5.5).
- CSV injection: `first_name="=CMD(x)"` stored as `"'=CMD(x)"` (LED-008 §7.3).
- Row cap at 5000 → `imported=5000` + synthetic truncation error at row 5001 (LED-008 §5.7).
- `find_candidate_duplicates` / `merge_candidates` honour LED-009 semantics (primary wins,
  secondary `status` soft-deleted + `merged_into`, idempotent replay).
- One `audit_event("candidate_import.completed", …)` per import.
- Flag off → import + dedupe + merge endpoints 404.
- Hermetic pytest `tests/test_rsk_005_candidate_import.py` (moto `candidates`+`ats_skills` bound to
  frozen handles; LED-008/LED-009 test matrices adapted).

**Dependencies:** CND-001 (candidate entity, `find_candidate_by_email`/`ByEmail` GSI, `ByPhone`
for phone dedupe), CND-002 (`CandidateCreateIn`); RSK-001 (`assign_skill` for `key_skills`).
Models on LED-008 + LED-009. Company path soft-depends on PTY/CCT company entity.

---

### RSK-006: Candidate hot-lists / named shortlists + quick-add-from-résumé

**Type:** Feature  **Priority:** P2  **Estimate:** 2 days

**Description**

Gap analysis §A: **"Candidate hot-list / quick-add-from-résumé — MISSING — no shortlist concept"**
(`OPENCATS_GAP_ANALYSIS.md:52`). OpenCATS lets recruiters build named **lists** (saved
shortlists/"hot lists") of candidates for bulk actions (bulk email, bulk pipeline add, export).
This ticket delivers named candidate lists + membership + a **quick-add-from-résumé** flow that
creates a candidate straight from an uploaded résumé and drops it onto a list. It is the
recruiting-specific analogue of MKT-007 static lists (gap analysis §D "static lists (MKT-007)") but
scoped to candidates, so it lives in the ATS family rather than forking MKT.

**DDB — no new table.** Hot-list rows live on the **candidates** table (single-table, owned by
CND-001), distinct PK prefix:

```
List META       pk="HOTLIST#{list_id}"   sk="META"
                { list_id, name, owner_sub, member_count(N), is_shared(BOOL), created_at(N),
                  updated_at(N) }
Membership      pk="HOTLIST#{list_id}"   sk="MEMBER#{candidate_id}"
                { candidate_id, added_by, added_at(N) }
Reverse (lists-of-candidate)
                pk="CANDIDATE#{candidate_id}"  sk="HOTLIST#{list_id}"
                { list_id, name, added_at(N) }   (so a candidate detail view can show its lists)
GSI  ByOwner (GSI1PK="HOTLIST_OWNER#{owner_sub}" / GSI1SK=created_at N) — "my lists";
     attr_types={"GSI1SK": "N"}  (CLAUDE.md numeric-GSI gotcha).
```

The dual membership rows (forward `HOTLIST#…`→`MEMBER#…` + reverse `CANDIDATE#…`→`HOTLIST#…`) are
the same bidirectional technique as RSK-001 and LED-009, so both "members of list" and "lists of
candidate" are O(query) with no scan.

**Service — `app/services/candidate_hotlists.py`** (new file):
- `create_hotlist(owner_sub, name, *, is_shared=False) -> dict` — META + `ByOwner` GSI row;
  `audit_event("ats.hotlist.created", …)`.
- `list_hotlists(owner_sub) -> list[dict]` — query `ByOwner` GSI.
- `add_to_hotlist(list_id, candidate_id, actor_sub)` / `remove_from_hotlist(...)` — write/delete
  both membership rows in a `batch_writer()`, maintain `member_count` (`ADD :one` / `:negone`,
  floor 0); idempotent (re-add is a no-op, no double count).
- `bulk_add_to_hotlist(list_id, candidate_ids, actor_sub) -> dict` — batched add for "select 20
  candidates → add to list" (returns `{added, skipped}`).
- `list_members(list_id, *, cursor=None, limit=50)` — paginated via `encode_cursor`/`decode_cursor`
  (`app/core/cursor.py:94`).
- `list_candidate_hotlists(candidate_id)` — reverse-row query for the candidate detail view.
- `delete_hotlist(list_id, actor_sub)` — owner/admin only; deletes META + all membership +
  reverse rows; `audit_event`.
- `quick_add_from_resume(owner_sub, raw_bytes, filename, *, list_id=None) -> dict` — the
  quick-add flow: (1) create a stub candidate via CND-\*'s `create_candidate` (name derived from
  filename or "Unparsed Candidate", flagged `source="resume_quickadd"`), (2) store the résumé via
  CND-003's attachment path (S3 put), (3) run RSK-002 `extract_resume_text` (best-effort), (4) run
  RSK-003 `_write_resume_index` so the new candidate is immediately résumé-searchable, (5) if
  `list_id` given, `add_to_hotlist`. Returns `{candidate_id, attachment_id, extraction_status,
  hotlist_id}`. Each enrich step is best-effort `try/except` (a parse failure still yields a usable
  candidate — same posture as RSK-002/KB-009).

**Router — extend the candidate/ATS router (static `/hotlists` before `/{candidate_id}`):**
- `POST /ui/ats/hotlists` (create), `GET /ui/ats/hotlists` (my lists),
  `DELETE /ui/ats/hotlists/{list_id}`.
- `POST /ui/ats/hotlists/{list_id}/members` (body `{candidate_ids:[…]}` → bulk add),
  `DELETE /ui/ats/hotlists/{list_id}/members/{candidate_id}`,
  `GET /ui/ats/hotlists/{list_id}/members`.
- `POST /ui/ats/candidates/quick-add-from-resume` (multipart `file` + optional `list_id`,
  10 MB guard, `asyncio.to_thread(quick_add_from_resume, …)`).
All `Depends(require_ui_session)` (CSRF auto on non-GET), flag-guarded
(`S.ats_recruiting_enabled`).

**Models:** `HotlistOut{list_id,name,member_count,is_shared,created_at}`,
`HotlistMemberOut{candidate_id,added_at}`, `BulkAddIn{candidate_ids:List[str]}`,
`QuickAddResumeOut{candidate_id,attachment_id,extraction_status,hotlist_id}`.

**Reuse citations:** dual fwd/reverse membership (RSK-001, LED-009 §3); `ByOwner` numeric GSI +
`attr_types` (LED-009 §3.1); `encode_cursor`/`decode_cursor` (`cursor.py:94`); batched-put counter
(`newsfeed.py:440`); multipart upload + 10 MB guard (`kyc_partner_api.py:186`, `newsfeed.py:3114`);
RSK-002 extraction + RSK-003 index for quick-add enrichment; `audit_event` (`alerts.py:644`).

**Acceptance Criteria**
- Create a hot-list → META + `ByOwner` GSI row; `list_hotlists(owner)` returns it.
- `add_to_hotlist` writes both forward + reverse rows and increments `member_count`; idempotent
  re-add does not double-count; `remove_from_hotlist` deletes both and decrements (floor 0).
- `bulk_add_to_hotlist([...20 ids])` adds all, returns accurate `{added, skipped}`.
- `list_members` paginates via signed cursor; `list_candidate_hotlists` returns the candidate's
  lists from the reverse rows.
- `delete_hotlist` removes META + all membership + reverse rows (no orphan reverse rows on
  candidates).
- `quick_add_from_resume`: creates a candidate, stores + extracts the résumé (RSK-002), indexes it
  (RSK-003 — the new candidate is immediately returned by `search_resumes` for a term in the
  résumé), and (when `list_id` given) adds it to the list — each enrich step best-effort so a parse
  failure still yields a usable candidate.
- Owner/admin authorization: a non-owner cannot delete or mutate another recruiter's private
  (`is_shared=False`) list.
- `audit_event` emitted on create/delete and quick-add.
- Flag off → all endpoints 404.
- Hermetic pytest `tests/test_rsk_006_hotlists.py` (moto `candidates` bound to frozen handle;
  dual-row membership, idempotent count, bulk add, cursor pagination, reverse lookup, cascade
  delete, quick-add chains RSK-002/003 with extraction stubbed/real, flag-off).

**Dependencies:** CND-001 (candidate entity + flag), CND-003 (résumé attachment path for
quick-add), RSK-002 (extraction) + RSK-003 (index) for quick-add enrichment. Independent of
RSK-004/005.

---

## Dependency order (build sequence)

```
CND-001/002/003 + JOB-001        (forward deps — core ATS vertical, separate ticket families)
        │
        ▼
RSK-001  skill registry + assignment store        (foundation)
        │
   ┌────┴───────────────┐
   ▼                    ▼
RSK-004              RSK-002  résumé text extraction
skill search             │
                         ▼
                    RSK-003  résumé full-text index
                         │
   ┌─────────────────────┼─────────────────────┐
   ▼                     ▼                     ▼
RSK-005              RSK-006              (global-search
candidate import     hot-lists +          integration —
(LED-008/009)        quick-add-from-       soft follow-up
  uses RSK-001       résumé (RSK-002/003)   in RSK-003)
```

Recommended merge order: **RSK-001 → RSK-002 → RSK-003 → RSK-004 → RSK-005 → RSK-006.**
RSK-004 can land any time after RSK-001; RSK-005 after RSK-001 (skill assignment from `key_skills`);
RSK-006 after RSK-002+RSK-003 (quick-add enrichment).
