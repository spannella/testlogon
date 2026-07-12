# ATS — Public Career Portal / Job Board + Self-Apply (PRT)

**Prefix:** `PRT` · **Area:** Recruiting / ATS (OpenCATS gap §D — "Career Portal + Self-apply")
**Source gap:** `docs/opencats/OPENCATS_GAP_ANALYSIS.md` §D ("Public job board" / "Self-apply → Candidate + pipeline" / "Résumé upload from portal; per-posting screening questionnaire" / "Career-portal config") and the Tier-2 cluster recommendation at `OPENCATS_GAP_ANALYSIS.md:106-107`.

This file decomposes the **public career portal** vertical: an unauthenticated job board listing public-flagged job orders, per-posting slug URLs + a jobs RSS feed, a candidate self-apply flow (creates a Candidate and adds it to the job order's pipeline at the initial "New/Applied" status), résumé upload from the portal, an optional per-posting screening questionnaire, and admin-managed portal branding/config.

---

## Cross-cutting constraints (read before any PRT ticket)

These constraints apply to **every** ticket below. They are not repeated per-ticket except where a ticket deviates.

1. **Net-new vertical, additive only.** The recruiting data model (Job Order, Candidate, Pipeline) does not exist in code today (`OPENCATS_GAP_ANALYSIS.md:32-36`). PRT depends on the Tier-1 ATS cluster — **JOB-\*** (Job Order entity + `is_public` flag), **CND-\*** (Candidate entity), **PIP-\*** (candidate↔job-order pipeline + ranked status workflow) — which are forward dependencies (proposed at `OPENCATS_GAP_ANALYSIS.md:100-104`, not yet ticketed as files). Every PRT service call into those modules is **lazy-imported and try/except-guarded** so PRT degrades gracefully (404 / empty list) when the Tier-1 modules are absent, exactly as CMP-006 lazy-imports `marketing_lists` / `T.leads` (`docs/suitecrm/specs/CMP-006.md:387-395`).

2. **Master feature flag, default OFF.** All PRT code is gated on `S.career_portal_enabled` (env `CAREER_PORTAL_ENABLED`, default `"0"`), following the `cart_reminders_enabled` bool-env idiom at `app/core/settings.py:821` and the CMP-006 default-off convention (`docs/suitecrm/specs/CMP-006.md:149`). With the flag off, every public endpoint returns **HTTP 404** (identical body to KB-011's flag-off behavior, `docs/suitecrm/specs/KB-011.md:144-146`) and the platform is byte-for-byte unchanged.

3. **Public endpoints are fully unauthenticated.** Public portal routes carry **no `Depends(...)` auth parameter** — the codebase pattern for public routes (e.g. `GET /calendar/public/event/{calendar_id}/{event_id}` at `app/routers/calendar.py:2079`, which has no auth dependency; KB-011 §2 "Auth dependencies"). They live on a dedicated `public_router = APIRouter(...)` with **no `dependencies=` argument**, mirroring the calendar `public_event_router` (`app/routers/calendar.py:89`) and the CMP-006 `public_router` (`docs/suitecrm/specs/CMP-006.md:304-318`).

4. **PUBLIC routes MUST be added to `API_KEY_ROUTE_EXEMPTIONS`.** Every public GET/POST route is registered in `API_KEY_ROUTE_EXEMPTIONS` at `app/services/api_key_route_scope_registry.py:70` (the same dict KB-011 extends for `/public/kb/*`, `docs/suitecrm/specs/KB-011.md:405-415`). Without the exemption the API-key middleware returns 403 for callers carrying an API key without the matching scope. Entries use the existing `"METHOD:/path": {"reason": "..."}` shape (`api_key_route_scope_registry.py:71-89`).

5. **Honeypot + per-IP rate-limit on the public apply endpoint.** The self-apply POST is anonymous and therefore reuses the CMP-006 abuse-mitigation plumbing verbatim: a hidden `honeypot` field → silent fake-success response with **no DDB write** (`docs/suitecrm/specs/CMP-006.md:357-359`), and per-IP rate limiting via `_bucket_limit(f"ip#{ip}", "rl#career_apply", max_n, 3600)` from `app/services/rate_limit.py:60` (the `_ip_user` keying convention at `rate_limit.py:81`), raising `HTTPException(429)` on breach. CSRF is bypassed because the request carries no `ui_session` cookie (the CSRF gate at `app/services/sessions.py:429` only fires when a session cookie is present — CMP-006 §7).

6. **No CSRF on public POST; admin writes use `require_ui_session` + role gate.** Admin config/list endpoints use `Depends(require_ui_session)` (imported from `app.services.sessions`, as in `app/routers/contacts.py:12`) with an inline `role in {Role.ADMIN, Role.ROOT}` check (`Role` / `normalize_role` from `app/auth/roles`), the CMP-006 admin pattern (`docs/suitecrm/specs/CMP-006.md:322-339`).

7. **SECOPS-007 dev/prod parity.** No `if S.dev_mode:` branches in PRT logic. The only env-determined difference is the S3 URL format returned by the file-manager presign helper (`/mock/s3/...` in dev vs presigned URL in prod), which is decided inside `presign_upload` at `app/services/filemanager.py:2223-2238` — not by PRT. Email/SES, DDB, and audit calls run identically in both environments (KB-011 §7, LED-005 §7.1).

8. **Numeric GSI sort keys** must be declared with `attr_types={"...": "N"}` in `scripts/local-ddb-init.py` (CLAUDE.md gotcha; CMP-006 §3.1 `attr_types={"GSI1SK": "N"}`). All `created_at` / `applied_at` GSI sort keys below follow this.

9. **Cursor pagination** uses `app/core/cursor.encode_cursor` / `decode_cursor` (`app/core/cursor.py:94`) for every paginated list — never raw `LastEvaluatedKey` (KB-011 §2 "Cursor pagination").

10. **Audit + best-effort side effects.** State mutations emit `audit_event(event, user_sub, **fields)` (`app/services/alerts.py:644`) inside `try/except`; the apply path uses `user_sub="anonymous"` (CMP-006 §7 "Audit trail"). Any failure in a best-effort side effect (audit, list-add, email, questionnaire-link) never fails the primary operation.

11. **Tests are hermetic.** pytest uses moto in-memory DDB bound to frozen `T`/`S` via `object.__setattr__`, route handlers called directly (never `TestClient`) on a fresh `asyncio.new_event_loop()`, per `tests/test_gap_0220_0221_ssh_stored_key.py` (CMP-006 §9.1, LED-005 §9.1). E2E specs run with `CAREER_PORTAL_ENABLED=1` and unauthenticated `page.request` for public routes (KB-011 §9.2).

**Dependency order:** PRT-001 (config/flag/table) → PRT-002 (public listing + slug) → PRT-003 (RSS) → PRT-004 (self-apply core) → PRT-005 (résumé + screening questionnaire) → PRT-006 (tests).

---

### PRT-001: Career-portal config table, flag, and admin branding settings

**Type:** Feature · **Priority:** P1 · **Estimate:** 1.5d

**Description**

Foundation ticket: the master flag, the config/branding store, and admin CRUD for it. Career-portal branding (logo, portal name, intro copy) is per-tenant operator config — there is one config row.

*Settings (`app/core/settings.py`, bool-env idiom at `:821`):*
```python
career_portal_enabled: bool = os.environ.get("CAREER_PORTAL_ENABLED", "0") not in ("0", "false", "False")
career_portal_table_name: str = os.environ.get("DDB_CAREER_PORTAL_TABLE", "CareerPortal")
career_portal_apply_rate_limit_per_ip_per_hour: int = int(os.environ.get("CAREER_PORTAL_APPLY_RATE_LIMIT_PER_IP_PER_HOUR", "10"))
career_portal_resume_max_bytes: int = int(os.environ.get("CAREER_PORTAL_RESUME_MAX_BYTES", str(10 * 1024 * 1024)))
career_portal_slug_prefix: str = os.environ.get("CAREER_PORTAL_SLUG_PREFIX", "")  # reserved for multi-tenant slug namespacing
```

*DDB (`scripts/local-ddb-init.py` `_table_defs()` at `:42`):* a single-table `CareerPortal` (PK `pk` (S) / SK `sk` (S)).
- Config row: `pk="CONFIG"`, `sk="META"` — `portal_name`, `intro_copy`, `logo_file_path` (a file-manager path, not a raw S3 key), `logo_url` (resolved at read time), `primary_color`, `support_email`, `updated_at` (N), `updated_by`.
- Posting-slug index row (written by JOB-\* publish; PRT owns the read shape): `pk="SLUG#{slug}"`, `sk="META"` → `{job_order_id, slug, created_at(N)}`. This is the resolve-by-slug analogue of the questionnaire `published_slug-index` (`docs/suitecrm/specs/CMP-005.md:30`). Sparse; no GSI needed for point lookup.

*Service (`app/services/career_portal.py`, new, synchronous like `cart_reminders.py`):* `_require_enabled()` → 404 when flag off (CMP-006 §4.2 `_require_web_lead_enabled`); `get_portal_config()` (returns defaults from `S` when no row exists, resolving `logo_url` from `logo_file_path` via the file-manager download-URL helper); `set_portal_config(data, actor_sub)`.

*Models (`app/models.py`):* `CareerPortalConfigIn` (portal_name ≤120, intro_copy ≤4000, logo_file_path optional, primary_color optional `^#[0-9a-fA-F]{6}$`, support_email optional) and `CareerPortalConfigOut` (adds resolved `logo_url`).

*Router (`app/routers/career_portal.py`, new — registered in `app/main.py`):* admin `GET/PUT /ui/admin/career-portal/config` (`require_ui_session` + ADMIN/ROOT inline gate, CMP-006 §4.3). Also declares the `public_router` instance (populated by PRT-002+) and the `T.career_portal` handle in `app/core/tables.py` next to `contacts` (`tables.py:354`).

*Reuse cited:* KB-011 (flag-gated 404 portal pattern), CMP-006 (settings/flag idiom, admin role gate, service `_require_enabled` guard), CMP-005 (slug→entity resolution model).

**Acceptance Criteria**
- `CAREER_PORTAL_ENABLED=0` → `get_portal_config` / `set_portal_config` raise 404; admin endpoints 404; no DDB I/O.
- With flag on and no config row, `get_portal_config()` returns the `S`-default branding (does not 500).
- `PUT /ui/admin/career-portal/config` as USER role → 403; as ADMIN/ROOT → 200 and persists; `updated_by`/`updated_at` set.
- `logo_url` resolves to `/mock/s3/...` in dev and a presigned URL in prod purely via the file-manager helper (no `dev_mode` branch in PRT).
- `CareerPortal` TableDef present in `scripts/local-ddb-init.py`; `T.career_portal` wired.

**Dependencies:** none hard. Forward-dep: JOB-\* writes the `SLUG#{slug}` row at publish (PRT-001 defines its read shape).

---

### PRT-002: Public job board listing + per-posting public slug page

**Type:** Feature · **Priority:** P1 · **Estimate:** 2d

**Description**

The unauthenticated job board: list all `is_public`-flagged, open job orders, and a per-posting detail page resolvable by a stable public slug. Reuses the KB-011 public-portal surface pattern and the questionnaire published-by-slug resolution (`app/routers/questionnaires.py:615-642`, `REPO.get_published_by_slug` at `:620`).

*Public endpoints (`public_router`, no auth — constraint 3):*
- `GET /public/careers/config` → `CareerPortalConfigOut` (branding for the portal header; delegates to `get_portal_config`).
- `GET /public/careers/jobs` → `CareerJobListOut` — lists public+open postings. Delegates to a JOB-\* query: job orders with `is_public=True` AND `status` in the open set, newest first, cursor-paginated (constraint 9). Lazy-import + try/except → empty list when JOB-\* absent (constraint 1).
- `GET /public/careers/jobs/{slug}` → `CareerJobDetailOut` — resolves `SLUG#{slug}`→`job_order_id` (PRT-001 row), point-loads the job order, and returns **only public-safe fields** (title, location, employment type, public description, posted date, and — if linked — the screening-questionnaire slug from PRT-005). Returns 404 if the slug is unknown, the job order is missing, not `is_public`, or not open (the "draft/expired never leak to public" rule from KB-011 §5 "Draft and expired articles").

*Models (`app/models.py`):* `CareerJobSummaryOut` (job_order_id, slug, title, location, employment_type, posted_at, openings); `CareerJobDetailOut` (extends summary + public_description, screening_questionnaire_slug, apply_path); `CareerJobListOut` (items, cursor, total_estimate=None).

*Route ordering:* on `public_router`, declare static segments (`/config`, `/jobs`) before the dynamic `/jobs/{slug}` so the literal `config`/`jobs` are not captured as a slug (the FastAPI declaration-order constraint, KB-011 §4.1).

*`API_KEY_ROUTE_EXEMPTIONS` (constraint 4):* add `GET:/public/careers/config`, `GET:/public/careers/jobs`, `GET:/public/careers/jobs/{slug}`.

*(Optional, additive)* a `careers` branch in the global search aggregator (`app/routers/search.py`): `ALLOWED_TYPES |= {"careers"}` gated on `S.career_portal_enabled` (the KB-009/KB-011 flag-independent-of-`_EXTENDED_SEARCH` pattern, `docs/suitecrm/specs/KB-011.md:353-358`), with a `_search_careers` returning `_empty_section()` on flag-off/error (`search.py:60`, `:43-45`). Marked optional so PRT-002 lands without it.

*Reuse cited:* KB-011 (public list/detail surface + exemptions + flag-off 404 + route ordering + search branch), CMP-005 (slug→entity resolution; published-by-slug pattern at `app/routers/questionnaires.py:620`), calendar public router (`app/routers/calendar.py:89,2079` — no-auth router pattern).

**Acceptance Criteria**
- Flag off → all three public endpoints 404.
- `GET /public/careers/jobs` returns only `is_public` + open postings, newest first, paginates via opaque cursor; non-public / closed postings never appear.
- `GET /public/careers/jobs/{slug}` 404s for unknown slug, non-public, or closed job; returns only public-safe fields (no internal pay/bill rate, no recruiter notes).
- All three routes present in `API_KEY_ROUTE_EXEMPTIONS`; an API-key caller without scope is not 403'd on them.
- JOB-\* absent at runtime → list returns `{items: [], cursor: null}`, detail returns 404 (no 500).

**Dependencies:** PRT-001. Forward-dep: JOB-\* (`is_public` flag, open-status set, query helper, slug-row write).

---

### PRT-003: Jobs RSS / Atom feed

**Type:** Feature · **Priority:** P2 · **Estimate:** 0.5d

**Description**

A public RSS 2.0 feed of the same public+open postings, so job boards / aggregators can syndicate openings. Pure read-through over PRT-002's listing query; no new storage.

*Public endpoint (`public_router`, no auth):* `GET /public/careers/jobs.rss` → an `application/rss+xml` `Response` (the dependency-free XML-string pattern used by the calendar iCal builder `_build_ics` returned via `Response(media_type="text/calendar")` at `app/routers/calendar.py:2105-2109`; no feed library). Each `<item>` carries `<title>`, `<link>` = `{S.public_base_url}/public/careers/jobs/{slug}` (public_base_url at `app/core/settings.py`, same dev/prod — CMP-005 §2), `<guid>` = job_order_id, `<pubDate>` (RFC-822 from `posted_at`), `<description>` = a tag-stripped excerpt of the public description (the regex-strip excerpt helper from KB-011 §4.2 `_extract_excerpt`, dependency-free). Channel `<title>`/`<description>` come from `get_portal_config`. Capped at the most-recent N (e.g. 50) postings.

*Service:* `build_jobs_rss() -> str` in `app/services/career_portal.py`, XML-escaping all interpolated text (manual `&`/`<`/`>`/`"` escaping, dependency-free).

*`API_KEY_ROUTE_EXEMPTIONS`:* add `GET:/public/careers/jobs.rss`.

*Reuse cited:* KB-011 (public surface + `_extract_excerpt` strip helper), calendar iCal builder (`app/routers/calendar.py:2097-2109` — dependency-free text-payload `Response` pattern).

**Acceptance Criteria**
- Flag off → `GET /public/careers/jobs.rss` 404.
- Returns valid RSS 2.0 XML (`Content-Type: application/rss+xml`) listing only public+open postings; `<link>` points at the per-posting slug page.
- Special characters in titles/descriptions are XML-escaped (no malformed feed).
- Route present in `API_KEY_ROUTE_EXEMPTIONS`.
- JOB-\* absent → feed renders with an empty `<channel>` (valid, zero items), no 500.

**Dependencies:** PRT-001, PRT-002.

---

### PRT-004: Candidate self-apply endpoint → Candidate + pipeline "New/Applied"

**Type:** Feature · **Priority:** P1 · **Estimate:** 2.5d

**Description**

The core flow: a public, no-auth POST that creates a Candidate and adds it to the target job order's pipeline at the initial ranked status (OpenCATS "100 New / Applied" — `OPENCATS_GAP_ANALYSIS.md:67`). This adapts the CMP-006 / LED-005 web-to-lead public-capture plumbing (honeypot, per-IP rate-limit, best-effort side effects, anonymous audit) to the recruiting domain.

*Public endpoint (`public_router`, no auth — constraints 3,5):*
```
POST /public/careers/jobs/{slug}/apply  → CareerApplyOut
```
Resolves `{slug}`→job_order_id (PRT-001 row), validates the posting is public+open (else 404), then in `create_application(...)` (`app/services/career_portal.py`):
1. `_require_enabled()`.
2. **Honeypot:** non-empty `honeypot` field → return fake `CareerApplyOut(application_id="bot", status="received")`, **no DDB write** (CMP-006 §5.1).
3. **Rate-limit:** `_bucket_limit(f"ip#{ip}", "rl#career_apply", S.career_portal_apply_rate_limit_per_ip_per_hour, 3600)` → 429 on breach (CMP-006 §5.2; `rate_limit.py:60,81`). IP taken from `X-Forwarded-For` first hop, last-octet-zeroed before any persistence (CMP-006 §5.10).
4. **Email normalize** via `normalize_email` wrapped in try/except → fall back to raw on failure (CMP-006 §5.3 — `normalize_email` *raises* on bad input, `app/core/normalize.py:60`).
5. **Create Candidate** by lazy-importing the CND-\* service (`create_candidate(...)` analogous to LED-003 `create_lead` / LED-005 `create_lead_from_submission`, `docs/suitecrm/specs/LED-005.md:267-349`), passing first_name/last_name/email/phone, `source="career_portal"` and `origin_job_order_id`. Idempotent on email where CND-\* supports it (LED-005 §5.4).
6. **Add to pipeline** by lazy-importing the PIP-\* service: `add_candidate_to_pipeline(job_order_id, candidate_id, status="100")` (the initial ranked status). Best-effort try/except — a pipeline-add failure does not lose the candidate (CMP-006 §5.4 list-add pattern).
7. **Audit** `audit_event("career_portal.applied", "anonymous", application_id=..., job_order_id=..., candidate_id=...)` best-effort (constraint 10).
8. Return `CareerApplyOut(application_id, candidate_id, status="received")`.

Each cross-module call (CND-\*, PIP-\*) is lazy-imported + try/except so PRT-004 degrades gracefully when Tier-1 is absent (constraint 1; CMP-006 §5.8). Résumé + screening answers are layered on in PRT-005 (`create_application` accepts the optional `resume_ticket_id` / `screening_response_session_id` params there).

*Models (`app/models.py`):* `CareerApplyIn` (first_name/last_name ≥1 ≤120, email ≤254, phone optional, cover_note optional ≤4000, `honeypot: Optional[str] = None` — no max-length so long values still hit the honeypot path not a 422, CMP-006 §7); `CareerApplyOut` (application_id, candidate_id optional, status="received").

*`API_KEY_ROUTE_EXEMPTIONS`:* add `POST:/public/careers/jobs/{slug}/apply`.

*Reuse cited:* CMP-006 (public no-auth capture, honeypot, per-IP rate-limit, IP-anonymization, anonymous audit, lazy-import graceful degradation), LED-005 (`create_lead_from_submission` extraction/best-effort/never-raise shape — adapted to Candidate creation), KB-011 (flag-gated public surface), CND-\*/PIP-\* (candidate + pipeline services).

**Acceptance Criteria**
- Flag off → apply endpoint 404.
- Valid apply for a public+open posting → creates a Candidate and a pipeline entry at status `"100"` (New/Applied); returns `{status: "received", candidate_id: ...}`.
- Apply to unknown/non-public/closed slug → 404 (no candidate created).
- Honeypot filled → 200 fake-success, no Candidate / pipeline / audit write.
- > N applies/hour from one IP → 429; stored IP is last-octet-zeroed.
- Malformed email → capture still proceeds (raw value), not a 400.
- CND-\* or PIP-\* absent at runtime → endpoint still returns 200 with whatever subset succeeded; no 500 (graceful degradation).
- Route present in `API_KEY_ROUTE_EXEMPTIONS`.

**Dependencies:** PRT-001, PRT-002. Forward-dep: CND-\* (Candidate create), PIP-\* (pipeline add + initial ranked status).

---

### PRT-005: Résumé upload + optional per-posting screening questionnaire

**Type:** Feature · **Priority:** P1 · **Estimate:** 2d

**Description**

Two additive layers on PRT-004's apply flow: (a) a résumé uploaded from the portal, wired through the file manager + S3 presign and attached to the created Candidate; (b) an optional per-posting screening questionnaire whose responses are stored on the Candidate. Reuses the existing questionnaires repository + the CMP-005 questionnaire-link pattern.

**(a) Résumé upload (file manager + S3 presign).** Two-step, mirroring the existing presigned-upload flow (`presign_upload` → client PUT → `register_presigned_upload`, `app/services/filemanager.py:2207,2264`):
- `POST /public/careers/jobs/{slug}/resume-presign` → `CareerResumePresignOut` — public, no-auth, honeypot+rate-limited (same gates as apply). Validates content-type ∈ {pdf, doc, docx} and declared size ≤ `S.career_portal_resume_max_bytes`. Calls `presign_upload(user=<portal-system-user>, path=f"/career-portal/resumes/{job_order_id}/{uuid}.{ext}", content_type=...)`. The résumé is owned by a dedicated system file-manager user (e.g. `"system_career_portal"`) so anonymous uploads land in a controlled namespace; returns `{upload_url, ticket_id, key, path}`. Dev returns `/mock/s3/...`, prod a presigned URL — decided inside `presign_upload` (`filemanager.py:2223-2238`), no PRT branch (constraint 7).
- The apply POST (PRT-004) gains an optional `resume_ticket_id`. When present, `create_application` calls `register_presigned_upload(...)` to finalize the file-manager node, then attaches the resulting path to the Candidate via the CND-\* résumé-linkage method (CND "primary resume" linkage, `OPENCATS_GAP_ANALYSIS.md:46`), best-effort.

**(b) Per-posting screening questionnaire (reuse questionnaires + CMP-005 link pattern).** A job order may carry an optional `screening_questionnaire_id` (JOB-\* field; PRT reads it). PRT does **not** add questionnaire behavior — it links a published questionnaire to a posting and stores the response on the candidate, exactly as CMP-005 links a published questionnaire to a campaign (`docs/suitecrm/specs/CMP-005.md:10-19`):
- `CareerJobDetailOut.screening_questionnaire_slug` (PRT-002) is resolved by `REPO.get_questionnaire(screening_questionnaire_id)` → its published slug (validated `status="published"`, CMP-005 §4.2 `_validate_questionnaire_link`). The frontend renders the standard published questionnaire form at `/questionnaires/published/{slug}` (the existing public submit pipeline, `app/routers/questionnaires.py:644-819`) and obtains a submitted `response_session_id`.
- The apply POST gains an optional `screening_response_session_id`. When present, `create_application` reads the submitted answers via `REPO.list_session_answers(questionnaire_id, response_session_id)` (`questionnaires_repository.py:573`, decrypted on read per LED-005 §7.4) and stores them on the Candidate (a `screening_answers` map / sub-row), best-effort. This is the LED-005 "answers→entity" pattern (`docs/suitecrm/specs/LED-005.md:117-129`) re-pointed from Lead to Candidate.

*Models:* `CareerResumePresignIn` (filename, content_type, size_bytes, honeypot); `CareerResumePresignOut` (upload_url, ticket_id, key, path, content_type). Extend `CareerApplyIn` with optional `resume_ticket_id`, `screening_response_session_id`.

*`API_KEY_ROUTE_EXEMPTIONS`:* add `POST:/public/careers/jobs/{slug}/resume-presign`.

*Reuse cited:* file manager presign (`presign_upload`/`register_presigned_upload`, `app/services/filemanager.py:2207,2264`), questionnaires repository (`get_questionnaire`/`get_published_by_slug`/`list_session_answers`, `questionnaires_repository.py`), CMP-005 (`_validate_questionnaire_link` published-questionnaire link + published-URL build, `docs/suitecrm/specs/CMP-005.md`), LED-005 (submitted-answers→entity extraction, `docs/suitecrm/specs/LED-005.md`), CND-\* (candidate résumé + screening-answer storage).

**Acceptance Criteria**
- Flag off → `resume-presign` 404.
- `resume-presign` rejects non-{pdf,doc,docx} and oversize declarations; returns a usable `upload_url` (`/mock/s3/...` in dev) + `ticket_id`.
- Apply with a valid `resume_ticket_id` → finalizes the file node and links the résumé to the created Candidate; a failed finalize does not lose the candidate (best-effort).
- A posting linking a published questionnaire surfaces `screening_questionnaire_slug` in its detail; a draft/unpublished questionnaire is not surfaced (CMP-005 validation).
- Apply with `screening_response_session_id` → the submitted answers are stored on the Candidate; absence of it → apply still succeeds.
- `resume-presign` route present in `API_KEY_ROUTE_EXEMPTIONS`; honeypot + rate-limit enforced identically to apply.

**Dependencies:** PRT-002, PRT-004. Forward-dep: JOB-\* (`screening_questionnaire_id` field), CND-\* (résumé linkage + screening-answer storage). Reuses live: file manager, questionnaires.

---

### PRT-006: Hermetic pytest + E2E (apply → candidate → pipeline)

**Type:** Test · **Priority:** P1 · **Estimate:** 1.5d

**Description**

End-to-end coverage of the portal, grounded in the canonical hermetic patterns (CMP-006 §9, LED-005 §9, KB-011 §9).

**Hermetic pytest** (`tests/test_prt_career_portal.py`): moto in-memory `CareerPortal` table (+ fake/stubbed CND-\*/PIP-\*/JOB-\* collaborators, lazy-imported so they're patchable at the PRT-service namespace) bound to frozen `T`/`S` via `object.__setattr__`; route handlers invoked directly on a fresh `asyncio.new_event_loop()`; `S.career_portal_enabled` toggled per-test. Stub `audit_event` and `send_alert_email` to no-ops. Cases:
1. Flag-off → every public endpoint (`/config`, `/jobs`, `/jobs/{slug}`, `/jobs.rss`, `/apply`, `/resume-presign`) raises 404.
2. Admin config: PUT as ADMIN persists, GET reflects it; USER role → 403.
3. `/jobs` lists only public+open postings, newest-first, cursor round-trips (page 1 → cursor → page 2).
4. `/jobs/{slug}` returns public-safe fields only; unknown/non-public/closed slug → 404.
5. RSS: valid XML, only public+open items, `<link>` = slug page, special chars escaped; JOB-\* absent → empty channel, no 500.
6. Apply happy-path: creates Candidate (spy on `create_candidate`) + pipeline entry at status `"100"` (spy on `add_candidate_to_pipeline`); returns `received`.
7. Apply honeypot → fake success, zero DDB / spy calls.
8. Apply rate-limit → 429 on the (N+1)th call from one IP (mock `T.sessions` for `_bucket_limit`).
9. Apply malformed email → still captured (raw), 200 not 400.
10. Apply with CND-\*/PIP-\* raising → 200, no 500 (graceful degradation).
11. `resume-presign` returns an upload URL + ticket; bad content-type / oversize → 4xx.
12. Apply with `resume_ticket_id` → `register_presigned_upload` + candidate-résumé-link spies called; with `screening_response_session_id` → `list_session_answers` read and stored on candidate.
13. IP anonymization: stored `source_ip` last-octet-zeroed.

**E2E Playwright** (`frontend/e2e/career-portal.spec.ts`, `CAREER_PORTAL_ENABLED=1`):
- Public listing + slug detail render (unauthenticated `page.request`); non-public job not listed.
- Full apply chain: POST `/public/careers/jobs/{slug}/apply` → assert (via an admin/Bearer call into CND-\*/PIP-\* once those ship) the Candidate exists and sits in the job order's pipeline at New/Applied.
- Honeypot submission → no candidate appears.
- Admin branding: `injectAuth(page, "charlie_admin")` → PUT config → public `/config` reflects the new portal name/logo.
- Résumé presign → PUT to `upload_url` → apply with `resume_ticket_id` → résumé linked to candidate.
- Flag-off section (`CAREER_PORTAL_ENABLED=0`): all public endpoints 404.

*Reuse cited:* `tests/test_gap_0220_0221_ssh_stored_key.py` (hermetic isolation), CMP-006 §9 / LED-005 §9 / KB-011 §9 (test-plan shape), CLAUDE.md "Key E2E patterns" (`injectAuth`, Bearer-vs-session, public `page.request`).

**Acceptance Criteria**
- All pytest cases pass offline (no real AWS/network); `just test` green.
- E2E apply→candidate→pipeline chain asserts the candidate lands at the initial ranked status; honeypot/flag-off/branding sections pass.
- Tests assert graceful degradation when Tier-1 collaborators are stubbed-absent (no 500s).

**Dependencies:** PRT-001..PRT-005. Forward-dep (E2E candidate/pipeline assertions): JOB-\*, CND-\*, PIP-\*.
