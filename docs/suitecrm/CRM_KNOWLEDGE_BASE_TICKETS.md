# CRM Knowledge Base — Implementation Tickets

**Area**: Knowledge Base
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T3] Knowledge Base — 12 tickets")

## What SuiteCRM provides in this area

SuiteCRM's Knowledge Base (AOS KB) module provides: article CRUD with rich-text body editor, a Draft/Published/Expired status lifecycle with workflow transitions, file attachments per article (images, PDFs, docs), a hierarchical category tree, article helpfulness ratings (helpful/not helpful with aggregate counts), article view counters, related-article linking, a public/unauthenticated portal for browsing and searching published articles, full-text prefix search integrated into the global search aggregator, a tags/keywords system with tag-indexed queries, article revision history with prior-body snapshots, and an admin management UI for article editing, category management, and publish/expire controls.

## Cross-cutting constraints

- **Additive only, default-off**: All tickets are gated by `S.knowledge_base_enabled` (env `KNOWLEDGE_BASE_ENABLED`, default `"0"`). With the flag off all KB routes return 404 and all workers are no-ops. The existing `app/routers/tickets.py`, `app/services/tickets.py`, and all other files are byte-for-byte unchanged unless a ticket says otherwise.
- **CAS-015 is the immediate prerequisite**: `docs/suitecrm/CRM_CASES_PORTAL_TICKETS.md` ticket CAS-015 defines the `crm_kb_articles` DynamoDB table (`PK=ARTICLE#{id}`, `SK=META`), the `crm_cases_kb_enabled` sub-flag, the base `KbArticleService` class (`app/services/kb_articles.py`), and the core CRUD + publish/archive + rating + basic search surface. Every KB ticket in this file **extends** CAS-015's work — none duplicate it. The KB feature flag (`KNOWLEDGE_BASE_ENABLED`) introduced in KB-001 is an independent top-level flag that governs the additional capabilities (attachments, categories, full-text search index, tags, revisions, portal, admin UI, global search integration, view counter). `crm_cases_kb_enabled` remains the sub-flag that wires case-deflection suggestions on ticket create.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: All new tables and extra rows on `crm_kb_articles` follow the `TableDef` pattern at `scripts/local-ddb-init.py:29`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` — omitting causes `ValidationException` at query time (CLAUDE.md gotcha). All code runs the same path in dev (moto, `DDB_ENDPOINT_URL=http://localhost:8001`) and prod.
- **Reuse existing primitives — never fork**:
  - S3 upload: `app.core.aws_clients.s3_client` factory; pattern from `app/routers/newsfeed.py:3117` (`POST /uploads/image` with `put_object`).
  - Tag index pattern: `app/routers/newsfeed.py:440` (`_write_tag_index`, `TAG#{tag}` row on same table, `TAG_STATS` counter row).
  - Atomic DDB increment: `UpdateExpression="ADD view_count :one"` as in `app/services/stories.py:160`.
  - Search token index pattern: `app/services/filemanager.py:1709` (`TOKEN#{token}#USER#{user}` PK → per-path SK rows), adapted for `TOKEN#{token}/ARTICLE#{id}`.
  - Rich-text / markdown sanitization: `render_markdown_sanitized_html` at `app/routers/newsfeed.py:1186`.
  - Email notification: `app/services/alerts.send_alert_email` (`app/services/alerts.py:459`), `audit_event` (`app/services/alerts.py:644`).
  - Cursor pagination: `app/core/cursor.encode_cursor` / `decode_cursor` (`app/core/cursor.py:94`).
  - Auth: `app/services/sessions.require_ui_session` for authenticated endpoints; `app/auth/policy.require_admin_or_root` for admin paths.
  - Global search fan-out: `app/routers/search.py:645` (`_search_aggregator` — add a `_search_kb` function and register it in `search_fns`).
  - Public route exemptions: add `/public/kb/*` routes to `API_KEY_ROUTE_EXEMPTIONS` in `app/services/api_key_route_scope_registry.py:70`.
- **Hermetic offline tests**: All pytest must use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles — canonical form: `tests/test_gap_0220_0221_ssh_stored_key.py`. No real AWS or network calls.
- **Route ordering**: Static path segments declared **before** dynamic `{article_id}` segments in the FastAPI router to avoid `templates`, `search`, `categories`, `related`, `attachments`, `revisions` being swallowed as article IDs.

---

### KB-001: Knowledge Base feature flag, settings & DynamoDB scaffolding
**Type:** Chore  **Priority:** P0  **Estimate:** 1d

**Description**

Introduce the top-level `KNOWLEDGE_BASE_ENABLED` feature flag, all new table-name settings, and the additional DynamoDB tables and GSIs not already created by CAS-001. This ticket is pure scaffolding — no user-visible behaviour.

**Settings additions** (`app/core/settings.py`) — follow the bool-env pattern at line 1875 (`messaging_translation_enabled`):

```python
knowledge_base_enabled: bool = os.environ.get("KNOWLEDGE_BASE_ENABLED", "0") not in ("0", "false", "False")

# Table names
kb_articles_table: str = os.environ.get("KB_ARTICLES_TABLE", "crm_kb_articles")
kb_attachments_bucket: str = os.environ.get("KB_ATTACHMENTS_BUCKET", "local-uploads")
kb_attachments_s3_prefix: str = os.environ.get("KB_ATTACHMENTS_S3_PREFIX", "kb-attachments/")
kb_attachment_max_bytes: int = int(os.environ.get("KB_ATTACHMENT_MAX_BYTES", str(20 * 1024 * 1024)))
```

**DynamoDB extras** (`scripts/local-ddb-init.py`): CAS-001 already creates `crm_kb_articles` with two GSIs (`ByCategory` on `category`/`published_at` and `ByStatus` on `status`/`published_at`). Add the following additional GSIs to that same `TableDef`:

- `ByAuthor` — PK=`author_sub`, SK=`created_at` (numeric) — so admins can list their own articles.
- `ByTag` — PK=`tag`, SK=`created_at` (numeric) — for tag-scoped queries (tag index rows carry `SK=TAG#{tag}` pattern per KB-007).

Add `attr_types={"created_at": "N", "published_at": "N"}` on the table (CAS-001 should already declare `published_at: N`; reinforce here).

Wire the `T.kb_articles` handle in `app/core/tables.py` alongside `T.tickets` (line 140), using `S.kb_articles_table`. Update the `Tables` dataclass and the `T = Tables(...)` initializer.

**Acceptance Criteria**
- `S.knowledge_base_enabled` defaults `False`; togglable via `KNOWLEDGE_BASE_ENABLED=1`.
- `T.kb_articles` resolves without error in a smoke pytest (`T.kb_articles.table.name` is non-empty).
- `just restart` creates/updates `crm_kb_articles` with `ByAuthor` and `ByTag` GSIs; no `ValidationException`.
- No existing route, table, or flag is changed.

**Dependencies**
- CAS-001 (creates `crm_kb_articles` base table and `S.crm_cases_kb_enabled`). KB-001 extends CAS-001 — must run after CAS-001 in migration order.

---

### KB-002: Article status lifecycle — Draft / Published / Expired transitions
**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

Extend the `KbArticleService` introduced in CAS-015 with a proper three-state lifecycle (`draft → published → expired`), transition validation, `expires_at` field, background expiry checker, and `audit_event` emission on every transition.

**Service additions** (`app/services/kb_articles.py` — extends CAS-015):

- `KbArticleService.publish_article(article_id, admin_sub)`:
  - Validates current `status == "draft"` (raises `KbArticleStateError` otherwise).
  - Sets `status="published"`, `published_at=now_ts()` (integer).
  - Calls `audit_event("kb.article.published", admin_sub, article_id=article_id)` via `app/services/alerts.audit_event` (`app/services/alerts.py:644`).
- `KbArticleService.expire_article(article_id, admin_sub, *, reason: str = "")`:
  - Validates current `status == "published"`.
  - Sets `status="expired"`, `expired_at=now_ts()`, optional `expiry_reason`.
  - Calls `audit_event("kb.article.expired", ...)`.
- `KbArticleService.unpublish_to_draft(article_id, admin_sub)`:
  - Allows `published → draft` reset (e.g. for corrections before re-publish).
  - Sets `status="draft"`, clears `published_at`.
- `expires_at: int | None` field on the article DDB item (stored alongside `published_at`).
- `start_kb_expiry_checker_task()` — async background loop (registered via `app.add_event_handler("startup", ...)` in `app/main.py`, gated on `S.knowledge_base_enabled`). Runs every 3600 s. Queries `ByStatus` GSI (`status="published"`), filters `expires_at <= now_ts()`, calls `expire_article` for each. Best-effort: exceptions are logged, not raised.

**Router** (`app/routers/kb_articles.py` — extends CAS-015):
- `POST /kb/articles/{article_id}/publish` — admin-only.
- `POST /kb/articles/{article_id}/expire` — admin-only; body `{reason: str}`.
- `POST /kb/articles/{article_id}/unpublish` — admin-only.
- All three gated on `S.knowledge_base_enabled`; respond 404 if flag off.

**Acceptance Criteria**
- Newly created article has `status="draft"`.
- `POST .../publish` transitions to `published`; `GET /public/kb/articles/{id}` returns the article.
- `POST .../expire` transitions to `expired`; article no longer appears in public list.
- Background expiry checker promotes `expires_at`-past articles to `expired` status (verified by patching `now_ts`).
- `audit_event` is called for each transition (verified by patching `app.services.alerts.audit_event`).
- Hermetic pytest: moto `crm_kb_articles` table; `now_ts` patched.

**Dependencies**
- KB-001 (flag + table handle), CAS-015 (base `KbArticleService`).

---

### KB-003: Article file attachments (S3 upload + download)
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Allow admins to attach files (PDFs, images, Word documents) to KB articles. Attachments are stored in S3 under `{S.kb_attachments_s3_prefix}{article_id}/{attachment_id}/{safe_filename}` and metadata is recorded as `ATTACHMENT#{attachment_id}` sub-items on the `crm_kb_articles` table (same PK as article, separate SK).

**DDB layout extension** (no new table; same `crm_kb_articles` table):
- `PK=ARTICLE#{article_id}`, `SK=ATTACHMENT#{attachment_id}`.
- Fields: `attachment_id`, `article_id`, `filename`, `content_type`, `size_bytes`, `s3_key`, `uploaded_by`, `created_at` (integer).
- No GSI needed — always queried via PK (list attachments for an article).

**Service additions** (`app/services/kb_articles.py`):
- `KbArticleService.add_attachment(article_id, *, uploaded_by, filename, content_type, size_bytes, s3_key)` — writes `ATTACHMENT#` sub-item.
- `KbArticleService.list_attachments(article_id)` — queries `PK=ARTICLE#{article_id}`, `SK begins_with ATTACHMENT#`.
- `KbArticleService.delete_attachment(article_id, attachment_id, admin_sub)` — deletes DDB row (does not delete S3 key; soft-delete via `deleted_at`).
- `KbArticleService.get_attachment(article_id, attachment_id)` — fetches single attachment row or raises 404.

**Router** (`app/routers/kb_articles.py`):
- `POST /kb/articles/{article_id}/attachments` — multipart upload; reads bytes into memory (cap at `S.kb_attachment_max_bytes`); calls `s3_client().put_object(Bucket=S.kb_attachments_bucket, Key=s3_key, Body=content, ContentType=...)` (pattern: `app/routers/newsfeed.py:3133`); then `add_attachment(...)`. Admin-only.
- `GET /kb/articles/{article_id}/attachments` — returns list. Publicly accessible for published articles.
- `GET /kb/articles/{article_id}/attachments/{attachment_id}` — in dev, returns `/mock/s3/...` redirect; in prod, returns a 300-second S3 presigned URL (pattern: `app/services/kyc_partner_api.py get_document_download`). No auth required for published articles.
- `DELETE /kb/articles/{article_id}/attachments/{attachment_id}` — admin-only; soft-deletes.

**Pydantic models** (`app/models.py`):
- `KbAttachmentOut`: `attachment_id`, `article_id`, `filename`, `content_type`, `size_bytes`, `url`, `created_at`.

**Acceptance Criteria**
- `POST .../attachments` with a PDF multipart file stores it in S3 and returns `KbAttachmentOut`.
- `GET .../attachments` returns the list including the newly uploaded file.
- `GET .../attachments/{id}` returns a URL (mock in dev, presigned in prod).
- `DELETE .../attachments/{id}` soft-deletes; item no longer appears in list.
- Attachment max-bytes limit enforced: request over `KB_ATTACHMENT_MAX_BYTES` gets 413.
- Hermetic pytest: S3 client patched to `_FakeS3` in-memory dict; moto `crm_kb_articles` table.

**Dependencies**
- KB-001 (S3 prefix/bucket settings, `T.kb_articles`), CAS-015 (base service and article CRUD).

---

### KB-004: KB category tree (hierarchical categories with parent/child nesting)
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Implement a hierarchical category tree stored as `CATEGORY#{category_id}` / `META` rows on the `crm_kb_articles` table. Categories carry a `parent_id` field enabling unlimited depth, plus a materialized `path` string (e.g. `"Support > Billing > Refunds"`) for breadcrumbs.

**DDB layout** (same `crm_kb_articles` table — no new table):
- `PK=CATEGORY#{category_id}`, `SK=META`.
- Fields: `category_id`, `name`, `slug`, `parent_id` (empty string for root), `path` (materialized `/`-delimited label path), `description`, `sort_order` (integer), `created_by`, `created_at` (integer), `updated_at` (integer).
- No dedicated GSI — root categories queried via scan with `begins_with(pk, "CATEGORY#")` and `FilterExpression: attribute_not_exists(parent_id) OR parent_id = :empty`; children queried via scan + client-side filter (tree is small, typically < 200 nodes).

**Service additions** (`app/services/kb_articles.py`):
- `KbArticleService.create_category(name, slug, parent_id="", description="", sort_order=0, created_by)` — validates slug uniqueness, computes `path` by walking up parent chain, puts `CATEGORY#` row.
- `KbArticleService.update_category(category_id, *, admin_sub, **fields)` — updates name/description/sort_order; recomputes `path` if `parent_id` changes (cascades to children via scan + update).
- `KbArticleService.delete_category(category_id, admin_sub)` — soft-deletes; refuses if articles are assigned to this category (raises `KbCategoryNotEmptyError`).
- `KbArticleService.list_categories(parent_id=None)` — returns flat list, optionally filtered by parent; caller builds tree from flat list.
- `KbArticleService.get_category(category_id)`.

**Router** (`app/routers/kb_articles.py`):
- `GET /public/kb/categories` — no auth; returns flat list of all categories (client builds tree). Gated on `S.knowledge_base_enabled`.
- `GET /public/kb/categories/{category_id}` — no auth; single category with its `path`.
- `POST /kb/categories` — admin-only.
- `PUT /kb/categories/{category_id}` — admin-only.
- `DELETE /kb/categories/{category_id}` — admin-only; returns 409 if category has articles.
- All routes declared **before** `/{article_id}` in the router file.

**Acceptance Criteria**
- `POST /kb/categories` creates root category; `POST /kb/categories` with `parent_id` set creates child; `path` is `"Parent > Child"`.
- `DELETE` returns 409 when articles are assigned to the category.
- `GET /public/kb/categories` returns all categories including nested ones.
- `PUT .../categories/{id}` with new `parent_id` recomputes `path` correctly.
- Hermetic pytest: moto `crm_kb_articles` table.

**Dependencies**
- KB-001 (`T.kb_articles`), CAS-015 (base service). Articles already have `category` field (CAS-015); this ticket formalizes it as a foreign key to `CATEGORY#` rows.

---

### KB-005: Article ratings (helpful / not helpful aggregate)
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Allow authenticated users to rate articles as helpful or not-helpful. Ratings are stored per-user to prevent double-voting; aggregates (`helpful_count`, `not_helpful_count`) are updated atomically on the article META row.

CAS-015 defines the `rate_article(helpful: bool)` method on `KbArticleService` but does not include per-user deduplication or atomic increments. This ticket completes that contract.

**DDB layout** (same `crm_kb_articles` table):
- Rating row: `PK=ARTICLE#{article_id}`, `SK=RATING#{user_sub}`.
- Fields: `user_sub`, `helpful` (bool), `rated_at` (integer).
- No GSI — per-user lookup is always `get_item(PK, SK)`.

**Service update** (`app/services/kb_articles.py`):
- `KbArticleService.rate_article(article_id, user_sub, helpful: bool)`:
  1. `get_item` existing rating row.
  2. If already exists with same `helpful` value → return `{"ok": True, "already_rated": True}` (idempotent).
  3. If changing vote: subtract old direction (`ADD helpful_count :-1` or `not_helpful_count :-1`) then add new; delete old rating row; put new rating row.
  4. First-time vote: `ADD helpful_count :1` or `ADD not_helpful_count :1` (same `ADD` pattern as `app/services/stories.py:160`); put rating row.
- Returns current aggregate counts from the updated article META.

**Router** (`app/routers/kb_articles.py`):
- `POST /kb/articles/{article_id}/rate` — requires `require_ui_session`; body `{helpful: bool}`. Returns `{ok, helpful_count, not_helpful_count, already_rated}`.

**Pydantic models** (`app/models.py`):
- `KbRateReq`: `helpful: bool`.
- `KbRateOut`: `ok: bool`, `helpful_count: int`, `not_helpful_count: int`, `already_rated: bool`.

**Acceptance Criteria**
- First `POST .../rate` with `helpful=true` → `helpful_count` incremented; rating row written.
- Second `POST .../rate` with same value → `already_rated=true`, counts unchanged (idempotent).
- Changing vote (true → false) → `helpful_count` decremented, `not_helpful_count` incremented.
- Unauthenticated request → 401.
- Hermetic pytest: moto `crm_kb_articles` table; three scenarios tested.

**Dependencies**
- KB-001 (flag), CAS-015 (base `rate_article` stub and `helpful_count`/`not_helpful_count` fields on META row).

---

### KB-006: Article view counter (atomic increment on GET)
**Type:** Feature  **Priority:** P2  **Estimate:** 0.5d

**Description**

Atomically increment `view_count` on the article META row each time a published article is fetched via the public GET endpoint. CAS-015 defines `increment_view_count` on the service but does not wire it into the router. This ticket wires it and adds per-user deduplication within a 24-hour window.

**Service update** (`app/services/kb_articles.py`):
- `KbArticleService.increment_view_count(article_id)`:
  - Calls `T.kb_articles.update_item(Key={"pk": f"ARTICLE#{article_id}", "sk": "META"}, UpdateExpression="ADD view_count :one", ExpressionAttributeValues={":one": 1})` (pattern: `app/services/stories.py:160`).
  - Wrapped in `try/except` — view count failure must never block article delivery.
- `KbArticleService.record_view(article_id, viewer_id)`:
  - Writes a `VIEW#{viewer_id}` sub-item (PK=`ARTICLE#{article_id}`, SK=`VIEW#{viewer_id}`) with `ttl` = `now_ts() + 86400` (24-hour DDB TTL so the same viewer increments at most once per day).
  - Calls `increment_view_count` only when no existing `VIEW#` row exists (`put_item` with `condition_expression=Attr("pk").not_exists()`; catches `ConditionalCheckFailedException` and skips increment).

**Router** (`app/routers/kb_articles.py`):
- `GET /public/kb/articles/{article_id}` — no auth required. After returning article data, fire-and-forget call to `record_view(article_id, viewer_id=request.client.host)` using client IP as anonymous viewer proxy when unauthenticated.
- `GET /kb/articles/{article_id}` — authenticated version; uses `user_sub` as `viewer_id`.

**Acceptance Criteria**
- First `GET /public/kb/articles/{id}` → `view_count` incremented to 1.
- Repeated GET within 24h from same viewer → `view_count` stays at 1 (deduplicated by `VIEW#` row).
- View count failure (DDB error) does not block article response.
- Hermetic pytest: moto table; `ConditionalCheckFailedException` path tested.

**Dependencies**
- KB-001 (flag, `T.kb_articles`), CAS-015 (base `get_article` endpoint, `view_count` field on META).

---

### KB-007: Article tags / keywords (tag index + tag-scoped browse)
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Allow admins to assign a list of normalized keyword tags to an article. Tags are indexed so that articles can be browsed and filtered by tag. Uses the same `TAG#{tag}` index pattern as `app/routers/newsfeed.py:440` (`_write_tag_index`).

**DDB layout extension** (same `crm_kb_articles` table):
- Tag index row: `PK=TAG#{tag}`, `SK=ARTICLE#{article_id}` (so querying PK=`TAG#password` lists all articles tagged "password").
- Fields: `article_id`, `tag`, `published_at` (integer, copy of article `published_at` — enables sorted queries).
- Queried via DDB `query(PK="TAG#{tag}")` on `crm_kb_articles` (uses the `ByTag` GSI if available, otherwise simple query since PK is hash key already on the table).
- `TAG_STATS` row: `PK=KB_TAG_STATS`, `SK=TAG#{tag}`, `count` (integer updated via `ADD`) — mirrors `app/routers/newsfeed.py:453`.

**Service additions** (`app/services/kb_articles.py`):
- `_normalize_tag(raw: str) -> str` — lowercase, strip leading `#`, keep only `[a-z0-9_-]`, max 50 chars.
- `_write_kb_tag_index(article_id, tags, published_at)` — batch-writes `TAG#{tag}` rows (mirrors `_write_tag_index` at `app/routers/newsfeed.py:440`); updates `KB_TAG_STATS` counter with `ADD count :1`.
- `_delete_kb_tag_index(article_id, old_tags)` — batch-deletes tag index rows when tags are removed or article is expired.
- `KbArticleService.set_tags(article_id, tags: list[str], admin_sub)` — normalizes tags (max 20), diffs against stored tags, calls `_write_kb_tag_index` / `_delete_kb_tag_index`, updates `tags` StringSet on META row.
- `KbArticleService.list_articles_by_tag(tag, limit=25, cursor=None)` — queries `PK=TAG#{normalize(tag)}`, returns article summaries.
- `KbArticleService.list_popular_tags(limit=50)` — scans `PK=KB_TAG_STATS`, sorts by `count` desc.

**Router** (`app/routers/kb_articles.py`):
- `GET /public/kb/tags` — no auth; returns popular tags. Gated on `S.knowledge_base_enabled`.
- `GET /public/kb/tags/{tag}/articles` — no auth; lists published articles for a tag; cursor-paginated.
- `PUT /kb/articles/{article_id}/tags` — admin-only; body `{tags: list[str]}`; replaces tag set.

**Acceptance Criteria**
- `PUT /kb/articles/{id}/tags` with `["billing", "refunds"]` writes two `TAG#billing` and `TAG#refunds` index rows.
- `GET /public/kb/tags/billing/articles` returns the tagged article.
- `PUT .../tags` with empty list removes all tag rows.
- `GET /public/kb/tags` returns popular tags sorted by count.
- Tag normalization: `" #Billing "` → `"billing"`.
- Hermetic pytest: moto table; tag write and query paths tested.

**Dependencies**
- KB-001 (flag, `T.kb_articles` with `ByTag` GSI), CAS-015 (article META row has `tags` StringSet field).

---

### KB-008: Related articles linking
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Allow admins to link articles as "related". Related links are bidirectional: adding A→B also adds B→A. Links are stored as `RELATED#{source_article_id}` / `ARTICLE#{target_article_id}` rows on the `crm_kb_articles` table.

**DDB layout** (same `crm_kb_articles` table):
- Link row: `PK=RELATED#{source_id}`, `SK=ARTICLE#{target_id}`.
- Fields: `source_id`, `target_id`, `linked_by`, `created_at` (integer).
- Reverse row also written: `PK=RELATED#{target_id}`, `SK=ARTICLE#{source_id}` (same fields, `source_id`/`target_id` swapped).
- No GSI needed — always accessed by PK.

**Service additions** (`app/services/kb_articles.py`):
- `KbArticleService.add_related(article_id, related_id, linked_by)` — validates both articles exist; writes forward and reverse rows in a `batch_writer` call; idempotent (conditional put with `attribute_not_exists(pk)`).
- `KbArticleService.remove_related(article_id, related_id, admin_sub)` — deletes both forward and reverse rows.
- `KbArticleService.list_related(article_id, limit=10)` — queries `PK=RELATED#{article_id}`, batch-fetches article summaries for each target.

**Router** (`app/routers/kb_articles.py`):
- `GET /public/kb/articles/{article_id}/related` — no auth; returns list of related article summaries.
- `POST /kb/articles/{article_id}/related` — admin-only; body `{related_article_id: str}`.
- `DELETE /kb/articles/{article_id}/related/{related_article_id}` — admin-only.

**Acceptance Criteria**
- `POST /kb/articles/A/related` with `{related_article_id: "B"}` → both `RELATED#A/ARTICLE#B` and `RELATED#B/ARTICLE#A` rows written.
- `GET /public/kb/articles/A/related` returns article B summary.
- `GET /public/kb/articles/B/related` returns article A summary (bidirectional verified).
- `DELETE /kb/articles/A/related/B` removes both rows; neither appears in related lists.
- Hermetic pytest: moto table; bidirectionality and idempotency tested.

**Dependencies**
- KB-001 (`T.kb_articles`), CAS-015 (article get/existence check).

---

### KB-009: Full-text search token index + global search integration
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Add a proper inverted-token search index for KB articles (instead of DDB `scan + contains`) and integrate KB results into the platform's global search aggregator at `app/routers/search.py`.

**Token index pattern** (same `crm_kb_articles` table — mirrors `app/services/filemanager.py:1709`):
- Index rows: `PK=SEARCH_TOKEN#{token}`, `SK=ARTICLE#{article_id}`.
- Fields: `article_id`, `title_snippet` (first 80 chars of title), `published_at` (integer), `status`.
- Tokens generated from `title` words only (max prefix length 8 chars — same cap as messaging search, see CLAUDE.md note on `_MSG_SEARCH_MAX_PREFIX_LEN`), all lowercase, alphanumeric + hyphen only. Max 60 tokens per article.

**Service additions** (`app/services/kb_articles.py`):
- `_build_kb_search_tokens(title: str) -> list[str]` — tokenizes title, generates prefixes of length 3–8 for each word, deduplicates; mirrors `_search_tokens` in `app/services/filemanager.py:966`.
- `_write_kb_search_index(article_id, title, published_at)` — batch-writes `SEARCH_TOKEN#` rows.
- `_delete_kb_search_index(article_id, old_title)` — batch-deletes old token rows.
- `KbArticleService.search_articles(q: str, limit=25) -> list[KbArticleSummaryOut]`:
  - Normalizes `q`, splits into at most 3 tokens.
  - For the first token: queries `PK=SEARCH_TOKEN#{prefix}` to get candidate `article_id` set.
  - Client-side filters candidates to those matching all remaining token prefixes (via `contains` on `title_snippet` in memory or a second DDB query).
  - Fetches article META for each candidate (batch_get), filters `status="published"`.
  - Returns sorted by `published_at` desc.
- Wire `_write_kb_search_index` into `create_article` and `update_article` (on title change) and `publish_article`.
- Wire `_delete_kb_search_index` into `expire_article` and `archive_article`.

**Global search integration** (`app/routers/search.py`):
- Add `_search_kb(q: str, limit: int) -> Dict[str, Any]` function (pattern: `_search_tickets` at line 401). Calls `KbArticleService().search_articles(q, limit=limit)` when `S.knowledge_base_enabled`. Returns `_empty_section()` when flag off.
- Add `"kb"` to `ALLOWED_TYPES` in the global search (line 43) when `_EXTENDED_SEARCH` is true.
- Register in `_search_aggregator` (line 645): `search_fns["kb"] = lambda: _search_kb(q, limit)`.
- Add `GET:/ui/search` KB paths to `API_KEY_ROUTE_EXEMPTIONS` for the public portal (articles are already public, so KB results are safe to return without API key scope).

**Acceptance Criteria**
- `POST /kb/articles` with title `"How to reset your password"` → `SEARCH_TOKEN#how`, `SEARCH_TOKEN#to`, `SEARCH_TOKEN#reset`, `SEARCH_TOKEN#your`, `SEARCH_TOKEN#password` (prefix variants) rows created.
- `GET /public/kb/search?q=password` (and `GET /ui/search?q=password&types=kb`) → returns the article.
- Search returns empty list (not error) when flag off.
- Updating article title deletes old token rows and writes new ones.
- Hermetic pytest: moto table; token write, query, and global-search integration tested.

**Dependencies**
- KB-001 (flag), CAS-015 (`search_articles` stub), KB-002 (publish hook wires index write). Does not require KB-004/005/006/007/008.

---

### KB-010: Article revision history / versioning
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Store a snapshot of the article body every time an admin saves an update. Revisions are stored as `REVISION#{article_id}` / `REV#{zero-padded-ts}#{revision_id}` rows on the `crm_kb_articles` table, enabling admins to view prior versions and optionally restore.

**DDB layout** (same `crm_kb_articles` table):
- Revision row: `PK=REVISION#{article_id}`, `SK=REV#{ts:012d}#{revision_id}`.
- Fields: `revision_id` (uuid), `article_id`, `rev_number` (integer, auto-incremented), `title_snapshot`, `body_html_snapshot`, `tags_snapshot`, `edited_by`, `edit_note` (optional), `created_at` (integer).
- Queried via `query(PK="REVISION#{article_id}", ScanIndexForward=False)` — newest first, using numeric-padded SK for correct sort.
- `rev_number` is maintained by `ADD rev_counter :1` on the article META row (atomic increment — pattern: `app/services/invoices.py:87` `ADD next_seq :inc`).

**Service additions** (`app/services/kb_articles.py`):
- `KbArticleService._snapshot_revision(article_id, current_item, edited_by, edit_note)` — private helper; writes `REVISION#` row with current title/body_html/tags as snapshot.
- `KbArticleService.update_article(article_id, admin_sub, *, title, body_html, edit_note="", **fields)` — updated to call `_snapshot_revision` before applying the update (so the snapshot is of the pre-update state). Only snapshots when `title` or `body_html` actually changes.
- `KbArticleService.list_revisions(article_id, limit=20, cursor=None)` — queries `REVISION#{article_id}`, cursor-paginated using `app/core/cursor.encode_cursor`.
- `KbArticleService.get_revision(article_id, revision_id)` — returns single revision row.
- `KbArticleService.restore_revision(article_id, revision_id, admin_sub)` — copies `title_snapshot`/`body_html_snapshot`/`tags_snapshot` back to META, snapshots the current state before restore, calls `_write_kb_search_index`.

**Router** (`app/routers/kb_articles.py`):
- `GET /kb/articles/{article_id}/revisions` — admin-only; returns cursor-paginated list.
- `GET /kb/articles/{article_id}/revisions/{revision_id}` — admin-only; returns single revision.
- `POST /kb/articles/{article_id}/revisions/{revision_id}/restore` — admin-only; body `{edit_note: str}`.

**Pydantic models** (`app/models.py`):
- `KbRevisionOut`: `revision_id`, `rev_number`, `title_snapshot`, `body_html_snapshot`, `tags_snapshot`, `edited_by`, `edit_note`, `created_at`.

**Acceptance Criteria**
- `PUT /kb/articles/{id}` with new body → revision row written with old body snapshot; `rev_number` incremented.
- `GET /kb/articles/{id}/revisions` returns the revision(s) in newest-first order.
- `POST .../revisions/{rev_id}/restore` restores title + body; new revision row records the pre-restore state.
- No revision written when body/title are unchanged (update with only `tags` changed → no snapshot).
- Hermetic pytest: moto table; snapshot, list, and restore paths tested; `rev_number` sequence verified.

**Dependencies**
- KB-001 (flag, `T.kb_articles`), CAS-015 (base `update_article`), KB-009 (search index rebuild on restore).

---

### KB-011: Public KB portal (unauthenticated article browsing & search)
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Publish a complete set of unauthenticated public endpoints for the KB portal (CAS-015 defines `GET /public/kb/articles` and `GET /public/kb/articles/{id}` but does not add category browse, tag browse, or search to the public surface). This ticket also wires those public routes into `API_KEY_ROUTE_EXEMPTIONS` so they work without an API key.

**Public router** (`app/routers/kb_articles.py` — all routes gated on `S.knowledge_base_enabled`):
- `GET /public/kb/articles` — no auth. Query params: `category_id`, `tag`, `status="published"` (only published visible to public), `limit=25`, `cursor`. Returns `{items: list[KbArticleSummaryOut], cursor, total_estimate}`. Sorted by `published_at` desc.
- `GET /public/kb/articles/{article_id}` — no auth. Returns `KbArticleOut` if `status="published"`; 404 otherwise. Triggers `record_view` (KB-006).
- `GET /public/kb/search` — no auth. Query param `q` (min 2, max 100 chars). Calls `KbArticleService.search_articles(q)` (KB-009). Returns `{items: list[KbArticleSummaryOut]}`.
- `GET /public/kb/categories` — defined in KB-004; formally part of the public portal surface.
- `GET /public/kb/tags` — defined in KB-007; part of public portal surface.

**API key exemptions** (`app/services/api_key_route_scope_registry.py`): add entries to `API_KEY_ROUTE_EXEMPTIONS` (line 70):
```python
"GET:/public/kb/articles": {"reason": "Public unauthenticated KB portal"},
"GET:/public/kb/articles/{article_id}": {"reason": "Public unauthenticated KB portal"},
"GET:/public/kb/search": {"reason": "Public unauthenticated KB portal"},
"GET:/public/kb/categories": {"reason": "Public unauthenticated KB portal"},
"GET:/public/kb/tags": {"reason": "Public unauthenticated KB portal"},
"GET:/public/kb/tags/{tag}/articles": {"reason": "Public unauthenticated KB portal"},
```

**Pydantic models** (`app/models.py`):
- `KbArticleSummaryOut`: `article_id`, `title`, `status`, `category_id`, `tags`, `view_count`, `helpful_count`, `not_helpful_count`, `published_at`, `excerpt` (first 200 chars of `body_html` stripped to plain text).
- `KbArticleOut`: all of `KbArticleSummaryOut` plus `body_html`, `author_sub`, `created_at`, `updated_at`, `attachments: list[KbAttachmentOut]`.

**Acceptance Criteria**
- `GET /public/kb/articles` returns published articles without auth.
- `GET /public/kb/articles/{id}` for a draft article returns 404.
- `GET /public/kb/search?q=reset` returns articles matching the query.
- All public routes return 404 when `KNOWLEDGE_BASE_ENABLED=0`.
- Public routes do not require `Authorization` header or `X-API-Key`.
- Hermetic pytest: moto table; public list, get, search, and flag-off paths tested.

**Dependencies**
- KB-001 (flag), CAS-015 (base public endpoints), KB-002 (published status), KB-003 (attachments in `KbArticleOut`), KB-004 (categories), KB-006 (view counter), KB-007 (tags), KB-009 (search).

---

### KB-012: Admin KB management UI (React frontend)
**Type:** Feature  **Priority:** P2  **Estimate:** 3d

**Description**

Build the admin-facing React frontend for managing Knowledge Base articles, categories, tags, and revisions. The public portal browsing page is delivered as part of this ticket (linked from the main navigation for non-admin users).

**Frontend files** (all new):

`frontend/src/api/endpoints/kb.ts`:
- Axios wrappers for all KB API endpoints: `listArticles`, `getArticle`, `createArticle`, `updateArticle`, `publishArticle`, `expireArticle`, `deleteArticle`, `rateArticle`, `listRevisions`, `restoreRevision`, `listCategories`, `createCategory`, `updateCategory`, `deleteCategory`, `setTags`, `addRelated`, `removeRelated`, `listAttachments`, `uploadAttachment`, `deleteAttachment`, `searchArticles`.

`frontend/src/api/types.ts` additions:
- `KbArticle`, `KbArticleSummary`, `KbCategory`, `KbRevision`, `KbAttachment`, `KbRateResult` TypeScript interfaces mirroring `app/models.py` additions.

`frontend/src/pages/knowledge/` (new directory):
- `KbAdminPage.tsx` — article list with create/edit/publish/expire actions. Uses `useQuery(["kb", "articles"])` and `useMutation`. Table columns: title, category, status badge, published_at, view_count, helpful/not-helpful ratio. Gated on `user.role >= "admin"`.
- `KbArticleEditorPage.tsx` — rich-text body editor (use `<textarea>` with `body_html` for MVP; add a Markdown preview pane reusing `render_markdown_sanitized_html` output). Fields: title, category selector (dropdown from `/public/kb/categories`), tags input (comma-separated), expiry date picker, body. Save → draft; separate Publish button calls `POST .../publish`.
- `KbCategoryEdminPage.tsx` — category tree view with inline create/rename/reorder/delete controls.
- `KbRevisionDrawer.tsx` — side drawer showing revision history list; click a revision to diff preview; Restore button calls `POST .../restore`.
- `KbPublicPage.tsx` — public-facing article browser: search bar, category sidebar, article cards with excerpt, tag chips, helpful rating buttons. Accessible at `/knowledge` (no auth required).
- `KbArticlePage.tsx` — individual article view: full `body_html` rendered, attachment download list, related articles panel, helpful/not-helpful buttons.

`frontend/src/App.tsx`:
- Add routes (lazy-loaded):
  - `/knowledge` → `KbPublicPage`
  - `/knowledge/:articleId` → `KbArticlePage`
  - `/admin/knowledge` → `KbAdminPage` (role-gated)
  - `/admin/knowledge/categories` → `KbCategoryAdminPage`
  - `/admin/knowledge/articles/new` → `KbArticleEditorPage`
  - `/admin/knowledge/articles/:articleId/edit` → `KbArticleEditorPage`

Navigation: add "Knowledge Base" link to the admin sidebar (if `user.role >= "admin"`) and a "Help Center" link in the main sidebar for all authenticated users pointing to `/knowledge`.

**Acceptance Criteria**
- Admin can navigate to `/admin/knowledge`, see article list, create a draft, publish it.
- Published article appears at `/knowledge` and `/knowledge/{articleId}`.
- Category selector in editor shows hierarchical categories; new category can be created from inline form.
- Article body renders HTML correctly; attachments appear as download links.
- Related articles panel shows linked articles with click-through.
- Revision drawer shows history; Restore button returns body to prior version.
- Helpful/not-helpful buttons update counts optimistically; React Query invalidates `["kb", "articles", articleId]`.
- E2E Playwright spec `frontend/e2e/knowledge-base.spec.ts` covers: admin CRUD (create/publish/expire), public browse, search, and helpful rating — all behind `KNOWLEDGE_BASE_ENABLED=1` seeded via `e2e_admin_session_setup.py`.

**Dependencies**
- All KB-001 through KB-011 (full backend surface).

---
