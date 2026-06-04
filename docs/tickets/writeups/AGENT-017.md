# AGENT-017: Marketing Agent — Investigation & Implementation Write-up

## 1. Summary & Classification

The Marketing Agent is a user-owned content-production pipeline that turns completed feature tickets into marketing collateral: blog posts, social media copy, newsletters, release notes, changelogs, SEO metadata, and landing page copy. It owns a full content lifecycle state machine (draft → review → approved → scheduled → published → archived), a content calendar, per-content engagement tracking (views/clicks/signups/shares), configurable brand-voice and audience settings, and a deterministic (mockable) generation path wired to the platform ticketing system.

- **Type**: Feature (new agent type)
- **Priority**: Medium
- **Status**: Implemented — backend service, router, frontend pages, and settings are all live
- **Persona**: Platform owner (any authenticated user who wants automated marketing collateral)
- **Cross-references**: AGENT-001 (registry), AGENT-003 (worker framework), AGENT-005 (context injection), AGENT-018 (cost tracking), INFRA-005 (compute cost)
- **Dev/Prod parity**: SECOPS-007 compliant — LLM execution gated behind `MARKETING_AGENT_EXECUTE_COMMANDS=0` (default off); deterministic mock path always used in dev and E2E

---

## 2. Current-State Investigation

### 2.1 Backend service (`app/services/agent_marketing.py`)

The service is fully implemented at `app/services/agent_marketing.py` (976 lines). The public API:

- **`create_content`** (line 294): validates `content_type` against a 9-value tuple (`CONTENT_TYPES`, line 43), enforces title ≤ 200 chars and body ≤ 20 000 chars, stores the item with `pk=USER#{user_id}`, `sk=CONTENT#{content_id}`, three GSIs for type, status, and scheduled date queries. JSON-encoded fields (`feature_refs`, `tags`, `seo_meta`, `variations`) serialised as strings in DDB; decoded by `_decode_json_field` (line 249).
- **`list_content`** (line 373): routes to GSI2 (status filter), GSI1 (type filter), or base table query depending on provided params; returns paginated cursor via `encode_cursor`/`decode_cursor`.
- **`approve_content`** (line 496), **`schedule_content`** (line 507), **`publish_content`** (line 529), **`archive_content`** (line 545), **`delete_content`** (line 553): deterministic state machine. `schedule_content` validates `publish_at > now_ts()` and writes `GSI3PK/GSI3SK` for calendar queries. `delete_content` guards `status == "draft"` before `delete_item`.
- **`get_calendar`** (line 589): queries `GSI3` for `GSI3PK = USER#{user_id}#SCHEDULED` with `GSI3SK between(start, end)`, then does a full-partition scan for published items whose `published_at` falls in the month window.
- **`record_engagement`** (line 643): atomic `ADD :one` increment on `T.marketing_engagement`, key `CONTENT#{content_id} / DAY#{YYYY-MM-DD}`, 365-day TTL.
- **`get_engagement_stats`** (line 667): ownership-check via `_get_item`, then queries engagement daily rows for the last N days, aggregates totals + per-variant breakdown.
- **`get_engagement_summary`** (line 720): full-partition scan of all the user's content, then calls `get_engagement_stats` per item, aggregates globally.
- **`generate_content_for_feature`** (line 916): deterministic template-based generation (`_generate_one`, line 836) — no LLM call when `S.marketing_agent_execute_commands` is falsy (default). Reads ticket subjects/descriptions from `tickets_svc.STORE.get_ticket(tid)` (line 942). Always creates drafts; never auto-publishes (security §7).

**Table bootstrap**: `ensure_tables()` (line 116) is idempotent and self-contained — creates `marketing_content`, `marketing_engagement`, and `agent_types` tables on first call if absent. The canonical definitions also live in `scripts/local-ddb-init.py`.

### 2.2 Backend router (`app/routers/agent_marketing.py`)

Fully implemented (277 lines). Prefix: `/ui/agents/marketing` (line 36). All 14 endpoints are present:

| Method | Path | Service call |
|--------|------|-------------|
| GET | `/content` | `svc.list_content` |
| POST | `/content` | `svc.create_content` |
| GET | `/content/{content_id}` | `svc.get_content` |
| PUT | `/content/{content_id}` | `svc.update_content` |
| POST | `/content/{content_id}/approve` | `svc.approve_content` |
| POST | `/content/{content_id}/schedule` | `svc.schedule_content` |
| POST | `/content/{content_id}/publish` | `svc.publish_content` |
| POST | `/content/{content_id}/archive` | `svc.archive_content` |
| DELETE | `/content/{content_id}` | `svc.delete_content` |
| GET | `/calendar` | `svc.get_calendar` |
| GET | `/content/{content_id}/engagement` | `svc.get_engagement_stats` |
| GET | `/engagement/summary` | `svc.get_engagement_summary` |
| GET/PUT | `/config` | `svc.get/update_marketing_config` |
| POST | `/generate` | `svc.generate_content_for_feature` |

Auth: all endpoints use `Depends(require_ui_session)`. User scope is enforced by embedding `user_id` in every DDB key — cross-tenant access is structurally impossible. State-machine violations (e.g., approving an already-published item) raise 409.

Router registered in `app/main.py` at lines 781–782 (unconditional, inside the large `try` block that loads all feature routers).

### 2.3 Settings (`app/core/settings.py:2251–2258`)

```
marketing_agent_enabled         = MARKETING_AGENT_ENABLED       (default "1"=true)
marketing_content_table_name    = MARKETING_CONTENT_TABLE_NAME  (default "marketing_content")
marketing_engagement_table_name = MARKETING_ENGAGEMENT_TABLE_NAME (default "marketing_engagement")
marketing_agent_execute_commands= MARKETING_AGENT_EXECUTE_COMMANDS (default "0"=false)
marketing_agent_auto_publish    = MARKETING_AGENT_AUTO_PUBLISH   (default "0"=false)
```

The `execute_commands` flag is the key dev/prod parity gate: when false (always in dev/E2E), `generate_content_for_feature` uses the deterministic template producer and never contacts an external LLM.

### 2.4 Table handles (`app/core/tables.py:280–281,515–516`)

`T.marketing_content` and `T.marketing_engagement` are both wired via `_safe_table`. The `agent_types` table (`T.agent_types`, line 267/502) is shared with other agent types for configuration storage.

### 2.5 Frontend

- **Pages**: `MarketingContentDashboardPage.tsx`, `MarketingContentEditorPage.tsx`, `MarketingContentCalendarPage.tsx`, `MarketingEngagementDashboardPage.tsx` all exist under `frontend/src/pages/agents/`.
- **API client**: `frontend/src/api/endpoints/marketingAgent.ts` provides all wrappers.
- **Routes**: `/agents/marketing`, `/agents/marketing/content/:contentId`, `/agents/marketing/calendar`, `/agents/marketing/engagement` are present in `frontend/src/App.tsx`.

### 2.6 Dev vs Prod behaviour

| Concern | Dev (local DDB + mock) | Prod (AWS DDB) |
|---------|----------------------|----------------|
| Table storage | DDB Local port 8001; `ensure_tables()` auto-creates on first request | AWS DDB on-demand; tables pre-created by infra pipeline |
| Content generation | Deterministic template (`MARKETING_AGENT_EXECUTE_COMMANDS=0`) | Real LLM call when `execute_commands=true` |
| Social publishing | No-op (no OAuth credentials in dev) | OAuth tokens from Secrets Manager |
| Engagement tracking | Same atomic `ADD` path; data ephemeral per `just restart` | Persistent; 365-day TTL |

---

## 3. Gap / Threat Analysis

### 3.1 What exists (verified)

- Full CRUD lifecycle with correct state machine enforcement
- GSI-backed type/status/calendar queries with numeric sort-key attributes properly declared
- Deterministic content generation from tickets (never requires a live LLM)
- Engagement atomic counters with 365-day DDB TTL
- Per-user config stored on `agent_types` table; brand voice/audience/A/B settings
- All Pydantic models in `app/models.py` (verified: `MarketingContentOut`, `EngagementStatsOut`, `CalendarEntryOut`, `MarketingGenerateResultOut`, etc.)

### 3.2 Remaining gaps

1. **No scheduled-publish background loop**: `schedule_content` sets `GSI3SK` and `status=scheduled`, but there is no background task that promotes scheduled content to `published` when `now_ts() >= scheduled_publish_at`. The ticket spec describes a "background loop every 30s", but it does not yet exist in `app/main.py`.
2. **`get_engagement_summary` is O(N content × 1 DDB query)**: each call scans all content then issues one engagement query per item. For users with many content pieces this will be slow (no pre-aggregated summary row).
3. **No real A/B test split tracking**: the engagement table stores `variant_id` per daily row, but there is no endpoint to register an impression against a specific variant — `record_engagement` accepts `variant_id` but the frontend does not currently call it with split-test context.
4. **`generate_content_for_feature` uses `tickets_svc.STORE.get_ticket`**: this works only when the ticket data is in the in-process ticket store. If tickets live solely in DDB (as they do in prod), `get_ticket` may return `None` for most IDs, silently skipping generation. The missing IDs are reported in `missing_ticket_ids` in the response, so the failure is observable.
5. **No feature-completion trigger integration**: the ticket spec describes an auto-trigger when a ticket transitions to `done`. This hook is not yet wired in the ticket status-transition code (`app/services/tickets.py`).

### 3.3 Error handling verification

- `schedule_content` with past `publish_at`: returns 400 "publish_at must be in the future" (line 516)
- Invalid `content_type`: returns 422 "Invalid content_type: {value}" (line 291)
- Status transition violation (e.g., approve a scheduled item): returns 409 (router line 128)
- Content not found: 404 with `{"code": "content_not_found", ...}` (router line 50-53)
- Delete non-draft content: 409 "Only draft content can be deleted; use archive instead" (service line 559)

---

## 4. Proposed Design / Fix

### 4.1 Scheduled-publish background loop (priority gap)

Add a startup task in `app/main.py` following the existing background task pattern (lines 326–327):

```python
# app/main.py (startup hook)
from app.services.agent_marketing import publish_due_scheduled_content

async def _run_marketing_scheduler():
    while True:
        try:
            publish_due_scheduled_content()
        except Exception:
            logger.exception("marketing scheduler error")
        await asyncio.sleep(30)

app.add_event_handler("startup", lambda: asyncio.ensure_future(_run_marketing_scheduler()))
```

**Service function** (`app/services/agent_marketing.py`):

```python
def publish_due_scheduled_content() -> int:
    """Publish all scheduled content whose scheduled_publish_at <= now."""
    # Scan GSI3 for all users' scheduled items (no user filter on GSI3PK prefix)
    # or use a separate "SCHEDULED_GLOBAL" index entry.
    # For now: scan T.marketing_content filtering status=scheduled and
    # scheduled_publish_at <= now_ts()
    ...
```

The simplest approach is a `FilterExpression` scan on `T.marketing_content` for `status = scheduled AND scheduled_publish_at <= :now`. At low scale (hundreds of items) this is acceptable. A GSI on a global `SCHEDULED` PK with `scheduled_publish_at` as SK would make it O(due items) for any scale.

**Dev/Prod parity**: the background loop runs in both modes identically; no AWS dependency.

### 4.2 Feature-completion trigger

Wire into `tickets_svc.update_ticket_status` (or an event emitted at `status → done` transition). Check `S.marketing_agent_enabled` and `trigger_on_feature_completion` in the user's marketing config before dispatching.

### 4.3 Engagement summary pre-aggregation

Add a `SUMMARY` row under each user's content partition (key `USER#{user_id}/SUMMARY#ENGAGEMENT`) updated atomically on each `record_engagement` call. `get_engagement_summary` reads this single item instead of iterating N content pieces.

### 4.4 Dev/Prod parity (SECOPS-007)

| Component | Dev | Prod | Flag |
|-----------|-----|------|------|
| LLM content generation | Deterministic template | Real LLM API | `MARKETING_AGENT_EXECUTE_COMMANDS` |
| Social OAuth publishing | No-op | Secrets Manager OAuth tokens | Not yet wired |
| Background scheduler | Same loop; DDB Local | Same loop; AWS DDB | None (always on) |
| Engagement tracking | DDB Local atomic ADD | AWS DDB atomic ADD | None |

### 4.5 Alternatives considered

- **Store JSON fields in DDB maps (not strings)**: rejected because DDB map types can't be indexed; strings allow future prefix queries if needed.
- **Separate engagement table per content type**: rejected; single `marketing_engagement` table is simpler and the daily-row SK pattern allows efficient TTL and per-day aggregation.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_marketing_agent.py`)

Concrete cases, all runnable offline with moto:

| Test | Assertion |
|------|-----------|
| `test_create_content_valid_types` | All 9 `CONTENT_TYPES` create successfully with status=draft |
| `test_create_content_body_too_long` | body > 20 000 chars → `ValueError` |
| `test_state_machine_approve` | draft → approved; approve again → `PermissionError` |
| `test_state_machine_schedule_past` | `publish_at = now-1` → `ValueError` |
| `test_state_machine_publish_unapproved` | publish draft → `PermissionError` |
| `test_delete_non_draft_blocked` | delete approved → `PermissionError` |
| `test_get_calendar_returns_scheduled_and_published` | Two items seeded; calendar returns both sorted by date |
| `test_engagement_atomic_add` | Two `record_engagement(view)` calls → `total_views = 2` |
| `test_engagement_variant_breakdown` | Two variants; by_variant dict has both keys |
| `test_generate_deterministic` | `generate_content_for_feature` with known ticket → title contains ticket subject |
| `test_cross_user_isolation` | User B cannot get User A's content (returns None) |

### 5.2 Playwright E2E (`frontend/e2e/agent-marketing.spec.ts`)

Section 687–690 as per ticket spec. Auth: `injectAuth(page, "alice")` with CSRF header. Key assertions:

- Section 687 (CRUD): POST → 201 `status=draft`; GET by id; list by `?type=blog_post`
- Section 688 (lifecycle): approve → schedule → publish → archive → delete
- Section 689 (calendar + engagement): calendar GET includes scheduled item; engagement summary returns numeric totals
- Section 690 (UI): all four page `data-testid` attributes visible; content cards rendered

**Run**: `npx playwright test e2e/agent-marketing.spec.ts` (requires `just restart` first to create tables and seed sessions).

### 5.3 Manual/QA steps

1. `just restart` → navigate to `/agents/marketing`
2. Click "Create Content" → fill form with `blog_post` type → submit → verify `status=draft` card appears
3. Approve → Schedule (1 hour from now) → verify `status=scheduled` + date shown in calendar
4. Call `POST /ui/agents/marketing/generate` with `feature_ticket_ids=["SOME-TICKET"]` → verify draft created for each configured `content_type`
5. Verify `GET /ui/agents/marketing/content/{id}/engagement` returns `{total_views: 0, by_day: []}`

### 5.4 Metrics / observability

Prometheus counters specified in ticket §11.1 are not yet wired to `app/metrics.py`. Add:
- `marketing_agent_content_generated_total` (labels: `content_type`, `status`)
- `marketing_agent_llm_cost_cents` (label: `model`) — emitted when `execute_commands=true`

### 5.5 Rollout

Feature flags already deployed:
- `MARKETING_AGENT_ENABLED=1` (on by default in dev; set to `0` to gate in prod)
- `MARKETING_AGENT_EXECUTE_COMMANDS=0` (always off; flip to `1` only after API key is configured)
- `MARKETING_AGENT_AUTO_PUBLISH=0` (safety — never auto-publish without explicit approval)

### 5.6 Effort estimate & order

- Scheduled-publish background loop: **S** (1-2 days)
- Feature-completion trigger hook: **S** (1 day, requires tickets.py edit)
- Engagement summary pre-aggregation: **M** (3 days — adds SUMMARY row, migration path for existing data)
- Full LLM integration (when API key available): **L** (5-7 days — provider abstraction, streaming, cost tracking)
