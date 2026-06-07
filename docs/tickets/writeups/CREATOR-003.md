# CREATOR-003: Creator Dashboard Mobile-Optimized View — Investigation & Implementation Write-up

## 1. Summary & Classification

**Type**: Feature — new page + backend aggregation endpoint  
**Priority**: Medium | **Status**: Substantially implemented (backend + partial frontend)  
**Area**: Creator tools — analytics, earnings, milestone notifications  
**Persona**: Content creators checking daily performance on mobile devices

Creators on the platform currently have no single "at a glance" view combining earnings, analytics, and live broadcast status. The existing routes scatter that data across `GET /ui/analytics/overview`, `GET /ui/earnings/summary`, and broadcast session listings — three separate round-trips with different date conventions (string dates vs. Unix timestamps). CREATOR-003 specifies a unified `/ui/dashboard/summary` endpoint that fans out to those services and a mobile-first React page at `/creator-dashboard`. It also adds a milestone detection system, per-user SSE stream for real-time earnings tickers, and push-notification hooks.

Cross-references: CREATOR-004 (affiliate earnings category to add), MON-003 (creator earnings dashboard), BCAST-001 (broadcast SSE pattern), SECOPS-007 (in-process SSE state is dev/prod transparent — no AWS dependency).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Backend — what is implemented

**Router**: `app/routers/creator_dashboard.py` — registered in `app/main.py:155,619`. Prefix is implicit (paths hard-coded per endpoint). Implements all five planned endpoint groups:

| Endpoint | Line | Status |
|---|---|---|
| `GET /ui/dashboard/summary` | `:66` | Implemented |
| `POST /ui/dashboard/refresh` | `:149` | Implemented |
| `GET /ui/dashboard/stream` (SSE) | `:169` | Implemented |
| `GET /ui/milestones` | `:198` | Implemented |
| `POST /ui/milestones/{id}/acknowledge` | `:208` | Implemented |
| `GET /ui/milestones/settings` | `:232` | Implemented |
| `PATCH /ui/milestones/settings` | `:241` | Implemented |

`dashboard_summary` (`app/routers/creator_dashboard.py:66`) fans out to three internal calls:
1. `get_earnings_summary(user_id, from_ts=today_start)` from `app/services/creator_earnings.py:212`
2. `get_overview(user_id, days_ago(7), today)` from `app/services/creator_analytics.py:192`
3. `list_sessions_by_creator(user_id, limit=10)` from broadcast store, client-filtered for `status=="live"`

Each call is wrapped in a try/except that degrades gracefully: failures populate `warnings: List[str]` in the response rather than returning a 500.

**Analytics service** (`app/services/creator_analytics.py`): `get_overview` at `:192` queries the `T.analytics_rollups` table with PK `CREATOR#{user_id}` and SK range `DAILY#{from_date}` to `DAILY#{to_date}`. Summary sentinel row at SK `SUMMARY` carries `total_subscribers`. `_query_rollups` at `:78` is the inner fetcher.

**Earnings service** (`app/services/creator_earnings.py`): `get_earnings_summary` at `:212` queries `T.billing` for credit entries in a timestamp range. The "today" query uses `_start_of_day_utc` (`app/services/creator_earnings.py:102`) to anchor the SK range. The `classify_entry` function at `:36` categorises reasons into `tips/subscriptions/unlocks/vod_purchases/other` — notably **no "affiliate" category yet** (see gap analysis).

**Milestones service** (`app/services/milestones.py`): `check_milestone` at `:49`, `acknowledge_milestone` at `:101`, `list_milestones` at `:119`, `get_milestone_settings` at `:145`, `update_milestone_settings` at `:167`. Milestones stored in the app single table with `pk=USER#{user_id}`, `sk=MILESTONE#{metric}#{threshold}`. Settings stored at `sk=MILESTONE_PREFS`.

**Dashboard SSE service** (`app/services/dashboard_sse.py`): `dashboard_sse_subscribe` / `dashboard_sse_publish` / `dashboard_sse_unsubscribe` follow the same in-process `asyncio.Queue` pattern as `app/services/broadcast_sse.py`. Enforces max-1-connection-per-user: new connections push a `{"_type":"close"}` event to replaced queues.

### 2.2 Frontend — what is implemented

**Route**: `frontend/src/App.tsx:397` — `<Route path="creator-dashboard" element={<CreatorDashboard />} />`, lazy-imported at `:159`.

**Component** (`frontend/src/pages/dashboard/CreatorDashboard.tsx`): 176 lines. Uses `useQuery(["dashboard-summary"], getDashboardSummary)` with `refetchInterval: 60_000` and a separate `useQuery(["milestones"], listMilestones)`. Renders:
- `<QuickActionBar />` (exists: `QuickActionBar.tsx`)
- 2×2/4-col KPI grid using `<KpiCard />` (exists: `KpiCard.tsx`)
- `<EarningsSummaryCard breakdown={...} />` (exists: `EarningsSummaryCard.tsx`)
- Inline active broadcasts list (no separate component)
- `<TopContentList />` (exists: `TopContentList.tsx`)
- Milestone dismissal list with `<MilestoneSettingsDialog />` (exists)

**Frontend API** (`frontend/src/api/endpoints/dashboard.ts`): implements `getDashboardSummary`, `refreshDashboard`, `listMilestones`, `acknowledgeMilestone`, `getMilestoneSettings`, `updateMilestoneSettings`.

**E2E tests**: `frontend/e2e/creator-dashboard.spec.ts` — 785 lines, 22 `test(` calls.

### 2.3 What is missing vs. the ticket specification

The ticket's `Section 5.1 Component Status` table listed five components as `NOT YET IMPLEMENTED`:

| Component | Ticket Status | Actual Status |
|---|---|---|
| `AnalyticsSparkline` | Not implemented | **Still absent** — no file in `frontend/src/pages/dashboard/`, not imported in `CreatorDashboard.tsx` |
| `MilestoneToast` | Not implemented | **Still absent** — milestone events surface as a list card, not a toast on SSE event |
| `ActiveBroadcastCard` | Not implemented | **Partially** — active broadcasts render as an inline `<ul>` inside `CreatorDashboard.tsx:123–138`, not an extracted component |
| `PullToRefresh` | Not implemented | **Still absent** — no pull-to-refresh gesture handler |
| `useSSE` hook | Designed but not present | **Still absent** — `CreatorDashboard.tsx` does NOT import a `useSSE` hook; SSE stream endpoint exists on the backend but the frontend polls via `refetchInterval` only |

The backend SSE endpoint `GET /ui/dashboard/stream` is fully implemented (`app/routers/creator_dashboard.py:169`) but the frontend never connects to it. The `dashboard_sse_publish` function exists (`app/services/dashboard_sse.py:39`) but is not called from any billing or subscription event handler — there are no callers of `dashboard_sse_publish` outside the service definition itself.

The `milestone:reached` SSE event and `earnings:update` event are defined in the backend SSE infrastructure but are not wired to real-time triggers. `check_milestone` (`app/services/milestones.py:49`) similarly has no call sites outside its own module — it is not invoked from subscription events, tip ledger writes, or analytics rollup updates.

---

## 3. Gap Analysis

### 3.1 SSE not wired to frontend
`GET /ui/dashboard/stream` is implemented but `CreatorDashboard.tsx` never opens an `EventSource`. A `useSSE` hook (as designed in the ticket's `Section 5.6`) does not exist anywhere in `frontend/src/`. The current fallback is polling every 60 seconds. This means the "Real-Time Revenue Ticker" user story is not satisfied.

**Sites that must change**: `frontend/src/pages/dashboard/CreatorDashboard.tsx` (add `useSSE` import and event handlers), new file `frontend/src/hooks/useSSE.ts`.

### 3.2 `dashboard_sse_publish` has no call sites
Even when the frontend SSE connection is added, the backend never publishes events because no upstream service calls `dashboard_sse_publish`. The planned integration points (tip ledger write, subscription creation, milestone check) were not wired:

- `app/services/tip_ledger.py` — `write_tip_ledger` does not import or call `dashboard_sse_publish`
- `app/services/milestones.py` — `check_milestone` does not call `_publish_milestone_sse`; the private helper `_publish_milestone_sse` is defined in the ticket's design sketch but not in the actual file
- Subscription event handlers — no `subscriber:new` SSE events

### 3.3 `check_milestone` has no call sites
`check_milestone` (`app/services/milestones.py:49`) is never invoked. The trigger points (tip receipt, subscription signup, analytics rollup completion) do not call it. Milestones can only be created if a developer manually seeds the DynamoDB table.

### 3.4 `AnalyticsSparkline` missing
The ticket calls for a sparkline chart over the 7-day earnings/views time series. `EarningsSummaryCard.tsx` displays a breakdown dict (subscriptions/tips/unlocks/vod) as a card but has no chart. The backend `GET /ui/analytics/revenue` and `GET /ui/analytics/views` time-series endpoints exist and could supply data, but the dashboard summary endpoint does not include time-series data — it would require a second query.

### 3.5 `affiliate` category not in earnings classifier
`app/services/creator_earnings.py:36` — `classify_entry` maps reasons to five categories; `"affiliate"` is absent. Affiliate commissions (reason `"Affiliate commission"`, from CREATOR-004) fall into `"other"`. This prevents the dashboard breakdown card from showing affiliate earnings correctly. One-line fix: add `if "affiliate" in reason: return "affiliate"` before the `return "other"` line, and expand the `earningsBreakdown` dict in the frontend.

### 3.6 Pull-to-refresh and mobile gestures
No `PullToRefresh` component exists. The ticket's acceptance criteria ("creators on mobile can pull to refresh") is not met. The "Refresh" button (`CreatorDashboard.tsx:76`) serves as a desktop alternative. The 429-rate-limit handling for the refresh endpoint is implemented on the mutation's `onError` handler.

### 3.7 `MilestoneToast` missing
Milestone achievements are visible only by loading the milestones query list (`["milestones"]`). There is no proactive toast notification when a new milestone is reached mid-session. The design called for an SSE `"milestone:reached"` event to trigger `toast.success(...)` — this chain is broken at both ends (no SSE consumer, no publisher).

---

## 4. Proposed Design / Fix

### 4.1 Wire `check_milestone` into upstream events

**`app/services/tip_ledger.py`**: After the credit `put_item` completes, call `check_milestone(recipient_user_id, "tips_total_cents", total)` where `total` is accumulated from the `get_quick_stats` helper (`app/services/creator_earnings.py:249`). Import lazily to avoid circular imports.

**`app/routers/subscription_server.py`** (or wherever `T.subscriptions` is written): After writing a new subscription record, call `check_milestone(creator_user_id, "subscribers", current_subscriber_count)`.

**`app/services/creator_analytics.py:523` (`upsert_daily_rollup`)**: After writing the rollup, call `check_milestone(user_id, "views", cumulative_views_from_summary)`.

### 4.2 Wire `dashboard_sse_publish` into `milestones.py`

Add the `_publish_milestone_sse` helper (as designed in ticket section 3.2) to `app/services/milestones.py` and call it from `check_milestone` after `_record_milestone`. Add `dashboard_sse_publish(user_id, {...})` call with `_type: "earnings:update"` in `write_tip_ledger` for the recipient.

### 4.3 Add `useSSE` hook and connect frontend

Create `frontend/src/hooks/useSSE.ts` (as designed in ticket section 5.6 — `EventSource` with exponential backoff on error, stable `handlersRef`). In `CreatorDashboard.tsx`:
- Call `useSSE("/ui/dashboard/stream", { "earnings:update": ..., "milestone:reached": ... })`
- `earnings:update` handler: `queryClient.setQueryData(["dashboard-summary"], ...)` to increment `today_earnings_cents`
- `milestone:reached` handler: `toast.success(...)` + `queryClient.invalidateQueries(["milestones"])`

### 4.4 Add `AnalyticsSparkline`

Option A: Add a `sparkline_data` field to `GET /ui/dashboard/summary` by including the last 7 days from the rollup rows already fetched by `get_overview`. The rollup data is already queried in `dashboard_summary`; surfacing the per-day `revenue_cents` and `views` arrays costs nothing extra.

Option B: A separate `GET /ui/dashboard/sparkline` endpoint (avoids growing the summary payload). Either works; Option A is simpler.

For the React component, use a lightweight SVG sparkline (no external charting library needed given shadcn/ui availability) or a `<recharts>` `<AreaChart>` (already available if the project has it).

### 4.5 Add `affiliate` category to earnings classifier

`app/services/creator_earnings.py:53–61` — add before `return "other"`:

```python
if "affiliate" in reason:
    return "affiliate"
```

Update `EarningsSummaryCard.tsx` to render the `affiliate` key in the breakdown.

### 4.6 Dev/Prod parity (SECOPS-007)

Dashboard SSE uses in-process `asyncio.Queue` (same pattern as broadcast SSE). No AWS dependency. The background milestone refresh and SSE publish work identically in dev (DynamoDB Local) and prod (DynamoDB). No mocking needed; the in-process state is ephemeral and intentionally non-persistent.

The `analytics_rollups` table is created by `scripts/local-ddb-init.py`. Milestone records use the existing `app_single_table` (via `T.app`). No new DDB table is required for milestones or SSE state.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_creator_dashboard.py`)

| Case | What to assert |
|---|---|
| `test_dashboard_summary_all_fields` | Response includes all required top-level keys; `warnings=[]` when all sub-calls succeed |
| `test_dashboard_summary_degraded` | When analytics service raises, `warnings` includes `"analytics_overview"` and partial data is returned |
| `test_milestone_detection` | `check_milestone(user_id, "subscribers", 100)` writes a MILESTONE record and returns milestone dict |
| `test_milestone_no_duplicate` | Second call with same threshold returns `None` |
| `test_milestone_acknowledge` | `acknowledge_milestone` sets `acknowledged=True`; subsequent `list_milestones` excludes it |
| `test_earnings_category_affiliate` | `classify_entry({"reason":"Affiliate commission"})` returns `"affiliate"` |
| `test_dashboard_sse_publish_consume` | `dashboard_sse_subscribe(uid)` then `dashboard_sse_publish(uid, ev)` delivers event to queue |

### 5.2 Playwright E2E (`frontend/e2e/creator-dashboard.spec.ts`)

22 tests already written (785 lines). Key gaps to add:
- SSE milestone toast: seed a milestone event via direct DDB write, load dashboard, verify `toast` text appears (requires mock SSE endpoint or direct queue injection)
- Pull-to-refresh: simulate touch `touchstart`/`touchmove`/`touchend` with Playwright's pointer events; assert `POST /ui/dashboard/refresh` fires
- `AnalyticsSparkline` renders after `sparkline_data` is present in response

### 5.3 Manual QA

1. `just restart` then `python3 e2e_session_setup.py`
2. Navigate to `http://localhost:3000/creator-dashboard`
3. Verify KPI cards show zeros for fresh Alice (no data seeded)
4. Seed analytics rollup directly via DynamoDB Local (`scripts/local-ddb-seed.py` or raw `put_item`)
5. Click "Refresh" — verify 429 toast after two rapid clicks (5-minute rate limit)

### 5.4 Metrics & observability

Add a `logger.info("dashboard_summary_generated", ...)` call with `{"warnings": warnings, "user_id": user_id}` in `dashboard_summary` — the existing SECOPS-001 telemetry pipeline picks this up automatically.

### 5.5 Effort estimate and rollout order

- Wire `check_milestone` call sites + SSE publish: **S** (2–3 hours, three files)
- `useSSE` hook + frontend SSE integration: **S** (1–2 hours)
- `AnalyticsSparkline` component: **M** (4–6 hours, includes sparkline data in API response)
- `PullToRefresh` gesture component: **M** (4–6 hours including mobile testing)
- `affiliate` earnings category: **S** (30 minutes, one-liner + frontend expansion)

**Rollback**: Feature is behind the `/creator-dashboard` route. Removing the route entry from `App.tsx` disables the page. The backend endpoint is additive and does not affect other routes.

**Open question**: SSE connections in a multi-worker uvicorn setup would lose events if published to a different worker process than the subscriber. The existing broadcast SSE has the same limitation and mitigates it by running `--workers 1` in dev. A production deployment requiring horizontal scaling would need a Redis pub/sub broker. This is documented in `docs/local-dev-stack.md` under the "S3 mock workers" note.
