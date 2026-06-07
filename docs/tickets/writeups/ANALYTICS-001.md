# ANALYTICS-001: Creator Analytics Dashboard — Investigation & Implementation Write-up

## 1. Summary & Classification

The Creator Analytics Dashboard provides creators with a self-service, data-driven view of their content performance, audience composition, and revenue attribution across all monetisation channels. Before this feature, creators had no time-series visibility: they could see a point-in-time earnings snapshot via MON-003's `/ui/earnings` endpoints, but had no way to trend views over weeks, decompose revenue by source, track subscriber growth and churn, or see audience demographics.

The implementation builds a three-layer stack: a background rollup job that pre-aggregates daily metrics from billing, video views, subscriptions, ad impressions, and call billing tables into a single `analytics_rollups` DynamoDB table; REST endpoints at `/ui/analytics/*` that serve time-ranged, granularity-selectable data read from those rollups; and a React dashboard at `/analytics` with Recharts-powered visualisations.

- **Type**: Feature (new analytics system)
- **Priority**: Medium
- **Status**: Implemented — all backend components, frontend page, routes, and settings are live
- **Persona**: Creator (content owner, monetisation user)
- **Cross-references**: MON-003 (creator earnings, upstream rollup dependency), ANALYTICS-002 (depth enhancements building on this ticket)
- **Dev/Prod parity**: SECOPS-007 compliant — `ANALYTICS_ROLLUP_ENABLED` flag (default 1) controls background job; same code path in both modes; no AWS-specific services used (DDB Local or AWS DDB, both work identically)

---

## 2. Current-State Investigation

### 2.1 Analytics settings (`app/core/settings.py:1750–1753`)

All four settings exist:
```
analytics_rollups_table_name      = DDB_ANALYTICS_ROLLUPS         (default "AnalyticsRollups")
analytics_rollup_enabled          = ANALYTICS_ROLLUP_ENABLED      (default "1"=true)
analytics_rollup_interval_seconds = ANALYTICS_ROLLUP_INTERVAL_SECONDS (default 900)
analytics_rollup_lookback_days    = ANALYTICS_ROLLUP_LOOKBACK_DAYS    (default 3)
```

### 2.2 Table handle (`app/core/tables.py:186,422`)

`T.analytics_rollups` is wired via `_safe_table(S.analytics_rollups_table_name)`. The DDB table is defined in `scripts/local-ddb-init.py` with a `ByDateCreatedAt` GSI using `date_scope` as partition key and numeric `created_at` as sort key.

### 2.3 Analytics service (`app/services/creator_analytics.py`)

The service is fully implemented (600+ lines). Key functions:

- **`_to_int`** (line 38): coerces `Decimal`, int, float, or digit-string to int. Correct for boto3 Decimal values.
- **`_to_float`** (line 49): coerces `Decimal` to float.
- **`_query_rollups`** (line 78): queries `T.analytics_rollups` with `pk=CREATOR#{user_id}` and `sk between DAILY#{from_date} and DAILY#{to_date}`. Paginates via `LastEvaluatedKey` loop (lines 86–99).
- **`get_overview`**: aggregates `total_views`, `revenue_cents`, `new_subscribers`, `total_subscribers` across all rollup rows in the date range; returns summary + top-content list.
- **`get_revenue`**: builds time series with per-source breakdown (`revenue_tips_cents`, `revenue_subscriptions_cents`, `revenue_unlocks_cents`, `revenue_vod_cents`, `revenue_ads_cents`, `revenue_calls_cents`). Supports `granularity=day/week/month` aggregation.
- **`get_views`**: time series of `total_views`, `unique_viewers`, `watch_time_seconds`.
- **`get_subscribers`**: time series of `new_subscribers`, `churned_subscribers`, `net_subscribers`, running `total_subscribers`.
- **`get_top_content`** (line 424): now includes title resolution and real engagement rates via `_resolve_content_details` (line 357) — **ANALYTICS-002 fixes were merged into this function**. See ANALYTICS-002 write-up for detail.
- **`get_audience`** (line 478): merges `audience_countries` and `audience_devices` maps across all rollup rows.
- **`upsert_daily_rollup`** (line 523): writes/updates `pk=CREATOR#{user_id}`, `sk=DAILY#{date}` with a full data merge. Also calls `build_engagement_rollup_fields` (FIN-012 enrichment) to compute `engagement_rate_bps`.
- **`upsert_summary_sentinel`**: writes a `SUMMARY` row for quick total subscriber count lookups.

### 2.4 Router (`app/routers/creator_analytics.py`)

Registered in `app/main.py` at lines 152 (import) and 616 (unconditional `include_router`). Prefix: `/ui/analytics`. Seven endpoints:

| Method | Path | Service call |
|--------|------|-------------|
| GET | `/overview` | `get_overview` |
| GET | `/revenue` | `get_revenue` |
| GET | `/views` | `get_views` |
| GET | `/subscribers` | `get_subscribers` |
| GET | `/top-content` | `get_top_content` |
| GET | `/audience` | `get_audience` |
| POST | `/refresh` | triggers rollup job |
| GET | `/content/{content_id}` | `get_content_detail` (ANALYTICS-002) |

The router uses `require_ui_session` (imported from `app/services/sessions`) for all endpoints. User scope is enforced via `user_sub` from session — no endpoint exposes another user's data. Date validation helpers `_validate_date`, `_validate_date_range`, `_today`, `_days_ago` are defined locally in the router.

### 2.5 Rollup background job

A background task starts at app startup (following the pattern at `app/main.py:326–327`). The job runs every `analytics_rollup_interval_seconds` (default 900s = 15 minutes) and processes the last `analytics_rollup_lookback_days` (default 3) days. It scans source tables:
- `T.billing` LEDGER entries per creator (per-user scan with `SK begins_with LEDGER#`, as done in `creator_earnings.py:57–73`)
- `T.video_views` for view counts
- `T.subscriptions` for subscriber changes
- `T.ad_impressions` and `T.call_billing_ledger` for ad/call revenue

For each creator–date pair, `upsert_daily_rollup` writes or updates the rollup row.

**Known limitation noted in ticket §8**: `T.billing` is not indexed by date. Per-creator scans (SK begins_with `LEDGER#`) are efficient for per-user aggregation, but a cross-creator date scan (needed if the admin GSI were used for platform-wide analytics) would require a full table scan. The current per-creator approach is correct for the rollup job which iterates creators.

### 2.6 Frontend (`frontend/src/pages/analytics/AnalyticsPage.tsx`)

The page exists and is routed at `/analytics` in `App.tsx`. It uses:
- `useSearchParams` for `from_date`, `to_date`, `granularity` URL state (shareable links)
- Six independent React Query hooks, one per endpoint, each with `staleTime: 5 * 60 * 1000`
- Recharts library (verified at `frontend/package.json:64`, `"recharts": "^3.8.1"`)
- shadcn/ui `Card` components for summary cards
- Sidebar and MobileNav entries for `/analytics` navigation

API wrappers are in `frontend/src/api/endpoints/analytics.ts` (all 7+ functions).

### 2.7 Dev vs Prod behaviour

| Concern | Dev (local DDB) | Prod (AWS DDB) |
|---------|----------------|---------------|
| Rollup table | DDB Local port 8001; `just restart` wipes data | AWS DDB on-demand; data persists |
| Rollup background job | Runs if `ANALYTICS_ROLLUP_ENABLED=1`; processes last 3 days | Same; processes last 3 days by default |
| Source table scans | Same boto3 calls against DDB Local | Same calls against AWS DDB |
| Rate limiting on `/refresh` | `rate_limit_or_429` via `T.sessions` (DDB Local) | Same via AWS DDB sessions table |
| Audience data | Populated from rollup `audience_countries`/`audience_devices` maps; empty in fresh stack | Same; populated as rollup processes real traffic events |

No AWS-specific services (Kinesis, Lambda, etc.) are used. The entire system is DDB-only, making dev/prod parity straightforward.

---

## 3. Gap / Threat Analysis

### 3.1 What exists (verified)

- `T.analytics_rollups` table with `ByDateCreatedAt` GSI and `created_at: N` attribute type
- All four settings at `settings.py:1750–1753`
- All seven router endpoints
- Background rollup job registered at startup
- Full `AnalyticsPage.tsx` with 4 summary cards, view/revenue/subscriber/audience charts
- `getAnalyticsContentDetail` in `analytics.ts` line 41 (ANALYTICS-002 additions merged)
- Recharts confirmed in `package.json`

### 3.2 Remaining gaps

1. **`top_content_ids` accumulation bug in rollup**: `get_top_content` (line 432) sums `total_views` from rollup items for each `cid in top_content_ids`. But `top_content_ids` is a list of IDs stored at the creator level, not a per-content view count. The function attributes the entire day's `total_views` to every content ID in the list — so if a creator had 500 views across 3 videos, each video gets 500 attributed views. This is an aggregation design flaw in the current schema: rollups do not store per-content view counts, only the list of top IDs seen. Fix requires either storing per-content view counts in the rollup (breaking change) or computing view counts at query time from `T.video_views` (the approach adopted by ANALYTICS-002's `_resolve_content_details`).

2. **`app_single_table` not wired as `T.app_single_table`**: the rollup job accesses newsfeed engagement data. The app_single_table is defined in DDB init (`scripts/local-ddb-init.py:216–228`) but is NOT wired as a named table handle in `T`. The `creator_analytics.py` service accesses it via `ddb.Table(os.environ.get("APP_TABLE", "app_single_table"))` (line 400) — a workaround that works but bypasses the standard `T`-based pattern. If the env var is not set, it falls back to `"app_single_table"` which matches the DDB init table name, so this is safe in practice.

3. **No backfill mechanism**: the rollup job processes only `analytics_rollup_lookback_days` (default 3) per run. Historical data older than 3 days is never populated unless the env var is temporarily increased and a manual `/refresh` is called. New creators will see empty analytics until the job has run for the lookback window.

4. **`audience_countries`/`audience_devices` sources**: the rollup job needs to source these from request metadata (User-Agent, GeoIP). In the current implementation, these fields are populated by the rollup job only if the source tables contain the data. The ticket notes that the platform "collects device user-agent and GeoIP headers at request time" but the actual write path (which service stores these and in which table) needs verification before the rollup can reliably aggregate them.

### 3.3 Input validation (verified in router)

- `from_date`/`to_date`: `_validate_date(s)` returns 400 for non-`YYYY-MM-DD` input
- `_validate_date_range` returns 400 if `from > to` or range > 365 days
- `granularity`: validated against `("day", "week", "month")`; 400 for unknown values
- `sort_by`: validated against `("views", "revenue")`; 400 for unknown values
- `limit`: clamped to `[1, 100]` via Query constraints

---

## 4. Proposed Design / Fix

### 4.1 Fix top_content view attribution

Replace the "total creator views attributed to every content ID" approach with per-content view counts stored in the rollup:

**Option A (Recommended for correctness)**: Store `content_views` as a DDB map in each rollup row: `{"vid_abc": 350, "vid_def": 150}`. The rollup job populates this by querying `T.video_views` for each video during the rollup window. `get_top_content` reads `content_views` from each rollup row instead of `total_views`.

**Option B (Current fallback)**: Use `_resolve_content_details` to read `view_count` from `T.video_metadata` at query time (already implemented for ANALYTICS-002). This gives real-time view counts but bypasses the time-range filter.

The ticket design is compatible with either — Option B is already in place via the ANALYTICS-002 `_resolve_content_details` function.

### 4.2 Wire `app_single_table` as a named handle

Add to `app/core/tables.py`:
```python
app_single: Any  # declaration
# wiring:
app_single=_safe_table(S.app_single_table_name),
```
Then replace the `ddb.Table(os.environ.get("APP_TABLE", ...))` pattern in `creator_analytics.py:400` with `T.app_single`.

### 4.3 Backfill endpoint enhancement

Add `?lookback_days=N` parameter to `POST /ui/analytics/refresh` for operator-triggered historical backfill. Cap at 90 days. Rate-limit separately (1 backfill per 1 hour) vs the normal 5-minute refresh cooldown.

### 4.4 Dev/Prod parity (SECOPS-007)

No changes needed — the system is already parity-correct. Both modes use the same DDB queries, same rollup logic, same feature flag. The only difference is data volume and persistence.

### 4.5 Alternatives considered

- **Real-time streaming (Kinesis → Lambda → rollup table)**: rejected for complexity and cost. Pre-aggregated DDB rows with a background job is simpler, cheaper, and sufficient for 15-minute freshness.
- **Single table scan per endpoint (no rollup)**: rejected; scanning the billing table for every dashboard load would be unbounded and would create read hot spots on creators with large ledgers.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_creator_analytics.py`)

All runnable offline with moto:

| Test | Assertion |
|------|-----------|
| `test_rollup_aggregates_billing_ledger` | Seed LEDGER entries; run rollup; `revenue_tips_cents` correct |
| `test_rollup_aggregates_video_views` | Seed view records; `total_views` + `unique_viewers` correct |
| `test_rollup_aggregates_subscriber_changes` | SUBSCRIBER entries → `new_subscribers`, `net_subscribers` |
| `test_rollup_idempotent` | Two rollup runs for same date → one row, counts not doubled |
| `test_overview_returns_zeros_for_empty_creator` | No rollup data → all zeros, no error |
| `test_revenue_breakdown_correct_attribution` | Known LEDGER entries → breakdown dict matches |
| `test_date_range_validation_rejects_inverted` | `from > to` → 400; range > 365 → 400 |
| `test_granularity_week_aggregation` | 14 daily rows → `granularity=week` produces 2 points |
| `test_refresh_rate_limit_429` | Two refreshes < 5 min → second is 429 |
| `test_cross_user_isolation` | Two creators' rollups; each sees only their own data |

### 5.2 Playwright E2E (`frontend/e2e/analytics.spec.ts`)

16 tests per ticket spec §10. Key assertions:
- Empty creator returns zeros for all summary cards (no error)
- Revenue breakdown includes seeded tip/subscription/unlock sources
- Time range filter produces correct number of time series points
- Audience endpoint returns `countries` and `devices` arrays
- Invalid date range returns 400
- Analytics page loads with 4 summary cards visible

### 5.3 Manual/QA steps

1. `just restart`; navigate to `/analytics` → verify empty state (zeros, no error)
2. Seed a billing LEDGER entry for Alice via DDB put_item → call `POST /ui/analytics/refresh` → reload page → verify revenue card shows non-zero
3. Set date range to "30d" preset → verify URL params update and charts re-render
4. Navigate to `/analytics/content/vid_testid` (with a seeded video) → verify detail page loads

### 5.4 Rollout checklist

- [x] `AnalyticsRollups` table in `scripts/local-ddb-init.py` with `ByDateCreatedAt` GSI and `created_at: N`
- [x] Settings at `settings.py:1750–1753`
- [x] `T.analytics_rollups` handle at `tables.py:186,422`
- [x] `creator_analytics_router` registered at `main.py:152,616`
- [x] `/analytics` route in `App.tsx`
- [x] Sidebar entry for Analytics navigation
- [x] `analytics.spec.ts` E2E test file exists

**Remaining before prod enable**: fix `top_content_ids` view attribution (§4.1), wire `T.app_single` handle (§4.2), verify audience data write path.

### 5.5 Effort estimates

- top_content view attribution fix: **S** (1-2 days)
- `T.app_single` table handle: **S** (< 1 day)
- Backfill endpoint enhancement: **S** (1 day)
- Audience data write path investigation: **S** (1 day investigation, then M fix if write path is missing)
