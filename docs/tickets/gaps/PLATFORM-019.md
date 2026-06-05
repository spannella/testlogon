# PLATFORM-019 gaps

- [HIGH] Analytics events table not created — `scripts/local-ddb-init.py` (no `analytics_events` entry) — Runtime `ResourceNotFoundException` the moment any event-recording call is made; rollup job can never run — Fix: add `TableDef("analytics_events", "pk", "sk", gsis=[{"name":"GSI1","pk":"GSI1PK","sk":"GSI1SK"}], ttl_field="ttl_epoch")` in local-ddb-init.py — Effort: S

- [HIGH] `analytics_events.py` service not implemented — `app/services/` (file absent) — All event-recording functions (`record_page_view`, `record_revenue_event`, `record_subscriber_event`, `record_engagement_event`) are missing; no raw analytics data is ever stored — Fix: create `app/services/analytics_events.py` with the four recording functions writing to `T.analytics_events` — Effort: M

- [HIGH] `analytics_rollup_engine.py` not implemented — `app/services/` (file absent) — Rollup computation engine (`run_rollup_loop`, `compute_daily_rollups`, `_compute_creator_daily`) does not exist; daily rollup rows are never populated from real data — Fix: create `app/services/analytics_rollup_engine.py` and register `run_rollup_loop` as a startup background task in `app/main.py` — Effort: M

- [HIGH] Refresh endpoint is still a no-op placeholder — `app/routers/creator_analytics.py:324` — `POST /ui/analytics/refresh` logs a message and returns immediately without computing anything; creators trigger a fake refresh — Fix: import and call `compute_daily_rollups(today, yesterday)` from the new rollup engine before returning — Effort: S

- [HIGH] Zero event instrumentation in any router — `app/routers/newsfeed.py`, `app/routers/messaging.py`, `app/routers/profile.py` (no `record_*` calls anywhere in codebase) — The analytics pipeline has no data source; rollup tables will always be empty even once the rollup engine exists — Fix: add `record_*()` calls at each instrumentation point listed in ticket §5.3 — Effort: M

- [MED] Admin platform-wide analytics endpoints not implemented — `app/routers/creator_analytics.py` (no `/ui/admin/analytics/*` routes) — Admins cannot view aggregate platform metrics; `AdminPlatformOverviewOut`, `AdminCreatorsOut` models are also absent from `app/models.py` — Fix: add `GET /ui/admin/analytics/overview`, `revenue`, `creators` endpoints behind `require_admin_session` — Effort: M

- [MED] `AdminAnalyticsPage.tsx` frontend page not built — `frontend/src/pages/admin/` (file absent); no route in `frontend/src/App.tsx` — Admin users have no UI for platform analytics even if the endpoints were present — Fix: create `AdminAnalyticsPage.tsx` and add `<Route path="admin/analytics" …>` to `App.tsx` — Effort: M

- [MED] `AnalyticsOverviewOut` missing `revenue_by_source` field — `app/models.py:2750-2756` — The overview response cannot expose per-source breakdown (subscriptions/tips/unlocks/shop); frontend would render all-zero chart — Fix: add `revenue_by_source: RevenueBySourceOut` field to `AnalyticsOverviewOut` and populate it in `get_overview()` — Effort: S

- [MED] `AnalyticsRefreshOut` missing `dates_refreshed` field — `app/models.py:2837-2840` — Ticket spec requires `{"ok":true,"refreshed_at":…,"dates_refreshed":[…]}`; current model returns `message` and `days_refreshed` int instead — Fix: rename/add fields to match the specified response contract — Effort: S

- [LOW] `analytics_rollup_lookback_days` default is 3, not 90 — `app/core/settings.py:1753` — Ticket states a 90-day lookback; current default produces stale dashboards on install — Fix: change default to `90` or add a note reconciling the discrepancy — Effort: S
