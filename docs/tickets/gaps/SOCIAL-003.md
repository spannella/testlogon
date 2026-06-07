# SOCIAL-003: Global Search — Gap Report

NOTE: SOCIAL-003 overlaps heavily with PLATFORM-011 (Unified Global Search). PLATFORM-011.md already documents the backend gaps (_search_messages, _search_tickets, _search_contacts authorization, and recentSearches store). The gaps below are SOCIAL-003-specific and should be deduped against PLATFORM-011 before scheduling.

- [HIGH] No rate limiting on `GET /ui/search` — `app/routers/search.py` (no `check_rate_limit` call) — any authenticated user can issue unlimited search requests per second, fan-out to 8+ backend modules; CPU and DDB read amplification attack possible — Fix: add `check_rate_limit(user_id, "global_search", max=30, window=60)` at the top of the aggregator endpoint — Effort: S

- [MED] `GLOBAL_SEARCH_ENABLED` feature flag is absent — `app/core/settings.py` (no `global_search_enabled` field), `app/routers/search.py` (no flag check) — ticket requires flag to gate the feature for rollback; without it there is no way to disable search without a code deploy — Fix: add `global_search_enabled: bool` to `Settings`; return 404 from the search router when disabled — Effort: S

- [MED] `_search_users` does not filter blocked users — `app/routers/search.py:86-111` calls `search_users()` from `app/services/discovery.py` which contains no blocking check; `app/services/discovery.py` has no `get_blocked_set` call — acceptance criterion 8.3 requires blocked users filtered from search results; currently blocked users appear in `results.users` — Fix: load `get_blocked_set(viewer_id) | get_blocked_by_set(viewer_id)` once before fan-out and pass to `_search_users`; filter results — Effort: M

- [LOW] No `search_per_module_timeout_ms` setting exists — `app/core/settings.py` has no such field; `app/routers/search.py` uses a hard-coded `timeout=5` seconds in the `ThreadPoolExecutor.submit` / `as_completed` call — ticket section 9.3 requires a configurable per-module timeout; tuning requires a code deploy — Fix: add `search_per_module_timeout_ms: int = 2000` to `Settings`; use `S.search_per_module_timeout_ms / 1000` — Effort: S
