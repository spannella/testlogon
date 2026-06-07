# GAP-0201: Platform benchmarks endpoint absent

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-012 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-012.md`); see also `docs/tickets/writeups/FIN-012.md`

## Location
`GET /ui/analytics/engagement/benchmarks`

## Problem / Impact
the ticket spec requires `GET /ui/analytics/engagement/benchmarks` (returning `EngagementBenchmarksOut` with `average_rate`, `median_rate`, `p25_rate`, `p75_rate`, `sample_size`, `my_percentile`) and `POST /internal/analytics/engagement/compute-benchmarks`, but neither endpoint nor any `compute_platform_benchmarks` / `get_platform_benchmarks` function exists in `app/routers/creator_analytics.py` or `app/services/engagement_rate.py`

## Fix
implement `compute_platform_benchmarks(date_str)` in `engagement_rate.py` and add the router endpoint; add daily job call from main startup

## Notes
This gap was identified by the second-pass as-built review of FIN-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
