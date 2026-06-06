# GAP-0106: top_content view attribution bug

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ANALYTICS-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ANALYTICS-001.md`); see also `docs/tickets/writeups/ANALYTICS-001.md`

## Location
`app/services/creator_analytics.py:432`

## Problem / Impact
get_top_content attributes entire day's total_views to every content ID in top_content_ids list; a creator with 500 views across 3 videos shows 500 attributed to each video; metric is incorrect and misleading

## Fix
store per-content view counts as a DDB map in rollup rows, or use _resolve_content_details live view counts from T.video_metadata (Option B already available via ANALYTICS-002)

## Notes
This gap was identified by the second-pass as-built review of ANALYTICS-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
