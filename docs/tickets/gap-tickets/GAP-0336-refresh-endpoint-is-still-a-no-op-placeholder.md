# GAP-0336: Refresh endpoint is still a no-op placeholder

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-019 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-019.md`); see also `docs/tickets/writeups/PLATFORM-019.md`

## Location
`app/routers/creator_analytics.py:324`

## Problem / Impact
Refresh endpoint is still a no-op placeholder

## Fix
import and call `compute_daily_rollups(today, yesterday)` from the new rollup engine before returning

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-019. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
