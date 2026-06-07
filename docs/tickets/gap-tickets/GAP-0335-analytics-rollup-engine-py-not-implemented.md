# GAP-0335: `analytics_rollup_engine.py` not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-019 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PLATFORM-019.md`); see also `docs/tickets/writeups/PLATFORM-019.md`

## Location
`analytics_rollup_engine.py`

## Problem / Impact
Rollup computation engine (`run_rollup_loop`, `compute_daily_rollups`, `_compute_creator_daily`) does not exist; daily rollup rows are never populated from real data

## Fix
create `app/services/analytics_rollup_engine.py` and register `run_rollup_loop` as a startup background task in `app/main.py`

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-019. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
