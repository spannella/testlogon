# GAP-0159: background refresh job not registered

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: DISC-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/DISC-001.md`); see also `docs/tickets/writeups/DISC-001.md`

## Location
`app/main.py`

## Problem / Impact
compute_for_you records never written; every user stays in cold-start/trending-fallback permanently despite algorithm being implemented

## Fix
add refresh_all_users() function and register asyncio periodic loop via app.add_event_handler("startup", ...) at S.reco_refresh_interval_hours cadence

## Notes
This gap was identified by the second-pass as-built review of DISC-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
