# GAP-0337: Zero event instrumentation in any router

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-019 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PLATFORM-019.md`); see also `docs/tickets/writeups/PLATFORM-019.md`

## Location
`app/routers/newsfeed.py`

## Problem / Impact
The analytics pipeline has no data source; rollup tables will always be empty even once the rollup engine exists

## Fix
add `record_*()` calls at each instrumentation point listed in ticket §5.3

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-019. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
