# GAP-0135: `_next_run_from_cron()` is a stub

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BOT-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BOT-002.md`); see also `docs/tickets/writeups/BOT-002.md`

## Location
`_next_run_from_cron()`

## Problem / Impact
returns `now_ts() + 3600` for every cron expression regardless of configured schedule; a `0 14 * * *` daily job fires ~60 min after creation, not at 14:00

## Fix
add `croniter` to `requirements.txt` and replace stub with real cron-next calculation

## Notes
This gap was identified by the second-pass as-built review of BOT-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
