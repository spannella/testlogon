# GAP-0204: `check_and_alert` never called

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-014 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/FIN-014.md`); see also `docs/tickets/writeups/FIN-014.md`

## Location
`check_and_alert`

## Problem / Impact
`check_and_alert` never called

## Fix
wire a background task (e.g. every 5 min per provider) in `app/main.py` startup that calls `check_and_alert(provider)` for each of `["stripe", "paypal", "ccbill"]`

## Notes
This gap was identified by the second-pass as-built review of FIN-014. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
