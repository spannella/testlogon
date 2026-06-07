# GAP-0213: No CSV import endpoint

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-017 · **Effort**: ?
**From**: gap audit (`docs/tickets/gaps/FIN-017.md`); see also `docs/tickets/writeups/FIN-017.md`

## Location
`app/routers/bulk_payout_tools.py`

## Problem / Impact
No CSV import endpoint

## Fix
See source write-up.

## Notes
This gap was identified by the second-pass as-built review of FIN-017. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
