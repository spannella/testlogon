# GAP-0350: UPS webhook has no timestamp-tolerance or replay-protection check

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SHOP-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/SHOP-004.md`); see also `docs/tickets/writeups/SHOP-004.md`

## Location
`app/routers/ups.py:91`

## Problem / Impact
UPS webhook has no timestamp-tolerance or replay-protection check

## Fix
store processed event IDs in DDB and reject duplicates; add X-UPS-Timestamp window check

## Notes
This gap was identified by the second-pass as-built review of SHOP-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
