# GAP-0200: Content ownership not validated on assign

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/FIN-011.md`); see also `docs/tickets/writeups/FIN-011.md`

## Location
`app/services/collaboration_revenue.py:115`

## Problem / Impact
Content ownership not validated on assign

## Fix
add content-metadata ownership check before `put_item` (cross-ref SEC-004)

## Notes
This gap was identified by the second-pass as-built review of FIN-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
