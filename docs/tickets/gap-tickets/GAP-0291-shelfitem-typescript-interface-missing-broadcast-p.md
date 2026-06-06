# GAP-0291: `ShelfItem` TypeScript interface missing broadcast pricing fields

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: LCOM-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/LCOM-004.md`); see also `docs/tickets/writeups/LCOM-004.md`

## Location
`ShelfItem`

## Problem / Impact
`ShelfItem` TypeScript interface missing broadcast pricing fields

## Fix
extend `ShelfItem` with optional pricing fields and add `setBroadcastPrice`/`clearBroadcastPrice` API functions

## Notes
This gap was identified by the second-pass as-built review of LCOM-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
