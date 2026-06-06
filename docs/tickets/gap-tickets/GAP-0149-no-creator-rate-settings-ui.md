# GAP-0149: No creator rate settings UI

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: CALL-011 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/CALL-011.md`); see also `docs/tickets/writeups/CALL-011.md`

## Location
`frontend/src/pages/settings/CallRateSettings.tsx`

## Problem / Impact
creators cannot configure their rate through the platform UI

## Fix
implement settings form at `/settings/call-rate` per §4.4

## Notes
This gap was identified by the second-pass as-built review of CALL-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
