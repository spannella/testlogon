# GAP-0196: Admin queue tab absent from PayoutDashboard

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-009 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-009.md`); see also `docs/tickets/writeups/FIN-009.md`

## Location
`frontend/src/pages/payouts/PayoutDashboard.tsx`

## Problem / Impact
Admin endpoints exist (`app/routers/admin_payouts.py`) but are inaccessible from the UI; admins must process payouts via raw API calls

## Fix
add "Admin Queue" tab visible to role >= ADMIN, with approve/reject actions and reject-reason dialog

## Notes
This gap was identified by the second-pass as-built review of FIN-009. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
