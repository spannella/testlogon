# GAP-0161: Admin advance-progress endpoint open to any authenticated user

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENGAGE-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENGAGE-001.md`); see also `docs/tickets/writeups/ENGAGE-001.md`

## Location
`app/routers/achievements.py:278`

## Problem / Impact
Admin advance-progress endpoint open to any authenticated user

## Fix
change `Depends(require_ui_session)` to `Depends(require_root_session)`

## Notes
This gap was identified by the second-pass as-built review of ENGAGE-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
