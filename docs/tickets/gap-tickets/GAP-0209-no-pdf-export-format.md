# GAP-0209: No PDF export format

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-016 · **Effort**: ?
**From**: gap audit (`docs/tickets/gaps/FIN-016.md`); see also `docs/tickets/writeups/FIN-016.md`

## Location
`app/routers/audit_export.py:78`

## Problem / Impact
No PDF export format

## Fix
See source write-up.

## Notes
This gap was identified by the second-pass as-built review of FIN-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
