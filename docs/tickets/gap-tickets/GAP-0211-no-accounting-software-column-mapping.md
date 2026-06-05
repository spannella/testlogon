# GAP-0211: No accounting-software column mapping

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-016 · **Effort**: ?
**From**: gap audit (`docs/tickets/gaps/FIN-016.md`); see also `docs/tickets/writeups/FIN-016.md`

## Location
`audit_export.py`

## Problem / Impact
No accounting-software column mapping

## Fix
See source write-up.

## Notes
This gap was identified by the second-pass as-built review of FIN-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
