# GAP-0210: No scheduled report system

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-016 · **Effort**: ?
**From**: gap audit (`docs/tickets/gaps/FIN-016.md`); see also `docs/tickets/writeups/FIN-016.md`

## Location
`audit_export_pipeline.py`

## Problem / Impact
neither `audit_export_pipeline.py` nor `audit_export.py` router contain a `SCHEDULE#*` row pattern or background task for recurring exports

## Fix
See source write-up.

## Notes
This gap was identified by the second-pass as-built review of FIN-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
