# GAP-0338: Export runs synchronously inline (no background worker)

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PRIVACY-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PRIVACY-001.md`); see also `docs/tickets/writeups/PRIVACY-001.md`

## Location
`app/routers/privacy.py:71-73`

## Problem / Impact
Export runs synchronously inline (no background worker)

## Fix
queue the export as a background `asyncio` task or use an `add_event_handler("startup", …)` loop; return 201 immediately and let the worker update status

## Notes
This gap was identified by the second-pass as-built review of PRIVACY-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
