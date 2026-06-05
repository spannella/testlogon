# GAP-0205: `check_and_alert` returns alert details but never sends email or notification

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-014 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/FIN-014.md`); see also `docs/tickets/writeups/FIN-014.md`

## Location
`check_and_alert`

## Problem / Impact
`check_and_alert` returns alert details but never sends email or notification

## Fix
call the platform email or in-app notification service from `check_and_alert` (or from the background task caller) when `breaches` is non-empty

## Notes
This gap was identified by the second-pass as-built review of FIN-014. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
