# GAP-0214: Fee BPS settings are not wired to live billing fee calculations

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-018 · **Effort**: ?
**From**: gap audit (`docs/tickets/gaps/FIN-018.md`); see also `docs/tickets/writeups/FIN-018.md`

## Location
`app/services/billing_config.py`

## Problem / Impact
Fee BPS settings are not wired to live billing fee calculations

## Fix
See source write-up.

## Notes
This gap was identified by the second-pass as-built review of FIN-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
