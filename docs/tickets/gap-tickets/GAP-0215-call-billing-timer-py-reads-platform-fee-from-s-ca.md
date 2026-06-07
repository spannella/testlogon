# GAP-0215: `call_billing_timer.py` reads platform fee from `S.call_billing_platform_fee_percent` (env var)

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-018 · **Effort**: ?
**From**: gap audit (`docs/tickets/gaps/FIN-018.md`); see also `docs/tickets/writeups/FIN-018.md`

## Location
`call_billing_timer.py`

## Problem / Impact
`call_billing_timer.py` reads platform fee from `S.call_billing_platform_fee_percent` (env var)

## Fix
See source write-up.

## Notes
This gap was identified by the second-pass as-built review of FIN-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
