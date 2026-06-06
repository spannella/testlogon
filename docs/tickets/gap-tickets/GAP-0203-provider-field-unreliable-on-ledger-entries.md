# GAP-0203: `provider` field unreliable on ledger entries

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-013 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-013.md`); see also `docs/tickets/writeups/FIN-013.md`

## Location
`provider`

## Problem / Impact
`provider` field unreliable on ledger entries

## Fix
pass `provider` through `new_ledger_entry`'s `extra` dict at all call sites (Stripe, PayPal, CCBill paths) (cross-ref SEC-004)

## Notes
This gap was identified by the second-pass as-built review of FIN-013. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
