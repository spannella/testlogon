# GAP-0208: Chargeback not auto-recorded from Stripe webhook

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-015 · **Effort**: ?
**From**: gap audit (`docs/tickets/gaps/FIN-015.md`); see also `docs/tickets/writeups/FIN-015.md`

## Location
`app/routers/billing.py:687`

## Problem / Impact
Chargeback not auto-recorded from Stripe webhook

## Fix
See source write-up.

## Notes
This gap was identified by the second-pass as-built review of FIN-015. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
