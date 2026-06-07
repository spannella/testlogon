# GAP-0195: Payout methods CRUD not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-009 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-009.md`); see also `docs/tickets/writeups/FIN-009.md`

## Location
`app/services/creator_payouts.py`

## Problem / Impact
Creators cannot configure bank/PayPal destinations; payout request hardcodes `"bank_transfer"` string with no real routing info

## Fix
add payout method service functions, router endpoints, `PayoutMethodIn`/Out models, and "Payout Methods" tab in dashboard

## Notes
This gap was identified by the second-pass as-built review of FIN-009. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
