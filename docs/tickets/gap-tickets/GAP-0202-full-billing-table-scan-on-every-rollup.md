# GAP-0202: Full billing table scan on every rollup

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-013 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-013.md`); see also `docs/tickets/writeups/FIN-013.md`

## Location
`app/services/platform_financial_dashboard.py:136`

## Problem / Impact
Full billing table scan on every rollup

## Fix
add the `GSI_LEDGER_DATE` GSI to the `billing` table as specified in the ticket (`scripts/local-ddb-init.py:59`) and replace the scan with a GSI query keyed by `ledger_date`

## Notes
This gap was identified by the second-pass as-built review of FIN-013. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
