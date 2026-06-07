# GAP-0262: Five template/witness router endpoints missing

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-007 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-007.md`); see also `docs/tickets/writeups/KYC-007.md`

## Location
`app/routers/kyc_cases.py`

## Problem / Impact
Five template/witness router endpoints missing

## Fix
add all five endpoints after creating the service

## Notes
This gap was identified by the second-pass as-built review of KYC-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
