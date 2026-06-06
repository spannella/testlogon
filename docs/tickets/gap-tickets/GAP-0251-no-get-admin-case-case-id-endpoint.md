# GAP-0251: No `GET /admin/case/{case_id}` endpoint

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-003.md`); see also `docs/tickets/writeups/KYC-003.md`

## Location
`GET /admin/case/{case_id}`

## Problem / Impact
admin must filter the by-status GSI across all statuses to find a call for a specific case; no direct case-level lookup exists

## Fix
add `GET /admin/case/{case_id}` backed by `STORE.get_call_for_case(case_id)` querying ByStatus GSI and filtering by `case_id`

## Notes
This gap was identified by the second-pass as-built review of KYC-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
