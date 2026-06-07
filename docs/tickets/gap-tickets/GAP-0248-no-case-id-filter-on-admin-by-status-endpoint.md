# GAP-0248: No `case_id` filter on admin by-status endpoint

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-002.md`); see also `docs/tickets/writeups/KYC-002.md`

## Location
`case_id`

## Problem / Impact
listing all documents across statuses for a specific case requires multiple calls or a full scan; no `case_id` query param exists

## Fix
add optional `case_id: str | None = Query(default=None)` with client-side `FilterExpression` on GSI result

## Notes
This gap was identified by the second-pass as-built review of KYC-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
