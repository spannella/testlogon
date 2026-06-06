# GAP-0284: `_bulk_fetch` fetches translations one-by-one with individual `GetItem` calls instead of using DynamoDB `BatchGetItem`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-020 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-020.md`); see also `docs/tickets/writeups/KYC-020.md`

## Location
`_bulk_fetch`

## Problem / Impact
`_bulk_fetch` fetches translations one-by-one with individual `GetItem` calls instead of using DynamoDB `BatchGetItem`

## Fix
replace the loop in `_bulk_fetch` with DDB `batch_get_item` (chunked in batches of 100), then fall back to individual `GetItem` only for cache-missed items

## Notes
This gap was identified by the second-pass as-built review of KYC-020. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
