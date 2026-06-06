# GAP-0192: `/receipts/zip` bulk export endpoint not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-004.md`); see also `docs/tickets/writeups/FIN-004.md`

## Location
`/receipts/zip`

## Problem / Impact
no `GET /ui/tax-documents/receipts/zip` endpoint exists; the FIN-004 spec requires bundling individual invoice PDFs for a date range into a ZIP download

## Fix
add `export_receipts_zip()` in the service and a `/receipts/zip` router endpoint using Python stdlib `zipfile` and S3 invoice fetches

## Notes
This gap was identified by the second-pass as-built review of FIN-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
