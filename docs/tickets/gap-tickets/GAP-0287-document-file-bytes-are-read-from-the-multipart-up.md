# GAP-0287: Document file bytes are read from the multipart upload but never stored in S3

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-021 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-021.md`); see also `docs/tickets/writeups/KYC-021.md`

## Location
`app/routers/kyc_partner_api.py:196-204`

## Problem / Impact
Document file bytes are read from the multipart upload but never stored in S3

## Fix
upload `contents` to S3 under `kyc-api-docs/{partner_id}/{application_id}/{document_id}` and pass the resulting S3 key to `upload_document()`; store the key on the document dict and expose a download endpoint

## Notes
This gap was identified by the second-pass as-built review of KYC-021. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
