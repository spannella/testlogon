# GAP-0121: `_upload_to_s3` helper missing

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BCAST-006 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/BCAST-006.md`); see also `docs/tickets/writeups/BCAST-006.md`

## Location
`_upload_to_s3`

## Problem / Impact
comment `# Upload to S3 would happen here in production`; MP4 and HLS output never uploaded

## Fix
create `_upload_to_s3(local_path, *, bucket, key)` using `boto3.client("s3", endpoint_url=...)`

## Notes
This gap was identified by the second-pass as-built review of BCAST-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
