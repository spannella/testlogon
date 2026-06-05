# GAP-0122: MP4 never uploaded to S3 in production path

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BCAST-008 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-008.md`); see also `docs/tickets/writeups/BCAST-008.md`

## Location
`broadcast_recording_worker.py:130`

## Problem / Impact
FFmpeg runs successfully but comment `# Upload to S3 would happen here in production` means the file stays on local disk; download URLs return 403/404

## Fix
implement `_upload_to_s3(local_path, bucket, key)` and call it after FFmpeg in `generate_mp4`

## Notes
This gap was identified by the second-pass as-built review of BCAST-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
