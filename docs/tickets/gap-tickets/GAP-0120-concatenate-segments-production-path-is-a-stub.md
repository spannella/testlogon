# GAP-0120: `concatenate_segments` production path is a stub

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BCAST-006 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/BCAST-006.md`); see also `docs/tickets/writeups/BCAST-006.md`

## Location
`concatenate_segments`

## Problem / Impact
logs segment count then returns `None` even when FFmpeg is present; all production recordings use mock metadata with `duration_seconds=0`

## Fix
implement FFmpeg concat demuxer subprocess + S3 upload via new `_upload_to_s3` helper

## Notes
This gap was identified by the second-pass as-built review of BCAST-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
