# GAP-0034: VideoMetadata.hls_manifest_url never populated after transcoding

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: VOD-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/VOD-005.md`); see also `docs/tickets/writeups/VOD-005.md`

## Location
`app/services/transcode_worker.py:195`

## Problem / Impact
VideoMetadata.hls_manifest_url never populated after transcoding

## Fix
after `complete_job_with_outputs`, fetch the VideoMetadata record and update `hls_manifest_url`, `thumbnail_url`, and renditions via `put_item`

## Notes
This gap was identified by the second-pass as-built review of VOD-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
