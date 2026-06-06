# GAP-0302: `thumbnail_url` / `hls_manifest_url` not populated in dev

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MOD-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/MOD-001.md`); see also `docs/tickets/writeups/MOD-001.md`

## Location
`thumbnail_url`

## Problem / Impact
fields are passed through from `VideoMetadataModel` but the ABR pipeline only writes these when a real transcode completes; in the local dev environment (moto S3, no real FFmpeg transcode), both fields are `null` for all pending-review videos, making the review UI a blank preview pane

## Fix
in dev mode, synthesize a mock `hls_manifest_url` from S3 mock path (same pattern used in `_message_out_from_item` for file messages)

## Notes
This gap was identified by the second-pass as-built review of MOD-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
