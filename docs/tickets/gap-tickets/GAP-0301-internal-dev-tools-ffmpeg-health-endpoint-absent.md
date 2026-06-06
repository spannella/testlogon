# GAP-0301: `/internal/dev-tools/ffmpeg-health` endpoint absent

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MEDIA-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/MEDIA-002.md`); see also `docs/tickets/writeups/MEDIA-002.md`

## Location
`/internal/dev-tools/ffmpeg-health`

## Problem / Impact
no HTTP health-check surface for FFmpeg; devtools UI cannot display binary status; monitoring integrations have no structured signal for FFmpeg availability

## Fix
add `GET /internal/dev-tools/ffmpeg-health` to `internal_devtools.py` calling `validate_ffmpeg()` from `ffmpeg_manager`

## Notes
This gap was identified by the second-pass as-built review of MEDIA-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
