# GAP-0381: `static/ads/` directory and placeholder creative files do not exist

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-018 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/VOD-018.md`); see also `docs/tickets/writeups/VOD-018.md`

## Location
`static/ads/`

## Problem / Impact
dev-mode ad slot URLs reference `/static/ads/placeholder_preroll.mp4`, `placeholder_midroll.mp4`, and `placeholder_overlay.png` but the directory `app/static/ads/` is absent; player requests for these assets return 404, breaking the full ad flow in dev/test

## Fix
create `app/static/ads/` and add placeholder files (e.g., generated with ffmpeg for the MP4s and a solid-color PNG)

## Notes
This gap was identified by the second-pass as-built review of VOD-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
