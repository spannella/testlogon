# GAP-0370: No client-side forensic watermark overlay

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-008 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/VOD-008.md`); see also `docs/tickets/writeups/VOD-008.md`

## Location
`frontend/src/pages/videos/VideoPlayerPage.tsx:479-504`

## Problem / Impact
Spec requires a `WatermarkOverlay` component with semi-transparent session ID text rendered over the player surface as a secondary deterrent against screen recording; the player renders `<MediaPlayer>` with no overlay div

## Fix
Add `<WatermarkOverlay sessionId={video.playback_token?.slice(0,12)} tenantId={video.owner_user_id} />` absolutely positioned over the player container

## Notes
This gap was identified by the second-pass as-built review of VOD-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
