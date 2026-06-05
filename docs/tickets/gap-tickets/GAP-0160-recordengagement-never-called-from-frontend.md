# GAP-0160: recordEngagement never called from frontend

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: DISC-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/DISC-001.md`); see also `docs/tickets/writeups/DISC-001.md`

## Location
`frontend/src/pages/videos/VideoPlayerPage.tsx`

## Problem / Impact
POST /ui/recommendations/engagement endpoint is live but zero signals are recorded; compute_affinity_scores always receives empty input

## Fix
call recordEngagement on video onEnded and at 30-second mark in VideoPlayerPage

## Notes
This gap was identified by the second-pass as-built review of DISC-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
