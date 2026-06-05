# GAP-0371: No automatic playback token refresh

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-008 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/VOD-008.md`); see also `docs/tickets/writeups/VOD-008.md`

## Location
`frontend/src/pages/videos/VideoPlayerPage.tsx:375-378`

## Problem / Impact
The player uses a static `playback_token` field from the video detail response (`video?.playback_token`); if the token expires during a long viewing session HLS.js will receive 401/403 on manifest/segment fetches causing fatal playback errors with no recovery path

## Fix
Add `usePlaybackEntitlement` hook with `refetchInterval: 90_000` to rotate the token before expiry and update the `playbackUrl` ref without tearing down the HLS instance

## Notes
This gap was identified by the second-pass as-built review of VOD-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
