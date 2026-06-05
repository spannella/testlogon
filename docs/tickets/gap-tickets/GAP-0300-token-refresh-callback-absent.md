# GAP-0300: token refresh callback absent

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MEDIA-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/MEDIA-001.md`); see also `docs/tickets/writeups/MEDIA-001.md`

## Location
`frontend/src/components/shared/MediaPlayer.tsx:1`

## Problem / Impact
token refresh callback absent

## Fix
add `onTokenExpiring?: () => Promise<string>` prop; schedule refresh 30s before JWT `exp` claim; update `hls.config.xhrSetup` with new token

## Notes
This gap was identified by the second-pass as-built review of MEDIA-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
