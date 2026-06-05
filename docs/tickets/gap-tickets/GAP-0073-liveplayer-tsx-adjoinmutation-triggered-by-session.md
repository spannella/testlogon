# GAP-0073: LivePlayer.tsx adJoinMutation triggered by session state instead of sessionId

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-020 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-020.md`); see also `docs/tickets/writeups/ADS-020.md`

## Location
`frontend/src/pages/broadcast/LivePlayer.tsx:138–142`

## Problem / Impact
if sessionMutation fails (auth/playback error), adJoinMutation never fires; pre-roll overlay never mounts; causes E2E tests 369.1/369.2 to fail

## Fix
change useEffect dependency from [session] to [sessionId, isAuthenticated] to decouple ad join from playback resolution

## Notes
This gap was identified by the second-pass as-built review of ADS-020. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
