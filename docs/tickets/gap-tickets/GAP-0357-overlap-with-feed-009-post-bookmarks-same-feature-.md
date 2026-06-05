# GAP-0357: Overlap with FEED-009 (post bookmarks): same feature, separate tickets

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SOCIAL-001 · **Effort**: ?
**From**: gap audit (`docs/tickets/gaps/SOCIAL-001.md`); see also `docs/tickets/writeups/SOCIAL-001.md`

## Location
`docs/tickets/gaps/FEED-009.md`

## Problem / Impact
see `docs/tickets/gaps/FEED-009.md` for all implementation gaps; SOCIAL-001 and FEED-009 describe the same bookmark/collections system and share the same codebase (`app/routers/newsfeed.py:6277-6470`, `frontend/src/pages/saved/SavedPage.tsx`); gaps already catalogued in FEED-009.md apply equally here

## Fix
See source write-up.

## Notes
This gap was identified by the second-pass as-built review of SOCIAL-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
