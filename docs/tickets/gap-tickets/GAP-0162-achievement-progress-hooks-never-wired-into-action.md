# GAP-0162: Achievement progress hooks never wired into action handlers

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENGAGE-001 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/ENGAGE-001.md`); see also `docs/tickets/writeups/ENGAGE-001.md`

## Location
`app/routers/newsfeed.py`

## Problem / Impact
achievements_enabled flag is false by default and none of the listed integration points (post creation, tip, broadcast start, subscribe, comment, follow, unlock, reaction, encrypted msg, calendar share) call `advance_progress` or `update_streak`, so no achievement ever auto-unlocks except via the admin endpoint

## Fix
add try/except advance_progress calls at each listed integration point (see ticket section 3.7)

## Notes
This gap was identified by the second-pass as-built review of ENGAGE-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
