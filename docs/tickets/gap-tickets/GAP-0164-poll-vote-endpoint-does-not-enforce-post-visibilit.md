# GAP-0164: Poll vote endpoint does not enforce post visibility/subscription gate

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENGAGE-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENGAGE-002.md`); see also `docs/tickets/writeups/ENGAGE-002.md`

## Location
`app/routers/newsfeed.py:6659`

## Problem / Impact
Poll vote endpoint does not enforce post visibility/subscription gate

## Fix
reuse the existing visibility/entitlement check from `_post_to_dict` or extract a shared `_check_post_access(post, user_id)` guard and call it before `cast_vote`

## Notes
This gap was identified by the second-pass as-built review of ENGAGE-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
