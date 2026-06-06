# GAP-0165: `display_name` always falls back to `user_sub` for question submitters

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENGAGE-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENGAGE-003.md`); see also `docs/tickets/writeups/ENGAGE-003.md`

## Location
`display_name`

## Problem / Impact
`display_name` always falls back to `user_sub` for question submitters

## Fix
fetch the user's profile display name from the profiles/account service using `ctx["user_sub"]` before calling `submit_question`, or add `display_name` to the session context

## Notes
This gap was identified by the second-pass as-built review of ENGAGE-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
