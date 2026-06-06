# GAP-0168: `_count_user_clips_for_session` uses `FilterExpression` with `Select=COUNT` but no pagination

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENGAGE-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENGAGE-005.md`); see also `docs/tickets/writeups/ENGAGE-005.md`

## Location
`_count_user_clips_for_session`

## Problem / Impact
DDB applies `FilterExpression` after reading up to 1 MB of items; for a busy session with many clips, a single `query()` call with `Select=COUNT` and a `FilterExpression` may silently under-count, allowing a user to exceed `_MAX_CLIPS_PER_BROADCAST=10`

## Fix
loop on `LastEvaluatedKey` to aggregate the full count across all pages

## Notes
This gap was identified by the second-pass as-built review of ENGAGE-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
