# GAP-0185: TOCTOU window between status check and atomic increment

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FILES-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/FILES-001.md`); see also `docs/tickets/writeups/FILES-001.md`

## Location
`app/services/file_share_links.py:297-317`

## Problem / Impact
both are already partially present at line 321; confirm `is_revoked` is included in the expression and not just the pre-check)

## Fix
fold the `is_revoked` and `expires_at` checks into the `ConditionExpression` (add `& Attr("is_revoked").ne(True) & Attr("expires_at").gt(now_ts())`

## Notes
This gap was identified by the second-pass as-built review of FILES-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
