# GAP-0359: No rate limiting on `GET /ui/search`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SOCIAL-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/SOCIAL-003.md`); see also `docs/tickets/writeups/SOCIAL-003.md`

## Location
`GET /ui/search`

## Problem / Impact
any authenticated user can issue unlimited search requests per second, fan-out to 8+ backend modules; CPU and DDB read amplification attack possible

## Fix
add `check_rate_limit(user_id, "global_search", max=30, window=60)` at the top of the aggregator endpoint

## Notes
This gap was identified by the second-pass as-built review of SOCIAL-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
