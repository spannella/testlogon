# GAP-0026: Revenue split hooks absent from all qualifying billing flows

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: LICENSE-003 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/LICENSE-003.md`); see also `docs/tickets/writeups/LICENSE-003.md`

## Location
`app/routers/messaging.py`

## Problem / Impact
Revenue split hooks absent from all qualifying billing flows

## Fix
add `process_revenue_split(...)` call after the primary ledger entry in each qualifying billing handler (messaging tip/unlock, newsfeed post tip/unlock, vod_purchase sale)

## Notes
This gap was identified by the second-pass as-built review of LICENSE-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
