# GAP-0045: ad_feedback records accumulate without TTL

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-005 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-005.md`); see also `docs/tickets/writeups/ADS-005.md`

## Location
`app/services/ad_feedback.py:record_ad_feedback`

## Problem / Impact
at scale (10M users × 20 hides) billing table grows to 200M+ items with no cleanup

## Fix
add expires_at = now_ts() + 90*86400 to every feedback item; enable TTL on billing table

## Notes
This gap was identified by the second-pass as-built review of ADS-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
