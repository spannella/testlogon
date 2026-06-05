# GAP-0001: no daily spent_today_cents reset task

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: ADS-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADS-004.md`); see also `docs/tickets/writeups/ADS-004.md`

## Location
`app/services/ad_serving.py:_has_budget`

## Problem / Impact
daily-budget campaigns exhaust first-day cap and never resume serving

## Fix
add startup background task that resets spent_today_cents=0 at midnight UTC for budget_type=daily campaigns

## Notes
This gap was identified by the second-pass as-built review of ADS-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
