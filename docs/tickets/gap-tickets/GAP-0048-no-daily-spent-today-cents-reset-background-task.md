# GAP-0048: no daily spent_today_cents reset background task

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADS-007 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADS-007.md`); see also `docs/tickets/writeups/ADS-007.md`

## Location
`app/services/ad_billing.py:_process_charge`

## Problem / Impact
daily-budget campaigns accumulate spend indefinitely; budget exhaustion is permanent after first day

## Fix
add startup background task resetting spent_today_cents=0 at midnight UTC with last_reset_date guard

## Notes
This gap was identified by the second-pass as-built review of ADS-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
