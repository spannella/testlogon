# GAP-0326: No toll-fraud global spending cap (SEC-014)

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-007 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PLATFORM-007.md`); see also `docs/tickets/writeups/PLATFORM-007.md`

## Location
`app/services/sms_delivery.py`

## Problem / Impact
Only a per-number daily limit (`sms_daily_limit_per_number=10`) exists; there is no global daily SMS spend ceiling, no per-country rate cap, and no absolute cost limiter to prevent toll-fraud pump attacks. SEC-014 requires a configurable daily cost cap (e.g., `SMS_DAILY_COST_CAP_USD`) that halts all outbound SMS once the estimated spend exceeds the threshold

## Fix
add `sms_daily_cost_cap_usd` setting; in `send_sms()` at `sms_delivery.py:174`, check cumulative daily segment count * cost-per-segment before publishing and return `rate_limited` if exceeded

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
