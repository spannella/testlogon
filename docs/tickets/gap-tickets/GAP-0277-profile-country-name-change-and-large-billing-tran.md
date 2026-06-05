# GAP-0277: Profile country/name change and large billing transactions never create trigger events

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-016 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-016.md`); see also `docs/tickets/writeups/KYC-016.md`

## Location
`app/routers/profile.py`

## Problem / Impact
The ticket integration points (`create_trigger_event` calls after profile nationality/name updates and after payments exceeding `kyc_large_transaction_threshold_cents`) are absent from both routers; the monitoring system is effectively blind to these events

## Fix
add `create_trigger_event(user_sub, "country_change", ...)` in the profile update handler and `create_trigger_event(user_sub, "large_transaction", ...)` in the billing payment handler

## Notes
This gap was identified by the second-pass as-built review of KYC-016. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
