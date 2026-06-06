# GAP-0280: Address-change detection hook is NOT wired into `app/services/profile.py`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-018 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-018.md`); see also `docs/tickets/writeups/KYC-018.md`

## Location
`app/services/profile.py`

## Problem / Impact
the ticket (§4.7) specifies that `update_profile` must compare old vs new address fields and call `AddressVerificationService.invalidate_verification(case_id=...)` for any active KYC cases when address changes; this cross-service hook was never added; users who change their address after verification will retain a stale `verified` status, allowing them to pass tier-2 readiness checks with an outdated address

## Fix
in `profile.py`'s `update_profile` function, after a successful DDB write, check if `address_line_1`, `city`, `state`, `postal_code`, or `country` changed and call `STORE.invalidate_verification` for each active KYC case for the user

## Notes
This gap was identified by the second-pass as-built review of KYC-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
