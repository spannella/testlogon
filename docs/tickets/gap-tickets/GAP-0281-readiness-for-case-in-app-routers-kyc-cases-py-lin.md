# GAP-0281: `_readiness_for_case` in `app/routers/kyc_cases.py` (line 244) does not gate tier_2/tier_3 cases on address verification status

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-018 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-018.md`); see also `docs/tickets/writeups/KYC-018.md`

## Location
`_readiness_for_case`

## Problem / Impact
the ticket (§4.8) specifies that for tier_2 and tier_3 cases the readiness check must include `"address_not_verified"` in `missing_requirements` when `address_verification.status` is not `verified` or `partial_match`; the current `_readiness_for_case` has no such check; tier_2 cases can be submitted without a verified address

## Fix
add a `KYC_ADDRESS_VERIFICATION_ENABLED`-gated check inside `_readiness_for_case` that queries `STORE.get_latest(case_id)` and appends `"address_not_verified"` to `missing_requirements` when the target tier requires it

## Notes
This gap was identified by the second-pass as-built review of KYC-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
