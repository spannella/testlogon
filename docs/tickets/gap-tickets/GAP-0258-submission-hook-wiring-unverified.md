# GAP-0258: Submission hook wiring unverified

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-006 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-006.md`); see also `docs/tickets/writeups/KYC-006.md`

## Location
`app/routers/kyc_cases.py:830`

## Problem / Impact
the architectural intent is for `SCREENING_STORE.screen_case()` to fire on every submission; whether the call is actually stitched at line 830 is noted as unconfirmed in the write-up

## Fix
verify the hook exists; if absent, add `SCREENING_STORE.screen_case(case_id, user_sub, trigger="submission")` wrapped in try/except so screening failure does not block submission

## Notes
This gap was identified by the second-pass as-built review of KYC-006. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
