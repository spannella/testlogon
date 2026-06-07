# GAP-0272: `kyc.case.approved` and `kyc.case.rejected` events never dispatched

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-011.md`); see also `docs/tickets/writeups/KYC-011.md`

## Location
`kyc.case.approved`

## Problem / Impact
`kyc.case.approved` and `kyc.case.rejected` events never dispatched

## Fix
add `_emit_kyc_event_safe(event="kyc.case.approved", user_sub=..., case_id=...)` / `kyc.case.rejected` at the end of `apply_admin_decision()` after a successful DDB update

## Notes
This gap was identified by the second-pass as-built review of KYC-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
