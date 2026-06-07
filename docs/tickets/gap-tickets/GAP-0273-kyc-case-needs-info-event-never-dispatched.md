# GAP-0273: `kyc.case.needs_info` event never dispatched

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-011.md`); see also `docs/tickets/writeups/KYC-011.md`

## Location
`kyc.case.needs_info`

## Problem / Impact
`kyc.case.needs_info` event never dispatched

## Fix
add `_emit_kyc_event_safe(event="kyc.case.needs_info", user_sub=case["user_sub"], case_id=case_id, requested_items=..., note=...)` after the successful DDB update

## Notes
This gap was identified by the second-pass as-built review of KYC-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
