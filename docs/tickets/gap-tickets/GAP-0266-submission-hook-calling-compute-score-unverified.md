# GAP-0266: Submission hook calling `compute_score()` unverified

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-008 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-008.md`); see also `docs/tickets/writeups/KYC-008.md`

## Location
`compute_score()`

## Problem / Impact
ticket spec requires `compute_score()` to fire after screening; whether the call is stitched at line 830 is not confirmed

## Fix
verify hook exists; if absent, add `KycRiskScoringService().compute_score(...)` in try/except after KYC-006 screening call

## Notes
This gap was identified by the second-pass as-built review of KYC-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
