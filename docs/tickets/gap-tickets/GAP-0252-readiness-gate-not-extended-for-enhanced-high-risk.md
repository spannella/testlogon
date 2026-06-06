# GAP-0252: Readiness gate not extended for enhanced/high_risk profiles

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-004.md`); see also `docs/tickets/writeups/KYC-004.md`

## Location
`app/routers/kyc_cases.py:244`

## Problem / Impact
users with `intake_profile=enhanced` or `high_risk` can submit without any residency document; violates AML/CDD enhanced due diligence requirements

## Fix
add residency check block using `RESIDENCY_STORE.get_verified_docs_for_case(case_id)` gated on `intake_profile in ("enhanced","high_risk")`

## Notes
This gap was identified by the second-pass as-built review of KYC-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
