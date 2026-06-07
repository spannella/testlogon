# GAP-0253: `get_verified_docs_for_case` helper missing

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-004.md`); see also `docs/tickets/writeups/KYC-004.md`

## Location
`get_verified_docs_for_case`

## Problem / Impact
`get_verified_docs_for_case` helper missing

## Fix
add `get_verified_docs_for_case(case_id)` querying the ByStatus GSI with `status=verified` and `FilterExpression: case_id`

## Notes
This gap was identified by the second-pass as-built review of KYC-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Implemented together with GAP-0252: get_verified_docs_for_case() added to KycResidencyStore in app/services/kyc_residency.py (reuses list_documents_for_case ByCase GSI + filters status==verified). Covered by tests/test_gap_0252_kyc_residency_gate.py (Class 2 exercises the real path). Verified present.
