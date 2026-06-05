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
