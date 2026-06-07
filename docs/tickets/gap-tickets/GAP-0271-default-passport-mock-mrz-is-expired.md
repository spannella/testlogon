# GAP-0271: Default passport mock MRZ is expired

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-010 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/KYC-010.md`); see also `docs/tickets/writeups/KYC-010.md`

## Location
`app/services/kyc_id_scanner.py`

## Problem / Impact
mock passport expiry `120415` parses to April 15, 2012; any E2E test calling `POST scan-document` without supplying `mrz_lines` gets `status="rejected"` instead of `"matched"`

## Fix
update `_MOCK_MRZ` passport expiry to a future date (e.g., `361231` → 2036-12-31) with recomputed check digits; or document required `mrz_lines` test fixture

## Notes
This gap was identified by the second-pass as-built review of KYC-010. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
