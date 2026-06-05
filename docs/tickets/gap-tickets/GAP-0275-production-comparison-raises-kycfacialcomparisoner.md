# GAP-0275: Production comparison raises `KycFacialComparisonError("comparison_service_error")` unconditionally

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-014 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/KYC-014.md`); see also `docs/tickets/writeups/KYC-014.md`

## Location
`KycFacialComparisonError("comparison_service_error")`

## Problem / Impact
Any deployment with `dev_mode=False` will return 500 on every comparison attempt; no AWS Rekognition or alternative provider is wired

## Fix
implement `_production_compare()` to call `boto3.client("rekognition").compare_faces()` with the S3 object references, or gate with a feature flag that routes to mock until production provider is configured

## Notes
This gap was identified by the second-pass as-built review of KYC-014. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
