# GAP-0279: `_readiness_for_case` in `app/routers/kyc_cases.py` (line 244) does not include template-signing completeness check

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-017 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-017.md`); see also `docs/tickets/writeups/KYC-017.md`

## Location
`_readiness_for_case`

## Problem / Impact
the ticket specifies (§3.6) that `_readiness_for_case` must check whether all tier-required templates have been signed and add `"unsigned_templates:..."` to `missing_requirements`; the current implementation checks only questionnaire, files, and signature packet without consulting `KycDocumentTemplateService.get_required_templates_for_tier()`; cases with un-signed template documents will appear ready when they are not

## Fix
add a `KYC_TEMPLATE_READINESS_GATE`-gated call to `SERVICE.get_required_templates_for_tier(target_tier)` in `_readiness_for_case` and append any missing slugs to `missing_requirements`

## Notes
This gap was identified by the second-pass as-built review of KYC-017. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
