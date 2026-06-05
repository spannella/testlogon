# GAP-0285: KYC questionnaire endpoint `start_kyc_questionnaire` (line 625) and email notifications do NOT call `kyc_translation_service.localize_questionnaire()` / `localize_email()`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-020 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/KYC-020.md`); see also `docs/tickets/writeups/KYC-020.md`

## Location
`start_kyc_questionnaire`

## Problem / Impact
the ticket (§4.9) specifies wiring `?lang=` into the questionnaire endpoint and calling `localize_email()` on all KYC case-status transition alert paths; neither integration is present; the service and router are fully built but not connected to the existing KYC flows; users always receive English questionnaires regardless of their locale

## Fix
add `lang: str = Query(default=None)` to `start_kyc_questionnaire`, resolve locale via `kyc_translation_service.resolve_locale_for_user()`, and call `localize_questionnaire()` before returning; add locale-aware email path to `apply_admin_decision` and `admin_request_more_info`

## Notes
This gap was identified by the second-pass as-built review of KYC-020. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
