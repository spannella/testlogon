# GAP-0261: `app/services/kyc_signature_templates.py` does not exist

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: KYC-007 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/KYC-007.md`); see also `docs/tickets/writeups/KYC-007.md`

## Location
`app/services/kyc_signature_templates.py`

## Problem / Impact
five hard-coded KYC consent/declaration templates (terms_of_service, aml_declaration, pep_declaration, tax_compliance, data_consent) with auto-populate and version tracking are absent

## Fix
create service with `KYC_TEMPLATE_TYPES` dict, `create_packets_for_case()`, `check_version_migration()`, and `auto_populate_fields()` calling `signature_packet_store.upsert_packet_field()` at line 133

## Notes
This gap was identified by the second-pass as-built review of KYC-007. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
