# GAP-0194: Admin TIN reveal endpoint missing

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-008 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-008.md`); see also `docs/tickets/writeups/FIN-008.md`

## Location
`app/routers/tax_form_1099.py`

## Problem / Impact
Admins cannot retrieve full decrypted TIN for compliance review; no IP-logged audit trail for TIN access

## Fix
add admin TIN reveal endpoint with `kms_decrypt` + `_write_tax_audit(action="tin_viewed", actor, target, ip)`

## Notes
This gap was identified by the second-pass as-built review of FIN-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
