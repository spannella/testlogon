# GAP-0020: TIN/SSN collection and KMS-encrypted storage absent

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: FIN-008 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/FIN-008.md`); see also `docs/tickets/writeups/FIN-008.md`

## Location
`app/services/tax_form_1099.py:55`

## Problem / Impact
1099 PDFs contain a hardcoded placeholder TIN, making generated forms non-compliant with IRS 1099-NEC requirements; no W-9 form submission path exists

## Fix
implement `submit_tax_info()` with `kms_encrypt(tin)` before storage, replace placeholder with real recipient TIN in `_render_1099_pdf`

## Notes
This gap was identified by the second-pass as-built review of FIN-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
