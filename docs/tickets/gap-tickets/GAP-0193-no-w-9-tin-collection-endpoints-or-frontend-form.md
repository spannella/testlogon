# GAP-0193: No W-9/TIN collection endpoints or frontend form

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-008 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/FIN-008.md`); see also `docs/tickets/writeups/FIN-008.md`

## Location
`app/routers/tax_form_1099.py`

## Problem / Impact
Creators cannot submit tax information; the tax info page specified in the ticket does not exist

## Fix
add W-9 submission router endpoints, `W9SubmissionIn`/`TaxInfoOut` models, `TaxInfoPage.tsx`

## Notes
This gap was identified by the second-pass as-built review of FIN-008. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Resolved — already implemented (verified 2026-06-06)

SKIP/already-built: the W-9/TIN collection workflow this gap describes is already implemented under GAP-0020/FIN-008 — POST/GET /ui/tax-forms/w9, W9SubmitIn/W9StatusOut, app/services/tax_info_w9.py (KMS-encrypted TIN), and the 1099 renderer reads the real TIN. Covered by tests/test_tax_info_w9_gap0020.py. No code change needed.
