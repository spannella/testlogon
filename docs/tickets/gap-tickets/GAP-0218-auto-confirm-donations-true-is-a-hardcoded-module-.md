# GAP-0218: `_AUTO_CONFIRM_DONATIONS = True` is a hardcoded module-level constant, not gated on `S.dev_mode`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: GROUP-003 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/GROUP-003.md`); see also `docs/tickets/writeups/GROUP-003.md`

## Location
`_AUTO_CONFIRM_DONATIONS = True`

## Problem / Impact
in production this would auto-confirm every donation without waiting for a real Stripe webhook, crediting the treasury for payments that have not actually cleared; any donation attempt (even a failed card) would be auto-confirmed and the treasury credited

## Fix
change to `_AUTO_CONFIRM_DONATIONS = S.dev_mode` so prod requires Stripe webhook confirmation; implement a `POST /internal/fundraisers/{id}/donations/{id}/confirm` webhook handler for production

## Notes
This gap was identified by the second-pass as-built review of GROUP-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
