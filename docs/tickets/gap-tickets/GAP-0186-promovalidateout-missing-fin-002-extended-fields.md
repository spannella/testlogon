# GAP-0186: `PromoValidateOut` missing FIN-002 extended fields

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/FIN-002.md`); see also `docs/tickets/writeups/FIN-002.md`

## Location
`PromoValidateOut`

## Problem / Impact
the response model lacks `error_code`, `discount_pct`, `original_price_cents`, `buy_x`, `get_y`, `free_item_description` fields defined in the ticket spec; frontend cannot render type-specific discount badges or specific error messages

## Fix
extend `PromoValidateOut` with the new optional fields and populate them in `validate_promo_code`

## Notes
This gap was identified by the second-pass as-built review of FIN-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
