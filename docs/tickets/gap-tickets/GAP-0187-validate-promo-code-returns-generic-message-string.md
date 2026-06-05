# GAP-0187: `validate_promo_code` returns generic `message` strings with no machine-readable `error_code`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/FIN-002.md`); see also `docs/tickets/writeups/FIN-002.md`

## Location
`validate_promo_code`

## Problem / Impact
each failure path sets only a human-readable `message`; no `error_code` key is returned; frontend `Checkout.tsx` and future surfaces cannot distinguish `expired` from `usage_limit` programmatically

## Fix
add `error_code` to each `fail` dict return: `not_found`, `deactivated`, `expired`, `usage_limit`, `already_used`, `min_order`, `product_mismatch`, `checkout_type_mismatch`

## Notes
This gap was identified by the second-pass as-built review of FIN-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
