# GAP-0342: Promo codes not integrated into subscription checkout

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PROMO-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PROMO-001.md`); see also `docs/tickets/writeups/PROMO-001.md`

## Location
`app/routers/subscription_server.py`

## Problem / Impact
Customers entering a promo code at subscription checkout get no discount; the entire new promo system is disconnected from the only checkout flow that exists

## Fix
add optional `promo_code: str | None` to `SubscribeIn` and call `promo_codes.validate_promo_code` + `redeem_promo_code` inside the subscribe handler, re-using the TOCTOU guard pattern described in ticket §3

## Notes
This gap was identified by the second-pass as-built review of PROMO-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
