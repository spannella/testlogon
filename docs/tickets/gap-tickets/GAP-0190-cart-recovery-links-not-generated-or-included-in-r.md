# GAP-0190: Cart recovery links not generated or included in reminder emails

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-003 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-003.md`); see also `docs/tickets/writeups/FIN-003.md`

## Location
`app/services/shoppingcart.py:824-835`

## Problem / Impact
the email body is a plain string with no unique recovery URL; clicking the link requires the user to already be logged in and to navigate to `/cart`; there is no `RECOVERY` token record, no `recover_cart` endpoint, and no one-time-use token flow

## Fix
add `generate_recovery_link()` and `recover_cart()` in `cart_reminders.py`; add `GET /ui/shoppingcart/recover/{token}` public endpoint; embed the recovery URL in the reminder email body

## Notes
This gap was identified by the second-pass as-built review of FIN-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
