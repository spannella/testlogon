# GAP-0308: Payout balance calculation (`get_available_balance`) does not exclude `state=reversed` credit entries

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MON-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/MON-004.md`); see also `docs/tickets/writeups/MON-004.md`

## Location
`get_available_balance`

## Problem / Impact
chargebacked subscription payments and refunded tip credits inflate the available balance, allowing creators to withdraw funds that were actually reversed; this is a direct financial loss to the platform

## Fix
add `Attr("state").ne("reversed")` to the FilterExpression on the billing query; also exclude `amount_cents=0` subscription-access entitlement records

## Notes
This gap was identified by the second-pass as-built review of MON-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
