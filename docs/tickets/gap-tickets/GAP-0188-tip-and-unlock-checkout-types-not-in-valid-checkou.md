# GAP-0188: `"tip"` and `"unlock"` checkout types not in `VALID_CHECKOUT_TYPES`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-002 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-002.md`); see also `docs/tickets/writeups/FIN-002.md`

## Location
`"tip"`

## Problem / Impact
set is `{"subscription", "vod", "shop"}`; promo codes created for tips or unlocks cannot be validated; FIN-002 spec requires tip/unlock surfaces

## Fix
add `"tip"` and `"unlock"` to `VALID_CHECKOUT_TYPES` and implement corresponding endpoint hooks in `app/routers/messaging.py` and `app/routers/newsfeed.py`

## Notes
This gap was identified by the second-pass as-built review of FIN-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
