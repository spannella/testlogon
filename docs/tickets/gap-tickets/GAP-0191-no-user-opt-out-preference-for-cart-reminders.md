# GAP-0191: No user opt-out preference for cart reminders

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-003 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-003.md`); see also `docs/tickets/writeups/FIN-003.md`

## Location
`app/routers/shoppingcart.py`

## Problem / Impact
there is no `GET/PUT /ui/shoppingcart/reminders/preferences` endpoint, no `OPTOUT` row in any DDB table, and no opt-out check in `send_cart_reminder`; users who have opted out of emails still receive reminders

## Fix
add opt-out storage in `cart_reminder_config` table (`OPTOUT/USER#{sub}` row), `is_user_opted_out()`, and preference endpoints

## Notes
This gap was identified by the second-pass as-built review of FIN-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
