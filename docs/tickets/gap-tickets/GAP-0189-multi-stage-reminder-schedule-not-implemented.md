# GAP-0189: Multi-stage reminder schedule not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: FIN-003 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/FIN-003.md`); see also `docs/tickets/writeups/FIN-003.md`

## Location
`app/services/shoppingcart.py:781-846`

## Problem / Impact
Multi-stage reminder schedule not implemented

## Fix
create `app/services/cart_reminders.py` with `process_abandoned_carts()` that reads from a `cart_reminder_config` DDB table and advances each cart through numbered stages

## Notes
This gap was identified by the second-pass as-built review of FIN-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
