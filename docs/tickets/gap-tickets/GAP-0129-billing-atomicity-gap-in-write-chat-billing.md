# GAP-0129: Billing atomicity gap in `_write_chat_billing()`

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BCAST-015 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-015.md`); see also `docs/tickets/writeups/BCAST-015.md`

## Location
`_write_chat_billing()`

## Problem / Impact
debit and credit `put_item` calls in separate `try/except`; credit failure after debit = viewer charged, broadcaster not paid (fourth occurrence of same pattern across BCAST-011/012/014)

## Fix
use `TransactWriteItems`; consolidate into shared `write_billing_pair()` utility in `app/services/billing_utils.py`

## Notes
This gap was identified by the second-pass as-built review of BCAST-015. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
