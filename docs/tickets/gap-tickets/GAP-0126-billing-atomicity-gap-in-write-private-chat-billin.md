# GAP-0126: Billing atomicity gap in `_write_private_chat_billing()`

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BCAST-012 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-012.md`); see also `docs/tickets/writeups/BCAST-012.md`

## Location
`_write_private_chat_billing()`

## Problem / Impact
debit and credit `put_item` calls in separate `try/except`; credit failure after debit = viewer charged, creator not paid

## Fix
use `TransactWriteItems` for atomic debit+credit

## Notes
This gap was identified by the second-pass as-built review of BCAST-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
