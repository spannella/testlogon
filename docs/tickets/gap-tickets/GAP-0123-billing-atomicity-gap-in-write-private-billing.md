# GAP-0123: Billing atomicity gap in `_write_private_billing()`

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BCAST-011 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-011.md`); see also `docs/tickets/writeups/BCAST-011.md`

## Location
`_write_private_billing()`

## Problem / Impact
debit and credit `put_item` calls wrapped in separate `try/except`; failed credit after successful debit = viewer charged, creator not paid

## Fix
use `TransactWriteItems` for atomic debit+credit; raise 500 on failure instead of silently swallowing

## Notes
This gap was identified by the second-pass as-built review of BCAST-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
