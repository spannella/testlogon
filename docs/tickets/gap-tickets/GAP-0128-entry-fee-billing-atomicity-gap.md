# GAP-0128: Entry fee billing atomicity gap

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BCAST-014 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-014.md`); see also `docs/tickets/writeups/BCAST-014.md`

## Location
`broadcast_lottery.py:484`

## Problem / Impact
debit and credit `put_item` calls in separate `try/except`; credit failure after debit = entrant charged, broadcaster not credited

## Fix
use `TransactWriteItems` for atomic debit+credit (same pattern as BCAST-011/012)

## Notes
This gap was identified by the second-pass as-built review of BCAST-014. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
