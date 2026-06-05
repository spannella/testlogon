# GAP-0132: Marketplace refund missing seller-side debit

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BILLING-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/BILLING-001.md`); see also `docs/tickets/writeups/BILLING-001.md`

## Location
`app/routers/billing.py:1164-1179`

## Problem / Impact
approve path only adjusts buyer balance; seller retains the credit for tipped/unlocked amount, enabling double-enrichment on refund

## Fix
write paired seller-DEBIT ledger entry via `new_ledger_entry()` when `reason` indicates tip/unlock

## Notes
This gap was identified by the second-pass as-built review of BILLING-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
