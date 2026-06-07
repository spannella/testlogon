# GAP-0363: execute_split writes ledger credit entries for each member but never calls `apply_wallet_delta`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SYND-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/SYND-003.md`); see also `docs/tickets/writeups/SYND-003.md`

## Location
`apply_wallet_delta`

## Problem / Impact
members receive a ledger credit record but their spendable wallet balance (`wallet_balance_cents` on their billing row) is never incremented; payout and wallet-balance endpoints will show $0 despite the member having earned revenue share

## Fix
add `apply_wallet_delta(T.billing, f"USER#{dist['user_id']}", dist["amount_cents"])` for each distribution entry

## Notes
This gap was identified by the second-pass as-built review of SYND-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
