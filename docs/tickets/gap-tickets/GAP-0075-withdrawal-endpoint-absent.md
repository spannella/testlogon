# GAP-0075: Withdrawal endpoint absent

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AFFILIATE-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AFFILIATE-001.md`); see also `docs/tickets/writeups/AFFILIATE-001.md`

## Location
`POST /ui/referrals/withdraw`

## Problem / Impact
users can view earned commissions but cannot redeem them; MON-004 payout integration is entirely missing

## Fix
implement `withdraw(user_id, amount_cents)` in service and add router endpoint per ticket §8 spec

## Notes
This gap was identified by the second-pass as-built review of AFFILIATE-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
