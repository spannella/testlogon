# SEC-004: Billing Authorization & Ledger Integrity

**Ticket**: SEC-004 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: `docs/security-audit-2026-06.md` (items 3 + money findings)

## Problem
- 🛡️ **Wallet `user_sub` IDOR** — `app/routers/billing.py:2316` (deposit) & `:2398`
  (withdraw) accept an optional `user_sub`; a `billing_support` admin can **credit
  any user** (charge own card → credit victim = laundering) or **drain any user's
  wallet**. The admin context check authorizes the actor but not the target.
- **`dev_add_charge`** (`billing.py:2238`) can write a `settled` debit directly →
  fabricate owed-debt without payment confirmation.
- **Tip ledger** (`app/services/tip_ledger.py:146-172`) writes debit/credit
  best-effort with silent failures → unmatched/duplicate ledger entries (money lost
  or credited without matching debit).
- **Unlock price unbounded** (`messaging.py:~13592`) — stored `lock_price_cents`
  charged with no upper bound.
- **Payout/deposit** positive-amount only enforced at Pydantic; add service-level
  `amount_cents > 0` defense (`creator_payouts.py`, withdraw/deposit).

## Fix
- Remove the `user_sub` override from wallet deposit/withdraw (operate on the
  authenticated user only); if admin-initiated adjustments are needed, a separate,
  two-person, audited endpoint with its own scope.
- Restrict `settled` ledger writes to webhook/payment-confirmation paths; dev-gate
  `dev_add_charge`.
- Make tip debit+credit **atomic** (DDB TransactWrite) or a status/reconcile record;
  no silent drops.
- Bound unlock/lock prices; add service-level positive-amount checks on all money moves.

## Testing
pytest: a billing_support admin cannot deposit-to / withdraw-from another user;
settled charge only via webhook path; tip writes are all-or-nothing; negative/zero
amounts rejected at the service layer; unlock price over cap rejected.
