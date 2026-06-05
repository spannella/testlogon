# GAP-0307: Subscription revenue is invisible to the creator earnings dashboard

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MON-003 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/MON-003.md`); see also `docs/tickets/writeups/MON-003.md`

## Location
`PK=CREATOR#{creator_id}`

## Problem / Impact
subscription server writes creator revenue under `PK=CREATOR#{creator_id}` in `T.subscriptions` (`app/routers/subscription_server.py:582,947`), but `_query_credit_entries` queries `PK=USER#{user_id}` in `T.billing` (`app/services/creator_earnings.py:144`)

## Fix
update `record_billing_payment` / `save_ledger_entry` to also write a `type=credit` LEDGER entry under `PK=USER#{creator_id}` in `T.billing`; or update `_query_credit_entries` to additionally query the subscriptions table under `CREATOR#` key

## Notes
This gap was identified by the second-pass as-built review of MON-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
