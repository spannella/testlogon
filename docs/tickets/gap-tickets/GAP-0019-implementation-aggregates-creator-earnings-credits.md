# GAP-0019: Implementation aggregates creator EARNINGS (credits) but spec requires consumer SPENDING (debits)

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: FIN-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/FIN-004.md`); see also `docs/tickets/writeups/FIN-004.md`

## Location
`app/services/consumer_tax_documents.py:4,107-163`

## Problem / Impact
the module docstring says "billing ledger *credit* (earnings) entries"; `_query_credit_entries` applies `FilterExpression: type = "credit"`; `classify_entry` from `creator_earnings.py` is used; the result is a creator 1099-style income summary, not the consumer spending summary (tips paid, subscriptions purchased, unlocks, shop orders) that FIN-004 specifies

## Fix
rewrite `_query_credit_entries` to query `type="debit"` entries and replace `classify_entry` with a `classify_category` function mapping debit reasons to consumer categories (subscriptions, tips, purchases, unlocks, deposits) per the ticket spec section 3.3

## Notes
This gap was identified by the second-pass as-built review of FIN-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
