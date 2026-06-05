# GAP-0039: no max-5-accounts-per-user rate limit

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-001.md`); see also `docs/tickets/writeups/ADS-001.md`

## Location
`app/services/ad_accounts.py:create_ad_account`

## Problem / Impact
unlimited account creation floods admin review queue

## Fix
count `list_accounts_by_owner` before put_item, raise ValueError if >= 5

## Notes
This gap was identified by the second-pass as-built review of ADS-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
