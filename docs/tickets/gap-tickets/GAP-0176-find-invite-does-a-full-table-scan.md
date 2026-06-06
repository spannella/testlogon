# GAP-0176: `_find_invite` does a full table scan

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-003 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-003.md`); see also `docs/tickets/writeups/ENTERPRISE-003.md`

## Location
`_find_invite`

## Problem / Impact
`_find_invite` does a full table scan

## Fix
Add an `invite-id-index` GSI to the `organizations` table (PK: `invite_id`) in `scripts/local-ddb-init.py` and use `query()` in `_find_invite`.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
