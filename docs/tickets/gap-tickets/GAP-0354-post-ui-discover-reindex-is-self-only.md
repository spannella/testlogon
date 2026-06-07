# GAP-0354: `POST /ui/discover/reindex` is self-only

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SOC-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/SOC-003.md`); see also `docs/tickets/writeups/SOC-003.md`

## Location
`POST /ui/discover/reindex`

## Problem / Impact
`POST /ui/discover/reindex` is self-only

## Fix
add an admin/root-gated `POST /ui/discover/admin/reindex-all` endpoint backed by `reindex_all_users()`

## Notes
This gap was identified by the second-pass as-built review of SOC-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
