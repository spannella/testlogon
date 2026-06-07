# GAP-0346: No `user reactivate` or `user undelete` commands

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ROOTCTL-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ROOTCTL-001.md`); see also `docs/tickets/writeups/ROOTCTL-001.md`

## Location
`user reactivate`

## Problem / Impact
No `user reactivate` or `user undelete` commands

## Fix
add `reactivate` and `undelete` sub-parsers mirroring `deactivate`/`delete` guard patterns (`--ticket`, `--confirm`)

## Notes
This gap was identified by the second-pass as-built review of ROOTCTL-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
