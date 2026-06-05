# GAP-0037: admin_capabilities system is dead code

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADMIN-PERMS-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADMIN-PERMS-001.md`); see also `docs/tickets/writeups/ADMIN-PERMS-001.md`

## Location
`app/cli/rootctl.py:51`

## Problem / Impact
never enforced

## Fix
repoint _admin_capabilities_set_command to write admin_profile.scopes (Option A in §4.1)

## Notes
This gap was identified by the second-pass as-built review of ADMIN-PERMS-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
