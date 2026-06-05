# GAP-0038: CLI admin grant produces implicit full admin

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ADMIN-PERMS-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ADMIN-PERMS-001.md`); see also `docs/tickets/writeups/ADMIN-PERMS-001.md`

## Location
`app/cli/rootctl.py:1303`

## Problem / Impact
_admin_grant_command UpdateExpression sets only role=admin with no admin_profile; normalize_admin_profile falls back to GENERAL type; GENERAL admins pass all require_admin_scope checks including permanent bans and impersonation

## Fix
add --scope and --profile-type args to grant command; write admin_profile in UpdateExpression

## Notes
This gap was identified by the second-pass as-built review of ADMIN-PERMS-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
