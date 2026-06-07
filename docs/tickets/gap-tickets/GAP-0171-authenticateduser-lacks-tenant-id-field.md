# GAP-0171: `AuthenticatedUser` lacks `tenant_id` field

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-001.md`); see also `docs/tickets/writeups/ENTERPRISE-001.md`

## Location
`AuthenticatedUser`

## Problem / Impact
The dataclass has no `tenant_id` field; sessions are not cross-validated against the request's `request.state.tenant_id`, so a session cookie minted for tenant-A works transparently on tenant-B. Described in ticket section 3.5.3 as a required fix.

## Fix
Add `tenant_id: str = "default"` to `AuthenticatedUser`, populate it from the JWT, validate it against `request.state.tenant_id` in `require_ui_session`.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
