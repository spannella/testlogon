# GAP-0172: `TenantMiddleware` blocks root admin from accessing suspended tenants

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-001.md`); see also `docs/tickets/writeups/ENTERPRISE-001.md`

## Location
`TenantMiddleware`

## Problem / Impact
The middleware returns 503 for `status=="suspended"` with no escape hatch; the ticket design (section 3.4) specifies that root admins must bypass the 503 check, but no bypass is implemented. An attacker could lock root out by suspending the default tenant.

## Fix
Check the `Authorization` header / cookie role before returning 503; bypass for authenticated ROOT sessions.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
