# GAP-0170: `tenant_pk()` helper defined but never called

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-001 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-001.md`); see also `docs/tickets/writeups/ENTERPRISE-001.md`

## Location
`tenant_pk()`

## Problem / Impact
The `tenant_pk()` / `tenant_pk_for()` helpers that prefix DynamoDB PKs with `TENANT#<tid>#` exist in `app/core/tenant.py` but zero service files import or call them; all existing services still use bare PKs (`USER#`, `CONV#`, etc.), so data isolation across tenants is not actually enforced in any table.

## Fix
Systematically migrate service layer PK construction to use `tenant_pk()`; add a lint rule/grep CI check to block raw PK construction.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
