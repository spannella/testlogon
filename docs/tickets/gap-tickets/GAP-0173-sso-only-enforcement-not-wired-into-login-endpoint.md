# GAP-0173: SSO-only enforcement not wired into login endpoint

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ENTERPRISE-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ENTERPRISE-002.md`); see also `docs/tickets/writeups/ENTERPRISE-002.md`

## Location
`app/routers/ui_session.py`

## Problem / Impact
The `is_sso_only_tenant()` helper is implemented in `app/services/sso_saml_provider.py` and referenced in the ticket's section 3.5, but `POST /ui/session/start` in `ui_session.py` never calls it. Users belonging to tenants with `sso_only=true` can still log in with a password.

## Fix
Call `is_sso_only_tenant(tenant_id)` at the top of `ui_session_start` and raise HTTP 403 when it returns True.

## Notes
This gap was identified by the second-pass as-built review of ENTERPRISE-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
