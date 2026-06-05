# GAP-0035: missing CSRF on template mutation endpoints

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADMIN-002 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADMIN-002.md`); see also `docs/tickets/writeups/ADMIN-002.md`

## Location
`app/routers/admin_notifications.py:1`

## Problem / Impact
PATCH /templates/{id} and POST /templates/{id}/test-send and /preview use require_admin_or_root not require_admin_or_root_csrf; cookie-authed browser sessions not CSRF-protected; attacker can forge template body changes via cross-site request

## Fix
switch PATCH and POST endpoints to require_admin_or_root_csrf dependency

## Notes
This gap was identified by the second-pass as-built review of ADMIN-002. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
