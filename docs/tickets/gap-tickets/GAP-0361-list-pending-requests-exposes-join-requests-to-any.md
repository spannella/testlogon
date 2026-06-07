# GAP-0361: list_pending_requests exposes join requests to any authenticated user

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SYND-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/SYND-001.md`); see also `docs/tickets/writeups/SYND-001.md`

## Location
`app/routers/syndicates.py:267-280`

## Problem / Impact
router comment says "Admin-only check done in service" but service has no admin guard; any user can enumerate pending join requests for any syndicate

## Fix
add `svc._require_admin(syndicate_id, session["user_sub"])` before service call in the `list_requests` router handler

## Notes
This gap was identified by the second-pass as-built review of SYND-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
