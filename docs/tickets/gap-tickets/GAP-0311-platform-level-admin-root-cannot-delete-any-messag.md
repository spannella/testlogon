# GAP-0311: platform-level admin/root cannot delete any message

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MSG-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/MSG-001.md`); see also `docs/tickets/writeups/MSG-001.md`

## Location
`app/routers/messaging.py:10762,10801`

## Problem / Impact
platform-level admin/root cannot delete any message

## Fix
check `ctx["role"] in {Role.ADMIN, Role.ROOT}` in `revoke_message_for_all` (or add a separate moderation endpoint) to allow platform admins to remove harmful content

## Notes
This gap was identified by the second-pass as-built review of MSG-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
