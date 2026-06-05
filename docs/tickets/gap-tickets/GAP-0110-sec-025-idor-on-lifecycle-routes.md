# GAP-0110: SEC-025 IDOR on lifecycle routes

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BCAST-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BCAST-001.md`); see also `docs/tickets/writeups/BCAST-001.md`

## Location
`broadcast.py:360,402,453`

## Problem / Impact
any admin/root can start/stop/delete another broadcaster's session; no session ownership check

## Fix
add `_require_operator_and_owner(session_id, ctx)` helper before lifecycle operations

## Notes
This gap was identified by the second-pass as-built review of BCAST-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
