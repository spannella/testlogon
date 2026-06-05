# GAP-0028: `POST /feed/record` accepts arbitrary `user_id` from request body (SEC-005 cross-ref)

**Status**: Open · **Severity**: CRIT (Critical) · **Source ticket**: PLATFORM-012 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/PLATFORM-012.md`); see also `docs/tickets/writeups/PLATFORM-012.md`

## Location
`POST /feed/record`

## Problem / Impact
Any authenticated user can call `POST /feed/record` with any `user_id` value and inject forged activity entries into another user's feed. The `session=Depends(require_ui_session)` provides `session["user_sub"]` but the handler passes `body.user_id` (caller-controlled) directly to `record_activity()` at line 159, with no ownership check or admin-role gate. Impact: user A can flood user B's activity feed with arbitrary social noise, impersonate actors, or inject misleading tip/follow entries

## Fix
replace `user_id=body.user_id` with `user_id=session["user_sub"]` at `activity_feed.py:159`; if an admin injection path is needed for test/debug, gate the free-form `user_id` field behind `require_admin_session`

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-012. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
