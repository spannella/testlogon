# SEC-018: Account-State Revocation Propagation (ban/role/deletion TOCTOU)

**Ticket**: SEC-018 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 3). Complements SEC-009 / ROOT-AUTH-001.

## Problem
Account-state changes don't take effect until token expiry / aren't checked on all paths:
- **Ban not enforced on the API-key auth path** — `require_ui_session` checks
  `is_user_currently_banned` for cookie/bearer, but the API-key short-circuit
  (`sessions.py:291-303`) returns before that check → banned user keeps API access.
- **Role downgrade cached in JWT** — role rides in the `ui_access_token`; a
  demotion from admin→user isn't effective until the ~15-min token refreshes
  (privilege persists).
- **Deletion request doesn't revoke sessions** — `account_deletion.py:175` starts the
  grace period but leaves existing sessions valid (a hijacked session can act / cancel
  the deletion during the window).
- **Soft-deleted email re-registration** — after finalize, the freed email can be
  re-registered and may inherit residual associations (Participants/contacts).
- **Deletion-cancel lacks step-up** (`privacy.py:157`).

## Fix
- Apply the ban check (and revoked check) on the **API-key** path too.
- Re-check role/ban against `account_state`/users per request for sensitive actions
  (or keep a per-session role + bump a "权限 epoch" that invalidates cached JWTs on
  role/ban change), so downgrades/bans are immediate.
- On deletion **request**, revoke sessions/API keys (keep cancel possible via re-auth).
- Quarantine/rotate the deleted email; ensure deletion cleans email-keyed associations.
- Require step-up for deletion cancel (match request).

## Testing
pytest: banned user's API key is rejected; demoted admin loses admin endpoints
immediately; deletion request kills active sessions; re-registering a deleted email
inherits nothing.
