# SEC-017: WebAuthn Passkey Register/Remove Requires Step-Up MFA

**Ticket**: SEC-017 · **Status**: Open · **Priority**: Critical · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 3)

## Problem
`app/routers/webauthn.py:28-46` — `POST /ui/webauthn/register/begin` and
`/register/finish` only require `require_ui_session` (no `require_fresh_mfa`). An
attacker with a **hijacked session** can **register their own passkey** on the
victim's account → persistent account takeover that survives password change/logout;
and (if removal is similarly ungated) **remove the victim's passkeys** → lockout.
Adding a strong auth factor must require step-up.

## Fix
- Require `require_fresh_mfa(ctx)` (recent MFA / re-auth) for WebAuthn register
  begin+finish AND for credential removal/disable (and for adding/removing any MFA
  factor generally — cross-ref SEC-009).
- Notify the user (email) when a new passkey/MFA factor is added.
- (Verify, already likely OK: registration challenge bound to the authenticated user +
  single-use; assertion challenge server-side, single-use, RP-ID/origin verified,
  signature counter checked.)

## Testing
pytest: register/remove passkey without fresh MFA → 401/step-up required; with fresh
MFA → succeeds; a notification is emitted on new factor.
