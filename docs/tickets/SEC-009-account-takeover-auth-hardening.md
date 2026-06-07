# SEC-009: Account-Takeover Hardening (OTP brute-force, device trust, code compare)

**Ticket**: SEC-009 · **Status**: Open · **Priority**: Critical · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 2). Complements ROOT-AUTH-001 (root-specific).

## Problems
1. **OTP/SMS/email brute force — no per-account lockout.** Verify is limited only by
   per-IP rate (XFF-spoofable, SEC-008), and `POST /ui/mfa/sms/begin` **resets the
   per-challenge attempt counter** → unlimited 6-digit guesses
   (`app/routers/ui_mfa.py`, `app/services/rate_limit.py:174`). Recovery codes: 48-bit,
   no global lockout.
2. **Device-trust MFA bypass.** The device cookie is a plain `secrets.token_urlsafe`
   not bound to user+server-secret (`app/services/device_trust.py:31`); a stolen
   cookie = permanent MFA skip, and an attacker with a session can self-trust a device
   → future access skips fresh-MFA (`sessions.py:358-366`).
3. **Non-constant-time code compare** (`!=` on hashed email/recovery codes,
   `ui_mfa.py:191`, `password_recovery.py:302`, `mfa_devices.py:276`).
4. **Password reset silently ignores** session/API-key revocation failures
   (`password_recovery.py:150-157` `except: pass`).
5. **Email/phone change** doesn't verify the NEW address before it becomes a
   login/reset identity (`mfa_devices.py:230-267`) → session-hijack lockout/takeover.
6. **Step-up finalize** lacks an atomic "all factors passed" condition (replay/race).

## Fix
- Cumulative **per-account attempt counter + lockout** for OTP/MFA/recovery that is
  NOT reset by `begin`; codes single-use; backoff.
- **Bind device trust** to `HMAC(server_secret, user_sub|device_id)` verified each
  request; TTL; auto-invalidate on IP/location change; "revoke all devices".
- Use `hmac.compare_digest` for all code/token comparisons.
- Don't swallow revocation errors on password reset (retry/fail-closed); reset
  invalidates all sessions + refresh tokens.
- Require verifying the new email/phone (link to the new address) + step-up before it
  becomes a login/reset factor.
- Atomic ConditionExpression on challenge finalize.

## Testing
pytest: brute-force locked after N attempts even across `begin` resets and rotated
IPs; forged/stolen device cookie does not skip MFA; constant-time compare; reset
revokes sessions; new email requires its own verification.
