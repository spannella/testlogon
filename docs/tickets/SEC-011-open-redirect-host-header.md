# SEC-011: Open Redirect (SAML RelayState) + Host-Header Trust

**Ticket**: SEC-011 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 2)

## Problem
- **SAML open redirect**: `app/routers/sso_saml.py:78,212` redirects (303) to the
  IdP-supplied `RelayState` with no allowlist → after SSO login the victim is sent to
  `https://attacker.com/...` (phishing / token-context theft).
- **Host-header trust**: `app/routers/kyc_eidv.py:87` builds the eID callback base from
  `request.base_url` (derived from the `Host`/`X-Forwarded-Host` header) → an attacker
  setting `Host: attacker.com` redirects the provider callback (carrying `session_id`)
  to their server. Audit other link-building (password-reset/share links) for the same.

## Fix
- Validate `RelayState` against an allowlist of relative paths / known origins (default
  to "/"); reject absolute external URLs.
- Build all server-generated URLs from the configured `S.public_base_url`, not
  `request.base_url`/Host; ignore `X-Forwarded-Host` unless from a trusted proxy.

## Testing
pytest: SAML ACS with `RelayState=https://evil.com` does not redirect off-site;
eID/reset/share URLs use `public_base_url` regardless of Host header.
