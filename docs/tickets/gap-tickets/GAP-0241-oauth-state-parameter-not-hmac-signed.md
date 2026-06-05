# GAP-0241: OAuth state parameter not HMAC-signed

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INTEG-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/INTEG-001.md`); see also `docs/tickets/writeups/INTEG-001.md`

## Location
`app/routers/google_drive_integration.py:122-131`

## Problem / Impact
the `initiate_google_drive_connect` endpoint returns a stub `auth_url` without generating or signing a `state` parameter; the ticket's acceptance criterion 12 requires HMAC-signed, time-limited state; in non-mock mode the `callback` endpoint does not validate `state` at all (line 155 raises 501); without signed state the OAuth flow is vulnerable to CSRF

## Fix
implement `_sign_oauth_state(user_sub)` using `S.google_oauth_state_signing_secret` + timestamp, verify in `complete_google_drive_connect`, and reject stale states (> `google_oauth_state_ttl_seconds`)

## Notes
This gap was identified by the second-pass as-built review of INTEG-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
