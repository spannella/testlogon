# GAP-0242: real OAuth token exchange not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INTEG-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/INTEG-001.md`); see also `docs/tickets/writeups/INTEG-001.md`

## Location
`app/routers/google_drive_integration.py:155`

## Problem / Impact
real OAuth token exchange not implemented

## Fix
implement token exchange POST to `S.google_oauth_token_url` with code, redirect_uri, client_id, client_secret; store access_token, refresh_token, expires_at

## Notes
This gap was identified by the second-pass as-built review of INTEG-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
