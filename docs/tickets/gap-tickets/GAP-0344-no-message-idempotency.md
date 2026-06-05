# GAP-0344: No message idempotency

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PWA-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PWA-004.md`); see also `docs/tickets/writeups/PWA-004.md`

## Location
`app/routers/messaging.py`

## Problem / Impact
backend `app/routers/messaging.py` send-message endpoint, frontend `frontend/src/api/types.ts:1249-1264`

## Fix
add optional `client_request_id` to `SendTextMessageReq` and backend create-message handler; use the offline action `id` as the key

## Notes
This gap was identified by the second-pass as-built review of PWA-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
