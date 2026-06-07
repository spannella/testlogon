# GAP-0317: No dedicated VAPID web-push subscribe/unsubscribe endpoint

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: NOTIFY-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/NOTIFY-001.md`); see also `docs/tickets/writeups/NOTIFY-001.md`

## Location
`app/routers/push.py:32-48`

## Problem / Impact
The backend `POST /ui/push/register` accepts only a FCM-style `{token, platform}` pair; the spec requires a proper web-push subscription endpoint accepting `{endpoint, keys_p256dh, keys_auth}` with `WEB_PUSH#` SK prefix and a DELETE unsubscribe path. Frontend `PushDevices.tsx:85` passes the entire subscription JSON as the `token` field, which the backend stores as a raw string and cannot decode for VAPID delivery. `web_push_send()` at `app/services/push.py:142` correctly reads `keys.p256dh` + `keys.auth` from a parsed subscription dict, but the stored blob is a JSON string, not a parsed dict

## Fix
add `POST /ui/push/subscribe` and `DELETE /ui/push/subscribe` endpoints that accept and store proper web-push subscription objects; update `send_push_for_alert` to deserialize the stored token if `platform=web`

## Notes
This gap was identified by the second-pass as-built review of NOTIFY-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
