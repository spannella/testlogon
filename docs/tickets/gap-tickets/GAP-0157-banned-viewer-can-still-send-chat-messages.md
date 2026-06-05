# GAP-0157: banned viewer can still send chat messages

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: DELEGATE-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/DELEGATE-004.md`); see also `docs/tickets/writeups/DELEGATE-004.md`

## Location
`app/services/broadcast_chat_store.py:158`

## Problem / Impact
send_chat_message calls _enforce_chat_mute but never calls is_viewer_banned; ban_viewer writes BAN# item that is never consulted on message send

## Fix
add _enforce_chat_ban(session_id, user_id) querying T.broadcast_moderation BAN# item before _enforce_chat_mute

## Notes
This gap was identified by the second-pass as-built review of DELEGATE-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
