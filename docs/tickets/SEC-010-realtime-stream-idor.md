# SEC-010: Realtime Stream Authorization (SSE/WS IDOR)

**Ticket**: SEC-010 · **Status**: Open · **Priority**: Critical · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 2)

## Problem
SSE/WS endpoints authenticate the user but **don't verify the subscriber is a
participant/owner of the channel** → real-time IDOR:
- `GET /broadcast/sessions/{id}/stream` (`broadcast.py:717`) — any authed user streams
  another session's viewer/health events (no `check_viewer_access`).
- `GET /broadcast/sessions/{id}/chat/stream` (`broadcast.py:1763`) — same IDOR, AND
  calls `_chat_msg_out(msg)` **without `viewer_user_id`** → **locked/expired message
  text leaks** (visibility rules skipped).
- `GET /watch_party/{id}/stream` (`watch_party.py:262`) — any authed user streams a
  private party's events (no participant check).
- `mint_ws_token`/`verify_ws_token` (`crypto.py:35-61`) minted/exposed via
  `/ui/ws_token` but **never verified** anywhere (dead auth mechanism).

## Fix
- Add an authorization check before subscribing on every SSE/WS channel: broadcast
  streams → `check_viewer_access(session_id, user, creator_id, visibility)`;
  watch-party → owner/participant check.
- Pass `viewer_user_id=ctx.user_sub` into `_chat_msg_out` in the chat stream so
  locked/expired redaction applies.
- Either wire `verify_ws_token` into the WS handshakes or remove it; ensure WS
  endpoints authorize per resource owner (browser-SSH already does).

## Testing
pytest/E2E: user B cannot subscribe to user A's private broadcast/chat/party stream
(403); locked message text is null in the chat stream for non-payers.
