# DELEGATE-004: Broadcast Chat Delegation — Investigation & Implementation Write-up

## 1. Summary & Classification

DELEGATE-004 enables delegates to moderate live broadcast chat and control broadcast sessions. Delegates with `broadcast_moderate` can pin, delete, mute, ban, and post announcements; delegates with `broadcast_control` can start, stop, and schedule broadcasts. All actions emit SSE events to chat participants and write to a dedicated `broadcast_moderation` DynamoDB table. Moderation actions are accompanied by visible system messages.

- **Type**: Feature (live-broadcast moderation delegation)
- **Priority**: Medium
- **Status**: Backend fully implemented with a separate `broadcast_moderation` table; frontend `ModeratorPanel.tsx` exists but is NOT integrated into `BroadcastPage.tsx`; ban enforcement is NOT wired into `send_chat_message`
- **Owning area**: Broadcast / authorization
- **User personas**: Moderator delegate (moderate chat), Controller delegate (control sessions), Creator (visibility of active moderators), Viewer (sees system messages)
- **Cross-references**: [[DELEGATE-001]] (required — `require_delegate_permission`, audit), [[SEC-005]] (IDOR — session ownership verified), [[SEC-018]] (revocation — next permission check returns 403), [[SECOPS-007]] (DDB Local vs prod), [[DELEGATE-005]] (broadcast delegation via API key)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service layer — `app/services/delegate_broadcast.py` (685 lines, fully implemented)

The service uses `T.broadcast_moderation` (registered at `tables.py:494`, table definition at `scripts/local-ddb-init.py:1880`) for all moderation state: pins, bans, moderator presence, announcements, and the moderation log.

| Function | Location | Notes |
|----------|----------|-------|
| `pin_chat_message` | `delegate_broadcast.py:47` | Unpin existing pin; write pin item; send system message; SSE `mod:pin`; write audit |
| `unpin_chat_message` | `delegate_broadcast.py:103` | Delete pin item; system message; SSE `mod:unpin` |
| `delete_moderated_message` | `delegate_broadcast.py:135` | Calls `send_chat_message(session_id, "system", ...)` for system notice; SSE `mod:delete`; audit |
| `mute_viewer` | `delegate_broadcast.py:166` | Calls `broadcast_chat_store.set_mute`; checks `mute_duration <= MAX_MUTE_DURATION_SECONDS`; blocks banning the creator at `line:181`; SSE `mod:mute`; audit |
| `ban_viewer` | `delegate_broadcast.py:209` | Writes `BAN#{user_id}` to `T.broadcast_moderation`; blocks banning creator at `line:221`; SSE `mod:ban`; audit |
| `unban_viewer` | `delegate_broadcast.py:256` | Deletes `BAN#{user_id}`; SSE `mod:unban` |
| `post_announcement` | `delegate_broadcast.py:285` | Writes announcement message item with `is_announcement=True`; SSE `mod:announcement` |
| `start_broadcast_as_delegate` | `delegate_broadcast.py:348` | Calls `require_delegate_permission(..., "broadcast_control")`; uses `broadcast_orchestrator.start_session` |
| `stop_broadcast_as_delegate` | `delegate_broadcast.py:387` | Same authorization; `broadcast_orchestrator.stop_session` |
| `schedule_broadcast_as_delegate` | `delegate_broadcast.py:426` | `broadcast_control`; creates session with `created_by=creator_id` |
| `register_moderator` | `delegate_broadcast.py:485` | Writes `MOD#{moderator_id}` item with `status=online` |
| `list_active_moderators` | `delegate_broadcast.py:517` | Queries `MOD#` prefix |
| `list_banned_viewers` | `delegate_broadcast.py:537` | Queries `BAN#` prefix |
| `is_viewer_banned` | `delegate_broadcast.py:557` | `get_item BAN#{user_id}` |
| `get_broadcast_moderation_log` | `delegate_broadcast.py:565` | Queries `LOG#` prefix |

`_require_broadcast_moderator` at `delegate_broadcast.py:599` verifies both: (1) `session.created_by == creator_id` (session ownership, preventing cross-creator moderation), and (2) `require_delegate_permission(..., "broadcast_moderate")` (delegation permission check).

SSE events use `broadcast_sse_publish` from `app/services/broadcast_sse.py:29`. This function is defined in the existing 49-line SSE service. The `mod:*` event types are new and sent without modifying `broadcast_sse.py` itself — they are passed as raw dict payloads that the SSE stream forwards. Whether clients receive and act on these event types depends on the frontend SSE consumer.

### 2.2 Router — `app/routers/delegate_broadcast.py` (252 lines)

All 14 endpoints from the ticket design are present under `/ui/broadcast/delegate`. Registration: `app/main.py:661` includes `delegate_broadcast_router`.

### 2.3 Ban enforcement gap (critical)

**`broadcast_chat_store.send_chat_message` does NOT call `is_viewer_banned`**.

The function at `broadcast_chat_store.py:136` calls only `_enforce_chat_mute` (line 158) before sending. There is no ban check. This means a banned viewer can still send messages — `ban_viewer` writes a `BAN#` item to `T.broadcast_moderation`, and `is_viewer_banned` can detect it, but nothing in `send_chat_message` calls that function.

The mute mechanism (`_enforce_chat_mute`) reads from the `BroadcastChatMutes` table. The ban mechanism uses `T.broadcast_moderation`. These are separate tables and the chat store only knows about mutes.

### 2.4 Frontend integration gap (BroadcastPage not wired)

`ModeratorPanel.tsx` (211 lines) exists and uses `getModerationLog`, `listActiveModerators`, `listBannedViewers` from `delegateBroadcast.ts`. But:

- `BroadcastPage.tsx` (1096 lines) has **no import of `ModeratorPanel`** — zero occurrences found.
- `BroadcastChat.tsx` has mute button (`muteChatUser` at line 11, 213) but no pin/delete/ban controls for delegate moderators.
- No `BroadcastControlPanel.tsx` exists for delegate start/stop/schedule.
- No `ModeratorActionBar.tsx`, `ModeratorUserMenu.tsx`, `AnnouncementComposer.tsx`, or `ActiveModerators.tsx` as standalone files.
- `mod:pin`, `mod:delete`, `mod:mute`, `mod:ban`, `mod:announcement` SSE events are dispatched but the frontend's SSE consumer (presumably in the broadcast page) does not handle them — no consumer code for these event types was found.

### 2.5 DynamoDB table

`broadcast_moderation` table has `pk` + `sk` with no GSIs. Defined at `scripts/local-ddb-init.py:1878`. This is sufficient for all access patterns (prefix queries by `SESSION#{sid}`).

### 2.6 Dev vs Prod behavior

`T.broadcast_moderation` uses DDB Local in dev. `broadcast_sse_publish` writes to an in-memory SSE queue (the existing pattern in `broadcast_sse.py`) — no AWS dependency. No feature flag gates broadcast delegation. `broadcast_moderation_table_name` is in `settings.py:2113`. Same code path in dev and prod.

---

## 3. Gap / Threat Analysis

### 3.1 Ban not enforced in send_chat_message (security/correctness gap)

`ban_viewer` correctly stores a `BAN#` item and sends a visible SSE event. But `broadcast_chat_store.send_chat_message` never calls `is_viewer_banned`. A banned user can continue sending messages until either their session closes or the ban is lifted. The acceptance criterion "Banned viewers cannot send messages" is not met.

**Exploit scenario**: Moderator bans user X for harassment. User X refreshes the page and continues sending messages. No backend enforcement stops them. The SSE event tells the frontend to hide new messages from the banned user, but clients not following the SSE protocol (or direct API calls) are not blocked.

This maps to [[SEC-005]]: a moderation action is taken but not enforced on the write path.

### 3.2 ModeratorPanel not mounted in BroadcastPage (functional gap)

The moderator panel exists as a standalone component but is never rendered. Delegates who open a broadcast stream have no moderation controls visible in the UI. All moderation actions can only be performed via direct API calls (e.g., from `delegates-broadcast.spec.ts` E2E tests).

### 3.3 mod:* SSE events not handled in frontend (functional gap)

When a pin, delete, mute, or ban event is dispatched via `broadcast_sse_publish`, the frontend SSE consumer (in the broadcast page) does not have handlers for `mod:*` event types. Pin indicators, "message removed" notices, and mute notifications are never shown to viewers or the moderator.

### 3.4 BroadcastControlPanel missing (functional gap)

`start_broadcast_as_delegate`, `stop_broadcast_as_delegate`, and `schedule_broadcast_as_delegate` endpoints exist, but no frontend component lets a delegate use them. Delegates with `broadcast_control` can only control broadcasts via direct API calls.

### 3.5 Authorization (SEC-005)

`_require_broadcast_moderator` at `delegate_broadcast.py:599` provides two-factor verification:
1. Session `created_by == creator_id` — prevents moderating someone else's broadcast.
2. `require_delegate_permission(..., "broadcast_moderate")` — enforces delegation.

Moderators cannot ban the creator (`ban_viewer:221` checks `user_id == session.created_by → 403`). Moderators cannot start/stop broadcasts without `broadcast_control` (separate permission). No privilege escalation paths exist at the service layer.

### 3.6 Revocation (SEC-018)

`require_delegate_permission` does a live DDB read on every call. After revocation, the next moderation action returns 403 immediately. No in-flight SSE termination mechanism exists — a revoked moderator's connection stays open until the next heartbeat. The heartbeat mechanism is not implemented in the broadcast delegation layer.

### 3.7 Code sites needing changes

| File | What | Priority |
|------|------|----------|
| `app/services/broadcast_chat_store.py:158` | Add `is_viewer_banned(session_id, user_id)` check before `_enforce_chat_mute` | High — fixes ban enforcement |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Import + render `ModeratorPanel` for delegates | Medium — core UX |
| `frontend/src/pages/broadcast/BroadcastChat.tsx` | Handle `mod:*` SSE events; add pin indicator + "message removed" rendering | Medium |
| `frontend/src/pages/broadcast/` | Add `BroadcastControlPanel.tsx`, `ModeratorActionBar.tsx`, `ModeratorUserMenu.tsx` | Medium |

---

## 4. Proposed Design / Fix

### 4.1 Ban enforcement fix (highest priority)

In `app/services/broadcast_chat_store.py`, at line 158, before `_enforce_chat_mute`:

```python
# Check delegate-issued bans (DELEGATE-004)
try:
    from app.services.delegate_broadcast import is_viewer_banned
    if is_viewer_banned(session_id, user_id):
        raise HTTPException(
            status_code=403,
            detail={"code": "BROADCAST_CHAT_BANNED", "message": "You are banned from this chat."},
        )
except ImportError:
    pass  # delegate_broadcast not available; skip ban check
```

The `try/except ImportError` guard prevents a circular import if `delegate_broadcast` imports `broadcast_chat_store` (which it does). The correct fix avoids this by injecting the ban check via a callable or by moving `is_viewer_banned` to a shared utility module.

A cleaner approach: move the ban check into `_enforce_chat_mute` or add a `_enforce_chat_ban` helper in `broadcast_chat_store.py` that directly queries `T.broadcast_moderation` without importing `delegate_broadcast`:

```python
def _enforce_chat_ban(session_id: str, user_id: str) -> None:
    """Raise 403 if user is banned in this session."""
    from app.core.tables import T
    resp = T.broadcast_moderation.get_item(
        Key={"pk": f"SESSION#{session_id}", "sk": f"BAN#{user_id}"}
    )
    if resp.get("Item"):
        raise HTTPException(403, {"code": "BROADCAST_CHAT_BANNED", "message": "You are banned from this chat."})
```

Call `_enforce_chat_ban(session_id, user_id)` at line 158 of `broadcast_chat_store.py`, before `_enforce_chat_mute`.

### 4.2 ModeratorPanel integration

In `BroadcastPage.tsx`, check if `useAuthStore` has `managingCreatorId` set and the user's delegation includes `broadcast_moderate`. If so:

```tsx
import ModeratorPanel from "./ModeratorPanel";
// ...
{managingCreatorId && <ModeratorPanel creatorId={managingCreatorId} sessionId={sessionId} />}
```

### 4.3 mod:* SSE event handling

In the broadcast SSE consumer (wherever `useEffect` listens to the EventSource), add handlers:

```typescript
case "mod:pin":
  setPinnedMessageId(event.message_id); break;
case "mod:delete":
  setDeletedMessageIds(prev => new Set(prev).add(event.message_id)); break;
case "mod:mute":
  if (event.user_id === currentUserId) setMuted(true); break;
case "mod:ban":
  if (event.user_id === currentUserId) setBanned(true); break;
```

### 4.4 Dev/Prod parity (SECOPS-007)

`T.broadcast_moderation` uses DDB Local in dev (same `ddb_endpoint_url` path). `broadcast_sse_publish` is in-memory. No AWS services required. The ban enforcement fix in `broadcast_chat_store.py` adds a DDB read on every message send — in dev this hits DDB Local, in prod it hits real DynamoDB. No mock needed.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_delegate_broadcast.py`)

| Case | Assertion |
|------|-----------|
| `test_pin_chat_message` | Pin item in `broadcast_moderation`; system message sent; SSE `mod:pin` dispatched |
| `test_delete_moderated_message` | Message soft-deleted; system message; SSE `mod:delete` |
| `test_mute_viewer_duration_cap` | 403 when `duration_seconds > 86400` |
| `test_ban_viewer_creates_item` | `BAN#{user_id}` item in `broadcast_moderation` |
| `test_banned_viewer_cannot_send` | 403 from `send_chat_message` after ban (once fix applied) |
| `test_ban_creator_rejected` | 403 when `user_id == session.created_by` |
| `test_start_broadcast_requires_control` | 403 with only `broadcast_moderate` |
| `test_moderator_registered` | `MOD#{moderator_id}` item created |
| `test_list_active_moderators` | Returns registered moderators |
| `test_session_ownership_enforced` | 403 when `session.created_by != creator_id` |

### 5.2 Playwright E2E (`frontend/e2e/delegates-broadcast.spec.ts`)

File exists. Sections 499-502 per ticket (16 tests). Tests exercising ban enforcement (test 499.4) will fail until `_enforce_chat_ban` is wired into `send_chat_message`. UI tests (ModeratorPanel, system messages) require BroadcastPage integration.

### 5.3 Manual verification

1. `just restart`.
2. Alice starts a broadcast session.
3. Bob (delegate with `broadcast_moderate`) calls `POST /ui/broadcast/delegate/alice/sessions/{sid}/ban` to ban viewer C.
4. Viewer C attempts to send a message — verify 403.
5. Bob calls unban — viewer C can send again.
6. Bob pins a message — verify `mod:pin` SSE received by Alice's frontend.
7. Alice revokes Bob — Bob's next moderation call returns 403.

### 5.4 Rollout

No feature flag exists for broadcast delegation. Add `broadcast_delegation_enabled` to `app/core/settings.py` alongside `broadcast_moderation_table_name` (line 2113). Gate `delegate_broadcast_router` registration in `main.py:661` on this flag.

### 5.5 Effort estimate

- Ban enforcement fix in `broadcast_chat_store.py`: **S** (1-2 hours)
- ModeratorPanel integration in `BroadcastPage.tsx`: **M** (1 day)
- mod:* SSE event handling in frontend: **M** (1 day)
- BroadcastControlPanel + ModeratorActionBar + ModeratorUserMenu: **L** (2-3 days)
- E2E fixes: **S** (0.5 day after ban fix)

Implementation order: ban fix → E2E run → UI integration.
