# MSG-003: Typing Indicators -- Real-time Push

**Ticket**: MSG-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 3-4 days

---

## 1. Executive Summary

The typing indicator system works end-to-end but introduces 0-3 seconds of latency because the frontend polls the server every 3 seconds instead of using the SSE (Server-Sent Events) stream that is already available. The backend already emits `typing:update` SSE events when a user starts typing (`app/routers/messaging.py:11356-11362`), and the frontend already maintains an SSE connection via `useMessagingStream` (`frontend/src/hooks/useMessagingStream.ts`). However, `useMessagingStream` does not handle the `typing:update` event type -- it is not in the `EVENT_TYPES` array (lines 96-129) and has no handler in the `handleEvent` function (lines 23-92). Meanwhile, the `TypingIndicator` component (`frontend/src/pages/messages/TypingIndicator.tsx:36-42`) uses React Query with a 3-second `refetchInterval` to poll `GET /conversations/{id}/typing`.

This is a quick win: add `typing:update` to the SSE event handler, use the SSE data to instantly update the typing state, and either remove or demote the polling to a fallback for SSE disconnects. The result is near-instant typing indicator updates (sub-100ms latency) instead of the current 0-3 second lag.

The business case is about perceived app quality. Typing indicators are one of the most visible real-time features in any messaging product. When there is a multi-second delay between someone starting to type and the indicator appearing, users perceive the app as slow or broken. This is particularly damaging for a platform competing with established messaging apps (iMessage, WhatsApp, Telegram) where typing indicators appear instantaneously. The fix requires only two frontend file changes -- zero backend work -- making it one of the highest-value-per-effort improvements available.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Instant Typing Indicator**

| Field | Value |
|-------|-------|
| Actor | Viewer (Bob) in a conversation with Alice |
| Story | As a conversation participant, I want to see "Alice is typing" appear instantly when Alice starts typing so the conversation feels alive and responsive. |
| Preconditions | Both Alice and Bob are in the same conversation. Bob has the conversation open. SSE stream is connected. |
| Acceptance Criteria | 1. Typing indicator appears within 200ms of Alice's keystroke POST reaching the server. 2. No visible delay compared to message delivery. 3. Indicator uses the same bouncing dots animation as current. |

**US-2: Prompt Typing Disappearance**

| Field | Value |
|-------|-------|
| Actor | Viewer (Bob) |
| Story | As a viewer, I want the typing indicator to disappear promptly when Alice stops typing so I'm not misled into thinking a message is coming. |
| Preconditions | Typing indicator is currently showing. Alice stops typing. |
| Acceptance Criteria | 1. Indicator disappears within 5 seconds of Alice's last keystroke (matching server-side TTL). 2. Client-side TTL cleanup runs every 2 seconds to catch expired entries. 3. When Alice sends her message, the indicator disappears immediately (message:new event clears typing). |

**US-3: Fallback on SSE Disconnect**

| Field | Value |
|-------|-------|
| Actor | Viewer (Bob) with intermittent connectivity |
| Story | As a viewer, I want typing indicators to still work even if the SSE stream disconnects so I don't lose the feature during network instability. |
| Preconditions | SSE stream disconnects (network issue). |
| Acceptance Criteria | 1. Fallback polling at 30-second interval activates automatically. 2. Typing state eventually catches up (within 30 seconds). 3. When SSE reconnects, instant updates resume without user action. |

### 2.2 Pain Points

1. **Perceived lag**: In fast-paced conversations, a 0-3 second delay before seeing "is typing" makes the indicator feel broken or useless. By the time it appears, the message may have already arrived, creating a backwards-feeling experience.
2. **Unnecessary network traffic**: Polling every 3 seconds generates ~20 HTTP requests per minute per open conversation, even when no one is typing. With 5 open conversations, that's 100 wasted requests per minute per user.
3. **Battery drain**: On mobile browsers, frequent polling prevents the browser from entering low-power network states. This is measurable on iOS Safari and Android Chrome.
4. **Backend load**: Each poll request hits DynamoDB (`tbl_typing.query`). At scale (10K concurrent users with 3 open conversations each), this generates 600K+ typing queries per minute -- all returning empty results when no one is typing.
5. **Inconsistency with other real-time features**: Messages, reactions, polls, and call events all arrive via SSE in real-time. Only typing uses polling, creating an inconsistent UX where messages appear instantly but the preceding "is typing" indicator lags behind.

### 2.3 Latency Comparison

| Mode | Best case | Worst case | Average | Requests/min | DDB reads/min |
|------|-----------|------------|---------|-------------|---------------|
| Polling (current, 3s) | 0ms | 3000ms | 1500ms | ~20/conversation | ~20/conversation |
| SSE (proposed) | <50ms | <200ms | <100ms | 0 (event-driven) | 0 (event-driven) |
| Fallback (proposed, 30s) | 0ms | 30000ms | 15000ms | ~2/conversation | ~2/conversation |

The SSE approach reduces per-conversation DDB reads from ~20/min to ~2/min (fallback only) -- a 90% reduction. For the overall system, this scales linearly with active conversations.

---

## 3. Current State Analysis

### 3.1 Backend Typing Flow

**POST /conversations/{conversation_id}/typing** (`app/routers/messaging.py:11341-11363`):

```python
@router.post("/conversations/{conversation_id}/typing")
def set_typing(conversation_id: str, inp: TypingIn, user_id: str = Depends(get_messaging_user_id)):
    require_participant_active(user_id, conversation_id)
    ts = now_ts()

    tbl_typing.put_item(
        Item={
            "conversation_id": conversation_id,
            "user_id": user_id,
            "is_typing": bool(inp.is_typing),
            "updated_at": ts,
            "ttl": ts + TYPING_TTL_SEC,
        }
    )

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="typing:update",
        payload={"user_id": user_id, "is_typing": bool(inp.is_typing), "updated_at": ts},
        respect_mute=False,
    )
    return {"ok": True, "is_typing": bool(inp.is_typing), "ttl": ts + TYPING_TTL_SEC}
```

Key observations:
- Line 11346-11353: `tbl_typing.put_item` stores typing state with TTL for expiration.
- Line 11356-11362: `fanout_event_to_conversation` broadcasts `typing:update` to all participants via SSE.
- Line 11360: Payload contains `user_id`, `is_typing` (bool), and `updated_at` (timestamp).
- Line 11361: `respect_mute=False` means typing events are sent even to users who have muted the conversation. This is intentional -- muting suppresses message notifications, not real-time presence information.

**`fanout_event_to_conversation` function** (`messaging.py:5244-5278`):

This function writes SSE events to `tbl_events` for each active participant in the conversation (except the sender). The events are then picked up by the SSE stream handler and pushed to connected clients. The event reaches the client's EventSource within the SSE poll interval (typically < 100ms for an active connection).

**Citations**:
- `app/routers/messaging.py:11341-11363` -- full `set_typing` endpoint
- `app/routers/messaging.py:11346-11353` -- DDB put_item with TTL
- `app/routers/messaging.py:11356-11362` -- fanout to SSE
- `app/routers/messaging.py:5244-5278` -- `fanout_event_to_conversation` implementation

### 3.2 Backend Typing Poll Endpoint

**GET /conversations/{conversation_id}/typing** (`app/routers/messaging.py:11366-11382`):

```python
@router.get("/conversations/{conversation_id}/typing", response_model=List[TypingUser])
def get_typing(conversation_id: str, user_id: str = Depends(get_messaging_user_id)):
    require_participant_active(user_id, conversation_id)

    resp = tbl_typing.query(KeyConditionExpression=Key("conversation_id").eq(conversation_id), Limit=200)
    items = resp.get("Items", [])
    ts = now_ts()

    out: List[TypingUser] = []
    for it in items:
        ttl = int(it.get("ttl", 0) or 0)
        if ttl and ttl <= ts:
            continue
        if not it.get("is_typing", False):
            continue
        out.append(TypingUser(user_id=it["user_id"], updated_at=int(it.get("updated_at", 0) or 0)))
    return out
```

This endpoint:
1. Queries all typing records for the conversation (Limit=200).
2. Filters out expired entries (TTL <= now).
3. Filters out `is_typing: false` entries.
4. Returns `[{user_id, updated_at}]`.

This is the endpoint the frontend polls every 3 seconds. It performs a DynamoDB Query per call.

**Citations**:
- `app/routers/messaging.py:11366-11382` -- full `get_typing` endpoint
- `app/routers/messaging.py:11370` -- DDB query on `conversation_id`
- `app/routers/messaging.py:11376-11377` -- TTL expiry check

### 3.3 SSE Stream Infrastructure

The SSE stream is served at `/messaging/events/stream` (referenced in `useMessagingStream.ts:4`):

```typescript
const MESSAGING_STREAM_URL = "/messaging/events/stream";
```

The `useMessagingStream` hook creates an `EventSource` connection with credentials:

```typescript
function connect() {
  es = new EventSource(MESSAGING_STREAM_URL, { withCredentials: true });

  es.onopen = () => {
    retryCount.current = 0;
  };

  es.onmessage = handleEvent;  // Fallback for un-typed events

  for (const type of EVENT_TYPES) {
    es.addEventListener(type, handleEvent);  // Named event listeners
  }

  es.onerror = () => {
    es?.close();
    es = null;
    const delay = Math.min(1000 * Math.pow(2, retryCount.current), MAX_RETRY_DELAY);
    retryCount.current++;
    retryTimer = setTimeout(connect, delay);
  };
}
```

The hook has automatic reconnection with exponential backoff (max 30 seconds). When the connection drops, it retries automatically.

**Citations**:
- `frontend/src/hooks/useMessagingStream.ts:4` -- SSE URL
- `frontend/src/hooks/useMessagingStream.ts:131-153` -- `connect()` function with EventSource setup
- `frontend/src/hooks/useMessagingStream.ts:146-152` -- error handler with exponential backoff

### 3.4 Frontend SSE Handler (The Gap)

**`EVENT_TYPES` array** (`useMessagingStream.ts:96-129`):

```typescript
const EVENT_TYPES = [
  "message:new",
  "message:revoked",
  "message:edited",
  "message:reaction",
  "message:locked",
  "message:unlocked",
  "message:expired",
  "once_media_consumed",
  "once_media_state_changed",
  "conversation_updated",
  "poll:vote",
  "poll:confirmed",
  "helpdesk.conversation.alerted",
  "helpdesk.conversation.assigned",
  "helpdesk.conversation.released",
  "helpdesk.conversation.no_agents_online",
  "call.invite",
  "call.accept",
  "call.decline",
  "call.end",
  "call.missed",
  "call.recording_request",
  "call.recording_accept",
  "call.recording_decline",
  "call.recording_started",
  "call.recording_stopped",
  "call.billing_tick",
  "call.balance_low",
  "call.balance_depleted",
  "webrtc.offer",
  "webrtc.answer",
  "webrtc.ice_candidate",
];
```

**`typing:update` is NOT in this array.** Since EventSource listeners are only registered for events in this array (line 142), the browser receives `typing:update` SSE events but silently ignores them -- they are never dispatched to `handleEvent`.

**`handleEvent` function** (`useMessagingStream.ts:23-92`):

The function handles message events, conversation updates, helpdesk events, poll events, call events, and WebRTC signaling. There is no branch for `typing:update`:

```typescript
function handleEvent(event: MessageEvent) {
  try {
    const data = JSON.parse(event.data as string);
    const conversationId = typeof data.conversation_id === "string" ? data.conversation_id : undefined;
    const eventType: string = (event.type ?? "") || (typeof data.type === "string" ? data.type : "");

    // Conversations list refresh
    if (eventType === "message:new" || eventType === "message:revoked" || ...) {
      queryClient.invalidateQueries({ queryKey: ["conversations"] });
    }

    // Message list refresh
    if (conversationId) {
      queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
    }

    // Poll events
    if (eventType === "poll:vote" || eventType === "poll:confirmed") { ... }

    // Call events → window.dispatchEvent
    if (eventType.startsWith("call.")) { ... }

    // WebRTC signals → window.dispatchEvent
    if (eventType.startsWith("webrtc.")) { ... }
  } catch {
    // Ignore parse errors
  }
}
```

**Citations**:
- `frontend/src/hooks/useMessagingStream.ts:96-129` -- `EVENT_TYPES` array (no `typing:update`)
- `frontend/src/hooks/useMessagingStream.ts:142-143` -- listeners registered only for EVENT_TYPES
- `frontend/src/hooks/useMessagingStream.ts:23-92` -- `handleEvent` with no typing branch

### 3.5 Frontend TypingIndicator Component

`frontend/src/pages/messages/TypingIndicator.tsx` (89 lines):

```typescript
const TYPING_POLL_MS = 3_000;
const TYPING_DEBOUNCE_MS = 2_000;

export function TypingIndicator({ conversationId, className }: TypingIndicatorProps) {
  const userId = useAuthStore((s) => s.userId);

  const { data: typers } = useQuery({
    queryKey: ["typing", conversationId],
    queryFn: () => getTyping(conversationId),
    refetchInterval: TYPING_POLL_MS,     // 3000ms <-- THE PROBLEM
    staleTime: TYPING_POLL_MS,           // 3000ms
    enabled: !!conversationId,
  });

  const others = (typers ?? []).filter((t) => t.user_id !== userId);

  if (others.length === 0) return null;

  const label =
    others.length === 1
      ? `${others[0]!.user_id} is typing`
      : `${others.length} people are typing`;

  return (
    <div className={cn("flex items-center gap-1.5 px-4 py-1.5 text-xs text-muted-foreground", className)}>
      <BouncingDots />
      <span>{label}</span>
    </div>
  );
}
```

**`useTypingSignal` hook** (lines 73-89):

```typescript
export function useTypingSignal(conversationId: string) {
  const lastSentRef = useRef(0);

  const onKeystroke = useCallback(() => {
    const now = Date.now();
    if (now - lastSentRef.current < TYPING_DEBOUNCE_MS) return;
    lastSentRef.current = now;
    sendTyping(conversationId).catch(() => {});
  }, [conversationId]);

  useEffect(() => {
    lastSentRef.current = 0;
  }, [conversationId]);

  return onKeystroke;
}
```

The hook debounces at 2 seconds -- it sends at most one typing POST every 2 seconds while the user is typing. This is efficient and does not need to change.

**Citations**:
- `frontend/src/pages/messages/TypingIndicator.tsx:7` -- `TYPING_POLL_MS = 3_000`
- `frontend/src/pages/messages/TypingIndicator.tsx:8` -- `TYPING_DEBOUNCE_MS = 2_000`
- `frontend/src/pages/messages/TypingIndicator.tsx:36-42` -- useQuery with 3s refetchInterval
- `frontend/src/pages/messages/TypingIndicator.tsx:73-89` -- `useTypingSignal` debounce hook

### 3.6 Gaps Summary

| Gap | Current | Required |
|-----|---------|----------|
| `typing:update` in EVENT_TYPES | MISSING | Add to array |
| Handler for `typing:update` in handleEvent | MISSING | Update React Query cache |
| Polling interval | 3 seconds | 30 seconds (fallback only) |
| Client-side TTL cleanup | MISSING | 2-second interval to clear expired entries |

---

## 4. Technical Architecture

### 4.1 Proposed Data Flow

```
Alice types keystroke
        │
        ▼
useTypingSignal() debounce (2s) → POST /conversations/{id}/typing
        │
        ▼
Backend: tbl_typing.put_item() + fanout_event_to_conversation("typing:update")
        │
        ▼
SSE event delivered to Bob's EventSource:
    event: typing:update
    data: {"conversation_id": "conv_123", "user_id": "alice_sub", "is_typing": true, "updated_at": 1748380800}
        │
        ▼
useMessagingStream.handleEvent()
    → detects eventType === "typing:update"
    → extracts conversation_id, user_id, is_typing, updated_at
        │
        ▼
queryClient.setQueryData(["typing", "conv_123"], updater)
    → adds/removes alice from the typers array
        │
        ▼
TypingIndicator re-renders (< 100ms total latency from keystroke to display)
    → "alice_sub is typing" appears with BouncingDots
```

### 4.2 SSE Event Payload Structure

The backend emits (messaging.py:11360):
```json
{
  "conversation_id": "conv_abc123",
  "user_id": "user_alice_sub",
  "is_typing": true,
  "updated_at": 1748380800
}
```

The `conversation_id` field is included in the payload by `fanout_event_to_conversation` (it adds the field to all fanned-out events). The `event.type` header is `typing:update`.

### 4.3 React Query Cache Update Strategy

Instead of `invalidateQueries` (which triggers a refetch), we use `setQueryData` for immediate cache updates:

```typescript
queryClient.setQueryData<TypingUser[]>(
  ["typing", conversationId],
  (old) => {
    const filtered = (old ?? []).filter((t) => t.user_id !== userId);
    if (isTyping) {
      return [...filtered, { user_id: userId, updated_at: updatedAt }];
    }
    return filtered;  // User stopped typing
  },
);
```

This approach:
- Does NOT trigger a network request (unlike `invalidateQueries`).
- Instantly updates the cache with the new typing state.
- Triggers a synchronous re-render of `TypingIndicator`.
- Is idempotent (duplicate events are handled by the `filter` + add pattern).

### 4.4 TTL Cleanup Architecture

Since the SSE stream only delivers `is_typing: true` events when users start typing, and `is_typing: false` events when they explicitly stop, there's a gap: if Alice navigates away (closes the tab), no `is_typing: false` event is sent. The server relies on TTL expiry (5 seconds) to clean up the DDB record. The client must also implement TTL cleanup:

```
┌─────────────────────────────────────────────────┐
│ Client-side TTL Cleanup (every 2 seconds)        │
│                                                   │
│ For each entry in ["typing", conversationId]:    │
│   if (entry.updated_at < now - 5 seconds):      │
│     → remove from cache                          │
│                                                   │
│ This catches "abandoned" typing states where:    │
│ - User closed tab (no stop event sent)           │
│ - Network dropped (stop event lost)              │
│ - Server TTL expired but no poll caught it       │
└─────────────────────────────────────────────────┘
```

---

## 5. Implementation Plan

### 5.1 Frontend: useMessagingStream.ts

**File: `frontend/src/hooks/useMessagingStream.ts`**

**Change 1**: Add `"typing:update"` to the `EVENT_TYPES` array (line 129, before the closing bracket):

```typescript
const EVENT_TYPES = [
  "message:new",
  "message:revoked",
  "message:edited",
  "message:reaction",
  "message:locked",
  "message:unlocked",
  "message:expired",
  "once_media_consumed",
  "once_media_state_changed",
  "conversation_updated",
  "poll:vote",
  "poll:confirmed",
  "helpdesk.conversation.alerted",
  "helpdesk.conversation.assigned",
  "helpdesk.conversation.released",
  "helpdesk.conversation.no_agents_online",
  "call.invite",
  "call.accept",
  "call.decline",
  "call.end",
  "call.missed",
  "call.recording_request",
  "call.recording_accept",
  "call.recording_decline",
  "call.recording_started",
  "call.recording_stopped",
  "call.billing_tick",
  "call.balance_low",
  "call.balance_depleted",
  "webrtc.offer",
  "webrtc.answer",
  "webrtc.ice_candidate",
  "typing:update",           // ← NEW
];
```

**Change 2**: Add handler in `handleEvent` function. Insert BEFORE the conversations list invalidation block (around line 29), because typing events should NOT invalidate the conversations list:

```typescript
function handleEvent(event: MessageEvent) {
  try {
    const data = JSON.parse(event.data as string);
    const conversationId = typeof data.conversation_id === "string" ? data.conversation_id : undefined;
    const eventType: string = (event.type ?? "") || (typeof data.type === "string" ? data.type : "");

    // ── Typing indicator: update cache directly (no network request) ──
    if (eventType === "typing:update" && conversationId) {
      const userId = typeof data.user_id === "string" ? data.user_id : undefined;
      const isTyping = data.is_typing === true;
      const updatedAt = typeof data.updated_at === "number" ? data.updated_at : Math.floor(Date.now() / 1000);

      if (userId) {
        queryClient.setQueryData<Array<{ user_id: string; updated_at: number }>>(
          ["typing", conversationId],
          (old) => {
            const filtered = (old ?? []).filter((t) => t.user_id !== userId);
            if (isTyping) {
              return [...filtered, { user_id: userId, updated_at: updatedAt }];
            }
            return filtered;
          },
        );
      }
      return; // Don't invalidate conversations/messages for typing events
    }

    // (existing handlers continue below...)
```

**Why `return` early**: Typing events should not trigger conversation list or message list invalidation. They are transient presence signals, not data mutations. Without the early return, every typing event would trigger refetches of the entire conversations list and message list.

### 5.2 Frontend: TypingIndicator.tsx

**File: `frontend/src/pages/messages/TypingIndicator.tsx`**

**Change 1**: Reduce polling interval from 3 seconds to 30 seconds:

```typescript
const TYPING_POLL_MS = 30_000; // Fallback poll; primary updates via SSE
```

The 30-second interval serves as a safety net:
- If SSE disconnects, the poll catches up within 30 seconds.
- If an SSE event is lost (rare), the poll corrects the state.
- The vast majority of the time, the SSE handler keeps the cache current and the poll returns the same data (no re-render triggered).

**Change 2**: Add client-side TTL cleanup effect. Insert after the useQuery hook:

```typescript
export function TypingIndicator({ conversationId, className }: TypingIndicatorProps) {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();

  const { data: typers } = useQuery({
    queryKey: ["typing", conversationId],
    queryFn: () => getTyping(conversationId),
    refetchInterval: TYPING_POLL_MS,     // 30_000ms (fallback)
    staleTime: TYPING_POLL_MS,
    enabled: !!conversationId,
  });

  // ── Client-side TTL cleanup ──────────────────────────────────────
  // SSE events add typers to the cache, but "stop typing" may be missed
  // if the user closes their tab or loses connectivity. This interval
  // removes stale entries based on the server's 5-second TTL.
  useEffect(() => {
    const cleanup = setInterval(() => {
      queryClient.setQueryData<Array<{ user_id: string; updated_at: number }>>(
        ["typing", conversationId],
        (old) => {
          if (!old || old.length === 0) return old;
          const cutoff = Math.floor(Date.now() / 1000) - 5; // 5s TTL
          const filtered = old.filter((t) => t.updated_at > cutoff);
          // Only update if something was removed (avoid unnecessary re-renders)
          return filtered.length === old.length ? old : filtered;
        },
      );
    }, 2000); // Check every 2 seconds

    return () => clearInterval(cleanup);
  }, [conversationId, queryClient]);

  // Filter out self
  const others = (typers ?? []).filter((t) => t.user_id !== userId);

  if (others.length === 0) return null;

  const label =
    others.length === 1
      ? `${others[0]!.user_id} is typing`
      : `${others.length} people are typing`;

  return (
    <div className={cn("flex items-center gap-1.5 px-4 py-1.5 text-xs text-muted-foreground", className)}>
      <BouncingDots />
      <span>{label}</span>
    </div>
  );
}
```

**Change 3**: Add `useQueryClient` import:

```typescript
import { useEffect, useCallback, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
```

### 5.3 Backend: No Changes Required

The backend already:
- Stores typing state in `tbl_typing` with TTL (line 11346-11353).
- Emits `typing:update` SSE events via `fanout_event_to_conversation` (line 11356-11362).
- Serves the `GET /conversations/{id}/typing` poll endpoint (line 11366-11382).
- Includes `conversation_id` in the SSE event payload.

No backend changes are needed. This is purely a frontend integration.

### 5.4 TypeScript Types

**File: `frontend/src/api/types.ts`**

Ensure `TypingUser` interface exists (it should already be defined from the messaging types):

```typescript
export interface TypingUser {
  user_id: string;
  updated_at: number;
}
```

If not present, add it. The typing response from `getTyping()` should already be typed as `TypingUser[]`.

### 5.5 Message Send Clears Typing

When a `message:new` SSE event arrives for a conversation, the existing handler invalidates `["messages", conversationId]`. We should ALSO clear the sender's typing entry from the cache, since sending a message implies they stopped typing:

```typescript
// Inside the message:new handler (already exists):
if (eventType === "message:new" && conversationId) {
  // Existing: refresh messages
  queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });

  // NEW: Clear sender from typing cache
  const senderId = typeof data.sender_id === "string" ? data.sender_id : undefined;
  if (senderId) {
    queryClient.setQueryData<Array<{ user_id: string; updated_at: number }>>(
      ["typing", conversationId],
      (old) => (old ?? []).filter((t) => t.user_id !== senderId),
    );
  }
}
```

This provides an immediate "stop typing" signal when a message is received, without waiting for the TTL to expire.

---

## 6. Security & Privacy Considerations

### 6.1 Typing Privacy

Typing indicators are already sent to all active conversation participants. The `fanout_event_to_conversation` function filters recipients by `status == "active"` (participants who have accepted the conversation). Removed or pending participants do not receive typing events. No change to privacy scope.

### 6.2 SSE Authentication

The SSE stream is authenticated via the same cookie-based session as the REST API. The EventSource is created with `withCredentials: true` (line 132). No additional authentication is needed for typing events since they travel over the same authenticated channel.

### 6.3 Muting Behavior

Typing events use `respect_mute=False` (messaging.py:11361). This means:
- Users who have MUTED a conversation still receive typing indicators.
- This is intentional: muting suppresses push notifications and sound, but real-time presence information (typing, read receipts) still flows.
- No change needed for this ticket.

### 6.4 Data Exposure

The typing SSE event only contains `user_id`, `is_typing`, `updated_at`, and `conversation_id`. No sensitive content is exposed. The user_id is already known to all conversation participants.

---

## 7. Performance Impact

### 7.1 Network Traffic Reduction

| Metric | Before (3s poll) | After (SSE + 30s fallback) | Reduction |
|--------|-------------------|---------------------------|-----------|
| HTTP requests/min per conversation | ~20 | ~2 (fallback only) | 90% |
| DDB reads/min per conversation | ~20 | ~2 (fallback only) | 90% |
| Bytes/min per conversation (empty responses) | ~10KB | ~1KB | 90% |
| Avg latency | 1500ms | <100ms | 93% |

For a user with 5 open conversations:
- **Before**: 100 requests/min, 100 DDB reads/min
- **After**: 10 requests/min, 10 DDB reads/min

### 7.2 SSE Event Volume

Typing events are already being written to `tbl_events` by the backend (`fanout_event_to_conversation`) regardless of whether the frontend consumes them. The SSE stream already delivers all event types to connected clients. Adding `typing:update` to the frontend handler introduces **zero additional backend load** -- the events were already being generated, transmitted, and received by the browser.

### 7.3 Client-Side CPU

The TTL cleanup interval (every 2 seconds) is negligible:
- Array filter on typically 0-3 items.
- Only triggers re-render if items were actually removed.
- `setQueryData` short-circuits if old and new arrays are reference-equal.

### 7.4 React Query Cache Size

Typing cache entries are tiny (`{user_id: string, updated_at: number}`). With a 5-second TTL, the cache typically holds 0-3 entries per conversation. Memory impact is negligible.

---

## 8. Testing Strategy

### 8.1 Unit Tests

No new unit tests needed (backend is unchanged). Existing typing endpoint tests in `tests/` continue to pass.

### 8.2 E2E Tests

**Test File**: `frontend/e2e/typing-realtime.spec.ts`

**Section 1: SSE Typing Indicator (5 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | Alice types; Bob sees indicator within 1 second | Alice sends POST /typing; Bob's page shows "is typing" | `page.getByText(/is typing/).toBeVisible()` within 1000ms |
| 2 | Alice stops typing; indicator disappears within 6 seconds | Alice sends is_typing=false; wait | "is typing" not visible within 6s |
| 3 | Multiple typers shown correctly | Alice and Charlie both send typing | Bob sees "2 people are typing" |
| 4 | Typing indicator clears when message is sent | Alice sends message (message:new event) | "is typing" disappears for Bob |
| 5 | Typing indicator clears after TTL expires | Alice sends typing; wait 6 seconds | "is typing" disappears (client-side cleanup) |

**Section 2: Fallback Behavior (2 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 6 | Typing shows with SSE disconnected (poll fallback) | Close EventSource via page.evaluate; Alice types | Bob sees indicator within 30s |
| 7 | SSE reconnection restores instant updates | Reconnect SSE | Verify sub-second indicator for next typing event |

**Section 3: Edge Cases (2 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 8 | Own typing not shown | Alice types in conversation | Alice does NOT see her own "is typing" indicator |
| 9 | Typing in different conversation doesn't cross-contaminate | Alice types in conv A | Bob in conv B does NOT see indicator |

**Test Implementation Notes**:

```typescript
// Sending typing signal from Alice's context
await alicePage.request.post(
  `/messaging/conversations/${conversationId}/typing`,
  {
    headers: { "x-csrf-token": sessions["alice"].csrf_token },
    data: { is_typing: true },
  },
);

// Wait for Bob to see the indicator
await expect(bobPage.getByText(/is typing/)).toBeVisible({ timeout: 1000 });

// To test SSE disconnect:
await bobPage.evaluate(() => {
  // Close all EventSource connections
  const sources = (window as any).__eventSources;
  if (sources) sources.forEach((es: EventSource) => es.close());
});
```

### 8.3 Manual Testing Checklist

1. Open two browser windows (Alice and Bob) in the same conversation.
2. Alice types in the compose area.
3. Verify Bob sees "alice is typing" appear almost instantly (no perceptible delay).
4. Verify the indicator disappears ~5 seconds after Alice stops typing.
5. Alice sends a message. Verify "is typing" disappears immediately for Bob.
6. Check browser DevTools Network tab: no frequent polling requests to `/typing` during active SSE.
7. Kill the SSE connection (DevTools > Network > EventSource > close). Verify that after 30s, typing still shows (poll fallback).
8. Restore connectivity. Verify instant typing returns.

---

## 9. Migration & Rollback

### 9.1 No Migration Needed

This is a pure frontend change. The SSE events are already being emitted by the backend and transmitted to clients. The fallback polling ensures the feature degrades gracefully. No database changes, no backend changes, no configuration changes.

### 9.2 Rollback Procedure

Revert the two frontend files:
- `frontend/src/hooks/useMessagingStream.ts` -- remove `typing:update` from EVENT_TYPES, remove handler
- `frontend/src/pages/messages/TypingIndicator.tsx` -- revert TYPING_POLL_MS to 3000, remove TTL cleanup effect

Typing indicators return to 3-second polling. No data loss, no backend changes to revert, no user action required.

### 9.3 Partial Rollback

If only the TTL cleanup causes issues, it can be removed independently while keeping the SSE handler. The 30-second fallback poll will catch any stale entries.

---

## 10. Files to Create

| File | Purpose |
|------|---------|
| `frontend/e2e/typing-realtime.spec.ts` | E2E tests for SSE typing (9 tests) |

## 11. Files to Modify

| File | Change | Lines Affected |
|------|--------|----------------|
| `frontend/src/hooks/useMessagingStream.ts` | Add `"typing:update"` to EVENT_TYPES; add handler to update typing query cache; clear sender on message:new | ~15 lines added |
| `frontend/src/pages/messages/TypingIndicator.tsx` | Add `useQueryClient` import; reduce poll interval to 30s; add client-side TTL cleanup effect | ~15 lines added, 1 line changed |

---

## 12. Acceptance Criteria

1. When Alice types in a conversation, Bob sees the typing indicator within 1 second (was 0-3 seconds).
2. The typing indicator updates are delivered via SSE `typing:update` events, not polling.
3. Polling interval is reduced to 30 seconds as a fallback for SSE disconnects.
4. SSE handler in `useMessagingStream.ts` includes `typing:update` in `EVENT_TYPES` and updates the React Query cache via `setQueryData` on receipt.
5. Client-side TTL cleanup removes stale typing entries every 2 seconds (5-second cutoff).
6. No backend changes are required.
7. Existing typing behavior (TTL-based expiry, debounced keystroke sends) is preserved unchanged.
8. `TypingIndicator` component continues to function correctly with the SSE-driven data source.
9. Typing indicator disappears immediately when the typer sends a message (message:new clears typing cache).
10. Own typing events are filtered out (self not shown).
11. All 9 E2E tests pass.

---

## 13. Dependencies

- **Messaging SSE Infrastructure (existing)**: `useMessagingStream.ts` hook, `/messaging/events/stream` endpoint.
- **Typing API (existing)**: `POST /conversations/{id}/typing`, `GET /conversations/{id}/typing`.
- **React Query (existing)**: `@tanstack/react-query` for cache management.

---

## 14. Open Questions & Risks

### 14.1 Open Questions

1. **Display name vs user_id**: Currently the indicator shows `user_id` (e.g., "e2e_alice@test.local is typing"). Should we resolve the user_id to a display name? This would require either including the display name in the SSE payload or maintaining a user name cache. Deferred to a follow-up ticket.
2. **Group chat throttling**: In a group chat with 50 participants all typing simultaneously, should we throttle the indicator display (e.g., "3 people are typing" max)? The current implementation already handles this via the `others.length` check, but at high concurrency the SSE events may cause many re-renders. Consider debouncing the cache update with a 100ms window.
3. **Typing in minimized conversations**: If Bob has the conversation list open but not a specific conversation, should typing indicators appear in the sidebar preview? This is out of scope for this ticket but worth considering.

### 14.2 Risks

1. **SSE event ordering**: If multiple typing events arrive rapidly (user types, stops, types again within 1 second), the cache must handle out-of-order events gracefully. The `updated_at` timestamp and the set-then-add pattern ensures the latest state wins.
2. **Cache divergence**: If an SSE event is lost (extremely rare but possible during reconnection), the typing cache may show stale data until the 30-second fallback poll corrects it or the TTL cleanup removes it. The 5-second client-side TTL provides a tight safety net.
3. **Test flakiness**: Timing-sensitive assertions ("visible within 1000ms") may be flaky on slow CI runners. Use generous timeouts in assertions (1000ms) while verifying that polling-era timing (3000ms+) is NOT happening.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Backend emits `typing:update` SSE event | `app/routers/messaging.py` | 11356-11362 | VERIFIED |
| `fanout_event_to_conversation` writes to tbl_events | `app/routers/messaging.py` | 5244-5278 | VERIFIED |
| Payload: user_id, is_typing, updated_at | `app/routers/messaging.py` | 11360 | VERIFIED |
| `respect_mute=False` for typing events | `app/routers/messaging.py` | 11361 | VERIFIED |
| DDB put_item with TTL | `app/routers/messaging.py` | 11346-11353 | VERIFIED |
| GET typing poll endpoint | `app/routers/messaging.py` | 11366-11382 | VERIFIED |
| TTL expiry check in get_typing | `app/routers/messaging.py` | 11376-11377 | VERIFIED |
| TypingIndicator polls every 3 seconds | `frontend/src/pages/messages/TypingIndicator.tsx` | 7, 36-42 | OUTDATED: TypingIndicator.tsx:7 shows `TYPING_FALLBACK_POLL_MS = 30_000` (30 seconds, NOT 3 seconds). The SSE-driven real-time update is ALREADY IMPLEMENTED |
| useTypingSignal debounces at 2 seconds | `frontend/src/pages/messages/TypingIndicator.tsx` | 8, 73-89 | VERIFIED |
| useMessagingStream EVENT_TYPES array | `frontend/src/hooks/useMessagingStream.ts` | 96-129 | VERIFIED |
| `typing:update` NOT in EVENT_TYPES | `frontend/src/hooks/useMessagingStream.ts` | 160 | INCORRECT: `typing:update` IS in EVENT_TYPES at line 160. The SSE handler exists at lines 70-86, writing directly to React Query cache. THIS WORK IS ALREADY DONE |
| handleEvent has no typing branch | `frontend/src/hooks/useMessagingStream.ts` | 70-86 | INCORRECT: typing:update handler EXISTS at lines 70-86, using `queryClient.setQueryData` to write typing state directly to cache |
| SSE URL is /messaging/events/stream | `frontend/src/hooks/useMessagingStream.ts` | 4 | VERIFIED |
| EventSource with withCredentials | `frontend/src/hooks/useMessagingStream.ts` | 132 | VERIFIED |
| EventSource listeners per EVENT_TYPES | `frontend/src/hooks/useMessagingStream.ts` | 142-143 | VERIFIED |
| Exponential backoff reconnection | `frontend/src/hooks/useMessagingStream.ts` | 146-152 | VERIFIED |
| BouncingDots animation component | `frontend/src/pages/messages/TypingIndicator.tsx` | 12-24 | VERIFIED |
| Others filter (exclude self) | `frontend/src/pages/messages/TypingIndicator.tsx` | 45 | VERIFIED |

<!-- CRITICAL NOTE: This ticket's core proposal (adding typing:update to the SSE handler and reducing polling) has been FULLY IMPLEMENTED:
- useMessagingStream.ts line 70-86: typing:update handler writes directly to React Query cache
- useMessagingStream.ts line 160: typing:update is in EVENT_TYPES array
- TypingIndicator.tsx line 7: TYPING_FALLBACK_POLL_MS = 30_000 (30s fallback, not 3s)
- TypingIndicator.tsx line 48-66: client-side TTL cleanup every 2s
The ticket should be marked as Complete. -->

---

## Testing Strategy

### Unit Tests
No backend unit tests required (frontend-only changes). Behavior verified via E2E tests.

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/typing-realtime.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~8 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

No dependencies -- this ticket can be implemented independently.

### Depended On By

No downstream dependents identified.

### Merge Strategy
**Independent -- frontend-only changes. Adds typing:update handler to useMessagingStream. Zero backend work.**

### Merge Checklist
- [ ] Service file created/modified: `frontend/src/hooks/useMessagingStream.ts (modified)`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/typing-realtime.spec.ts`
