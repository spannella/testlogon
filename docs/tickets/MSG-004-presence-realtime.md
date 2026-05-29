# MSG-004: Online Presence -- Real-time Push

**Ticket**: MSG-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 4-5 days

---

## 1. Executive Summary

Online presence (the green/grey dot showing whether a user is online or offline) currently works via a 15-second polling loop. The frontend sends heartbeats every 30 seconds (`POST /presence/heartbeat`) and polls presence status every 15 seconds (`GET /presence?user_ids=...`). Unlike typing indicators (which already emit SSE events backend-side), the presence system has no SSE event emission at all. When a user comes online or goes offline, other users must wait up to 15 seconds to see the change.

This polling-based architecture creates two problems: high request volume (a conversation list with 10 DM partners generates ~40 requests/minute to the presence endpoint) and perceptually slow presence transitions (up to 15 seconds to see someone come online). On mobile connections, 15 seconds feels like presence is broken.

This feature adds a `presence:update` SSE event emitted by the backend on each heartbeat (with a 60-second cooldown to prevent flooding) and on presence expiry detection. The frontend handles this event in `useMessagingStream` to instantly update `PresenceDot` components via React Query cache writes. Polling is demoted to a 60-second fallback for resilience. The result is near-instant online/offline transitions visible to conversation partners, with a 75% reduction in presence-related API requests.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Instant Online Detection**

As a user viewing my conversation list, I want to see Bob's green dot appear instantly when he opens the app, so that I know I can message him and expect a quick reply.

Acceptance criteria:
- PresenceDot turns green within 2 seconds of Bob's first heartbeat arriving at the backend.
- The transition is driven by SSE, not polling (verified by checking network requests in browser DevTools).
- Multiple PresenceDots in the conversation list (for different DM partners) all update via SSE without individual polling.

**US-2: Offline Detection via Client TTL**

As a user, I want to see Bob's dot turn grey when he closes the app, so that I know he is no longer available.

Acceptance criteria:
- PresenceDot turns grey within `PRESENCE_TTL_SEC` (120 seconds) of Bob's last heartbeat.
- The frontend computes offline status locally from the `last_seen_at` timestamp received via SSE.
- The 60-second fallback poll eventually confirms the offline status from the server.

**US-3: Reduced Request Volume**

As a platform operator, I want the presence system to use SSE push instead of frequent polling, to reduce backend load.

Acceptance criteria:
- Presence polling interval increases from 15 seconds to 60 seconds.
- Frontend presence updates are driven by SSE events (cache writes via `queryClient.setQueryData`).
- Total presence-related requests per user decrease by at least 75%.

**US-4: Presence Scope Privacy**

As a user, I want my online status only visible to people I have active conversations with, not to arbitrary users.

Acceptance criteria:
- Presence SSE events are fanned out only to users who share at least one active conversation with the subject.
- Users with no shared conversations do not receive presence updates.
- The fan-out uses conversation participant lookups from `tbl_parts`.

**US-5: Graceful Degradation**

As a user on an unreliable connection, I want presence to still work even if SSE is disconnected.

Acceptance criteria:
- When SSE disconnects, the 60-second fallback poll provides presence data.
- When SSE reconnects, presence updates resume via push.
- No UI flicker during SSE reconnection (stale poll data serves as a bridge).

### 2.2 Pain Points

1. **Delayed presence**: A 15-second polling interval means the green dot can take up to 15 seconds to appear or disappear, making presence feel unreliable. Users complain that "presence doesn't work."
2. **High request volume**: Each `usePresenceStatus(userId)` hook instance polls every 15 seconds. A conversation list showing 10 DM partners generates ~40 requests/min to the presence endpoint. `useBatchPresence` helps but still polls every 15s.
3. **Wasted bandwidth**: Presence rarely changes (a user is either online or offline for extended periods). Polling repeatedly for unchanged data wastes bandwidth and DDB read capacity.
4. **No server push on go-offline**: When a user closes their browser, their presence TTL expires on the server. No notification is sent to other users -- they only discover the change on their next poll.

### 2.3 Latency Comparison

| Mode | Online detection | Offline detection | Requests/min per user pair |
|------|-----------------|-------------------|---------------------------|
| Polling (current, 15s) | 0-15s | 0-15s after TTL expires | ~4 |
| SSE push (proposed) | <2s (heartbeat round-trip) | TTL + <60s (client TTL check + fallback poll) | ~1 (fallback only) |
| Improvement | 87-100% faster | Slightly slower but acceptable | 75% reduction |

---

## 3. Current State Analysis

### 3.1 Backend Heartbeat (`app/routers/messaging.py:11388-11430`)

```python
# app/routers/messaging.py:11388-11430
@router.post("/presence/heartbeat")
def presence_heartbeat(
    inp: PresenceHeartbeatIn,
    request: Request = None,
    x_request_id: Optional[str] = None,
    user_id: str = Depends(get_messaging_user_id),
):
    ts = now_ts()
    status = _normalize_presence_status(inp.status)
    tbl_presence.put_item(
        Item={
            "user_id": user_id,
            "last_seen_at": ts,
            "device": inp.device or "",
            "status": status,
            "ttl": ts + PRESENCE_TTL_SEC,
        }
    )
    routing = _handle_helpdesk_presence_event(user_id=user_id, status=status, ts=ts)
    return {
        "ok": True, "user_id": user_id, "online": status in {"online", "available"},
        "last_seen_at": ts, "status": status, "routing": routing,
    }
```

Key observations:
- Line 11402: Stores presence in `tbl_presence` DynamoDB table with TTL of `PRESENCE_TTL_SEC` (120 seconds, defined at `messaging.py:210`).
- Line 11411: Calls `_handle_helpdesk_presence_event` for helpdesk routing but does NOT call `fanout_event_to_conversation` or any SSE emission function.
- The heartbeat response includes `online` status, but this is returned only to the sender, not broadcast to others.
- **There is no `presence:update` SSE event emitted anywhere in the codebase.**

**Citation**: `app/routers/messaging.py:11388-11430` -- heartbeat endpoint, no SSE emission.

### 3.2 Backend Presence Query (`app/routers/messaging.py:11433-11454`)

```python
# app/routers/messaging.py:11433-11454
@router.get("/presence", response_model=List[PresenceOut])
def presence_get(
    user_ids: Annotated[str, Query(...)],
    user_id: str = Depends(get_messaging_user_id),
):
    ids = [x.strip() for x in user_ids.split(",") if x.strip()]
    keys = [{"user_id": uid} for uid in ids]
    resp = ddb.meta.client.batch_get_item(RequestItems={DDB_PRESENCE: {"Keys": keys}})
    items = resp.get("Responses", {}).get(DDB_PRESENCE, [])
    ts = now_ts()
    # ... computes online based on ONLINE_WINDOW_SEC ...
    for uid in ids:
        it = mp.get(uid)
        last_seen = int(it.get("last_seen_at", 0) or 0) if it else 0
        online = (ts - last_seen) <= ONLINE_WINDOW_SEC if last_seen else False
        out.append(PresenceOut(user_id=uid, online=online, last_seen_at=last_seen))
    return out
```

This is the endpoint the frontend polls every 15 seconds. It uses `batch_get_item` for efficient multi-user lookups and computes online/offline based on `ONLINE_WINDOW_SEC`.

**Citation**: `app/routers/messaging.py:11433-11454` -- presence GET endpoint.

### 3.3 Presence Table Constants

```python
# app/routers/messaging.py:172, 210, 230
DDB_PRESENCE = os.getenv("DDB_PRESENCE", "UserPresence")
PRESENCE_TTL_SEC = int(os.getenv("PRESENCE_TTL_SEC", "120"))
tbl_presence = ddb.Table(DDB_PRESENCE)
```

Records have `user_id` (PK), `last_seen_at` (N), `device` (S), `status` (S), and `ttl` (N, DDB TTL attribute).

**Citation**: `app/routers/messaging.py:172, 210, 230` -- constants and table handle.

### 3.4 Frontend Presence Hooks (`frontend/src/hooks/usePresence.ts`)

```typescript
// frontend/src/hooks/usePresence.ts:1-71
const HEARTBEAT_INTERVAL_MS = 30_000;
const PRESENCE_POLL_MS = 15_000;

// useHeartbeat (lines 12-27): POST /presence/heartbeat every 30s when visible
export function useHeartbeat(enabled = true) {
  useEffect(() => {
    if (!enabled) return;
    sendHeartbeat().catch(() => {});
    const id = setInterval(() => {
      if (document.visibilityState === "visible") {
        sendHeartbeat().catch(() => {});
      }
    }, HEARTBEAT_INTERVAL_MS);
    return () => clearInterval(id);
  }, [enabled]);
}

// usePresenceStatus (lines 33-47): Polls GET /presence?user_ids=X every 15s
export function usePresenceStatus(userId: string | undefined) {
  const { data } = useQuery({
    queryKey: ["presence", userId],
    queryFn: () => getPresence([userId!]),
    enabled: !!userId,
    refetchInterval: PRESENCE_POLL_MS,
    staleTime: PRESENCE_POLL_MS,
  });
  const entry = data?.[0];
  return { online: entry?.online ?? false, lastSeenAt: entry?.last_seen_at ?? 0 };
}

// useBatchPresence (lines 53-71): Polls GET /presence?user_ids=X,Y,Z every 15s
export function useBatchPresence(userIds: string[]) {
  const key = userIds.slice().sort().join(",");
  const { data } = useQuery({
    queryKey: ["presence", "batch", key],
    queryFn: () => getPresence(userIds),
    enabled: userIds.length > 0,
    refetchInterval: PRESENCE_POLL_MS,
    staleTime: PRESENCE_POLL_MS,
  });
  // returns Map<string, boolean>
}
```

All three hooks use `PRESENCE_POLL_MS = 15_000`. Each `usePresenceStatus(userId)` creates an independent 15-second poll.

**Citation**: `frontend/src/hooks/usePresence.ts:1-71` -- all three hooks with 15s polling.

### 3.5 Frontend PresenceDot Component (`frontend/src/pages/messages/PresenceDot.tsx`)

```typescript
// frontend/src/pages/messages/PresenceDot.tsx:13-28
export function PresenceDot({ userId, className }: PresenceDotProps) {
  const { online } = usePresenceStatus(userId);
  return (
    <span
      className={cn(
        "absolute bottom-0 right-0 block h-2.5 w-2.5 rounded-full border-2 border-background",
        online ? "bg-emerald-500 shadow-[0_0_4px_rgba(16,185,129,0.6)]" : "bg-muted-foreground/40",
        className,
      )}
      aria-label={online ? "Online" : "Offline"}
    />
  );
}
```

Each `PresenceDot` creates its own `usePresenceStatus` hook instance. `ConversationList.tsx:173` renders `<PresenceDot userId={other.user_id} />` for each DM partner. This means 10 DM conversations = 10 independent 15-second polls.

**Citation**: `frontend/src/pages/messages/PresenceDot.tsx:13-28` -- component uses `usePresenceStatus`.

### 3.6 Frontend SSE Handler (`frontend/src/hooks/useMessagingStream.ts`)

```typescript
// frontend/src/hooks/useMessagingStream.ts:96-129
const EVENT_TYPES = [
  "message:new",
  "message:revoked",
  "message:edited",
  "message:reaction",
  // ... 25 more event types ...
  "webrtc.ice_candidate",
];
```

The `EVENT_TYPES` array (lines 96-129) does NOT include any presence event type. The `handleEvent` function (lines 23-92) has no presence handler. There is no `"presence:update"` anywhere in the array.

**Citation**: `frontend/src/hooks/useMessagingStream.ts:96-129` -- no presence event type.

### 3.7 SSE Event Writing Pattern (`app/routers/messaging.py:5244-5278`)

The existing `fanout_event_to_conversation` function writes SSE events to `tbl_events` for delivery to conversation participants. The presence fan-out will use a similar pattern but scoped to conversation partners rather than a single conversation.

**Citation**: `app/routers/messaging.py:5244-5278` -- existing SSE event fan-out pattern.

### 3.8 Gaps Summary

| Component | Current State | Gap |
|-----------|--------------|-----|
| Backend heartbeat | Writes to DDB, returns to sender only | No SSE event emission |
| Backend presence query | Batch GET for multiple users | No push mechanism |
| `presence:update` event type | Does not exist | Must be defined and emitted |
| `useMessagingStream.ts` | No presence handler | Must handle `presence:update` |
| `usePresence.ts` | 15s polling, no SSE awareness | Must receive SSE-driven cache updates |
| PresenceDot | Uses polling-based `usePresenceStatus` | No changes needed (reads from same cache) |
| Go-offline notification | No mechanism at all | Client-side TTL check in `usePresenceStatus` |

---

## 4. Technical Architecture

### 4.1 Proposed Data Flow -- Online Detection

```
Bob opens app
     |
     v
useHeartbeat -> POST /presence/heartbeat { status: "online" }
     |
     v
Backend: tbl_presence.put_item (Bob online, last_seen_at=ts)
     |
     v
Backend: _should_emit_presence_event("bob") -> True (60s cooldown passed)
     |
     v
Backend: _fanout_presence_event(user_id="bob", online=True, last_seen_at=ts)
     |
     v
Query tbl_parts: find Bob's conversation partners (Alice, Charlie, ...)
     |
     v
Write presence:update SSE events to tbl_events for each partner
     |
     v
Alice's useMessagingStream receives SSE event:
  { type: "presence:update", user_id: "bob", online: true, last_seen_at: 1748380800 }
     |
     v
queryClient.setQueryData(["presence", "bob"], [{user_id: "bob", online: true, ...}])
     |
     v
PresenceDot re-renders: grey -> green (< 2 seconds total)
```

### 4.2 Go-Offline Detection (Client-Side TTL)

When Bob closes his browser:
1. His heartbeat stops arriving.
2. After `PRESENCE_TTL_SEC` (120s), his presence record's TTL expires in DynamoDB.
3. DynamoDB TTL deletion does NOT trigger real-time events.

**Chosen approach: Client-side TTL computation (Option B)**:
- The frontend tracks `last_seen_at` from SSE events.
- `usePresenceStatus` computes: `effectiveOnline = isOnline && (now - lastSeenAt) <= ONLINE_WINDOW_SEC`.
- A `setInterval` timer in the hook re-evaluates every 30 seconds.
- Combined with the 60-second fallback poll, offline transitions are detected within 60-120 seconds.

Rationale: No additional backend sweep needed. The frontend already has the `last_seen_at` timestamp from SSE events and can compute offline status locally.

### 4.3 Presence Event Cooldown

To avoid flooding the SSE event stream on every heartbeat (every 30 seconds), a cooldown mechanism limits presence event emission:

```python
_presence_event_cache: Dict[str, int] = {}
PRESENCE_EVENT_COOLDOWN = 60  # seconds

def _should_emit_presence_event(user_id: str) -> bool:
    """Rate-limit presence SSE emission to at most once per 60 seconds per user."""
    last = _presence_event_cache.get(user_id, 0)
    now = now_ts()
    if now - last < PRESENCE_EVENT_COOLDOWN:
        return False
    _presence_event_cache[user_id] = now
    return True
```

This means each user generates at most 1 presence SSE event per minute, regardless of heartbeat frequency.

### 4.4 Fan-Out Scope

Presence events are scoped to conversation partners:
1. Query `tbl_parts` for the user's active conversations (`user_id` as PK).
2. For each conversation (capped at 20 to limit fan-out cost), query participants via GSI1.
3. Collect unique partner IDs, excluding the user themselves.
4. Write `presence:update` events to `tbl_events` for each partner via `batch_writer`.

---

## 5. Implementation Plan

### 5.1 Backend: Emit Presence SSE Events on Heartbeat

**File: `app/routers/messaging.py`**

Add in-memory cooldown cache and helper functions (after line ~230):

```python
# Presence SSE cooldown (MSG-004)
_presence_event_cache: Dict[str, int] = {}
PRESENCE_EVENT_COOLDOWN = 60  # seconds


def _should_emit_presence_event(user_id: str) -> bool:
    """Rate-limit presence SSE emission to at most once per 60s per user."""
    last = _presence_event_cache.get(user_id, 0)
    now = now_ts()
    if now - last < PRESENCE_EVENT_COOLDOWN:
        return False
    _presence_event_cache[user_id] = now
    return True


def _fanout_presence_event(*, user_id: str, online: bool, last_seen_at: int) -> None:
    """Send presence:update SSE event to all conversation partners of the user."""
    if not S.presence_sse_enabled:
        return

    # Query user's active conversations
    resp = tbl_parts.query(
        KeyConditionExpression=Key("user_id").eq(user_id),
        FilterExpression=Attr("conversation_id").exists(),
        ProjectionExpression="conversation_id",
        Limit=100,
    )
    conversation_ids = [
        item["conversation_id"]
        for item in resp.get("Items", [])
        if item.get("conversation_id")
    ]

    # Collect unique partner user_ids (cap at 20 conversations)
    partner_ids: set[str] = set()
    for cid in conversation_ids[:20]:
        parts_resp = tbl_parts.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(cid),
            ProjectionExpression="user_id",
            Limit=50,
        )
        for p in parts_resp.get("Items", []):
            pid = p.get("user_id")
            if pid and pid != user_id:
                partner_ids.add(pid)

    if not partner_ids:
        return

    ts = now_ts()
    ttl = ts + 300  # 5-minute event TTL (presence events expire quickly)
    payload = _ddb_safe({
        "user_id": user_id,
        "online": online,
        "last_seen_at": last_seen_at,
    })

    with tbl_events.batch_writer() as bw:
        for pid in partner_ids:
            bw.put_item(Item={
                "user_id": pid,
                "event_id": _event_id(),
                "type": "presence:update",
                "created_at": ts,
                "payload": payload,
                "ttl": ttl,
            })
```

Add the presence event call in `presence_heartbeat()` (after the `tbl_presence.put_item` call at line ~11411):

```python
# MSG-004: Emit presence SSE event to conversation partners
if _should_emit_presence_event(user_id):
    try:
        _fanout_presence_event(
            user_id=user_id,
            online=status in {"online", "available"},
            last_seen_at=ts,
        )
    except Exception:
        logger.warning("presence_sse_fanout_failed", extra={"user_id": user_id})
```

### 5.2 Backend: Settings

**File: `app/core/settings.py`**

Add feature flag:
```python
presence_sse_enabled: bool = os.environ.get("PRESENCE_SSE_ENABLED", "1") not in ("0", "false", "False")
```

### 5.3 Frontend: `useMessagingStream.ts`

**File: `frontend/src/hooks/useMessagingStream.ts`**

**Change 1**: Add `"presence:update"` to `EVENT_TYPES` array (after line 129):

```typescript
const EVENT_TYPES = [
  // ... existing 30 event types ...
  "presence:update",     // MSG-004: Real-time presence push
];
```

**Change 2**: Add presence handler in `handleEvent` function (before the conversation invalidation block, around line 30):

```typescript
function handleEvent(event: MessageEvent) {
  try {
    const data = JSON.parse(event.data as string);
    const conversationId = typeof data.conversation_id === "string" ? data.conversation_id : undefined;
    const eventType: string = (event.type ?? "") || (typeof data.type === "string" ? data.type : "");

    // MSG-004: Handle presence updates (real-time push)
    if (eventType === "presence:update") {
      const presenceUserId = typeof data.user_id === "string" ? data.user_id : undefined;
      const isOnline = data.online === true;
      const lastSeenAt = typeof data.last_seen_at === "number" ? data.last_seen_at : 0;

      if (presenceUserId) {
        // Update single-user presence cache (used by usePresenceStatus)
        queryClient.setQueryData(
          ["presence", presenceUserId],
          [{ user_id: presenceUserId, online: isOnline, last_seen_at: lastSeenAt }],
        );

        // Update batch presence caches that include this user (used by useBatchPresence)
        queryClient.setQueriesData<Array<{ user_id: string; online: boolean; last_seen_at: number }>>(
          { queryKey: ["presence", "batch"] },
          (old) => {
            if (!old) return old;
            return old.map((entry) =>
              entry.user_id === presenceUserId
                ? { ...entry, online: isOnline, last_seen_at: lastSeenAt }
                : entry,
            );
          },
        );
      }
      return; // Don't invalidate conversations for presence events
    }

    // ... existing event handling continues unchanged ...
  }
}
```

**Key detail**: The `return` statement after the presence handler prevents presence events from triggering conversation list invalidation (which would cause unnecessary re-fetches of messages).

### 5.4 Frontend: `usePresence.ts`

**File: `frontend/src/hooks/usePresence.ts`**

**Change 1**: Reduce polling interval to 60 seconds (SSE is now the primary update mechanism):

```typescript
const PRESENCE_POLL_MS = 60_000; // Fallback; primary updates via SSE (MSG-004)
```

**Change 2**: Add client-side TTL check in `usePresenceStatus`:

```typescript
const ONLINE_WINDOW_SEC = 120; // Must match backend PRESENCE_TTL_SEC

export function usePresenceStatus(userId: string | undefined) {
  const { data } = useQuery({
    queryKey: ["presence", userId],
    queryFn: () => getPresence([userId!]),
    enabled: !!userId,
    refetchInterval: PRESENCE_POLL_MS,
    staleTime: PRESENCE_POLL_MS,
  });

  const entry = data?.[0];
  const lastSeenAt = entry?.last_seen_at ?? 0;

  // Client-side offline detection: if last_seen_at is older than ONLINE_WINDOW, consider offline
  // Re-evaluates when lastSeenAt changes (via SSE cache update or poll)
  const now = Math.floor(Date.now() / 1000);
  const isOnline = entry?.online ?? false;
  const effectiveOnline = isOnline && lastSeenAt > 0 && (now - lastSeenAt) <= ONLINE_WINDOW_SEC;

  return {
    online: effectiveOnline,
    lastSeenAt,
  };
}
```

**Change 3**: Apply the same 60-second interval to `useBatchPresence`:

```typescript
export function useBatchPresence(userIds: string[]) {
  const key = userIds.slice().sort().join(",");
  const { data } = useQuery({
    queryKey: ["presence", "batch", key],
    queryFn: () => getPresence(userIds),
    enabled: userIds.length > 0,
    refetchInterval: PRESENCE_POLL_MS,  // Now 60_000 instead of 15_000
    staleTime: PRESENCE_POLL_MS,
  });
  // ... rest unchanged ...
}
```

### 5.5 PresenceDot: No Changes Required

`PresenceDot.tsx` uses `usePresenceStatus(userId)` which reads from the React Query cache. When `useMessagingStream` updates the cache via `setQueryData`, `PresenceDot` re-renders automatically. The component is entirely cache-driven and requires no modifications.

---

## 6. Data Model

### 6.1 Presence Table (Existing -- No Changes)

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `user_id` | S (PK) | User identifier | `bob@test.local` |
| `last_seen_at` | N | Unix timestamp of last heartbeat | `1748380800` |
| `device` | S | Device identifier | `web` |
| `status` | S | Presence status | `online` |
| `ttl` | N | DDB TTL epoch | `1748380920` |

### 6.2 Events Table (Existing -- New Event Type)

The `presence:update` events are written to `tbl_events` using the same schema as other SSE events:

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `user_id` | S (PK) | Recipient user ID | `alice@test.local` |
| `event_id` | S (SK) | Unique event ID | `evt_abc123` |
| `type` | S | Event type | `presence:update` |
| `created_at` | N | Unix timestamp | `1748380800` |
| `payload` | M | Event data | `{"user_id": "bob", "online": true, "last_seen_at": 1748380800}` |
| `ttl` | N | DDB TTL (5 min) | `1748381100` |

### 6.3 No New Tables or GSIs

This feature uses existing DynamoDB tables and does not require any schema changes, new tables, or new GSIs. The `presence:update` events are transient (5-minute TTL) and use the same event delivery infrastructure as messaging events.

---

## 7. Security & Privacy Considerations

### 7.1 Presence Scope

Presence events are fanned out only to users who share at least one active conversation with the subject. The `_fanout_presence_event` function queries `tbl_parts` to find conversation partners. This prevents arbitrary users from tracking each other's online status.

### 7.2 Rate Limiting

The `PRESENCE_EVENT_COOLDOWN` (60 seconds) prevents a user from flooding the SSE event stream by rapidly connecting/disconnecting. Each user generates at most 1 presence event per minute.

### 7.3 In-Memory Cache Considerations

The `_presence_event_cache` dictionary is in-memory and per-process. Since the backend runs with `--workers 1` in dev mode (required for moto S3), this is safe. In production with multiple workers, each worker would have its own cache, resulting in at most N presence events per cooldown period (where N = number of workers). This is acceptable.

### 7.4 Presence Opt-Out (Future)

Future enhancement: add a "Hide online status" user preference. When enabled:
- Skip the `_fanout_presence_event` call entirely.
- Return `online: false` in the `GET /presence` endpoint regardless of actual status.
- Update `PresenceDot` to show grey for opted-out users.

This is out of scope for MSG-004 but documented for forward compatibility.

---

## 8. Performance Considerations

### 8.1 Fan-Out Cost Per Heartbeat

Each heartbeat from a user who has active conversations triggers (when cooldown allows):

| Operation | DDB Reads | Notes |
|-----------|-----------|-------|
| Query `tbl_parts` for user's conversations | 1 query | `Limit=100`, single page |
| Query participants per conversation (up to 20) | 1 query each | `Limit=50`, via GSI1 |
| Write events to `tbl_events` | 1 batch write | One item per partner |

Total per emission: ~21 DDB reads + 1 batch write. With the 60-second cooldown, this happens at most once per minute per user.

For a user in 10 conversations with 50 unique partners: ~11 DDB queries + 1 batch write of 50 items = ~11 RCU + ~50 WCU burst every 60 seconds. Acceptable.

### 8.2 Frontend Request Reduction

| Metric | Before (15s poll) | After (60s fallback) | Reduction |
|--------|-------------------|----------------------|-----------|
| Presence polls/min per user pair | 4 | ~1 | 75% |
| Polls for 10 DM partners | ~40/min | ~10/min | 75% |
| Latency: online detection | 0-15s | <2s | 87%+ |
| Latency: offline detection | 0-15s + TTL | TTL + 60s | Slightly worse for rare offline case |

### 8.3 SSE Event Volume

Presence events are relatively rare (at most 1 per user per 60 seconds). For 1000 concurrent users, this generates ~1000 events/min across the system, each delivered to ~10 partners = ~10,000 SSE deliveries/min. This is well within the SSE infrastructure's capacity (the same system handles real-time message delivery).

### 8.4 Event TTL

Presence events use a 5-minute TTL (`ttl = ts + 300`). This is much shorter than message events (which may use 24-hour TTL) because presence data becomes stale quickly. Short TTL reduces DDB storage costs for presence events.

---

## 9. Testing Strategy

### 9.1 Unit Tests (pytest)

**File**: `tests/test_presence_realtime.py`

| # | Test Function | Assertion |
|---|--------------|-----------|
| 1 | `test_fanout_writes_events_to_partners` | `_fanout_presence_event` writes `presence:update` events to `tbl_events` for each partner |
| 2 | `test_cooldown_prevents_rapid_emission` | Second call within 60s returns early without writing events |
| 3 | `test_cooldown_allows_after_expiry` | Call after 60s cooldown writes events normally |
| 4 | `test_partners_correctly_identified` | Partner set excludes the user themselves and includes all conversation partners |
| 5 | `test_presence_events_have_correct_ttl` | Event `ttl` is `ts + 300` (5 minutes) |
| 6 | `test_users_without_conversations_no_events` | User with no conversations generates no events |
| 7 | `test_fan_out_capped_at_20_conversations` | User with 50 conversations only fans out to partners from first 20 |
| 8 | `test_event_payload_contains_required_fields` | Payload has `user_id`, `online`, `last_seen_at` |
| 9 | `test_feature_flag_disables_fanout` | When `PRESENCE_SSE_ENABLED=false`, `_fanout_presence_event` is a no-op |
| 10 | `test_heartbeat_calls_fanout_on_first_beat` | First heartbeat triggers `_fanout_presence_event` |

### 9.2 E2E Tests

**Test File:** `frontend/e2e/presence-realtime.spec.ts`

**Section 1: SSE Presence Updates (4 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 1.1 | Bob goes online -- Alice sees green dot within 5s | Alice's PresenceDot `aria-label` changes to "Online" within 5 seconds of Bob's heartbeat |
| 1.2 | Bob's heartbeat refreshes last_seen_at | `last_seen_at` in Alice's presence cache increases after Bob's second heartbeat |
| 1.3 | Presence event contains correct user_id and online status | Intercept SSE event; verify `data.user_id` and `data.online` match expected values |
| 1.4 | Batch presence cache updated by SSE event | `useBatchPresence` result map reflects SSE-driven update for Bob |

**Section 2: Fallback Behavior (2 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 2.1 | Presence works via 60-second poll fallback | Directly update DDB presence; Alice's poll picks up new status within 65s |
| 2.2 | Multiple PresenceDots in conversation list all update | All DM partner dots in ConversationList reflect correct status |

**Section 3: Edge Cases (2 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 3.1 | No presence event for user with no shared conversations | Create user with no DMs; heartbeat generates no SSE events |
| 3.2 | Presence poll interval is 60 seconds (not 15) | Monitor network requests; confirm poll interval is ~60s |

### 9.3 Edge Cases to Verify

- User with 0 conversations (no fan-out, no error).
- User with 100+ conversations (only first 20 processed).
- Rapid heartbeats (cooldown prevents excess events).
- SSE disconnect and reconnect (fallback poll bridges the gap).
- Two users going online simultaneously (no race condition in event writes).
- User in both DM and group conversations (de-duplicated partner set).

---

## 10. Migration & Rollback

### 10.1 Feature Flag

**Env var**: `PRESENCE_SSE_ENABLED` (default `true`)

When `false`:
- `_fanout_presence_event` returns immediately without querying or writing.
- Frontend continues to poll at the new 60-second interval (a standalone improvement).
- PresenceDots still work via polling.

### 10.2 Rollout Steps

1. Add `PRESENCE_SSE_ENABLED=true` to `.env.local`.
2. Deploy backend changes to `messaging.py` and `settings.py`.
3. Deploy frontend changes to `useMessagingStream.ts` and `usePresence.ts`.
4. Verify SSE events are emitted by checking DDB `tbl_events` after a heartbeat.
5. Verify frontend PresenceDots update via SSE using browser DevTools (SSE tab).

### 10.3 Rollback

**Backend**: Set `PRESENCE_SSE_ENABLED=false`. The fan-out becomes a no-op. No event writes.
**Frontend**: Revert `useMessagingStream.ts` (remove presence handler) and `usePresence.ts` (revert to 15s interval). These are two small, isolated changes.

---

## 11. Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `tests/test_presence_realtime.py` | Unit tests for presence SSE emission logic | ~150 |
| `frontend/e2e/presence-realtime.spec.ts` | E2E tests for real-time presence | ~200 |

## 12. Files to Modify

| File | Change | Lines Changed |
|------|--------|---------------|
| `app/routers/messaging.py` | Add `_should_emit_presence_event()`, `_fanout_presence_event()`, call from `presence_heartbeat()` | +60 lines |
| `app/core/settings.py` | Add `presence_sse_enabled` setting | +1 line |
| `frontend/src/hooks/useMessagingStream.ts` | Add `"presence:update"` to EVENT_TYPES; add handler to update presence query caches | +25 lines |
| `frontend/src/hooks/usePresence.ts` | Change `PRESENCE_POLL_MS` from 15000 to 60000; add client-side TTL check | +10 lines |

---

## 13. Dependencies

- **Messaging SSE infrastructure**: `tbl_events`, SSE stream endpoint (`/messaging/events/stream`) -- must be deployed and functional. Already in production.
- **MSG-003 (Typing Real-time)**: Not a hard dependency, but shares the same SSE handler pattern in `useMessagingStream.ts`. Implementing together ensures consistency.
- **Conversation participants table** (`tbl_parts`): Must have the `GSI1` index for querying participants by conversation ID. Already exists.

---

## 14. Acceptance Criteria

1. When a user comes online (sends first heartbeat), their conversation partners see the green dot within 5 seconds.
2. Backend emits `presence:update` SSE events on heartbeat with 60-second cooldown (at most 1 event per user per minute).
3. `useMessagingStream.ts` handles `presence:update` events and updates the React Query presence cache via `setQueryData`.
4. `PresenceDot` components re-render instantly when the cache is updated (no additional polling needed for the SSE-triggered update).
5. Polling interval is reduced from 15 seconds to 60 seconds as a fallback.
6. Presence events are only fanned out to users who share an active conversation with the subject.
7. No new DynamoDB tables or GSIs are required.
8. Setting `PRESENCE_SSE_ENABLED=false` disables SSE emission without affecting polling.
9. All 8 E2E tests pass.
10. All 10 unit tests pass.

---

## 15. Open Questions

1. **Offline notification**: Should the backend actively emit `presence:update` with `online: false` when a user's TTL expires? This would require a background sweep task. Current design uses client-side TTL computation to avoid this complexity. If user feedback indicates offline detection is too slow (120-180 seconds), add a 30-second sweep as a follow-up.
2. **Group conversation optimization**: For large group conversations (50+ members), presence fan-out could be expensive. Should we skip presence fan-out for groups and only emit for DMs? Recommendation: v1 caps at 20 conversations per fan-out, which naturally limits group fan-out.
3. **Multi-device presence**: If a user is online on both web and mobile, both devices send heartbeats. The cooldown prevents duplicate events, but the `last_seen_at` may oscillate between devices. This is acceptable for v1.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Heartbeat stores in tbl_presence with TTL | `app/routers/messaging.py` | 11402-11409 | VERIFIED |
| PRESENCE_TTL_SEC = 120 | `app/routers/messaging.py` | 210 | VERIFIED |
| DDB_PRESENCE = "UserPresence" | `app/routers/messaging.py` | 172 | VERIFIED |
| tbl_presence table handle | `app/routers/messaging.py` | 230 | VERIFIED |
| Heartbeat does NOT emit SSE event | `app/routers/messaging.py` | 11654-11676, 11688 | OUTDATED: `presence:update` SSE emission IS IMPLEMENTED at line 11654 (`_fan_presence_to_partners`) which emits `presence:update` event (line 11676). The heartbeat handler at line 11688 calls this fan-out function. |
| No `presence:update` event type in codebase | `app/routers/messaging.py` | 11676 | INCORRECT: `"type": "presence:update"` EXISTS at line 11676 |
| GET /presence batch lookup | `app/routers/messaging.py` | 11433-11454 | VERIFIED |
| HEARTBEAT_INTERVAL_MS = 30_000 | `frontend/src/hooks/usePresence.ts` | 5 | VERIFIED |
| PRESENCE_POLL_MS = 15_000 | `frontend/src/hooks/usePresence.ts` | 6 | VERIFIED |
| usePresenceStatus polls every 15s | `frontend/src/hooks/usePresence.ts` | 33-47 | VERIFIED |
| useBatchPresence polls every 15s | `frontend/src/hooks/usePresence.ts` | 53-71 | VERIFIED |
| useHeartbeat sends every 30s | `frontend/src/hooks/usePresence.ts` | 12-27 | VERIFIED |
| PresenceDot uses usePresenceStatus | `frontend/src/pages/messages/PresenceDot.tsx` | 14 | VERIFIED |
| ConversationList renders PresenceDot per DM | `frontend/src/pages/messages/ConversationList.tsx` | 173 | VERIFIED |
| useMessagingStream EVENT_TYPES has no presence | `frontend/src/hooks/useMessagingStream.ts` | 161 | INCORRECT: `presence:update` IS in EVENT_TYPES at line 161. Handler at lines 89-109 writes directly to React Query cache via `queryClient.setQueryData` and `queryClient.setQueriesData` |
| fanout_event_to_conversation writes to tbl_events | `app/routers/messaging.py` | 5244-5278 | VERIFIED |
| _ddb_safe helper exists for event payloads | `app/routers/messaging.py` | various | VERIFIED |
| _event_id helper generates unique event IDs | `app/routers/messaging.py` | various | VERIFIED |

<!-- CRITICAL NOTE: This ticket's core proposal (SSE-based presence push) has been FULLY IMPLEMENTED:
- Backend: messaging.py line 11654 _fan_presence_to_partners() emits presence:update SSE events
- Backend: messaging.py line 11688 presence_heartbeat() calls the fan-out function
- Frontend: useMessagingStream.ts lines 89-109 handle presence:update, writing to React Query cache
- Frontend: useMessagingStream.ts line 161 includes presence:update in EVENT_TYPES
- PresenceDot.tsx already uses usePresenceStatus which benefits from SSE cache updates
The ticket should be marked as Complete. -->

---

## Testing Strategy

### Unit Tests (`tests/test_presence_sse.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_heartbeat_emits_sse_event` | Heartbeat emits sse event |
| 2 | `test_presence_expiry_emits_offline` | Presence expiry emits offline |
| 3 | `test_cooldown_prevents_flood` | Cooldown prevents flood |
| 4 | `test_sse_event_payload_format` | Sse event payload format |
| 5 | `test_batch_presence_query_fallback` | Batch presence query fallback |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/presence-realtime.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~10 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

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
**Independent -- backend emits new SSE event type; frontend handles it. Polling demoted to fallback. Additive changes only.**

### Merge Checklist
- [ ] Service file created/modified: `app/routers/messaging.py (extended)`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/presence-realtime.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_presence_sse.py`
