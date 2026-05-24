# BCAST-005: Live Chat Overlay for Broadcast Viewers

## 1. Overview & Motivation

### Problem Statement

Live broadcasts lack real-time viewer interaction. The platform has a fully functional
broadcast infrastructure (sessions, profiles, start/stop/playback via
`app/routers/broadcast.py`) and a mature messaging system with SSE delivery
(`app/routers/messaging.py`), but no mechanism for viewers to participate in a broadcast
via chat. Viewer engagement is a critical differentiator for live content -- without it,
broadcasts feel like passive one-way streams rather than interactive events.

The existing messaging system (`/messaging/*` endpoints) is designed for private
conversations between known participants with full CRUD, encryption, threading, and
compliance tooling. A broadcast chat has fundamentally different requirements:
many-to-many ephemeral messages, high write throughput, fan-out to potentially thousands
of concurrent viewers, and broadcaster-controlled moderation. Bolting this onto the
existing conversation model would create unacceptable complexity and performance concerns
(DynamoDB hot partitions, SSE connection per-user, conversation participant limits).

### User Stories

1. **As a viewer**, I want to see a live chat alongside the broadcast player so I can
   follow other viewers' reactions in real time.
2. **As a viewer**, I want to send a chat message during a live broadcast so I can
   participate in the community discussion.
3. **As a viewer**, I want chat messages to appear as a scrolling overlay on the player
   (optional) so I can watch and read simultaneously without looking away.
4. **As a broadcaster**, I want to delete inappropriate chat messages so I can keep the
   conversation on-topic and safe.
5. **As a broadcaster**, I want to temporarily mute a viewer so repeat offenders cannot
   spam the chat.
6. **As a broadcaster**, I want to see the last 100 messages on page load so the chat
   feels active even for late joiners.
7. **As an admin**, I want to disable chat for a specific session if it becomes
   unmanageable.

### Key Requirements (from ticket)

- Messages appear for all viewers within 2 seconds of send
- Rate limiting: 1 message per 2 seconds per user
- Broadcaster can moderate (delete messages)
- Chat history loads on page entry (last 100 messages)
- Backend: `POST /broadcast/sessions/{id}/chat` + `GET /broadcast/sessions/{id}/chat/stream` (SSE)
- DynamoDB table for broadcast chat messages (PK: session_id, SK: timestamp#msg_id)
- Frontend: chat panel in `LivePlayer.tsx` with message list + input
- Overlay rendering on the video player

---

## 2. Current State Analysis

### 2.1 Broadcast Infrastructure

**Backend services** (`app/services/broadcast_*.py`):
- `broadcast_store.py`: CRUD for sessions and profiles via DynamoDB (`BroadcastSessions`,
  `BroadcastProfiles` tables). Sessions have a `status` field with values: `draft`,
  `provisioning`, `ready`, `live`, `stopping`, `stopped`, `error`.
- `broadcast_provider.py`: Provider protocol with `LocalBroadcastProvider` (instant
  transitions) and `AwsBroadcastProvider` (MediaLive/MediaPackage).
- `broadcast_orchestrator.py`: Coordinates state machine transitions with the provider.
- `broadcast_state_machine.py`: Validates legal status transitions.
- `broadcast_audit.py`: Records actions to `BroadcastActionAudit` table.

**Router** (`app/routers/broadcast.py`, 355 lines):
- All endpoints under `/broadcast/*` prefix
- Auth via `require_ui_session` dependency (returns `ctx` with `user_sub`, `role`)
- Admin/root gating via `_require_operator_role(ctx)` for start/stop/delete
- Correlation ID tracking via `x-correlation-id` header
- No existing chat or SSE endpoints

**DynamoDB tables** (from `scripts/local-ddb-init.py`):
- `BroadcastSessions`: PK=`session_id`, GSIs: `ByStatusCreatedAt`, `ByCreatorCreatedAt`
- `BroadcastOutputs`: PK=`session_id`, SK=`scope`
- `BroadcastActionAudit`: PK=`audit_id`, GSIs: `ByActorCreatedAt`, `ByCreatedAt`

**Settings** (`app/core/settings.py`): `broadcast_provider`, `broadcast_devtools_enabled`,
various `broadcast_local_*` fields. No chat-specific settings exist yet.

### 2.2 Messaging SSE Delivery Pattern

The existing real-time messaging delivery (`app/routers/messaging.py` lines 11036-11070)
uses a **polling-based SSE pattern**:

```python
@router.get("/events/stream")
async def events_stream(after, limit, poll_ms, request, user_id):
    async def gen():
        cursor = after
        while True:
            raw_events = await anyio.to_thread.run_sync(_ddb_fetch_events, user_id, cursor, limit)
            if events:
                for ev in events:
                    cursor = ev["event_id"]
                    yield _sse_pack(ev, event=ev.get("type", "message"))
                continue
            await asyncio.sleep(poll_ms / 1000.0)
    return StreamingResponse(gen(), media_type="text/event-stream")
```

Key characteristics:
- **Per-user event table**: `UserEvents` table with PK=`user_id`, SK=`event_id`
- **Fan-out at write time**: `fanout_event_to_conversation()` (line 5127) writes an
  event row for each participant in a conversation via `batch_writer`
- **Poll interval**: Default 1000ms, configurable up to 5000ms
- **SSE format**: `_sse_pack()` emits `event: <type>\ndata: <json>\n\n`
- **Heartbeat**: Sends `: ping\n\n` comment every 15 seconds to keep connection alive

**Frontend SSE consumer** (`frontend/src/hooks/useMessagingStream.ts`):
- Uses native `EventSource` with named event listeners
- Exponential backoff reconnect (up to 30s)
- Invalidates React Query caches on receipt of events
- Handles 20+ event types (`message:new`, `message:revoked`, `poll:vote`, etc.)

### 2.3 Why the Messaging SSE Pattern Does Not Scale for Broadcast Chat

The messaging system fans out events by writing one DDB row per recipient. For a broadcast
with 1000 concurrent viewers, each chat message would require 1000 DDB writes -- this is
both expensive and slow (batch_writer handles 25 items per batch = 40 batches per message).

Additionally, the `UserEvents` table design is per-user, meaning each viewer's SSE stream
independently polls their own partition. This is fine for private messaging (low
write frequency per user) but wasteful for broadcast chat where all viewers receive the
same messages.

### 2.4 Rate Limiting Patterns

The codebase has two rate-limit patterns:

1. **In-memory sliding window** (`_MASS_MESSAGE_USER_CREATE_TS` / `_MASS_MESSAGE_TENANT_CREATE_TS`
   in `messaging.py` line 308): Uses `collections.deque` protected by `threading.Lock`.
   Trims entries older than the window, checks length against limit, appends current
   timestamp on success.

2. **DDB-backed rate limit** (`_enforce_lottery_unlock_rate_limit` at line 2888): Similar
   sliding window but stores timestamps in a dict keyed by compound key. Uses
   `threading.Lock` for thread safety.

For broadcast chat, the in-memory approach is preferable (single-process dev mode,
no persistence needed for rate limits that reset on restart).

### 2.5 Moderation Patterns

- **Message revocation** (`revoke_message_for_all`, line 9320): Sets `revoked_at` + `revoked_by`
  on the message item. Checks sender ownership or admin role.
- **Content reports** (`app/services/content_reports_store.py`): Transaction-based report
  creation with topic validation. Reports link to content via `content_type` + `content_id`.
- **Conversation muting** (`muted_until` field on participants): Time-based mute.

---

## 3. Technical Design

### 3.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Viewer Browser                                                  │
│  ┌──────────────────┐  ┌──────────────────────────────────────┐ │
│  │ LivePlayer.tsx    │  │ BroadcastChat.tsx                    │ │
│  │ (video + overlay)│  │ (message list + input)               │ │
│  │                  │  │                                      │ │
│  │  ┌────────────┐  │  │  ┌─────────┐  ┌──────────────────┐  │ │
│  │  │ChatOverlay │  │  │  │Messages │  │ ComposeInput     │  │ │
│  │  │(scrolling) │  │  │  │(scroll) │  │ (rate-limited)   │  │ │
│  │  └────────────┘  │  │  └─────────┘  └──────────────────┘  │ │
│  └──────────────────┘  └──────────────────────────────────────┘ │
│              ▲ EventSource SSE                                    │
└──────────────┼──────────────────────────────────────────────────┘
               │
┌──────────────┼──────────────────────────────────────────────────┐
│  Backend     │                                                   │
│  ┌───────────▼───────────────────────────────────────────────┐  │
│  │ GET /broadcast/sessions/{id}/chat/stream (SSE)            │  │
│  │   - Polls BroadcastChat DDB table (session_id partition)  │  │
│  │   - Returns chat:message / chat:delete / chat:mute events │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ POST /broadcast/sessions/{id}/chat                        │  │
│  │   - Rate limit check (1 msg / 2s per user)               │  │
│  │   - Session must be status="live"                         │  │
│  │   - Write to BroadcastChat table                          │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ DELETE /broadcast/sessions/{id}/chat/{msg_id}             │  │
│  │   - Broadcaster/admin only                                │  │
│  │   - Marks message as deleted in DDB                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ POST /broadcast/sessions/{id}/chat/mute                   │  │
│  │   - Broadcaster/admin only                                │  │
│  │   - Sets mute_until for target user on session            │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Chat Message Model

```python
# app/models_broadcast.py (additions)

class BroadcastChatMessageModel:
    """DynamoDB item for a broadcast chat message."""
    session_id: str          # PK
    sort_key: str            # SK = "{timestamp_ms}#{msg_id}" (lexicographic order = chronological)
    message_id: str          # UUID hex (e.g., "cm_" + uuid4().hex)
    sender_id: str           # user_sub of the sender
    sender_display_name: str # display name at time of send (denormalized)
    text: str                # plain text, max 280 chars
    created_at: int          # Unix timestamp (seconds)
    deleted: bool            # soft-delete flag (default False)
    deleted_by: str | None   # who deleted it (broadcaster/admin sub)
```

**Pydantic request/response models** (in `app/routers/broadcast.py`):

```python
class BroadcastChatSendIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=280)

class BroadcastChatMessageOut(BaseModel):
    message_id: str
    session_id: str
    sender_id: str
    sender_display_name: str
    text: str
    created_at: int
    deleted: bool = False

class BroadcastChatMuteIn(BaseModel):
    target_user_id: str = Field(..., min_length=1)
    duration_seconds: int = Field(default=300, ge=30, le=86400)  # 30s to 24h

class BroadcastChatMuteOut(BaseModel):
    target_user_id: str
    muted_until: int
    session_id: str
```

### 3.3 DynamoDB Schema

**Table: `BroadcastChatMessages`**

| Attribute | Type | Role |
|-----------|------|------|
| `session_id` | S | Partition Key |
| `sort_key` | S | Sort Key (`{ts_ms_zero_padded}#{msg_id}`) |
| `message_id` | S | Unique message identifier |
| `sender_id` | S | User sub |
| `sender_display_name` | S | Denormalized display name |
| `text` | S | Message text (max 280 chars) |
| `created_at` | N | Unix timestamp (seconds) |
| `deleted` | BOOL | Soft-delete flag |
| `deleted_by` | S | Who deleted (null if not deleted) |
| `ttl` | N | DynamoDB TTL (24 hours after broadcast ends) |

**Sort key format**: Zero-padded millisecond timestamp + `#` + message ID ensures
lexicographic ordering equals chronological ordering. Example:
`0001716580123456#cm_abc123def456`.

**TTL strategy**: When a broadcast stops, a cleanup task sets TTL on all chat messages
to `stopped_at + 86400` (24 hours after end). This provides a grace period for VOD
replay chat but avoids permanent storage costs.

**Table: `BroadcastChatMutes`**

| Attribute | Type | Role |
|-----------|------|------|
| `session_user` | S | PK = `{session_id}#{user_id}` |
| `muted_until` | N | Unix timestamp when mute expires |
| `muted_by` | S | Actor who issued the mute |
| `created_at` | N | When the mute was issued |

Single-item table for O(1) mute lookups during message send.

**DynamoDB table definition** (to add to `scripts/local-ddb-init.py`):

```python
TableDef(
    _resolve_table_name(S.broadcast_chat_messages_table_name, "BroadcastChatMessages"),
    "session_id",
    "sort_key",
    attr_types={"created_at": "N"},
),
TableDef(
    _resolve_table_name(S.broadcast_chat_mutes_table_name, "BroadcastChatMutes"),
    "session_user",
),
```

### 3.4 SSE Fan-out Design (Session-Level Polling)

Unlike the messaging system's per-user fan-out (write one event row per recipient), the
broadcast chat uses **session-level polling**: all viewers' SSE connections poll the same
DynamoDB partition (`session_id`). This is feasible because:

1. **All viewers see the same messages** -- no per-user filtering needed.
2. **Single partition read scales well** for read-heavy workloads (DynamoDB eventually
   consistent reads scale to 3000+ RCU per partition).
3. **No write amplification** -- one DDB write per message, regardless of viewer count.

```python
@router.get("/sessions/{session_id}/chat/stream")
async def broadcast_chat_stream(
    session_id: str,
    after: Optional[str] = None,
    poll_ms: Annotated[int, Query(ge=200, le=3000)] = 500,
    ctx: dict = Depends(_ctx),
):
    """SSE stream for broadcast chat. All viewers share the same partition read."""
    session = get_session(session_id)
    if session.status not in ("live", "ready"):
        raise HTTPException(403, "Chat is only available for live broadcasts")

    async def gen():
        cursor = after
        last_ping = time.time()
        yield ": stream-open\n\n"

        while True:
            now = time.time()
            if now - last_ping > 15:
                yield ": ping\n\n"
                last_ping = now

            messages = await anyio.to_thread.run_sync(
                _fetch_chat_messages, session_id, cursor, 50
            )
            if messages:
                for msg in messages:
                    cursor = msg["sort_key"]
                    if msg.get("deleted"):
                        yield _sse_pack({"message_id": msg["message_id"]}, event="chat:delete")
                    else:
                        yield _sse_pack(_chat_msg_out(msg), event="chat:message")
                continue

            await asyncio.sleep(poll_ms / 1000.0)

    return StreamingResponse(gen(), media_type="text/event-stream")
```

**Poll interval**: Default 500ms (faster than messaging's 1000ms default) to meet the
"within 2 seconds" delivery requirement. With 500ms polling, worst-case latency is
~500ms (message written just before next poll).

### 3.5 Rate Limiting

In-memory sliding window, same pattern as mass messaging rate limits:

```python
_CHAT_RATE_LOCK = threading.Lock()
_CHAT_RATE_BUCKETS: dict[str, int] = {}  # key: "{session_id}#{user_id}" -> last_send_ts_ms

CHAT_RATE_LIMIT_MS = 2000  # 1 message per 2 seconds

def _enforce_chat_rate_limit(session_id: str, user_id: str) -> None:
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    with _CHAT_RATE_LOCK:
        last = _CHAT_RATE_BUCKETS.get(key, 0)
        if now_ms - last < CHAT_RATE_LIMIT_MS:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "BROADCAST_CHAT_RATE_LIMITED",
                    "message": "You can send one message every 2 seconds.",
                    "retry_after_ms": CHAT_RATE_LIMIT_MS - (now_ms - last),
                },
            )
        _CHAT_RATE_BUCKETS[key] = now_ms
```

### 3.6 Moderation Actions

**Delete message** -- broadcaster or admin can remove any message:

```python
@router.delete("/sessions/{session_id}/chat/{message_id}")
def delete_chat_message(session_id: str, message_id: str, ctx: dict = Depends(_ctx)):
    session = get_session(session_id)
    # Allow: session creator OR admin/root
    if ctx["user_sub"] != session.created_by:
        _require_operator_role(ctx)

    # Find and soft-delete the message
    # Query by session_id with a filter on message_id (since sort_key includes timestamp)
    tbl_chat.update_item(
        Key={"session_id": session_id, "sort_key": _find_sort_key(session_id, message_id)},
        UpdateExpression="SET deleted = :t, deleted_by = :u",
        ExpressionAttributeValues={":t": True, ":u": ctx["user_sub"]},
    )
    return {"ok": True, "message_id": message_id}
```

**Mute viewer** -- broadcaster or admin can temporarily silence a user:

```python
@router.post("/sessions/{session_id}/chat/mute", response_model=BroadcastChatMuteOut)
def mute_chat_user(session_id: str, body: BroadcastChatMuteIn, ctx: dict = Depends(_ctx)):
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        _require_operator_role(ctx)

    muted_until = now_ts() + body.duration_seconds
    tbl_chat_mutes.put_item(Item={
        "session_user": f"{session_id}#{body.target_user_id}",
        "muted_until": muted_until,
        "muted_by": ctx["user_sub"],
        "created_at": now_ts(),
    })
    return BroadcastChatMuteOut(
        target_user_id=body.target_user_id,
        muted_until=muted_until,
        session_id=session_id,
    )
```

**Mute enforcement at send time**:

```python
def _enforce_chat_mute(session_id: str, user_id: str) -> None:
    key = f"{session_id}#{user_id}"
    resp = tbl_chat_mutes.get_item(Key={"session_user": key})
    item = resp.get("Item")
    if item:
        muted_until = int(item.get("muted_until", 0) or 0)
        if muted_until > now_ts():
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "BROADCAST_CHAT_MUTED",
                    "message": "You are temporarily muted in this chat.",
                    "muted_until": muted_until,
                },
            )
```

### 3.7 Chat Send Endpoint

```python
@router.post("/sessions/{session_id}/chat", response_model=BroadcastChatMessageOut,
             status_code=status.HTTP_201_CREATED)
def send_chat_message(session_id: str, body: BroadcastChatSendIn, ctx: dict = Depends(_ctx)):
    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(403, "Chat is only available while the broadcast is live")

    user_id = ctx["user_sub"]
    _enforce_chat_mute(session_id, user_id)
    _enforce_chat_rate_limit(session_id, user_id)

    # Resolve sender display name
    display_name = _resolve_display_name(user_id)

    ts = now_ts()
    ts_ms = int(time.time() * 1000)
    msg_id = "cm_" + uuid4().hex
    sort_key = f"{ts_ms:016d}#{msg_id}"

    item = {
        "session_id": session_id,
        "sort_key": sort_key,
        "message_id": msg_id,
        "sender_id": user_id,
        "sender_display_name": display_name,
        "text": body.text.strip(),
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 24 * 3600,  # 7 day default TTL
    }
    tbl_chat.put_item(Item=item)

    return BroadcastChatMessageOut(
        message_id=msg_id,
        session_id=session_id,
        sender_id=user_id,
        sender_display_name=display_name,
        text=body.text.strip(),
        created_at=ts,
        deleted=False,
    )
```

### 3.8 Chat History Endpoint

```python
@router.get("/sessions/{session_id}/chat", response_model=BroadcastChatHistoryOut)
def get_chat_history(
    session_id: str,
    limit: int = Query(default=100, ge=1, le=200),
    before: Optional[str] = Query(default=None),
    ctx: dict = Depends(_ctx),
):
    """Load recent chat history. Returns messages in chronological order (oldest first)."""
    session = get_session(session_id)

    kwargs = {
        "KeyConditionExpression": Key("session_id").eq(session_id),
        "Limit": limit,
        "ScanIndexForward": False,  # newest first for fetch
        "FilterExpression": Attr("deleted").ne(True),
    }
    if before:
        kwargs["KeyConditionExpression"] &= Key("sort_key").lt(before)

    resp = tbl_chat.query(**kwargs)
    items = resp.get("Items", [])
    # Reverse to chronological order for display
    items.reverse()

    messages = [_chat_msg_out(item) for item in items]
    return BroadcastChatHistoryOut(
        messages=messages,
        has_more=bool(resp.get("LastEvaluatedKey")),
        oldest_sort_key=items[0]["sort_key"] if items else None,
    )
```

### 3.9 Frontend: BroadcastChat Component

```typescript
// frontend/src/pages/broadcast/BroadcastChat.tsx

interface BroadcastChatProps {
  sessionId: string;
  isBroadcaster: boolean;  // enables moderation controls
}

export function BroadcastChat({ sessionId, isBroadcaster }: BroadcastChatProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputText, setInputText] = useState("");
  const [cooldown, setCooldown] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Load initial history
  useEffect(() => {
    fetch(`/broadcast/sessions/${sessionId}/chat?limit=100`)
      .then(r => r.json())
      .then(data => setMessages(data.messages));
  }, [sessionId]);

  // SSE connection for real-time updates
  useEffect(() => {
    const lastSortKey = messages[messages.length - 1]?.sort_key;
    const url = `/broadcast/sessions/${sessionId}/chat/stream${
      lastSortKey ? `?after=${encodeURIComponent(lastSortKey)}` : ""
    }`;
    const es = new EventSource(url, { withCredentials: true });

    es.addEventListener("chat:message", (event) => {
      const msg = JSON.parse(event.data);
      setMessages(prev => [...prev, msg].slice(-500)); // keep last 500 in memory
    });

    es.addEventListener("chat:delete", (event) => {
      const { message_id } = JSON.parse(event.data);
      setMessages(prev => prev.filter(m => m.message_id !== message_id));
    });

    es.onerror = () => { /* exponential backoff reconnect */ };
    eventSourceRef.current = es;

    return () => es.close();
  }, [sessionId]);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = async () => {
    if (!inputText.trim() || cooldown) return;
    setCooldown(true);
    setTimeout(() => setCooldown(false), 2000);

    await fetch(`/broadcast/sessions/${sessionId}/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-csrf-token": getCsrfToken() },
      body: JSON.stringify({ text: inputText.trim() }),
    });
    setInputText("");
  };

  return (
    <div className="flex flex-col h-full border-l">
      <div className="flex-1 overflow-y-auto p-2 space-y-1">
        {messages.map(msg => (
          <ChatMessageRow
            key={msg.message_id}
            message={msg}
            isBroadcaster={isBroadcaster}
            onDelete={handleDelete}
            onMute={handleMute}
          />
        ))}
        <div ref={messagesEndRef} />
      </div>
      <div className="border-t p-2 flex gap-2">
        <Input
          value={inputText}
          onChange={e => setInputText(e.target.value)}
          onKeyDown={e => e.key === "Enter" && handleSend()}
          placeholder="Send a message..."
          maxLength={280}
          disabled={cooldown}
        />
        <Button onClick={handleSend} disabled={cooldown || !inputText.trim()}>
          Send
        </Button>
      </div>
    </div>
  );
}
```

### 3.10 Frontend: Chat Overlay on Video Player

The overlay renders chat messages floating over the video, similar to Twitch's
transparent overlay or NicoNico-style scrolling comments.

```typescript
// frontend/src/pages/broadcast/ChatOverlay.tsx

interface ChatOverlayProps {
  messages: ChatMessage[];
  enabled: boolean;
}

export function ChatOverlay({ messages, enabled }: ChatOverlayProps) {
  const [overlayMessages, setOverlayMessages] = useState<OverlayMessage[]>([]);

  useEffect(() => {
    if (!enabled) return;
    // When a new message arrives, add it to the overlay queue with an animation ID
    const latest = messages[messages.length - 1];
    if (!latest) return;
    setOverlayMessages(prev => [
      ...prev.slice(-20),  // keep max 20 on screen
      { ...latest, animationId: `overlay-${latest.message_id}`, enteredAt: Date.now() },
    ]);
  }, [messages, enabled]);

  // Remove messages after 8 seconds (animation duration)
  useEffect(() => {
    const timer = setInterval(() => {
      setOverlayMessages(prev =>
        prev.filter(m => Date.now() - m.enteredAt < 8000)
      );
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  if (!enabled) return null;

  return (
    <div className="absolute inset-0 pointer-events-none overflow-hidden">
      {overlayMessages.map((msg, idx) => (
        <div
          key={msg.animationId}
          className="absolute text-white text-sm font-medium drop-shadow-lg animate-scroll-left whitespace-nowrap"
          style={{
            top: `${(idx % 8) * 12 + 5}%`,
            animationDelay: `${(idx % 3) * 200}ms`,
          }}
        >
          <span className="text-blue-300 mr-1">{msg.sender_display_name}:</span>
          {msg.text}
        </div>
      ))}
    </div>
  );
}
```

**CSS animation** (in `frontend/src/index.css` or Tailwind config):

```css
@keyframes scroll-left {
  from { transform: translateX(100%); }
  to { transform: translateX(-100%); }
}
.animate-scroll-left {
  animation: scroll-left 8s linear forwards;
}
```

### 3.11 Frontend: useBroadcastChatStream Hook

```typescript
// frontend/src/hooks/useBroadcastChatStream.ts

export function useBroadcastChatStream(sessionId: string, enabled = true) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!enabled || !sessionId) return;

    let es: EventSource | null = null;
    let retryCount = 0;

    function connect(afterCursor?: string) {
      const params = new URLSearchParams();
      if (afterCursor) params.set("after", afterCursor);
      params.set("poll_ms", "500");

      es = new EventSource(
        `/broadcast/sessions/${sessionId}/chat/stream?${params}`,
        { withCredentials: true }
      );

      es.onopen = () => { setConnected(true); retryCount = 0; };

      es.addEventListener("chat:message", (event) => {
        const msg: ChatMessage = JSON.parse(event.data);
        setMessages(prev => [...prev, msg].slice(-500));
      });

      es.addEventListener("chat:delete", (event) => {
        const { message_id } = JSON.parse(event.data);
        setMessages(prev => prev.filter(m => m.message_id !== message_id));
      });

      es.addEventListener("chat:mute", (event) => {
        // Could show a UI notification to the muted user
      });

      es.onerror = () => {
        es?.close();
        setConnected(false);
        const delay = Math.min(1000 * 2 ** retryCount, 15000);
        retryCount++;
        setTimeout(() => connect(), delay);
      };
    }

    connect();
    return () => { es?.close(); };
  }, [sessionId, enabled]);

  return { messages, connected };
}
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/broadcast_chat_store.py` | DynamoDB CRUD for chat messages + mutes |
| `frontend/src/pages/broadcast/BroadcastChat.tsx` | Chat panel component (sidebar) |
| `frontend/src/pages/broadcast/ChatOverlay.tsx` | Scrolling overlay on player |
| `frontend/src/pages/broadcast/ChatMessageRow.tsx` | Single chat message with mod actions |
| `frontend/src/hooks/useBroadcastChatStream.ts` | SSE hook for real-time chat events |
| `frontend/src/api/endpoints/broadcast-chat.ts` | API endpoint wrappers |
| `frontend/e2e/broadcast-chat.spec.ts` | E2E test suite |
| `tests/test_broadcast_chat_store.py` | Unit tests for chat store |

### 4.2 Files to Modify

| File | Change |
|------|--------|
| `app/routers/broadcast.py` | Add chat send, stream, history, delete, mute endpoints |
| `app/core/settings.py` | Add `broadcast_chat_messages_table_name`, `broadcast_chat_mutes_table_name`, `broadcast_chat_rate_limit_ms`, `broadcast_chat_max_message_length` |
| `app/core/tables.py` | Add `broadcast_chat_messages` and `broadcast_chat_mutes` table handles |
| `scripts/local-ddb-init.py` | Add `BroadcastChatMessages` and `BroadcastChatMutes` table definitions |
| `frontend/vite.config.ts` | Ensure `/broadcast` proxy exists (may already be there from BCAST-001) |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Integrate `BroadcastChat` panel + `ChatOverlay` |
| `frontend/src/index.css` | Add `@keyframes scroll-left` animation |

### 4.3 Implementation Order

**Phase 1: Backend Store Layer (1.5 hours)**

1. Add settings to `app/core/settings.py`:
   ```python
   broadcast_chat_messages_table_name: str = os.environ.get("DDB_BROADCAST_CHAT_MESSAGES", "BroadcastChatMessages")
   broadcast_chat_mutes_table_name: str = os.environ.get("DDB_BROADCAST_CHAT_MUTES", "BroadcastChatMutes")
   broadcast_chat_rate_limit_ms: int = int(os.environ.get("BROADCAST_CHAT_RATE_LIMIT_MS", "2000"))
   broadcast_chat_max_message_length: int = int(os.environ.get("BROADCAST_CHAT_MAX_MESSAGE_LENGTH", "280"))
   ```

2. Add table handles to `app/core/tables.py`:
   ```python
   broadcast_chat_messages=ddb.Table(S.broadcast_chat_messages_table_name),
   broadcast_chat_mutes=ddb.Table(S.broadcast_chat_mutes_table_name),
   ```

3. Add table definitions to `scripts/local-ddb-init.py`.

4. Create `app/services/broadcast_chat_store.py`:
   - `send_chat_message(session_id, user_id, display_name, text) -> dict`
   - `get_chat_history(session_id, limit, before_sort_key) -> dict`
   - `fetch_chat_messages_after(session_id, after_sort_key, limit) -> list[dict]`
   - `delete_chat_message(session_id, message_id) -> bool`
   - `get_mute_status(session_id, user_id) -> int | None` (returns muted_until or None)
   - `set_mute(session_id, user_id, duration_seconds, actor) -> dict`

5. Write unit tests in `tests/test_broadcast_chat_store.py`.

**Phase 2: Backend Endpoints (2 hours)**

1. Add Pydantic models to `app/routers/broadcast.py`:
   - `BroadcastChatSendIn`, `BroadcastChatMessageOut`, `BroadcastChatHistoryOut`
   - `BroadcastChatMuteIn`, `BroadcastChatMuteOut`

2. Add endpoints:
   - `POST /broadcast/sessions/{session_id}/chat` -- send message
   - `GET /broadcast/sessions/{session_id}/chat` -- load history
   - `GET /broadcast/sessions/{session_id}/chat/stream` -- SSE stream
   - `DELETE /broadcast/sessions/{session_id}/chat/{message_id}` -- delete message
   - `POST /broadcast/sessions/{session_id}/chat/mute` -- mute user

3. Rate limiting: in-memory sliding window with `threading.Lock`.

4. Mute enforcement: check `BroadcastChatMutes` table before accepting message.

5. SSE stream: follow existing pattern from `events_stream` (line 11036) -- poll DDB,
   yield events, send heartbeat pings.

**Phase 3: Frontend API Layer (30 min)**

1. Create `frontend/src/api/endpoints/broadcast-chat.ts`:
   - `sendChatMessage(sessionId, text)`
   - `getChatHistory(sessionId, limit?, before?)`
   - `deleteChatMessage(sessionId, messageId)`
   - `muteChatUser(sessionId, targetUserId, durationSeconds)`

2. Create `frontend/src/hooks/useBroadcastChatStream.ts`.

**Phase 4: Frontend Chat Panel (2 hours)**

1. Create `BroadcastChat.tsx`:
   - Message list with auto-scroll
   - Text input with 280 char limit
   - Send button with 2s cooldown indicator
   - Initial history load (last 100 messages)
   - SSE integration via `useBroadcastChatStream`

2. Create `ChatMessageRow.tsx`:
   - Display: avatar/initials, display name, text, timestamp
   - Moderation controls (visible to broadcaster): delete button, mute button
   - Deleted messages show "[Message removed]" or are hidden entirely

3. Integrate into `LivePlayer.tsx`:
   - Resizable sidebar panel (collapsible)
   - Toggle button to show/hide chat
   - Pass `isBroadcaster` prop based on session `created_by` matching current user

**Phase 5: Chat Overlay (1.5 hours)**

1. Create `ChatOverlay.tsx`:
   - Absolutely positioned over video player
   - Messages scroll from right to left over 8 seconds
   - Stagger vertical positions to avoid overlap (modulo 8 rows)
   - Maximum 20 concurrent overlay messages
   - Auto-cleanup after animation duration

2. Add CSS animation to `frontend/src/index.css`.

3. Add toggle button in `LivePlayer.tsx` to enable/disable overlay.

**Phase 6: Polish + Error Handling (1 hour)**

1. Handle SSE disconnection gracefully (show "Reconnecting..." badge).
2. Show rate-limit feedback in UI (disable input for remaining cooldown, show timer).
3. Handle mute response (show "You are muted for X minutes" banner).
4. Handle session not live (show "Chat is unavailable" state).
5. Responsive layout: chat panel below player on mobile, beside player on desktop.

### 4.4 Dependencies

- **BCAST-002** (Live Player page): The chat panel integrates into `LivePlayer.tsx`. If
  this page does not yet exist, create a minimal stub that the chat panel attaches to.
- **Session auth**: Uses existing `require_ui_session` -- no new auth work needed.
- **Display name resolution**: Needs access to users table to resolve `sender_display_name`.
  Use existing `get_profile_identity` from `app/services/profile.py`.

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_chat_store.py`)

Using `moto` for DynamoDB mocking (same pattern as other service tests in `tests/`):

```python
import pytest
from moto import mock_dynamodb
from app.services.broadcast_chat_store import (
    send_chat_message,
    get_chat_history,
    fetch_chat_messages_after,
    delete_chat_message,
    get_mute_status,
    set_mute,
)

@mock_dynamodb
class TestBroadcastChatStore:
    def setup_method(self):
        # Create BroadcastChatMessages and BroadcastChatMutes tables
        ...

    def test_send_message_creates_item(self):
        result = send_chat_message("sess1", "user1", "Alice", "Hello chat!")
        assert result["message_id"].startswith("cm_")
        assert result["text"] == "Hello chat!"

    def test_get_history_returns_chronological_order(self):
        for i in range(5):
            send_chat_message("sess1", "user1", "Alice", f"msg {i}")
        history = get_chat_history("sess1", limit=5)
        texts = [m["text"] for m in history["messages"]]
        assert texts == ["msg 0", "msg 1", "msg 2", "msg 3", "msg 4"]

    def test_get_history_respects_limit(self):
        for i in range(10):
            send_chat_message("sess1", "user1", "Alice", f"msg {i}")
        history = get_chat_history("sess1", limit=3)
        assert len(history["messages"]) == 3
        assert history["has_more"] is True

    def test_delete_message_soft_deletes(self):
        msg = send_chat_message("sess1", "user1", "Alice", "bad message")
        delete_chat_message("sess1", msg["message_id"])
        # Deleted messages excluded from history
        history = get_chat_history("sess1", limit=100)
        assert all(m["message_id"] != msg["message_id"] for m in history["messages"])

    def test_fetch_after_cursor(self):
        msgs = [send_chat_message("sess1", "user1", "Alice", f"m{i}") for i in range(5)]
        cursor = msgs[2]["sort_key"]
        after = fetch_chat_messages_after("sess1", cursor, 50)
        assert len(after) == 2  # msgs[3] and msgs[4]

    def test_mute_status_none_when_not_muted(self):
        assert get_mute_status("sess1", "user1") is None

    def test_mute_status_returns_expiry(self):
        set_mute("sess1", "user1", 300, "broadcaster1")
        status = get_mute_status("sess1", "user1")
        assert status is not None
        assert status > int(time.time())

    def test_mute_expired_returns_none(self):
        # Manually set muted_until to past
        ...
        assert get_mute_status("sess1", "user1") is None
```

### 5.2 Backend Integration Tests (pytest, FastAPI TestClient)

```python
class TestBroadcastChatEndpoints:
    def test_send_requires_live_session(self, client, auth_headers):
        # Session in draft status -> 403
        resp = client.post(f"/broadcast/sessions/{draft_session_id}/chat",
                          json={"text": "hello"}, headers=auth_headers)
        assert resp.status_code == 403

    def test_send_message_success(self, client, auth_headers, live_session_id):
        resp = client.post(f"/broadcast/sessions/{live_session_id}/chat",
                          json={"text": "Great stream!"}, headers=auth_headers)
        assert resp.status_code == 201
        assert resp.json()["text"] == "Great stream!"

    def test_rate_limit_blocks_fast_sends(self, client, auth_headers, live_session_id):
        client.post(f"/broadcast/sessions/{live_session_id}/chat",
                   json={"text": "msg1"}, headers=auth_headers)
        resp = client.post(f"/broadcast/sessions/{live_session_id}/chat",
                          json={"text": "msg2"}, headers=auth_headers)
        assert resp.status_code == 429
        assert "BROADCAST_CHAT_RATE_LIMITED" in resp.json()["detail"]["code"]

    def test_muted_user_cannot_send(self, client, broadcaster_headers, viewer_headers, live_session_id):
        # Broadcaster mutes viewer
        client.post(f"/broadcast/sessions/{live_session_id}/chat/mute",
                   json={"target_user_id": "viewer1", "duration_seconds": 60},
                   headers=broadcaster_headers)
        # Viewer tries to send
        resp = client.post(f"/broadcast/sessions/{live_session_id}/chat",
                          json={"text": "hello"}, headers=viewer_headers)
        assert resp.status_code == 403
        assert "BROADCAST_CHAT_MUTED" in resp.json()["detail"]["code"]

    def test_delete_message_requires_broadcaster_or_admin(self, client, viewer_headers, live_session_id):
        msg = client.post(f"/broadcast/sessions/{live_session_id}/chat",
                         json={"text": "hi"}, headers=viewer_headers).json()
        # Viewer cannot delete others' messages (but this is their own -- still blocked
        # because delete is broadcaster-only)
        # Actually: viewer deleting their own is allowed? Design decision: no,
        # only broadcaster/admin can delete to keep moderation centralized.
        resp = client.delete(
            f"/broadcast/sessions/{live_session_id}/chat/{msg['message_id']}",
            headers=viewer_headers)
        assert resp.status_code == 403

    def test_history_returns_last_100(self, client, auth_headers, live_session_id):
        # Send 5 messages (limited for test speed)
        for i in range(5):
            time.sleep(0.01)  # ensure distinct timestamps
            client.post(f"/broadcast/sessions/{live_session_id}/chat",
                       json={"text": f"msg {i}"}, headers=auth_headers)
        resp = client.get(f"/broadcast/sessions/{live_session_id}/chat?limit=100",
                         headers=auth_headers)
        assert resp.status_code == 200
        assert len(resp.json()["messages"]) == 5
```

### 5.3 E2E Tests (`frontend/e2e/broadcast-chat.spec.ts`)

Following the established E2E pattern (`e2e_admin_session_setup.py` identities, cookie
injection, CSRF headers):

**Section 90: Chat Send API (6 tests)**
- Sends a chat message to a live session
- Verifies 403 when session is not live (draft/stopped)
- Verifies 429 rate limit on rapid sends (send twice within 2s)
- Verifies message text max length (281 chars rejected)
- Verifies empty text rejected
- Verifies sender_display_name populated from profile

**Section 91: Chat History API (4 tests)**
- Loads last N messages in chronological order
- Respects `limit` parameter (request 3, get 3 even if more exist)
- Supports `before` cursor for pagination
- Excludes deleted messages from history

**Section 92: Chat Moderation API (5 tests)**
- Broadcaster can delete any message
- Admin/root can delete any message
- Regular viewer cannot delete messages (403)
- Broadcaster can mute a viewer
- Muted viewer receives 403 with `BROADCAST_CHAT_MUTED` code

**Section 93: Chat SSE Stream (4 tests)**
- Opens SSE stream and receives new messages in real time
- Receives `chat:delete` event when message is deleted
- Stream returns 403 for non-live sessions
- Stream reconnects after disconnect (verify second message received)

**Section 94: Chat UI (6 tests)**
- Chat panel visible on live player page
- Message input sends and appears in chat list
- Send button disabled during 2s cooldown
- Character counter shows remaining chars (280 max)
- Broadcaster sees delete button on messages
- Regular viewer does not see delete button

**Section 95: Chat Overlay (3 tests)**
- Overlay toggle button works (show/hide)
- New messages appear in overlay area with scrolling animation
- Overlay messages disappear after animation duration

### 5.4 Concurrent Viewer Simulation

To validate the "within 2 seconds" delivery requirement under load, add a focused
load test that can be run manually:

```typescript
// frontend/e2e/broadcast-chat-load.spec.ts (manual, not in CI)

test.describe("Broadcast Chat Load", () => {
  test("messages delivered to 10 concurrent viewers within 2s", async ({ browser }) => {
    // Create 10 viewer pages, each with SSE connection
    const viewers: Page[] = [];
    for (let i = 0; i < 10; i++) {
      const ctx = await browser.newContext();
      const page = await ctx.newPage();
      await injectAuth(page, "alice");
      await page.goto(`/live/${liveSessionId}`);
      viewers.push(page);
    }

    // Wait for all SSE connections to open
    await Promise.all(viewers.map(v =>
      v.waitForFunction(() => (window as any).__chatConnected === true)
    ));

    // Send a message from the broadcaster
    const sendTime = Date.now();
    await apiPost(broadcasterPage, "root", `/broadcast/sessions/${liveSessionId}/chat`, {
      text: `Load test ${sendTime}`,
    });

    // Verify all viewers received the message within 2 seconds
    await Promise.all(viewers.map(v =>
      expect(v.getByText(`Load test ${sendTime}`)).toBeVisible({ timeout: 2000 })
    ));

    // Cleanup
    for (const v of viewers) await v.close();
  });
});
```

### 5.5 Test Data Isolation

- Each test run uses a unique broadcast session (created in `beforeAll`).
- Chat messages are isolated to that session (PK = session_id).
- No cross-run pollution since each session ID is a fresh UUID.
- `afterAll` deletes the test session, which (via TTL) will eventually clean up chat
  messages -- but since each run uses unique session IDs, stale data does not affect tests.

### 5.6 Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| Rate limit state from previous test | Each test section uses a unique session; rate limit key includes session_id |
| SSE connection race | Wait for `": stream-open"` comment in SSE before sending test messages |
| Timing-sensitive rate limit test | Use `time.sleep(2.1)` between sends to clear the window, verify second send succeeds |
| Mute expiry during test | Use long duration (300s) in mute tests -- test will finish well before expiry |
| DDB eventual consistency | Use `ConsistentRead=True` in store functions; SSE polling inherently handles eventual consistency by retrying |
| Display name resolution | Seed a profile record for test users in `beforeAll` or tolerate fallback name |

---

## Appendix A: API Reference Summary

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/broadcast/sessions/{id}/chat` | `require_ui_session` | Send chat message |
| GET | `/broadcast/sessions/{id}/chat` | `require_ui_session` | Load chat history |
| GET | `/broadcast/sessions/{id}/chat/stream` | `require_ui_session` | SSE real-time stream |
| DELETE | `/broadcast/sessions/{id}/chat/{msg_id}` | broadcaster/admin | Delete chat message |
| POST | `/broadcast/sessions/{id}/chat/mute` | broadcaster/admin | Mute a viewer |

## Appendix B: SSE Event Types

| Event | Payload | Trigger |
|-------|---------|---------|
| `chat:message` | Full `BroadcastChatMessageOut` JSON | New message sent |
| `chat:delete` | `{ "message_id": "..." }` | Message deleted by moderator |
| `chat:mute` | `{ "target_user_id": "...", "muted_until": N }` | User muted (sent only to the muted user's stream -- requires future per-user filtering or client-side check) |

## Appendix C: Configuration

| Setting | Default | Purpose |
|---------|---------|---------|
| `DDB_BROADCAST_CHAT_MESSAGES` | `BroadcastChatMessages` | Table name |
| `DDB_BROADCAST_CHAT_MUTES` | `BroadcastChatMutes` | Table name |
| `BROADCAST_CHAT_RATE_LIMIT_MS` | `2000` | Min ms between messages per user per session |
| `BROADCAST_CHAT_MAX_MESSAGE_LENGTH` | `280` | Max characters per chat message |
| `BROADCAST_CHAT_HISTORY_DEFAULT_LIMIT` | `100` | Default messages loaded on page entry |
| `BROADCAST_CHAT_OVERLAY_ENABLED` | `true` | Feature flag for overlay rendering |

## Appendix D: Existing File Reference

| File | Relevance |
|------|-----------|
| `app/routers/broadcast.py` | Broadcast router -- add chat endpoints here |
| `app/services/broadcast_store.py` | DDB patterns for broadcast entities |
| `app/services/broadcast_provider.py` | Session model + provider protocol |
| `app/core/settings.py` | Settings dataclass -- add chat config |
| `app/core/tables.py` | Table handles -- add chat tables |
| `scripts/local-ddb-init.py` | Table creation -- add chat table defs |
| `app/routers/messaging.py:5127` | `fanout_event_to_conversation()` -- fan-out pattern reference |
| `app/routers/messaging.py:11036` | `events_stream()` -- SSE streaming pattern reference |
| `app/routers/messaging.py:283` | `_trim_mass_message_rate_window()` -- rate limit pattern |
| `app/routers/messaging.py:4728` | `_ensure_can_revoke_message()` -- moderation pattern |
| `frontend/src/hooks/useMessagingStream.ts` | SSE EventSource hook pattern |
| `frontend/src/pages/messages/ConversationView.tsx` | Message list rendering + auto-scroll |
| `app/services/profile.py` | `get_profile_identity()` for display name resolution |
| `e2e_admin_session_setup.py` | Test session seeding for E2E |
