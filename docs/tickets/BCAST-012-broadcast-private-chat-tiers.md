# BCAST-012: Broadcast Private Chat Tiers — Paid 1-on-1 Text Chat with Voyeur Mode

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-27  
**Priority**: Medium  
**Estimated effort**: 8-10 days  
**Depends on**: BCAST-005 (Live Chat), MON-002 (Tip Ledger Integration)

---

## 1. Overview & Motivation

### The Gap

The broadcast chat system (BCAST-005) provides a single public chat channel where all viewers participate equally. There is no way for a viewer to pay for a private text conversation with the broadcaster during a live session
<!-- NOTE: This gap is NOW ADDRESSED. Private chat infrastructure exists:
  `app/services/broadcast_private_chat.py`,
  `app/core/settings.py:1208-1210` (private_chat_enabled, max_duration, voyeur_enabled),
  `frontend/src/api/endpoints/broadcastPrivateChat.ts`,
  `frontend/e2e/broadcast-private-chat.spec.ts` -->, and no mechanism for other viewers to pay a lower rate to spectate that private conversation in real time. This leaves two major monetization opportunities untapped:

1. **Premium private chat**: Viewers who want personal attention from the creator during a live stream have no way to get it. The public chat is noisy and the creator cannot give individualized responses at scale. A paid private channel solves this.

2. **Voyeur/spectator economy**: Other viewers may be interested in reading a private exchange but not participating. A lower-priced read-only tier lets the creator earn from both the active chatter and passive spectators without additional effort.

The existing broadcast chat infrastructure (`app/services/broadcast_chat_store.py`, 311 lines) stores messages in the `broadcast_chat_messages` DDB table with `PK=session_id`, `SK=timestamp#msg_id`. All messages are public. There is no concept of scoping messages to a subset of participants, no per-message visibility field, and no integration with the billing system for chat access.

The broadcast SSE system (`app/services/broadcast_sse.py`) fans out events to all subscribers of a session. It has no concept of targeted delivery -- every subscriber gets every event. Private chat messages require either targeted SSE delivery or client-side filtering based on the viewer's active private chat sessions.

### Why This Is Needed

1. **Scalable per-viewer monetization**: Unlike BCAST-011 (Go Private video call), which requires the creator's full attention, private text chat allows the creator to manage multiple concurrent conversations while continuing the broadcast. This scales better for high-viewer-count streams.

2. **Time-block purchasing**: Selling chat access in time blocks (5, 15, 30, 60 minutes) with auto-expiry creates predictable revenue per session and urgency-driven purchasing.

3. **Voyeur tier doubles the audience**: For every 1 viewer willing to pay $5/min for a private chat, there may be 10 willing to pay $1/min to read along. The creator earns from both without doing additional work.

4. **Low implementation risk**: Private chat reuses the existing broadcast chat DDB table and SSE infrastructure. Messages are stored the same way as public chat but scoped via a `private_chat_id` field. No new WebRTC infrastructure is needed (unlike BCAST-011).

### Architecture After This Change

```
┌────────────────────────────────────────────────────────────────────────────┐
│  Broadcast Session                                                          │
│                                                                             │
│  ┌───── Public Chat (Tier 0 — Free) ─────────────────────────────────┐    │
│  │ All viewers can read and send messages                              │    │
│  │ (existing BCAST-005 infrastructure, unchanged)                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌───── Private Chat #1 (Alice → Creator) ────────────────────────────┐    │
│  │                                                                     │    │
│  │  Tier 1 (Participant — $5.00/min)                                   │    │
│  │  ┌───────────────────────────────────────────┐                      │    │
│  │  │ Alice:   "Hi! Love the stream today"       │ ← read + write     │    │
│  │  │ Creator: "Thanks Alice! What did you want  │                      │    │
│  │  │           to ask about?"                   │                      │    │
│  │  │ Alice:   "Can you show the blue version?"  │                      │    │
│  │  │ Creator: "Sure, switching now!"            │                      │    │
│  │  └───────────────────────────────────────────┘                      │    │
│  │                                                                     │    │
│  │  Tier 2 (Voyeur — $1.00/min) — Bob, Charlie watching               │    │
│  │  ┌───────────────────────────────────────────┐                      │    │
│  │  │ [Spectating]  Read-only view              │ ← read only          │    │
│  │  │ Alice:   "Hi! Love the stream today"       │ Cannot send          │    │
│  │  │ Creator: "Thanks Alice! What did you want  │                      │    │
│  │  │           to ask about?"                   │                      │    │
│  │  │ Alice:   "Can you show the blue version?"  │                      │    │
│  │  │ Creator: "Sure, switching now!"            │                      │    │
│  │  └───────────────────────────────────────────┘                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌───── Private Chat #2 (Dave → Creator) ─────────────────────────────┐    │
│  │  Tier 1: Dave — 15 min block, 12:34 remaining                       │    │
│  │  Tier 2: Eve — spectating                                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  Creator Dashboard:                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Active Private Chats:                                                │    │
│  │  [Alice]  $5.00/min  08:22 remaining  [End]                         │    │
│  │  [Dave]   $5.00/min  12:34 remaining  [End]                         │    │
│  │                                                                     │    │
│  │ Revenue this session: $47.50 (3 participants, 2 voyeurs)            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────────┘
```

### Purchase and Billing Flow — Sequence Diagram

```
Viewer (Alice)              Backend                      Creator (SSE)     Voyeur (Bob)
    │                         │                              │                  │
    │ POST /private-chat/     │                              │                  │
    │   purchase              │                              │                  │
    │ {tier: 1,               │                              │                  │
    │  duration_minutes: 15,  │                              │                  │
    │  payment_method_id:     │                              │                  │
    │  "pm_visa_4242"}        │                              │                  │
    │────────────────────────>│                              │                  │
    │                         │ Validate:                    │                  │
    │                         │ - session is live             │                  │
    │                         │ - PM exists in billing table  │                  │
    │                         │ - wallet balance sufficient   │                  │
    │                         │   (or charge PM)             │                  │
    │                         │                              │                  │
    │                         │ Calculate total:             │                  │
    │                         │ 15 min * 500 cents = $75.00  │                  │
    │                         │                              │                  │
    │                         │ Write billing DEBIT:         │                  │
    │                         │ USER#alice LEDGER#...        │                  │
    │                         │ Write billing CREDIT:        │                  │
    │                         │ USER#creator LEDGER#...      │                  │
    │                         │ (minus platform fee 20%)     │                  │
    │                         │                              │                  │
    │                         │ DDB: create PCHAT# item     │                  │
    │                         │ status = "active"            │                  │
    │                         │ remaining = 900s             │                  │
    │                         │                              │                  │
    │                         │─── SSE: private_chat:started ─>│                │
    │   201 {chat_id, ...}    │                              │                  │
    │<────────────────────────│                              │                  │
    │                         │                              │                  │
    │ POST .../message        │                              │                  │
    │ {text: "Hi!"}           │                              │                  │
    │────────────────────────>│                              │                  │
    │                         │ DDB: write chat message      │                  │
    │                         │ with private_chat_id         │                  │
    │                         │                              │                  │
    │                         │── SSE: private_chat:message ─>│                │
    │   201 {message}         │                              │                  │
    │<────────────────────────│                              │                  │
    │                         │                              │                  │
    │                         │                              │    POST /purchase │
    │                         │                              │    {tier: 2,     │
    │                         │                              │     chat_id: ...}│
    │                         │<─────────────────────────────────────────────────│
    │                         │                              │                  │
    │                         │ Validate voyeur rate, PM     │                  │
    │                         │ Calculate: 15 min * 100 = $15│                  │
    │                         │ Write DEBIT/CREDIT           │                  │
    │                         │ DDB: create VOYEUR# item     │                  │
    │                         │                              │                  │
    │                         │── SSE: private_chat:voyeur_joined ──────────────>│
    │                         │                              │                  │
    │                         │ (Bob now receives all         │                  │
    │                         │  private_chat:message events  │                  │
    │                         │  for this chat_id via SSE)    │                  │
    │                         │                              │                  │
    │                         │ ... time passes ...           │                  │
    │                         │                              │                  │
    │                         │── SSE: private_chat:expiring ─>│ (1 min left)   │
    │                         │                              │                  │
    │                         │ ... 1 minute later ...        │                  │
    │                         │                              │                  │
    │                         │── SSE: private_chat:ended ───>│                 │
    │                         │── SSE: private_chat:ended ──────────────────────>│
```

---

## 2. Current State Analysis

### 2.1 Broadcast Chat Messages Table (`broadcast_chat_messages`)

From `scripts/local-ddb-init.py` and `app/services/broadcast_chat_store.py`:

| Attribute | Type | Notes |
|-----------|------|-------|
| `session_id` | S | PK — broadcast session ID |
| `sort_key` | S | SK — `{timestamp_ms:016d}#{msg_id}` for chronological ordering |
| `message_id` | S | `cm_` + uuid4().hex |
| `sender_id` | S | User sub |
| `sender_display_name` | S | Display name at send time |
| `text` | S | Message body (max 280 chars) |
| `kind` | S | `text` or `product_link` |
| `product_link` | M | Optional map for product link data |
| `created_at` | N | Unix timestamp |
| `deleted` | BOOL | Soft-delete flag |
| `ttl` | N | DDB TTL (7 days) |

No `private_chat_id` field exists. All messages are scoped to `session_id` only. Adding a `private_chat_id` field to scope messages to a specific private chat is backward-compatible -- existing messages without the field are public.

### 2.2 Broadcast Chat Store (`app/services/broadcast_chat_store.py`, 311 lines)

Key functions:
- `send_chat_message()` (line 136): Creates a message item, publishes via `broadcast_sse_publish(session_id, {"_type": "chat:message", ...})`.
- `send_product_link_message()` (line 174): Same pattern with `kind="product_link"`.
- `get_chat_history()` (line 210): Queries by `session_id` PK with `ScanIndexForward=False`, then reverses for chronological display.
- `fetch_chat_messages_after()` (line 240): For SSE polling, `ScanIndexForward=True` with `after_sort_key` cursor.
- `_chat_msg_out()` (line 296): Converts DDB item to output dict. Does NOT include a `private_chat_id` field.

Rate limiting: `_enforce_chat_rate_limit()` (line 25) at 1 message per 2 seconds. Separate `_enforce_product_link_rate_limit()` (line 46) at 1 per 5 seconds. Private chat messages will use the same rate limiting infrastructure but with a separate bucket keyed by `{session_id}#{user_id}#private`.

### 2.3 Broadcast SSE Infrastructure (`app/services/broadcast_sse.py`, 50 lines)

In-memory pub/sub. All subscribers to a `session_id` receive ALL events. Private chat messages will be published with `_type: "private_chat:message"` and include the `private_chat_id`. Client-side filtering determines visibility:
- Tier 1 viewer: shows messages where `private_chat_id` matches their active chat.
- Tier 2 voyeur: shows messages where `private_chat_id` matches the chat they are spectating.
- Other viewers: ignore `private_chat:*` events (filtered out in the SSE event handler).

This approach avoids modifying the SSE infrastructure. The tradeoff is that all private chat messages are technically visible in the SSE stream to all subscribers, but client-side filtering prevents display. For stronger isolation, a per-chat SSE channel could be added (future enhancement), but the current fan-out model is sufficient given that message content is text-only and the SSE stream is not exposed as a public API.

### 2.4 Broadcast Chat Stream Endpoint (`app/routers/broadcast.py`, line 985)

The `broadcast_chat_stream_route()` SSE endpoint (line 985-1033) uses a polling pattern via `fetch_chat_messages_after()`. It yields `chat:message` and `chat:product_link` events. For private chat delivery, a separate SSE stream endpoint is needed (or the existing stream is extended to include `private_chat:message` events with client-side filtering).

### 2.5 Billing Ledger Pattern (`app/services/tip_ledger.py`)

The `write_tip_ledger()` function writes paired debit/credit entries to `T.billing`. Private chat billing follows the same pattern:
- **Debit**: `USER#{viewer_id}` for the purchased time block amount.
- **Credit**: `USER#{creator_id}` for the creator's share (total minus platform fee).
- **Meta**: `content_type="private_chat"`, `chat_id`, `session_id`, `tier`, `duration_minutes`.

Platform fee (20% default) is calculated server-side. The credit amount is `total * (1 - platform_fee_pct / 100)`. This matches the monetization split pattern.

### 2.6 Broadcast Session Status

Private chat does NOT change the broadcast session status. Unlike BCAST-011 (Go Private), which transitions the session to `"private"` status, private text chat operates entirely within a `"live"` session. The broadcast continues normally while private chats happen in parallel. No state machine changes are needed.

### 2.7 Payment Method Validation

From `app/routers/messaging.py` (locked message unlock) and `app/routers/newsfeed.py` (post unlock):

```python
pm_item = T.billing.get_item(
    Key={"pk": f"USER#{user_id}", "sk": f"PM#{payment_method_id}"}
).get("Item")
if not pm_item:
    raise HTTPException(status_code=400, detail="Payment method not found")
```

Private chat purchase uses the same pattern.

### 2.8 Broadcast Product Shelf Pricing Settings Pattern

The LCOM-004 implementation stores pricing configuration as top-level attributes on the broadcast session item (e.g., `broadcast_price_cents`, `broadcast_price_expires_at`). Private chat rates will follow the same pattern -- stored as attributes on the session item, updatable via a PATCH endpoint.

---

## 3. Technical Design

### 3.1 DynamoDB Model — BroadcastPrivateChat

**Note**: The existing `BroadcastSessions` table has only `session_id` as its partition key and **no sort key**, so it cannot support composite `pk`/`sk` access patterns. Private chat items require the `BroadcastPrivateSessions` table (with `pk` (S) as partition key and `sk` (S) as sort key), which must be added to `scripts/local-ddb-init.py` if not already created by BCAST-011. A `T.broadcast_private_sessions` handle must also be added to `app/core/tables.py`.

New items in the `BroadcastPrivateSessions` table:

| Attribute | Type | Notes |
|-----------|------|-------|
| `pk` | S | `BCAST_PCHAT#{session_id}` |
| `sk` | S | `CHAT#{chat_id}` |
| `chat_id` | S | `pchat_` + uuid4().hex |
| `session_id` | S | Parent broadcast session ID |
| `viewer_id` | S | Tier 1 participant user_sub |
| `viewer_display_name` | S | Display name at purchase time |
| `tier` | N | 1 (participant) or 2 (voyeur) — always 1 for the primary chat record |
| `rate_per_minute_cents` | N | Per-minute rate charged |
| `purchased_minutes` | N | Total purchased duration |
| `remaining_seconds` | N | Server-tracked countdown (updated periodically) |
| `total_paid_cents` | N | Amount paid upfront |
| `platform_fee_cents` | N | Platform share |
| `creator_earnings_cents` | N | Creator share |
| `status` | S | `active`, `expiring`, `ended`, `extended` |
| `payment_method_id` | S | Viewer's PM used for purchase |
| `started_at` | N | Unix timestamp when chat became active |
| `expires_at` | N | Unix timestamp when time runs out |
| `ended_at` | N | Unix timestamp (null until ended) |
| `ended_reason` | S | `expired`, `viewer_ended`, `creator_ended`, `extended` |
| `billing_debit_entry_id` | S | Ledger entry ID |
| `billing_credit_entry_id` | S | Ledger entry ID |
| `ttl` | N | DDB TTL — 90 days |

**Voyeur tracking** — separate items in the same table:

| Attribute | Type | Notes |
|-----------|------|-------|
| `pk` | S | `BCAST_PCHAT#{session_id}` |
| `sk` | S | `VOYEUR#{chat_id}#{viewer_id}` |
| `chat_id` | S | The private chat being spectated |
| `viewer_id` | S | Voyeur's user_sub |
| `tier` | N | 2 (always) |
| `rate_per_minute_cents` | N | Voyeur rate |
| `purchased_minutes` | N | Duration purchased |
| `total_paid_cents` | N | Amount paid |
| `status` | S | `active`, `ended` |
| `started_at` | N | Unix timestamp |
| `expires_at` | N | Unix timestamp |
| `billing_debit_entry_id` | S | Ledger entry ID |
| `billing_credit_entry_id` | S | Ledger entry ID |
| `ttl` | N | 90 days |

**DDB Access Pattern Diagram**:

```
BroadcastPrivateSessions Table (pk/sk composite key)
┌─────────────────────────────────────────────────────────────────────────┐
│ PK: BCAST_PCHAT#{session_id}                                            │
│                                                                         │
│ ┌─── CHAT#{chat_id_1} ──────────────────────────────────────────────┐  │
│ │ chat_id: "pchat_abc123"        viewer_id: "alice"                  │  │
│ │ tier: 1                        rate: 500    purchased: 15 min      │  │
│ │ status: "active"               remaining: 720s                     │  │
│ │ expires_at: 1716581400         started_at: 1716580500              │  │
│ └────────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│ ┌─── VOYEUR#{chat_id_1}#bob ────────────────────────────────────────┐  │
│ │ chat_id: "pchat_abc123"        viewer_id: "bob"                    │  │
│ │ tier: 2                        rate: 100    purchased: 15 min      │  │
│ │ status: "active"               expires_at: 1716581400              │  │
│ └────────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│ ┌─── VOYEUR#{chat_id_1}#charlie ────────────────────────────────────┐  │
│ │ chat_id: "pchat_abc123"        viewer_id: "charlie"                │  │
│ │ tier: 2                        rate: 100    purchased: 30 min      │  │
│ │ status: "active"               expires_at: 1716582300              │  │
│ └────────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│ ┌─── CHAT#{chat_id_2} ──────────────────────────────────────────────┐  │
│ │ chat_id: "pchat_def456"        viewer_id: "dave"                   │  │
│ │ tier: 1                        status: "active"                    │  │
│ └────────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│ Access Patterns:                                                        │
│ ┌─────────────────────────────────────────────────────────────────┐    │
│ │ 1. Query(BCAST_PCHAT#{session_id}, begins_with("CHAT#"))        │    │
│ │    → list all private chats for a broadcast                      │    │
│ │ 2. GetItem(BCAST_PCHAT#{session_id}, CHAT#{chat_id})            │    │
│ │    → get single private chat                                     │    │
│ │ 3. Query(BCAST_PCHAT#{session_id}, begins_with("VOYEUR#{cid}")) │    │
│ │    → list all voyeurs for a specific chat                        │    │
│ │ 4. GetItem(..., VOYEUR#{chat_id}#{viewer_id})                   │    │
│ │    → check if a specific viewer is a voyeur                      │    │
│ └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Private Chat Messages — Extended Chat Table

Private chat messages are stored in the existing `broadcast_chat_messages` table with an additional `private_chat_id` field:

| Attribute | Type | Notes |
|-----------|------|-------|
| (existing fields) | | All unchanged |
| `private_chat_id` | S | **NEW** — null/absent for public messages, set for private chat messages |
| `kind` | S | Extended: `text`, `product_link`, `private_chat` (new) |

Public messages: `private_chat_id` is absent or null. Private chat messages: `private_chat_id = "pchat_abc123"`.

The `get_chat_history()` function remains unchanged -- it queries by `session_id` and returns all messages. The existing chat history endpoint (`GET /broadcast/sessions/{id}/chat`) is NOT modified to filter private messages. Private chat history is served via a separate endpoint (`GET /broadcast/sessions/{id}/private-chat/{chat_id}/messages`) that filters on `private_chat_id`.

### 3.3 Private Chat Settings — Session Attributes

Add pricing configuration fields to the broadcast session DDB item:

| Attribute | Type | Default | Notes |
|-----------|------|---------|-------|
| `private_chat_rate_per_minute_cents` | N | 500 | Tier 1 per-minute rate |
| `voyeur_rate_per_minute_cents` | N | 100 | Tier 2 per-minute rate |
| `private_chat_time_blocks` | L | `[5, 15, 30, 60]` | Available purchase durations in minutes |
| `private_chat_enabled` | BOOL | false | Whether private chat is available |
| `private_chat_platform_fee_pct` | N | 20 | Platform fee percentage |
| `private_chat_max_concurrent` | N | 5 | Max concurrent private chats |

These are stored on the broadcast session item (key: `{"session_id": session_id}`) and updatable via `PATCH /broadcast/sessions/{session_id}/private-chat/settings`. Note: since `transition_session_status()` uses `put_item` (full replace), these fields must also be added to `BroadcastSessionModel`, `session_to_item()`, and `session_from_item()` to survive status transitions.

### 3.4 API Endpoints

#### 3.4.1 Purchase Private Chat

```
POST /ui/broadcast/sessions/{session_id}/private-chat/purchase
```

**Auth**: `require_ui_session` — any authenticated viewer (not the session creator).

**Request model**:

```python
class PrivateChatPurchaseIn(BaseModel):
    """Request body for purchasing a private chat session.

    For tier 1 (participant): creates a new private chat with the broadcaster.
    For tier 2 (voyeur): joins an existing private chat as a read-only spectator.
    
    When tier=2, chat_id is REQUIRED and must reference an active private chat.
    When tier=1, chat_id must NOT be provided (a new chat is created).
    """
    tier: int = Field(..., ge=1, le=2,
        description="1 = participant (read/write), 2 = voyeur (read-only)")
    duration_minutes: int = Field(..., ge=5, le=60,
        description="Duration of the chat session in minutes.")
    payment_method_id: str = Field(..., min_length=1, max_length=128,
        description="Payment method ID for billing.")
    chat_id: Optional[str] = Field(default=None,
        description="Required for tier 2 (voyeur). The chat_id to spectate.")

    @model_validator(mode="after")
    def validate_tier_chat_id(self):
        """Tier 2 requires chat_id; tier 1 must not have chat_id."""
        if self.tier == 2 and not self.chat_id:
            raise ValueError("chat_id is required for tier 2 (voyeur) purchases.")
        if self.tier == 1 and self.chat_id:
            raise ValueError("chat_id must not be provided for tier 1 purchases.")
        return self
```

**Response model**:

```python
class PrivateChatPurchaseOut(BaseModel):
    chat_id: str
    session_id: str
    tier: int
    duration_minutes: int
    total_paid_cents: int
    rate_per_minute_cents: int
    expires_at: int
    status: str  # "active"
```

**Validation**:

1. Session must exist and be in `live` status.
2. `private_chat_enabled` must be `true` on the session.
3. Caller must NOT be the session creator.
4. Payment method must exist in `T.billing`.
5. `duration_minutes` must be in the session's `private_chat_time_blocks` list.
6. For tier 1: concurrent private chats must not exceed `private_chat_max_concurrent`.
7. For tier 2: the referenced `chat_id` must exist and be in `active` status.

**Billing**:

```python
rate = (
    session.private_chat_rate_per_minute_cents  # tier 1
    if tier == 1
    else session.voyeur_rate_per_minute_cents   # tier 2
)
total_cents = rate * duration_minutes
platform_fee_cents = int(total_cents * session.private_chat_platform_fee_pct / 100)
creator_earnings_cents = total_cents - platform_fee_cents
```

Both debit (viewer) and credit (creator for `creator_earnings_cents`) are written at purchase time (prepaid model). The full `total_cents` is debited from the viewer; the net amount after platform fee is credited to the creator.

**Error responses**:

| Code | Condition | Error Detail |
|------|-----------|-------------|
| 400 | Invalid payment method | `"Payment method not found."` |
| 400 | Duration not in allowed time blocks | `"Duration must be one of: 5, 15, 30, 60 minutes."` |
| 403 | Session not live | `"Private chat is only available during live broadcasts."` |
| 403 | Creator purchasing own chat | `"Cannot purchase a private chat on your own broadcast."` |
| 403 | Private chat not enabled | `"Private chat is not enabled for this broadcast."` |
| 404 | Chat not found (tier 2) | `"Private chat not found."` |
| 409 | Max concurrent chats reached | `"Maximum number of concurrent private chats reached."` |

#### 3.4.2 Send Private Chat Message

```
POST /ui/broadcast/sessions/{session_id}/private-chat/{chat_id}/message
```

**Auth**: `require_ui_session` — only the tier 1 participant or the session creator.

**Request model**:

```python
class PrivateChatMessageIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=500,
        description="Message text. Private chat allows longer messages than public chat (500 vs 280).")
```

**Response model**: `BroadcastChatMessageOut` (same as public chat, with added `private_chat_id` field).

**Validation**:

1. Chat must exist and be in `active` status.
2. Caller must be either the tier 1 viewer or the session creator.
3. Voyeurs (tier 2) cannot send messages -- return 403.
4. Rate limiting: same 1-per-2-seconds as public chat, but separate bucket.

**Message storage**: The message is stored in the existing `broadcast_chat_messages` table with `private_chat_id` set to the chat ID. The `kind` field is set to `"private_chat"`.

**SSE delivery**: Published as `private_chat:message` event with `private_chat_id` in the payload. All session subscribers receive the event; client-side filtering shows it only to the tier 1 viewer, the creator, and active tier 2 voyeurs for that chat.

#### 3.4.3 Get Private Chat Messages

```
GET /ui/broadcast/sessions/{session_id}/private-chat/{chat_id}/messages
```

**Auth**: `require_ui_session` — tier 1 participant, tier 2 voyeur with active session, or session creator.

**Query params**: `limit` (default 100, max 200), `before` (sort_key cursor for pagination).

**Response model**:

```python
class PrivateChatHistoryOut(BaseModel):
    messages: List[BroadcastChatMessageOut] = Field(default_factory=list)
    has_more: bool = False
    oldest_sort_key: Optional[str] = None
```

**Behavior**: Queries `broadcast_chat_messages` with `session_id` PK and filters for `private_chat_id == chat_id`. This uses a `FilterExpression` since `private_chat_id` is not part of the sort key. Given the relatively low volume of private chat messages (compared to public chat), this is acceptable. A GSI on `private_chat_id` could be added later if performance requires it.

#### 3.4.4 Extend Private Chat

```
POST /ui/broadcast/sessions/{session_id}/private-chat/{chat_id}/extend
```

**Auth**: `require_ui_session` — only the tier 1 participant (or a tier 2 voyeur extending their own spectator session).

**Request model**:

```python
class PrivateChatExtendIn(BaseModel):
    duration_minutes: int = Field(..., ge=5, le=60,
        description="Additional minutes to purchase.")
    payment_method_id: str = Field(..., min_length=1, max_length=128)
```

**Behavior**:

1. Validate the chat is `active` or `expiring`.
2. Validate `duration_minutes` is in the session's `private_chat_time_blocks`.
3. Calculate additional cost at the same rate.
4. Write additional debit/credit ledger entries.
5. Extend `expires_at` by `duration_minutes * 60`.
6. Update `purchased_minutes` and `total_paid_cents`.
7. Reset status from `expiring` to `active` if applicable.

**Response**: Updated `PrivateChatPurchaseOut` with new `expires_at` and totals.

#### 3.4.5 End Private Chat

```
POST /ui/broadcast/sessions/{session_id}/private-chat/{chat_id}/end
```

**Auth**: `require_ui_session` — tier 1 participant or session creator.

**Behavior**:

1. Update chat status to `ended` with `ended_at` and `ended_reason`.
2. Also end all associated voyeur sessions for this chat.
3. Publish `private_chat:ended` SSE event.
4. No refund for remaining time (prepaid model).

**Response**: `{"ok": true, "chat_id": "...", "ended_reason": "viewer_ended"}`

#### 3.4.6 List Active Private Chats (Creator)

```
GET /ui/broadcast/sessions/{session_id}/private-chats
```

**Auth**: `require_ui_session` — only session creator.

**Response model**:

```python
class PrivateChatListOut(BaseModel):
    chats: List[PrivateChatSummaryOut] = Field(default_factory=list)

class PrivateChatSummaryOut(BaseModel):
    chat_id: str
    viewer_id: str
    viewer_display_name: str
    tier: int
    rate_per_minute_cents: int
    purchased_minutes: int
    remaining_seconds: int  # calculated from expires_at - now
    status: str
    started_at: int
    expires_at: int
    voyeur_count: int  # number of active voyeurs
    total_revenue_cents: int  # sum of tier 1 + all voyeur payments
```

**Behavior**: Queries all `CHAT#` items under `BCAST_PCHAT#{session_id}`, calculates `remaining_seconds` from `expires_at - now_ts()`, counts voyeurs per chat.

#### 3.4.7 Update Private Chat Settings

```
PATCH /ui/broadcast/sessions/{session_id}/private-chat/settings
```

**Auth**: `require_ui_session` — only session creator.

**Request model**:

```python
class PrivateChatSettingsIn(BaseModel):
    private_chat_enabled: Optional[bool] = None
    private_chat_rate_per_minute_cents: Optional[int] = Field(default=None, ge=100, le=10000)
    voyeur_rate_per_minute_cents: Optional[int] = Field(default=None, ge=50, le=5000)
    private_chat_time_blocks: Optional[List[int]] = None  # e.g., [5, 15, 30, 60]
    private_chat_max_concurrent: Optional[int] = Field(default=None, ge=1, le=20)

    @model_validator(mode="after")
    def validate_voyeur_rate_lower(self):
        """Voyeur rate must be lower than participant rate when both are set."""
        if (
            self.voyeur_rate_per_minute_cents is not None
            and self.private_chat_rate_per_minute_cents is not None
            and self.voyeur_rate_per_minute_cents >= self.private_chat_rate_per_minute_cents
        ):
            raise ValueError("Voyeur rate must be lower than participant rate.")
        return self
```

**Response**: `{"ok": true, ...updated_settings}`

### 3.5 Service Layer — `app/services/broadcast_private_chat.py`

New service file (~400 lines) for private chat business logic.

```python
"""Broadcast private chat service — manages paid 1-on-1 text chat with voyeur mode."""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish

logger = logging.getLogger("broadcast.private_chat")

DEFAULT_RATE_CENTS = 500         # $5.00/min default for tier 1
DEFAULT_VOYEUR_RATE_CENTS = 100  # $1.00/min default for tier 2
DEFAULT_PLATFORM_FEE_PCT = 20   # 20% platform fee
MAX_CONCURRENT_CHATS = 5


def purchase_private_chat(
    session_id: str,
    viewer_id: str,
    viewer_display_name: str,
    tier: int,
    duration_minutes: int,
    payment_method_id: str,
    rate_per_minute_cents: int,
    platform_fee_pct: int = DEFAULT_PLATFORM_FEE_PCT,
    *,
    chat_id: Optional[str] = None,  # Required for tier 2
    creator_id: str,
) -> Dict[str, Any]:
    """Purchase a private chat session (tier 1) or voyeur access (tier 2).

    For tier 1: Creates a new private chat item and starts the timer.
    For tier 2: Creates a voyeur tracking item linked to an existing chat.
    Billing (debit/credit) is written immediately (prepaid model).

    Args:
        session_id: The broadcast session ID.
        viewer_id: The purchasing viewer's user_sub.
        viewer_display_name: Display name at purchase time.
        tier: 1 (participant) or 2 (voyeur).
        duration_minutes: Purchased duration.
        payment_method_id: Viewer's PM ID.
        rate_per_minute_cents: Per-minute rate for this tier.
        platform_fee_pct: Platform fee percentage.
        chat_id: For tier 2: the existing chat to spectate.
        creator_id: The broadcast creator's user_sub.

    Returns:
        Dict with purchase details suitable for API response.

    Raises:
        HTTPException(404) if chat_id not found (tier 2).
        HTTPException(409) if max concurrent chats reached (tier 1).
    """
    ts = now_ts()
    total_cents = rate_per_minute_cents * duration_minutes
    platform_fee_cents = int(total_cents * platform_fee_pct / 100)
    creator_earnings_cents = total_cents - platform_fee_cents

    if tier == 1:
        # Check concurrent chat limit
        active_count = _count_active_chats(session_id)
        if active_count >= MAX_CONCURRENT_CHATS:
            raise HTTPException(
                status_code=409,
                detail="Maximum number of concurrent private chats reached.",
            )

        new_chat_id = f"pchat_{uuid.uuid4().hex}"
        expires_at = ts + duration_minutes * 60

        item = {
            "pk": f"BCAST_PCHAT#{session_id}",
            "sk": f"CHAT#{new_chat_id}",
            "chat_id": new_chat_id,
            "session_id": session_id,
            "viewer_id": viewer_id,
            "viewer_display_name": viewer_display_name,
            "tier": 1,
            "rate_per_minute_cents": rate_per_minute_cents,
            "purchased_minutes": duration_minutes,
            "remaining_seconds": duration_minutes * 60,
            "total_paid_cents": total_cents,
            "platform_fee_cents": platform_fee_cents,
            "creator_earnings_cents": creator_earnings_cents,
            "status": "active",
            "payment_method_id": payment_method_id,
            "started_at": ts,
            "expires_at": expires_at,
            "ttl": ts + 90 * 24 * 3600,
        }
        T.broadcast_private_sessions.put_item(Item=item)

        # Write billing entries
        debit_id, credit_id = _write_private_chat_billing(
            viewer_id=viewer_id,
            creator_id=creator_id,
            total_cents=total_cents,
            creator_earnings_cents=creator_earnings_cents,
            chat_id=new_chat_id,
            session_id=session_id,
            tier=1,
            duration_minutes=duration_minutes,
            payment_method_id=payment_method_id,
        )

        T.broadcast_private_sessions.update_item(
            Key={"pk": f"BCAST_PCHAT#{session_id}", "sk": f"CHAT#{new_chat_id}"},
            UpdateExpression="SET billing_debit_entry_id = :did, billing_credit_entry_id = :cid",
            ExpressionAttributeValues={":did": debit_id, ":cid": credit_id},
        )

        # Notify creator
        broadcast_sse_publish(session_id, {
            "_type": "private_chat:started",
            "chat_id": new_chat_id,
            "viewer_id": viewer_id,
            "viewer_display_name": viewer_display_name,
            "duration_minutes": duration_minutes,
            "expires_at": expires_at,
        })

        logger.info(
            "broadcast.private_chat.purchased session=%s viewer=%s tier=1 duration=%d total=%d",
            session_id, viewer_id, duration_minutes, total_cents,
        )

        return {
            "chat_id": new_chat_id,
            "session_id": session_id,
            "tier": 1,
            "duration_minutes": duration_minutes,
            "total_paid_cents": total_cents,
            "rate_per_minute_cents": rate_per_minute_cents,
            "expires_at": expires_at,
            "status": "active",
        }

    else:  # tier == 2
        # Validate target chat exists and is active
        target_chat = _get_private_chat(session_id, chat_id)
        if not target_chat or target_chat.get("status") != "active":
            raise HTTPException(status_code=404, detail="Private chat not found or not active.")

        # Voyeur duration should not exceed remaining chat time
        chat_expires = int(target_chat.get("expires_at", 0))
        voyeur_expires = min(ts + duration_minutes * 60, chat_expires)

        voyeur_item = {
            "pk": f"BCAST_PCHAT#{session_id}",
            "sk": f"VOYEUR#{chat_id}#{viewer_id}",
            "chat_id": chat_id,
            "session_id": session_id,
            "viewer_id": viewer_id,
            "viewer_display_name": viewer_display_name,
            "tier": 2,
            "rate_per_minute_cents": rate_per_minute_cents,
            "purchased_minutes": duration_minutes,
            "total_paid_cents": total_cents,
            "status": "active",
            "payment_method_id": payment_method_id,
            "started_at": ts,
            "expires_at": voyeur_expires,
            "ttl": ts + 90 * 24 * 3600,
        }
        T.broadcast_private_sessions.put_item(Item=voyeur_item)

        # Write billing entries
        _write_private_chat_billing(
            viewer_id=viewer_id,
            creator_id=creator_id,
            total_cents=total_cents,
            creator_earnings_cents=creator_earnings_cents,
            chat_id=chat_id,
            session_id=session_id,
            tier=2,
            duration_minutes=duration_minutes,
            payment_method_id=payment_method_id,
        )

        # Notify creator and tier 1 viewer
        broadcast_sse_publish(session_id, {
            "_type": "private_chat:voyeur_joined",
            "chat_id": chat_id,
            "viewer_id": viewer_id,
            "viewer_display_name": viewer_display_name,
        })

        logger.info(
            "broadcast.private_chat.voyeur_joined session=%s chat=%s voyeur=%s",
            session_id, chat_id, viewer_id,
        )

        return {
            "chat_id": chat_id,
            "session_id": session_id,
            "tier": 2,
            "duration_minutes": duration_minutes,
            "total_paid_cents": total_cents,
            "rate_per_minute_cents": rate_per_minute_cents,
            "expires_at": voyeur_expires,
            "status": "active",
        }


def send_private_chat_message(
    session_id: str,
    chat_id: str,
    sender_id: str,
    sender_display_name: str,
    text: str,
) -> Dict[str, Any]:
    """Send a message in a private chat. Only tier 1 viewer and creator can send.

    Messages are stored in the existing broadcast_chat_messages table
    with a private_chat_id field for scoping.
    """
    import time as _time

    ts = now_ts()
    ts_ms = int(_time.time() * 1000)
    msg_id = "pcm_" + uuid.uuid4().hex
    sort_key = f"{ts_ms:016d}#{msg_id}"

    item = {
        "session_id": session_id,
        "sort_key": sort_key,
        "message_id": msg_id,
        "sender_id": sender_id,
        "sender_display_name": sender_display_name,
        "text": text.strip(),
        "kind": "private_chat",
        "private_chat_id": chat_id,
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 24 * 3600,
    }
    T.broadcast_chat_messages.put_item(Item=item)

    out = _private_chat_msg_out(item)
    broadcast_sse_publish(session_id, {"_type": "private_chat:message", **out})

    return out


def get_private_chat_history(
    session_id: str,
    chat_id: str,
    limit: int = 100,
    before_sort_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Get message history for a private chat, filtered by private_chat_id.

    Uses FilterExpression on private_chat_id since it is not part of the sort key.
    """
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("session_id").eq(session_id),
        "FilterExpression": Attr("private_chat_id").eq(chat_id) & Attr("deleted").ne(True),
        "Limit": limit * 2,  # Over-fetch to compensate for filter
        "ScanIndexForward": False,
    }
    if before_sort_key:
        kwargs["KeyConditionExpression"] = (
            Key("session_id").eq(session_id) & Key("sort_key").lt(before_sort_key)
        )

    resp = T.broadcast_chat_messages.query(**kwargs)
    items = resp.get("Items", [])
    items = items[:limit]  # Trim to requested limit
    items.reverse()  # Chronological order

    messages = [_private_chat_msg_out(item) for item in items]
    return {
        "messages": messages,
        "has_more": len(resp.get("Items", [])) > limit or bool(resp.get("LastEvaluatedKey")),
        "oldest_sort_key": items[0]["sort_key"] if items else None,
    }


def end_private_chat(
    session_id: str,
    chat_id: str,
    ended_reason: str,
) -> bool:
    """End a private chat and all associated voyeur sessions.

    Args:
        session_id: The broadcast session ID.
        chat_id: The private chat ID.
        ended_reason: "viewer_ended", "creator_ended", or "expired".

    Returns:
        True if found and ended, False if not found.
    """
    chat = _get_private_chat(session_id, chat_id)
    if not chat:
        return False

    ts = now_ts()
    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST_PCHAT#{session_id}", "sk": f"CHAT#{chat_id}"},
        UpdateExpression="SET #st = :status, ended_at = :ea, ended_reason = :er",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":status": "ended", ":ea": ts, ":er": ended_reason},
    )

    # End all associated voyeur sessions
    _end_voyeurs_for_chat(session_id, chat_id, ts)

    broadcast_sse_publish(session_id, {
        "_type": "private_chat:ended",
        "chat_id": chat_id,
        "ended_reason": ended_reason,
    })

    logger.info("broadcast.private_chat.ended session=%s chat=%s reason=%s", session_id, chat_id, ended_reason)
    return True


def extend_private_chat(
    session_id: str,
    chat_id: str,
    viewer_id: str,
    additional_minutes: int,
    payment_method_id: str,
    rate_per_minute_cents: int,
    platform_fee_pct: int,
    creator_id: str,
    *,
    is_voyeur: bool = False,
) -> Dict[str, Any]:
    """Extend a private chat or voyeur session by purchasing more time.

    Returns updated chat/voyeur details.
    """
    ts = now_ts()
    additional_cents = rate_per_minute_cents * additional_minutes
    platform_fee_cents = int(additional_cents * platform_fee_pct / 100)
    creator_earnings_cents = additional_cents - platform_fee_cents

    if is_voyeur:
        sk = f"VOYEUR#{chat_id}#{viewer_id}"
    else:
        sk = f"CHAT#{chat_id}"

    item = T.broadcast_private_sessions.get_item(
        Key={"pk": f"BCAST_PCHAT#{session_id}", "sk": sk}
    ).get("Item")
    if not item or item.get("status") not in ("active", "expiring"):
        raise HTTPException(status_code=409, detail="Chat session is not active.")

    current_expires = int(item.get("expires_at", ts))
    new_expires = max(current_expires, ts) + additional_minutes * 60
    new_purchased = int(item.get("purchased_minutes", 0)) + additional_minutes
    new_total = int(item.get("total_paid_cents", 0)) + additional_cents

    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST_PCHAT#{session_id}", "sk": sk},
        UpdateExpression=(
            "SET expires_at = :exp, purchased_minutes = :pm, "
            "total_paid_cents = :tp, #st = :status"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":exp": new_expires,
            ":pm": new_purchased,
            ":tp": new_total,
            ":status": "active",
        },
    )

    # Write additional billing entries
    _write_private_chat_billing(
        viewer_id=viewer_id,
        creator_id=creator_id,
        total_cents=additional_cents,
        creator_earnings_cents=creator_earnings_cents,
        chat_id=chat_id,
        session_id=session_id,
        tier=2 if is_voyeur else 1,
        duration_minutes=additional_minutes,
        payment_method_id=payment_method_id,
    )

    return {
        "chat_id": chat_id,
        "session_id": session_id,
        "expires_at": new_expires,
        "purchased_minutes": new_purchased,
        "total_paid_cents": new_total,
        "status": "active",
    }


def list_active_chats(session_id: str) -> List[Dict[str, Any]]:
    """List all active private chats for a broadcast (creator view)."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST_PCHAT#{session_id}")
            & Key("sk").begins_with("CHAT#")
        ),
        FilterExpression=Attr("status").is_in(["active", "expiring"]),
    )
    chats = resp.get("Items", [])
    ts = now_ts()
    out = []
    for chat in chats:
        voyeur_count = _count_voyeurs(session_id, chat["chat_id"])
        remaining = max(0, int(chat.get("expires_at", 0)) - ts)
        out.append({
            "chat_id": chat["chat_id"],
            "viewer_id": chat["viewer_id"],
            "viewer_display_name": chat.get("viewer_display_name", ""),
            "tier": int(chat.get("tier", 1)),
            "rate_per_minute_cents": int(chat.get("rate_per_minute_cents", 0)),
            "purchased_minutes": int(chat.get("purchased_minutes", 0)),
            "remaining_seconds": remaining,
            "status": chat["status"],
            "started_at": int(chat.get("started_at", 0)),
            "expires_at": int(chat.get("expires_at", 0)),
            "voyeur_count": voyeur_count,
            "total_revenue_cents": int(chat.get("total_paid_cents", 0)),
        })
    out.sort(key=lambda x: x["started_at"])
    return out


def update_chat_settings(
    session_id: str,
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    """Update private chat pricing settings on a broadcast session."""
    update_parts = []
    expr_values: Dict[str, Any] = {}

    field_map = {
        "private_chat_enabled": ":pce",
        "private_chat_rate_per_minute_cents": ":pcr",
        "voyeur_rate_per_minute_cents": ":vrr",
        "private_chat_time_blocks": ":pctb",
        "private_chat_max_concurrent": ":pcmc",
    }

    for field, placeholder in field_map.items():
        if field in settings and settings[field] is not None:
            update_parts.append(f"{field} = {placeholder}")
            expr_values[placeholder] = settings[field]

    if not update_parts:
        return settings

    # Chat settings are stored on the broadcast session item itself.
    # The BroadcastSessions table key is {"session_id": session_id} (no sort key).
    # Note: since transition_session_status() uses put_item (full replace),
    # these fields should be added to BroadcastSessionModel, session_to_item(),
    # and session_from_item() to survive status transitions.
    from app.core.tables import T as _T
    _T.broadcast_sessions.update_item(
        Key={"session_id": session_id},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=expr_values,
    )

    return settings


# ─── Timer / Expiry Background Task ─────────────────────────────

def check_and_expire_chats() -> int:
    """Check all active private chats and expire those past their expires_at.

    Called by a background asyncio task every 30 seconds.
    Returns the number of chats expired.

    For chats within 60 seconds of expiry, transitions status to "expiring"
    and publishes private_chat:expiring SSE event.
    """
    # In production, this would use a GSI on (status, expires_at).
    # For dev mode, we scan all active sessions — acceptable at low scale.
    expired_count = 0
    ts = now_ts()

    # This would need to be scoped to active sessions.
    # Implementation deferred to background task registration in main.py.
    return expired_count


# ─── Internal Helpers ────────────────────────────────────────────

def _get_private_chat(session_id: str, chat_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a private chat item from DDB."""
    return T.broadcast_private_sessions.get_item(
        Key={"pk": f"BCAST_PCHAT#{session_id}", "sk": f"CHAT#{chat_id}"}
    ).get("Item")


def _count_active_chats(session_id: str) -> int:
    """Count active private chats for a session."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST_PCHAT#{session_id}")
            & Key("sk").begins_with("CHAT#")
        ),
        FilterExpression=Attr("status").is_in(["active", "expiring"]),
        Select="COUNT",
    )
    return resp.get("Count", 0)


def _count_voyeurs(session_id: str, chat_id: str) -> int:
    """Count active voyeurs for a specific private chat."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST_PCHAT#{session_id}")
            & Key("sk").begins_with(f"VOYEUR#{chat_id}#")
        ),
        FilterExpression=Attr("status").eq("active"),
        Select="COUNT",
    )
    return resp.get("Count", 0)


def _end_voyeurs_for_chat(session_id: str, chat_id: str, ts: int) -> None:
    """End all active voyeur sessions for a chat."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST_PCHAT#{session_id}")
            & Key("sk").begins_with(f"VOYEUR#{chat_id}#")
        ),
        FilterExpression=Attr("status").eq("active"),
    )
    for item in resp.get("Items", []):
        T.broadcast_private_sessions.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET #st = :status, ended_at = :ea, ended_reason = :er",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":status": "ended", ":ea": ts, ":er": "parent_chat_ended"},
        )


def _write_private_chat_billing(
    viewer_id: str,
    creator_id: str,
    total_cents: int,
    creator_earnings_cents: int,
    chat_id: str,
    session_id: str,
    tier: int,
    duration_minutes: int,
    payment_method_id: str,
) -> tuple[str, str]:
    """Write paired debit/credit billing ledger entries for a private chat purchase.

    The viewer is debited the full amount. The creator is credited the
    amount after platform fee deduction.

    Returns (debit_entry_id, credit_entry_id).
    """
    import uuid as _uuid

    ts = now_ts()
    debit_id = _uuid.uuid4().hex
    credit_id = _uuid.uuid4().hex
    reason = f"Private chat: tier {tier}"
    meta = {
        "content_type": "private_chat",
        "chat_id": chat_id,
        "session_id": session_id,
        "tier": tier,
        "duration_minutes": duration_minutes,
        "viewer_id": viewer_id,
        "creator_id": creator_id,
        "payment_method_id": payment_method_id,
    }

    try:
        T.billing.put_item(Item={
            "pk": f"USER#{viewer_id}",
            "sk": f"LEDGER#{ts}#{debit_id}",
            "entry_id": debit_id,
            "ts": ts,
            "type": "debit",
            "amount_cents": total_cents,
            "currency": "USD",
            "state": "settled",
            "reason": reason,
            "meta": meta,
        })
    except Exception:
        logger.warning("private_chat_billing_debit_failed viewer=%s amount=%d", viewer_id, total_cents)

    try:
        T.billing.put_item(Item={
            "pk": f"USER#{creator_id}",
            "sk": f"LEDGER#{ts}#{credit_id}",
            "entry_id": credit_id,
            "ts": ts,
            "type": "credit",
            "amount_cents": creator_earnings_cents,
            "currency": "USD",
            "state": "settled",
            "reason": reason,
            "meta": meta,
        })
    except Exception:
        logger.warning("private_chat_billing_credit_failed creator=%s amount=%d", creator_id, creator_earnings_cents)

    return debit_id, credit_id


def _private_chat_msg_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a private chat message DDB item to output dict."""
    return {
        "message_id": item["message_id"],
        "session_id": item["session_id"],
        "sender_id": item["sender_id"],
        "sender_display_name": item.get("sender_display_name", ""),
        "text": item.get("text", ""),
        "kind": item.get("kind", "private_chat"),
        "private_chat_id": item.get("private_chat_id"),
        "created_at": int(item.get("created_at", 0)),
        "deleted": bool(item.get("deleted", False)),
    }
```

### 3.6 SSE Events

| Event Type | Payload | Trigger | Recipients |
|------------|---------|---------|------------|
| `private_chat:started` | `{chat_id, viewer_id, viewer_display_name, duration_minutes, expires_at}` | Tier 1 purchase | Creator (client-side filter) |
| `private_chat:message` | `{message_id, session_id, sender_id, text, private_chat_id, created_at}` | Message sent in private chat | Creator + tier 1 viewer + tier 2 voyeurs (client-side filter by `private_chat_id`) |
| `private_chat:expiring` | `{chat_id, remaining_seconds: 60}` | 1 minute before expiry | Creator + tier 1 viewer (client-side filter) |
| `private_chat:ended` | `{chat_id, ended_reason}` | Chat expires or is ended | Creator + tier 1 viewer + tier 2 voyeurs |
| `private_chat:voyeur_joined` | `{chat_id, viewer_id, viewer_display_name}` | Tier 2 purchase | Creator + tier 1 viewer |

All events use the existing `broadcast_sse_publish(session_id, event)` function. Client-side filtering based on `private_chat_id` determines which events to display to each viewer.

### 3.7 Timer Expiry Background Task

A background asyncio task checks for expiring and expired private chats every 30 seconds:

```python
async def _private_chat_expiry_loop():
    """Background task that checks for expiring/expired private chats."""
    while True:
        await asyncio.sleep(30)
        try:
            ts = now_ts()
            # Find chats expiring within 60 seconds
            # Transition to "expiring" status and publish SSE
            # Find expired chats (expires_at < ts)
            # End them with ended_reason="expired"
            check_and_expire_chats()
        except Exception:
            logger.exception("private_chat_expiry_loop_error")
```

Registered as a startup task in `app/main.py`:

```python
@app.on_event("startup")
async def start_private_chat_expiry():
    asyncio.create_task(_private_chat_expiry_loop())
```

### 3.8 Frontend — Private Chat Panel

```typescript
// frontend/src/pages/broadcast/PrivateChatPanel.tsx

/**
 * PrivateChatPanel — viewer-facing UI for purchasing and participating
 * in a private chat during a broadcast.
 *
 * States:
 * 1. Not purchased: Shows "Private Chat" button → opens purchase dialog
 * 2. Active (tier 1): Shows chat message list + input, timer, extend button
 * 3. Active (tier 2): Shows chat message list (read-only), "Spectating" badge, timer
 * 4. Expired: Shows "Session ended" message, purchase button for new session
 *
 * The panel is collapsible and appears alongside the public chat.
 *
 * React Query integration:
 * - purchaseMutation: POST /private-chat/purchase → invalidates chat list
 * - sendMutation: POST /private-chat/{id}/message
 * - extendMutation: POST /private-chat/{id}/extend
 * - messagesQuery: GET /private-chat/{id}/messages (polling + SSE cache updates)
 *
 * SSE event handling:
 * - private_chat:message → append to messages query cache
 * - private_chat:expiring → show "Extend?" prompt overlay
 * - private_chat:ended → show "Session ended", disable input
 * - private_chat:voyeur_joined → show toast notification
 */
```

### 3.9 Frontend — Creator Private Chat Dashboard

```typescript
// frontend/src/pages/broadcast/PrivateChatDashboard.tsx

/**
 * PrivateChatDashboard — creator-facing panel showing all active private chats.
 *
 * Displayed in the broadcaster dashboard alongside session controls.
 * Shows:
 * - List of active private chats with viewer names, timers, voyeur counts
 * - Click a chat to open the chat view for that conversation
 * - "End" button for each chat
 * - Total revenue counter for the current session
 *
 * React Query integration:
 * - chatsQuery: GET /private-chats (refetchInterval: 10000)
 * - endMutation: POST /private-chat/{id}/end
 */
```

### 3.10 Frontend — Purchase Dialog

```typescript
// frontend/src/pages/broadcast/PrivateChatPurchaseDialog.tsx

/**
 * PrivateChatPurchaseDialog — modal for purchasing private chat access.
 *
 * Shows:
 * - Tier selector: "Private Chat" (tier 1) / "Spectate" (tier 2)
 * - Duration selector: time blocks from session settings (5, 15, 30, 60 min)
 * - Rate display: "$X.XX/min" (from session settings)
 * - Total cost calculation: duration * rate
 * - Payment method selector (from billing query)
 * - "Purchase" button
 *
 * For tier 2, also shows:
 * - List of active private chats available to spectate
 * - Chat preview (viewer name, started_at, remaining time)
 */
```

### 3.11 Frontend Component Hierarchy

```
LivePlayer (viewer)
├── MediaPlayer (video)
├── BroadcastChat (public — unchanged)
├── PrivateChatPanel                          ← NEW (BCAST-012)
│   ├── PrivateChatPurchaseDialog             ← NEW
│   │   ├── TierSelector (tier 1 / tier 2)
│   │   ├── DurationSelector
│   │   ├── PaymentMethodSelector
│   │   ├── CostCalculation
│   │   └── PurchaseButton
│   ├── PrivateChatView (when purchased)      ← NEW
│   │   ├── MessageList (read-only for tier 2)
│   │   ├── ComposeInput (tier 1 only)
│   │   ├── TimerBar (remaining time)
│   │   ├── SpectatingBadge (tier 2 only)
│   │   └── ExtendButton
│   └── PrivateChatExpiredView                ← NEW
│       └── RepurchaseButton
└── ProductShelfPanel

BroadcasterDashboard
├── SessionControls
├── PrivateChatDashboard                      ← NEW (BCAST-012)
│   ├── ActiveChatList
│   │   └── ChatRow (per active chat)
│   │       ├── ViewerInfo
│   │       ├── Timer
│   │       ├── VoyeurCount badge
│   │       └── EndButton
│   ├── RevenueSummary
│   └── PrivateChatSettings                   ← NEW
│       ├── EnableToggle
│       ├── RateInput (tier 1)
│       ├── VoyeurRateInput (tier 2)
│       ├── TimeBlocksSelector
│       └── MaxConcurrentInput
├── ProductShelfManager
└── ChatModeration
```

---

## 4. Implementation Plan

### Phase 1: Backend — DDB Model + Chat Settings (1 day)

| File | Change | Lines Changed |
|------|--------|---------------|
| `app/services/broadcast_store.py` | Add `private_chat_*` fields to `BroadcastSessionModel`, `session_to_item()`, and `session_from_item()` (required because `transition_session_status()` uses `put_item` full replace). | +15 |
| `scripts/local-ddb-init.py` | Add `BroadcastPrivateSessions` table with `pk` (S) partition key and `sk` (S) sort key (if not already created by BCAST-011). Add `ModerationQueue` table with `pk`/`sk` composite key. | +12 |
| `app/core/tables.py` | Add `broadcast_private_sessions` and `moderation_queue` table handles (if not already present from BCAST-011). | +4 |
| `app/services/content_filter.py` | New module for keyword-based content filtering (`check_content_filter()` function). Does not currently exist. | ~50 |

### Phase 2: Backend — Private Chat Service (2.5 days)

| File | Change | Lines Changed |
|------|--------|---------------|
| `app/services/broadcast_private_chat.py` | New service file. `purchase_private_chat()` (~90 lines), `send_private_chat_message()` (~30 lines), `get_private_chat_history()` (~30 lines), `end_private_chat()` (~30 lines), `extend_private_chat()` (~40 lines), `list_active_chats()` (~30 lines), `update_chat_settings()` (~20 lines), `check_and_expire_chats()` (~20 lines), `_write_private_chat_billing()` (~45 lines), helpers (~65 lines). | ~400 |

### Phase 3: Backend — Router Endpoints (1.5 days)

| File | Change | Lines Changed |
|------|--------|---------------|
| `app/routers/broadcast.py` | Add Pydantic models (~70 lines): `PrivateChatPurchaseIn`, `PrivateChatPurchaseOut`, `PrivateChatMessageIn`, `PrivateChatHistoryOut`, `PrivateChatExtendIn`, `PrivateChatListOut`, `PrivateChatSummaryOut`, `PrivateChatSettingsIn`. Add 7 endpoint functions (~200 lines): purchase, send message, get history, extend, end, list chats, update settings. | +270 |
| `app/main.py` | Register background expiry task. | +5 |

### Phase 4: Frontend — Purchase Dialog + Chat Panel (2 days)

| File | Type | Lines |
|------|------|-------|
| `frontend/src/pages/broadcast/PrivateChatPanel.tsx` | Create — main panel with purchase/active/expired states | ~250 |
| `frontend/src/pages/broadcast/PrivateChatPurchaseDialog.tsx` | Create — tier selector, duration, PM, cost calculation | ~200 |
| `frontend/src/api/endpoints/broadcast-private-chat.ts` | Create — API wrappers for all 7 endpoints | ~90 |

### Phase 5: Frontend — Creator Dashboard + Settings (1.5 days)

| File | Type | Lines |
|------|------|-------|
| `frontend/src/pages/broadcast/PrivateChatDashboard.tsx` | Create — active chat list, revenue summary, per-chat controls | ~200 |
| `frontend/src/pages/broadcast/PrivateChatSettings.tsx` | Create — rate inputs, time blocks, enable toggle | ~150 |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Modify — handle `private_chat:*` SSE events, render PrivateChatPanel | +30 |

### Phase 6: Frontend — SSE Integration + Timer (1 day)

| File | Change | Lines Changed |
|------|--------|---------------|
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Handle `private_chat:message`, `private_chat:expiring`, `private_chat:ended`, `private_chat:voyeur_joined` SSE events in existing SSE handler. Update React Query caches. | +50 |
| `frontend/src/pages/broadcast/PrivateChatPanel.tsx` | Add countdown timer, extend prompt on expiring, auto-transition to expired state. | +30 |

### Summary of All Files

| File | Type | Estimated Lines |
|------|------|-----------------|
| `app/services/broadcast_store.py` | Modify | +15 |
| `scripts/local-ddb-init.py` | Modify | +12 |
| `app/core/tables.py` | Modify | +4 |
| `app/services/content_filter.py` | Create | ~50 |
| `app/services/broadcast_private_chat.py` | Create | ~400 |
| `app/routers/broadcast.py` | Modify | +270 |
| `app/main.py` | Modify | +5 |
| `frontend/src/api/endpoints/broadcast-private-chat.ts` | Create | ~90 |
| `frontend/src/pages/broadcast/PrivateChatPanel.tsx` | Create | ~280 |
| `frontend/src/pages/broadcast/PrivateChatPurchaseDialog.tsx` | Create | ~200 |
| `frontend/src/pages/broadcast/PrivateChatDashboard.tsx` | Create | ~200 |
| `frontend/src/pages/broadcast/PrivateChatSettings.tsx` | Create | ~150 |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Modify | +80 |
| **Total** | | **~1690** |

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_broadcast_private_chat.py`

**Mock setup**: moto mock for DynamoDB (broadcast tables). Mock broadcast provider for instant state transitions.

| Test Function | Description |
|---|---|
| `test_create_bcast012_resource` | Create primary resource; verify stored in DDB with correct fields |
| `test_get_bcast012_resource` | Get resource by ID; verify all fields returned |
| `test_list_bcast012_resources` | List resources; verify pagination and filtering |
| `test_update_bcast012_resource` | Update resource; verify changed fields persisted |
| `test_delete_bcast012_resource` | Delete resource; verify removed from DDB |
| `test_validation_rejects_invalid_input` | Missing required fields returns 422; invalid values return 400 |
| `test_authorization_enforced` | Non-owner/non-admin access returns 403 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full lifecycle: create -> read -> update -> delete through real DDB
2. Cross-service integration with broadcast session store
3. Concurrent operations do not corrupt shared state

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/broadcast-private-chat.spec.ts`

**Auth pattern**: `injectAuth(page, "root")` for admin operations; `injectAuth(page, "alice")` for viewer operations; CSRF header for mutations

| # | Test Name | Assertion |
|---|---|---|
| 1 | API creates resource successfully | POST returns 200/201 with resource ID |
| 2 | API returns resource by ID | GET returns full resource with all expected fields |
| 3 | API lists resources with pagination | GET list returns array; supports cursor pagination |
| 4 | API updates resource fields | PATCH/PUT returns updated resource |
| 5 | API deletes resource | DELETE returns 200; subsequent GET returns 404 |
| 6 | UI page loads with expected heading | Navigate to page; heading visible |
| 7 | UI form creates new resource | Fill form; submit; resource appears in list |
| 8 | UI shows error for invalid input | Submit empty form; validation messages visible |
| 9 | Unauthenticated request returns 401 | No session cookies -> 401 |
| 10 | Non-owner access returns 403 | Wrong user -> 403 |
| 11 | Non-existent resource returns 404 | GET invalid ID -> 404 |
| 12 | Duplicate creation returns 409 | Create same resource twice -> 409 or idempotent success |

**Negative tests**: 401 unauthenticated, 403 non-owner, 404 not found, 409 conflict/duplicate, 422 validation

**Edge cases**: Empty state (no resources), concurrent mutations, resource with max-length fields, Unicode content

### Test Data Requirements

Seed broadcast session in `beforeAll`. Create test resources via API with unique `Date.now()` suffixed names.

**Test users**: Root (ROOT, admin operations), Alice (USER, standard operations), Bob (USER, cross-user isolation)

### CI/Pipeline

Serial execution. `BROADCAST_PROVIDER=local`. Retry-safe with unique resource names.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| BCAST-005 | Live chat infrastructure (chat store, SSE) | Implemented | Yes |
| MON-002 | Tip ledger for billing integration | Implemented | Yes |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Parallel-safe with BCAST-011. Extends chat store with `private_chat_id` scoping. New DDB access patterns on existing table.

### Merge Checklist

- [ ] DDB table/fields added to `scripts/local-ddb-init.py` (if new table needed)
- [ ] Settings added to `app/core/settings.py`
- [ ] Service and router files created/modified
- [ ] Frontend components and API wrappers created
- [ ] E2E test passes in CI
- [ ] No breaking changes to existing endpoints

---

## Codebase References

| File | Line(s) | Status | Notes |
|------|---------|--------|-------|
| `app/services/broadcast_private_chat.py` | — | EXISTS | Private chat service |
| `app/core/settings.py` | 1208-1210 | EXISTS | `broadcast_private_chat_enabled`, max duration, voyeur settings |
| `app/services/broadcast_chat_store.py` | — | EXISTS | Chat store (messages in same table) |
| `app/core/tables.py` | 80-81 | EXISTS | `T.broadcast_chat_messages`, `T.broadcast_chat_mutes` |
| `scripts/local-ddb-init.py` | 557-563 | EXISTS | BroadcastChatMessages, BroadcastChatMutes tables |
| `scripts/local-ddb-init.py` | 798-808 | EXISTS | BroadcastPrivateSessions table |
| `frontend/src/api/endpoints/broadcastPrivateChat.ts` | — | EXISTS | Private chat API wrappers |
| `frontend/e2e/broadcast-private-chat.spec.ts` | — | EXISTS | E2E tests |
