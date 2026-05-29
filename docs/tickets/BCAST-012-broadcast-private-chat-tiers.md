# BCAST-012: Broadcast Private Chat Tiers — Paid 1-on-1 Text Chat with Voyeur Mode

**Status**: Proposed  
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

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_private_chat.py`)

New file, ~450 lines, using `moto` for DynamoDB mocking.

```python
import pytest
from decimal import Decimal
from moto import mock_dynamodb
from app.services.broadcast_private_chat import (
    purchase_private_chat,
    send_private_chat_message,
    get_private_chat_history,
    end_private_chat,
    extend_private_chat,
    list_active_chats,
)


def test_tier_1_purchase_creates_active_chat(broadcast_table, billing_table):
    """Tier 1 purchase creates a chat item with status='active'."""
    result = purchase_private_chat(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        tier=1, duration_minutes=15, payment_method_id="pm_123",
        rate_per_minute_cents=500, creator_id="creator_1",
    )
    assert result["status"] == "active"
    assert result["tier"] == 1
    assert result["total_paid_cents"] == 7500  # 15 * 500
    assert result["expires_at"] > 0


def test_tier_1_purchase_writes_billing_entries(broadcast_table, billing_table):
    """Tier 1 purchase writes debit for viewer and credit for creator."""
    purchase_private_chat(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        tier=1, duration_minutes=15, payment_method_id="pm_123",
        rate_per_minute_cents=500, creator_id="creator_1",
    )
    # Query billing for alice debit
    from boto3.dynamodb.conditions import Key
    resp = billing_table.query(
        KeyConditionExpression=Key("pk").eq("USER#alice") & Key("sk").begins_with("LEDGER#")
    )
    assert len(resp["Items"]) == 1
    assert resp["Items"][0]["type"] == "debit"
    assert int(resp["Items"][0]["amount_cents"]) == 7500

    # Query billing for creator credit (minus platform fee)
    resp = billing_table.query(
        KeyConditionExpression=Key("pk").eq("USER#creator_1") & Key("sk").begins_with("LEDGER#")
    )
    assert len(resp["Items"]) == 1
    assert resp["Items"][0]["type"] == "credit"
    assert int(resp["Items"][0]["amount_cents"]) == 6000  # 7500 - 20% = 6000


def test_tier_1_purchase_rejects_when_max_concurrent_reached(broadcast_table, billing_table):
    """Tier 1 purchase rejected when max concurrent chats reached."""
    for i in range(5):
        purchase_private_chat(
            session_id="sess_1", viewer_id=f"viewer_{i}", viewer_display_name=f"Viewer {i}",
            tier=1, duration_minutes=5, payment_method_id=f"pm_{i}",
            rate_per_minute_cents=500, creator_id="creator_1",
        )
    with pytest.raises(Exception) as exc_info:
        purchase_private_chat(
            session_id="sess_1", viewer_id="viewer_6", viewer_display_name="Viewer 6",
            tier=1, duration_minutes=5, payment_method_id="pm_6",
            rate_per_minute_cents=500, creator_id="creator_1",
        )
    assert "409" in str(exc_info.value.status_code)


def test_tier_2_purchase_creates_voyeur_item(broadcast_table, billing_table):
    """Tier 2 purchase creates a voyeur tracking item."""
    chat = purchase_private_chat(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        tier=1, duration_minutes=15, payment_method_id="pm_123",
        rate_per_minute_cents=500, creator_id="creator_1",
    )
    voyeur = purchase_private_chat(
        session_id="sess_1", viewer_id="bob", viewer_display_name="Bob",
        tier=2, duration_minutes=15, payment_method_id="pm_456",
        rate_per_minute_cents=100, creator_id="creator_1",
        chat_id=chat["chat_id"],
    )
    assert voyeur["tier"] == 2
    assert voyeur["chat_id"] == chat["chat_id"]
    assert voyeur["total_paid_cents"] == 1500  # 15 * 100


def test_tier_2_purchase_fails_for_nonexistent_chat(broadcast_table, billing_table):
    """Tier 2 purchase fails when target chat does not exist."""
    with pytest.raises(Exception) as exc_info:
        purchase_private_chat(
            session_id="sess_1", viewer_id="bob", viewer_display_name="Bob",
            tier=2, duration_minutes=15, payment_method_id="pm_456",
            rate_per_minute_cents=100, creator_id="creator_1",
            chat_id="pchat_nonexistent",
        )
    assert "404" in str(exc_info.value.status_code)


def test_send_message_stores_with_private_chat_id(broadcast_table, chat_table):
    """Messages sent in private chat have private_chat_id field set."""
    result = send_private_chat_message(
        session_id="sess_1", chat_id="pchat_abc",
        sender_id="alice", sender_display_name="Alice",
        text="Hello from private chat!",
    )
    assert result["private_chat_id"] == "pchat_abc"
    assert result["kind"] == "private_chat"
    assert result["text"] == "Hello from private chat!"


def test_get_history_filters_by_private_chat_id(broadcast_table, chat_table):
    """Chat history returns only messages for the specified private_chat_id."""
    send_private_chat_message("sess_1", "pchat_1", "alice", "Alice", "msg for chat 1")
    send_private_chat_message("sess_1", "pchat_2", "bob", "Bob", "msg for chat 2")
    history = get_private_chat_history("sess_1", "pchat_1")
    assert len(history["messages"]) == 1
    assert history["messages"][0]["text"] == "msg for chat 1"


def test_end_chat_ends_all_voyeurs(broadcast_table, billing_table):
    """Ending a private chat also ends all voyeur sessions."""
    chat = purchase_private_chat(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        tier=1, duration_minutes=15, payment_method_id="pm_123",
        rate_per_minute_cents=500, creator_id="creator_1",
    )
    purchase_private_chat(
        session_id="sess_1", viewer_id="bob", viewer_display_name="Bob",
        tier=2, duration_minutes=15, payment_method_id="pm_456",
        rate_per_minute_cents=100, creator_id="creator_1",
        chat_id=chat["chat_id"],
    )
    end_private_chat("sess_1", chat["chat_id"], "creator_ended")
    chats = list_active_chats("sess_1")
    assert len(chats) == 0


def test_extend_chat_increases_expires_at(broadcast_table, billing_table):
    """Extending a chat increases expires_at and purchased_minutes."""
    chat = purchase_private_chat(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        tier=1, duration_minutes=5, payment_method_id="pm_123",
        rate_per_minute_cents=500, creator_id="creator_1",
    )
    original_expires = chat["expires_at"]
    extended = extend_private_chat(
        session_id="sess_1", chat_id=chat["chat_id"],
        viewer_id="alice", additional_minutes=10,
        payment_method_id="pm_123", rate_per_minute_cents=500,
        platform_fee_pct=20, creator_id="creator_1",
    )
    assert extended["expires_at"] > original_expires
    assert extended["purchased_minutes"] == 15  # 5 + 10


def test_list_active_chats_includes_voyeur_count(broadcast_table, billing_table):
    """list_active_chats includes voyeur_count for each chat."""
    chat = purchase_private_chat(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        tier=1, duration_minutes=15, payment_method_id="pm_123",
        rate_per_minute_cents=500, creator_id="creator_1",
    )
    purchase_private_chat(
        session_id="sess_1", viewer_id="bob", viewer_display_name="Bob",
        tier=2, duration_minutes=15, payment_method_id="pm_456",
        rate_per_minute_cents=100, creator_id="creator_1",
        chat_id=chat["chat_id"],
    )
    purchase_private_chat(
        session_id="sess_1", viewer_id="charlie", viewer_display_name="Charlie",
        tier=2, duration_minutes=15, payment_method_id="pm_789",
        rate_per_minute_cents=100, creator_id="creator_1",
        chat_id=chat["chat_id"],
    )
    chats = list_active_chats("sess_1")
    assert len(chats) == 1
    assert chats[0]["voyeur_count"] == 2


def test_platform_fee_deducted_from_creator_credit(broadcast_table, billing_table):
    """Creator credit is total minus platform fee."""
    purchase_private_chat(
        session_id="sess_1", viewer_id="alice", viewer_display_name="Alice",
        tier=1, duration_minutes=10, payment_method_id="pm_123",
        rate_per_minute_cents=500, platform_fee_pct=20, creator_id="creator_1",
    )
    from boto3.dynamodb.conditions import Key
    resp = billing_table.query(
        KeyConditionExpression=Key("pk").eq("USER#creator_1") & Key("sk").begins_with("LEDGER#")
    )
    credit = resp["Items"][0]
    # 10 min * 500 = 5000 total, 20% fee = 1000, creator gets 4000
    assert int(credit["amount_cents"]) == 4000
```

### 5.2 E2E Tests (`frontend/e2e/broadcast-private-chat.spec.ts`)

New file, ~450 lines.

**Section 125: Private Chat Purchase + Messaging (5 tests)**:

1. `Viewer purchases tier 1 private chat with valid PM and duration`
   - Create broadcast session, set to live, enable private chat
   - Viewer sends POST private-chat/purchase with tier=1, duration=5
   - Assert 201 with chat_id, status="active", total_paid_cents = 5 * rate

2. `Viewer sends message in active private chat`
   - Purchase tier 1 chat
   - POST message with text="Hello private"
   - Assert 201 with private_chat_id set, kind="private_chat"

3. `Private chat message history returns only scoped messages`
   - Send 2 messages to private chat and 1 to public chat
   - GET private-chat/{id}/messages
   - Assert exactly 2 messages returned, all with correct private_chat_id

4. `Voyeur cannot send messages (403)`
   - Purchase tier 1 (Alice), then tier 2 (Bob spectating Alice's chat)
   - Bob attempts POST message to the private chat
   - Assert 403

5. `Creator can send messages in any private chat`
   - Purchase tier 1 (Alice)
   - Creator sends POST message to Alice's private chat
   - Assert 201

**Section 126: Voyeur Tier + Billing (4 tests)**:

1. `Viewer purchases tier 2 voyeur access to existing chat`
   - Alice purchases tier 1, Bob purchases tier 2 on Alice's chat
   - Assert Bob's purchase response has tier=2, chat_id matches Alice's

2. `Tier 2 purchase fails for nonexistent chat (404)`
   - Bob tries to purchase tier 2 with chat_id="pchat_invalid"
   - Assert 404

3. `Billing debit is full amount, credit is minus platform fee`
   - Purchase tier 1 at 500/min for 10 min
   - Query billing: viewer debit = 5000, creator credit = 4000 (20% fee)

4. `Extending a chat purchases additional time and writes billing`
   - Purchase 5 min chat, then extend by 10 min
   - Assert new expires_at is later
   - Assert additional billing entries written (separate debit/credit for extension)

---

## 6. Security Considerations

### 6.1 Authentication & Authorization

- All private chat endpoints require `require_ui_session`.
- **Purchase**: Any authenticated viewer except the session creator.
- **Send message**: Only tier 1 viewer or session creator. Voyeurs (tier 2) receive 403.
- **Get history**: Tier 1 viewer, active tier 2 voyeur, or session creator. Other viewers receive 403.
- **Extend**: Only the original purchaser (tier 1 or their own tier 2 session).
- **End**: Tier 1 viewer or session creator.
- **List chats**: Only session creator.
- **Settings**: Only session creator.

### 6.2 Message Isolation

Private chat messages are stored in the same DDB table as public messages but scoped by `private_chat_id`. The `get_chat_history()` endpoint (public chat) does NOT filter out private messages by default. However, the public chat SSE stream emits `chat:message` events (without `private_chat_id`), while private messages emit `private_chat:message` events. The public history endpoint should be updated to add `FilterExpression: Attr("private_chat_id").not_exists()` to exclude private messages from public history results.

### 6.3 SSE Visibility

All SSE events are broadcast to all session subscribers. Private chat message content (text) is visible in the raw SSE stream to any subscriber. Client-side filtering provides UI-level isolation but not network-level. For stronger isolation:
- Future enhancement: per-chat SSE channels (separate subscription per private chat)
- Alternative: encrypt private chat message text with a session key shared only with authorized viewers

For MVP, client-side filtering is acceptable. The SSE stream is not a documented public API, and messages are short-lived text (7-day TTL).

### 6.4 Payment Abuse Prevention

- Purchases are prepaid: the full amount is debited before the chat becomes active.
- No refund for early termination (viewer or creator ending the chat before time expires).
- Time blocks are constrained to predefined durations (e.g., [5, 15, 30, 60] minutes) -- viewers cannot purchase arbitrary sub-minute increments.
- Maximum concurrent chats per session (default 5) prevents a single viewer from monopolizing the creator's attention by purchasing many simultaneous chats.

### 6.5 Rate Limiting

- Private chat messages use the same 1-per-2-seconds rate limit as public chat.
- Purchase requests are implicitly rate-limited by payment method validation (PM lookup per request).
- No additional rate limiting on purchases beyond the max concurrent constraint.

---

## 7. Migration & Rollback Plan

### 7.1 Schema Changes

- **New DDB table**: Private chat items require the `BroadcastPrivateSessions` table with `pk`/`sk` composite keys (shared with BCAST-011 if implemented first). The existing `BroadcastSessions` table has only `session_id` as PK (no SK) and cannot support composite key patterns. If BCAST-011 has already created this table, no additional table is needed. Also, `T.moderation_queue` (new `ModerationQueue` table with `pk`/`sk` keys) and `app/services/content_filter.py` (new module) must be created for the content moderation features.
- **Messages**: Use the existing `broadcast_chat_messages` table with an additional `private_chat_id` attribute.
- **Session fields**: New optional fields (`private_chat_enabled`, `private_chat_rate_per_minute_cents`, etc.) on session items. These must be added to `BroadcastSessionModel`, `session_to_item()`, and `session_from_item()` because `transition_session_status()` uses `put_item` (full replace). Existing sessions without these fields treat private chat as disabled (default `false`).
- **Backward-compatible**: Existing public chat is completely unaffected. The `private_chat_id` field on messages is optional -- existing messages without it continue to work as public messages.

### 7.2 Rollback Steps

1. Revert code changes (remove private chat endpoints and service).
2. Delete `app/services/broadcast_private_chat.py`.
3. Private chat DDB items in `BroadcastPrivateSessions` can remain (TTL will expire them) or be batch-deleted.
4. Messages with `private_chat_id` set will persist in the chat messages table but will never be returned by any endpoint after rollback (no code reads `private_chat_id` outside the private chat endpoints).

### 7.3 Feature Flag

`private_chat_enabled` on each broadcast session serves as a per-session feature flag. Globally, the feature can be disabled by setting `BROADCAST_PRIVATE_CHAT_ENABLED=false` in `.env.local`, which the purchase endpoint checks before proceeding.

---

## 8. Performance & Capacity Planning

### 8.1 Expected Throughput

| Metric | Estimate | Basis |
|--------|----------|-------|
| Private chat purchases/min | 5 | Per live broadcast |
| Private chat messages/sec | 2 | Per active chat (creator + viewer) |
| Voyeur purchases/min | 10 | Higher volume, lower friction |
| Total additional DDB WCUs | ~15 | Messages + purchases + billing |

### 8.2 DDB Impact

- **Messages**: Private chat messages are stored in the same table as public messages. They share the same `session_id` partition. In a busy session with 5 concurrent private chats + public chat, the partition could see ~12 messages/sec (2/sec per private chat + 2/sec public). This is well within DDB hot partition limits (1000 WCU per partition).
- **Private chat items**: Low volume (max 5 + voyeurs per session). Negligible DDB impact.
- **Billing entries**: 2 entries per purchase (debit + credit). At 15 purchases/min, this adds ~0.5 WCU to the billing table.

### 8.3 Latency Impact

- **Purchase endpoint**: PM validation (1 DDB read) + billing writes (2 DDB writes) + chat item write (1 DDB write) = ~20-30ms.
- **Send message**: 1 DDB write + SSE publish = ~10ms. Same as public chat.
- **Get history**: 1 DDB query with FilterExpression = ~10-20ms. The filter adds some overhead vs. public chat (which has no filter), but the private chat volume is low.

---

## 9. Acceptance Criteria

1. A viewer can purchase a tier 1 private chat during a live broadcast.
2. The purchase debits the viewer and credits the creator (minus platform fee) immediately.
3. The tier 1 viewer and creator can exchange messages in the private chat.
4. A voyeur (tier 2) can purchase read-only access to an active private chat at a lower rate.
5. Voyeurs can read messages but cannot send them (403 on send attempt).
6. The creator can manage multiple concurrent private chats (up to the configured limit).
7. Private chat messages are scoped and do not appear in the public chat history.
8. A countdown timer runs for each session; at 1 minute remaining, an "expiring" event is published.
9. Viewers can extend their session by purchasing additional time blocks.
10. When time expires, the chat auto-ends and all associated voyeur sessions end.
11. The creator can configure rates, time blocks, and enable/disable private chat via settings.
12. Creator credit amount correctly deducts the platform fee percentage.
13. All 5 Section 125 E2E tests pass.
14. All 4 Section 126 E2E tests pass.

---

## 10. Content Moderation in Private Chats

### 10.1 Problem Statement

Although private chats are between specific participants, the platform remains liable for content exchanged through its systems. Content policies (hate speech, threats, CSAM, spam) apply equally to private and public channels. The challenge is enforcing policies without undermining the "private" nature that users pay for.

### 10.2 Automated Keyword Filtering

All private chat messages pass through a keyword content filter before being stored. **Note**: `app/services/content_filter.py` does not currently exist and must be created as part of this ticket (or as a prerequisite). The public broadcast chat does not currently have content filtering either — this would be a new capability shared between public and private chat:

```python
def send_private_chat_message(
    session_id: str,
    chat_id: str,
    sender_id: str,
    sender_display_name: str,
    text: str,
) -> Dict[str, Any]:
    # Automated content filter (shared with public chat)
    filter_result = check_content_filter(text)
    if filter_result.blocked:
        raise HTTPException(
            status_code=400,
            detail=f"Message blocked by content filter: {filter_result.reason}",
        )
    if filter_result.flagged:
        # Allow the message but flag for moderator review
        _flag_private_chat_message(
            session_id=session_id,
            chat_id=chat_id,
            sender_id=sender_id,
            text=text,
            flag_reason=filter_result.reason,
        )

    # ... existing message storage logic ...
```

**Filter tiers**:

| Tier | Action | Example Content |
|------|--------|-----------------|
| Block | Message rejected with 400 | Hate speech, slurs, CSAM-related keywords |
| Flag | Message delivered but queued for moderator review | Harassment patterns, solicitation keywords |
| Pass | Message delivered normally | Normal conversation |

The keyword list would be maintained in `app/services/content_filter.py`. **Note**: This module does not currently exist and must be created as part of this implementation. The `check_content_filter()` function referenced above is new code to be written.

### 10.3 Report Mechanism for Viewers

Tier 1 viewers and voyeurs can report private chat messages:

```python
@router.post("/{session_id}/private-chat/{chat_id}/messages/{message_id}/report")
def report_private_chat_message(
    session_id: str,
    chat_id: str,
    message_id: str,
    body: ReportIn,  # { reason: str, details: Optional[str] }
    ctx=Depends(require_ui_session),
):
    """Report a private chat message for content policy violation."""
    # Validate the reporter has access to this chat (tier 1, tier 2, or creator)
    _validate_chat_access(session_id, chat_id, ctx["user_sub"])

    report_id = f"rpt_{uuid.uuid4().hex}"
    # NOTE: T.moderation_queue does not currently exist in app/core/tables.py.
    # A new ModerationQueue DDB table (with pk/sk composite key) must be added
    # to scripts/local-ddb-init.py and app/core/tables.py before this code works.
    T.moderation_queue.put_item(Item={
        "pk": f"REPORT#{report_id}",
        "sk": f"REPORT#{report_id}",
        "report_id": report_id,
        "reporter_id": ctx["user_sub"],
        "content_type": "private_chat_message",
        "session_id": session_id,
        "chat_id": chat_id,
        "message_id": message_id,
        "reason": body.reason,
        "details": body.details,
        "status": "pending",
        "created_at": now_ts(),
    })

    return {"ok": True, "report_id": report_id}
```

### 10.4 Creator Block and Ban

The creator can block a viewer from their private chat and ban them from future purchases:

```python
@router.post("/{session_id}/private-chat/{chat_id}/block")
def block_private_chat_viewer(
    session_id: str,
    chat_id: str,
    ctx=Depends(require_ui_session),
):
    """Creator blocks a viewer and ends their private chat immediately."""
    session = _get_and_validate_session(session_id)
    if session.created_by != ctx["user_sub"]:
        raise HTTPException(403, "Only the broadcaster can block viewers.")

    chat = _get_private_chat(session_id, chat_id)
    if not chat:
        raise HTTPException(404, "Private chat not found.")

    # End the chat
    end_private_chat(session_id, chat_id, "creator_blocked")

    # Add viewer to block list (prevents future purchases)
    T.broadcast_private_sessions.put_item(Item={
        "pk": f"BCAST_BLOCK#{session_id}",
        "sk": f"USER#{chat['viewer_id']}",
        "viewer_id": chat["viewer_id"],
        "blocked_by": ctx["user_sub"],
        "blocked_at": now_ts(),
        "reason": "creator_block",
    })

    return {"ok": True, "blocked_viewer_id": chat["viewer_id"]}
```

The purchase endpoint checks the block list before allowing a purchase:

```python
# In purchase_private_chat():
block_item = T.broadcast_private_sessions.get_item(
    Key={"pk": f"BCAST_BLOCK#{session_id}", "sk": f"USER#{viewer_id}"}
).get("Item")
if block_item:
    raise HTTPException(403, "You have been blocked from private chat on this broadcast.")
```

### 10.5 Moderator Access to Private Chat Logs

Platform moderators can access private chat message history when investigating a report or legal/compliance request. Access is gated behind the `_require_operator_role(ctx)` pattern (which checks for `admin` or `root` role) and requires a documented justification:

```python
@router.get("/{session_id}/private-chat/{chat_id}/messages/admin")
def admin_get_private_chat_messages(
    session_id: str,
    chat_id: str,
    justification: str = Query(..., min_length=10, max_length=500),
    ctx: dict = Depends(_ctx),
):
    # NOTE: The broadcast router does not use require_admin_session (which does not exist).
    # Instead, it uses the _require_operator_role(ctx) pattern where ctx = _ctx(session, profile_id).
    _require_operator_role(ctx)
    """Admin endpoint to read private chat messages for moderation.

    Requires justification text that is logged to the audit trail.
    """
    # Log the access to the moderation audit log
    log_moderation_access(
        admin_id=ctx["user_sub"],
        resource_type="private_chat",
        resource_id=f"{session_id}/{chat_id}",
        justification=justification,
    )

    return get_private_chat_history(session_id, chat_id, limit=200)
```

All admin accesses to private chat logs are recorded in the moderation audit log (`app/services/moderation_audit_log.py`) for compliance review.

---

## 11. Voyeur Privacy and Ethics

### 11.1 Disclosure to All Parties

Transparency is a core principle. When voyeurs join a private chat, all parties are notified:

**Broadcaster notification**: The creator always sees the full list of voyeurs, including identities and count:

```
SSE event: private_chat:voyeur_joined
{ chat_id: "pchat_abc", viewer_id: "bob", viewer_display_name: "Bob" }
```

**Tier 1 participant notification**: The active chatter is notified that voyeurs are present, but with limited information to protect voyeur privacy:

```
SSE event: private_chat:voyeur_count_update
{ chat_id: "pchat_abc", voyeur_count: 3 }
```

The tier 1 viewer sees: "3 spectators are watching this chat" but does NOT see voyeur identities (only the count).

### 11.2 Voyeur Count Display

Both the tier 1 viewer and the broadcaster see a voyeur count badge in the chat UI:

```typescript
// In PrivateChatView.tsx
{voyeurCount > 0 && (
  <div className="flex items-center gap-1 text-xs text-muted-foreground">
    <Eye className="h-3 w-3" />
    <span>{voyeurCount} spectator{voyeurCount !== 1 ? "s" : ""}</span>
  </div>
)}
```

### 11.3 Opt-Out of Voyeur Mode (Premium Privacy)

The tier 1 viewer can pay a premium to disable voyeur access on their private chat, ensuring a truly private conversation:

```python
class PrivateChatPurchaseIn(BaseModel):
    # ... existing fields ...
    no_voyeurs: bool = Field(
        default=False,
        description="If true, voyeur mode is disabled for this chat. "
                    "Premium price applies (2x the tier 1 rate)."
    )
```

**Pricing for no-voyeur mode**:
```python
if body.no_voyeurs:
    # Premium pricing: 2x the base tier 1 rate
    rate = session.private_chat_rate_per_minute_cents * 2
    # The premium surcharge compensates the creator for lost voyeur revenue
```

When `no_voyeurs=true` is set on a chat, all tier 2 purchase attempts for that chat return 403:

```python
# In purchase_private_chat(), tier 2 path:
target_chat = _get_private_chat(session_id, chat_id)
if target_chat.get("no_voyeurs"):
    raise HTTPException(403, "This private chat has voyeur mode disabled.")
```

### 11.4 Voyeur Identity Anonymization

Voyeur identities are visible to the **broadcaster** but hidden from the **tier 1 viewer**:

| Data Point | Visible to Creator | Visible to Tier 1 Viewer | Visible to Voyeur |
|------------|-------------------|--------------------------|-------------------|
| Voyeur display name | Yes | No | N/A (their own) |
| Voyeur user ID | Yes | No | N/A |
| Voyeur count | Yes | Yes (count only) | Yes (count only) |
| Voyeur join/leave events | Yes (with name) | Yes (count change only) | No |

This design balances creator visibility (know who is paying to watch) with tier 1 viewer privacy (not knowing who is reading their messages).

### 11.5 Voyeur Ethics Disclosure

The purchase dialog for tier 2 includes a clear disclosure:

```
┌──────────────────────────────────────────────┐
│  Spectate Private Chat                        │
│                                                │
│  You will be able to READ messages exchanged   │
│  between [Alice] and the creator.              │
│                                                │
│  Important:                                    │
│  - Both the creator and the participant will    │
│    be informed that spectators are present      │
│  - You cannot send messages (read-only)         │
│  - The participant will see the spectator count │
│    but NOT your identity                        │
│  - The creator will see your identity           │
│                                                │
│  [Cancel]  [I Understand — Purchase]           │
└──────────────────────────────────────────────┘
```

---

## 12. Auto-Extension and Upsell

### 12.1 Smart Upsell at Time Remaining Threshold

When a private chat has 1 minute remaining, the viewer receives an `expiring` SSE event. The frontend shows an upsell prompt with a discount for purchasing a longer time block:

```typescript
// In PrivateChatPanel.tsx — shown when remainingSeconds < 60
{showExtendPrompt && (
  <div className="absolute bottom-16 inset-x-0 mx-4 p-3 bg-primary/95 text-primary-foreground rounded-lg shadow-lg animate-in fade-in slide-in-from-bottom-2">
    <p className="text-sm font-medium">Time is running out!</p>
    <div className="flex gap-2 mt-2">
      <Button size="sm" variant="secondary" onClick={() => extendChat(5)}>
        +5 min (${(rate * 5 / 100).toFixed(2)})
      </Button>
      <Button size="sm" variant="secondary" onClick={() => extendChat(15)}>
        +15 min (${(rate * 15 * 0.9 / 100).toFixed(2)})
        <Badge variant="outline" className="ml-1">10% off</Badge>
      </Button>
      <Button size="sm" variant="secondary" onClick={() => extendChat(30)}>
        +30 min (${(rate * 30 * 0.8 / 100).toFixed(2)})
        <Badge variant="outline" className="ml-1">20% off</Badge>
      </Button>
    </div>
  </div>
)}
```

**Discount tiers for extension**:

| Extension Block | Discount | Rationale |
|----------------|----------|-----------|
| 5 minutes | 0% | Minimum extension, no discount |
| 15 minutes | 10% off | Moderate commitment rewarded |
| 30 minutes | 20% off | Larger commitment, larger discount |
| 60 minutes | 25% off | Maximum extension, best value |

Discounts are configurable per session via the settings endpoint.

### 12.2 "Add 5 More Minutes" Inline CTA

A persistent "Add time" button is shown in the chat panel header when the session is below 5 minutes remaining:

```typescript
{remainingSeconds < 300 && (
  <Button
    size="sm"
    variant="outline"
    className="gap-1"
    onClick={() => extendMutation.mutate({ duration_minutes: 5 })}
    disabled={extendMutation.isPending}
  >
    <Plus className="h-3 w-3" />
    +5 min (${(rate * 5 / 100).toFixed(2)})
  </Button>
)}
```

### 12.3 Auto-Extend Toggle

Viewers can opt in to automatic extension, which purchases additional time blocks automatically when the session is about to expire:

```python
class PrivateChatAutoExtendIn(BaseModel):
    enabled: bool = True
    extend_minutes: int = Field(default=5, ge=5, le=60)
    max_total_spend_cents: int = Field(default=10000, ge=0)  # $100 max total auto-spend
```

**Backend auto-extend logic** (in the expiry background task):

```python
def _try_auto_extend(session_id: str, chat_item: Dict) -> bool:
    """Attempt to auto-extend a chat if the viewer has opted in."""
    if not chat_item.get("auto_extend_enabled"):
        return False

    extend_minutes = int(chat_item.get("auto_extend_minutes", 5))
    max_spend = int(chat_item.get("auto_extend_max_spend_cents", 10000))
    total_spent = int(chat_item.get("total_paid_cents", 0))
    rate = int(chat_item.get("rate_per_minute_cents", 0))
    additional_cost = rate * extend_minutes

    if total_spent + additional_cost > max_spend:
        return False  # Would exceed spending cap

    # Process the extension
    extend_private_chat(
        session_id=session_id,
        chat_id=chat_item["chat_id"],
        viewer_id=chat_item["viewer_id"],
        additional_minutes=extend_minutes,
        payment_method_id=chat_item.get("payment_method_id", ""),
        rate_per_minute_cents=rate,
        platform_fee_pct=int(chat_item.get("platform_fee_pct", 20)),
        creator_id=_get_session_creator(session_id),
    )

    broadcast_sse_publish(session_id, {
        "_type": "private_chat:auto_extended",
        "chat_id": chat_item["chat_id"],
        "extended_minutes": extend_minutes,
        "new_total_paid_cents": total_spent + additional_cost,
    })

    return True
```

**Balance depletion**: When auto-extend is enabled and the viewer's max spend is reached, the session ends with `ended_reason: "auto_extend_limit_reached"` and the viewer sees:

```
"Auto-extend limit reached ($100.00 total). Session will end when time runs out."
```

---

## 13. Analytics Dashboard for Private Chat

### 13.1 Creator Analytics Endpoint

```python
@router.get("/{session_id}/private-chat/analytics")
def get_private_chat_analytics(
    session_id: str,
    ctx=Depends(require_ui_session),
):
    """Get analytics for private chat activity in a broadcast session."""
    session = _get_and_validate_session(session_id)
    if session.created_by != ctx["user_sub"]:
        raise HTTPException(403, "Only the broadcaster can view analytics.")

    all_chats = _get_all_chats(session_id)  # All statuses, not just active
    all_voyeurs = _get_all_voyeurs(session_id)

    total_revenue = sum(int(c.get("total_paid_cents", 0)) for c in all_chats)
    total_voyeur_revenue = sum(int(v.get("total_paid_cents", 0)) for v in all_voyeurs)

    # Average duration
    completed_chats = [c for c in all_chats if c.get("ended_at")]
    avg_duration = 0
    if completed_chats:
        durations = [int(c["ended_at"]) - int(c["started_at"]) for c in completed_chats]
        avg_duration = sum(durations) // len(durations)

    # Repeat viewers
    viewer_ids = [c.get("viewer_id") for c in all_chats]
    unique_viewers = len(set(viewer_ids))
    repeat_viewers = len(viewer_ids) - unique_viewers

    # Tier distribution
    tier_1_count = len(all_chats)
    tier_2_count = len(all_voyeurs)

    return {
        "session_id": session_id,
        "total_private_chats": len(all_chats),
        "active_private_chats": len([c for c in all_chats if c.get("status") == "active"]),
        "total_revenue_cents": total_revenue + total_voyeur_revenue,
        "tier_1_revenue_cents": total_revenue,
        "tier_2_revenue_cents": total_voyeur_revenue,
        "average_duration_seconds": avg_duration,
        "unique_viewers": unique_viewers,
        "repeat_viewers": repeat_viewers,
        "tier_distribution": {
            "tier_1": tier_1_count,
            "tier_2": tier_2_count,
        },
    }
```

### 13.2 Creator Analytics Dashboard UI

```typescript
// frontend/src/pages/broadcast/PrivateChatAnalytics.tsx

/**
 * PrivateChatAnalytics — analytics panel shown to creators after or during a broadcast.
 *
 * Displays:
 * - Total revenue from private chats (broken down by tier 1 and tier 2)
 * - Average session duration
 * - Repeat viewer rate (viewers who purchased multiple times)
 * - Peak demand times (when most purchases occurred)
 * - Tier distribution pie chart (tier 1 vs tier 2 revenue)
 * - Per-session revenue table with export
 */
```

**Key metrics displayed**:

```
┌───────────────────────────────────────────────────────┐
│  Private Chat Analytics — Session "Evening Stream"     │
│                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐│
│  │ Total Revenue │  │ Avg Duration │  │ Unique       ││
│  │  $247.50      │  │  12m 34s     │  │ Viewers: 8   ││
│  └──────────────┘  └──────────────┘  └──────────────┘│
│                                                        │
│  Revenue Breakdown:                                    │
│  ┌─────────────────────────────────────────────────┐  │
│  │ Tier 1 (Participants): $192.50  (77.8%)          │  │
│  │ Tier 2 (Voyeurs):       $55.00  (22.2%)          │  │
│  └─────────────────────────────────────────────────┘  │
│                                                        │
│  Session Details:                                      │
│  ┌──────────┬──────────┬─────────┬────────┬────────┐  │
│  │ Viewer   │ Duration │ Tier    │ Amount │ Status │  │
│  ├──────────┼──────────┼─────────┼────────┼────────┤  │
│  │ Alice    │ 15:00    │ Tier 1  │ $75.00 │ Ended  │  │
│  │ Bob      │ 15:00    │ Tier 2  │ $15.00 │ Ended  │  │
│  │ Charlie  │ 30:00    │ Tier 1  │$120.00 │ Active │  │
│  │ Dave     │ 05:00    │ Tier 1  │ $25.00 │ Ended  │  │
│  │ Eve      │ 20:00    │ Tier 2  │ $20.00 │ Active │  │
│  └──────────┴──────────┴─────────┴────────┴────────┘  │
│                                                        │
│  [Export to CSV]                                       │
└───────────────────────────────────────────────────────┘
```

### 13.3 CSV Export

The analytics endpoint supports a CSV export parameter:

```python
@router.get("/{session_id}/private-chat/analytics/export")
def export_private_chat_analytics(
    session_id: str,
    ctx=Depends(require_ui_session),
):
    """Export private chat analytics as CSV."""
    session = _get_and_validate_session(session_id)
    if session.created_by != ctx["user_sub"]:
        raise HTTPException(403, "Only the broadcaster can export analytics.")

    all_chats = _get_all_chats(session_id)
    all_voyeurs = _get_all_voyeurs(session_id)

    csv_rows = [["viewer_display_name", "tier", "duration_minutes", "amount_cents", "status", "started_at", "ended_at"]]
    for chat in all_chats:
        duration = 0
        if chat.get("started_at") and chat.get("ended_at"):
            duration = (int(chat["ended_at"]) - int(chat["started_at"])) // 60
        csv_rows.append([
            chat.get("viewer_display_name", ""),
            "1",
            str(duration),
            str(int(chat.get("total_paid_cents", 0))),
            chat.get("status", ""),
            str(int(chat.get("started_at", 0))),
            str(int(chat.get("ended_at", 0))),
        ])
    for v in all_voyeurs:
        csv_rows.append([
            v.get("viewer_display_name", ""),
            "2",
            str(int(v.get("purchased_minutes", 0))),
            str(int(v.get("total_paid_cents", 0))),
            v.get("status", ""),
            str(int(v.get("started_at", 0))),
            "",
        ])

    import io, csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerows(csv_rows)

    from fastapi.responses import StreamingResponse
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=private_chat_{session_id}.csv"},
    )
```

### 13.4 Cross-Session Analytics (Future Enhancement)

For creators who want to track private chat performance across multiple broadcasts, the creator earnings dashboard (MON-003) will aggregate private chat revenue. This is out of scope for BCAST-012 but the billing ledger entries written by this ticket (with `content_type: "private_chat"`) enable the aggregation query:

```python
# In MON-003: query billing table for all private_chat credits
resp = T.billing.query(
    KeyConditionExpression=Key("pk").eq(f"USER#{creator_id}") & Key("sk").begins_with("LEDGER#"),
    FilterExpression=Attr("meta.content_type").eq("private_chat"),
)
```

---

## 14. Acceptance Criteria (Extended)

| # | Criterion | Pass Condition |
|---|-----------|----------------|
| AC-1 | Viewer purchases tier 1 private chat | POST `/purchase` with tier=1 returns 201, `status: "active"`, correct `total_paid_cents` |
| AC-2 | Purchase debits viewer and credits creator | Billing table has DEBIT for viewer (full amount) and CREDIT for creator (minus platform fee) |
| AC-3 | Tier 1 viewer and creator exchange messages | POST `/message` succeeds for both; messages have `private_chat_id` set |
| AC-4 | Voyeur purchases tier 2 access | POST `/purchase` with tier=2 and valid `chat_id` returns 201, `tier: 2` |
| AC-5 | Voyeur cannot send messages | POST `/message` from voyeur returns 403 |
| AC-6 | Creator manages multiple concurrent chats | Up to `private_chat_max_concurrent` chats active simultaneously |
| AC-7 | Private messages not in public chat history | GET `/chat` (public) does not return messages with `private_chat_id` set |
| AC-8 | Expiring event at 1 minute remaining | SSE `private_chat:expiring` event received by tier 1 viewer and creator |
| AC-9 | Viewer extends session | POST `/extend` increases `expires_at` and writes additional billing entries |
| AC-10 | Chat auto-ends on expiry | Background task transitions chat to "ended" and ends all voyeur sessions |
| AC-11 | Creator configures rates and time blocks | PATCH `/settings` updates session-level pricing; subsequent purchases use new rates |
| AC-12 | Platform fee correctly deducted | Creator credit = `total - floor(total * fee_pct / 100)` |
| AC-13 | Voyeur count displayed to tier 1 viewer | SSE `voyeur_count_update` received; UI shows "N spectators" badge |
| AC-14 | No-voyeur premium option (if enabled) | Purchasing with `no_voyeurs: true` charges 2x rate; tier 2 purchase attempts return 403 |
| AC-15 | Auto-extend purchases time automatically | When enabled, chat extends before expiry; billing entries written; spending cap honored |
| AC-16 | Content filter blocks prohibited messages | Messages with blocked keywords return 400; flagged messages are stored and queued for review |
| AC-17 | Creator can block viewer from private chat | POST `/block` ends chat and prevents future purchases from blocked viewer |
| AC-18 | Admin can access private chat logs with justification | GET `/messages/admin` returns messages; access logged to audit trail |
| AC-19 | Analytics endpoint returns correct metrics | Revenue, duration, viewer count, tier distribution all match billing ledger totals |
| AC-20 | CSV export produces valid file | GET `/analytics/export` returns downloadable CSV with all session data |
| AC-21 | All Section 125 E2E tests pass | 5 tests covering purchase, messaging, history, voyeur restriction, creator send |
| AC-22 | All Section 126 E2E tests pass | 4 tests covering voyeur purchase, billing, extension |

---

## 15. Related Tickets

| Ticket | Relationship |
|--------|-------------|
| BCAST-005 | Public chat infrastructure reused; messages stored in same table |
| BCAST-011 | Go Private (video call) — complementary feature; BCAST-012 is text-only |
| MON-002 | Billing ledger pattern reused for purchase debit/credit |
| MON-003 | Creator earnings dashboard will aggregate private chat credits |
| MON-004 | Creator payouts include private chat revenue |
| LCOM-004 | Session-level pricing settings pattern reused for chat rate configuration |

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
