# BCAST-015: Rich Messaging Features in Broadcast Chat

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: Medium  
**Estimated effort**: 10-12 days  
**Depends on**: BCAST-005 (Live Chat), BCAST-012 (Private Chat Tiers), MON-002 (Tip Ledger Integration)

---

## 1. Overview & Motivation

### The Gap

The broadcast chat system (BCAST-005) supports only two message kinds: `text` (280-character plain text) and `product_link` (product cards from the live commerce shelf). The main messenger (`app/routers/messaging.py`, 13000+ lines) has accumulated a rich set of interactive message features over dozens of tickets -- reactions, replies, view-once, encryption, expiring messages, and locked/tipped paywalled content. None of these features exist in broadcast chat.
<!-- CORRECTED: was "12000+ lines", actually 13020 lines -->

The broadcast chat store (`app/services/broadcast_chat_store.py`, 310 lines) has a minimal item schema:
<!-- VERIFIED: app/services/broadcast_chat_store.py:310 lines (wc -l) -->

| Field | Type | Notes |
|-------|------|-------|
| `session_id` | S | PK |
| `sort_key` | S | SK — `{ts_ms:016d}#{msg_id}` |
| `message_id` | S | `cm_` + uuid4().hex |
| `sender_id` | S | User sub |
| `sender_display_name` | S | Display name at send time |
| `text` | S | Max 280 chars |
| `kind` | S | `text` or `product_link` |
| `product_link` | M | Optional product link data |
| `created_at` | N | Unix timestamp |
| `deleted` | BOOL | Soft-delete flag |
| `deleted_by` | S | Actor who deleted |
| `ttl` | N | 7-day DDB TTL |

There is no `reactions` map, no `reply_to_message_id` field, no `expires_at` timestamp, no `lock_price_cents` paywall, no `view_once` flag, and no `encryption` envelope. The `_chat_msg_out()` helper (line 296) strips the item down to just `message_id`, `session_id`, `sender_id`, `sender_display_name`, `text`, `kind`, `created_at`, and `deleted`. The SSE delivery (`broadcast_sse_publish`) sends the same flat dict to all subscribers.
<!-- VERIFIED: app/services/broadcast_chat_store.py:296 (_chat_msg_out), app/services/broadcast_sse.py:29 (broadcast_sse_publish) -->

The `BroadcastChatMessageOut` Pydantic model in `app/routers/broadcast.py` (line 1211) has no fields for reactions, replies, expiry, locking, or encryption -- only the 9 fields listed above.
<!-- VERIFIED: app/routers/broadcast.py:1211 -->

### Why This Is Needed

1. **Viewer engagement**: Reactions are the single most impactful engagement feature for live chat. Twitch, YouTube Live, and TikTok Live all support emoji reactions on chat messages. Without them, broadcast chat feels like a one-way text scroll with no way for viewers to express lightweight agreement, amusement, or excitement without typing a full message.

2. **Conversation threading**: In a fast-moving broadcast chat, messages scroll off-screen quickly. Without a reply/quote mechanism, viewers cannot reference earlier messages, ask follow-up questions, or indicate which message they are responding to. This creates fragmented, hard-to-follow conversations.

3. **Broadcaster monetization**: Locked messages allow broadcasters to gate premium content (exclusive announcements, discount codes, behind-the-scenes info) behind a per-message paywall. Tips attached to messages let viewers send monetary appreciation. Both features are already proven in the main messenger and translate naturally to the broadcast context.

4. **Ephemeral content**: Expiring messages let broadcasters send time-limited flash-sale codes, temporary announcements, or countdown-sensitive information that auto-clears from the chat after a configurable window. View-once messages enable exclusive "peek" content that each viewer can see exactly once.

5. **Feature parity with private chat**: BCAST-012 (Private Chat Tiers) introduced paid 1-on-1 text chat within broadcasts, but even private chat messages are plain text. Bringing rich messaging to both public and private broadcast chat creates a unified experience.

### Architecture After This Change

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Broadcast Chat Message (Extended Schema)                                │
│                                                                          │
│  Existing fields:                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ session_id, sort_key, message_id, sender_id, sender_display_name │   │
│  │ text, kind, product_link, created_at, deleted, deleted_by, ttl   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Phase A — Reactions:                                                    │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ reactions: { "👍": {"alice", "bob"}, "🔥": {"charlie"} }         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Phase B — Replies:                                                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ reply_to_message_id: "cm_abc123"                                  │   │
│  │ reply_to_preview: { sender_display_name: "Alice",                 │   │
│  │                     text: "Great stream!" }                       │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Phase C — Expiring Messages (broadcaster-only):                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ expires_at: 1716581400                                            │   │
│  │ (text replaced with "[This message has expired]" after expiry)    │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Phase D — Locked/Tipped Messages (broadcaster-only):                    │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ lock_price_cents: 500                                             │   │
│  │ lock_description: "Exclusive discount code"                       │   │
│  │ unlocked_by: { "alice": "unlock_xxx", "bob": "unlock_yyy" }      │   │
│  │ tip_amount_cents: 200                                             │   │
│  │ tip_total_cents: 1400                                             │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Phase E — View-Once (broadcaster-only):                                 │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ view_once: true                                                   │   │
│  │ view_once_seen: { "alice", "bob" }                                │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Phase F — Encrypted (future, private tiers only):                       │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ encryption: { version: 1, alg: "AES-256-GCM", ... }              │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### SSE Event Flow — Reactions Example

```
Viewer (Alice)              Backend                     All Viewers (SSE)
    │                         │                              │
    │ POST /sessions/{id}/    │                              │
    │   chat/{msg}/react      │                              │
    │ { emoji: "🔥" }        │                              │
    │────────────────────────>│                              │
    │                         │ DDB: ADD reactions.🔥 :u     │
    │                         │ (atomic set-add operation)   │
    │                         │                              │
    │                         │── SSE: chat:reaction ───────>│
    │                         │  { message_id, emoji: "🔥",  │
    │                         │    action: "add",            │
    │                         │    user_id: "alice",         │
    │                         │    counts: {"🔥": 3} }       │
    │   200 { ok: true }      │                              │
    │<────────────────────────│                              │
```

### Locked Message Flow — Sequence Diagram

```
Broadcaster                 Backend                     Viewer (Alice)
    │                         │                              │
    │ POST /sessions/{id}/    │                              │
    │   chat                  │                              │
    │ { text: "SECRET CODE",  │                              │
    │   lock_price_cents: 500,│                              │
    │   lock_description:     │                              │
    │   "Unlock for the code"}│                              │
    │────────────────────────>│                              │
    │                         │ DDB: write message with      │
    │                         │ lock_price_cents=500         │
    │                         │                              │
    │                         │── SSE: chat:message ────────>│
    │                         │  { text: null,               │
    │                         │    lock_price_cents: 500,    │
    │                         │    lock_description:         │
    │                         │    "Unlock for the code",    │
    │                         │    is_unlocked: false }      │
    │                         │                              │
    │                         │    Alice sees:               │
    │                         │    ┌─────────────────────┐   │
    │                         │    │ 🔒 Unlock for the   │   │
    │                         │    │   code               │   │
    │                         │    │ [Unlock for $5.00]   │   │
    │                         │    └─────────────────────┘   │
    │                         │                              │
    │                         │   POST .../chat/{msg}/unlock │
    │                         │   { payment_method_id: "..." }│
    │                         │<─────────────────────────────│
    │                         │                              │
    │                         │ Validate PM, write billing   │
    │                         │ DDB: ADD unlocked_by.alice   │
    │                         │                              │
    │                         │── SSE: chat:unlock ─────────>│
    │                         │  { message_id,               │
    │                         │    text: "SECRET CODE",      │
    │                         │    user_id: "alice" }        │
    │                         │                              │
    │                         │    Alice now sees:           │
    │                         │    ┌─────────────────────┐   │
    │                         │    │ 🔓 SECRET CODE      │   │
    │                         │    │ (Unlocked)           │   │
    │                         │    └─────────────────────┘   │
```

---

## 2. Current State Analysis

### 2.1 Broadcast Chat Messages Table (`broadcast_chat_messages`)

From `scripts/local-ddb-init.py` and `app/services/broadcast_chat_store.py`:
<!-- VERIFIED: scripts/local-ddb-init.py:557 (BroadcastChatMessages table, PK=session_id, SK=sort_key) -->
<!-- VERIFIED: app/core/tables.py:80 (T.broadcast_chat_messages handle) -->

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
| `deleted_by` | S | Who deleted it |
| `ttl` | N | DDB TTL (7 days) |

No `reactions`, `reply_to_message_id`, `expires_at`, `lock_price_cents`, `view_once`, or `encryption` fields exist. Adding these fields is backward-compatible -- existing messages without them continue to work as plain text messages.

### 2.2 Broadcast Chat Store (`app/services/broadcast_chat_store.py`, 310 lines)
<!-- VERIFIED: 310 lines (wc -l) -->

Key functions and their relevance to this ticket:

- **`send_chat_message()`** (line 136): Creates a basic text message item with `session_id`, `sort_key`, `message_id`, `sender_id`, `sender_display_name`, `text`, `created_at`, `deleted`, `ttl`. Publishes via `broadcast_sse_publish(session_id, {"_type": "chat:message", ...})`. Must be extended to accept and store reactions-related fields, reply metadata, expiry, locking, and view-once flags.
<!-- VERIFIED: app/services/broadcast_chat_store.py:136 -->

- **`send_product_link_message()`** (line 174): Same pattern with `kind="product_link"`. Unaffected by this ticket.
<!-- VERIFIED: app/services/broadcast_chat_store.py:174 -->

- **`get_chat_history()`** (line 210): Queries by `session_id` PK with `ScanIndexForward=False`, reverses for chronological display. The `FilterExpression` currently only filters `deleted != True`. Must be extended to apply expiry logic (text redaction) and per-viewer visibility (lock status, view-once consumption) at output time.
<!-- VERIFIED: app/services/broadcast_chat_store.py:210 -->

- **`_chat_msg_out()`** (line 296): Converts DDB item to output dict with 9 fields. Must be extended to include `reactions_counts`, `reply_to_message_id`, `reply_to_preview`, `expires_at`, `lock_price_cents`, `lock_description`, `is_unlocked`, `tip_amount_cents`, `tip_total_cents`, `view_once`, `view_once_consumed`, and `encryption`.
<!-- VERIFIED: app/services/broadcast_chat_store.py:296 -->

- **`_enforce_chat_rate_limit()`** (line 25): In-memory rate limiting at 1 msg/2s per user. No changes needed -- reactions and unlocks will have their own separate rate limits.
<!-- VERIFIED: app/services/broadcast_chat_store.py:25 -->

- **`_enforce_chat_mute()`** (line 117): Checks DDB `broadcast_chat_mutes` table. Muted users should still be able to react (reactions are lightweight) but not send text or reply. Design decision: muted users CAN react but CANNOT send messages, replies, or tips.
<!-- VERIFIED: app/services/broadcast_chat_store.py:117 -->

### 2.3 Broadcast Router Chat Models (`app/routers/broadcast.py`, lines 1194-1280)
<!-- VERIFIED: app/routers/broadcast.py:1197 (BroadcastChatSendIn), :1201 (BroadcastChatProductLinkOut), :1211 (BroadcastChatMessageOut) -->

Current Pydantic models:

```python
class BroadcastChatSendIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=280)

class BroadcastChatMessageOut(BaseModel):
    message_id: str
    session_id: str
    sender_id: str
    sender_display_name: str
    text: str
    kind: str = "text"
    product_link: Optional[BroadcastChatProductLinkOut] = None
    created_at: int
    deleted: bool = False
```

`BroadcastChatSendIn` accepts only `text`. No `reply_to_message_id`, `expires_in_seconds`, `lock_price_cents`, `view_once`, or `encryption` fields. The model must be extended for each phase.

`BroadcastChatMessageOut` has no `reactions_counts`, `my_reactions`, `reply_to_message_id`, `reply_to_preview`, `expires_at`, `lock_price_cents`, `is_unlocked`, `view_once`, `view_once_consumed`, `tip_amount_cents`, or `tip_total_cents` fields.

### 2.4 Messenger Reaction Pattern (`app/routers/messaging.py`, line 9835)
<!-- VERIFIED: app/routers/messaging.py:9835 (@router.post decorator), :9836 (react_to_message function def) -->

The messenger stores reactions as a DDB map: `reactions: { emoji: { user_id_set } }`. Atomic DDB `ADD` and `DELETE` operations are used to modify the per-emoji user sets:

```python
# Add reaction:
tbl_msgs.update_item(
    Key={"conversation_id": conversation_id, "message_id": message_id},
    UpdateExpression="ADD reactions.#e :u",
    ExpressionAttributeNames={"#e": inp.emoji},
    ExpressionAttributeValues={":u": {user_id}},
    ConditionExpression="attribute_exists(message_id)",
)

# Remove reaction:
tbl_msgs.update_item(
    Key={"conversation_id": conversation_id, "message_id": message_id},
    UpdateExpression="DELETE reactions.#e :u",
    ExpressionAttributeNames={"#e": inp.emoji},
    ExpressionAttributeValues={":u": {user_id}},
    ConditionExpression="attribute_exists(message_id) AND attribute_exists(reactions.#e)",
)
```

The `ReactIn` model (line 2130) accepts `emoji: str` and `action: Literal["add", "remove"]`. After mutation, a `reaction:update` event is fanned out via `fanout_event_to_conversation()`. The broadcast chat equivalent will use `broadcast_sse_publish()` instead.
<!-- VERIFIED: app/routers/messaging.py:2130 (ReactIn), :9878 (reaction:update event type) -->

The `MessageOut` model (line 2305) includes `reactions_counts: Optional[Dict[str, int]]` (line 2344) and `my_reactions: Optional[List[str]]` (line 2345). The counts are computed at read time by `_reaction_summaries()` (line 5311):
<!-- CORRECTED: was "line 2327", actually MessageOut starts at line 2305; reactions_counts at line 2344 -->
<!-- CORRECTED: was "_build_reaction_counts() (line 5312)", actually "_reaction_summaries() (line 5311)" -->

```python
reactions = message_item.get("reactions") or {}
counts = {}
mine = []
for emoji, userset in reactions.items():
    counts[emoji] = len(userset)
    if user_id in userset:
        mine.append(emoji)
```

### 2.5 Messenger Reply Pattern

The `SendTextMessageIn` model (line 1844) includes `reply_to_message_id: Optional[str]`. On send, `_validate_reply_target()` (line 5375) checks the parent message exists. The reply stores the parent `message_id` on the child message item. There is no denormalized `reply_to_preview` -- the frontend fetches the parent message separately. For broadcast chat, where message volume is higher and fetching individual messages is expensive, a denormalized `reply_to_preview` is preferred.
<!-- VERIFIED: app/routers/messaging.py:1844 (SendTextMessageIn), :1847 (reply_to_message_id field), :5375 (_validate_reply_target) -->

### 2.6 Messenger Expiry Pattern

The `SendTextMessageIn` model includes `expires_in_seconds: Optional[int] = Field(ge=10, le=604800)`. On send, `expires_at` is computed as `created_at + expires_in_seconds` and stored on the message item. At read time, `_is_expired()` (line 3667) checks `expires_at < now_ts()`. If expired, `_message_out_from_item()` (line 3745) replaces the message text with `None` and sets `expired: True` on the output.
<!-- VERIFIED: app/routers/messaging.py:1856 (expires_in_seconds field) -->
<!-- CORRECTED: was "_is_expired() (line 3668)", actually line 3667 (def), body at 3668 -->
<!-- CORRECTED: was "_message_out_from_item() (line 3782)", actually line 3745 -->

### 2.7 Messenger Lock/Unlock Pattern (`app/routers/messaging.py`, line 12472)
<!-- CORRECTED: was "line 12473", actually @router.post decorator at line 12472 -->

Locked messages have `lock_price_cents` and optional `lock_description`. The `unlock_message()` endpoint (line 12476) validates the payment method against `T.billing`, writes an `unlocked_by` map entry (`unlocked_by.{user_id} = payment_id`), and writes paired debit/credit billing ledger entries. The sender always sees `is_unlocked: true`. Other viewers see `is_unlocked: false` and `text: null` until they pay.
<!-- VERIFIED: app/routers/messaging.py:12476 (unlock_message function def), :12496 (PM validation) -->

### 2.8 Messenger View-Once Pattern

Messages with `view_once: true` use a `view_once_seen` set on the message item. The `view` endpoint (line 10197) adds the viewer's user_id to the set. `_is_view_once_consumed()` (line 3674) checks membership. Consumed messages hide their text content.
<!-- VERIFIED: app/routers/messaging.py:10197 (mark_message_viewed, note: this is the general view endpoint, not a view-once-specific endpoint), :3674 (_is_view_once_consumed) -->

### 2.9 Messenger Tip Pattern

Tips use the `TipLedgerEntry` class in `app/services/tip_ledger.py` (line 20). The `write_tip_ledger()` function (line 87) writes paired debit/credit entries to `T.billing`. Tips increment `tip_amount_cents` on the message item. For broadcast chat, tips on locked messages function as the unlock mechanism. Standalone tip-on-message ("super chat" style) is a separate action.
<!-- VERIFIED: app/services/tip_ledger.py:20 (TipLedgerEntry class), :87 (write_tip_ledger function) -->

### 2.10 Broadcast SSE Infrastructure (`app/services/broadcast_sse.py`, 49 lines)
<!-- VERIFIED: app/services/broadcast_sse.py:49 lines (wc -l), :29 (broadcast_sse_publish), :11 (broadcast_sse_subscribe), :19 (broadcast_sse_unsubscribe) -->

In-memory pub/sub. `broadcast_sse_publish(session_id, event)` fans out to all subscribers via `asyncio.Queue`. All new SSE events (`chat:reaction`, `chat:unlock`, `chat:view_once_consumed`, `chat:expired`) use this same infrastructure. No changes needed to the pub/sub mechanism itself -- only new event types are added.

### 2.11 Broadcast Chat Rate Limiting

Current rate limits (in-memory, per `{session_id}#{user_id}` key):
<!-- VERIFIED: app/core/settings.py:494 (broadcast_chat_rate_limit_ms default 2000) -->
- Text messages: 1 per 2 seconds (`S.broadcast_chat_rate_limit_ms`)
- Product links: 1 per 5 seconds

Rich features need separate rate limits:
- Reactions: 1 per 500ms (fast toggling allowed)
- Unlocks: 1 per 2 seconds (prevents accidental double-unlock)
- Tips: 1 per 5 seconds (prevents accidental double-tip)
- View-once consumption: no rate limit needed (one-shot action per message per user)

---

## 3. Technical Design

### 3.1 Extended Chat Message Schema

New fields added to the `broadcast_chat_messages` DDB table item:

| Attribute | Type | Phase | Notes |
|-----------|------|-------|-------|
| `reactions` | M | A | `{ emoji_str: SS(user_ids) }` — same pattern as messaging |
| `reply_to_message_id` | S | B | Parent message ID |
| `reply_to_preview` | M | B | `{ sender_display_name: S, text: S }` — denormalized snapshot |
| `expires_at` | N | C | Unix timestamp; text redacted after this time |
| `lock_price_cents` | N | D | Paywall price in cents |
| `lock_description` | S | D | Teaser text visible while locked |
| `unlocked_by` | M | D | `{ user_id: payment_id }` — tracks who has unlocked |
| `tip_amount_cents` | N | D | Attached tip on send (optional) |
| `tip_total_cents` | N | D | Accumulated tips from all viewers |
| `view_once` | BOOL | E | One-view content flag |
| `view_once_seen` | SS | E | Set of user_ids who have viewed |
| `encryption` | M | F | `MessageEncryptionEnvelope` equivalent |

All new fields are optional and default to absent. Existing messages without these fields are unaffected. The `_chat_msg_out()` function conditionally includes them in the output only when present.

### 3.2 Extended Pydantic Models

#### 3.2.1 Extended Send Input

```python
class BroadcastChatSendIn(BaseModel):
    """Extended chat message input supporting rich messaging features.

    Base fields (always available):
      - text: Required for plain text messages, optional when encryption provided.

    Phase A (Reactions): No send-time fields; reactions are a separate endpoint.

    Phase B (Replies):
      - reply_to_message_id: References a parent message in the same session.

    Phase C (Expiry, broadcaster-only):
      - expires_in_seconds: Message auto-expires after this many seconds (10s-7d).

    Phase D (Locked/Tipped, broadcaster-only):
      - lock_price_cents: Paywall price. Viewers must pay to see text.
      - lock_description: Teaser shown to locked viewers.
      - tip_amount_cents: Tip attached by sender (available to all senders).
      - tip_payment_method_id: PM for the attached tip.

    Phase E (View-Once, broadcaster-only):
      - view_once: Content visible to each viewer exactly once.

    Phase F (Encrypted, future):
      - encryption: AES-256-GCM encryption envelope.
    """
    text: Optional[str] = Field(default=None, min_length=1, max_length=280)
    reply_to_message_id: Optional[str] = Field(default=None, max_length=128)
    expires_in_seconds: Optional[int] = Field(default=None, ge=10, le=604800)
    lock_price_cents: Optional[int] = Field(default=None, ge=1, le=100_000)
    lock_description: Optional[str] = Field(default=None, max_length=200)
    tip_amount_cents: Optional[int] = Field(default=None, ge=1, le=100_000)
    tip_payment_method_id: Optional[str] = Field(default=None, max_length=200)
    view_once: bool = False
    encryption: Optional[MessageEncryptionEnvelope] = None
    # <!-- VERIFIED: MessageEncryptionEnvelope at app/routers/messaging.py:1790 -->

    @model_validator(mode="after")
    def _validate_shape(self):
        if self.encryption and self.text:
            raise ValueError("Provide either text or encryption, not both")
        if not self.encryption and not self.text:
            raise ValueError("text is required when encryption is not provided")
        if self.view_once and self.lock_price_cents:
            raise ValueError("view_once and lock_price_cents are mutually exclusive")
        if self.lock_price_cents and self.expires_in_seconds:
            raise ValueError("Locked messages cannot also be expiring")
        return self
```

#### 3.2.2 Extended Message Output

```python
class BroadcastChatMessageOut(BaseModel):
    """Extended chat message output with rich messaging fields.

    Per-viewer fields (computed at read time based on the requesting viewer):
      - is_unlocked: True if the viewer has paid to unlock, or if the viewer
        is the sender (senders always see their own content).
      - view_once_consumed: True if the viewer has already viewed this message.
      - my_reactions: List of emoji the requesting viewer has reacted with.

    Content visibility rules:
      - If expired: text=None, expired=True
      - If locked and not unlocked by viewer: text=None, lock_price_cents shown
      - If view_once and already consumed: text=None, view_once_consumed=True
      - Otherwise: text shown normally
    """
    message_id: str
    session_id: str
    sender_id: str
    sender_display_name: str
    text: Optional[str] = None
    kind: str = "text"
    product_link: Optional[BroadcastChatProductLinkOut] = None
    created_at: int
    deleted: bool = False

    # Phase A — Reactions
    reactions_counts: Optional[Dict[str, int]] = None
    my_reactions: Optional[List[str]] = None

    # Phase B — Replies
    reply_to_message_id: Optional[str] = None
    reply_to_preview: Optional[Dict[str, str]] = None

    # Phase C — Expiry
    expires_at: Optional[int] = None
    expired: bool = False

    # Phase D — Locked / Tipped
    lock_price_cents: Optional[int] = None
    lock_description: Optional[str] = None
    is_unlocked: bool = True  # default True = not locked
    tip_amount_cents: Optional[int] = None
    tip_total_cents: Optional[int] = None

    # Phase E — View-Once
    view_once: bool = False
    view_once_consumed: bool = False
```

#### 3.2.3 Reaction Input

```python
class BroadcastChatReactIn(BaseModel):
    """Reaction toggle on a broadcast chat message.

    Allowed emoji set is restricted for performance and UI consistency:
    👍, ❤️, 😂, 🔥, 😮, 👏 (6 fixed emoji).
    """
    emoji: str = Field(min_length=1, max_length=32)
    action: Literal["add", "remove"] = "add"

    @model_validator(mode="after")
    def _validate_emoji(self):
        allowed = {"👍", "❤️", "😂", "🔥", "😮", "👏"}
        if self.emoji not in allowed:
            raise ValueError(
                f"Emoji must be one of: {', '.join(sorted(allowed))}"
            )
        return self
```

#### 3.2.4 Unlock Input

```python
class BroadcastChatUnlockIn(BaseModel):
    """Unlock a locked broadcast chat message by paying the lock price."""
    payment_method_id: str = Field(..., min_length=1, max_length=200)
```

#### 3.2.5 Tip Input

```python
class BroadcastChatTipIn(BaseModel):
    """Send a tip on an existing broadcast chat message ('super chat' style)."""
    amount_cents: int = Field(..., ge=1, le=100_000)
    payment_method_id: str = Field(..., min_length=1, max_length=200)
```

### 3.3 API Endpoints

#### 3.3.1 Phase A — Reactions

**React to message**:

```
POST /ui/broadcast/sessions/{session_id}/chat/{message_id}/react
```

**Auth**: `require_ui_session` — any authenticated viewer.

**Request**: `BroadcastChatReactIn` (`{ emoji: "🔥", action: "add" }`)

**Behavior**:

1. Session must be `live` or `stopped` (reactions allowed during VOD replay).
2. Message must exist and not be deleted.
3. Rate limit: 1 reaction per 500ms per user per session (separate bucket from text messages).
4. Muted users CAN react (reactions are non-disruptive).
5. DDB atomic `ADD` or `DELETE` on `reactions.{emoji}` user set.
6. Compute updated reaction counts after mutation.
7. SSE event `chat:reaction` with `{ message_id, emoji, action, user_id, counts }`.

**Response**: `{ ok: true, reactions_counts: { "🔥": 3, "👍": 1 } }`

**Error responses**:

| Code | Condition | Detail |
|------|-----------|--------|
| 400 | Emoji not in allowed set | `"Emoji must be one of: ..."` |
| 400 | Message deleted or not found | `"Message not found"` |
| 429 | Reaction rate limit | `"Too many reactions. Try again shortly."` |

**Unreact** is handled by the same endpoint with `action: "remove"`. There is no separate `unreact` endpoint.

#### 3.3.2 Phase B — Replies

**No new endpoint needed.** Replies are sent via the existing `POST /sessions/{id}/chat` endpoint with the `reply_to_message_id` field populated in `BroadcastChatSendIn`.

**Server-side behavior on send with reply_to_message_id**:

1. Validate the referenced message exists in the same session and is not deleted.
2. Fetch the parent message to build `reply_to_preview`:
   ```python
   reply_to_preview = {
       "sender_display_name": parent["sender_display_name"],
       "text": parent["text"][:100] if parent.get("text") else "[Hidden content]",
   }
   ```
3. Store `reply_to_message_id` and `reply_to_preview` on the new message item.
4. The SSE `chat:message` event includes `reply_to_message_id` and `reply_to_preview`.

**Truncation**: Parent text is truncated to 100 characters in the preview to limit DDB item size and UI rendering. If the parent message is locked and the replier has not unlocked it, the preview shows `"[Locked message]"`. If expired, the preview shows `"[This message has expired]"`. If view-once, the preview shows `"[View-once message]"`.

#### 3.3.3 Phase C — Expiring Messages

**No new endpoint needed.** Expiring messages are sent via the existing `POST /sessions/{id}/chat` endpoint with `expires_in_seconds` populated.

**Authorization**: Only the session creator (broadcaster) can send expiring messages. If a non-broadcaster sends `expires_in_seconds`, return 403.

**Server-side behavior on send**:

1. Compute `expires_at = created_at + expires_in_seconds`.
2. Store `expires_at` on the message item.
3. DDB TTL is set to `min(default_ttl, expires_at + 3600)` — the message is physically deleted 1 hour after expiry (grace period for late-loading clients).

**Read-time behavior in `_chat_msg_out()`**:

```python
if item.get("expires_at") and int(item["expires_at"]) < now_ts():
    out["text"] = None
    out["expired"] = True
```

**SSE event**: The standard `chat:message` event includes `expires_at`. The frontend runs a client-side countdown timer. No server-side push is needed at the moment of expiry -- the frontend hides expired messages locally based on the timestamp.

#### 3.3.4 Phase D — Locked Messages

**Send locked message** (via existing send endpoint with `lock_price_cents`):

**Authorization**: Only the session creator can send locked messages.

**Server-side behavior on send**:

1. Store `lock_price_cents`, `lock_description`, and `unlocked_by` (empty map `{}`) on the item.
2. The SSE `chat:message` event for other viewers has `text: null` and `is_unlocked: false`. The broadcaster and the sender see `text` and `is_unlocked: true`.

**Unlock locked message**:

```
POST /ui/broadcast/sessions/{session_id}/chat/{message_id}/unlock
```

**Auth**: `require_ui_session` — any authenticated viewer except the sender.

**Request**: `BroadcastChatUnlockIn` (`{ payment_method_id: "pm_visa_4242" }`)

**Behavior**:

1. Message must exist, have `lock_price_cents > 0`, and not be deleted.
2. Caller must NOT be the message sender (sender always sees their own content).
3. Caller must not have already unlocked (check `unlocked_by` map).
4. Validate `payment_method_id` exists in `T.billing` for the user.
5. Rate limit: 1 unlock per 2 seconds per user per session.
6. Write billing ledger entries:
   - DEBIT: `USER#{viewer_id}` for `lock_price_cents`
   - CREDIT: `USER#{broadcaster_id}` for `lock_price_cents * (1 - platform_fee_pct / 100)`
7. DDB: `SET unlocked_by.#uid = :pid` (atomic map entry add).
8. SSE event `chat:unlock` with `{ message_id, user_id, text }` — targeted to the unlocking viewer (other viewers ignore via client-side filter on `user_id`).

**Response**:

```python
class BroadcastChatUnlockOut(BaseModel):
    ok: bool = True
    message_id: str
    text: str
    unlock_payment_id: str
    amount_cents: int
```

**Error responses**:

| Code | Condition | Detail |
|------|-----------|--------|
| 400 | Message not locked | `"Message is not locked"` |
| 400 | Already unlocked | `"Already unlocked"` |
| 400 | Sender trying to unlock own | `"Sender cannot unlock their own message"` |
| 400 | Payment method not found | `"Payment method not found"` |

#### 3.3.5 Phase D — Tips on Messages

**Tip a message** ("super chat" style, available to all viewers on any non-deleted message):

```
POST /ui/broadcast/sessions/{session_id}/chat/{message_id}/tip
```

**Auth**: `require_ui_session` — any authenticated viewer.

**Request**: `BroadcastChatTipIn` (`{ amount_cents: 500, payment_method_id: "pm_123" }`)

**Behavior**:

1. Message must exist and not be deleted.
2. Caller must NOT be the message sender (cannot tip yourself).
3. Validate payment method.
4. Rate limit: 1 tip per 5 seconds per user per session.
5. Write billing ledger entries (debit tipper, credit broadcaster).
6. DDB: Atomic increment `tip_total_cents` by `amount_cents`.
   ```python
   T.broadcast_chat_messages.update_item(
       Key={"session_id": session_id, "sort_key": sort_key},
       UpdateExpression="ADD tip_total_cents :amt",
       ExpressionAttributeValues={":amt": amount_cents},
   )
   ```
7. SSE event `chat:tip` with `{ message_id, tipper_id, tipper_display_name, amount_cents, new_total_cents }`.

**Response**:

```python
class BroadcastChatTipOut(BaseModel):
    ok: bool = True
    message_id: str
    tip_payment_id: str
    amount_cents: int
    new_total_cents: int
```

#### 3.3.6 Phase E — View-Once

**Send view-once message** (via existing send endpoint with `view_once: true`):

**Authorization**: Only the session creator can send view-once messages.

**Server-side behavior on send**:

1. Store `view_once: true` on the item. Do NOT store an empty `view_once_seen` set (DynamoDB rejects empty sets).
2. The SSE `chat:message` event includes `view_once: true` and `text: null` for all viewers (text hidden until viewed).

**Mark view-once as consumed**:

```
POST /ui/broadcast/sessions/{session_id}/chat/{message_id}/view
```

**Auth**: `require_ui_session` — any authenticated viewer except the sender.

**Behavior**:

1. Message must have `view_once: true`.
2. Caller must not have already viewed (check `view_once_seen` set).
3. DDB: Atomic `ADD view_once_seen :u`.
4. Return the full message text in the response (this is the one-time reveal).
5. SSE event `chat:view_once_consumed` with `{ message_id, user_id }` — so the frontend can update the UI for that viewer.

**Response**:

```python
class BroadcastChatViewOnceOut(BaseModel):
    ok: bool = True
    message_id: str
    text: str
    view_once_consumed: bool = True
```

### 3.4 Service Layer — `app/services/broadcast_chat_rich.py`
<!-- NEW: to be created -->

New service file (~500 lines) for rich messaging business logic, separated from the base `broadcast_chat_store.py` to keep the original file unchanged and allow independent phase rollbacks.

```python
"""Broadcast chat rich messaging features — reactions, replies, expiry,
locking, tipping, and view-once for broadcast chat messages (BCAST-015)."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Set

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish

logger = logging.getLogger("broadcast.chat.rich")

# ─── Allowed Reactions ────────────────────────────────────────────

ALLOWED_REACTIONS: Set[str] = {"👍", "❤️", "😂", "🔥", "😮", "👏"}

# ─── Rate Limiting (separate buckets from text messages) ──────────

_REACTION_RATE_LOCK = threading.Lock()
_REACTION_RATE_BUCKETS: Dict[str, int] = {}
_REACTION_RATE_MS = 500  # 1 reaction per 500ms

_UNLOCK_RATE_LOCK = threading.Lock()
_UNLOCK_RATE_BUCKETS: Dict[str, int] = {}
_UNLOCK_RATE_MS = 2000  # 1 unlock per 2s

_TIP_RATE_LOCK = threading.Lock()
_TIP_RATE_BUCKETS: Dict[str, int] = {}
_TIP_RATE_MS = 5000  # 1 tip per 5s


def _enforce_rate_limit(
    buckets: Dict[str, int],
    lock: threading.Lock,
    key: str,
    limit_ms: int,
    code: str,
    message: str,
) -> None:
    """Generic in-memory rate limiter."""
    now_ms = int(time.time() * 1000)
    with lock:
        last = buckets.get(key, 0)
        if now_ms - last < limit_ms:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": code,
                    "message": message,
                    "retry_after_ms": limit_ms - (now_ms - last),
                },
            )
        buckets[key] = now_ms


# ─── Phase A: Reactions ──────────────────────────────────────────

def react_to_chat_message(
    session_id: str,
    message_id: str,
    user_id: str,
    emoji: str,
    action: str,  # "add" or "remove"
) -> Dict[str, Any]:
    """Add or remove a reaction on a broadcast chat message.

    Uses DDB atomic ADD/DELETE on the reactions map.
    Publishes chat:reaction SSE event with updated counts.

    Returns dict with ok=True and updated reactions_counts.
    """
    if emoji not in ALLOWED_REACTIONS:
        raise HTTPException(400, f"Emoji not allowed. Use one of: {ALLOWED_REACTIONS}")

    _enforce_rate_limit(
        _REACTION_RATE_BUCKETS, _REACTION_RATE_LOCK,
        f"{session_id}#{user_id}", _REACTION_RATE_MS,
        "BROADCAST_REACTION_RATE_LIMITED",
        "Too many reactions. Try again shortly.",
    )

    sort_key = _find_sort_key(session_id, message_id)
    if not sort_key:
        raise HTTPException(400, "Message not found")

    expr_names = {"#e": emoji}

    try:
        if action == "add":
            T.broadcast_chat_messages.update_item(
                Key={"session_id": session_id, "sort_key": sort_key},
                UpdateExpression="ADD reactions.#e :u",
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues={":u": {user_id}},
            )
        else:
            T.broadcast_chat_messages.update_item(
                Key={"session_id": session_id, "sort_key": sort_key},
                UpdateExpression="DELETE reactions.#e :u",
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues={":u": {user_id}},
            )
    except Exception as e:
        logger.warning("broadcast.chat.react_failed: %s", str(e))
        raise HTTPException(400, f"Reaction update failed: {str(e)}")

    # Re-fetch to compute updated counts
    item = T.broadcast_chat_messages.get_item(
        Key={"session_id": session_id, "sort_key": sort_key}
    ).get("Item", {})
    counts = _build_reaction_counts(item)

    broadcast_sse_publish(session_id, {
        "_type": "chat:reaction",
        "message_id": message_id,
        "emoji": emoji,
        "action": action,
        "user_id": user_id,
        "counts": counts,
    })

    return {"ok": True, "reactions_counts": counts}


# ─── Phase D: Unlock ─────────────────────────────────────────────

def unlock_chat_message(
    session_id: str,
    message_id: str,
    user_id: str,
    payment_method_id: str,
    broadcaster_id: str,
) -> Dict[str, Any]:
    """Unlock a locked broadcast chat message by paying the lock price.

    Validates PM, writes billing debit/credit, updates unlocked_by map.
    Publishes chat:unlock SSE event targeted to the unlocking viewer.

    Returns dict with ok, text, unlock_payment_id, amount_cents.
    """
    _enforce_rate_limit(
        _UNLOCK_RATE_BUCKETS, _UNLOCK_RATE_LOCK,
        f"{session_id}#{user_id}", _UNLOCK_RATE_MS,
        "BROADCAST_UNLOCK_RATE_LIMITED",
        "Unlock rate limited. Try again shortly.",
    )

    sort_key = _find_sort_key(session_id, message_id)
    if not sort_key:
        raise HTTPException(400, "Message not found")

    item = T.broadcast_chat_messages.get_item(
        Key={"session_id": session_id, "sort_key": sort_key}
    ).get("Item")
    if not item:
        raise HTTPException(400, "Message not found")
    if not item.get("lock_price_cents"):
        raise HTTPException(400, "Message is not locked")
    if item.get("sender_id") == user_id:
        raise HTTPException(400, "Sender cannot unlock their own message")
    if user_id in (item.get("unlocked_by") or {}):
        raise HTTPException(400, "Already unlocked")

    # Validate payment method
    pm_item = T.billing.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"PM#{payment_method_id}"}
    ).get("Item")
    if not pm_item:
        raise HTTPException(400, "Payment method not found")

    amount_cents = int(item["lock_price_cents"])
    unlock_payment_id = "bcunlock_" + uuid.uuid4().hex

    # Write billing
    _write_chat_billing(
        payer_id=user_id,
        recipient_id=broadcaster_id,
        amount_cents=amount_cents,
        reason="Broadcast chat message unlock",
        content_type="broadcast_chat_unlock",
        content_id=message_id,
        session_id=session_id,
        payment_method_id=payment_method_id,
    )

    # Update DDB
    T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": sort_key},
        UpdateExpression="SET unlocked_by.#uid = :pid",
        ExpressionAttributeNames={"#uid": user_id},
        ExpressionAttributeValues={":pid": unlock_payment_id},
    )

    broadcast_sse_publish(session_id, {
        "_type": "chat:unlock",
        "message_id": message_id,
        "user_id": user_id,
        "text": item.get("text", ""),
    })

    return {
        "ok": True,
        "message_id": message_id,
        "text": item.get("text", ""),
        "unlock_payment_id": unlock_payment_id,
        "amount_cents": amount_cents,
    }


# ─── Phase D: Tips ───────────────────────────────────────────────

def tip_chat_message(
    session_id: str,
    message_id: str,
    tipper_id: str,
    tipper_display_name: str,
    amount_cents: int,
    payment_method_id: str,
    broadcaster_id: str,
) -> Dict[str, Any]:
    """Send a tip on a broadcast chat message ('super chat' style).

    Validates PM, writes billing, atomically increments tip_total_cents.
    Publishes chat:tip SSE event.
    """
    _enforce_rate_limit(
        _TIP_RATE_BUCKETS, _TIP_RATE_LOCK,
        f"{session_id}#{tipper_id}", _TIP_RATE_MS,
        "BROADCAST_TIP_RATE_LIMITED",
        "Tip rate limited. Try again shortly.",
    )

    sort_key = _find_sort_key(session_id, message_id)
    if not sort_key:
        raise HTTPException(400, "Message not found")

    item = T.broadcast_chat_messages.get_item(
        Key={"session_id": session_id, "sort_key": sort_key}
    ).get("Item")
    if not item:
        raise HTTPException(400, "Message not found")
    if item.get("sender_id") == tipper_id:
        raise HTTPException(400, "Cannot tip your own message")

    # Validate payment method
    pm_item = T.billing.get_item(
        Key={"pk": f"USER#{tipper_id}", "sk": f"PM#{payment_method_id}"}
    ).get("Item")
    if not pm_item:
        raise HTTPException(400, "Payment method not found")

    tip_payment_id = "bctip_" + uuid.uuid4().hex

    _write_chat_billing(
        payer_id=tipper_id,
        recipient_id=broadcaster_id,
        amount_cents=amount_cents,
        reason="Broadcast chat tip",
        content_type="broadcast_chat_tip",
        content_id=message_id,
        session_id=session_id,
        payment_method_id=payment_method_id,
    )

    # Atomic increment tip_total_cents
    resp = T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": sort_key},
        UpdateExpression="ADD tip_total_cents :amt",
        ExpressionAttributeValues={":amt": amount_cents},
        ReturnValues="UPDATED_NEW",
    )
    new_total = int(resp.get("Attributes", {}).get("tip_total_cents", amount_cents))

    broadcast_sse_publish(session_id, {
        "_type": "chat:tip",
        "message_id": message_id,
        "tipper_id": tipper_id,
        "tipper_display_name": tipper_display_name,
        "amount_cents": amount_cents,
        "new_total_cents": new_total,
    })

    return {
        "ok": True,
        "message_id": message_id,
        "tip_payment_id": tip_payment_id,
        "amount_cents": amount_cents,
        "new_total_cents": new_total,
    }


# ─── Phase E: View-Once ──────────────────────────────────────────

def consume_view_once_chat_message(
    session_id: str,
    message_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Mark a view-once broadcast chat message as consumed for this viewer.

    Returns the full message text (one-time reveal).
    """
    sort_key = _find_sort_key(session_id, message_id)
    if not sort_key:
        raise HTTPException(400, "Message not found")

    item = T.broadcast_chat_messages.get_item(
        Key={"session_id": session_id, "sort_key": sort_key}
    ).get("Item")
    if not item:
        raise HTTPException(400, "Message not found")
    if not item.get("view_once"):
        raise HTTPException(400, "Message is not view-once")
    if item.get("sender_id") == user_id:
        raise HTTPException(400, "Sender does not need to consume their own view-once message")

    seen = item.get("view_once_seen") or set()
    if user_id in seen:
        raise HTTPException(400, "Already viewed")

    T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": sort_key},
        UpdateExpression="ADD view_once_seen :u",
        ExpressionAttributeValues={":u": {user_id}},
    )

    broadcast_sse_publish(session_id, {
        "_type": "chat:view_once_consumed",
        "message_id": message_id,
        "user_id": user_id,
    })

    return {
        "ok": True,
        "message_id": message_id,
        "text": item.get("text", ""),
        "view_once_consumed": True,
    }


# ─── Helpers ─────────────────────────────────────────────────────

def _find_sort_key(session_id: str, message_id: str) -> Optional[str]:
    """Find sort_key by message_id. Delegates to broadcast_chat_store."""
    from app.services.broadcast_chat_store import _find_sort_key as _find
    return _find(session_id, message_id)


def _build_reaction_counts(item: Dict[str, Any]) -> Dict[str, int]:
    """Compute reaction emoji counts from the reactions DDB map."""
    reactions = item.get("reactions") or {}
    counts: Dict[str, int] = {}
    for emoji, user_set in reactions.items():
        if isinstance(user_set, set):
            counts[emoji] = len(user_set)
        elif isinstance(user_set, dict):
            # DDB may return a dict for SS in some deserialization modes
            counts[emoji] = len(user_set)
    return counts


def _get_my_reactions(item: Dict[str, Any], user_id: str) -> List[str]:
    """Get list of emoji the given user has reacted with."""
    reactions = item.get("reactions") or {}
    mine: List[str] = []
    for emoji, user_set in reactions.items():
        if user_id in user_set:
            mine.append(emoji)
    return mine


def _write_chat_billing(
    payer_id: str,
    recipient_id: str,
    amount_cents: int,
    reason: str,
    content_type: str,
    content_id: str,
    session_id: str,
    payment_method_id: str,
) -> tuple:
    """Write paired debit/credit billing ledger entries.

    Follows the same pattern as tip_ledger.write_tip_ledger()
    and broadcast_private_chat._write_private_chat_billing().
    """
    ts = now_ts()
    debit_id = uuid.uuid4().hex
    credit_id = uuid.uuid4().hex
    platform_fee_pct = 20  # 20% platform fee
    creator_amount = int(amount_cents * (100 - platform_fee_pct) / 100)

    meta = {
        "content_type": content_type,
        "content_id": content_id,
        "session_id": session_id,
        "payer_id": payer_id,
        "recipient_id": recipient_id,
        "payment_method_id": payment_method_id,
    }

    try:
        T.billing.put_item(Item={
            "pk": f"USER#{payer_id}",
            "sk": f"LEDGER#{ts}#{debit_id}",
            "entry_id": debit_id,
            "ts": ts,
            "type": "debit",
            "amount_cents": amount_cents,
            "currency": "USD",
            "state": "settled",
            "reason": reason,
            "meta": meta,
        })
    except Exception:
        logger.warning("broadcast_chat_billing_debit_failed payer=%s amount=%d", payer_id, amount_cents)

    try:
        T.billing.put_item(Item={
            "pk": f"USER#{recipient_id}",
            "sk": f"LEDGER#{ts}#{credit_id}",
            "entry_id": credit_id,
            "ts": ts,
            "type": "credit",
            "amount_cents": creator_amount,
            "currency": "USD",
            "state": "settled",
            "reason": reason,
            "meta": meta,
        })
    except Exception:
        logger.warning("broadcast_chat_billing_credit_failed recipient=%s amount=%d", recipient_id, creator_amount)

    return debit_id, credit_id


def reset_rich_rate_limits() -> None:
    """Clear all rich-feature rate limit state (for tests)."""
    with _REACTION_RATE_LOCK:
        _REACTION_RATE_BUCKETS.clear()
    with _UNLOCK_RATE_LOCK:
        _UNLOCK_RATE_BUCKETS.clear()
    with _TIP_RATE_LOCK:
        _TIP_RATE_BUCKETS.clear()
```

### 3.5 Extended `_chat_msg_out()` — Per-Viewer Message Rendering

The existing `_chat_msg_out()` in `broadcast_chat_store.py` must be extended to accept a `viewer_user_id` parameter and apply per-viewer visibility rules. A new function `chat_msg_out_rich()` handles this:

```python
def chat_msg_out_rich(
    item: Dict[str, Any],
    viewer_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Convert DDB item to output dict with rich messaging fields.

    Applies per-viewer content visibility rules:
    1. Expired messages: text=None, expired=True
    2. Locked messages (viewer has not unlocked): text=None, is_unlocked=False
    3. View-once messages (viewer has consumed): text=None, view_once_consumed=True
    4. View-once messages (viewer has not consumed): text=None (hidden until consumed)
    5. Sender always sees their own content regardless of lock/view-once/expiry.
    """
    ts = now_ts()
    sender_id = item.get("sender_id", "")
    is_sender = viewer_user_id == sender_id

    # Base fields
    out: Dict[str, Any] = {
        "message_id": item["message_id"],
        "session_id": item["session_id"],
        "sender_id": sender_id,
        "sender_display_name": item.get("sender_display_name", ""),
        "text": item.get("text", ""),
        "kind": item.get("kind", "text"),
        "created_at": int(item.get("created_at", 0)),
        "deleted": bool(item.get("deleted", False)),
    }

    if item.get("product_link"):
        out["product_link"] = item["product_link"]

    # Phase A — Reactions
    reactions = item.get("reactions") or {}
    if reactions:
        counts: Dict[str, int] = {}
        mine: List[str] = []
        for emoji, user_set in reactions.items():
            count = len(user_set) if isinstance(user_set, (set, dict)) else 0
            if count > 0:
                counts[emoji] = count
            if viewer_user_id and viewer_user_id in user_set:
                mine.append(emoji)
        if counts:
            out["reactions_counts"] = counts
        if mine:
            out["my_reactions"] = mine

    # Phase B — Replies
    if item.get("reply_to_message_id"):
        out["reply_to_message_id"] = item["reply_to_message_id"]
    if item.get("reply_to_preview"):
        out["reply_to_preview"] = item["reply_to_preview"]

    # Phase C — Expiry
    expires_at = item.get("expires_at")
    if expires_at:
        out["expires_at"] = int(expires_at)
        if int(expires_at) < ts and not is_sender:
            out["text"] = None
            out["expired"] = True

    # Phase D — Locked messages
    lock_price = item.get("lock_price_cents")
    if lock_price:
        out["lock_price_cents"] = int(lock_price)
        out["lock_description"] = item.get("lock_description")
        unlocked_by = item.get("unlocked_by") or {}
        is_unlocked = is_sender or (viewer_user_id in unlocked_by)
        out["is_unlocked"] = is_unlocked
        if not is_unlocked:
            out["text"] = None

    # Phase D — Tips
    if item.get("tip_amount_cents"):
        out["tip_amount_cents"] = int(item["tip_amount_cents"])
    if item.get("tip_total_cents"):
        out["tip_total_cents"] = int(item["tip_total_cents"])

    # Phase E — View-once
    if item.get("view_once"):
        out["view_once"] = True
        seen = item.get("view_once_seen") or set()
        consumed = not is_sender and viewer_user_id in seen
        out["view_once_consumed"] = consumed
        if not is_sender:
            # Text is only revealed via the consume endpoint response,
            # never in the list/history endpoint.
            out["text"] = None

    return out
```

### 3.6 SSE Events — Full Reference

| Event Type | Phase | Payload | Trigger | Recipients |
|------------|-------|---------|---------|------------|
| `chat:reaction` | A | `{ message_id, emoji, action, user_id, counts }` | Viewer reacts | All viewers (SSE fan-out) |
| `chat:message` | B,C,D,E | Extended `BroadcastChatMessageOut` with `reply_to_*`, `expires_at`, `lock_*`, `view_once` | New message sent | All viewers (per-viewer fields not included in SSE; client requests full message if needed) |
| `chat:unlock` | D | `{ message_id, user_id, text }` | Viewer unlocks message | All viewers (client-side filter: only the unlocking viewer shows the text) |
| `chat:tip` | D | `{ message_id, tipper_id, tipper_display_name, amount_cents, new_total_cents }` | Viewer tips message | All viewers |
| `chat:view_once_consumed` | E | `{ message_id, user_id }` | Viewer consumes view-once | All viewers (client-side: consuming viewer updates their local state) |

**Client-side filtering for `chat:unlock`**: The SSE event includes the full `text` and the `user_id` who unlocked. All viewers receive the event. The frontend checks `event.user_id === currentUserId` — only the matching viewer reveals the text. This avoids creating per-user SSE channels while keeping the text secret from other viewers. The text is exposed in the SSE payload, but since SSE connections require authenticated sessions, only authenticated viewers of the broadcast can see the SSE stream. For production hardening, the `text` field could be omitted from the SSE event and the viewer could re-fetch the message via GET (accepting the latency tradeoff).

### 3.7 Frontend — Reaction Bar Component
<!-- NEW: to be created -->

```typescript
// frontend/src/pages/broadcast/ChatReactionBar.tsx

/**
 * ChatReactionBar — renders reaction counts below a chat message
 * and provides click-to-toggle for each emoji.
 *
 * Props:
 *   messageId: string
 *   sessionId: string
 *   reactionsCountsMap: Record<string, number> | null
 *   myReactions: string[] | null
 *
 * Renders a row of emoji buttons. Each shows the emoji + count.
 * Active reactions (in myReactions) are highlighted.
 * Clicking toggles add/remove via POST .../react.
 *
 * The "+" button at the end opens a popover with all 6 allowed emoji
 * for adding a new reaction type that doesn't yet have any count.
 *
 * Optimistic updates: on click, immediately update local state,
 * revert on error.
 */
```

### 3.8 Frontend — Reply Quote Component
<!-- NEW: to be created -->

```typescript
// frontend/src/pages/broadcast/ChatReplyQuote.tsx

/**
 * ChatReplyQuote — renders a quoted parent message above the reply.
 *
 * Props:
 *   replyToPreview: { sender_display_name: string, text: string } | null
 *
 * Renders:
 *   ┌──────────────────────────────────┐
 *   │ ↳ Alice: Great stream today!     │
 *   └──────────────────────────────────┘
 *
 * For hidden content, shows placeholder:
 *   ↳ Alice: [Locked message]
 *   ↳ Alice: [This message has expired]
 *   ↳ Alice: [View-once message]
 *
 * Clicking the quote scrolls to the parent message (if still in view).
 */
```

### 3.9 Frontend — Locked Message Card
<!-- NEW: to be created -->

```typescript
// frontend/src/pages/broadcast/ChatLockedCard.tsx

/**
 * ChatLockedCard — renders a locked message paywall card.
 *
 * Props:
 *   messageId: string
 *   sessionId: string
 *   lockPriceCents: number
 *   lockDescription: string | null
 *   isUnlocked: boolean
 *
 * When locked (isUnlocked=false):
 *   ┌──────────────────────────────────┐
 *   │ 🔒 Exclusive discount code       │
 *   │                                   │
 *   │ [Unlock for $5.00]               │
 *   └──────────────────────────────────┘
 *
 * Clicking "Unlock" opens a PM selector dialog (same pattern as
 * MessageBubble unlock in messages). On success, reveals the text
 * and updates the card to show unlocked state.
 *
 * When unlocked (isUnlocked=true):
 *   ┌──────────────────────────────────┐
 *   │ 🔓 SECRET_CODE_XYZ              │
 *   │ (Unlocked)                       │
 *   └──────────────────────────────────┘
 */
```

### 3.10 Frontend — View-Once Message
<!-- NEW: to be created -->

```typescript
// frontend/src/pages/broadcast/ChatViewOnceCard.tsx

/**
 * ChatViewOnceCard — renders a view-once message that reveals on tap.
 *
 * Props:
 *   messageId: string
 *   sessionId: string
 *   viewOnce: boolean
 *   viewOnceConsumed: boolean
 *   text: string | null (null until consumed)
 *
 * Before consumption:
 *   ┌──────────────────────────────────┐
 *   │ 👁 View-once message             │
 *   │ [Tap to view once]              │
 *   └──────────────────────────────────┘
 *
 * Clicking triggers POST .../view. Response contains the text.
 * Text shown for 10 seconds in an overlay, then hidden:
 *   ┌──────────────────────────────────┐
 *   │ 👁 The secret is...              │
 *   │ (Auto-hiding in 8s)             │
 *   └──────────────────────────────────┘
 *
 * After consumption:
 *   ┌──────────────────────────────────┐
 *   │ 👁 Already viewed                │
 *   └──────────────────────────────────┘
 */
```

### 3.11 Frontend — Tip Badge
<!-- NEW: to be created -->

```typescript
// frontend/src/pages/broadcast/ChatTipBadge.tsx

/**
 * ChatTipBadge — shows accumulated tips on a message.
 *
 * Props:
 *   tipTotalCents: number | null
 *   tipAmountCents: number | null  (attached tip from sender)
 *
 * Renders below the message text:
 *   💰 $14.00 in tips
 *
 * If tipAmountCents (attached by sender):
 *   💰 $2.00 tip attached · $14.00 total
 *
 * A "Tip" button next to the badge opens a tip dialog where the
 * viewer selects an amount and payment method.
 */
```

### 3.12 Frontend Component Integration — ChatMessageRow Extension
<!-- CORRECTED: ChatMessageRow.tsx does not exist as a separate component. Message rendering is currently inline in BroadcastChat.tsx. This component must be extracted or created from scratch. -->

The `ChatMessageRow.tsx` component renders a single chat message. It must be extracted from the inline rendering in `BroadcastChat.tsx` (from BCAST-005) and extended to conditionally render:

```
ChatMessageRow
├── ChatReplyQuote (if reply_to_message_id present)
├── Message text (or locked/expired/view-once placeholder)
│   ├── ChatLockedCard (if lock_price_cents && !is_unlocked)
│   ├── ChatViewOnceCard (if view_once)
│   ├── "[This message has expired]" (if expired)
│   └── Plain text (default)
├── ChatReactionBar (always rendered; empty state shows "+")
├── ChatTipBadge (if tip_total_cents > 0)
└── Moderation controls (delete, mute — broadcaster only)
```

### 3.13 Frontend — Compose Bar Extension

The `BroadcastChat` compose input area is extended for broadcasters only:

```
ComposeInput (extended for broadcaster)
├── Text input (280 chars, unchanged)
├── Reply indicator (shows quoted message, with X to cancel reply)
├── Feature toggles (broadcaster-only, hidden for regular viewers):
│   ├── ⏱ Expiry toggle → time picker (10s–7d)
│   ├── 🔒 Lock toggle → price input (cents)
│   ├── 👁 View-once toggle
│   └── 💰 Attach tip → amount input (available to all senders)
└── Send button
```

**Reply flow**: Viewer clicks reply icon on a message → compose bar shows reply quote + text input. The `reply_to_message_id` is attached to the send request. Available to all viewers, not just the broadcaster.

---

## 4. Implementation Plan

### Phase A: Reactions (2 days)

| Day | File | Change | Lines |
|-----|------|--------|-------|
| 1 | `app/services/broadcast_chat_rich.py` | Create — `react_to_chat_message()`, `_build_reaction_counts()`, `_get_my_reactions()`, rate limiting. | ~120 | <!-- NEW: to be created -->
| 1 | `app/routers/broadcast.py` | Add `BroadcastChatReactIn` model. Add `POST /sessions/{id}/chat/{msg_id}/react` endpoint. | +40 |
| 1 | `app/services/broadcast_chat_store.py` | Extend `_chat_msg_out()` to include `reactions_counts` and `my_reactions` (or add `chat_msg_out_rich()` alongside). | +25 |
| 2 | `frontend/src/pages/broadcast/ChatReactionBar.tsx` | Create — reaction bar component with click-to-toggle. | ~100 | <!-- NEW: to be created -->
| 2 | `frontend/src/pages/broadcast/ChatMessageRow.tsx` | Create (extract from BroadcastChat.tsx) — integrate `ChatReactionBar` below each message. | +15 | <!-- CORRECTED: does not exist yet; must be extracted from BroadcastChat.tsx -->
| 2 | `frontend/src/api/endpoints/broadcast-chat.ts` | Add `reactToChatMessage(sessionId, messageId, emoji, action)` wrapper. | +10 | <!-- VERIFIED: file exists -->
| 2 | `frontend/src/pages/broadcast/BroadcastChat.tsx` | Handle `chat:reaction` SSE event — update local reaction counts. | +20 | <!-- VERIFIED: file exists -->

### Phase B: Replies (1.5 days)

| Day | File | Change | Lines |
|-----|------|--------|-------|
| 3 | `app/services/broadcast_chat_store.py` | Extend `send_chat_message()` to accept `reply_to_message_id`, validate parent, build `reply_to_preview`, store both fields. | +35 |
| 3 | `app/routers/broadcast.py` | Extend `BroadcastChatSendIn` with `reply_to_message_id`. Extend `BroadcastChatMessageOut` with `reply_to_message_id` and `reply_to_preview`. | +10 |
| 3 | `frontend/src/pages/broadcast/ChatReplyQuote.tsx` | Create — reply quote component. | ~60 | <!-- NEW: to be created -->
| 3-4 | `frontend/src/pages/broadcast/ChatMessageRow.tsx` | Modify — render `ChatReplyQuote` when `reply_to_message_id` is present. Add reply icon button. | +20 |
| 4 | `frontend/src/pages/broadcast/BroadcastChat.tsx` | Add reply state to compose bar (selectedReplyMessage). Attach `reply_to_message_id` to send payload. Show cancel reply button. | +30 |

### Phase C: Expiring Messages (1.5 days)

| Day | File | Change | Lines |
|-----|------|--------|-------|
| 4 | `app/services/broadcast_chat_store.py` | Extend `send_chat_message()` to accept `expires_in_seconds`, compute and store `expires_at`. Enforce broadcaster-only. | +20 |
| 4 | `app/services/broadcast_chat_store.py` | Extend `_chat_msg_out()` / `chat_msg_out_rich()` to check `expires_at < now` and redact text. | +10 |
| 4 | `app/routers/broadcast.py` | Extend `BroadcastChatSendIn` with `expires_in_seconds`. Extend `BroadcastChatMessageOut` with `expires_at` and `expired`. | +8 |
| 5 | `frontend/src/pages/broadcast/ChatMessageRow.tsx` | Modify — show countdown timer for expiring messages. Show `[This message has expired]` when expired. Client-side timer using `setInterval`. | +40 |
| 5 | `frontend/src/pages/broadcast/BroadcastChat.tsx` | Add expiry toggle to broadcaster compose bar. Time picker (dropdown: 30s, 1m, 5m, 15m, 1h, 24h). | +30 |

### Phase D: Locked Messages and Tips (3.5 days)

| Day | File | Change | Lines |
|-----|------|--------|-------|
| 5-6 | `app/services/broadcast_chat_rich.py` | Add `unlock_chat_message()`, `tip_chat_message()`, `_write_chat_billing()`. | +180 |
| 6 | `app/services/broadcast_chat_store.py` | Extend `send_chat_message()` to accept `lock_price_cents`, `lock_description`, `tip_amount_cents`, `tip_payment_method_id`. Store `unlocked_by: {}` for locked messages. Process attached tip billing on send. | +40 |
| 6 | `app/routers/broadcast.py` | Add `BroadcastChatUnlockIn`, `BroadcastChatUnlockOut`, `BroadcastChatTipIn`, `BroadcastChatTipOut` models. Add `POST .../unlock` and `POST .../tip` endpoints. Extend output model with lock/tip fields. | +80 |
| 7 | `frontend/src/pages/broadcast/ChatLockedCard.tsx` | Create — locked message card with unlock button + PM selector dialog. | ~120 |
| 7 | `frontend/src/pages/broadcast/ChatTipBadge.tsx` | Create — tip badge + tip dialog with amount input + PM selector. | ~100 |
| 7-8 | `frontend/src/pages/broadcast/ChatMessageRow.tsx` | Modify — integrate `ChatLockedCard` and `ChatTipBadge`. | +25 |
| 8 | `frontend/src/pages/broadcast/BroadcastChat.tsx` | Handle `chat:unlock` and `chat:tip` SSE events. Update local message cache. Add lock + tip toggles to broadcaster compose bar. | +40 |
| 8 | `frontend/src/api/endpoints/broadcast-chat.ts` | Add `unlockChatMessage()` and `tipChatMessage()` wrappers. | +20 |

### Phase E: View-Once Messages (1.5 days)

| Day | File | Change | Lines |
|-----|------|--------|-------|
| 9 | `app/services/broadcast_chat_rich.py` | Add `consume_view_once_chat_message()`. | +50 |
| 9 | `app/services/broadcast_chat_store.py` | Extend `send_chat_message()` to accept `view_once`. Extend `chat_msg_out_rich()` to apply view-once visibility rules. | +15 |
| 9 | `app/routers/broadcast.py` | Add `BroadcastChatViewOnceOut` model. Add `POST .../view` endpoint. Extend output model with `view_once` and `view_once_consumed`. | +30 |
| 9-10 | `frontend/src/pages/broadcast/ChatViewOnceCard.tsx` | Create — view-once card with tap-to-reveal + auto-hide timer. | ~80 |
| 10 | `frontend/src/pages/broadcast/ChatMessageRow.tsx` | Modify — integrate `ChatViewOnceCard`. | +10 |
| 10 | `frontend/src/pages/broadcast/BroadcastChat.tsx` | Handle `chat:view_once_consumed` SSE event. Add view-once toggle to broadcaster compose bar. | +20 |

### Phase F: Encrypted Messages (future, not in this ticket scope)

Phase F is deferred to a follow-up ticket. Public broadcast chat does not need E2E encryption -- all viewers see the same content. Encryption only makes sense for BCAST-012 private chat tiers, where the conversation is between two parties. When implemented, it would reuse the `MessageEncryptionEnvelope` model from `app/routers/messaging.py` (line 1790), store the envelope on the chat message item, and require client-side key exchange via the existing PBKDF2-SHA256 / AES-256-GCM pattern. No server-side changes beyond storing the `encryption` map field would be needed.
<!-- VERIFIED: app/routers/messaging.py:1790 (MessageEncryptionEnvelope) -->

### Summary of All Files

| File | Type | Phase | Estimated Lines |
|------|------|-------|-----------------|
| `app/services/broadcast_chat_rich.py` | Create | A,D,E | ~500 | <!-- NEW: to be created -->
| `app/services/broadcast_chat_store.py` | Modify | A,B,C,D,E | +145 | <!-- VERIFIED: exists, 310 lines -->
| `app/routers/broadcast.py` | Modify | A,B,C,D,E | +168 | <!-- VERIFIED: exists, 2530 lines -->
| `frontend/src/pages/broadcast/ChatReactionBar.tsx` | Create | A | ~100 | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/ChatReplyQuote.tsx` | Create | B | ~60 | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/ChatLockedCard.tsx` | Create | D | ~120 | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/ChatTipBadge.tsx` | Create | D | ~100 | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/ChatViewOnceCard.tsx` | Create | E | ~80 | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/ChatMessageRow.tsx` | Create (extract from BroadcastChat.tsx) | A,B,C,D,E | +110 | <!-- CORRECTED: was "Modify" but file does not exist; must be extracted from BroadcastChat.tsx -->
| `frontend/src/pages/broadcast/BroadcastChat.tsx` | Modify | A,B,C,D,E | +140 | <!-- VERIFIED: exists -->
| `frontend/src/api/endpoints/broadcast-chat.ts` | Modify | A,D,E | +50 | <!-- VERIFIED: exists -->
| `frontend/e2e/broadcast-chat-rich.spec.ts` | Create | A,B,C,D,E | ~600 | <!-- NEW: to be created -->
| `tests/test_broadcast_chat_rich.py` | Create | A,B,C,D,E | ~400 | <!-- NEW: to be created -->
| **Total** | | | **~2573** |

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_broadcast_rich_chat.py`

**Mock setup**: moto mock for DynamoDB (broadcast tables). Mock broadcast provider for instant state transitions.

| Test Function | Description |
|---|---|
| `test_create_bcast015_resource` | Create primary resource; verify stored in DDB with correct fields |
| `test_get_bcast015_resource` | Get resource by ID; verify all fields returned |
| `test_list_bcast015_resources` | List resources; verify pagination and filtering |
| `test_update_bcast015_resource` | Update resource; verify changed fields persisted |
| `test_delete_bcast015_resource` | Delete resource; verify removed from DDB |
| `test_validation_rejects_invalid_input` | Missing required fields returns 422; invalid values return 400 |
| `test_authorization_enforced` | Non-owner/non-admin access returns 403 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full lifecycle: create -> read -> update -> delete through real DDB
2. Cross-service integration with broadcast session store
3. Concurrent operations do not corrupt shared state

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/broadcast-rich-chat.spec.ts`

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
| BCAST-005 | Base chat store and SSE delivery | Implemented | Yes |
| BCAST-012 | Private chat tiers for scoped delivery | Implemented | Yes |
| MON-002 | Tip ledger for locked/tipped messages | Implemented | Yes |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Sequential after BCAST-005 and BCAST-012. Extends chat item schema with reactions, replies, expiry, locking fields.

### Merge Checklist

- [ ] DDB table/fields added to `scripts/local-ddb-init.py` (if new table needed)
- [ ] Settings added to `app/core/settings.py`
- [ ] Service and router files created/modified
- [ ] Frontend components and API wrappers created
- [ ] E2E test passes in CI
- [ ] No breaking changes to existing endpoints

## Codebase References

| File | Relevance |
|------|-----------|
| `app/services/broadcast_chat_store.py` (310 lines) | Base chat store — extended with rich fields in `send_chat_message()` and `_chat_msg_out()` | <!-- VERIFIED: 310 lines -->
| `app/routers/broadcast.py` (2530 lines) | Broadcast router — new endpoints added after existing chat section (line 1194+) | <!-- VERIFIED: 2530 lines -->
| `app/services/broadcast_sse.py` (49 lines) | SSE pub/sub — `broadcast_sse_publish()` used for all new event types | <!-- VERIFIED: 49 lines -->
| `app/routers/messaging.py:9835` | `react_to_message()` — DDB reaction pattern reference | <!-- VERIFIED: :9835 decorator, :9836 function -->
| `app/routers/messaging.py:1790` | `MessageEncryptionEnvelope` — encryption model reference (Phase F) | <!-- VERIFIED: :1790 -->
| `app/routers/messaging.py:12472` | `unlock_message()` — lock/unlock pattern reference | <!-- CORRECTED: was :12473, actually @router.post at :12472, function at :12476 -->
| `app/routers/messaging.py:10197` | View-once consume endpoint pattern reference | <!-- VERIFIED: :10197 (mark_message_viewed) -->
| `app/services/tip_ledger.py:87` | `write_tip_ledger()` — billing ledger pattern reference | <!-- VERIFIED: :87 -->
| `app/core/tables.py` | Table handles — `T.broadcast_chat_messages` (line 80), `T.billing` (line 22) | <!-- VERIFIED: tables.py:80 (broadcast_chat_messages), :22 (billing) -->
| `scripts/local-ddb-init.py` | Table definitions — no changes needed (existing table, additive fields) | <!-- VERIFIED: :557 (BroadcastChatMessages table def) -->
| `app/services/broadcast_chat_rich.py` | EXISTS | Rich chat message processing |
| `frontend/e2e/broadcast-chat-rich.spec.ts` | EXISTS | E2E tests for rich chat |
| `frontend/src/pages/broadcast/ChatReactionBar.tsx` | EXISTS | Reaction UI |
| `frontend/src/pages/broadcast/ChatReplyQuote.tsx` | EXISTS | Reply quote UI |
| `frontend/src/pages/broadcast/ChatLockedCard.tsx` | EXISTS | Locked message UI |
| `frontend/src/pages/broadcast/ChatOverlay.tsx` | EXISTS | Chat overlay component |
