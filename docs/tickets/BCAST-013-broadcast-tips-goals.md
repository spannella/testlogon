# BCAST-013: Broadcast Live Tipping, Tip Goals, and Tip Monitor

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: High  
**Estimated effort**: 10-14 days  
**Dependencies**: BCAST-005 (live chat), MON-002 (tip ledger integration), SOCIAL-005 (tip leaderboards)

---

## 1. Overview & Motivation

### The Gap

The broadcast system (`app/routers/broadcast.py`, 2530 lines) has a mature live chat subsystem (BCAST-005) that supports text messages, product link cards, muting, and moderation. The existing tip ledger (`app/services/tip_ledger.py`) enables paired debit/credit billing entries for tips on messages, posts, and comments. The tip leaderboard (`app/routers/tip_leaderboard.py`) aggregates supporter rankings per creator. <!-- VERIFIED: app/routers/broadcast.py:2530 lines, app/services/tip_ledger.py, app/routers/tip_leaderboard.py -->

However, **there is no mechanism to tip during a live broadcast**. The current chat message kinds in `broadcast_chat_store.py` are limited to `"text"` (default) and `"product_link"` (line 196). The `BroadcastChatSendIn` model (line 1197 of `broadcast.py`) accepts only `text: str`. There is no: <!-- VERIFIED: broadcast_chat_store.py:304 (kind default "text"), broadcast_chat_store.py:196 (kind="product_link"), broadcast.py:1197 (BroadcastChatSendIn) --> <!-- CORRECTED: product_link kind was "line 304", actually "line 196" (line 304 is where the default "text" appears in _chat_msg_out, but the product_link kind assignment is at line 196) -->

1. Way for viewers to send monetary tips during a live broadcast
2. Running total of tips received during a broadcast session
3. Goal-setting mechanism where broadcasters define fundraising targets with progress tracking
4. Visual tip ticker or animation overlay in the broadcast viewer
5. Broadcaster-side tip summary dashboard during or after a broadcast

The tip ledger's `TipLedgerEntry.content_type` (line 50 of `tip_ledger.py`) currently validates against `("message", "post", "comment")` only -- `"broadcast"` is not in the allowed set, so any attempt to write a broadcast tip ledger entry would raise `ValueError`. <!-- VERIFIED: tip_ledger.py:50 -->

### Why This Is Needed

1. **Creator monetization**: Live tipping is the primary revenue mechanism for live-streaming platforms. Creators earn directly from viewer engagement without requiring subscriptions or product sales.
2. **Viewer engagement**: Tips create a positive feedback loop -- the viewer gets recognition (their tip message appears in chat with a highlighted badge), the broadcaster acknowledges them, and other viewers are incentivized to tip.
3. **Tip goals gamify giving**: Goals (e.g., "500 tips to do a cooking segment") turn passive viewing into interactive participation. Progress bars create urgency and social proof.
4. **Parity with competitors**: Twitch (Bits/Cheers), YouTube (Super Chat), and Kick (tips) all feature live tipping with visual overlays. This is table-stakes for creator adoption.
5. **Data-driven creator tools**: A tip monitor/summary gives broadcasters real-time insight into which content resonates and which viewer segments are most engaged.

### Architecture After This Change

```
Live Broadcast Tipping Architecture

  Viewer (Browser)                              Backend (FastAPI)
  ┌────────────────────┐                       ┌────────────────────────────┐
  │ BroadcastTipButton │──POST /chat/tip──────>│ send_tip_message_route()   │
  │  ├─ Amount presets  │                       │  ├─ Validate PM from       │
  │  ├─ Custom amount   │                       │  │   billing table          │
  │  └─ PM selector     │                       │  ├─ Write tip ledger       │
  └────────────────────┘                       │  │   (debit/credit)         │
                                                │  ├─ Write tip chat msg     │
  ┌────────────────────┐                       │  │   to DDB (kind="tip")    │
  │ TipTicker          │<─SSE "chat:tip"───────│  ├─ Update session          │
  │  └─ Animated feed  │                       │  │   tip_total_cents        │
  │                    │<─SSE "tip:total"──────│  ├─ SSE: chat:tip           │
  └────────────────────┘                       │  ├─ SSE: tip:total_update   │
                                                │  └─ Update goal progress   │
  ┌────────────────────┐                       │     └─ SSE: goal:progress   │
  │ TipGoalBar         │<─SSE "goal:progress"──│        or goal:reached      │
  │  └─ Progress bar   │<─SSE "goal:reached"───│                             │
  └────────────────────┘                       └────────────────────────────┘

  ┌────────────────────┐                       ┌────────────────────────────┐
  │ BroadcastTipSummary│<─GET /tips/summary────│ get_tip_summary()          │
  │  ├─ Running total  │                       │  ├─ Read session record    │
  │  ├─ Top tippers    │                       │  │   (tip_total_cents)      │
  │  └─ Tip breakdown  │                       │  ├─ Query tip chat msgs    │
  └────────────────────┘                       │  └─ Aggregate by tipper    │
                                                └────────────────────────────┘

  DynamoDB Storage:
  ┌─────────────────────────────────────────────────────────────────┐
  │ BroadcastChatMessages (existing table, BCAST-005)              │
  │ PK: session_id  SK: sort_key                                   │
  │ kind="tip" messages stored alongside text and product_link     │
  │ New fields: tip_amount_cents, tip_currency, tip_payment_id     │
  ├─────────────────────────────────────────────────────────────────┤
  │ BroadcastSessions (existing table)                             │
  │ New fields: tip_total_cents, tip_count, tip_goal_ids           │
  ├─────────────────────────────────────────────────────────────────┤
  │ BroadcastTipGoals (NEW table)                                  │
  │ PK: session_id  SK: goal_id                                    │
  │ Fields: label, target_cents, current_cents, reached, order     │
  ├─────────────────────────────────────────────────────────────────┤
  │ billing (existing table)                                       │
  │ pk=USER#{sub}  sk=LEDGER#{ts}#{id} — debit/credit entries      │
  └─────────────────────────────────────────────────────────────────┘
```

---

## 2. Current State Analysis

### 2.1 Broadcast Chat Messages (`app/services/broadcast_chat_store.py`)

The chat store manages messages in the `BroadcastChatMessages` DynamoDB table. Each message has:

```python
# Lines 154-164 — send_chat_message() item structure <!-- VERIFIED: broadcast_chat_store.py:154-164 -->
item = {
    "session_id": session_id,
    "sort_key": sort_key,          # "{ts_ms:016d}#{msg_id}"
    "message_id": msg_id,          # "cm_" + uuid4().hex
    "sender_id": user_id,
    "sender_display_name": display_name,
    "text": text.strip(),
    "created_at": ts,              # now_ts() — integer Unix seconds
    "deleted": False,
    "ttl": ts + 7 * 24 * 3600,    # 7-day TTL
}
```

The `kind` field defaults to `"text"` (line 304 in `_chat_msg_out()`). Product link messages set `kind="product_link"` (line 196). **There is no `"tip"` kind.** <!-- VERIFIED: broadcast_chat_store.py:304 (kind default), broadcast_chat_store.py:196 (product_link kind) --> <!-- CORRECTED: product_link kind was "line 195", actually line 196 -->

The `_chat_msg_out()` helper (lines 296-310) builds the output dict with: `message_id`, `session_id`, `sender_id`, `sender_display_name`, `text`, `kind`, `created_at`, `deleted`, and optionally `product_link`. **No tip-related fields (`tip_amount_cents`, `tip_currency`, etc.) are included.** <!-- VERIFIED: broadcast_chat_store.py:296-310 -->

### 2.2 Chat Rate Limiting (`app/services/broadcast_chat_store.py`, lines 18-65) <!-- VERIFIED: broadcast_chat_store.py:18-65 -->

Two in-memory rate limit buckets exist:

1. `_CHAT_RATE_BUCKETS` — 2000ms per message (line 29, via `S.broadcast_chat_rate_limit_ms`) <!-- VERIFIED: broadcast_chat_store.py:21,29 -->
2. `_PRODUCT_LINK_RATE_BUCKETS` — 5000ms per product share (line 50) <!-- VERIFIED: broadcast_chat_store.py:22,50 -->

Tip messages need their own rate limit bucket to prevent tip spam while not blocking regular chat messages. A 3-second cooldown per tip is appropriate (fast enough for excitement, slow enough to prevent accidental double-tips).

### 2.3 Chat SSE Events (`app/services/broadcast_sse.py`)

The SSE pub/sub system (lines 1-50) uses in-memory `asyncio.Queue` per subscriber. Events are dicts with a `_type` key. Current event types published from chat: <!-- VERIFIED: broadcast_sse.py:1-50 (entire file) -->

- `"chat:message"` (line 169 in `broadcast_chat_store.py`) <!-- VERIFIED: broadcast_chat_store.py:169 -->
- `"chat:product_link"` (line 205) <!-- VERIFIED: broadcast_chat_store.py:205 -->
- `"chat:delete"` (line 274) <!-- VERIFIED: broadcast_chat_store.py:274 -->
- `"chat:mute"` (line 104) <!-- VERIFIED: broadcast_chat_store.py:104 -->

The SSE stream route (`broadcast.py` lines 619-639) pops `_type` from the dict and uses it as the SSE event name. The chat-specific polling stream (`broadcast.py` lines 1405-1453) also dispatches `chat:message`, `chat:product_link`, and `chat:delete`. <!-- VERIFIED: broadcast.py:619-639 (SSE stream), broadcast.py:632 (pops _type), broadcast.py:1405-1453 (chat poll stream) --> <!-- CORRECTED: SSE stream route was "lines 620-639", actually starts at line 619 (@router.get decorator) -->

**New events needed**: `"chat:tip"`, `"tip:total_update"`, `"goal:progress"`, `"goal:reached"`.

### 2.4 Broadcast Session Model (`app/models_broadcast.py`, lines 37-69) <!-- VERIFIED: models_broadcast.py:37-69 --> <!-- CORRECTED: was "lines 37-70", model ends at line 69 (line 70 is blank) -->

`BroadcastSessionModel` currently has scheduling fields (BCAST-009), go-private fields (BCAST-011), and private chat fields (BCAST-012). **No tip tracking fields exist.** The session record does not store:

- `tip_total_cents` — running total of all tips received during the session
- `tip_count` — number of tips received
- `tip_goal_ids` — list of goal IDs associated with this session

### 2.5 Session Store (`app/services/broadcast_store.py`)

`session_to_item()` (line 111) and `session_from_item()` (line 148) serialize/deserialize the session model. They must be extended to handle the new tip fields. <!-- VERIFIED: broadcast_store.py:111 (session_to_item), broadcast_store.py:148 (session_from_item) -->

`update_session_fields()` (line 435) allows partial updates to a session via a dict of field names and values. This function reads the current session, merges fields, and writes back with `put_item()`. It can be used for atomic-ish tip total updates, but a DynamoDB `update_item` with `ADD` expression would be more efficient for incrementing `tip_total_cents` (avoids read-before-write). <!-- VERIFIED: broadcast_store.py:435 (update_session_fields) -->

### 2.6 Tip Ledger (`app/services/tip_ledger.py`)

`TipLedgerEntry` (lines 20-61) validates `content_type in ("message", "post", "comment")` at line 50-51. The `write_tip_ledger()` function (line 87) writes paired debit/credit entries to `T.billing` with keys `pk=USER#{user_sub}`, `sk=LEDGER#{ts}#{id}`. <!-- VERIFIED: tip_ledger.py:20-61 (TipLedgerEntry class), tip_ledger.py:50-51 (validation), tip_ledger.py:87 (write_tip_ledger) --> <!-- CORRECTED: was "lines 20-60", class __init__ ends at line 60 but last attribute is line 60, so 20-61 is more accurate (line 61 is blank) -->

The `_reason_for_content_type()` helper (line 63) maps content types to reason strings. Both the validation set and the reason map must be extended to include `"broadcast"` as a valid content type. <!-- VERIFIED: tip_ledger.py:63 -->

### 2.7 Billing Table Payment Method Validation

The existing tip flow in `app/routers/messaging.py` (lines 12378-12392) validates payment methods by querying the billing table for items with `sk` starting with `"PM#"`: <!-- VERIFIED: messaging.py:12378-12392 -->

```python
billing_items = billing_tbl.query(
    KeyConditionExpression="pk = :pk",
    ExpressionAttributeValues={":pk": f"USER#{user_id}"},
).get("Items", [])
pm_ids = {
    it["payment_method_id"]
    for it in billing_items
    if it.get("sk", "").startswith("PM#") and "payment_method_id" in it
}
if inp.payment_method_id not in pm_ids:
    raise HTTPException(400, "Payment method not found")
```

The broadcast tip endpoint will use the same pattern.

### 2.8 Chat Router Models (`app/routers/broadcast.py`, lines 1197-1238) <!-- VERIFIED: broadcast.py:1197 (BroadcastChatSendIn), broadcast.py:1211-1221 (BroadcastChatMessageOut), broadcast.py:1229-1238 (mute models) -->

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

`BroadcastChatMessageOut` has no tip fields. `kind` is a plain string, not a validated Literal, so adding `"tip"` requires no schema migration -- just behavioral changes.

### 2.9 Frontend Chat Component (`frontend/src/pages/broadcast/BroadcastChat.tsx`)

The `BroadcastChat` component (line 23) maintains a `messages` state array of `ChatMessage` type. It subscribes to SSE events `chat:message` and `chat:delete` (lines 61-69). It does **not** handle `chat:tip` events. The `ChatMessage` interface (defined in `frontend/src/api/endpoints/broadcast-chat.ts`, lines 5-13) has no tip fields. <!-- VERIFIED: BroadcastChat.tsx:23 (component), BroadcastChat.tsx:24 (messages state), BroadcastChat.tsx:61-69 (SSE listeners), broadcast-chat.ts:5-13 (ChatMessage interface) -->

### 2.10 Broadcast Chat Send Route (`app/routers/broadcast.py`, lines 1240-1280) <!-- VERIFIED: broadcast.py:1240-1280 -->

The `send_chat_message_route()` validates that the session is `"live"` (line 1248), resolves the sender's display name from the profile table (lines 1256-1264), and calls `_store_send_chat()` (line 1266). The route returns a `BroadcastChatMessageOut`. The tip endpoint will follow the same pattern but with additional payment validation, ledger writes, and tip-specific fields. <!-- VERIFIED: broadcast.py:1245 (route function), broadcast.py:1248 (status check), broadcast.py:1256-1264 (display name), broadcast.py:1266 (_store_send_chat) --> <!-- CORRECTED: display name resolution was "lines 1257-1264", actually starts at line 1256 -->

### 2.11 Broadcast Session Out Model (`app/routers/broadcast.py`, lines 105-131) <!-- VERIFIED: broadcast.py:105-131 (BroadcastSessionOut, last field announcement_post_id at line 131) -->

`BroadcastSessionOut` already includes scheduling fields from BCAST-009. New tip fields (`tip_total_cents`, `tip_count`) must be added for display in the broadcaster dashboard and viewer UI.

### 2.12 Tip Leaderboard (`app/routers/tip_leaderboard.py`)

The existing leaderboard at `GET /ui/creators/{creator_id}/top-supporters` (line 29) supports `period` param (`7d`, `30d`, `all`) and returns `TopSupportersOut` with `supporters`, `total_tip_cents`, and `total_supporters` fields. The broadcast tip summary can leverage the same aggregation logic but scoped to a single session rather than a time period. <!-- VERIFIED: tip_leaderboard.py:29 (route), TopSupportersOut in app/models.py:2399-2405 (has creator_id, period, supporters, total_tip_cents, total_supporters, computed_at) -->

### 2.13 Settings (`app/core/settings.py`)

Broadcast chat settings (lines 492-496): <!-- VERIFIED: settings.py:492-496 -->
- `broadcast_chat_rate_limit_ms: int = 2000` — general chat rate limit <!-- VERIFIED: settings.py:494 -->
- `broadcast_chat_max_message_length: int = 280` <!-- VERIFIED: settings.py:495 -->

No tip-specific settings exist. New settings needed for tip rate limiting, min/max amounts, and goal limits.

---

## 3. Technical Design

### 3.1 Backend Models

#### 3.1.1 Extended BroadcastSessionModel (`app/models_broadcast.py`)

Add tip tracking fields to `BroadcastSessionModel` after the existing private chat fields (after line 69): <!-- VERIFIED: models_broadcast.py:69 (last private chat field: private_chat_voyeur_price_cents) -->

```python
class BroadcastSessionModel(BaseModel):
    # ... existing fields through line 69 ...

    # Live Tipping (BCAST-013)
    tip_total_cents: int = 0
    tip_count: int = 0
    tip_enabled: bool = True
    tip_min_cents: int = 100        # $1.00 minimum
    tip_max_cents: int = 100000     # $1,000.00 maximum
```

#### 3.1.2 Tip Chat Message Input (`app/routers/broadcast.py`)

New request model for tip chat messages:

```python
class BroadcastChatTipIn(BaseModel):
    """Request body for sending a tip in broadcast chat."""
    amount_cents: int = Field(..., ge=100, le=100000, description="Tip amount in cents. Min $1, max $1000.")
    text: str = Field(default="", max_length=280, description="Optional message text accompanying the tip.")
    payment_method_id: str = Field(..., min_length=1, max_length=200, description="Payment method ID from billing table.")
    currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")
```

#### 3.1.3 Extended BroadcastChatMessageOut (`app/routers/broadcast.py`)

Add tip fields to the existing output model:

```python
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
    # Tip fields (BCAST-013)
    tip_amount_cents: Optional[int] = None
    tip_currency: Optional[str] = None
    tip_payment_id: Optional[str] = None
```

#### 3.1.4 Tip Goal Models

New models in `app/routers/broadcast.py`:

```python
class BroadcastTipGoalCreateIn(BaseModel):
    """Request body for creating a tip goal."""
    label: str = Field(..., min_length=1, max_length=200, description="Goal label (e.g., 'Cooking segment!')")
    target_cents: int = Field(..., ge=100, le=10000000, description="Goal target amount in cents. Min $1, max $100,000.")
    sort_order: int = Field(default=0, ge=0, le=4, description="Display order (0-4).")

class BroadcastTipGoalOut(BaseModel):
    """Response model for a tip goal."""
    goal_id: str
    session_id: str
    label: str
    target_cents: int
    current_cents: int = 0
    reached: bool = False
    reached_at: Optional[int] = None
    sort_order: int = 0
    created_at: int

class BroadcastTipGoalUpdateIn(BaseModel):
    """Request body for updating a tip goal."""
    label: Optional[str] = Field(default=None, min_length=1, max_length=200)
    target_cents: Optional[int] = Field(default=None, ge=100, le=10000000)
    sort_order: Optional[int] = Field(default=None, ge=0, le=4)

class BroadcastTipGoalsListOut(BaseModel):
    """Response model for listing all goals for a session."""
    goals: List[BroadcastTipGoalOut] = Field(default_factory=list)
    session_id: str
```

#### 3.1.5 Tip Summary Model

```python
class BroadcastTipSummaryOut(BaseModel):
    """Tip summary for a broadcast session."""
    session_id: str
    total_cents: int = 0
    tip_count: int = 0
    currency: str = "USD"
    top_tippers: List[BroadcastTopTipperItem] = Field(default_factory=list)
    recent_tips: List[BroadcastRecentTipItem] = Field(default_factory=list)

class BroadcastTopTipperItem(BaseModel):
    user_id: str
    display_name: str
    total_cents: int
    tip_count: int

class BroadcastRecentTipItem(BaseModel):
    message_id: str
    sender_id: str
    sender_display_name: str
    amount_cents: int
    text: str
    created_at: int
```

#### 3.1.6 Extended Tip Ledger Content Types (`app/services/tip_ledger.py`)

Modify the `TipLedgerEntry.__init__` validation (line 50) to accept `"broadcast"`: <!-- VERIFIED: tip_ledger.py:50 -->

```python
# Current (line 50-51):
if content_type not in ("message", "post", "comment"):
    raise ValueError(f"Invalid content_type: {content_type}")

# Updated:
if content_type not in ("message", "post", "comment", "broadcast"):
    raise ValueError(f"Invalid content_type: {content_type}")
```

Extend `_reason_for_content_type()` (line 63): <!-- VERIFIED: tip_ledger.py:63 -->

```python
# Current (lines 65-69): <!-- CORRECTED: was "lines 64-69", dict starts at line 65 -->
return {
    "message": "Tip: message",
    "post": "Tip: post",
    "comment": "Tip: comment",
}.get(content_type, f"Tip: {content_type}")

# Updated:
return {
    "message": "Tip: message",
    "post": "Tip: post",
    "comment": "Tip: comment",
    "broadcast": "Tip: broadcast",
}.get(content_type, f"Tip: {content_type}")
```

### 3.2 Service Layer

#### 3.2.1 Broadcast Tip Service (`app/services/broadcast_tip_store.py`) <!-- NEW: to be created -->

New file implementing tip-specific chat message storage and session tip aggregation:

```python
"""Broadcast live tip service — tip chat messages, session totals, and goal tracking (BCAST-013)."""

from __future__ import annotations

import threading
import time
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish
from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger

# ─── Rate Limiting (in-memory, separate bucket for tips) ────────

_TIP_RATE_LOCK = threading.Lock()
_TIP_RATE_BUCKETS: Dict[str, int] = {}  # "{session_id}#{user_id}" -> last_tip_ts_ms

TIP_RATE_LIMIT_MS = 3000  # 3 seconds between tips


def _enforce_tip_rate_limit(session_id: str, user_id: str) -> None:
    """Raise 429 if user is sending tips faster than allowed."""
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    with _TIP_RATE_LOCK:
        last = _TIP_RATE_BUCKETS.get(key, 0)
        if now_ms - last < TIP_RATE_LIMIT_MS:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "BROADCAST_TIP_RATE_LIMITED",
                    "message": "You can send one tip every 3 seconds.",
                    "retry_after_ms": TIP_RATE_LIMIT_MS - (now_ms - last),
                },
            )
        _TIP_RATE_BUCKETS[key] = now_ms


def reset_tip_rate_limits() -> None:
    """Clear all tip rate limit state (for tests)."""
    with _TIP_RATE_LOCK:
        _TIP_RATE_BUCKETS.clear()


# ─── Payment Method Validation ──────────────────────────────────

def _validate_payment_method(user_id: str, payment_method_id: str) -> None:
    """Validate that the given payment method belongs to the user.

    Queries the billing table for items with sk starting with 'PM#'.
    Raises 400 if the payment method is not found.
    """
    billing_pk = f"USER#{user_id}"
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(billing_pk),
    )
    items = resp.get("Items", [])
    pm_ids = {
        it["payment_method_id"]
        for it in items
        if it.get("sk", "").startswith("PM#") and "payment_method_id" in it
    }
    if payment_method_id not in pm_ids:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "PAYMENT_METHOD_NOT_FOUND",
                "message": "Payment method not found. Add a payment method in Billing.",
            },
        )


# ─── Tip Chat Message ──────────────────────────────────────────

def send_tip_message(
    *,
    session_id: str,
    user_id: str,
    display_name: str,
    amount_cents: int,
    currency: str = "USD",
    payment_method_id: str,
    text: str = "",
    broadcaster_id: str,
) -> Dict[str, Any]:
    """Send a tip as a chat message. Validates PM, writes ledger, updates session total.

    Steps:
    1. Enforce tip rate limit
    2. Enforce chat mute check
    3. Validate payment method
    4. Validate tip amount (100 <= amount_cents <= 100000)
    5. Generate tip payment ID
    6. Write paired debit/credit entries to billing table via TipLedgerEntry
    7. Write tip chat message to BroadcastChatMessages table (kind="tip")
    8. Atomically increment session tip_total_cents and tip_count
    9. Publish SSE events: chat:tip, tip:total_update
    10. Update goal progress if goals exist

    Returns:
        Dict with message fields + tip fields.
    """
    from app.services.broadcast_chat_store import _enforce_chat_mute

    # 1. Rate limit
    _enforce_tip_rate_limit(session_id, user_id)

    # 2. Mute check
    _enforce_chat_mute(session_id, user_id)

    # 3. Validate PM
    _validate_payment_method(user_id, payment_method_id)

    # 4. Validate amount bounds
    if amount_cents < 100:
        raise HTTPException(400, {"code": "TIP_TOO_SMALL", "message": "Minimum tip is $1.00 (100 cents)."})
    if amount_cents > 100000:
        raise HTTPException(400, {"code": "TIP_TOO_LARGE", "message": "Maximum tip is $1,000.00 (100000 cents)."})

    # 5. Prevent self-tip
    if user_id == broadcaster_id:
        raise HTTPException(400, {"code": "CANNOT_TIP_SELF", "message": "You cannot tip your own broadcast."})

    # 6. Generate IDs
    tip_payment_id = f"bctip_{uuid4().hex}"
    ts = now_ts()
    ts_ms = int(time.time() * 1000)
    msg_id = "cm_" + uuid4().hex
    sort_key = f"{ts_ms:016d}#{msg_id}"

    # 7. Write billing ledger entries
    ledger_entry = TipLedgerEntry(
        tipper_user_id=user_id,
        recipient_user_id=broadcaster_id,
        amount_cents=amount_cents,
        currency=currency,
        content_type="broadcast",
        content_id=f"{session_id}#{msg_id}",
        payment_method_id=payment_method_id,
        tip_payment_id=tip_payment_id,
        extra_meta={
            "session_id": session_id,
            "message_id": msg_id,
            "display_name": display_name,
        },
    )
    write_tip_ledger(ledger_entry)

    # 8. Write tip chat message to DDB
    tip_text = text.strip() if text else ""
    item: Dict[str, Any] = {
        "session_id": session_id,
        "sort_key": sort_key,
        "message_id": msg_id,
        "sender_id": user_id,
        "sender_display_name": display_name,
        "text": tip_text,
        "kind": "tip",
        "tip_amount_cents": amount_cents,
        "tip_currency": currency,
        "tip_payment_id": tip_payment_id,
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 24 * 3600,
    }
    T.broadcast_chat_messages.put_item(Item=item)

    # 9. Atomically increment session tip totals
    new_totals = _increment_session_tip_totals(session_id, amount_cents)

    # 10. Publish SSE events
    out = _tip_msg_out(item)
    broadcast_sse_publish(session_id, {"_type": "chat:tip", **out})
    broadcast_sse_publish(session_id, {
        "_type": "tip:total_update",
        "session_id": session_id,
        "tip_total_cents": new_totals["tip_total_cents"],
        "tip_count": new_totals["tip_count"],
        "latest_tip": {
            "sender_id": user_id,
            "sender_display_name": display_name,
            "amount_cents": amount_cents,
            "message_id": msg_id,
        },
    })

    # 11. Update goal progress
    _update_goals_for_tip(session_id, amount_cents)

    return {**out, "sort_key": sort_key}


def _increment_session_tip_totals(session_id: str, amount_cents: int) -> Dict[str, int]:
    """Atomically increment tip_total_cents and tip_count on the session record.

    Uses DynamoDB update_item with ADD expression for atomicity (no read-before-write).
    Returns the new values of tip_total_cents and tip_count.
    """
    resp = T.broadcast_sessions.update_item(
        Key={"session_id": session_id},
        UpdateExpression=(
            "ADD tip_total_cents :amt, tip_count :one "
            "SET updated_at = :now"
        ),
        ExpressionAttributeValues={
            ":amt": amount_cents,
            ":one": 1,
            ":now": now_ts(),
        },
        ReturnValues="UPDATED_NEW",
    )
    attrs = resp.get("Attributes", {})
    return {
        "tip_total_cents": int(attrs.get("tip_total_cents", 0)),
        "tip_count": int(attrs.get("tip_count", 0)),
    }


def _tip_msg_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a tip DDB item to output dict."""
    return {
        "message_id": item["message_id"],
        "session_id": item["session_id"],
        "sender_id": item["sender_id"],
        "sender_display_name": item.get("sender_display_name", ""),
        "text": item.get("text", ""),
        "kind": "tip",
        "tip_amount_cents": int(item.get("tip_amount_cents", 0)),
        "tip_currency": item.get("tip_currency", "USD"),
        "tip_payment_id": item.get("tip_payment_id", ""),
        "created_at": int(item.get("created_at", 0)),
        "deleted": bool(item.get("deleted", False)),
    }


# ─── Tip Summary ───────────────────────────────────────────────

def get_tip_summary(session_id: str, *, limit: int = 10) -> Dict[str, Any]:
    """Get tip summary for a broadcast session.

    Returns:
    - total_cents, tip_count from session record
    - top_tippers: aggregated from tip chat messages
    - recent_tips: latest N tip messages
    """
    from app.services.broadcast_store import get_session

    session = get_session(session_id)
    total_cents = int(getattr(session, "tip_total_cents", 0) or 0)
    tip_count_val = int(getattr(session, "tip_count", 0) or 0)

    # Query tip messages from chat table
    tip_messages = _query_tip_messages(session_id, limit=200)

    # Aggregate top tippers
    tipper_agg: Dict[str, Dict[str, Any]] = {}
    for msg in tip_messages:
        uid = msg["sender_id"]
        if uid not in tipper_agg:
            tipper_agg[uid] = {
                "user_id": uid,
                "display_name": msg.get("sender_display_name", uid),
                "total_cents": 0,
                "tip_count": 0,
            }
        tipper_agg[uid]["total_cents"] += int(msg.get("tip_amount_cents", 0))
        tipper_agg[uid]["tip_count"] += 1

    top_tippers = sorted(tipper_agg.values(), key=lambda x: x["total_cents"], reverse=True)[:limit]

    # Recent tips (newest first)
    recent = sorted(tip_messages, key=lambda m: m.get("created_at", 0), reverse=True)[:limit]
    recent_tips = [
        {
            "message_id": m["message_id"],
            "sender_id": m["sender_id"],
            "sender_display_name": m.get("sender_display_name", ""),
            "amount_cents": int(m.get("tip_amount_cents", 0)),
            "text": m.get("text", ""),
            "created_at": int(m.get("created_at", 0)),
        }
        for m in recent
    ]

    return {
        "session_id": session_id,
        "total_cents": total_cents,
        "tip_count": tip_count_val,
        "currency": "USD",
        "top_tippers": top_tippers,
        "recent_tips": recent_tips,
    }


def _query_tip_messages(session_id: str, *, limit: int = 200) -> List[Dict[str, Any]]:
    """Query all tip messages for a session from the chat table.

    Uses FilterExpression on kind="tip" — DynamoDB fetches up to 1MB before filtering.
    For sessions with many non-tip messages, this may need pagination.
    """
    all_tips: List[Dict[str, Any]] = []
    last_key = None
    pages = 0
    while pages < 10:  # cap at 10 pages to avoid runaway scans
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("session_id").eq(session_id),
            "FilterExpression": Attr("kind").eq("tip") & Attr("deleted").ne(True),
            "Limit": 500,
            "ScanIndexForward": False,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.broadcast_chat_messages.query(**kwargs)
        all_tips.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(all_tips) >= limit:
            break
        pages += 1
    return all_tips[:limit]
```

#### 3.2.2 Broadcast Tip Goal Service (`app/services/broadcast_tip_goals.py`) <!-- NEW: to be created -->

New file implementing goal CRUD and progress tracking:

```python
"""Broadcast tip goal service — CRUD and progress tracking (BCAST-013)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish

logger = logging.getLogger(__name__)

MAX_GOALS_PER_SESSION = 5


def create_goal(
    *,
    session_id: str,
    label: str,
    target_cents: int,
    sort_order: int = 0,
    actor: str,
) -> Dict[str, Any]:
    """Create a tip goal for a broadcast session.

    Raises 409 if the session already has MAX_GOALS_PER_SESSION goals.
    """
    existing = list_goals(session_id)
    if len(existing) >= MAX_GOALS_PER_SESSION:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "MAX_GOALS_REACHED",
                "message": f"Maximum {MAX_GOALS_PER_SESSION} goals per session.",
            },
        )

    goal_id = f"goal_{uuid4().hex[:12]}"
    ts = now_ts()
    item = {
        "session_id": session_id,
        "goal_id": goal_id,
        "label": label,
        "target_cents": target_cents,
        "current_cents": 0,
        "reached": False,
        "reached_at": None,
        "sort_order": sort_order,
        "created_at": ts,
        "created_by": actor,
    }
    # Remove None values
    item = {k: v for k, v in item.items() if v is not None}
    T.broadcast_tip_goals.put_item(Item=item)

    # Publish goal created event
    out = _goal_out(item)
    broadcast_sse_publish(session_id, {"_type": "goal:created", **out})

    return out


def list_goals(session_id: str) -> List[Dict[str, Any]]:
    """List all goals for a session, ordered by sort_order then created_at."""
    resp = T.broadcast_tip_goals.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda g: (int(g.get("sort_order", 0)), int(g.get("created_at", 0))))
    return [_goal_out(item) for item in items]


def get_goal(session_id: str, goal_id: str) -> Dict[str, Any]:
    """Get a single goal by session_id and goal_id."""
    resp = T.broadcast_tip_goals.get_item(
        Key={"session_id": session_id, "goal_id": goal_id},
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, {"code": "GOAL_NOT_FOUND", "message": "Tip goal not found."})
    return _goal_out(item)


def update_goal(
    session_id: str,
    goal_id: str,
    *,
    label: Optional[str] = None,
    target_cents: Optional[int] = None,
    sort_order: Optional[int] = None,
) -> Dict[str, Any]:
    """Update a tip goal. Only non-None fields are modified."""
    # Verify goal exists
    _ = get_goal(session_id, goal_id)

    update_parts = []
    expr_values: Dict[str, Any] = {}
    if label is not None:
        update_parts.append("label = :lbl")
        expr_values[":lbl"] = label
    if target_cents is not None:
        update_parts.append("target_cents = :tgt")
        expr_values[":tgt"] = target_cents
    if sort_order is not None:
        update_parts.append("sort_order = :so")
        expr_values[":so"] = sort_order

    if not update_parts:
        return get_goal(session_id, goal_id)

    T.broadcast_tip_goals.update_item(
        Key={"session_id": session_id, "goal_id": goal_id},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=expr_values,
    )

    updated = get_goal(session_id, goal_id)
    broadcast_sse_publish(session_id, {"_type": "goal:updated", **updated})
    return updated


def delete_goal(session_id: str, goal_id: str) -> bool:
    """Delete a tip goal."""
    _ = get_goal(session_id, goal_id)  # 404 if not found
    T.broadcast_tip_goals.delete_item(
        Key={"session_id": session_id, "goal_id": goal_id},
    )
    broadcast_sse_publish(session_id, {
        "_type": "goal:deleted",
        "session_id": session_id,
        "goal_id": goal_id,
    })
    return True


def advance_goal_progress(session_id: str, tip_amount_cents: int) -> List[Dict[str, Any]]:
    """Distribute a tip amount across active (non-reached) goals.

    Goals are filled in sort_order. Each goal receives tip amount up to its
    remaining capacity. Overflow spills to the next goal. Once a goal reaches
    its target, it is marked as reached and a goal:reached SSE event fires.

    Returns list of updated goal states.
    """
    goals = T.broadcast_tip_goals.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
    ).get("Items", [])

    if not goals:
        return []

    # Sort by sort_order, then created_at
    goals.sort(key=lambda g: (int(g.get("sort_order", 0)), int(g.get("created_at", 0))))

    remaining = tip_amount_cents
    updated: List[Dict[str, Any]] = []

    for goal in goals:
        if remaining <= 0:
            break
        if goal.get("reached"):
            updated.append(_goal_out(goal))
            continue

        current = int(goal.get("current_cents", 0))
        target = int(goal.get("target_cents", 0))
        capacity = max(0, target - current)

        if capacity <= 0:
            # Already met but not marked — mark now
            _mark_goal_reached(session_id, goal["goal_id"], current)
            goal["reached"] = True
            goal["current_cents"] = current
            updated.append(_goal_out(goal))
            continue

        applied = min(remaining, capacity)
        new_current = current + applied
        remaining -= applied
        reached_now = new_current >= target

        # Atomic update
        update_expr = "ADD current_cents :amt"
        expr_vals: Dict[str, Any] = {":amt": applied}
        if reached_now:
            update_expr += " SET reached = :t, reached_at = :ts"
            expr_vals[":t"] = True
            expr_vals[":ts"] = now_ts()

        T.broadcast_tip_goals.update_item(
            Key={"session_id": session_id, "goal_id": goal["goal_id"]},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_vals,
        )

        goal["current_cents"] = new_current
        goal["reached"] = reached_now
        goal_out = _goal_out(goal)
        updated.append(goal_out)

        # Publish progress SSE event
        broadcast_sse_publish(session_id, {
            "_type": "goal:progress",
            **goal_out,
            "tip_applied_cents": applied,
        })

        # Publish reached event if threshold crossed
        if reached_now:
            broadcast_sse_publish(session_id, {
                "_type": "goal:reached",
                **goal_out,
            })

    return updated


def _mark_goal_reached(session_id: str, goal_id: str, current_cents: int) -> None:
    """Mark a goal as reached (idempotent)."""
    T.broadcast_tip_goals.update_item(
        Key={"session_id": session_id, "goal_id": goal_id},
        UpdateExpression="SET reached = :t, reached_at = :ts",
        ExpressionAttributeValues={":t": True, ":ts": now_ts()},
    )


def _goal_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB goal item to output dict."""
    return {
        "goal_id": item.get("goal_id", ""),
        "session_id": item.get("session_id", ""),
        "label": item.get("label", ""),
        "target_cents": int(item.get("target_cents", 0)),
        "current_cents": int(item.get("current_cents", 0)),
        "reached": bool(item.get("reached", False)),
        "reached_at": int(item["reached_at"]) if item.get("reached_at") else None,
        "sort_order": int(item.get("sort_order", 0)),
        "created_at": int(item.get("created_at", 0)),
    }
```

The `_update_goals_for_tip()` call in `broadcast_tip_store.py` simply delegates to `advance_goal_progress()`:

```python
def _update_goals_for_tip(session_id: str, amount_cents: int) -> None:
    """Update tip goals with the new tip amount. Silent on errors."""
    try:
        from app.services.broadcast_tip_goals import advance_goal_progress
        advance_goal_progress(session_id, amount_cents)
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "broadcast_tip_goal_update_failed",
            extra={"session_id": session_id, "amount": amount_cents},
        )
```

### 3.3 API Endpoints

All endpoints are added to `app/routers/broadcast.py` under the existing `router = APIRouter(prefix="/broadcast", tags=["broadcast"])`. <!-- VERIFIED: broadcast.py uses this router pattern -->

#### 3.3.1 Send Tip in Broadcast Chat

```
POST /broadcast/sessions/{session_id}/chat/tip
```

**Auth**: `require_ui_session` via `Depends(_ctx)`. <!-- VERIFIED: broadcast.py:187 (_ctx wraps require_ui_session) -->

**Request body**: `BroadcastChatTipIn` — `amount_cents`, `text`, `payment_method_id`, `currency`.

**Response**: `BroadcastChatMessageOut` (201 Created) — includes `kind="tip"`, `tip_amount_cents`, `tip_currency`, `tip_payment_id`.

**Behavior**:

1. Validate session exists and `status == "live"` (403 otherwise with code `BROADCAST_NOT_LIVE`).
2. Validate `tip_enabled` on session (403 if disabled with code `TIPPING_DISABLED`).
3. Validate `amount_cents` within session's `tip_min_cents`..`tip_max_cents` range.
4. Resolve sender display name from profile table.
5. Call `send_tip_message()` from `broadcast_tip_store`.
6. Return `BroadcastChatMessageOut` with tip fields populated.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 400 | `TIP_TOO_SMALL` | `amount_cents < 100` |
| 400 | `TIP_TOO_LARGE` | `amount_cents > 100000` |
| 400 | `CANNOT_TIP_SELF` | Tipper is the broadcaster |
| 400 | `PAYMENT_METHOD_NOT_FOUND` | PM does not belong to user |
| 403 | `BROADCAST_NOT_LIVE` | Session is not in `"live"` status |
| 403 | `TIPPING_DISABLED` | `tip_enabled == False` on session |
| 403 | `BROADCAST_CHAT_MUTED` | User is muted in this chat |
| 429 | `BROADCAST_TIP_RATE_LIMITED` | Tip sent within 3 seconds of previous |

#### 3.3.2 Get Tip Summary

```
GET /broadcast/sessions/{session_id}/tips/summary
```

**Auth**: `require_ui_session`.

**Query params**:
- `top_limit: int` (default 10, max 50) — number of top tippers to return.
- `recent_limit: int` (default 10, max 50) — number of recent tips to return.

**Response**: `BroadcastTipSummaryOut`.

**Behavior**: Calls `get_tip_summary()`. Available to all authenticated users (viewers see public data; broadcaster sees same data plus can cross-reference with billing).

#### 3.3.3 Configure Session Tipping

```
PATCH /broadcast/sessions/{session_id}/tips/config
```

**Auth**: `require_ui_session` — only session creator.

**Request body**:

```python
class BroadcastTipConfigIn(BaseModel):
    tip_enabled: Optional[bool] = None
    tip_min_cents: Optional[int] = Field(default=None, ge=100, le=100000)
    tip_max_cents: Optional[int] = Field(default=None, ge=100, le=100000)
```

**Response**: `BroadcastSessionOut` with updated tip config fields.

**Behavior**:
1. Validate caller is session creator (403 otherwise).
2. Validate `tip_min_cents <= tip_max_cents` if both are provided.
3. Use `update_session_fields()` to merge changes into session record.
4. Return updated session.

#### 3.3.4 Create Tip Goal

```
POST /broadcast/sessions/{session_id}/goals
```

**Auth**: `require_ui_session` — only session creator.

**Request body**: `BroadcastTipGoalCreateIn`.

**Response**: `BroadcastTipGoalOut` (201 Created).

**Behavior**:
1. Validate caller is session creator.
2. Validate session status is `"draft"`, `"scheduled"`, `"ready"`, or `"live"` (goals can be set up before and during broadcast).
3. Call `create_goal()`.

#### 3.3.5 List Tip Goals

```
GET /broadcast/sessions/{session_id}/goals
```

**Auth**: `require_ui_session` — any authenticated user.

**Response**: `BroadcastTipGoalsListOut`.

**Behavior**: Calls `list_goals()`. Goals are public to all viewers during a broadcast.

#### 3.3.6 Update Tip Goal

```
PATCH /broadcast/sessions/{session_id}/goals/{goal_id}
```

**Auth**: `require_ui_session` — only session creator.

**Request body**: `BroadcastTipGoalUpdateIn`.

**Response**: `BroadcastTipGoalOut`.

#### 3.3.7 Delete Tip Goal

```
DELETE /broadcast/sessions/{session_id}/goals/{goal_id}
```

**Auth**: `require_ui_session` — only session creator.

**Response**: `{"ok": True, "goal_id": "..."}`.

### 3.4 DynamoDB Changes

#### 3.4.1 BroadcastTipGoals Table (NEW)

Add to `scripts/local-ddb-init.py`:

```python
TableDef(
    _resolve_table_name(S.broadcast_tip_goals_table_name, "BroadcastTipGoals"),
    "session_id",   # Partition key
    "goal_id",      # Sort key
),
```

| Attribute | Type | Value |
|-----------|------|-------|
| `session_id` | S | Broadcast session ID |
| `goal_id` | S | `"goal_" + uuid4().hex[:12]` |
| `label` | S | Goal label text |
| `target_cents` | N | Target amount in cents |
| `current_cents` | N | Current progress in cents |
| `reached` | BOOL | Whether target has been met |
| `reached_at` | N | Unix timestamp when goal was reached (or absent) |
| `sort_order` | N | Display order (0-4) |
| `created_at` | N | Unix timestamp of creation |
| `created_by` | S | Creator user sub |

No GSIs needed -- all queries are by `session_id` (partition key). Goal lists per session are small (max 5 items).

#### 3.4.2 BroadcastSessions Table — New Attributes

New attributes on existing `BroadcastSessions` table items (no schema change required, just new attribute names):

| Attribute | Type | Default | Purpose |
|-----------|------|---------|---------|
| `tip_total_cents` | N | 0 | Running total of all tips in session |
| `tip_count` | N | 0 | Number of tips received |
| `tip_enabled` | BOOL | True | Whether tipping is enabled for this session |
| `tip_min_cents` | N | 100 | Minimum tip amount |
| `tip_max_cents` | N | 100000 | Maximum tip amount |

These are updated via `ADD` expressions (atomic increment) so no read-before-write race is possible.

#### 3.4.3 BroadcastChatMessages Table — Tip Attributes on Items

Tip messages are stored in the same `BroadcastChatMessages` table with these additional attributes:

| Attribute | Type | Condition | Purpose |
|-----------|------|-----------|---------|
| `kind` | S | `"tip"` | Distinguishes tip messages from text and product_link |
| `tip_amount_cents` | N | Present when `kind="tip"` | Tip amount |
| `tip_currency` | S | Present when `kind="tip"` | Currency code |
| `tip_payment_id` | S | Present when `kind="tip"` | Ledger reference |

No table schema change needed -- DynamoDB is schemaless. These are just new attributes on items with `kind="tip"`.

### 3.5 Settings Changes (`app/core/settings.py`)

Add after the existing broadcast chat settings block (lines 492-496): <!-- VERIFIED: settings.py:494 (broadcast_chat_rate_limit_ms), settings.py:496 (broadcast_chat_history_default_limit) --> <!-- CORRECTED: was "after line 494", more precisely should be after line 496 (broadcast_chat_history_default_limit) or after line 504 (end of broadcast block) to avoid splitting the chat settings group -->

```python
# Broadcast tipping (BCAST-013)
broadcast_tip_rate_limit_ms: int = int(os.environ.get("BROADCAST_TIP_RATE_LIMIT_MS", "3000"))
broadcast_tip_min_cents: int = int(os.environ.get("BROADCAST_TIP_MIN_CENTS", "100"))
broadcast_tip_max_cents: int = int(os.environ.get("BROADCAST_TIP_MAX_CENTS", "100000"))
broadcast_tip_goals_max_per_session: int = int(os.environ.get("BROADCAST_TIP_GOALS_MAX", "5"))
broadcast_tip_goals_table_name: str = os.environ.get("DDB_BROADCAST_TIP_GOALS", "BroadcastTipGoals")
broadcast_tipping_enabled: bool = os.environ.get("BROADCAST_TIPPING_ENABLED", "1") not in ("0", "false", "False")
```

### 3.6 Tables Changes (`app/core/tables.py`)

Add to the `Tables` dataclass (after `broadcast_private_sessions` at line 88): <!-- VERIFIED: tables.py:88 (broadcast_private_sessions: Any) -->

```python
broadcast_tip_goals: Any
```
<!-- NEW: to be created -->

Add to the `T = Tables(...)` constructor (after `broadcast_private_sessions=` at line 188): <!-- VERIFIED: tables.py:188 (broadcast_private_sessions=ddb.Table(...)) -->

```python
broadcast_tip_goals=ddb.Table(S.broadcast_tip_goals_table_name),
```

### 3.7 Session Store Changes (`app/services/broadcast_store.py`)

Extend `session_to_item()` (line 111) to include tip fields: <!-- VERIFIED: broadcast_store.py:111 -->

```python
# After private_chat fields (line 142): <!-- VERIFIED: broadcast_store.py:142 (private_chat_voyeur_price_cents in session_to_item) -->
# Tipping (BCAST-013)
"tip_total_cents": session.tip_total_cents,
"tip_count": session.tip_count,
"tip_enabled": session.tip_enabled,
"tip_min_cents": session.tip_min_cents,
"tip_max_cents": session.tip_max_cents,
```

Extend `session_from_item()` (line 148) to read tip fields: <!-- VERIFIED: broadcast_store.py:148 -->

```python
# After private_chat fields (line 178): <!-- VERIFIED: broadcast_store.py:178 (private_chat_voyeur_price_cents in session_from_item) -->
# Tipping (BCAST-013)
tip_total_cents=int(item.get("tip_total_cents", 0) or 0),
tip_count=int(item.get("tip_count", 0) or 0),
tip_enabled=bool(item.get("tip_enabled", True)),
tip_min_cents=int(item.get("tip_min_cents", 100) or 100),
tip_max_cents=int(item.get("tip_max_cents", 100000) or 100000),
```

### 3.8 Chat Store Changes (`app/services/broadcast_chat_store.py`)

Extend `_chat_msg_out()` (line 296) to include tip fields when present: <!-- VERIFIED: broadcast_chat_store.py:296 -->

```python
def _chat_msg_out(item: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "message_id": item["message_id"],
        "session_id": item["session_id"],
        "sender_id": item["sender_id"],
        "sender_display_name": item.get("sender_display_name", ""),
        "text": item.get("text", ""),
        "kind": item.get("kind", "text"),
        "created_at": int(item.get("created_at", 0)),
        "deleted": bool(item.get("deleted", False)),
    }
    if item.get("product_link"):
        out["product_link"] = item["product_link"]
    # Tip fields (BCAST-013)
    if item.get("kind") == "tip":
        out["tip_amount_cents"] = int(item.get("tip_amount_cents", 0))
        out["tip_currency"] = item.get("tip_currency", "USD")
        out["tip_payment_id"] = item.get("tip_payment_id", "")
    return out
```

The SSE chat polling stream (`broadcast.py` lines 1405-1453) uses `_chat_msg_out()` already (line 1444), so tip messages will be included in the stream with their tip fields. The event type dispatch (line 1446) must be extended: <!-- VERIFIED: broadcast.py:1444 (_chat_msg_out call), broadcast.py:1446 (event_type dispatch) -->

```python
# Current (line 1446): <!-- VERIFIED: broadcast.py:1446 -->
event_type = "chat:product_link" if out.get("kind") == "product_link" else "chat:message"

# Updated:
if out.get("kind") == "product_link":
    event_type = "chat:product_link"
elif out.get("kind") == "tip":
    event_type = "chat:tip"
else:
    event_type = "chat:message"
```

### 3.9 BroadcastSessionOut Extension (`app/routers/broadcast.py`)

Add tip fields to `BroadcastSessionOut` (after line 131): <!-- VERIFIED: broadcast.py:131 (announcement_post_id is last field before model close) -->

```python
class BroadcastSessionOut(BaseModel):
    # ... existing fields ...
    # Tipping (BCAST-013)
    tip_total_cents: int = 0
    tip_count: int = 0
    tip_enabled: bool = True
    tip_min_cents: int = 100
    tip_max_cents: int = 100000
```

### 3.10 SSE Events

| Event Type | Payload | Published By | Trigger |
|------------|---------|-------------|---------|
| `chat:tip` | `{message_id, session_id, sender_id, sender_display_name, text, kind:"tip", tip_amount_cents, tip_currency, tip_payment_id, created_at}` | `send_tip_message()` | Viewer sends a tip |
| `tip:total_update` | `{session_id, tip_total_cents, tip_count, latest_tip: {sender_id, sender_display_name, amount_cents, message_id}}` | `send_tip_message()` | After session total is incremented |
| `goal:created` | `{goal_id, session_id, label, target_cents, current_cents, sort_order, created_at}` | `create_goal()` | Broadcaster creates a goal |
| `goal:progress` | `{goal_id, session_id, label, target_cents, current_cents, reached, tip_applied_cents}` | `advance_goal_progress()` | Tip advances a goal |
| `goal:reached` | `{goal_id, session_id, label, target_cents, current_cents, reached: true, reached_at}` | `advance_goal_progress()` | Goal target met |
| `goal:updated` | `{goal_id, session_id, label, target_cents, current_cents, ...}` | `update_goal()` | Broadcaster edits a goal |
| `goal:deleted` | `{session_id, goal_id}` | `delete_goal()` | Broadcaster deletes a goal |

All events are published via `broadcast_sse_publish(session_id, event)` (from `app/services/broadcast_sse.py` line 29), which distributes to all SSE subscribers for that session. The `_type` key is popped by the SSE stream route (line 632) and used as the SSE event name. <!-- VERIFIED: broadcast_sse.py:29 (broadcast_sse_publish), broadcast.py:632 (item.pop("_type", "update")) -->

### 3.11 Frontend Types

Add to `frontend/src/api/endpoints/broadcast-chat.ts`: <!-- VERIFIED: file exists, ChatMessage interface at lines 5-13 -->

```typescript
export interface ChatMessage {
  message_id: string;
  session_id: string;
  sender_id: string;
  sender_display_name: string;
  text: string;
  kind?: string;
  created_at: number;
  deleted: boolean;
  // Tip fields (BCAST-013)
  tip_amount_cents?: number;
  tip_currency?: string;
  tip_payment_id?: string;
}
```

Add to `frontend/src/api/endpoints/broadcast.ts`: <!-- VERIFIED: file exists -->

```typescript
export interface BroadcastSession {
  // ... existing fields ...
  // Tipping (BCAST-013)
  tip_total_cents?: number;
  tip_count?: number;
  tip_enabled?: boolean;
  tip_min_cents?: number;
  tip_max_cents?: number;
}

export interface BroadcastTipGoal {
  goal_id: string;
  session_id: string;
  label: string;
  target_cents: number;
  current_cents: number;
  reached: boolean;
  reached_at: number | null;
  sort_order: number;
  created_at: number;
}

export interface BroadcastTipSummary {
  session_id: string;
  total_cents: number;
  tip_count: number;
  currency: string;
  top_tippers: Array<{
    user_id: string;
    display_name: string;
    total_cents: number;
    tip_count: number;
  }>;
  recent_tips: Array<{
    message_id: string;
    sender_id: string;
    sender_display_name: string;
    amount_cents: number;
    text: string;
    created_at: number;
  }>;
}

export interface BroadcastTipConfigIn {
  tip_enabled?: boolean;
  tip_min_cents?: number;
  tip_max_cents?: number;
}
```

### 3.12 Frontend API Endpoints

New file `frontend/src/api/endpoints/broadcast-tips.ts`: <!-- NEW: to be created -->

```typescript
import { api } from "@/api/client";
import type {
  BroadcastTipGoal,
  BroadcastTipSummary,
  BroadcastTipConfigIn,
  BroadcastSession,
} from "./broadcast";
import type { ChatMessage } from "./broadcast-chat";

// ─── Tip Actions ───────────────────────────────────────────────

export interface SendTipIn {
  amount_cents: number;
  text?: string;
  payment_method_id: string;
  currency?: string;
}

export const sendBroadcastTip = (sessionId: string, body: SendTipIn) =>
  api.post<ChatMessage>(
    `/broadcast/sessions/${sessionId}/chat/tip`,
    body,
  );

export const getTipSummary = (
  sessionId: string,
  params?: { top_limit?: number; recent_limit?: number },
) =>
  api.get<BroadcastTipSummary>(
    `/broadcast/sessions/${sessionId}/tips/summary`,
    params as Record<string, string>,
  );

export const updateTipConfig = (sessionId: string, body: BroadcastTipConfigIn) =>
  api.patch<BroadcastSession>(
    `/broadcast/sessions/${sessionId}/tips/config`,
    body,
  );

// ─── Tip Goals ─────────────────────────────────────────────────

export interface CreateGoalIn {
  label: string;
  target_cents: number;
  sort_order?: number;
}

export interface UpdateGoalIn {
  label?: string;
  target_cents?: number;
  sort_order?: number;
}

export const createTipGoal = (sessionId: string, body: CreateGoalIn) =>
  api.post<BroadcastTipGoal>(
    `/broadcast/sessions/${sessionId}/goals`,
    body,
  );

export const listTipGoals = (sessionId: string) =>
  api.get<{ goals: BroadcastTipGoal[]; session_id: string }>(
    `/broadcast/sessions/${sessionId}/goals`,
  );

export const updateTipGoal = (
  sessionId: string,
  goalId: string,
  body: UpdateGoalIn,
) =>
  api.patch<BroadcastTipGoal>(
    `/broadcast/sessions/${sessionId}/goals/${goalId}`,
    body,
  );

export const deleteTipGoal = (sessionId: string, goalId: string) =>
  api.del<{ ok: boolean; goal_id: string }>(
    `/broadcast/sessions/${sessionId}/goals/${goalId}`,
  );
```

### 3.13 Frontend Components

#### 3.13.1 `BroadcastTipButton.tsx`

New component: `frontend/src/pages/broadcast/BroadcastTipButton.tsx` <!-- NEW: to be created -->

```typescript
interface BroadcastTipButtonProps {
  sessionId: string;
  tipEnabled: boolean;
  tipMinCents: number;
  tipMaxCents: number;
  /** True if the current user is the broadcaster (hide tip button) */
  isBroadcaster: boolean;
}
```

**UI layout**:

```
┌───────────────────────────────────────────────────────────────┐
│ [ $ Tip ]   <-- floating button, bottom-right of chat panel   │
│                                                               │
│ On click, opens dialog:                                       │
│ ┌─────────────────────────────────────┐                       │
│ │ Send a Tip                    [X]   │                       │
│ ├─────────────────────────────────────┤                       │
│ │ Amount:                             │                       │
│ │ [ $1 ] [ $5 ] [ $10 ] [ $25 ]      │                       │
│ │ Custom: [ $_____ ]                  │                       │
│ │                                     │                       │
│ │ Message (optional):                 │                       │
│ │ [ ________________________________ ]│                       │
│ │                                     │                       │
│ │ Payment Method:                     │                       │
│ │ [ Visa **** 4242              ▼ ]   │                       │
│ │                                     │                       │
│ │          [ Send $5.00 Tip ]         │                       │
│ └─────────────────────────────────────┘                       │
└───────────────────────────────────────────────────────────────┘
```

**State management**:

- `selectedAmount: number | null` — from preset buttons or custom input
- `customAmount: string` — raw input string for custom amounts
- `tipText: string` — optional message text
- `selectedPm: string | null` — selected payment method ID
- `isSubmitting: boolean`

**Payment method fetching**: Uses `useQuery(["billing", "payment-methods"], fetchPaymentMethods)` (same query key as existing billing components to share cache).

**Behavior**:
- Preset buttons: `$1` (100), `$5` (500), `$10` (1000), `$25` (2500). Clicking one selects it and highlights the button.
- Custom input: dollar amount with decimal support. Converts to cents on submit. Client-side validation: `>= tipMinCents/100`, `<= tipMaxCents/100`.
- Send button disabled while `isSubmitting` or no PM selected or no amount selected.
- On success: close dialog, show toast "Tip sent!", clear fields. Optional confetti animation via CSS.
- On error: show error message inline in dialog. Rate limit errors show countdown timer.
- If no payment methods: show "Add a payment method in Billing" link instead of PM selector.
- Hidden when `isBroadcaster` is true (cannot tip yourself).
- Hidden when `tipEnabled` is false (show tooltip "Tipping is disabled for this broadcast").

#### 3.13.2 `TipTicker.tsx`

New component: `frontend/src/pages/broadcast/TipTicker.tsx` <!-- NEW: to be created -->

```typescript
interface TipTickerProps {
  sessionId: string;
  /** Maximum number of tips to show in the ticker at once */
  maxVisible?: number; // default: 5
}

interface TipEvent {
  sender_display_name: string;
  amount_cents: number;
  text: string;
  message_id: string;
  timestamp: number; // when the event was received (client time)
}
```

**UI layout**: A floating vertical strip, positioned at the top-right of the video/chat area. Tips slide in from the right and fade out after 8 seconds.

```
┌──────────────────────────────┐
│                              │
│  ┌────────────────────────┐  │
│  │ 💰 Alice tipped $25.00 │  │
│  │ "Love this content!"   │  │
│  └────────────────────────┘  │
│  ┌────────────────────────┐  │
│  │ 💰 Bob tipped $5.00    │  │
│  └────────────────────────┘  │
│  ┌────────────────────────┐  │
│  │ 💰 Carol tipped $10.00 │  │
│  │ "Keep going!"          │  │
│  └────────────────────────┘  │
│                              │
└──────────────────────────────┘
```

**Behavior**:
- Listens to SSE `chat:tip` events via the broadcast event stream.
- Maintains a sliding window of recent tips (max `maxVisible`).
- Each tip card shows: sender display name, formatted amount, and optional text (truncated to 80 chars).
- Tips fade out after 8 seconds via CSS transition.
- Large tips ($25+) have a highlighted gold border and slightly larger font.
- Tip cards are stacked newest-first (newest at top).

#### 3.13.3 `TipGoalBar.tsx`

New component: `frontend/src/pages/broadcast/TipGoalBar.tsx` <!-- NEW: to be created -->

```typescript
interface TipGoalBarProps {
  goal: BroadcastTipGoal;
  /** Show edit/delete buttons (broadcaster only) */
  showActions?: boolean;
  onEdit?: (goalId: string) => void;
  onDelete?: (goalId: string) => void;
}
```

**UI layout**:

```
┌────────────────────────────────────────────────────────────────┐
│ 🎯 Cooking Segment!                          $350 / $500      │
│ ████████████████████████████░░░░░░░░░░░░░░░░  70%             │
│                                       [Edit] [Delete]          │
└────────────────────────────────────────────────────────────────┘

When goal is reached:
┌────────────────────────────────────────────────────────────────┐
│ 🎯 Cooking Segment!  ✅ REACHED!             $500 / $500      │
│ ██████████████████████████████████████████████ 100%            │
└────────────────────────────────────────────────────────────────┘
```

**Behavior**:
- Progress bar fills proportionally (`current_cents / target_cents * 100%`).
- Color transitions: <50% blue, 50-80% yellow, 80-99% orange, 100% green with pulse animation.
- When `reached` transitions from false to true, a confetti burst animation plays.
- Edit/Delete buttons visible only when `showActions` is true.
- Dollar amounts formatted with `Intl.NumberFormat("en-US", { style: "currency", currency: "USD" })`.

#### 3.13.4 `BroadcastTipSummary.tsx`

New component: `frontend/src/pages/broadcast/BroadcastTipSummary.tsx` <!-- NEW: to be created -->

```typescript
interface BroadcastTipSummaryProps {
  sessionId: string;
  /** Whether to show the full panel (broadcaster) or compact view (viewer) */
  variant: "full" | "compact";
}
```

**Data fetching**: `useQuery(["broadcast", "tips", "summary", sessionId], () => getTipSummary(sessionId), { refetchInterval: 15_000 })`.

**UI layout (full variant, broadcaster panel)**:

```
┌─────────────────────────────────────────────────────────┐
│ Tip Summary                                             │
│─────────────────────────────────────────────────────────│
│                                                         │
│  Total Tips: $1,234.56          Tips Count: 47          │
│                                                         │
│  Top Supporters                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │ 1. Alice      $350.00  (12 tips)                 │  │
│  │ 2. Bob        $250.00  (8 tips)                  │  │
│  │ 3. Carol      $150.00  (5 tips)                  │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
│  Recent Tips                                            │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Alice     $25.00   "Love this!"    2 min ago     │  │
│  │ Bob       $10.00                   5 min ago     │  │
│  │ Carol     $5.00    "Great stream"  8 min ago     │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**Compact variant** (visible to all viewers): Just the running total and top 3 tippers.

```
┌─────────────────────────────────────┐
│ 💰 $1,234.56 from 47 tips          │
│ Top: Alice $350 · Bob $250 · Carol  │
└─────────────────────────────────────┘
```

### 3.14 Frontend Integration Points

#### 3.14.1 BroadcastChat.tsx Changes

The existing `BroadcastChat` component (`frontend/src/pages/broadcast/BroadcastChat.tsx`) must handle the `chat:tip` SSE event: <!-- VERIFIED: BroadcastChat.tsx exists -->

```typescript
// Add alongside existing SSE event listeners (lines 61-69): <!-- VERIFIED: BroadcastChat.tsx:61-69 -->
es.addEventListener("chat:tip", (event) => {
  const msg: ChatMessage = JSON.parse(event.data);
  setMessages((prev) => [...prev, msg].slice(-500));
});
```

Tip messages in the chat list render with a special card (gold background, amount badge):

```typescript
// In the message rendering loop:
{msg.kind === "tip" ? (
  <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-2">
    <div className="flex items-center gap-2">
      <Badge variant="outline" className="bg-yellow-400 text-black font-bold">
        ${(msg.tip_amount_cents! / 100).toFixed(2)}
      </Badge>
      <span className="font-semibold">{msg.sender_display_name}</span>
    </div>
    {msg.text && <p className="text-sm mt-1">{msg.text}</p>}
  </div>
) : (
  // existing text/product_link rendering
)}
```

#### 3.14.2 LivePlayer.tsx Changes

The `LivePlayer` component (`frontend/src/pages/broadcast/LivePlayer.tsx`) must: <!-- VERIFIED: LivePlayer.tsx exists -->

1. Render `TipTicker` overlay on the video player area.
2. Render `TipGoalBar` components above or below the video.
3. Render `BroadcastTipButton` in the chat panel area.
4. Subscribe to goal SSE events and update goal state.

#### 3.14.3 BroadcastPage.tsx Changes

The `BroadcastPage` dashboard (`frontend/src/pages/broadcast/BroadcastPage.tsx`) must: <!-- VERIFIED: BroadcastPage.tsx exists -->

1. Show `BroadcastTipSummary` (full variant) in the session detail view.
2. Show goal management (create/edit/delete) in the session settings panel.
3. Show tip configuration (enable/disable, min/max) in session settings.

---

## 4. Implementation Plan

### Phase 1: Backend Models + Tip Ledger Extension (1 day)

| File | Change |
|------|--------|
| `app/models_broadcast.py` | Add `tip_total_cents`, `tip_count`, `tip_enabled`, `tip_min_cents`, `tip_max_cents` to `BroadcastSessionModel`. | <!-- VERIFIED: file exists, model at line 37 -->
| `app/services/tip_ledger.py` | Add `"broadcast"` to `content_type` validation set (line 50) and `_reason_for_content_type()` map (line 63). | <!-- VERIFIED: tip_ledger.py:50,63 -->
| `app/services/broadcast_store.py` | Extend `session_to_item()` (line 111) and `session_from_item()` (line 148) with tip fields. | <!-- VERIFIED: broadcast_store.py:111,148 -->
| `app/services/broadcast_chat_store.py` | Extend `_chat_msg_out()` (line 296) to include tip fields when `kind="tip"`. | <!-- VERIFIED: broadcast_chat_store.py:296 -->
| `app/core/settings.py` | Add 6 new tip-related settings after the broadcast chat settings block (line 496). | <!-- VERIFIED: settings.py:496 --> <!-- CORRECTED: was "after line 494", should be after line 496 to avoid splitting broadcast_chat settings group -->
| `app/core/tables.py` | Add `broadcast_tip_goals` table handle. | <!-- VERIFIED: tables.py exists, last broadcast handle at line 88 -->
| `scripts/local-ddb-init.py` | Add `BroadcastTipGoals` table definition. | <!-- VERIFIED: file exists -->

### Phase 2: Tip Service + Goal Service (2-3 days)

| File | Change |
|------|--------|
| `app/services/broadcast_tip_store.py` | New file: `send_tip_message()`, `get_tip_summary()`, `_validate_payment_method()`, `_increment_session_tip_totals()`, `_query_tip_messages()`, rate limit functions. | <!-- NEW: to be created -->
| `app/services/broadcast_tip_goals.py` | New file: `create_goal()`, `list_goals()`, `get_goal()`, `update_goal()`, `delete_goal()`, `advance_goal_progress()`. | <!-- NEW: to be created -->

### Phase 3: API Endpoints (1-2 days)

| File | Change |
|------|--------|
| `app/routers/broadcast.py` | Add Pydantic models: `BroadcastChatTipIn`, `BroadcastTipGoalCreateIn`, `BroadcastTipGoalOut`, `BroadcastTipGoalUpdateIn`, `BroadcastTipGoalsListOut`, `BroadcastTipSummaryOut`, `BroadcastTopTipperItem`, `BroadcastRecentTipItem`, `BroadcastTipConfigIn`. Add endpoints: `POST /sessions/{id}/chat/tip`, `GET /sessions/{id}/tips/summary`, `PATCH /sessions/{id}/tips/config`, `POST /sessions/{id}/goals`, `GET /sessions/{id}/goals`, `PATCH /sessions/{id}/goals/{goal_id}`, `DELETE /sessions/{id}/goals/{goal_id}`. Extend `BroadcastSessionOut` and `BroadcastChatMessageOut` with tip fields. Extend SSE chat stream event type dispatch (line 1446). | <!-- VERIFIED: broadcast.py:1446 -->

### Phase 4: Frontend Types + API Layer (1 day)

| File | Change |
|------|--------|
| `frontend/src/api/endpoints/broadcast-chat.ts` | Add tip fields to `ChatMessage` interface. |
| `frontend/src/api/endpoints/broadcast.ts` | Add tip fields to `BroadcastSession`. Add `BroadcastTipGoal`, `BroadcastTipSummary`, `BroadcastTipConfigIn` interfaces. |
| `frontend/src/api/endpoints/broadcast-tips.ts` | New file: all tip and goal API function wrappers. |

### Phase 5: Frontend Components (3-4 days)

| File | Change |
|------|--------|
| `frontend/src/pages/broadcast/BroadcastTipButton.tsx` | New: tip dialog with amount presets and PM selector. |
| `frontend/src/pages/broadcast/TipTicker.tsx` | New: animated floating tip feed overlay. |
| `frontend/src/pages/broadcast/TipGoalBar.tsx` | New: animated progress bar with label and amounts. |
| `frontend/src/pages/broadcast/BroadcastTipSummary.tsx` | New: broadcaster-only stats panel (full) + viewer compact view. |
| `frontend/src/pages/broadcast/BroadcastChat.tsx` | Handle `chat:tip` SSE event. Render tip messages with special card styling. |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Integrate TipTicker, TipGoalBar, BroadcastTipButton overlays. Subscribe to goal SSE events. |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Add BroadcastTipSummary to session detail. Add goal management UI. Add tip config UI. |

### Phase 6: E2E Tests (2 days)

| File | Change |
|------|--------|
| `frontend/e2e/broadcast-tips.spec.ts` | New: sections 131-137 (40+ tests). |

### Summary of All Files

| File | Type | Estimated Lines Changed/Added |
|------|------|-------------------------------|
| `app/models_broadcast.py` | Modify | +6 |
| `app/services/tip_ledger.py` | Modify | +4 |
| `app/services/broadcast_store.py` | Modify | +20 |
| `app/services/broadcast_chat_store.py` | Modify | +10 |
| `app/services/broadcast_tip_store.py` | Create | ~300 | <!-- NEW: to be created -->
| `app/services/broadcast_tip_goals.py` | Create | ~280 | <!-- NEW: to be created -->
| `app/routers/broadcast.py` | Modify | ~250 |
| `app/core/settings.py` | Modify | +6 |
| `app/core/tables.py` | Modify | +3 |
| `scripts/local-ddb-init.py` | Modify | +8 |
| `frontend/src/api/endpoints/broadcast-chat.ts` | Modify | +5 |
| `frontend/src/api/endpoints/broadcast.ts` | Modify | +40 |
| `frontend/src/api/endpoints/broadcast-tips.ts` | Create | ~80 | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/BroadcastTipButton.tsx` | Create | ~200 | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/TipTicker.tsx` | Create | ~120 | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/TipGoalBar.tsx` | Create | ~100 | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/BroadcastTipSummary.tsx` | Create | ~150 | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/BroadcastChat.tsx` | Modify | +30 |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Modify | +60 |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Modify | +80 |
| `frontend/e2e/broadcast-tips.spec.ts` | Create | ~600 | <!-- NEW: to be created -->
| **Total** | | **~2350** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_tips.py`) <!-- NEW: to be created -->

New file, ~250 lines. Tests service functions with moto-mocked DynamoDB.

```python
import pytest
from moto import mock_dynamodb
from unittest.mock import patch, MagicMock

from app.services.broadcast_tip_store import (
    send_tip_message,
    get_tip_summary,
    _validate_payment_method,
    _increment_session_tip_totals,
    _enforce_tip_rate_limit,
    reset_tip_rate_limits,
)
from app.services.broadcast_tip_goals import (
    create_goal,
    list_goals,
    get_goal,
    update_goal,
    delete_goal,
    advance_goal_progress,
    MAX_GOALS_PER_SESSION,
)


# ─── Tip Message Tests ─────────────────────────────────────────

def test_send_tip_writes_ledger_entries(broadcast_tables, billing_tables):
    """Verify send_tip_message writes debit + credit to billing table."""
    _seed_payment_method("viewer1", "pm_test_123")
    _seed_session("s1", created_by="broadcaster1")
    result = send_tip_message(
        session_id="s1",
        user_id="viewer1",
        display_name="Viewer One",
        amount_cents=500,
        payment_method_id="pm_test_123",
        broadcaster_id="broadcaster1",
    )
    assert result["kind"] == "tip"
    assert result["tip_amount_cents"] == 500
    assert result["tip_currency"] == "USD"
    # Verify billing entries
    debit_items = _query_billing("USER#viewer1", "LEDGER#")
    assert len(debit_items) == 1
    assert debit_items[0]["amount_cents"] == 500
    assert debit_items[0]["type"] == "debit"
    credit_items = _query_billing("USER#broadcaster1", "LEDGER#")
    assert len(credit_items) == 1
    assert credit_items[0]["amount_cents"] == 500
    assert credit_items[0]["type"] == "credit"


def test_send_tip_increments_session_totals(broadcast_tables, billing_tables):
    """Two tips should increment tip_total_cents and tip_count atomically."""
    _seed_payment_method("viewer1", "pm1")
    _seed_session("s1", created_by="broadcaster1")
    send_tip_message(session_id="s1", user_id="viewer1", display_name="V1",
                     amount_cents=100, payment_method_id="pm1", broadcaster_id="broadcaster1")
    reset_tip_rate_limits()
    send_tip_message(session_id="s1", user_id="viewer1", display_name="V1",
                     amount_cents=200, payment_method_id="pm1", broadcaster_id="broadcaster1")
    session = _get_session("s1")
    assert int(session.get("tip_total_cents", 0)) == 300
    assert int(session.get("tip_count", 0)) == 2


def test_send_tip_rejects_self_tip(broadcast_tables, billing_tables):
    """Broadcaster cannot tip their own broadcast."""
    _seed_payment_method("broadcaster1", "pm1")
    _seed_session("s1", created_by="broadcaster1")
    with pytest.raises(HTTPException) as exc_info:
        send_tip_message(session_id="s1", user_id="broadcaster1",
                         display_name="BC", amount_cents=100,
                         payment_method_id="pm1", broadcaster_id="broadcaster1")
    assert exc_info.value.status_code == 400
    assert "CANNOT_TIP_SELF" in str(exc_info.value.detail)


def test_send_tip_rejects_invalid_pm(broadcast_tables, billing_tables):
    """Non-existent payment method returns 400."""
    _seed_session("s1", created_by="broadcaster1")
    with pytest.raises(HTTPException) as exc_info:
        send_tip_message(session_id="s1", user_id="viewer1",
                         display_name="V1", amount_cents=100,
                         payment_method_id="pm_nonexistent",
                         broadcaster_id="broadcaster1")
    assert exc_info.value.status_code == 400


def test_send_tip_rejects_below_minimum(broadcast_tables, billing_tables):
    """Tip below 100 cents returns 400."""
    _seed_payment_method("viewer1", "pm1")
    _seed_session("s1", created_by="broadcaster1")
    with pytest.raises(HTTPException) as exc_info:
        send_tip_message(session_id="s1", user_id="viewer1",
                         display_name="V1", amount_cents=50,
                         payment_method_id="pm1", broadcaster_id="broadcaster1")
    assert exc_info.value.status_code == 400
    assert "TIP_TOO_SMALL" in str(exc_info.value.detail)


def test_tip_rate_limit(broadcast_tables, billing_tables):
    """Two tips within 3 seconds returns 429."""
    _seed_payment_method("viewer1", "pm1")
    _seed_session("s1", created_by="broadcaster1")
    send_tip_message(session_id="s1", user_id="viewer1",
                     display_name="V1", amount_cents=100,
                     payment_method_id="pm1", broadcaster_id="broadcaster1")
    with pytest.raises(HTTPException) as exc_info:
        send_tip_message(session_id="s1", user_id="viewer1",
                         display_name="V1", amount_cents=100,
                         payment_method_id="pm1", broadcaster_id="broadcaster1")
    assert exc_info.value.status_code == 429


# ─── Tip Summary Tests ──────────────────────────────────────────

def test_tip_summary_aggregates_correctly(broadcast_tables, billing_tables):
    """Summary returns correct total, count, top tippers, and recent tips."""
    _seed_payment_method("v1", "pm1")
    _seed_payment_method("v2", "pm2")
    _seed_session("s1", created_by="bc1")
    send_tip_message(session_id="s1", user_id="v1", display_name="V1",
                     amount_cents=500, payment_method_id="pm1", broadcaster_id="bc1")
    reset_tip_rate_limits()
    send_tip_message(session_id="s1", user_id="v2", display_name="V2",
                     amount_cents=200, payment_method_id="pm2", broadcaster_id="bc1")
    reset_tip_rate_limits()
    send_tip_message(session_id="s1", user_id="v1", display_name="V1",
                     amount_cents=300, payment_method_id="pm1", broadcaster_id="bc1")
    summary = get_tip_summary("s1")
    assert summary["total_cents"] == 1000
    assert summary["tip_count"] == 3
    assert len(summary["top_tippers"]) == 2
    assert summary["top_tippers"][0]["user_id"] == "v1"
    assert summary["top_tippers"][0]["total_cents"] == 800
    assert len(summary["recent_tips"]) == 3


# ─── Goal Tests ─────────────────────────────────────────────────

def test_create_goal_succeeds(goal_tables):
    """Creating a goal returns the goal with zero progress."""
    goal = create_goal(session_id="s1", label="Dance break", target_cents=1000, actor="bc1")
    assert goal["label"] == "Dance break"
    assert goal["target_cents"] == 1000
    assert goal["current_cents"] == 0
    assert goal["reached"] is False


def test_create_goal_max_limit(goal_tables):
    """Creating more than MAX_GOALS_PER_SESSION goals returns 409."""
    for i in range(MAX_GOALS_PER_SESSION):
        create_goal(session_id="s1", label=f"Goal {i}", target_cents=1000, actor="bc1")
    with pytest.raises(HTTPException) as exc_info:
        create_goal(session_id="s1", label="Too many", target_cents=1000, actor="bc1")
    assert exc_info.value.status_code == 409


def test_advance_goal_fills_in_order(goal_tables):
    """Tips fill goals in sort_order. Overflow spills to next goal."""
    create_goal(session_id="s1", label="G1", target_cents=500, sort_order=0, actor="bc1")
    create_goal(session_id="s1", label="G2", target_cents=1000, sort_order=1, actor="bc1")
    updated = advance_goal_progress("s1", 600)
    assert len(updated) == 2
    assert updated[0]["current_cents"] == 500  # G1 filled
    assert updated[0]["reached"] is True
    assert updated[1]["current_cents"] == 100  # overflow to G2
    assert updated[1]["reached"] is False


def test_advance_goal_reached_event(goal_tables):
    """When a goal is reached, SSE goal:reached event is published."""
    create_goal(session_id="s1", label="G1", target_cents=100, actor="bc1")
    with patch("app.services.broadcast_tip_goals.broadcast_sse_publish") as mock_sse:
        advance_goal_progress("s1", 100)
        reached_calls = [c for c in mock_sse.call_args_list
                        if c[0][1].get("_type") == "goal:reached"]
        assert len(reached_calls) == 1


def test_delete_goal(goal_tables):
    """Deleting a goal removes it from the table."""
    goal = create_goal(session_id="s1", label="G1", target_cents=100, actor="bc1")
    delete_goal("s1", goal["goal_id"])
    goals = list_goals("s1")
    assert len(goals) == 0


def test_update_goal(goal_tables):
    """Updating a goal modifies only the specified fields."""
    goal = create_goal(session_id="s1", label="Old Label", target_cents=100, actor="bc1")
    updated = update_goal("s1", goal["goal_id"], label="New Label")
    assert updated["label"] == "New Label"
    assert updated["target_cents"] == 100  # unchanged
```

### 5.2 E2E Tests (`frontend/e2e/broadcast-tips.spec.ts`) <!-- NEW: to be created -->

New file, ~600 lines, sections 131-137.

**Test Setup (`beforeAll`)**:

```typescript
let rootPage: Page;
let alicePage: Page;
const TS = Date.now();
let profileId: string;
let sessionId: string;

const ALICE_SUB = sessions.alice.user_sub;
const ROOT_SUB = sessions.root.user_sub;

test.beforeAll(async ({ browser }) => {
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");

  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");

  // Create broadcast profile
  const profileResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
    name: `tip-test-profile-${TS}`,
    region: "us-east-1",
    rendition_preset: "720p",
  });
  profileId = profileResp.id;

  // Create and start session
  const sessionResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
    profile_id: profileId,
  });
  sessionId = sessionResp.id;

  // Transition to live (provisioning -> ready -> live)
  await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/start`, {
    reason: "e2e-tip-test",
  });

  // Seed Alice's payment method
  await seedPaymentMethod(ALICE_SUB, "pm_alice_tip_test");
});
```

**Section 131: Broadcast Tip API — Basic (6 tests)**:

1. `Alice sends a $5 tip to the broadcaster` — POST `/chat/tip` with `amount_cents: 500`, verify 201 response with `kind: "tip"`, `tip_amount_cents: 500`.
2. `Tip appears in chat history` — GET `/chat` and verify the tip message is in the `messages` array with `kind: "tip"`.
3. `Session tip_total_cents is incremented` — GET `/sessions/{id}` and verify `tip_total_cents: 500`, `tip_count: 1`.
4. `Second tip increments total` — Send another $10 tip, verify `tip_total_cents: 1500`, `tip_count: 2`.
5. `Tip with optional text includes text in response` — Send tip with `text: "Great stream!"`, verify response includes the text.
6. `Tip ledger has debit entry for Alice` — Query billing table for `USER#${ALICE_SUB}` and verify a debit entry with `reason: "Tip: broadcast"` and `amount_cents: 500`.

**Section 132: Broadcast Tip Validation (6 tests)**:

1. `Tip below $1 minimum returns 400` — Send with `amount_cents: 50`, expect 400 with code `TIP_TOO_SMALL`.
2. `Tip above $1000 maximum returns 400` — Send with `amount_cents: 200000`, expect 400 with code `TIP_TOO_LARGE`.
3. `Tip with invalid payment method returns 400` — Send with `payment_method_id: "pm_nonexistent"`, expect 400.
4. `Broadcaster cannot tip own broadcast` — Root sends tip to own session, expect 400 with code `CANNOT_TIP_SELF`.
5. `Tip on non-live session returns 403` — Stop the session first, attempt tip, expect 403 with code `BROADCAST_NOT_LIVE`.
6. `Tip rate limit returns 429 on rapid tips` — Send two tips in quick succession (within 3s), expect 429 on second.

**Section 133: Tip Summary API (4 tests)**:

1. `Tip summary returns correct total and count` — GET `/tips/summary`, verify `total_cents` and `tip_count` match accumulated tips.
2. `Top tippers are sorted by total descending` — Have Alice and Bob (via separate seeded PM) both tip, verify Alice's total is first if larger.
3. `Recent tips are sorted by created_at descending` — Verify `recent_tips[0]` is the most recent tip.
4. `Summary with no tips returns zero values` — Fresh session with no tips, verify `total_cents: 0`, `tip_count: 0`, empty arrays.

**Section 134: Tip Goal CRUD API (7 tests)**:

1. `Broadcaster creates a tip goal` — POST `/goals` with `{label: "Dance break", target_cents: 5000}`, verify 201 with `goal_id`, `current_cents: 0`, `reached: false`.
2. `List goals returns created goals` — GET `/goals`, verify the goal is in the list.
3. `Broadcaster creates a second goal with higher sort_order` — Create with `sort_order: 1`, verify list is ordered correctly.
4. `Broadcaster updates goal label` — PATCH `/goals/{id}` with `{label: "New label"}`, verify updated.
5. `Broadcaster deletes a goal` — DELETE `/goals/{id}`, verify 200 and goal is gone from list.
6. `Non-creator cannot create goals` — Alice (viewer) attempts POST `/goals`, expect 403.
7. `Maximum 5 goals per session` — Create 5 goals, attempt 6th, expect 409 with code `MAX_GOALS_REACHED`.

**Section 135: Tip Goal Progress (5 tests)**:

1. `Tip advances goal progress` — Create goal with `target_cents: 1000`. Send $5 tip. Verify goal `current_cents: 500`.
2. `Tip reaching goal marks it as reached` — Send enough tips to reach `target_cents`. Verify `reached: true` and `reached_at` is set.
3. `Overflow spills to next goal` — Create two goals (G1: $5, G2: $10). Send $8 tip. Verify G1 reached ($5), G2 has $3 progress.
4. `Already-reached goals are skipped` — Goal G1 already reached. New tip goes to G2 only.
5. `Goal progress with no goals is a no-op` — Send tip with no goals set. Verify no errors, session totals still increment.

**Section 136: Tip Config API (3 tests)**:

1. `Broadcaster disables tipping` — PATCH `/tips/config` with `{tip_enabled: false}`. Verify session response has `tip_enabled: false`.
2. `Tip on disabled-tipping session returns 403` — With tipping disabled, attempt tip, expect 403 with code `TIPPING_DISABLED`.
3. `Broadcaster sets custom min/max` — PATCH `/tips/config` with `{tip_min_cents: 500, tip_max_cents: 50000}`. Verify $4.99 tip rejected, $5.00 accepted.

**Section 137: Broadcast Tips UI (5 tests)**:

1. `Tip button is visible on live broadcast page` — Navigate to `/broadcast/live/{sessionId}` as Alice. Verify `getByRole("button", { name: /tip/i })` is visible.
2. `Tip dialog opens with amount presets` — Click tip button. Verify dialog with `$1`, `$5`, `$10`, `$25` buttons.
3. `Tip dialog shows payment method selector` — Verify dropdown with Alice's seeded PM.
4. `Goal progress bar renders with correct percentage` — Create a goal, send some tips, navigate. Verify progress bar element with correct width style.
5. `Tip button is hidden for broadcaster` — Navigate as root (session creator). Verify tip button is not visible.

### 5.3 Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Tip during session status transition (live -> stopping) | Tip is accepted if session is still `"live"` at validation time. If status changed between check and write, tip message is written but SSE may not be received by disconnecting viewers. |
| Two viewers tip simultaneously | Each tip writes its own ledger entries independently. `ADD` expression on session totals is atomic. Both tips are counted correctly. |
| Tip with amount_cents = 100 (exact minimum) | Accepted. Boundary value is inclusive (`ge=100`). |
| Tip with amount_cents = 100000 (exact maximum) | Accepted. Boundary value is inclusive (`le=100000`). |
| Goal with target_cents = current_cents (already met) | `advance_goal_progress` marks it as reached and publishes `goal:reached` event. |
| Delete goal with progress | Goal is deleted regardless of progress. Tip total on session is unaffected. |
| Viewer with no payment methods | Tip dialog shows "Add a payment method in Billing" message. Send button is disabled. |
| Muted viewer attempts to tip | Returns 403 with code `BROADCAST_CHAT_MUTED` (same as regular chat). |
| Very large tip ($1000) followed by rate limit | Tip is accepted. Rate limit prevents a second tip within 3 seconds but does not retroactively block the first. |
| Session stopped — tip summary still accessible | GET `/tips/summary` works for any session regardless of status. Historical data persists. |
| Goal overflow exceeds all goals | Extra amount beyond all goals is not tracked anywhere (it adds to session `tip_total_cents` but not to any goal). This is intentional — goals track threshold milestones, not total allocation. |

### 5.4 Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| Tip rate limit blocking sequential tests | Call `reset_tip_rate_limits()` in service-level tests. In E2E, wait 3.5 seconds between tips or use `test.setTimeout(60_000)`. |
| SSE events not received before assertion | For UI tests asserting tip visibility in chat, use `page.waitForResponse` matching the POST `/chat/tip` endpoint. For goal progress, poll the GET `/goals` endpoint. |
| Session state accumulation from prior runs | Each test run creates a fresh session with unique profile name (`TS` suffix). |
| Tip summary aggregation timing | Summary queries DDB directly (not SSE). A short delay (500ms) after the last tip ensures the `_increment_session_tip_totals` update has propagated. |
| Goal progress SSE race with assertion | Do not assert SSE event content directly. Instead, assert the goal state via GET `/goals` after a short delay. |

---

## 6. Security Considerations

### 6.1 Authentication & Authorization

- **Send tip**: Requires `require_ui_session` (cookie-based session). Only viewers who are authenticated can tip. The tipper's identity is derived from the session (`ctx["user_sub"]`), not from request body, preventing identity spoofing.
- **Tip config**: Only the session creator (`ctx["user_sub"] == session.created_by`) can modify tip settings. Viewers cannot disable or change tip limits.
- **Goal CRUD**: Only the session creator can create, update, or delete goals. Viewers can list goals (read-only).
- **Tip summary**: Available to any authenticated user. Contains aggregate data only — individual tipper `user_id` values are exposed, but display names are already public in chat.

### 6.2 Payment Method Validation

Payment methods are validated against the billing table before every tip. The query pattern matches the existing messaging tip flow (`app/routers/messaging.py` lines 12378-12392): <!-- VERIFIED: messaging.py:12378-12392 -->

1. Query `T.billing` with `pk=USER#{user_id}`.
2. Filter items with `sk` starting with `"PM#"`.
3. Extract `payment_method_id` from each item.
4. Verify the submitted `payment_method_id` is in the set.

This prevents users from submitting arbitrary PM IDs that belong to other users.

### 6.3 Input Validation

| Field | Validation | Rationale |
|-------|-----------|-----------|
| `amount_cents` | `ge=100, le=100000` | Prevents dust tips and unreasonably large tips. $1 min, $1000 max. |
| `text` | `max_length=280` | Same as regular chat messages. Prevents abuse via long strings. |
| `payment_method_id` | `min_length=1, max_length=200` | Must be non-empty and bounded. |
| `currency` | `pattern=r"^[A-Z]{3}$"` | ISO 4217 format enforcement. |
| `goal.label` | `min_length=1, max_length=200` | Non-empty, bounded. |
| `goal.target_cents` | `ge=100, le=10000000` | $1 min, $100K max target. |
| `goal.sort_order` | `ge=0, le=4` | Max 5 goals, orders 0-4. |

### 6.4 Abuse Vectors

| Attack | Mitigation |
|--------|------------|
| Tip spam (rapid fire) | 3-second rate limit per user per session. Rate limit response includes `retry_after_ms`. |
| Tip text abuse (hate speech, spam) | Tip text is a chat message — existing chat moderation (mute, delete) applies. Moderators can delete tip messages. |
| Fake payment method IDs | PM validation against billing table. Non-existent PM returns 400. |
| Self-tipping for leaderboard manipulation | Explicit self-tip check (`user_id == broadcaster_id`) returns 400. |
| Goal manipulation by non-creator | All goal mutation endpoints verify `ctx["user_sub"] == session.created_by`. |
| Concurrent goal progress corruption | DynamoDB `ADD` expression is atomic. Two concurrent tips both add correctly. |
| Billing ledger manipulation | Ledger writes are append-only (`put_item`). No update or delete API for ledger entries. |

### 6.5 Financial Controls

- **Idempotency**: Each tip generates a unique `tip_payment_id` (`bctip_{uuid}`). In production, this ID should be used as an idempotency key for the payment processor to prevent double-charging on retries.
- **Ledger consistency**: Debit and credit entries are written separately (not in a transaction). If one write fails, the tip is partially recorded. The existing `write_tip_ledger()` pattern (lines 108-147 in `tip_ledger.py`) logs warnings on write failures but does not propagate exceptions. <!-- VERIFIED: tip_ledger.py:108-147 (try/except blocks for debit and credit writes) --> This is consistent with the existing messaging tip behavior.
- **Currency enforcement**: Only USD is supported in v1. The `currency` field defaults to `"USD"` and the Pydantic validator ensures it matches the ISO 4217 pattern. Multi-currency support would require exchange rate logic and is out of scope.

---

## 7. Migration & Rollback Plan

### 7.1 DDB Changes

1. **New table `BroadcastTipGoals`**: Created by `scripts/local-ddb-init.py`. In production, create via `aws dynamodb create-table` before code deploy. Simple PK/SK table, no GSIs.
2. **New attributes on `BroadcastSessions`**: `tip_total_cents`, `tip_count`, `tip_enabled`, `tip_min_cents`, `tip_max_cents` are new attributes on existing items. DynamoDB is schemaless — no migration needed. Existing sessions will have these fields absent; `session_from_item()` defaults them to `0`/`True`/`100`/`100000`.
3. **New attributes on `BroadcastChatMessages`**: `tip_amount_cents`, `tip_currency`, `tip_payment_id` on items with `kind="tip"`. No schema change.

### 7.2 Schema Backward Compatibility

- All new fields on `BroadcastSessionModel` have defaults (`tip_total_cents=0`, `tip_count=0`, `tip_enabled=True`, `tip_min_cents=100`, `tip_max_cents=100000`). Existing sessions without these fields work correctly.
- `BroadcastChatMessageOut` gains optional tip fields (all `Optional` with `None` defaults). Existing clients that do not read these fields are unaffected.
- The `_chat_msg_out()` helper only adds tip fields when `kind == "tip"`. Existing text and product_link messages are unchanged.
- `TipLedgerEntry.content_type` validation is expanded from 3 to 4 allowed values. Existing code that passes `"message"`, `"post"`, or `"comment"` is unaffected.

### 7.3 Feature Flag

- `BROADCAST_TIPPING_ENABLED` (default `"true"`): Controls whether the tip endpoint is active. When `"false"`, `POST /chat/tip` returns 403 with code `TIPPING_DISABLED`.
- Per-session `tip_enabled` flag: Broadcasters can disable tipping for individual sessions.
- Both flags must be `true` for tipping to work.

### 7.4 Rollback Steps

1. Set `BROADCAST_TIPPING_ENABLED=false` to disable tipping globally. Existing tip data remains in DDB.
2. Revert frontend to remove tip UI components. Chat history with `kind="tip"` messages will show as plain text messages (graceful degradation — the text field still contains any tip message text).
3. Revert backend endpoints. Existing `BroadcastTipGoals` table and tip attributes on sessions are orphaned but harmless.
4. No data migration needed on rollback. Tip ledger entries in the billing table are permanent financial records and should not be deleted.

### 7.5 Zero-Downtime Deployment

- Backend endpoints are additive (new routes + modified models with optional fields).
- No existing endpoint behavior is changed.
- New DDB table creation is independent of application deployment.
- Frontend changes are bundled in the Vite build.
- The `ADD` expression for session tip totals works correctly even if the attribute does not exist on the item (DynamoDB `ADD` on a non-existent numeric attribute treats it as 0).

---

## 8. Acceptance Criteria

### Tipping Core

1. A viewer can send a tip (100-100000 cents) to a live broadcast by submitting `POST /broadcast/sessions/{id}/chat/tip` with `amount_cents`, `payment_method_id`, and optional `text`. The response is a 201 with `kind: "tip"` and the tip amount fields populated.
2. The tipper's payment method is validated against the billing table before the tip is processed. An invalid or missing PM returns HTTP 400 with code `PAYMENT_METHOD_NOT_FOUND`.
3. Each tip writes paired debit (tipper) and credit (broadcaster) entries to the billing table with `reason: "Tip: broadcast"` and the session ID in metadata.
4. The broadcaster's own attempt to tip their broadcast returns HTTP 400 with code `CANNOT_TIP_SELF`.
5. Tips below the minimum (default 100 cents) return HTTP 400 with code `TIP_TOO_SMALL`. Tips above the maximum (default 100000 cents) return HTTP 400 with code `TIP_TOO_LARGE`.
6. Tips on a non-live session return HTTP 403 with code `BROADCAST_NOT_LIVE`.
7. Tips are rate-limited to one per 3 seconds per user per session. Exceeding the limit returns HTTP 429 with code `BROADCAST_TIP_RATE_LIMITED` and `retry_after_ms`.
8. Muted users cannot tip (HTTP 403 with code `BROADCAST_CHAT_MUTED`).

### Tip Monitor / Running Total

9. Each tip atomically increments `tip_total_cents` and `tip_count` on the session record using DynamoDB `ADD` expressions (no read-before-write race).
10. After each tip, a `tip:total_update` SSE event is published to all session subscribers containing `tip_total_cents`, `tip_count`, and the latest tip's sender info.
11. `GET /broadcast/sessions/{id}/tips/summary` returns the session tip total, count, top tippers (aggregated by user, sorted by total descending), and recent tips (sorted by time descending).
12. The tip summary endpoint is accessible to all authenticated users and works for sessions in any status (including stopped).

### Tip Goals

13. A broadcaster can create up to 5 tip goals per session via `POST /broadcast/sessions/{id}/goals` with `label` and `target_cents`.
14. Attempting to create a 6th goal returns HTTP 409 with code `MAX_GOALS_REACHED`.
15. Goals can be created when the session is in `draft`, `scheduled`, `ready`, or `live` status.
16. `GET /broadcast/sessions/{id}/goals` returns all goals ordered by `sort_order` then `created_at`.
17. When a tip is received, goal progress is advanced sequentially by sort_order. Each goal fills up to its `target_cents` before overflow spills to the next goal.
18. When a goal's `current_cents` reaches or exceeds `target_cents`, it is marked `reached: true` and a `goal:reached` SSE event is published.
19. Progress updates for each affected goal publish `goal:progress` SSE events with the applied amount and current state.
20. Only the session creator can create, update, or delete goals. Viewers get HTTP 403.

### Tip Configuration

21. A broadcaster can enable/disable tipping and set custom min/max amounts via `PATCH /broadcast/sessions/{id}/tips/config`.
22. When tipping is disabled (`tip_enabled: false`), `POST /chat/tip` returns HTTP 403 with code `TIPPING_DISABLED`.

### Chat Integration

23. Tip messages appear in chat history (`GET /broadcast/sessions/{id}/chat`) alongside regular messages, with `kind: "tip"` and tip amount fields.
24. The SSE chat polling stream (`/chat/stream`) dispatches tip messages with event type `chat:tip`.
25. Tip messages in the chat are rendered with a highlighted card (gold background, amount badge) in the frontend.

### Frontend Components

26. The `BroadcastTipButton` is visible to viewers on live broadcasts and hidden for the broadcaster. It opens a dialog with amount presets ($1, $5, $10, $25), custom input, and payment method selector.
27. The `TipTicker` overlay shows recent tips sliding in with animations and fading out after 8 seconds.
28. The `TipGoalBar` renders a progress bar with the goal label, current/target amounts, and percentage. Reaching the target triggers a visual celebration.
29. The `BroadcastTipSummary` (full variant) shows running total, top supporters, and recent tips to the broadcaster. The compact variant shows a one-line summary to viewers.

### Testing

30. All E2E tests (sections 131-137) pass with 0 flakes on 3 consecutive runs.
31. Unit tests cover: tip message creation + ledger write, session total increment, PM validation, rate limiting, self-tip prevention, amount validation, goal CRUD, goal progress advancement with overflow, and goal reached detection.

---

## 9. Error Handling Matrix

| Error Condition | HTTP Status | Error Code | User Message | Recovery |
|----------------|-------------|------------|--------------|----------|
| Tip below minimum | 400 | `TIP_TOO_SMALL` | "Minimum tip is $1.00 (100 cents)." | Increase tip amount |
| Tip above maximum | 400 | `TIP_TOO_LARGE` | "Maximum tip is $1,000.00 (100000 cents)." | Decrease tip amount |
| Self-tip attempt | 400 | `CANNOT_TIP_SELF` | "You cannot tip your own broadcast." | N/A |
| Invalid payment method | 400 | `PAYMENT_METHOD_NOT_FOUND` | "Payment method not found. Add a payment method in Billing." | Add PM in billing settings |
| Session not live | 403 | `BROADCAST_NOT_LIVE` | "Chat is only available while the broadcast is live" | Wait for broadcast to go live |
| Tipping disabled | 403 | `TIPPING_DISABLED` | "Tipping is disabled for this broadcast." | N/A |
| User is muted | 403 | `BROADCAST_CHAT_MUTED` | "You are temporarily muted in this chat." | Wait for mute to expire |
| Not session creator (goal CRUD) | 403 | `NOT_SESSION_CREATOR` | "Only the broadcaster can manage goals." | Use the broadcaster's session |
| Tip rate limited | 429 | `BROADCAST_TIP_RATE_LIMITED` | "You can send one tip every 3 seconds." | Wait `retry_after_ms` |
| Max goals reached | 409 | `MAX_GOALS_REACHED` | "Maximum 5 goals per session." | Delete an existing goal first |
| Goal not found | 404 | `GOAL_NOT_FOUND` | "Tip goal not found." | Check goal_id |
| Session not found | 404 | (FastAPI default) | "broadcast session not found" | Check session_id |
| Invalid currency code | 422 | (Pydantic validation) | "String should match pattern '^[A-Z]{3}$'" | Use valid ISO 4217 code |

---

## 10. Performance & Capacity Planning

### 10.1 Throughput

| Operation | Expected Rate | DDB Cost |
|-----------|--------------|----------|
| Send tip (peak) | 10-50 tips/second per session | 3 WCU per tip (chat message + session ADD + goal ADD) |
| Tip summary query | 1-5 requests/second per session | 5-50 RCU (scans tip messages with FilterExpression) |
| Goal progress update | 10-50/second (follows tip rate) | 1 WCU per goal updated |
| List goals | 1-5 requests/second | 1 RCU (max 5 items) |

### 10.2 Hot Partition Analysis

- **BroadcastChatMessages**: Partition key is `session_id`. A popular broadcast with 1000+ tips shares a partition with all other chat messages. DynamoDB's 10GB/3000 RCU per partition is not a concern for 7-day-TTL messages.
- **BroadcastSessions**: The `ADD` expression on `tip_total_cents` hits the same item for every tip. At 50 tips/second, this is 50 WCU on a single item. DDB can handle this (3000 WCU per partition), but at extreme scale (1000+ tips/second), adaptive capacity may be needed.
- **BroadcastTipGoals**: Max 5 items per session. Negligible DDB load.

### 10.3 Tip Summary Scan Cost

`_query_tip_messages()` uses `FilterExpression` on `kind="tip"`. For a session with 10,000 chat messages (1,000 tips, 9,000 text), DynamoDB reads up to 1MB per page before filtering. With ~200 bytes per message, one page holds ~5,000 messages. The filter returns ~500 tip messages per page. For 10,000 messages, 2 pages are needed (2 x ~1MB reads). At 4KB per RCU, this costs ~500 RCU.

**Optimization for high-traffic sessions**: If tip summary becomes a hot endpoint, consider a GSI on `BroadcastChatMessages` with partition key `session_id` and sort key `kind#created_at` to enable efficient tip-only queries. This adds WCU cost on every message write but eliminates the FilterExpression scan. Not needed for v1.

---

## 11. Appendix: API Reference Summary

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/broadcast/sessions/{id}/chat/tip` | Session (viewer) | Send a tip in broadcast chat |
| GET | `/broadcast/sessions/{id}/tips/summary` | Session (any) | Get tip summary (total, top tippers, recent) |
| PATCH | `/broadcast/sessions/{id}/tips/config` | Session (creator) | Configure tipping (enable/disable, min/max) |
| POST | `/broadcast/sessions/{id}/goals` | Session (creator) | Create a tip goal |
| GET | `/broadcast/sessions/{id}/goals` | Session (any) | List tip goals |
| PATCH | `/broadcast/sessions/{id}/goals/{goal_id}` | Session (creator) | Update a tip goal |
| DELETE | `/broadcast/sessions/{id}/goals/{goal_id}` | Session (creator) | Delete a tip goal |

## 12. Appendix: Configuration

| Setting | Default | Env Var | Purpose |
|---------|---------|---------|---------|
| `broadcast_tipping_enabled` | `true` | `BROADCAST_TIPPING_ENABLED` | Global feature flag |
| `broadcast_tip_rate_limit_ms` | `3000` | `BROADCAST_TIP_RATE_LIMIT_MS` | Minimum ms between tips per user per session |
| `broadcast_tip_min_cents` | `100` | `BROADCAST_TIP_MIN_CENTS` | Default minimum tip ($1.00) |
| `broadcast_tip_max_cents` | `100000` | `BROADCAST_TIP_MAX_CENTS` | Default maximum tip ($1,000) |
| `broadcast_tip_goals_max_per_session` | `5` | `BROADCAST_TIP_GOALS_MAX` | Maximum goals per session |
| `broadcast_tip_goals_table_name` | `BroadcastTipGoals` | `DDB_BROADCAST_TIP_GOALS` | DDB table for tip goals |

## 13. Appendix: Related Tickets

| Ticket | Relationship | Detail |
|--------|-------------|--------|
| BCAST-005 | Prerequisite | Live chat infrastructure (messages, muting, SSE) |
| MON-002 | Prerequisite | Tip ledger integration (debit/credit billing entries) |
| SOCIAL-005 | Enhancement | Tip leaderboards — broadcast tips feed into creator leaderboard |
| BCAST-009 | Parallel | Scheduling — goals can be pre-configured on scheduled broadcasts |
| BCAST-011 | Parallel | Go-private — tips during private sessions use the same system |
| MON-003 | Downstream | Creator earnings dashboard includes broadcast tip revenue |
| MON-004 | Downstream | Creator payouts include broadcast tip credits |
