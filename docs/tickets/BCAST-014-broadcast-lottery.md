# BCAST-014: Lottery Messages in Broadcast Chat

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: Medium  
**Estimated effort**: 8-10 days  
**Dependencies**: BCAST-005 (live chat — implemented), messaging lottery infrastructure (implemented)

---

## 1. Overview & Motivation

### The Gap

The broadcast chat system (`app/services/broadcast_chat_store.py`, 310 lines) currently supports two message kinds: `"text"` (line 304) and `"product_link"` (line 196). Messages are simple ephemeral items stored in the `BroadcastChatMessages` DynamoDB table with `session_id` as partition key and a `sort_key` composed of `{ts_ms:016d}#{msg_id}` (line 152). Real-time delivery uses `broadcast_sse_publish()` from `app/services/broadcast_sse.py` (line 29), which pushes events to all SSE subscribers for a session via in-memory `asyncio.Queue` channels.
<!-- CORRECTED: was 311 lines, actually 310 lines -->
<!-- VERIFIED: broadcast_chat_store.py:304 (kind), :196 (product_link), :152 (sort_key) -->
<!-- VERIFIED: broadcast_sse.py:29 (broadcast_sse_publish) -->

Meanwhile, the platform already has a complete lottery system for DM messaging:

- **Lottery config persistence**: `app/services/messaging_lottery_store.py` — `put_lottery_config()` (line 98) stores immutable outcome definitions with weighted basis points summing to 10,000. Outcomes support `payload_type` of `"text"`, `"image"`, or `"video"` (line 58). <!-- VERIFIED: messaging_lottery_store.py:98 (put_lottery_config), :57-58 (payload_type) -->
- **Cryptographic RNG**: `app/services/messaging_lottery_rng.py` — `choose_weighted_outcome()` (line 33) selects an outcome using `_secure_roll_1_to_10000()` (line 28), which uses `secrets.randbelow()` for cryptographic randomness. <!-- VERIFIED: messaging_lottery_rng.py:33 (choose_weighted_outcome), :28 (_secure_roll_1_to_10000), :30 (secrets.randbelow) -->
- **Idempotent unlock**: `put_lottery_unlock()` (line 133) writes one unlock record per recipient with a conditional expression preventing duplicate draws. <!-- VERIFIED: messaging_lottery_store.py:133 (put_lottery_unlock) -->
- **DM lottery endpoints**: `app/routers/messaging.py` — `POST /messages/lottery` (line 11585), `POST /messages/{id}/lottery/unlock` (line 11838), `GET /messages/{id}/lottery` (line 11981). <!-- VERIFIED: messaging.py:11585, :11838, :11981 -->

There is **no mechanism for lottery-style interactive draws in broadcast chat**. Broadcasters cannot:

1. Drop a lottery card into the live chat for viewers to enter
2. Charge an optional entry fee to participate
3. Trigger a live draw that assigns randomized outcomes to entrants
4. Reveal results in real time via SSE to all viewers simultaneously
5. Limit entries by count or time window

### Why This Is Needed

1. **Viewer engagement**: Lotteries create a participation loop — viewers stay in the broadcast to enter, watch the draw, and see results. This directly improves watch time and concurrent viewer count.
2. **Monetization**: Optional entry fees (tips) create a new revenue stream for broadcasters. The existing billing ledger pattern (`LEDGER#{ts}#{entry_id}` in the `billing` table, see `app/routers/messaging.py` line 12527) handles payment recording. <!-- VERIFIED: messaging.py:12527 (led_sk = f"LEDGER#{unlock_ts}#{led_entry_id}") -->
3. **Reusable infrastructure**: The outcome schema, weight validation (`_normalized_outcomes` at `messaging_lottery_store.py` line 42), and RNG (`choose_weighted_outcome`) are already battle-tested. Broadcast lottery reuses them directly rather than reimplementing. <!-- VERIFIED: messaging_lottery_store.py:42 (_normalized_outcomes) -->
4. **Competitive parity**: Twitch channel points predictions, YouTube Super Chat lotteries, and TikTok Live gifts with random rewards are standard engagement features. Broadcast lottery is the platform equivalent.
5. **Creator tooling**: Combined with the product shelf (LCOM-001), a broadcaster can attach product discount codes or exclusive content as lottery outcomes, linking engagement to commerce.

### Architecture After This Change

```
Broadcast Chat Message Kinds (Extended)

  Existing:
    kind="text"           → plain chat message (send_chat_message, line 136)  <!-- VERIFIED: broadcast_chat_store.py:136 -->
    kind="product_link"   → product card (send_product_link_message, line 174)  <!-- VERIFIED: broadcast_chat_store.py:174 -->

  New:
    kind="lottery"        → lottery card (send_lottery_message — new)

Lottery State Machine:

  POST /broadcast/sessions/{id}/chat/lottery
  (broadcaster creates lottery)
       |
       v
  +--------+   entry timeout   +----------------+   POST .../draw   +---------+
  |  open  | ───────────────> | entries_closed  | ───────────────> |  drawn  |
  +--------+                  +----------------+                   +---------+
       |                             |
       |  POST .../close             |  POST .../draw
       +──────────> entries_closed ──+──────────> drawn

  SSE Events (all published via broadcast_sse_publish):

  lottery:created    → all viewers see the lottery card appear
  lottery:entry      → entry count update broadcast to all
  lottery:closed     → entries are closed, draw imminent
  lottery:result     → per-entrant outcome revealed to all

Reused Components:

  messaging_lottery_rng.py::choose_weighted_outcome()  → outcome selection
  messaging_lottery_store.py::_normalized_outcomes()    → outcome validation
  broadcast_sse.py::broadcast_sse_publish()             → real-time delivery
  broadcast_chat_store.py::_chat_msg_out()              → message serialization
```

---

## 2. Current State Analysis

### 2.1 Broadcast Chat Message Model (`app/routers/broadcast.py`)

The `BroadcastChatMessageOut` model at line 1211: <!-- VERIFIED: broadcast.py:1211 -->

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
```

The `kind` field defaults to `"text"` and currently only has `"product_link"` as an alternative (set at `broadcast_chat_store.py` line 196). There is no `"lottery"` kind, no lottery payload field, and no state machine for interactive message types. <!-- VERIFIED: broadcast_chat_store.py:196 -->

### 2.2 Chat Message Storage (`app/services/broadcast_chat_store.py`)

Messages are stored in `T.broadcast_chat_messages` (table handle at `app/core/tables.py` line 80 field declaration, line 180 initialization) with schema:
<!-- VERIFIED: tables.py:80 (dataclass field broadcast_chat_messages: Any), :180 (ddb.Table(S.broadcast_chat_messages_table_name)) -->

- **PK**: `session_id` (S)
- **SK**: `sort_key` (S) — format `{ts_ms:016d}#{msg_id}`

The `send_chat_message()` function at line 136 creates items with fields: `session_id`, `sort_key`, `message_id` (`"cm_" + uuid4().hex`), `sender_id`, `sender_display_name`, `text`, `created_at`, `deleted`, `ttl`. The `_chat_msg_out()` serializer at line 296 maps DDB items to response dicts, including the `kind` field (line 304) and optional `product_link` (line 308).
<!-- VERIFIED: broadcast_chat_store.py:136 (send_chat_message), :296 (_chat_msg_out), :304 (kind), :308 (product_link) -->

### 2.3 SSE Delivery (`app/services/broadcast_sse.py`)

`broadcast_sse_publish()` at line 29 fans out events to all subscribers of a session. The SSE stream route at `broadcast.py` line 1405 (`broadcast_chat_stream_route`) maps `kind` to SSE event types: `"chat:product_link"` for product links, `"chat:message"` for text (line 1446). New lottery event types must be added to this dispatch logic.
<!-- VERIFIED: broadcast_sse.py:29, broadcast.py:1405 (decorator), :1406 (def broadcast_chat_stream_route), :1446 (event_type dispatch) -->

### 2.4 Chat Rate Limiting (`app/services/broadcast_chat_store.py`)

Two rate limit buckets exist:

- `_enforce_chat_rate_limit()` at line 25: 1 message per `broadcast_chat_rate_limit_ms` (default 2000ms, setting at `app/core/settings.py` line 494) <!-- VERIFIED: broadcast_chat_store.py:25, settings.py:494 -->
- `_enforce_product_link_rate_limit()` at line 46: 1 product link per 5000ms <!-- VERIFIED: broadcast_chat_store.py:46 -->

Lottery creation needs its own rate limit (broadcasters should not spam lotteries).

### 2.5 Existing Lottery Outcome Schema (`app/services/messaging_lottery_store.py`)

`_normalized_outcomes()` at line 42 validates: <!-- VERIFIED: messaging_lottery_store.py:42 -->

- 2-10 outcomes per lottery (line 43) <!-- VERIFIED: messaging_lottery_store.py:43 -->
- Each outcome has `outcome_id`, `display_label`, `weight_bps` (>0), `payload_type` (text|image|video), and type-specific fields (`text_content` for text, `media_asset_id` for image/video)
- Weights must sum to exactly 10,000 basis points (line 90) <!-- VERIFIED: messaging_lottery_store.py:90 -->

This validation logic can be called directly from the broadcast lottery service.

### 2.6 Existing Lottery RNG (`app/services/messaging_lottery_rng.py`)

`choose_weighted_outcome()` at line 33 accepts a sequence of outcomes and returns `(selected_outcome, rng_roll)`. It uses cumulative weight ranges and `secrets.randbelow()` for cryptographic security (line 30). The function is stateless and can be called for each entrant in a broadcast lottery draw.
<!-- VERIFIED: messaging_lottery_rng.py:33 (choose_weighted_outcome), :30 (secrets.randbelow(10_000) + 1) -->

### 2.7 Billing Ledger Pattern

Entry fees (tips) follow the established billing pattern seen in message unlock (`app/routers/messaging.py` line 12523-12545): <!-- VERIFIED: messaging.py:12523-12545 -->

```python
billing_tbl.put_item(Item={
    "pk": f"USER#{user_id}",
    "sk": f"LEDGER#{ts}#{entry_id}",
    "entry_id": entry_id,
    "ts": ts,
    "type": "debit",
    "amount_cents": amount_cents,
    "currency": "USD",
    "state": "settled",
    "reason": "...",
    "meta": { ... },
})
```

Payment method validation follows the same pattern: query `billing` table for `pk=USER#{user_id}, sk=PM#{pm_id}` to verify the payment method exists, and `sk=BILLING` for the `default_payment_method_id`.

### 2.8 Chat Mute Enforcement (`app/services/broadcast_chat_store.py`)

`_enforce_chat_mute()` at line 117 raises 403 if a user is muted. This should also block muted users from entering lotteries, since entry is a form of chat interaction. <!-- VERIFIED: broadcast_chat_store.py:117 -->

### 2.9 Broadcaster Authorization Pattern

The product link endpoint at `broadcast.py` line 1353 enforces `ctx["user_sub"] != session.created_by` to restrict product link sharing to the broadcaster. Lottery creation must use the same check. <!-- VERIFIED: broadcast.py:1353 -->

---

## 3. Technical Design

### 3.1 New Service: `app/services/broadcast_lottery.py`
<!-- NEW: to be created -->

New file implementing lottery lifecycle, entry management, and draw execution.

```python
"""Broadcast chat lottery service — create, enter, close, draw (BCAST-014)."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Mapping
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish
from app.services.messaging_lottery_store import _normalized_outcomes, LotteryConfigValidationError
from app.services.messaging_lottery_rng import choose_weighted_outcome, LotterySelectionError

logger = logging.getLogger(__name__)

# ─── Lottery States ────────────────────────────────────────────

LOTTERY_STATES = {"open", "entries_closed", "drawn"}
LOTTERY_TRANSITIONS = {
    "open": {"entries_closed", "drawn"},       # close entries or skip straight to draw
    "entries_closed": {"drawn"},               # draw after closing
    "drawn": set(),                            # terminal
}

# ─── Rate Limiting (in-memory) ────────────────────────────────

_LOTTERY_RATE_LOCK = threading.Lock()
_LOTTERY_CREATE_BUCKETS: Dict[str, int] = {}   # "{session_id}#{user_id}" -> last_create_ts_ms
_LOTTERY_ENTRY_BUCKETS: Dict[str, int] = {}    # "{session_id}#{user_id}" -> last_entry_ts_ms

LOTTERY_CREATE_COOLDOWN_MS = 30_000   # Broadcaster can create 1 lottery per 30s
LOTTERY_ENTRY_COOLDOWN_MS = 2_000     # Viewer can enter 1 lottery per 2s


def _enforce_lottery_create_rate_limit(session_id: str, user_id: str) -> None:
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    with _LOTTERY_RATE_LOCK:
        last = _LOTTERY_CREATE_BUCKETS.get(key, 0)
        if now_ms - last < LOTTERY_CREATE_COOLDOWN_MS:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "BROADCAST_LOTTERY_CREATE_RATE_LIMITED",
                    "message": f"You can create one lottery every {LOTTERY_CREATE_COOLDOWN_MS // 1000} seconds.",
                    "retry_after_ms": LOTTERY_CREATE_COOLDOWN_MS - (now_ms - last),
                },
            )
        _LOTTERY_CREATE_BUCKETS[key] = now_ms


def _enforce_lottery_entry_rate_limit(session_id: str, user_id: str) -> None:
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    with _LOTTERY_RATE_LOCK:
        last = _LOTTERY_ENTRY_BUCKETS.get(key, 0)
        if now_ms - last < LOTTERY_ENTRY_COOLDOWN_MS:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "BROADCAST_LOTTERY_ENTRY_RATE_LIMITED",
                    "message": "You can enter one lottery every 2 seconds.",
                    "retry_after_ms": LOTTERY_ENTRY_COOLDOWN_MS - (now_ms - last),
                },
            )
        _LOTTERY_ENTRY_BUCKETS[key] = now_ms


def reset_lottery_rate_limits() -> None:
    """Clear all lottery rate limit state (for tests)."""
    with _LOTTERY_RATE_LOCK:
        _LOTTERY_CREATE_BUCKETS.clear()
        _LOTTERY_ENTRY_BUCKETS.clear()


# ─── Create Lottery ───────────────────────────────────────────

def create_lottery(
    *,
    session_id: str,
    broadcaster_id: str,
    display_name: str,
    title: str,
    outcomes: Sequence[Mapping[str, Any]],
    max_entries: Optional[int] = None,
    entry_fee_cents: int = 0,
    duration_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a lottery in a broadcast chat session.

    Stores two items in BroadcastChatMessages:
    1. The chat message itself (kind="lottery") — visible in chat history
    2. A lottery config item (sort_key="LOTTERY#{lottery_id}") — holds
       mutable state (entries, status) separate from the immutable chat message

    Returns the lottery config dict.
    """
    _enforce_lottery_create_rate_limit(session_id, broadcaster_id)

    # Validate outcomes using the existing messaging lottery validation
    normalized = _normalized_outcomes(outcomes)

    ts = now_ts()
    ts_ms = int(time.time() * 1000)
    lottery_id = "lot_" + uuid4().hex
    msg_id = "cm_" + uuid4().hex
    sort_key = f"{ts_ms:016d}#{msg_id}"

    closes_at = (ts + duration_seconds) if duration_seconds else None

    # Item 1: Chat message (appears in chat history via get_chat_history)
    chat_item = {
        "session_id": session_id,
        "sort_key": sort_key,
        "message_id": msg_id,
        "sender_id": broadcaster_id,
        "sender_display_name": display_name,
        "text": title,
        "kind": "lottery",
        "lottery_id": lottery_id,
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 24 * 3600,
    }
    T.broadcast_chat_messages.put_item(Item=chat_item)

    # Item 2: Lottery config (mutable state, separate sort_key namespace)
    config_item = {
        "session_id": session_id,
        "sort_key": f"LOTTERY#{lottery_id}",
        "lottery_id": lottery_id,
        "message_id": msg_id,
        "broadcaster_id": broadcaster_id,
        "title": title,
        "outcomes": normalized,
        "total_weight_bps": 10_000,
        "max_entries": max_entries,
        "entry_fee_cents": entry_fee_cents,
        "currency": "USD",
        "duration_seconds": duration_seconds,
        "closes_at": closes_at,
        "status": "open",
        "entry_count": 0,
        "created_at": ts,
        "updated_at": ts,
        "drawn_at": None,
    }
    T.broadcast_chat_messages.put_item(Item=config_item)

    # Publish creation event via SSE
    broadcast_sse_publish(session_id, {
        "_type": "lottery:created",
        "lottery_id": lottery_id,
        "message_id": msg_id,
        "title": title,
        "broadcaster_id": broadcaster_id,
        "entry_fee_cents": entry_fee_cents,
        "max_entries": max_entries,
        "closes_at": closes_at,
        "outcome_count": len(normalized),
    })

    return config_item


# ─── Enter Lottery ────────────────────────────────────────────

def enter_lottery(
    *,
    session_id: str,
    lottery_id: str,
    user_id: str,
    display_name: str,
    payment_method_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Register a viewer's entry into a broadcast lottery.

    Entry item stored with sort_key="LENTRY#{lottery_id}#{user_id}".
    Uses conditional write to enforce idempotency (one entry per user per lottery).

    Returns entry record dict.
    """
    from botocore.exceptions import ClientError

    _enforce_lottery_entry_rate_limit(session_id, user_id)

    # Enforce mute check
    from app.services.broadcast_chat_store import _enforce_chat_mute
    _enforce_chat_mute(session_id, user_id)

    # Load lottery config
    config = get_lottery_config(session_id, lottery_id)
    if not config:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail={"code": "LOTTERY_NOT_FOUND", "message": "Lottery not found"})

    if config["status"] != "open":
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_NOT_OPEN", "message": "Lottery is no longer accepting entries"},
        )

    # Check max entries
    if config.get("max_entries") and config["entry_count"] >= config["max_entries"]:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_FULL", "message": "Lottery has reached maximum entries"},
        )

    # Check closes_at
    ts = now_ts()
    if config.get("closes_at") and ts >= config["closes_at"]:
        # Auto-close if past deadline
        _transition_lottery_status(session_id, lottery_id, "entries_closed", ts)
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_CLOSED", "message": "Lottery entry period has ended"},
        )

    # Validate and charge entry fee if required
    entry_fee_cents = int(config.get("entry_fee_cents", 0) or 0)
    fee_payment_id = None
    if entry_fee_cents > 0:
        fee_payment_id = _charge_entry_fee(
            user_id=user_id,
            broadcaster_id=config["broadcaster_id"],
            entry_fee_cents=entry_fee_cents,
            lottery_id=lottery_id,
            session_id=session_id,
            payment_method_id=payment_method_id,
        )

    # Broadcaster cannot enter own lottery
    if user_id == config["broadcaster_id"]:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=403,
            detail={"code": "BROADCASTER_CANNOT_ENTER", "message": "Broadcaster cannot enter their own lottery"},
        )

    # Write entry item (idempotent — conditional on not existing)
    entry_item = {
        "session_id": session_id,
        "sort_key": f"LENTRY#{lottery_id}#{user_id}",
        "lottery_id": lottery_id,
        "user_id": user_id,
        "display_name": display_name,
        "entered_at": ts,
        "entry_fee_cents": entry_fee_cents,
        "fee_payment_id": fee_payment_id,
        "outcome_id": None,         # Populated on draw
        "rng_roll": None,           # Populated on draw
    }
    try:
        T.broadcast_chat_messages.put_item(
            Item=entry_item,
            ConditionExpression="attribute_not_exists(sort_key)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # Already entered — idempotent success
            existing = T.broadcast_chat_messages.get_item(
                Key={"session_id": session_id, "sort_key": f"LENTRY#{lottery_id}#{user_id}"},
            ).get("Item", entry_item)
            return {"entry": existing, "already_entered": True}
        raise

    # Atomically increment entry count on config item
    T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": f"LOTTERY#{lottery_id}"},
        UpdateExpression="SET entry_count = entry_count + :one, updated_at = :ts",
        ExpressionAttributeValues={":one": 1, ":ts": ts},
    )

    # Publish entry event (count update) via SSE
    new_count = config["entry_count"] + 1  # Approximate; DDB update is authoritative
    broadcast_sse_publish(session_id, {
        "_type": "lottery:entry",
        "lottery_id": lottery_id,
        "entry_count": new_count,
        "user_id": user_id,
        "display_name": display_name,
    })

    return {"entry": entry_item, "already_entered": False}


# ─── Close Entries ────────────────────────────────────────────

def close_lottery_entries(
    *,
    session_id: str,
    lottery_id: str,
    actor_id: str,
) -> Dict[str, Any]:
    """Close entries for a lottery (broadcaster only). Transitions open -> entries_closed."""
    config = get_lottery_config(session_id, lottery_id)
    if not config:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail={"code": "LOTTERY_NOT_FOUND", "message": "Lottery not found"})

    if config["broadcaster_id"] != actor_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail={"code": "NOT_BROADCASTER", "message": "Only the broadcaster can close entries"})

    if config["status"] != "open":
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_NOT_OPEN", "message": f"Lottery is already {config['status']}"},
        )

    ts = now_ts()
    _transition_lottery_status(session_id, lottery_id, "entries_closed", ts)

    broadcast_sse_publish(session_id, {
        "_type": "lottery:closed",
        "lottery_id": lottery_id,
        "entry_count": int(config.get("entry_count", 0)),
    })

    config["status"] = "entries_closed"
    config["updated_at"] = ts
    return config


# ─── Draw ─────────────────────────────────────────────────────

def draw_lottery(
    *,
    session_id: str,
    lottery_id: str,
    actor_id: str,
) -> Dict[str, Any]:
    """Execute the lottery draw. Assigns an outcome to each entrant using
    choose_weighted_outcome() from messaging_lottery_rng.py.

    Transitions: open -> drawn OR entries_closed -> drawn.
    Returns the draw results.
    """
    config = get_lottery_config(session_id, lottery_id)
    if not config:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail={"code": "LOTTERY_NOT_FOUND", "message": "Lottery not found"})

    if config["broadcaster_id"] != actor_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail={"code": "NOT_BROADCASTER", "message": "Only the broadcaster can draw"})

    if config["status"] == "drawn":
        # Idempotent: return existing results
        results = _get_draw_results(session_id, lottery_id)
        return {"lottery_id": lottery_id, "status": "drawn", "results": results, "idempotent": True}

    if config["status"] not in ("open", "entries_closed"):
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_INVALID_STATE", "message": f"Cannot draw from state {config['status']}"},
        )

    ts = now_ts()
    outcomes = config["outcomes"]

    # Fetch all entry items
    entries = _list_entries(session_id, lottery_id)
    if not entries:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={"code": "LOTTERY_NO_ENTRIES", "message": "Cannot draw with zero entries"},
        )

    # Draw outcome for each entrant
    results = []
    for entry in entries:
        selected, rng_roll = choose_weighted_outcome(outcomes)

        # Update entry item with outcome
        T.broadcast_chat_messages.update_item(
            Key={"session_id": session_id, "sort_key": entry["sort_key"]},
            UpdateExpression="SET outcome_id = :oid, rng_roll = :roll, drawn_at = :ts",
            ExpressionAttributeValues={
                ":oid": selected["outcome_id"],
                ":roll": rng_roll,
                ":ts": ts,
            },
        )

        results.append({
            "user_id": entry["user_id"],
            "display_name": entry.get("display_name", ""),
            "outcome_id": selected["outcome_id"],
            "display_label": selected.get("display_label"),
            "payload_type": selected["payload_type"],
            "text_content": selected.get("text_content"),
            "media_asset_id": selected.get("media_asset_id"),
            "rng_roll": rng_roll,
        })

    # Transition lottery to drawn
    _transition_lottery_status(session_id, lottery_id, "drawn", ts)

    # Set drawn_at on config
    T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": f"LOTTERY#{lottery_id}"},
        UpdateExpression="SET drawn_at = :ts",
        ExpressionAttributeValues={":ts": ts},
    )

    # Publish results via SSE
    broadcast_sse_publish(session_id, {
        "_type": "lottery:result",
        "lottery_id": lottery_id,
        "results": results,
        "drawn_at": ts,
    })

    return {"lottery_id": lottery_id, "status": "drawn", "results": results, "idempotent": False}


# ─── Helpers ──────────────────────────────────────────────────

def get_lottery_config(session_id: str, lottery_id: str) -> Optional[Dict[str, Any]]:
    """Fetch the mutable lottery config item."""
    resp = T.broadcast_chat_messages.get_item(
        Key={"session_id": session_id, "sort_key": f"LOTTERY#{lottery_id}"},
    )
    return resp.get("Item")


def get_lottery_entry(session_id: str, lottery_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Check if a user has entered a specific lottery."""
    resp = T.broadcast_chat_messages.get_item(
        Key={"session_id": session_id, "sort_key": f"LENTRY#{lottery_id}#{user_id}"},
    )
    return resp.get("Item")


def _list_entries(session_id: str, lottery_id: str, limit: int = 1000) -> List[Dict[str, Any]]:
    """Fetch all entry items for a lottery.

    Uses a begins_with query on sort_key prefix "LENTRY#{lottery_id}#".
    """
    entries: List[Dict[str, Any]] = []
    last_key = None
    prefix = f"LENTRY#{lottery_id}#"

    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("session_id").eq(session_id) & Key("sort_key").begins_with(prefix),
            "Limit": min(limit - len(entries), 500),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.broadcast_chat_messages.query(**kwargs)
        entries.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(entries) >= limit:
            break

    return entries


def _get_draw_results(session_id: str, lottery_id: str) -> List[Dict[str, Any]]:
    """Fetch stored draw results from entry items (after draw has completed)."""
    entries = _list_entries(session_id, lottery_id)
    config = get_lottery_config(session_id, lottery_id)
    outcomes_by_id = {}
    if config:
        outcomes_by_id = {o["outcome_id"]: o for o in (config.get("outcomes") or [])}

    results = []
    for entry in entries:
        oid = entry.get("outcome_id")
        if not oid:
            continue
        outcome = outcomes_by_id.get(oid, {})
        results.append({
            "user_id": entry["user_id"],
            "display_name": entry.get("display_name", ""),
            "outcome_id": oid,
            "display_label": outcome.get("display_label"),
            "payload_type": outcome.get("payload_type"),
            "text_content": outcome.get("text_content"),
            "media_asset_id": outcome.get("media_asset_id"),
            "rng_roll": int(entry.get("rng_roll", 0)),
        })
    return results


def _transition_lottery_status(session_id: str, lottery_id: str, new_status: str, ts: int) -> None:
    """Update the status field on the lottery config item."""
    T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": f"LOTTERY#{lottery_id}"},
        UpdateExpression="SET #st = :s, updated_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": new_status, ":ts": ts},
    )


def _charge_entry_fee(
    *,
    user_id: str,
    broadcaster_id: str,
    entry_fee_cents: int,
    lottery_id: str,
    session_id: str,
    payment_method_id: Optional[str] = None,
) -> str:
    """Charge the entry fee and write billing ledger entries.

    Follows the same pattern as message unlock billing at
    app/routers/messaging.py line 12523-12545.

    Returns the fee_payment_id.
    """
    import uuid
    from app.core.aws import ddb

    ts = now_ts()
    fee_payment_id = "lotfee_" + uuid.uuid4().hex

    # Validate payment method exists
    billing_tbl = ddb.Table(S.billing_table_name)
    if payment_method_id:
        pm_resp = billing_tbl.get_item(Key={"pk": f"USER#{user_id}", "sk": f"PM#{payment_method_id}"})
        if not pm_resp.get("Item"):
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail="Payment method not found")
    else:
        # Use default payment method
        billing_resp = billing_tbl.get_item(Key={"pk": f"USER#{user_id}", "sk": "BILLING"})
        billing_item = billing_resp.get("Item")
        if not billing_item or not billing_item.get("default_payment_method_id"):
            from fastapi import HTTPException
            raise HTTPException(
                status_code=400,
                detail={"code": "NO_PAYMENT_METHOD", "message": "Add a payment method in Billing to enter paid lotteries"},
            )
        payment_method_id = billing_item["default_payment_method_id"]

    # Debit entry for the viewer (entrant)
    try:
        debit_entry_id = uuid.uuid4().hex
        billing_tbl.put_item(Item={
            "pk": f"USER#{user_id}",
            "sk": f"LEDGER#{ts}#{debit_entry_id}",
            "entry_id": debit_entry_id,
            "ts": ts,
            "type": "debit",
            "amount_cents": entry_fee_cents,
            "currency": "USD",
            "state": "settled",
            "reason": "Lottery entry fee",
            "meta": {
                "lottery_id": lottery_id,
                "session_id": session_id,
                "fee_payment_id": fee_payment_id,
                "payment_method_id": payment_method_id,
            },
        })
    except Exception:
        logger.exception("Failed to write lottery entry fee debit for user=%s lottery=%s", user_id, lottery_id)

    # Credit entry for the broadcaster
    try:
        credit_entry_id = uuid.uuid4().hex
        billing_tbl.put_item(Item={
            "pk": f"USER#{broadcaster_id}",
            "sk": f"LEDGER#{ts}#{credit_entry_id}",
            "entry_id": credit_entry_id,
            "ts": ts,
            "type": "credit",
            "amount_cents": entry_fee_cents,
            "currency": "USD",
            "state": "settled",
            "reason": "Lottery entry fee received",
            "meta": {
                "lottery_id": lottery_id,
                "session_id": session_id,
                "fee_payment_id": fee_payment_id,
                "from_user_id": user_id,
            },
        })
    except Exception:
        logger.exception("Failed to write lottery entry fee credit for broadcaster=%s lottery=%s", broadcaster_id, lottery_id)

    return fee_payment_id


def get_lottery_status_for_viewer(
    session_id: str,
    lottery_id: str,
    viewer_id: str,
) -> Optional[Dict[str, Any]]:
    """Get lottery state from a specific viewer's perspective.

    Returns config + whether the viewer has entered + their personal outcome (if drawn).
    """
    config = get_lottery_config(session_id, lottery_id)
    if not config:
        return None

    entry = get_lottery_entry(session_id, lottery_id, viewer_id)
    viewer_outcome = None
    if entry and entry.get("outcome_id"):
        outcomes_by_id = {o["outcome_id"]: o for o in (config.get("outcomes") or [])}
        oc = outcomes_by_id.get(entry["outcome_id"], {})
        viewer_outcome = {
            "outcome_id": entry["outcome_id"],
            "display_label": oc.get("display_label"),
            "payload_type": oc.get("payload_type"),
            "text_content": oc.get("text_content"),
            "media_asset_id": oc.get("media_asset_id"),
            "rng_roll": int(entry.get("rng_roll", 0)),
        }

    return {
        "lottery_id": config["lottery_id"],
        "title": config["title"],
        "status": config["status"],
        "entry_count": int(config.get("entry_count", 0)),
        "max_entries": config.get("max_entries"),
        "entry_fee_cents": int(config.get("entry_fee_cents", 0)),
        "closes_at": config.get("closes_at"),
        "created_at": int(config.get("created_at", 0)),
        "drawn_at": config.get("drawn_at"),
        "has_entered": entry is not None,
        "viewer_outcome": viewer_outcome,
    }
```

### 3.2 DynamoDB Storage Design

Lottery data is co-located in the existing `BroadcastChatMessages` table (`app/core/tables.py` line 80 field / line 180 init, `scripts/local-ddb-init.py` line 557). This avoids creating a new table and leverages the existing `session_id` partition key for data locality. Three item types share the partition:
<!-- VERIFIED: tables.py:80 (field), :180 (init); local-ddb-init.py:557 -->

```
┌──────────────────────────────────────────────────────────────────────────┐
│ BroadcastChatMessages Table — Lottery Items                              │
├───────────────────────┬──────────────────────────────────────────────────┤
│ Partition Key          │ Sort Key                                         │
│ session_id (S)         │ sort_key (S)                                     │
├───────────────────────┼──────────────────────────────────────────────────┤
│                       │                                                  │
│  Item Type 1: Chat message (kind="lottery")                              │
│  SK = "{ts_ms:016d}#{msg_id}"                                            │
│  Appears in chat history via get_chat_history()                          │
│  Fields: message_id, sender_id, text (=title), kind="lottery",           │
│          lottery_id, created_at, deleted, ttl                            │
│                       │                                                  │
│  Item Type 2: Lottery config (mutable state)                             │
│  SK = "LOTTERY#{lottery_id}"                                             │
│  Fields: lottery_id, message_id, broadcaster_id, title, outcomes[],      │
│          total_weight_bps, max_entries, entry_fee_cents, currency,        │
│          duration_seconds, closes_at, status, entry_count,               │
│          created_at, updated_at, drawn_at                                │
│                       │                                                  │
│  Item Type 3: Entry record (one per entrant per lottery)                 │
│  SK = "LENTRY#{lottery_id}#{user_id}"                                    │
│  Fields: lottery_id, user_id, display_name, entered_at,                  │
│          entry_fee_cents, fee_payment_id,                                │
│          outcome_id (null until draw), rng_roll (null until draw)         │
│                       │                                                  │
│  Access Patterns:                                                        │
│                       │                                                  │
│  1. Get lottery config:                                                  │
│     GetItem(PK=session_id, SK="LOTTERY#{lottery_id}")                    │
│                       │                                                  │
│  2. Check user entry:                                                    │
│     GetItem(PK=session_id, SK="LENTRY#{lottery_id}#{user_id}")           │
│                       │                                                  │
│  3. List all entries for draw:                                           │
│     Query(PK=session_id, SK begins_with "LENTRY#{lottery_id}#")          │
│                       │                                                  │
│  4. Chat message appears in history:                                     │
│     Existing Query(PK=session_id, SK < before_sort_key) picks it up      │
│     because the chat SK is timestamp-prefixed                            │
│                       │                                                  │
└───────────────────────┴──────────────────────────────────────────────────┘
```

**Why co-locate instead of a new table?** The `LOTTERY#` and `LENTRY#` sort key prefixes are lexicographically after all timestamp-prefixed chat messages (digits `0-9` < uppercase `L`), so they never interfere with chat history pagination. The `get_chat_history()` function (line 210) uses `ScanIndexForward=False` and `sort_key.lt(before_sort_key)` — lottery config/entry items have non-numeric SK prefixes that are always greater than any timestamp SK, so they are naturally excluded from chat history queries. Only the `kind="lottery"` chat message item (with a timestamp SK) appears in history. <!-- VERIFIED: broadcast_chat_store.py:210 (get_chat_history) -->

**No new table definition needed in `scripts/local-ddb-init.py`**. The existing `BroadcastChatMessages` table at line 557 supports all three item types. <!-- VERIFIED: local-ddb-init.py:557 -->

### 3.3 Pydantic Models (`app/routers/broadcast.py`)

Add the following models alongside the existing `BroadcastChatMessageOut` at line 1211: <!-- VERIFIED: broadcast.py:1211 -->
<!-- NEW: models to be added to broadcast.py -->

```python
# ─── Lottery Models (BCAST-014) ──────────────────────────────

class BroadcastLotteryOutcomeIn(BaseModel):
    """One outcome in a broadcast lottery configuration."""
    display_label: Optional[str] = Field(default=None, max_length=80)
    weight_bps: int = Field(ge=1, le=10_000)
    payload_type: Literal["text", "image", "video"]
    text_content: Optional[str] = Field(default=None, max_length=4000)
    media_asset_id: Optional[str] = Field(default=None, min_length=1, max_length=256)


class BroadcastLotteryCreateIn(BaseModel):
    """Request body for creating a lottery in broadcast chat."""
    title: str = Field(..., min_length=1, max_length=120)
    outcomes: List[BroadcastLotteryOutcomeIn] = Field(..., min_length=2, max_length=10)
    max_entries: Optional[int] = Field(default=None, ge=1, le=10_000)
    entry_fee_cents: int = Field(default=0, ge=0, le=100_000)
    duration_seconds: Optional[int] = Field(default=None, ge=10, le=3600)


class BroadcastLotteryEntryIn(BaseModel):
    """Request body for entering a broadcast lottery."""
    payment_method_id: Optional[str] = Field(default=None, max_length=128)


class BroadcastLotteryOutcomeOut(BaseModel):
    """A single outcome in the lottery results."""
    outcome_id: str
    display_label: Optional[str] = None
    weight_bps: int
    payload_type: Literal["text", "image", "video"]
    text_content: Optional[str] = None
    media_asset_id: Optional[str] = None


class BroadcastLotteryConfigOut(BaseModel):
    """Full lottery config visible to the broadcaster."""
    lottery_id: str
    message_id: str
    title: str
    status: Literal["open", "entries_closed", "drawn"]
    outcomes: List[BroadcastLotteryOutcomeOut]
    entry_count: int = 0
    max_entries: Optional[int] = None
    entry_fee_cents: int = 0
    currency: str = "USD"
    duration_seconds: Optional[int] = None
    closes_at: Optional[int] = None
    created_at: int
    drawn_at: Optional[int] = None


class BroadcastLotteryResultEntryOut(BaseModel):
    """One entrant's draw result."""
    user_id: str
    display_name: str
    outcome_id: str
    display_label: Optional[str] = None
    payload_type: Literal["text", "image", "video"]
    text_content: Optional[str] = None
    media_asset_id: Optional[str] = None
    rng_roll: int


class BroadcastLotteryDrawOut(BaseModel):
    """Response from the draw endpoint."""
    lottery_id: str
    status: Literal["drawn"] = "drawn"
    results: List[BroadcastLotteryResultEntryOut] = Field(default_factory=list)
    idempotent: bool = False


class BroadcastLotteryEntryOut(BaseModel):
    """Response from the entry endpoint."""
    lottery_id: str
    user_id: str
    entered_at: int
    already_entered: bool = False
    entry_fee_cents: int = 0


class BroadcastLotteryViewerStatusOut(BaseModel):
    """Lottery state from a specific viewer's perspective."""
    lottery_id: str
    title: str
    status: Literal["open", "entries_closed", "drawn"]
    entry_count: int = 0
    max_entries: Optional[int] = None
    entry_fee_cents: int = 0
    closes_at: Optional[int] = None
    created_at: int
    drawn_at: Optional[int] = None
    has_entered: bool = False
    viewer_outcome: Optional[BroadcastLotteryResultEntryOut] = None
```

### 3.4 Extend `BroadcastChatMessageOut`
<!-- NEW: field to be added to existing model at broadcast.py:1211 -->

Add a `lottery_id` field to the existing chat message model:

```python
class BroadcastChatMessageOut(BaseModel):
    message_id: str
    session_id: str
    sender_id: str
    sender_display_name: str
    text: str
    kind: str = "text"
    product_link: Optional[BroadcastChatProductLinkOut] = None
    lottery_id: Optional[str] = None      # NEW: set when kind="lottery"
    created_at: int
    deleted: bool = False
```

### 3.5 Extend `_chat_msg_out()` in `broadcast_chat_store.py`

Add `lottery_id` to the output serializer at line 296: <!-- VERIFIED: broadcast_chat_store.py:296 (_chat_msg_out) -->

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
    if item.get("lottery_id"):                           # NEW
        out["lottery_id"] = item["lottery_id"]            # NEW
    return out
```

### 3.6 API Endpoints (`app/routers/broadcast.py`)

#### 3.6.1 Create Lottery

```
POST /broadcast/sessions/{session_id}/chat/lottery
```

**Auth**: `require_ui_session` via `_ctx` — must be session creator (broadcaster).

**Request body**: `BroadcastLotteryCreateIn`

**Response**: `BroadcastLotteryConfigOut` (201)

**Behavior**:

1. Load session via `get_session(session_id)`. Verify `session.status == "live"` (403 otherwise — same check as `send_chat_message_route` at line 1248). <!-- VERIFIED: broadcast.py:1248 -->
2. Verify `ctx["user_sub"] == session.created_by` (403 — same check as product link at line 1353). <!-- VERIFIED: broadcast.py:1353 -->
3. Resolve broadcaster display name from profile table (same pattern as product link at line 1371-1377). <!-- VERIFIED: broadcast.py:1371-1377 -->
4. Convert `BroadcastLotteryOutcomeIn` list to outcome dicts, adding `outcome_id = "oc_" + uuid4().hex[:8]` for each.
5. Call `create_lottery()` from `broadcast_lottery.py`.
6. Return `BroadcastLotteryConfigOut`.

#### 3.6.2 Enter Lottery

```
POST /broadcast/sessions/{session_id}/chat/lottery/{lottery_id}/enter
```

**Auth**: `require_ui_session` via `_ctx` — any authenticated viewer.

**Request body**: `BroadcastLotteryEntryIn` (optional `payment_method_id`)

**Response**: `BroadcastLotteryEntryOut` (200)

**Behavior**:

1. Load session via `get_session(session_id)`. Verify `session.status == "live"` (403).
2. Resolve viewer display name from profile table.
3. Call `enter_lottery()`. It handles mute check, state validation, max entries, entry fee, idempotent write.
4. Return `BroadcastLotteryEntryOut`.

#### 3.6.3 Close Entries

```
POST /broadcast/sessions/{session_id}/chat/lottery/{lottery_id}/close
```

**Auth**: `require_ui_session` via `_ctx` — must be session creator.

**Response**: `BroadcastLotteryConfigOut` (200)

**Behavior**:

1. Load session. Verify broadcaster.
2. Call `close_lottery_entries()`. Transitions `open -> entries_closed`.
3. Return updated config.

#### 3.6.4 Draw Lottery

```
POST /broadcast/sessions/{session_id}/chat/lottery/{lottery_id}/draw
```

**Auth**: `require_ui_session` via `_ctx` — must be session creator.

**Response**: `BroadcastLotteryDrawOut` (200)

**Behavior**:

1. Load session. Verify broadcaster.
2. Call `draw_lottery()`. For each entrant, calls `choose_weighted_outcome()` from `messaging_lottery_rng.py` (line 33). Results stored per-entry and published via SSE `"lottery:result"`. <!-- VERIFIED: messaging_lottery_rng.py:33 -->
3. Idempotent: if already drawn, returns stored results with `idempotent=True`.
4. Return `BroadcastLotteryDrawOut`.

#### 3.6.5 Get Lottery Status (Viewer)

```
GET /broadcast/sessions/{session_id}/chat/lottery/{lottery_id}
```

**Auth**: `require_ui_session` via `_ctx` — any authenticated viewer.

**Response**: `BroadcastLotteryViewerStatusOut` (200)

**Behavior**:

1. Call `get_lottery_status_for_viewer()` with `viewer_id = ctx["user_sub"]`.
2. Returns config + whether the viewer entered + their personal outcome (if drawn).
3. Outcome details (text_content, media_asset_id) are only included for the requesting viewer's own result, not other entrants' results. This preserves the reveal experience.

#### 3.6.6 Get Draw Results (Broadcaster)

```
GET /broadcast/sessions/{session_id}/chat/lottery/{lottery_id}/results
```

**Auth**: `require_ui_session` via `_ctx` — must be session creator.

**Response**: `BroadcastLotteryDrawOut` (200)

**Behavior**:

1. Verify broadcaster.
2. Load config + all entry items with outcomes.
3. Return full results list (broadcaster sees all entrants' outcomes).

### 3.7 SSE Stream Extension (`app/routers/broadcast.py`)

Modify the SSE stream route at line 1405 to handle lottery event types. Currently at line 1446: <!-- VERIFIED: broadcast.py:1405 (route), :1446 (dispatch) -->

```python
event_type = "chat:product_link" if out.get("kind") == "product_link" else "chat:message"
```

Extend to:

```python
if out.get("kind") == "product_link":
    event_type = "chat:product_link"
elif out.get("kind") == "lottery":
    event_type = "chat:lottery"
else:
    event_type = "chat:message"
```

Additionally, the SSE generator needs to handle non-chat-message events (`lottery:created`, `lottery:entry`, `lottery:closed`, `lottery:result`). These are already published via `broadcast_sse_publish()` but the polling-based SSE stream at line 1405 only reads from the DDB table via `_store_fetch_after()`. The lottery lifecycle events bypass this — they are delivered through the in-memory pub/sub. <!-- VERIFIED: broadcast.py:1405, :1434 -->

**Two delivery paths**:

1. **Polling path** (line 1434): `_store_fetch_after()` fetches new DDB items. The `kind="lottery"` chat message item is picked up here and sent as `event: chat:lottery`. <!-- VERIFIED: broadcast.py:1434 -->
2. **Pub/sub path**: Lottery state events (`lottery:created`, `lottery:entry`, `lottery:closed`, `lottery:result`) are delivered via `broadcast_sse_subscribe()` queues. The current SSE generator only uses the polling path. It must be augmented to also drain the pub/sub queue.

The recommended approach is to switch the SSE generator to a hybrid model that checks both the DDB poll and the in-memory queue:

```python
async def gen():
    cursor = after
    last_ping = time.time()
    q = broadcast_sse_subscribe(session_id)
    try:
        yield ": stream-open\n\n"
        while True:
            now = time.time()
            if now - last_ping > 15:
                yield ": ping\n\n"
                last_ping = now

            # Drain in-memory queue (lottery lifecycle events)
            while not q.empty():
                try:
                    event = q.get_nowait()
                    etype = event.pop("_type", "broadcast:event")
                    payload = json.dumps(event, separators=(",", ":"), default=str)
                    yield f"event: {etype}\ndata: {payload}\n\n"
                    last_ping = time.time()
                except asyncio.QueueEmpty:
                    break

            # Poll DDB for new chat messages
            messages = await anyio.to_thread.run_sync(
                lambda: _store_fetch_after(session_id, cursor, 50)
            )
            # ... existing message processing ...

            await asyncio.sleep(poll_ms / 1000.0)
    finally:
        broadcast_sse_unsubscribe(session_id, q)
```

### 3.8 SSE Event Reference

| Event Type | Payload | Trigger | Audience |
|------------|---------|---------|----------|
| `chat:lottery` | `BroadcastChatMessageOut` with `kind="lottery"`, `lottery_id` | Lottery created (via DDB poll) | All viewers |
| `lottery:created` | `{lottery_id, message_id, title, entry_fee_cents, max_entries, closes_at, outcome_count}` | `create_lottery()` | All viewers |
| `lottery:entry` | `{lottery_id, entry_count, user_id, display_name}` | `enter_lottery()` | All viewers |
| `lottery:closed` | `{lottery_id, entry_count}` | `close_lottery_entries()` or auto-close on timeout | All viewers |
| `lottery:result` | `{lottery_id, results: [{user_id, display_name, outcome_id, display_label, payload_type, text_content, media_asset_id, rng_roll}], drawn_at}` | `draw_lottery()` | All viewers |

### 3.9 Frontend Types (`frontend/src/api/types.ts`)
<!-- NEW: types to be added to existing frontend/src/api/types.ts -->

```typescript
// ─── Broadcast Lottery (BCAST-014) ─────────────────────────────

export interface BroadcastLotteryOutcomeIn {
  display_label?: string;
  weight_bps: number;
  payload_type: "text" | "image" | "video";
  text_content?: string;
  media_asset_id?: string;
}

export interface BroadcastLotteryCreateIn {
  title: string;
  outcomes: BroadcastLotteryOutcomeIn[];
  max_entries?: number | null;
  entry_fee_cents?: number;
  duration_seconds?: number | null;
}

export interface BroadcastLotteryEntryIn {
  payment_method_id?: string;
}

export interface BroadcastLotteryOutcomeOut {
  outcome_id: string;
  display_label?: string;
  weight_bps: number;
  payload_type: "text" | "image" | "video";
  text_content?: string;
  media_asset_id?: string;
}

export interface BroadcastLotteryConfigOut {
  lottery_id: string;
  message_id: string;
  title: string;
  status: "open" | "entries_closed" | "drawn";
  outcomes: BroadcastLotteryOutcomeOut[];
  entry_count: number;
  max_entries?: number | null;
  entry_fee_cents: number;
  currency: string;
  duration_seconds?: number | null;
  closes_at?: number | null;
  created_at: number;
  drawn_at?: number | null;
}

export interface BroadcastLotteryResultEntry {
  user_id: string;
  display_name: string;
  outcome_id: string;
  display_label?: string;
  payload_type: "text" | "image" | "video";
  text_content?: string;
  media_asset_id?: string;
  rng_roll: number;
}

export interface BroadcastLotteryDrawOut {
  lottery_id: string;
  status: "drawn";
  results: BroadcastLotteryResultEntry[];
  idempotent: boolean;
}

export interface BroadcastLotteryEntryOut {
  lottery_id: string;
  user_id: string;
  entered_at: number;
  already_entered: boolean;
  entry_fee_cents: number;
}

export interface BroadcastLotteryViewerStatus {
  lottery_id: string;
  title: string;
  status: "open" | "entries_closed" | "drawn";
  entry_count: number;
  max_entries?: number | null;
  entry_fee_cents: number;
  closes_at?: number | null;
  created_at: number;
  drawn_at?: number | null;
  has_entered: boolean;
  viewer_outcome?: BroadcastLotteryResultEntry | null;
}
```

### 3.10 Frontend API Endpoints (`frontend/src/api/endpoints/broadcast-chat.ts`)
<!-- NEW: lottery endpoints to be added to existing broadcast-chat.ts -->

Extend the existing broadcast chat API file:

```typescript
// ─── Lottery endpoints (BCAST-014) ─────────────────────────────

import type {
  BroadcastLotteryCreateIn,
  BroadcastLotteryEntryIn,
  BroadcastLotteryConfigOut,
  BroadcastLotteryDrawOut,
  BroadcastLotteryEntryOut,
  BroadcastLotteryViewerStatus,
} from "@/api/types";

export const createLottery = (sessionId: string, data: BroadcastLotteryCreateIn) =>
  api.post<BroadcastLotteryConfigOut>(
    `/broadcast/sessions/${sessionId}/chat/lottery`,
    data,
  );

export const enterLottery = (
  sessionId: string,
  lotteryId: string,
  data?: BroadcastLotteryEntryIn,
) =>
  api.post<BroadcastLotteryEntryOut>(
    `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/enter`,
    data ?? {},
  );

export const closeLotteryEntries = (sessionId: string, lotteryId: string) =>
  api.post<BroadcastLotteryConfigOut>(
    `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/close`,
    {},
  );

export const drawLottery = (sessionId: string, lotteryId: string) =>
  api.post<BroadcastLotteryDrawOut>(
    `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/draw`,
    {},
  );

export const getLotteryStatus = (sessionId: string, lotteryId: string) =>
  api.get<BroadcastLotteryViewerStatus>(
    `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}`,
  );

export const getLotteryResults = (sessionId: string, lotteryId: string) =>
  api.get<BroadcastLotteryDrawOut>(
    `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/results`,
  );
```

### 3.11 Frontend Components

#### 3.11.1 BroadcastLotteryCard (`frontend/src/components/broadcast/BroadcastLotteryCard.tsx`)
<!-- NEW: to be created -->

Interactive card rendered inline in the chat when a `kind="lottery"` message appears. This is the primary viewer interaction surface.

```typescript
interface BroadcastLotteryCardProps {
  sessionId: string;
  lotteryId: string;
  title: string;
  isBroadcaster: boolean;
}

/**
 * State management:
 *   - useQuery(["broadcast-lottery", sessionId, lotteryId], () => getLotteryStatus(...))
 *   - Refetch interval: 5000ms while status != "drawn"
 *   - SSE events (lottery:entry, lottery:closed, lottery:result) trigger
 *     queryClient.invalidateQueries(["broadcast-lottery", sessionId, lotteryId])
 *
 * Visual states:
 *
 * ┌──────────────────────────────────────────────┐
 * │  🎰 Friday Night Giveaway                    │
 * │                                              │
 * │  Status: OPEN                                │
 * │  Entries: 42 / 100                           │
 * │  Entry fee: $5.00                            │
 * │  Closes in: 2m 34s                           │
 * │                                              │
 * │  [ Enter Lottery ]     ← viewer button       │
 * │                                              │
 * │  --- broadcaster controls (if isBroadcaster) │
 * │  [ Close Entries ] [ Draw Winners ]          │
 * └──────────────────────────────────────────────┘
 *
 * After entering:
 * │  ✓ You're in! (entry #42)                    │
 * │  Waiting for draw...                         │
 *
 * After draw (viewer who entered):
 * │  🎉 Your result: "20% Off Coupon"            │
 * │  [View Prize]                                │
 *
 * After draw (viewer who didn't enter):
 * │  Draw complete — 42 winners revealed          │
 *
 * Entry fee flow:
 *   If entry_fee_cents > 0, clicking "Enter Lottery" shows a
 *   payment method selector (same pattern as ComposeBar tip PM
 *   selector in frontend/src/pages/messages/ConversationView.tsx).
 *   Uses useQuery(["billing", "payment-methods"]) for PM list.
 */
```

#### 3.11.2 LotteryResultOverlay (`frontend/src/components/broadcast/LotteryResultOverlay.tsx`)
<!-- NEW: to be created -->

Full-screen animated overlay that appears when a `lottery:result` SSE event arrives and the viewer has entered the lottery.

```typescript
interface LotteryResultOverlayProps {
  result: BroadcastLotteryResultEntry;
  onDismiss: () => void;
}

/**
 * Animation sequence:
 *   1. Backdrop fades in (0.3s)
 *   2. "Drumroll" countdown text pulses (1.5s)
 *   3. Result card slides in from bottom with spring animation
 *   4. Display label shown large: "You won: 20% Off Coupon!"
 *   5. If payload_type is "image" or "video", show media preview
 *   6. If payload_type is "text", show text_content in a styled card
 *   7. Auto-dismiss after 8 seconds or on click
 *
 * Uses framer-motion (already in the project for other animations)
 * or CSS keyframes if framer-motion is not available.
 *
 * Accessibility:
 *   - role="dialog" aria-modal="true"
 *   - Auto-focus dismiss button
 *   - Escape key dismisses
 */
```

#### 3.11.3 BroadcastLotteryCreator (`frontend/src/components/broadcast/BroadcastLotteryCreator.tsx`)
<!-- NEW: to be created -->

Broadcaster-side UI for configuring and creating a lottery. Rendered in the broadcaster control panel (below the chat input).

```typescript
interface BroadcastLotteryCreatorProps {
  sessionId: string;
  onCreated: (lotteryId: string) => void;
}

/**
 * Form layout:
 *
 * ┌──────────────────────────────────────────────────┐
 * │  Create Lottery                                  │
 * │                                                  │
 * │  Title: [ Friday Night Giveaway          ]       │
 * │                                                  │
 * │  Outcomes:                                       │
 * │  ┌────────────────────────────────────────────┐  │
 * │  │ Label: [ Grand Prize     ]  Weight: [ 10 ]%│  │
 * │  │ Type:  [text ▼]  Content: [ Free month ]   │  │
 * │  │                                     [ x ]  │  │
 * │  ├────────────────────────────────────────────┤  │
 * │  │ Label: [ Runner Up       ]  Weight: [ 30 ]%│  │
 * │  │ Type:  [text ▼]  Content: [ 20% off    ]   │  │
 * │  │                                     [ x ]  │  │
 * │  ├────────────────────────────────────────────┤  │
 * │  │ Label: [ Participation   ]  Weight: [ 60 ]%│  │
 * │  │ Type:  [text ▼]  Content: [ Thanks!    ]   │  │
 * │  │                                     [ x ]  │  │
 * │  └────────────────────────────────────────────┘  │
 * │  [ + Add Outcome ]                               │
 * │                                                  │
 * │  Weight total: 100% ✓ (must equal 100%)          │
 * │                                                  │
 * │  Optional:                                       │
 * │  Entry fee: [ $0.00  ]                           │
 * │  Max entries: [ 100  ] (blank = unlimited)       │
 * │  Duration: [ 5 ] minutes (blank = manual close)  │
 * │                                                  │
 * │           [ Cancel ]  [ Create Lottery ]          │
 * └──────────────────────────────────────────────────┘
 *
 * Validation:
 *   - Title required, 1-120 chars
 *   - 2-10 outcomes
 *   - Weight percentages displayed as 0-100 (converted to basis points * 100)
 *   - Weight total must sum to 100%
 *   - Text outcomes require content; image/video outcomes require media_asset_id
 *
 * useMutation(["broadcast-lottery-create"], (data) => createLottery(sessionId, data))
 *   onSuccess: calls onCreated(lottery_id), resets form, shows success toast
 */
```

#### 3.11.4 BroadcastChat.tsx Modifications (`frontend/src/pages/broadcast/BroadcastChat.tsx`)
<!-- VERIFIED: BroadcastChat.tsx exists at frontend/src/pages/broadcast/BroadcastChat.tsx -->

Modify the existing `BroadcastChat` component (line 23) to: <!-- VERIFIED: BroadcastChat.tsx:23 (export function BroadcastChat) -->

1. **Render lottery cards**: When a message has `kind === "lottery"`, render `<BroadcastLotteryCard>` instead of the text bubble.
2. **Handle SSE lottery events**: Add event listeners for `lottery:created`, `lottery:entry`, `lottery:closed`, `lottery:result` alongside the existing `chat:message` and `chat:delete` listeners (line 61-68). <!-- VERIFIED: BroadcastChat.tsx:61-68 (chat:message at :61, chat:delete at :66) -->
3. **Show lottery creator**: When `isBroadcaster` is true, add a "Create Lottery" button next to the chat input that toggles the `BroadcastLotteryCreator` panel.
4. **Show result overlay**: When a `lottery:result` event arrives and the current user is an entrant, show `LotteryResultOverlay`.

```typescript
// In the SSE useEffect at line 44: <!-- VERIFIED: BroadcastChat.tsx:44 (SSE useEffect) -->

es.addEventListener("lottery:created", (event) => {
  const data = JSON.parse(event.data);
  // Add a synthetic lottery message to the chat
  setMessages((prev) => [...prev, {
    message_id: data.message_id,
    session_id: sessionId,
    sender_id: data.broadcaster_id,
    sender_display_name: "",
    text: data.title,
    kind: "lottery",
    lottery_id: data.lottery_id,
    created_at: Math.floor(Date.now() / 1000),
    deleted: false,
  }].slice(-500));
});

es.addEventListener("lottery:entry", (event) => {
  const data = JSON.parse(event.data);
  // Invalidate lottery query to refresh entry count
  queryClient.invalidateQueries(["broadcast-lottery", sessionId, data.lottery_id]);
});

es.addEventListener("lottery:closed", (event) => {
  const data = JSON.parse(event.data);
  queryClient.invalidateQueries(["broadcast-lottery", sessionId, data.lottery_id]);
});

es.addEventListener("lottery:result", (event) => {
  const data = JSON.parse(event.data);
  queryClient.invalidateQueries(["broadcast-lottery", sessionId, data.lottery_id]);
  // Check if current user is in results
  const myResult = data.results.find((r: any) => r.user_id === currentUserId);
  if (myResult) {
    setResultOverlay(myResult);
  }
});
```

---

## 4. Implementation Plan

### Phase 1: Service Layer (2 days)

| File | Change |
|------|--------|
| `app/services/broadcast_lottery.py` | Create: full service (~450 lines). Functions: `create_lottery()`, `enter_lottery()`, `close_lottery_entries()`, `draw_lottery()`, `get_lottery_config()`, `get_lottery_entry()`, `get_lottery_status_for_viewer()`, `_list_entries()`, `_get_draw_results()`, `_transition_lottery_status()`, `_charge_entry_fee()`, rate limit helpers. | <!-- NEW: to be created -->
| `app/services/broadcast_chat_store.py` | Modify: add `lottery_id` to `_chat_msg_out()` (line 296). ~3 lines. | <!-- VERIFIED: broadcast_chat_store.py:296 -->

### Phase 2: API Endpoints + Models (2 days)

| File | Change |
|------|--------|
| `app/routers/broadcast.py` | Add: 6 endpoints (create, enter, close, draw, get status, get results). Add: 10 Pydantic models. Modify: `BroadcastChatMessageOut` (add `lottery_id`). Modify: SSE stream generator (lottery event dispatch). ~250 lines added. | <!-- VERIFIED: broadcast.py exists, currently 2530 lines -->

### Phase 3: Frontend Types + API (1 day)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add: 10 TypeScript interfaces for lottery types. ~80 lines. | <!-- VERIFIED: types.ts exists; broadcast lottery types not yet present -->
| `frontend/src/api/endpoints/broadcast-chat.ts` | Add: 6 API function wrappers (`createLottery`, `enterLottery`, `closeLotteryEntries`, `drawLottery`, `getLotteryStatus`, `getLotteryResults`). ~40 lines. | <!-- VERIFIED: broadcast-chat.ts exists; lottery endpoints not yet present -->

### Phase 4: Frontend Components (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/components/broadcast/BroadcastLotteryCard.tsx` | Create: interactive lottery card (~200 lines). | <!-- NEW: to be created -->
| `frontend/src/components/broadcast/LotteryResultOverlay.tsx` | Create: animated result reveal (~100 lines). | <!-- NEW: to be created -->
| `frontend/src/components/broadcast/BroadcastLotteryCreator.tsx` | Create: outcome configuration form (~250 lines). | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/BroadcastChat.tsx` | Modify: render lottery cards, handle SSE events, add creator button, show result overlay. ~80 lines added. | <!-- VERIFIED: BroadcastChat.tsx exists at frontend/src/pages/broadcast/BroadcastChat.tsx -->
| `frontend/src/api/endpoints/broadcast-chat.ts` | Already covered in Phase 3. |

### Phase 5: E2E Tests (1-2 days)

| File | Change |
|------|--------|
| `frontend/e2e/broadcast-lottery.spec.ts` | Create: ~400 lines, 2 sections. | <!-- NEW: to be created -->

### Summary of All Files

| File | Type | Estimated Lines |
|------|------|-----------------|
| `app/services/broadcast_lottery.py` | Create | ~450 | <!-- NEW: to be created -->
| `app/services/broadcast_chat_store.py` | Modify | +5 | <!-- VERIFIED: exists, 310 lines -->
| `app/routers/broadcast.py` | Modify | +250 | <!-- VERIFIED: exists, 2530 lines -->
| `frontend/src/api/types.ts` | Modify | +80 | <!-- VERIFIED: exists -->
| `frontend/src/api/endpoints/broadcast-chat.ts` | Modify | +40 | <!-- VERIFIED: exists, 55 lines -->
| `frontend/src/components/broadcast/BroadcastLotteryCard.tsx` | Create | ~200 | <!-- NEW: to be created -->
| `frontend/src/components/broadcast/LotteryResultOverlay.tsx` | Create | ~100 | <!-- NEW: to be created -->
| `frontend/src/components/broadcast/BroadcastLotteryCreator.tsx` | Create | ~250 | <!-- NEW: to be created -->
| `frontend/src/pages/broadcast/BroadcastChat.tsx` | Modify | +80 | <!-- VERIFIED: exists -->
| `frontend/e2e/broadcast-lottery.spec.ts` | Create | ~400 | <!-- NEW: to be created -->
| **Total** | | **~1855** |

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_broadcast_lottery.py`

**Mock setup**: moto mock for DynamoDB (broadcast tables). Mock broadcast provider for instant state transitions.

| Test Function | Description |
|---|---|
| `test_create_bcast014_resource` | Create primary resource; verify stored in DDB with correct fields |
| `test_get_bcast014_resource` | Get resource by ID; verify all fields returned |
| `test_list_bcast014_resources` | List resources; verify pagination and filtering |
| `test_update_bcast014_resource` | Update resource; verify changed fields persisted |
| `test_delete_bcast014_resource` | Delete resource; verify removed from DDB |
| `test_validation_rejects_invalid_input` | Missing required fields returns 422; invalid values return 400 |
| `test_authorization_enforced` | Non-owner/non-admin access returns 403 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full lifecycle: create -> read -> update -> delete through real DDB
2. Cross-service integration with broadcast session store
3. Concurrent operations do not corrupt shared state

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/broadcast-lottery.spec.ts`

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
| BCAST-005 | Live chat message kinds and SSE delivery | Implemented | Yes |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Independent. Reuses existing lottery RNG and config infrastructure from messaging. New chat message kind `lottery_card` and `lottery_result`.

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
| `app/services/broadcast_lottery.py` | — | EXISTS | Lottery service |
| `app/core/settings.py` | 517-520 | EXISTS | `broadcast_lottery_enabled`, `broadcast_lottery_max_outcomes`, `max_entry_fee_cents`, `max_duration_seconds` |
| `app/services/broadcast_chat_store.py` | — | EXISTS | Chat store (lottery items co-located) |
| `frontend/e2e/broadcast-lottery.spec.ts` | — | EXISTS | E2E tests |
