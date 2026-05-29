# MON-002: Record All Tips in the Billing Ledger

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: High  
**Estimated effort**: 3-4 days

---

## 1. Overview & Motivation

### The Gap

The platform has four distinct tipping surfaces — message attached tips, post-send message tips, post tips, and comment tips — but their billing ledger integration is **inconsistent and incomplete**:

1. **Message attached tips** (`app/routers/messaging.py`, line 7591): Write a debit LEDGER entry for the sender (line 7629-7645), but **only when the message is not scheduled** (line 7624: `if not is_scheduled`). No credit entry is written for the recipient.

2. **Post-send message tips** (`app/routers/messaging.py`, line 12038): Write a debit LEDGER entry for the tipper (lines 12094-12128). No credit entry for the message author.

3. **Post tips** (`app/routers/newsfeed.py`, line 3678): Write a debit LEDGER entry for the tipper (lines 3717-3735). No credit entry for the post author.

4. **Comment tips** (`app/routers/newsfeed.py`, line 4516): **No ledger entry at all.** The tip amount is only recorded on the comment item via `tip_total_cents` DDB attribute. Comment tip revenue is completely invisible in billing history.

This means:
- **Creator earnings are under-reported**: Tips received never appear as credits in the creator's billing history. The earnings dashboard (MON-003) cannot accurately aggregate revenue.
- **Reconciliation is impossible**: Without paired debit/credit ledger entries, the platform cannot verify that tips sent equal tips received.
- **Comment tips are invisible**: Neither the tipper nor the recipient has any billing record of comment tips.
- **Inconsistent metadata**: Existing ledger entries lack a uniform schema for tip-specific fields (tipper ID, recipient ID, content type, content ID).

### Why This Is Needed

1. **Accurate creator revenue tracking**: MON-003 (Creator Earnings Dashboard) depends on credit entries in the billing ledger to aggregate revenue. Without tip credits, dashboard totals will be wrong.

2. **Payout eligibility**: MON-004 (Creator Payouts) calculates available balance from ledger credits minus completed payouts. Missing tip credits mean creators cannot withdraw tip revenue.

3. **Tax reporting**: Tip income must be tracked for 1099-K reporting thresholds. Incomplete ledger records create compliance risk.

4. **Audit trail**: Every monetary transaction must have both a debit (from buyer) and credit (to seller) for reconciliation. The current state has debits without credits.

### Architecture After This Change

```
Tipping Surface           Current State              After This Change
─────────────────────────────────────────────────────────────────────────
Message attached tip      Debit (conditional)     →  Debit (always) + Credit
Post-send message tip     Debit (always)          →  Debit (always) + Credit
Post tip                  Debit (always)          →  Debit (always) + Credit
Comment tip               Nothing                 →  Debit + Credit
─────────────────────────────────────────────────────────────────────────

Ledger Entry Schema (unified):
┌──────────────────────────────────────────────────────────┐
│ pk:  USER#{user_id}                                       │
│ sk:  LEDGER#{timestamp}#{entry_id}                        │
│ entry_id:  uuid                                           │
│ ts:  unix_timestamp                                       │
│ type:  "debit" | "credit"                                 │
│ amount_cents:  int                                        │
│ currency:  "USD"                                          │
│ state:  "settled"                                         │
│ reason:  "Tip: message" | "Tip: post" | "Tip: comment"   │
│ meta:                                                     │
│   ├── content_type: "message" | "post" | "comment"        │
│   ├── content_id: str                                     │
│   ├── conversation_id: str (messages only)                │
│   ├── post_id: str (posts/comments only)                  │
│   ├── tipper_user_id: str                                 │
│   ├── recipient_user_id: str                              │
│   ├── payment_method_id: str                              │
│   └── tip_payment_id: str                                 │
└──────────────────────────────────────────────────────────┘

Data Flow for Each Tip Type:

  Tipper → Endpoint → [validate PM] → [update content item tip_amount_cents]
       │                                       │
       │                                       ├── write_tip_ledger()
       │                                       │     ├── DEBIT → USER#{tipper}
       │                                       │     └── CREDIT → USER#{recipient}
       │                                       │
       └── Response {ok, tip_payment_id, ...}
```

---

## 2. Current State Analysis

### 2.1 Message Attached Tips (`app/routers/messaging.py`, lines 7587-7645)

When `inp.tip_amount_cents` is set on a `SendTextMessageIn`:

```python
# Line 7591-7595: Create tip metadata
if inp.tip_amount_cents:
    tip_amount_cents = inp.tip_amount_cents
    tip_currency = "USD"
    tip_payment_id = "tip_" + new_id()
```

The tip fields are stored on the message DDB item (lines 7616-7623). The `tip_payment_method_id` is optionally stored on the item (line 7622: `if inp.tip_payment_method_id:`), but this only gates storing the PM on the item, not the billing write. The billing ledger write is **conditional** on one thing:
1. The message must not be scheduled (line 7624: `if not is_scheduled`)

The ledger write itself always includes `payment_method_id: inp.tip_payment_method_id` in the meta dict (which may be `None` if no PM was provided).

**Problems:**
- No credit entry is ever written for the message recipient.
- The `reason` field is `"Tip attached to message"` — inconsistent with the post-send tip's `"Tip sent"`.
- The `meta` dict does not include `tipper_user_id` or `recipient_user_id`.

### 2.2 Post-Send Message Tips (`app/routers/messaging.py`, lines 12038-12128)

The `send_message_tip()` endpoint:

```python
# Lines 12094-12116: Write billing ledger debit
billing_tbl_led.put_item(Item={
    "pk": f"USER#{user_id}",
    "sk": f"LEDGER#{ts}#{led_entry_id}",
    "entry_id": led_entry_id,
    "ts": ts,
    "type": "debit",
    "amount_cents": inp.amount_cents,
    "currency": inp.currency,
    "state": "settled",
    "reason": "Tip sent",
    "meta": {
        "conversation_id": conversation_id,
        "message_id": message_id,
        "tip_payment_id": tip_payment_id,
    },
})
```

**Problems:**
- No credit entry for `msg.get("sender_id")` (the message author who receives the tip).
- `meta` does not include `tipper_user_id`, `recipient_user_id`, `content_type`, or `payment_method_id` (the PM is stored on the message item as `tip_payment_method_id` but NOT in the ledger meta).
- The `reason` is `"Tip sent"` — does not clarify it was on a message.

### 2.3 Post Tips (`app/routers/newsfeed.py`, lines 3677-3735)

The `tip_post()` endpoint:

```python
# Lines 3717-3735: Write billing ledger debit
billing_tbl_led.put_item(Item={
    "pk": f"USER#{user_id}",
    "sk": f"LEDGER#{ts_now}#{led_entry_id}",
    ...
    "reason": "Post tip",
    "meta": {"post_id": post_id, "payment_method_id": req.payment_method_id},
})
```

**Problems:**
- No credit entry for the post author (`post.get("user_id")`).
- `meta` lacks `tipper_user_id`, `recipient_user_id`, `content_type`.

### 2.4 Comment Tips (`app/routers/newsfeed.py`, lines 4515-4567)

The `tip_comment()` endpoint:

```python
# Line 4546-4550: Only updates comment DDB item
updated = ddb_update_item(
    key=key,
    update_expr="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",
    expr_vals={":z": 0, ":amt": req.amount_cents},
)
```

**No billing ledger write at all.** The payment intent is created and confirmed (lines 4535-4543), but the resulting charge is not recorded in the billing ledger. This is the worst gap — there is zero financial record of comment tips.

### 2.5 Billing Ledger Table Structure

From `app/routers/billing.py` and existing ledger writes:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | String | `USER#{user_sub}` |
| `sk` | String | `LEDGER#{unix_ts}#{uuid}` |
| `entry_id` | String | Unique entry ID (UUID hex) |
| `ts` | Number | Unix timestamp |
| `type` | String | `"debit"` or `"credit"` |
| `amount_cents` | Number | Amount in cents |
| `currency` | String | ISO 4217 code |
| `state` | String | `"settled"`, `"pending"`, `"refunded"` |
| `reason` | String | Human-readable description |
| `meta` | Map | Arbitrary metadata dict |

### 2.6 Scheduled Message Tip Delivery

The scheduled message delivery loop (`_deliver_scheduled_message` in messaging.py) promotes scheduled messages. Currently, if a scheduled message has `tip_amount_cents` and `tip_payment_method_id`, the billing ledger write happens at delivery time. This pattern must be preserved — the debit should only be written when the message is actually delivered, not when it is scheduled. However, the credit must also be written at delivery time.

### 2.7 Image Message Tips (`app/routers/messaging.py`, `create_image_message`)

Image messages also support `tip_amount_cents` and `tip_payment_method_id`. The same conditional ledger write pattern as text messages applies. The tip fields are stored on the image message DDB item, but the ledger write has the same gaps (no credit, conditional on PM).

---

## 3. Technical Design

### 3.1 Unified Tip Ledger Service: `app/services/tip_ledger.py`

Create a dedicated service to encapsulate all tip billing writes, ensuring consistency across all tipping surfaces.

```python
"""Tip billing ledger integration.

Writes paired debit/credit entries for every tip transaction.
All four tipping surfaces (message attached, post-send message, post, comment)
call through this module.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


class TipLedgerEntry:
    """Data required to write a tip ledger entry pair.
    
    Attributes:
        tipper_user_id: The user sending the tip (debited).
        recipient_user_id: The user receiving the tip (credited).
        amount_cents: Tip amount in cents. Must be > 0.
        currency: ISO 4217 currency code (default "USD").
        content_type: Type of content being tipped ("message", "post", "comment").
        content_id: Unique ID of the tipped content item.
        payment_method_id: Optional PM used for the tip. None for tips deducted from wallet.
        tip_payment_id: Unique tip transaction ID. Auto-generated if not provided.
        extra_meta: Additional metadata to include in both ledger entries.
    """

    def __init__(
        self,
        *,
        tipper_user_id: str,
        recipient_user_id: str,
        amount_cents: int,
        currency: str = "USD",
        content_type: str,              # "message" | "post" | "comment"
        content_id: str,                # message_id, post_id, or comment_id
        payment_method_id: Optional[str] = None,
        tip_payment_id: Optional[str] = None,
        extra_meta: Optional[Dict[str, Any]] = None,
    ):
        if amount_cents <= 0:
            raise ValueError("amount_cents must be > 0")
        if content_type not in ("message", "post", "comment"):
            raise ValueError(f"Invalid content_type: {content_type}")
        self.tipper_user_id = tipper_user_id
        self.recipient_user_id = recipient_user_id
        self.amount_cents = amount_cents
        self.currency = currency
        self.content_type = content_type
        self.content_id = content_id
        self.payment_method_id = payment_method_id
        self.tip_payment_id = tip_payment_id or f"tip_{uuid.uuid4().hex}"
        self.extra_meta = extra_meta or {}


def _reason_for_content_type(content_type: str) -> str:
    """Map content type to a standardized reason string.
    
    Returns:
        "Tip: message" | "Tip: post" | "Tip: comment"
    """
    return {
        "message": "Tip: message",
        "post": "Tip: post",
        "comment": "Tip: comment",
    }.get(content_type, f"Tip: {content_type}")


def _build_meta(entry: TipLedgerEntry) -> Dict[str, Any]:
    """Build the unified metadata dict for a tip ledger entry.
    
    Always includes: content_type, content_id, tipper_user_id,
    recipient_user_id, tip_payment_id.
    Optionally includes: payment_method_id (if provided).
    Merges any extra_meta from the entry.
    """
    meta: Dict[str, Any] = {
        "content_type": entry.content_type,
        "content_id": entry.content_id,
        "tipper_user_id": entry.tipper_user_id,
        "recipient_user_id": entry.recipient_user_id,
        "tip_payment_id": entry.tip_payment_id,
    }
    if entry.payment_method_id:
        meta["payment_method_id"] = entry.payment_method_id
    meta.update(entry.extra_meta)
    return meta


def write_tip_ledger(entry: TipLedgerEntry) -> Dict[str, str]:
    """Write paired debit + credit ledger entries for a tip.

    Writes two items to T.billing:
      1. DEBIT under USER#{tipper_user_id}
      2. CREDIT under USER#{recipient_user_id}
    
    Both items share the same ts, amount_cents, currency, reason, and meta.
    
    Both writes are best-effort -- failure does not propagate to the caller.
    This matches the existing tip pattern where the content-level tip update
    (e.g., incrementing tip_total_cents on the message) is the primary
    operation, and ledger writes are secondary.
    
    Returns:
        Dict with "debit_entry_id" and "credit_entry_id" keys.
    """
    ts = now_ts()
    debit_id = uuid.uuid4().hex
    credit_id = uuid.uuid4().hex
    reason = _reason_for_content_type(entry.content_type)
    meta = _build_meta(entry)

    result = {"debit_entry_id": debit_id, "credit_entry_id": credit_id}

    # 1. Write debit entry (charge to tipper)
    try:
        T.billing.put_item(Item={
            "pk": f"USER#{entry.tipper_user_id}",
            "sk": f"LEDGER#{ts}#{debit_id}",
            "entry_id": debit_id,
            "ts": ts,
            "type": "debit",
            "amount_cents": entry.amount_cents,
            "currency": entry.currency,
            "state": "settled",
            "reason": reason,
            "meta": meta,
        })
    except Exception:
        logger.warning(
            "tip_ledger_debit_write_failed",
            extra={"tipper": entry.tipper_user_id, "content_type": entry.content_type,
                   "content_id": entry.content_id, "amount": entry.amount_cents},
        )

    # 2. Write credit entry (income to recipient)
    try:
        T.billing.put_item(Item={
            "pk": f"USER#{entry.recipient_user_id}",
            "sk": f"LEDGER#{ts}#{credit_id}",
            "entry_id": credit_id,
            "ts": ts,
            "type": "credit",
            "amount_cents": entry.amount_cents,
            "currency": entry.currency,
            "state": "settled",
            "reason": reason,
            "meta": meta,
        })
    except Exception:
        logger.warning(
            "tip_ledger_credit_write_failed",
            extra={"recipient": entry.recipient_user_id, "content_type": entry.content_type,
                   "content_id": entry.content_id, "amount": entry.amount_cents},
        )

    return result
```

### 3.2 Refactor: Message Attached Tips

**File**: `app/routers/messaging.py`, lines 7624-7645

Replace the inline ledger write with a call to the unified service:

```python
# BEFORE (lines 7624-7645):
if not is_scheduled:
    try:
        billing_tbl_tip = ddb.Table(S.billing_table_name)
        _tip_led_id = uuid.uuid4().hex
        billing_tbl_tip.put_item(Item={...})
    except Exception:
        pass

# AFTER:
if not is_scheduled:
    # Determine recipient (the other participant in the DM, or group message recipients)
    recipient_id = _resolve_tip_recipient(conversation_id, user_id)
    if recipient_id:
        from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
        write_tip_ledger(TipLedgerEntry(
            tipper_user_id=user_id,
            recipient_user_id=recipient_id,
            amount_cents=tip_amount_cents,
            currency="USD",
            content_type="message",
            content_id=mid,
            payment_method_id=inp.tip_payment_method_id,
            tip_payment_id=tip_payment_id,
            extra_meta={"conversation_id": conversation_id},
        ))
```

**Key change**: The inline ledger write is replaced with a call to the unified `write_tip_ledger()` service, which writes both a **debit** entry for the tipper and a **credit** entry for the recipient. The PM remains optional metadata.

**Data flow after refactor:**
```
send_text_message handler
  │
  ├── Create message DDB item (with tip_amount_cents, tip_payment_id)
  ├── Send SSE notification
  │
  └── IF not is_scheduled AND tip_amount_cents > 0:
        ├── _resolve_tip_recipient(conversation_id, user_id)
        │     └── For DM: returns the other participant
        │     └── For group: returns None (tip goes to... nobody for attached tips)
        │
        └── IF recipient_id:
              └── write_tip_ledger(TipLedgerEntry(...))
                    ├── DEBIT → USER#{tipper}
                    └── CREDIT → USER#{recipient}
```

Helper to resolve tip recipient:
```python
def _resolve_tip_recipient(conversation_id: str, sender_id: str) -> Optional[str]:
    """For DMs, return the other participant. For groups, return None (tips go to message author).
    
    DM conversations have exactly 2 participants. Group conversations have 3+.
    For DMs, the tip recipient is unambiguous -- it is the other participant.
    For groups, attached tips are ambiguous (who receives them?) -- this
    function returns None, and the caller should skip the ledger write.
    Post-send tips on group messages use the message author directly.
    
    Args:
        conversation_id: The conversation containing the message.
        sender_id: The user sending the tipped message.
    
    Returns:
        The recipient user_id for DMs, or None for group chats.
    """
    convo = _get_conversation_or_none(conversation_id)
    if not convo:
        return None
    participants = convo.get("participants", {})
    other_ids = [pid for pid in participants if pid != sender_id]
    if len(other_ids) == 1:
        return other_ids[0]
    return None  # Group chat: recipient is the message author, resolved elsewhere
```

### 3.3 Refactor: Post-Send Message Tips

**File**: `app/routers/messaging.py`, lines 12094-12128

Replace inline ledger write:

```python
# AFTER:
msg_author = msg.get("sender_id")
if msg_author and msg_author != user_id:
    from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
    write_tip_ledger(TipLedgerEntry(
        tipper_user_id=user_id,
        recipient_user_id=msg_author,
        amount_cents=inp.amount_cents,
        currency=inp.currency,
        content_type="message",
        content_id=message_id,
        payment_method_id=inp.payment_method_id,
        tip_payment_id=tip_payment_id,
        extra_meta={"conversation_id": conversation_id},
    ))
```

Note: The `msg_author != user_id` guard prevents self-tip ledger writes. The endpoint already rejects self-tips at line 12050, but this is defense-in-depth.

### 3.4 Refactor: Post Tips

**File**: `app/routers/newsfeed.py`, lines 3717-3735

Replace inline ledger write:

```python
# AFTER:
post_author = post.get("user_id")
if post_author and post_author != user_id:
    from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
    write_tip_ledger(TipLedgerEntry(
        tipper_user_id=user_id,
        recipient_user_id=post_author,
        amount_cents=req.amount_cents,
        currency=req.currency,
        content_type="post",
        content_id=post_id,
        payment_method_id=req.payment_method_id,
        extra_meta={"post_id": post_id},
    ))
```

### 3.5 Add: Comment Tips Ledger Write

**File**: `app/routers/newsfeed.py`, after line 4550

Insert ledger write after the `ddb_update_item` call:

```python
# NEW: Write billing ledger entries for comment tip
comment_author = updated.get("user_id") or target.get("user_id")
if comment_author and comment_author != tipper_id:
    from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
    write_tip_ledger(TipLedgerEntry(
        tipper_user_id=tipper_id,
        recipient_user_id=comment_author,
        amount_cents=req.amount_cents,
        currency=req.currency,
        content_type="comment",
        content_id=comment_id,
        payment_method_id=getattr(req, "payment_method_id", None),
        extra_meta={"post_id": post_id, "comment_id": comment_id},
    ))
```

### 3.6 Scheduled Message Delivery

**File**: `app/routers/messaging.py` (in `_deliver_scheduled_message`)

When a scheduled tipped message is delivered, the current code must be updated to use `write_tip_ledger()` instead of inline writes. The recipient resolution should use the conversation's participants.

**Line-by-line changes:**
1. After the message item is promoted from scheduled to delivered (the `update_item` call that sets `scheduled=False`)
2. Check if `tip_amount_cents > 0` on the promoted message item
3. Resolve the recipient via `_resolve_tip_recipient(conversation_id, sender_id)`
4. Call `write_tip_ledger()` with content_type="message" and the message ID

### 3.7 Image Message Tips

**File**: `app/routers/messaging.py` (in `create_image_message`)

Image messages also support `tip_amount_cents`. The same pattern applies — replace any inline ledger writes with `write_tip_ledger()`.

**Specific location:** After the image message DDB item is written and the SSE notification is sent, if `tip_amount_cents > 0`, call `write_tip_ledger()` with content_type="message".

### 3.8 Backward Compatibility

The `reason` field changes from the current inconsistent values to the new unified format:

| Surface | Old reason | New reason |
|---------|-----------|------------|
| Message attached | `"Tip attached to message"` | `"Tip: message"` |
| Post-send message | `"Tip sent"` | `"Tip: message"` |
| Post tip | `"Post tip"` | `"Tip: post"` |
| Comment tip | (none) | `"Tip: comment"` |

Existing ledger entries retain their old `reason` values. The earnings dashboard (MON-003) should query by `meta.content_type` for categorization, not by `reason` string.

### 3.9 Error Handling

All ledger writes remain best-effort (wrapped in try/except). The tip operation itself (updating `tip_amount_cents` on the content item) succeeds regardless of ledger write success. This matches the existing pattern.

If the debit write succeeds but the credit write fails, there will be an orphaned debit. A future reconciliation job (out of scope) can detect and repair these by scanning for unpaired entries.

**State machine for tip lifecycle:**
```
TIP_INITIATED → CONTENT_UPDATED → DEBIT_WRITTEN → CREDIT_WRITTEN → COMPLETE
                       │                │                │
                       │                │                └── CREDIT_FAILED (orphaned debit)
                       │                └── DEBIT_FAILED (content has tip but no ledger)
                       └── (always succeeds -- atomic DDB update_item)
```

---

## 4. Implementation Plan

### Step 1: Create Tip Ledger Service

**File**: `app/services/tip_ledger.py` (new file, ~130 lines)

Contains `TipLedgerEntry` class, `_reason_for_content_type()`, `_build_meta()`, and `write_tip_ledger()` function as specified in section 3.1.

**Line-by-line description:**
- Lines 1-10: Module docstring, imports (logging, uuid, typing, T, now_ts)
- Lines 12-55: `TipLedgerEntry` class with `__init__`, input validation
- Lines 58-65: `_reason_for_content_type()` mapper function
- Lines 68-85: `_build_meta()` builder function
- Lines 88-130: `write_tip_ledger()` main function with debit + credit writes

### Step 2: Refactor Message Attached Tips

**File**: `app/routers/messaging.py`

**Location**: Lines 7624-7645 (inside `send_text_message` handler)

- **Delete** lines 7624-7645 (inline `billing_tbl_tip.put_item(Item={...})`)
- **Insert** `_resolve_tip_recipient()` call + `write_tip_ledger()` invocation (~8 lines)
- **Add** `_resolve_tip_recipient()` helper function near line 7500 (~15 lines)
- **Remove** the `if inp.tip_payment_method_id:` gate — write ledger unconditionally when tip amount is present
- **Net change**: ~7 lines removed, ~23 lines added = +16 lines

### Step 3: Refactor Post-Send Message Tips

**File**: `app/routers/messaging.py`

**Location**: Lines 12094-12128 (inside `send_message_tip` handler)

- **Delete** lines 12094-12128 (inline `billing_tbl_led.put_item(Item={...})`)
- **Insert** `write_tip_ledger()` call with `msg.get("sender_id")` as recipient (~10 lines)
- **Net change**: ~34 lines removed, ~10 lines added = -24 lines

### Step 4: Refactor Post Tips

**File**: `app/routers/newsfeed.py`

**Location**: Lines 3717-3735 (inside `tip_post` handler)

- **Delete** lines 3717-3735 (inline `billing_tbl_led.put_item(Item={...})`)
- **Insert** `write_tip_ledger()` call with `post.get("user_id")` as recipient (~10 lines)
- **Net change**: ~18 lines removed, ~10 lines added = -8 lines

### Step 5: Add Comment Tips Ledger

**File**: `app/routers/newsfeed.py`

**Location**: After line 4550 (inside `tip_comment` handler, after DDB update)

- **Insert** `write_tip_ledger()` call with `content_type="comment"` (~10 lines)
- No existing code to replace — this is net-new
- **Net change**: +10 lines

### Step 6: Update Scheduled Message Delivery

**File**: `app/routers/messaging.py`

**Location**: Inside `_deliver_scheduled_message` function

- Replace any inline tip ledger writes with `write_tip_ledger()`
- Add recipient resolution for the scheduled message's conversation

### Step 7: Update Image Message Tips

**File**: `app/routers/messaging.py`

**Location**: Inside `create_image_message` handler (tip handling section)

- Replace inline writes with `write_tip_ledger()`

### Summary of Files Modified

| File | Change Type | Estimated Lines Changed |
|------|-------------|------------------------|
| `app/services/tip_ledger.py` | New service | ~130 |
| `app/routers/messaging.py` | Refactor 3 tip write sites + add helper | ~60 (net reduction) |
| `app/routers/newsfeed.py` | Refactor 1 tip site + add 1 new | ~30 |
| **Total** | | **~220** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_tip_ledger.py`)

New file, ~400 lines. Tests the `tip_ledger` service in isolation with moto-mocked DynamoDB.

**Complete test function signatures with assertions:**

```python
import pytest
from decimal import Decimal
from moto import mock_dynamodb
from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger, _reason_for_content_type, _build_meta
from app.core.tables import T


@pytest.fixture
def billing_table():
    """Create moto-mocked billing table."""
    # ... create table with pk/sk schema ...


def test_debit_entry_written_for_tipper(billing_table):
    """write_tip_ledger creates debit for tipper."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    result = write_tip_ledger(entry)
    
    # Query billing table for Alice's ledger entries
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq("USER#alice") & Key("sk").begins_with("LEDGER#")
    )
    items = resp["Items"]
    assert len(items) == 1
    assert items[0]["type"] == "debit"
    assert int(items[0]["amount_cents"]) == 500
    assert items[0]["reason"] == "Tip: message"
    assert items[0]["entry_id"] == result["debit_entry_id"]


def test_credit_entry_written_for_recipient(billing_table):
    """write_tip_ledger creates credit for recipient."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    write_tip_ledger(entry)
    
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq("USER#bob") & Key("sk").begins_with("LEDGER#")
    )
    items = resp["Items"]
    assert len(items) == 1
    assert items[0]["type"] == "credit"
    assert int(items[0]["amount_cents"]) == 500


def test_debit_and_credit_have_same_amount_currency_ts(billing_table):
    """Debit and credit have same amount, currency, and timestamp."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="post", content_id="post_456",
    )
    write_tip_ledger(entry)
    
    debit = T.billing.query(KeyConditionExpression=Key("pk").eq("USER#alice") & Key("sk").begins_with("LEDGER#"))["Items"][0]
    credit = T.billing.query(KeyConditionExpression=Key("pk").eq("USER#bob") & Key("sk").begins_with("LEDGER#"))["Items"][0]
    
    assert int(debit["amount_cents"]) == int(credit["amount_cents"])
    assert debit["currency"] == credit["currency"]
    assert int(debit["ts"]) == int(credit["ts"])


def test_meta_contains_all_required_fields(billing_table):
    """Meta contains all required fields."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="comment", content_id="cmt_789",
        payment_method_id="pm_123",
    )
    write_tip_ledger(entry)
    
    debit = T.billing.query(KeyConditionExpression=Key("pk").eq("USER#alice") & Key("sk").begins_with("LEDGER#"))["Items"][0]
    meta = debit["meta"]
    assert meta["content_type"] == "comment"
    assert meta["content_id"] == "cmt_789"
    assert meta["tipper_user_id"] == "alice"
    assert meta["recipient_user_id"] == "bob"
    assert "tip_payment_id" in meta
    assert meta["payment_method_id"] == "pm_123"


def test_extra_meta_is_merged(billing_table):
    """Extra meta is merged into the ledger entry meta."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
        extra_meta={"conversation_id": "conv_abc"},
    )
    write_tip_ledger(entry)
    
    debit = T.billing.query(KeyConditionExpression=Key("pk").eq("USER#alice") & Key("sk").begins_with("LEDGER#"))["Items"][0]
    assert debit["meta"]["conversation_id"] == "conv_abc"


def test_payment_method_id_is_optional(billing_table):
    """Call without PM -- meta does not contain payment_method_id key."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    write_tip_ledger(entry)
    
    debit = T.billing.query(KeyConditionExpression=Key("pk").eq("USER#alice") & Key("sk").begins_with("LEDGER#"))["Items"][0]
    assert "payment_method_id" not in debit["meta"]


def test_reason_strings_are_correct():
    """Reason strings map correctly for all content types."""
    assert _reason_for_content_type("message") == "Tip: message"
    assert _reason_for_content_type("post") == "Tip: post"
    assert _reason_for_content_type("comment") == "Tip: comment"
    assert _reason_for_content_type("unknown") == "Tip: unknown"


def test_ddb_debit_failure_does_not_prevent_credit(billing_table, monkeypatch):
    """DDB failure on debit does not prevent credit write."""
    original_put = T.billing.put_item
    call_count = 0
    def failing_put(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:  # First call = debit
            raise Exception("DDB write error")
        return original_put(**kwargs)
    monkeypatch.setattr(T.billing, "put_item", failing_put)
    
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    write_tip_ledger(entry)  # Should not raise
    
    # Credit should still be written
    credit_items = T.billing.query(KeyConditionExpression=Key("pk").eq("USER#bob") & Key("sk").begins_with("LEDGER#"))["Items"]
    assert len(credit_items) == 1


def test_ddb_credit_failure_does_not_raise(billing_table, monkeypatch):
    """DDB failure on credit does not raise."""
    original_put = T.billing.put_item
    call_count = 0
    def failing_put(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 2:  # Second call = credit
            raise Exception("DDB write error")
        return original_put(**kwargs)
    monkeypatch.setattr(T.billing, "put_item", failing_put)
    
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    result = write_tip_ledger(entry)  # Should not raise
    assert "debit_entry_id" in result
    assert "credit_entry_id" in result


def test_return_value_contains_both_entry_ids(billing_table):
    """Return value contains both entry IDs."""
    entry = TipLedgerEntry(
        tipper_user_id="alice", recipient_user_id="bob",
        amount_cents=500, content_type="message", content_id="msg_123",
    )
    result = write_tip_ledger(entry)
    assert isinstance(result["debit_entry_id"], str)
    assert isinstance(result["credit_entry_id"], str)
    assert len(result["debit_entry_id"]) == 32  # UUID hex
    assert result["debit_entry_id"] != result["credit_entry_id"]


def test_tip_ledger_entry_rejects_zero_amount():
    """TipLedgerEntry rejects amount_cents <= 0."""
    with pytest.raises(ValueError, match="amount_cents must be > 0"):
        TipLedgerEntry(tipper_user_id="a", recipient_user_id="b",
                       amount_cents=0, content_type="message", content_id="x")


def test_tip_ledger_entry_rejects_invalid_content_type():
    """TipLedgerEntry rejects invalid content_type."""
    with pytest.raises(ValueError, match="Invalid content_type"):
        TipLedgerEntry(tipper_user_id="a", recipient_user_id="b",
                       amount_cents=100, content_type="video", content_id="x")
```

### 5.2 Integration Tests (via existing E2E test files)

Update the existing tip-related E2E tests to verify ledger entries.

#### In `frontend/e2e/messaging-features.spec.ts` (Section 11 -- Tips):

Add assertions after existing tip tests:

11a. **Message attached tip creates debit ledger entry for Alice**
    - After sending tipped message, query billing table for Alice
    - Assert LEDGER entry with `meta.content_type="message"`

11b. **Message attached tip creates credit ledger entry for Bob**
    - Query billing table for Bob
    - Assert LEDGER entry with type=credit, `meta.content_type="message"`

11c. **Post-send tip creates paired ledger entries**
    - After tipping Bob's message, verify both debit (Alice) and credit (Bob)

#### In `frontend/e2e/feed.spec.ts` (Section 9 -- Post Tips):

9a. **Post tip creates credit for post author**
    - After tipping a post, query billing table for post author
    - Assert credit LEDGER entry

9b. **Comment tip creates debit and credit**
    - Tip a comment → verify both entries exist with `content_type="comment"`

### 5.3 New E2E Tests (`frontend/e2e/tip-ledger.spec.ts`)

New file, ~350 lines. Focused end-to-end verification of the unified tip ledger.

**Section 85: Tip Ledger -- Messages (5 tests)**:

1. `Attached tip writes debit for sender and credit for recipient`
2. `Post-send tip writes paired ledger entries`
3. `Tip without payment_method_id still writes ledger entries`
4. `Scheduled tipped message writes ledger on delivery (not on schedule)`
5. `Ledger entry meta contains conversation_id and message_id`

**Section 86: Tip Ledger -- Posts (4 tests)**:

1. `Post tip writes debit for tipper`
2. `Post tip writes credit for post author`
3. `Post tip ledger meta contains post_id and content_type=post`
4. `Multiple tips on same post create separate ledger entries`

**Section 87: Tip Ledger -- Comments (4 tests)**:

1. `Comment tip writes debit for tipper`
2. `Comment tip writes credit for comment author`
3. `Comment tip ledger meta contains post_id, comment_id, content_type=comment`
4. `Self-tip on comment is rejected (no ledger entry)`

**Section 88: Tip Ledger -- Cross-Cutting (3 tests)**:

1. `All tip types use consistent reason format ("Tip: {type}")`
2. `Debit and credit entries have matching amount and currency`
3. `Tipper billing history shows all tip debits chronologically`

**Test Setup (beforeAll)**:
- Seed sessions for Alice and Bob
- Create DM conversation between them
- Create newsfeed posts and comments
- Add payment method for Alice

### 5.4 Edge Cases to Cover

1. **Self-tipping prevention**: All four surfaces already prevent self-tips at the endpoint level (e.g., messaging.py line 12050: `msg.get("sender_id") == user_id`). The ledger service should not be called in self-tip scenarios. Verify no credit is written when tipper == recipient.

2. **Group chat tip recipient resolution**: In a group chat, the tip recipient is the **message author** (not all group members). The `_resolve_tip_recipient()` helper must use `msg.get("sender_id")` for post-send tips, and the conversation's other participant only for attached tips in DMs.

3. **Concurrent tips**: Two users tipping the same message simultaneously. DDB `update_item` with `SET tip_amount_cents = if_not_exists(...) + :amt` is atomic, so the counter is correct. Each tip generates independent ledger entries with unique entry IDs.

4. **Very large tips**: The `tip_amount_cents` field allows up to 100,000 (= $1,000). Verify that the ledger amount matches the message/post update.

5. **Currency mismatch**: The tipper specifies `currency` in the request. Currently all tips default to USD. The ledger should store the actual currency from the request, not hardcode USD.

6. **Decimal coercion**: DDB stores numbers as `Decimal`. When reading ledger entries back, compare with `int(entry["amount_cents"])` to avoid `Decimal != int` assertion failures.

7. **Idempotency**: If the endpoint is retried (e.g., network timeout), the message's `tip_amount_cents` gets incremented again (no idempotency guard). This is a pre-existing bug outside MON-002 scope, but the ledger write should not create orphaned entries. Consider documenting this for a future fix.

### 5.5 Migration of Existing Data

No migration is required. Existing ledger entries retain their original `reason` and `meta` format. The earnings dashboard (MON-003) should support both old and new formats:

```python
# Old format detection:
if "content_type" not in entry.get("meta", {}):
    # Legacy entry -- infer content_type from reason
    if "message" in reason.lower():
        content_type = "message"
    elif "post" in reason.lower():
        content_type = "post"
    else:
        content_type = "unknown"
```

---

## 6. Security Considerations

### 6.1 Authentication & Authorization

- All tip endpoints require `require_ui_session` (cookie auth) or Bearer token auth. Anonymous tips are not possible.
- Self-tipping is prevented at the endpoint level before `write_tip_ledger()` is called. The service itself does not enforce this (it trusts the caller). If a code path bypasses the self-tip check, the service would write self-debit + self-credit entries (net zero financial impact, but bad audit trail). Defense: add an assertion in `TipLedgerEntry.__init__()` that `tipper_user_id != recipient_user_id`.
- CSRF is enforced for cookie-authenticated POST requests to all tip endpoints.

### 6.2 Input Validation

- `amount_cents`: Validated at the endpoint level (Pydantic `ge=1, le=100000`). The `TipLedgerEntry` constructor additionally rejects `amount_cents <= 0`.
- `content_type`: Constrained to exactly 3 values ("message", "post", "comment") in `TipLedgerEntry.__init__()`.
- `payment_method_id`: Optional. When provided, validated against DDB at the endpoint level (PM must exist and belong to the user).

### 6.3 Rate Limiting

- Existing tip endpoints already have implicit rate limiting through payment method validation. Each tip requires a valid PM lookup.
- No additional rate limiting is added by MON-002. The ledger writes are secondary effects, not new endpoints.
- Future consideration: rate-limit tip frequency (e.g., max 20 tips per minute per user) to prevent ledger spam.

### 6.4 Abuse Vectors

- **Tip washing**: User A tips User B, User B tips User A for the same amount. Both have offsetting debit/credit entries. Net financial effect is zero, but ledger volume increases. Not a security risk, but a nuisance. Out of scope for MON-002.
- **Orphaned debits from credit write failure**: If the debit succeeds but credit fails, the tipper is charged but the recipient never receives the credit. The reconciliation job (future) will detect these. For now, the best-effort pattern is acceptable given tip amounts are small.
- **Ledger entry enumeration**: Ledger entries are keyed by `USER#{user_id}` PK. A user can only query their own entries. No cross-user ledger access is possible through the API.

### 6.5 Data Privacy

- Ledger entry metadata includes `tipper_user_id` and `recipient_user_id`. This is PII-adjacent (user identifiers).
- The billing ledger is accessible only to the owning user via authenticated endpoints. Admin access requires `AdminScope.BILLING_SUPPORT`.
- Tip metadata does not include message content, only IDs. No message text leaks into billing records.

### 6.6 OWASP Considerations

- **Injection**: All fields are stored as DDB attributes (not SQL). No injection risk.
- **Broken Access Control**: Ledger entries are partitioned by `USER#`. Cross-user queries are structurally impossible in DDB.
- **Sensitive Data Exposure**: Payment method IDs (not full card numbers) are stored in metadata. This is acceptable -- the PM ID is a reference, not the credential.

---

## 7. Migration & Rollback Plan

### 7.1 No Schema Changes

MON-002 does not add new DDB tables or modify existing table schemas. All changes are to application code (new service file, refactored endpoint handlers).

### 7.2 Data Backfill

**No backfill is performed.** Existing tip debit entries retain their original format. Missing credit entries for historical tips are not retroactively created. Rationale:
- Historical tips may be months old. Writing credits now would distort time-based earnings aggregation.
- The earnings dashboard (MON-003) will show "earnings from {deployment date}" for tip credits.
- A future optional backfill script could scan LEDGER entries with reason containing "Tip" and write corresponding credit entries.

### 7.3 Feature Flag

No feature flag is needed. The change is a code-level refactor of existing tip handling. The `write_tip_ledger()` function is called unconditionally when a tip is processed. If a rollback is needed, the previous code (inline ledger writes) can be restored.

### 7.4 Rollback Steps

1. Revert the code changes (restore inline ledger writes in messaging.py and newsfeed.py).
2. Delete `app/services/tip_ledger.py`.
3. No data cleanup needed -- credit entries written by the new code are valid and can remain.
4. Deployment is zero-downtime (hot reload of uvicorn).

### 7.5 Zero-Downtime Deployment

- The new `tip_ledger.py` module is loaded on import. No startup-time table creation or migration.
- The refactored endpoint handlers are backward-compatible -- they accept the same request shapes and return the same response shapes.
- The only visible difference post-deployment: ledger entries now include credit entries and use the new `reason` format. This is transparent to existing API consumers.

---

## 8. Operational Runbook

### 8.1 Metrics to Add

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `tip_ledger_write_total` | Counter | `type={debit,credit}`, `content_type`, `status={success,failure}` | Ledger write attempts |
| `tip_ledger_orphan_total` | Counter | `missing={debit,credit}` | Cases where one write succeeded and the other failed |
| `tip_amount_cents` | Histogram | `content_type` | Tip amount distribution |

### 8.2 Alerting Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Orphan rate > 1% | `rate(tip_ledger_orphan_total[5m]) / rate(tip_ledger_write_total[5m]) > 0.01` | High |
| Credit write failure rate > 5% | `rate(tip_ledger_write_total{type=credit,status=failure}[5m]) > 0.05` | Medium |
| Zero tip ledger writes in 1 hour | `increase(tip_ledger_write_total[1h]) == 0` | Low |

### 8.3 Common Debugging Scenarios

**Scenario: Creator reports missing tip revenue in earnings**
1. Identify the tip by content_id (message_id, post_id, or comment_id).
2. Query `T.billing` for `PK=USER#{creator_id}, SK begins_with LEDGER#`.
3. Filter for entries where `meta.content_id` matches.
4. If no credit entry exists, check CloudWatch logs for `tip_ledger_credit_write_failed`.
5. Manually write the credit entry using the debit entry as a template.

**Scenario: Tipper sees debit but recipient does not see credit**
1. This is an orphaned debit. The credit write failed.
2. Manually write the credit entry.
3. Investigate DDB throttling or errors in CloudWatch.

**Scenario: Comment tip shows in DDB but not in billing history**
1. Pre-MON-002 comment tips have no ledger entries. This is expected for historical data.
2. Post-MON-002 comment tips should have both debit and credit entries.

### 8.4 Log Patterns

```
# Successful tip ledger write
{"level": "info", "event": "tip_ledger_written", "content_type": "message", "amount": 500}

# Failed debit write
{"level": "warning", "event": "tip_ledger_debit_write_failed", "tipper": "alice", "content_type": "post"}

# Failed credit write
{"level": "warning", "event": "tip_ledger_credit_write_failed", "recipient": "bob", "content_type": "comment"}
```

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput

| Metric | Estimate | Basis |
|--------|----------|-------|
| Message tips/sec | 2 | Based on current tip volume |
| Post tips/sec | 1 | Lower frequency than messages |
| Comment tips/sec | 0.5 | Least common tip surface |
| Total ledger writes/sec | 7 | 3.5 tips/sec x 2 entries each |

### 9.2 DDB Additional Load

Each tip now writes 2 ledger entries (previously 0 or 1). Additional load per tip:
- 1-2 additional WCUs on `T.billing` (credit entry always, debit entry was sometimes missing)
- ~150 bytes per entry

At 3.5 tips/sec: ~7 additional WCU on the billing table. Trivial for on-demand billing mode.

### 9.3 Latency Impact

The `write_tip_ledger()` function performs 2 sequential DDB `put_item` calls. Each takes ~5-10ms. Total added latency: ~10-20ms per tip endpoint response.

This is acceptable because:
- Tip endpoints are not latency-sensitive (user clicks "Send Tip" and waits for confirmation)
- The ledger writes are after the primary content update, so the user sees the UI update before ledger writes complete
- If either write is slow, the try/except catches the timeout and returns normally

---

## 10. Dependency Analysis

### 10.1 Blocked By

- None. MON-002 refactors existing code and adds a new service module. No external dependencies.

### 10.2 Blocks

| Ticket | Dependency |
|--------|-----------|
| MON-003 | Earnings dashboard depends on credit entries from MON-002 for accurate tip revenue |
| MON-004 | Payout system needs credit entries for available balance calculation |

### 10.3 Integration Points

- **Billing table (`T.billing`)**: Writes additional LEDGER entries. Must be compatible with existing ledger query patterns.
- **Messaging router (`app/routers/messaging.py`, 12670 lines)**: Refactors 3 inline ledger write sites.
- **Newsfeed router (`app/routers/newsfeed.py`, 4966 lines)**: Refactors 1 site, adds 1 new site.
- **Existing E2E tests**: Tip-related tests in messaging-features.spec.ts, bug-fixes.spec.ts, bug-fixes-2.spec.ts, and feed.spec.ts should continue passing. The new credit entries are additional writes that do not affect endpoint response shapes.

---

## 11. Acceptance Criteria

1. All four tipping surfaces (message attached, post-send message, post, comment) write paired debit + credit LEDGER entries.
2. Debit and credit entries have matching `amount_cents`, `currency`, and `ts` values.
3. Both entries contain a `meta` map with `content_type`, `content_id`, `tipper_user_id`, and `recipient_user_id`.
4. Message tips include `conversation_id` in meta; post/comment tips include `post_id`.
5. Comment tips include `comment_id` in meta.
6. The `reason` field uses the format "Tip: {content_type}" for all new entries.
7. Message attached tips write ledger entries even when `tip_payment_method_id` is not provided.
8. Scheduled tipped messages write ledger entries at delivery time, not at schedule time.
9. Self-tips do not generate ledger entries.
10. Failure of one ledger write (debit or credit) does not prevent the other or raise an error.
11. All existing tip-related E2E tests continue to pass.
12. All 12 new unit tests pass.
13. All 16 new E2E tests pass.

---

## 12. Error Handling Matrix

| Endpoint | Condition | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-----------|-------------|------------|---------------------|-----------------|
| POST /messages (with tip) | tip_amount_cents <= 0 | 422 | `validation_error` | Pydantic validation error | Provide positive amount |
| POST /messages (with tip) | tip_amount_cents > 100000 | 422 | `validation_error` | Max tip exceeded | Reduce amount |
| POST /messages/{id}/tip | Message not found | 404 | `message_not_found` | "Message not found" | Verify message ID |
| POST /messages/{id}/tip | Self-tip attempt | 400 | `self_tip` | "Cannot tip your own message" | N/A |
| POST /messages/{id}/tip | PM not found | 400 | `pm_not_found` | "Payment method not found" | Add a PM |
| POST /posts/{id}/tip | Post not found | 404 | `post_not_found` | "Post not found" | Verify post ID |
| POST /posts/{id}/tip | Self-tip | 400 | `self_tip` | "Cannot tip your own post" | N/A |
| POST /posts/{id}/comments/{cid}/tip | Comment not found | 404 | `comment_not_found` | "Comment not found" | Verify IDs |
| POST /posts/{id}/comments/{cid}/tip | Self-tip | 400 | `self_tip` | "Cannot tip your own comment" | N/A |
| All tip endpoints | Ledger debit write fails | N/A | N/A | (silent -- tip succeeds) | Reconciliation job |
| All tip endpoints | Ledger credit write fails | N/A | N/A | (silent -- tip succeeds) | Reconciliation job |

---

## 13. Frontend Component Specifications

No new frontend components are introduced by MON-002. The changes are entirely backend. Existing tip UI components (ComposeBar tip panel, TipDialog, PostCard tip button, CommentRow tip button) continue to work unchanged.

**Potential future frontend enhancement**: Add a "Tip History" section to the billing page showing all tip debits with content type badges. This is out of scope for MON-002 but enabled by the structured `meta.content_type` field.

**Query key considerations for existing components:**
- `["billing", "payment-methods"]` -- unchanged
- `["messages"]` -- unchanged (tip_amount_cents on messages is unaffected)
- `["conversations"]` -- unchanged

---

## 14. Related Tickets

- **MON-001**: VOD pay-per-view uses the same LEDGER# pattern for purchase debit/credit
- **MON-003**: Creator earnings dashboard aggregates tip credits from the ledger
- **MON-004**: Creator payouts depend on accurate credit entries for balance calculation

---

## Codebase References

| File | Line(s) | What was verified |
|------|---------|-------------------|
| `app/services/tip_ledger.py` | 20-150 | ALREADY EXISTS (151 lines): `TipLedgerEntry` class (20), `write_tip_ledger()` (88) — writes paired debit/credit ledger entries for all tip types. This is the exact service this ticket proposes |
| `app/routers/messaging.py` | 7772-7773 | ALREADY USING: message attached tips call `write_tip_ledger(TipLedgerEntry(...))` |
| `app/routers/messaging.py` | 8040-8041 | ALREADY USING: image attached tips call `write_tip_ledger()` |
| `app/routers/messaging.py` | 8645-8646 | ALREADY USING: gallery attached tips call `write_tip_ledger()` |
| `app/routers/messaging.py` | 12391-12392 | ALREADY USING: post-send message tips call `write_tip_ledger()` |
| `app/routers/messaging.py` | 12674-12675 | ALREADY USING: message tip endpoint calls `write_tip_ledger()` |
| `app/routers/newsfeed.py` | 3942-3943 | ALREADY USING: post tips call `write_tip_ledger()` |
| `app/routers/newsfeed.py` | 4807-4808 | ALREADY USING: comment tips call `write_tip_ledger()` |
| `app/services/broadcast_tip_store.py` | 18, 149 | ALREADY USING: broadcast tips call `write_tip_ledger()` |
<!-- NOTE: This ticket's core proposal (a centralized tip ledger service with paired debit/credit entries) has been FULLY IMPLEMENTED in app/services/tip_ledger.py. All four tipping surfaces (message, post, comment, broadcast) already use it. The ticket should be marked as Complete. -->

---

## Testing Strategy

### Unit Tests (`tests/test_tip_ledger.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_message_tip_writes_credit_entry` | Message tip writes credit entry |
| 2 | `test_message_tip_writes_debit_entry` | Message tip writes debit entry |
| 3 | `test_post_tip_writes_bilateral_entries` | Post tip writes bilateral entries |
| 4 | `test_comment_tip_writes_ledger_entry` | Comment tip writes ledger entry |
| 5 | `test_scheduled_message_tip_deferred` | Scheduled message tip deferred |
| 6 | `test_tip_metadata_includes_content_ref` | Tip metadata includes content ref |
| 7 | `test_reconciliation_debits_equal_credits` | Reconciliation debits equal credits |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/tip-ledger.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~12 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

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

| Ticket | What It Needs |
|--------|--------------|
| MON-003 | Creator Earnings Dashboard aggregates tip credits |

### Merge Strategy
**Independent -- modifies existing tip code paths to add credit ledger entries. Backward-compatible (adds entries, does not change existing behavior).**

### Merge Checklist
- [ ] Service file created/modified: `app/routers/messaging.py + app/routers/newsfeed.py (modified)`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/tip-ledger.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_tip_ledger.py`
