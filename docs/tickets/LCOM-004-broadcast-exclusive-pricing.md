# LCOM-004: Broadcast-Exclusive Pricing — Time-Limited Discounts During Live Streams

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: Medium  
**Estimated effort**: 5-7 days  
**Depends on**: LCOM-001 (Broadcast Product Shelf), LCOM-003 (Broadcast Quick-Buy)

---

## 1. Overview & Motivation

### The Gap

LCOM-001 introduces a product shelf that links catalog items to broadcast sessions, and LCOM-003 provides a quick-buy checkout flow. However, the shelf always displays the catalog's standard price. Broadcasters have no way to offer **broadcast-exclusive discounts** — lower prices that are available only while the stream is live. This eliminates one of the most powerful conversion tools in live commerce: urgency-driven pricing.

The current product shelf (from LCOM-001) stores a denormalized `price_cents` copied from the catalog at the time the product is added to the shelf. This price is static for the lifetime of the shelf item. The quick-buy endpoint (LCOM-003) reads `shelf_item.price_cents` to calculate the order total. Neither system supports an alternate broadcast-specific price or time-limited pricing.

### Why This Is Needed

1. **Urgency drives conversion**: "This price is only available while we're live" is the single most effective call-to-action in live commerce. TikTok Shop reports 2-4x higher conversion when live-exclusive pricing is used vs. standard pricing.
2. **Creator flexibility**: Broadcasters need to set competitive prices for their live audience without permanently discounting their catalog. When the broadcast ends, prices revert automatically — no manual cleanup required.
3. **Time-limited deals within broadcasts**: A broadcaster may want to offer a flash deal for the next 10 minutes during their stream. This requires expiry-within-broadcast pricing, not just session-wide discounts.
4. **Visual impact**: A struck-through original price with a highlighted broadcast price and a "LIVE DEAL" badge is a proven UI pattern that signals value to viewers.

### Architecture After This Change

```
┌────────────────────────────────────────────────────────────────────────┐
│  Broadcaster Dashboard                                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Product Shelf Manager (from LCOM-001)                            │  │
│  │                                                                  │  │
│  │  ┌──────────────────────────────────────────────────────────┐    │  │
│  │  │ "Winter Jacket"    Catalog: $49.99                       │    │  │
│  │  │                                                          │    │  │
│  │  │  ┌─────────────────────────────────────────────────┐     │    │  │
│  │  │  │ Broadcast Price: [$  39 .99]  [x] Enable       │     │    │  │
│  │  │  │ Expires in:      [10] minutes  (optional)       │     │    │  │
│  │  │  └─────────────────────────────────────────────────┘     │    │  │
│  │  └──────────────────────────────────────────────────────────┘    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────────────┬─────────────────────────────────────────────┘
                           │ PATCH /broadcast/{id}/products/{item_id}/price
                           │ body: { broadcast_price_cents, expires_at? }
                           ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Backend                                                                │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ BroadcastProductShelf table                                      │  │
│  │ session_id | SK=ITEM#{item_id}                                   │  │
│  │   price_cents: 4999             ← catalog price (unchanged)      │  │
│  │   broadcast_price_cents: 3999   ← NEW: live-exclusive price      │  │
│  │   broadcast_price_expires_at: N ← NEW: optional expiry timestamp │  │
│  │   broadcast_price_set_by: S     ← NEW: who set the price        │  │
│  │   broadcast_price_set_at: N     ← NEW: when it was set          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Quick-Buy (LCOM-003) price resolution:                                │
│    effective_price = broadcast_price_cents                              │
│                      IF broadcast_price_cents is set                    │
│                      AND session.status == "live"                       │
│                      AND (no expiry OR expiry > now)                    │
│                      ELSE price_cents (catalog price)                   │
│                                                                         │
│  SSE event: shelf:price_update → viewers see price change in real time │
└────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Viewer Player                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ProductShelfCard                                                 │  │
│  │  ┌──────┐                                                        │  │
│  │  │ img  │  "Winter Jacket"                                       │  │
│  │  │      │   ~~$49.99~~  $39.99   [LIVE DEAL]                     │  │
│  │  │      │   Ends in: 09:42                                       │  │
│  │  └──────┘                         [Quick Buy]                    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### Pricing Resolution Flowchart

```
                    ┌─────────────────────────┐
                    │ resolve_effective_price  │
                    │ (shelf_item, status)     │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │ broadcast_price_cents    │
                    │ is set and > 0?          │
                    └───────┬─────────┬───────┘
                      yes   │         │  no
                    ┌───────▼───┐     │
                    │ session   │     │
                    │ == "live"?│     │
                    └───┬───┬──┘     │
                  yes   │   │ no     │
                    ┌───▼───┐        │
                    │ expiry │        │
                    │ set?   │        │
                    └──┬──┬─┘        │
                 yes   │  │ no       │
               ┌───────▼──┐          │
               │ now <     │         │
               │ expiry?   │         │
               └──┬────┬──┘         │
            yes   │    │ no         │
                  │    │            │
         ┌────────▼┐   │            │
         │ USE      │   │            │
         │ BROADCAST│   │            │
         │ PRICE    │   └──────┬─────┘
         └──────────┘          │
                      ┌────────▼────────┐
                      │ USE CATALOG     │
                      │ PRICE           │
                      └─────────────────┘
```

### Real-Time Price Sync Sequence Diagram

```
Broadcaster                    Backend                         Viewer (SSE)
    │                            │                                │
    │ PATCH .../price            │                                │
    │ {broadcast_price_cents:    │                                │
    │  3999, expires_in: 600}    │                                │
    │───────────────────────────>│                                │
    │                            │                                │
    │                    Validate:                                │
    │                    - session exists                         │
    │                    - caller == created_by                   │
    │                    - 3999 < 4999 (catalog)                 │
    │                    - session.status in                      │
    │                      [draft, ready, live]                   │
    │                            │                                │
    │                    DDB update_item:                         │
    │                    SET broadcast_price_cents = 3999         │
    │                    SET broadcast_price_expires_at           │
    │                      = now_ts() + 600                      │
    │                    SET broadcast_price_set_by               │
    │                    SET broadcast_price_set_at               │
    │                            │                                │
    │                    Re-read item                             │
    │                    resolve_effective_price()                │
    │                            │                                │
    │                    IF session == "live":                    │
    │                    broadcast_sse_publish(session_id,        │
    │                      {"_type": "shelf:price_update",       │
    │                       "effective_price_cents": 3999,        │
    │                       "is_broadcast_price": true,           │
    │                       "discount_pct": 20,                  │
    │                       "broadcast_price_expires_at": T+600})│
    │                            │                                │
    │                            │─ ─ ─ ─ SSE event ─ ─ ─ ─ ─ >│
    │                            │                                │
    │    200 BroadcastPriceOut   │                    React Query │
    │<───────────────────────────│                    invalidation│
    │                            │                                │
    │                            │                    BroadcastPrice
    │                            │                    renders:    │
    │                            │                    ~~$49.99~~  │
    │                            │                    $39.99      │
    │                            │                    LIVE DEAL   │
    │                            │                    -20%        │
    │                            │                    Ends in 9:59│
```

---

## 2. Current State Analysis

### 2.1 Product Shelf Data Model (LCOM-001)

The `BroadcastProductShelf` table (introduced in LCOM-001) has this schema:

| Attribute | Type | Notes |
|-----------|------|-------|
| `session_id` | S | PK |
| `SK` | S | `ITEM#{item_id}` |
| `item_id` | S | Catalog item ID |
| `category_id` | S | Category |
| `name` | S | Denormalized |
| `price_cents` | N | Denormalized catalog price at add-time |
| `currency` | S | Default `USD` |
| `image_url` | S | Primary image |
| `display_order` | N | Ordering |
| `added_by` | S | Broadcaster sub |
| `added_at` | N | Timestamp |

No broadcast-specific pricing fields exist. The `price_cents` is a static snapshot of the catalog price.

### 2.2 Product Shelf Service (LCOM-001)

`app/services/broadcast_product_shelf.py` (441 lines) — `_shelf_item_out()` (line 23) returns a dict with `price_cents` as the only price field. `add_product_to_shelf()` copies `price_cents` from the catalog item at add-time. `list_shelf_products()` (line 178) returns all items sorted by `display_order`.

<!-- NOTE: resolve_effective_price() already exists at line 211, set_broadcast_price() at line 315, clear_broadcast_price() at line 399, _shelf_item_out_with_pricing() at line 264, and list_shelf_products_with_pricing() at line 296 — all LCOM-004 service functions are already implemented -->

### 2.3 Quick-Buy Price Resolution (LCOM-003)

<!-- NOTE: app/services/broadcast_orders.py does NOT exist yet — new implementation required (LCOM-003 prerequisite) -->

The quick-buy order service (to be created by LCOM-003) will read `shelf_item.price_cents` to calculate the order total. Once created, it must be extended to prefer `broadcast_price_cents` when available and valid.

### 2.4 Broadcast Session Status (`app/services/broadcast_store.py`)

Session status values: `draft`, `provisioning`, `ready`, `live`, `stopping`, `stopped`, `error`. Broadcast prices should only be effective when `status == "live"`. When the session transitions away from `live`, all broadcast prices automatically become inactive — the catalog price takes over.

### 2.5 SSE Infrastructure (`app/services/broadcast_sse.py`)

`broadcast_sse_publish(session_id, event)` (line 29) fans out events to all subscribers via in-memory `asyncio.Queue` instances (see `app/services/broadcast_sse.py:29`). The `_BROADCAST_SUBSCRIBERS` dict (line 8) maps `session_id` to a set of queues. The `broadcast_sse_subscribe()` function (line 11) creates a new queue with `maxsize=100`, and `broadcast_sse_unsubscribe()` (line 19) removes it. Dead queues (full) are discarded during publish (lines 38-43, via `QueueFull` catch). Already used for `shelf:add`, `shelf:remove`, `chat:message`, `chat:product_link`, etc. Price updates will use a new `shelf:price_update` event type.

### 2.6 Frontend Price Display Patterns

<!-- NOTE: ProductShelfCard.tsx and QuickBuyDialog.tsx do NOT exist yet — new implementation required -->

The product shelf card (to be created) will display `price_cents` as `${(price_cents / 100).toFixed(2)}`. The quick-buy dialog (LCOM-003) will show the same price. Neither component has any concept of a broadcast-exclusive price, strikethrough display, or countdown timer. The existing frontend API file `frontend/src/api/endpoints/broadcast-shelf.ts` (44 lines) provides `ShelfItem` interface and API functions but does NOT yet include broadcast pricing fields or `setBroadcastPrice`/`clearBroadcastPrice` endpoints.

### 2.7 DDB TTL for Expiring Prices

DynamoDB TTL can automatically delete items after expiry, but this is too coarse for broadcast pricing — we want the shelf item to remain, just with the broadcast price field becoming ineffective. Instead, the backend checks `broadcast_price_expires_at` against `now_ts()` at read time and the frontend runs a client-side countdown timer.

### 2.8 Broadcast Router Structure (`app/routers/broadcast.py`)

The broadcast router (~3969 lines) is registered in `app/main.py` at prefix `/broadcast` (see `app/main.py`). Key structure:
- Lines 1-76: Imports and router declaration (line 76). The router imports from `broadcast_store`, `broadcast_recording`, `broadcast_audit`, `broadcast_orchestrator`, `broadcast_sse`, `broadcast_chat_store`, `broadcast_viewers`, and `broadcast_health`. `BroadcastPriceSetIn` and `BroadcastPriceOut` imported from `app/models` at line 73.
- Pricing Pydantic fields on `BroadcastShelfItemOut` at lines 1829-1835 (broadcast_price_cents, broadcast_price_expires_at, effective_price_cents, is_broadcast_price, discount_pct, original_price_cents).
- Shelf listing endpoint (`list_shelf_products_route`) at line 1928 — already calls `list_shelf_products_with_pricing(session_id, session.status)` at line 1937.
- Chat product link route at line 1446 — already uses `resolve_effective_price` (import at line 1465, call at line 1471) and includes pricing snapshot in `product_link_data` (lines 1494-1498).
- **Pricing endpoints already exist**: `set_broadcast_price_route` (PATCH) at line 1975, `clear_broadcast_price_route` (DELETE) at line 2022.

### 2.9 Broadcast Chat Store Rate Limiting Pattern

`app/services/broadcast_chat_store.py` (423 lines) implements in-memory rate limiting via `_CHAT_RATE_LOCK` (threading.Lock, line 20) and `_CHAT_RATE_BUCKETS` dict (line 21). The `_enforce_chat_rate_limit()` function (line 25) checks `now_ms - last < limit_ms` under the lock and raises a 429 with structured error detail including `retry_after_ms`. The `_enforce_product_link_rate_limit()` function (line 46) applies a separate 5-second rate limit for product link sharing. This same pattern should be used for price-change rate limiting to prevent broadcasters from spamming price updates (which would cause excessive SSE fan-out).

### 2.10 DDB Access Patterns for BroadcastProductShelf

The shelf uses `session_id` as PK and `SK=ITEM#{item_id}` as sort key. All pricing fields are stored as top-level attributes on the same item — no new table or GSI needed. The `get_item` call pattern:

```python
T.broadcast_product_shelf.get_item(
    Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
).get("Item")
```

The `update_item` call for setting pricing fields uses `UpdateExpression` with `SET` for active fields and `REMOVE` for clearing the expiry when no expiry is desired. This is a single-item atomic update — no transaction needed.

### 2.11 Billing Shared Helpers (`app/services/billing_shared.py`)

The billing module (see `app/services/billing_shared.py`: `user_pk()` at line 16, `ddb_get()` at line 20, `ensure_balance_row()` at line 62) provides helpers for payment method validation and ledger entry creation. For broadcast pricing, the billing system is not directly involved in setting prices — it's only relevant when the viewer purchases via quick-buy (LCOM-003). The quick-buy order record will include `was_broadcast_price: true` and `original_price_cents` fields for audit purposes.

---

## 3. Technical Design

### 3.1 Extended Shelf Item Schema

Add four new fields to the `BroadcastProductShelf` table items:

| Attribute | Type | Notes |
|-----------|------|-------|
| `broadcast_price_cents` | N | Exclusive price during broadcast (null = no discount) |
| `broadcast_price_expires_at` | N | Optional Unix timestamp when the broadcast price expires (null = valid for entire broadcast) |
| `broadcast_price_set_by` | S | User sub of the broadcaster who set the price |
| `broadcast_price_set_at` | N | When the broadcast price was set |

No new table or GSI is needed. These fields are added to existing shelf items via `update_item`.

**DDB Access Pattern Diagram**:

```
BroadcastProductShelf Table
┌─────────────────────────────────────────────────────────────────────────────┐
│ PK: session_id                                                              │
│ SK: ITEM#{item_id}                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ ┌─ Existing Fields (LCOM-001) ──────────────────────────────────────────┐  │
│ │ item_id          (S)  "cat_item_abc123"                                │  │
│ │ category_id      (S)  "cat_def456"                                     │  │
│ │ name             (S)  "Winter Jacket"                                   │  │
│ │ price_cents      (N)  4999                  ← catalog price snapshot   │  │
│ │ currency         (S)  "USD"                                            │  │
│ │ image_url        (S)  "/mock/s3/..."                                   │  │
│ │ display_order    (N)  1                                                │  │
│ │ added_by         (S)  "user_broadcaster_sub"                           │  │
│ │ added_at         (N)  1716580000                                       │  │
│ └────────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│ ┌─ NEW Fields (LCOM-004) ───────────────────────────────────────────────┐  │
│ │ broadcast_price_cents       (N)  3999       ← exclusive price         │  │
│ │ broadcast_price_expires_at  (N)  1716580600 ← optional expiry         │  │
│ │ broadcast_price_set_by      (S)  "user_broadcaster_sub"               │  │
│ │ broadcast_price_set_at      (N)  1716580000                           │  │
│ └────────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│ Access Patterns:                                                            │
│ ┌───────────────────────────────────────────────────────────────────────┐   │
│ │ 1. GetItem(session_id, ITEM#{item_id})  — single item price check    │   │
│ │ 2. Query(session_id, begins_with("ITEM#")) — list all shelf items    │   │
│ │ 3. UpdateItem(session_id, ITEM#{item_id}) — set/clear price fields   │   │
│ │ 4. DeleteItem(session_id, ITEM#{item_id}) — remove from shelf        │   │
│ │    (deletes pricing fields too; no orphan risk)                       │   │
│ └───────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Price Resolution Logic

A single function that determines the effective price for a shelf item.

<!-- NOTE: resolve_effective_price() already exists at app/services/broadcast_product_shelf.py:211 — implementation matches the spec below -->

```python
# app/services/broadcast_product_shelf.py — already implemented (line 211)

from app.core.time import now_ts
from typing import Any, Dict, Optional

def resolve_effective_price(shelf_item: Dict[str, Any], session_status: str) -> Dict[str, Any]:
    """
    Determine the effective price for a shelf item.

    This is the SINGLE SOURCE OF TRUTH for price resolution in the entire
    broadcast commerce pipeline. Both the shelf listing endpoint and the
    quick-buy endpoint MUST call this function. Client-submitted prices
    are NEVER trusted.

    Args:
        shelf_item: The raw DynamoDB item from BroadcastProductShelf table.
        session_status: The current broadcast session status string
            (one of: draft, provisioning, ready, live, stopping, stopped, error).

    Returns:
        {
            "effective_price_cents": int,    # price to display and charge
            "original_price_cents": int,     # catalog price (always present)
            "is_broadcast_price": bool,      # True if broadcast discount is active
            "broadcast_price_expires_at": int | None,  # expiry timestamp or None
            "discount_pct": int,             # 0-100 integer percentage
        }

    Broadcast price is active when ALL conditions are met:
        1. broadcast_price_cents is set and > 0
        2. session_status == "live"
        3. Not expired (broadcast_price_expires_at is None OR > now_ts())

    Edge cases:
        - broadcast_price_cents == 0: treated as "no discount" (inactive)
        - broadcast_price_cents >= original: should not happen (validated at set-time)
          but if it does, resolve_effective_price still returns it as active.
          The SET endpoint prevents this, but defense-in-depth means we don't
          second-guess stored data at read time.
        - original_price_cents == 0: free item; discount_pct = 0 (avoid div-by-zero)
    """
    original = int(shelf_item.get("price_cents", 0))
    broadcast = shelf_item.get("broadcast_price_cents")
    expires_at = shelf_item.get("broadcast_price_expires_at")

    # Broadcast price is effective only when:
    # 1. broadcast_price_cents is set and > 0
    # 2. Session is live
    # 3. Not expired (if expiry is set)
    broadcast_active = (
        broadcast is not None
        and int(broadcast) > 0
        and session_status == "live"
        and (expires_at is None or int(expires_at) > now_ts())
    )

    if broadcast_active:
        effective = int(broadcast)
        discount_pct = round((1 - effective / original) * 100) if original > 0 else 0
        return {
            "effective_price_cents": effective,
            "original_price_cents": original,
            "is_broadcast_price": True,
            "broadcast_price_expires_at": int(expires_at) if expires_at else None,
            "discount_pct": max(0, min(100, discount_pct)),
        }

    return {
        "effective_price_cents": original,
        "original_price_cents": original,
        "is_broadcast_price": False,
        "broadcast_price_expires_at": None,
        "discount_pct": 0,
    }
```

### 3.3 API Endpoints

#### 3.3.1 Set Broadcast Price

```
PATCH /broadcast/sessions/{session_id}/products/{item_id}/price
```

**Auth**: `require_ui_session` — only session creator (broadcaster).

**Request model** (already exists at `app/models.py:2426`):

```python
class BroadcastPriceSetIn(BaseModel):
    """Request body for setting a broadcast-exclusive price.

    The broadcast_price_cents MUST be strictly less than the catalog price
    (stored as price_cents on the shelf item). This is enforced both in
    the Pydantic validator (against the request body) and in the service
    layer (against the actual DDB value). The double-check prevents a
    race where the catalog price was updated between request validation
    and DDB write.
    """
    broadcast_price_cents: int = Field(..., gt=0, le=99999999,
        description="Broadcast-exclusive price in cents. Must be less than catalog price.")
    expires_in_seconds: Optional[int] = Field(
        default=None, ge=60, le=86400,
        description="Optional: price expires N seconds from now (1 min to 24 hours)"
    )

    @field_validator("broadcast_price_cents")
    @classmethod
    def price_must_be_positive(cls, v: int) -> int:
        """Ensure broadcast price is a positive integer.
        Additional check beyond gt=0 for defense in depth against
        Decimal serialization edge cases from DynamoDB."""
        if v <= 0:
            raise ValueError("broadcast_price_cents must be positive")
        return v

    @field_validator("expires_in_seconds")
    @classmethod
    def expiry_range_check(cls, v: Optional[int]) -> Optional[int]:
        """Validate expiry is within acceptable range.
        Minimum 60s prevents flickering prices.
        Maximum 86400s (24h) prevents effectively permanent discounts
        that bypass catalog price management."""
        if v is not None and (v < 60 or v > 86400):
            raise ValueError("expires_in_seconds must be between 60 and 86400")
        return v
```

**Response model** (already exists at `app/models.py:2440`):

```python
class BroadcastPriceOut(BaseModel):
    """Response after setting or querying a broadcast price.
    Includes both the raw broadcast price and the resolved effective price."""
    session_id: str
    item_id: str
    original_price_cents: int
    broadcast_price_cents: int
    broadcast_price_expires_at: Optional[int] = None
    discount_pct: int = Field(..., ge=0, le=100)
    set_by: str
    set_at: int
```

**Full endpoint implementation**:

<!-- NOTE: set_broadcast_price_route already exists at app/routers/broadcast.py:1975 — implementation matches the spec below -->

```python
# app/routers/broadcast.py — already implemented (line 1975)

@router.patch(
    "/sessions/{session_id}/products/{item_id}/price",
    response_model=BroadcastPriceOut,
)
def set_broadcast_price_route(
    session_id: str,
    item_id: str,
    body: BroadcastPriceSetIn,
    ctx: dict = Depends(_ctx),
):
    """Set a broadcast-exclusive price on a shelf product.

    Only the session creator (broadcaster) can set prices.
    The broadcast price must be strictly less than the catalog price.
    If expires_in_seconds is provided, the price reverts after that duration.
    When the session is live, a shelf:price_update SSE event is published.
    """
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the broadcaster can set broadcast prices."
        )
    if session.status in ("stopping", "stopped", "error"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot set price on a session in terminal state."
        )

    from app.services.broadcast_product_shelf import set_broadcast_price
    result = set_broadcast_price(
        session_id=session_id,
        item_id=item_id,
        broadcast_price_cents=body.broadcast_price_cents,
        set_by=ctx["user_sub"],
        expires_in_seconds=body.expires_in_seconds,
        is_live=(session.status == "live"),
    )
    return BroadcastPriceOut(
        session_id=session_id,
        item_id=item_id,
        original_price_cents=result["original_price_cents"],
        broadcast_price_cents=result["broadcast_price_cents"],
        broadcast_price_expires_at=result.get("broadcast_price_expires_at"),
        discount_pct=result["discount_pct"],
        set_by=ctx["user_sub"],
        set_at=result["broadcast_price_set_at"],
    )
```

**Error responses**:

| Code | Condition | Error Detail |
|------|-----------|-------------|
| 400 | Broadcast price >= catalog price | `"Broadcast price ({broadcast_price_cents}) must be less than catalog price ({catalog_price})."` |
| 400 | broadcast_price_cents <= 0 | `"broadcast_price_cents must be positive"` |
| 403 | Caller is not session creator | `"Only the broadcaster can set broadcast prices."` |
| 404 | Product not on shelf | `"Product not on shelf."` |
| 409 | Session in terminal state (stopping/stopped/error) | `"Cannot set price on a session in terminal state."` |
| 422 | Pydantic validation failure | Standard FastAPI validation error |

#### 3.3.2 Clear Broadcast Price

```
DELETE /broadcast/sessions/{session_id}/products/{item_id}/price
```

**Auth**: `require_ui_session` — only session creator.

**Full endpoint implementation**:

<!-- NOTE: clear_broadcast_price_route already exists at app/routers/broadcast.py:2022 — implementation matches the spec below -->

```python
@router.delete("/sessions/{session_id}/products/{item_id}/price")
def clear_broadcast_price_route(
    session_id: str,
    item_id: str,
    ctx: dict = Depends(_ctx),
):
    """Remove broadcast-exclusive pricing from a shelf product.

    The catalog price is restored as the effective price.
    If the session is live, publishes shelf:price_update SSE event.
    """
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the broadcaster can clear broadcast prices."
        )

    from app.services.broadcast_product_shelf import clear_broadcast_price
    cleared = clear_broadcast_price(
        session_id=session_id,
        item_id=item_id,
        is_live=(session.status == "live"),
    )
    if not cleared:
        raise HTTPException(status_code=404, detail="Product not on shelf.")
    return {"ok": True, "item_id": item_id}
```

**Behavior**:

1. Validate session and ownership.
2. Remove `broadcast_price_cents`, `broadcast_price_expires_at`, `broadcast_price_set_by`, `broadcast_price_set_at` from the shelf item using `REMOVE` update expression.
3. If session is `live`, publish `shelf:price_update` SSE event with `is_broadcast_price: false`.
4. Return `{"ok": True, "item_id": item_id}`.

#### 3.3.3 Extended Shelf Listing

The existing `GET /broadcast/sessions/{session_id}/products` endpoint (from LCOM-001) is extended to include pricing information. The response model is augmented:

```python
class BroadcastShelfItemOut(BaseModel):
    """Extended with broadcast pricing fields.

    Fields marked NEW are added by LCOM-004. The existing LCOM-001 fields
    remain unchanged. The effective_price_cents field is computed server-side
    by resolve_effective_price() and reflects the price a viewer would pay
    right now via quick-buy.
    """
    session_id: str
    item_id: str
    category_id: str
    name: str
    description: Optional[str] = None
    price_cents: int                                       # catalog price
    currency: str = "USD"
    image_url: Optional[str] = None
    display_order: int = 0
    added_by: str
    added_at: int
    # Broadcast pricing (LCOM-004)
    broadcast_price_cents: Optional[int] = None            # NEW
    broadcast_price_expires_at: Optional[int] = None       # NEW
    effective_price_cents: int                              # NEW — resolved price
    is_broadcast_price: bool = False                        # NEW
    discount_pct: int = 0                                  # NEW
```

The `_shelf_item_out` function is updated to call `resolve_effective_price()` and merge the result.

### 3.4 Service Layer Extension — `app/services/broadcast_product_shelf.py`

Functions for broadcast pricing management.

<!-- NOTE: All functions below already exist in app/services/broadcast_product_shelf.py: set_broadcast_price() at line 315, clear_broadcast_price() at line 399, _shelf_item_out_with_pricing() at line 264 -->

```python
# app/services/broadcast_product_shelf.py — already implemented

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish
from fastapi import HTTPException
from typing import Any, Dict, Optional
import logging

logger = logging.getLogger("broadcast.pricing")


def set_broadcast_price(
    session_id: str,
    item_id: str,
    broadcast_price_cents: int,
    set_by: str,
    *,
    expires_in_seconds: Optional[int] = None,
    is_live: bool = False,
) -> Dict[str, Any]:
    """Set a broadcast-exclusive price on a shelf item.

    Args:
        session_id: The broadcast session ID.
        item_id: The catalog item ID (must already be on the shelf).
        broadcast_price_cents: The discounted price in cents.
        set_by: User sub of the broadcaster setting the price.
        expires_in_seconds: Optional duration until price reverts.
        is_live: Whether the session is currently live (triggers SSE).

    Returns:
        Dict with the updated shelf item including resolved pricing.

    Raises:
        HTTPException(404) if product not on shelf.
        HTTPException(400) if broadcast_price_cents >= catalog price.
    """
    # Get existing shelf item
    item = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    ).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Product not on shelf.")

    catalog_price = int(item.get("price_cents", 0))
    if broadcast_price_cents >= catalog_price:
        raise HTTPException(
            status_code=400,
            detail=f"Broadcast price ({broadcast_price_cents}) must be less than catalog price ({catalog_price})."
        )

    ts = now_ts()
    expires_at = (ts + expires_in_seconds) if expires_in_seconds else None

    # Build atomic update expression
    # SET for active fields, conditional REMOVE for optional expiry
    update_expr = (
        "SET broadcast_price_cents = :bp, "
        "broadcast_price_set_by = :sb, "
        "broadcast_price_set_at = :sa"
    )
    expr_values: Dict[str, Any] = {
        ":bp": broadcast_price_cents,
        ":sb": set_by,
        ":sa": ts,
    }

    if expires_at:
        update_expr += ", broadcast_price_expires_at = :exp"
        expr_values[":exp"] = expires_at
    else:
        # REMOVE must be a separate clause from SET — DDB syntax
        update_expr += " REMOVE broadcast_price_expires_at"

    T.broadcast_product_shelf.update_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values,
    )

    logger.info(
        "broadcast.pricing.set session_id=%s item_id=%s price=%d set_by=%s expires_in=%s",
        session_id, item_id, broadcast_price_cents, set_by, expires_in_seconds,
    )

    # Re-read the updated item
    updated = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    ).get("Item", {})

    out = _shelf_item_out_with_pricing(updated, "live" if is_live else "draft")

    if is_live:
        broadcast_sse_publish(session_id, {"_type": "shelf:price_update", **out})

    return out


def clear_broadcast_price(
    session_id: str,
    item_id: str,
    *,
    is_live: bool = False,
) -> bool:
    """Remove broadcast-exclusive pricing from a shelf item.

    Args:
        session_id: The broadcast session ID.
        item_id: The catalog item ID.
        is_live: Whether the session is currently live (triggers SSE).

    Returns:
        True if the item was found and pricing was cleared, False if not found.
    """
    item = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    ).get("Item")
    if not item:
        return False

    T.broadcast_product_shelf.update_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"},
        UpdateExpression=(
            "REMOVE broadcast_price_cents, broadcast_price_expires_at, "
            "broadcast_price_set_by, broadcast_price_set_at"
        ),
    )

    logger.info(
        "broadcast.pricing.clear session_id=%s item_id=%s",
        session_id, item_id,
    )

    if is_live:
        updated = T.broadcast_product_shelf.get_item(
            Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
        ).get("Item", {})
        out = _shelf_item_out_with_pricing(updated, "live")
        broadcast_sse_publish(session_id, {"_type": "shelf:price_update", **out})

    return True


def _shelf_item_out_with_pricing(item: Dict[str, Any], session_status: str) -> Dict[str, Any]:
    """Extended shelf item output with resolved pricing.

    Merges the base shelf item output (from LCOM-001's _shelf_item_out) with
    the resolved pricing fields from resolve_effective_price().

    Args:
        item: Raw DDB item from BroadcastProductShelf table.
        session_status: Current session status for price resolution.

    Returns:
        Dict with all shelf item fields plus pricing resolution fields.
    """
    base = _shelf_item_out(item)
    pricing = resolve_effective_price(item, session_status)
    base.update({
        "broadcast_price_cents": (
            int(item["broadcast_price_cents"])
            if item.get("broadcast_price_cents") is not None
            else None
        ),
        "broadcast_price_expires_at": (
            int(item["broadcast_price_expires_at"])
            if item.get("broadcast_price_expires_at")
            else None
        ),
        "broadcast_price_set_at": (
            int(item["broadcast_price_set_at"])
            if item.get("broadcast_price_set_at")
            else None
        ),
        "effective_price_cents": pricing["effective_price_cents"],
        "is_broadcast_price": pricing["is_broadcast_price"],
        "discount_pct": pricing["discount_pct"],
        "original_price_cents": pricing["original_price_cents"],
    })
    return base
```

### 3.5 Quick-Buy Price Integration (LCOM-003 Modification)

<!-- NOTE: app/services/broadcast_orders.py does NOT exist yet — new implementation required (LCOM-003 prerequisite). When created, its create_quick_buy_order() must use the effective price instead of the raw shelf price: -->

```python
# Before (LCOM-003):
unit_price = int(shelf_item.get("price_cents", 0))

# After (LCOM-004):
from app.services.broadcast_product_shelf import resolve_effective_price

# The session status is always "live" at this point because the quick-buy
# endpoint already validates session.status == "live" before reaching here.
# Passing the actual status ensures defense-in-depth — if the session
# transitions away from "live" between the check and this call, the
# catalog price is used instead.
pricing = resolve_effective_price(shelf_item, session.status)
unit_price = pricing["effective_price_cents"]

# Store both prices in the order for audit trail:
order = {
    ...
    "unit_price_cents": unit_price,
    "original_price_cents": pricing["original_price_cents"],
    "was_broadcast_price": pricing["is_broadcast_price"],
    "discount_pct": pricing["discount_pct"],
    ...
}
```

**Important validation**: The quick-buy endpoint must also verify that the broadcast is still live when applying the broadcast price. If the session transitions to `stopped` between the viewer clicking "Buy" and the request arriving, the catalog price should be used instead. This prevents stale discount application.

**Race condition analysis for price changes during purchase**:

```
Time    Broadcaster                   Backend                        Viewer
T+0     Sets price to $39.99         Stores in DDB                  Sees $39.99
T+1                                                                  Clicks "Buy"
T+2     Clears broadcast price       Removes from DDB               Request in flight
T+3                                  Quick-buy handler runs          
T+3.1                                resolve_effective_price()
T+3.2                                broadcast_price_cents = None
T+3.3                                → uses catalog price $49.99
T+3.4                                → order created at $49.99       Gets order at $49.99
```

This is the CORRECT behavior. The server always resolves the current effective price at purchase time. The client-displayed price is informational only. If the viewer's displayed price was $39.99 but the server charges $49.99 because the deal expired, the order confirmation shows $49.99 and the viewer can see the price they actually paid.

### 3.6 Chat Product Link Price Integration (LCOM-002 Modification)

When sending a product link via `POST /broadcast/sessions/{id}/chat/product`, the `product_link` data should include broadcast pricing fields so the product link card in chat shows the correct price.

<!-- NOTE: This integration is already implemented in app/routers/broadcast.py at the send_chat_product_link_route (line 1446). The route imports resolve_effective_price at line 1465, calls it at line 1471, and assembles the pricing fields into product_link_data at lines 1494-1498. -->

```python
# In app/routers/broadcast.py — already implemented (lines 1465-1498)

from app.services.broadcast_product_shelf import resolve_effective_price

# Resolve the current effective price for the product link snapshot
pricing = resolve_effective_price(shelf_item, session_status)

product_link_data = {
    "item_id": shelf_item["item_id"],
    "name": shelf_item.get("name", ""),
    "price_cents": int(shelf_item.get("price_cents", 0)),
    "broadcast_price_cents": shelf_item.get("broadcast_price_cents"),      # NEW
    "broadcast_price_expires_at": shelf_item.get("broadcast_price_expires_at"),  # NEW
    "effective_price_cents": pricing["effective_price_cents"],              # NEW
    "is_broadcast_price": pricing["is_broadcast_price"],                  # NEW
    "discount_pct": pricing["discount_pct"],                              # NEW
    "image_url": shelf_item.get("image_url"),
    "currency": shelf_item.get("currency", "USD"),
}
```

**Important note on snapshotting**: The product link message stores a SNAPSHOT of the pricing at the time the link was shared. If the broadcaster changes the price after the link is sent, the link card still shows the old price. This is intentional — chat messages are immutable. The "Buy Now" button on the link card always opens `QuickBuyDialog` which fetches the CURRENT price from the server before confirming the purchase.

### 3.7 SSE Events

| Event Type | Payload | Trigger |
|------------|---------|---------|
| `shelf:price_update` | Full `BroadcastShelfItemOut` with pricing fields | Broadcast price set or cleared during live session |

**SSE event schema detail**:

```json
{
    "_type": "shelf:price_update",
    "session_id": "sess_abc123",
    "item_id": "cat_item_xyz",
    "name": "Winter Jacket",
    "price_cents": 4999,
    "broadcast_price_cents": 3999,
    "broadcast_price_expires_at": 1716580600,
    "effective_price_cents": 3999,
    "is_broadcast_price": true,
    "discount_pct": 20,
    "original_price_cents": 4999,
    "currency": "USD",
    "image_url": "/mock/s3/...",
    "display_order": 1
}
```

**SSE delivery guarantee**: The in-memory pub/sub (`broadcast_sse.py`) is best-effort. If a viewer's queue is full (100 items), the queue is discarded (lines 38-43). The frontend handles this via periodic refetch — `useQuery` with `refetchInterval: 30000` on the shelf listing ensures price convergence within 30 seconds even if an SSE event is lost.

### 3.8 Frontend — Price Display Component

<!-- NOTE: frontend/src/pages/broadcast/BroadcastPrice.tsx does NOT exist yet — new implementation required -->

```typescript
// frontend/src/pages/broadcast/BroadcastPrice.tsx — TO BE CREATED

/**
 * BroadcastPrice — displays the effective price for a broadcast shelf item.
 *
 * When a broadcast-exclusive price is active, renders:
 *   - Struck-through original price (muted color, smaller font)
 *   - Highlighted effective price (green, bold)
 *   - "LIVE DEAL -N%" destructive badge
 *   - Countdown timer if expiry is set
 *
 * When no broadcast price is active, renders just the price in bold.
 *
 * The countdown timer updates every second via setInterval. When it
 * reaches zero, it shows "Deal ended" and the parent component should
 * refetch the shelf listing to get the current price.
 *
 * Accessibility:
 *   - aria-label on the price container describes the discount
 *   - aria-live="polite" on the countdown so screen readers announce changes
 *   - "LIVE DEAL" badge uses role="status" for announcement
 *
 * Responsive behavior:
 *   - On mobile (<640px), badge text shortens to "-N%"
 *   - On desktop, shows full "LIVE DEAL -N%"
 */

import { useState, useEffect, useCallback } from "react";
import { Badge } from "@/components/ui/badge";

interface BroadcastPriceProps {
  originalPriceCents: number;
  effectivePriceCents: number;
  isBroadcastPrice: boolean;
  discountPct: number;
  expiresAt: number | null;  // unix timestamp
  currency?: string;
  /** Called when countdown reaches zero — parent should refetch pricing */
  onExpired?: () => void;
  /** Compact mode for inline display (chat product links) */
  compact?: boolean;
}

export function BroadcastPrice({
  originalPriceCents,
  effectivePriceCents,
  isBroadcastPrice,
  discountPct,
  expiresAt,
  currency = "USD",
  onExpired,
  compact = false,
}: BroadcastPriceProps) {
  const [countdown, setCountdown] = useState<string | null>(null);

  // Countdown timer for expiring prices
  useEffect(() => {
    if (!expiresAt) { setCountdown(null); return; }

    const tick = () => {
      const remaining = expiresAt - Math.floor(Date.now() / 1000);
      if (remaining <= 0) {
        setCountdown("Expired");
        clearInterval(interval);
        onExpired?.();
        return;
      }
      const mins = Math.floor(remaining / 60);
      const secs = remaining % 60;
      setCountdown(`${mins}:${String(secs).padStart(2, "0")}`);
    };

    tick(); // immediate first tick to avoid 1s blank
    const interval = setInterval(tick, 1000);

    return () => clearInterval(interval);
  }, [expiresAt, onExpired]);

  const formatPrice = useCallback(
    (cents: number) => {
      // Use Intl.NumberFormat for proper locale-aware currency formatting
      return new Intl.NumberFormat("en-US", {
        style: "currency",
        currency,
        minimumFractionDigits: 2,
      }).format(cents / 100);
    },
    [currency],
  );

  if (!isBroadcastPrice) {
    return (
      <span className="font-bold" data-testid="price-effective">
        {formatPrice(effectivePriceCents)}
      </span>
    );
  }

  return (
    <div
      className={compact ? "flex items-center gap-1.5" : "flex flex-col"}
      aria-label={`${formatPrice(effectivePriceCents)}, was ${formatPrice(originalPriceCents)}, ${discountPct}% off`}
    >
      <div className="flex items-center gap-2">
        <span
          className="text-muted-foreground line-through text-sm"
          data-testid="price-original"
        >
          {formatPrice(originalPriceCents)}
        </span>
        <span
          className="font-bold text-green-600 dark:text-green-400"
          data-testid="price-effective"
        >
          {formatPrice(effectivePriceCents)}
        </span>
        <Badge
          variant="destructive"
          className="text-xs px-1 py-0"
          role="status"
          data-testid="price-badge"
        >
          <span className="hidden sm:inline">LIVE DEAL </span>
          -{discountPct}%
        </Badge>
      </div>
      {countdown && countdown !== "Expired" && (
        <span
          className="text-xs text-orange-500 dark:text-orange-400"
          aria-live="polite"
          data-testid="price-countdown"
        >
          Ends in {countdown}
        </span>
      )}
      {countdown === "Expired" && (
        <span
          className="text-xs text-muted-foreground"
          data-testid="price-expired"
        >
          Deal ended
        </span>
      )}
    </div>
  );
}
```

### 3.9 Frontend — Broadcaster Price Editor

<!-- NOTE: frontend/src/pages/broadcast/BroadcastPriceEditor.tsx does NOT exist yet — new implementation required -->

```typescript
// frontend/src/pages/broadcast/BroadcastPriceEditor.tsx — TO BE CREATED

/**
 * BroadcastPriceEditor — broadcaster-facing UI for setting/clearing
 * broadcast-exclusive prices on shelf items.
 *
 * Rendered inside the ProductShelfManager for each shelf item.
 * Uses a toggle switch to enable/disable the broadcast price.
 * When enabled, shows:
 *   - Dollar input for the broadcast price
 *   - Dropdown for expiry duration (or "Entire broadcast")
 *   - "Set Broadcast Price" button
 * When disabled (toggled off), immediately calls clearBroadcastPrice.
 *
 * The component validates client-side that the broadcast price is:
 *   1. Greater than $0.00
 *   2. Less than the catalog price
 * before enabling the submit button. Server-side validation provides
 * the authoritative check.
 *
 * React Query integration:
 *   - setPriceMutation invalidates ["broadcast-shelf", sessionId]
 *   - clearPriceMutation invalidates ["broadcast-shelf", sessionId]
 *   - This ensures the shelf listing refetches with updated pricing
 *
 * Accessibility:
 *   - Switch has aria-label "Enable broadcast price for {item name}"
 *   - Price input has aria-describedby linking to the catalog price hint
 *   - Submit button disabled state announced via aria-disabled
 */

import { useState, useMemo } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { setBroadcastPrice, clearBroadcastPrice } from "@/api/endpoints/broadcast-shelf";

interface ShelfItem {
  item_id: string;
  name: string;
  price_cents: number;
  broadcast_price_cents: number | null;
  broadcast_price_expires_at: number | null;
  effective_price_cents: number;
  is_broadcast_price: boolean;
  discount_pct: number;
}

interface BroadcastPriceEditorProps {
  sessionId: string;
  item: ShelfItem;
  onPriceSet: () => void;
}

export function BroadcastPriceEditor({ sessionId, item, onPriceSet }: BroadcastPriceEditorProps) {
  const queryClient = useQueryClient();
  const [enabled, setEnabled] = useState(!!item.broadcast_price_cents);
  const [priceDollars, setPriceDollars] = useState(
    item.broadcast_price_cents ? (item.broadcast_price_cents / 100).toFixed(2) : ""
  );
  const [expiresMinutes, setExpiresMinutes] = useState<number | null>(null);

  // Derived validation state
  const priceCents = useMemo(() => {
    const parsed = parseFloat(priceDollars);
    return isNaN(parsed) ? 0 : Math.round(parsed * 100);
  }, [priceDollars]);

  const isValidPrice = priceCents > 0 && priceCents < item.price_cents;
  const savingsPercent = isValidPrice
    ? Math.round((1 - priceCents / item.price_cents) * 100)
    : 0;

  const setPriceMutation = useMutation({
    mutationFn: () => setBroadcastPrice(sessionId, item.item_id, {
      broadcast_price_cents: priceCents,
      expires_in_seconds: expiresMinutes ? expiresMinutes * 60 : undefined,
    }),
    onSuccess: () => {
      toast.success("Broadcast price set!");
      queryClient.invalidateQueries({ queryKey: ["broadcast-shelf", sessionId] });
      onPriceSet();
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail || "Failed to set broadcast price.";
      toast.error(typeof detail === "string" ? detail : JSON.stringify(detail));
    },
  });

  const clearPriceMutation = useMutation({
    mutationFn: () => clearBroadcastPrice(sessionId, item.item_id),
    onSuccess: () => {
      toast.success("Broadcast price cleared.");
      setEnabled(false);
      setPriceDollars("");
      setExpiresMinutes(null);
      queryClient.invalidateQueries({ queryKey: ["broadcast-shelf", sessionId] });
      onPriceSet();
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail || "Failed to clear broadcast price.";
      toast.error(typeof detail === "string" ? detail : JSON.stringify(detail));
    },
  });

  return (
    <div className="border rounded-lg p-3 space-y-2" data-testid="price-editor">
      <div className="flex items-center justify-between">
        <Label className="text-sm font-medium">Broadcast Price</Label>
        <Switch
          checked={enabled}
          onCheckedChange={(v) => {
            setEnabled(v);
            if (!v) clearPriceMutation.mutate();
          }}
          aria-label={`Enable broadcast price for ${item.name}`}
        />
      </div>
      {enabled && (
        <>
          <div className="flex gap-2 items-center">
            <span className="text-sm text-muted-foreground">$</span>
            <Input
              type="number"
              step="0.01"
              min="0.01"
              max={(item.price_cents / 100 - 0.01).toFixed(2)}
              value={priceDollars}
              onChange={e => setPriceDollars(e.target.value)}
              className="w-24"
              aria-label="Broadcast price in dollars"
              aria-describedby="catalog-price-hint"
            />
            <span id="catalog-price-hint" className="text-xs text-muted-foreground">
              (catalog: ${(item.price_cents / 100).toFixed(2)})
            </span>
            {isValidPrice && (
              <Badge variant="outline" className="text-xs">
                -{savingsPercent}%
              </Badge>
            )}
          </div>
          {priceCents >= item.price_cents && priceDollars !== "" && (
            <p className="text-xs text-destructive" role="alert">
              Must be less than catalog price (${(item.price_cents / 100).toFixed(2)})
            </p>
          )}
          <div className="flex gap-2 items-center">
            <Label className="text-xs">Expires in:</Label>
            <Select value={expiresMinutes?.toString() || "none"} onValueChange={v =>
              setExpiresMinutes(v === "none" ? null : parseInt(v))
            }>
              <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="none">Entire broadcast</SelectItem>
                <SelectItem value="5">5 minutes</SelectItem>
                <SelectItem value="10">10 minutes</SelectItem>
                <SelectItem value="15">15 minutes</SelectItem>
                <SelectItem value="30">30 minutes</SelectItem>
                <SelectItem value="60">1 hour</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Button
            size="sm"
            onClick={() => setPriceMutation.mutate()}
            disabled={!isValidPrice || setPriceMutation.isPending}
            aria-label="Set broadcast price"
          >
            {setPriceMutation.isPending ? "Setting..." : "Set Broadcast Price"}
          </Button>
        </>
      )}
    </div>
  );
}
```

### 3.10 Frontend — SSE Event Handler for Price Updates

```typescript
// Integration in frontend/src/pages/broadcast/LivePlayer.tsx (exists, see LivePlayer.tsx)
// or a dedicated useBroadcastShelfEvents hook

/**
 * Handle shelf:price_update SSE events.
 *
 * When a shelf:price_update event arrives, update the React Query cache
 * for the shelf listing. This avoids a full refetch — instead, we
 * surgically update the specific item in the cached list.
 *
 * Pattern matches the existing chat:message and purchase:completed handlers
 * already in LivePlayer.tsx.
 */

// Inside the SSE event handler (useEffect in LivePlayer):
case "shelf:price_update": {
  const update = JSON.parse(event.data);
  queryClient.setQueryData<ShelfItem[]>(
    ["broadcast-shelf", sessionId],
    (old) => {
      if (!old) return old;
      return old.map((item) =>
        item.item_id === update.item_id
          ? {
              ...item,
              broadcast_price_cents: update.broadcast_price_cents,
              broadcast_price_expires_at: update.broadcast_price_expires_at,
              effective_price_cents: update.effective_price_cents,
              is_broadcast_price: update.is_broadcast_price,
              discount_pct: update.discount_pct,
            }
          : item,
      );
    },
  );
  break;
}
```

### 3.11 Frontend TypeScript Types

<!-- NOTE: frontend/src/api/endpoints/broadcast-shelf.ts (44 lines) exists but does NOT yet include broadcast pricing fields, setBroadcastPrice, or clearBroadcastPrice API functions — extension required -->

```typescript
// frontend/src/api/endpoints/broadcast-shelf.ts (to be extended)

export interface ShelfItem {
  session_id: string;
  item_id: string;
  category_id: string;
  name: string;
  description: string | null;
  price_cents: number;
  currency: string;
  image_url: string | null;
  display_order: number;
  added_by: string;
  added_at: number;
  // Broadcast pricing (LCOM-004)
  broadcast_price_cents: number | null;        // NEW
  broadcast_price_expires_at: number | null;   // NEW
  effective_price_cents: number;               // NEW
  is_broadcast_price: boolean;                 // NEW
  discount_pct: number;                        // NEW
}

export interface BroadcastPriceResponse {
  session_id: string;
  item_id: string;
  original_price_cents: number;
  broadcast_price_cents: number;
  broadcast_price_expires_at: number | null;
  discount_pct: number;
  set_by: string;
  set_at: number;
}

// API functions:
export const setBroadcastPrice = (
  sessionId: string,
  itemId: string,
  body: { broadcast_price_cents: number; expires_in_seconds?: number },
) => api.patch<BroadcastPriceResponse>(
  `/broadcast/sessions/${sessionId}/products/${itemId}/price`,
  body,
);

export const clearBroadcastPrice = (sessionId: string, itemId: string) =>
  api.del<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/products/${itemId}/price`);
```

### 3.12 Frontend Component Hierarchy

```
LivePlayer (viewer)
├── MediaPlayer (video)
├── ProductShelfPanel
│   └── ProductShelfCard (per item)
│       ├── BroadcastPrice                    ← NEW (LCOM-004)
│       │   ├── OriginalPrice (strikethrough)
│       │   ├── EffectivePrice (green, bold)
│       │   ├── DiscountBadge ("LIVE DEAL -N%")
│       │   └── CountdownTimer ("Ends in M:SS")
│       └── QuickBuyButton
│           └── QuickBuyDialog (LCOM-003)
│               └── BroadcastPrice (inside dialog, compact mode)
├── BroadcastChat
│   └── ChatMessage (per msg)
│       └── ProductLinkCard (kind=product_link)
│           └── BroadcastPrice (compact mode)  ← NEW (LCOM-004)
└── ChatOverlay

BroadcasterDashboard
├── SessionControls
├── ProductShelfManager
│   └── ShelfItemRow (per item)
│       ├── ProductInfo (name, image, catalog price)
│       └── BroadcastPriceEditor              ← NEW (LCOM-004)
│           ├── EnableSwitch
│           ├── PriceInput
│           ├── ExpirySelect
│           ├── SavingsPreview (Badge "-N%")
│           └── SetPriceButton
├── PurchaseCounter (LCOM-003)
└── ChatModeration
```

---

## 4. Implementation Plan

### Phase 1: Backend — Price Resolution + Schema (1 day) -- ALREADY IMPLEMENTED

| File | Change | Status |
|------|--------|--------|
| `app/services/broadcast_product_shelf.py` (441 lines) | `resolve_effective_price()` at line 211, `set_broadcast_price()` at line 315, `clear_broadcast_price()` at line 399, `_shelf_item_out_with_pricing()` at line 264, `list_shelf_products_with_pricing()` at line 296. | **Done** |

### Phase 2: Backend — Pricing Endpoints (1 day) -- ALREADY IMPLEMENTED

| File | Change | Status |
|------|--------|--------|
| `app/models.py` | `BroadcastPriceSetIn` at line 2426, `BroadcastPriceOut` at line 2440. | **Done** |
| `app/routers/broadcast.py` (~3969 lines) | `set_broadcast_price_route()` PATCH at line 1975, `clear_broadcast_price_route()` DELETE at line 2022. Shelf listing at line 1928 already calls `list_shelf_products_with_pricing`. `BroadcastShelfItemOut` pricing fields at lines 1829-1835. | **Done** |

### Phase 3: Backend — Quick-Buy Integration (0.5 days) -- BLOCKED (LCOM-003)

| File | Change | Status |
|------|--------|--------|
| `app/services/broadcast_orders.py` | Does NOT exist yet — LCOM-003 prerequisite. When created, must use `resolve_effective_price()` for unit price, add `original_price_cents`, `was_broadcast_price`, `discount_pct` to order record. | **Not started** |

### Phase 4: Backend — Chat Product Link Integration (0.5 days) -- ALREADY IMPLEMENTED

| File | Change | Status |
|------|--------|--------|
| `app/routers/broadcast.py` | `send_chat_product_link_route` (line 1446) already imports and calls `resolve_effective_price` (lines 1465, 1471) and assembles pricing snapshot in `product_link_data` (lines 1494-1498). | **Done** |

### Phase 5: Frontend — Price Display Components (1.5 days) -- NOT STARTED

| File | Type | Lines | Status |
|------|------|-------|--------|
| `frontend/src/pages/broadcast/BroadcastPrice.tsx` | Create — price display with strikethrough, badge, countdown, Intl.NumberFormat, accessibility attrs, `onExpired` callback, compact mode | ~130 | **Does not exist** |
| `frontend/src/pages/broadcast/BroadcastPriceEditor.tsx` | Create — broadcaster price setting UI with validation, React Query mutations, error toasts, savings preview badge | ~160 | **Does not exist** |
| `frontend/src/api/endpoints/broadcast-shelf.ts` | Modify — extend `ShelfItem` interface (currently 44 lines, no pricing fields), add `BroadcastPriceResponse`, add `setBroadcastPrice()`, `clearBroadcastPrice()` API functions | +40 | **Exists but needs extension** |

### Phase 6: Frontend — Integration (1 day) -- NOT STARTED

| File | Change | Lines Changed | Status |
|------|--------|---------------|--------|
| `frontend/src/pages/broadcast/ProductShelfCard.tsx` | Replace simple price display with `BroadcastPrice` component. Pass `onExpired` to trigger shelf refetch. | +15 | **Does not exist** |
| `frontend/src/pages/broadcast/ProductLinkCard.tsx` | Add `BroadcastPrice` display (compact mode) when broadcast pricing fields present in link data. | +12 | **Does not exist** |
| `frontend/src/pages/broadcast/QuickBuyDialog.tsx` | Show effective price with `BroadcastPrice` component. Show both original and broadcast price in order summary. | +18 | **Does not exist** |
| `frontend/src/pages/broadcast/ProductShelfManager.tsx` | Add `BroadcastPriceEditor` for each shelf item in the manager list. | +10 | **Exists** |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Handle `shelf:price_update` SSE event — update React Query cache surgically. | +20 | **Exists** |

### Phase 7: Client-side Expiry Handling (0.5 days)

When a broadcast price expires client-side (countdown reaches 0):

1. `BroadcastPrice` component shows "Deal ended" text.
2. The `onExpired` callback fires, triggering a shelf listing refetch via `queryClient.invalidateQueries({ queryKey: ["broadcast-shelf", sessionId] })`.
3. The refetched data has `is_broadcast_price: false` (server resolves at read time).
4. `QuickBuyDialog` shows the catalog price after refetch.
5. No additional API call is needed beyond the shelf refetch — the backend always re-validates at purchase time.

### Summary of All Files

| File | Type | Estimated Lines | Status |
|------|------|-----------------|--------|
| `app/services/broadcast_product_shelf.py` | Modify | +155 | **Already implemented** (441 lines total) |
| `app/models.py` | Modify | +30 | **Already implemented** (lines 2426-2448) |
| `app/routers/broadcast.py` | Modify | +90 | **Already implemented** (~3969 lines total) |
| `app/services/broadcast_orders.py` | Modify | +20 | **Does not exist** (LCOM-003 prerequisite) |
| `app/services/broadcast_chat_store.py` | N/A | 0 | **Integration done in broadcast.py instead** (line 1465) |
| `frontend/src/api/endpoints/broadcast-shelf.ts` | Modify | +40 | **Exists** (44 lines, needs pricing extension) |
| `frontend/src/pages/broadcast/BroadcastPrice.tsx` | Create | ~130 | **Does not exist** |
| `frontend/src/pages/broadcast/BroadcastPriceEditor.tsx` | Create | ~160 | **Does not exist** |
| `frontend/src/pages/broadcast/ProductShelfCard.tsx` | Create | +15 | **Does not exist** |
| `frontend/src/pages/broadcast/ProductLinkCard.tsx` | Create | +12 | **Does not exist** |
| `frontend/src/pages/broadcast/QuickBuyDialog.tsx` | Create | +18 | **Does not exist** (LCOM-003 prerequisite) |
| `frontend/src/pages/broadcast/ProductShelfManager.tsx` | Modify | +10 | **Exists** |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Modify | +20 | **Exists** |
| **Total** | | **~685** | Backend done; frontend remaining |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_pricing.py`)

~400 lines, using `moto` for DynamoDB mocking.

```python
# tests/test_broadcast_pricing.py

import pytest
from unittest.mock import patch
from decimal import Decimal
from moto import mock_dynamodb

from app.core.time import now_ts
from app.services.broadcast_product_shelf import (
    resolve_effective_price,
    set_broadcast_price,
    clear_broadcast_price,
    _shelf_item_out_with_pricing,
)
from app.core.tables import T

# ── Test Fixtures ─────────────────────────────────────────────

SHELF_ITEM_BASE = {
    "session_id": "sess_test1",
    "SK": "ITEM#item_test1",
    "item_id": "item_test1",
    "category_id": "cat_test1",
    "name": "Winter Jacket",
    "price_cents": 4999,
    "currency": "USD",
    "image_url": "/mock/s3/jacket.jpg",
    "display_order": 1,
    "added_by": "user_broadcaster",
    "added_at": 1716580000,
}

SHELF_ITEM_NO_DISCOUNT = {**SHELF_ITEM_BASE}

SHELF_ITEM = {**SHELF_ITEM_BASE}


def _seed_shelf_item(table, item=None):
    """Seed a shelf item into the BroadcastProductShelf table."""
    table.put_item(Item=item or {**SHELF_ITEM_BASE})


@mock_dynamodb
class TestResolveEffectivePrice:
    """Test the core price resolution logic."""

    def test_no_broadcast_price_returns_catalog_price(self):
        """When no broadcast price is set, effective price equals catalog price."""
        pricing = resolve_effective_price(SHELF_ITEM_NO_DISCOUNT, "live")
        assert pricing["effective_price_cents"] == 4999
        assert pricing["is_broadcast_price"] is False
        assert pricing["discount_pct"] == 0
        assert pricing["original_price_cents"] == 4999
        assert pricing["broadcast_price_expires_at"] is None

    def test_broadcast_price_active_when_live(self):
        """Broadcast price is used when session is live and price is set."""
        item = {**SHELF_ITEM, "broadcast_price_cents": 3999}
        pricing = resolve_effective_price(item, "live")
        assert pricing["effective_price_cents"] == 3999
        assert pricing["is_broadcast_price"] is True
        assert pricing["discount_pct"] == 20  # (4999-3999)/4999 * 100 ≈ 20

    def test_broadcast_price_inactive_when_stopped(self):
        """Broadcast price reverts to catalog when session is stopped."""
        item = {**SHELF_ITEM, "broadcast_price_cents": 3999}
        pricing = resolve_effective_price(item, "stopped")
        assert pricing["effective_price_cents"] == 4999
        assert pricing["is_broadcast_price"] is False

    def test_broadcast_price_inactive_when_draft(self):
        """Broadcast price is stored but inactive when session is in draft."""
        item = {**SHELF_ITEM, "broadcast_price_cents": 3999}
        pricing = resolve_effective_price(item, "draft")
        assert pricing["effective_price_cents"] == 4999
        assert pricing["is_broadcast_price"] is False

    def test_broadcast_price_inactive_when_ready(self):
        """Broadcast price is stored but inactive when session is ready."""
        item = {**SHELF_ITEM, "broadcast_price_cents": 3999}
        pricing = resolve_effective_price(item, "ready")
        assert pricing["effective_price_cents"] == 4999

    def test_broadcast_price_inactive_when_provisioning(self):
        """Broadcast price inactive during provisioning."""
        item = {**SHELF_ITEM, "broadcast_price_cents": 3999}
        pricing = resolve_effective_price(item, "provisioning")
        assert pricing["effective_price_cents"] == 4999

    def test_broadcast_price_inactive_when_error(self):
        """Broadcast price inactive when session errored."""
        item = {**SHELF_ITEM, "broadcast_price_cents": 3999}
        pricing = resolve_effective_price(item, "error")
        assert pricing["effective_price_cents"] == 4999

    def test_broadcast_price_inactive_when_expired(self):
        """Broadcast price reverts to catalog after expiry timestamp."""
        item = {**SHELF_ITEM, "broadcast_price_cents": 3999,
                "broadcast_price_expires_at": now_ts() - 60}  # expired 1 min ago
        pricing = resolve_effective_price(item, "live")
        assert pricing["effective_price_cents"] == 4999
        assert pricing["is_broadcast_price"] is False

    def test_broadcast_price_active_before_expiry(self):
        """Broadcast price is active before expiry timestamp."""
        item = {**SHELF_ITEM, "broadcast_price_cents": 3999,
                "broadcast_price_expires_at": now_ts() + 600}  # expires in 10 min
        pricing = resolve_effective_price(item, "live")
        assert pricing["effective_price_cents"] == 3999
        assert pricing["is_broadcast_price"] is True
        assert pricing["broadcast_price_expires_at"] is not None

    def test_broadcast_price_zero_is_inactive(self):
        """A broadcast_price_cents of 0 is treated as no discount."""
        item = {**SHELF_ITEM, "broadcast_price_cents": 0}
        pricing = resolve_effective_price(item, "live")
        assert pricing["effective_price_cents"] == 4999
        assert pricing["is_broadcast_price"] is False

    def test_discount_pct_calculation_50_percent(self):
        """50% discount: $49.99 -> $25.00."""
        item = {**SHELF_ITEM, "broadcast_price_cents": 2500}
        pricing = resolve_effective_price(item, "live")
        assert pricing["discount_pct"] == 50

    def test_discount_pct_calculation_1_cent(self):
        """Extreme discount: $49.99 -> $0.01 = 100% off."""
        item = {**SHELF_ITEM, "broadcast_price_cents": 1}
        pricing = resolve_effective_price(item, "live")
        assert pricing["discount_pct"] == 100  # round((1 - 1/4999) * 100) = 100

    def test_discount_pct_clamped_to_0_100(self):
        """Discount percentage is clamped between 0 and 100."""
        # Pathological case: broadcast price > catalog price
        # (shouldn't happen but test the clamping)
        item = {**SHELF_ITEM, "broadcast_price_cents": 9999}
        pricing = resolve_effective_price(item, "live")
        assert pricing["discount_pct"] == 0  # clamped to 0 (max(0, min(100, -100)))

    def test_original_price_zero_prevents_div_by_zero(self):
        """Free items don't cause division by zero in discount calculation."""
        item = {**SHELF_ITEM, "price_cents": 0, "broadcast_price_cents": 0}
        pricing = resolve_effective_price(item, "live")
        assert pricing["discount_pct"] == 0

    def test_decimal_values_from_dynamodb(self):
        """DynamoDB returns Decimal, not int. Verify coercion works."""
        item = {
            **SHELF_ITEM,
            "price_cents": Decimal("4999"),
            "broadcast_price_cents": Decimal("3999"),
            "broadcast_price_expires_at": Decimal(str(now_ts() + 600)),
        }
        pricing = resolve_effective_price(item, "live")
        assert pricing["effective_price_cents"] == 3999
        assert isinstance(pricing["effective_price_cents"], int)


@mock_dynamodb
class TestSetBroadcastPrice:
    """Test the set_broadcast_price service function."""

    def setup_method(self):
        """Create BroadcastProductShelf table and seed a shelf item."""
        # Table creation handled by moto mock
        pass

    def test_set_broadcast_price_returns_updated_item(self):
        result = set_broadcast_price("sess1", "item1", 3999, "user1")
        assert result["broadcast_price_cents"] == 3999
        assert result["effective_price_cents"] == 3999

    def test_set_broadcast_price_with_expiry(self):
        result = set_broadcast_price("sess1", "item1", 3999, "user1",
                                     expires_in_seconds=600)
        assert result["broadcast_price_expires_at"] is not None
        assert result["broadcast_price_expires_at"] > now_ts()

    def test_set_broadcast_price_without_expiry_clears_existing_expiry(self):
        """Setting price without expiry should REMOVE any existing expiry."""
        set_broadcast_price("sess1", "item1", 3999, "user1", expires_in_seconds=600)
        result = set_broadcast_price("sess1", "item1", 2999, "user1")
        # No expiry passed → REMOVE broadcast_price_expires_at
        assert result.get("broadcast_price_expires_at") is None

    def test_set_broadcast_price_above_catalog_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            set_broadcast_price("sess1", "item1", 9999, "user1")
        assert exc.value.status_code == 400

    def test_set_broadcast_price_equal_to_catalog_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            set_broadcast_price("sess1", "item1", 4999, "user1")
        assert exc.value.status_code == 400

    def test_set_broadcast_price_on_nonexistent_item_raises_404(self):
        with pytest.raises(HTTPException) as exc:
            set_broadcast_price("sess1", "nonexistent", 3999, "user1")
        assert exc.value.status_code == 404

    def test_set_broadcast_price_publishes_sse_when_live(self):
        with patch("app.services.broadcast_product_shelf.broadcast_sse_publish") as mock_pub:
            set_broadcast_price("sess1", "item1", 3999, "user1", is_live=True)
            mock_pub.assert_called_once()
            call_args = mock_pub.call_args
            assert call_args[0][0] == "sess1"
            assert call_args[0][1]["_type"] == "shelf:price_update"

    def test_set_broadcast_price_no_sse_when_draft(self):
        with patch("app.services.broadcast_product_shelf.broadcast_sse_publish") as mock_pub:
            set_broadcast_price("sess1", "item1", 3999, "user1", is_live=False)
            mock_pub.assert_not_called()

    def test_set_broadcast_price_stores_set_by_and_set_at(self):
        result = set_broadcast_price("sess1", "item1", 3999, "user_abc")
        assert result["broadcast_price_set_at"] is not None
        assert result["broadcast_price_set_at"] > 0


@mock_dynamodb
class TestClearBroadcastPrice:
    """Test the clear_broadcast_price service function."""

    def test_clear_broadcast_price_removes_fields(self):
        set_broadcast_price("sess1", "item1", 3999, "user1")
        assert clear_broadcast_price("sess1", "item1") is True
        item = T.broadcast_product_shelf.get_item(
            Key={"session_id": "sess1", "SK": "ITEM#item1"}
        ).get("Item")
        assert "broadcast_price_cents" not in item
        assert "broadcast_price_expires_at" not in item
        assert "broadcast_price_set_by" not in item
        assert "broadcast_price_set_at" not in item

    def test_clear_nonexistent_returns_false(self):
        assert clear_broadcast_price("sess1", "nonexistent") is False

    def test_clear_publishes_sse_when_live(self):
        set_broadcast_price("sess1", "item1", 3999, "user1")
        with patch("app.services.broadcast_product_shelf.broadcast_sse_publish") as mock_pub:
            clear_broadcast_price("sess1", "item1", is_live=True)
            mock_pub.assert_called_once()
            payload = mock_pub.call_args[0][1]
            assert payload["_type"] == "shelf:price_update"
            assert payload["is_broadcast_price"] is False

    # ── Quick-Buy Integration ─────────────────────────────────────

    def test_quick_buy_uses_broadcast_price(self):
        set_broadcast_price("sess1", "item1", 3999, "seller1")
        shelf_item = T.broadcast_product_shelf.get_item(
            Key={"session_id": "sess1", "SK": "ITEM#item1"}
        ).get("Item")
        pricing = resolve_effective_price(shelf_item, "live")
        assert pricing["effective_price_cents"] == 3999

    def test_quick_buy_uses_catalog_price_when_expired(self):
        set_broadcast_price("sess1", "item1", 3999, "seller1",
                            expires_in_seconds=-1)  # already expired
        shelf_item = T.broadcast_product_shelf.get_item(
            Key={"session_id": "sess1", "SK": "ITEM#item1"}
        ).get("Item")
        pricing = resolve_effective_price(shelf_item, "live")
        assert pricing["effective_price_cents"] == 4999

    # ── List with Pricing ─────────────────────────────────────────

    def test_list_includes_pricing_fields(self):
        set_broadcast_price("sess1", "item1", 3999, "user1")
        items = list_shelf_products("sess1", session_status="live")
        assert items[0]["is_broadcast_price"] is True
        assert items[0]["effective_price_cents"] == 3999
        assert items[0]["broadcast_price_cents"] == 3999
```

### 5.2 E2E Tests (`frontend/e2e/broadcast-pricing.spec.ts`)

**Section 130: Broadcast Price API (8 tests)**:

```typescript
test.describe("Section 130: Broadcast Price API", () => {
  test("130.1 — Broadcaster sets broadcast price on a shelf product", async ({ page }) => {
    // PATCH /broadcast/sessions/{sessionId}/products/{itemId}/price
    // Body: { broadcast_price_cents: 3999 }
    // Assert: 200, broadcast_price_cents == 3999, discount_pct == 20
  });

  test("130.2 — Broadcast price must be less than catalog price — 400 if equal", async ({ page }) => {
    // PATCH with broadcast_price_cents == price_cents (4999)
    // Assert: 400
  });

  test("130.3 — Broadcast price must be less than catalog price — 400 if higher", async ({ page }) => {
    // PATCH with broadcast_price_cents > price_cents (9999)
    // Assert: 400
  });

  test("130.4 — Broadcast price with expiry sets expires_at in the future", async ({ page }) => {
    // PATCH with expires_in_seconds: 600
    // Assert: broadcast_price_expires_at > now
  });

  test("130.5 — Clear broadcast price removes pricing fields", async ({ page }) => {
    // SET price, then DELETE
    // GET shelf listing: broadcast_price_cents == null, is_broadcast_price == false
  });

  test("130.6 — Shelf listing includes effective_price_cents with broadcast price when live", async ({ page }) => {
    // Set price, list shelf
    // Assert: effective_price_cents == broadcast_price_cents
  });

  test("130.7 — Non-broadcaster cannot set broadcast price — 403", async ({ page }) => {
    // Use Bob's session to PATCH Alice's broadcast
    // Assert: 403
  });

  test("130.8 — Setting price on non-shelf product returns 404", async ({ page }) => {
    // PATCH with item_id that doesn't exist on shelf
    // Assert: 404
  });
});
```

**Section 131: Price Expiry (4 tests)**:

```typescript
test.describe("Section 131: Price Expiry", () => {
  test("131.1 — Broadcast price is effective before expiry timestamp", async ({ page }) => {
    // Set price with 600s expiry
    // Immediately list shelf
    // Assert: is_broadcast_price == true, effective_price_cents == broadcast price
  });

  test("131.2 — Broadcast price reverts to catalog price after expiry timestamp", async ({ page }) => {
    // Set price with very short expiry (use negative offset or mock time)
    // Backend: set_broadcast_price with expires_in_seconds that results in past timestamp
    // List shelf
    // Assert: is_broadcast_price == false, effective_price_cents == catalog price
  });

  test("131.3 — Quick-buy uses broadcast price before expiry", async ({ page }) => {
    // Set broadcast price with 600s expiry
    // Quick-buy order
    // Assert: order.unit_price_cents == broadcast price
  });

  test("131.4 — Quick-buy uses catalog price after expiry (server-side)", async ({ page }) => {
    // Set broadcast price with already-expired timestamp
    // Quick-buy order
    // Assert: order.unit_price_cents == catalog price
  });
});
```

**Section 132: Quick-Buy with Broadcast Price (4 tests)**:

```typescript
test.describe("Section 132: Quick-Buy with Broadcast Price", () => {
  test("132.1 — Quick-buy order total uses broadcast price", async ({ page }) => {
    // Set broadcast price to 3999, buy 1 item
    // Assert: total_cents == 3999 (not 4999)
  });

  test("132.2 — Order record includes was_broadcast_price: true", async ({ page }) => {
    // Purchase with broadcast price active
    // GET order details
    // Assert: was_broadcast_price == true, discount_pct > 0
  });

  test("132.3 — Order record includes original_price_cents for audit", async ({ page }) => {
    // Purchase with broadcast price
    // Assert: original_price_cents == 4999 (catalog)
  });

  test("132.4 — Quick-buy after session stops uses catalog price", async ({ page }) => {
    // Set broadcast price, stop session, attempt purchase
    // Purchase should use catalog price or fail (session not live)
  });
});
```

**Section 133: SSE Price Updates (3 tests)**:

```typescript
test.describe("Section 133: SSE Price Updates", () => {
  test("133.1 — Viewer receives shelf:price_update when price set", async ({ page }) => {
    // Subscribe to SSE, set broadcast price
    // Assert: received event with _type == "shelf:price_update"
    // Assert: event.is_broadcast_price == true
  });

  test("133.2 — Event includes pricing fields", async ({ page }) => {
    // Assert: event has effective_price_cents, discount_pct, broadcast_price_expires_at
  });

  test("133.3 — Viewer receives shelf:price_update when price cleared", async ({ page }) => {
    // Set price, subscribe SSE, clear price
    // Assert: event.is_broadcast_price == false
  });
});
```

**Section 134: Price Display UI — Viewer (5 tests)**:

```typescript
test.describe("Section 134: Price Display UI — Viewer", () => {
  test("134.1 — Shelf card shows strikethrough original + broadcast price", async ({ page }) => {
    // Navigate to broadcast viewer, set broadcast price
    // Assert: getByTestId("price-original") has line-through class
    // Assert: getByTestId("price-effective") shows $39.99
  });

  test("134.2 — LIVE DEAL badge is visible", async ({ page }) => {
    // Assert: getByTestId("price-badge") visible with text containing "LIVE DEAL"
  });

  test("134.3 — Countdown timer shows remaining time", async ({ page }) => {
    // Set price with 600s expiry
    // Assert: getByTestId("price-countdown") visible with "Ends in" text
  });

  test("134.4 — Price display reverts when countdown reaches zero", async ({ page }) => {
    // Set price with very short expiry
    // Wait for expiry
    // Assert: getByTestId("price-expired") shows "Deal ended"
    // After refetch: only effective price shown (no strikethrough)
  });

  test("134.5 — Quick-buy dialog shows broadcast price with discount", async ({ page }) => {
    // Open QuickBuyDialog
    // Assert: dialog contains BroadcastPrice with strikethrough + badge
  });
});
```

**Section 135: Price Editor UI — Broadcaster (4 tests)**:

```typescript
test.describe("Section 135: Price Editor UI — Broadcaster", () => {
  test("135.1 — Price editor toggle enables/disables", async ({ page }) => {
    // Navigate to broadcaster dashboard
    // Assert: Switch labeled "Enable broadcast price" exists
    // Toggle on: price input appears
    // Toggle off: calls clearBroadcastPrice
  });

  test("135.2 — Price input validates broadcast < catalog", async ({ page }) => {
    // Enter value >= catalog price
    // Assert: validation message appears, submit button disabled
  });

  test("135.3 — Expiry duration dropdown options", async ({ page }) => {
    // Open dropdown
    // Assert: "Entire broadcast", "5 minutes", "10 minutes", etc. all present
  });

  test("135.4 — Set Broadcast Price button updates shelf", async ({ page }) => {
    // Enter valid price, click "Set Broadcast Price"
    // Assert: toast "Broadcast price set!" appears
    // Shelf listing refetch shows new broadcast price
  });
});
```

**Test setup** (beforeAll):

```typescript
test.beforeAll(async ({ browser }) => {
  // 1. Create broadcast session (Alice as broadcaster)
  //    POST /broadcast/sessions
  //    body: { profile_id: profileId }

  // 2. Start session to transition to live
  //    POST /broadcast/sessions/{sessionId}/start

  // 3. Create catalog category + item
  //    POST /ui/catalog/categories body: { name: "E2E Pricing Cat" }
  //    POST /ui/catalog/categories/{catId}/items body: { name: "E2E Jacket", price_cents: 4999 }

  // 4. Add item to broadcast shelf (LCOM-001 endpoint)
  //    POST /broadcast/sessions/{sessionId}/products
  //    body: { item_id, category_id }

  // 5. Seed payment method for Bob (viewer) — for quick-buy tests
  //    DDB put_item: pk=USER#{bobSub}, sk=PM#{pmId}
  //    DDB put_item: pk=USER#{bobSub}, sk=BILLING with default_payment_method_id
});
```

### 5.3 Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Broadcast price set to $0.01 | Allowed — valid discount. Frontend shows extreme discount badge (-100%) |
| Broadcast price set while session is in draft | Stored but `is_broadcast_price=false` until session goes live |
| Multiple price changes during a broadcast | Each change publishes SSE event; latest price is authoritative |
| Price expiry during quick-buy dialog open | Client countdown shows "Deal ended"; purchase still goes through at catalog price (server validates) |
| Session stops while broadcast price is set | All queries return catalog price; broadcast price fields remain in DDB but are inactive |
| Broadcast price set, then product removed from shelf | Price data deleted with the shelf item (DELETE shelf item removes entire DDB row) |
| Viewer cached old price, submits quick-buy with stale effective_price | Server always resolves current effective price; order uses server-side price, not client-submitted |
| Two concurrent price updates | Last-writer-wins (DDB update_item is atomic). SSE delivers the latest state. |
| Broadcast price cleared then re-set within same second | `broadcast_price_set_at` might be the same timestamp; this is harmless (no ordering dependency on set_at) |
| DynamoDB returns Decimal for price fields | `int()` coercion in `resolve_effective_price` handles this (tested in unit tests) |
| Session transitions from live to stopping while price update in flight | `set_broadcast_price_route` checks status before calling service; if status changed to stopping between check and write, the price is stored but `is_live=False` so no SSE event is published. On next shelf listing, the status check returns catalog price. |

### 5.4 Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| Price expiry timing in tests | Use 600s expiry in "before expiry" tests (won't expire during test run); use negative expiry or manual DDB timestamp override for "after expiry" tests |
| SSE event race | Register listener BEFORE triggering price set (same pattern as messaging-features.spec.ts) |
| Countdown timer UI assertions | Assert `toBeVisible("Ends in")` text presence, not exact countdown value (value changes every second) |
| Quick-buy price race | Server always resolves price at purchase time; client price display is informational only |
| Shelf item state from previous test sections | Use unique sessions per section (e.g., `sess_130`, `sess_131`, etc.) or create fresh sessions in each section's `beforeAll` |
| Discount percentage rounding | Use known integer prices that produce clean percentages (e.g., 5000 -> 4000 = 20%, 5000 -> 2500 = 50%) instead of 4999 -> 3999 = 20.004% rounded to 20 |
| `strict mode violation` on price text | Use `data-testid` locators (`getByTestId("price-effective")`) instead of `getByText("$39.99")` which may match multiple elements (shelf card + dialog + chat link) |
| Test data accumulation | Unique timestamp in session IDs: `sess_130_${Date.now()}`. Each test section creates its own session. |

---

## 6. Security Considerations

### 6.1 Price Tampering Prevention

- **Server-side price resolution**: The quick-buy endpoint (LCOM-003) calls `resolve_effective_price()` using the DDB shelf item, not any client-submitted price. There is no `price` field in `BroadcastQuickBuyIn`. A malicious client sending a lower price in the request body is ignored — the field doesn't exist in the Pydantic model.
- **Broadcast price < catalog price enforcement**: The `set_broadcast_price` service function validates `broadcast_price_cents < catalog_price` using the stored DDB `price_cents`, not any client-submitted catalog price. A malicious broadcaster cannot set a "discount" by first inflating the catalog price — the catalog price is a snapshot frozen at shelf-add time.
- **Integer-only prices**: Both `broadcast_price_cents` and `price_cents` are integers (cents). No floating-point arithmetic in the payment path. The Pydantic `Field(gt=0, le=99999999)` constraint prevents negative prices, zero prices, and absurdly large prices.

### 6.2 Authorization Controls

- **Session creator only**: Only `session.created_by` can set or clear broadcast prices. This is enforced in both the PATCH and DELETE endpoint handlers by comparing `ctx["user_sub"]` (from the authenticated session) with `session.created_by` (from DDB). Non-creators get 403.
- **Admin/root cannot set prices**: Unlike chat moderation (where admins can delete messages), price setting is restricted to the session creator. This prevents an admin from accidentally discounting a broadcaster's products. If admin price override is needed later, it should be a separate audit-logged endpoint.
- **CSRF protection**: Both endpoints use `require_ui_session` (`Depends(_ctx)`) which enforces CSRF token validation for cookie-based auth. The frontend axios client automatically includes `x-csrf-token`.

### 6.3 Discount Abuse Prevention

- **No price increases via broadcast price**: The backend rejects `broadcast_price_cents >= price_cents`. A broadcaster cannot use the broadcast pricing system to RAISE prices above the catalog price.
- **Expiry limits**: `expires_in_seconds` is clamped to `[60, 86400]`. A broadcaster cannot set a 1-second flash sale (too short to be useful, could cause UX confusion) or a 30-day "broadcast exclusive" (defeats the purpose of time-limited pricing).
- **Price update rate limiting**: Although not implemented in Phase 1, a rate limit on price changes (e.g., max 10 changes per minute per session) should be added before production launch to prevent SSE flood from rapid price toggling. The pattern from `broadcast_chat_store.py` `_enforce_chat_rate_limit()` (line 23) can be reused.

### 6.4 Audit Trail

Every broadcast price change is recorded in the shelf item itself:
- `broadcast_price_set_by`: Who set the price (user sub).
- `broadcast_price_set_at`: When it was set (Unix timestamp).
- Quick-buy orders include `was_broadcast_price`, `original_price_cents`, `discount_pct` for post-hoc audit of discount usage.

For production, consider writing price change events to `broadcast_action_audit` (via `record_broadcast_action()` from `app/services/broadcast_audit.py`) with action type `"price_set"` or `"price_clear"`. This provides a full timeline of all price changes for a session.

### 6.5 Price Consistency During Concurrent Access

**Scenario**: Two browser tabs both set broadcast prices simultaneously.

**Resolution**: DynamoDB `update_item` is atomic at the item level. The last write wins. Both writes succeed, but the second one overwrites the first. The SSE event from the second write is published after the first, so viewers converge on the latest price. There is no transaction needed because there is no invariant that requires reading and writing multiple items atomically.

**Scenario**: Broadcaster sets price while viewer is mid-purchase.

**Resolution**: The quick-buy endpoint reads the shelf item and resolves the price in a single handler invocation. If the broadcaster's `update_item` completes between the viewer's `get_item` and their purchase write, the viewer gets the price that was active at the time of their `get_item` read. This is acceptable — DDB is eventually consistent, and the price change propagates on the next read. The viewer pays the price that was active when their purchase started.

### 6.6 Input Sanitization

- `broadcast_price_cents` is an `int` in Pydantic — no string injection possible.
- `expires_in_seconds` is an `Optional[int]` — no string injection.
- `item_id` and `session_id` are path parameters used in DDB key construction (`f"ITEM#{item_id}"`). Since DDB keys are strings and DDB does not support query injection, there is no injection risk. However, the `#` character in the key prefix provides natural namespacing.

---

## 7. Migration & Rollback Plan

### 7.1 Schema Migration

**No new tables required**. LCOM-004 adds four optional attributes to existing `BroadcastProductShelf` items. DynamoDB is schemaless — no `ALTER TABLE` or migration script needed. Old items without the new fields are handled gracefully by `resolve_effective_price()` (missing `broadcast_price_cents` = no discount).

**Backward compatibility**: The `_shelf_item_out` function (LCOM-001) returns a dict. LCOM-004 wraps it in `_shelf_item_out_with_pricing()` which adds the new fields. Old API clients that don't expect the new fields will simply ignore them (standard JSON forward-compatibility). The original `price_cents` field is unchanged.

### 7.2 Feature Flag Rollout Phases

1. **Phase 0** (Day 0): Deploy backend with `resolve_effective_price()` and extended `_shelf_item_out_with_pricing()`. The shelf listing now always returns pricing fields, but `is_broadcast_price` is `false` for all items (no one has set a broadcast price yet). Zero risk.
2. **Phase 1** (Day 1): Deploy PATCH and DELETE endpoints behind feature flag `BROADCAST_EXCLUSIVE_PRICING_ENABLED`. Default `false`.
3. **Phase 2** (Day 2): Deploy frontend `BroadcastPrice` and `BroadcastPriceEditor` components. The editor is hidden when the feature flag is disabled (backend returns 404 for the pricing endpoint).
4. **Phase 3** (Day 3): Enable flag for 10% of broadcasters (A/B test). Monitor SSE fan-out volume, DDB write patterns, conversion rate delta.
5. **Phase 4** (Day 7): Enable for all broadcasters. Monitor for 48 hours.
6. **Phase 5** (Day 14): Remove feature flag. Pricing is always available.

### 7.3 Rollback Steps

**If pricing display issues discovered**:
1. Set `BROADCAST_EXCLUSIVE_PRICING_ENABLED=false`.
2. Backend returns 404 for pricing endpoints.
3. Frontend hides `BroadcastPriceEditor`.
4. Existing broadcast prices remain in DDB but are never returned as `is_broadcast_price=true` (because the feature flag disables resolution).
5. Shelf listing returns `is_broadcast_price=false` for all items.

**If quick-buy pricing bugs discovered**:
1. Rollback `broadcast_orders.py` to pre-LCOM-004 version (remove `resolve_effective_price` call).
2. Quick-buy uses `shelf_item.price_cents` (catalog price) for all orders.
3. No data migration needed — orders already created with broadcast prices are valid historical records.

**Full frontend rollback**:
1. Revert frontend build to pre-LCOM-004.
2. `BroadcastPrice` component removed; `ProductShelfCard` shows `price_cents` directly.
3. `BroadcastPriceEditor` removed from `ProductShelfManager`.
4. Backend pricing fields in shelf listing are ignored by the old frontend.

### 7.4 Zero-Downtime Deployment

- No new DDB tables to create.
- No schema migrations.
- New endpoints are additive (PATCH + DELETE on new paths).
- Existing endpoints extended with additional response fields (backward-compatible).
- Frontend changes bundled in Vite build — single atomic deploy.
- SSE event handler additions are additive (unknown event types are ignored by old clients).

---

## 8. Operational Runbook

### 8.1 Key Metrics

| Metric | Description | Source |
|--------|-------------|--------|
| `broadcast.pricing.set_count` | Counter of broadcast prices set | Endpoint |
| `broadcast.pricing.clear_count` | Counter of broadcast prices cleared | Endpoint |
| `broadcast.pricing.set_latency_ms` | P50/P95/P99 for set-price endpoint | Middleware |
| `broadcast.pricing.discount_applied_count` | Orders where `was_broadcast_price=true` | Order creation |
| `broadcast.pricing.discount_revenue_cents` | Sum of `discount_pct * original_price_cents / 100` for broadcast-priced orders | Computed |
| `broadcast.pricing.expired_count` | Prices that expired during broadcast (countdown reached 0) | Frontend event |
| `broadcast.pricing.sse_events_published` | Counter of `shelf:price_update` SSE events | Service |
| `broadcast.pricing.conversion_rate_with_discount` | Orders / shelf views when broadcast price active | Computed |
| `broadcast.pricing.conversion_rate_without_discount` | Orders / shelf views when no broadcast price | Computed (baseline) |

### 8.2 Alerting Thresholds

| Alert | Threshold | Action |
|-------|-----------|--------|
| Set-price P99 > 500ms | 5 consecutive minutes | Check DDB throttling on BroadcastProductShelf |
| SSE fan-out failure rate > 1% | 5 minutes | Check subscriber count, queue sizes |
| Discount applied to >50% of orders | Informational | Verify discount amounts are reasonable |
| Set-price 400 error rate > 30% | 5 minutes | Broadcasters may be confused by UI; check validation messages |
| Price change rate > 20/min/session | Informational | Consider adding rate limiting |

### 8.3 Common Debugging

**Problem: Broadcast price not showing in viewer UI**
1. Verify broadcast price is set: `GET /broadcast/sessions/{id}/products` — check `is_broadcast_price` field.
2. If `is_broadcast_price=false` but `broadcast_price_cents` is set:
   - Check session status: must be `"live"`.
   - Check `broadcast_price_expires_at`: may have expired.
3. If SSE event not received:
   - Verify SSE connection is established (check browser DevTools Network tab for EventSource).
   - Check `broadcast_sse_subscriber_count(session_id)` — should be > 0.
   - Check subscriber queue sizes for `QueueFull` drops.

**Problem: Quick-buy charging catalog price instead of broadcast price**
1. Verify broadcast price is active at time of purchase (check logs for `resolve_effective_price` output).
2. Check if price expired between dialog open and purchase submit.
3. Check if session status changed from `live` to `stopping` during purchase.
4. Check order record: `was_broadcast_price` field tells you what the server resolved.

**Problem: "Deal ended" showing when deal should be active**
1. Check client clock vs server clock — client countdown uses `Date.now()` which may differ from server `now_ts()`.
2. NTP sync issue: if client clock is ahead of server by > expiry duration, the deal appears expired locally while still active server-side.
3. Frontend workaround: fetch server time from a lightweight endpoint and use server-relative countdown.

**Problem: Broadcast price set but `discount_pct` is wrong**
1. Check `price_cents` and `broadcast_price_cents` in DDB.
2. Verify formula: `round((1 - broadcast / original) * 100)`.
3. DynamoDB stores numbers as `Decimal`; ensure `int()` coercion happens before division.

### 8.4 Log Patterns

```
# Successful price set
INFO broadcast.pricing.set session_id=sess_abc item_id=item_xyz price=3999 set_by=user_123 expires_in=600

# Successful price clear
INFO broadcast.pricing.clear session_id=sess_abc item_id=item_xyz

# Price set rejected (above catalog)
WARN broadcast.pricing.set_rejected session_id=sess_abc item_id=item_xyz attempted=9999 catalog=4999 reason=above_catalog

# SSE publish for price update
DEBUG broadcast.sse session_id=sess_abc event_type=shelf:price_update subscriber_count=142

# Quick-buy with broadcast price
INFO broadcast.quickbuy session_id=sess_abc order_id=bord_xyz was_broadcast_price=true effective=3999 original=4999 discount_pct=20
```

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput

For a popular broadcast with 10,000 concurrent viewers:

| Operation | Rate | DDB Impact |
|-----------|------|------------|
| Set/clear broadcast price | 1-5 per broadcast (low frequency) | 1 WCU per set (< 1KB item update) |
| Shelf listing with pricing | 10,000 on initial load + 1/30s per viewer (refetch) | ~333 RCU/min (eventually consistent reads) |
| SSE price_update fan-out | 1 event per price change x 10,000 subscribers | In-memory only (no DDB) |
| Quick-buy with price resolution | 50/min (peak burst) | 1 RCU per shelf item read |

Price setting is a broadcaster-only operation and happens at most a few times per broadcast. The DDB impact is negligible.

### 9.2 Latency Budget for Price Set (< 200ms target)

| Step | Target | Measured (DDB local) |
|------|--------|---------------------|
| Session lookup (`get_session`) | < 20ms | ~10ms |
| Auth check (`ctx["user_sub"] == created_by`) | < 1ms | ~0.01ms |
| Shelf item lookup (`get_item`) | < 20ms | ~10ms |
| Price validation (< catalog) | < 1ms | ~0.01ms |
| DDB update_item (4 fields) | < 20ms | ~10ms |
| Re-read updated item | < 20ms | ~10ms |
| `resolve_effective_price()` | < 1ms | ~0.05ms |
| SSE publish (if live) | < 5ms | ~1ms |
| **Total** | **< 90ms** | **~41ms** |

Client-side latency includes network round-trip (~50-200ms), giving total perceived latency of 100-300ms.

### 9.3 Latency Budget for Shelf Listing with Pricing

The shelf listing now calls `resolve_effective_price()` for each item. For a shelf with 20 items (typical max):

| Step | Target | Measured |
|------|--------|---------|
| DDB query (all shelf items) | < 30ms | ~15ms |
| Session status lookup | < 20ms | ~10ms (cached in-request) |
| 20x `resolve_effective_price()` | < 1ms total | ~0.5ms |
| Response serialization | < 5ms | ~2ms |
| **Total** | **< 60ms** | **~28ms** |

The `resolve_effective_price()` function is pure computation (no I/O) — it reads from the already-fetched shelf item dict. The overhead per item is ~25 microseconds.

### 9.4 Hot Partition Analysis

- **BroadcastProductShelf table**: Partitioned by `session_id`. A single broadcast session's shelf items share one partition. With max ~50 items per shelf and ~5 price updates per broadcast, write throughput is < 0.1 WCU average. No hot partition risk.
- **Shelf listing reads**: 10,000 concurrent viewers all read the same `session_id` partition. At 1 read per 30 seconds per viewer, this is ~333 eventually-consistent RCU/min on one partition. DDB partitions can sustain 3,000 RCU, so this is well within limits.
- **SSE fan-out**: No DDB involved. In-memory queue push is O(1) per subscriber. For 10,000 subscribers, total time is ~10ms.

### 9.5 Client-Side Countdown Timer Performance

Each `BroadcastPrice` component with an active countdown runs a `setInterval(tick, 1000)`. For a shelf with 20 items, all with countdown timers, this creates 20 intervals. Each tick does:
- One subtraction: `expiresAt - Math.floor(Date.now() / 1000)`
- One string format: `` `${mins}:${String(secs).padStart(2, "0")}` ``
- One `useState` update: `setCountdown(str)`

Total CPU per tick: < 0.1ms. With 20 items, total: < 2ms/second. Negligible.

**Memory**: Each interval closure holds a reference to `expiresAt` (number) and `onExpired` (callback). Total memory per timer: < 1KB. For 20 items: < 20KB. Negligible.

**Cleanup**: `useEffect` returns `clearInterval` — timers are cleaned up when the component unmounts (e.g., shelf panel closed or broadcast ends).

---

## 10. Dependency Analysis

### 10.1 LCOM Ticket Chain

```
LCOM-001 (Shelf)
    │
    ├── LCOM-002 (Chat Links)
    │       └── Uses shelf data for product link cards
    │           └── LCOM-004 adds pricing fields to link snapshot
    │
    ├── LCOM-003 (Quick-Buy)
    │       └── Reads shelf price for order total
    │           └── LCOM-004 changes price resolution to prefer broadcast price
    │
    └── LCOM-004 (Exclusive Pricing)  ← THIS TICKET
            └── Adds broadcast_price_cents to shelf items
            └── Modifies shelf listing to include resolved pricing
            └── Adds set/clear price endpoints
            └── Modifies quick-buy to use resolved price
            └── Modifies chat product links to include pricing
```

**LCOM-004 depends on**:
- **LCOM-001**: Without the shelf, there are no items to set prices on. The `BroadcastProductShelf` table, `_shelf_item_out()`, and `list_shelf_products()` must exist.
- **LCOM-003**: Without quick-buy, broadcast pricing has no purchase path. The `create_quick_buy_order()` function must exist to be modified.

**LCOM-004 modifies**:
- **LCOM-001**: Extends `_shelf_item_out` → `_shelf_item_out_with_pricing`, adds pricing fields to shelf listing response.
- **LCOM-002**: Extends product link data to include broadcast pricing snapshot.
- **LCOM-003**: Changes `unit_price` resolution from `shelf_item.price_cents` to `resolve_effective_price()`.

### 10.2 Integration with Existing Systems

| System | Integration | Direction | Coupling |
|--------|------------|-----------|----------|
| Broadcast SSE (`broadcast_sse.py`) | Publishes `shelf:price_update` events | Write | Loose (fire-and-forget) |
| Broadcast Store (`broadcast_store.py`) | Reads session status for price resolution | Read | Loose (single `get_session` call) |
| Broadcast Chat Store (`broadcast_chat_store.py`) | Includes pricing in product link messages | Read | Loose (data passed at link creation) |
| Catalog (`catalog.py`) | Original `price_cents` copied to shelf at add-time | Read (at add-time) | Decoupled (snapshot) |
| Billing (`billing_shared.py`) | PM validation + ledger writes at quick-buy | Read/Write (at purchase) | Via LCOM-003 |
| Product Shelf (LCOM-001) | Core data model extended with pricing fields | Read/Write | Tight (same DDB table) |

### 10.3 Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Price resolution bug charges wrong amount | Low | High | Server-side resolution is single source of truth; comprehensive unit tests |
| SSE flood from rapid price changes | Medium | Medium | Rate-limit price changes; dead queue cleanup |
| Client countdown drift from server time | Medium | Low | Server re-validates at purchase time; countdown is informational |
| Stale broadcast price in chat product link | Medium | Low | Link is a snapshot; "Buy" button always fetches current price |

---

## 11. Acceptance Criteria

### 11.1 Functional

1. Broadcaster can set a broadcast-exclusive price on any shelf product that is strictly less than the catalog price.
2. Broadcaster can optionally set an expiry duration (1 minute to 24 hours) for the broadcast price.
3. Broadcaster can clear a broadcast price at any time, reverting to catalog price.
4. Shelf listing returns `effective_price_cents`, `is_broadcast_price`, `discount_pct` for each item.
5. Broadcast price is only active when the session status is `"live"`.
6. Broadcast price reverts to catalog price when the session stops (no manual cleanup needed).
7. Broadcast price reverts to catalog price when the expiry timestamp passes.
8. Quick-buy orders use the effective (broadcast) price when active, catalog price otherwise.
9. Quick-buy order records include `was_broadcast_price`, `original_price_cents`, and `discount_pct` for audit.
10. Viewers see `shelf:price_update` SSE events in real time when broadcaster changes prices during a live session.
11. Viewer UI shows struck-through original price, highlighted broadcast price, "LIVE DEAL" badge, and optional countdown timer.
12. Broadcaster UI shows a price editor with toggle, price input, expiry dropdown, and savings preview.
13. Chat product links include broadcast pricing snapshot at the time the link was shared.
14. Non-broadcasters receive 403 when attempting to set/clear broadcast prices.

### 11.2 Non-Functional

1. Set-price endpoint responds in < 200ms P95.
2. Shelf listing with pricing resolves in < 100ms P95 (20 items).
3. SSE price update event delivered within 100ms of price change.
4. No DDB throttling during price set/clear operations.
5. Client-side countdown timer accuracy within 1 second of server time.
6. All 28 E2E tests pass with 0 flakes on 3 consecutive runs.
7. Unit test coverage for `resolve_effective_price()` includes all 8 rows of the truth table.

---

## 12. Error Handling Matrix

| Error | HTTP Status | Error Code | User Message | Recovery Action |
|-------|-------------|-----------|--------------|----------------|
| Session not found | 404 | (default) | "Broadcast session not found." | Check session ID |
| Product not on shelf | 404 | (default) | "Product not on shelf." | Refresh shelf listing |
| Broadcast price >= catalog price | 400 | (default) | "Broadcast price ({N}) must be less than catalog price ({M})." | Enter a lower price |
| Broadcast price <= 0 | 422 | VALIDATION_ERROR | "broadcast_price_cents must be greater than 0" | Enter a positive price |
| expires_in_seconds < 60 | 422 | VALIDATION_ERROR | "expires_in_seconds must be >= 60" | Use a longer expiry |
| expires_in_seconds > 86400 | 422 | VALIDATION_ERROR | "expires_in_seconds must be <= 86400" | Use a shorter expiry |
| Caller is not session creator | 403 | (default) | "Only the broadcaster can set broadcast prices." | Use broadcaster account |
| Session in terminal state | 409 | (default) | "Cannot set price on a session in terminal state." | Session is over; no action |
| DDB write failure | 500 | INTERNAL_ERROR | "Failed to update price. Please try again." | Retry |
| SSE publish failure | (silent) | (none) | (none) | Self-healing: viewers refetch shelf every 30s |
| CSRF token mismatch | 403 | CSRF_INVALID | "Invalid CSRF token." | Refresh page |
| Unauthorized (no session) | 401 | (default) | "Authentication required." | Log in |

### Concurrency/Race Condition Handling

```
         Broadcaster Tab 1                Backend                   Broadcaster Tab 2
              │                              │                           │
              │ PATCH: set price=3999        │ PATCH: set price=2999     │
              │─────────────────────────────>│<───────────────────────────│
              │                              │                           │
              │                    DDB update_item                       │
              │                    (last-writer-wins)                    │
              │                              │                           │
              │                    If Tab 2 arrives last:               │
              │                    broadcast_price_cents = 2999         │
              │                              │                           │
              │                    SSE: shelf:price_update              │
              │                    { broadcast_price_cents: 2999 }       │
              │                              │                           │
              │    200 { price: 3999 }       │  200 { price: 2999 }     │
              │<─────────────────────────────│───────────────────────────>│
              │                              │                           │
              │  Note: Tab 1 sees its OWN    │                           │
              │  price in the response,      │                           │
              │  but the SSE event shows     │                           │
              │  the final (Tab 2) price.    │                           │
              │  After shelf refetch, both   │                           │
              │  tabs converge on 2999.      │                           │
```

**Why this is acceptable**: Broadcast pricing is a single-broadcaster operation. The race condition above requires the same broadcaster to have two tabs open and set prices simultaneously, which is an edge case. The final state is deterministic (last writer wins) and both tabs converge after the next shelf refetch (30s max, or sooner via SSE).

---

## 13. Analytics & Attribution

### 13.1 Discount Attribution

Every quick-buy order includes:
- `was_broadcast_price: bool` — whether the broadcast price was applied.
- `original_price_cents: int` — the catalog price (what the viewer would have paid without the discount).
- `discount_pct: int` — the discount percentage.
- `unit_price_cents: int` — the actual price charged.

This enables computing:
- **Discount revenue impact**: `sum(original_price - effective_price)` for all broadcast-priced orders.
- **Conversion lift**: Compare conversion rate for discounted vs. non-discounted products within the same broadcast.
- **Average discount depth**: `avg(discount_pct)` across all broadcast-priced orders.
- **Revenue per viewer with discount**: `sum(effective_price) / unique_viewers` when discount is active.
- **Revenue per viewer without discount**: Same metric for periods when no discount is active (same broadcast).

### 13.2 Broadcaster Discount Effectiveness Report

```
Broadcast: "Winter Collection Launch" (2 hours)
─────────────────────────────────────────────────────

Product              │ Catalog │ BC Price │ Discount │ Orders (BC) │ Orders (No BC) │ Lift
─────────────────────┼─────────┼──────────┼──────────┼─────────────┼────────────────┼──────
Winter Jacket        │ $49.99  │ $39.99   │ -20%     │ 45          │ 12             │ +275%
Wool Scarf           │ $19.99  │ $14.99   │ -25%     │ 82          │ 28             │ +193%
Leather Gloves       │ $34.99  │ —        │ —        │ —           │ 15             │ baseline

Totals:
  Revenue from broadcast-priced orders: $3,027.63
  Revenue from catalog-priced orders:   $2,594.73
  Discount given (total):               $782.20
  Net revenue lift:                     +16.7%
```

### 13.3 Conversion Funnel Tracking

```
Broadcast Started (session_id)
    │
    ▼
Shelf Viewed (viewer opens shelf panel)
    │
    ├─── No Broadcast Price ───────────────────┐
    │                                           │
    ▼                                           ▼
Product Viewed (sees catalog price)    Product Viewed (sees LIVE DEAL badge)
    │                                           │
    ▼                                           ▼
Quick Buy Clicked                      Quick Buy Clicked (urgency-driven)
    │                                           │
    ▼                                           ▼
Purchase Completed (catalog price)     Purchase Completed (broadcast price)
```

Track each funnel step as an analytics event with `session_id`, `item_id`, `has_broadcast_price`, and `timestamp`. This enables:
- Funnel drop-off analysis at each step.
- A/B comparison of conversion rate with vs. without broadcast pricing.
- Heatmap of discount effectiveness by time-in-broadcast (early vs. late flash deals).

### 13.4 A/B Test Hooks

- **Discount visibility**: Show the "LIVE DEAL" badge to 50% of viewers, hide it for the other 50%. Measure conversion difference to quantify badge impact.
- **Countdown timer presence**: Show countdown for 50%, hide for 50%. Measure whether countdown urgency increases conversion.
- **Discount depth**: Test 10%, 20%, 30% discounts on the same product across different broadcasts. Find the optimal discount depth for conversion lift vs. margin.
- **Flash deal timing**: Test flash deals at broadcast start vs. mid-broadcast vs. end. Measure which timing maximizes total revenue.

### 13.5 Pricing Analytics Dashboard Wireframe

```
┌─────────────────────────────────────────────────────────────────────┐
│  Broadcast Pricing Analytics                                         │
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │ Broadcast Deals  │  │ Avg Discount    │  │ Conversion Lift │     │
│  │      47          │  │    -22%         │  │    +187%        │     │
│  │  set this month  │  │  depth          │  │  vs no deal     │     │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘     │
│                                                                      │
│  Revenue Impact (Last 30 Days)                                       │
│  ┌───────────────────────────────────────────────────────────┐      │
│  │  ██████████████████████████████  $12,450 (with deals)     │      │
│  │  ████████████                    $ 5,200 (without deals)  │      │
│  └───────────────────────────────────────────────────────────┘      │
│                                                                      │
│  Discount Depth vs Conversion                                        │
│  ┌───────────────────────────────────────────────────────────┐      │
│  │     *                                                      │      │
│  │            *                                               │      │
│  │                     *                                      │      │
│  │                              *                             │      │
│  │  ─────────────────────────────────────                    │      │
│  │  10%      20%      30%      40%     50%                   │      │
│  └───────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Appendix A: API Reference Summary

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| PATCH | `/broadcast/sessions/{id}/products/{item_id}/price` | Session creator | Set broadcast-exclusive price |
| DELETE | `/broadcast/sessions/{id}/products/{item_id}/price` | Session creator | Clear broadcast price |
| GET | `/broadcast/sessions/{id}/products` | Any authenticated | List shelf (now includes pricing) |

## Appendix B: Price Resolution Truth Table

| Session Status | broadcast_price_cents | expires_at | now < expires_at | Effective Price | is_broadcast_price |
|---------------|----------------------|------------|------------------|-----------------|-------------------|
| `live` | set (> 0) | null | N/A | broadcast_price_cents | true |
| `live` | set (> 0) | set | yes | broadcast_price_cents | true |
| `live` | set (> 0) | set | no | price_cents (catalog) | false |
| `live` | null | N/A | N/A | price_cents (catalog) | false |
| `live` | 0 | N/A | N/A | price_cents (catalog) | false |
| `draft` | set | any | any | price_cents (catalog) | false |
| `ready` | set | any | any | price_cents (catalog) | false |
| `stopped` | set | any | any | price_cents (catalog) | false |
| `stopping` | set | any | any | price_cents (catalog) | false |
| `error` | set | any | any | price_cents (catalog) | false |
| any | 0 | any | any | price_cents (catalog) | false |

## Appendix C: SSE Event Schema

```json
{
    "_type": "shelf:price_update",
    "session_id": "string",
    "item_id": "string",
    "name": "string",
    "price_cents": 4999,
    "broadcast_price_cents": 3999,
    "broadcast_price_expires_at": 1716580600,
    "effective_price_cents": 3999,
    "is_broadcast_price": true,
    "discount_pct": 20,
    "original_price_cents": 4999,
    "currency": "USD",
    "image_url": "/mock/s3/...",
    "display_order": 1
}
```

## Appendix D: Broadcast Price Lifecycle Diagram

```
                         ┌──────────────┐
                         │ No broadcast │
                         │ price set    │
                         └──────┬───────┘
                                │
                    Broadcaster PATCH /price
                    { broadcast_price_cents: 3999 }
                                │
                         ┌──────▼───────┐
                         │ Broadcast    │
                         │ price stored │
                    ┌────│ in DDB       │────┐
                    │    └──────────────┘    │
                    │                        │
          Session   │                        │  Session
          is "live" │                        │  not "live"
                    │                        │
           ┌────────▼────────┐    ┌─────────▼─────────┐
           │ ACTIVE          │    │ STORED BUT         │
           │ is_broadcast_   │    │ INACTIVE           │
           │ price = true    │    │ is_broadcast_      │
           │ effective =     │    │ price = false      │
           │ broadcast_price │    │ effective =        │
           │                 │    │ catalog_price      │
           └────┬───────┬───┘    └─────────┬──────────┘
                │       │                   │
   Expiry      │       │ Broadcaster       │ Session
   reached     │       │ DELETE /price     │ goes "live"
                │       │                   │
    ┌───────────▼──┐    │           ┌──────▼──────┐
    │ EXPIRED      │    │           │ ACTIVE      │
    │ is_broadcast_│    │           │ (see left)  │
    │ price = false│    │           └─────────────┘
    │ fields still │    │
    │ in DDB       │    │
    └──────────────┘    │
                        │
                 ┌──────▼───────┐
                 │ CLEARED      │
                 │ fields       │
                 │ REMOVEd      │
                 │ from DDB     │
                 └──────────────┘
```

## Appendix E: Related Tickets

- **LCOM-001**: Broadcast product shelf (prerequisite — prices are set on shelf items)
- **LCOM-002**: Chat product links (product link cards show broadcast pricing)
- **LCOM-003**: Broadcast quick-buy (checkout uses resolved effective price)

## Appendix F: Glossary

| Term | Definition |
|------|-----------|
| Broadcast price | A temporary, lower-than-catalog price set by the broadcaster for a specific shelf item during a broadcast session |
| Catalog price | The standard price of a product, stored as `price_cents` on the shelf item (snapshotted from the catalog at shelf-add time) |
| Effective price | The price that a viewer will pay right now — either the broadcast price (if active) or the catalog price |
| Price resolution | The process of determining the effective price based on broadcast price availability, session status, and expiry |
| Flash deal | A broadcast price with a short expiry duration (typically 5-15 minutes) |
| Session-wide discount | A broadcast price with no expiry — active for the entire broadcast duration |
| Price reversion | The automatic return to catalog price when a broadcast price expires or the session ends |

---

## Codebase References

All file paths are relative to the repository root.

### Backend — Already Implemented
- `app/services/broadcast_product_shelf.py` (441 lines) — Core pricing service
  - `_shelf_item_out()` at line 23
  - `get_shelf_product_raw()` at line 158
  - `list_shelf_products()` at line 178
  - `resolve_effective_price()` at line 211 — single source of truth for price resolution
  - `_shelf_item_out_with_pricing()` at line 264
  - `list_shelf_products_with_pricing()` at line 296
  - `set_broadcast_price()` at line 315
  - `clear_broadcast_price()` at line 399
- `app/routers/broadcast.py` (~3969 lines) — Router with pricing endpoints
  - Router prefix `/broadcast` at line 76
  - `BroadcastPriceSetIn` / `BroadcastPriceOut` imported from `app/models` at line 73
  - `BroadcastShelfItemOut` pricing fields at lines 1829-1835
  - `BroadcastShelfListOut` at line 1838
  - `list_shelf_products_route()` at line 1928 (calls `list_shelf_products_with_pricing`)
  - `send_chat_product_link_route()` at line 1446 (includes pricing snapshot at lines 1494-1498)
  - `set_broadcast_price_route()` (PATCH) at line 1975
  - `clear_broadcast_price_route()` (DELETE) at line 2022
- `app/models.py` — Pydantic models
  - `BroadcastPriceSetIn` at line 2426
  - `BroadcastPriceOut` at line 2440
- `app/services/broadcast_sse.py` (49 lines) — SSE pub/sub infrastructure
  - `_BROADCAST_SUBSCRIBERS` dict at line 8
  - `broadcast_sse_subscribe()` at line 11
  - `broadcast_sse_unsubscribe()` at line 19
  - `broadcast_sse_publish()` at line 29 — used by set/clear pricing for `shelf:price_update` events
  - Dead queue cleanup at lines 38-43
- `app/services/broadcast_chat_store.py` (423 lines) — Chat store with rate limiting patterns
  - `_CHAT_RATE_LOCK` at line 20
  - `_CHAT_RATE_BUCKETS` at line 21
  - `_enforce_chat_rate_limit()` at line 25
  - `_enforce_product_link_rate_limit()` at line 46
  - `send_product_link_message()` at line 219
  - `_chat_msg_out()` at line 344 (passes through `product_link` at line 366)
- `app/services/billing_shared.py` (~260 lines) — Billing helpers
  - `user_pk()` at line 16
  - `ddb_get()` at line 20
  - `ensure_balance_row()` at line 62
- `scripts/local-ddb-init.py` — DynamoDB table definitions
  - `BroadcastProductShelf` table definition at line 578

### Backend — Does Not Exist Yet
- `app/services/broadcast_orders.py` — Quick-buy order service (LCOM-003 prerequisite)

### Frontend — Exists
- `frontend/src/api/endpoints/broadcast-shelf.ts` (44 lines) — Shelf API (needs pricing field extension)
  - `ShelfItem` interface at line 5 (missing pricing fields)
  - `addShelfProduct()` at line 33, `removeShelfProduct()` at line 36, `getShelfProducts()` at line 39, `reorderShelf()` at line 42
  - Missing: `setBroadcastPrice()`, `clearBroadcastPrice()`, `BroadcastPriceResponse` type
- `frontend/src/pages/broadcast/LivePlayer.tsx` — Live player (exists, needs SSE handler for `shelf:price_update`)
- `frontend/src/pages/broadcast/ProductShelfManager.tsx` — Broadcaster shelf manager (exists, needs `BroadcastPriceEditor` integration)

### Frontend — Does Not Exist Yet
- `frontend/src/pages/broadcast/BroadcastPrice.tsx` — Price display component with strikethrough, badge, countdown
- `frontend/src/pages/broadcast/BroadcastPriceEditor.tsx` — Broadcaster price editor with toggle, validation, mutations
- `frontend/src/pages/broadcast/ProductShelfCard.tsx` — Viewer shelf card (LCOM-001 frontend)
- `frontend/src/pages/broadcast/ProductLinkCard.tsx` — Chat product link card (LCOM-002 frontend)
- `frontend/src/pages/broadcast/QuickBuyDialog.tsx` — Quick-buy dialog (LCOM-003 frontend)

---

## Testing Strategy

### Unit Tests (`tests/test_broadcast_exclusive_pricing.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_set_broadcast_price` | Set broadcast price |
| 2 | `test_clear_broadcast_price` | Clear broadcast price |
| 3 | `test_resolve_effective_price_uses_broadcast` | Resolve effective price uses broadcast |
| 4 | `test_resolve_effective_price_fallback_catalog` | Resolve effective price fallback catalog |
| 5 | `test_price_expiry_after_session_end` | Price expiry after session end |
| 6 | `test_flash_deal_timer` | Flash deal timer |
| 7 | `test_viewer_sees_both_prices` | Viewer sees both prices |
| 8 | `test_set_price_requires_session_creator` | Set price requires session creator |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/broadcast-exclusive-pricing.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~18 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `BROADCAST_EXCLUSIVE_PRICING_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What It Provides | Hard/Soft |
|--------|-----------------|-----------|
| LCOM-001 | Broadcast Product Shelf for shelf item storage | Hard |
| LCOM-003 | Broadcast Quick-Buy for price resolution | Hard |

### Depended On By

No downstream dependents identified.

### Merge Strategy
**Sequential -- requires LCOM-001 and LCOM-003 merged first. Extends shelf items with broadcast_price_cents field and modifies quick-buy price resolution.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: BROADCAST_EXCLUSIVE_PRICING_ENABLED=true
- [ ] Service file created/modified: `app/services/broadcast_product_shelf.py (extended)`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/broadcast-exclusive-pricing.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_broadcast_exclusive_pricing.py`
