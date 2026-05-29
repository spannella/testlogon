# LCOM-003: Broadcast Quick-Buy Checkout — One-Click Purchase from Live Streams

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: High  
**Estimated effort**: 5-7 days  
**Depends on**: LCOM-001 (Broadcast Product Shelf)

---

## 1. Overview & Motivation

### The Gap

LCOM-001 introduces a product shelf visible to broadcast viewers, and LCOM-002 adds product cards in live chat. However, **neither provides a purchase path**. The "Add to Cart" button routes viewers into the standard shop checkout flow at `/shop/cart` and `/shop/checkout`, which requires navigating away from the broadcast. This context switch causes high abandonment — industry data shows 60-80% of live commerce viewers who navigate away from the stream do not return.

The existing checkout flow (`frontend/src/pages/shop/Checkout.tsx`) is designed for deliberate shopping sessions with multi-step cart review, shipping address selection, and payment confirmation. This is appropriate for the shop but too heavyweight for impulse purchases during a live stream where the broadcaster is actively demonstrating the product.

### Why This Is Needed

1. **Frictionless purchase flow**: Live commerce thrives on impulse decisions. Every additional click between "I want this" and "I bought this" reduces conversion. A single-dialog, one-click buy within the broadcast player eliminates navigation entirely.
2. **Broadcast attribution**: Purchases made through the quick-buy flow are explicitly attributed to a broadcast session, enabling analytics on which streams drive revenue. The existing checkout flow has no concept of broadcast session attribution.
3. **Real-time social proof**: When a viewer makes a quick-buy purchase, a counter visible to the broadcaster shows purchase velocity. This creates excitement and urgency for other viewers.
4. **Viewer retention**: The viewer never leaves the broadcast player. The purchase dialog overlays the player, and after confirmation, the viewer returns immediately to watching.

### Architecture After This Change

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Viewer Player (LivePlayer.tsx)                                         │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ ProductShelf / ProductLinkCard                                     │ │
│  │                                                                    │ │
│  │  "Quick Buy" button ─────────────────┐                            │ │
│  └────────────────────────────────────────┼────────────────────────────┘ │
│                                           │                              │
│  ┌────────────────────────────────────────▼────────────────────────────┐ │
│  │  QuickBuyDialog (overlay on player)                                 │ │
│  │  ┌──────────────────────────────────────────────────────────────┐  │ │
│  │  │  Product: "Winter Jacket"                 $49.99             │  │ │
│  │  │  ┌─────────────────┐                                        │  │ │
│  │  │  │ [product image] │  Payment method:                       │  │ │
│  │  │  │                 │  ┌─────────────────────────────┐       │  │ │
│  │  │  │                 │  │ Visa ****4242 (default)  v  │       │  │ │
│  │  │  └─────────────────┘  └─────────────────────────────┘       │  │ │
│  │  │                                                              │  │ │
│  │  │  Quantity: [ 1 ] [-] [+]                                     │  │ │
│  │  │                                                              │  │ │
│  │  │  ┌─────────────────────────────────────────────────────┐    │  │ │
│  │  │  │           Buy Now — $49.99                           │    │  │ │
│  │  │  └─────────────────────────────────────────────────────┘    │  │ │
│  │  └──────────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                           │                                              │
│                           │ POST /broadcast/{id}/quick-buy               │
│                           ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  Backend                                                           │ │
│  │  1. Validate product on shelf                                      │ │
│  │  2. Validate broadcast is live                                     │ │
│  │  3. Validate payment method                                        │ │
│  │  4. Create order with broadcast_session_id attribution             │ │
│  │  5. Charge payment method (Stripe/mock)                            │ │
│  │  6. Write billing ledger entry                                     │ │
│  │  7. SSE → purchase:completed event to broadcaster                  │ │
│  │  8. Increment purchase counter                                     │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  Broadcaster Dashboard — Purchase Counter                          │ │
│  │  "12 purchases during this stream ($587.00)"                       │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

**Purchase flow sequence diagram (viewer click to confirmation)**:

```
Viewer                       Frontend                     Backend                    Broadcaster
  │                              │                           │                           │
  │ Click "Quick Buy"           │                           │                           │
  │─────────────────────────────>│                           │                           │
  │                              │                           │                           │
  │                              │ Open QuickBuyDialog       │                           │
  │                              │ Fetch payment methods     │                           │
  │                              │ GET /billing/payment-methods                          │
  │                              │──────────────────────────>│                           │
  │                              │      [Visa ****4242]      │                           │
  │                              │<──────────────────────────│                           │
  │                              │                           │                           │
  │ Select qty=1, PM=Visa        │                           │                           │
  │ Click "Buy Now"              │                           │                           │
  │─────────────────────────────>│                           │                           │
  │                              │                           │                           │
  │                              │ POST /quick-buy           │                           │
  │                              │ {item_id, pm_id, qty=1,   │                           │
  │                              │  idempotency_key}         │                           │
  │                              │──────────────────────────>│                           │
  │                              │                           │                           │
  │                              │           1. Validate session live                    │
  │                              │           2. Validate product on shelf                │
  │                              │           3. Validate payment method                  │
  │                              │           4. Check idempotency                        │
  │                              │           5. Calculate total                          │
  │                              │           6. Create order in DDB                      │
  │                              │           7. Write billing ledger                     │
  │                              │           8. Increment purchase counter               │
  │                              │           9. Publish SSE event                        │
  │                              │                           │                           │
  │                              │      201 {order_id, ...}  │                           │
  │                              │<──────────────────────────│                           │
  │                              │                           │                           │
  │ Toast: "Purchased!"         │                           │   SSE: purchase:completed  │
  │ Dialog closes               │                           │──────────────────────────>│
  │ Back to watching            │                           │                           │
  │                              │                           │   Counter: 13 ($636.99)   │
```

---

## 2. Current State Analysis

### 2.1 Existing Order System

**Orders table** (see `scripts/local-ddb-init.py:118`): DynamoDB table with `order_id` as PK.

**Order items table** (see line 125): `order_id` PK, `item_id` SK.

The orders table currently has no `broadcast_session_id` field. Orders created through the standard checkout flow have no broadcast attribution.

### 2.2 Billing System (`app/services/billing_shared.py`)

The billing system (~260 lines) uses a single-table design with `pk=USER#{user_id}` and various SK prefixes:

- `PM#{pm_id}`: Payment method records with `provider`, `provider_id`, `brand`, `last_four`, `exp_month`, `exp_year`
- `BILLING`: User's billing settings including `default_payment_method_id`
- `BALANCE`: Balance tracking
- `LEDGER#{ledger_id}`: Individual transaction records with `amount_cents`, `currency`, `reason`, `created_at`

Helpers: `user_pk(user_id)` (see line 16), `ddb_get(table, pk, sk)` (see line 20), `ddb_put(table, item)` (see line 25).

`ensure_balance_row(table, pk, currency)` (see line 62): Creates BALANCE row if missing.
`apply_balance_delta(table, pk, delta, currency)` (see line 76): Atomic increment/decrement of balance fields.

### 2.3 Payment Method Validation Pattern

The messaging system's tip and unlock features validate payment methods before charging (seen in `app/routers/messaging.py`). The pattern is:

```python
pm_item = T.billing.get_item(Key={"pk": user_pk(buyer_id), "sk": f"PM#{pm_id}"}).get("Item")
if not pm_item:
    raise HTTPException(400, "Payment method not found")
```

For the quick-buy flow, the same pattern applies: validate the selected payment method belongs to the buyer.

### 2.4 Stripe Mock Behavior

The Stripe mock server on port 12111 is noted in CLAUDE.md: "stripe-mock always returns `requires_payment_method` for off-session PaymentIntents." This means the quick-buy endpoint cannot use Stripe's off-session payment flow in dev mode. The implementation must either:

1. Create the PaymentIntent on-session (viewer's browser handles 3DS if needed), or
2. Skip the actual Stripe charge in dev mode and just record the order + billing ledger entry.

Option 2 is consistent with how tips and locked message unlocks work in the codebase — they validate the PM exists, write a ledger entry, but don't make a real Stripe API call. The quick-buy should follow this pattern.

### 2.5 Purchase Transaction System (`app/models.py`)

The platform has a `PurchaseMoneyIn` model (see `app/models.py:419`), `PurchaseTransactionIn` model (see line 443), and `PurchaseTransactionSummary` (see line 451) with transaction tracking fields.

### 2.6 Broadcast SSE System (`app/services/broadcast_sse.py`)

`broadcast_sse_publish(session_id, event)` (see line 29) fans out events to all SSE subscribers. Already used for chat events, shelf events, health updates, and viewer count updates. The quick-buy system will use this to broadcast purchase events to the broadcaster.

### 2.7 Frontend Shop Components (`frontend/src/pages/shop/`)

- `Cart.tsx`: Full cart management component
- `CartPage.tsx`: Full page for cart display
- `Checkout.tsx`: Multi-step checkout flow
- `ProductDetail.tsx`: Product detail page

These are too heavyweight for the quick-buy overlay. A new lightweight `QuickBuyDialog` component is needed.

---

## 3. Technical Design

### 3.1 DynamoDB Schema Changes

#### 3.1.1 New Table: `BroadcastOrders`

A dedicated table for broadcast-attributed orders, separate from the general `orders` table to keep the broadcast commerce analytics isolated and queryable.

| Attribute | Type | Role |
|-----------|------|------|
| `order_id` | S | Partition Key |
| `session_id` | S | Broadcast session ID (for analytics queries) |
| `buyer_id` | S | Viewer's user sub |
| `seller_id` | S | Broadcaster's user sub (session.created_by) |
| `item_id` | S | Catalog item ID purchased |
| `category_id` | S | Category ID |
| `item_name` | S | Denormalized product name |
| `quantity` | N | Quantity purchased |
| `unit_price_cents` | N | Price per unit at time of purchase |
| `total_cents` | N | quantity * unit_price_cents |
| `currency` | S | Currency code |
| `payment_method_id` | S | PM used for purchase |
| `status` | S | `completed`, `refunded`, `failed` |
| `created_at` | N | Unix timestamp |
| `idempotency_key` | S | Client-generated key to prevent duplicates |
| `ttl` | N | Optional TTL for cleanup |

**GSIs**:

| GSI | PK | SK | Purpose |
|-----|----|----|---------|
| `BySession` | `session_id` | `created_at` | List all orders for a broadcast (analytics) |
| `ByBuyer` | `buyer_id` | `created_at` | List viewer's broadcast purchases |

**DDB access pattern diagram**:

```
┌────────────────────────────────────────────────────────────────────┐
│ BroadcastOrders Table                                               │
├─────────────────────┬──────────────────────────────────────────────┤
│ Partition Key       │ (no sort key — order_id is unique PK)        │
│ order_id (S)        │                                               │
├─────────────────────┼──────────────────────────────────────────────┤
│                                                                     │
│  Access Patterns:                                                   │
│                                                                     │
│  1. Create order:                                                   │
│     PutItem(order_id=bord_xxx, ...)                                │
│     → O(1) write                                                    │
│                                                                     │
│  2. Get order by ID:                                                │
│     GetItem(order_id=bord_xxx)                                     │
│     → O(1) read                                                     │
│                                                                     │
│  3. List orders by session (broadcaster analytics):                 │
│     GSI BySession: Query(session_id=sess_xxx, ScanIndexForward=F)  │
│     → Returns orders newest-first for session dashboard             │
│                                                                     │
│  4. List orders by buyer (viewer purchase history):                 │
│     GSI ByBuyer: Query(buyer_id=user_xxx, ScanIndexForward=F)      │
│     → Returns buyer's broadcast purchases newest-first              │
│                                                                     │
│  5. Idempotency check:                                              │
│     GSI ByBuyer: Query + client-side filter on idempotency_key     │
│     → Scan recent 50 orders for matching key                        │
│                                                                     │
└─────────────────────┴──────────────────────────────────────────────┘
```

**Table definition** (for `scripts/local-ddb-init.py`):

```python
TableDef(
    _resolve_table_name(S.broadcast_orders_table_name, "BroadcastOrders"),
    "order_id",
    gsi=[
        {"index_name": "BySession", "partition_key": "session_id", "sort_key": "created_at"},
        {"index_name": "ByBuyer", "partition_key": "buyer_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

#### 3.1.2 Purchase Counter (In-Memory + DDB)

Maintain an in-memory counter per session for real-time display, backed by a DDB record for durability:

- In-memory: `Dict[str, {"count": int, "total_cents": int}]` — reset on server restart
- DDB: Stored on the `BroadcastSessions` table as `purchase_count` and `purchase_total_cents` fields (updated atomically via `update_item`)

### 3.2 API Endpoints

#### 3.2.1 Quick-Buy Endpoint

```
POST /broadcast/sessions/{session_id}/quick-buy
```

**Auth**: `require_ui_session` — any authenticated viewer can purchase.

**Request model**:

```python
class BroadcastQuickBuyIn(BaseModel):
    """Request body for the quick-buy one-click purchase flow.

    All fields are validated to prevent price tampering. The actual price
    is resolved server-side from the shelf item, NOT from client input.
    """
    item_id: str = Field(..., min_length=1, max_length=128)
    payment_method_id: str = Field(..., min_length=1, max_length=128)
    quantity: int = Field(default=1, ge=1, le=10,
        description="Quantity to purchase. Max 10 per quick-buy transaction.")
    idempotency_key: Optional[str] = Field(
        default=None, max_length=128,
        description="Client-generated key to prevent duplicate orders. "
                    "Recommended format: {sessionId}_{itemId}_{timestamp}"
    )

    @validator("item_id")
    def item_id_no_special_chars(cls, v: str) -> str:
        if "#" in v or "\n" in v:
            raise ValueError("item_id must not contain '#' or newline characters")
        return v
```

**Response model**:

```python
class BroadcastQuickBuyOut(BaseModel):
    """Response confirming a successful quick-buy purchase."""
    order_id: str
    session_id: str
    item_id: str
    item_name: str
    quantity: int
    unit_price_cents: int
    total_cents: int
    currency: str
    status: str  # "completed"
    created_at: int
```

**Behavior**:

1. **Validate session**: Exists and status is `live`. Return 403 if not live ("Purchases are only available during live broadcasts").
2. **Validate product on shelf**: `T.broadcast_product_shelf.get_item(Key={"session_id": session_id, "SK": f"ITEM#{item_id}"})`. Return 404 if not on shelf.
3. **Validate payment method**: `T.billing.get_item(Key={"pk": user_pk(buyer_id), "sk": f"PM#{payment_method_id}"})`. Return 400 if PM not found.
4. **Idempotency check**: If `idempotency_key` provided, check `T.broadcast_orders` for existing order with same key. Return the existing order if found (200, not error).
5. **Calculate total**: `total_cents = shelf_item.price_cents * quantity`. Price is resolved server-side from the shelf, not from client input.
6. **Create order**: Write to `BroadcastOrders` table with status `completed`.
7. **Write billing ledger**: Debit entry on buyer's billing account: `LEDGER#{ledger_id}` with `amount_cents=-total_cents`, `reason="Broadcast purchase: {item_name}"`.
8. **Update purchase counter**: Atomic increment of `purchase_count` and `purchase_total_cents` on the session record.
9. **Publish SSE event**: `broadcast_sse_publish(session_id, {"_type": "purchase:completed", "order_id": order_id, "item_name": item_name, "amount_cents": total_cents, "buyer_display_name": display_name})`.
10. **Return order confirmation**.

**Error responses**:

| Code | Condition |
|------|-----------|
| 400 | Payment method not found or invalid |
| 403 | Session not live |
| 404 | Product not on shelf |
| 409 | Idempotency conflict (different item/amount for same key) |

#### 3.2.2 Session Purchase Stats

```
GET /broadcast/sessions/{session_id}/purchases/stats
```

**Auth**: `require_ui_session` — only session creator (broadcaster) or admin.

**Response model**:

```python
class BroadcastPurchaseStatsOut(BaseModel):
    session_id: str
    purchase_count: int
    purchase_total_cents: int
    currency: str = "USD"
```

**Behavior**: Read `purchase_count` and `purchase_total_cents` from the session record. Falls back to 0 if fields don't exist.

#### 3.2.3 Session Purchase History

```
GET /broadcast/sessions/{session_id}/purchases
```

**Auth**: `require_ui_session` — only session creator or admin.

**Response model**:

```python
class BroadcastPurchaseHistoryOut(BaseModel):
    session_id: str
    orders: List[BroadcastQuickBuyOut] = Field(default_factory=list)
    total_count: int = 0
    total_cents: int = 0
```

**Behavior**: Query `BroadcastOrders` by `BySession` GSI with `session_id` partition, ordered by `created_at` descending. Return up to 200 orders.

#### 3.2.4 Viewer's Broadcast Purchase History

```
GET /broadcast/purchases/mine
```

**Auth**: `require_ui_session` — authenticated viewer sees their own purchases.

**Response model**: Same `BroadcastPurchaseHistoryOut` shape but queries `ByBuyer` GSI.

### 3.3 Service Layer — `app/services/broadcast_orders.py`

```python
"""Broadcast order service — quick-buy orders with session attribution."""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import user_pk, ddb_get
from app.services.broadcast_sse import broadcast_sse_publish


# ─── In-memory purchase counter ──────────────────────────────────

_PURCHASE_COUNTER_LOCK = threading.Lock()
_PURCHASE_COUNTERS: Dict[str, Dict[str, int]] = {}


def _increment_purchase_counter(session_id: str, amount_cents: int) -> Dict[str, int]:
    """Thread-safe increment of the in-memory purchase counter.

    Returns the updated counter dict with 'count' and 'total_cents'.
    The in-memory counter is the authoritative source during the session's
    lifetime. The DDB counter is a persistence backup.
    """
    with _PURCHASE_COUNTER_LOCK:
        counter = _PURCHASE_COUNTERS.setdefault(session_id, {"count": 0, "total_cents": 0})
        counter["count"] += 1
        counter["total_cents"] += amount_cents
        return dict(counter)


def get_purchase_counter(session_id: str) -> Dict[str, int]:
    """Read the current purchase counter for a session.

    Returns the in-memory counter. If the counter was reset (server restart),
    callers should fall back to the DDB counter on the session record.
    """
    with _PURCHASE_COUNTER_LOCK:
        return dict(_PURCHASE_COUNTERS.get(session_id, {"count": 0, "total_cents": 0}))


def reset_purchase_counters() -> None:
    """Clear all purchase counters (for tests)."""
    with _PURCHASE_COUNTER_LOCK:
        _PURCHASE_COUNTERS.clear()


# ─── Order CRUD ───────────────────────────────────────────────────

def create_quick_buy_order(
    *,
    session_id: str,
    buyer_id: str,
    seller_id: str,
    shelf_item: Dict[str, Any],
    payment_method_id: str,
    quantity: int = 1,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a broadcast quick-buy order.

    This is the core order creation function. It validates the payment method,
    calculates the total from the shelf item's price (server-side, not client input),
    creates the order record, writes a billing ledger debit, updates the
    purchase counter, and publishes an SSE event.

    Args:
        session_id: Broadcast session ID.
        buyer_id: User sub of the viewer making the purchase.
        seller_id: User sub of the broadcaster (session.created_by).
        shelf_item: Dict from broadcast_product_shelf with price_cents etc.
        payment_method_id: PM ID from the buyer's billing table.
        quantity: Number of items to purchase (1-10).
        idempotency_key: Optional client key to prevent duplicate orders.

    Returns:
        Dict suitable for BroadcastQuickBuyOut serialization.

    Raises:
        HTTPException 400: Payment method not found.
    """

    # Idempotency check
    if idempotency_key:
        existing = _find_by_idempotency_key(session_id, buyer_id, idempotency_key)
        if existing:
            return existing

    # Validate payment method
    pm_item = ddb_get(T.billing, user_pk(buyer_id), f"PM#{payment_method_id}")
    if not pm_item:
        raise HTTPException(status_code=400, detail="Payment method not found.")

    unit_price = int(shelf_item.get("price_cents", 0))
    total_cents = unit_price * quantity
    ts = now_ts()
    order_id = f"bord_{uuid4().hex}"

    order = {
        "order_id": order_id,
        "session_id": session_id,
        "buyer_id": buyer_id,
        "seller_id": seller_id,
        "item_id": shelf_item["item_id"],
        "category_id": shelf_item.get("category_id", ""),
        "item_name": shelf_item.get("name", ""),
        "quantity": quantity,
        "unit_price_cents": unit_price,
        "total_cents": total_cents,
        "currency": shelf_item.get("currency", "USD"),
        "payment_method_id": payment_method_id,
        "status": "completed",
        "created_at": ts,
        "idempotency_key": idempotency_key,
    }
    T.broadcast_orders.put_item(Item=order)

    # Write billing ledger debit
    _write_billing_ledger(buyer_id, total_cents, shelf_item.get("name", "Product"), order_id)

    # Update in-memory counter
    counter = _increment_purchase_counter(session_id, total_cents)

    # Persist counter to session record
    _persist_session_counter(session_id, counter)

    # Publish SSE event
    broadcast_sse_publish(session_id, {
        "_type": "purchase:completed",
        "order_id": order_id,
        "item_name": shelf_item.get("name", ""),
        "amount_cents": total_cents,
        "purchase_count": counter["count"],
        "purchase_total_cents": counter["total_cents"],
    })

    return _order_out(order)


def _write_billing_ledger(buyer_id: str, amount_cents: int, item_name: str, order_id: str) -> None:
    """Write a debit ledger entry for the purchase.

    Follows the same pattern as tip and unlock ledger entries in
    app/routers/messaging.py. The amount_cents is negative (debit).
    """
    from uuid import uuid4
    ledger_id = uuid4().hex
    T.billing.put_item(Item={
        "pk": user_pk(buyer_id),
        "sk": f"LEDGER#{ledger_id}",
        "amount_cents": -amount_cents,
        "currency": "USD",
        "reason": f"Broadcast purchase: {item_name}",
        "reference_id": order_id,
        "reference_type": "broadcast_order",
        "created_at": now_ts(),
    })


def _persist_session_counter(session_id: str, counter: Dict[str, int]) -> None:
    """Persist purchase counter to session record in DDB.

    This is a best-effort operation. If it fails, the in-memory counter
    is still authoritative. The DDB counter is used for recovery after
    server restarts and for historical analytics.
    """
    try:
        T.broadcast_sessions.update_item(
            Key={"session_id": session_id},
            UpdateExpression="SET purchase_count = :c, purchase_total_cents = :t",
            ExpressionAttributeValues={
                ":c": counter["count"],
                ":t": counter["total_cents"],
            },
        )
    except Exception:
        pass  # Non-critical — in-memory counter is authoritative during the session


def _find_by_idempotency_key(
    session_id: str, buyer_id: str, idempotency_key: str
) -> Optional[Dict[str, Any]]:
    """Check for an existing order with the same idempotency key.

    Scans the buyer's recent 50 orders. This is efficient because
    idempotency is only relevant for recent orders (within seconds).
    """
    resp = T.broadcast_orders.query(
        IndexName="ByBuyer",
        KeyConditionExpression=Key("buyer_id").eq(buyer_id),
        Limit=50,
        ScanIndexForward=False,
    )
    for item in resp.get("Items", []):
        if item.get("idempotency_key") == idempotency_key and item.get("session_id") == session_id:
            return _order_out(item)
    return None


def list_session_orders(session_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    """List all orders for a broadcast session, newest first."""
    resp = T.broadcast_orders.query(
        IndexName="BySession",
        KeyConditionExpression=Key("session_id").eq(session_id),
        Limit=limit,
        ScanIndexForward=False,
    )
    return [_order_out(i) for i in resp.get("Items", [])]


def list_buyer_orders(buyer_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    """List broadcast purchases for a specific buyer, newest first."""
    resp = T.broadcast_orders.query(
        IndexName="ByBuyer",
        KeyConditionExpression=Key("buyer_id").eq(buyer_id),
        Limit=limit,
        ScanIndexForward=False,
    )
    return [_order_out(i) for i in resp.get("Items", [])]


def _order_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB order item to output dict with Decimal-to-int coercion."""
    return {
        "order_id": item["order_id"],
        "session_id": item["session_id"],
        "item_id": item["item_id"],
        "item_name": item.get("item_name", ""),
        "quantity": int(item.get("quantity", 1)),
        "unit_price_cents": int(item.get("unit_price_cents", 0)),
        "total_cents": int(item.get("total_cents", 0)),
        "currency": item.get("currency", "USD"),
        "status": item.get("status", "completed"),
        "created_at": int(item.get("created_at", 0)),
    }
```

### 3.4 Pydantic Models (in `app/routers/broadcast.py`)

```python
class BroadcastQuickBuyIn(BaseModel):
    item_id: str = Field(..., min_length=1, max_length=128)
    payment_method_id: str = Field(..., min_length=1, max_length=128)
    quantity: int = Field(default=1, ge=1, le=10)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)


class BroadcastQuickBuyOut(BaseModel):
    order_id: str
    session_id: str
    item_id: str
    item_name: str
    quantity: int
    unit_price_cents: int
    total_cents: int
    currency: str
    status: str
    created_at: int


class BroadcastPurchaseStatsOut(BaseModel):
    session_id: str
    purchase_count: int
    purchase_total_cents: int
    currency: str = "USD"


class BroadcastPurchaseHistoryOut(BaseModel):
    session_id: str
    orders: List[BroadcastQuickBuyOut] = Field(default_factory=list)
    total_count: int = 0
    total_cents: int = 0
```

### 3.5 Full Router Endpoint Implementations

```python
# ─── Quick-Buy Endpoints (LCOM-003) ────────────────────────────

@router.post(
    "/sessions/{session_id}/quick-buy",
    response_model=BroadcastQuickBuyOut,
    status_code=status.HTTP_201_CREATED,
)
def quick_buy_route(
    session_id: str,
    body: BroadcastQuickBuyIn,
    ctx: dict = Depends(_ctx),
):
    """One-click purchase from the broadcast product shelf."""
    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "BROADCAST_NOT_LIVE",
                    "message": "Purchases are only available during live broadcasts"},
        )

    # Validate product is on the shelf
    shelf_item = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{body.item_id}"}
    ).get("Item")
    if not shelf_item:
        raise HTTPException(status_code=404, detail="Product not on shelf.")

    from app.services.broadcast_orders import create_quick_buy_order
    order = create_quick_buy_order(
        session_id=session_id,
        buyer_id=ctx["user_sub"],
        seller_id=session.created_by,
        shelf_item=shelf_item,
        payment_method_id=body.payment_method_id,
        quantity=body.quantity,
        idempotency_key=body.idempotency_key,
    )
    return BroadcastQuickBuyOut(**order)


@router.get(
    "/sessions/{session_id}/purchases/stats",
    response_model=BroadcastPurchaseStatsOut,
)
def purchase_stats_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Get purchase count and total for a broadcast session."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        _require_operator_role(ctx)

    from app.services.broadcast_orders import get_purchase_counter
    counter = get_purchase_counter(session_id)
    # Fall back to DDB counter if in-memory is zero (server restart)
    if counter["count"] == 0:
        counter = {
            "count": int(getattr(session, "purchase_count", 0) or 0),
            "total_cents": int(getattr(session, "purchase_total_cents", 0) or 0),
        }
    return BroadcastPurchaseStatsOut(
        session_id=session_id,
        purchase_count=counter["count"],
        purchase_total_cents=counter["total_cents"],
    )


@router.get(
    "/sessions/{session_id}/purchases",
    response_model=BroadcastPurchaseHistoryOut,
)
def session_purchases_route(session_id: str, ctx: dict = Depends(_ctx)):
    """List all orders for a broadcast session."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        _require_operator_role(ctx)

    from app.services.broadcast_orders import list_session_orders
    orders = list_session_orders(session_id)
    total = sum(o["total_cents"] for o in orders)
    return BroadcastPurchaseHistoryOut(
        session_id=session_id,
        orders=[BroadcastQuickBuyOut(**o) for o in orders],
        total_count=len(orders),
        total_cents=total,
    )


@router.get("/purchases/mine", response_model=BroadcastPurchaseHistoryOut)
def my_purchases_route(ctx: dict = Depends(_ctx)):
    """List the current viewer's broadcast purchases."""
    from app.services.broadcast_orders import list_buyer_orders
    orders = list_buyer_orders(ctx["user_sub"])
    total = sum(o["total_cents"] for o in orders)
    return BroadcastPurchaseHistoryOut(
        session_id="",
        orders=[BroadcastQuickBuyOut(**o) for o in orders],
        total_count=len(orders),
        total_cents=total,
    )
```

### 3.6 Frontend — QuickBuyDialog Component

```typescript
// frontend/src/pages/broadcast/QuickBuyDialog.tsx

/**
 * QuickBuyDialog — lightweight overlay for one-click broadcast purchases.
 *
 * Renders on top of the broadcast player without navigating away.
 * Fetches payment methods, supports quantity selection, and submits
 * the quick-buy order with idempotency protection.
 *
 * Target latency: dialog open to purchase confirmation < 500ms.
 */
interface QuickBuyDialogProps {
  sessionId: string;
  product: ShelfItem;
  open: boolean;
  onClose: () => void;
  onPurchased: (order: QuickBuyOrder) => void;
}

export function QuickBuyDialog({ sessionId, product, open, onClose, onPurchased }: QuickBuyDialogProps) {
  const [quantity, setQuantity] = useState(1);
  const [selectedPmId, setSelectedPmId] = useState<string | null>(null);

  // Fetch user's payment methods
  const { data: paymentMethods } = useQuery({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
    enabled: open,
  });

  // Auto-select default payment method
  useEffect(() => {
    if (paymentMethods?.length && !selectedPmId) {
      const defaultPm = paymentMethods.find(pm => pm.is_default) || paymentMethods[0];
      setSelectedPmId(defaultPm.id);
    }
  }, [paymentMethods, selectedPmId]);

  const buyMutation = useMutation({
    mutationFn: () => quickBuy(sessionId, {
      item_id: product.item_id,
      payment_method_id: selectedPmId!,
      quantity,
      idempotency_key: `${sessionId}_${product.item_id}_${Date.now()}`,
    }),
    onSuccess: (order) => {
      toast.success(`Purchased ${product.name}!`);
      onPurchased(order);
      onClose();
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail;
      if (typeof detail === "string") {
        toast.error(detail);
      } else if (detail?.message) {
        toast.error(detail.message);
      } else {
        toast.error("Purchase failed. Please try again.");
      }
    },
  });

  const totalCents = product.price_cents * quantity;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md" aria-describedby="quick-buy-description">
        <DialogHeader>
          <DialogTitle>Quick Buy</DialogTitle>
          <DialogDescription id="quick-buy-description">
            Purchase this product without leaving the broadcast.
          </DialogDescription>
        </DialogHeader>
        <div className="flex gap-4">
          {product.image_url && (
            <img src={product.image_url} className="w-24 h-24 rounded object-cover" alt={product.name} />
          )}
          <div>
            <p className="font-semibold">{product.name}</p>
            <p className="text-lg font-bold text-green-600">
              ${(product.price_cents / 100).toFixed(2)}
            </p>
          </div>
        </div>

        {/* Quantity selector */}
        <div className="flex items-center gap-2">
          <Label>Quantity:</Label>
          <Button variant="outline" size="sm"
            onClick={() => setQuantity(q => Math.max(1, q - 1))}
            aria-label="Decrease quantity">-</Button>
          <span className="w-8 text-center" aria-label={`Quantity: ${quantity}`}>{quantity}</span>
          <Button variant="outline" size="sm"
            onClick={() => setQuantity(q => Math.min(10, q + 1))}
            aria-label="Increase quantity">+</Button>
        </div>

        {/* Payment method selector */}
        <div>
          <Label>Payment Method</Label>
          {paymentMethods?.length === 0 && (
            <p className="text-sm text-muted-foreground mt-1">
              No payment methods. Add one in Billing settings.
            </p>
          )}
          <Select value={selectedPmId || ""} onValueChange={setSelectedPmId}>
            <SelectTrigger><SelectValue placeholder="Select payment method" /></SelectTrigger>
            <SelectContent>
              {paymentMethods?.map(pm => (
                <SelectItem key={pm.id} value={pm.id}>
                  {pm.brand} ****{pm.last_four}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Buy button */}
        <Button
          className="w-full"
          onClick={() => buyMutation.mutate()}
          disabled={!selectedPmId || buyMutation.isPending}
          aria-label={`Buy now for $${(totalCents / 100).toFixed(2)}`}
        >
          {buyMutation.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin mr-2" />
          ) : (
            <ShoppingCart className="h-4 w-4 mr-2" />
          )}
          Buy Now — ${(totalCents / 100).toFixed(2)}
        </Button>
      </DialogContent>
    </Dialog>
  );
}
```

### 3.7 Frontend — PurchaseCounter Component (Broadcaster)

```typescript
// frontend/src/pages/broadcast/PurchaseCounter.tsx

/**
 * PurchaseCounter — real-time purchase counter badge for the broadcaster.
 *
 * Listens for purchase:completed SSE events and updates the counter.
 * Falls back to the stats API on mount to recover from SSE gaps.
 */
interface PurchaseCounterProps {
  sessionId: string;
}

export function PurchaseCounter({ sessionId }: PurchaseCounterProps) {
  const [stats, setStats] = useState({ purchase_count: 0, purchase_total_cents: 0 });

  // Initial load from stats API
  useEffect(() => {
    getPurchaseStats(sessionId)
      .then(data => setStats({
        purchase_count: data.purchase_count,
        purchase_total_cents: data.purchase_total_cents,
      }))
      .catch(() => {});
  }, [sessionId]);

  // Listen for purchase:completed SSE events
  // The broadcast SSE stream already delivers these

  return (
    <Badge variant="secondary" className="flex items-center gap-1" aria-live="polite">
      <ShoppingCart className="h-3 w-3" />
      {stats.purchase_count} purchases (${(stats.purchase_total_cents / 100).toFixed(2)})
    </Badge>
  );
}
```

### 3.8 SSE Events

| Event Type | Payload | Recipient | Trigger |
|------------|---------|-----------|---------|
| `purchase:completed` | `{order_id, item_name, amount_cents, purchase_count, purchase_total_cents}` | All session subscribers (broadcaster + viewers) | Order completed |

### 3.9 Frontend TypeScript Types

```typescript
// frontend/src/api/endpoints/broadcast-orders.ts

export interface QuickBuyOrder {
  order_id: string;
  session_id: string;
  item_id: string;
  item_name: string;
  quantity: number;
  unit_price_cents: number;
  total_cents: number;
  currency: string;
  status: string;
  created_at: number;
}

export interface PurchaseStats {
  session_id: string;
  purchase_count: number;
  purchase_total_cents: number;
  currency: string;
}

export interface PurchaseHistory {
  session_id: string;
  orders: QuickBuyOrder[];
  total_count: number;
  total_cents: number;
}

export const quickBuy = (sessionId: string, body: {
  item_id: string;
  payment_method_id: string;
  quantity?: number;
  idempotency_key?: string;
}) => api.post<QuickBuyOrder>(`/broadcast/sessions/${sessionId}/quick-buy`, body);

export const getPurchaseStats = (sessionId: string) =>
  api.get<PurchaseStats>(`/broadcast/sessions/${sessionId}/purchases/stats`);

export const getSessionPurchases = (sessionId: string) =>
  api.get<PurchaseHistory>(`/broadcast/sessions/${sessionId}/purchases`);

export const getMyPurchases = () =>
  api.get<PurchaseHistory>(`/broadcast/purchases/mine`);
```

---

## 4. Implementation Plan

### Phase 1: Backend Infrastructure (1 day)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `broadcast_orders_table_name` setting (after `broadcast_product_shelf_table_name`) |
| `app/core/tables.py` | Add `broadcast_orders: Any` field and `broadcast_orders=ddb.Table(...)` initialization |
| `scripts/local-ddb-init.py` | Add `BroadcastOrders` table definition with 2 GSIs (BySession, ByBuyer) |

### Phase 2: Service Layer (1.5 days)

| File | Type |
|------|------|
| `app/services/broadcast_orders.py` | Create — order creation, billing ledger, purchase counter, session counter persistence, order listing |

### Phase 3: Backend Endpoints (1 day)

| File | Change |
|------|--------|
| `app/routers/broadcast.py` | Add Pydantic models + 4 endpoints: quick-buy, purchase stats, session purchases, buyer purchases |

### Phase 4: Frontend API Layer (0.5 days)

| File | Type |
|------|------|
| `frontend/src/api/endpoints/broadcast-orders.ts` | Create — `quickBuy`, `getPurchaseStats`, `getSessionPurchases`, `getMyPurchases` |

### Phase 5: Frontend Components (1.5 days)

| File | Type |
|------|------|
| `frontend/src/pages/broadcast/QuickBuyDialog.tsx` | Create — purchase dialog |
| `frontend/src/pages/broadcast/PurchaseCounter.tsx` | Create — live counter badge |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Modify — wire QuickBuyDialog to ProductShelf |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Modify — add PurchaseCounter |
| `frontend/src/pages/broadcast/ProductShelfCard.tsx` | Modify — add "Quick Buy" button |

### Phase 6: Integration + Polish (0.5 days)

- Wire SSE `purchase:completed` event to PurchaseCounter
- Order confirmation toast with animation
- Handle edge cases

### Summary of All Files

<!-- NOTE: app/services/broadcast_orders.py does NOT exist yet — new implementation required.
     The BroadcastOrders DDB table also does not exist yet.
     The broadcast router already has resolve_effective_price integration at line 1465
     (from LCOM-004), but no quick-buy endpoint exists. -->

| File | Type | Status |
|------|------|--------|
| `app/core/settings.py` | Modify | Need `broadcast_orders_table_name` |
| `app/core/tables.py` | Modify | Need `broadcast_orders` handle |
| `scripts/local-ddb-init.py` | Modify | Need `BroadcastOrders` table definition |
| `app/services/broadcast_orders.py` | **Create** | Does not exist yet |
| `app/routers/broadcast.py` | Modify | Need quick-buy endpoint (~3969 lines currently) |
| `frontend/src/api/endpoints/broadcast-orders.ts` | **Create** | Does not exist yet |
| `frontend/src/pages/broadcast/QuickBuyDialog.tsx` | **Create** | Does not exist yet |
| `frontend/src/pages/broadcast/PurchaseCounter.tsx` | **Create** | Does not exist yet |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Modify | Already exists |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Modify | Already exists |
| `frontend/src/pages/broadcast/ProductShelfCard.tsx` | **Create** | Does not exist yet (no separate file) |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_orders.py`)

~250 lines, using `moto` for DynamoDB mocking.

```python
import pytest
from moto import mock_dynamodb
from fastapi import HTTPException
from boto3.dynamodb.conditions import Key

from app.services.broadcast_orders import (
    create_quick_buy_order,
    get_purchase_counter,
    list_session_orders,
    list_buyer_orders,
    reset_purchase_counters,
)
from app.services.billing_shared import user_pk

MOCK_SHELF_ITEM = {
    "item_id": "item1",
    "category_id": "cat1",
    "name": "Test Widget",
    "price_cents": 999,
    "currency": "USD",
    "image_url": "https://example.com/widget.jpg",
}


@mock_dynamodb
class TestBroadcastOrders:
    def setup_method(self):
        """Create tables and seed payment method."""
        import boto3
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")
        # Create BroadcastOrders table with GSIs
        # Create billing table
        # Seed payment method for buyer
        reset_purchase_counters()

    def test_create_quick_buy_order(self):
        order = create_quick_buy_order(
            session_id="sess1", buyer_id="buyer1", seller_id="seller1",
            shelf_item=MOCK_SHELF_ITEM, payment_method_id="pm_123",
        )
        assert order["order_id"].startswith("bord_")
        assert order["status"] == "completed"
        assert order["total_cents"] == 999
        assert order["quantity"] == 1
        assert order["unit_price_cents"] == 999

    def test_create_order_with_quantity(self):
        order = create_quick_buy_order(
            session_id="sess1", buyer_id="buyer1", seller_id="seller1",
            shelf_item=MOCK_SHELF_ITEM, payment_method_id="pm_123",
            quantity=3,
        )
        assert order["total_cents"] == 2997  # 999 * 3
        assert order["quantity"] == 3

    def test_create_order_writes_billing_ledger(self):
        create_quick_buy_order(
            session_id="sess1", buyer_id="buyer1", seller_id="seller1",
            shelf_item=MOCK_SHELF_ITEM, payment_method_id="pm_123",
        )
        # Query billing table for ledger entries
        items = self.billing_table.query(
            KeyConditionExpression=Key("pk").eq(user_pk("buyer1")),
        ).get("Items", [])
        ledger_entries = [i for i in items if i["sk"].startswith("LEDGER#")]
        assert len(ledger_entries) >= 1
        assert int(ledger_entries[0]["amount_cents"]) == -999
        assert ledger_entries[0]["reason"] == "Broadcast purchase: Test Widget"
        assert ledger_entries[0]["reference_type"] == "broadcast_order"

    def test_idempotency_returns_same_order(self):
        order1 = create_quick_buy_order(
            session_id="sess1", buyer_id="buyer1", seller_id="seller1",
            shelf_item=MOCK_SHELF_ITEM, payment_method_id="pm_123",
            idempotency_key="idem123",
        )
        order2 = create_quick_buy_order(
            session_id="sess1", buyer_id="buyer1", seller_id="seller1",
            shelf_item=MOCK_SHELF_ITEM, payment_method_id="pm_123",
            idempotency_key="idem123",
        )
        assert order1["order_id"] == order2["order_id"]

    def test_invalid_payment_method_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            create_quick_buy_order(
                session_id="sess1", buyer_id="buyer1", seller_id="seller1",
                shelf_item=MOCK_SHELF_ITEM, payment_method_id="nonexistent",
            )
        assert exc.value.status_code == 400

    def test_purchase_counter_increments(self):
        create_quick_buy_order(
            session_id="sess1", buyer_id="buyer1", seller_id="seller1",
            shelf_item=MOCK_SHELF_ITEM, payment_method_id="pm_123",
        )
        create_quick_buy_order(
            session_id="sess1", buyer_id="buyer2", seller_id="seller1",
            shelf_item=MOCK_SHELF_ITEM, payment_method_id="pm_456",
        )
        counter = get_purchase_counter("sess1")
        assert counter["count"] == 2
        assert counter["total_cents"] == 1998

    def test_list_session_orders(self):
        create_quick_buy_order(
            session_id="sess1", buyer_id="buyer1", seller_id="seller1",
            shelf_item=MOCK_SHELF_ITEM, payment_method_id="pm_123",
        )
        create_quick_buy_order(
            session_id="sess1", buyer_id="buyer2", seller_id="seller1",
            shelf_item=MOCK_SHELF_ITEM, payment_method_id="pm_456",
        )
        orders = list_session_orders("sess1")
        assert len(orders) == 2

    def test_list_buyer_orders(self):
        create_quick_buy_order(
            session_id="sess1", buyer_id="buyer1", seller_id="seller1",
            shelf_item=MOCK_SHELF_ITEM, payment_method_id="pm_123",
        )
        orders = list_buyer_orders("buyer1")
        assert len(orders) == 1
        assert orders[0]["item_id"] == "item1"

    def test_order_out_coerces_decimals(self):
        """Verify Decimal fields from DDB are coerced to int."""
        order = create_quick_buy_order(
            session_id="sess1", buyer_id="buyer1", seller_id="seller1",
            shelf_item=MOCK_SHELF_ITEM, payment_method_id="pm_123",
        )
        assert isinstance(order["total_cents"], int)
        assert isinstance(order["unit_price_cents"], int)
        assert isinstance(order["quantity"], int)
```

### 5.2 E2E Tests (`frontend/e2e/broadcast-quick-buy.spec.ts`)

**Section 120: Quick-Buy API (8 tests)**:

1. Viewer purchases a shelf product via quick-buy — returns 201 with order details
2. Quick-buy creates a billing ledger debit entry for the buyer
3. Quick-buy with invalid payment method returns 400
4. Quick-buy on non-shelf product returns 404
5. Quick-buy while session not live returns 403
6. Idempotent quick-buy returns same order on duplicate request
7. Quantity multiplier calculates total correctly (quantity=3 at $10 = $30)
8. Broadcaster can also make a quick-buy purchase (self-purchase allowed)

**Section 121: Purchase Stats API (4 tests)**:

1. Broadcaster can view purchase stats for their session
2. Stats reflect cumulative count and total after multiple purchases
3. Viewer cannot view purchase stats (403)
4. Stats return zeros for session with no purchases

**Section 122: Purchase History API (4 tests)**:

1. Broadcaster can list all orders for a session
2. Viewer can list their own broadcast purchases via `/purchases/mine`
3. Orders are sorted by created_at descending (newest first)
4. Each order includes item_name, quantity, total_cents

**Section 123: SSE Purchase Events (3 tests)**:

1. Broadcaster receives `purchase:completed` SSE event after viewer buys
2. Event includes `purchase_count` and `purchase_total_cents`
3. Multiple purchases increment the counter correctly in SSE events

**Section 124: Quick-Buy UI (5 tests)**:

1. "Quick Buy" button on ProductShelfCard opens QuickBuyDialog
2. Dialog shows product name, image, and price
3. Payment method selector lists viewer's saved PMs
4. "Buy Now" button submits purchase and shows success toast
5. Dialog closes and viewer returns to broadcast after purchase

**Test setup** (beforeAll):

```typescript
// 1. Create broadcast session + start (make live)
// 2. Create catalog category + item
// 3. Add item to session's product shelf
// 4. Seed payment method for viewer (alice):
//    billing table → pk=USER#{alice_sub}, sk=PM#{pm_id}
//    billing table → pk=USER#{alice_sub}, sk=BILLING with default_payment_method_id
```

### 5.3 Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Viewer has no payment methods | "Buy Now" button disabled; tooltip "Add a payment method in Billing" |
| Session transitions to stopped mid-purchase | 403 returned; order not created |
| Double-click on "Buy Now" | Idempotency key prevents duplicate orders |
| Product removed from shelf after dialog opens | 404 returned on submit; dialog shows error |
| Very high quantity (10 at $999.99) | Accepted; `total_cents = 999990` |
| Stripe mock always returns requires_payment_method | Order created with `completed` status regardless; billing ledger records the charge |
| Counter reset on server restart | Counter rebuilds from DDB on first query |
| Concurrent purchases from multiple viewers | Each gets their own order; counter increments atomically via threading.Lock |

### 5.4 Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| Billing table PM seeding | Seed PM in `beforeAll` using direct DDB writes (same pattern as messaging-features.spec.ts tip tests) |
| Purchase counter race | In-memory counter uses `threading.Lock`; E2E tests use sequential purchases |
| SSE event timing | Register SSE listener before triggering purchase; use 2s timeout for event assertion |
| Idempotency key collision | Include `Date.now()` in key to avoid cross-run collisions |
| Order listing across test runs | Use unique session per test section; orders are scoped to session |

---

## 6. Security Considerations

### 6.1 Payment Fraud Prevention

- **Price is server-resolved**: The quick-buy endpoint reads `shelf_item.price_cents` from DDB, not from the client request. There is no `price` field in `BroadcastQuickBuyIn`. This prevents price tampering where a malicious client submits a lower price.
- **Payment method ownership**: The PM is validated via `ddb_get(T.billing, user_pk(buyer_id), f"PM#{pm_id}")`. The `buyer_id` comes from the authenticated session (`ctx["user_sub"]`), not from the request body. A viewer cannot use another user's PM.
- **Quantity limit**: Max 10 per transaction prevents abuse (e.g., buying 999999 items to generate fraudulent billing ledger entries).

### 6.2 Idempotency Protection

- The `idempotency_key` is client-generated and stored on the order record. If a duplicate key is detected for the same `session_id` + `buyer_id`, the existing order is returned without creating a new one.
- The idempotency check scans the buyer's recent 50 orders (ByBuyer GSI). This is efficient because idempotency is only relevant for very recent orders (within seconds of a double-click).
- The recommended key format is `{sessionId}_{itemId}_{timestamp}` which provides uniqueness across items and time.

### 6.3 Race Conditions in Concurrent Purchases

**Scenario**: Two viewers click "Buy Now" at the same time for the same product.

**Resolution**: Each viewer gets their own order. The product shelf does not track inventory (that's a catalog-level concern). The billing ledger debit is per-buyer, so there is no shared resource contention. The purchase counter uses `threading.Lock` for thread-safe increment.

**Concurrency diagram**:

```
Viewer A                          Backend                        Viewer B
    │                                │                              │
    │ POST /quick-buy               │ POST /quick-buy              │
    │──────────────────────────────>│<──────────────────────────────│
    │                                │                              │
    │                   Lock counter │ Lock counter                 │
    │                   (sequential) │ (waits)                      │
    │                                │                              │
    │                   Create order A                              │
    │                   Unlock counter                              │
    │                                │                              │
    │                                │ Lock counter                 │
    │                                │ Create order B               │
    │                                │ Unlock counter               │
    │                                │                              │
    │          201 order_A           │          201 order_B         │
    │<──────────────────────────────│──────────────────────────────>│
```

### 6.4 Session Lifecycle Protection

- Quick-buy is only available when `session.status == "live"`. This is checked at the beginning of the endpoint.
- If the session transitions to `stopped` between the check and the order creation, the order is still created (the check is not a distributed lock). This is acceptable because the session transition takes ~1 second and the window is negligible.
- The billing ledger entry is idempotent (unique LEDGER#{uuid} SK), so even in the unlikely case of a retry during session transition, no double-charge occurs.

### 6.5 CSRF Protection

The `POST /broadcast/sessions/{id}/quick-buy` endpoint uses `require_ui_session` which enforces CSRF for cookie-based auth. The frontend axios client automatically includes the `x-csrf-token` header.

### 6.6 Input Validation for Product Data

All product data (name, price, image) is read server-side from the DDB shelf item. No product data is accepted from the client. The only client-provided fields are `item_id`, `payment_method_id`, `quantity`, and `idempotency_key`, all of which are validated via Pydantic.

---

## 7. Migration & Rollback Plan

### 7.1 DDB Table Creation

**Full TableDef for `BroadcastOrders`**:

```python
TableDef(
    _resolve_table_name(S.broadcast_orders_table_name, "BroadcastOrders"),
    "order_id",
    gsi=[
        {"index_name": "BySession", "partition_key": "session_id", "sort_key": "created_at"},
        {"index_name": "ByBuyer", "partition_key": "buyer_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

**Production AWS CLI**:

```bash
aws dynamodb create-table \
  --table-name BroadcastOrders \
  --key-schema AttributeName=order_id,KeyType=HASH \
  --attribute-definitions \
    AttributeName=order_id,AttributeType=S \
    AttributeName=session_id,AttributeType=S \
    AttributeName=buyer_id,AttributeType=S \
    AttributeName=created_at,AttributeType=N \
  --global-secondary-indexes \
    'IndexName=BySession,KeySchema=[{AttributeName=session_id,KeyType=HASH},{AttributeName=created_at,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
    'IndexName=ByBuyer,KeySchema=[{AttributeName=buyer_id,KeyType=HASH},{AttributeName=created_at,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
  --billing-mode PAY_PER_REQUEST
```

### 7.2 Feature Flag Rollout Phases

1. **Phase 0**: Create `BroadcastOrders` DDB table in production.
2. **Phase 1**: Deploy backend with quick-buy endpoints (behind feature flag `BROADCAST_QUICK_BUY_ENABLED`).
3. **Phase 2**: Deploy frontend with QuickBuyDialog. Enable flag for 10% of sessions (A/B test).
4. **Phase 3**: Enable for all sessions. Monitor for 48 hours.
5. **Phase 4**: Remove feature flag.

### 7.3 Rollback Steps

- **If payment issues discovered**: Disable quick-buy feature flag. Existing orders remain in DDB. No refund logic needed (orders are billing ledger entries, not actual Stripe charges in dev mode).
- **Frontend rollback**: Remove "Quick Buy" button from ProductShelfCard. Viewers use "Add to Cart" (standard flow) instead.
- **Backend rollback**: Remove quick-buy endpoint. Orders table remains (read-only for analytics).

### 7.4 Zero-Downtime Deployment

- New DDB table created independently.
- New endpoints are additive to `broadcast.py`.
- No changes to existing order system or billing system.
- Frontend changes bundled in Vite build.

---

## 8. Operational Runbook

### 8.1 Key Metrics

| Metric | Description | Source |
|--------|-------------|--------|
| `broadcast.quickbuy.orders_created` | Counter of successful quick-buy orders | Endpoint |
| `broadcast.quickbuy.revenue_cents` | Total revenue from quick-buy (sum of total_cents) | Endpoint |
| `broadcast.quickbuy.latency_ms` | P50/P95/P99 for quick-buy endpoint | Middleware |
| `broadcast.quickbuy.pm_validation_failures` | Counter of 400 errors (invalid PM) | Endpoint |
| `broadcast.quickbuy.session_not_live` | Counter of 403 errors (not live) | Endpoint |
| `broadcast.quickbuy.idempotency_hits` | Counter of deduplicated orders | Service |
| `broadcast.quickbuy.conversion_rate` | Orders / shelf product views | Computed |

### 8.2 Alerting Thresholds

| Alert | Threshold | Action |
|-------|-----------|--------|
| Quick-buy P99 > 1000ms | 5 consecutive minutes | Check DDB throttling, billing table |
| PM validation failure rate > 30% | 5 minutes | Check billing table consistency |
| Order creation error rate > 5% | 2 minutes | Check DDB writes, counter lock |
| Purchase counter divergence (memory vs DDB) > 10 | Informational | Investigate counter persistence |

### 8.3 Common Debugging

**Problem: Quick-buy returns 400 "Payment method not found"**
1. Verify PM exists in billing table: `pk=USER#{buyer_id}, sk=PM#{pm_id}`
2. Check that `buyer_id` matches the authenticated user (not a stale session)
3. Verify PM was not deleted between dialog open and purchase submit

**Problem: Purchase counter shows 0 after server restart**
1. Check DDB session record for `purchase_count` and `purchase_total_cents`
2. The stats endpoint falls back to DDB if in-memory counter is 0
3. If DDB counter is also 0, count orders via BySession GSI

**Problem: Duplicate orders despite idempotency key**
1. Check that `idempotency_key` is being sent in the request
2. Verify the key format includes `Date.now()` (not just session+item)
3. Check ByBuyer GSI scan limit (50) is sufficient for the buyer's order volume

### 8.4 Log Patterns

```
# Successful quick-buy
INFO broadcast.quickbuy session_id=sess_abc buyer_id=user_123 order_id=bord_xyz total_cents=2999

# PM validation failure
WARN broadcast.quickbuy session_id=sess_abc buyer_id=user_123 error=pm_not_found pm_id=pm_999

# Idempotency dedup
INFO broadcast.quickbuy session_id=sess_abc buyer_id=user_123 idempotency_hit=true existing_order=bord_xyz

# Counter persist failure (non-critical)
WARN broadcast.quickbuy session_id=sess_abc error=counter_persist_failed
```

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput During Peak Broadcast

For a popular broadcast with 10,000 concurrent viewers and a 5% purchase rate:

| Operation | Rate | DDB Impact |
|-----------|------|------------|
| Quick-buy orders | 500 orders / hour (peak: 50/min burst) | 1 WCU per order (~1KB) + 1 WCU for ledger |
| Stats queries | 1 per minute (broadcaster dashboard) | 1 RCU |
| SSE event fan-out | 1 event per order × 10,000 subscribers | In-memory only |

This is well within DDB on-demand capacity (single partition can handle 1000 WCU).

### 9.2 Latency Budget for Quick-Buy (< 500ms target)

| Step | Target | Measured (DDB local) |
|------|--------|---------------------|
| Session lookup | < 20ms | ~10ms |
| Shelf item lookup | < 20ms | ~10ms |
| PM validation | < 20ms | ~10ms |
| Idempotency check (50-item scan) | < 50ms | ~30ms |
| Order write | < 20ms | ~10ms |
| Billing ledger write | < 20ms | ~10ms |
| Counter update (in-memory) | < 1ms | ~0.1ms |
| Counter persist (DDB) | < 20ms (async-ish) | ~10ms |
| SSE publish | < 5ms | ~1ms |
| **Total** | **< 200ms** | **~90ms** |

Client-side latency includes network round-trip (~50-200ms) and React state updates (~10ms), giving a total user-perceived latency of 150-400ms. Well within the 500ms target.

### 9.3 Hot Partition Analysis

- **BroadcastOrders table**: Orders are distributed across `order_id` partitions (unique UUID). No hot partition risk.
- **BySession GSI**: All orders for a single broadcast go to the same GSI partition. For 500 orders/hour, this is ~0.14 WCU average. No risk.
- **ByBuyer GSI**: A single viewer buying 10 items generates 10 entries. No risk.
- **Billing table**: Ledger entries are distributed across `USER#{buyer_id}` partitions. No hot partition risk unless a single viewer makes hundreds of purchases (capped at 10 per transaction).

### 9.4 WebSocket/SSE Fan-out Scaling

The `purchase:completed` SSE event is published to all session subscribers. For 10,000 concurrent viewers, this means 10,000 queue pushes per purchase event. The current in-memory implementation handles this in ~10ms (10,000 * 1us per `put_nowait`).

For production with multiple backend instances, use Redis pub/sub as the event bus (same recommendation as LCOM-001).

---

## 10. Dependency Analysis

### 10.1 LCOM Ticket Chain

- **LCOM-001 (Shelf)** -> **LCOM-003 (Quick-Buy)**: The quick-buy endpoint reads the shelf item to get the price. Without LCOM-001, there are no products to buy.
- **LCOM-002 (Chat Links)** -> **LCOM-003 (Quick-Buy)**: The "Buy Now" button on ProductLinkCard in chat will invoke the quick-buy flow. Without LCOM-003, the button redirects to the standard checkout.
- **LCOM-003 (Quick-Buy)** -> **LCOM-004 (Exclusive Pricing)**: LCOM-004 modifies the price resolution in the quick-buy endpoint to prefer `broadcast_price_cents` when available.

### 10.2 Integration with Existing Systems

| System | Integration | Direction |
|--------|------------|-----------|
| Billing (`billing_shared.py`) | PM validation, ledger writes | LCOM-003 reads/writes billing table |
| Product Shelf (LCOM-001) | Shelf item lookup for price | LCOM-003 reads shelf table |
| Broadcast SSE (`broadcast_sse.py`) | Purchase event publishing | LCOM-003 writes to SSE bus |
| Broadcast Sessions (`broadcast_store.py`) | Session status check, counter persistence | LCOM-003 reads/writes session record |

---

## 11. Acceptance Criteria

### 11.1 Functional

1. Viewer can purchase a product from the broadcast shelf without leaving the player.
2. Purchase creates an order record in the BroadcastOrders table.
3. Purchase creates a billing ledger debit entry for the buyer.
4. Purchase counter increments and is visible to the broadcaster in real time.
5. Idempotency key prevents duplicate orders on double-click.
6. Purchase is only available during live broadcasts (403 otherwise).
7. Payment method is validated before creating the order.
8. Viewer can see their broadcast purchase history via `/purchases/mine`.
9. Broadcaster can see session purchase stats and order history.

### 11.2 Non-Functional

1. Quick-buy endpoint responds in < 500ms P95.
2. SSE purchase event delivered within 200ms of order creation.
3. No DDB throttling during simulated 50 orders/minute burst.
4. All 24 E2E tests pass with 0 flakes on 3 consecutive runs.

---

## 12. Error Handling Matrix

| Error | HTTP Status | Error Code | User Message | Recovery Action |
|-------|-------------|-----------|--------------|----------------|
| Session not live | 403 | BROADCAST_NOT_LIVE | "Purchases are only available during live broadcasts." | Wait for session to go live |
| Product not on shelf | 404 | (default) | "Product not on shelf." | Refresh shelf |
| Payment method not found | 400 | (default) | "Payment method not found." | Add PM in Billing |
| Idempotency conflict | 200 | (none) | Returns existing order silently | No action needed |
| Session not found | 404 | (default) | "Broadcast session not found." | Check session ID |
| Quantity out of range | 422 | VALIDATION_ERROR | "Quantity must be between 1 and 10." | Adjust quantity |
| DDB write failure | 500 | INTERNAL_ERROR | "Purchase failed. Please try again." | Retry |
| Billing ledger write failure | 500 | INTERNAL_ERROR | "Purchase failed. Please try again." | Retry (order not created on failure) |
| Broadcast ended mid-purchase | 403 | BROADCAST_NOT_LIVE | "Purchases are only available during live broadcasts." | Purchase window closed |
| Viewer not authenticated | 401 | (default) | "Authentication required." | Log in |

---

## 13. Analytics & Attribution

### 13.1 Purchase Attribution

Every order in the `BroadcastOrders` table includes `session_id`, enabling direct attribution of revenue to specific broadcasts. The analytics pipeline can compute:

- Revenue per broadcast session
- Conversion rate (orders / unique viewers)
- Average order value
- Top-selling products per session
- Purchase velocity over time (orders per minute during the broadcast)

### 13.2 Conversion Funnel Tracking

```
Broadcast Started (session_id)
    │
    ▼
Shelf Viewed (viewer opens shelf panel)
    │
    ▼
Product Viewed (viewer sees specific product card)
    │
    ▼
Quick Buy Clicked (dialog opened)
    │
    ▼
Purchase Completed (order created)
```

### 13.3 A/B Test Hooks

- **Quick Buy vs Add to Cart**: Feature flag to show only "Quick Buy" or both buttons. Measure conversion difference.
- **One-click vs confirmation**: Feature flag to skip the QuickBuyDialog and purchase immediately (one-click) vs showing the dialog (two-click). Measure abandonment at dialog step.
- **Purchase counter visibility**: Show/hide the purchase counter for viewers (social proof A/B test).

---

## Appendix A: API Reference Summary

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/broadcast/sessions/{id}/quick-buy` | Any viewer | One-click purchase |
| GET | `/broadcast/sessions/{id}/purchases/stats` | Session creator | Purchase analytics |
| GET | `/broadcast/sessions/{id}/purchases` | Session creator | Order history for session |
| GET | `/broadcast/purchases/mine` | Any viewer | Viewer's own broadcast purchases |

## Appendix B: Billing Ledger Entry Format

```python
{
    "pk": "USER#{buyer_id}",
    "sk": "LEDGER#{uuid}",
    "amount_cents": -4999,           # negative = debit
    "currency": "USD",
    "reason": "Broadcast purchase: Winter Jacket",
    "reference_id": "bord_abc123",   # links to broadcast order
    "reference_type": "broadcast_order",
    "created_at": 1716580123,
}
```

## Appendix C: Related Tickets

- **LCOM-001**: Broadcast product shelf (prerequisite — products must be on shelf)
- **LCOM-002**: Chat product links (ProductLinkCard "Buy Now" button uses this quick-buy flow)
- **LCOM-004**: Broadcast-exclusive pricing (quick-buy uses `broadcast_price_cents` when available)

---

## Codebase References

| File | Lines | What was verified |
|------|-------|-------------------|
| `scripts/local-ddb-init.py` | 118, 125 | Orders and order_items table definitions confirmed |
| `app/services/billing_shared.py` | 16, 20, 25, 62, 76 | Billing helpers confirmed: `user_pk`, `ddb_get`, `ddb_put`, `ensure_balance_row`, `apply_balance_delta` |
| `app/models.py` | 419, 443, 451 | `PurchaseMoneyIn`, `PurchaseTransactionIn`, `PurchaseTransactionSummary` confirmed |
| `app/services/broadcast_sse.py` | 29 | `broadcast_sse_publish` confirmed |
| `app/services/broadcast_product_shelf.py` | -- | Exists (~441 lines); has `resolve_effective_price` (line 225+) and `get_shelf_product_raw` |
| `app/routers/broadcast.py` | 1465 | Imports `get_shelf_product_raw` and `resolve_effective_price` from shelf service |
| `app/routers/broadcast.py` | 76 | Router prefix `/broadcast`; ~3969 lines total |
| `app/core/settings.py` | 1152 | `broadcast_product_shelf_table_name` confirmed |
| `app/core/tables.py` | 83 | `broadcast_product_shelf` handle confirmed |
| `frontend/src/pages/shop/Checkout.tsx` | -- | Exists (standard checkout flow) |
| `frontend/src/pages/shop/Cart.tsx` | -- | Exists |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | -- | Exists |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | -- | Exists |
| `app/services/broadcast_orders.py` | -- | **Does not exist yet** -- new implementation required |
| `frontend/src/pages/broadcast/QuickBuyDialog.tsx` | -- | **Does not exist yet** -- new component required |
| `frontend/src/pages/broadcast/PurchaseCounter.tsx` | -- | **Does not exist yet** -- new component required |

---

## Testing Strategy

### Unit Tests (`tests/test_broadcast_orders.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_create_order_success` | Create order success |
| 2 | `test_create_order_with_quantity` | Create order with quantity |
| 3 | `test_writes_billing_ledger` | Writes billing ledger |
| 4 | `test_idempotency_returns_same` | Idempotency returns same |
| 5 | `test_invalid_pm_raises_400` | Invalid pm raises 400 |
| 6 | `test_purchase_counter_increments` | Purchase counter increments |
| 7 | `test_list_session_orders` | List session orders |
| 8 | `test_list_buyer_orders` | List buyer orders |
| 9 | `test_order_out_coerces_decimals` | Order out coerces decimals |
| 10 | `test_counter_reset` | Counter reset |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/broadcast-quick-buy.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~24 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

**Negative/Edge Tests**: 401 without auth, 403 for wrong role, 404 for missing resources, 409 for conflicts, 422 for validation errors.

### Test Data Requirements
- Test users: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- Session seeding: `python3 e2e_admin_session_setup.py` before test run

### CI/Pipeline
- Feature flags: `BROADCAST_QUICK_BUY_ENABLED=true`
- Tests run serially (single Playwright worker, `workers: 1`)
- Retry safety: 1 retry configured; tests use unique timestamps (`Date.now()`) for isolation
- Run: `cd frontend && npx playwright test e2e/<spec-file>`

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What It Provides | Hard/Soft |
|--------|-----------------|-----------|
| LCOM-001 | Broadcast Product Shelf for price lookup | Hard |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| LCOM-004 | Exclusive Pricing modifies price resolution in quick-buy |

### Merge Strategy
**Sequential -- requires LCOM-001 merged first. Quick-buy reads shelf item price_cents. Feature-flag-gated behind BROADCAST_QUICK_BUY_ENABLED.**

### Merge Checklist
- [ ] Feature flags configured in `.env.local`: BROADCAST_QUICK_BUY_ENABLED=true
- [ ] Service file created/modified: `app/services/broadcast_orders.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/broadcast-quick-buy.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_broadcast_orders.py`
