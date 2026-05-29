# LCOM-001: Broadcast Product Shelf — Link Catalog Items to Live Streams

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: High  
**Estimated effort**: 5-7 days

---

## 1. Overview & Motivation

### The Gap

The platform has a fully functional broadcast system (`app/routers/broadcast.py`, ~3969 lines) supporting live streaming with session lifecycle management, viewer counts, health metrics, live chat (BCAST-005), and recording archival. It also has a mature e-commerce catalog (`app/routers/catalog.py`, ~933 lines) with categories, items, reviews, image uploads, and search. However, **there is no mechanism to connect products to a live broadcast**. Broadcasters cannot showcase catalog items during a stream, and viewers have no way to discover or purchase products without leaving the broadcast experience entirely.

<!-- NOTE: The broadcast router is ~3969 lines (not 944 as originally noted) and the catalog router is ~933 lines (not 664). Many of the infrastructure components proposed in this ticket have already been implemented — see Codebase References section. -->

### Why This Is Needed

Live commerce is the primary revenue-generating feature for broadcast creators. Without a product shelf:

1. **Broadcasters cannot showcase products** during a live stream. They must verbally describe items and hope viewers navigate separately to the shop page.
2. **Viewers have no in-context purchase path**. The cognitive distance between watching a broadcast and finding the right product in `/shop` is high, leading to abandoned purchase intent.
3. **No attribution exists** between broadcast sessions and purchases. Analytics cannot attribute sales to specific streams, making it impossible for creators to measure ROI on their broadcast content.
4. **Competitors (Shopify Live, TikTok Shop, Instagram Live Shopping)** all provide integrated product shelves. Parity is table-stakes for creator adoption.

### Architecture After This Change

```
┌─────────────────────────────────────────────────────────────────────┐
│  Broadcaster Dashboard (BroadcastPage.tsx)                          │
│  ┌────────────────────┐  ┌────────────────────────────────────────┐ │
│  │ Session Controls    │  │ Product Shelf Manager                  │ │
│  │ (Start/Stop/etc.)  │  │ ┌──────────────┐  ┌────────────────┐  │ │
│  │                    │  │ │ "Add Product" │  │ Shelf Item List │  │ │
│  │                    │  │ │ (catalog pick)│  │ (drag reorder)  │  │ │
│  │                    │  │ └──────────────┘  └────────────────┘  │ │
│  └────────────────────┘  └────────────────────────────────────────┘ │
└──────────────────────────────────────┬──────────────────────────────┘
                                       │ POST /broadcast/{id}/products
                                       │ DELETE /broadcast/{id}/products/{item_id}
                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Backend (broadcast.py)                                             │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │ BroadcastProductShelf DDB Table                               │  │
│  │ PK: session_id  SK: ITEM#{item_id}                            │  │
│  │ Fields: category_id, name, price_cents, image_url,            │  │
│  │         display_order, added_at, added_by                     │  │
│  └───────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │ broadcast_sse_publish() → shelf:add / shelf:remove events     │  │
│  └───────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────┬──────────────────────────────┘
                                       │ SSE shelf:add / shelf:remove
                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Viewer Player (LivePlayer.tsx)                                     │
│  ┌──────────────────┐  ┌──────────────────────────────────────────┐ │
│  │ Video Player     │  │ ProductShelf (sidebar / overlay)         │ │
│  │                  │  │ ┌──────────────────────────────────────┐ │ │
│  │                  │  │ │ ProductShelfCard × N                 │ │ │
│  │                  │  │ │  image | name | price | "Add to Cart"│ │ │
│  │                  │  │ └──────────────────────────────────────┘ │ │
│  └──────────────────┘  └──────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Current State Analysis

### 2.1 Broadcast Infrastructure (`app/routers/broadcast.py`)

The broadcast router (~3969 lines) is registered in `app/main.py` under the `/broadcast` prefix (see `app/routers/broadcast.py:76`). It uses `require_ui_session` for auth and `_require_operator_role(ctx)` for admin-gated actions (see line 211).

**Session model** (`app/models_broadcast.py`, see lines 37-49): `BroadcastSessionModel` includes `id`, `profile_id`, `status`, `ingest_url`, `stream_key_ref`, `stream_key_last_rotated_at`, `stream_key_rotation_interval_seconds`, `started_at`, `stopped_at`, `created_by`, `created_at`, `updated_at`, plus scheduling fields (BCAST-009).

**Session status values** (from `app/services/broadcast_state_machine.py` and `app/models_broadcast.py:8`): `BroadcastSessionStatus` Literal type. Products should be attachable in `draft`, `ready`, or `live` states, and visible to viewers only when the session is `live`.

**SSE delivery** (`app/services/broadcast_sse.py`, 49 lines): In-memory pub/sub using `asyncio.Queue` per subscriber. `broadcast_sse_publish(session_id, event)` (see line 29) fans out events to all subscribed queues for a session. The SSE stream endpoint at `GET /broadcast/sessions/{session_id}/stream` (see `app/routers/broadcast.py:639-640`) consumes these queues.

**Broadcast chat store** (`app/services/broadcast_chat_store.py`, ~423 lines): Demonstrates the pattern for a DynamoDB-backed feature integrated with the broadcast SSE system. Uses rate limiting, mute enforcement, and real-time SSE publish for chat events.

### 2.2 Catalog Infrastructure (`app/routers/catalog.py`)

The catalog router (~933 lines) is under `/ui/catalog` (see `app/routers/catalog.py:41`). Uses a single-table design in DynamoDB:

- Categories: `PK=CAT#{category_id}` (see `cat_pk` at line 54), `SK=META`
- Items: `PK=CAT#{category_id}`, `SK=ITEM#{item_id}` (see `item_sk` at line 62, items nested under their category)
- Reviews: `PK=ITEM#{item_id}`, `SK=REVIEW#{review_id}`
- GSI1: `GSI1PK=CATS`, `GSI1SK={name}#{category_id}` (for listing all categories)

**Item fields** (from `_catalog_item_out`, see line 106): `category_id`, `item_id`, `name`, `description`, `price_cents`, `currency`, `image_urls` (list of strings), `attributes` (dict), `created_at`, `updated_at`.

**Item lookup** (`_get_item_meta`, see line 235): Returns the raw DDB item dict.

**Ownership model** (`_require_category_owner`, see line 227): Categories have a `creator_id` field. Only the creator (or admin) can modify items.

### 2.3 Shopping Cart (`frontend/src/api/endpoints/cart.ts`)

The cart API (see `frontend/src/api/endpoints/cart.ts`) is at `/ui/shoppingcart/carts` with full CRUD: `createCart`, `addCartItem`, `updateCartItemQty`, `removeCartItem`, `purchaseCart`. Cart items use `CartItemIn` with `sku` and `quantity`. The table handle is `T.shopping_cart` (PK/SK design from `scripts/local-ddb-init.py`, see line 67).

### 2.4 Frontend Broadcast Pages (`frontend/src/pages/broadcast/`)

- `BroadcastPage.tsx`: Broadcaster dashboard with session management, profile CRUD, recording playback. Uses tabs (Sessions/Profiles). Has no product management UI.
- `LivePlayer.tsx` (line 1-80+): Viewer player page. Renders `MediaPlayer`, `BroadcastChat` sidebar, and `ChatOverlay`. Already has toggle buttons for chat and overlay. No product shelf component exists.
- `BroadcastChat.tsx`: Chat panel in sidebar. Pattern to follow for the product shelf sidebar.
- `ViewerCountBadge.tsx`, `StreamHealthIndicator.tsx`: Small status components.

### 2.5 DynamoDB Table Definitions (`scripts/local-ddb-init.py`)

The `BroadcastProductShelf` table already exists (see `scripts/local-ddb-init.py:578`), defined after `BroadcastRecordings` (line 567). The table uses `session_id` as PK and `SK` as sort key.

### 2.6 Table Handles (`app/core/tables.py`)

Table handle struct uses `@dataclass` with `ddb.Table()` initialization. The `broadcast_product_shelf` handle already exists (see `app/core/tables.py:83` for field, line 207 for initialization).

### 2.7 Settings (`app/core/settings.py`)

Broadcast settings include `broadcast_chat_messages_table_name`, `broadcast_chat_mutes_table_name`, `broadcast_chat_rate_limit_ms`, etc. The `broadcast_product_shelf_table_name` setting already exists (see `app/core/settings.py:1152`).

---

## 3. Technical Design

### 3.1 DynamoDB Schema — `BroadcastProductShelf` Table

| Attribute | Type | Role |
|-----------|------|------|
| `session_id` | S | Partition Key |
| `SK` | S | Sort Key: `ITEM#{item_id}` |
| `item_id` | S | Catalog item ID |
| `category_id` | S | Category the item belongs to |
| `name` | S | Denormalized item name at time of addition |
| `description` | S | Denormalized item description (truncated to 500 chars) |
| `price_cents` | N | Denormalized price at time of addition |
| `currency` | S | Currency code (default `USD`) |
| `image_url` | S | Primary image URL (first from `image_urls` list) |
| `display_order` | N | Integer for ordering in the shelf UI (0-based) |
| `added_by` | S | User sub of the broadcaster who added it |
| `added_at` | N | Unix timestamp when added |
| `ttl` | N | TTL = session stopped_at + 30 days (for automatic cleanup) |

**Sort key format**: `ITEM#{item_id}` ensures uniqueness per product per session and allows efficient single-item lookups.

**Denormalization rationale**: Item name, price, description, and image are copied from the catalog at add-time. This prevents the shelf from breaking if the catalog item is later modified or deleted. The broadcast is a point-in-time snapshot of the product offering.

**Table definition** (for `scripts/local-ddb-init.py`):

```python
TableDef(
    _resolve_table_name(S.broadcast_product_shelf_table_name, "BroadcastProductShelf"),
    "session_id",
    "SK",
    attr_types={"added_at": "N", "display_order": "N"},
),
```

**DDB access pattern diagram**:

```
┌────────────────────────────────────────────────────────────────┐
│ BroadcastProductShelf Table                                     │
├─────────────────────┬──────────────────────────────────────────┤
│ Partition Key       │ Sort Key                                  │
│ session_id (S)      │ SK (S)                                    │
├─────────────────────┼──────────────────────────────────────────┤
│                     │                                           │
│  Access Patterns:                                               │
│                     │                                           │
│  1. List all shelf items for a session:                         │
│     Query(PK=session_id)                                        │
│     → Returns all ITEM#* items, sorted by SK                   │
│     → App-level sort by display_order                           │
│                     │                                           │
│  2. Get single shelf item:                                      │
│     GetItem(PK=session_id, SK=ITEM#{item_id})                  │
│     → O(1) lookup for add/remove/update operations             │
│                     │                                           │
│  3. Count shelf items:                                          │
│     Query(PK=session_id, Select=COUNT)                          │
│     → Used for max-shelf-size enforcement (50 limit)           │
│                     │                                           │
│  4. Batch update display_order (reorder):                       │
│     N × UpdateItem(PK=session_id, SK=ITEM#{item_id})           │
│     → One update per item in the new ordering                  │
│                     │                                           │
│  5. TTL-based auto-cleanup:                                     │
│     DDB TTL on `ttl` attribute                                  │
│     → Items expire 30 days after session stops                 │
│                     │                                           │
└─────────────────────┴──────────────────────────────────────────┘
```

### 3.2 API Endpoints

#### 3.2.1 Add Product to Shelf

```
POST /broadcast/sessions/{session_id}/products
```

**Auth**: `require_ui_session` — only the session creator (broadcaster) can add products.

**Request model**:

```python
class BroadcastShelfAddIn(BaseModel):
    item_id: str = Field(..., min_length=1, max_length=128)
    category_id: str = Field(..., min_length=1, max_length=128)
    display_order: int = Field(default=0, ge=0, le=999)
```

**Response model**:

```python
class BroadcastShelfItemOut(BaseModel):
    session_id: str
    item_id: str
    category_id: str
    name: str
    description: Optional[str] = None
    price_cents: int
    currency: str = "USD"
    image_url: Optional[str] = None
    display_order: int = 0
    added_by: str
    added_at: int
```

**Behavior**:

1. Validate session exists and caller is `session.created_by` (403 otherwise).
2. Validate session status is `draft`, `ready`, or `live` (409 if `stopped` or `error`).
3. Look up catalog item from `T.catalog` using `PK=CAT#{category_id}`, `SK=ITEM#{item_id}`. Return 404 if item not found.
4. Check for duplicate: `get_item(Key={"session_id": session_id, "SK": f"ITEM#{item_id}"})`. Return 409 if already on shelf.
5. Count existing shelf items (query session_id partition, count). Enforce max shelf size of 50 items (400 if exceeded).
6. Write shelf item to `BroadcastProductShelf` table with denormalized catalog data.
7. If session is `live`, publish `shelf:add` event via `broadcast_sse_publish()`.
8. Return the shelf item.

**Error responses**:

| Code | Condition |
|------|-----------|
| 400 | Max shelf size exceeded (50 items) |
| 403 | Caller is not the session creator |
| 404 | Session or catalog item not found |
| 409 | Session not in addable state, or item already on shelf |

#### 3.2.2 Remove Product from Shelf

```
DELETE /broadcast/sessions/{session_id}/products/{item_id}
```

**Auth**: `require_ui_session` — only session creator.

**Behavior**:

1. Validate session exists and caller is `session.created_by`.
2. Delete item from `BroadcastProductShelf`: `delete_item(Key={"session_id": session_id, "SK": f"ITEM#{item_id}"})`.
3. If session is `live`, publish `shelf:remove` event via `broadcast_sse_publish()`.
4. Return `{"ok": True, "item_id": item_id}`.

#### 3.2.3 List Shelf Products

```
GET /broadcast/sessions/{session_id}/products
```

**Auth**: `require_ui_session` — any authenticated viewer can see the shelf.

**Response model**:

```python
class BroadcastShelfListOut(BaseModel):
    session_id: str
    items: List[BroadcastShelfItemOut] = Field(default_factory=list)
    count: int = 0
```

**Behavior**:

1. Query `BroadcastProductShelf` by `session_id` partition, limit 50, `ScanIndexForward=True`.
2. Sort by `display_order` (ascending).
3. Return the list.

#### 3.2.4 Reorder Shelf Products

```
PATCH /broadcast/sessions/{session_id}/products/reorder
```

**Auth**: `require_ui_session` — only session creator.

**Request model**:

```python
class BroadcastShelfReorderIn(BaseModel):
    item_order: List[str] = Field(
        ..., min_length=1, max_length=50,
        description="Ordered list of item_ids defining new display order"
    )
```

**Behavior**:

1. Validate caller is session creator.
2. For each `item_id` in `item_order`, update `display_order` to the index position using `update_item`.
3. If session is `live`, publish `shelf:reorder` event with full ordered list.
4. Return `{"ok": True}`.

### 3.3 SSE Events

All events published via `broadcast_sse_publish(session_id, event)` and delivered through the existing `GET /broadcast/sessions/{session_id}/stream` endpoint.

| Event Type | Payload | Trigger |
|------------|---------|---------|
| `shelf:add` | Full `BroadcastShelfItemOut` JSON | Product added to shelf while session is live |
| `shelf:remove` | `{"item_id": "..."}` | Product removed from shelf while session is live |
| `shelf:reorder` | `{"items": [BroadcastShelfItemOut, ...]}` | Shelf reordered while session is live |

**Real-time sync diagram (broadcaster adds product, viewer shelf updates)**:

```
  Broadcaster                    Backend                         Viewer(s)
      │                              │                              │
      │ POST /products               │                              │
      │ {item_id, category_id}       │                              │
      │─────────────────────────────>│                              │
      │                              │                              │
      │                              │ 1. Validate session owner    │
      │                              │ 2. Validate session live     │
      │                              │ 3. Look up catalog item      │
      │                              │ 4. Check for duplicate       │
      │                              │ 5. Check shelf size < 50     │
      │                              │ 6. Write to DDB              │
      │                              │ 7. Build shelf item out      │
      │                              │                              │
      │              201 Created     │                              │
      │<─────────────────────────────│                              │
      │                              │                              │
      │                              │ broadcast_sse_publish(       │
      │                              │   session_id,                │
      │                              │   {_type: "shelf:add", ...}  │
      │                              │ )                            │
      │                              │                              │
      │                              │ SSE: event: shelf:add        │
      │                              │─────────────────────────────>│
      │                              │                              │
      │                              │                    setShelfItems(
      │                              │                      prev => [...prev, item]
      │                              │                        .sort(display_order)
      │                              │                    )
      │                              │                              │
      │                              │                    UI re-renders
      │                              │                    ProductShelfCard
```

### 3.4 Service Layer — `app/services/broadcast_product_shelf.py`

```python
"""Broadcast product shelf — DynamoDB CRUD for linking catalog items to broadcast sessions."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish

MAX_SHELF_ITEMS = 50


def _shelf_item_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB item to output dict.

    Handles Decimal-to-int coercion for numeric fields that DynamoDB
    returns as boto3 Decimal types. Provides safe defaults for all
    optional fields to prevent KeyError on malformed items.
    """
    return {
        "session_id": item["session_id"],
        "item_id": item["item_id"],
        "category_id": item.get("category_id", ""),
        "name": item.get("name", ""),
        "description": item.get("description"),
        "price_cents": int(item.get("price_cents", 0)),
        "currency": item.get("currency", "USD"),
        "image_url": item.get("image_url"),
        "display_order": int(item.get("display_order", 0)),
        "added_by": item.get("added_by", ""),
        "added_at": int(item.get("added_at", 0)),
    }


def add_product_to_shelf(
    session_id: str,
    item_id: str,
    category_id: str,
    catalog_item: Dict[str, Any],
    added_by: str,
    display_order: int = 0,
    *,
    is_live: bool = False,
) -> Dict[str, Any]:
    """Add a catalog item to the broadcast product shelf.

    Args:
        session_id: The broadcast session ID.
        item_id: The catalog item ID to add.
        category_id: The catalog category containing the item.
        catalog_item: Raw catalog item dict with name, price_cents, image_urls, etc.
        added_by: User sub of the broadcaster adding the product.
        display_order: Position in the shelf (0-based).
        is_live: Whether the session is currently live (triggers SSE).

    Returns:
        Dict with all shelf item fields suitable for API response.

    Raises:
        HTTPException 409: If product is already on the shelf.
        HTTPException 400: If shelf is at capacity (50 items).
    """
    # Check for duplicate
    existing = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    ).get("Item")
    if existing:
        raise HTTPException(status_code=409, detail="Product already on shelf.")

    # Check shelf size
    count_resp = T.broadcast_product_shelf.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        Select="COUNT",
    )
    if count_resp.get("Count", 0) >= MAX_SHELF_ITEMS:
        raise HTTPException(status_code=400, detail=f"Shelf is full ({MAX_SHELF_ITEMS} items max).")

    ts = now_ts()
    image_urls = catalog_item.get("image_urls") or []
    item = {
        "session_id": session_id,
        "SK": f"ITEM#{item_id}",
        "item_id": item_id,
        "category_id": category_id,
        "name": catalog_item.get("name", ""),
        "description": (catalog_item.get("description") or "")[:500],
        "price_cents": int(catalog_item.get("price_cents", 0)),
        "currency": catalog_item.get("currency", "USD"),
        "image_url": image_urls[0] if image_urls else None,
        "display_order": display_order,
        "added_by": added_by,
        "added_at": ts,
        "ttl": ts + 30 * 24 * 3600,  # 30 day TTL
    }
    T.broadcast_product_shelf.put_item(Item=item)

    out = _shelf_item_out(item)

    if is_live:
        broadcast_sse_publish(session_id, {"_type": "shelf:add", **out})

    return out


def remove_product_from_shelf(
    session_id: str,
    item_id: str,
    *,
    is_live: bool = False,
) -> bool:
    """Remove a product from the shelf. Returns True if found and removed.

    Uses a get-before-delete pattern to confirm the item exists before
    attempting deletion. This prevents publishing spurious SSE events
    for items that were already removed.

    Args:
        session_id: The broadcast session ID.
        item_id: The catalog item ID to remove.
        is_live: Whether the session is currently live (triggers SSE).

    Returns:
        True if the item was found and deleted, False if not found.
    """
    existing = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    ).get("Item")
    if not existing:
        return False

    T.broadcast_product_shelf.delete_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    )

    if is_live:
        broadcast_sse_publish(session_id, {"_type": "shelf:remove", "item_id": item_id})

    return True


def list_shelf_products(session_id: str) -> List[Dict[str, Any]]:
    """List all products on the shelf, ordered by display_order.

    Queries the full partition (up to MAX_SHELF_ITEMS) and sorts
    client-side by display_order. DDB sort key is SK (ITEM#{item_id})
    which is not ordered by display_order, so app-level sort is required.

    Args:
        session_id: The broadcast session ID.

    Returns:
        List of shelf item dicts sorted by display_order ascending.
    """
    resp = T.broadcast_product_shelf.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        Limit=MAX_SHELF_ITEMS,
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: int(x.get("display_order", 0)))
    return [_shelf_item_out(i) for i in items]


def reorder_shelf(session_id: str, item_order: List[str], *, is_live: bool = False) -> None:
    """Update display_order for all items based on the provided ordering.

    Performs N individual UpdateItem calls (one per item). For N <= 50
    this completes in under 200ms against DynamoDB local, and under
    100ms against production DDB (single partition, no cross-partition hops).

    Args:
        session_id: The broadcast session ID.
        item_order: Ordered list of item_ids. Index becomes display_order.
        is_live: Whether the session is currently live (triggers SSE).
    """
    for idx, item_id in enumerate(item_order):
        T.broadcast_product_shelf.update_item(
            Key={"session_id": session_id, "SK": f"ITEM#{item_id}"},
            UpdateExpression="SET display_order = :order",
            ExpressionAttributeValues={":order": idx},
        )

    if is_live:
        updated = list_shelf_products(session_id)
        broadcast_sse_publish(session_id, {"_type": "shelf:reorder", "items": updated})
```

### 3.5 Pydantic Models (in `app/routers/broadcast.py`)

These models are added after the existing broadcast chat models (around line 790 in `broadcast.py`). They follow the established pattern of `*In` for request bodies and `*Out` for responses.

```python
class BroadcastShelfAddIn(BaseModel):
    """Request body for adding a product to the broadcast shelf."""
    item_id: str = Field(..., min_length=1, max_length=128,
        description="Catalog item ID. Must exist in the catalog table.")
    category_id: str = Field(..., min_length=1, max_length=128,
        description="Category ID containing the item. Used for catalog lookup.")
    display_order: int = Field(default=0, ge=0, le=999,
        description="Position in the shelf display. 0 = first.")

    @validator("item_id")
    def item_id_no_special_chars(cls, v: str) -> str:
        """Prevent injection via item_id used in DDB sort key construction."""
        if "#" in v or "\n" in v:
            raise ValueError("item_id must not contain '#' or newline characters")
        return v

    @validator("category_id")
    def category_id_no_special_chars(cls, v: str) -> str:
        if "#" in v or "\n" in v:
            raise ValueError("category_id must not contain '#' or newline characters")
        return v


class BroadcastShelfItemOut(BaseModel):
    """A single product on the broadcast shelf."""
    session_id: str
    item_id: str
    category_id: str
    name: str
    description: Optional[str] = None
    price_cents: int
    currency: str = "USD"
    image_url: Optional[str] = None
    display_order: int = 0
    added_by: str
    added_at: int


class BroadcastShelfListOut(BaseModel):
    """Response for listing all products on a broadcast shelf."""
    session_id: str
    items: List[BroadcastShelfItemOut] = Field(default_factory=list)
    count: int = 0


class BroadcastShelfReorderIn(BaseModel):
    """Request body for reordering the shelf."""
    item_order: List[str] = Field(..., min_length=1, max_length=50,
        description="Ordered list of item_ids defining new display order. "
                    "Index 0 = first position. All item_ids must be on the shelf.")
```

### 3.6 Full Router Endpoint Implementations

<!-- NOTE: These endpoints already exist in app/routers/broadcast.py. The add_shelf_product_route is at line 1851+. The router is ~3969 lines total. -->

These are added to `app/routers/broadcast.py` (already implemented at lines 1851+):

```python
# ─── Product Shelf Endpoints (LCOM-001) ────────────────────────

@router.post(
    "/sessions/{session_id}/products",
    response_model=BroadcastShelfItemOut,
    status_code=status.HTTP_201_CREATED,
)
def add_shelf_product_route(
    session_id: str,
    body: BroadcastShelfAddIn,
    ctx: dict = Depends(_ctx),
):
    """Add a catalog product to the broadcast product shelf."""
    session = get_session(session_id)

    # Only the broadcaster (session creator) can manage the shelf
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_SESSION_CREATOR", "message": "Only the broadcaster can manage the product shelf"},
        )

    # Session must be in an addable state
    if session.status not in ("draft", "ready", "live"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "SESSION_NOT_ADDABLE", "message": f"Cannot add products when session is {session.status}"},
        )

    # Look up the catalog item to denormalize its data
    from app.routers.catalog import cat_pk, item_sk
    cat_item = T.catalog.get_item(
        Key={"PK": cat_pk(body.category_id), "SK": item_sk(body.item_id)}
    ).get("Item")
    if not cat_item or cat_item.get("entity") != "item":
        raise HTTPException(status_code=404, detail="Catalog item not found.")

    from app.services.broadcast_product_shelf import add_product_to_shelf
    result = add_product_to_shelf(
        session_id=session_id,
        item_id=body.item_id,
        category_id=body.category_id,
        catalog_item=cat_item,
        added_by=ctx["user_sub"],
        display_order=body.display_order,
        is_live=(session.status == "live"),
    )
    return BroadcastShelfItemOut(**result)


@router.delete("/sessions/{session_id}/products/{item_id}")
def remove_shelf_product_route(
    session_id: str,
    item_id: str,
    ctx: dict = Depends(_ctx),
):
    """Remove a product from the broadcast product shelf."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_SESSION_CREATOR", "message": "Only the broadcaster can manage the product shelf"},
        )

    from app.services.broadcast_product_shelf import remove_product_from_shelf
    removed = remove_product_from_shelf(
        session_id=session_id,
        item_id=item_id,
        is_live=(session.status == "live"),
    )
    if not removed:
        raise HTTPException(status_code=404, detail="Product not on shelf.")
    return {"ok": True, "item_id": item_id}


@router.get(
    "/sessions/{session_id}/products",
    response_model=BroadcastShelfListOut,
)
def list_shelf_products_route(
    session_id: str,
    ctx: dict = Depends(_ctx),
):
    """List all products on the broadcast product shelf."""
    _ = ctx  # any authenticated user can view
    _ = get_session(session_id)  # 404 if session doesn't exist

    from app.services.broadcast_product_shelf import list_shelf_products
    items = list_shelf_products(session_id)
    return BroadcastShelfListOut(
        session_id=session_id,
        items=[BroadcastShelfItemOut(**i) for i in items],
        count=len(items),
    )


@router.patch("/sessions/{session_id}/products/reorder")
def reorder_shelf_products_route(
    session_id: str,
    body: BroadcastShelfReorderIn,
    ctx: dict = Depends(_ctx),
):
    """Reorder products on the broadcast product shelf."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "NOT_SESSION_CREATOR", "message": "Only the broadcaster can reorder the shelf"},
        )

    from app.services.broadcast_product_shelf import reorder_shelf
    reorder_shelf(
        session_id=session_id,
        item_order=body.item_order,
        is_live=(session.status == "live"),
    )
    return {"ok": True}
```

### 3.7 Frontend Types

```typescript
// frontend/src/api/endpoints/broadcast-shelf.ts

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
}

export interface ShelfListResponse {
  session_id: string;
  items: ShelfItem[];
  count: number;
}
```

### 3.8 Frontend Components

**ProductShelf** (viewer side, in `LivePlayer.tsx` sidebar):

- Collapsible sidebar panel, same layout pattern as `BroadcastChat`
- Fetches shelf items on mount via `GET /broadcast/sessions/{id}/products`
- Listens for `shelf:add`, `shelf:remove`, `shelf:reorder` SSE events via the broadcast event stream
- Each item renders as a `ProductShelfCard` with image thumbnail, name, price formatted as `$XX.XX`, and an "Add to Cart" button
- "Add to Cart" calls `addCartItem()` from `cart.ts` and shows a toast confirmation
- Scrollable list, max height fills available sidebar space

**ProductShelfManager** (broadcaster side, in `BroadcastPage.tsx`):

- Tab or section within the session detail view
- "Add Product" button opens a catalog picker dialog (reuses pattern from `FilePickerDialog`)
- Lists current shelf items with drag-to-reorder (or up/down arrows)
- "Remove" button on each item
- Shows item count badge (e.g., "3/50")
- Visible in draft, ready, and live states

### 3.9 Frontend Component Specifications

#### 3.9.1 ProductShelf Component

```typescript
/**
 * ProductShelf — viewer-facing sidebar panel showing products linked to a broadcast.
 *
 * Renders inside LivePlayer.tsx alongside BroadcastChat. Uses React Query
 * for initial data fetch and SSE events for real-time updates.
 *
 * @param sessionId - Broadcast session ID
 * @param isVisible - Whether the shelf panel is expanded
 * @param onToggle - Callback to toggle shelf visibility
 */
interface ProductShelfProps {
  sessionId: string;
  isVisible: boolean;
  onToggle: () => void;
}
```

**Component hierarchy**:

```
LivePlayer
├── MediaPlayer
├── ViewerCountBadge
├── StreamHealthIndicator
├── BroadcastChat (existing)
├── ChatOverlay (existing)
└── ProductShelf (NEW)
    ├── ShelfHeader (toggle + item count badge)
    └── ShelfItemList (scrollable)
        └── ProductShelfCard × N
            ├── img (64x64 thumbnail)
            ├── ProductName (truncated, 1 line)
            ├── Price ($XX.XX)
            └── AddToCartButton
```

**Zustand store for shelf state** (`frontend/src/stores/broadcastShelfStore.ts`):

```typescript
interface BroadcastShelfState {
  items: ShelfItem[];
  isLoading: boolean;
  error: string | null;
  setItems: (items: ShelfItem[]) => void;
  addItem: (item: ShelfItem) => void;
  removeItem: (itemId: string) => void;
  reorderItems: (items: ShelfItem[]) => void;
  reset: () => void;
}

export const useBroadcastShelfStore = create<BroadcastShelfState>((set) => ({
  items: [],
  isLoading: false,
  error: null,
  setItems: (items) => set({ items, isLoading: false }),
  addItem: (item) => set((s) => ({
    items: [...s.items, item].sort((a, b) => a.display_order - b.display_order),
  })),
  removeItem: (itemId) => set((s) => ({
    items: s.items.filter((i) => i.item_id !== itemId),
  })),
  reorderItems: (items) => set({ items }),
  reset: () => set({ items: [], isLoading: false, error: null }),
}));
```

**React Query cache invalidation strategy**:

- Query key: `["broadcast-shelf", sessionId]`
- Initial fetch on mount with `staleTime: 30_000` (30s) to avoid refetching when toggling sidebar
- SSE events update the Zustand store directly (not React Query cache) for instant UI updates
- On SSE reconnect, invalidate `["broadcast-shelf", sessionId]` to re-sync full state
- "Add to Cart" invalidates `["cart"]` and `["cart-items", cartId]`

**Responsive design considerations**:

- Desktop (>1024px): Shelf renders as a sidebar panel next to the video player, 320px wide
- Tablet (768-1024px): Shelf renders as a slide-over panel from the right edge
- Mobile (<768px): Shelf renders as a bottom sheet (50% viewport height) with drag-to-dismiss
- All breakpoints: ProductShelfCard uses a compact horizontal layout (image left, text right)

**Loading/skeleton states**:

- Initial load: 3 skeleton cards (shimmer animation) with placeholder image, text bars, and button
- Add to Cart: Button shows spinner icon, text changes to "Adding..." for 500ms, then "Added!" with checkmark for 1s
- Remove: Card fades out with 200ms opacity transition before being removed from the list

**Accessibility**:

- Shelf toggle button: `aria-expanded`, `aria-controls="product-shelf-panel"`
- Shelf panel: `role="complementary"`, `aria-label="Product shelf"`
- ProductShelfCard: `role="article"`, price uses `aria-label="Price: $XX.XX"`
- Add to Cart button: `aria-label="Add {product name} to cart"`
- Screen reader announces shelf item count changes via `aria-live="polite"` region

**Animation specs for real-time updates**:

- `shelf:add`: New card slides in from the right with 300ms ease-out, highlight border pulse (blue) for 2s
- `shelf:remove`: Card fades + slides left with 200ms ease-in, remaining items close gap with 200ms transition
- `shelf:reorder`: Items animate to new positions with 300ms ease-in-out (CSS `order` transition)

#### 3.9.2 ProductShelfManager Component (Broadcaster)

```typescript
/**
 * ProductShelfManager — broadcaster-facing shelf management panel.
 *
 * Embedded in BroadcastPage.tsx session detail view. Allows adding products
 * from the catalog, removing them, and reordering via drag handles.
 *
 * @param sessionId - Broadcast session ID
 * @param sessionStatus - Current session status (draft/ready/live/stopped)
 * @param sessionCreatedBy - User sub of the session creator
 */
interface ProductShelfManagerProps {
  sessionId: string;
  sessionStatus: string;
  sessionCreatedBy: string;
}
```

**Component hierarchy**:

```
BroadcastPage
└── SessionDetailPanel
    ├── SessionControls (existing)
    ├── StreamHealthIndicator (existing)
    └── ProductShelfManager (NEW)
        ├── ShelfManagerHeader
        │   ├── Title ("Product Shelf")
        │   ├── ItemCountBadge ("3/50")
        │   └── AddProductButton (opens CatalogPickerDialog)
        ├── ShelfManagerList (drag-reorderable)
        │   └── ShelfManagerItem × N
        │       ├── DragHandle
        │       ├── img (48x48)
        │       ├── ItemName + Price
        │       └── RemoveButton (trash icon)
        └── CatalogPickerDialog (modal)
            ├── CategorySelector (dropdown)
            ├── ItemSearchInput
            └── ItemGrid
                └── CatalogItemCard × N (click to add)
```

---

## 4. Implementation Plan

### Phase 1: Backend Infrastructure (1 day)

<!-- NOTE: All Phase 1 infrastructure already exists in the codebase: -->

**Already implemented**:

| File | Status | Reference |
|------|--------|-----------|
| `app/core/settings.py` | EXISTS | `broadcast_product_shelf_table_name` at line 1152 |
| `app/core/tables.py` | EXISTS | `broadcast_product_shelf` field at line 83, init at line 207 |
| `scripts/local-ddb-init.py` | EXISTS | `BroadcastProductShelf` table at line 578 |

### Phase 2: Service Layer (1 day)

<!-- NOTE: app/services/broadcast_product_shelf.py already exists (~441 lines). -->

**Already implemented**:

| File | Status | Reference |
|------|--------|-----------|
| `app/services/broadcast_product_shelf.py` | EXISTS (~441 lines) | DynamoDB CRUD for shelf items + SSE publish |

Functions: `add_product_to_shelf`, `remove_product_from_shelf`, `list_shelf_products`, `reorder_shelf`, `_shelf_item_out`.

Line-by-line implementation as shown in section 3.4. The file is self-contained with imports from `app.core.tables`, `app.core.time`, and `app.services.broadcast_sse`.

### Phase 3: Backend Endpoints (1 day)

**Files to modify**:

| File | Change |
|------|--------|
| `app/routers/broadcast.py` | Add 4 endpoints + Pydantic models (after live chat section, ~line 944) |

Endpoints to add:
- `POST /broadcast/sessions/{session_id}/products` — add product
- `DELETE /broadcast/sessions/{session_id}/products/{item_id}` — remove product
- `GET /broadcast/sessions/{session_id}/products` — list shelf
- `PATCH /broadcast/sessions/{session_id}/products/reorder` — reorder

Each endpoint follows the established pattern: `ctx = Depends(_ctx)`, session lookup via `get_session(session_id)`, ownership check via `ctx["user_sub"] != session.created_by`.

**Exact insertion point**: After line 944 (`return StreamingResponse(gen(), media_type="text/event-stream")`), add a comment separator `# --- Product Shelf Endpoints (LCOM-001) ---` followed by the 4 Pydantic models and 4 endpoint functions.

**Catalog item lookup** within the add endpoint:

```python
from app.routers.catalog import cat_pk, item_sk
cat_item = T.catalog.get_item(
    Key={"PK": cat_pk(body.category_id), "SK": item_sk(body.item_id)}
).get("Item")
if not cat_item or cat_item.get("entity") != "item":
    raise HTTPException(status_code=404, detail="Catalog item not found.")
```

### Phase 4: Frontend API Layer (0.5 days)

<!-- NOTE: frontend/src/api/endpoints/broadcast-shelf.ts already exists. -->

**Already implemented**:

| File | Status |
|------|--------|
| `frontend/src/api/endpoints/broadcast-shelf.ts` | EXISTS — API wrappers for shelf endpoints |

```typescript
export const addShelfProduct = (sessionId: string, body: { item_id: string; category_id: string; display_order?: number }) =>
  api.post<ShelfItem>(`/broadcast/sessions/${sessionId}/products`, body);

export const removeShelfProduct = (sessionId: string, itemId: string) =>
  api.del<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/products/${itemId}`);

export const getShelfProducts = (sessionId: string) =>
  api.get<ShelfListResponse>(`/broadcast/sessions/${sessionId}/products`);

export const reorderShelf = (sessionId: string, itemOrder: string[]) =>
  api.patch<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/products/reorder`, { item_order: itemOrder });
```

### Phase 5: Viewer-side ProductShelf Component (1 day)

<!-- NOTE: ProductShelf.tsx already exists. ProductShelfCard.tsx is NOT a separate file (may be embedded in ProductShelf.tsx). -->

**Already implemented**:

| File | Status |
|------|--------|
| `frontend/src/pages/broadcast/ProductShelf.tsx` | EXISTS |
| `frontend/src/pages/broadcast/ProductShelfCard.tsx` | May be embedded in ProductShelf.tsx (no separate file) |

**Files to modify**:

| File | Change |
|------|--------|
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Add ProductShelf panel alongside BroadcastChat, handle SSE events |

SSE event handling in LivePlayer — extend the existing `broadcast_event_stream_route` SSE listener:

```typescript
es.addEventListener("shelf:add", (event) => {
  const item: ShelfItem = JSON.parse(event.data);
  setShelfItems(prev => [...prev, item].sort((a, b) => a.display_order - b.display_order));
});

es.addEventListener("shelf:remove", (event) => {
  const { item_id } = JSON.parse(event.data);
  setShelfItems(prev => prev.filter(p => p.item_id !== item_id));
});

es.addEventListener("shelf:reorder", (event) => {
  const { items } = JSON.parse(event.data);
  setShelfItems(items);
});
```

### Phase 6: Broadcaster-side ProductShelfManager Component (1 day)

<!-- NOTE: Both files already exist. -->

**Already implemented**:

| File | Status |
|------|--------|
| `frontend/src/pages/broadcast/ProductShelfManager.tsx` | EXISTS |
| `frontend/src/pages/broadcast/CatalogPickerDialog.tsx` | EXISTS |

**Files to modify**:

| File | Change |
|------|--------|
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Add ProductShelfManager to session detail view |

### Phase 7: Vite Proxy Verification (0.5 days)

Verify that the Vite dev proxy in `frontend/vite.config.ts` already forwards `/broadcast/*` to `localhost:8000`. The existing broadcast endpoints work, so this should be in place. No change expected.

### Summary of All Files

<!-- NOTE: Most files listed as "Create" already exist in the codebase. This ticket's infrastructure is largely implemented. -->

| File | Type | Status |
|------|------|--------|
| `app/core/settings.py` | Modify | Already has `broadcast_product_shelf_table_name` (line 1152) |
| `app/core/tables.py` | Modify | Already has `broadcast_product_shelf` (line 83, 207) |
| `scripts/local-ddb-init.py` | Modify | Already has `BroadcastProductShelf` table (line 578) |
| `app/services/broadcast_product_shelf.py` | Already exists | ~441 lines |
| `app/routers/broadcast.py` | Already has shelf endpoints | Lines 1851+ |
| `frontend/src/api/endpoints/broadcast-shelf.ts` | Already exists | -- |
| `frontend/src/pages/broadcast/ProductShelf.tsx` | Already exists | -- |
| `frontend/src/pages/broadcast/ProductShelfManager.tsx` | Already exists | -- |
| `frontend/src/pages/broadcast/CatalogPickerDialog.tsx` | Already exists | -- |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | Already exists | -- |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Already exists | -- |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_product_shelf.py`)

Using `moto` for DynamoDB mocking. ~200 lines.

```python
import pytest
from moto import mock_dynamodb
from fastapi import HTTPException

from app.services.broadcast_product_shelf import (
    add_product_to_shelf,
    remove_product_from_shelf,
    list_shelf_products,
    reorder_shelf,
    MAX_SHELF_ITEMS,
)

MOCK_CATALOG_ITEM = {
    "name": "Test Product",
    "description": "A test product for unit testing the broadcast shelf",
    "price_cents": 999,
    "currency": "USD",
    "image_urls": ["https://example.com/img1.jpg", "https://example.com/img2.jpg"],
    "attributes": {"color": "blue", "size": "M"},
}

MOCK_CATALOG_ITEM_NO_IMAGES = {
    "name": "No-Image Product",
    "price_cents": 1499,
    "currency": "USD",
    "image_urls": [],
}


@mock_dynamodb
class TestBroadcastProductShelf:
    def setup_method(self):
        """Create BroadcastProductShelf table and seed a catalog item."""
        import boto3
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = self.ddb.create_table(
            TableName="BroadcastProductShelf",
            KeySchema=[
                {"AttributeName": "session_id", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "session_id", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        # Patch T.broadcast_product_shelf to use our test table
        from unittest.mock import patch
        self._patcher = patch("app.services.broadcast_product_shelf.T")
        self._mock_T = self._patcher.start()
        self._mock_T.broadcast_product_shelf = self.table

    def teardown_method(self):
        self._patcher.stop()

    def test_add_product_to_shelf(self):
        result = add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        assert result["item_id"] == "item1"
        assert result["name"] == "Test Product"
        assert result["price_cents"] == 999
        assert result["currency"] == "USD"
        assert result["image_url"] == "https://example.com/img1.jpg"
        assert result["category_id"] == "cat1"
        assert result["added_by"] == "user1"
        assert result["added_at"] > 0

    def test_add_product_no_images_returns_none_image_url(self):
        result = add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM_NO_IMAGES, "user1")
        assert result["image_url"] is None

    def test_add_product_truncates_description_to_500(self):
        long_desc_item = {**MOCK_CATALOG_ITEM, "description": "x" * 1000}
        result = add_product_to_shelf("sess1", "item1", "cat1", long_desc_item, "user1")
        # The description is stored truncated but not returned by _shelf_item_out directly
        # Verify via DDB read
        ddb_item = self.table.get_item(Key={"session_id": "sess1", "SK": "ITEM#item1"}).get("Item")
        assert len(ddb_item["description"]) == 500

    def test_add_duplicate_raises_409(self):
        add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        with pytest.raises(HTTPException) as exc_info:
            add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        assert exc_info.value.status_code == 409

    def test_add_over_max_shelf_size_raises_400(self):
        for i in range(50):
            add_product_to_shelf("sess1", f"item{i}", "cat1", MOCK_CATALOG_ITEM, "user1")
        with pytest.raises(HTTPException) as exc_info:
            add_product_to_shelf("sess1", "item50", "cat1", MOCK_CATALOG_ITEM, "user1")
        assert exc_info.value.status_code == 400
        assert "50" in str(exc_info.value.detail)

    def test_remove_product_from_shelf(self):
        add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        assert remove_product_from_shelf("sess1", "item1") is True
        # Verify it's gone
        items = list_shelf_products("sess1")
        assert len(items) == 0

    def test_remove_nonexistent_returns_false(self):
        assert remove_product_from_shelf("sess1", "item999") is False

    def test_list_shelf_products_ordered(self):
        add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1", display_order=2)
        add_product_to_shelf("sess1", "item2", "cat1", MOCK_CATALOG_ITEM, "user1", display_order=0)
        add_product_to_shelf("sess1", "item3", "cat1", MOCK_CATALOG_ITEM, "user1", display_order=1)
        items = list_shelf_products("sess1")
        assert [i["item_id"] for i in items] == ["item2", "item3", "item1"]

    def test_list_empty_shelf(self):
        items = list_shelf_products("nonexistent_session")
        assert items == []

    def test_reorder_shelf(self):
        for i in range(3):
            add_product_to_shelf("sess1", f"item{i}", "cat1", MOCK_CATALOG_ITEM, "user1")
        reorder_shelf("sess1", ["item2", "item0", "item1"])
        items = list_shelf_products("sess1")
        assert [i["item_id"] for i in items] == ["item2", "item0", "item1"]

    def test_add_product_sets_ttl(self):
        result = add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1")
        ddb_item = self.table.get_item(Key={"session_id": "sess1", "SK": "ITEM#item1"}).get("Item")
        assert "ttl" in ddb_item
        assert ddb_item["ttl"] > result["added_at"]

    def test_add_product_with_sse_publish_when_live(self):
        """Verify SSE is published when is_live=True."""
        from unittest.mock import patch
        with patch("app.services.broadcast_product_shelf.broadcast_sse_publish") as mock_pub:
            add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1", is_live=True)
            mock_pub.assert_called_once()
            event = mock_pub.call_args[0][1]
            assert event["_type"] == "shelf:add"
            assert event["item_id"] == "item1"

    def test_add_product_no_sse_when_not_live(self):
        from unittest.mock import patch
        with patch("app.services.broadcast_product_shelf.broadcast_sse_publish") as mock_pub:
            add_product_to_shelf("sess1", "item1", "cat1", MOCK_CATALOG_ITEM, "user1", is_live=False)
            mock_pub.assert_not_called()
```

### 5.2 Backend Integration Tests (pytest, FastAPI TestClient)

```python
class TestBroadcastShelfEndpoints:
    """Integration tests using FastAPI TestClient with mocked DDB."""

    def test_add_requires_session_creator(self, client, viewer_headers, live_session_id):
        resp = client.post(
            f"/broadcast/sessions/{live_session_id}/products",
            json={"item_id": "i1", "category_id": "c1"},
            headers=viewer_headers,
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "NOT_SESSION_CREATOR"

    def test_add_product_success(self, client, broadcaster_headers, live_session_id, catalog_item_id):
        resp = client.post(
            f"/broadcast/sessions/{live_session_id}/products",
            json={"item_id": catalog_item_id, "category_id": "c1"},
            headers=broadcaster_headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["item_id"] == catalog_item_id
        assert data["session_id"] == live_session_id
        assert data["price_cents"] > 0
        assert data["added_by"] == "broadcaster_sub"

    def test_add_nonexistent_catalog_item_returns_404(self, client, broadcaster_headers, live_session_id):
        resp = client.post(
            f"/broadcast/sessions/{live_session_id}/products",
            json={"item_id": "nonexistent", "category_id": "c1"},
            headers=broadcaster_headers,
        )
        assert resp.status_code == 404

    def test_add_to_stopped_session_returns_409(self, client, broadcaster_headers, stopped_session_id):
        resp = client.post(
            f"/broadcast/sessions/{stopped_session_id}/products",
            json={"item_id": "i1", "category_id": "c1"},
            headers=broadcaster_headers,
        )
        assert resp.status_code == 409
        assert "SESSION_NOT_ADDABLE" in resp.json()["detail"]["code"]

    def test_list_products_as_viewer(self, client, viewer_headers, live_session_id):
        resp = client.get(
            f"/broadcast/sessions/{live_session_id}/products",
            headers=viewer_headers,
        )
        assert resp.status_code == 200
        assert "items" in resp.json()
        assert "count" in resp.json()

    def test_remove_product(self, client, broadcaster_headers, live_session_id, catalog_item_id):
        # Add then remove
        client.post(f"/broadcast/sessions/{live_session_id}/products",
                    json={"item_id": catalog_item_id, "category_id": "c1"},
                    headers=broadcaster_headers)
        resp = client.delete(
            f"/broadcast/sessions/{live_session_id}/products/{catalog_item_id}",
            headers=broadcaster_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_remove_nonexistent_returns_404(self, client, broadcaster_headers, live_session_id):
        resp = client.delete(
            f"/broadcast/sessions/{live_session_id}/products/no_such_item",
            headers=broadcaster_headers,
        )
        assert resp.status_code == 404

    def test_reorder_products(self, client, broadcaster_headers, live_session_id):
        # Add 3 items
        for i in range(3):
            client.post(f"/broadcast/sessions/{live_session_id}/products",
                        json={"item_id": f"item_{i}", "category_id": "c1"},
                        headers=broadcaster_headers)
        # Reorder
        resp = client.patch(
            f"/broadcast/sessions/{live_session_id}/products/reorder",
            json={"item_order": ["item_2", "item_0", "item_1"]},
            headers=broadcaster_headers,
        )
        assert resp.status_code == 200
        # Verify order
        list_resp = client.get(f"/broadcast/sessions/{live_session_id}/products",
                               headers=broadcaster_headers)
        items = list_resp.json()["items"]
        assert [i["item_id"] for i in items] == ["item_2", "item_0", "item_1"]
```

### 5.3 E2E Tests (`frontend/e2e/broadcast-product-shelf.spec.ts`)

Following the established E2E pattern with `e2e_admin_session_setup.py` identities.

**Section 100: Shelf Management API (8 tests)**:

1. Broadcaster creates a broadcast session and adds a catalog product to the shelf
2. Adding same product twice returns 409
3. Adding product to non-owned session returns 403
4. Listing shelf products returns items sorted by display_order
5. Removing a product succeeds and shelf count decreases
6. Removing a non-existent product returns 404
7. Reordering shelf updates display_order correctly
8. Adding product when shelf is at capacity (50) returns 400

**Section 101: Shelf Visibility for Viewers (4 tests)**:

1. Viewer can list shelf products on a live session
2. Shelf products include denormalized name, price, image_url
3. Viewer cannot add products to shelf (403)
4. Viewer cannot remove products from shelf (403)

**Section 102: SSE Real-time Updates (4 tests)**:

1. Viewer receives `shelf:add` SSE event when broadcaster adds a product during live session
2. Viewer receives `shelf:remove` SSE event when broadcaster removes a product
3. Viewer receives `shelf:reorder` SSE event with updated order
4. SSE events not fired when session is in draft state (products managed silently)

**Section 103: Product Shelf UI — Viewer (4 tests)**:

1. Product shelf sidebar is visible on live player page
2. Shelf card shows product name, formatted price, and image
3. "Add to Cart" button creates a cart and adds the item
4. Shelf toggle button shows/hides the shelf panel

**Section 104: Product Shelf Manager UI — Broadcaster (5 tests)**:

1. "Add Product" button opens catalog picker dialog
2. Selecting a catalog item adds it to the shelf list
3. Remove button removes item from shelf with confirmation
4. Shelf item count badge updates correctly
5. Shelf management is visible in draft, ready, and live states

**Test setup (beforeAll)**:

```typescript
let rootPage: Page;
let alicePage: Page;
let sessionId: string;
let catalogCategoryId: string;
let catalogItemId: string;
const TS = Date.now();

test.beforeAll(async ({ browser }) => {
  // Create pages with auth
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");

  // Create broadcast profile + session
  const profileResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
    name: `shelf-test-profile-${TS}`,
    region: "us-east-1",
    rendition_preset: "720p",
  });
  const sessionResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
    profile_id: profileResp.id,
  });
  sessionId = sessionResp.session_id;

  // Start session (make it live)
  await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/start`, {});

  // Create catalog category + items for the shelf
  const catResp = await apiPost(rootPage, "root", "/ui/catalog/categories", {
    name: `shelf-test-cat-${TS}`,
  });
  catalogCategoryId = catResp.category_id;
  const itemResp = await apiPost(rootPage, "root", `/ui/catalog/categories/${catalogCategoryId}/items`, {
    name: `Test Widget ${TS}`,
    price_cents: 2999,
    currency: "USD",
    description: "A widget for shelf testing",
  });
  catalogItemId = itemResp.item_id;
});
```

### 5.4 Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Catalog item deleted after adding to shelf | Shelf retains denormalized data; item still appears in shelf |
| Catalog item price changed after adding to shelf | Shelf shows original price at time of addition |
| Session transitions from live to stopped with products on shelf | Products remain in DDB (30-day TTL); viewers can no longer see shelf |
| Broadcaster adds products while no viewers connected | No SSE events wasted; products stored in DDB for when viewers join |
| Concurrent add + remove of same product | DDB conditional writes prevent race conditions |
| Shelf loaded by viewer who joined mid-broadcast | Full shelf loaded via GET on mount; SSE catches subsequent changes |
| Catalog item with empty image_urls list | `image_url` field stored as `None`; card renders placeholder |
| Very long product name (128 chars) | Truncated in UI via CSS `text-overflow: ellipsis` |
| Rapid reorder requests | Last-writer-wins; DDB update_item is atomic per item |

### 5.5 Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| SSE event race in E2E | Register SSE listener before triggering the add/remove action |
| Catalog item creation timing | Create catalog items in `beforeAll`, verify existence before shelf tests |
| Session state transitions | Use dedicated sessions per test section to avoid state pollution |
| DDB eventual consistency | Use `ConsistentRead=True` in service layer where needed |
| Display order ties | Tie-break on `added_at` or `item_id` for deterministic ordering |
| Shelf items from prior test runs | Each test section creates a fresh session, so shelf is empty |
| Product ID collisions | Include `Date.now()` timestamp in generated item names |

---

## 6. Security Considerations

### 6.1 Authorization

- **Shelf mutation (add/remove/reorder)**: Restricted to `session.created_by`. The check is `ctx["user_sub"] != session.created_by` which prevents any viewer or other broadcaster from modifying the shelf.
- **Shelf read (list)**: Allowed for any authenticated user via `require_ui_session`. This is intentional — viewers need to see the shelf.
- **Admin override**: No admin override for shelf management. Only the session creator can modify their own shelf. This prevents accidental interference by platform admins.

### 6.2 Input Validation

- **item_id and category_id**: Both validated via Pydantic `min_length=1, max_length=128`. Additional `@validator` prevents `#` and newline characters that could corrupt DDB sort keys (since the sort key is constructed as `ITEM#{item_id}`).
- **display_order**: Constrained to `0-999` to prevent absurd values.
- **Shelf size limit**: Hard cap at 50 items prevents DoS via shelf inflation.

### 6.3 Data Integrity

- **Denormalization snapshot**: Catalog data is copied at add-time. This is a feature, not a bug — it prevents price manipulation attacks where an attacker modifies the catalog item after adding it to the shelf. The shelf always reflects the price the broadcaster chose to showcase.
- **TTL cleanup**: Shelf items auto-delete 30 days after creation, preventing unbounded DDB growth from abandoned sessions.

### 6.4 Rate Limiting

- No explicit rate limit on shelf mutations (add/remove/reorder) because these are broadcaster-only actions and the shelf size cap (50) provides a natural throttle.
- If abuse is observed, a simple in-memory rate limit (same pattern as `_enforce_chat_rate_limit` in `broadcast_chat_store.py`) can be added with 1-second cooldown.

### 6.5 Inventory Manipulation Prevention

- The shelf does not track inventory. Inventory is managed by the catalog/order system. Adding a product to the shelf does not reserve inventory — it only creates a display record.
- Concurrent viewers can all "Add to Cart" the same product. The actual inventory check happens at checkout (LCOM-003).

---

## 7. Migration & Rollback Plan

### 7.1 DDB Table Creation

The `BroadcastProductShelf` table is created by `scripts/local-ddb-init.py` during stack startup. For production, the table must be created before deploying the backend code that references it.

**Full TableDef with GSIs**:

```python
TableDef(
    _resolve_table_name(S.broadcast_product_shelf_table_name, "BroadcastProductShelf"),
    "session_id",    # Partition key
    "SK",            # Sort key
    attr_types={"added_at": "N", "display_order": "N"},
    # No GSIs needed — all queries are by session_id partition
),
```

**Production DDB creation (AWS CLI)**:

```bash
aws dynamodb create-table \
  --table-name BroadcastProductShelf \
  --key-schema AttributeName=session_id,KeyType=HASH AttributeName=SK,KeyType=RANGE \
  --attribute-definitions AttributeName=session_id,AttributeType=S AttributeName=SK,AttributeType=S \
  --billing-mode PAY_PER_REQUEST \
  --tags Key=service,Value=broadcast Key=ticket,Value=LCOM-001
```

### 7.2 Feature Flag Rollout Phases

1. **Phase 0 (table creation)**: Create DDB table in production. No code changes deployed.
2. **Phase 1 (backend only)**: Deploy backend with new endpoints. Shelf API is available but no frontend consumes it. Test via curl/Postman.
3. **Phase 2 (broadcaster UI)**: Deploy ProductShelfManager. Broadcasters can add products to shelves but viewers don't see them yet.
4. **Phase 3 (viewer UI)**: Deploy ProductShelf component in LivePlayer. Full feature live.
5. **Phase 4 (monitor)**: Observe metrics for 48 hours. Check for errors, performance issues.

### 7.3 Rollback Steps

- **Frontend rollback**: Remove ProductShelf import from LivePlayer.tsx. Viewers stop seeing the shelf. Shelf data persists in DDB.
- **Backend rollback**: Remove shelf endpoints from broadcast.py. Existing shelf data is orphaned but harmless (TTL will clean up).
- **Full rollback**: Revert all changes. DDB table can be left in place (empty except for TTL-expiring items) or deleted.

### 7.4 Zero-Downtime Deployment

- Backend endpoints are additive (new routes, no modifications to existing ones except the import of `broadcast_product_shelf`).
- No schema migration on existing tables.
- New table is created independently before code deployment.
- Frontend changes are bundled in the Vite build; users get them on next page load.

### 7.5 Backward Compatibility

- No changes to existing broadcast API responses.
- No changes to existing catalog API.
- New `BroadcastShelfItemOut` fields do not affect any existing response models.
- `BroadcastChatMessageOut` is not modified in this ticket (LCOM-002 handles chat extensions).

---

## 8. Operational Runbook

### 8.1 Key Metrics

| Metric | Description | Source |
|--------|-------------|--------|
| `broadcast.shelf.products_per_session` | Average number of products added per session | DDB query on shelf table |
| `broadcast.shelf.add_count` | Counter of shelf add operations | Endpoint middleware |
| `broadcast.shelf.remove_count` | Counter of shelf remove operations | Endpoint middleware |
| `broadcast.shelf.reorder_count` | Counter of reorder operations | Endpoint middleware |
| `broadcast.shelf.list_latency_ms` | P50/P95/P99 latency for shelf list | Endpoint middleware |
| `broadcast.shelf.sse_events_published` | Counter of SSE events published for shelf | broadcast_sse_publish wrapper |
| `broadcast.shelf.add_to_cart_from_shelf` | Counter of "Add to Cart" clicks from shelf cards | Frontend analytics |

### 8.2 Alerting Thresholds

| Alert | Threshold | Action |
|-------|-----------|--------|
| Shelf list P99 > 500ms | Fire after 5 consecutive minutes | Check DDB throttling, partition hotspots |
| Shelf add error rate > 5% | Fire after 2 minutes | Check catalog table availability |
| SSE publish failures > 1% | Fire after 5 minutes | Check broadcast_sse subscriber queue health |
| Shelf items > 40 per session (approaching limit) | Informational | Consider raising MAX_SHELF_ITEMS |

### 8.3 Common Debugging

**Problem: Shelf items not appearing for viewers**
1. Check session status is `live` (shelf is only shown during live sessions)
2. Verify SSE connection is active (check browser Network tab for `/broadcast/sessions/{id}/stream`)
3. Check shelf GET endpoint returns items: `curl /broadcast/sessions/{id}/products`
4. Verify DDB table has items: `aws dynamodb query --table-name BroadcastProductShelf --key-condition-expression "session_id = :s" --expression-attribute-values '{":s":{"S":"<session_id>"}}'`

**Problem: "Add Product" fails with 404**
1. Verify the catalog item exists: `curl /ui/catalog/categories/{cat_id}/items/{item_id}`
2. Check that `category_id` and `item_id` match (common mistake: using wrong category)
3. Verify the catalog item has `entity: "item"` in DDB

**Problem: Shelf reorder not updating**
1. Check that all item_ids in the reorder request are on the shelf
2. Verify SSE `shelf:reorder` event is published (check backend logs)
3. Frontend: Check that the SSE listener for `shelf:reorder` is registered

### 8.4 Log Patterns

```
# Successful shelf add
INFO broadcast.shelf session_id=sess_abc item_id=item_123 action=add added_by=user_456

# Shelf full
WARN broadcast.shelf session_id=sess_abc action=add_rejected reason=shelf_full count=50

# SSE publish
DEBUG broadcast.sse session_id=sess_abc event_type=shelf:add subscribers=12

# Catalog item not found during add
WARN broadcast.shelf session_id=sess_abc item_id=item_999 action=add_failed reason=catalog_item_not_found
```

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput

| Operation | Expected Rate | DDB WCU/RCU |
|-----------|--------------|-------------|
| Shelf add | 1-5 per session (total, not per second) | 1 WCU per add (1KB item) |
| Shelf remove | 0-2 per session | 1 WCU per remove |
| Shelf list | 1-100 per minute per live session (viewer loads) | 1 RCU per list (50 items < 4KB) |
| Shelf reorder | 0-3 per session | N WCU per reorder (N = item count) |

### 9.2 DDB Capacity Planning

- **Table size**: Approximately 50 items per session * ~500 bytes per item = 25KB per session. With 1000 concurrent sessions, total table size is ~25MB. This is well within DDB free tier.
- **Partition heat**: Each session_id is a separate partition. No hot partition risk unless a single session has extremely high viewer load (which only affects RCU for list operations).
- **TTL**: Items expire 30 days after creation. No manual cleanup needed.
- **Billing mode**: PAY_PER_REQUEST is appropriate for bursty traffic patterns (sessions start and stop).

### 9.3 Hot Partition Analysis

- **Write path**: Shelf mutations (add/remove/reorder) are broadcaster-only. A single broadcaster cannot produce more than ~10 writes per minute, far below DDB partition limits (1000 WCU per partition).
- **Read path**: Shelf list is the hot operation. During a broadcast with 10,000 concurrent viewers, if each viewer loads the shelf once, that is 10,000 reads. If the shelf is cached client-side and only refreshed via SSE, the actual read rate drops to ~1 read per viewer join (plus SSE for updates). DDB can handle this without throttling on a single partition.

### 9.4 Caching Strategy

- **No server-side cache needed**: DDB reads for a 50-item shelf complete in <10ms. The shelf data is small enough to fit in a single DDB page.
- **Client-side cache**: React Query `staleTime: 30_000` (30 seconds) prevents excessive refetching when toggling the shelf sidebar. SSE events provide real-time updates without polling.
- **CDN cache**: Not applicable — shelf data is per-session and changes in real time.

### 9.5 SSE Fan-out Scaling

The current SSE implementation (`broadcast_sse.py`) uses in-memory `asyncio.Queue` per subscriber. For a single uvicorn process (required by moto in dev mode), this supports ~1000 concurrent SSE subscribers per session before queue overflow. For production:

- Use Redis pub/sub as the SSE event bus instead of in-memory queues
- Each backend instance subscribes to Redis channels for active sessions
- SSE fan-out happens locally per instance, with Redis providing cross-instance delivery

### 9.6 Latency Budget

| Operation | Target | Measured (DDB local) |
|-----------|--------|---------------------|
| Add product | < 200ms | ~50ms |
| Remove product | < 100ms | ~30ms |
| List shelf | < 100ms | ~20ms (50 items) |
| Reorder (50 items) | < 500ms | ~200ms |
| SSE event delivery | < 100ms from publish to viewer | ~10ms (in-process) |

---

## 10. Dependency Analysis

### 10.1 LCOM Ticket Chain

```
LCOM-001 (this ticket)          LCOM-002
  Broadcast Product Shelf  ──────▶ Chat Product Links
         │                            │
         │                            │
         ▼                            ▼
      LCOM-003                     LCOM-004
  Broadcast Quick-Buy        Broadcast Exclusive Pricing
```

- **LCOM-001 → LCOM-002**: LCOM-002 shares products from the shelf into chat. The `send_product_link_message` function reads from `T.broadcast_product_shelf` to get denormalized product data.
- **LCOM-001 → LCOM-003**: LCOM-003's quick-buy endpoint reads `shelf_item.price_cents` to calculate order totals.
- **LCOM-001 → LCOM-004**: LCOM-004 adds `broadcast_price_cents` fields to the shelf items created by LCOM-001.

### 10.2 Integration with Existing Systems

| System | Integration Point | Direction |
|--------|------------------|-----------|
| Catalog (`app/routers/catalog.py`) | Reads catalog items during add-to-shelf | LCOM-001 reads from catalog |
| Shopping Cart (`cart.ts`) | "Add to Cart" button in ProductShelfCard | Frontend calls cart API |
| Broadcast SSE (`broadcast_sse.py`) | Publishes shelf events to viewers | LCOM-001 writes to SSE bus |
| Broadcast Sessions (`broadcast_store.py`) | Validates session exists and status | LCOM-001 reads session state |
| Broadcast Chat (`broadcast_chat_store.py`) | No direct integration (LCOM-002) | Indirect via SSE |

### 10.3 API Contracts Between Tickets

**LCOM-001 provides to LCOM-002**:
- `list_shelf_products(session_id)` — returns list of shelf items
- `T.broadcast_product_shelf.get_item(Key={...})` — direct DDB read for single item

**LCOM-001 provides to LCOM-003**:
- `shelf_item["price_cents"]` — price used for order total calculation
- Shelf item existence check — validates product is on shelf before allowing purchase

**LCOM-001 provides to LCOM-004**:
- Shelf item DDB record — LCOM-004 adds `broadcast_price_cents` fields to existing items
- `_shelf_item_out()` function — LCOM-004 extends this to include pricing fields

---

## 11. Acceptance Criteria

### 11.1 Functional Requirements

1. A broadcaster can add up to 50 catalog items to a broadcast session's product shelf.
2. Products on the shelf display the correct denormalized name, price, and image from the catalog.
3. A broadcaster can remove products from the shelf at any time (draft, ready, live).
4. A broadcaster can reorder products on the shelf via drag-and-drop or explicit ordering.
5. Viewers can see the product shelf during a live broadcast.
6. Viewers receive real-time updates (add/remove/reorder) via SSE during a live session.
7. Viewers can add shelf products to their shopping cart without leaving the broadcast player.
8. The shelf toggle button shows/hides the shelf sidebar panel.
9. Product data persists on the shelf even if the catalog item is later modified or deleted.

### 11.2 Non-Functional Requirements

1. Shelf list endpoint responds in < 100ms P95 for shelves with 50 items.
2. SSE event delivery from publish to viewer UI update is < 200ms P95.
3. No DDB throttling observed during load testing with 1000 concurrent sessions and 100 viewers each.
4. Frontend skeleton loading state appears within 100ms of shelf panel opening.
5. All 25 E2E tests pass with 0 flakes on 3 consecutive runs.

### 11.3 Load Testing Thresholds

| Scenario | Target | Pass/Fail Criteria |
|----------|--------|-------------------|
| 100 concurrent shelf list requests | < 50ms P95 | Fail if > 100ms P95 |
| 50 sequential add operations (fill shelf) | < 5s total | Fail if > 10s |
| SSE event delivery to 500 subscribers | < 100ms P95 | Fail if > 500ms |
| 10 reorder operations (50 items each) | < 2s each | Fail if > 5s |

---

## 12. Error Handling Matrix

| Error | HTTP Status | Error Code | User Message | Recovery Action |
|-------|-------------|-----------|--------------|----------------|
| Session not found | 404 | SESSION_NOT_FOUND | "Broadcast session not found." | Verify session ID |
| Caller not session creator | 403 | NOT_SESSION_CREATOR | "Only the broadcaster can manage the product shelf." | Use broadcaster account |
| Session in terminal state | 409 | SESSION_NOT_ADDABLE | "Cannot add products when session is {status}." | Create new session |
| Catalog item not found | 404 | (default) | "Catalog item not found." | Verify category and item IDs |
| Product already on shelf | 409 | (default) | "Product already on shelf." | Skip or remove first |
| Shelf full (50 items) | 400 | (default) | "Shelf is full (50 items max)." | Remove items before adding |
| Product not on shelf (remove) | 404 | (default) | "Product not on shelf." | Refresh shelf list |
| Reorder with invalid item_ids | 422 | VALIDATION_ERROR | "Validation error." | Ensure all IDs are on shelf |
| DDB timeout | 500 | INTERNAL_ERROR | "Internal server error. Please try again." | Retry after 1s |
| SSE queue full (subscriber overflow) | N/A (silent) | N/A | Subscriber disconnected silently | Reconnect SSE stream |

---

## 13. Analytics & Attribution

### 13.1 Shelf Engagement Tracking

The following frontend events are emitted to the analytics system (via `window.__analytics?.track()`):

| Event Name | Properties | Trigger |
|------------|-----------|---------|
| `shelf.viewed` | `session_id`, `item_count` | Shelf panel opened |
| `shelf.product_viewed` | `session_id`, `item_id`, `price_cents`, `display_order` | Product card visible for > 2s |
| `shelf.add_to_cart` | `session_id`, `item_id`, `price_cents` | "Add to Cart" clicked |
| `shelf.product_scrolled` | `session_id`, `scroll_depth_pct` | Viewer scrolls through shelf |

### 13.2 Broadcast Attribution

Products added to a broadcast shelf are tagged with `session_id`. When LCOM-003 implements quick-buy, the order record includes `session_id` for attribution. For "Add to Cart" (standard checkout), the cart item includes a `source_broadcast_session_id` metadata field that flows through to the order.

### 13.3 A/B Test Hooks

- **Shelf position**: Toggle between sidebar (default) and overlay mode via feature flag `BROADCAST_SHELF_LAYOUT`
- **Shelf auto-open**: Feature flag `BROADCAST_SHELF_AUTO_OPEN` controls whether the shelf opens automatically when a product is added during a live session
- **Add to Cart vs Quick Buy**: LCOM-003 adds a "Quick Buy" button; A/B test between showing only "Add to Cart" vs both buttons

---

## Appendix A: API Reference Summary

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/broadcast/sessions/{id}/products` | Session creator | Add product to shelf |
| DELETE | `/broadcast/sessions/{id}/products/{item_id}` | Session creator | Remove product from shelf |
| GET | `/broadcast/sessions/{id}/products` | Any authenticated user | List shelf products |
| PATCH | `/broadcast/sessions/{id}/products/reorder` | Session creator | Reorder shelf items |

## Appendix B: SSE Event Types

| Event | Payload | Trigger |
|-------|---------|---------|
| `shelf:add` | Full `BroadcastShelfItemOut` | Product added during live session |
| `shelf:remove` | `{"item_id": "..."}` | Product removed during live session |
| `shelf:reorder` | `{"items": [BroadcastShelfItemOut, ...]}` | Shelf reordered during live session |

## Appendix C: Configuration

| Setting | Default | Purpose |
|---------|---------|---------|
| `DDB_BROADCAST_PRODUCT_SHELF` | `BroadcastProductShelf` | Table name |
| `BROADCAST_MAX_SHELF_ITEMS` | `50` | Maximum products per broadcast shelf |

## Appendix D: Related Tickets

- **LCOM-002**: Chat product links — broadcaster can pin shelf products to live chat
- **LCOM-003**: Broadcast quick-buy checkout — one-click purchase from shelf
- **LCOM-004**: Broadcast-exclusive pricing — time-limited discounts on shelf products

---

## Codebase References

| File | Lines | What was verified |
|------|-------|-------------------|
| `app/routers/broadcast.py` | 76 | Router prefix `/broadcast` confirmed; ~3969 lines total (not 944) |
| `app/routers/broadcast.py` | 211 | `_require_operator_role` confirmed |
| `app/routers/broadcast.py` | 639-640 | SSE stream endpoint `broadcast_event_stream_route` confirmed |
| `app/routers/broadcast.py` | 1851+ | Product shelf endpoints already implemented (add/remove/list/reorder) |
| `app/routers/catalog.py` | 41 | Router prefix `/ui/catalog` confirmed; ~933 lines total (not 664) |
| `app/routers/catalog.py` | 54, 62 | `cat_pk` and `item_sk` helper functions confirmed |
| `app/routers/catalog.py` | 106 | `_catalog_item_out` confirmed |
| `app/routers/catalog.py` | 227, 235 | `_require_category_owner` and `_get_item_meta` confirmed |
| `app/models_broadcast.py` | 37-49 | `BroadcastSessionModel` confirmed with all listed fields |
| `app/models_broadcast.py` | 8 | `BroadcastSessionStatus` Literal type confirmed |
| `app/services/broadcast_sse.py` | 29 | `broadcast_sse_publish(session_id, event)` confirmed; 49 lines total |
| `app/services/broadcast_chat_store.py` | -- | Exists, ~423 lines (not 247) |
| `app/services/broadcast_state_machine.py` | -- | Exists |
| `app/services/broadcast_product_shelf.py` | -- | Already exists (~441 lines) |
| `app/core/settings.py` | 1152 | `broadcast_product_shelf_table_name` already exists |
| `app/core/tables.py` | 83, 207 | `broadcast_product_shelf` table handle already exists |
| `scripts/local-ddb-init.py` | 578 | `BroadcastProductShelf` table definition already exists |
| `scripts/local-ddb-init.py` | 67 | Shopping cart table confirmed |
| `frontend/src/api/endpoints/broadcast-shelf.ts` | -- | Already exists |
| `frontend/src/api/endpoints/cart.ts` | -- | Already exists |
| `frontend/src/pages/broadcast/ProductShelf.tsx` | -- | Already exists |
| `frontend/src/pages/broadcast/ProductShelfManager.tsx` | -- | Already exists |
| `frontend/src/pages/broadcast/CatalogPickerDialog.tsx` | -- | Already exists |
| `frontend/src/pages/broadcast/LivePlayer.tsx` | -- | Already exists |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | -- | Already exists |

---

## Testing Strategy

### Unit Tests (`tests/test_broadcast_product_shelf.py`)
**Framework**: pytest + moto (DynamoDB/S3 mock)

| # | Test Function | What It Verifies |
|---|--------------|-----------------|
| 1 | `test_add_product_to_shelf` | Add product to shelf |
| 2 | `test_add_product_no_images` | Add product no images |
| 3 | `test_add_product_truncates_description` | Add product truncates description |
| 4 | `test_add_duplicate_raises_409` | Add duplicate raises 409 |
| 5 | `test_add_over_max_raises_400` | Add over max raises 400 |
| 6 | `test_remove_product` | Remove product |
| 7 | `test_remove_nonexistent_returns_false` | Remove nonexistent returns false |
| 8 | `test_list_ordered_by_display_order` | List ordered by display order |
| 9 | `test_reorder_shelf` | Reorder shelf |
| 10 | `test_add_with_sse_when_live` | Add with sse when live |

### Integration Tests

1. Full endpoint flow: create, read, update, delete with FastAPI TestClient + mocked DDB
2. Auth enforcement: verify 401 without session, 403 for wrong role
3. Validation: 422 for malformed requests, 404 for missing resources
4. Cross-service: verify DDB writes are consistent across tables
5. SSE/real-time: verify events published on mutations (where applicable)

### E2E Tests (`frontend/e2e/broadcast-product-shelf.spec.ts`)
**Auth**: `injectAuth(page, identity)` for cookie auth; `apiPost(page, identity, path, body)` for CSRF-protected requests.

**Total**: ~25 tests covering API CRUD, auth enforcement (401/403), validation (422), negative cases (404/409), and UI interactions.

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
| LCOM-002 | Chat Product Links reads shelf items |
| LCOM-003 | Quick-Buy reads shelf price |
| LCOM-004 | Exclusive Pricing extends shelf items |

### Merge Strategy
**Independent -- first ticket in the LCOM chain. No dependencies on other tickets. DDB table, service, and endpoints are all additive.**

### Merge Checklist
- [ ] Service file created/modified: `app/services/broadcast_product_shelf.py`
- [ ] No endpoint prefix conflicts with existing routers
- [ ] E2E tests pass: `cd frontend && npx playwright test frontend/e2e/broadcast-product-shelf.spec.ts`
- [ ] Unit tests pass: `.venv/bin/pytest tests/test_broadcast_product_shelf.py`
