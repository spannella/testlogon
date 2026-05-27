# LCOM-002: Chat Product Links — Rich Product Cards in Broadcast Live Chat

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: High  
**Estimated effort**: 4-6 days  
**Depends on**: LCOM-001 (Broadcast Product Shelf)

---

## 1. Overview & Motivation

### The Gap

LCOM-001 introduces a product shelf sidebar that viewers can browse during a live stream. However, the live chat and the product shelf operate as completely independent channels. When a broadcaster demonstrates a product on camera and says "check out this item," viewers must manually scroll through the shelf to find it. There is no mechanism for the broadcaster to **direct attention** to a specific product within the flow of the live chat conversation.

The existing broadcast chat (`app/services/broadcast_chat_store.py`, 247 lines) supports only plain text messages of up to 280 characters. The messaging system (`app/routers/messaging.py`, 12,670 lines) supports rich message kinds — `text`, `image`, `file`, `audio`, `video`, `gallery`, `file_share`, `calendar_share`, `calendar_event`, `meeting_poll`, `video_share` — but broadcast chat is a separate system with no message kind support.

### Why This Is Needed

1. **Broadcaster product callouts are ephemeral**: When a broadcaster says "look at this jacket" on camera, the moment passes. A pinned product card in chat provides a permanent, clickable reference that late joiners can also see.
2. **Higher conversion from contextual promotion**: Product cards embedded in the chat timeline appear at exactly the moment the broadcaster discusses the product, creating a natural "see it, click it, buy it" flow. Industry data shows 3-5x higher click-through rates on contextual product placements vs. static shelf listings.
3. **Chat engagement around products**: Viewers can react to and discuss the specific product card, creating social proof ("I just bought this!" comments beneath the card).
4. **Parity with competitors**: TikTok Shop and YouTube Shopping both allow product pins in live chat.

### Architecture After This Change

```
┌───────────────────────────────────────────────────────────────────────┐
│  Broadcaster Dashboard                                                │
│  ┌──────────────────────────┐                                        │
│  │ BroadcastChat Panel      │                                        │
│  │ ┌──────────────────────┐ │                                        │
│  │ │ "Share Product" btn  │─┼──▶ ShelfProductPicker dialog           │
│  │ └──────────────────────┘ │    (picks from session's shelf)        │
│  │                          │                                        │
│  │ ┌──────────────────────┐ │                                        │
│  │ │ Chat timeline        │ │    POST /broadcast/{id}/chat/product   │
│  │ │ ┌──────────────────┐ │ │    body: { item_id }                   │
│  │ │ │ ProductLinkCard  │ │ │                                        │
│  │ │ │ ┌──────┐ Title   │ │ │                                        │
│  │ │ │ │ img  │ $29.99  │ │ │                                        │
│  │ │ │ │      │ Buy Now │ │ │                                        │
│  │ │ │ └──────┘         │ │ │                                        │
│  │ │ └──────────────────┘ │ │                                        │
│  │ │                      │ │                                        │
│  │ │ "Love this!"         │ │                                        │
│  │ │ "Just ordered!"      │ │                                        │
│  │ └──────────────────────┘ │                                        │
│  └──────────────────────────┘                                        │
└───────────────────────────────────────────────────────────────────────┘
              │ SSE: chat:product_link
              ▼
┌───────────────────────────────────────────────────────────────────────┐
│  Viewer Player (LivePlayer.tsx)                                       │
│  ┌──────────────────────────┐                                        │
│  │ BroadcastChat Panel      │                                        │
│  │ ┌──────────────────────┐ │                                        │
│  │ │ Chat timeline        │ │                                        │
│  │ │ ┌──────────────────┐ │ │                                        │
│  │ │ │ ProductLinkCard  │ │ │                                        │
│  │ │ │ ┌──────┐ Title   │ │ │                                        │
│  │ │ │ │ img  │ $29.99  │ │ │                                        │
│  │ │ │ │      │ Add to  │ │ │  <-- Viewer clicks "Add to Cart"      │
│  │ │ │ └──────┘ Cart    │ │ │      or "Quick Buy" (LCOM-003)        │
│  │ │ └──────────────────┘ │ │                                        │
│  │ └──────────────────────┘ │                                        │
│  └──────────────────────────┘                                        │
└───────────────────────────────────────────────────────────────────────┘
```

**Product link share flow sequence diagram**:

```
Broadcaster                    Backend                          Viewer(s)
    │                              │                               │
    │ Click "Share Product"        │                               │
    │ → ShelfProductPicker opens   │                               │
    │                              │                               │
    │ Select item from shelf       │                               │
    │                              │                               │
    │ POST /chat/product           │                               │
    │ {item_id: "item123"}         │                               │
    │─────────────────────────────>│                               │
    │                              │                               │
    │                              │ 1. Validate session live      │
    │                              │ 2. Validate caller = creator  │
    │                              │ 3. Look up item on shelf      │
    │                              │ 4. Enforce rate limit (5s)    │
    │                              │ 5. Build product_link data    │
    │                              │ 6. Write to ChatMessages DDB  │
    │                              │ 7. Publish SSE event          │
    │                              │                               │
    │             201 Created      │                               │
    │<─────────────────────────────│                               │
    │                              │                               │
    │    Card appears in chat      │  SSE: chat:product_link       │
    │                              │──────────────────────────────>│
    │                              │                               │
    │                              │                   Parse event │
    │                              │                   Render card │
    │                              │                   in timeline │
    │                              │                               │
    │                              │         Viewer clicks         │
    │                              │         "Add to Cart"         │
    │                              │                               │
    │                              │   POST /shoppingcart/...      │
    │                              │<──────────────────────────────│
    │                              │                               │
    │                              │         200 OK                │
    │                              │──────────────────────────────>│
    │                              │                               │
    │                              │         Toast: "Added!"       │
```

---

## 2. Current State Analysis

### 2.1 Broadcast Chat Message Model (`app/services/broadcast_chat_store.py`)

The current chat message DDB item (line 131-141) has these fields:

```python
item = {
    "session_id": session_id,
    "sort_key": sort_key,          # "{ts_ms:016d}#{msg_id}"
    "message_id": msg_id,          # "cm_" + uuid4().hex
    "sender_id": user_id,
    "sender_display_name": display_name,
    "text": text.strip(),          # plain text, max 280 chars
    "created_at": ts,
    "deleted": False,
    "ttl": ts + 7 * 24 * 3600,
}
```

No `kind` field exists. All messages are implicitly `text` kind. The output function `_chat_msg_out` (line 237-247) returns a fixed set of fields.

### 2.2 Chat Send Endpoint (`app/routers/broadcast.py`, lines 807-850)

The `send_chat_message_route` (line 812) accepts `BroadcastChatSendIn` which has only a `text` field (lines 776-777). The route validates session is live, resolves display name from profile table, then delegates to `_store_send_chat`.

### 2.3 Chat SSE Delivery

Chat messages are published via `broadcast_sse_publish(session_id, {"_type": "chat:message", ...})` (line 146 in `broadcast_chat_store.py`). The SSE stream endpoint (`broadcast_chat_stream_route`, line 898-944) yields events with `event: chat:message` and `event: chat:delete` types. The frontend `BroadcastChat.tsx` component listens for these events.

### 2.4 Existing Message Kind Pattern (Messaging System)

The platform's messaging system (`app/routers/messaging.py`) supports a `kind` field on messages (line 2291):

```python
kind: Literal["text", "image", "file", "audio", "video", "gallery",
              "file_share", "calendar_share", "calendar_event",
              "meeting_poll", "video_share"]
```

Each kind has dedicated rendering in `MessageBubble.tsx` (line 157-160, 529, 604, 958+, 1126+, 1179+, 1396+). The pattern is: backend stores the kind and associated metadata, frontend conditionally renders based on `message.kind`.

### 2.5 Frontend Chat Message Rendering (`frontend/src/pages/broadcast/BroadcastChat.tsx`)

The current `BroadcastChat` component renders chat messages as simple text rows with sender display name. The SSE connection is established in a `useEffect` (line 44) connecting to `/broadcast/sessions/${sessionId}/chat/stream?poll_ms=500`. Event listeners handle `chat:message` and `chat:delete`. There is no concept of message kinds or rich rendering.

### 2.6 Product Shelf (LCOM-001 Prerequisite)

LCOM-001 introduces a `BroadcastProductShelf` DynamoDB table with `session_id` as PK and `SK=ITEM#{item_id}`. Products on the shelf have denormalized `name`, `price_cents`, `currency`, `image_url`, and `display_order`. The shelf is the authoritative source of which products are available for the broadcast.

### 2.7 Frontend Cart Integration (`frontend/src/api/endpoints/cart.ts`)

The cart API provides `createCart`, `addCartItem(cartId, { sku, quantity })`, and `purchaseCart`. The cart system uses SKU-based item identification, so product link cards need to map `item_id` to the appropriate SKU format.

---

## 3. Technical Design

### 3.1 Extended Chat Message Model

Add a `kind` field and optional `product_link` embedded object to the broadcast chat message:

```python
# DDB item shape (extended from broadcast_chat_store.py)
item = {
    "session_id": session_id,
    "sort_key": sort_key,
    "message_id": msg_id,
    "sender_id": user_id,
    "sender_display_name": display_name,
    "text": text,                          # For product_link: auto-generated "Shared: {product name}"
    "kind": "product_link",                # NEW — "text" (default) or "product_link"
    "product_link": {                      # NEW — present only when kind=product_link
        "item_id": item_id,
        "category_id": category_id,
        "name": name,                      # denormalized from shelf
        "description": description,        # truncated to 200 chars
        "price_cents": price_cents,
        "currency": currency,
        "image_url": image_url,
    },
    "created_at": ts,
    "deleted": False,
    "ttl": ts + 7 * 24 * 3600,
}
```

### 3.2 API Endpoints

#### 3.2.1 Share Product in Chat

```
POST /broadcast/sessions/{session_id}/chat/product
```

**Auth**: `require_ui_session` — only the session creator (broadcaster) can share product links. This is a moderation decision: allowing all viewers to spam product links would degrade chat quality.

**Request model**:

```python
class BroadcastChatProductLinkIn(BaseModel):
    """Request body for sharing a product link in broadcast chat.

    The item_id must reference a product that is currently on the
    session's product shelf (added via LCOM-001). This prevents
    sharing arbitrary catalog items that the broadcaster hasn't curated.
    """
    item_id: str = Field(..., min_length=1, max_length=128,
        description="Item ID of a product on the session's shelf.")

    @validator("item_id")
    def item_id_no_special_chars(cls, v: str) -> str:
        """Prevent DDB sort key injection."""
        if "#" in v or "\n" in v:
            raise ValueError("item_id must not contain '#' or newline characters")
        return v
```

**Response model** (reuses `BroadcastChatMessageOut` with additions):

```python
class BroadcastChatProductLinkData(BaseModel):
    """Embedded product data within a product_link chat message."""
    item_id: str
    category_id: str
    name: str
    description: Optional[str] = None
    price_cents: int
    currency: str = "USD"
    image_url: Optional[str] = None


class BroadcastChatMessageOut(BaseModel):
    """Extended to support product_link kind.

    Backward compatible: existing text messages return kind="text"
    and product_link=None.
    """
    message_id: str
    session_id: str
    sender_id: str
    sender_display_name: str
    text: str
    created_at: int
    deleted: bool = False
    kind: str = "text"                                     # NEW
    product_link: Optional[BroadcastChatProductLinkData] = None  # NEW
```

**Behavior**:

1. Validate session exists and is `live`. Return 403 if not live.
2. Validate caller is `session.created_by`. Return 403 if not broadcaster.
3. Look up the product on the session's shelf: `T.broadcast_product_shelf.get_item(Key={"session_id": session_id, "SK": f"ITEM#{item_id}"})`. Return 404 if product is not on the shelf — this prevents sharing arbitrary catalog items that the broadcaster hasn't curated.
4. Rate limit: product links use a separate, more lenient rate limit — 1 per 5 seconds (to prevent spamming the chat with product cards). Reuse the in-memory rate limit pattern from `broadcast_chat_store.py` with a separate bucket key prefix.
5. Build the message item with `kind="product_link"` and embedded `product_link` data from the shelf item.
6. Write to `BroadcastChatMessages` table.
7. Publish via `broadcast_sse_publish()` with `_type: "chat:product_link"`.
8. Return the message.

**Error responses**:

| Code | Condition |
|------|-----------|
| 403 | Session not live, or caller is not broadcaster |
| 404 | Product not on shelf (must add via LCOM-001 first) |
| 429 | Product link rate limit exceeded (1 per 5 seconds) |

#### 3.2.2 Updated Chat History

The existing `GET /broadcast/sessions/{session_id}/chat` endpoint returns chat history. The `_chat_msg_out` function must be extended to include `kind` and `product_link` fields:

```python
def _chat_msg_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB item to output dict — extended for product links.

    Backward compatible: messages without a `kind` field default to "text".
    This handles pre-migration messages that were stored before the kind
    field was introduced.
    """
    out = {
        "message_id": item["message_id"],
        "session_id": item["session_id"],
        "sender_id": item["sender_id"],
        "sender_display_name": item.get("sender_display_name", ""),
        "text": item.get("text", ""),
        "created_at": int(item.get("created_at", 0)),
        "deleted": bool(item.get("deleted", False)),
        "kind": item.get("kind", "text"),
    }
    if item.get("product_link"):
        pl = item["product_link"]
        out["product_link"] = {
            "item_id": pl.get("item_id", ""),
            "category_id": pl.get("category_id", ""),
            "name": pl.get("name", ""),
            "description": pl.get("description"),
            "price_cents": int(pl.get("price_cents", 0)),
            "currency": pl.get("currency", "USD"),
            "image_url": pl.get("image_url"),
        }
    return out
```

#### 3.2.3 Updated SSE Stream

The existing SSE stream at `GET /broadcast/sessions/{session_id}/chat/stream` (line 898-944) emits `chat:message` events. Product link messages are emitted as `chat:product_link` — a distinct event type so the frontend can render them differently:

```python
if msg.get("deleted"):
    payload = json.dumps({"message_id": msg["message_id"]}, separators=(",", ":"))
    yield f"event: chat:delete\ndata: {payload}\n\n"
elif msg.get("kind") == "product_link":
    payload = json.dumps(_chat_msg_out(msg), separators=(",", ":"), default=str)
    yield f"event: chat:product_link\ndata: {payload}\n\n"
else:
    payload = json.dumps(_chat_msg_out(msg), separators=(",", ":"), default=str)
    yield f"event: chat:message\ndata: {payload}\n\n"
```

### 3.3 Service Layer Extension — `app/services/broadcast_chat_store.py`

Add a new function alongside `send_chat_message`:

```python
# ─── Product Link Rate Limiting ────────────────────────────────

_PRODUCT_LINK_RATE_LOCK = threading.Lock()
_PRODUCT_LINK_RATE_BUCKETS: Dict[str, int] = {}
PRODUCT_LINK_RATE_LIMIT_MS = 5000  # 1 product link per 5 seconds


def _enforce_product_link_rate_limit(session_id: str, user_id: str) -> None:
    """Enforce dedicated rate limit for product link sharing.

    Uses a separate bucket from the text chat rate limit so that
    sending a text message does not consume the product link budget
    and vice versa. Key format: "PL#{session_id}#{user_id}".

    Raises:
        HTTPException 429: With BROADCAST_PRODUCT_LINK_RATE_LIMITED code
        and retry_after_ms indicating when the next share is allowed.
    """
    key = f"PL#{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    with _PRODUCT_LINK_RATE_LOCK:
        last = _PRODUCT_LINK_RATE_BUCKETS.get(key, 0)
        if now_ms - last < PRODUCT_LINK_RATE_LIMIT_MS:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "BROADCAST_PRODUCT_LINK_RATE_LIMITED",
                    "message": "You can share one product every 5 seconds.",
                    "retry_after_ms": PRODUCT_LINK_RATE_LIMIT_MS - (now_ms - last),
                },
            )
        _PRODUCT_LINK_RATE_BUCKETS[key] = now_ms


def reset_product_link_rate_limits() -> None:
    """Clear product link rate limit state (for tests)."""
    with _PRODUCT_LINK_RATE_LOCK:
        _PRODUCT_LINK_RATE_BUCKETS.clear()


def send_product_link_message(
    session_id: str,
    user_id: str,
    display_name: str,
    shelf_item: Dict[str, Any],
) -> Dict[str, Any]:
    """Send a product_link chat message. Enforces product link rate limit.

    The product_link data is denormalized from the shelf item at send time.
    This means if the shelf item is later removed or its price changes,
    the chat message retains the data as it was when shared.

    Args:
        session_id: The broadcast session ID.
        user_id: The broadcaster's user sub.
        display_name: Display name to show as sender.
        shelf_item: Dict from broadcast_product_shelf.list_shelf_products()
                    or a direct DDB read of the shelf item.

    Returns:
        Dict suitable for BroadcastChatMessageOut serialization.
    """
    _enforce_product_link_rate_limit(session_id, user_id)

    ts = now_ts()
    ts_ms = int(time.time() * 1000)
    msg_id = "cm_" + uuid4().hex
    sort_key = f"{ts_ms:016d}#{msg_id}"

    product_link_data = {
        "item_id": shelf_item["item_id"],
        "category_id": shelf_item.get("category_id", ""),
        "name": shelf_item.get("name", ""),
        "description": (shelf_item.get("description") or "")[:200],
        "price_cents": int(shelf_item.get("price_cents", 0)),
        "currency": shelf_item.get("currency", "USD"),
        "image_url": shelf_item.get("image_url"),
    }

    item = {
        "session_id": session_id,
        "sort_key": sort_key,
        "message_id": msg_id,
        "sender_id": user_id,
        "sender_display_name": display_name,
        "text": f"Shared: {shelf_item.get('name', 'Product')}",
        "kind": "product_link",
        "product_link": product_link_data,
        "created_at": ts,
        "deleted": False,
        "ttl": ts + 7 * 24 * 3600,
    }
    T.broadcast_chat_messages.put_item(Item=item)

    out = _chat_msg_out(item)
    broadcast_sse_publish(session_id, {"_type": "chat:product_link", **out})

    return {**out, "sort_key": sort_key}
```

### 3.4 Full Router Endpoint Implementation

Added to `app/routers/broadcast.py` after the existing chat endpoints:

```python
@router.post(
    "/sessions/{session_id}/chat/product",
    response_model=BroadcastChatMessageOut,
    status_code=status.HTTP_201_CREATED,
)
def share_product_in_chat_route(
    session_id: str,
    body: BroadcastChatProductLinkIn,
    ctx: dict = Depends(_ctx),
):
    """Share a product from the shelf as a rich card in broadcast chat.

    Only the broadcaster (session creator) can share product links.
    The product must be on the session's product shelf (LCOM-001).
    Rate limited to 1 product link per 5 seconds per broadcaster.
    """
    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "BROADCAST_NOT_LIVE",
                "message": "Chat is only available while the broadcast is live",
            },
        )
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "NOT_SESSION_CREATOR",
                "message": "Only the broadcaster can share products in chat",
            },
        )

    # Validate product is on the shelf
    from app.services.broadcast_product_shelf import list_shelf_products
    shelf_items = list_shelf_products(session_id)
    shelf_item = next((s for s in shelf_items if s["item_id"] == body.item_id), None)
    if not shelf_item:
        raise HTTPException(
            status_code=404,
            detail="Product not found on session shelf. Add it first via the product shelf.",
        )

    # Resolve display name
    user_id = ctx["user_sub"]
    display_name = user_id
    try:
        from app.core.tables import T as _T
        profile_resp = _T.profile.get_item(Key={"user_sub": user_id})
        profile_item = profile_resp.get("Item")
        if profile_item and profile_item.get("display_name"):
            display_name = profile_item["display_name"]
    except Exception:
        pass

    from app.services.broadcast_chat_store import send_product_link_message
    result = send_product_link_message(
        session_id=session_id,
        user_id=user_id,
        display_name=display_name,
        shelf_item=shelf_item,
    )

    # Build response with product_link data
    product_link_data = None
    if result.get("product_link"):
        product_link_data = BroadcastChatProductLinkData(**result["product_link"])

    return BroadcastChatMessageOut(
        message_id=result["message_id"],
        session_id=result["session_id"],
        sender_id=result["sender_id"],
        sender_display_name=result["sender_display_name"],
        text=result["text"],
        created_at=result["created_at"],
        deleted=result.get("deleted", False),
        kind=result.get("kind", "text"),
        product_link=product_link_data,
    )
```

### 3.5 Frontend — ProductLinkCard Component

```typescript
// frontend/src/pages/broadcast/ProductLinkCard.tsx

import { ShoppingCart } from "lucide-react";
import { Button } from "@/components/ui/button";

/**
 * ProductLinkCard — rich product card rendered in the broadcast chat timeline.
 *
 * Displays product image, name, description (truncated), price, and an
 * "Add to Cart" CTA button. Used for both broadcaster and viewer chat panels.
 *
 * Responsive: on mobile (<640px), image shrinks to 48x48 and description
 * is hidden. On desktop, full layout with 64x64 image and 2-line description.
 *
 * Accessibility:
 * - role="article" on the card root
 * - aria-label on the Add to Cart button includes product name
 * - Price has aria-label for screen readers
 */
interface ProductLinkCardProps {
  /** Product data embedded in the chat message */
  productLink: {
    item_id: string;
    category_id: string;
    name: string;
    description: string | null;
    price_cents: number;
    currency: string;
    image_url: string | null;
  };
  /** Callback when viewer clicks "Add to Cart" */
  onAddToCart: (itemId: string, categoryId: string) => void;
  /** Whether the Add to Cart action is in progress */
  isAddingToCart?: boolean;
}

export function ProductLinkCard({ productLink, onAddToCart, isAddingToCart }: ProductLinkCardProps) {
  const price = (productLink.price_cents / 100).toFixed(2);

  return (
    <div
      role="article"
      aria-label={`Product: ${productLink.name}`}
      className="border rounded-lg p-2 bg-blue-50 dark:bg-blue-950 my-1 transition-all duration-200 hover:shadow-md"
    >
      <div className="flex gap-2">
        {productLink.image_url ? (
          <img
            src={productLink.image_url}
            alt={productLink.name}
            className="w-16 h-16 sm:w-12 sm:h-12 object-cover rounded flex-shrink-0"
            loading="lazy"
          />
        ) : (
          <div className="w-16 h-16 sm:w-12 sm:h-12 rounded bg-muted flex items-center justify-center flex-shrink-0">
            <ShoppingCart className="h-6 w-6 text-muted-foreground" />
          </div>
        )}
        <div className="flex-1 min-w-0">
          <p className="font-semibold text-sm truncate">{productLink.name}</p>
          {productLink.description && (
            <p className="text-xs text-muted-foreground line-clamp-2 hidden sm:block">
              {productLink.description}
            </p>
          )}
          <div className="flex items-center justify-between mt-1">
            <span
              className="text-sm font-bold text-green-600 dark:text-green-400"
              aria-label={`Price: $${price}`}
            >
              ${price}
            </span>
            <Button
              size="sm"
              variant="default"
              onClick={() => onAddToCart(productLink.item_id, productLink.category_id)}
              disabled={isAddingToCart}
              aria-label={`Add ${productLink.name} to cart`}
              className="h-6 text-xs"
            >
              <ShoppingCart className="h-3 w-3 mr-1" />
              {isAddingToCart ? "Adding..." : "Add to Cart"}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
```

### 3.6 Frontend — Updated BroadcastChat Component

Extend `BroadcastChat.tsx` to handle `chat:product_link` events and render `ProductLinkCard` for product link messages:

```typescript
// In BroadcastChat.tsx SSE event handlers (inside the useEffect at line 44):

es.addEventListener("chat:product_link", (event) => {
  const msg: ChatMessage = JSON.parse(event.data);
  setMessages(prev => [...prev, msg].slice(-500));
  // Auto-scroll if not user-scrolled
  if (!userScrolledRef.current) {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }
});

// In message rendering loop:
{msg.kind === "product_link" && msg.product_link ? (
  <ProductLinkCard
    productLink={msg.product_link}
    onAddToCart={handleAddToCart}
  />
) : (
  <span className="text-sm">{msg.text}</span>
)}
```

### 3.7 Frontend — ShelfProductPicker Dialog

A dialog for the broadcaster to select which shelf product to share in chat:

```typescript
// frontend/src/pages/broadcast/ShelfProductPicker.tsx

import { useQuery } from "@tanstack/react-query";
import { getShelfProducts } from "@/api/endpoints/broadcast-shelf";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

/**
 * ShelfProductPicker — modal dialog for broadcaster to select a product
 * from their session's shelf to share as a rich card in chat.
 *
 * Only shows products that are currently on the shelf (LCOM-001).
 * Products that were removed will not appear.
 *
 * @param sessionId - Broadcast session ID
 * @param open - Whether the dialog is open
 * @param onClose - Callback to close the dialog
 * @param onSelect - Callback with the selected item_id
 */
interface ShelfProductPickerProps {
  sessionId: string;
  open: boolean;
  onClose: () => void;
  onSelect: (itemId: string) => void;
}

export function ShelfProductPicker({ sessionId, open, onClose, onSelect }: ShelfProductPickerProps) {
  const { data: shelf, isLoading } = useQuery({
    queryKey: ["broadcast-shelf", sessionId],
    queryFn: () => getShelfProducts(sessionId),
    enabled: open,
    staleTime: 10_000,
  });

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent aria-describedby="shelf-picker-description">
        <DialogHeader>
          <DialogTitle>Share Product in Chat</DialogTitle>
          <DialogDescription id="shelf-picker-description">
            Select a product from your shelf to share with viewers.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2 max-h-[400px] overflow-y-auto">
          {isLoading && (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-16 bg-muted animate-pulse rounded" />
              ))}
            </div>
          )}
          {shelf?.items.map((item) => (
            <button
              key={item.item_id}
              onClick={() => { onSelect(item.item_id); onClose(); }}
              className="w-full flex items-center gap-3 p-2 rounded hover:bg-accent transition-colors"
              aria-label={`Share ${item.name} ($${(item.price_cents / 100).toFixed(2)})`}
            >
              {item.image_url && <img src={item.image_url} className="w-12 h-12 rounded object-cover" alt="" />}
              <div className="text-left flex-1">
                <p className="font-medium text-sm">{item.name}</p>
                <p className="text-xs text-muted-foreground">${(item.price_cents / 100).toFixed(2)}</p>
              </div>
            </button>
          ))}
          {!isLoading && shelf?.items.length === 0 && (
            <p className="text-sm text-muted-foreground text-center py-4">
              No products on shelf. Add products first.
            </p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
```

### 3.8 Updated Chat TypeScript Types

```typescript
// frontend/src/api/endpoints/broadcast-chat.ts (extended)

export interface ProductLinkData {
  item_id: string;
  category_id: string;
  name: string;
  description: string | null;
  price_cents: number;
  currency: string;
  image_url: string | null;
}

export interface ChatMessage {
  message_id: string;
  session_id: string;
  sender_id: string;
  sender_display_name: string;
  text: string;
  created_at: number;
  deleted: boolean;
  kind: "text" | "product_link";             // NEW
  product_link?: ProductLinkData;             // NEW
}

// New API function:
export const shareProductInChat = (sessionId: string, itemId: string) =>
  api.post<ChatMessage>(`/broadcast/sessions/${sessionId}/chat/product`, { item_id: itemId });
```

### 3.9 React Query Cache Invalidation Strategy

| Action | Invalidated Keys | Reason |
|--------|-----------------|--------|
| Share product in chat | None (SSE handles real-time) | Chat uses SSE for real-time delivery, not polling |
| Open ShelfProductPicker | `["broadcast-shelf", sessionId]` if stale | Ensure picker shows current shelf state |
| Add to Cart from card | `["cart"]`, `["cart-items", cartId]` | Cart state must reflect the new item |
| SSE reconnect | `["broadcast-chat-history", sessionId]` | Refetch full history to catch missed messages |

---

## 4. Implementation Plan

### Phase 1: Backend — Extend Chat Model (0.5 days)

**Files to modify**:

| File | Change |
|------|--------|
| `app/services/broadcast_chat_store.py` | Add `send_product_link_message`, product link rate limit, extend `_chat_msg_out` with `kind` and `product_link` fields |

**Line-by-line changes**:

1. After line 20 (`_CHAT_RATE_BUCKETS`), add `_PRODUCT_LINK_RATE_LOCK`, `_PRODUCT_LINK_RATE_BUCKETS`, `PRODUCT_LINK_RATE_LIMIT_MS`
2. After `reset_rate_limits()` (line 44), add `_enforce_product_link_rate_limit()` and `reset_product_link_rate_limits()`
3. After `send_chat_message()` (ends at line 148), add `send_product_link_message()` function
4. Modify `_chat_msg_out()` (line 237-247): add `kind` field defaulting to `"text"`, add conditional `product_link` dict

### Phase 2: Backend — Product Link Endpoint (0.5 days)

**Files to modify**:

| File | Change |
|------|--------|
| `app/routers/broadcast.py` | Add `BroadcastChatProductLinkIn` model, `BroadcastChatProductLinkData` model, `POST /sessions/{session_id}/chat/product` endpoint, update `BroadcastChatMessageOut` |

**Exact insertion point**: After the existing `BroadcastChatMuteOut` model (lines 801-804) and before `send_chat_message_route` (line 807), add the new Pydantic models. The endpoint itself goes after the `broadcast_chat_stream_route` function (after line 944).

**Import addition**: Add `send_product_link_message` to the broadcast_chat_store import block at line 37-45.

### Phase 3: Backend — Update SSE Stream (0.5 days)

**Files to modify**:

| File | Change |
|------|--------|
| `app/routers/broadcast.py` | Update `broadcast_chat_stream_route` (line 898-944) to emit `chat:product_link` event type for product link messages |

In the SSE generator loop (line 930-938), change the single `else` branch to check for `kind == "product_link"`:

```python
# Before (lines 933-938):
if msg.get("deleted"):
    payload = json.dumps({"message_id": msg["message_id"]}, ...)
    yield f"event: chat:delete\ndata: {payload}\n\n"
else:
    payload = json.dumps(_chat_msg_out(msg), ...)
    yield f"event: chat:message\ndata: {payload}\n\n"

# After:
if msg.get("deleted"):
    payload = json.dumps({"message_id": msg["message_id"]}, ...)
    yield f"event: chat:delete\ndata: {payload}\n\n"
elif msg.get("kind") == "product_link":
    payload = json.dumps(_chat_msg_out(msg), ...)
    yield f"event: chat:product_link\ndata: {payload}\n\n"
else:
    payload = json.dumps(_chat_msg_out(msg), ...)
    yield f"event: chat:message\ndata: {payload}\n\n"
```

### Phase 4: Frontend — ProductLinkCard + Types (1 day)

**Files to create**:

| File | Purpose |
|------|---------|
| `frontend/src/pages/broadcast/ProductLinkCard.tsx` | Rich product card component for chat timeline |
| `frontend/src/pages/broadcast/ShelfProductPicker.tsx` | Dialog for broadcaster to pick shelf product to share |

**Files to modify**:

| File | Change |
|------|--------|
| `frontend/src/api/endpoints/broadcast-chat.ts` | Add `ProductLinkData` type, extend `ChatMessage` with `kind` and `product_link`, add `shareProductInChat` function |

**Changes to `broadcast-chat.ts`** (line-by-line):

1. After the `ChatMessage` interface (line 13), add `kind: "text" | "product_link"` field and `product_link?: ProductLinkData` field
2. Before the `ChatMessage` interface, add the new `ProductLinkData` interface
3. After `muteChatUser` function (line 54), add `shareProductInChat` function

### Phase 5: Frontend — BroadcastChat Integration (1 day)

**Files to modify**:

| File | Change |
|------|--------|
| `frontend/src/pages/broadcast/BroadcastChat.tsx` | Add SSE listener for `chat:product_link`, conditionally render `ProductLinkCard` vs text, add "Share Product" button for broadcaster, add `handleAddToCart` callback |

Key changes:

1. **Import ProductLinkCard** at top of file (after existing imports)
2. **Add `chat:product_link` SSE event listener** (line 60, alongside existing `chat:message` listener)
3. **Conditional rendering** in message loop: check `msg.kind === "product_link"` to render ProductLinkCard
4. **Add "Share Product" button** (shopping bag icon) in chat input area, visible only when `isBroadcaster` is true
5. **Add `handleAddToCart` callback**: calls `createCart()` if no active cart, then `addCartItem(cartId, { sku: item_id, quantity: 1 })`
6. **Add toast** on successful add-to-cart
7. **Add ShelfProductPicker dialog state**: `const [pickerOpen, setPickerOpen] = useState(false)`

### Phase 6: Frontend — Chat Overlay Extension (0.5 days)

**Files to modify**:

| File | Change |
|------|--------|
| `frontend/src/pages/broadcast/ChatOverlay.tsx` | Product link messages in overlay show a compact format: "{name} - ${price}" with a shopping bag icon, instead of the full card |

### Summary of All Files

| File | Type | Estimated Lines |
|------|------|-----------------|
| `app/services/broadcast_chat_store.py` | Modify | +60 |
| `app/routers/broadcast.py` | Modify | +60 |
| `frontend/src/api/endpoints/broadcast-chat.ts` | Modify | +20 |
| `frontend/src/pages/broadcast/ProductLinkCard.tsx` | Create | ~80 |
| `frontend/src/pages/broadcast/ShelfProductPicker.tsx` | Create | ~100 |
| `frontend/src/pages/broadcast/BroadcastChat.tsx` | Modify | +40 |
| `frontend/src/pages/broadcast/ChatOverlay.tsx` | Modify | +15 |
| **Total** | | **~375** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_chat_product_link.py`)

~150 lines, using `moto` for DynamoDB mocking.

```python
import time
import pytest
from moto import mock_dynamodb
from fastapi import HTTPException

from app.services.broadcast_chat_store import (
    send_product_link_message,
    send_chat_message,
    get_chat_history,
    reset_product_link_rate_limits,
    reset_rate_limits,
    _chat_msg_out,
    PRODUCT_LINK_RATE_LIMIT_MS,
)

MOCK_SHELF_ITEM = {
    "item_id": "item1",
    "category_id": "cat1",
    "name": "Test Product",
    "description": "A wonderful test product for chat link testing",
    "price_cents": 2999,
    "currency": "USD",
    "image_url": "https://example.com/img1.jpg",
}

MOCK_SHELF_ITEM_NO_IMAGE = {
    "item_id": "item2",
    "category_id": "cat1",
    "name": "Imageless Product",
    "price_cents": 999,
    "currency": "USD",
    "image_url": None,
}


@mock_dynamodb
class TestBroadcastChatProductLink:
    def setup_method(self):
        """Create BroadcastChatMessages table and reset rate limits."""
        import boto3
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = self.ddb.create_table(
            TableName="BroadcastChatMessages",
            KeySchema=[
                {"AttributeName": "session_id", "KeyType": "HASH"},
                {"AttributeName": "sort_key", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "session_id", "AttributeType": "S"},
                {"AttributeName": "sort_key", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        # Patch T.broadcast_chat_messages
        from unittest.mock import patch
        self._patcher = patch("app.services.broadcast_chat_store.T")
        self._mock_T = self._patcher.start()
        self._mock_T.broadcast_chat_messages = self.table
        reset_product_link_rate_limits()
        reset_rate_limits()

    def teardown_method(self):
        self._patcher.stop()

    def test_send_product_link_message(self):
        result = send_product_link_message("sess1", "user1", "Alice", MOCK_SHELF_ITEM)
        assert result["kind"] == "product_link"
        assert result["product_link"]["item_id"] == "item1"
        assert result["product_link"]["name"] == "Test Product"
        assert result["product_link"]["price_cents"] == 2999
        assert result["text"] == "Shared: Test Product"
        assert result["message_id"].startswith("cm_")

    def test_product_link_rate_limit(self):
        send_product_link_message("sess1", "user1", "Alice", MOCK_SHELF_ITEM)
        with pytest.raises(HTTPException) as exc_info:
            send_product_link_message("sess1", "user1", "Alice", MOCK_SHELF_ITEM)
        assert exc_info.value.status_code == 429
        assert "BROADCAST_PRODUCT_LINK_RATE_LIMITED" in exc_info.value.detail["code"]
        assert "retry_after_ms" in exc_info.value.detail

    def test_product_link_appears_in_history(self):
        send_product_link_message("sess1", "user1", "Alice", MOCK_SHELF_ITEM)
        history = get_chat_history("sess1")
        assert len(history["messages"]) == 1
        assert history["messages"][0]["kind"] == "product_link"
        assert history["messages"][0]["product_link"]["item_id"] == "item1"

    def test_text_message_defaults_to_text_kind(self):
        send_chat_message("sess1", "user1", "Alice", "Hello", skip_rate_limit=True)
        history = get_chat_history("sess1")
        assert history["messages"][0]["kind"] == "text"
        assert history["messages"][0].get("product_link") is None

    def test_product_link_description_truncated(self):
        shelf_item = {**MOCK_SHELF_ITEM, "description": "x" * 500}
        result = send_product_link_message("sess1", "user1", "Alice", shelf_item)
        assert len(result["product_link"]["description"]) <= 200

    def test_product_link_rate_limit_independent_from_text_rate_limit(self):
        """Text messages have their own rate limit; product links have a separate one."""
        send_chat_message("sess1", "user1", "Alice", "hello", skip_rate_limit=False)
        # Immediately sending a product link should NOT be blocked by the text rate limit
        result = send_product_link_message("sess1", "user1", "Alice", MOCK_SHELF_ITEM)
        assert result["kind"] == "product_link"

    def test_product_link_no_image(self):
        result = send_product_link_message("sess1", "user1", "Alice", MOCK_SHELF_ITEM_NO_IMAGE)
        assert result["product_link"]["image_url"] is None
        assert result["product_link"]["name"] == "Imageless Product"

    def test_chat_msg_out_backward_compatible(self):
        """Messages without a kind field default to 'text'."""
        legacy_item = {
            "message_id": "cm_test",
            "session_id": "sess1",
            "sender_id": "user1",
            "sender_display_name": "Alice",
            "text": "Old message",
            "created_at": 1234567890,
            "deleted": False,
            # No "kind" field
        }
        out = _chat_msg_out(legacy_item)
        assert out["kind"] == "text"
        assert "product_link" not in out

    def test_mixed_messages_in_history(self):
        """Text and product_link messages interleave correctly."""
        send_chat_message("sess1", "user1", "Alice", "Hi!", skip_rate_limit=True)
        send_product_link_message("sess1", "user1", "Alice", MOCK_SHELF_ITEM)
        send_chat_message("sess1", "user2", "Bob", "Cool!", skip_rate_limit=True)
        history = get_chat_history("sess1")
        assert len(history["messages"]) == 3
        assert history["messages"][0]["kind"] == "text"
        assert history["messages"][1]["kind"] == "product_link"
        assert history["messages"][2]["kind"] == "text"
```

### 5.2 Backend Integration Tests

```python
class TestBroadcastChatProductLinkEndpoint:
    def test_broadcaster_can_share_product(self, client, broadcaster_headers, live_session_id, shelf_item_id):
        resp = client.post(
            f"/broadcast/sessions/{live_session_id}/chat/product",
            json={"item_id": shelf_item_id},
            headers=broadcaster_headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["kind"] == "product_link"
        assert data["product_link"]["item_id"] == shelf_item_id
        assert data["text"].startswith("Shared:")

    def test_viewer_cannot_share_product(self, client, viewer_headers, live_session_id, shelf_item_id):
        resp = client.post(
            f"/broadcast/sessions/{live_session_id}/chat/product",
            json={"item_id": shelf_item_id},
            headers=viewer_headers,
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "NOT_SESSION_CREATOR"

    def test_product_must_be_on_shelf(self, client, broadcaster_headers, live_session_id):
        resp = client.post(
            f"/broadcast/sessions/{live_session_id}/chat/product",
            json={"item_id": "not_on_shelf"},
            headers=broadcaster_headers,
        )
        assert resp.status_code == 404

    def test_product_link_in_history(self, client, viewer_headers, live_session_id):
        resp = client.get(
            f"/broadcast/sessions/{live_session_id}/chat?limit=100",
            headers=viewer_headers,
        )
        assert resp.status_code == 200
        product_msgs = [m for m in resp.json()["messages"] if m["kind"] == "product_link"]
        assert len(product_msgs) >= 1
        assert product_msgs[0]["product_link"]["item_id"] is not None

    def test_not_live_returns_403(self, client, broadcaster_headers, draft_session_id, shelf_item_id):
        resp = client.post(
            f"/broadcast/sessions/{draft_session_id}/chat/product",
            json={"item_id": shelf_item_id},
            headers=broadcaster_headers,
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "BROADCAST_NOT_LIVE"

    def test_rate_limit_returns_429(self, client, broadcaster_headers, live_session_id, shelf_item_id):
        # First share succeeds
        resp1 = client.post(
            f"/broadcast/sessions/{live_session_id}/chat/product",
            json={"item_id": shelf_item_id},
            headers=broadcaster_headers,
        )
        assert resp1.status_code == 201
        # Immediate second share is rate limited
        resp2 = client.post(
            f"/broadcast/sessions/{live_session_id}/chat/product",
            json={"item_id": shelf_item_id},
            headers=broadcaster_headers,
        )
        assert resp2.status_code == 429
        assert "retry_after_ms" in resp2.json()["detail"]
```

### 5.3 E2E Tests (`frontend/e2e/broadcast-chat-products.spec.ts`)

**Section 110: Product Link API (6 tests)**:

1. Broadcaster shares a product link in live chat — returns 201 with `kind=product_link`
2. Viewer cannot share product links — returns 403
3. Product not on shelf — returns 404
4. Product link appears in chat history with full `product_link` data
5. Product link rate limit — second share within 5s returns 429
6. Product link while session not live — returns 403

**Section 111: Product Link SSE (3 tests)**:

1. Viewer receives `chat:product_link` SSE event when broadcaster shares a product
2. Product link event includes `product_link` data (item_id, name, price_cents, image_url)
3. Product link and regular text messages interleave correctly in chat timeline

**Section 112: Product Link UI — Viewer (5 tests)**:

1. Product link card renders in chat with product name and price
2. Product link card shows product image when available
3. "Add to Cart" button on product card triggers cart API
4. Product link card without image renders with placeholder
5. Product link appears in chat overlay in compact format

**Section 113: Product Link UI — Broadcaster (4 tests)**:

1. "Share Product" button is visible in chat input area for broadcaster
2. Clicking opens ShelfProductPicker dialog with shelf items
3. Selecting a product sends `chat/product` POST and card appears in chat
4. "Share Product" button is not visible for viewers

**Test setup**:

```typescript
let rootPage: Page;
let alicePage: Page;
let sessionId: string;
let shelfItemId: string;
const TS = Date.now();

test.beforeAll(async ({ browser }) => {
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");

  // 1. Create broadcast session (root as broadcaster)
  const profile = await apiPost(rootPage, "root", "/broadcast/profiles", {
    name: `chat-link-profile-${TS}`,
    region: "us-east-1",
    rendition_preset: "720p",
  });
  const session = await apiPost(rootPage, "root", "/broadcast/sessions", {
    profile_id: profile.id,
  });
  sessionId = session.session_id;

  // 2. Create catalog category + item
  const cat = await apiPost(rootPage, "root", "/ui/catalog/categories", {
    name: `chat-link-cat-${TS}`,
  });
  const item = await apiPost(rootPage, "root", `/ui/catalog/categories/${cat.category_id}/items`, {
    name: `Chat Widget ${TS}`,
    price_cents: 1599,
    currency: "USD",
  });
  shelfItemId = item.item_id;

  // 3. Add item to session's product shelf (LCOM-001 endpoint)
  await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/products`, {
    item_id: shelfItemId,
    category_id: cat.category_id,
  });

  // 4. Start session (make it live)
  await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/start`, {});
});
```

### 5.4 Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Product removed from shelf after sharing | Existing product link messages in chat remain visible with denormalized data |
| Chat history loaded with mixed text and product_link messages | Both render correctly, product links as cards and text as plain messages |
| Multiple product links shared rapidly | Rate limit enforced at 1 per 5 seconds; second share within window returns 429 |
| Product link message deleted by moderator | `chat:delete` event hides the card like any other message |
| Viewer joins mid-broadcast | Chat history includes product link messages; SSE catches new ones |
| Product link in ChatOverlay | Renders compact format: product name + price, no full card |
| DDB item with no `kind` field (pre-migration messages) | `_chat_msg_out` defaults `kind` to `"text"`, backward compatible |
| Product link with null description | Card renders without description line; layout adjusts |
| Product link with null image_url | Card renders placeholder icon instead of image |
| Broadcaster shares same product multiple times | Each creates a new chat message with denormalized data at that point in time |

### 5.5 Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| Product link rate limit state from previous test | Use unique session per test section; rate limit keys include session_id |
| SSE event ordering | Product link SSE events are guaranteed FIFO per session (single DDB partition) |
| Shelf dependency | Create shelf items in `beforeAll`; assert shelf is populated before product link tests |
| Cart state from previous tests | Create a fresh cart in each test that uses add-to-cart |
| Kind field absent on old messages | Default to `"text"` in `_chat_msg_out` ensures backward compatibility |
| Rate limit timing edge cases | Use `time.sleep(6)` between rate-limited tests to ensure clean state |

---

## 6. Security Considerations

### 6.1 Authorization Model

- **Product link sharing**: Restricted to the session creator (broadcaster). This is a deliberate moderation choice — if all viewers could share product links, the chat would be flooded with link spam.
- **Viewing product links**: Any authenticated viewer can see product links in chat (they appear in the chat history and SSE stream).
- **Deleting product link messages**: Same rules as text messages — broadcaster or admin can delete via `DELETE /broadcast/sessions/{id}/chat/{message_id}`.

### 6.2 Shelf-Gating Prevents Arbitrary Product Injection

Product links can only reference items that are currently on the session's shelf. This prevents a malicious broadcaster from injecting links to arbitrary catalog items (e.g., a competitor's product) or non-existent items. The shelf acts as a curated allowlist.

### 6.3 Rate Limiting Prevents Spam

The 5-second product link rate limit prevents the broadcaster from flooding the chat with product cards. This is separate from the text message rate limit (2 seconds, from `S.broadcast_chat_rate_limit_ms`). Both rate limits use in-memory buckets keyed by `session_id#user_id`, so they cannot be bypassed by switching sessions.

### 6.4 Input Validation

- **item_id**: Validated via Pydantic `min_length=1, max_length=128` plus custom validator rejecting `#` and newline characters.
- **Product link data**: All fields are denormalized from the shelf (trusted data), not from user input. The description is truncated to 200 characters.
- **XSS prevention**: Product names and descriptions are rendered as text content (not `dangerouslySetInnerHTML`) in React, so HTML entities are auto-escaped.

### 6.5 CSRF Protection

The `POST /broadcast/sessions/{id}/chat/product` endpoint uses `require_ui_session` which enforces CSRF for cookie-based auth. The frontend must include the `x-csrf-token` header (automatically handled by the axios client in `api/client.ts`).

---

## 7. Migration & Rollback Plan

### 7.1 No Schema Migration Required

This ticket modifies the DDB item shape for `BroadcastChatMessages` by adding `kind` and `product_link` fields. Since DynamoDB is schema-less, no migration is needed. Existing messages without these fields will default to `kind: "text"` via the `_chat_msg_out` function.

### 7.2 Feature Flag Rollout

1. **Phase 0**: Deploy backend changes. `_chat_msg_out` is backward compatible — existing chat endpoints return `kind: "text"` for all pre-existing messages.
2. **Phase 1**: Deploy frontend with `ProductLinkCard` but keep "Share Product" button behind feature flag `BROADCAST_CHAT_PRODUCT_LINKS_ENABLED`. Viewers can see product links if any exist, but broadcasters cannot create them yet.
3. **Phase 2**: Enable the feature flag for all broadcasters.
4. **Phase 3**: Remove the feature flag after 2 weeks of stable operation.

### 7.3 Rollback Steps

- **Frontend rollback**: Remove `ProductLinkCard` rendering. Product link messages fall back to rendering as text (showing "Shared: Product Name"). No data loss.
- **Backend rollback**: Remove `share_product_in_chat_route` endpoint. Existing product link messages in DDB are orphaned but render as text via backward-compatible `_chat_msg_out`. No data migration needed.

### 7.4 Backward Compatibility

- The `kind` field defaults to `"text"` for all existing messages.
- The `product_link` field is optional and only included when `kind == "product_link"`.
- The existing `chat:message` SSE event type is unchanged. Only the new `chat:product_link` event type is added.
- Old frontend versions (without ProductLinkCard) will render product link messages as text: "Shared: Product Name".

---

## 8. Operational Runbook

### 8.1 Key Metrics

| Metric | Description | Source |
|--------|-------------|--------|
| `broadcast.chat.product_links_shared` | Counter of product links shared per session | Endpoint |
| `broadcast.chat.product_link_rate_limited` | Counter of 429 responses for product link rate limiting | Endpoint |
| `broadcast.chat.product_link_cart_adds` | Counter of "Add to Cart" from product link cards | Frontend analytics |
| `broadcast.chat.product_link_click_rate` | Ratio of cart adds to product links viewed | Computed |
| `broadcast.chat.product_link_latency_ms` | P50/P95/P99 for the share endpoint | Endpoint middleware |

### 8.2 Alerting Thresholds

| Alert | Threshold | Action |
|-------|-----------|--------|
| Product link share P99 > 500ms | 5 consecutive minutes | Check shelf list query performance |
| Product link 404 rate > 20% | 2 minutes | Check shelf consistency (products removed mid-session) |
| Product link 429 rate > 50% | Informational | Broadcaster is sharing rapidly; rate limit working as designed |

### 8.3 Common Debugging

**Problem: Product link card not appearing in viewer's chat**
1. Check SSE connection in browser Network tab — look for `chat:product_link` event
2. Verify product link message exists in chat history: `GET /broadcast/sessions/{id}/chat?limit=100`
3. Check that frontend SSE listener includes `chat:product_link` handler
4. Check browser console for React rendering errors

**Problem: "Share Product" button not showing for broadcaster**
1. Verify `isBroadcaster` prop is true in BroadcastChat
2. Check that the broadcaster's user_sub matches `session.created_by`
3. Verify shelf has products (button may be hidden when shelf is empty)

### 8.4 Log Patterns

```
# Successful product link share
INFO broadcast.chat session_id=sess_abc action=product_link item_id=item_123 broadcaster=user_456

# Rate limited
WARN broadcast.chat session_id=sess_abc action=product_link_rate_limited broadcaster=user_456 retry_after_ms=3200

# Product not on shelf
WARN broadcast.chat session_id=sess_abc action=product_link_failed item_id=item_999 reason=not_on_shelf
```

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput

Product link sharing is a low-frequency operation — a typical broadcaster shares 5-20 product links per hour-long broadcast. This is orders of magnitude below DDB write capacity limits.

| Operation | Expected Rate | DDB Impact |
|-----------|--------------|------------|
| Share product link | 1-5 per minute peak | 1 WCU per write (~1KB item) |
| Chat history with product links | Same as existing chat history | No additional RCU (same query) |
| SSE delivery | Same as existing chat SSE | No additional cost |

### 9.2 Product Link Card Rendering Performance

- **ProductLinkCard** is a lightweight functional component (~80 lines). No heavy computations.
- **Image loading**: Uses `loading="lazy"` to prevent waterfall loading when scrolling through chat history with many product links.
- **Memory**: Each product link message adds ~200 bytes to the chat message state (same as a text message plus the product_link object). With 500 messages max in memory (enforced by `.slice(-500)`), this is ~100KB max.

### 9.3 Rate Limit Memory

The in-memory rate limit buckets use one entry per `session_id#user_id` pair. With 1000 concurrent sessions and 1 broadcaster each, this is 1000 entries * ~50 bytes = 50KB. Negligible.

---

## 10. Dependency Analysis

### 10.1 Dependencies

| Dependency | Type | Notes |
|------------|------|-------|
| LCOM-001 (Product Shelf) | Hard prerequisite | Product links must reference items on the shelf |
| Broadcast chat system | Integration | Product links are stored in the same DDB table as text messages |
| Broadcast SSE | Integration | New event type `chat:product_link` |
| Shopping cart API | Frontend integration | "Add to Cart" button calls cart endpoints |

### 10.2 Downstream Consumers

| Consumer | How They Use LCOM-002 |
|----------|----------------------|
| LCOM-003 (Quick-Buy) | "Buy Now" button on ProductLinkCard uses quick-buy flow |
| LCOM-004 (Exclusive Pricing) | Product link cards show broadcast price when available |
| Analytics | Product link shares are tracked for conversion attribution |

### 10.3 API Contract

LCOM-002 adds one new endpoint and modifies the response shape of two existing endpoints:

- **New**: `POST /broadcast/sessions/{id}/chat/product` (depends on shelf data from LCOM-001)
- **Modified**: `GET /broadcast/sessions/{id}/chat` (response now includes `kind` and `product_link` fields — backward compatible)
- **Modified**: `GET /broadcast/sessions/{id}/chat/stream` (SSE stream now emits `chat:product_link` events — additive)

---

## 11. Acceptance Criteria

### 11.1 Functional

1. Broadcaster can share a product from the shelf as a rich card in live chat.
2. Product link card displays name, price, image, and "Add to Cart" button.
3. Viewers see product link cards in real time via SSE.
4. Product link messages persist in chat history and are visible to late joiners.
5. Rate limit prevents sharing more than 1 product link per 5 seconds.
6. Only the broadcaster can share product links (viewers get 403).
7. Product must be on the shelf (404 if not).
8. "Add to Cart" on a product link card adds the item to the viewer's shopping cart.
9. Product link cards in ChatOverlay show compact format.

### 11.2 Non-Functional

1. Product link share endpoint responds in < 100ms P95.
2. SSE event delivery for product links is < 200ms P95.
3. Chat history with 100 mixed text+product_link messages renders in < 500ms.
4. All 18 E2E tests pass with 0 flakes on 3 consecutive runs.

---

## 12. Error Handling Matrix

| Error | HTTP Status | Error Code | User Message | Recovery Action |
|-------|-------------|-----------|--------------|----------------|
| Session not live | 403 | BROADCAST_NOT_LIVE | "Chat is only available while the broadcast is live." | Wait for session to go live |
| Caller not broadcaster | 403 | NOT_SESSION_CREATOR | "Only the broadcaster can share products in chat." | N/A (role-based) |
| Product not on shelf | 404 | (default) | "Product not found on session shelf. Add it first." | Add product to shelf via LCOM-001 |
| Rate limited | 429 | BROADCAST_PRODUCT_LINK_RATE_LIMITED | "You can share one product every 5 seconds." | Wait `retry_after_ms` milliseconds |
| Session not found | 404 | (default) | "Broadcast session not found." | Check session ID |
| Invalid item_id format | 422 | VALIDATION_ERROR | "item_id must not contain '#' or newline." | Fix item_id |
| Shelf read failure | 500 | INTERNAL_ERROR | "Internal server error." | Retry |

---

## 13. Real-time Synchronization

### 13.1 SSE Event Schema

**Event: `chat:product_link`**

```json
{
  "message_id": "cm_abc123def456",
  "session_id": "sess_789",
  "sender_id": "user_broadcaster",
  "sender_display_name": "StreamerAlice",
  "text": "Shared: Winter Jacket",
  "created_at": 1716580123,
  "deleted": false,
  "kind": "product_link",
  "product_link": {
    "item_id": "item_123",
    "category_id": "cat_456",
    "name": "Winter Jacket",
    "description": "Warm insulated winter jacket",
    "price_cents": 4999,
    "currency": "USD",
    "image_url": "https://cdn.example.com/jacket.jpg"
  }
}
```

### 13.2 Optimistic UI Updates

Product link messages are not optimistic — the broadcaster sees the card only after the server confirms (201 response). This is because:

1. The product link data comes from the server (shelf lookup), not from the client.
2. Rate limiting happens server-side, so optimistic display could show a card that gets 429'd.
3. The latency for the share endpoint is < 100ms, so the delay is imperceptible.

### 13.3 Conflict Resolution

| Scenario | Resolution |
|----------|-----------|
| Product removed from shelf while link is being shared | Share succeeds with stale data (denormalized at share time). Future shares of the same item will fail with 404. |
| Product price changed on shelf after link shared | Chat card shows the price at share time. Shelf card shows the current price. |
| SSE reconnect after gap | Client re-fetches chat history to catch any missed product link messages. SSE catches subsequent messages. |
| Viewer adds product to cart but product was removed from catalog | Cart add may fail at checkout; this is a catalog-level concern, not LCOM-002. |

---

## 14. Analytics & Attribution

### 14.1 Product Link Engagement Tracking

| Event | Properties | Trigger |
|-------|-----------|---------|
| `chat.product_link.shared` | `session_id`, `item_id`, `price_cents` | Broadcaster shares a product link |
| `chat.product_link.viewed` | `session_id`, `item_id`, `viewer_id` | Product link card visible in viewport for > 1s |
| `chat.product_link.cart_add` | `session_id`, `item_id`, `viewer_id`, `price_cents` | Viewer clicks "Add to Cart" on product link |
| `chat.product_link.click_rate` | `session_id`, `views`, `clicks`, `rate` | Computed at end of session |

### 14.2 Conversion Funnel

```
Product Link Shared (broadcaster action)
    │
    ▼
Product Link Viewed (viewer sees card in chat)
    │
    ▼
"Add to Cart" Clicked (viewer action)
    │
    ▼
Cart → Checkout → Purchase (standard flow, or LCOM-003 quick-buy)
```

The attribution chain: `broadcast_session_id → product_link_message_id → cart_item → order`. This enables analytics like "products shared in chat during Session X generated $Y in purchases."

---

## Appendix A: API Reference Summary

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/broadcast/sessions/{id}/chat/product` | Session creator | Share product link in chat |
| GET | `/broadcast/sessions/{id}/chat` | Any authenticated | Chat history (now includes product_link messages) |
| GET | `/broadcast/sessions/{id}/chat/stream` | Any authenticated | SSE stream (now emits chat:product_link events) |

## Appendix B: SSE Event Types (Extended)

| Event | Payload | Trigger |
|-------|---------|---------|
| `chat:message` | `BroadcastChatMessageOut` (kind=text) | Text message sent |
| `chat:product_link` | `BroadcastChatMessageOut` (kind=product_link, includes product_link data) | Product shared in chat |
| `chat:delete` | `{"message_id": "..."}` | Message deleted by moderator |

## Appendix C: Related Tickets

- **LCOM-001**: Broadcast product shelf (prerequisite — products must be on shelf before sharing in chat)
- **LCOM-003**: Broadcast quick-buy checkout (the "Buy Now" button on ProductLinkCard will use this)
- **LCOM-004**: Broadcast-exclusive pricing (product link cards will show broadcast price when available)

## Appendix D: Frontend Component Tree

```
BroadcastChat (modified)
├── ChatMessageList
│   ├── TextMessage (existing, kind="text")
│   └── ProductLinkCard (NEW, kind="product_link")
│       ├── ProductImage (64x64 or placeholder)
│       ├── ProductInfo (name, description, price)
│       └── AddToCartButton
├── ChatInput (existing)
│   ├── TextInput (existing)
│   └── ShareProductButton (NEW, broadcaster only)
└── ShelfProductPicker (NEW, dialog)
    └── ShelfItemList
        └── ShelfItemButton × N (click to share)
```
