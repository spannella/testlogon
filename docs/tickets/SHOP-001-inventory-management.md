# SHOP-001: Inventory Management

**Ticket**: SHOP-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Executive Summary

The catalog system currently has no concept of stock quantity. Sellers can create items with a name, description, price, images, and attributes, but there is no `stock_count` field to track how many units are available. This means a seller cannot indicate when an item is out of stock, the checkout flow cannot prevent overselling, and there is no mechanism to alert sellers when inventory runs low. For any e-commerce platform handling physical goods or limited-quantity digital products, inventory management is a fundamental capability.

This feature adds a `stock_count` integer field to catalog items, a dedicated `PATCH /ui/catalog/items/{id}/stock` endpoint for atomic stock adjustments, automatic stock decrement on purchase, an out-of-stock guard in the checkout flow, a low-stock alert trigger integrated with the existing alerts system, and frontend UI for managing stock in the ItemEditor dialog and viewing stock levels in the admin catalog table.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Seller | I want to set a stock quantity when creating a catalog item. | ItemEditor shows a "Stock quantity" numeric input; value is saved to DynamoDB. |
| Seller | I want to adjust stock (restock or correct) without editing the full item. | `PATCH /ui/catalog/items/{id}/stock` accepts a delta or absolute value. |
| Seller | I want to see current stock levels at a glance in my catalog table. | Admin catalog table shows a "Stock" column with numeric badge (red when low). |
| Seller | I want to be alerted when an item drops below a configurable low-stock threshold. | Alert written to the alerts table when `stock_count` falls below threshold. |
| Buyer | I should not be able to purchase an out-of-stock item. | Cart purchase returns 409 with "out of stock" message when `stock_count <= 0`. |
| Buyer | I want to see "In Stock" / "Out of Stock" / "Low Stock" status on product pages. | ProductDetail page shows stock status badge. |

### 2.2 Pain Points

1. **Overselling**: Without stock tracking, sellers can accept orders for items they cannot fulfill, leading to cancellations and poor buyer experience.
2. **Manual tracking**: Sellers must track inventory externally (spreadsheets, notes) and manually remove items from the catalog when sold out.
3. **No urgency signals**: Buyers have no "Only 3 left!" urgency indicator, reducing conversion on limited items.
4. **No restock workflow**: When items sell out, sellers get no notification and must manually check each listing.

---

## 3. Current State Analysis

### 3.1 Catalog Item Model

The `CatalogItemOut` Pydantic model (`app/models.py:538-549`) defines the item response shape. It includes `category_id`, `item_id`, `name`, `description`, `price_cents`, `currency`, `image_urls`, `attributes`, `creator_id`, `created_at`, and `updated_at`. There is no `stock_count`, `stock_status`, or inventory-related field.

The `CatalogItemCreateIn` model (`app/models.py:519-526`) accepts `name`, `description`, `price_cents`, `currency`, `image_urls`, and `attributes`. No stock quantity input.

The `CatalogItemPatchIn` model (`app/models.py:529-535`) allows partial updates to `name`, `description`, `price_cents`, `currency`, `image_urls`, and `attributes`. No stock field.

### 3.2 Catalog Router

`app/routers/catalog.py` (664 lines) implements full CRUD:

- **Create** (`app/routers/catalog.py:308-341`): `POST /ui/catalog/categories/{category_id}/items` builds a DynamoDB item with `PK=CAT#{category_id}`, `SK=ITEM#{item_id}`. The item dict (lines 316-331) has no `stock_count` attribute.
- **Update** (`app/routers/catalog.py:430-478`): `PATCH /ui/catalog/categories/{category_id}/items/{item_id}` builds a dynamic `UpdateExpression` for each non-null patch field. No stock-related branch exists.
- **List** (`app/routers/catalog.py:344-356`): Returns paginated items under a category.
- **Delete** (`app/routers/catalog.py` further down): Soft or hard delete.

There is no `/stock` endpoint, no stock validation in any flow, and no inventory-related function in the entire file.

### 3.3 DynamoDB Table

The catalog table is defined in `scripts/local-ddb-init.py:68` as `shopping_catalog` with `PK` (partition key) and `SK` (sort key). The table handle is in `app/core/tables.py:35,133` as `T.catalog`. Settings reference: `app/core/settings.py:712` (`catalog_table_name`).

### 3.4 Shopping Cart Purchase Flow

`app/services/shoppingcart.py:428-527` (`purchase_cart`) processes a cart purchase. The function:
1. Validates the cart is `OPEN` (line 440)
2. Lists cart items and sums total (lines 442-443)
3. Creates a commerce order (lines 449-456)
4. Updates cart status to `PURCHASED` (lines 461-484)
5. Processes entitlements (lines 501-508)
6. Records purchase history (lines 510-518)

At no point does it check item stock levels or decrement stock counts. The `list_items` call at line 442 fetches cart items but does not cross-reference catalog item availability.

### 3.5 Frontend ItemEditor

`frontend/src/pages/shop/ItemEditor.tsx` (313 lines) is a dialog for creating/editing catalog items. It manages state for `name`, `description`, `priceDollars`, `currency`, `attrs`, and `imageUrls` (lines 54-60). There is no `stockCount` state variable, no stock input field, and no stock display.

### 3.6 Frontend Types

`frontend/src/api/types.ts:1719-1731` defines the `CatalogItem` interface with no `stock_count` or `stock_status` field. `CatalogItemIn` (types.ts:1709-1717) similarly has no stock field.

### 3.7 Alerts System

The alerts service (`app/services/alerts.py:265-301`) provides `write_alert(user_sub, *, event, outcome, title, details)` which stores alerts in the `alerts` DynamoDB table with TTL, priority classification, and unread count tracking. This is the integration point for low-stock notifications.

### 3.8 Gaps

1. No `stock_count` field on catalog items (model, DynamoDB, API)
2. No stock adjustment endpoint
3. No stock validation during checkout
4. No stock decrement on purchase
5. No low-stock alert mechanism
6. No stock UI in ItemEditor or admin catalog table
7. No stock status display on product pages

---

## 4. Technical Architecture

### 4.1 System Diagram

```
+-------------------+       +---------------------+       +----------------------+
|  ItemEditor       |       |   Catalog Router     |       |   DynamoDB           |
|  (create/edit)    |------>| POST items           |------>| CAT#{cat_id}         |
|  stock_count input|       | PATCH items/{id}     |       | ITEM#{item_id}       |
+-------------------+       |                      |       | stock_count: N       |
                            | PATCH items/{id}/    |       | low_stock_threshold: N|
+-------------------+       |   stock              |       +----------------------+
|  AdminCatalog     |       +---------------------+               |
|  stock column     |               |                              |
+-------------------+               v                              |
                            +---------------------+       +----------------------+
+-------------------+       |  Purchase Flow       |       |   Alerts Table       |
|  ProductDetail    |       |  (shoppingcart.py)   |------>| low_stock_alert      |
|  stock badge      |       |  stock validation    |       +----------------------+
+-------------------+       |  stock decrement     |
                            +---------------------+
```

### 4.2 Data Flow -- Stock Adjustment

1. Seller opens ItemEditor, enters stock quantity (e.g., 50)
2. On save, frontend sends `stock_count: 50` as part of the create/patch payload
3. Backend stores `stock_count` as a Number attribute on the DynamoDB item
4. Alternatively, seller uses dedicated stock endpoint: `PATCH /ui/catalog/items/{id}/stock` with `{ "delta": -5 }` or `{ "absolute": 45 }`
5. Backend performs atomic `ADD stock_count :delta` or `SET stock_count = :val`
6. After update, if `stock_count <= low_stock_threshold`, trigger low-stock alert

### 4.3 Data Flow -- Purchase Stock Decrement

1. `purchase_cart()` iterates cart items
2. For each item with a `category_id` and `item_id`, performs atomic decrement: `ADD stock_count :neg_qty` with `ConditionExpression: stock_count >= :qty`
3. If condition fails (insufficient stock), raises 409 with item details
4. All decrements succeed before marking cart as PURCHASED
5. If any decrement triggers `stock_count <= low_stock_threshold`, write low-stock alert

---

## 5. Data Model Changes

### 5.1 Catalog Item -- New Fields

| Field | Type | Description | Default | Example |
|-------|------|-------------|---------|---------|
| `stock_count` | N | Current units in stock; `null` = unlimited (no tracking) | `null` | `50` |
| `low_stock_threshold` | N | Alert when stock falls to or below this value | `5` | `10` |
| `stock_status` | S | Computed: `in_stock`, `low_stock`, `out_of_stock`, or `unlimited` | `unlimited` | `low_stock` |
| `stock_updated_at` | S | ISO timestamp of last stock change | `null` | `2026-05-27T10:00:00Z` |

**DynamoDB item example after stock is set:**

```json
{
  "PK": "CAT#electronics",
  "SK": "ITEM#1748380800000_abc123",
  "entity": "item",
  "category_id": "electronics",
  "item_id": "1748380800000_abc123",
  "name": "Wireless Headphones",
  "price_cents": 4999,
  "stock_count": 12,
  "low_stock_threshold": 5,
  "stock_updated_at": "2026-05-27T14:30:00Z",
  "created_at": "2026-05-20T10:00:00Z",
  "updated_at": "2026-05-27T14:30:00Z"
}
```

### 5.2 Stock Status Computation

The `stock_status` field is computed at read time, not stored:

```python
def _compute_stock_status(item: dict) -> str:
    sc = item.get("stock_count")
    if sc is None:
        return "unlimited"
    sc = int(sc)
    if sc <= 0:
        return "out_of_stock"
    threshold = int(item.get("low_stock_threshold", 5) or 5)
    if sc <= threshold:
        return "low_stock"
    return "in_stock"
```

### 5.3 Settings in `app/core/settings.py`

```python
catalog_default_low_stock_threshold: int = int(os.environ.get("CATALOG_LOW_STOCK_THRESHOLD", "5"))
catalog_stock_alerts_enabled: bool = os.environ.get("CATALOG_STOCK_ALERTS_ENABLED", "1") not in ("0", "false", "False")
```

---

## 6. API Contract Design

### 6.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/catalog/categories/{cat_id}/items` | `require_ui_session` | Create item (now accepts `stock_count`) |
| PATCH | `/ui/catalog/categories/{cat_id}/items/{item_id}` | `require_ui_session` | Update item (now accepts `stock_count`, `low_stock_threshold`) |
| PATCH | `/ui/catalog/items/{item_id}/stock` | `require_ui_session` | Dedicated stock adjustment endpoint |
| GET | `/ui/catalog/categories/{cat_id}/items` | `require_ui_session` | List items (response now includes `stock_count`, `stock_status`) |

### 6.2 PATCH `/ui/catalog/items/{item_id}/stock`

**Request body:**

```json
{
  "delta": -5,
  "reason": "Sold 5 units at event"
}
```

Or absolute set:

```json
{
  "absolute": 100,
  "reason": "Restocked from warehouse"
}
```

Only one of `delta` or `absolute` may be provided.

**Response (200):**

```json
{
  "item_id": "1748380800000_abc123",
  "stock_count": 45,
  "stock_status": "in_stock",
  "low_stock_threshold": 5,
  "stock_updated_at": "2026-05-27T15:00:00Z"
}
```

**Error (409 -- stock would go negative):**

```json
{
  "detail": "Insufficient stock: current=3, requested_delta=-5"
}
```

### 6.3 Updated CatalogItemOut Response

```json
{
  "category_id": "electronics",
  "item_id": "...",
  "name": "Wireless Headphones",
  "price_cents": 4999,
  "currency": "USD",
  "stock_count": 12,
  "stock_status": "in_stock",
  "low_stock_threshold": 5,
  "stock_updated_at": "2026-05-27T14:30:00Z",
  "image_urls": [],
  "attributes": {},
  "created_at": "...",
  "updated_at": "..."
}
```

Items where `stock_count` was never set return `stock_count: null, stock_status: "unlimited"`.

### 6.4 Error Codes

| Status | Condition |
|--------|-----------|
| 200 | Success |
| 400 | Both `delta` and `absolute` provided, or neither |
| 403 | Not the category owner |
| 404 | Item not found |
| 409 | Stock would go negative (delta mode) |
| 409 | Cart purchase blocked by out-of-stock item |
| 422 | Invalid delta/absolute value |

---

## 7. Implementation Plan

### 7.1 Backend Model Changes

**File: `app/models.py`**

Update `CatalogItemCreateIn` (line 519):
```python
class CatalogItemCreateIn(BaseModel):
    item_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    price_cents: int = Field(ge=0, le=10_000_000_00)
    currency: str = "USD"
    image_urls: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    stock_count: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    low_stock_threshold: Optional[int] = Field(default=None, ge=0, le=10_000_000)
```

Update `CatalogItemPatchIn` (line 529):
```python
class CatalogItemPatchIn(BaseModel):
    # ... existing fields ...
    stock_count: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    low_stock_threshold: Optional[int] = Field(default=None, ge=0, le=10_000_000)
```

Update `CatalogItemOut` (line 538):
```python
class CatalogItemOut(BaseModel):
    # ... existing fields ...
    stock_count: Optional[int] = None
    stock_status: str = "unlimited"
    low_stock_threshold: int = 5
    stock_updated_at: Optional[str] = None
```

Add new model:
```python
class CatalogStockAdjustIn(BaseModel):
    delta: Optional[int] = None
    absolute: Optional[int] = Field(default=None, ge=0)
    reason: Optional[str] = None

class CatalogStockOut(BaseModel):
    item_id: str
    stock_count: Optional[int] = None
    stock_status: str = "unlimited"
    low_stock_threshold: int = 5
    stock_updated_at: Optional[str] = None
```

### 7.2 Backend Router Changes

**File: `app/routers/catalog.py`**

1. Update `create_item` (line 308): Add `stock_count` and `low_stock_threshold` to the DynamoDB item dict if provided in the request body.

2. Update `update_item` (line 430): Add `stock_count` and `low_stock_threshold` branches in the dynamic update builder (alongside existing `name`, `price_cents`, etc.).

3. Add new endpoint:

```python
@router.patch("/items/{item_id}/stock", response_model=CatalogStockOut)
async def adjust_stock(
    item_id: str,
    body: CatalogStockAdjustIn,
    ctx=Depends(require_ui_session),
):
    # Find item, verify ownership
    # Atomic DynamoDB update (ADD for delta, SET for absolute)
    # Check low_stock_threshold, trigger alert if needed
    # Return updated stock info
```

4. Add `_compute_stock_status()` helper function and apply it whenever building `CatalogItemOut`.

5. Update the item-to-model mapping throughout the router to include the new stock fields.

### 7.3 Purchase Flow Stock Validation

**File: `app/services/shoppingcart.py`**

In `purchase_cart()` (line 428), before the commerce order creation (line 449):

1. Iterate `items` and collect those with `category_id` + `item_id` references
2. For each catalog-backed item, perform atomic stock decrement:
   ```python
   T.catalog.update_item(
       Key={"PK": f"CAT#{cat_id}", "SK": f"ITEM#{item_id}"},
       UpdateExpression="ADD stock_count :neg SET stock_updated_at = :now",
       ConditionExpression="stock_count >= :qty OR attribute_not_exists(stock_count)",
       ExpressionAttributeValues={":neg": -qty, ":qty": qty, ":now": _now_iso()},
   )
   ```
3. If `ConditionalCheckFailedException`, raise `HTTPException(409, "Item X is out of stock")`
4. After decrement, check if new stock is below threshold and trigger alert

### 7.4 Low-Stock Alert Integration

**File: `app/routers/catalog.py`** (new helper)

```python
from app.services.alerts import write_alert

def _check_low_stock_alert(item: dict, new_stock: int) -> None:
    threshold = int(item.get("low_stock_threshold", S.catalog_default_low_stock_threshold) or 5)
    if new_stock <= threshold and S.catalog_stock_alerts_enabled:
        creator_id = item.get("creator_id")
        if creator_id:
            write_alert(
                creator_id,
                event="catalog.low_stock",
                outcome="warning",
                title=f"Low stock: {item.get('name', 'Unknown item')} ({new_stock} remaining)",
                details={
                    "item_id": item.get("item_id"),
                    "item_name": item.get("name"),
                    "stock_count": new_stock,
                    "threshold": threshold,
                    "alert_type": "catalog.low_stock",
                },
            )
```

### 7.5 Frontend Changes

**File: `frontend/src/api/types.ts`**

Update `CatalogItem` interface (line 1719):
```typescript
export interface CatalogItem {
  // ... existing fields ...
  stock_count?: number | null;
  stock_status: string;
  low_stock_threshold: number;
  stock_updated_at?: string;
}
```

Update `CatalogItemIn` interface (line 1709):
```typescript
export interface CatalogItemIn {
  // ... existing fields ...
  stock_count?: number | null;
  low_stock_threshold?: number;
}
```

**File: `frontend/src/pages/shop/ItemEditor.tsx`**

Add `stockCount` state (after line 60):
```typescript
const [stockCount, setStockCount] = useState<string>("");
const [lowStockThreshold, setLowStockThreshold] = useState<string>("5");
```

Add stock input fields in the form (between Price/Currency grid and Attributes section, around line 222):
```tsx
<div className="grid grid-cols-2 gap-4">
  <div className="space-y-1">
    <Label htmlFor="item-stock">Stock Quantity</Label>
    <Input
      id="item-stock"
      type="number"
      min="0"
      value={stockCount}
      onChange={(e) => setStockCount(e.target.value)}
      placeholder="Unlimited"
    />
  </div>
  <div className="space-y-1">
    <Label htmlFor="item-threshold">Low Stock Alert At</Label>
    <Input
      id="item-threshold"
      type="number"
      min="0"
      value={lowStockThreshold}
      onChange={(e) => setLowStockThreshold(e.target.value)}
      placeholder="5"
    />
  </div>
</div>
```

**File: `frontend/src/pages/shop/AdminCatalog.tsx`**

Add "Stock" column to the DataTable with a colored badge:
- Green for `in_stock`
- Yellow for `low_stock`
- Red for `out_of_stock`
- Grey for `unlimited`

**File: `frontend/src/pages/shop/ProductDetail.tsx`**

Add stock status badge near the price:
```tsx
{item.stock_status === "out_of_stock" && (
  <Badge variant="destructive">Out of Stock</Badge>
)}
{item.stock_status === "low_stock" && (
  <Badge variant="warning">Only {item.stock_count} left</Badge>
)}
```

Disable "Add to Cart" button when `stock_status === "out_of_stock"`.

---

## 8. Security & Privacy Considerations

### 8.1 Authorization

- Only the category owner can adjust stock (enforced by `_require_category_owner` in catalog.py:313).
- The stock endpoint must verify ownership the same way via `_require_item_owner()` helper.
- Buyers see `stock_count` and `stock_status` but NOT `low_stock_threshold` (seller configuration). The `CatalogItemPublicOut` response model omits it.
- Admin/root users can adjust stock on any item (bypass ownership check).

### 8.2 Race Conditions

- Stock decrements use DynamoDB `ConditionExpression` for atomic check-and-decrement.
- Two concurrent purchases of the last unit: one succeeds, one gets 409. The condition `stock_count >= :qty` ensures exactly one wins.
- The `ADD` operation is atomic at the DynamoDB level; no application-level locking needed.
- Cart with multiple items: decrements are applied sequentially. If item 3 fails, items 1-2 are already decremented. A compensating write (re-increment items 1-2) is triggered before returning 409.

### 8.3 Data Integrity

- `stock_count` is never negative (enforced by `ConditionExpression: stock_count >= :qty`).
- Items without `stock_count` (null/missing) are treated as unlimited -- the condition `attribute_not_exists(stock_count)` allows purchase.
- The `absolute` mode requires `ge=0` validation in Pydantic (cannot set negative stock).
- Stock adjustment `reason` field is audit-logged (written to stock_history items).

### 8.4 Input Validation

```python
class CatalogStockAdjustIn(BaseModel):
    delta: Optional[int] = Field(default=None, ge=-1_000_000, le=1_000_000)
    absolute: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    reason: Optional[str] = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def exactly_one_mode(self):
        if (self.delta is None) == (self.absolute is None):
            raise ValueError("Provide exactly one of 'delta' or 'absolute'")
        return self
```

### 8.5 curl Examples

```bash
# Create item with stock
curl -s -b cookies.txt \
  -H "x-csrf-token: $CSRF" \
  -H "Content-Type: application/json" \
  -d '{"name":"Headphones","price_cents":4999,"stock_count":50,"low_stock_threshold":5}' \
  "http://localhost:8000/ui/catalog/categories/electronics/items" | jq .stock_status

# Adjust stock (delta)
curl -s -b cookies.txt \
  -H "x-csrf-token: $CSRF" \
  -H "Content-Type: application/json" \
  -X PATCH \
  -d '{"delta":-10,"reason":"Sold at event"}' \
  "http://localhost:8000/ui/catalog/items/$ITEM_ID/stock" | jq .

# Adjust stock (absolute)
curl -s -b cookies.txt \
  -H "x-csrf-token: $CSRF" \
  -H "Content-Type: application/json" \
  -X PATCH \
  -d '{"absolute":100,"reason":"Warehouse restock"}' \
  "http://localhost:8000/ui/catalog/items/$ITEM_ID/stock" | jq .stock_count

# Purchase cart (stock decremented)
curl -s -b cookies.txt \
  -H "x-csrf-token: $CSRF" \
  -X POST \
  "http://localhost:8000/ui/cart/$CART_ID/purchase" | jq .
```

---

## 9. Performance Considerations

### 9.1 DynamoDB Read/Write Estimates

| Operation | WCU | RCU | Latency |
|-----------|-----|-----|---------|
| Create item (with stock) | 1 WCU (same as without) | 0 | ~10ms |
| Adjust stock (delta) | 1 WCU (update_item) | 0 | ~8ms |
| Adjust stock (absolute) | 1 WCU (update_item) | 0 | ~8ms |
| Purchase 1 item (stock decrement) | 1 WCU | 0 | ~8ms |
| Purchase 5 items (stock decrements) | 5 WCU (sequential) | 0 | ~40ms |
| List items (page of 50, includes stock) | 0 | ~25 RCU | ~30ms |
| Low-stock alert write | 1 WCU (alerts table) | 0 | ~5ms |

### 9.2 Stock Check During Purchase

Each cart item with a `category_id` requires one additional DynamoDB `update_item` call (the atomic decrement). For a typical cart of 1-5 items, this adds 1-5 DDB operations (~5-40ms total latency due to sequential execution).

### 9.3 Stock Status Computation

`_compute_stock_status()` is a pure function with no DDB calls. Negligible overhead. Called in `_catalog_item_out()` at read time.

### 9.4 Low-Stock Alert Throttling

To avoid alert spam on high-velocity items, deduplicate low-stock alerts per item per hour using a TTL-based sentinel key:

```python
def _should_send_low_stock_alert(item_id: str) -> bool:
    """Check if we already sent a low-stock alert for this item in the last hour."""
    sentinel_key = {"pk": f"ALERT_SENTINEL#{item_id}", "sk": "LOW_STOCK"}
    existing = T.catalog.get_item(Key=sentinel_key).get("Item")
    if existing:
        return False  # Already alerted recently
    # Write sentinel with 1-hour TTL
    T.catalog.put_item(Item={
        **sentinel_key,
        "ttl": int(time.time()) + 3600,
    })
    return True
```

### 9.5 Compensating Writes on Partial Purchase Failure

If a multi-item purchase fails on item N (out of stock), items 1..N-1 have already been decremented. The compensating logic re-increments them:

```python
def _rollback_stock_decrements(decremented: List[Tuple[str, str, int]]):
    """Re-increment stock for items that were decremented before a failure."""
    for cat_id, item_id, qty in decremented:
        try:
            T.catalog.update_item(
                Key={"PK": f"CAT#{cat_id}", "SK": f"ITEM#{item_id}"},
                UpdateExpression="ADD stock_count :qty",
                ExpressionAttributeValues={":qty": qty},
            )
        except Exception:
            logger.error("Failed to rollback stock for %s/%s", cat_id, item_id)
```

---

## 10. Testing Strategy

### 10.1 Unit Tests (pytest)

**File:** `tests/test_catalog_inventory.py`

| # | Test | Assertion |
|---|------|-----------|
| 1 | Create item with stock_count stores value in DDB | `item["stock_count"] == 50` |
| 2 | Create item without stock_count defaults to null (unlimited) | `item.get("stock_count") is None` |
| 3 | Patch item stock_count updates DDB | After patch, DDB item has new stock value |
| 4 | Stock adjust with positive delta increments | stock goes from 10 to 15 with delta=5 |
| 5 | Stock adjust with negative delta decrements | stock goes from 10 to 7 with delta=-3 |
| 6 | Stock adjust preventing negative returns 409 | delta=-20 on stock=5 raises HTTPException(409) |
| 7 | Stock adjust with absolute sets exact value | stock becomes 100 regardless of prior value |
| 8 | Both delta and absolute provided returns 400 | Pydantic validation error |
| 9 | Neither delta nor absolute provided returns 400 | Pydantic validation error |
| 10 | _compute_stock_status returns "unlimited" for None | `_compute_stock_status({"stock_count": None})` == "unlimited" |
| 11 | _compute_stock_status returns "out_of_stock" for 0 | `_compute_stock_status({"stock_count": 0})` == "out_of_stock" |
| 12 | _compute_stock_status returns "low_stock" at threshold | `stock_count=5, threshold=5` -> "low_stock" |
| 13 | _compute_stock_status returns "in_stock" above threshold | `stock_count=10, threshold=5` -> "in_stock" |
| 14 | Purchase decrements stock for each catalog item | After purchase, stock reduced by cart quantities |
| 15 | Purchase of out-of-stock item returns 409 | `stock_count=0`; purchase raises 409 |
| 16 | Purchase of unlimited item (null stock) succeeds | No stock check; purchase completes |
| 17 | Multi-item purchase: partial failure rollbacks | Item 2 OOS; item 1's stock re-incremented |
| 18 | Low-stock alert written when threshold crossed | Alert in alerts table with event="catalog.low_stock" |
| 19 | Low-stock alert not written when stock above threshold | No alert written |
| 20 | Low-stock alert throttled (sentinel prevents duplicate) | Second decrement within 1 hour does not write alert |
| 21 | Non-owner cannot adjust stock | 403 returned |

```python
class TestComputeStockStatus:
    def test_unlimited(self):
        assert _compute_stock_status({}) == "unlimited"
        assert _compute_stock_status({"stock_count": None}) == "unlimited"

    def test_out_of_stock(self):
        assert _compute_stock_status({"stock_count": 0}) == "out_of_stock"
        assert _compute_stock_status({"stock_count": -1}) == "out_of_stock"

    def test_low_stock(self):
        assert _compute_stock_status({"stock_count": 5, "low_stock_threshold": 5}) == "low_stock"
        assert _compute_stock_status({"stock_count": 3, "low_stock_threshold": 5}) == "low_stock"

    def test_in_stock(self):
        assert _compute_stock_status({"stock_count": 50, "low_stock_threshold": 5}) == "in_stock"


class TestStockAdjust:
    def test_delta_decrement(self, client, auth_headers, item_id):
        resp = client.patch(f"/ui/catalog/items/{item_id}/stock",
            json={"delta": -5, "reason": "sold"},
            headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["stock_count"] == 45  # was 50

    def test_delta_prevents_negative(self, client, auth_headers, item_id):
        # Set stock to 3 first
        client.patch(f"/ui/catalog/items/{item_id}/stock",
            json={"absolute": 3}, headers=auth_headers)
        resp = client.patch(f"/ui/catalog/items/{item_id}/stock",
            json={"delta": -5}, headers=auth_headers)
        assert resp.status_code == 409
        assert "Insufficient stock" in resp.json()["detail"]

    def test_absolute_set(self, client, auth_headers, item_id):
        resp = client.patch(f"/ui/catalog/items/{item_id}/stock",
            json={"absolute": 100, "reason": "restock"},
            headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["stock_count"] == 100


class TestPurchaseStockDecrement:
    def test_purchase_decrements(self, client, auth_headers, cart_with_stocked_item):
        cart_id, item_id = cart_with_stocked_item
        resp = client.post(f"/ui/cart/{cart_id}/purchase", headers=auth_headers)
        assert resp.status_code == 200
        # Verify stock decremented
        item_resp = client.get(f"/ui/catalog/items/{item_id}", headers=auth_headers)
        assert item_resp.json()["stock_count"] == 49  # was 50, qty=1

    def test_oos_purchase_blocked(self, client, auth_headers, cart_with_oos_item):
        cart_id, _ = cart_with_oos_item
        resp = client.post(f"/ui/cart/{cart_id}/purchase", headers=auth_headers)
        assert resp.status_code == 409
        assert "out of stock" in resp.json()["detail"].lower()
```

### 10.2 E2E Tests

**Test File:** `frontend/e2e/catalog-inventory.spec.ts`

**Section 1: Stock CRUD API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Create item with stock_count | 200; response has `stock_count: 50, stock_status: "in_stock"` |
| 2 | Create item without stock_count | 200; `stock_count: null, stock_status: "unlimited"` |
| 3 | Adjust stock with positive delta (restock) | 200; `stock_count` increased by delta |
| 4 | Adjust stock with negative delta (sold) | 200; `stock_count` decreased by delta |
| 5 | Adjust stock to zero | 200; `stock_status: "out_of_stock"` |
| 6 | Adjust stock below zero returns 409 | 409; "Insufficient stock" detail |

**Section 2: Stock Validation API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 7 | Both delta and absolute returns 400 | `{"delta":5,"absolute":10}` -> 422 validation error |
| 8 | Neither delta nor absolute returns 400 | `{}` -> 422 validation error |
| 9 | Non-owner cannot adjust stock | Bob adjusts Alice's item; 403 |
| 10 | Absolute with negative value returns 422 | `{"absolute":-1}` -> 422 |

**Section 3: Stock in Purchase Flow (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | Purchase decrements stock | After purchase, GET item shows `stock_count` reduced by quantity |
| 12 | Purchase out-of-stock item fails | 409; "out of stock" detail |
| 13 | Purchase unlimited item succeeds | No stock field; purchase completes normally |
| 14 | Low-stock alert created after purchase | Alerts endpoint returns `catalog.low_stock` event |
| 15 | Multi-item cart: one OOS item blocks entire purchase | 409; other items' stock not permanently decremented |

**Section 4: ItemEditor UI (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 16 | Stock input visible in create dialog | `#item-stock` input visible |
| 17 | Stock value pre-filled in edit dialog | `#item-stock` has correct value from API |
| 18 | Threshold input visible | `#item-threshold` input with default "5" |
| 19 | Stock badge in admin table -- in stock | Green "In Stock" badge visible |
| 20 | Stock badge in admin table -- out of stock | Red "Out of Stock" badge visible |

**Section 5: Product Detail UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 21 | In-stock item shows no special badge | Normal "Add to Cart" button enabled |
| 22 | Low-stock item shows "Only N left" badge | Yellow badge with count visible |
| 23 | Out-of-stock item shows badge + disabled button | "Out of Stock" badge; "Add to Cart" disabled |
| 24 | Unlimited item shows no stock indicator | No stock badge rendered |

---

## 10.3 Component Trees

### ItemEditor (Stock Fields)

```
ItemEditor (existing dialog)
  |-- ... existing fields (name, description, price, currency, attrs, images)
  |-- NEW: Stock Section (below price/currency grid)
  |     |-- Grid (2 columns)
  |           |-- div.space-y-1
  |           |     |-- Label: "Stock Quantity"
  |           |     |-- Input#item-stock (type=number, min=0, placeholder="Unlimited")
  |           |-- div.space-y-1
  |                 |-- Label: "Low Stock Alert At"
  |                 |-- Input#item-threshold (type=number, min=0, placeholder="5")
  |-- ... existing submit button
```

### AdminCatalog (Stock Column)

```
AdminCatalog (existing table)
  |-- DataTable
        |-- Column: Name (existing)
        |-- Column: Price (existing)
        |-- NEW Column: Stock
        |     |-- StockBadge
        |           |-- Badge variant="success": "In Stock (N)"   (stock_status === "in_stock")
        |           |-- Badge variant="warning": "Low (N)"        (stock_status === "low_stock")
        |           |-- Badge variant="destructive": "Out of Stock" (stock_status === "out_of_stock")
        |           |-- Badge variant="outline": "Unlimited"       (stock_status === "unlimited")
        |-- Column: Actions (existing)
```

### ProductDetail (Stock Badge)

```
ProductDetail (existing page)
  |-- ... product images, title, description
  |-- Price display (existing)
  |-- NEW: StockStatusIndicator
  |     |-- Badge variant="warning": "Only {stock_count} left!" (low_stock)
  |     |-- Badge variant="destructive": "Out of Stock"         (out_of_stock)
  |     |-- (nothing rendered for in_stock or unlimited)
  |-- AddToCartButton
        |-- disabled={item.stock_status === "out_of_stock"}
        |-- tooltip="Out of stock" (when disabled)
```

---

## 11. Migration & Rollback Plan

### 11.1 Feature Flag

`CATALOG_STOCK_ALERTS_ENABLED` (default `true`). Stock tracking itself requires no flag -- items without `stock_count` behave as unlimited (backward compatible).

### 11.2 Migration

No schema migration needed. Existing items have no `stock_count` attribute, which is treated as `null` = unlimited. The new fields are additive.

### 11.3 Rollback

Remove the stock check from `purchase_cart()`. All items revert to unlimited behavior. Existing `stock_count` attributes remain in DDB but are ignored.

---

## 12. Files to Create

| File | Purpose |
|------|---------|
| `tests/test_catalog_inventory.py` | Unit tests for stock logic |
| `frontend/e2e/catalog-inventory.spec.ts` | E2E tests |

## 13. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add `stock_count`, `low_stock_threshold`, `stock_status`, `stock_updated_at` to CatalogItem models; add `CatalogStockAdjustIn`, `CatalogStockOut` |
| `app/routers/catalog.py` | Add `PATCH /items/{id}/stock` endpoint; update `create_item` and `update_item` to handle stock fields; add `_compute_stock_status` and `_check_low_stock_alert` helpers |
| `app/services/shoppingcart.py` | Add stock validation and decrement in `purchase_cart()` |
| `app/core/settings.py` | Add `catalog_default_low_stock_threshold`, `catalog_stock_alerts_enabled` |
| `frontend/src/api/types.ts` | Add stock fields to `CatalogItem` and `CatalogItemIn` interfaces |
| `frontend/src/pages/shop/ItemEditor.tsx` | Add stock quantity and threshold inputs |
| `frontend/src/pages/shop/AdminCatalog.tsx` | Add stock column to DataTable |
| `frontend/src/pages/shop/ProductDetail.tsx` | Add stock status badge; disable "Add to Cart" when out of stock |
| `frontend/src/api/endpoints/cart.ts` | Add `adjustStock()` API call |

---

## 14. Acceptance Criteria

1. Seller can set `stock_count` when creating or editing a catalog item via ItemEditor.
2. `GET /ui/catalog/categories/{cat_id}/items` returns `stock_count`, `stock_status`, `low_stock_threshold` for each item.
3. `PATCH /ui/catalog/items/{id}/stock` performs atomic delta or absolute stock adjustment.
4. Stock cannot go below zero (409 on over-decrement).
5. `purchase_cart()` atomically decrements stock for each catalog-backed item and returns 409 if any item is out of stock.
6. Items with no `stock_count` set (null) are treated as unlimited and skip stock validation.
7. Low-stock alert is written to the alerts table when stock falls to or below `low_stock_threshold`.
8. Admin catalog table shows a stock column with color-coded badge.
9. Product detail page shows "Out of Stock" badge and disables "Add to Cart" when `stock_count <= 0`.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| CatalogItemOut has no stock fields | `app/models.py` | 573+ | VERIFIED (was 538; line drift) |
| CatalogItemCreateIn has no stock fields | `app/models.py` | 530+ | VERIFIED (was 519; line drift) |
| CatalogItemPatchIn has no stock fields | `app/models.py` | 542+ | VERIFIED (was 529; line drift) |
| create_item stores no stock_count | `app/routers/catalog.py` | 333+ | VERIFIED (was 316; line drift) |
| update_item has no stock branch | `app/routers/catalog.py` | 492+ | VERIFIED (was 430; line drift) |
| Catalog router (no inventory ops) | `app/routers/catalog.py` | 1-933 | VERIFIED (was 664 lines; now 933 — router has grown) |
| Catalog table definition | `scripts/local-ddb-init.py` | 73 | VERIFIED (was 68; line drift) |
| Catalog table handle | `app/core/tables.py` | 35, 133 | VERIFIED |
| Catalog table setting | `app/core/settings.py` | 749 | VERIFIED (was 712; line drift) |
| purchase_cart has no stock check | `app/services/shoppingcart.py` | 469+ | VERIFIED (was 428; line drift) |
| ItemEditor has no stock input | `frontend/src/pages/shop/ItemEditor.tsx` | 352 lines total | VERIFIED |
| CatalogItem type has no stock field | `frontend/src/api/types.ts` | 1833+ | VERIFIED (was 1719; line drift) |
| write_alert function | `app/services/alerts.py` | 355+ | VERIFIED (was 265; line drift — file grew from ~680 to 899 lines) |


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_inventory.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_shop_001_create` | Create primary entity; 201 |
| 2 | `test_shop_001_read` | Read back entity; correct fields |
| 3 | `test_shop_001_update` | Update entity; 200; changes reflected |
| 4 | `test_shop_001_delete` | Delete entity; 200/204 |
| 5 | `test_shop_001_auth_required` | No auth; 401 |
| 6 | `test_shop_001_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/inventory.spec.ts` -- 14 tests

**Auth**: `injectAuth(page, identity)` for cookie auth; CSRF header for mutations.

Tests cover API CRUD, UI rendering, negative cases (401/403/404/422), and edge cases.

**Negative/edge tests**: 401 unauthenticated, 403 insufficient role, 404 not found, 422 validation error, 409 conflict

### Test Data Requirements

- DDB seeds: feature-specific tables via setup scripts
- Test users: Alice, Bob, Root, Charlie (admin)
- Sessions via `e2e_admin_session_setup.py`

### CI/Pipeline

- Feature flags: Feature-specific flags (see Rollout Plan section)
- Serial execution (1 worker), 1 retry per playwright.config.ts
- Retry-safe: unique timestamps in test data


---

## Dependencies & Merge Safety

### Depends On

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | Standalone feature |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| SHOP-002 | Enhances | Promo checkout integration respects stock limits |

### Merge Strategy

**Independent** -- Extends existing catalog items with stock_count field.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/inventory.spec.ts`
