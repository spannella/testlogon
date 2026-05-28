# SHOP-003: Cart Abandonment Reminders

**Ticket**: SHOP-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 7-9 days

---

## 1. Executive Summary

The shopping cart system (`app/services/shoppingcart.py`, 536 lines) tracks carts with `cart_id`, `status`, `created_at`, `purchased_at`, and `currency`, but has no concept of expiration or abandonment. Carts remain in `OPEN` status indefinitely. There is no background job to detect stale carts, no reminder notification when a buyer leaves items in their cart, and no TTL to auto-expire abandoned carts. Meanwhile, the platform already has a scheduler infrastructure (`unified_scheduler.py`, `schedule_executors.py`) and a full alerts system (`alerts.py` with email, SMS, push, webhook, and in-app notifications).

Industry data shows 70%+ cart abandonment rates, with reminder emails recovering 5-15% of abandoned carts. For a commerce platform without cart abandonment recovery, this represents significant unrealized revenue. Every item left in a cart is a buyer who showed purchase intent but did not complete checkout -- the highest-value audience for conversion messaging.

This feature adds a `last_activity_at` timestamp and `abandoned_at` field to cart records, a configurable abandonment threshold (default 24 hours), a new background task (`_cart_abandonment_loop`) that runs periodically to detect stale carts, integration with the alerts system to send abandonment reminders (in-app + email), a DynamoDB TTL for automatic cleanup of ancient carts, and an admin-visible cart abandonment metric. The system is designed to be non-intrusive: at most 2 reminders per cart with a 48-hour cooldown between reminders.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Receive Abandonment Reminder**

As a buyer, I want a reminder if I leave items in my cart for more than 24 hours, so that I do not forget about items I intended to purchase.

Acceptance criteria:
- In-app alert with event type `cart.abandoned` appears in the notification bell after 24 hours of cart inactivity.
- Email reminder sent to the buyer's registered email address.
- Alert title: "You left items in your cart".
- Alert includes a link to the cart page (`/cart?cartId={cart_id}`).
- Reminder is not sent if the cart has zero items.

**US-2: Return to Cart via Reminder Link**

As a buyer, I want to click the abandonment reminder and navigate directly to my cart, so that I can complete my purchase quickly.

Acceptance criteria:
- In-app alert detail includes `link: "/cart?cartId={cart_id}"`.
- Clicking the alert in the notification center navigates to the cart with items visible.
- Cart is still in `OPEN` status and items are intact.

**US-3: No Reminder Spam**

As a buyer, I do not want to be spammed with repeated reminders, so that my notification experience remains useful.

Acceptance criteria:
- At most 1 reminder per cart per 48-hour window (configurable via `CART_ABANDONMENT_REMINDER_COOLDOWN_HOURS`).
- Maximum 2 reminders total per cart (configurable via `CART_ABANDONMENT_MAX_REMINDERS`).
- After 2 reminders, the cart is never alerted again (regardless of continued inactivity).
- Users can disable `cart.abandoned` alerts via notification preferences.

**US-4: Admin Abandonment Visibility**

As a seller/admin, I want to see how many carts are abandoned, so that I can optimize my checkout funnel.

Acceptance criteria:
- Admin API endpoint returns: total open carts, total abandoned carts, abandonment rate percentage.
- Metric updates after each background scan.

**US-5: Automatic Cart Cleanup**

As the system, abandoned carts older than 30 days should be cleaned up automatically to prevent storage growth.

Acceptance criteria:
- DynamoDB TTL attribute `ttl` is set on cart records.
- TTL value is `last_activity_at + (CART_TTL_DAYS * 86400)`.
- Activity on a cart (add/update/remove item) resets the TTL.
- Purchased carts do not have TTL set (they are historical records).
- DDB automatically deletes expired items.

### 2.2 Pain Points

1. **Lost revenue**: Buyers who add items but do not complete checkout represent significant unrealized revenue. Reminders recover 5-15% of these carts.
2. **No lifecycle management**: Carts accumulate indefinitely in `OPEN` status, consuming DynamoDB storage and polluting the cart list view with ancient empty carts.
3. **No visibility**: Sellers have no insight into how often buyers abandon carts. Without data, checkout funnel optimization is impossible.
4. **Wasted existing infrastructure**: The alerts system (`write_alert`, `send_alert_email`) and scheduler infrastructure (`unified_scheduler.py`) are fully operational but unused for cart lifecycle management.

---

## 3. Current State Analysis

### 3.1 Shopping Cart Service (`app/services/shoppingcart.py`)

**`start_cart`** (line 237-250): Creates a cart with `status: "OPEN"`, `created_at`, `currency: "USD"`. No `last_activity_at`, `expires_at`, or `ttl` field.

```python
# app/services/shoppingcart.py:237-250
def start_cart(user_sub: str) -> Dict[str, Any]:
    cart_id = uuid.uuid4().hex
    now = _now_iso()
    item = {
        "PK": _user_pk(user_sub),
        "SK": _cart_sk(cart_id),
        "type": "cart",
        "cart_id": cart_id,
        "status": "OPEN",
        "created_at": now,
        "currency": "USD",
    }
    T.shopping_cart.put_item(Item=item)
    return _cart_from_item(item)
```

**`add_item`** (line 287): Adds/updates cart items under `CART#{cart_id}#ITEM#{sku}` but does NOT update any timestamp on the parent cart record.

**`update_quantity`**: Modifies item quantity but does not touch the parent cart.

**`remove_item`**: Deletes an item but does not touch the parent cart.

**`purchase_cart`** (line 428): Transitions cart from `OPEN` to `PURCHASED`. No abandonment-related logic.

**`_cart_from_item`** (line 51-59): Extracts response fields -- has no abandonment fields:

```python
# app/services/shoppingcart.py:51-59
def _cart_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "cart_id": item.get("cart_id"),
        "status": item.get("status"),
        "created_at": item.get("created_at"),
        "purchased_at": item.get("purchased_at"),
        "purchased_total_cents": _ddb_int(item["purchased_total_cents"]) if item.get("purchased_total_cents") is not None else None,
        "currency": item.get("currency", "USD"),
    }
```

**Citation**: `app/services/shoppingcart.py:51-59, 237-250, 287, 428` -- no activity tracking or abandonment logic.

### 3.2 DynamoDB Table

**Table name**: `shopping_cart` (defined at `scripts/local-ddb-init.py:66`)
**Table handle**: `T.shopping_cart` (defined at `app/core/tables.py:34,132`)
**Setting**: `S.shopping_cart_table_name` (defined at `app/core/settings.py:710`)

**Key schema**:
- PK: `PK` (S) = `USER#{user_sub}`
- SK: `SK` (S) = `CART#{cart_id}` (for cart records) or `CART#{cart_id}#ITEM#{sku}` (for item records)

**Gaps**:
- No TTL attribute configured on the table.
- No GSI for querying carts by status or activity time.
- No `last_activity_at` field on any existing cart record.

**Citation**: `scripts/local-ddb-init.py:66` -- table definition.
**Citation**: `app/core/tables.py:34,132` -- table handle.
**Citation**: `app/core/settings.py:710` -- table name setting.

### 3.3 Scheduled Actions System (`app/services/scheduled_actions.py`)

The scheduled actions framework provides:

```python
# app/services/scheduled_actions.py:91-134
def create_action(
    user_sub: str,
    action_type: str,
    scheduled_at: int,
    payload: dict,
    title: str = "",
    description: str = "",
    notify_before_seconds: int = 0,
) -> Dict[str, Any]:
    # Creates action with status="pending", GSI_DUE_PK="DUE", GSI_DUE_SK=scheduled_at
```

- **`create_action`** (line 91): Creates a scheduled action with `action_type`, `scheduled_at`, `payload`.
- **`query_due_actions`** (line 355): Returns actions where `scheduled_at <= now` and `status = "pending"`.
- **`claim_action`** / **`mark_action_completed`** / **`mark_action_failed`** (lines 377-427): Lifecycle management with optimistic locking.

**Citation**: `app/services/scheduled_actions.py:91, 355, 377-427` -- scheduled action framework.

### 3.4 Schedule Executors (`app/services/schedule_executors.py`)

Three existing executors:

```python
# app/services/schedule_executors.py:15
async def execute_scheduled_post(user_sub: str, payload: Dict[str, Any]) -> None:
# app/services/schedule_executors.py:93
async def execute_scheduled_file_share(user_sub: str, payload: Dict[str, Any]) -> None:
# app/services/schedule_executors.py:165
async def execute_scheduled_catalog_sale(user_sub: str, payload: Dict[str, Any]) -> None:
```

No `execute_cart_abandonment_check` or any cart-related executor exists.

**Citation**: `app/services/schedule_executors.py:15, 93, 165` -- only post, file_share, catalog_sale executors.

### 3.5 Alerts System (`app/services/alerts.py`)

```python
# app/services/alerts.py:265-320
def write_alert(user_sub: str, *, event: str, outcome: str, title: str, details: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # Writes in-app alert to T.alerts with priority, TTL, SSE publish
    # Returns {"alert_id": ..., "ts": ...}

# app/services/alerts.py:332-353
def send_alert_email(to_emails: List[str], subject: str, body_text: str) -> None:
    # In dev mode: writes to .logs/dev/emails.log
    # In prod: sends via SES
```

The alerts system supports:
- In-app alerts with `event` type, `outcome`, `title`, `details` (including a `link` field for navigation).
- Email alerts via SES (dev mode logs to file).
- SSE publish for real-time notification bell updates.
- Per-user alert preferences (enable/disable channels per event type).

**Citation**: `app/services/alerts.py:265-320` -- `write_alert` function.
**Citation**: `app/services/alerts.py:332-353` -- `send_alert_email` function.

### 3.6 Unified Scheduler (`app/services/unified_scheduler.py`)

The background task loop (lines 33-65) runs as a startup task in `app/main.py`:
1. Queries due actions via `query_due_actions()`.
2. Claims each action atomically.
3. Routes to the appropriate executor based on `action_type`.
4. Marks actions completed or failed.

This infrastructure is ideal for periodic cart abandonment checks but is not currently used for that purpose.

**Citation**: `app/services/unified_scheduler.py:33-65` -- background task loop.

### 3.7 Gaps Summary

| Component | Current State | Gap |
|-----------|--------------|-----|
| Cart record schema | `cart_id`, `status`, `created_at`, `currency` | No `last_activity_at`, `abandoned_at`, `reminder_count`, `ttl` |
| Item mutations | Write item records only | Do not update parent cart activity timestamp |
| `_cart_from_item` | Returns 6 fields | No abandonment fields in response |
| DDB table | PK/SK only | No GSI for status+activity query, no TTL configured |
| Background jobs | Scheduler exists, no cart executor | Need `_cart_abandonment_loop` or executor |
| Alerts integration | `write_alert` + `send_alert_email` ready | No `cart.abandoned` event type |
| Admin metrics | No abandonment tracking | Need abandonment rate endpoint |

---

## 4. Technical Architecture

### 4.1 System Diagram

```
+---------------------+       +---------------------+       +---------------------+
|  Shopping Cart       |       |  Background Loop     |       |  DynamoDB           |
|  Service             |       |  _cart_abandonment_  |       |                     |
|                      |       |  loop() every 60min  |       | shopping_cart table  |
|  add_item()          |       |                      |       | PK=USER#...         |
|  update_quantity()   |------>| scan_abandoned_      |------>| SK=CART#...         |
|  remove_item()       |  set  |   carts()            |query  | last_activity_at: N |
|  _touch_cart_        |  ttl  |                      | GSI   | ttl: N              |
|  activity()          |       +----------+-----------+       +---------------------+
+---------------------+                  |
                                          v
                               +---------------------+       +---------------------+
                               |  Alerts Service      |       |  alerts table        |
                               |                      |------>| event=cart.abandoned |
                               | write_alert()        |       | link=/cart?cartId=.. |
                               | send_alert_email()   |       +---------------------+
                               +---------------------+
                                          |
                                          v
                               +---------------------+
                               |  Email Log (dev)     |
                               |  .logs/dev/emails.log|
                               +---------------------+
```

### 4.2 Data Flow -- Activity Tracking

1. Buyer calls `add_item()`, `update_quantity()`, or `remove_item()`.
2. After the item mutation, `_touch_cart_activity(user_sub, cart_id)` is called.
3. `_touch_cart_activity` does `update_item` on the parent cart record:
   - `SET last_activity_at = :ts, #ttl = :ttl`
   - Where `ttl = ts + (CART_TTL_DAYS * 86400)` (e.g., 30 days from now).
4. This resets the abandonment clock and extends the DDB auto-cleanup TTL.

### 4.3 Data Flow -- Abandonment Detection

1. Background loop runs every `CART_ABANDONMENT_CHECK_INTERVAL_MINUTES` (default 60 minutes).
2. Queries the `ByStatusActivity` GSI: `status = "OPEN" AND last_activity_at < now - threshold`.
3. Filters results in-memory:
   - Skip carts where `last_reminder_at + cooldown > now` (recently reminded).
   - Skip carts where `reminder_count >= max_reminders` (already maxed out).
   - Skip carts with no items (empty carts not worth reminding).
4. For each qualifying cart, call `send_cart_reminder(cart)`.
5. `send_cart_reminder`:
   - Writes in-app alert via `write_alert()` with `event="cart.abandoned"`.
   - Sends email reminder via `send_alert_email()`.
   - Updates cart record: `SET last_reminder_at = :ts, abandoned_at = if_not_exists(abandoned_at, :ts), ADD reminder_count :one`.

### 4.4 Data Flow -- TTL Auto-Cleanup

1. DynamoDB TTL is enabled on the `shopping_cart` table with attribute `ttl`.
2. Every `_touch_cart_activity` call sets `ttl = last_activity_at + (CART_TTL_DAYS * 86400)`.
3. `start_cart` sets initial `ttl` (30 days from creation).
4. `purchase_cart` removes the `ttl` attribute (purchased carts are permanent records).
5. DynamoDB automatically deletes items whose `ttl` is in the past (within ~48 hours of expiry).

---

## 5. Data Model Changes

### 5.1 Cart Record -- New Fields

| Field | Type | Description | Default | Example |
|-------|------|-------------|---------|---------|
| `last_activity_at` | N | Unix timestamp of last add/update/remove action | Same as creation `ts` | `1748380800` |
| `abandoned_at` | N | Unix timestamp when cart was first detected as abandoned | `0` (not abandoned) | `1748467200` |
| `last_reminder_at` | N | Unix timestamp of last abandonment reminder sent | `0` (never reminded) | `1748467200` |
| `reminder_count` | N | Number of reminders sent for this cart | `0` | `1` |
| `ttl` | N | DynamoDB TTL epoch for auto-cleanup (removed on purchase) | `created_ts + 30*86400` | `1751059200` |

### 5.2 Updated Cart DynamoDB Item Example

```json
{
  "PK": "USER#alice@test.local",
  "SK": "CART#abc123def456",
  "type": "cart",
  "cart_id": "abc123def456",
  "status": "OPEN",
  "created_at": "2026-05-20T10:00:00+00:00",
  "last_activity_at": 1747742400,
  "abandoned_at": 0,
  "last_reminder_at": 0,
  "reminder_count": 0,
  "currency": "USD",
  "ttl": 1750334400
}
```

**After first abandonment reminder:**
```json
{
  "PK": "USER#alice@test.local",
  "SK": "CART#abc123def456",
  "type": "cart",
  "cart_id": "abc123def456",
  "status": "OPEN",
  "created_at": "2026-05-20T10:00:00+00:00",
  "last_activity_at": 1747742400,
  "abandoned_at": 1747828800,
  "last_reminder_at": 1747828800,
  "reminder_count": 1,
  "currency": "USD",
  "ttl": 1750334400
}
```

### 5.3 GSI for Abandoned Cart Scan

Add a GSI to the shopping_cart table in `scripts/local-ddb-init.py`:

```python
# scripts/local-ddb-init.py -- add to shopping_cart TableDef
TableDef(
    _resolve_table_name(S.shopping_cart_table_name, "shopping_cart"),
    "PK", "SK",
    gsis=[
        GsiDef("ByStatusActivity", "status", "last_activity_at"),
    ],
    attr_types={"last_activity_at": "N"},
)
```

**GSI**: `ByStatusActivity`
- Partition key: `status` (S) -- enables filtering to `"OPEN"` carts only.
- Sort key: `last_activity_at` (N) -- enables range query for activity before a threshold.
- **`attr_types`**: `{"last_activity_at": "N"}` -- REQUIRED for numeric sort key GSI (see CLAUDE.md gotchas).

This allows efficient queries: `status = "OPEN" AND last_activity_at < :cutoff_timestamp`.

**Note**: Only cart-type items (not item-type records) have the `status` field, so only cart records are indexed.

### 5.4 Settings in `app/core/settings.py`

```python
# Cart Abandonment (SHOP-003)
cart_abandonment_enabled: bool = os.environ.get("CART_ABANDONMENT_ENABLED", "1") not in ("0", "false", "False")
cart_abandonment_threshold_hours: int = int(os.environ.get("CART_ABANDONMENT_THRESHOLD_HOURS", "24"))
cart_abandonment_check_interval_minutes: int = int(os.environ.get("CART_ABANDONMENT_CHECK_INTERVAL_MINUTES", "60"))
cart_abandonment_max_reminders: int = int(os.environ.get("CART_ABANDONMENT_MAX_REMINDERS", "2"))
cart_abandonment_reminder_cooldown_hours: int = int(os.environ.get("CART_ABANDONMENT_REMINDER_COOLDOWN_HOURS", "48"))
cart_ttl_days: int = int(os.environ.get("CART_TTL_DAYS", "30"))
```

---

## 6. Implementation Plan

### Phase 1: Activity Tracking

#### 6.1 `_touch_cart_activity` helper

**File: `app/services/shoppingcart.py`** (new function, ~15 lines)

```python
def _touch_cart_activity(user_sub: str, cart_id: str) -> None:
    """Update last_activity_at and TTL on the parent cart record."""
    from app.core.settings import S
    ts = int(datetime.now(timezone.utc).timestamp())
    ttl_epoch = ts + (S.cart_ttl_days * 86400)
    T.shopping_cart.update_item(
        Key={"PK": _user_pk(user_sub), "SK": _cart_sk(cart_id)},
        UpdateExpression="SET last_activity_at = :ts, #ttl = :ttl",
        ExpressionAttributeNames={"#ttl": "ttl"},
        ExpressionAttributeValues={":ts": ts, ":ttl": ttl_epoch},
    )
```

#### 6.2 Integrate into mutations

Call `_touch_cart_activity(user_sub, cart_id)` at the end of:
- `add_item()` (after the item `put_item` or `update_item`)
- `update_quantity()` (after the quantity update)
- `remove_item()` (after the item delete)

#### 6.3 Update `start_cart()`

**File: `app/services/shoppingcart.py`** -- modify `start_cart` (line 237):

```python
def start_cart(user_sub: str) -> Dict[str, Any]:
    cart_id = uuid.uuid4().hex
    now = _now_iso()
    ts = int(datetime.now(timezone.utc).timestamp())
    ttl_epoch = ts + (S.cart_ttl_days * 86400)
    item = {
        "PK": _user_pk(user_sub),
        "SK": _cart_sk(cart_id),
        "type": "cart",
        "cart_id": cart_id,
        "status": "OPEN",
        "created_at": now,
        "last_activity_at": ts,
        "abandoned_at": 0,
        "last_reminder_at": 0,
        "reminder_count": 0,
        "currency": "USD",
        "ttl": ttl_epoch,
    }
    T.shopping_cart.put_item(Item=item)
    return _cart_from_item(item)
```

#### 6.4 Update `purchase_cart()` -- Remove TTL

After purchase, remove the TTL so purchased carts are never auto-deleted:

```python
# In purchase_cart(), after status update to PURCHASED:
try:
    T.shopping_cart.update_item(
        Key={"PK": cart["PK"], "SK": cart["SK"]},
        UpdateExpression="REMOVE #ttl",
        ExpressionAttributeNames={"#ttl": "ttl"},
    )
except Exception:
    pass  # Non-critical: TTL removal is best-effort
```

#### 6.5 Update `_cart_from_item()`

**File: `app/services/shoppingcart.py`** -- modify `_cart_from_item` (line 51):

```python
def _cart_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "cart_id": item.get("cart_id"),
        "status": item.get("status"),
        "created_at": item.get("created_at"),
        "purchased_at": item.get("purchased_at"),
        "purchased_total_cents": _ddb_int(item["purchased_total_cents"]) if item.get("purchased_total_cents") is not None else None,
        "currency": item.get("currency", "USD"),
        # SHOP-003: Abandonment fields
        "last_activity_at": _ddb_int(item.get("last_activity_at", 0)),
        "abandoned_at": _ddb_int(item.get("abandoned_at", 0)),
        "reminder_count": _ddb_int(item.get("reminder_count", 0)),
    }
```

### Phase 2: Abandonment Detection and Reminders

#### 6.6 `scan_abandoned_carts()`

**File: `app/services/shoppingcart.py`** (new function, ~30 lines)

```python
def scan_abandoned_carts(*, threshold_hours: int = 24) -> List[Dict[str, Any]]:
    """Find OPEN carts with no activity in the last threshold_hours.
    
    Uses ByStatusActivity GSI: status="OPEN" AND last_activity_at < cutoff.
    Filters out recently reminded carts and carts at max reminders.
    """
    from app.core.settings import S
    cutoff = int(datetime.now(timezone.utc).timestamp()) - (threshold_hours * 3600)
    now = int(datetime.now(timezone.utc).timestamp())
    cooldown = S.cart_abandonment_reminder_cooldown_hours * 3600
    max_reminders = S.cart_abandonment_max_reminders

    resp = T.shopping_cart.query(
        IndexName="ByStatusActivity",
        KeyConditionExpression=Key("status").eq("OPEN") & Key("last_activity_at").lt(cutoff),
        Limit=200,
    )
    items = resp.get("Items", [])

    # Filter in-memory: skip recently reminded or maxed-out carts
    eligible = []
    for item in items:
        last_reminder = int(item.get("last_reminder_at", 0) or 0)
        count = int(item.get("reminder_count", 0) or 0)
        if count >= max_reminders:
            continue
        if (last_reminder + cooldown) > now:
            continue
        eligible.append(item)

    return eligible
```

#### 6.7 `send_cart_reminder()`

**File: `app/services/shoppingcart.py`** (new function, ~40 lines)

```python
def send_cart_reminder(cart: Dict[str, Any]) -> None:
    """Send an abandonment reminder for a single cart.
    
    Writes in-app alert, sends email, updates cart reminder tracking.
    """
    from app.services.alerts import write_alert, send_alert_email
    from app.services.profile import get_profile

    user_sub = cart["PK"].replace("USER#", "")
    cart_id = cart.get("cart_id", "")
    ts = int(datetime.now(timezone.utc).timestamp())

    # Count items in this cart
    prefix = f"CART#{cart_id}#ITEM#"
    items_resp = T.shopping_cart.query(
        KeyConditionExpression=Key("PK").eq(cart["PK"]) & Key("SK").begins_with(prefix),
        Select="COUNT",
    )
    items_count = items_resp.get("Count", 0)
    if items_count == 0:
        return  # Don't remind for empty carts

    # Write in-app alert
    write_alert(
        user_sub,
        event="cart.abandoned",
        outcome="reminder",
        title="You left items in your cart",
        details={
            "cart_id": cart_id,
            "alert_type": "cart.abandoned",
            "link": f"/cart?cartId={cart_id}",
            "items_count": str(items_count),
        },
    )

    # Send email reminder
    profile = get_profile(user_sub) or {}
    email = profile.get("email") or profile.get("displayed_email")
    if email:
        send_alert_email(
            [email],
            subject="You left items in your cart",
            body_text=(
                f"You have {items_count} item(s) waiting in your cart. "
                f"Complete your purchase: /cart?cartId={cart_id}"
            ),
        )

    # Update cart reminder tracking
    T.shopping_cart.update_item(
        Key={"PK": cart["PK"], "SK": cart["SK"]},
        UpdateExpression=(
            "SET last_reminder_at = :ts, "
            "abandoned_at = if_not_exists(abandoned_at, :ts) "
            "ADD reminder_count :one"
        ),
        ExpressionAttributeValues={":ts": ts, ":one": 1},
    )
```

### Phase 3: Background Task

#### 6.8 Background Loop Registration

**File: `app/main.py`** (add to startup tasks)

```python
async def _cart_abandonment_loop():
    """Periodic background task to detect and remind about abandoned carts."""
    import asyncio
    from app.services.shoppingcart import scan_abandoned_carts, send_cart_reminder
    from app.core.settings import S

    # Initial delay to let other services start
    await asyncio.sleep(10)

    while True:
        if S.cart_abandonment_enabled:
            try:
                carts = scan_abandoned_carts(
                    threshold_hours=S.cart_abandonment_threshold_hours,
                )
                for cart in carts:
                    try:
                        send_cart_reminder(cart)
                    except Exception:
                        logger.warning("cart_reminder_failed", extra={"cart_id": cart.get("cart_id")})
            except Exception:
                logger.exception("Cart abandonment check failed")
        await asyncio.sleep(S.cart_abandonment_check_interval_minutes * 60)

app.add_event_handler("startup", lambda: asyncio.ensure_future(_cart_abandonment_loop()))
```

### Phase 4: DynamoDB Table Changes

#### 6.9 GSI and TTL Configuration

**File: `scripts/local-ddb-init.py`** -- update shopping_cart TableDef:

```python
TableDef(
    _resolve_table_name(S.shopping_cart_table_name, "shopping_cart"),
    "PK", "SK",
    gsis=[
        GsiDef("ByStatusActivity", "status", "last_activity_at"),
    ],
    attr_types={"last_activity_at": "N"},
    ttl_attribute="ttl",
)
```

**Note**: Adding a GSI requires a table recreation in dev mode (clean restart via `just restart`). Existing items without `last_activity_at` or `status` will not appear in the GSI until updated.

### Phase 5: Frontend Types Update

#### 6.10 TypeScript Type Update

**File: `frontend/src/api/types.ts`** -- update `CartSummary` interface:

```typescript
export interface CartSummary {
  cart_id: string;
  status: string;
  created_at: string;
  purchased_at?: string;
  purchased_total_cents?: number;
  currency: string;
  // SHOP-003: Abandonment tracking
  last_activity_at?: number;
  abandoned_at?: number;
  reminder_count?: number;
}
```

---

## 7. Security & Privacy Considerations

### 7.1 Reminder Content

Cart abandonment emails MUST NOT include item names, prices, or quantities in the email body. Email may be forwarded or viewed on shared devices. The email says "You have items in your cart" with a generic link, not "You left Wireless Headphones ($49.99) in your cart."

In-app alerts may include `items_count` as a number (e.g., "3 items") since in-app alerts are only visible to the authenticated user.

### 7.2 Unsubscribe / Preference Control

Users can disable `cart.abandoned` alerts via the alert preferences system (`frontend/src/pages/alerts/AlertPrefs.tsx`). The `cart.abandoned` event type must be added to the `ALERT_EVENT_TYPES` list in `app/services/alerts.py` to appear in preferences.

### 7.3 Rate Limiting

- **Reminder cooldown**: `CART_ABANDONMENT_REMINDER_COOLDOWN_HOURS: 48` -- prevents reminder spam.
- **Max reminders**: `CART_ABANDONMENT_MAX_REMINDERS: 2` -- hard cap per cart.
- **Background loop interval**: 60 minutes -- limits scan frequency.
- **Scan limit**: `Limit=200` in the GSI query -- prevents runaway scans.

### 7.4 Data Minimization

Abandoned cart data (abandoned_at, reminder_count) is automatically cleaned up via DDB TTL after 30 days of inactivity. No manual purge required.

---

## 8. Testing Strategy

### 8.1 Unit Tests (pytest)

**File**: `tests/test_cart_abandonment.py`

| # | Test Function | Assertion |
|---|--------------|-----------|
| 1 | `test_touch_cart_activity_updates_last_activity_at` | After `_touch_cart_activity`, cart's `last_activity_at` is recent timestamp |
| 2 | `test_touch_cart_activity_sets_ttl` | After `_touch_cart_activity`, cart's `ttl` is ~30 days in the future |
| 3 | `test_scan_abandoned_carts_returns_stale_carts` | Cart with `last_activity_at` 25h ago appears in scan results |
| 4 | `test_scan_abandoned_carts_skips_active_carts` | Cart with `last_activity_at` 1h ago NOT in scan results |
| 5 | `test_scan_abandoned_carts_skips_recently_reminded` | Cart with `last_reminder_at` 12h ago (within 48h cooldown) NOT in results |
| 6 | `test_scan_abandoned_carts_skips_maxed_reminders` | Cart with `reminder_count=2` NOT in scan results |
| 7 | `test_send_cart_reminder_writes_alert` | After `send_cart_reminder`, alert with event `cart.abandoned` exists in T.alerts |
| 8 | `test_send_cart_reminder_updates_tracking_fields` | After reminder, `last_reminder_at` > 0 and `reminder_count` incremented |
| 9 | `test_send_cart_reminder_skips_empty_cart` | Cart with zero items: `send_cart_reminder` returns without writing alert |
| 10 | `test_start_cart_initializes_last_activity_at` | New cart has `last_activity_at` set to current timestamp |
| 11 | `test_add_item_triggers_touch_activity` | After `add_item`, parent cart `last_activity_at` updated |
| 12 | `test_purchased_carts_not_scanned` | Cart with `status=PURCHASED` NOT in scan results (GSI filters by status=OPEN) |
| 13 | `test_purchase_removes_ttl` | After `purchase_cart`, the `ttl` attribute is removed from cart record |
| 14 | `test_abandoned_at_set_once` | Second reminder does not overwrite `abandoned_at` (uses `if_not_exists`) |
| 15 | `test_feature_flag_disabled` | When `CART_ABANDONMENT_ENABLED=false`, scan returns empty |

### 8.2 E2E Tests

**Test File:** `frontend/e2e/cart-abandonment.spec.ts`

**Section 1: Activity Tracking API (3 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 1.1 | start_cart sets last_activity_at | Create cart; response includes `last_activity_at > 0` |
| 1.2 | add_item updates last_activity_at | Add item to cart; GET cart shows updated `last_activity_at` |
| 1.3 | Cart list returns abandonment fields | List carts; response items include `abandoned_at` and `reminder_count` fields |

**Section 2: Abandonment Detection API (4 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 2.1 | Cart with recent activity is not abandoned | Scan endpoint returns empty for active cart |
| 2.2 | Cart older than threshold detected | Backdate `last_activity_at` in DDB; scan returns the cart |
| 2.3 | Reminder creates in-app alert | Trigger reminder; GET alerts contains event `cart.abandoned` |
| 2.4 | Alert links to correct cart | Alert details contain `link: "/cart?cartId={id}"` |

**Section 3: Reminder Limits (3 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 3.1 | First reminder increments count | After reminder; GET cart shows `reminder_count: 1` |
| 3.2 | Cooldown prevents immediate second reminder | Scan immediately after reminder returns empty for same cart |
| 3.3 | Max reminders respected | Cart with `reminder_count: 2` excluded from scan results |

### 8.3 Edge Cases

- Cart created but never receives any items (empty cart, no reminder sent).
- Cart with items from multiple creators (single activity timestamp, no per-creator split).
- User with multiple open carts (each tracked independently).
- Cart abandoned, reminded, then user adds more items (resets `last_activity_at`, future reminders restart from that point).
- Race condition: cart purchased between scan and reminder send (graceful handling needed -- check status before sending).
- Very large number of abandoned carts (200 limit per scan protects against runaway).

---

## 9. Migration & Rollout

### 9.1 Feature Flag

`CART_ABANDONMENT_ENABLED` (env var, default `true`). When `false`:
- The `_cart_abandonment_loop` background task runs but is a no-op (skips scan/send).
- Activity tracking (`_touch_cart_activity`) still runs (harmless, ensures data is ready when feature is enabled).
- Cart responses still include the new fields (all default to 0).

### 9.2 DynamoDB Changes

1. **Add GSI `ByStatusActivity`** to shopping_cart table in `scripts/local-ddb-init.py`.
   - Requires table recreation in dev (run `just restart`).
   - In production: create GSI via DDB UpdateTable (online, no downtime).
   - **Must include `attr_types={"last_activity_at": "N"}`** for numeric sort key.

2. **Enable TTL** with attribute name `ttl` on the shopping_cart table.
   - In `scripts/local-ddb-init.py`: add `ttl_attribute="ttl"` to TableDef.
   - In production: enable via DDB UpdateTimeToLive API.

3. **Backward compatibility**: Existing items without `last_activity_at` or `ttl` are simply not indexed/expired. They will not appear in the abandonment scan (which queries the GSI). As users interact with their carts, the new fields are populated.

### 9.3 Data Migration for Existing Carts

Existing `OPEN` carts have no `last_activity_at`. Options:
- **Option A (recommended)**: No migration. Existing carts without `last_activity_at` do not appear in the GSI. They will never be flagged as abandoned. Next activity on the cart populates the field.
- **Option B**: One-time script to backfill `last_activity_at = created_at` for all OPEN carts. More correct but requires a DDB scan.

Recommendation: Option A for simplicity. Existing carts that are truly abandoned will be cleaned up by DDB TTL once the `ttl` field is added (via Option B script if desired).

### 9.4 Rollback

Set `CART_ABANDONMENT_ENABLED=false`. The background loop stops. Cart records retain the new fields but they are inert. GSI and TTL remain configured but have no functional impact.

---

## 10. Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `tests/test_cart_abandonment.py` | Unit tests for abandonment logic | ~200 |
| `frontend/e2e/cart-abandonment.spec.ts` | E2E tests | ~150 |

## 11. Files to Modify

| File | Change | Lines Added/Changed |
|------|--------|---------------------|
| `app/services/shoppingcart.py` | Add `_touch_cart_activity`, `scan_abandoned_carts`, `send_cart_reminder`; update `start_cart`, `add_item`, `update_quantity`, `remove_item`, `_cart_from_item`, `purchase_cart` | ~100 new + ~20 modified |
| `app/core/settings.py` | Add `cart_abandonment_*` and `cart_ttl_days` settings | +6 lines |
| `app/main.py` | Register `_cart_abandonment_loop` as startup background task | +20 lines |
| `scripts/local-ddb-init.py` | Add GSI `ByStatusActivity` to shopping_cart table; add `ttl_attribute="ttl"` | +5 lines |
| `app/services/alerts.py` | Add `"cart.abandoned"` to `ALERT_EVENT_TYPES` list | +1 line |
| `frontend/src/api/types.ts` | Add `last_activity_at`, `abandoned_at`, `reminder_count` to `CartSummary` interface | +3 lines |

---

## 12. Acceptance Criteria

1. Every cart mutation (`add_item`, `update_quantity`, `remove_item`) updates `last_activity_at` on the parent cart record.
2. `start_cart` initializes `last_activity_at` to the creation timestamp.
3. Background task detects carts with `last_activity_at` older than 24 hours (configurable via `CART_ABANDONMENT_THRESHOLD_HOURS`).
4. Detected abandoned carts with items trigger an in-app alert with `event: "cart.abandoned"` and a clickable link to the cart.
5. Email reminder sent to the cart owner's email address (logged to file in dev mode).
6. At most 2 reminders per cart (`CART_ABANDONMENT_MAX_REMINDERS`), with a 48-hour cooldown between reminders (`CART_ABANDONMENT_REMINDER_COOLDOWN_HOURS`).
7. `PURCHASED` carts are never flagged as abandoned.
8. Empty carts (zero items) are never reminded.
9. DynamoDB TTL auto-deletes OPEN carts with no activity for 30 days (`CART_TTL_DAYS`).
10. Purchased carts do NOT have TTL set (permanent records).
11. Setting `CART_ABANDONMENT_ENABLED=false` disables the background scan without affecting other cart operations.
12. `ByStatusActivity` GSI uses `attr_types={"last_activity_at": "N"}` for numeric sort key.
13. All 15 unit tests pass.
14. All 10 E2E tests pass.

---

## 13. Dependencies

- **Alerts system**: `app/services/alerts.py` -- `write_alert`, `send_alert_email` must be deployed. Already operational.
- **Profile service**: `app/services/profile.py` -- `get_profile` for email lookup. Already operational.
- **Shopping cart table**: Must support GSI addition (`just restart` in dev for table recreation).
- **DynamoDB TTL**: Must be enabled on the table (via `scripts/local-ddb-init.py`).

---

## 14. Open Questions

1. **Item-level detail in reminder**: Should the email include item count or item names? Current design: item count only in alert detail, no item names in email (privacy). Revisit based on user feedback.
2. **Admin dashboard integration**: Should abandoned cart metrics appear in the existing analytics page, or a dedicated admin endpoint? Defer admin visibility to a follow-up ticket.
3. **Multi-cart handling**: If a user has 5 abandoned carts, should they get 5 separate alerts or one batched alert? Current design: one alert per cart (up to max_reminders each). For users with many abandoned carts, this could be noisy. Consider batching in v2.
4. **Cart recovery incentive**: Should the abandonment email include a promo code incentive (e.g., "10% off if you checkout within 24 hours")? This is a powerful conversion tool but requires SHOP-002 (promo checkout integration) to be implemented first.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Cart schema has no TTL/expiry/activity fields | `app/services/shoppingcart.py` | 51-59 | VERIFIED |
| start_cart creates no last_activity_at | `app/services/shoppingcart.py` | 237-250 | VERIFIED |
| add_item does not touch parent cart | `app/services/shoppingcart.py` | 287-312 | VERIFIED |
| purchase_cart transitions to PURCHASED | `app/services/shoppingcart.py` | 428-536 | VERIFIED |
| _cart_from_item has 6 fields only | `app/services/shoppingcart.py` | 51-59 | VERIFIED |
| shoppingcart.py is 536 lines | `app/services/shoppingcart.py` | 1-536 | VERIFIED |
| Shopping cart table defined in local-ddb-init | `scripts/local-ddb-init.py` | 66 | VERIFIED |
| Shopping cart table handle | `app/core/tables.py` | 34, 132 | VERIFIED |
| Shopping cart table setting | `app/core/settings.py` | 710 | VERIFIED |
| No cart-related executor in schedule_executors | `app/services/schedule_executors.py` | 1-165 | VERIFIED |
| scheduled_actions.py create_action | `app/services/scheduled_actions.py` | 91-134 | VERIFIED |
| query_due_actions | `app/services/scheduled_actions.py` | 355 | VERIFIED |
| write_alert function with event, title, details | `app/services/alerts.py` | 265-320 | VERIFIED |
| send_alert_email (dev mode logs to file) | `app/services/alerts.py` | 332-353 | VERIFIED |
| No "abandonment" or "cart.*reminder" in codebase | grep full codebase | N/A | VERIFIED (0 results) |
| DDB FilterExpression after page fetch gotcha | `CLAUDE.md` | gotchas | VERIFIED |
| attr_types required for numeric GSI sort keys | `CLAUDE.md` | gotchas | VERIFIED |
