# LCOM-003: Broadcast Quick-Buy Checkout — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

LCOM-003 introduces a one-click "Quick Buy" checkout overlay that lets viewers purchase a product from the broadcast shelf without leaving the live stream. The feature requires a new `BroadcastOrders` DynamoDB table, a `broadcast_orders` service, four new REST endpoints in the broadcast router, an idempotent purchase flow that writes a billing ledger debit, a purchase counter (in-memory + DDB persistence), an SSE `purchase:completed` event fan-out to broadcasters, and new frontend components (`QuickBuyDialog`, `PurchaseCounter`, `broadcast-orders.ts`). **Nothing in this ticket is implemented.** The broadcaster-side prerequisites (LCOM-001 product shelf, LCOM-004 pricing) are fully built; the checkout layer itself is entirely absent.

**Type**: Feature (money path — SEC-004, SEC-024 price-tampering surface).
**Priority**: High.
**Status**: UNBUILT.
**Owning area**: Broadcast commerce / billing.
**Persona**: Authenticated viewers who want to purchase a shelf product during a live stream without navigating away; broadcasters who want per-session purchase analytics.

Cross-referenced: [[LCOM-001]] (shelf prerequisite), [[LCOM-004]] (effective-price resolution), [[SEC-004]] (billing authz & integrity), [[SEC-024]] (e-commerce price tampering & refund entitlement), [[SECOPS-007]] (dev/prod parity via `S.dev_mode`).

---

## 2. Current-State Investigation (what exists today)

### 2.1 What LCOM-001 and LCOM-004 provide (prerequisites complete)

`app/services/broadcast_product_shelf.py` contains `add_product_to_shelf` (line 45), `list_shelf_products` (line 170), and `resolve_effective_price` (line 211). The router at `app/routers/broadcast.py` exposes `GET /broadcast/sessions/{id}/products` (line 2180) returning `BroadcastShelfListOut` with items, and `PATCH /broadcast/sessions/{id}/products/{item_id}/price` (line 2227) for broadcast-exclusive pricing. These are the inputs the quick-buy flow reads from.

`resolve_effective_price` (line 211) returns `{effective_price_cents, original_price_cents, is_broadcast_price, discount_pct, broadcast_price_expires_at}`. This is the single source of truth for the price that any checkout must use — client-submitted prices are never trusted (SEC-024).

### 2.2 Billing infrastructure (reusable, exists)

`app/services/billing_shared.py`: `user_pk(user_id)` (line 23), `ddb_get(table, pk, sk)` (line 27), `new_ledger_entry(table, pk, ...)` (line 224). The billing table (`T.billing`) uses `pk=USER#{user_sub}`, `sk=PM#{pm_id}` for payment methods and `sk=LEDGER#{id}` for transactions. This exact pattern is used by messaging tips (`app/routers/messaging.py`) and locked-message unlocks.

### 2.3 Broadcast SSE (exists)

`app/services/broadcast_sse.py:29` `broadcast_sse_publish(session_id, event)` fans out to all SSE subscribers. Already delivers `shelf:add`, `shelf:remove`, `chat:message`, `purchase:completed` events via the existing stream at `GET /broadcast/sessions/{id}/stream`.

### 2.4 What is missing

| Component | Path | Status |
|-----------|------|--------|
| `BroadcastOrders` DynamoDB table | `scripts/local-ddb-init.py` | MISSING |
| `broadcast_orders_table_name` setting | `app/core/settings.py` | MISSING |
| `broadcast_orders` table handle | `app/core/tables.py` | MISSING |
| `app/services/broadcast_orders.py` | New service file | MISSING |
| Quick-buy endpoint `POST /broadcast/sessions/{id}/quick-buy` | `app/routers/broadcast.py` | MISSING |
| Purchase stats endpoint `GET .../purchases/stats` | `app/routers/broadcast.py` | MISSING |
| Session purchase history `GET .../purchases` | `app/routers/broadcast.py` | MISSING |
| Viewer purchase history `GET /broadcast/purchases/mine` | `app/routers/broadcast.py` | MISSING |
| `BroadcastQuickBuyIn/Out` Pydantic models | `app/routers/broadcast.py` | MISSING |
| `frontend/src/api/endpoints/broadcast-orders.ts` | Frontend API layer | MISSING |
| `frontend/src/pages/broadcast/QuickBuyDialog.tsx` | Frontend component | MISSING |
| `frontend/src/pages/broadcast/PurchaseCounter.tsx` | Frontend component | MISSING |
| "Quick Buy" button on `ProductShelf.tsx` / `ProductShelfCard` | `frontend/src/pages/broadcast/ProductShelf.tsx` | MISSING |
| `purchase:completed` SSE handler in `LivePlayer.tsx` | `frontend/src/pages/broadcast/LivePlayer.tsx` | MISSING |
| `PurchaseCounter` integration in `BroadcastPage.tsx` | `frontend/src/pages/broadcast/BroadcastPage.tsx` | MISSING |

The broadcast router (`app/routers/broadcast.py`, ~3969 lines) has no reference to `quick_buy`, `broadcast_orders`, `purchase_stats`, or `purchases/mine`. `app/core/settings.py` has `broadcast_product_shelf_table_name` (line 1462) but no `broadcast_orders_table_name`. `app/core/tables.py` has `broadcast_product_shelf` (line 156/392) but no `broadcast_orders`.

---

## 3. Gap / Threat Analysis

### 3.1 Functional gaps

The feature is entirely unbuilt. Viewers clicking "Quick Buy" have no purchase path within the broadcast player; they must navigate to `/shop/cart` and `/shop/checkout`, causing high abandonment and zero broadcast attribution.

### 3.2 Security requirements (SEC-004 / SEC-024)

The money path must satisfy:

1. **Price resolved server-side from shelf**: `create_quick_buy_order` must call `resolve_effective_price(shelf_item, session.status)` (from `app/services/broadcast_product_shelf.py:211`) rather than trusting client-submitted `unit_price_cents`. Never accept a price from the request body.
2. **Payment method ownership**: Validate `T.billing.get_item(Key={"pk": user_pk(buyer_id), "sk": f"PM#{payment_method_id}"})` before charging. A missing or wrong PM raises 400.
3. **Session liveness gate**: Quick-buy is only valid when `session.status == "live"`. If the session transitions to `stopped` between the viewer clicking Buy and the request arriving, the endpoint returns 403 — the effective price might have reverted and the broadcast price no longer applies.
4. **Idempotency**: Client must send `idempotency_key`; the service checks recent buyer orders before creating a new one to prevent double-charges on network retry.
5. **Self-purchase allowed**: The broadcaster may purchase from their own shelf (common for testing). No restriction needed.
6. **Billing ledger debit**: Write `LEDGER#{id}` with `amount_cents=-total_cents`, `reference_type="broadcast_order"` for audit trail, consistent with `app/routers/messaging.py` tip/unlock pattern.
7. **Stripe mock**: In dev mode, `stripe-mock` returns `requires_payment_method` for off-session PaymentIntents (CLAUDE.md). Do not make a Stripe API call. Validate PM existence in DDB and write the ledger — sufficient for dev-mode parity (SECOPS-007). In prod the payment gateway call wraps around step 6.

### 3.3 Code sites that must change

- `app/core/settings.py` — add `broadcast_orders_table_name`
- `app/core/tables.py` — add `broadcast_orders: Any` field and `_safe_table(...)` init
- `scripts/local-ddb-init.py` — add `BroadcastOrders` `TableDef` with GSIs `BySession` and `ByBuyer` (both sort on `created_at` numeric — requires `attr_types={"created_at": "N"}`)
- `app/services/broadcast_orders.py` — create new file
- `app/routers/broadcast.py` — add 4 endpoints + Pydantic models
- `frontend/src/api/endpoints/broadcast-orders.ts` — create
- `frontend/src/pages/broadcast/QuickBuyDialog.tsx` — create
- `frontend/src/pages/broadcast/PurchaseCounter.tsx` — create
- `frontend/src/pages/broadcast/ProductShelf.tsx` — add "Quick Buy" button to `ProductShelfCard`
- `frontend/src/pages/broadcast/LivePlayer.tsx` — add `purchase:completed` SSE listener, wire `QuickBuyDialog`
- `frontend/src/pages/broadcast/BroadcastPage.tsx` — add `PurchaseCounter` to session detail view

---

## 4. Proposed Design / Fix

### 4.1 DynamoDB — `BroadcastOrders` table

Single-item table (`order_id` PK, no SK) with two GSIs:

| GSI | PK | SK | Purpose |
|-----|----|----|---------|
| `BySession` | `session_id` | `created_at` (N) | Broadcaster analytics |
| `ByBuyer` | `buyer_id` | `created_at` (N) | Viewer purchase history |

`scripts/local-ddb-init.py` entry:
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

Order item fields: `order_id` (`bord_{uuid4().hex}`), `session_id`, `buyer_id`, `seller_id`, `item_id`, `category_id`, `item_name`, `quantity` (1–10), `unit_price_cents` (from `resolve_effective_price`), `original_price_cents`, `was_broadcast_price` (bool), `discount_pct`, `total_cents`, `currency`, `payment_method_id`, `status` (`completed`/`refunded`), `created_at`, `idempotency_key`.

### 4.2 Service layer — `app/services/broadcast_orders.py`

Key functions:

```python
def create_quick_buy_order(*, session_id, buyer_id, seller_id,
        shelf_item, session_status, payment_method_id, quantity=1,
        idempotency_key=None) -> Dict[str, Any]:
    # 1. Idempotency check via ByBuyer GSI scan (last 50 orders)
    # 2. Validate PM: ddb_get(T.billing, user_pk(buyer_id), f"PM#{payment_method_id}")
    # 3. Resolve price server-side: resolve_effective_price(shelf_item, session_status)
    # 4. unit_price = pricing["effective_price_cents"]; total = unit_price * quantity
    # 5. PutItem to T.broadcast_orders
    # 6. new_ledger_entry(T.billing, user_pk(buyer_id), amount=-total, reason=...)
    # 7. _increment_purchase_counter(session_id, total); _persist_session_counter(...)
    # 8. broadcast_sse_publish(session_id, {"_type": "purchase:completed", ...})
    # 9. return _order_out(order)

def get_purchase_counter(session_id) -> Dict[str, int]: ...  # in-memory fallback to DDB
def list_session_orders(session_id, limit=200) -> List[Dict]: ...  # BySession GSI
def list_buyer_orders(buyer_id, limit=200) -> List[Dict]: ...  # ByBuyer GSI
```

In-memory counter uses `threading.Lock` (same pattern as `broadcast_chat_store.py:_CHAT_RATE_LOCK` at line 19).

### 4.3 Router endpoints (add to `app/routers/broadcast.py`)

```
POST   /broadcast/sessions/{id}/quick-buy       → BroadcastQuickBuyOut (201)
GET    /broadcast/sessions/{id}/purchases/stats → BroadcastPurchaseStatsOut
GET    /broadcast/sessions/{id}/purchases       → BroadcastPurchaseHistoryOut (broadcaster/admin only)
GET    /broadcast/purchases/mine                → BroadcastPurchaseHistoryOut
```

The quick-buy endpoint checks `session.status == "live"` (403 otherwise), validates the shelf item exists, then delegates to `create_quick_buy_order`. Price is never read from `body`.

### 4.4 Frontend

- **`broadcast-orders.ts`**: `quickBuy(sessionId, body)`, `getPurchaseStats(sessionId)`, `getSessionPurchases(sessionId)`, `getMyPurchases()`.
- **`QuickBuyDialog.tsx`**: shadcn `Dialog` overlay; fetches payment methods via `["billing", "payment-methods"]` React Query key; quantity stepper (1–10); `useMutation` calls `quickBuy`; `idempotency_key = \`${sessionId}_${itemId}_${Date.now()}\``; shows `BroadcastPrice` component for effective price. On success: `toast.success(...)`, close dialog, fire `onPurchased(order)`.
- **`PurchaseCounter.tsx`**: Badge showing `N purchases ($X.XX)`. Fetches initial stats from `getPurchaseStats`. Updates via `purchase:completed` SSE event dispatched from `LivePlayer.tsx`.
- **`ProductShelf.tsx` / `ProductShelfCard`**: Add "Quick Buy" button that opens `QuickBuyDialog` with the shelf item.
- **`LivePlayer.tsx`**: Add `purchase:completed` SSE listener on the broadcast stream EventSource; dispatch `window.dispatchEvent(new CustomEvent("purchase:completed", {detail: data}))` for `PurchaseCounter` to consume.
- **`BroadcastPage.tsx`**: Add `<PurchaseCounter sessionId={...} />` in the broadcaster session detail view alongside `ProductShelfManager`.

### 4.5 Dev/Prod parity (SECOPS-007)

In dev mode (`S.dev_mode == True`): skip the actual Stripe/PayPal charge; validate PM in DDB, write ledger, create order with `status="completed"`. Same code path as tips/unlocks in `app/routers/messaging.py`. In prod: wrap a Stripe PaymentIntent creation around step 6 using the PM's `provider_id`.

### 4.6 Alternatives considered

- **Reuse standard `/shop/cart` + `/shop/checkout`**: Rejected — requires navigating away from the broadcast, causing high abandonment. No broadcast attribution possible.
- **Store orders in the existing `orders` table**: Rejected — ticket specifies isolated broadcast analytics via `BroadcastOrders`. A dedicated table and GSIs enable per-session revenue reporting without polluting general order history.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_broadcast_orders.py`)

| Case | Assertion |
|------|-----------|
| `test_create_order_uses_effective_price` | `unit_price_cents == pricing["effective_price_cents"]`, not raw `price_cents` |
| `test_create_order_writes_ledger_debit` | LEDGER row has `amount_cents == -total_cents`, `reference_type == "broadcast_order"` |
| `test_idempotency_same_key_returns_same_order` | Second call with same `idempotency_key` returns `order_id` from first call |
| `test_invalid_pm_raises_400` | `HTTPException(400)` when PM not in billing table |
| `test_quantity_multiplied` | `total_cents == unit_price * 3` for `quantity=3` |
| `test_purchase_counter_increments` | `get_purchase_counter("sess1")["count"] == 2` after two orders |
| `test_list_session_orders` | `BySession` GSI returns both orders |
| `test_list_buyer_orders` | `ByBuyer` GSI returns buyer's orders |
| `test_decimal_coercion` | `isinstance(order["total_cents"], int)` (DDB returns Decimal) |

### 5.2 Playwright E2E (`frontend/e2e/broadcast-quick-buy.spec.ts`)

**Section 120: Quick-Buy API (8 tests)**: viewer purchases, billing ledger debit, invalid PM → 400, product not on shelf → 404, session not live → 403, idempotent duplicate, quantity multiplier, broadcaster self-purchase.

**Section 121: Purchase Stats API (4 tests)**: broadcaster views stats, stats accumulate after multiple purchases, viewer cannot view stats → 403, zero stats for fresh session.

**Section 122: Purchase History API (4 tests)**: broadcaster lists session orders, viewer lists own purchases via `/purchases/mine`, orders newest-first, order includes `item_name`/`quantity`/`total_cents`.

**Section 123: QuickBuyDialog UI (4 tests)**: "Quick Buy" button visible on shelf card, dialog opens with product info + PM dropdown, "Buy Now" triggers purchase + toast confirmation, dialog closes and viewer stays on broadcast page.

All tests run with mocked DDB (moto) and no real Stripe calls. Use `injectAuth(page, "alice")` + `apiPost(page, "alice", ...)` for cookie-auth; seed PM via DDB direct write before UI tests.

### 5.3 Observability

- Log each `create_quick_buy_order` call at INFO level with `session_id`, `buyer_id`, `item_id`, `total_cents`, `was_broadcast_price`.
- The `purchase:completed` SSE event includes `purchase_count` and `purchase_total_cents` for live broadcaster dashboard metrics.

### 5.4 Rollout

Feature flag: no new flag needed — the endpoints are additive and behind `require_ui_session`. Broadcaster sees the `PurchaseCounter` only when `session.status == "live"`. Viewer sees "Quick Buy" button only when `isLive && productShelf.length > 0`.

**Effort estimate**: M (3–4 days). Suggested order: DDB infra → service → router endpoints → `broadcast-orders.ts` → `QuickBuyDialog` → `PurchaseCounter` → wire SSE in `LivePlayer`.

**Risks**: Stripe mock always returns `requires_payment_method` for off-session — must confirm dev-mode bypass is in place before E2E tests. Counter in-memory state is lost on server restart; fall back to DDB `purchase_count` field on `BroadcastSessions` table (update via `update_item`).
