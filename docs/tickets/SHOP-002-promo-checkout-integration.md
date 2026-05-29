# SHOP-002: Promo Code Integration in Checkout

**Ticket**: SHOP-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 6-8 days

---

## 1. Executive Summary

The platform has a fully-featured promo code system and a fully-featured checkout flow, but they are not connected. The promo code service (`app/services/promo_codes.py`, 450+ lines) supports creating codes with percentage discounts, fixed-amount discounts, and free trials, along with validation rules (expiration, max uses, per-user limits, creator scope, checkout type, minimum purchase). The frontend has a dedicated `PromoCodesPage` for sellers to manage codes. Separately, the checkout page (`frontend/src/pages/shop/Checkout.tsx`, 266 lines) displays a cart summary, payment method selector, and "Place Order" button -- but has zero promo code integration. There is no input field for entering a code, no discount calculation display, and no redemption call during purchase.

The disconnect means sellers can create promo codes but buyers cannot use them. The promo code system is effectively dead code from the buyer's perspective -- fully implemented, tested, and operational, but with no user-facing entry point in the checkout flow. This is the single most impactful commerce UX gap on the platform.

This feature wires the existing promo code validation and redemption into the checkout flow. It adds an "Apply promo code" expandable input in the Checkout page, calls `validate_promo_code()` to show a real-time discount preview, passes the validated code through to `purchase_cart()`, calls `redeem_promo_code()` on successful purchase, and displays the discount as a line item in the order summary. The backend `purchase_cart()` function is updated to accept an optional `promo_code` parameter and re-validate server-side before applying the discount.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Enter Promo Code at Checkout**

As a buyer, I want to enter a promo code during checkout and see my discount, so that I pay the correct reduced price.

Acceptance criteria:
- Expandable "Have a promo code?" section below the order summary.
- Text input with an "Apply" button.
- On valid code: green success message with discount amount (e.g., "Code applied: -$7.50 discount").
- On invalid code: red error message with specific reason (e.g., "This code has expired").
- Loading state during validation (spinner on Apply button).

**US-2: See Discount in Order Summary**

As a buyer, I want the discounted total reflected on the order summary and "Place Order" button, so that I know exactly what I will be charged.

Acceptance criteria:
- Discount appears as a green line item: "Promo discount (SUMMER20)" with "-$7.50".
- Total updates from original to discounted amount.
- "Place Order" button text shows discounted total: "Place Order -- $42.50" (was "$50.00").
- Original subtotal still shown for reference.

**US-3: Remove Applied Code**

As a buyer, I want to remove an applied code and revert to the original price, so that I can try a different code or pay full price.

Acceptance criteria:
- "Remove" button appears next to the applied code.
- Clicking Remove clears the discount, reverts total, and re-enables the promo input.
- "Place Order" button reverts to original total.

**US-4: Server-Side Re-Validation**

As a buyer, I want my promo code re-validated at purchase time, so that race conditions between validation and purchase do not result in incorrect discounts.

Acceptance criteria:
- Backend `purchase_cart()` re-validates the code before applying the discount.
- If the code became invalid (expired, maxed out) between validation and purchase, the purchase returns 422 with a clear error.
- Frontend shows the error and the buyer can retry without the code.

**US-5: Code Redemption Tracking**

As a seller, I want promo code usage counts to increment when codes are used in purchases, so that my usage limits work correctly.

Acceptance criteria:
- `current_uses` on the promo code record increments atomically after successful purchase.
- A `REDEEM#` item is written to the promo codes table per user per redemption.
- `max_uses` and `max_uses_per_user` limits are enforced during validation.

**US-6: Creator Scope Validation**

As a seller, I want promo codes I created to work only for my own catalog items, so that other sellers' codes do not affect my pricing.

Acceptance criteria:
- Promo validation checks that the code's `creator_user_id` matches the cart items' creator.
- Error message "This code is not valid for this creator" shown when there is a mismatch.
- For v1, all cart items must belong to the same creator (mixed-creator carts show a clear error).

### 2.2 Pain Points

1. **Unused system**: Sellers can create promo codes through the PromoCodesPage but have no way to let buyers use them. The codes are effectively dead features.
2. **No discount incentives**: Buyers have no mechanism to get discounts on catalog purchases, reducing conversion rates and average order value.
3. **Manual workarounds**: Sellers must manually adjust item prices to simulate discounts, losing the audit trail, usage limits, and time-based expiration that the promo system provides.
4. **Broken seller expectation**: When sellers create promo codes with usage limits and expiration dates, they expect buyers to be able to enter them during checkout. The current gap creates confusion.

---

## 3. Current State Analysis

### 3.1 Promo Code Service (`app/services/promo_codes.py`)

**Create** (`create_promo_code`, line 85):

```python
# app/services/promo_codes.py:85-96
def create_promo_code(
    creator_id: str,
    code: str,
    discount_type: str,           # "percentage", "fixed_amount", "free_trial"
    discount_value: int = 0,       # Percentage (1-100) or fixed amount in cents
    free_trial_days: int = 0,
    applies_to: Optional[List[str]] = None,  # ["subscription", "vod", "shop"]
    min_purchase_cents: int = 0,
    max_uses: int = 0,             # 0 = unlimited
    max_uses_per_user: int = 1,
    expires_at: int = 0,           # 0 = never expires
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
```

**Validate** (`validate_promo_code`, line 239):

```python
# app/services/promo_codes.py:239-332
def validate_promo_code(
    code: str,
    user_id: Optional[str],
    checkout_type: str,            # Must match code's applies_to list
    item_price_cents: int,         # Used for discount calculation
    creator_user_id: str,          # Must match code's creator_user_id
) -> Dict[str, Any]:
    """Returns: {valid, code_id, discount_type, discount_cents, final_price_cents, free_trial_days, message}"""
```

Validation checks (in order):
1. Code existence and active status (line 261-264)
2. Expiry check (line 269-273)
3. Max uses check (line 276-281)
4. Per-user limit check (line 284-291)
5. Checkout type applicability (line 294-298)
6. Creator scope check (line 301-304)
7. Free trial + non-subscription check (line 307-311)
8. Minimum purchase check (line 314-319)
9. Discount calculation (line 322)

**Calculate discount** (`_calculate_discount`, line 335):

```python
# app/services/promo_codes.py:335-352
def _calculate_discount(promo: Dict[str, Any], item_price_cents: int) -> Tuple[int, int, int]:
    """Returns (discount_cents, final_price_cents, free_trial_days)."""
    dtype = promo["discount_type"]
    value = int(promo.get("discount_value") or 0)
    if dtype == "percentage":
        discount = int(item_price_cents * value / 100)
        discount = min(discount, item_price_cents)  # Cap at total
        return discount, max(0, item_price_cents - discount), 0
    elif dtype == "fixed_amount":
        discount = min(value, item_price_cents)      # Cap at total
        return discount, max(0, item_price_cents - discount), 0
    elif dtype == "free_trial":
        return item_price_cents, 0, trial
    return 0, item_price_cents, 0
```

**Redeem** (`redeem_promo_code`, line 357):

```python
# app/services/promo_codes.py:357-364
def redeem_promo_code(
    code_id: str,
    user_id: str,
    original_price_cents: int = 0,
    final_price_cents: int = 0,
    checkout_type: str = "",
    checkout_item_id: str = "",
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Atomically increments current_uses, records REDEEM# item per user."""
```

**Citation**: `app/services/promo_codes.py:85-96, 239-332, 335-352, 357-364` -- complete promo lifecycle.

### 3.2 Promo Code Router (`app/routers/promo_codes.py`)

| Endpoint | Method | Path | Purpose |
|----------|--------|------|---------|
| `create_promo_code` | POST | `/ui/promo-codes` | Create a new code |
| `list_promo_codes` | GET | `/ui/promo-codes` | List creator's codes |
| `get_promo_code` | GET | `/ui/promo-codes/{code_id}` | Get code with stats |
| `update_promo_code` | PATCH | `/ui/promo-codes/{code_id}` | Update code |
| `delete_promo_code` | DELETE | `/ui/promo-codes/{code_id}` | Deactivate code |
| `validate` | POST | `/ui/promo-codes/validate` | Validate a code (line 140) |
| `redeem` | POST | `/ui/promo-codes/redeem` | Redeem a code (line 160) |

**Citation**: `app/routers/promo_codes.py:140-181` -- validate and redeem endpoints.

### 3.3 Frontend Promo Code API (`frontend/src/api/endpoints/promoCodes.ts`)

Both validation and redemption wrappers already exist:

```typescript
// frontend/src/api/endpoints/promoCodes.ts:40-55
export const validatePromoCode = (body: {
  code: string;
  checkout_type: "subscription" | "vod" | "shop";
  item_price_cents: number;
  creator_user_id: string;
}) => api.post<PromoValidateOut>("/ui/promo-codes/validate", body);

export const redeemPromoCode = (body: {
  code_id: string;
  original_price_cents: number;
  final_price_cents: number;
  checkout_type: string;
  checkout_item_id?: string;
}) => api.post<{ ok: boolean; redeemed_at: number }>("/ui/promo-codes/redeem", body);
```

**Citation**: `frontend/src/api/endpoints/promoCodes.ts:40-55` -- wrappers exist and are tested.

### 3.4 Frontend Types (`frontend/src/api/types.ts`)

`PromoCodeOut`, `PromoCodeListOut`, `PromoCodeStatsOut`, and `PromoValidateOut` interfaces are defined at lines 3135-3160.

**Citation**: `frontend/src/api/types.ts:3135-3160` -- types defined.

### 3.5 Checkout Page (`frontend/src/pages/shop/Checkout.tsx`, 266 lines)

The checkout page has three main sections:

```typescript
// frontend/src/pages/shop/Checkout.tsx:63-78
const purchaseMutation = useMutation({
  mutationFn: () => purchaseCart(cartId),
  onSuccess: (data) => {
    queryClient.invalidateQueries({ queryKey: ["carts"] });
    queryClient.invalidateQueries({ queryKey: ["cart-items", cartId] });
    setPurchaseResult("success");
    setOrderId(data.order_id);
    setConfirmOpen(false);
    toast.success("Order placed successfully!");
  },
  onError: () => {
    setPurchaseResult("error");
    setConfirmOpen(false);
    toast.error("Purchase failed");
  },
});
```

1. **Order Summary** (lines 169-192): Maps over `items` showing name, quantity, and `line_total_cents`. Displays cart total.
2. **Payment Method** (lines 194-240): Lists payment methods with radio-button selection.
3. **Place Order** (lines 242-261): Button triggering `purchaseCart(cartId)` via mutation.

**Gaps in Checkout.tsx**:
- No import of any promo code API function.
- No promo-related state variables.
- No discount calculation or display.
- No promo input field or expandable section.
- `purchaseCart(cartId)` is called with no promo parameter.

**Citation**: `frontend/src/pages/shop/Checkout.tsx:1-266` -- no promo code UI.

### 3.6 Purchase Flow Backend (`app/services/shoppingcart.py:428`)

```python
# app/services/shoppingcart.py:428
def purchase_cart(user_sub: str, cart_id: str, *, idempotency_key: str | None = None) -> Dict[str, Any]:
```

The function:
1. Gets cart and verifies OPEN status (lines 429-440).
2. Lists items and sums `total_cents` (lines 442-443).
3. Creates commerce order via `commerce_order_service.create_order_from_line_items` (line 450).
4. Updates cart to PURCHASED status (line 462-484).
5. Records purchase history (line 510-518).

At no point does it accept a promo code, validate it, apply a discount, or call redemption.

**Citation**: `app/services/shoppingcart.py:428-536` -- purchase_cart with no promo support.

### 3.7 Cart Purchase API (`frontend/src/api/endpoints/cart.ts:42-43`)

```typescript
// frontend/src/api/endpoints/cart.ts:42-43
export const purchaseCart = (cartId: string) =>
  api.post<CartPurchase>(`/ui/shoppingcart/carts/${cartId}/purchase`);
```

No request body, no promo parameter.

**Citation**: `frontend/src/api/endpoints/cart.ts:42-43` -- no promo parameter.

### 3.8 Gaps Summary

| Component | Current State | Gap |
|-----------|--------------|-----|
| `Checkout.tsx` | No promo input or discount display | Full promo UI needed |
| `purchaseCart` (frontend) | No request body | Must pass promo_code |
| `purchase_cart` (backend) | No promo parameter | Must accept, validate, apply discount, redeem |
| Order summary | Shows original total only | Must show discount line item |
| "Place Order" button | Shows original total | Must show discounted total |
| Cart record | No promo fields | Must store promo_code_id, discount_cents, original_total_cents |

---

## 4. Technical Architecture

### 4.1 System Diagram

```
+--------------------+       +------------------------+       +---------------------+
| Checkout.tsx       |       |  Backend               |       |  DynamoDB           |
|                    |       |                        |       |                     |
| 1. [promo input]  |------>| POST /promo-codes/     |------>| promo_codes table   |
|    "Apply" button  |       |   validate             |       | code lookup         |
|                    |<------| { valid, discount }    |<------| validation rules    |
| 2. discount shown  |       |                        |       |                     |
|    in order summary|       |                        |       +---------------------+
|                    |       |                        |
| 3. [Place Order]  |------>| POST /carts/{id}/      |------>| shopping_cart table  |
|    button          |       |   purchase             |       | update w/ promo     |
|    (with promo)    |       |   { promo_code: "..." }|       |                     |
|                    |       |                        |       +---------------------+
|                    |       | purchase_cart():        |
|                    |       |   re-validate promo    |------>| promo_codes table   |
|                    |       |   apply discount       |       | re-check limits     |
|                    |       |   create order         |       |                     |
|                    |       |   redeem code          |------>| increment uses      |
|                    |       |                        |       | write REDEEM# item  |
|                    |<------| { order_id, total,     |       |                     |
|                    |       |   discount_cents, ... }|       +---------------------+
+--------------------+       +------------------------+
```

### 4.2 Data Flow

1. Buyer enters promo code in checkout, clicks "Apply".
2. Frontend calls `POST /ui/promo-codes/validate` with `{ code, checkout_type: "shop", item_price_cents: cart_total, creator_user_id }`.
3. If `valid: true`, frontend stores the result in local state and displays discount in order summary.
4. Buyer clicks "Place Order".
5. Frontend calls `POST /ui/shoppingcart/carts/{id}/purchase` with `{ promo_code: "SUMMER20" }` in the request body.
6. Backend `purchase_cart()`:
   a. Lists items, calculates original total.
   b. Resolves `creator_user_id` from cart items (all items must be from same creator for v1).
   c. Re-validates the promo code (may have expired or maxed out since step 2).
   d. If invalid: raises `HTTPException(422, detail=...)`.
   e. Calculates discount: `final_total = max(0, total_cents - discount_cents)`.
   f. Creates commerce order with discounted total.
   g. Updates cart to PURCHASED with `promo_code_id`, `discount_cents`, `original_total_cents`.
   h. Calls `redeem_promo_code()` to increment usage and record redemption.
7. Frontend shows order confirmation with discounted amount.

### 4.3 Creator Scope Handling

A cart may contain items from multiple creators. Promo codes are creator-scoped (`creator_user_id`). Two approaches:

**Option A (v1, recommended)**: Only allow promo codes when all cart items belong to the same creator. Return `422` error if cart has mixed creators: "Promo codes require all items from the same creator."

**Option B (v2, future)**: Apply discount only to items from the matching creator, leaving other items at full price. Requires per-item discount allocation logic.

Helper function for v1:
```python
def _resolve_cart_creator(items: List[Dict[str, Any]]) -> Optional[str]:
    """Return the single creator_user_id if all items are from the same creator.
    Returns None if mixed or no creator info."""
    creators = set()
    for item in items:
        cid = item.get("creator_user_id") or item.get("seller_id")
        if cid:
            creators.add(cid)
    if len(creators) == 1:
        return creators.pop()
    return None
```

---

## 5. API Contract Changes

### 5.1 Updated Purchase Endpoint

**Path**: `POST /ui/shoppingcart/carts/{cart_id}/purchase`

The existing endpoint currently accepts no body. Add an optional request body:

**Request model** (new Pydantic model in `app/models.py`):

```python
class CartPurchaseIn(BaseModel):
    promo_code: Optional[str] = None       # Human-readable code string
    promo_code_id: Optional[str] = None    # Direct code ID (alternative)
```

Both fields are optional. If `promo_code` is provided (the human-readable string), the backend resolves it to a `code_id` via `get_promo_code_by_string()`. If `promo_code_id` is provided directly, it is used. If neither is provided, purchase proceeds without discount.

**Updated Response (200)**:

```json
{
  "cart_id": "abc123def456",
  "order_id": "ord_xyz789",
  "purchased_at": "2026-05-27T15:00:00+00:00",
  "purchased_total_cents": 4250,
  "original_total_cents": 5000,
  "discount_cents": 750,
  "promo_code_id": "pc_abc123def456",
  "promo_discount_type": "percentage",
  "currency": "USD",
  "buyer": { "display_name": "Alice", "email": "alice@test.local" },
  "purchase_txn_id": "txn_..."
}
```

New fields: `original_total_cents`, `discount_cents`, `promo_code_id`, `promo_discount_type`. These are `0`/`null` when no promo is applied.

**Example curl (with promo)**:
```bash
curl -X POST -b "ui_session=...; ui_access_token=..." \
  -H "x-csrf-token: ..." -H "Content-Type: application/json" \
  -d '{"promo_code": "SUMMER20"}' \
  http://localhost:8000/ui/shoppingcart/carts/abc123/purchase
```

**Example curl (without promo, backward compatible)**:
```bash
curl -X POST -b "ui_session=...; ui_access_token=..." \
  -H "x-csrf-token: ..." \
  http://localhost:8000/ui/shoppingcart/carts/abc123/purchase
```

**Error responses**:

| Status | Body | Condition |
|--------|------|-----------|
| 200 | Success (with or without promo) | Normal purchase |
| 400 | `{"detail": "Promo codes require all items from the same creator"}` | Mixed-creator cart with promo |
| 409 | `{"detail": "Cart is not open"}` | Cart already purchased |
| 422 | `{"detail": "This code has expired"}` | Promo expired between validate and purchase |
| 422 | `{"detail": "This code has been fully redeemed"}` | Promo maxed out between validate and purchase |
| 422 | `{"detail": "This code is not valid for this creator"}` | Creator mismatch |

### 5.2 Validate Endpoint (Existing, No Changes)

**Path**: `POST /ui/promo-codes/validate`

Already exists and works correctly. The checkout page calls this for real-time validation.

**Request body**:
```json
{
  "code": "SUMMER20",
  "checkout_type": "shop",
  "item_price_cents": 5000,
  "creator_user_id": "seller@test.local"
}
```

**Response (200)**:
```json
{
  "valid": true,
  "code_id": "pc_abc123",
  "discount_type": "percentage",
  "discount_cents": 750,
  "final_price_cents": 4250,
  "free_trial_days": 0,
  "message": null
}
```

---

## 6. Implementation Plan

### Phase 1: Backend Changes

#### 6.1 Pydantic Model (`app/models.py`)

Add after existing cart models:

```python
# -- Cart Purchase with Promo (SHOP-002) --

class CartPurchaseIn(BaseModel):
    promo_code: Optional[str] = None
    promo_code_id: Optional[str] = None
```

#### 6.2 Update `purchase_cart()` (`app/services/shoppingcart.py`)

Update function signature (line 428):

```python
def purchase_cart(
    user_sub: str,
    cart_id: str,
    *,
    idempotency_key: str | None = None,
    promo_code: str | None = None,
    promo_code_id: str | None = None,
) -> Dict[str, Any]:
```

Add promo validation between item listing (line 443) and order creation (line 450):

```python
    items = list_items(user_sub, cart_id)
    total_cents = sum(item.get("line_total_cents", 0) for item in items)
    
    # SHOP-002: Promo code validation and discount
    discount_cents = 0
    resolved_promo = None
    original_total_cents = total_cents
    
    if promo_code or promo_code_id:
        from app.services.promo_codes import validate_promo_code, get_promo_code_by_string
        
        creator_id = _resolve_cart_creator(items)
        if not creator_id:
            raise HTTPException(400, "Promo codes require all items from the same creator")
        
        code_str = promo_code
        if not code_str and promo_code_id:
            promo_item = _get_promo_by_id(promo_code_id)
            code_str = promo_item.get("code") if promo_item else None
        
        if code_str:
            result = validate_promo_code(
                code=code_str,
                user_id=user_sub,
                checkout_type="shop",
                item_price_cents=total_cents,
                creator_user_id=creator_id,
            )
            if not result["valid"]:
                raise HTTPException(422, result["message"] or "Invalid promo code")
            discount_cents = result["discount_cents"]
            resolved_promo = result
    
    final_total = max(0, total_cents - discount_cents)
```

Use `final_total` instead of `total_cents` for order creation:

```python
    line_items = _commercial_line_items_from_cart_items(items, cart_id)
    order = commerce_order_service.create_order_from_line_items(
        user_id=user_sub,
        source_system="shopping_cart",
        correlation_id=canonical_idempotency_key,
        line_items=line_items,
        metadata={
            "cart_id": cart_id,
            "idempotency_key": canonical_idempotency_key,
            "promo_code_id": resolved_promo["code_id"] if resolved_promo else None,
            "discount_cents": discount_cents,
            "original_total_cents": original_total_cents,
        },
    )
```

After successful purchase, redeem the code:

```python
    # SHOP-002: Redeem promo code on successful purchase
    if resolved_promo and resolved_promo.get("code_id"):
        try:
            from app.services.promo_codes import redeem_promo_code
            redeem_promo_code(
                code_id=resolved_promo["code_id"],
                user_id=user_sub,
                original_price_cents=original_total_cents,
                final_price_cents=final_total,
                checkout_type="shop",
                checkout_item_id=cart_id,
            )
        except Exception:
            logger.warning("promo_redemption_failed", extra={
                "code_id": resolved_promo["code_id"],
                "cart_id": cart_id,
            })
```

Store promo info on the cart record:

```python
    if resolved_promo:
        update_expr += ", promo_code_id = :promo_id, discount_cents = :discount, original_total_cents = :orig_total"
        expr_values[":promo_id"] = resolved_promo["code_id"]
        expr_values[":discount"] = discount_cents
        expr_values[":orig_total"] = original_total_cents
```

Update the return dict:

```python
    return {
        "cart_id": cart_id,
        "order_id": order_id,
        "purchased_at": now,
        "purchased_total_cents": final_total,
        "original_total_cents": original_total_cents,
        "discount_cents": discount_cents,
        "promo_code_id": resolved_promo["code_id"] if resolved_promo else None,
        "promo_discount_type": resolved_promo["discount_type"] if resolved_promo else None,
        "currency": cart.get("currency", "USD"),
        "buyer": buyer,
        "purchase_txn_id": txn_id,
    }
```

#### 6.3 Update Cart Purchase Route

**File: `app/routers/shoppingcart.py`** (wherever the purchase route is defined)

Update the route handler to accept the optional body:

```python
from app.models import CartPurchaseIn

@router.post("/carts/{cart_id}/purchase")
def purchase(cart_id: str, body: CartPurchaseIn = CartPurchaseIn(), session=Depends(require_ui_session)):
    user_sub = session["user_sub"]
    result = purchase_cart(
        user_sub, cart_id,
        promo_code=body.promo_code,
        promo_code_id=body.promo_code_id,
    )
    return result
```

Using `CartPurchaseIn = CartPurchaseIn()` as default ensures backward compatibility: requests without a body still work (all fields default to None).

### Phase 2: Frontend Changes

#### 6.4 Update `purchaseCart` API wrapper

**File: `frontend/src/api/endpoints/cart.ts`**

```typescript
export const purchaseCart = (
  cartId: string,
  body?: { promo_code?: string; promo_code_id?: string },
) =>
  api.post<CartPurchase>(
    `/ui/shoppingcart/carts/${cartId}/purchase`,
    body ?? {},
  );
```

#### 6.5 Add TypeScript Types

**File: `frontend/src/api/types.ts`**

Ensure `PromoValidateOut` interface exists:

```typescript
export interface PromoValidateOut {
  valid: boolean;
  code_id: string | null;
  discount_type: string | null;
  discount_cents: number;
  final_price_cents: number;
  free_trial_days: number;
  message: string | null;
}
```

Update `CartPurchase` type to include promo fields:

```typescript
export interface CartPurchase {
  cart_id: string;
  order_id: string;
  purchased_at: string;
  purchased_total_cents: number;
  original_total_cents?: number;
  discount_cents?: number;
  promo_code_id?: string;
  promo_discount_type?: string;
  currency: string;
  buyer?: Record<string, unknown>;
  purchase_txn_id?: string;
}
```

#### 6.6 Update Checkout Page (`frontend/src/pages/shop/Checkout.tsx`)

**Add state variables** (after line 44):

```typescript
const [promoCode, setPromoCode] = useState("");
const [promoResult, setPromoResult] = useState<PromoValidateOut | null>(null);
const [promoError, setPromoError] = useState("");
const [promoLoading, setPromoLoading] = useState(false);
const [promoExpanded, setPromoExpanded] = useState(false);
```

**Add imports**:

```typescript
import { validatePromoCode } from "@/api/endpoints/promoCodes";
import { Tag, Loader2, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import type { PromoValidateOut } from "@/api/types";
```

**Add promo validation handler**:

```typescript
const handleApplyPromo = async () => {
  if (!promoCode.trim()) return;
  setPromoLoading(true);
  setPromoError("");
  try {
    const result = await validatePromoCode({
      code: promoCode.trim(),
      checkout_type: "shop",
      item_price_cents: total?.total_cents ?? 0,
      creator_user_id: creatorId ?? "",
    });
    if (result.valid) {
      setPromoResult(result);
      setPromoError("");
    } else {
      setPromoError(result.message ?? "Invalid code");
      setPromoResult(null);
    }
  } catch {
    setPromoError("Failed to validate code");
    setPromoResult(null);
  } finally {
    setPromoLoading(false);
  }
};

const handleRemovePromo = () => {
  setPromoResult(null);
  setPromoCode("");
  setPromoError("");
};
```

**Derive `creatorId` from cart items** (helper at top of component):

```typescript
const creatorId = useMemo(() => {
  const ids = new Set(items.map((i) => i.creator_user_id ?? i.seller_id).filter(Boolean));
  return ids.size === 1 ? [...ids][0] : undefined;
}, [items]);
```

**Add promo code UI** (between Order Summary card and Payment Method card, around line 193):

```tsx
{/* Promo Code -- SHOP-002 */}
<Card>
  <CardContent className="py-4">
    <button
      className="flex items-center gap-2 text-sm text-primary hover:underline"
      onClick={() => setPromoExpanded(!promoExpanded)}
    >
      <Tag className="h-4 w-4" />
      Have a promo code?
    </button>
    {promoExpanded && (
      <div className="mt-3 space-y-2">
        <div className="flex gap-2">
          <Input
            placeholder="Enter code"
            value={promoCode}
            onChange={(e) => setPromoCode(e.target.value.toUpperCase())}
            disabled={!!promoResult}
            onKeyDown={(e) => e.key === "Enter" && !promoResult && handleApplyPromo()}
          />
          {promoResult ? (
            <Button variant="outline" size="sm" onClick={handleRemovePromo}>
              <X className="h-4 w-4" />
            </Button>
          ) : (
            <Button onClick={handleApplyPromo} disabled={promoLoading || !promoCode.trim()}>
              {promoLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : "Apply"}
            </Button>
          )}
        </div>
        {promoError && <p className="text-sm text-destructive">{promoError}</p>}
        {promoResult && (
          <p className="text-sm text-green-600 font-medium">
            Code applied: -{formatCents(promoResult.discount_cents)} discount
          </p>
        )}
      </div>
    )}
  </CardContent>
</Card>
```

**Update Order Summary** to show discount line item (after the items map, around line 184):

```tsx
<Separator />
{promoResult && (
  <div className="flex items-center justify-between text-sm text-green-600">
    <span>Promo discount ({promoCode})</span>
    <span>-{formatCents(promoResult.discount_cents)}</span>
  </div>
)}
<div className="flex items-center justify-between font-semibold">
  <span>Total</span>
  <span className="text-lg">
    {total
      ? formatCents(
          promoResult ? promoResult.final_price_cents : total.total_cents,
          total.currency,
        )
      : "..."}
  </span>
</div>
```

**Update purchase mutation** to pass promo code:

```typescript
const purchaseMutation = useMutation({
  mutationFn: () =>
    purchaseCart(cartId, promoResult ? { promo_code: promoCode } : undefined),
  onSuccess: (data) => {
    queryClient.invalidateQueries({ queryKey: ["carts"] });
    queryClient.invalidateQueries({ queryKey: ["cart-items", cartId] });
    setPurchaseResult("success");
    setOrderId(data.order_id);
    setConfirmOpen(false);
    toast.success("Order placed successfully!");
  },
  onError: (err: AxiosError<{ detail: string }>) => {
    const detail = err.response?.data?.detail;
    if (err.response?.status === 422) {
      // Promo code became invalid between validate and purchase
      setPromoError(detail || "Promo code is no longer valid");
      setPromoResult(null);
      toast.error(detail || "Promo code error -- please try again");
    } else {
      setPurchaseResult("error");
      toast.error("Purchase failed");
    }
    setConfirmOpen(false);
  },
});
```

**Update "Place Order" button** to show discounted total:

```tsx
<Button
  size="lg"
  className="w-full"
  disabled={!selectedMethodId || items.length === 0}
  onClick={() => setConfirmOpen(true)}
>
  Place Order
  {total
    ? ` — ${formatCents(
        promoResult ? promoResult.final_price_cents : total.total_cents,
        total.currency,
      )}`
    : ""}
</Button>
```

---

## 7. Security & Privacy Considerations

### 7.1 Double Validation (Critical)

The backend MUST re-validate the promo code during `purchase_cart()`, not rely on the frontend's earlier validation. Between the user clicking "Apply" and clicking "Place Order":
- The code may expire.
- Another user may use the last remaining use.
- The code may be deactivated by the seller.

The re-validation in `purchase_cart()` prevents these race conditions.

### 7.2 CSRF Protection

The purchase endpoint already requires CSRF tokens for cookie-auth requests. The promo code is submitted in the same request body, inheriting the CSRF protection.

### 7.3 Promo Code Brute Force

The existing `POST /ui/promo-codes/validate` endpoint has no dedicated rate limiting. A malicious user could enumerate valid codes by trying random strings. Mitigations:
- Add per-user rate limit: 10 validation attempts per minute.
- Code pattern is `^[A-Za-z0-9_-]{3,30}$` (restricted character set).
- Invalid code responses are generic ("Code not found") to prevent information leakage.

### 7.4 Discount Manipulation

The discount is calculated server-side using `_calculate_discount()`. The frontend displays the discount for UX purposes but the actual deduction is computed in `purchase_cart()`. A user cannot manipulate the discount amount by modifying client-side state.

---

## 8. Testing Strategy

### 8.1 Unit Tests (pytest)

**File**: `tests/test_cart_promo.py`

| # | Test Function | Assertion |
|---|--------------|-----------|
| 1 | `test_purchase_with_valid_percentage_promo` | 20% code on $50 cart -> `purchased_total_cents = 4000`, `discount_cents = 1000` |
| 2 | `test_purchase_with_valid_fixed_amount_promo` | $10 off code on $50 cart -> `purchased_total_cents = 4000`, `discount_cents = 1000` |
| 3 | `test_purchase_with_invalid_promo_returns_422` | Expired code -> HTTPException 422 |
| 4 | `test_purchase_with_expired_promo_returns_422` | Code expired between validate and purchase -> 422 |
| 5 | `test_purchase_with_promo_redeems_code` | After purchase, `current_uses` incremented by 1 |
| 6 | `test_purchase_without_promo_works_unchanged` | No promo_code param -> purchase works as before, no discount |
| 7 | `test_purchase_with_wrong_creator_promo_returns_422` | Code for creator A used with creator B items -> 422 |
| 8 | `test_purchase_stores_discount_on_cart_record` | After purchase, cart DDB item has `promo_code_id`, `discount_cents`, `original_total_cents` |
| 9 | `test_purchase_with_mixed_creator_cart_returns_400` | Cart with items from 2 creators + promo -> 400 |
| 10 | `test_fixed_amount_caps_at_cart_total` | $100 off code on $50 cart -> `discount_cents = 5000`, `purchased_total_cents = 0` |
| 11 | `test_percentage_100_gives_free` | 100% code -> `discount_cents = total_cents`, `purchased_total_cents = 0` |
| 12 | `test_redeem_failure_does_not_block_purchase` | Redemption write fails -> purchase still succeeds (best-effort redemption) |

### 8.2 E2E Tests

**Test File:** `frontend/e2e/checkout-promo.spec.ts`

**Section 1: Promo Validation API (5 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 1.1 | Valid percentage code returns discount | POST validate; `valid: true`, `discount_type: "percentage"`, `discount_cents > 0` |
| 1.2 | Expired code returns invalid with message | POST validate; `valid: false`, `message` contains "expired" |
| 1.3 | Code with wrong checkout_type returns invalid | POST validate with `checkout_type: "subscription"`; `valid: false` |
| 1.4 | Code at max uses returns invalid | Create code with `max_uses: 1`, redeem once; validate again; `valid: false`, `message` contains "fully redeemed" |
| 1.5 | Fixed amount code caps discount at cart total | Code for $100 off on $50 cart; `discount_cents = 5000`, `final_price_cents = 0` |

**Section 2: Checkout with Promo (5 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 2.1 | Apply valid code shows discount in UI | Navigate to checkout; expand promo; enter code; click Apply; green discount text visible |
| 2.2 | Apply invalid code shows error in UI | Enter expired code; click Apply; red error text visible |
| 2.3 | Remove applied code reverts total | Apply code; click Remove; total reverts to original; promo input re-enabled |
| 2.4 | Place order with promo completes successfully | Apply code; click Place Order; confirm; success screen with order ID |
| 2.5 | Promo code usage incremented after purchase | After purchase; GET promo stats shows `current_uses` incremented |

**Section 3: Checkout UI (3 tests)**

| # | Test Title | Assertion |
|---|-----------|-----------|
| 3.1 | "Have a promo code?" section is expandable | Click text; input field appears |
| 3.2 | "Place Order" button shows discounted total | Apply valid code; button text includes discounted amount |
| 3.3 | Promo input disabled after code applied | Apply code; input has `disabled` attribute; Remove button visible |

### 8.3 Edge Cases

- Apply code, navigate away, return to checkout: promo state is lost (local state only).
- Apply code for cart with $0 items (edge case for percentage discount).
- Promo code with `min_purchase_cents > cart_total`: validation fails with "Minimum purchase of $X.XX required".
- Very long promo code (30 chars max per `CODE_PATTERN` regex).
- Code with special characters (rejected by `CODE_PATTERN`).
- Two users racing to use the last remaining redemption of a code.
- Purchase timeout: promo validated but purchase hangs; user retries.

---

## 9. Migration & Rollback

### 9.1 Backward Compatibility

The promo parameter in `purchase_cart()` is optional. Existing calls without a promo code (including the current frontend, other clients, and E2E tests) continue to work identically. The `CartPurchaseIn` model defaults all fields to `None`.

The cart record gains new optional fields (`promo_code_id`, `discount_cents`, `original_total_cents`) that do not affect existing records. `_cart_from_item` can ignore fields that do not exist.

### 9.2 Feature Flag

No explicit feature flag needed. The promo UI is additive (a new expandable section in the checkout page). To "disable" promo at checkout:
- Remove or hide the "Have a promo code?" section in `Checkout.tsx`.
- The backend promo parameter is optional and backward compatible.

### 9.3 Rollout Steps

1. Deploy backend changes to `purchase_cart()` and the router.
2. Deploy `CartPurchaseIn` model to `app/models.py`.
3. Deploy frontend changes to `Checkout.tsx` and `cart.ts`.
4. Verify with E2E tests.
5. Monitor for 422 errors from promo race conditions (expected to be very rare).

### 9.4 Rollback

1. Frontend: remove promo-related code from `Checkout.tsx`. Purchase mutation reverts to calling `purchaseCart(cartId)` without body.
2. Backend: `purchase_cart()` ignores `promo_code`/`promo_code_id` params (they default to None, no discount is applied). No schema rollback needed.

---

## 10. Performance Considerations

### 10.1 Validation Latency

The `validate_promo_code()` function performs:
1. `get_promo_code_by_string(code)` -- GSI query on promo_codes table (~5ms).
2. Expiry, max uses, per-user checks -- single-item reads (~3ms each).
3. Discount calculation -- in-memory, ~0ms.

Total: ~15ms. Acceptable for a user-triggered action (clicking "Apply").

### 10.2 Purchase with Promo

The `purchase_cart()` function adds:
1. `_resolve_cart_creator(items)` -- iterates items in-memory (~0ms).
2. `validate_promo_code()` -- ~15ms (re-validation).
3. `redeem_promo_code()` -- conditional update + put_item (~10ms).

Total additional latency: ~25ms. Not user-perceptible.

### 10.3 DDB Capacity Impact

- Promo validation: 1-3 RCU per validation request.
- Promo redemption: 1 WCU (conditional update) + 1 WCU (REDEEM item).
- No additional DDB reads for the purchase flow beyond the re-validation.

---

## 11. Acceptance Criteria

1. Checkout page has an expandable "Have a promo code?" section with text input and "Apply" button.
2. Entering a valid code displays the discount as a green line item in the order summary.
3. Entering an invalid, expired, or maxed-out code displays a clear error message below the input.
4. The "Place Order" button and total display the discounted amount when a code is applied.
5. Applied codes can be removed via a "Remove" button, reverting the total to the original amount.
6. `purchase_cart()` re-validates the promo code server-side before applying the discount.
7. Successful purchase calls `redeem_promo_code()`, atomically incrementing `current_uses`.
8. Cart DDB record stores `promo_code_id`, `discount_cents`, and `original_total_cents` after purchase.
9. Purchase without a promo code works identically to the current behavior (full backward compatibility).
10. Mixed-creator carts with a promo code return a clear 400 error.
11. All 12 unit tests pass.
12. All 13 E2E tests pass.

---

## 12. Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `tests/test_cart_promo.py` | Unit tests for promo integration in purchase | ~200 |
| `frontend/e2e/checkout-promo.spec.ts` | E2E tests for checkout promo flow | ~250 |

## 13. Files to Modify

| File | Change | Lines Changed |
|------|--------|---------------|
| `app/services/shoppingcart.py` | Add `promo_code`/`promo_code_id` params to `purchase_cart()`; validate, apply discount, redeem, store on cart record | ~40 new + ~15 modified |
| `app/models.py` | Add `CartPurchaseIn` model with optional `promo_code`, `promo_code_id` | +4 lines |
| `app/routers/shoppingcart.py` | Update purchase route to accept `CartPurchaseIn` body | ~5 lines modified |
| `frontend/src/pages/shop/Checkout.tsx` | Add promo state, validation handler, promo input UI, discount display, update purchase mutation | ~80 new lines |
| `frontend/src/api/endpoints/cart.ts` | Update `purchaseCart` to accept optional body with `promo_code` | ~3 lines modified |
| `frontend/src/api/types.ts` | Add `PromoValidateOut` interface (if not present), update `CartPurchase` with promo fields | ~10 lines |

---

## 14. Dependencies

- **Promo code system**: `app/services/promo_codes.py` and `app/routers/promo_codes.py` -- must be deployed and functional. Already operational.
- **Frontend promo API**: `frontend/src/api/endpoints/promoCodes.ts` -- `validatePromoCode` and `redeemPromoCode` wrappers already exist and are tested.
- **Shopping cart**: `app/services/shoppingcart.py` -- must be deployed. Already operational.
- **Commerce order service**: `commerce_order_service.create_order_from_line_items` -- used by `purchase_cart()`. Already operational.

---

## 15. Open Questions

1. **Promo code auto-discovery**: Should the checkout page automatically check if the user has any available promo codes and display them? This would require a new endpoint: `GET /ui/promo-codes/available?checkout_type=shop&creator_id=...`. Defer to v2.
2. **Multiple promo codes**: Should users be able to stack multiple codes on a single purchase? Current design: one code per purchase. Stacking is complex (discount order matters) and deferred to v2.
3. **Free trial codes at checkout**: Free trial codes (`discount_type: "free_trial"`) are only valid for subscriptions. Should the checkout page handle this gracefully, or should the validate endpoint reject it? Current design: validate endpoint returns `valid: false` with "Free trial codes are only valid for subscriptions" -- this is correct behavior.
4. **Creator ID derivation**: How should `creator_user_id` be derived from cart items? Current plan: use `item.creator_user_id` or `item.seller_id` field on cart items. If this field is not populated on existing items, we need to look up the catalog item's creator. Verify field availability during implementation.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Checkout.tsx (now 420 lines, was 266) | `frontend/src/pages/shop/Checkout.tsx` | 1-420 | VERIFIED (line drift — file grew) |
| purchaseCart wrapper accepts no body | `frontend/src/api/endpoints/cart.ts` | 43 | VERIFIED (was 42; line drift) |
| validate_promo_code exists with full validation chain | `app/services/promo_codes.py` | 239 | VERIFIED |
| _calculate_discount handles percentage, fixed, free_trial | `app/services/promo_codes.py` | 335 | VERIFIED |
| redeem_promo_code increments current_uses atomically | `app/services/promo_codes.py` | 357+ | VERIFIED |
| create_promo_code with all parameters | `app/services/promo_codes.py` | 85 | VERIFIED |
| CODE_PATTERN = ^[A-Za-z0-9_-]{3,30}$ | `app/services/promo_codes.py` | 24 | VERIFIED |
| VALID_CHECKOUT_TYPES = subscription, vod, shop | `app/services/promo_codes.py` | 25 | VERIFIED |
| Frontend validatePromoCode wrapper | `frontend/src/api/endpoints/promoCodes.ts` | 40-45 | VERIFIED |
| Frontend redeemPromoCode wrapper | `frontend/src/api/endpoints/promoCodes.ts` | 49-55 | VERIFIED |
| PromoCodeOut type defined | `frontend/src/api/types.ts` | 3135-3152 | VERIFIED (may have drifted) |
| Promo validate endpoint | `app/routers/promo_codes.py` | 141 | VERIFIED (was 140; line drift) |
| Promo redeem endpoint | `app/routers/promo_codes.py` | 161 | VERIFIED (was 160; line drift) |
| purchase_cart signature (no promo param) | `app/services/shoppingcart.py` | 469 | VERIFIED (was 428; line drift) |
| purchase_cart total + order logic | `app/services/shoppingcart.py` | 469+ | VERIFIED (exact sub-lines drifted ~40 lines) |


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_promo_checkout.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_shop_002_create` | Create primary entity; 201 |
| 2 | `test_shop_002_read` | Read back entity; correct fields |
| 3 | `test_shop_002_update` | Update entity; 200; changes reflected |
| 4 | `test_shop_002_delete` | Delete entity; 200/204 |
| 5 | `test_shop_002_auth_required` | No auth; 401 |
| 6 | `test_shop_002_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/promo-checkout.spec.ts` -- 12 tests

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
| PROMO-001 | Required | Promo code validation API from PROMO-001 |
| SHOP-001 | Optional | Stock validation during checkout |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | No downstream dependents identified |

### Merge Strategy

**Sequential** -- Requires PROMO-001 merged for promo validation endpoints.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/promo-checkout.spec.ts`
