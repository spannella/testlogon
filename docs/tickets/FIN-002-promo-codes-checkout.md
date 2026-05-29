# FIN-002: Promo Codes in Checkout UI

**Ticket**: FIN-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 6-8 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-002 completes the promo code integration across all checkout surfaces. The promo code backend (`app/services/promo_codes.py`) already supports creation, validation, discount calculation, and redemption -- and the shop `Checkout.tsx` has a basic promo code input with validate/apply flow. However, promo codes are not available in subscription checkout, tip flows, or unlock flows. The validation UI lacks visual feedback for discount types (percentage, fixed, free shipping, buy-X-get-Y), and there is no "applied discount" line item in the order summary. This ticket extends promo code support to all payment surfaces, adds a polished discount preview UI, and enforces all validation rules (expiry, usage limits, minimum order, eligible products) with clear error messages.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Consumer | As a buyer, I want to enter a promo code during subscription checkout. | Promo input field appears on subscription purchase page; valid code shows discount preview. |
| Consumer | As a buyer, I want to see the exact discount amount before completing purchase. | Applied promo shows: original price, discount line (with type label), and final price. |
| Consumer | As a buyer, I want clear error messages when a promo code is invalid. | Error messages: "Code expired", "Already used", "Minimum order $X required", "Not valid for this product". |
| Consumer | As a buyer, I want to remove an applied promo code. | "Remove" button clears the promo and recalculates total to original price. |
| Creator | As a creator, I want my promo codes to work across shop, subscriptions, and tips. | `checkout_type` parameter supports "shop", "subscription", "tip", "unlock". |
| Creator | As a creator, I want buy-X-get-Y promos to display correctly. | UI shows "Buy 2 Get 1 Free" with the free item clearly indicated in the order summary. |
| Admin | As an admin, I want to see promo code usage stats. | Existing `get_promo_stats` endpoint returns redemption count and revenue impact. |

### 1.3 Why This Is Needed

The promo code backend is fully built (`create_promo_code`, `validate_promo_code`, `redeem_promo_code`, `_calculate_discount`) but only partially surfaced in the shop checkout UI. Subscription purchases, tips, and unlocks have no promo code entry point. The existing shop checkout promo input works for basic validation but lacks visual polish: no discount breakdown, no type-specific messaging, and error messages are generic. Completing this integration increases promo code utility for creators and conversion rates for buyers.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Promo code service | `app/services/promo_codes.py` | Full CRUD: `create_promo_code`, `validate_promo_code`, `redeem_promo_code`, `_calculate_discount`, `get_promo_stats` |
| Promo code validation | `app/services/promo_codes.py:239` | `validate_promo_code(code, user_id, checkout_type, item_price_cents, creator_user_id)` |
<!-- VERIFIED: app/services/promo_codes.py:239 — validate_promo_code; :335 — _calculate_discount; :357 — redeem_promo_code; :85 — create_promo_code; :421 — get_promo_stats -->
| Discount calculation | `app/services/promo_codes.py:335` | `_calculate_discount(promo, item_price_cents)` -- returns `(discount_cents, final_price, trial_days)` |
| Promo code redemption | `app/services/promo_codes.py:357` | `redeem_promo_code(code_id, user_id, ...)` -- writes redemption record, increments usage count |
| Shop checkout UI | `frontend/src/pages/shop/Checkout.tsx:53-131` | Has promo code state, `handleApplyPromo`, `handleRemovePromo`, `effectiveTotal`; calls `validatePromoCode` |
| Promo API wrapper | `frontend/src/api/endpoints/promoCodes.ts` | `validatePromoCode(params)` endpoint wrapper |
| Cart purchase API | `app/routers/shoppingcart.py:169` | `purchase_cart` accepts `promo_code` and `promo_code_id` in `CartPurchaseIn` body |
| Promo types | `app/models.py` | `PromoValidateOut` includes `valid`, `message`, `discount_cents`, `final_price_cents`, `discount_type`, `trial_days` |
| Subscription checkout | `frontend/src/pages/subscriptions/SubscribePage.tsx` | No promo code input currently |

### 2.2 Gaps

1. **Subscription checkout has no promo input** -- `SubscribePage.tsx` handles plan selection and payment but lacks a promo code field.
2. **Tip and unlock flows have no promo support** -- `ComposeBar.tsx` tip panel and `MessageBubble.tsx` unlock button do not accept promo codes.
3. **No discount breakdown in order summary** -- the shop checkout shows `effectiveTotal` but no visual line showing original price, discount type, and savings amount.
4. **Generic error messages** -- validation errors show "Invalid code" without specifying the reason (expired, usage limit, min order, product mismatch).
5. **No buy-X-get-Y visual feedback** -- the backend supports `buy_x_get_y` discount type but the UI has no rendering for it.
6. **No promo code on subscription server** -- `app/routers/subscription_server.py` does not accept or validate promo codes on subscription creation.
7. **Free shipping promo has no effect** -- `_calculate_discount` handles `free_shipping` but cart purchase does not apply it to shipping costs.

---

## 3. Technical Design

### 3.1 Architecture & Data Flow

```
                    Promo Code Validation Flow
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ PromoCodeInput │────>│ POST /ui/promo-    │────>│  DynamoDB     │
  │ (shared comp)  │     │  codes/validate    │     │  promo_codes  │
  │                │     │  (promo_codes.py)   │     │  table        │
  │ code + type +  │     │                    │     │               │
  │ price          │     │ 1. find code       │     │ PK=CODE#code  │
  │                │     │ 2. check active    │     │ SK=META       │
  │                │     │ 3. check expiry    │     │               │
  │                │     │ 4. check limits    │     │ Redemptions:  │
  │                │     │ 5. check min_order │     │ PK=CODE#code  │
  │                │     │ 6. calc discount   │     │ SK=USER#sub   │
  └───────────────┘     └────────────────────┘     └──────────────┘
        │                        │
        v                        v
  ┌───────────────┐     ┌────────────────────┐
  │ Discount Card  │     │ PromoValidateOut   │
  │ (UI feedback)  │     │ {valid, discount_  │
  │                │     │  cents, final_     │
  │ Badge: "20%    │     │  price, error_code,│
  │  OFF"          │     │  discount_type...} │
  │ Original: $25  │     │                    │
  │ Discount: -$5  │     │                    │
  │ Total: $20     │     │                    │
  └───────────────┘     └────────────────────┘

                    Promo Code Redemption Flow
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ Checkout/Tip/  │────>│ Purchase endpoint  │────>│ 1. Re-validate│
  │ Subscribe/     │     │ (various routers)  │     │    promo code │
  │ Unlock button  │     │                    │     │ 2. Apply disc.│
  │                │     │ promo_code param   │     │ 3. Charge     │
  │ (sends promo_  │     │ in request body    │     │    amount     │
  │  code with     │     │                    │     │ 4. redeem_    │
  │  payment)      │     │                    │     │    promo_code │
  └───────────────┘     └────────────────────┘     └──────────────┘
```

### 3.2 Backend Changes

No new DynamoDB tables. The existing `promo_codes` table and service handle all storage and validation. Changes are to the validation and redemption hooks in other services.

#### 3.2.1 Extend `validate_promo_code` Response

Add detailed error reasons to `PromoValidateOut`:

```python
class PromoValidateOut(BaseModel):
    valid: bool
    message: str = ""
    error_code: Optional[str] = None  # NEW: "expired", "usage_limit", "min_order", "product_mismatch", "already_used"
    discount_cents: int = 0
    final_price_cents: int = 0
    discount_type: str = ""  # "percentage", "fixed", "free_shipping", "buy_x_get_y"
    discount_pct: int = 0  # NEW: percentage value for display (e.g., 20 for "20% off")
    trial_days: int = 0
    original_price_cents: int = 0  # NEW: price before discount for display
    buy_x: int = 0  # NEW: for buy_x_get_y display
    get_y: int = 0  # NEW: for buy_x_get_y display
    free_item_description: str = ""  # NEW: "1 item free" for buy_x_get_y
```

#### 3.2.2 Subscription Promo Code Support

**Modify**: `app/routers/subscription_server.py`

Add optional `promo_code` field to `SubscribeIn` model. On subscription creation:
1. If `promo_code` is present, call `validate_promo_code(code, user_id, checkout_type="subscription", item_price_cents=plan_price)`.
2. If valid, apply discount to first billing cycle (or apply `trial_days` for free trial promos).
3. Call `redeem_promo_code` after successful subscription creation.
4. Store `promo_code_id` on the subscription record for audit trail.

**New model fields**:

```python
class SubscribeIn(BaseModel):
    plan_id: str
    payment_method_id: Optional[str] = None
    promo_code: Optional[str] = None  # NEW
```

#### 3.2.3 Tip/Unlock Promo Code Support

**Modify**: `app/routers/messaging.py` and `app/routers/newsfeed.py`

Add optional `promo_code` to tip and unlock request bodies. Promo codes for tips/unlocks are validated with `checkout_type="tip"` or `checkout_type="unlock"`. Discount is applied to the tip/unlock amount before processing.

```python
class TipMessageIn(BaseModel):
    amount_cents: int
    payment_method_id: str
    promo_code: Optional[str] = None  # NEW

class UnlockMessageIn(BaseModel):
    payment_method_id: str
    promo_code: Optional[str] = None  # NEW
```

#### 3.2.4 Detailed Error Reasons

**Modify**: `app/services/promo_codes.py:validate_promo_code`

Map validation failures to specific `error_code` values:

| Validation Failure | `error_code` | `message` |
|-------------------|-------------|-----------|
| Code not found | `not_found` | "Promo code not found" |
| Code deactivated | `deactivated` | "This promo code is no longer active" |
| Past `expires_at` | `expired` | "This promo code has expired" |
| `max_uses` reached | `usage_limit` | "This promo code has reached its usage limit" |
| `max_uses_per_user` reached | `already_used` | "You have already used this promo code" |
| Below `min_order_cents` | `min_order` | "Minimum order of ${min/100:.2f} required" |
| Product not eligible | `product_mismatch` | "This code is not valid for the selected items" |
| Wrong `checkout_type` | `checkout_type_mismatch` | "This code cannot be used for this purchase type" |

### 3.3 Detailed DynamoDB Access Patterns

| Access Pattern | Table | Key Condition | Filter | Use Case |
|---------------|-------|---------------|--------|----------|
| Validate promo code | `promo_codes` | PK=`CODE#{code_upper}`, SK=`META` | -- | Lookup promo code by normalized code string |
| Check user redemption | `promo_codes` | PK=`CODE#{code_upper}`, SK=`USER#{user_id}` | -- | Check if user already redeemed this code |
| Count total redemptions | `promo_codes` | PK=`CODE#{code_upper}`, SK `begins_with("USER#")` | -- | Count usage for max_uses check |
| Redeem promo code | `promo_codes` | PK=`CODE#{code_upper}`, SK=`USER#{user_id}` | ConditionExpression: attribute_not_exists(sk) | Atomic redemption (prevents double-redeem) |
| Increment usage counter | `promo_codes` | PK=`CODE#{code_upper}`, SK=`META` | -- | ADD usage_count :1 (atomic increment) |
| Get promo stats | `promo_codes` | PK=`CODE#{code_upper}`, SK `begins_with("USER#")` | -- | Count redemptions for stats endpoint |
| List creator promos | `promo_codes` GSI1 | GSI1PK=`CREATOR#{creator_id}`, GSI1SK desc | -- | List all promos created by a creator |

### 3.4 API Request/Response Examples

**Validate percentage promo code**:

```
POST /ui/promo-codes/validate
Content-Type: application/json
x-csrf-token: <csrf>

{
  "code": "SAVE20",
  "checkout_type": "shop",
  "item_price_cents": 2500,
  "creator_user_id": "alice@test.local"
}
```

**Response (200) -- valid promo**:
```json
{
  "valid": true,
  "message": "20% off applied!",
  "error_code": null,
  "discount_cents": 500,
  "final_price_cents": 2000,
  "discount_type": "percentage",
  "discount_pct": 20,
  "trial_days": 0,
  "original_price_cents": 2500,
  "buy_x": 0,
  "get_y": 0,
  "free_item_description": ""
}
```

**Validate expired promo code**:

```
POST /ui/promo-codes/validate
Content-Type: application/json
x-csrf-token: <csrf>

{
  "code": "OLDCODE",
  "checkout_type": "shop",
  "item_price_cents": 2500
}
```

**Response (200) -- invalid promo**:
```json
{
  "valid": false,
  "message": "This promo code has expired",
  "error_code": "expired",
  "discount_cents": 0,
  "final_price_cents": 2500,
  "discount_type": "",
  "discount_pct": 0,
  "trial_days": 0,
  "original_price_cents": 2500,
  "buy_x": 0,
  "get_y": 0,
  "free_item_description": ""
}
```

**Subscribe with promo code**:

```
POST /api/subscriptions/subscribe
Content-Type: application/json
X-User-Id: bob@test.local

{
  "plan_id": "plan_abc123",
  "payment_method_id": "pm_xyz",
  "promo_code": "FIRSTMONTH50"
}
```

**Response (201)**:
```json
{
  "subscription_id": "sub_def456",
  "plan_id": "plan_abc123",
  "status": "active",
  "current_period_start": 1748520100,
  "current_period_end": 1751112100,
  "promo_applied": true,
  "discount_cents": 500,
  "charged_cents": 500
}
```

**Tip with promo code (zero-amount rejection)**:

```
POST /ui/messaging/conversations/conv_123/messages/msg_456/tip
Content-Type: application/json
x-csrf-token: <csrf>

{
  "amount_cents": 100,
  "payment_method_id": "pm_xyz",
  "promo_code": "FREE100PCT"
}
```

**Response (422)**:
```json
{
  "detail": "Tip amount after discount must be at least $0.01"
}
```

### 3.5 Pydantic Model Definitions

```python
# In app/models.py — extended PromoValidateOut

class PromoValidateOut(BaseModel):
    """Response model for promo code validation."""
    valid: bool
    message: str = ""
    error_code: Optional[str] = Field(
        default=None,
        description="Specific error code: expired, usage_limit, min_order, "
                    "product_mismatch, already_used, not_found, deactivated, "
                    "checkout_type_mismatch",
    )
    discount_cents: int = 0
    final_price_cents: int = 0
    discount_type: str = Field(
        default="",
        description="percentage, fixed, free_shipping, buy_x_get_y",
    )
    discount_pct: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Percentage value for display (e.g., 20 for 20% off)",
    )
    trial_days: int = 0
    original_price_cents: int = Field(
        default=0,
        ge=0,
        description="Price before discount for display",
    )
    buy_x: int = Field(default=0, ge=0)
    get_y: int = Field(default=0, ge=0)
    free_item_description: str = ""


class PromoValidateIn(BaseModel):
    """Request model for promo code validation."""
    code: str = Field(..., min_length=1, max_length=50)
    checkout_type: str = Field(
        ...,
        pattern=r"^(shop|subscription|tip|unlock)$",
        description="Type of checkout surface",
    )
    item_price_cents: int = Field(..., ge=0)
    creator_user_id: Optional[str] = Field(
        default=None,
        description="Creator who owns the content (for creator-scoped promos)",
    )


# Extended subscription model
class SubscribeWithPromoIn(BaseModel):
    """Request model for subscribing with optional promo code."""
    plan_id: str
    payment_method_id: Optional[str] = None
    promo_code: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Optional promo code to apply to first billing cycle",
    )

---

## 4. DynamoDB Access Patterns

| Access Pattern | Table | Key Condition | Filter | Use Case |
|---------------|-------|---------------|--------|----------|
| Find promo by code | `promo_codes` | PK=`CODE#{code_upper}`, SK=`META` | — | GetItem for validation |
| Check user redemption | `promo_codes` | PK=`CODE#{code}`, SK=`USER#{user_sub}` | — | GetItem; check if user already used this code |
| Record redemption | `promo_codes` | PK=`CODE#{code}`, SK=`USER#{user_sub}` | — | PutItem with `redeemed_at`, `checkout_type`, `discount_cents` |
| Increment usage count | `promo_codes` | PK=`CODE#{code}`, SK=`META` | — | UpdateItem ADD `usage_count :1` |
| List promos by creator | `promo_codes` GSI1 | GSI1PK=`CREATOR#{creator_sub}` | — | Creator's promo management |
| Get promo stats | `promo_codes` | PK=`CODE#{code}`, SK begins_with `USER#` | — | Count redemptions |

**Example DynamoDB Item** (promo code):

```json
{
  "pk": {"S": "CODE#SAVE20"},
  "sk": {"S": "META"},
  "code": {"S": "SAVE20"},
  "discount_type": {"S": "percentage"},
  "discount_value": {"N": "20"},
  "checkout_types": {"SS": ["shop", "subscription"]},
  "min_order_cents": {"N": "1000"},
  "max_usage": {"N": "100"},
  "usage_count": {"N": "42"},
  "expires_at": {"N": "1751112100"},
  "is_active": {"BOOL": true},
  "creator_sub": {"S": "alice@test.local"},
  "created_at": {"N": "1748520100"}
}
```

**Example DynamoDB Item** (redemption record):

```json
{
  "pk": {"S": "CODE#SAVE20"},
  "sk": {"S": "USER#bob@test.local"},
  "redeemed_at": {"N": "1748525000"},
  "checkout_type": {"S": "subscription"},
  "discount_cents": {"N": "200"},
  "original_price_cents": {"N": "1000"}
}
```

---

## 5. API Request/Response Examples

**Validate promo code** (curl):

```bash
curl -X POST http://localhost:8000/ui/promo-codes/validate \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_bob; ui_csrf=csrf_b; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_b" \
  -d '{
    "code": "SAVE20",
    "checkout_type": "subscription",
    "item_price_cents": 1000,
    "creator_user_id": "alice@test.local"
  }'
```

**Response (200)** — valid:
```json
{
  "valid": true,
  "message": "20% off applied",
  "discount_cents": 200,
  "final_price_cents": 800,
  "discount_type": "percentage",
  "discount_pct": 20,
  "original_price_cents": 1000
}
```

**Response (200)** — expired:
```json
{
  "valid": false,
  "message": "This promo code has expired",
  "error_code": "expired",
  "discount_cents": 0,
  "final_price_cents": 1000
}
```

**Subscribe with promo** (curl):

```bash
curl -X POST http://localhost:8000/api/subscriptions/subscribe \
  -H "Content-Type: application/json" \
  -H "X-User-Id: bob@test.local" \
  -d '{
    "plan_id": "plan_abc123",
    "payment_method_id": "pm_xyz",
    "promo_code": "SAVE20"
  }'
```

**Response (201)**:
```json
{
  "subscription_id": "sub_def456",
  "plan_id": "plan_abc123",
  "status": "active",
  "promo_applied": true,
  "discount_cents": 200,
  "charged_cents": 800
}
```

---

## 6. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Code not found | 200 | `not_found` | "Promo code not found" | Check spelling |
| Code expired | 200 | `expired` | "This promo code has expired" | Use a different code |
| Usage limit reached | 200 | `usage_limit` | "This promo code has reached its usage limit" | Contact creator |
| Already used by this user | 200 | `already_used` | "You've already used this promo code" | Each code usable once per user |
| Min order not met | 200 | `min_order` | "Minimum order of $X.XX required" | Add more items |
| Wrong checkout type | 200 | `checkout_type_mismatch` | "This code is not valid for this purchase type" | Use at correct checkout |
| Product mismatch | 200 | `product_mismatch` | "This code is not valid for this product" | Check eligible products |
| Deactivated | 200 | `deactivated` | "This promo code is no longer active" | Contact creator |
| Tip becomes zero after discount | 422 | — | "Tip amount after discount must be at least $0.01" | Increase tip or remove code |
| Code too long | 422 | `validation_error` | Pydantic validation | Enter shorter code |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Log in |

---

## 7. Frontend Component Tree

```
PromoCodeInput (shared component — used in all checkout flows)
├── Input (code text field)
│   └── placeholder: "Enter promo code"
├── ApplyButton → validate promo
│   └── Loading state while validating
├── DiscountCard (visible when promo applied)
│   ├── Badge (discount type: "20% OFF" / "$5 OFF" / "FREE SHIPPING" / "BUY 2 GET 1")
│   ├── OriginalPrice (strikethrough)
│   ├── DiscountLine ("-$X.XX")
│   ├── FinalPrice (bold)
│   └── RemoveButton → clear promo
├── ErrorMessage (visible when validation fails)
│   └── Type-specific message from error_code
└── BuyXGetYDisplay (visible when discount_type="buy_x_get_y")
    ├── "Buy {buy_x}, Get {get_y} Free"
    └── FreeItemDescription

Checkout.tsx (shop — enhanced)
├── CartSummary
├── PromoCodeInput
├── OrderTotal (updated with discount)
└── PurchaseButton

SubscribePage.tsx (subscriptions — new promo support)
├── PlanCard
├── PromoCodeInput (new)
├── PriceSummary (original + discount + final)
└── SubscribeButton

ComposeBar TipPanel (messaging — new promo support)
├── TipAmountInput
├── PromoCodeInput (new, compact variant)
├── PaymentMethodSelector
└── SendTipButton

MessageBubble UnlockDialog (messaging — new promo support)
├── LockDescription
├── UnlockPrice
├── PromoCodeInput (new, compact variant)
├── PaymentMethodSelector
└── UnlockButton
```

---

## 8. Implementation Plan

### 8.1 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/subscription_server.py` | Accept `promo_code` on subscribe endpoint |
| `app/routers/messaging.py` | Accept `promo_code` on tip and unlock endpoints |
| `frontend/src/pages/shop/Checkout.tsx` | Enhance PromoCodeInput with DiscountCard |
| `frontend/src/pages/subscriptions/SubscribePage.tsx` | Add PromoCodeInput |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add PromoCodeInput to tip panel |
| `frontend/src/pages/messages/MessageBubble.tsx` | Add PromoCodeInput to unlock dialog |

### 8.2 Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/components/shared/PromoCodeInput.tsx` | Shared promo code input with DiscountCard |

---

## 9. E2E Test Plan

### 9.1 Test File

`frontend/e2e/promo-codes-checkout.spec.ts` — 15 tests across 4 sections.

### 9.2 Section 503: Promo Validation API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 503.1 | Validate percentage discount | POST validate with SAVE20; 200; valid=true, discount_type=percentage, discount_cents correct |
| 503.2 | Validate fixed discount | POST validate with FLAT500; 200; valid=true, discount_type=fixed, discount_cents=500 |
| 503.3 | Reject expired code | POST validate with expired code; 200; valid=false, error_code=expired |
| 503.4 | Reject code below min order | POST validate with item_price=500, min_order=1000; 200; valid=false, error_code=min_order |
| 503.5 | Reject wrong checkout type | POST validate shop code on subscription; 200; valid=false, error_code=checkout_type_mismatch |

### 9.3 Section 504: Subscription with Promo (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 504.1 | Subscribe with valid promo | POST subscribe with promo_code; 201; promo_applied=true, charged_cents < plan_price |
| 504.2 | Subscribe with invalid promo returns error | POST subscribe with expired promo; 400 or promo_applied=false |
| 504.3 | Promo redemption recorded | After subscribe; check redemption record exists for user |

### 9.4 Section 505: Tip/Unlock with Promo (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 505.1 | Tip with percentage promo | POST tip with promo_code; 200; discount applied to tip |
| 505.2 | Tip that becomes $0 rejected | POST tip $1 with FREE100PCT; 422; "at least $0.01" |
| 505.3 | Unlock with fixed promo | POST unlock with FLAT500 promo; 200; charged less than lock price |
| 505.4 | Second redemption rejected | POST tip with already-used promo; 200 validation shows already_used |

### 9.5 Section 506: Promo Code UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 506.1 | Promo input visible on subscription page | Navigate to subscribe; promo input field visible |
| 506.2 | Valid promo shows discount card | Enter valid code; click Apply; DiscountCard with savings amount visible |
| 506.3 | Remove promo restores original price | Click "Remove"; price reverts to original; discount card hidden |

---

## 10. Security Considerations

- Promo codes are case-insensitive (stored uppercase)
- Validation is re-run at purchase time (not just at preview time) to prevent replay
- Per-user usage limits enforced via DDB redemption records
- Creator-scoped promos only apply to that creator's content
- Rate limiting on validation endpoint: 30 requests/minute per user

---

## 11. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Promo validation latency | < 50ms | Single GetItem + optional GetItem for redemption check |
| Promo redemption write | < 20ms | PutItem + atomic ADD on usage_count |
| Frontend discount preview | Instant | Computed client-side from validation response |
| Promo lookup miss (wrong code) | < 10ms | Single GetItem returns None |

---

## 12. Observability

### 12.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `promo_validated_total` | Counter | `result` (valid/invalid), `error_code` | Validation requests |
| `promo_redeemed_total` | Counter | `checkout_type`, `discount_type` | Successful redemptions |
| `promo_discount_cents_total` | Counter | `checkout_type` | Total discount amount given |
| `promo_validation_latency_ms` | Histogram | — | Validation request latency |

### 12.2 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High promo abuse | Single user validates > 50 codes/hour | Medium | Rate limit and review |
| Revenue loss from promos | Discount total > $10K/day | Low | Review promo settings |
| Validation errors spike | > 10% of validations return server error | High | Check DDB health |

---

## 13. Rollout Plan

### 13.1 Feature Flag

```python
promo_in_subscriptions_enabled: bool = os.environ.get("PROMO_SUBSCRIPTIONS_ENABLED", "true").lower() == "true"
promo_in_tips_enabled: bool = os.environ.get("PROMO_TIPS_ENABLED", "true").lower() == "true"
```

### 13.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Enhanced shop UI | Deploy improved PromoCodeInput with DiscountCard | 2 days | Existing shop E2E pass |
| Phase 2: Subscriptions | Enable promo on subscription checkout | 3 days | Section 504 tests pass |
| Phase 3: Tips/Unlocks | Enable promo on tip and unlock flows | 3 days | Section 505 tests pass |
| Phase 4: GA | All promo surfaces live | Permanent | No revenue anomalies |

### 13.3 Rollback

1. Disable per-surface flags — only affects new redemptions
2. Already-redeemed promos remain recorded
3. No data migration needed

---

## 14. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Promo code backend | Existing (`promo_codes.py`) | Available |
| Shop checkout | Existing (`Checkout.tsx`) | Available |
| Subscription server | Existing (`subscription_server.py`) | Modify |
| Billing integration | Existing | Available |


# Extended tip model
class TipWithPromoIn(BaseModel):
    """Request model for tipping with optional promo code."""
    amount_cents: int = Field(..., ge=100)
    payment_method_id: str
    promo_code: Optional[str] = Field(
        default=None,
        max_length=50,
    )


# Extended unlock model
class UnlockWithPromoIn(BaseModel):
    """Request model for unlocking with optional promo code."""
    payment_method_id: str
    promo_code: Optional[str] = Field(
        default=None,
        max_length=50,
    )
```

### 3.6 Frontend Changes

#### 3.6.1 Shared PromoCodeInput Component

**New file**: `frontend/src/components/shared/PromoCodeInput.tsx` (~180 lines)

A reusable promo code input component used across all checkout surfaces:

```typescript
interface PromoCodeInputProps {
  checkoutType: "shop" | "subscription" | "tip" | "unlock";
  itemPriceCents: number;
  creatorUserId?: string;
  onPromoApplied: (result: PromoValidateOut) => void;
  onPromoRemoved: () => void;
}
```

#### 3.6.2 Frontend Component Tree

```
PromoCodeInput (new shared component)
├── CollapsibleTrigger: "Have a promo code?" (ChevronDown icon)
└── CollapsibleContent
    ├── InputRow
    │   ├── Input (text, placeholder="Enter code")
    │   └── ApplyButton (disabled while validating; shows Loader2 spinner)
    ├── ErrorAlert (conditional, when validation failed)
    │   ├── AlertCircle icon
    │   └── Error message (specific: expired, usage_limit, etc.)
    └── SuccessCard (conditional, when valid promo applied)
        ├── DiscountBadge
        │   ├── "20% OFF" (percentage)
        │   ├── "$5 OFF" (fixed)
        │   ├── "FREE SHIPPING" (free_shipping)
        │   └── "BUY 2 GET 1" (buy_x_get_y)
        ├── OriginalPrice (strikethrough)
        ├── DiscountAmount (green, negative: "-$5.00")
        ├── FinalPrice (bold)
        └── RemoveButton (X icon) → onPromoRemoved

OrderSummaryDiscount (new shared component)
├── SubtotalLine: "Subtotal" + "$25.00"
├── DiscountLine: "Promo: SAVE20 (20% off)" + "-$5.00" (green)
├── Separator (dashed line)
└── TotalLine: "Total" + "$20.00" (bold)

Checkout.tsx (modified)
├── CartItems
├── PromoCodeInput (replaces inline promo state)
├── OrderSummaryDiscount (replaces simple total)
├── PaymentMethodSelector
└── PurchaseButton

SubscribePage.tsx (modified)
├── PlanDetails
├── PromoCodeInput (NEW)
├── OrderSummaryDiscount (NEW)
├── PaymentMethodSelector
└── SubscribeButton

ComposeBar.tsx tip panel (modified)
├── TipAmountInput
├── PaymentMethodSelector
├── PromoCodeInput (NEW, collapsed by default)
└── SendTipButton

MessageBubble.tsx unlock dialog (modified)
├── LockDescription
├── UnlockPrice
├── PaymentMethodSelector
├── PromoCodeInput (NEW, collapsed by default)
└── UnlockButton
```

#### 3.6.3 Order Summary Discount Line

**New file**: `frontend/src/components/shared/OrderSummaryDiscount.tsx` (~80 lines)

Renders the discount breakdown in any order summary:

```
  Subtotal                    $25.00
  Promo: SAVE20 (20% off)    -$5.00
  ──────────────────────────────────
  Total                       $20.00
```

#### 3.6.4 Integration Points

| File | Change |
|------|--------|
| `frontend/src/pages/shop/Checkout.tsx` | Replace inline promo state with `<PromoCodeInput>` + `<OrderSummaryDiscount>` |
| `frontend/src/pages/subscriptions/SubscribePage.tsx` | Add `<PromoCodeInput checkoutType="subscription">` before payment method selector |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add optional `<PromoCodeInput checkoutType="tip">` inside tip amount panel |
| `frontend/src/pages/messages/MessageBubble.tsx` | Add optional `<PromoCodeInput checkoutType="unlock">` in unlock dialog |

### 3.7 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/components/shared/PromoCodeInput.tsx` | Reusable promo code input + validation | ~180 |
| `frontend/src/components/shared/OrderSummaryDiscount.tsx` | Discount breakdown display | ~80 |
| `frontend/e2e/promo-checkout.spec.ts` | E2E tests | ~550 |

### 3.8 Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add `error_code`, `discount_pct`, `original_price_cents`, `buy_x`, `get_y`, `free_item_description` to `PromoValidateOut`; add `promo_code` to `SubscribeIn`, `TipMessageIn`, `UnlockMessageIn` |
| `app/services/promo_codes.py` | Return `error_code` from `validate_promo_code`; populate new fields in response |
| `app/routers/subscription_server.py` | Accept and validate `promo_code` on subscription creation |
| `app/routers/messaging.py` | Accept `promo_code` on tip and unlock endpoints; apply discount |
| `app/routers/newsfeed.py` | Accept `promo_code` on post tip and unlock endpoints; apply discount |
| `frontend/src/pages/shop/Checkout.tsx` | Replace inline promo code handling with `PromoCodeInput` component |
| `frontend/src/pages/subscriptions/SubscribePage.tsx` | Add `PromoCodeInput` for subscription promo codes |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add optional promo code input in tip panel |
| `frontend/src/pages/messages/MessageBubble.tsx` | Add optional promo code input in unlock dialog |
| `frontend/src/api/types.ts` | Update `PromoValidateOut` with new fields |

---

## 4. Promo Code Flow

### 4.1 Validation Flow

```
User types promo code → clicks "Apply"
  → POST /ui/promo-codes/validate
    {code, checkout_type, item_price_cents, creator_user_id}
  → Backend validates:
    1. Code exists and is active
    2. Not expired
    3. Usage limits not exceeded (global + per-user)
    4. Minimum order met
    5. Eligible products/checkout types match
  → Returns PromoValidateOut:
    {valid: true, discount_type: "percentage", discount_pct: 20,
     discount_cents: 500, final_price_cents: 2000, original_price_cents: 2500}
  → UI updates: shows discount card, updates total display
```

### 4.2 Redemption Flow

```
User clicks "Purchase" / "Subscribe" / "Send Tip" / "Unlock"
  → Backend:
    1. Re-validates promo code (guard against race conditions)
    2. If still valid: applies discount to amount
    3. Processes payment at discounted amount
    4. Calls redeem_promo_code (increments usage, writes redemption record)
    5. Returns success
  → If promo expired between validate and purchase:
    → 422 with detail message
    → UI clears promo, shows error toast
```

### 4.3 Discount Type Rendering

| `discount_type` | Badge Text | Discount Line |
|-----------------|-----------|---------------|
| `percentage` | "20% OFF" | "Promo: SAVE20 (20% off) -$5.00" |
| `fixed` | "$5 OFF" | "Promo: FLAT5 ($5.00 off) -$5.00" |
| `free_shipping` | "FREE SHIPPING" | "Promo: FREESHIP (free shipping) -$3.99" |
| `buy_x_get_y` | "BUY 2 GET 1" | "Promo: B2G1 (buy 2 get 1 free) -$8.99" |

### 4.4 Edge Cases

- **Promo expires during checkout session**: Re-validation at purchase time returns 422; UI clears promo and shows toast error.
- **Promo + subscription trial**: If promo grants `trial_days`, the first billing cycle is deferred. If promo grants a discount, it applies to the first cycle only.
- **Promo on zero-amount tips**: Tips must be >= 100 cents; a 100% promo on a $1 tip results in $0 payment. Backend rejects zero-amount tips after discount (422: "Tip amount after discount must be at least $0.01").
- **Multiple promo codes**: Only one promo code per transaction. Attempting to apply a second replaces the first.
- **Cart total changes after promo applied**: If user adds/removes items after applying promo, the promo is re-validated against the new total. If minimum order is no longer met, promo is auto-removed with a toast warning.
- **Creator-scoped promos**: Some promos are scoped to a specific creator. Validation checks `creator_user_id` match; mismatch returns `product_mismatch` error.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/promo-checkout.spec.ts`

### Section 543: Promo Code Validation API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 543.1 | Valid percentage promo returns discount details | Create 20% promo code. Validate with $25 item. Response: `valid: true`, `discount_type: "percentage"`, `discount_pct: 20`, `discount_cents: 500`, `final_price_cents: 2000`. |
| 543.2 | Expired promo returns error_code "expired" | Create promo with `expires_at` in the past. Validate. Response: `valid: false`, `error_code: "expired"`, `message` contains "expired". |
| 543.3 | Usage limit exceeded returns error_code "usage_limit" | Create promo with `max_uses: 1`. Redeem once. Validate again. Response: `valid: false`, `error_code: "usage_limit"`. |
| 543.4 | Below minimum order returns error_code "min_order" | Create promo with `min_order_cents: 5000`. Validate with $20 item. Response: `valid: false`, `error_code: "min_order"`. |
| 543.5 | Wrong checkout_type returns error_code "checkout_type_mismatch" | Create promo for `checkout_type: "shop"`. Validate with `checkout_type: "subscription"`. Response: `valid: false`, `error_code: "checkout_type_mismatch"`. |

### Section 544: Shop Checkout Promo UI (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 544.1 | Promo code input expands and validates | Click "Have a promo code?" then input visible. Enter code then click "Apply" then discount card appears with badge and savings. |
| 544.2 | Discount line appears in order summary | After applying promo, order summary shows original price (strikethrough), discount line with code name, and updated total. |
| 544.3 | Remove promo restores original price | Click "Remove" on applied promo. Discount line disappears, total returns to original. |
| 544.4 | Invalid code shows specific error message | Enter expired code then "Apply" then error alert with "This promo code has expired". |

### Section 545: Subscription Promo Code API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 545.1 | Subscribe with valid promo applies discount | Create plan ($10/mo). Create 50% promo. Subscribe with `promo_code`. Billing ledger shows $5.00 charge (not $10). |
| 545.2 | Subscribe with trial promo defers billing | Create promo with `trial_days: 7`. Subscribe. Subscription `status: "trialing"`, `trial_end` set. |
| 545.3 | Subscribe with invalid promo returns 422 | Subscribe with nonexistent promo code. Response: 422 with detail message. |
| 545.4 | Promo redemption increments usage count | After successful subscription with promo, `get_promo_stats` shows `redemption_count` incremented. |

### Section 546: Tip and Unlock Promo Codes (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 546.1 | Tip with percentage promo discounts amount | Alice creates 25% promo. Bob tips Alice $10 with promo. Billing shows $7.50 charge. Alice receives full $10 credit (discount absorbed by platform). |
| 546.2 | Unlock with fixed promo reduces price | Alice locks message at $5. Creates $2-off promo. Bob unlocks with promo. Billing shows $3.00 charge. |
| 546.3 | Zero-amount tip after discount is rejected | Create 100% promo. Bob tips $1.00 with promo then 422: "Tip amount after discount must be at least $0.01". |
| 546.4 | Per-user usage limit enforced on tips | Create promo with `max_uses_per_user: 1`. Bob tips with promo (success). Bob tips again with same promo then `valid: false`, `error_code: "already_used"`. |
| 546.5 | Creator-scoped promo rejects other creators | Alice creates promo scoped to herself. Bob tips Charlie (not Alice) with Alice's promo then `valid: false`, `error_code: "product_mismatch"`. |

### Section 547: Promo Code Edge Cases (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 547.1 | Fixed amount promo exceeding price caps at price | Create $50-off promo. Apply to $25 item. `discount_cents` = 2500, `final_price_cents` = 0. |
| 547.2 | Case-insensitive promo code validation | Create code "SAVE20". Validate with "save20". Valid. |
| 547.3 | Deactivated promo returns error_code "deactivated" | Create promo, deactivate it. Validate. `error_code: "deactivated"`. |
| 547.4 | Free shipping promo on subscription returns no discount | Create free_shipping promo. Validate with `checkout_type: "subscription"`. `discount_cents: 0` (shipping not applicable). |
| 547.5 | Buy-X-get-Y fields populated in response | Create buy-2-get-1 promo. Validate. Response has `buy_x: 2`, `get_y: 1`, `free_item_description`. |
| 547.6 | Promo re-validation at purchase time | Apply promo, then deactivate code via admin API, then purchase. Response: 422 "Promo code is no longer valid". |

**Total E2E tests: 24**

---

## 6. Error Handling

### 6.1 Error Matrix

| Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|----------|-------------|------------|---------------|-----------------|
| Code not found | 200 (valid=false) | `not_found` | "Promo code not found" | Show error in PromoCodeInput; user re-enters |
| Code deactivated | 200 (valid=false) | `deactivated` | "This promo code is no longer active" | Show error; clear input |
| Code expired | 200 (valid=false) | `expired` | "This promo code has expired" | Show error with expiry info |
| Usage limit reached | 200 (valid=false) | `usage_limit` | "This promo code has reached its usage limit" | Show error; suggest other codes |
| User already used | 200 (valid=false) | `already_used` | "You have already used this promo code" | Show error; clear input |
| Below min order | 200 (valid=false) | `min_order` | "Minimum order of $X.XX required" | Show error with minimum amount |
| Product mismatch | 200 (valid=false) | `product_mismatch` | "This code is not valid for the selected items" | Show error |
| Checkout type mismatch | 200 (valid=false) | `checkout_type_mismatch` | "This code cannot be used for this purchase type" | Show error |
| Zero tip after discount | 422 | -- | "Tip amount after discount must be at least $0.01" | Increase tip amount or remove promo |
| Promo expired at purchase | 422 | -- | "Promo code is no longer valid" | Clear promo; recalculate total; show toast |

---

## 7. Security Considerations

### 7.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Validate promo | `require_ui_session` | Any authenticated user |
| Redeem promo | Internal (called by purchase flows) | Validated within transaction |
| Create/manage promos | `require_ui_session` | Creator who owns the promo |

### 7.2 Race Condition Protection

- **Double-validate**: Promo is re-validated at purchase time, not just at UI apply time. Between validate and purchase, usage limits, expiry, or deactivation may have changed.
- **Atomic redemption**: `redeem_promo_code` uses DynamoDB `ConditionExpression` on usage count to prevent concurrent over-redemption.
- **Idempotent redemption**: Redemption records keyed by `(code_id, user_id, timestamp)` prevent duplicate redemptions for the same transaction.

### 7.3 Abuse Prevention

- Promo code brute-force: rate limit `/validate` to 10 requests per minute per user.
- Promo code sharing: `max_uses_per_user` limits prevent one user from over-consuming.
- Promo stacking: Only one promo per transaction enforced at both UI and API level.

---

## 8. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Validate latency | < 100ms p95 | Single DDB get_item + optional user check; no joins |
| Redemption latency | < 200ms p95 | Atomic update with ConditionExpression; single DDB call |
| Cart re-validation on item change | < 150ms | Frontend debounces re-validation by 500ms on cart changes |
| PromoCodeInput render | < 16ms | React.memo on component; validation state local |
| Concurrent redemption | Exactly-once | DDB ConditionExpression prevents double-increment |

---

## 9. Observability

### 9.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `promo_validated_total` | Counter | `checkout_type`, `valid` | Number of promo validations |
| `promo_redeemed_total` | Counter | `checkout_type`, `discount_type` | Number of successful redemptions |
| `promo_discount_cents_total` | Counter | `checkout_type` | Total discount amount applied |
| `promo_validation_error_total` | Counter | `error_code` | Validation failures by error type |

### 9.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Promo validated (valid) | INFO | `code`, `user_id`, `checkout_type`, `discount_cents` |
| Promo validated (invalid) | INFO | `code`, `user_id`, `checkout_type`, `error_code` |
| Promo redeemed | INFO | `code`, `user_id`, `checkout_type`, `discount_cents`, `transaction_id` |
| Promo expired at purchase time | WARN | `code`, `user_id`, `checkout_type` |

### 9.3 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| High promo failure rate | > 80% of validations return invalid | Medium |
| Promo brute-force attempt | > 50 validations/min from single user | High |
| Redemption race condition | ConditionCheck failures > 5/min | Low |

---

## 10. Rollout Plan

### 10.1 Feature Flag

```python
# app/core/settings.py
promo_codes_all_surfaces_enabled: bool = os.environ.get(
    "PROMO_CODES_ALL_SURFACES_ENABLED", "true"
).lower() == "true"
```

When disabled, promo codes only work in shop checkout (existing behavior). Subscription, tip, and unlock surfaces do not show the PromoCodeInput component, and backend rejects `promo_code` on those endpoints with 400.

### 10.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Enhanced validation | Deploy `error_code` field and new PromoCodeInput component in shop checkout only | 2 days | Unit tests pass; shop E2E tests pass |
| Phase 2: Subscription promos | Enable promo code on SubscribePage | 2 days | Subscription promo E2E tests pass |
| Phase 3: Tip/unlock promos | Enable promo code on tip and unlock flows | 2 days | Tip/unlock promo E2E tests pass |
| Phase 4: GA | Remove feature flag; all surfaces enabled | Permanent | All 24 E2E tests pass; monitoring clean |

---

## 11. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/promo_codes.py` | Exists | `validate_promo_code`, `redeem_promo_code`, `_calculate_discount` |
| `app/routers/shoppingcart.py` | Exists | Existing promo code integration in cart purchase |
| `frontend/src/pages/shop/Checkout.tsx` | Exists (modify) | Replace inline promo handling with reusable component |
| `app/routers/subscription_server.py` | Exists (modify) | Add promo code acceptance to subscription creation |
| `app/routers/messaging.py` | Exists (modify) | Add promo code to tip/unlock endpoints |
| `app/routers/newsfeed.py` | Exists (modify) | Add promo code to post tip/unlock endpoints |
| `app/models.py` | Exists (modify) | Extend `PromoValidateOut`, `SubscribeIn`, `TipMessageIn`, `UnlockMessageIn` |
| `frontend/src/api/endpoints/promoCodes.ts` | Exists | `validatePromoCode` API wrapper |

---

## 12. Acceptance Criteria

1. Promo code input is available in shop checkout, subscription checkout, tip panel, and unlock dialog.
2. Valid promo codes show a discount preview with type-specific badge, original price, discount amount, and final price.
3. Invalid promo codes show specific error messages (expired, usage limit, minimum order, product mismatch).
4. Promo codes are re-validated at purchase time; expired codes between validate and purchase return 422.
5. Subscription promos support both discount and trial-period grant.
6. Only one promo code per transaction; applying a new code replaces the previous one.
7. Promo redemption atomically increments usage count to prevent over-redemption.
8. All 24 E2E tests pass.

---

## Codebase References

### Existing Files (verified)
| File | Key Functions | Lines |
|------|--------------|-------|
| `app/services/promo_codes.py` | `create_promo_code`, `validate_promo_code`, `_calculate_discount`, `redeem_promo_code`, `get_promo_stats` | 85, 239, 335, 357, 421 |
| `app/routers/promo_codes.py` | Promo code CRUD router | - |
| `app/main.py` | `app.include_router(promo_codes_router)` | 451 |
| `scripts/local-ddb-init.py` | `PromoCodes` table | 902 |
| `frontend/src/api/endpoints/promoCodes.ts` | Frontend promo code API | - |
| `frontend/src/pages/promo/PromoCodesPage.tsx` | Promo code management UI | - |

### Files to Modify (extension needed)
| File | Change Needed |
|------|--------------|
| `frontend/src/pages/subscriptions/SubscribePage.tsx` | Add promo code input |
| `app/routers/subscription_server.py` | Accept promo code on subscription creation |
| `app/routers/messaging.py` | Add promo code to tip/unlock endpoints |
| `app/routers/newsfeed.py` | Add promo code to post tip/unlock endpoints |
