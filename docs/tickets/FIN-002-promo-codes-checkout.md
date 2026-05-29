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
| Promo code service | `app/services/promo_codes.py` (~460 lines) | Full CRUD: `create_promo_code`, `validate_promo_code`, `redeem_promo_code`, `_calculate_discount`, `get_promo_stats` |
| Promo code validation | `app/services/promo_codes.py:239` | `validate_promo_code(code, user_id, checkout_type, item_price_cents, creator_user_id)` -- checks expiry, usage limits, min order, eligible products |
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

### 3.1 Backend Changes

No new DynamoDB tables. The existing `promo_codes` table and service handle all storage and validation. Changes are to the validation and redemption hooks in other services.

#### 3.1.1 Extend `validate_promo_code` Response

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

#### 3.1.2 Subscription Promo Code Support

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

#### 3.1.3 Tip/Unlock Promo Code Support

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

#### 3.1.4 Detailed Error Reasons

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

### 3.2 Frontend Changes

#### 3.2.1 Shared PromoCodeInput Component

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

**Component tree**:

```
PromoCodeInput
├── Collapsible trigger: "Have a promo code?" (ChevronDown icon)
└── Collapsible content:
    ├── Input field + "Apply" Button (inline)
    ├── Error alert (if validation failed)
    │   └── Error message with specific reason
    └── Success card (if valid promo applied)
        ├── Discount type badge ("20% OFF" / "$5 OFF" / "FREE SHIPPING" / "BUY 2 GET 1")
        ├── Original price (strikethrough)
        ├── Discount amount (green, negative)
        ├── Final price (bold)
        └── "Remove" button (X icon)
```

#### 3.2.2 Order Summary Discount Line

**New file**: `frontend/src/components/shared/OrderSummaryDiscount.tsx` (~80 lines)

Renders the discount breakdown in any order summary:

```
  Subtotal                    $25.00
  Promo: SAVE20 (20% off)    -$5.00
  ──────────────────────────────────
  Total                       $20.00
```

#### 3.2.3 Integration Points

| File | Change |
|------|--------|
| `frontend/src/pages/shop/Checkout.tsx` | Replace inline promo state with `<PromoCodeInput>` + `<OrderSummaryDiscount>` |
| `frontend/src/pages/subscriptions/SubscribePage.tsx` | Add `<PromoCodeInput checkoutType="subscription">` before payment method selector |
| `frontend/src/pages/messages/ComposeBar.tsx` | Add optional `<PromoCodeInput checkoutType="tip">` inside tip amount panel |
| `frontend/src/pages/messages/MessageBubble.tsx` | Add optional `<PromoCodeInput checkoutType="unlock">` in unlock dialog |

### 3.3 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/components/shared/PromoCodeInput.tsx` | Reusable promo code input + validation | ~180 |
| `frontend/src/components/shared/OrderSummaryDiscount.tsx` | Discount breakdown display | ~80 |
| `frontend/e2e/promo-checkout.spec.ts` | E2E tests | ~550 |

### 3.4 Files to Modify

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
| 544.1 | Promo code input expands and validates | Click "Have a promo code?" → input visible. Enter code → click "Apply" → discount card appears with badge and savings. |
| 544.2 | Discount line appears in order summary | After applying promo, order summary shows original price (strikethrough), discount line with code name, and updated total. |
| 544.3 | Remove promo restores original price | Click "Remove" on applied promo. Discount line disappears, total returns to original. |
| 544.4 | Invalid code shows specific error message | Enter expired code → "Apply" → error alert with "This promo code has expired". |

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
| 546.3 | Zero-amount tip after discount is rejected | Create 100% promo. Bob tips $1.00 with promo → 422: "Tip amount after discount must be at least $0.01". |
| 546.4 | Per-user usage limit enforced on tips | Create promo with `max_uses_per_user: 1`. Bob tips with promo (success). Bob tips again with same promo → `valid: false`, `error_code: "already_used"`. |
| 546.5 | Creator-scoped promo rejects other creators | Alice creates promo scoped to herself. Bob tips Charlie (not Alice) with Alice's promo → `valid: false`, `error_code: "product_mismatch"`. |

**Total E2E tests: 18**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Validate promo | `require_ui_session` | Any authenticated user |
| Redeem promo | Internal (called by purchase flows) | Validated within transaction |
| Create/manage promos | `require_ui_session` | Creator who owns the promo |

### 6.2 Race Condition Protection

- **Double-validate**: Promo is re-validated at purchase time, not just at UI apply time. Between validate and purchase, usage limits, expiry, or deactivation may have changed.
- **Atomic redemption**: `redeem_promo_code` uses DynamoDB `ConditionExpression` on usage count to prevent concurrent over-redemption.
- **Idempotent redemption**: Redemption records keyed by `(code_id, user_id, timestamp)` prevent duplicate redemptions for the same transaction.

### 6.3 Abuse Prevention

- Promo code brute-force: rate limit `/validate` to 10 requests per minute per user.
- Promo code sharing: `max_uses_per_user` limits prevent one user from over-consuming.
- Promo stacking: Only one promo per transaction enforced at both UI and API level.

---

## 7. Dependencies

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

## 8. Acceptance Criteria

1. Promo code input is available in shop checkout, subscription checkout, tip panel, and unlock dialog.
2. Valid promo codes show a discount preview with type-specific badge, original price, discount amount, and final price.
3. Invalid promo codes show specific error messages (expired, usage limit, minimum order, product mismatch).
4. Promo codes are re-validated at purchase time; expired codes between validate and purchase return 422.
5. Subscription promos support both discount and trial-period grant.
6. Only one promo code per transaction; applying a new code replaces the previous one.
7. Promo redemption atomically increments usage count to prevent over-redemption.
8. All 18 E2E tests pass.
