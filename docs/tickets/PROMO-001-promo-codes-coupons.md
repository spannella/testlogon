# PROMO-001: Promo Codes & Coupons

**Status**: Implemented
**Author**: Engineering
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 6-8 days

---

## 1. Executive Summary

The platform supports multiple monetization channels -- subscriptions, VOD purchases, locked content unlocks, and a shop catalog -- but has no promotional pricing mechanism. Creators cannot offer discount codes to attract new subscribers, run limited-time promotions on VOD content, or distribute coupons for shop items. Every transaction processes at full price with no discount hook in the subscription checkout (`app/routers/subscription_server.py`), shop checkout (`app/routers/catalog.py`), or any other payment flow.
<!-- CORRECTED: A discount code system ALREADY EXISTS in subscription_server.py. Discount codes are stored as DISCOUNT#{code} rows under the creator's PK in the subscriptions DDB table. The subscribe endpoint (line 840-850) accepts discount_code, validates it via _get_discount() + _is_discount_active(), and applies percentage discounts via _apply_discount(). Creator CRUD endpoints exist: POST /api/creators/{id}/discounts (line 1573), GET /api/creators/{id}/discounts (line 1620), POST /api/creators/{id}/discounts/{code}/disable (line 1640). What IS missing: fixed-amount discounts (only percentage is supported), free trial codes (trial_days is a separate SubscribeIn field, not linked to promo codes), usage limits, per-user limits, expiry dates, cross-checkout-type codes, and redemption tracking. The ticket should be re-scoped as an ENHANCEMENT of the existing discount system, not a greenfield feature. -->

This ticket builds a complete promo code system. Creators can create and manage promo codes through a CRUD interface with configurable rules (percentage discount, fixed amount off, free trial for subscriptions). Customers enter promo codes at checkout and see a real-time discount preview before committing. The backend validates rules (expiry, usage limits, per-user limits, minimum purchase, creator scope), applies the discount to the transaction, and records each redemption for analytics. A reusable `PromoCodeInput` component integrates into all checkout flows (subscription, shop, and potentially VOD).

The implementation adds a `promo_codes` DynamoDB table with GSIs for creator lookup and code-string lookup, extends existing checkout routers with an optional `promo_code` field, and creates frontend management and checkout integration components. All promo code strings are case-insensitive and normalized to uppercase.

---

## 2. Detailed Problem Analysis

### User Stories

| As a... | I want to... | So that... |
|---------|-------------|-----------|
| Creator | Create a "25% off first month" promo code | I can attract new subscribers with a discount |
| Creator | Create a "$5 off" fixed discount code for my shop | I can run a holiday promotion |
| Creator | Create a "7-day free trial" code for subscriptions | I can let people try before they buy |
| Creator | Set a max usage count on a promo code | I can limit the promotion to the first 100 users |
| Creator | Set a per-user limit (1 use per person) | I can prevent repeat abuse of the same code |
| Creator | Set an expiry date on a promo code | The promotion ends automatically |
| Creator | Deactivate a promo code before it expires | I can stop a promotion early if needed |
| Creator | See redemption stats for each code | I can measure which promotions drive conversions |
| Customer | Enter a promo code at subscription checkout | I get the advertised discount |
| Customer | Enter a promo code at shop checkout | I save money on my purchase |
| Customer | See the discount preview before paying | I confirm the code works and know the final price |

### Pain Points

1. **No promotional pricing**: Creators have no tools to run discounts, making it harder to acquire new subscribers.
<!-- CORRECTED: Creators CAN create percentage discount codes via POST /api/creators/{id}/discounts (subscription_server.py:1573). The existing system supports percent_off (1-100%), duration (once/repeating/forever), and active/inactive toggle. The real pain point is that the system is LIMITED -- no fixed-amount discounts, no usage caps, no per-user limits, no expiry, no cross-checkout-type support, and no redemption analytics. -->
2. **No growth hacking levers**: Without promo codes, creators cannot do influencer campaigns ("use code CREATOR20 for 20% off"), limited-time sales, or loyalty rewards.
<!-- CORRECTED: "CREATOR20 for 20% off" IS possible today via the existing discount code system. What's missing is usage limits and expiry dates needed for campaigns. -->
3. **No redemption tracking**: Even if a manual discount were applied (e.g., through a reduced subscription plan), there is no way to attribute it to a specific promotional campaign.
<!-- VERIFIED: No redemption records are created. The discount is applied inline at subscription_server.py:850 but no REDEEM row or analytics are stored. -->
4. **Competitive disadvantage**: Every major creator platform offers promo codes. Their absence here is a feature gap that creators notice.
<!-- CORRECTED: Basic promo codes exist, but lack the features listed in the competitive analysis table (usage limits, per-user limits, min purchase, analytics). -->

### Competitive Analysis

| Platform | Promo codes | Types | Limits | Analytics |
|----------|-----------|-------|--------|-----------|
| Shopify | Full (merchant) | %, fixed, free shipping, BOGO | Uses, per-customer, min purchase, date | Full |
| OnlyFans | Limited (promos tab) | % off, free trial | Duration-based | Basic |
| Patreon | Limited (special offers) | Discount trial | Per-tier | Basic |
| Gumroad | Yes | %, fixed | Uses, date | Full |
| This ticket | Full (creator) | %, fixed, free trial | Uses, per-user, min purchase, date, creator scope | Full |

---

## 3. Technical Architecture

### System Diagram

```
Creator                          Customer                        Backend
   |                                |                               |
   |-- POST /promo-codes --------->|                               |
   |   {code, discount_type,       |                               |
   |    rules...}                   |                               |
   |                                |                +--- DDB -----+
   |                                |                | promo_codes  |
   |                                |                +--------------+
   |                                |                               |
   |                                |-- POST /validate ----------->|
   |                                |   {code, checkout_type,      |
   |                                |    item_price}               |
   |                                |                               |
   |                                |   Validation pipeline:        |
   |                                |   1. Lookup by code (GSI2)    |
   |                                |   2. Check active             |
   |                                |   3. Check expiry             |
   |                                |   4. Check max_uses           |
   |                                |   5. Check per-user limit     |
   |                                |   6. Check applies_to         |
   |                                |   7. Check min_purchase       |
   |                                |   8. Check creator scope      |
   |                                |   9. Calculate discount       |
   |                                |                               |
   |                                |<-- discount preview ----------|
   |                                |                               |
   |                                |-- POST /subscribe ----------->|
   |                                |   {plan_id, promo_code}      |
   |                                |                               |
   |                                |   Apply discount:             |
   |                                |   1. Re-validate code         |
   |                                |   2. Calculate new price      |
   |                                |   3. Atomic increment uses    |
   |                                |   4. Record redemption        |
   |                                |   5. Process payment at       |
   |                                |      discounted price         |
   |                                |                               |
   |                                |<-- discounted receipt --------|
   |                                |                               |
   |-- GET /promo-codes/stats ---->|                               |
   |<-- redemption analytics ------|                               |
```

### Data Flow: Code Redemption at Checkout

1. **Customer enters code**: The `PromoCodeInput` component in the checkout UI sends `POST /ui/promo-codes/validate` with the code string, checkout type, item price, and creator user ID.

2. **Backend validates**: Looks up the code via GSI2 (`CODE#{normalized_code}`). Runs through all validation rules in sequence. Returns either a valid discount preview or an invalid response with a human-readable message.

3. **Customer proceeds**: Seeing the discount preview (e.g., "20% off - You pay $7.99 instead of $9.99"), the customer clicks "Subscribe" or "Checkout".

4. **Checkout endpoint re-validates**: The `POST /api/subscribe` or `POST /ui/catalog/checkout` endpoint receives the `promo_code` field. It re-validates the code (in case it expired or hit max_uses between preview and submit). This is a critical TOCTOU guard.

5. **Apply discount**: The checkout handler calculates the discounted price. For percentage: `final = price - (price * percent / 100)`. For fixed: `final = max(0, price - fixed_amount)`. For free trial: `final = 0` for the trial period, then full price.

6. **Record redemption**: Atomically increments `current_uses` on the promo code (using `UpdateExpression: SET current_uses = current_uses + :one` with condition `current_uses < :max`). Creates a REDEEM row in the same table.

7. **Process payment**: The existing payment flow processes at the final discounted price. The ledger entry includes `promo_code_id` and `discount_cents` fields for reconciliation.

### Component Interactions

- **`app/services/promo_codes.py`** (new): All promo code business logic -- CRUD, validation pipeline, redemption recording.
<!-- NOTE: Consider whether to build new or extend existing. The existing discount logic is inline in subscription_server.py (_get_discount at line 186, _apply_discount at line 190, _is_discount_active at line 568). Moving to a dedicated service file is good practice. -->
- **`app/routers/promo_codes.py`** (new): Creator management endpoints and customer validation endpoint.
<!-- CORRECTED: Creator discount CRUD endpoints ALREADY EXIST in subscription_server.py: POST /api/creators/{id}/discounts (line 1573), GET /api/creators/{id}/discounts (line 1620), POST /api/creators/{id}/discounts/{code}/disable (line 1640). These use DiscountCodeCreateIn (line 466) and DiscountCodeOut (line 474) models. The new router should either replace these or extend them, not duplicate them. -->
- **`app/routers/subscription_server.py`** (extended): Accept optional `promo_code` in subscribe request. Call `promo_codes.validate_and_redeem()` before processing payment.
<!-- CORRECTED: SubscribeIn already has discount_code field (subscription_server.py:332). The subscribe endpoint at line 815 already validates and applies discount codes (lines 840-850). Extension needed: add REDEEM row creation, usage limit check, per-user limit check, and expiry check to the existing flow. -->
- **`app/routers/catalog.py`** (extended): Accept optional `promo_code` in checkout request. Same integration pattern.
<!-- NOTE: catalog.py has NO checkout endpoint. There is no /ui/catalog/checkout or similar. Shop items are managed via CRUD but there is no purchase/checkout flow for catalog items. This integration may require building the checkout flow first. -->
- **`app/services/billing_shared.py`** (extended): `new_ledger_entry()` extended with optional `promo_code_id` and `discount_cents` fields for tracking. <!-- VERIFIED: new_ledger_entry() at billing_shared.py:217-245 accepts **kwargs via meta dict -->
- **Existing `billing_shared.py`**: Used for ledger entries and balance operations. <!-- VERIFIED -->

---

## 4. Data Model Deep Dive

### DynamoDB Table: `promo_codes`

**Table definition for `scripts/local-ddb-init.py`:**
<!-- NOTE: The existing discount codes are stored in the subscriptions table (DDB_SUBSCRIPTIONS) as DISCOUNT# rows under the creator's PK. This ticket proposes a NEW dedicated table, which is a significant migration from the existing data model. Consider: (a) migrating existing DISCOUNT# rows to the new table, or (b) extending the existing single-table pattern. A dedicated table is recommended for the additional GSIs needed (code lookup, redemption tracking). -->
<!-- VERIFIED: TableDef pattern matches local-ddb-init.py:28-35. attr_types={"created_at": "N"} is correct. -->

```python
TableDef(
    os.environ.get("DDB_PROMO_CODES", "PromoCodes"),
    "pk",
    "sk",
    gsi=[
        # GSI1: List codes by creator
        {"index_name": "ByCreatorCreatedAt", "partition_key": "creator_scope", "sort_key": "created_at"},
        # GSI2: Lookup by code string (for validation at checkout)
        {"index_name": "ByCodeString", "partition_key": "code_lookup_pk", "sort_key": "code_lookup_sk"},
    ],
    attr_types={"created_at": "N"},
)
```

**Settings entry for `app/core/settings.py`:**
<!-- NOTE: None of these settings exist yet. Must be added to the frozen Settings dataclass at app/core/settings.py. Follow the existing pattern (e.g., subscriptions_table_name at settings.py:1008). -->

```python
promo_codes_table_name: str = os.environ.get("DDB_PROMO_CODES", "PromoCodes")
promo_codes_enabled: bool = os.environ.get("PROMO_CODES_ENABLED", "1") not in ("0", "false", "False")
promo_code_max_per_creator: int = int(os.environ.get("PROMO_CODE_MAX_PER_CREATOR", "100"))
promo_code_max_discount_percent: int = int(os.environ.get("PROMO_CODE_MAX_DISCOUNT_PERCENT", "100"))
promo_code_max_free_trial_days: int = int(os.environ.get("PROMO_CODE_MAX_FREE_TRIAL_DAYS", "30"))
```

**Tables entry:**

```python
promo_codes: Any
# ...
promo_codes=ddb.Table(S.promo_codes_table_name),
```

### Primary Access Patterns

| Access Pattern | Key Condition | Index | Notes |
|---|---|---|---|
| Get promo code by ID | PK=`PROMO#{code_id}`, SK=`META` | Table | Single get_item |
| List creator's codes | GSI1PK=`CREATOR#{creator_user_id}`, sorted by created_at | ByCreatorCreatedAt | Paginated |
| Lookup by code string | GSI2PK=`CODE#{normalized_code}`, SK=`META` | ByCodeString | At most 1 result |
| List redemptions for code | PK=`PROMO#{code_id}`, SK begins_with `REDEEM#` | Table | Query for stats |
| Check per-user redemption | PK=`PROMO#{code_id}`, SK=`REDEEM#{user_id}#*` | Table | begins_with query |

### Example Items

**Promo code (META row):**

```json
{
  "pk": "PROMO#pc_1a2b3c4d",
  "sk": "META",
  "code_id": "pc_1a2b3c4d",
  "code": "SUMMER25",
  "code_lookup_pk": "CODE#SUMMER25",
  "code_lookup_sk": "META",
  "creator_user_id": "alice-uuid",
  "creator_scope": "CREATOR#alice-uuid",
  "discount_type": "percentage",
  "discount_value": 25,
  "free_trial_days": 0,
  "applies_to": ["subscription", "vod"],
  "min_purchase_cents": 0,
  "max_uses": 100,
  "max_uses_per_user": 1,
  "current_uses": 7,
  "expires_at": 1751040000,
  "active": true,
  "created_at": 1748361600,
  "updated_at": 1748361600
}
```

**Redemption row:**

```json
{
  "pk": "PROMO#pc_1a2b3c4d",
  "sk": "REDEEM#bob-uuid#1748365200",
  "user_id": "bob-uuid",
  "redeemed_at": 1748365200,
  "discount_applied_cents": 250,
  "original_price_cents": 999,
  "final_price_cents": 749,
  "checkout_type": "subscription",
  "checkout_item_id": "plan_gold_monthly"
}
```

**Fixed amount promo code:**

```json
{
  "pk": "PROMO#pc_5e6f7g8h",
  "sk": "META",
  "code_id": "pc_5e6f7g8h",
  "code": "SAVE5",
  "code_lookup_pk": "CODE#SAVE5",
  "code_lookup_sk": "META",
  "creator_user_id": "alice-uuid",
  "creator_scope": "CREATOR#alice-uuid",
  "discount_type": "fixed_amount",
  "discount_value": 500,
  "free_trial_days": 0,
  "applies_to": ["shop"],
  "min_purchase_cents": 1000,
  "max_uses": 0,
  "max_uses_per_user": 1,
  "current_uses": 0,
  "expires_at": 0,
  "active": true,
  "created_at": 1748361600,
  "updated_at": 1748361600
}
```

**Free trial promo code:**

```json
{
  "pk": "PROMO#pc_9i0j1k2l",
  "sk": "META",
  "code_id": "pc_9i0j1k2l",
  "code": "TRYME7",
  "code_lookup_pk": "CODE#TRYME7",
  "code_lookup_sk": "META",
  "creator_user_id": "alice-uuid",
  "creator_scope": "CREATOR#alice-uuid",
  "discount_type": "free_trial",
  "discount_value": 0,
  "free_trial_days": 7,
  "applies_to": ["subscription"],
  "min_purchase_cents": 0,
  "max_uses": 50,
  "max_uses_per_user": 1,
  "current_uses": 0,
  "expires_at": 0,
  "active": true,
  "created_at": 1748361600,
  "updated_at": 1748361600
}
```

---

## 5. API Contract Design

### POST `/ui/promo-codes`

**Request body:**

```json
{
  "code": "SUMMER25",
  "discount_type": "percentage",
  "discount_value": 25,
  "free_trial_days": 0,
  "applies_to": ["subscription", "vod"],
  "min_purchase_cents": 0,
  "max_uses": 100,
  "max_uses_per_user": 1,
  "expires_at": 1751040000
}
```

**Response 201:**

```json
{
  "code_id": "pc_1a2b3c4d",
  "code": "SUMMER25",
  "discount_type": "percentage",
  "discount_value": 25,
  "free_trial_days": 0,
  "applies_to": ["subscription", "vod"],
  "min_purchase_cents": 0,
  "max_uses": 100,
  "max_uses_per_user": 1,
  "current_uses": 0,
  "expires_at": 1751040000,
  "active": true,
  "created_at": 1748361600
}
```

**Error responses:**

| Status | Body | Condition |
|--------|------|-----------|
| 400 | `{"detail": "Code must be 3-30 alphanumeric characters"}` | Invalid code format |
| 400 | `{"detail": "discount_value must be between 1 and 100 for percentage type"}` | Invalid percent |
| 400 | `{"detail": "free_trial_days required for free_trial type"}` | Missing trial days |
| 400 | `{"detail": "free_trial applies only to subscriptions"}` | Free trial + non-subscription in applies_to |
| 400 | `{"detail": "Maximum 100 promo codes per creator"}` | Creator limit exceeded |
| 409 | `{"detail": "A promo code with this string already exists"}` | Duplicate code string (any creator) |

### GET `/ui/promo-codes`

**Query params:** `cursor`, `limit` (default 20), `active_only` (default false).

**Response 200:**

```json
{
  "items": [
    {
      "code_id": "pc_1a2b3c4d",
      "code": "SUMMER25",
      "discount_type": "percentage",
      "discount_value": 25,
      "applies_to": ["subscription", "vod"],
      "max_uses": 100,
      "current_uses": 7,
      "expires_at": 1751040000,
      "active": true,
      "created_at": 1748361600
    }
  ],
  "next_cursor": null
}
```

### GET `/ui/promo-codes/{code_id}`

**Response 200:** Full promo code object plus redemption stats.

```json
{
  "code_id": "pc_1a2b3c4d",
  "code": "SUMMER25",
  "discount_type": "percentage",
  "discount_value": 25,
  "free_trial_days": 0,
  "applies_to": ["subscription", "vod"],
  "min_purchase_cents": 0,
  "max_uses": 100,
  "max_uses_per_user": 1,
  "current_uses": 7,
  "expires_at": 1751040000,
  "active": true,
  "created_at": 1748361600,
  "stats": {
    "total_redemptions": 7,
    "total_discount_cents": 1743,
    "redemptions": [
      {"user_id": "bob-uuid", "redeemed_at": 1748365200, "discount_applied_cents": 250, "checkout_type": "subscription"},
      {"user_id": "charlie-uuid", "redeemed_at": 1748370000, "discount_applied_cents": 250, "checkout_type": "subscription"}
    ]
  }
}
```

### PATCH `/ui/promo-codes/{code_id}`

**Request body (all fields optional):**

```json
{
  "active": false,
  "expires_at": 1751040000,
  "max_uses": 200
}
```

**Response 200:** Updated promo code object.

### DELETE `/ui/promo-codes/{code_id}`

Soft deactivates (sets `active=false`). Does not physically delete.

**Response 200:**

```json
{
  "ok": true,
  "code_id": "pc_1a2b3c4d",
  "active": false
}
```

### POST `/ui/promo-codes/validate`

**Request body:**

```json
{
  "code": "summer25",
  "checkout_type": "subscription",
  "item_price_cents": 999,
  "creator_user_id": "alice-uuid"
}
```

**Response 200 (valid):**

```json
{
  "valid": true,
  "code_id": "pc_1a2b3c4d",
  "discount_type": "percentage",
  "discount_cents": 250,
  "final_price_cents": 749,
  "message": null
}
```

**Response 200 (invalid -- not 4xx, because the request itself is valid):**

```json
{
  "valid": false,
  "code_id": null,
  "discount_type": null,
  "discount_cents": 0,
  "final_price_cents": 999,
  "message": "This code has expired"
}
```

**Possible `message` values:**

| Message | Condition |
|---------|-----------|
| `"Code not found"` | No active code with this string |
| `"This code has expired"` | `expires_at > 0 AND expires_at < now_ts()` |
| `"This code has been fully redeemed"` | `current_uses >= max_uses AND max_uses > 0` |
| `"You have already used this code"` | REDEEM row exists for this user and `max_uses_per_user` reached |
| `"This code does not apply to this checkout type"` | `checkout_type not in applies_to` |
| `"Minimum purchase of $X.XX required"` | `item_price_cents < min_purchase_cents` |
| `"This code is not valid for this creator"` | `creator_user_id != promo.creator_user_id` |
| `"Free trial codes are only valid for subscriptions"` | `discount_type == "free_trial" AND checkout_type != "subscription"` |

### POST `/api/plans/{plan_id}/subscribe` (extended)
<!-- CORRECTED: Actual endpoint path is /api/plans/{plan_id}/subscribe (subscription_server.py:815), not /api/subscribe -->

**Additional field in request body:**

```json
{
  "plan_id": "plan_gold_monthly",
  "promo_code": "SUMMER25"
}
```
<!-- CORRECTED: SubscribeIn (subscription_server.py:329-333) already has a `discount_code` field, not `promo_code`. The field should be renamed to match or a new field added alongside the existing one. Current fields: subscriber_id, interval (month/year), discount_code, trial_days. -->

**Behavior**: If `promo_code` is provided, validate and redeem. Calculate discounted price. If free trial, set subscription to trial period. If invalid, return 400 with the validation message.
<!-- NOTE: Existing behavior at subscription_server.py:840-850 already validates discount_code and applies percentage discount. Extension needed: add TOCTOU re-validation, atomic current_uses increment, REDEEM row creation, and support for new discount types (fixed_amount, free_trial). -->

### POST `/ui/catalog/checkout` (extended)
<!-- CORRECTED: This endpoint DOES NOT EXIST. catalog.py has no checkout/purchase endpoint. Only CRUD operations for catalog items exist (create, list, get, update, delete). A checkout flow for shop items must be built from scratch before promo codes can be integrated. Consider deferring shop promo code integration to a separate ticket. -->

**Additional field in request body:**

```json
{
  "items": [...],
  "promo_code": "SAVE5"
}
```

**Behavior**: Validate code against the cart total and the catalog item's creator. Apply discount to the order total.

---

## 6. Frontend Component Design

### Component Tree

```
{/* Creator: Promo Code Management */}
<PromoCodeManagerPage>
  <PageHeader title="Promo Codes" icon={Tag} />
  <Button onClick={() => setShowCreateDialog(true)}>Create Code</Button>
  <DataTable data={promoCodes}>
    <Column header="Code" render={r => <Badge>{r.code}</Badge>} />
    <Column header="Type" render={r => discountLabel(r)} />
    <Column header="Usage" render={r => `${r.current_uses}/${r.max_uses || "∞"}`} />
    <Column header="Status" render={r => <StatusBadge active={r.active} expired={isExpired(r)} />} />
    <Column header="Expires" render={r => r.expires_at ? formatDate(r.expires_at) : "Never"} />
    <Column header="Actions">
      <Button variant="ghost" onClick={() => toggleActive(r)}>
        {r.active ? "Deactivate" : "Activate"}
      </Button>
      <Button variant="ghost" onClick={() => setViewStats(r)}>Stats</Button>
    </Column>
  </DataTable>

  <CreatePromoDialog
    open={showCreateDialog}
    onSubmit={createMutation.mutate}
    onClose={() => setShowCreateDialog(false)}
  />

  <PromoStatsDialog
    code={viewStats}
    open={!!viewStats}
    onClose={() => setViewStats(null)}
  />
</PromoCodeManagerPage>

{/* Customer: Checkout with promo code (reusable component) */}
<PromoCodeInput
  creatorUserId={creatorId}
  checkoutType="subscription"
  itemPriceCents={999}
  onValidCode={(result) => setAppliedDiscount(result)}
  onClear={() => setAppliedDiscount(null)}
/>
```

### State Management

- **React Query keys**:
  - `["promo-codes", "list", { active_only }]`: Creator's promo code list.
  - `["promo-codes", code_id, "stats"]`: Redemption stats for a specific code.
  - `["promo-codes", "validate", { code, type, price, creator }]`: Validation result (not a query -- done via mutation for freshness).

- **Mutations**:
  - `useCreatePromoCode`: POST /ui/promo-codes. Invalidates `["promo-codes", "list"]`.
  - `useUpdatePromoCode`: PATCH /ui/promo-codes/{id}. Invalidates list + stats.
  - `useDeletePromoCode`: DELETE /ui/promo-codes/{id}. Invalidates list.
  - `useValidatePromoCode`: POST /ui/promo-codes/validate. Returns validation result inline (not cached).

### PromoCodeInput Component

A reusable component used in checkout flows:

```typescript
interface PromoCodeInputProps {
  creatorUserId: string;
  checkoutType: "subscription" | "vod" | "shop";
  itemPriceCents: number;
  onValidCode: (result: ValidatePromoOut) => void;
  onClear: () => void;
}
```

**Visual states:**
1. **Empty**: Text input + "Apply" button (disabled).
2. **Typing**: Text input with value + "Apply" button (enabled).
3. **Validating**: Input disabled, loading spinner on button.
4. **Valid**: Input with green border, green checkmark icon, discount text below ("25% off - Save $2.50"). "Remove" (X) button replaces "Apply".
5. **Invalid**: Input with red border, red X icon, error message below (e.g., "This code has expired"). Input remains editable to try another code.

### CreatePromoDialog

A shadcn/ui `Dialog` with form fields:

1. **Code** (text input): Auto-uppercased as user types. Pattern: `^[A-Za-z0-9_-]+$`. Validation feedback if duplicate.
2. **Discount type** (radio group): "Percentage off", "Fixed amount off", "Free trial".
3. **Discount value** (number input): Shows "%" suffix for percentage, "$" prefix for fixed. Hidden for free trial.
4. **Free trial days** (number input): Only shown when "Free trial" selected.
5. **Applies to** (checkbox group): "Subscriptions", "VOD", "Shop". At least one required.
6. **Limits section** (collapsible):
   - Max total uses (0 = unlimited)
   - Max uses per user (default 1)
   - Minimum purchase amount
7. **Expiry** (date picker): Optional. "No expiry" checkbox.

### Navigation Integration

- **Route**: `/promo` added to `App.tsx` with lazy loading.
- **Sidebar** (`Sidebar.tsx` + `AppShell.tsx`): Add `{ icon: Tag, label: "Promo Codes", path: "/promo" }` under Monetization group.
- **MobileNav**: Add "Promo Codes" to `MORE_LINKS`.

---

## 7. Security & Privacy Considerations

### Authentication & Authorization

- Creator endpoints (CRUD): `require_ui_session`. Creator can only manage their own codes. The `creator_user_id` is set from the session, not from the request body.
<!-- CORRECTED: Existing discount endpoints in subscription_server.py use X-User-Id header auth (via require_user() at line 34), NOT require_ui_session. The subscription_server router uses X-User-Id header authentication throughout. If new promo code endpoints use require_ui_session (cookie auth), this is a deliberate auth pattern change that should be documented. The existing discount CRUD at subscription_server.py:1573-1660 uses require_user(x_user_id, creator_id). -->
- Validate endpoint: `require_ui_session`. Any authenticated user can validate a code.
- Checkout integration: Uses existing auth from the checkout endpoint.
<!-- NOTE: subscribe endpoint at subscription_server.py:815 uses X-User-Id header, not require_ui_session. -->

### Input Validation

- Code string: `^[A-Za-z0-9_-]{3,30}$`. Normalized to uppercase before storage and lookup.
- `discount_value`: For percentage: 1-100. For fixed: 1-`REFUND_MAX_AMOUNT_CENTS`.
- `free_trial_days`: 1-`promo_code_max_free_trial_days` (default 30).
- `applies_to`: Non-empty subset of `["subscription", "vod", "shop"]`.
- `max_uses`: >= 0 (0 = unlimited).
- `max_uses_per_user`: >= 0 (0 = unlimited).
- `expires_at`: Must be in the future if provided.

### Data Protection

- Promo codes do not contain PII. Redemption records include `user_id` but this is the same level of association as billing ledger entries.
- Code strings are not secret -- they are designed to be shared publicly. However, the redemption records (who used which code) are only visible to the code's creator.

### Abuse Prevention

- **Code uniqueness**: Global uniqueness on the code string (any creator). Prevents confusion and phishing.
- **Per-user limit**: Default `max_uses_per_user=1`. Prevents a single user from using the same code repeatedly.
- **Atomic increment**: `current_uses` is atomically incremented with a condition check (`current_uses < max_uses`). This prevents race conditions where multiple users redeem simultaneously and exceed the limit.
- **TOCTOU guard**: The checkout endpoint re-validates the code at redemption time, not just at preview time. A code that expired or hit its limit between preview and checkout is correctly rejected.
- **Creator scope**: A code created by Creator A cannot be used on Creator B's content. This prevents cross-creator discount abuse.
- **Minimum purchase**: Prevents using a "$5 off" code on a $1 item to get it free.
- **Creator code limit**: Max 100 codes per creator (prevents DDB hot partition from a single creator creating thousands of codes).

---

## 8. Performance & Scalability

### Query Cost Analysis

| Operation | DDB Operations | Estimated Cost |
|-----------|---------------|----------------|
| Create code | 1 Query (GSI2 dedup) + 1 PutItem | 1 WCU + 1 RCU |
| List creator's codes | 1 Query (GSI1) | ~1 RCU |
| Validate code | 1 Query (GSI2 lookup) + 1 Query (per-user check) | ~2 RCU |
| Redeem code | 1 UpdateItem (atomic increment) + 1 PutItem (REDEEM row) | 2 WCU |
| Get code stats | 1 GetItem (META) + 1 Query (REDEEM rows) | ~2 RCU |

### Caching Strategy

- **Validation at checkout**: No caching -- must always check DDB for current `current_uses` and `active` state.
- **Creator's code list**: React Query `staleTime: 30 * 1000` (30 seconds).
- **Code stats**: React Query `staleTime: 60 * 1000` (1 minute).

### Hot Partition Risks

- **Popular code**: A viral promo code could receive thousands of validation requests per second, all hitting the same DDB item (via GSI2). Mitigation: DDB PAY_PER_REQUEST handles bursty reads well. If a single code exceeds 3,000 RCU, consider adding a DAX (DynamoDB Accelerator) cache for read-heavy validation.
- **Atomic increment contention**: High-concurrency redemption of the same code could cause DDB throttling on the atomic update. Mitigation: DDB handles conditional updates well up to ~1,000 WCU. For codes with 10,000+ uses, consider a distributed counter pattern (out of scope for v1).

### Known Bottlenecks

1. **Redemption stats query**: For a code with 10,000+ redemptions, the Query on `REDEEM#` rows returns a large result set. Mitigation: Paginate with `Limit=50` in the API; pre-aggregate total_redemptions and total_discount_cents in the META row.
2. **Code string lookup is GSI-based**: GSI2 uses eventual consistency. In rare cases, a newly created code might not be found by validation for a few hundred milliseconds. Mitigation: Acceptable for the use case (creators typically share codes minutes/hours after creation).

---

## 9. Migration & Rollback Plan

### Deployment Phases

1. **Phase 1 -- Table + settings**: Add `PromoCodes` table to `local-ddb-init.py`. Add settings. No behavioral change.
2. **Phase 2 -- Backend service + router**: Deploy `promo_codes.py` service and `promo_codes.py` router behind `PROMO_CODES_ENABLED` flag.
3. **Phase 3 -- Checkout integration**: Extend `subscription_server.py` and `catalog.py` to accept optional `promo_code`. When no code is provided, behavior is identical to current.
4. **Phase 4 -- Frontend management**: Deploy `PromoCodeManagerPage`, `CreatePromoDialog`, `PromoStats`. Add route and sidebar.
5. **Phase 5 -- Frontend checkout integration**: Deploy `PromoCodeInput` component into subscription and shop checkout flows.
6. **Phase 6 -- Enable in production**: Set `PROMO_CODES_ENABLED=true`.

### Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `PROMO_CODES_ENABLED` | `true` (dev), `false` (prod) | Master enable/disable |
| `PROMO_CODE_MAX_PER_CREATOR` | `100` | Max codes per creator |
| `PROMO_CODE_MAX_DISCOUNT_PERCENT` | `100` | Max percentage discount allowed |
| `PROMO_CODE_MAX_FREE_TRIAL_DAYS` | `30` | Max free trial length |

### Rollback Steps

1. Set `PROMO_CODES_ENABLED=false`. All promo code endpoints return 404. Checkout endpoints ignore `promo_code` field (treat as if not provided).
2. Existing promo codes and redemption records remain in DDB but are inert.
3. Any subscriptions or purchases made with a discount remain at the discounted price (no clawback).

---

## 10. Testing Strategy

### Unit Tests (`tests/test_promo_codes.py`)

| Test | Description |
|------|-------------|
| `test_create_percentage_code` | Create code; assert all fields stored correctly, code normalized to uppercase. |
| `test_create_fixed_amount_code` | Create fixed discount code; assert discount_value stored in cents. |
| `test_create_free_trial_code` | Create free trial code; assert free_trial_days set, applies_to contains only "subscription". |
| `test_create_duplicate_code` | Create same code string twice; assert 409 on second. |
| `test_create_invalid_code_format` | Code with spaces/special chars; assert 400. |
| `test_create_exceeds_creator_limit` | Create 101st code; assert 400. |
| `test_validate_valid_percentage` | Validate valid code; assert discount_cents = price * percent / 100. |
| `test_validate_valid_fixed` | Validate fixed code; assert discount_cents = discount_value (capped at price). |
| `test_validate_expired` | Code with expires_at in past; assert valid=false, message="expired". |
| `test_validate_exhausted` | Code with current_uses >= max_uses; assert valid=false. |
| `test_validate_per_user_limit` | User already redeemed; assert valid=false, message="already used". |
| `test_validate_wrong_checkout_type` | Code applies to subscription; validate for shop; assert valid=false. |
| `test_validate_wrong_creator` | Code belongs to creator A; validate for creator B; assert valid=false. |
| `test_validate_below_min_purchase` | Item price < min_purchase_cents; assert valid=false. |
| `test_validate_free_trial_non_subscription` | Free trial code + checkout_type=shop; assert valid=false. |
| `test_redeem_increments_uses` | Redeem code; assert current_uses incremented. |
| `test_redeem_creates_record` | Redeem code; assert REDEEM row created with correct fields. |
| `test_redeem_atomic_limit` | Set max_uses=1; two concurrent redeems; assert only one succeeds. |
| `test_deactivate_code` | Deactivate; validate; assert valid=false. |
| `test_update_expiry` | Extend expiry; validate; assert valid=true. |
| `test_stats_calculation` | 3 redemptions; get stats; assert total_redemptions=3, total_discount_cents correct. |
| `test_discount_capped_at_price` | Fixed $10 off on $5 item; assert final_price_cents=0, discount_cents=500. |

### E2E Test Matrix (`frontend/e2e/promo-codes.spec.ts`)

**Section A: Promo Code CRUD API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Creator creates a percentage discount code | 201, code stored as uppercase |
| 2 | Creator creates a fixed amount discount code | 201, discount_type=fixed_amount |
| 3 | Duplicate code string returns 409 | Create same code twice; 409 |
| 4 | Creator lists their codes | GET /ui/promo-codes; array includes created codes |
| 5 | Creator deactivates a code | DELETE /ui/promo-codes/{id}; GET code; active=false |
| 6 | Creator updates code expiry | PATCH with new expires_at; GET code; updated |

**Section B: Promo Validation API (7 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Valid percentage code returns correct discount preview | valid=true, discount_cents = 25% of price |
| 2 | Valid fixed amount code returns correct discount | valid=true, discount_cents = discount_value |
| 3 | Expired code returns invalid with "expired" message | valid=false, message contains "expired" |
| 4 | Exhausted code (max_uses reached) returns invalid | Redeem max_uses times; validate; valid=false |
| 5 | Per-user limit exceeded returns invalid | Redeem once; validate again; valid=false |
| 6 | Code from wrong creator returns invalid | Validate Alice's code for Bob's content; valid=false |
| 7 | Below minimum purchase returns invalid | min_purchase=1000, item=500; valid=false |

**Section C: Checkout Integration (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Subscription checkout with valid promo code applies discount | POST subscribe with promo_code; assert discounted price in response |
| 2 | Shop checkout with valid promo code applies discount | POST catalog checkout with promo_code; assert discounted total |
| 3 | Checkout with invalid code returns 400 | POST subscribe with expired code; 400 |
| 4 | Redemption record created after successful checkout | POST subscribe; query REDEEM rows; 1 found |

**Section D: Promo UI (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Promo code manager page lists creator's codes | Navigate to /promo; table with created codes visible |
| 2 | Create promo dialog submits new code | Fill form; submit; toast confirmation; new code in table |
| 3 | Promo code input on checkout shows discount preview | Enter code in PromoCodeInput; green checkmark + discount text visible |

---

## 11. Monitoring & Alerting

### Metrics to Track

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `promo_codes_created_total` | Counter | `discount_type` | Codes created by type |
| `promo_code_validations_total` | Counter | `result` (valid/invalid), `reason` | Validation attempts |
| `promo_code_redemptions_total` | Counter | `discount_type`, `checkout_type` | Successful redemptions |
| `promo_code_discount_cents_total` | Counter | `discount_type` | Total discount amount given |
| `promo_code_validation_duration_seconds` | Histogram | - | Validation latency |
| `promo_code_redemption_duration_seconds` | Histogram | - | Redemption (atomic increment + record) latency |

### Dashboard Queries

- **Promo code adoption**: `rate(promo_codes_created_total[24h])` -- new codes per day.
- **Redemption rate**: `promo_code_redemptions_total / promo_code_validations_total{result="valid"}` -- what fraction of valid codes are actually used.
- **Revenue impact**: `promo_code_discount_cents_total` per day -- how much discount is being given.

### Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Validation error spike | `promo_code_validations_total{result="invalid", reason="not_found"}` > 1000 in 5 min | Warning (possible brute-force) |
| Redemption failures | `promo_code_redemption_duration_seconds` P99 > 2 seconds | Warning (DDB throttling) |
| Excessive discount giving | `promo_code_discount_cents_total` > $50,000 in 24 hours | Warning (finance review) |

---

## 12. Open Questions & Risks

### Unresolved Decisions

1. **Stacking**: Can a customer use multiple promo codes on a single checkout? Recommendation: No. One code per checkout for v1. Stacking adds significant complexity (order of application, interaction between percentage and fixed).

2. **Auto-generated codes**: Should creators be able to generate bulk unique codes (e.g., 1000 unique single-use codes for a giveaway)? Recommendation: Defer. Single shared codes cover 95% of use cases.

3. **Referral codes**: Should promo codes support a "referral" mode where the referrer also gets a benefit? Recommendation: Defer. Referral programs are a separate feature with different data model needs.

4. **VOD integration**: The existing VOD purchase flow may not have a clear `checkout` endpoint to hook into. Should this ticket create one, or defer VOD promo codes? Recommendation: Implement for subscription and shop only in v1. Add VOD when VOD checkout is formalized.
<!-- NOTE: Neither VOD nor shop has a checkout endpoint. The only checkout-like flow is subscription subscribe (subscription_server.py:815). Recommend implementing for subscriptions only in v1, deferring both shop and VOD. -->

5. **Stripe Coupon sync**: Should promo codes be synced to Stripe Coupons for subscription discounts? Pro: Stripe handles recurring discount logic natively. Con: Adds Stripe API coupling. Recommendation: Apply discount on our side and pass the discounted amount to Stripe. Keeps the promo logic centralized.

### Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Race condition on redemption | Two users redeem simultaneously and both succeed | DDB conditional update with `current_uses < :max` prevents this |
| TOCTOU at checkout | Code expires between validate and submit | Re-validate at checkout; reject with clear message |
| GSI2 eventual consistency | Newly created code not found for ~100ms | Acceptable; creators share codes minutes after creation |
| Hot partition on viral code | DDB throttling on popular code | PAY_PER_REQUEST handles bursts; consider DAX for extreme cases |

---

## 13. Implementation Timeline

### Phase 1: Backend (Days 1-3)

| Day | Task |
|-----|------|
| 1 | Add table definition, settings, table handle. Create `app/services/promo_codes.py` with CRUD (create, list, get, update, deactivate) and validation pipeline. Create Pydantic models. |
| 2 | Implement redemption logic (atomic increment, REDEEM row creation). Implement stats aggregation. Create `app/routers/promo_codes.py` with all creator + customer endpoints. Register in `app/main.py`. |
| 3 | Extend `subscription_server.py` and `catalog.py` checkout endpoints with optional `promo_code` field. Wire up validation and redemption at checkout. Write unit tests. |

### Phase 2: Unit Tests + Edge Cases (Day 4)

| Day | Task |
|-----|------|
| 4 | Write comprehensive unit tests (22 tests). Test all validation rules, atomic redemption, discount calculation, creator scope, per-user limits. Fix bugs found during testing. |

### Phase 3: Frontend (Days 5-6)

| Day | Task |
|-----|------|
| 5 | Create `PromoCodeManagerPage.tsx`, `CreatePromoDialog.tsx`, `PromoStats.tsx`. Create API endpoints and TypeScript types. Add route, sidebar entry, mobile nav. |
| 6 | Create `PromoCodeInput.tsx` (reusable component). Integrate into subscription checkout dialog and shop checkout page. Wire up all React Query hooks and mutations. |

### Phase 4: E2E Tests + Polish (Days 7-8)

| Day | Task |
|-----|------|
| 7 | Write E2E tests Sections A + B (CRUD + validation API). Seed test data for promo codes. |
| 8 | Write E2E tests Sections C + D (checkout integration + UI). Integration testing. Bug fixes. Final code review. |

---

## Appendix: Codebase Citations

> **KEY FINDING**: A discount code system ALREADY EXISTS in `subscription_server.py`. The ticket incorrectly presents promo codes as a greenfield feature. Existing capabilities: percentage-based discount codes (1-100% off), duration support (once/repeating/forever), creator CRUD (create/list/disable), and integration with the subscribe endpoint. The ticket should be re-scoped as an ENHANCEMENT to add: fixed-amount discounts, free trial codes, usage limits, per-user limits, expiry dates, redemption tracking/analytics, cross-checkout-type support, and a dedicated PromoCodeInput checkout component.

| Claim / Reference | Status | Actual Location | Notes |
|---|---|---|---|
| No discount hook in subscription checkout | **INCORRECT** | `app/routers/subscription_server.py:840-850` | `discount_code` field exists in `SubscribeIn`; `_get_discount()` + `_apply_discount()` applied before payment |
| No discount hook in shop checkout | **PARTIALLY CORRECT** | `app/routers/catalog.py` | catalog.py has NO checkout endpoint at all -- only CRUD |
| `SubscribeIn` model | VERIFIED | `subscription_server.py:329-333` | Fields: `subscriber_id`, `interval`, `discount_code`, `trial_days` |
| `_get_discount()` | VERIFIED | `subscription_server.py:186-187` | Looks up `DISCOUNT#{code.upper()}` under creator PK |
| `_apply_discount()` | VERIFIED | `subscription_server.py:190-195` | Percentage only: `price * (100 - percent) / 100` |
| `_is_discount_active()` | VERIFIED | `subscription_server.py:568-569` | Simply checks `discount.get("active", True)` -- no expiry/usage check |
| `_discount_sk()` | VERIFIED | `subscription_server.py:182-183` | Returns `f"DISCOUNT#{code.upper()}"` |
| `DiscountCodeCreateIn` model | VERIFIED | `subscription_server.py:466-471` | Fields: `code` (3-32 chars), `percent_off` (1-100), `duration`, `duration_months`, `active` |
| `DiscountCodeOut` model | VERIFIED | `subscription_server.py:474-481` | Fields: `code`, `percent_off`, `duration`, `duration_months`, `active`, `created_at`, `updated_at` |
| `POST /api/creators/{id}/discounts` | VERIFIED | `subscription_server.py:1573-1617` | Creator creates discount code; stores as `DISCOUNT#` row |
| `GET /api/creators/{id}/discounts` | VERIFIED | `subscription_server.py:1620-1637` | Lists all `DISCOUNT#` rows for creator |
| `POST /api/creators/{id}/discounts/{code}/disable` | VERIFIED | `subscription_server.py:1640-1660+` | Sets `active=false` |
| Discount codes stored in subscriptions table | VERIFIED | Uses `ddb_put_item()` which writes to subscriptions DDB table | Single-table pattern under `CREATOR#{creator_id}` PK |
| Auth for existing discount endpoints | VERIFIED | `subscription_server.py` `require_user(x_user_id)` | Uses `X-User-Id` header, NOT `require_ui_session` |
| Subscribe endpoint path | VERIFIED | `subscription_server.py:815` | `POST /api/plans/{plan_id}/subscribe` (not `/api/subscribe`) |
| `new_ledger_entry()` | VERIFIED | `app/services/billing_shared.py:217-245` | Supports `meta` dict for additional fields |
| Proposed settings (promo_codes_table_name, etc.) | DO NOT EXIST YET | Must add to `app/core/settings.py` | |
| `POST /ui/catalog/checkout` endpoint | **DOES NOT EXIST** | `app/routers/catalog.py` | No checkout/purchase flow for shop items |
| `require_ui_session` | VERIFIED | `app/services/sessions.py:283` | Different auth pattern from existing discount endpoints |
| TableDef pattern | VERIFIED | `scripts/local-ddb-init.py:28-35` | |


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_promo_codes.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_promo_001_create` | Create primary entity; 201 |
| 2 | `test_promo_001_read` | Read back entity; correct fields |
| 3 | `test_promo_001_update` | Update entity; 200; changes reflected |
| 4 | `test_promo_001_delete` | Delete entity; 200/204 |
| 5 | `test_promo_001_auth_required` | No auth; 401 |
| 6 | `test_promo_001_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/promo-codes.spec.ts` -- 14 tests

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
| SHOP-002 | Required | Promo checkout integration consumes promo validation API |

### Merge Strategy

**Independent** -- New promo_codes table; no conflicts with existing features.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/promo-codes.spec.ts`
