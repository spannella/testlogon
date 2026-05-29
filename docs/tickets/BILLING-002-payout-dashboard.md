# BILLING-002: Payout Dashboard Frontend

**Ticket**: BILLING-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 6-8 days

---

## 1. Executive Summary

The backend payout system is fully implemented and E2E tested. Four endpoints exist in `app/routers/creator_payouts.py:35-105`: balance retrieval, payout request creation, payout listing, and payout cancellation. The earnings subsystem (`app/routers/creator_earnings.py:19-61`) provides summary and transaction listing. All endpoints use `require_ui_session` authentication and return properly modeled Pydantic responses. E2E tests in `frontend/e2e/creator-payouts.spec.ts` verify the API layer.

However, there is no frontend page. No `/payouts` route exists in `App.tsx`. No PayoutDashboard component exists anywhere in `frontend/src/pages/`. The sidebar (`Sidebar.tsx`) has no "Payouts" link. Creators cannot see their earnings breakdown, request withdrawals, or track payout history through the UI -- they must use API calls directly.

This ticket creates a complete Payout Dashboard page with: balance summary cards (available, pending, on-hold, total earned), an earnings breakdown pie chart, a payout request form with validation, a paginated payout history table, and an earnings transaction log. The page aggregates data from both the payouts and earnings endpoints into a single unified creator monetization dashboard. The dashboard is a critical path feature for creator retention -- without it, creators accumulate income that they cannot access, inspect, or withdraw through the application interface.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: View Available Balance**

As a creator, I want to see my available balance at a glance so that I know how much I can withdraw.

Acceptance criteria:
- Dashboard shows four balance cards: Available Balance, Pending Payouts, On Hold, and Total Earned.
- All amounts are displayed in USD currency format (e.g., "$125.00").
- The Available Balance card has green styling and is the most prominent.
- The minimum payout threshold ($10.00) is displayed near the request form.
- Balance values update automatically after a payout request or cancellation.

**US-2: Request a Payout**

As a creator, I want to request a payout of my available earnings so that I can receive the money I have earned.

Acceptance criteria:
- Form includes an amount input (in dollars, converted to cents on submit), a method selector (bank_transfer, paypal), and an optional notes field.
- Client-side validation prevents: amounts below the minimum ($10), amounts exceeding available balance, empty amount.
- On submit, form sends `POST /ui/payouts/request` and shows a success toast on 201.
- Duplicate request (409) shows "You already have a pending payout request" toast.
- After success, form fields clear and balance/history queries re-fetch automatically.

**US-3: View Payout History**

As a creator, I want to see the status of all my payout requests so that I can track when I will receive my money.

Acceptance criteria:
- Paginated table shows: Date, Amount, Method, Status (color-coded badge), and Actions columns.
- Status badges: green for "completed", yellow for "requested", blue for "approved", orange for "processing", red for "rejected", grey for "cancelled".
- "Load more" button appears when a `next_cursor` is returned by the API.
- Completed payouts show the `completed_at` date in the Date column.
- Rejected payouts show the `reject_reason` in an expandable row detail.

**US-4: Cancel a Pending Payout**

As a creator, I want to cancel a pending payout request so that the funds are returned to my available balance.

Acceptance criteria:
- Cancel button appears only on payouts with status "requested" or "approved".
- Clicking Cancel opens a confirmation dialog: "Are you sure you want to cancel this payout request for $X.XX?"
- On confirm, sends `POST /ui/payouts/{payout_id}/cancel` and shows a success toast.
- After cancellation, status badge changes to "cancelled" and balance card updates.
- No cancel button on "processing", "completed", "rejected", or "cancelled" payouts.

**US-5: View Earnings Breakdown**

As a creator, I want to see a breakdown of my earnings by source so that I understand where my income comes from.

Acceptance criteria:
- Pie chart (or bar chart) shows five categories: Subscriptions, Tips, Unlocks, VOD Purchases, Other.
- Each category shows its dollar amount and percentage of total.
- Date range picker filters the summary data (calls `GET /ui/earnings/summary?from_ts=...&to_ts=...`).
- Empty state shows "No earnings yet" when total is zero.

**US-6: View Earnings Transactions**

As a creator, I want to see individual earning transactions so that I can reconcile my income.

Acceptance criteria:
- Paginated table shows: Date/Time, Amount, Category (badge), and Reason columns.
- Date range filter matches the earnings summary filter and applies to transactions.
- Cursor-based "Load more" pagination via `next_cursor`.
- Transaction `meta` object is viewable via an expandable detail row (shows content_type, content_id, tipper_user_id).

**US-7: Filter Earnings by Date Range**

As a creator, I want to filter my earnings by date range so that I can analyze trends over specific periods.

Acceptance criteria:
- Date range picker with presets: "Last 7 days", "Last 30 days", "Last 90 days", "All time".
- Custom date range selection via calendar popover.
- Changing the date range updates both the summary breakdown and the transactions table.
- API calls include `from_ts` and `to_ts` query parameters as Unix timestamps.

### 2.2 Pain Points

1. **Zero visibility into earnings**: Creators accumulate tip/subscription/unlock income but have no way to see it without API knowledge. This is the single largest creator experience gap.
2. **No withdrawal mechanism in UI**: Despite `POST /ui/payouts/request` working perfectly, creators cannot trigger payouts through the interface. They must use curl or a browser console.
3. **No financial history**: No transaction log means creators cannot reconcile their earnings or track individual income events. Tax reporting is impossible.
4. **Missing from navigation**: The sidebar Commerce group (`Sidebar.tsx:94-107`) lists Shop, Cart, Billing, Orders, Subscriptions, Analytics, Referrals, Promo Codes -- but not Payouts. Creators do not even know the feature exists.
<!-- NOTE: Payouts sidebar link NOW exists at Sidebar.tsx:105. This pain point has been addressed. -->
5. **No date-range filtering**: Even through the API, there is no UI surface to explore earnings trends over time.

---

## 3. Current State Analysis

### 3.1 Payout Router (`app/routers/creator_payouts.py:35-105`)

Four fully functional endpoints, all using `Depends(require_ui_session)` for cookie-based auth:

```python
# app/routers/creator_payouts.py:35-47
@router.get("/balance", response_model=PayoutBalanceOut)
def payout_balance(session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    result = get_available_balance(user_id)
    return PayoutBalanceOut(
        available_cents=result["available_cents"],
        pending_cents=result["pending_cents"],
        total_earned_cents=result["total_earned_cents"],
        hold_cents=result["hold_cents"],
        currency="USD",
        minimum_payout_cents=S.payout_minimum_cents,
    )
```

| Endpoint | Method | Path | Response Model | Purpose |
|----------|--------|------|---------------|---------|
| `payout_balance` | GET | `/ui/payouts/balance` | `PayoutBalanceOut` | Available/pending/hold/total earned |
| `create_payout_request` | POST | `/ui/payouts/request` | `PayoutCreateOut` | Request withdrawal |
| `cancel_payout_request` | POST | `/ui/payouts/{payout_id}/cancel` | `PayoutActionOut` | Cancel pending payout |
| `list_payouts` | GET | `/ui/payouts` | `PayoutListOut` | Paginated payout history |

**Citation**: `app/routers/creator_payouts.py:35-105` -- all four endpoints verified working with E2E tests.

### 3.2 Earnings Router (`app/routers/creator_earnings.py:19-61`)

Two fully functional endpoints with date range filtering:

```python
# app/routers/creator_earnings.py:19-37
@router.get("/summary", response_model=EarningsSummaryOut)
def earnings_summary(
    from_ts: Optional[int] = Query(default=None, description="Start of time range (Unix seconds)"),
    to_ts: Optional[int] = Query(default=None, description="End of time range (Unix seconds)"),
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    result = get_earnings_summary(user_id, from_ts=from_ts or 0, to_ts=to_ts or 0)
    return EarningsSummaryOut(
        total_cents=result["total_cents"],
        breakdown=EarningsBreakdown(**result["breakdown"]),
        transaction_count=result["transaction_count"],
        currency=result["currency"],
    )
```

| Endpoint | Method | Path | Response Model | Purpose |
|----------|--------|------|---------------|---------|
| `earnings_summary` | GET | `/ui/earnings/summary` | `EarningsSummaryOut` | Total + breakdown by category |
| `earnings_transactions` | GET | `/ui/earnings/transactions` | `EarningsTransactionsOut` | Paginated credit entries |

**Citation**: `app/routers/creator_earnings.py:19-61` -- summary with `from_ts`/`to_ts` filters; transactions with cursor pagination.

### 3.3 Pydantic Models (`app/models.py:2315-2391`)

All response models are defined and typed. Key models with exact field signatures:

```python
# app/models.py:2315-2320
class EarningsBreakdown(BaseModel):
    subscriptions: int = 0
    tips: int = 0
    unlocks: int = 0
    vod_purchases: int = 0
    other: int = 0

# app/models.py:2347-2353
class PayoutBalanceOut(BaseModel):
    available_cents: int = 0
    pending_cents: int = 0
    total_earned_cents: int = 0
    hold_cents: int = 0
    currency: str = "USD"
    minimum_payout_cents: int = 1000

# app/models.py:2356-2359
class PayoutRequestIn(BaseModel):
    amount_cents: int = Field(ge=100)
    method: str = "bank_transfer"
    notes: str = Field(default="", max_length=500)

# app/models.py:2362-2373
class PayoutOut(BaseModel):
    payout_id: str
    user_id: str
    amount_cents: int
    method: str = "bank_transfer"
    status: str
    created_at: int
    updated_at: int
    notes: str = ""
    reject_reason: str = ""
    approved_by: str = ""
    completed_at: Optional[int] = None
```

**Citation**: `app/models.py:2315-2391` -- complete model definitions, all fields typed.

### 3.4 Service Layer (`app/services/creator_payouts.py`)

The service layer implements the full payout lifecycle:

```python
# app/services/creator_payouts.py:55-108
def get_available_balance(user_id: str) -> dict:
    """Calculate available balance from billing ledger credits.
    Queries T.billing for pk=USER#{user_id}, sk begins_with LEDGER#, type=credit.
    Only includes entries where ts + hold_period <= now_ts().
    Subtracts any pending/approved/processing payout amounts."""
    pk = f"USER#{user_id}"
    now = now_ts()
    hold_period = S.payout_hold_period_seconds
    # ... loops through all billing ledger pages ...
    pending_cents = _get_active_payout_total(user_id)
    available_cents = max(0, available_cents - pending_cents)
```

Key service functions:
- `get_available_balance(user_id)` (line 55): Queries billing credits, applies hold period, subtracts active payouts.
- `_get_active_payout_total(user_id)` (line 111): Sums amounts for all payouts in `ACTIVE_PAYOUT_STATES` (`requested`, `approved`, `processing`).
- `_has_active_payout(user_id)` (line 138): Boolean check preventing duplicate active payout requests.
- `request_payout(user_id, amount_cents, method, notes)` (line 164): Creates payout with validations (minimum, balance, no duplicates).
- `cancel_payout(payout_id, user_id)` (line 208): Cancels payout (must be `requested` or `approved`, must belong to user).
- `list_user_payouts(user_id, limit, cursor)` (line 235): Paginated list via `ByUserCreatedAt` GSI.

**Citation**: `app/services/creator_payouts.py:55-108` -- balance calculation with hold period.
**Citation**: `app/services/creator_payouts.py:164-205` -- `request_payout` with minimum, duplicate, and balance validation.

### 3.5 Earnings Service Layer (`app/services/creator_earnings.py`)

```python
# app/services/creator_earnings.py:22-33
def _reason_to_category(reason: str) -> str:
    """Map a ledger credit reason to an earnings category."""
    reason_lower = reason.lower() if reason else ""
    if "subscription" in reason_lower:
        return "subscriptions"
    if reason_lower.startswith("tip"):
        return "tips"
    if "unlock" in reason_lower:
        return "unlocks"
    if "vod" in reason_lower:
        return "vod_purchases"
    return "other"
```

- `get_earnings_summary(user_id, from_ts, to_ts)` (line 47): Aggregates all credit entries, groups by category via `_reason_to_category`.
- `get_earnings_transactions(user_id, limit, cursor, from_ts, to_ts)` (line 117): Paginated list of individual credits with category tagging.

**Citation**: `app/services/creator_earnings.py:47-114` -- summary aggregation with DDB pagination loop.
**Citation**: `app/services/creator_earnings.py:117-207` -- transactions with cursor and FilterExpression loop.

### 3.6 Configuration

- `S.payout_minimum_cents`: Minimum withdrawal amount (default $10.00 / 1000 cents). Referenced at `app/routers/creator_payouts.py:46`.
- `S.payout_hold_period_seconds`: How long credits are held before becoming available. Referenced at `app/services/creator_payouts.py:66`.

### 3.7 DynamoDB Tables

**Billing table** (`T.billing`):
- PK: `pk` (S) = `USER#{user_id}`
- SK: `sk` (S) = `LEDGER#{timestamp}#{entry_id}`
- Credit entries: `type = "credit"`, `amount_cents`, `reason`, `meta`, `ts`, `currency`

**Creator Payouts table** (`T.creator_payouts`):
- PK: `payout_id` (S)
- GSI `ByUserCreatedAt`: `user_id` (PK), `created_at` (SK, type N)
- GSI `ByStatusCreatedAt`: `status` (PK), `created_at` (SK, type N)

### 3.8 What Does NOT Exist

<!-- NOTE: The items below were accurate at ticket-writing time but have since been implemented. -->
- ~~No `/payouts` route in `frontend/src/App.tsx`~~ — NOW EXISTS at `App.tsx:186` (`<Route path="payouts" element={<PayoutDashboard />} />`) (see `frontend/src/App.tsx:67,186`)
- ~~No page component in `frontend/src/pages/`~~ — NOW EXISTS: `frontend/src/pages/payouts/PayoutDashboard.tsx`
- ~~No API endpoint wrapper in `frontend/src/api/endpoints/`~~ — NOW EXISTS: `frontend/src/api/endpoints/payouts.ts`
- ~~No sidebar navigation entry~~ — NOW EXISTS at `Sidebar.tsx:105` ("Payouts" in Commerce group)
- No TypeScript types for payout or earnings responses in `frontend/src/api/types.ts` — status unknown, may also have been added

---

## 4. Implementation Plan

### Phase 1: API Client Layer and TypeScript Types

#### 4.1 TypeScript Types (`frontend/src/api/types.ts` additions)

Add the following interfaces at the end of `frontend/src/api/types.ts`:

```typescript
// -- Creator Payouts (BILLING-002) --

export interface PayoutBalance {
  available_cents: number;
  pending_cents: number;
  total_earned_cents: number;
  hold_cents: number;
  currency: string;
  minimum_payout_cents: number;
}

export interface Payout {
  payout_id: string;
  user_id: string;
  amount_cents: number;
  method: string;
  status: string;
  created_at: number;
  updated_at: number;
  notes: string;
  reject_reason: string;
  approved_by: string;
  completed_at: number | null;
}

export interface PayoutCreateResp {
  ok: boolean;
  payout_id: string;
  amount_cents: number;
  status: string;
}

export interface PayoutActionResp {
  ok: boolean;
  payout_id: string;
  status: string;
}

export interface PayoutListResp {
  items: Payout[];
  next_cursor: string | null;
}

export interface EarningsBreakdown {
  subscriptions: number;
  tips: number;
  unlocks: number;
  vod_purchases: number;
  other: number;
}

export interface EarningsSummary {
  total_cents: number;
  breakdown: EarningsBreakdown;
  transaction_count: number;
  currency: string;
}

export interface EarningsTransaction {
  entry_id: string;
  ts: number;
  amount_cents: number;
  reason: string;
  category: string;
  currency: string;
  meta: Record<string, unknown>;
}

export interface EarningsTransactionsResp {
  items: EarningsTransaction[];
  next_cursor: string | null;
}
```

#### 4.2 API Client (`frontend/src/api/endpoints/payouts.ts`)

**New file**: `frontend/src/api/endpoints/payouts.ts` (~60 lines)

```typescript
import { api } from "@/api/client";
import type {
  PayoutBalance,
  PayoutCreateResp,
  PayoutActionResp,
  PayoutListResp,
  EarningsSummary,
  EarningsTransactionsResp,
} from "@/api/types";

// -- Payouts --

export const getPayoutBalance = () =>
  api.get<PayoutBalance>("/ui/payouts/balance").then((r) => r.data);

export const requestPayout = (body: {
  amount_cents: number;
  method?: string;
  notes?: string;
}) =>
  api.post<PayoutCreateResp>("/ui/payouts/request", body).then((r) => r.data);

export const cancelPayout = (payoutId: string) =>
  api.post<PayoutActionResp>(`/ui/payouts/${payoutId}/cancel`).then((r) => r.data);

export const listPayouts = (params?: { limit?: number; cursor?: string }) =>
  api.get<PayoutListResp>("/ui/payouts", { params }).then((r) => r.data);

// -- Earnings --

export const getEarningsSummary = (params?: {
  from_ts?: number;
  to_ts?: number;
}) =>
  api.get<EarningsSummary>("/ui/earnings/summary", { params }).then((r) => r.data);

export const getEarningsTransactions = (params?: {
  limit?: number;
  cursor?: string;
  from_ts?: number;
  to_ts?: number;
}) =>
  api.get<EarningsTransactionsResp>("/ui/earnings/transactions", { params }).then((r) => r.data);
```

### Phase 2: Page Component

#### 4.3 Page Component Layout (`frontend/src/pages/payouts/PayoutDashboard.tsx`)

**New file**: `frontend/src/pages/payouts/PayoutDashboard.tsx` (~350 lines)

Component tree:

```
PayoutDashboard
├── Header ("Payouts" + Wallet icon)
├── BalanceCardsRow
│   ├── BalanceCard: Available Balance (green, large text, primary CTA)
│   │   └── Shows formatted USD amount, "Available to withdraw" subtitle
│   ├── BalanceCard: Pending Payouts (yellow)
│   │   └── Shows pending payout amounts currently in transit
│   ├── BalanceCard: On Hold (orange)
│   │   └── Shows credits within the hold period (not yet available)
│   └── BalanceCard: Total Earned (blue)
│       └── Shows lifetime earnings across all categories
├── PayoutRequestSection (Card)
│   ├── CardHeader: "Request Payout"
│   ├── AmountInput (dollar input, converts to cents on submit)
│   │   ├── Validation: required, >= minimum_payout_cents, <= available_cents
│   │   └── Helper text: "Minimum: $10.00"
│   ├── MethodSelector (Select component)
│   │   └── Options: "Bank Transfer", "PayPal"
│   ├── NotesTextarea (optional, maxLength=500)
│   └── SubmitButton: "Request Payout" (disabled while invalid or pending)
│       └── Loading state with Loader2 spinner
├── EarningsBreakdownCard
│   ├── CardHeader: "Earnings Breakdown" + DateRangePicker
│   ├── DateRangePicker (presets: 7d, 30d, 90d, All Time + custom)
│   ├── PieChart / BarChart (5 category segments)
│   │   ├── Subscriptions segment + dollar amount
│   │   ├── Tips segment + dollar amount
│   │   ├── Unlocks segment + dollar amount
│   │   ├── VOD Purchases segment + dollar amount
│   │   └── Other segment + dollar amount
│   └── Total footer: "X transactions totaling $Y.YY"
├── PayoutHistoryTable (Card)
│   ├── CardHeader: "Payout History"
│   ├── Table
│   │   ├── Header Row: Date | Amount | Method | Status | Actions
│   │   └── Data Rows (sorted by created_at desc)
│   │       ├── Date: formatted from created_at timestamp
│   │       ├── Amount: formatted USD
│   │       ├── Method: "Bank Transfer" or "PayPal"
│   │       ├── Status: Badge component (color-coded)
│   │       │   ├── completed -> green
│   │       │   ├── requested -> yellow
│   │       │   ├── approved -> blue
│   │       │   ├── processing -> orange
│   │       │   ├── rejected -> red (+ expandable reject_reason)
│   │       │   └── cancelled -> grey
│   │       └── Actions: Cancel button (if status in [requested, approved])
│   ├── EmptyState: "No payout requests yet"
│   └── LoadMoreButton (visible when next_cursor is not null)
└── EarningsTransactionsTable (Card)
    ├── CardHeader: "Earnings Transactions" + same DateRangePicker
    ├── Table
    │   ├── Header Row: Date/Time | Amount | Category | Reason
    │   └── Data Rows (sorted by ts desc)
    │       ├── Date/Time: formatted from ts timestamp
    │       ├── Amount: formatted USD (green text for credits)
    │       ├── Category: Badge (subscriptions=purple, tips=green, unlocks=blue, vod=orange, other=grey)
    │       └── Reason: text (e.g., "Tip: message", "Subscription payment")
    ├── EmptyState: "No earnings yet"
    └── LoadMoreButton (visible when next_cursor is not null)
```

#### 4.4 React Query Hooks and Cache Strategy

```typescript
// Balance query -- refetches every 30s and after mutations
const balanceQ = useQuery({
  queryKey: ["payouts", "balance"],
  queryFn: getPayoutBalance,
  staleTime: 30_000,
  refetchInterval: 30_000,
});

// Payout history -- refetches every 60s
const payoutsQ = useQuery({
  queryKey: ["payouts", "list"],
  queryFn: () => listPayouts({ limit: 25 }),
  staleTime: 60_000,
});

// Earnings summary -- depends on date range state
const summaryQ = useQuery({
  queryKey: ["earnings", "summary", fromTs, toTs],
  queryFn: () => getEarningsSummary({ from_ts: fromTs, to_ts: toTs }),
  staleTime: 60_000,
});

// Earnings transactions -- depends on date range state
const txnQ = useQuery({
  queryKey: ["earnings", "transactions", fromTs, toTs],
  queryFn: () => getEarningsTransactions({
    limit: 50,
    from_ts: fromTs,
    to_ts: toTs,
  }),
  staleTime: 60_000,
});

// Request payout mutation
const requestMut = useMutation({
  mutationFn: requestPayout,
  onSuccess: () => {
    toast.success("Payout requested successfully");
    queryClient.invalidateQueries({ queryKey: ["payouts"] });
  },
  onError: (err: AxiosError<{ detail: string }>) => {
    const detail = err.response?.data?.detail;
    if (err.response?.status === 409) {
      toast.error("You already have a pending payout request");
    } else {
      toast.error(detail || "Failed to request payout");
    }
  },
});

// Cancel payout mutation
const cancelMut = useMutation({
  mutationFn: cancelPayout,
  onSuccess: () => {
    toast.success("Payout cancelled");
    queryClient.invalidateQueries({ queryKey: ["payouts"] });
  },
  onError: (err: AxiosError<{ detail: string }>) => {
    const detail = err.response?.data?.detail;
    toast.error(detail || "Failed to cancel payout");
  },
});
```

**Cache invalidation strategy**:
- Both `requestMut` and `cancelMut` invalidate `["payouts"]` which covers both `["payouts", "balance"]` and `["payouts", "list"]`.
- Date range changes cause new query keys, so React Query automatically fetches fresh data.
- No optimistic updates needed (balance depends on server-side calculation).

### Phase 3: Navigation Integration

#### 4.5 Sidebar Entry (`frontend/src/components/layout/Sidebar.tsx`)

Add to Commerce group (after "Analytics" at line 90, before "Referrals" at line 91):

```typescript
{ label: "Payouts", i18nKey: "nav.payouts", path: "/payouts", icon: <Wallet className="h-5 w-5" /> },
```

Import `Wallet` from `lucide-react` at the top of the file.

#### 4.6 MobileSidebar Entry (`frontend/src/components/layout/AppShell.tsx`)

Add "Payouts" to the Commerce group in the MobileSidebar section, matching the Sidebar placement.

#### 4.7 MobileNav Entry (`frontend/src/components/layout/MobileNav.tsx`)

Add "Payouts" to `MORE_LINKS`:

```typescript
{ label: "Payouts", path: "/payouts", icon: <Wallet className="h-4 w-4" /> },
```

#### 4.8 Route Registration (`frontend/src/App.tsx`)

Add lazy import:
```tsx
const PayoutDashboard = lazy(() => import("@/pages/payouts/PayoutDashboard"));
```

Add route inside protected routes (between `analytics` and `referrals`):
```tsx
<Route path="payouts" element={<PayoutDashboard />} />
```

---

## 5. Data Model Reference

### 5.1 Billing Table (Existing -- Read Only)

The dashboard reads from the billing table but does not write to it.

| Attribute | Type | Example |
|-----------|------|---------|
| `pk` | S | `USER#alice@test.local` |
| `sk` | S | `LEDGER#1748380800#a1b2c3d4` |
| `entry_id` | S | `a1b2c3d4` |
| `ts` | N | `1748380800` |
| `type` | S | `credit` |
| `amount_cents` | N | `500` |
| `currency` | S | `USD` |
| `state` | S | `settled` |
| `reason` | S | `Tip: message` |
| `meta` | M | `{"content_type": "message", "tipper_user_id": "bob@test.local"}` |

### 5.2 Creator Payouts Table (Existing -- Read/Write)

| Attribute | Type | Example |
|-----------|------|---------|
| `payout_id` | S (PK) | `payout_a1b2c3d4e5f6` |
| `user_id` | S | `alice@test.local` |
| `amount_cents` | N | `5000` |
| `method` | S | `bank_transfer` |
| `status` | S | `requested` |
| `created_at` | N | `1748380800` |
| `updated_at` | N | `1748380800` |
| `notes` | S | `Monthly withdrawal` |
| `reject_reason` | S | `` |
| `approved_by` | S | `` |
| `completed_at` | N | `0` |

**GSIs**:

| GSI | PK | SK | Purpose |
|-----|----|----|---------|
| `ByUserCreatedAt` | `user_id` (S) | `created_at` (N) | List payouts for a user, sorted by date |
| `ByStatusCreatedAt` | `status` (S) | `created_at` (N) | Admin: filter payouts by status |

**`attr_types`**: `{"created_at": "N"}` -- must be declared for numeric sort key GSIs.

### 5.3 Example DynamoDB Items

**Payout request (pending)**:
```json
{
  "payout_id": "payout_a1b2c3d4e5f6",
  "user_id": "alice@test.local",
  "amount_cents": 5000,
  "method": "bank_transfer",
  "status": "requested",
  "created_at": 1748380800,
  "updated_at": 1748380800,
  "notes": "Monthly withdrawal",
  "reject_reason": "",
  "approved_by": "",
  "completed_at": null
}
```

**Billing credit entry (tip)**:
```json
{
  "pk": "USER#alice@test.local",
  "sk": "LEDGER#1748380800#a1b2c3d4",
  "entry_id": "a1b2c3d4",
  "ts": 1748380800,
  "type": "credit",
  "amount_cents": 500,
  "currency": "USD",
  "state": "settled",
  "reason": "Tip: message",
  "meta": {
    "content_type": "message",
    "content_id": "m_abc123",
    "tipper_user_id": "bob@test.local",
    "recipient_user_id": "alice@test.local",
    "tip_payment_id": "tip_xyz789"
  }
}
```

---

## 6. API Design Reference

### 6.1 GET `/ui/payouts/balance`

**Auth**: `require_ui_session` (cookie + CSRF for non-GET)
**Request**: No parameters.
**Response (200)**:
```json
{
  "available_cents": 12500,
  "pending_cents": 5000,
  "total_earned_cents": 25000,
  "hold_cents": 7500,
  "currency": "USD",
  "minimum_payout_cents": 1000
}
```

**Example curl**:
```bash
curl -b "ui_session=...; ui_access_token=..." \
  http://localhost:8000/ui/payouts/balance
```

**Error responses**: 401 (not authenticated).

### 6.2 POST `/ui/payouts/request`

**Auth**: `require_ui_session` (cookie + CSRF)
**Request body**:
```json
{
  "amount_cents": 5000,
  "method": "bank_transfer",
  "notes": "Monthly withdrawal"
}
```
**Response (201)**:
```json
{
  "ok": true,
  "payout_id": "payout_a1b2c3d4",
  "amount_cents": 5000,
  "status": "requested"
}
```

**Example curl**:
```bash
curl -X POST -b "ui_session=...; ui_access_token=..." \
  -H "x-csrf-token: ..." -H "Content-Type: application/json" \
  -d '{"amount_cents":5000,"method":"bank_transfer"}' \
  http://localhost:8000/ui/payouts/request
```

**Error responses**:
| Status | Body | Condition |
|--------|------|-----------|
| 400 | `{"detail": "Amount must be at least 1000 cents ($10.00)"}` | Below minimum |
| 400 | `{"detail": "Insufficient balance. Available: 500 cents"}` | Exceeds available |
| 409 | `{"detail": "A payout request is already pending"}` | Duplicate active payout |
| 401 | `{"detail": "Not authenticated"}` | Missing/invalid session |

### 6.3 POST `/ui/payouts/{payout_id}/cancel`

**Auth**: `require_ui_session` (cookie + CSRF)
**Request**: No body. Payout ID in URL path.
**Response (200)**:
```json
{
  "ok": true,
  "payout_id": "payout_a1b2c3d4",
  "status": "cancelled"
}
```

**Error responses**:
| Status | Body | Condition |
|--------|------|-----------|
| 400 | `{"detail": "Cannot cancel payout in 'completed' state"}` | Wrong status |
| 403 | `{"detail": "Not your payout"}` | User doesn't own the payout |
| 404 | `{"detail": "Payout not found"}` | Non-existent payout_id |

### 6.4 GET `/ui/payouts?limit=25&cursor=...`

**Auth**: `require_ui_session`
**Query parameters**: `limit` (1-100, default 25), `cursor` (optional)
**Response (200)**:
```json
{
  "items": [
    {
      "payout_id": "payout_a1b2c3d4",
      "user_id": "alice@test.local",
      "amount_cents": 5000,
      "method": "bank_transfer",
      "status": "requested",
      "created_at": 1748380800,
      "updated_at": 1748380800,
      "notes": "Monthly withdrawal",
      "reject_reason": "",
      "approved_by": "",
      "completed_at": null
    }
  ],
  "next_cursor": null
}
```

### 6.5 GET `/ui/earnings/summary?from_ts=...&to_ts=...`

**Auth**: `require_ui_session`
**Query parameters**: `from_ts` (optional, Unix seconds), `to_ts` (optional, Unix seconds)
**Response (200)**:
```json
{
  "total_cents": 25000,
  "breakdown": {
    "subscriptions": 10000,
    "tips": 8000,
    "unlocks": 4000,
    "vod_purchases": 2000,
    "other": 1000
  },
  "transaction_count": 47,
  "currency": "USD"
}
```

### 6.6 GET `/ui/earnings/transactions?limit=50&cursor=...&from_ts=...&to_ts=...`

**Auth**: `require_ui_session`
**Response (200)**:
```json
{
  "items": [
    {
      "entry_id": "a1b2c3d4",
      "ts": 1748380800,
      "amount_cents": 500,
      "reason": "Tip: message",
      "category": "tips",
      "currency": "USD",
      "meta": {
        "content_type": "message",
        "tipper_user_id": "bob@test.local"
      }
    }
  ],
  "next_cursor": "eyJwayI6IlVTRVIj..."
}
```

---

## 7. Validation Rules (Frontend)

### 7.1 Payout Request Form

| Field | Validation | Error message |
|-------|-----------|---------------|
| Amount | Required, numeric > 0 | "Amount is required" |
| Amount | >= `minimum_payout_cents` / 100 | "Minimum payout is $10.00" |
| Amount | <= `available_cents` / 100 | "Insufficient available balance" |
| Method | Required, one of ["bank_transfer", "paypal"] | "Select a payout method" |
| Notes | Optional, max 500 chars | "Notes must be 500 characters or fewer" |

Use React Hook Form + Zod schema:

```typescript
const payoutSchema = z.object({
  amount: z.number()
    .positive("Amount must be greater than zero")
    .refine(
      (v) => v * 100 >= (balanceQ.data?.minimum_payout_cents ?? 1000),
      `Minimum payout is $${((balanceQ.data?.minimum_payout_cents ?? 1000) / 100).toFixed(2)}`
    )
    .refine(
      (v) => v * 100 <= (balanceQ.data?.available_cents ?? 0),
      "Insufficient available balance"
    ),
  method: z.enum(["bank_transfer", "paypal"]),
  notes: z.string().max(500).optional(),
});
```

### 7.2 Cancel Action

- Only enabled when status is "requested" or "approved".
- Confirmation dialog: "Are you sure you want to cancel this payout request for $X.XX?"
- On success: invalidate both `["payouts", "balance"]` and `["payouts", "list"]`.

---

## 8. Error Handling

| HTTP Status | Backend Condition | Frontend Handling |
|-------------|------------------|-------------------|
| 400 | Amount below minimum | Show inline error under amount field: "Minimum payout is $10.00" |
| 400 | Insufficient balance | Show inline error under amount field: "Insufficient available balance" |
| 409 | Duplicate payout (already active) | Show toast: "You already have a pending payout request" |
| 403 | Cancel on someone else's payout | Should not occur (UI only shows own payouts); fallback toast |
| 404 | Cancel on non-existent payout | Toast: "Payout not found" |
| 401 | Not authenticated | Redirected to login by axios interceptor |
| 422 | Validation error (invalid field format) | Show generic form error |

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_payout_dashboard.py`

**Mock setup**: moto mock for DynamoDB (billing tables). stripe-mock on port 12111 for payment provider calls.

| Test Function | Description |
|---|---|
| `test_create_resource` | Create primary resource; verify stored correctly |
| `test_get_resource_by_id` | Get resource; verify all fields returned |
| `test_list_resources` | List with pagination; verify count and order |
| `test_update_resource` | Update fields; verify changes persisted |
| `test_delete_or_cancel_resource` | Delete/cancel; verify status change |
| `test_validation_rejects_invalid` | Missing/invalid fields return 400/422 |
| `test_authorization_enforced` | Non-owner/non-admin returns 403 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full lifecycle through real DDB
2. Cross-service with billing ledger validation
3. Concurrent requests handled correctly

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/payout-dashboard.spec.ts`

**Auth pattern**: `injectAuth(page, "alice")` for customer; `injectAuth(page, "root")` for admin; CSRF header for mutations

| # | Test Name | Assertion |
|---|---|---|
| 1 | API creates resource | POST returns 200/201 with ID |
| 2 | API returns resource by ID | GET returns full resource |
| 3 | API lists with pagination | GET list returns array |
| 4 | API updates resource | PATCH returns updated resource |
| 5 | UI page loads with heading | Navigate to page; heading visible |
| 6 | UI form submits successfully | Fill form; submit; success toast |
| 7 | UI shows validation errors | Submit invalid; error messages visible |
| 8 | Unauthenticated returns 401 | No session -> 401 |
| 9 | Non-owner returns 403 | Wrong user -> 403 |
| 10 | Not found returns 404 | Invalid ID -> 404 |
| 11 | Duplicate returns 409 | Create twice -> 409 |

**Negative tests**: 401 unauthenticated, 403 non-owner/non-admin, 404 not found, 409 conflict, 422 validation

**Edge cases**: Zero balance payout attempt, refund exceeding original amount, concurrent refund requests

### Test Data Requirements

Seed billing data via DDB `put_item` in `beforeAll`. Use unique IDs per test run.

**Test users**: Alice (USER, customer), Charlie (ADMIN, queue management), Root (ROOT, admin operations)

### CI/Pipeline

Serial execution. `stripe-mock` on port 12111. Retry-safe.

---

## Dependencies & Merge Safety

### Depends On

No upstream dependencies. This ticket is self-contained.

### Depended On By

No downstream dependents identified.

### Merge Strategy

Independent. Frontend-only page. Backend payout endpoints already exist and are E2E tested.

### Merge Checklist

- [ ] Route `/payouts` added to `App.tsx`
- [ ] PayoutDashboard page component created
- [ ] Sidebar entry added
- [ ] React Query hooks for balance/payouts/earnings endpoints
- [ ] E2E tests pass in CI
- [ ] No breaking changes to existing payout API

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Payout balance endpoint | `app/routers/creator_payouts.py` | 35-47 | VERIFIED |
| Payout request endpoint | `app/routers/creator_payouts.py` | 50-76 | VERIFIED |
| Payout cancel endpoint | `app/routers/creator_payouts.py` | 79-92 | VERIFIED |
| Payout list endpoint | `app/routers/creator_payouts.py` | 95-106 | VERIFIED |
| Earnings summary endpoint | `app/routers/creator_earnings.py` | 19-37 | VERIFIED |
| Earnings transactions endpoint | `app/routers/creator_earnings.py` | 40-61 | VERIFIED |
| PayoutBalanceOut model | `app/models.py` | 2347-2353 | VERIFIED |
| PayoutRequestIn model (ge=100) | `app/models.py` | 2356-2359 | VERIFIED |
| PayoutOut model (all fields) | `app/models.py` | 2362-2373 | VERIFIED |
| PayoutCreateOut model | `app/models.py` | 2376-2380 | VERIFIED |
| PayoutListOut model | `app/models.py` | 2383-2385 | VERIFIED |
| PayoutActionOut model | `app/models.py` | 2388-2391 | VERIFIED |
| EarningsSummaryOut model | `app/models.py` | 2323-2327 | VERIFIED |
| EarningsBreakdown model | `app/models.py` | 2315-2320 | VERIFIED |
| EarningsTransactionOut model | `app/models.py` | 2330-2337 | VERIFIED |
| EarningsTransactionsOut model | `app/models.py` | 2340-2342 | VERIFIED |
| get_available_balance queries billing credits | `app/services/creator_payouts.py` | 55-108 | VERIFIED |
| _get_active_payout_total sums active payouts | `app/services/creator_payouts.py` | 111-135 | VERIFIED |
| _has_active_payout duplicate check | `app/services/creator_payouts.py` | 138-161 | VERIFIED |
| request_payout with minimum/balance/duplicate validation | `app/services/creator_payouts.py` | 164-205 | VERIFIED |
| cancel_payout ownership + status check | `app/services/creator_payouts.py` | 208-232 | VERIFIED |
| list_user_payouts with ByUserCreatedAt GSI | `app/services/creator_payouts.py` | 235-253 | VERIFIED |
| _reason_to_category maps tip prefix to "tips" | `app/services/creator_earnings.py` | 22-33 | VERIFIED |
| get_earnings_summary aggregates with pagination loop | `app/services/creator_earnings.py` | 47-114 | VERIFIED |
| get_earnings_transactions with cursor pagination | `app/services/creator_earnings.py` | 117-207 | VERIFIED |
| S.payout_minimum_cents used in balance endpoint | `app/routers/creator_payouts.py` | 46 | VERIFIED |
| S.payout_hold_period_seconds in balance calc | `app/services/creator_payouts.py` | 66 | VERIFIED |
| S.payout_minimum_cents setting defined | `app/core/settings.py` | 1177 | VERIFIED |
| S.payout_hold_period_seconds setting defined | `app/core/settings.py` | 1176 | VERIFIED |
| ACTIVE_PAYOUT_STATES = requested, approved, processing | `app/services/creator_payouts.py` | 24 | VERIFIED |
| /payouts route in App.tsx | `frontend/src/App.tsx` | 67, 186 | VERIFIED (now exists) |
| PayoutDashboard page component | `frontend/src/pages/payouts/PayoutDashboard.tsx` | exists | VERIFIED (now exists) |
| Payout API wrappers | `frontend/src/api/endpoints/payouts.ts` | exists | VERIFIED (now exists) |
| Sidebar Commerce group has Payouts | `frontend/src/components/layout/Sidebar.tsx` | 105 | VERIFIED (now exists) |
| E2E API tests exist | `frontend/e2e/creator-payouts.spec.ts` | exists | VERIFIED |
