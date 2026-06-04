# BILLING-002: Payout Dashboard Frontend — Investigation & Implementation Write-up

> Type: feature | Priority: High | Status: Implemented | Area: billing / creator-monetization

## 1. Summary & Classification

BILLING-002 adds a creator-facing Payout Dashboard page (`/payouts`) that surfaces the fully implemented backend payout and earnings API as a usable UI. Before this ticket, creators had no way to view their available balance, request a withdrawal, or inspect their earnings breakdown through the application — they had to use raw API calls. The backend at `app/routers/creator_payouts.py:35-105` and `app/routers/creator_earnings.py:19-61` was complete and E2E tested before this ticket started.

**Type**: Frontend feature (no new backend endpoints required). **Priority**: High. **User persona**: Content creators with accumulated platform earnings.

**Cross-references**: Depends on the billing ledger infrastructure (shared utilities in `app/services/billing_shared.py`). BILLING-004 (dev wallet deposit bypass) is adjacent but concerns the wallet, not creator payouts. SECOPS-007 is not directly relevant here since this ticket adds no new server-side capabilities — it wraps existing authenticated API calls in a UI.

---

## 2. Current-State Investigation (what exists today)

### 2.1 Backend — fully implemented before this ticket

**`app/routers/creator_payouts.py:35-105`** defines four endpoints, all using `Depends(require_ui_session)` (cookie+CSRF for non-GET):

| Endpoint | Method | Path | Response model |
|----------|--------|------|---------------|
| `payout_balance` | GET | `/ui/payouts/balance` | `PayoutBalanceOut` |
| `create_payout_request` | POST | `/ui/payouts/request` | `PayoutCreateOut` |
| `cancel_payout_request` | POST | `/ui/payouts/{payout_id}/cancel` | `PayoutActionOut` |
| `list_payouts` | GET | `/ui/payouts` | `PayoutListOut` |

**`app/routers/creator_earnings.py:19-61`** defines two endpoints:

| Endpoint | Method | Path | Response model |
|----------|--------|------|---------------|
| `earnings_summary` | GET | `/ui/earnings/summary` | `EarningsSummaryOut` |
| `earnings_transactions` | GET | `/ui/earnings/transactions` | `EarningsTransactionsOut` |

Both earnings endpoints accept optional `from_ts` and `to_ts` query parameters (Unix seconds) for date-range filtering.

**Pydantic models** (`app/models.py:2315-2391`):
- `EarningsBreakdown` at 2315: five integer fields `subscriptions`, `tips`, `unlocks`, `vod_purchases`, `other`
- `PayoutBalanceOut` at 2347: `available_cents`, `pending_cents`, `total_earned_cents`, `hold_cents`, `currency`, `minimum_payout_cents`
- `PayoutRequestIn` at 2356: `amount_cents: int = Field(ge=100)`, `method: str = "bank_transfer"`, `notes: str` max 500
- `PayoutOut` at 2362: full payout record including `reject_reason`, `approved_by`, `completed_at`
- `PayoutListOut` at 2383: `items: List[PayoutOut]`, `next_cursor: Optional[str]`

**Service layer**:
- `get_available_balance(user_id)` at `app/services/creator_payouts.py:55`: queries `T.billing` for PK=`USER#{user_id}` credits, applies `S.payout_hold_period_seconds` (line 66, default 604800 = 7 days from `app/core/settings.py:1487`), subtracts active payouts via `_get_active_payout_total()` (line 111).
- `request_payout(user_id, amount_cents, method, notes)` at line 164: validates minimum (`S.payout_minimum_cents` = 1000 from `settings.py:1489`), balance sufficiency, and no duplicate active payout (`_has_active_payout()` at line 138).
- `cancel_payout(payout_id, user_id)` at line 208: validates ownership and that status is in `{"requested", "approved"}` (the two cancellable states).
- `list_user_payouts(user_id, limit, cursor)` at line 235: queries `T.creator_payouts` via `ByUserCreatedAt` GSI.
- `ACTIVE_PAYOUT_STATES` at line 24: `{"requested", "approved", "processing"}` — the set of statuses that block new payout requests and are subtracted from available balance.

**Earnings service** at `app/services/creator_earnings.py`:
- `_reason_to_category()` at line 22: maps ledger credit reason strings to the five breakdown categories. "Tip" prefix → `"tips"`, "subscription" substring → `"subscriptions"`, "unlock" → `"unlocks"`, "vod" → `"vod_purchases"`, else `"other"`.
- `get_earnings_summary()` at line 47: loops through all billing ledger pages (standard `LastEvaluatedKey` loop to handle sparse FilterExpression pagination), aggregates by category.
- `get_earnings_transactions()` at line 117: paginated list with cursor encoding from `app/core/cursor.py`.

**DynamoDB tables**: `T.billing` for credits/debits, `T.creator_payouts` (wired at `app/core/tables.py`) with `ByUserCreatedAt` GSI (PK=`user_id`, SK=`created_at` N) and `ByStatusCreatedAt` GSI. The `attr_types={"created_at": "N"}` declaration is critical for numeric sort key.

### 2.2 Frontend — state at implementation

All the following were missing at ticket inception and are now implemented:

**Route**: `frontend/src/App.tsx:401` — `<Route path="payouts" element={<PayoutDashboard />} />`. The lazy import is at `App.tsx:126`.

**Page component**: `frontend/src/pages/payouts/PayoutDashboard.tsx` (623 lines). Implements balance cards, payout request form (React Hook Form + Zod), payout history table with cancel action, earnings breakdown, and earnings transactions table.

**API client**: `frontend/src/api/endpoints/payouts.ts` exposes `getPayoutBalance()`, `requestPayout()`, `cancelPayout()`, `listPayouts()`, `getEarningsSummary()`, `getEarningsTransactions()` — all wrapping the axios instance from `api/client.ts`.

**Sidebar**: `frontend/src/components/layout/Sidebar.tsx:130` — `"Payouts"` entry with `Wallet` icon in the Commerce group, path `/payouts`.

---

## 3. Gap / Threat Analysis

### 3.1 Key requirement gaps resolved

The central gap was the complete absence of a frontend for a functioning backend. `POST /ui/payouts/request` returned correct 201 responses, but no UI surface existed to trigger it. The creator experience was broken at the navigation layer: the Sidebar Commerce group listed Shop, Billing, Subscriptions, Analytics, and Referrals but not Payouts. Creators had no discovery path to the feature.

### 3.2 Edge cases and failure modes

**409 duplicate payout**: `create_payout_request` returns 409 when `_has_active_payout()` finds an active request. The frontend `onError` handler must differentiate this from generic 400 errors to show the specific message "You already have a pending payout request" rather than a generic toast.

**Balance validation ordering**: Client-side Zod validation compares the form amount against `balanceQ.data?.available_cents`. If the balance query is stale or unfetched, the validator uses a fallback of 0, which blocks all submissions. The form should disable the submit button with a loading state while the balance query is pending, and only run the refine validators once `balanceQ.data` is available.

**Hold period UX**: The `hold_cents` field in `PayoutBalanceOut` represents credits still within `S.payout_hold_period_seconds` (default 7 days). The UI must clearly distinguish "On Hold (not yet available)" from "Pending Payouts (in transit)". Displaying only `available_cents` without context on `hold_cents` leaves creators confused about why their balance appears lower than expected.

**`_reason_to_category` coverage**: The category mapping at `creator_earnings.py:22` uses substring matching on the ledger credit `reason` field. New ledger credit reasons (e.g., from future features like live-stream tips) may fall into `"other"` rather than the correct category. The mapping should be treated as best-effort, and the `"other"` bucket should be explained in the UI.

**Infinite query for earnings transactions**: The `from_ts`/`to_ts` filters change the query key entirely (`["earnings", "transactions", fromTs, toTs]`), which means React Query creates a fresh cache entry for each date-range selection. This is correct behavior for cursor-based pagination (the cursor is only valid within a fixed filter scope), but the implementation must reset the cursor state when the date range changes.

### 3.3 Abuse potential

The payout request endpoints are rate-limited by the duplicate-active-payout check at the service layer. A creator cannot flood the payout queue because `_has_active_payout()` blocks a second request while the first is in any active state. Cancellation is also ownership-checked at `cancel_payout()` line 208.

---

## 4. Proposed Design / Fix

### 4.1 Component architecture (as implemented)

`PayoutDashboard.tsx` (623 lines) is a single-file page component. The key React Query configuration:

**Balance query**: `queryKey: ["payouts", "balance"]`, `staleTime: 30_000`, `refetchInterval: 30_000`. Auto-refreshes every 30 seconds to reflect recently approved payouts. Both `requestMut.onSuccess` and `cancelMut.onSuccess` invalidate `["payouts"]` (covers both `balance` and `list` sub-keys).

**Payout list query**: `queryKey: ["payouts", "list"]`, cursor-based pagination. "Load more" button appends pages. Status badges are color-coded: `completed` = green, `requested` = yellow, `approved` = blue, `processing` = orange, `rejected` = red, `cancelled` = grey.

**Earnings queries**: `queryKey: ["earnings", "summary", fromTs, toTs]` and `["earnings", "transactions", fromTs, toTs]`. Date-range presets (7d, 30d, 90d, all-time) set `fromTs`/`toTs` as Unix timestamps. Custom calendar range via popover.

**Zod schema for payout form**:
```typescript
amount: z.number().positive()
  .refine(v => v * 100 >= (balanceQ.data?.minimum_payout_cents ?? 1000), ...)
  .refine(v => v * 100 <= (balanceQ.data?.available_cents ?? 0), ...)
method: z.enum(["bank_transfer", "paypal"])
notes: z.string().max(500).optional()
```

Dollar input converts to cents on submit: `Math.round(values.amount * 100)`.

### 4.2 TypeScript types

Types are defined in `frontend/src/api/types.ts`. Key interfaces mirror the backend Pydantic models: `PayoutBalance`, `Payout`, `PayoutCreateResp`, `PayoutActionResp`, `PayoutListResp`, `EarningsBreakdown`, `EarningsSummary`, `EarningsTransaction`, `EarningsTransactionsResp`.

### 4.3 API client (`frontend/src/api/endpoints/payouts.ts`)

All functions use the axios instance from `api/client.ts` which attaches the `x-csrf-token` header automatically from the `ui_csrf` cookie. GET requests do not require CSRF. POST requests (deposit, cancel) do. The axios instance's 401 interceptor handles session expiry by redirecting to `/login`.

### 4.4 Dev/Prod parity (SECOPS-007)

The payout and earnings API calls are entirely transparent to the dev/prod split. The frontend calls `/ui/payouts/balance` via Vite's proxy (`vite.config.ts` proxies `/ui` to `http://localhost:8000`), and the backend's `get_available_balance()` queries `T.billing` via `DDB_ENDPOINT_URL=http://localhost:8001` in dev and real DynamoDB in prod. No mock layers are needed for the payout service — it works correctly end-to-end in dev because it reads real DDB Local data seeded by E2E setup scripts. The `creator_payouts.spec.ts` E2E tests confirm the API layer runs offline.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_payout_dashboard.py`)

Tests use moto-mocked DynamoDB and the FastAPI test client. No Stripe or external calls needed for payout tests.

| Test | Coverage |
|------|----------|
| `test_payout_balance_zero_for_new_user` | GET balance → 0 cents, minimum 1000 |
| `test_request_payout_below_minimum_returns_400` | 99 cents → 400 |
| `test_request_payout_exceeds_balance_returns_400` | Amount > available → 400 |
| `test_duplicate_active_payout_returns_409` | Second request while first is `requested` → 409 |
| `test_cancel_payout_changes_status_to_cancelled` | POST cancel → `cancelled` |
| `test_cancel_payout_wrong_user_returns_403` | Bob cancels Alice's payout → 403 |
| `test_cancel_completed_payout_returns_400` | `completed` payout cannot be cancelled |
| `test_earnings_summary_categorizes_tips` | Credit with reason "Tip: message" → `tips` bucket |
| `test_earnings_transactions_pagination` | Cursor pagination, `next_cursor` present when more items |

### 5.2 E2E tests (`frontend/e2e/creator-payouts.spec.ts`)

This spec already exists and tests the API layer. The UI layer can be verified by:
1. `injectAuth(page, "alice")` then navigate to `/payouts`.
2. Seed a billing credit for Alice in DDB `beforeAll`.
3. Assert balance cards are visible and `available_cents > 0`.
4. Fill the payout form with a valid amount, click submit, assert success toast.
5. Cancel the pending payout, assert status badge changes to "cancelled".
6. Seed earnings transactions in DDB; verify the earnings breakdown table renders categories.

Key E2E pattern: use `page.request.post(...)` with `headers: { "x-csrf-token": sessions.alice.csrf_token }` for POST mutations. Use `await page.evaluate(() => window.dispatchEvent(new Event("online")))` to trigger React Query invalidation after seeding DDB data externally.

### 5.3 Manual verification steps

1. `just restart` to clear test data.
2. Navigate to `http://localhost:3000/payouts`.
3. Verify the page heading "Payouts" is visible and four balance cards render.
4. Use the existing "Dev Seeder" in the Dev Tools UI (port 3001) to seed ledger credits for the test user.
5. Refresh the page; verify `available_cents` reflects seeded credits minus hold period.
6. Submit a payout request via the form; verify toast and history row appear.
7. Cancel the pending payout; verify status badge updates to "cancelled" and balance card increases.

### 5.4 Rollout

No feature flag is required — the route is protected by `ProtectedRoute` in `App.tsx` (requires authentication). The Sidebar entry at `Sidebar.tsx:130` is visible to all authenticated users. Since the backend endpoints were already deployed and tested, activating the UI does not introduce new risk surface. No database migrations needed.

### 5.4 Observability and admin considerations

The payout service has no admin-facing management UI. If a payout gets stuck in `"approved"` or `"processing"` state (e.g., bank transfer fails silently), only a developer with DDB access can diagnose or advance the state. An admin endpoint `GET /ui/admin/payouts?status=processing` querying the `ByStatusCreatedAt` GSI (PK=`processing`, SK=`created_at` N) would unblock support workflows. This is out of scope for BILLING-002 but should be tracked as a follow-up.

The balance recalculation in `get_available_balance()` at `creator_payouts.py:55` loops through the entire billing ledger for the user (`ddb_query_pk(T.billing, pk)`) on every balance request. For users with large ledgers (many transactions over time), this scan may be slow. The `refetchInterval: 30_000` in the dashboard means this query runs every 30 seconds per active user. Mitigation: the service already has a hold-period optimization (skipping credits still within `payout_hold_period_seconds`), but a cached balance summary row would be more efficient at scale.

### 5.5 Earnings breakdown quality

The `_reason_to_category()` mapping at `creator_earnings.py:22-33` uses `reason.lower()` substring matching. This is fragile: if a future feature writes a credit with `reason="Unlock bonus"` (containing "unlock"), it would be correctly categorized. But `reason="Shop sale item"` would fall into `"other"` rather than a hypothetical `"shop"` category. The breakdown categories are hardcoded in `EarningsBreakdown` at `models.py:2315`. Extending categories requires a Pydantic model change, a service-layer change, and a frontend chart update. For now, the `"other"` bucket serves as a catch-all and its dollar amount is shown in the UI to avoid silent data loss.

**Effort estimate**: Implemented (623-line component, full React Query integration, Zod validation). Remaining gap: Playwright E2E spec for the UI layer (`payout-dashboard.spec.ts`) covering balance cards, form submission, cancel flow, and earnings chart rendering. Backend spec (`creator-payouts.spec.ts`) already exists and verifies the API layer.
