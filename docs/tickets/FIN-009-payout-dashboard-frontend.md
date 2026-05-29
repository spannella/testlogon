# FIN-009: Payout Dashboard Frontend

**Ticket**: FIN-009
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-009 replaces the minimal payout dashboard stub with a full-featured creator payout management page. The backend is fully implemented in `app/services/creator_payouts.py` (443 lines) and `app/routers/creator_payouts.py` (user-facing, 105 lines) + `app/routers/admin_payouts.py` (admin, 104 lines) with endpoints for balance, request, cancel, list, and admin operations. The existing frontend at `frontend/src/pages/payouts/PayoutDashboard.tsx` (623 lines) covers basic functionality but is missing payout method management, schedule display, status tracking visuals, admin payout queue, and batch processing. This ticket completes the frontend.
<!-- VERIFIED: app/services/creator_payouts.py — 443 lines total -->
<!-- VERIFIED: app/routers/creator_payouts.py — 105 lines, prefix="/ui/payouts" -->
<!-- VERIFIED: app/routers/admin_payouts.py — 104 lines, prefix="/v1/admin/payouts" -->
<!-- VERIFIED: frontend/src/pages/payouts/PayoutDashboard.tsx — 623 lines -->
<!-- NOTE: Ticket says "393 lines" for creator_payouts.py — actual is 443 lines -->
<!-- NOTE: Admin endpoints are NOT in creator_payouts.py router — they are in a SEPARATE app/routers/admin_payouts.py -->

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to see my available balance and pending payout amounts. | Dashboard shows available, pending, hold, and total earned amounts. |
| Creator | As a creator, I want to request a payout with minimum threshold enforcement. | "Request Payout" button opens dialog; amount validated against minimum and available balance. |
| Creator | As a creator, I want to manage my payout methods (bank, PayPal). | Payout methods section with add/edit/delete/set-default actions. |
| Creator | As a creator, I want to see my payout history with status tracking. | Payout history table shows requested, approved, processing, completed, failed, cancelled statuses with color badges. |
| Creator | As a creator, I want to see when my next automatic payout is scheduled. | Schedule card shows next payout date and frequency. |
| Creator | As a creator, I want to cancel a pending payout request. | Cancel button on pending payout; confirmation dialog; status changes to cancelled. |
| Admin | As an admin, I want to see the pending payout queue. | Admin tab shows all pending payouts across creators, sortable by amount/date. |
| Admin | As an admin, I want to approve or reject payout requests. | Approve/Reject buttons on each pending payout; reject requires reason. |
| Admin | As an admin, I want to batch-process approved payouts. | "Process All Approved" button triggers batch completion. |

### 1.3 Why This Is Needed

The backend payout system is fully operational (`request_payout`, `approve_payout`, `reject_payout`, `complete_payout`, `get_payout_stats`) but the frontend only surfaces basic balance + request functionality. Creators need status tracking, method management, and schedule visibility. Admins need a queue view with batch operations. Without this, admin payout processing happens via direct API calls or scripts.
<!-- VERIFIED: All five functions exist in app/services/creator_payouts.py at lines 164, 292, 321, 351, 393 -->

---

## 2. Current State Analysis

### 2.1 Existing Backend (Complete)

| Function | Location | Status |
|----------|----------|--------|
| `get_available_balance` | `app/services/creator_payouts.py:55` | Complete -- returns available, pending, total_earned, hold |
| `request_payout` | `app/services/creator_payouts.py:164` | Complete -- validates amount, checks balance, creates payout record |
| `cancel_payout` | `app/services/creator_payouts.py:208` | Complete -- validates ownership, checks status=requested |
| `list_user_payouts` | `app/services/creator_payouts.py:235` | Complete -- paginated list via ByUserCreatedAt GSI |
| `list_payouts_admin` | `app/services/creator_payouts.py:256` | Complete -- admin list with optional status filter |
| `approve_payout` | `app/services/creator_payouts.py:292` | Complete -- transitions requested→approved |
| `reject_payout` | `app/services/creator_payouts.py:321` | Complete -- transitions requested→rejected with reason |
| `complete_payout` | `app/services/creator_payouts.py:351` | Complete -- transitions approved→completed |
| `get_payout_stats` | `app/services/creator_payouts.py:393` | Complete -- aggregate stats |

<!-- VERIFIED: All 9 function line numbers confirmed exact against codebase -->

### 2.2 Existing Router Endpoints

<!-- NOTE: User-facing endpoints are in app/routers/creator_payouts.py (prefix="/ui/payouts").
     Admin endpoints are in a SEPARATE file app/routers/admin_payouts.py (prefix="/v1/admin/payouts"),
     NOT at /ui/payouts/admin/* as shown below. The ticket paths must be updated. -->

| Method | Path | Auth | Status |
|--------|------|------|--------|
| `GET` | `/ui/payouts/balance` | `require_ui_session` | Complete |
| `POST` | `/ui/payouts/request` | `require_ui_session` | Complete |
| `POST` | `/ui/payouts/{id}/cancel` | `require_ui_session` | Complete |
| `GET` | `/ui/payouts` | `require_ui_session` | Complete |
| `GET` | `/v1/admin/payouts` | `require_admin_or_root` | Complete |
| `POST` | `/v1/admin/payouts/{id}/approve` | `require_admin_or_root` | Complete |
| `POST` | `/v1/admin/payouts/{id}/reject` | `require_admin_or_root` | Complete |
| `GET` | `/v1/admin/payouts/stats` | `require_admin_or_root` | Complete |
<!-- VERIFIED: app/routers/creator_payouts.py:35-105 — user endpoints at /ui/payouts -->
<!-- VERIFIED: app/routers/admin_payouts.py:32-103 — admin endpoints at /v1/admin/payouts -->
<!-- NOTE: Admin auth uses require_admin_or_root (from app/auth/policy), NOT require_admin_session -->

### 2.3 Pydantic Models

<!-- NOTE: Several models shown below are INCORRECT vs actual codebase.
     Corrections inline. PayoutMethodIn does NOT exist yet — new implementation required. -->

```python
# In app/models.py (ACTUAL — lines 2347-2400)

class PayoutBalanceOut(BaseModel):       # line 2347
    available_cents: int = 0
    pending_cents: int = 0
    total_earned_cents: int = 0
    hold_cents: int = 0
    currency: str = "USD"
    minimum_payout_cents: int = 1000

class PayoutRequestIn(BaseModel):        # line 2356
    amount_cents: int = Field(ge=100)    # NOT ge=2500; actual minimum is 100 cents ($1)
    method: str = "bank_transfer"        # NOT "payout_method_id"
    notes: str = Field(default="", max_length=500)

class PayoutOut(BaseModel):              # line 2362
    payout_id: str
    user_id: str
    amount_cents: int
    method: str = "bank_transfer"        # NOT "currency" / "payout_method_id"
    status: str
    created_at: int
    updated_at: int
    notes: str = ""
    reject_reason: str = ""
    approved_by: str = ""
    completed_at: Optional[int] = None

class PayoutCreateOut(BaseModel):        # line 2376
    ok: bool
    payout_id: str
    amount_cents: int
    status: str

class PayoutListOut(BaseModel):          # line 2383
    items: List[PayoutOut]
    next_cursor: Optional[str] = None

class PayoutActionOut(BaseModel):        # line 2388
    ok: bool
    payout_id: str
    status: str

class PayoutStatsOut(BaseModel):         # line 2394
    total_requested: int = 0
    total_requested_amount_cents: int = 0
    total_approved: int = 0
    total_processing: int = 0
```
<!-- NOTE: PayoutMethodIn does NOT exist in app/models.py — new implementation required for FIN-009 -->
<!-- NOTE: Ticket claimed amount_cents ge=2500 ($25 minimum) but actual is ge=100 ($1).
     However, settings.py:1177 has payout_minimum_cents=1000 ($10) used by balance endpoint. -->

### 2.4 Existing Frontend (Stub)

The current `PayoutDashboard.tsx` (623 lines) includes:
- Balance display cards (available, pending, hold, total earned)
- Request payout dialog with amount/method inputs
- Payout history table with basic status display
- Cancel button on pending payouts
<!-- VERIFIED: frontend/src/pages/payouts/PayoutDashboard.tsx — 623 lines -->
<!-- VERIFIED: frontend/src/api/endpoints/payouts.ts — 57 lines, has getPayoutBalance, requestPayout, cancelPayout, listPayouts, getEarningsSummary, getEarningsTransactions -->
<!-- VERIFIED: Route "/payouts" at frontend/src/App.tsx:186, lazy-loaded at line 67 -->

### 2.4 Gaps

1. **No payout method management UI** -- no way to add/edit bank accounts or PayPal.
2. **No payout schedule display** -- no information about automatic payout timing.
3. **No visual status timeline** -- status badges exist but no progress indicator.
4. **No admin payout queue view** -- admin endpoints exist but no admin UI.
5. **No batch processing UI** -- no "Process All" button for admin.
6. **No earnings summary integration** -- the payout page does not show earnings breakdown.
7. **No payout receipt/detail view** -- clicking a payout shows nothing.

### 2.5 New Backend Endpoints Needed

<!-- NOTE: The batch-complete endpoint should go in app/routers/admin_payouts.py at prefix /v1/admin/payouts,
     NOT at /ui/payouts/admin/batch-complete, to match the existing admin endpoint pattern. -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/payouts/methods` | `require_ui_session` | List creator's payout methods |
| `POST` | `/ui/payouts/methods` | `require_ui_session` | Add payout method |
| `PUT` | `/ui/payouts/methods/{id}` | `require_ui_session` | Update payout method |
| `DELETE` | `/ui/payouts/methods/{id}` | `require_ui_session` | Delete payout method |
| `POST` | `/ui/payouts/methods/{id}/default` | `require_ui_session` | Set as default payout method |
| `GET` | `/ui/payouts/schedule` | `require_ui_session` | Get payout schedule info |
| `GET` | `/ui/payouts/{id}` | `require_ui_session` | Get single payout detail |
| `POST` | `/v1/admin/payouts/batch-complete` | `require_admin_or_root` | Batch complete approved payouts |

---

## 3. Technical Design

### 3.1 Data Model Extensions

#### 3.1.1 Payout Method (CreatorPayouts Table)

**PK**: `payout_id = PM#{user_id}#{method_id}`

| Field | Type | Description |
|-------|------|-------------|
| `payout_id` | S | `PM#{user_id}#{method_id}` (PK) |
| `user_id` | S | Owner user ID |
| `method_id` | S | `pm_<uuid4_hex[:12]>` |
| `method_type` | S | `"bank_transfer"`, `"paypal"`, `"check"` |
| `label` | S | User-friendly label (e.g., "Chase checking ****4567") |
| `is_default` | BOOL | Whether this is the default payout method |
| `details` | M | Method-specific details (account last4, PayPal email, etc.) |
| `status` | S | `"active"`, `"inactive"` |
| `created_at` | N | Creation timestamp |
| `updated_at` | N | Last update timestamp |

GSI `ByUserCreatedAt` already exists (`user_id` PK, `created_at` SK), so payout methods stored with this schema will be queryable alongside payout records. To distinguish, filter by `payout_id` prefix `PM#`.
<!-- VERIFIED: scripts/local-ddb-init.py:763-770 — CreatorPayouts table with GSIs ByUserCreatedAt and ByStatusCreatedAt -->

#### 3.1.2 Payout Schedule (CreatorPayouts Table)

**PK**: `payout_id = SCHEDULE#{user_id}`

| Field | Type | Description |
|-------|------|-------------|
| `user_id` | S | Creator user ID |
| `frequency` | S | `"weekly"`, `"biweekly"`, `"monthly"`, `"manual"` |
| `next_payout_date` | S | `YYYY-MM-DD` |
| `minimum_amount_cents` | N | Minimum amount for auto-payout |
| `method_id` | S | Default payout method to use |
| `enabled` | BOOL | Whether automatic payouts are active |
| `updated_at` | N | Last update timestamp |

### 3.2 Backend Service Extension

**Extend**: `app/services/creator_payouts.py` (~150 additional lines)
<!-- VERIFIED: app/services/creator_payouts.py — currently 443 lines, will grow to ~593 -->
<!-- NOTE: Functions list_payout_methods, add_payout_method, update_payout_method, delete_payout_method,
     set_default_payout_method, get_payout_schedule, get_payout_detail, batch_complete_payouts
     do NOT exist yet — new implementation required -->

```python
# -- Payout Methods (FIN-009) --

def list_payout_methods(user_id: str) -> List[Dict[str, Any]]:
    """List all payout methods for a user."""
    ...

def add_payout_method(
    user_id: str,
    method_type: str,
    label: str,
    details: Dict[str, Any],
    is_default: bool = False,
) -> Dict[str, Any]:
    """Add a new payout method."""
    ...

def update_payout_method(
    user_id: str,
    method_id: str,
    label: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Update an existing payout method."""
    ...

def delete_payout_method(user_id: str, method_id: str) -> bool:
    """Delete a payout method. Cannot delete the default if it's the only one."""
    ...

def set_default_payout_method(user_id: str, method_id: str) -> Dict[str, Any]:
    """Set a payout method as the default."""
    ...

def get_payout_schedule(user_id: str) -> Dict[str, Any]:
    """Get the payout schedule for a creator."""
    ...

def get_payout_detail(payout_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Get full details for a single payout."""
    ...

def batch_complete_payouts(admin_user_id: str) -> Dict[str, Any]:
    """Complete all approved payouts. Returns {completed, failed, total}."""
    ...
```

### 3.3 Router Extensions

**Extend**: `app/routers/creator_payouts.py` (~120 additional lines) for payout methods + schedule + detail endpoints.
**Extend**: `app/routers/admin_payouts.py` (~20 additional lines) for batch-complete endpoint.

Add the new endpoints listed in section 2.5.
<!-- VERIFIED: app/routers/creator_payouts.py — currently 105 lines -->
<!-- VERIFIED: app/routers/admin_payouts.py — currently 104 lines -->

### 3.4 Request/Response Models

**Add to `app/models.py`** (currently ~2400+ lines, payout models at lines 2347-2400):

```python
# -- Payout Dashboard Frontend (FIN-009) --

class PayoutMethodIn(BaseModel):
    method_type: str = Field(pattern="^(bank_transfer|paypal|check)$")
    label: str = Field(min_length=3, max_length=100)
    details: Dict[str, Any] = Field(default_factory=dict)
    is_default: bool = False

class PayoutMethodOut(BaseModel):
    method_id: str
    method_type: str
    label: str
    is_default: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)
    status: str = "active"
    created_at: int = 0

class PayoutMethodListOut(BaseModel):
    items: List[PayoutMethodOut] = Field(default_factory=list)

class PayoutScheduleOut(BaseModel):
    frequency: str = "manual"
    next_payout_date: str = ""
    minimum_amount_cents: int = 0
    method_id: str = ""
    enabled: bool = False

class PayoutDetailOut(PayoutOut):
    earnings_breakdown: Dict[str, int] = Field(default_factory=dict)
    method_label: str = ""

class BatchCompleteOut(BaseModel):
    completed: int = 0
    failed: int = 0
    total: int = 0
```
<!-- NOTE: All 7 models above (PayoutMethodIn through BatchCompleteOut) do NOT exist yet in app/models.py — new implementation required -->
<!-- NOTE: PayoutDetailOut extends PayoutOut which uses field "method" (not "payout_method_id") — ensure consistency -->

### 3.5 Frontend Components

**Rewrite**: `frontend/src/pages/payouts/PayoutDashboard.tsx` (~800 lines, replacing 623)

The existing file is extended with new sections. Use tabs to organize the expanded content.
<!-- VERIFIED: frontend/src/pages/payouts/PayoutDashboard.tsx — 623 lines, exists and will be rewritten -->

**Component tree**:

```
PayoutDashboard
├── Tabs
│   ├── Tab: "Overview"
│   │   ├── BalanceCards (4-card grid)
│   │   │   ├── Card: "Available" (green, DollarSign icon)
│   │   │   ├── Card: "Pending Payouts" (yellow, Clock icon)
│   │   │   ├── Card: "On Hold" (gray, Lock icon)
│   │   │   └── Card: "Total Earned" (blue, TrendingUp icon)
│   │   ├── EarningsBreakdown (pie chart / bar)
│   │   │   ├── Subscriptions segment
│   │   │   ├── Tips segment
│   │   │   ├── Unlocks segment
│   │   │   └── Other segment
│   │   ├── RequestPayoutDialog
│   │   │   ├── Amount input (validates min threshold + available)
│   │   │   ├── Method selector (from payout methods)
│   │   │   ├── Notes textarea
│   │   │   └── Button: "Request Payout"
│   │   └── ScheduleCard
│   │       ├── Frequency display
│   │       ├── Next payout date
│   │       └── Minimum amount
│   ├── Tab: "Payout History"
│   │   └── DataTable
│   │       ├── Column: Date (formatted)
│   │       ├── Column: Amount (formatted cents)
│   │       ├── Column: Method (badge)
│   │       ├── Column: Status (colored badge with icon)
│   │       │   ├── "requested" → yellow
│   │       │   ├── "approved" → blue
│   │       │   ├── "processing" → purple
│   │       │   ├── "completed" → green
│   │       │   ├── "failed" → red
│   │       │   └── "cancelled" → gray
│   │       ├── Column: Actions (Cancel button for requested)
│   │       └── Pagination
│   ├── Tab: "Payout Methods"
│   │   ├── MethodList
│   │   │   ├── MethodCard (per method)
│   │   │   │   ├── Method type icon (Bank / PayPal / Check)
│   │   │   │   ├── Label
│   │   │   │   ├── Details (last 4, email, etc.)
│   │   │   │   ├── Default badge
│   │   │   │   ├── "Set Default" button
│   │   │   │   ├── "Edit" button
│   │   │   │   └── "Delete" button
│   │   │   └── Empty state: "No payout methods configured"
│   │   └── AddMethodDialog
│   │       ├── Method type selector
│   │       ├── Label input
│   │       ├── Details fields (type-specific)
│   │       │   ├── Bank: routing #, account # (last 4), account type
│   │       │   ├── PayPal: email
│   │       │   └── Check: mailing address
│   │       └── Button: "Add Method"
│   └── Tab: "Admin Queue" (admin/root only)
│       ├── StatsCards
│       │   ├── Total Requested count
│       │   ├── Total Requested amount
│       │   ├── Approved count
│       │   └── Processing count
│       ├── AdminPayoutTable
│       │   ├── Column: Creator
│       │   ├── Column: Amount
│       │   ├── Column: Method
│       │   ├── Column: Status
│       │   ├── Column: Requested Date
│       │   └── Column: Actions (Approve / Reject buttons)
│       ├── RejectDialog
│       │   ├── Reason textarea (required)
│       │   └── Button: "Reject Payout"
│       └── Button: "Process All Approved" (batch complete)
```

### 3.6 New Frontend API Endpoints

**Extend**: `frontend/src/api/endpoints/payouts.ts` (~60 additional lines)
<!-- VERIFIED: frontend/src/api/endpoints/payouts.ts — currently 57 lines with getPayoutBalance, requestPayout, cancelPayout, listPayouts, getEarningsSummary, getEarningsTransactions -->

```typescript
// Payout methods
export const listPayoutMethods = () =>
  api.get<PayoutMethodListOut>("/ui/payouts/methods");

export const addPayoutMethod = (data: PayoutMethodIn) =>
  api.post<PayoutMethodOut>("/ui/payouts/methods", data);

export const updatePayoutMethod = (methodId: string, data: Partial<PayoutMethodIn>) =>
  api.put<PayoutMethodOut>(`/ui/payouts/methods/${methodId}`, data);

export const deletePayoutMethod = (methodId: string) =>
  api.del<{ ok: boolean }>(`/ui/payouts/methods/${methodId}`);

export const setDefaultPayoutMethod = (methodId: string) =>
  api.post<PayoutMethodOut>(`/ui/payouts/methods/${methodId}/default`);

export const getPayoutSchedule = () =>
  api.get<PayoutScheduleOut>("/ui/payouts/schedule");

export const getPayoutDetail = (payoutId: string) =>
  api.get<PayoutDetailOut>(`/ui/payouts/${payoutId}`);

// Admin
export const batchCompletePayouts = () =>
  api.post<BatchCompleteOut>("/v1/admin/payouts/batch-complete");
```
<!-- NOTE: Admin batch-complete must use /v1/admin/payouts/ prefix (per app/routers/admin_payouts.py:32), NOT /ui/payouts/admin/ -->

### 3.7 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/e2e/fin-payouts.spec.ts` | E2E tests | ~400 |

### 3.8 Files to Modify

| File | Change |
|------|--------|
| `app/services/creator_payouts.py` | Add payout method + schedule + batch complete functions |
| `app/routers/creator_payouts.py` | Add payout methods, schedule, detail endpoints |
| `app/routers/admin_payouts.py` | Add batch-complete endpoint |
| `app/models.py` | Add PayoutMethod*, PayoutSchedule*, BatchComplete* models |
| `frontend/src/pages/payouts/PayoutDashboard.tsx` | Full rewrite with tabs, methods, schedule, admin |
| `frontend/src/api/endpoints/payouts.ts` | Add new API wrappers |
| `frontend/src/api/types.ts` | Add TypeScript interfaces |

---

## 4. Status Tracking Visuals

### 4.1 Status Badge Colors

| Status | Color | Icon | Description |
|--------|-------|------|-------------|
| `requested` | Yellow/Amber | Clock | Awaiting admin review |
| `approved` | Blue | CheckCircle | Approved, awaiting processing |
| `processing` | Purple | Loader | Transfer in progress |
| `completed` | Green | CheckCheck | Funds sent |
| `failed` | Red | XCircle | Transfer failed |
| `cancelled` | Gray | Ban | Cancelled by creator |
| `rejected` | Red | XOctagon | Rejected by admin |

### 4.2 Status Timeline (Payout Detail View)

When clicking a payout row, a detail panel shows a vertical timeline:

```
● Requested — May 15, 2026
● Approved — May 16, 2026 (by admin@platform.com)
● Processing — May 17, 2026
● Completed — May 18, 2026
```

Each step shows the timestamp and actor (if applicable). Steps not yet reached are grayed out.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/fin-payouts.spec.ts`

### Section 571: Payout Methods API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 571.1 | Add bank transfer payout method | POST /payouts/methods; 201; method_type = "bank_transfer" |
| 571.2 | Add PayPal payout method | POST with method_type=paypal; 201; label includes "PayPal" |
| 571.3 | Set default payout method | POST /payouts/methods/{id}/default; GET methods; is_default = true |
| 571.4 | Delete non-default payout method | DELETE; 200; GET methods; deleted method absent |

### Section 572: Payout Lifecycle API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 572.1 | Request payout with sufficient balance | Seed credits; POST request; 201; status = "requested" |
| 572.2 | Request below minimum threshold rejected | POST with amount < minimum; 400; error mentions minimum |
| 572.3 | Cancel pending payout | POST cancel; 200; status = "cancelled" |
| 572.4 | Cannot cancel non-pending payout | Cancel completed payout; 400; error |

### Section 573: Admin Payout Queue API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 573.1 | Admin lists pending payouts | GET /v1/admin/payouts?status=requested; items include test payout |
| 573.2 | Admin approves payout | POST /v1/admin/payouts/{id}/approve; status = "approved" |
| 573.3 | Admin rejects payout with reason | POST /v1/admin/payouts/{id}/reject with reason; status = "rejected"; reject_reason present |
| 573.4 | Batch complete processes approved payouts | Approve payout; POST batch-complete; completed >= 1 |

### Section 574: Payout Dashboard UI (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 574.1 | Dashboard shows balance cards | Navigate to /payouts; "Available", "Pending", "On Hold", "Total Earned" visible |
| 574.2 | Request Payout dialog opens | Click "Request Payout"; dialog with amount input visible |
| 574.3 | Payout History tab shows payout records | Click "Payout History" tab; table with status badges visible |
| 574.4 | Payout Methods tab shows methods | Click "Payout Methods" tab; method cards or empty state visible |
| 574.5 | Add Method dialog creates a method | Click "Add Method"; fill form; submit; new method appears in list |
| 574.6 | Admin Queue tab visible for admin user | Root navigates to /payouts; "Admin Queue" tab visible |

### Section 575: Payout Edge Cases & Negative Tests (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 575.1 | Request payout with zero balance | POST request; 400; "Insufficient balance" |
| 575.2 | Request exceeds available balance | POST amount > available; 400; error message |
| 575.3 | Duplicate active payout request | Request payout; request again before first processed; 409; "Active payout exists" |
| 575.4 | Delete default payout method fails | DELETE default method; 400; "Cannot delete default method" |
| 575.5 | Admin rejects payout — creator sees rejected status | Admin rejects; creator GET history; status="rejected" with reason |

### Section 576: Concurrent Access Tests (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 576.1 | Two creators request payouts simultaneously | Both succeed with distinct payout IDs |
| 576.2 | Admin approves while creator cancels | Race condition: whichever completes first wins; other gets 400 |
| 576.3 | Balance recalculation after payout | Request and complete payout; available balance reduced by payout amount |

**Total E2E tests: 26**

---

## 6. API Request/Response Examples

**Request a payout** (curl):

```bash
curl -X POST http://localhost:8000/ui/payouts/request \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_a" \
  -d '{"amount_cents": 5000, "payout_method_id": "pm_bank_123"}'
```

**Response (201)**:
```json
{
  "payout_id": "po_abc123",
  "amount_cents": 5000,
  "currency": "usd",
  "status": "requested",
  "payout_method_id": "pm_bank_123",
  "created_at": 1748520100
}
```

**Get payout balance** (curl):

```bash
curl -X GET http://localhost:8000/ui/payouts/balance \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "available_cents": 15000,
  "pending_cents": 5000,
  "hold_cents": 2000,
  "total_earned_cents": 45000
}
```

**Admin approve payout** (curl):

```bash
curl -X POST http://localhost:8000/v1/admin/payouts/po_abc123/approve \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_r; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_r"
```

**Response (200)**:
```json
{"ok": true, "payout_id": "po_abc123", "status": "approved"}
```

---

## 7. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Insufficient balance | 400 | `insufficient_balance` | "Insufficient balance for payout" | Earn more or reduce amount |
| Below minimum threshold | 400 | `below_minimum` | "Minimum payout is $10.00" | Increase amount |
<!-- NOTE: Actual payout_minimum_cents in settings.py:1177 is 1000 ($10.00), NOT 2500 ($25.00) -->
| Active payout exists | 409 | `active_payout_exists` | "You already have a pending payout" | Wait or cancel existing |
| Cancel non-pending payout | 400 | `cannot_cancel` | "Only pending payouts can be cancelled" | No action |
| Delete default method | 400 | `cannot_delete_default` | "Set another method as default first" | Change default then delete |
| Payout not found | 404 | `not_found` | "Payout not found" | Check payout ID |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Log in |
| Non-admin access to admin | 403 | `forbidden` | "Admin access required" | Use admin account |

---

## 8. Observability

### 8.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `payout_requested_total` | Counter | `method_type` | Payouts requested |
| `payout_approved_total` | Counter | — | Payouts approved by admin |
| `payout_rejected_total` | Counter | `reason` | Payouts rejected |
| `payout_completed_total` | Counter | — | Payouts completed |
| `payout_amount_cents` | Histogram | — | Payout amounts |
| `payout_processing_latency_hours` | Histogram | — | Time from request to completion |

### 8.2 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Payout queue backlog | > 50 pending payouts for > 24h | High | Admin review queue |
| High rejection rate | > 20% of payouts rejected | Medium | Review rejection reasons |
| Payout amount anomaly | Single payout > $10,000 | High | Manual review required |

---

## 9. Rollout Plan

### 9.1 Feature Flag

```python
payout_dashboard_enabled: bool = os.environ.get("PAYOUT_DASHBOARD_ENABLED", "true").lower() == "true"
```
<!-- NOTE: payout_dashboard_enabled does NOT exist yet in app/core/settings.py — new addition required.
     Existing payout settings at lines 1176-1177: payout_hold_period_seconds and payout_minimum_cents -->

### 9.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend | Deploy payout endpoints; flag OFF | 2 days | Unit tests pass |
| Phase 2: Internal | Enable dashboard for internal | 3 days | All 26 E2E pass |
| Phase 3: Canary | Enable for 10% of creators | 3 days | No financial errors |
| Phase 4: GA | Enable for all | Permanent | Admin workflow smooth |

### 9.3 Rollback

1. Set flag OFF — dashboard shows read-only balance
2. Pending payouts remain in queue (admin can still process via API)
3. No financial data loss

---

## 10. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| All creator endpoints | `require_ui_session` | Returns only caller's data |
| Admin list/approve/reject/batch | `require_admin_session` | Admin role required |
| Cancel payout | `require_ui_session` | Validates payout belongs to caller |

### 6.2 Payout Method Sensitivity

- Bank account numbers: only store last 4 digits. Full details are never returned via API.
- PayPal email: stored in full (needed for disbursement).
- Method details are user-specific and scoped by `user_id`.

### 6.3 Financial Safety

- `request_payout` validates amount against available balance (computed in real-time from ledger).
<!-- VERIFIED: app/services/creator_payouts.py:164 — request_payout validates balance -->
- Duplicate payout prevention: `_has_active_payout` checks for existing requested/approved/processing payouts.
<!-- VERIFIED: app/services/creator_payouts.py:138 — _has_active_payout function -->
- Admin approval is required before processing; no auto-approval.
- Batch complete only processes approved payouts (skips requested).

---

## 11. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Balance computation | < 100ms | Sum ledger entries in DDB; cache result per request |
| Payout history list | < 50ms for 100 payouts | GSI on user_sub + created_at; paginated |
| Admin queue query | < 200ms for 500 pending | GSI on status + created_at |
| Batch complete throughput | 50 payouts/batch | Sequential processing with error isolation |
| Dashboard initial load | < 500ms | Parallel queries: balance + history + methods + schedule |
| Optimistic UI for cancel | Instant | Remove from cache before API response |

---

## 12. Frontend Component Tree

```
PayoutDashboard
├── BalanceCards (row of 4 stat cards)
│   ├── AvailableBalanceCard
│   ├── PendingBalanceCard
│   ├── HoldBalanceCard
│   └── TotalEarnedCard
├── RequestPayoutButton → opens RequestPayoutDialog
│   ├── AmountInput
│   ├── PayoutMethodSelector
│   └── ConfirmButton
├── Tabs
│   ├── PayoutHistoryTab
│   │   └── PayoutTable
│   │       └── PayoutRow (status badge, amount, date, method, cancel button)
│   ├── PayoutMethodsTab
│   │   ├── MethodCard (for each method)
│   │   │   ├── MethodDetails (type, label, last4/email)
│   │   │   ├── DefaultBadge (if is_default)
│   │   │   └── Actions (set default, edit, delete)
│   │   └── AddMethodButton → AddMethodDialog
│   ├── PayoutScheduleTab
│   │   ├── NextPayoutCard
│   │   ├── ScheduleSettings (frequency, minimum threshold)
│   │   └── AutoPayoutToggle
│   └── AdminQueueTab (root/admin only)
│       └── AdminPayoutTable
│           └── AdminPayoutRow (approve button, reject button with reason input)
└── BatchCompleteButton (admin only)
```

---

## 13. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/creator_payouts.py` | Exists (443 lines, complete backend) | All payout operations |
| `app/routers/creator_payouts.py` | Exists (105 lines, user endpoints) | Extend with methods/schedule/detail endpoints |
| `app/routers/admin_payouts.py` | Exists (104 lines, admin endpoints) | Extend with batch-complete endpoint |
| `app/services/creator_earnings.py` | Exists | Earnings breakdown for dashboard |
| `app/services/billing_shared.py` | Exists | Balance calculations |
| `frontend/src/pages/payouts/PayoutDashboard.tsx` | Exists (623 lines, functional stub) | Rewrite target |
| `frontend/src/api/endpoints/payouts.ts` | Exists (57 lines) | Extend with new wrappers |
<!-- VERIFIED: All 7 dependencies exist in codebase -->
<!-- VERIFIED: app/main.py:434 — creator_payouts_router registered -->
<!-- VERIFIED: app/main.py:435 — admin_payouts_router registered -->

---

## 8. Acceptance Criteria

1. Payout dashboard displays available balance, pending, hold, and total earned.
2. Creator can add, edit, delete, and set default payout methods.
3. Creator can request a payout with minimum threshold enforcement.
4. Payout history shows all payouts with colored status badges.
5. Payout schedule card shows next automatic payout date.
6. Creator can cancel a pending (requested) payout.
7. Admin tab shows pending payout queue with approve/reject actions.
8. Admin can batch-complete all approved payouts.
9. Non-admin users cannot see the Admin Queue tab.
10. All 18 E2E tests pass.

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/creator_payouts.py` | 55 | `get_available_balance` — balance from billing ledger |
| `app/services/creator_payouts.py` | 111 | `_get_active_payout_total` — sum pending/approved/processing |
| `app/services/creator_payouts.py` | 138 | `_has_active_payout` — duplicate payout prevention |
| `app/services/creator_payouts.py` | 164 | `request_payout` — validates amount, creates record |
| `app/services/creator_payouts.py` | 208 | `cancel_payout` — ownership + status check |
| `app/services/creator_payouts.py` | 235 | `list_user_payouts` — paginated via ByUserCreatedAt GSI |
| `app/services/creator_payouts.py` | 256 | `list_payouts_admin` — admin list with status filter |
| `app/services/creator_payouts.py` | 292 | `approve_payout` — requested to approved transition |
| `app/services/creator_payouts.py` | 321 | `reject_payout` — requested to rejected with reason |
| `app/services/creator_payouts.py` | 351 | `complete_payout` — approved to completed transition |
| `app/services/creator_payouts.py` | 393 | `get_payout_stats` — aggregate stats |
| `app/routers/creator_payouts.py` | 32 | Router prefix `/ui/payouts` |
| `app/routers/creator_payouts.py` | 35-105 | User endpoints: balance, request, cancel, list |
| `app/routers/admin_payouts.py` | 32 | Router prefix `/v1/admin/payouts` |
| `app/routers/admin_payouts.py` | 35-103 | Admin endpoints: list, stats, approve, reject, complete |
| `app/main.py` | 111-112 | Router imports (creator_payouts_router, admin_payouts_router) |
| `app/main.py` | 434-435 | Router registrations |
| `app/models.py` | 2347-2353 | `PayoutBalanceOut` (available, pending, total_earned, hold, currency, minimum) |
| `app/models.py` | 2356-2359 | `PayoutRequestIn` (amount_cents ge=100, method, notes) |
| `app/models.py` | 2362-2374 | `PayoutOut` (payout_id, user_id, amount_cents, method, status, etc.) |
| `app/models.py` | 2376-2380 | `PayoutCreateOut` (ok, payout_id, amount_cents, status) |
| `app/models.py` | 2383-2385 | `PayoutListOut` (items + next_cursor) |
| `app/models.py` | 2388-2391 | `PayoutActionOut` (ok, payout_id, status) |
| `app/models.py` | 2394-2399 | `PayoutStatsOut` (total_requested, amount, approved, processing) |
| `app/services/creator_earnings.py` | 47 | `get_earnings_summary` — earnings breakdown |
| `app/core/settings.py` | 1176 | `payout_hold_period_seconds` (default 604800 = 7 days) |
| `app/core/settings.py` | 1177 | `payout_minimum_cents` (default 1000 = $10.00) |
| `scripts/local-ddb-init.py` | 763-770 | CreatorPayouts table with ByUserCreatedAt + ByStatusCreatedAt GSIs |
| `frontend/src/pages/payouts/PayoutDashboard.tsx` | 1-623 | Existing dashboard (rewrite target) |
| `frontend/src/api/endpoints/payouts.ts` | 1-57 | Existing API wrappers (extend) |
| `frontend/src/App.tsx` | 67 | Lazy import of PayoutDashboard |
| `frontend/src/App.tsx` | 186 | Route `/payouts` |
