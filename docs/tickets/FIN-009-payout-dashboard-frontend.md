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

FIN-009 replaces the minimal payout dashboard stub with a full-featured creator payout management page. The backend is fully implemented in `app/services/creator_payouts.py` (393 lines) and `app/routers/creator_payouts.py` with endpoints for balance, request, cancel, list, and admin operations. The existing frontend at `frontend/src/pages/payouts/PayoutDashboard.tsx` (623 lines) covers basic functionality but is missing payout method management, schedule display, status tracking visuals, admin payout queue, and batch processing. This ticket completes the frontend.

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

### 2.2 Existing Router Endpoints

| Method | Path | Auth | Status |
|--------|------|------|--------|
| `GET` | `/ui/payouts/balance` | `require_ui_session` | Complete |
| `POST` | `/ui/payouts/request` | `require_ui_session` | Complete |
| `POST` | `/ui/payouts/{id}/cancel` | `require_ui_session` | Complete |
| `GET` | `/ui/payouts` | `require_ui_session` | Complete |
| `GET` | `/ui/payouts/admin/list` | `require_admin_session` | Complete |
| `POST` | `/ui/payouts/admin/{id}/approve` | `require_admin_session` | Complete |
| `POST` | `/ui/payouts/admin/{id}/reject` | `require_admin_session` | Complete |
| `GET` | `/ui/payouts/admin/stats` | `require_admin_session` | Complete |

### 2.3 Existing Frontend (Stub)

The current `PayoutDashboard.tsx` (623 lines) includes:
- Balance display cards (available, pending, hold, total earned)
- Request payout dialog with amount/method inputs
- Payout history table with basic status display
- Cancel button on pending payouts

### 2.4 Gaps

1. **No payout method management UI** -- no way to add/edit bank accounts or PayPal.
2. **No payout schedule display** -- no information about automatic payout timing.
3. **No visual status timeline** -- status badges exist but no progress indicator.
4. **No admin payout queue view** -- admin endpoints exist but no admin UI.
5. **No batch processing UI** -- no "Process All" button for admin.
6. **No earnings summary integration** -- the payout page does not show earnings breakdown.
7. **No payout receipt/detail view** -- clicking a payout shows nothing.

### 2.5 New Backend Endpoints Needed

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/payouts/methods` | `require_ui_session` | List creator's payout methods |
| `POST` | `/ui/payouts/methods` | `require_ui_session` | Add payout method |
| `PUT` | `/ui/payouts/methods/{id}` | `require_ui_session` | Update payout method |
| `DELETE` | `/ui/payouts/methods/{id}` | `require_ui_session` | Delete payout method |
| `POST` | `/ui/payouts/methods/{id}/default` | `require_ui_session` | Set as default payout method |
| `GET` | `/ui/payouts/schedule` | `require_ui_session` | Get payout schedule info |
| `GET` | `/ui/payouts/{id}` | `require_ui_session` | Get single payout detail |
| `POST` | `/ui/payouts/admin/batch-complete` | `require_admin_session` | Batch complete approved payouts |

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

**Extend**: `app/routers/creator_payouts.py` (~120 additional lines)

Add the new endpoints listed in section 2.5.

### 3.4 Request/Response Models

**Add to `app/models.py`**:

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

### 3.5 Frontend Components

**Rewrite**: `frontend/src/pages/payouts/PayoutDashboard.tsx` (~800 lines, replacing 623)

The existing file is extended with new sections. Use tabs to organize the expanded content.

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
  api.post<BatchCompleteOut>("/ui/payouts/admin/batch-complete");
```

### 3.7 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/e2e/fin-payouts.spec.ts` | E2E tests | ~400 |

### 3.8 Files to Modify

| File | Change |
|------|--------|
| `app/services/creator_payouts.py` | Add payout method + schedule + batch complete functions |
| `app/routers/creator_payouts.py` | Add new endpoints |
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
| 573.1 | Admin lists pending payouts | GET admin/list?status=requested; items include test payout |
| 573.2 | Admin approves payout | POST admin/{id}/approve; status = "approved" |
| 573.3 | Admin rejects payout with reason | POST admin/{id}/reject with reason; status = "rejected"; reject_reason present |
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

**Total E2E tests: 18**

---

## 6. Security Considerations

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
- Duplicate payout prevention: `_has_active_payout` checks for existing requested/approved/processing payouts.
- Admin approval is required before processing; no auto-approval.
- Batch complete only processes approved payouts (skips requested).

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/creator_payouts.py` | Exists (complete backend) | All payout operations |
| `app/routers/creator_payouts.py` | Exists (core endpoints) | Extend with new endpoints |
| `app/services/creator_earnings.py` | Exists | Earnings breakdown for dashboard |
| `app/services/billing_shared.py` | Exists | Balance calculations |
| `frontend/src/pages/payouts/PayoutDashboard.tsx` | Exists (stub) | Rewrite target |
| `frontend/src/api/endpoints/payouts.ts` | Exists | Extend with new wrappers |

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
