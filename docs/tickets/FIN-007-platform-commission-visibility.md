# FIN-007: Platform Commission Visibility

**Ticket**: FIN-007
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 7-9 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-007 adds transparent platform commission visibility so creators can see, on every transaction and in aggregate, how much was the gross amount, how much the platform took as a fee, and what their net earnings are. Currently, billing ledger entries record only the net credit to the creator -- the platform fee is deducted silently before writing the ledger entry, and there is no record of the gross amount or fee percentage. This ticket adds commission tracking at the transaction level and a summary dashboard showing totals.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to see the platform fee on every transaction. | Each billing history entry shows gross, fee amount, fee %, and net. |
| Creator | As a creator, I want to see my total fees paid over a period. | Dashboard card shows total gross, total fees, total net for selected date range. |
| Creator | As a creator, I want to know the commission rate for each revenue type. | Commission rates page shows rate per transaction type (tips, unlocks, subscriptions, shop). |
| Admin | As an admin, I want to configure commission rates per transaction type. | Admin panel to set/update rates; changes apply to future transactions only. |
| Creator | As a creator, I want to understand why different transactions have different fee rates. | Tooltip or info section explains rate tiers. |
| System | Commission rates must be stored and auditable, not hardcoded. | Rates stored in DynamoDB with change history. |

### 1.3 Why This Is Needed

Creator trust requires financial transparency. Without visible commission breakdowns, creators cannot verify they are being charged the correct rate, cannot forecast their actual income, and cannot compare rates across platforms. The billing ledger already exists (`billing_shared.py:new_ledger_entry`) but records only the net amount. Adding `gross_amount_cents` and `platform_fee_cents` to the `meta` dict of each ledger entry enables full transparency without changing the core ledger schema.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Billing shared | `app/services/billing_shared.py:217-248` | `new_ledger_entry` writes credits; `meta` dict is extensible |
| Creator earnings | `app/services/creator_earnings.py:47-114` | `get_earnings_summary` aggregates credits by category |
| Earnings transactions | `app/services/creator_earnings.py:117+` | `get_earnings_transactions` returns paginated ledger entries |
| Tip ledger | `app/services/tip_ledger.py` | Writes paired debit/credit entries for tips |
| Syndicate split | `app/services/syndicate_revenue_split.py` | Already implements `platform_fee_pct` deduction before splits |
| Payout balance | `app/services/creator_payouts.py:55-108` | `get_available_balance` sums all credits |
| Settings | `app/core/settings.py` | Config via env vars; no commission rate settings yet |

### 2.2 Current Fee Handling

Today, platform fees are applied inconsistently:

1. **Tips**: The full tip amount is credited to the creator. No platform fee deducted.
2. **Unlocks**: The full unlock price is credited. No platform fee.
3. **Subscriptions**: Revenue recorded in `subscription_server.py` -- fee handling varies.
4. **Syndicate splits**: `syndicate_revenue_split.py` deducts `platform_fee_pct` (default 15%) before distributing. This is the only place with explicit fee logic.

### 2.3 Gaps

1. **No commission rate configuration** -- rates are either hardcoded or non-existent.
2. **No gross/fee/net fields** on billing ledger entries -- only net amount stored.
3. **No commission summary** dashboard or API endpoint.
4. **No per-transaction fee display** in billing history UI.
5. **No admin UI** for managing commission rates.
6. **No audit trail** for rate changes.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 Commission Rate Configuration (Billing Table)

**PK**: `PLATFORM`, **SK**: `COMMISSION_RATES`

| Field | Type | Description |
|-------|------|-------------|
| `rates` | M | Map of `{transaction_type: {rate_pct: N, min_fee_cents: N, max_fee_cents: N}}` |
| `updated_at` | N | Last update timestamp |
| `updated_by` | S | Admin who last updated |

Default rates:

```json
{
  "tips": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
  "unlocks": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
  "subscriptions": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
  "shop_sales": {"rate_pct": 15, "min_fee_cents": 0, "max_fee_cents": 0},
  "vod_purchases": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
  "call_revenue": {"rate_pct": 25, "min_fee_cents": 0, "max_fee_cents": 0}
}
```

#### 3.1.2 Commission Rate Audit Log (Billing Table)

**PK**: `PLATFORM`, **SK**: `COMMISSION_AUDIT#{timestamp}#{audit_id}`

| Field | Type | Description |
|-------|------|-------------|
| `audit_id` | S | Unique audit entry ID |
| `action` | S | `"rates_updated"` |
| `previous_rates` | M | Snapshot of rates before change |
| `new_rates` | M | Snapshot of rates after change |
| `changed_by` | S | Admin user ID |
| `created_at` | N | Timestamp |

#### 3.1.3 Enhanced Ledger Entry Meta

Existing ledger entries gain three new fields in `meta`:

```python
meta = {
    ...existing_fields,
    "gross_amount_cents": 1000,      # Original transaction amount
    "platform_fee_cents": 200,       # Fee deducted
    "platform_fee_pct": 20,          # Rate applied
}
```

The `amount_cents` on the ledger entry remains the net (creator's share). The gross and fee are in `meta` for display purposes.

### 3.2 Backend Service

**New file**: `app/services/platform_commission.py` (~250 lines)

```python
"""Platform commission rate management and fee calculation (FIN-007)."""

from __future__ import annotations
import logging
from math import floor
from typing import Any, Dict, Optional
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ulidish

logger = logging.getLogger(__name__)

DEFAULT_RATES = {
    "tips": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
    "unlocks": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
    "subscriptions": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
    "shop_sales": {"rate_pct": 15, "min_fee_cents": 0, "max_fee_cents": 0},
    "vod_purchases": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
    "call_revenue": {"rate_pct": 25, "min_fee_cents": 0, "max_fee_cents": 0},
}


def get_commission_rates() -> Dict[str, Any]:
    """Get current platform commission rates."""
    ...


def update_commission_rates(
    admin_user_id: str,
    rates: Dict[str, Dict[str, int]],
) -> Dict[str, Any]:
    """Update commission rates. Writes audit log entry."""
    ...


def calculate_commission(
    transaction_type: str,
    gross_amount_cents: int,
) -> Dict[str, int]:
    """Calculate fee and net for a gross amount.

    Returns: {gross_amount_cents, platform_fee_cents, net_amount_cents, rate_pct}
    """
    ...


def get_commission_summary(
    user_id: str,
    from_ts: int = 0,
    to_ts: int = 0,
) -> Dict[str, Any]:
    """Aggregate gross, fees, and net from ledger entries with commission meta.

    Returns: {total_gross, total_fees, total_net, breakdown_by_type}
    """
    ...


def get_rate_audit_log(limit: int = 50) -> list:
    """Get commission rate change history for admin review."""
    ...
```

### 3.3 Backend Router

**New file**: `app/routers/platform_commission.py` (~120 lines)

### 3.4 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/commission/rates` | `require_ui_session` | Get current commission rates (public to all creators) |
| `PUT` | `/ui/commission/rates` | `require_admin_session` | Update commission rates (admin only) |
| `GET` | `/ui/commission/rates/audit` | `require_admin_session` | Get rate change audit log |
| `GET` | `/ui/commission/summary` | `require_ui_session` | Get commission summary for authenticated creator |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Platform Commission Visibility (FIN-007) --

class CommissionRateEntry(BaseModel):
    rate_pct: int = Field(ge=0, le=100)
    min_fee_cents: int = Field(default=0, ge=0)
    max_fee_cents: int = Field(default=0, ge=0)

class CommissionRatesOut(BaseModel):
    rates: Dict[str, CommissionRateEntry] = Field(default_factory=dict)
    updated_at: int = 0
    updated_by: str = ""

class CommissionRatesUpdateIn(BaseModel):
    rates: Dict[str, CommissionRateEntry]

class CommissionSummaryBreakdown(BaseModel):
    transaction_type: str
    gross_cents: int = 0
    fee_cents: int = 0
    net_cents: int = 0
    rate_pct: int = 0
    transaction_count: int = 0

class CommissionSummaryOut(BaseModel):
    total_gross_cents: int = 0
    total_fee_cents: int = 0
    total_net_cents: int = 0
    breakdown: List[CommissionSummaryBreakdown] = Field(default_factory=list)
    currency: str = "USD"

class CommissionAuditEntry(BaseModel):
    audit_id: str
    action: str
    changed_by: str
    created_at: int
    previous_rates: Dict[str, Any] = Field(default_factory=dict)
    new_rates: Dict[str, Any] = Field(default_factory=dict)
```

### 3.6 Integration with Existing Billing Flows

Each billing flow that writes a creator credit must be updated to:

1. Call `calculate_commission(transaction_type, gross_amount)` to get the fee.
2. Write the credit with `amount_cents = net_amount_cents`.
3. Include `gross_amount_cents`, `platform_fee_cents`, `platform_fee_pct` in `meta`.

Integration points:

| Flow | File | Change |
|------|------|--------|
| Tip credits | `app/services/tip_ledger.py` | Deduct fee before crediting; add meta fields |
| Unlock credits | `app/routers/messaging.py` (unlock path) | Deduct fee; add meta |
| Subscription credits | `app/routers/subscription_server.py` | Deduct fee; add meta |
| Shop sale credits | `app/services/catalog_orders.py` | Deduct fee; add meta |
| VOD purchase credits | `app/services/vod_purchases.py` | Deduct fee; add meta |

### 3.7 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/billing/CommissionPage.tsx` | Commission rates + summary dashboard | ~300 |
| `frontend/src/api/endpoints/commission.ts` | API wrappers | ~35 |

**Component tree for CommissionPage**:

```
CommissionPage
├── Card: "Commission Summary"
│   ├── DateRangePicker (from/to)
│   ├── Summary Grid (3 columns)
│   │   ├── "Total Gross" — large number
│   │   ├── "Platform Fees" — large number (red)
│   │   └── "Your Net" — large number (green)
│   └── Breakdown Table
│       ├── Column: Revenue Type
│       ├── Column: Rate (%)
│       ├── Column: Gross
│       ├── Column: Fees
│       ├── Column: Net
│       └── Column: Transactions
├── Card: "Commission Rates"
│   ├── Rate Table
│   │   ├── Row: Tips — 20%
│   │   ├── Row: Unlocks — 20%
│   │   ├── Row: Subscriptions — 20%
│   │   ├── Row: Shop Sales — 15%
│   │   ├── Row: VOD Purchases — 20%
│   │   └── Row: Call Revenue — 25%
│   └── Info text: "Rates are set by the platform and may change."
└── [Admin Only] Card: "Update Rates"
    ├── Editable rate inputs per type
    └── Button: "Save Rates"
```

### 3.8 Billing History Enhancement

The existing billing history page (`frontend/src/pages/billing/`) should be enhanced to show gross/fee/net columns when commission meta is present on a transaction. This is a display-only change in the existing `BillingHistory` component.

### 3.9 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/platform_commission.py` | Commission rate management + fee calculation | ~250 |
| `app/routers/platform_commission.py` | Commission API endpoints | ~120 |
| `frontend/src/pages/billing/CommissionPage.tsx` | Commission dashboard UI | ~300 |
| `frontend/src/api/endpoints/commission.ts` | API wrappers | ~35 |
| `frontend/e2e/fin-commission.spec.ts` | E2E tests | ~380 |

### 3.10 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `platform_commission` router |
| `app/models.py` | Add commission models |
| `app/services/tip_ledger.py` | Integrate commission calculation |
| `frontend/src/api/types.ts` | Add TypeScript interfaces |
| `frontend/src/App.tsx` | Add `/billing/commission` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add link under Billing group |

---

## 4. Fee Calculation Rules

### 4.1 Basic Calculation

```
platform_fee_cents = floor(gross_amount_cents * rate_pct / 100)
net_amount_cents = gross_amount_cents - platform_fee_cents
```

### 4.2 Min/Max Fee Caps

If `min_fee_cents > 0`, the fee is at least that amount (unless gross is 0). If `max_fee_cents > 0`, the fee is capped at that amount. This allows "minimum $0.50 fee" or "maximum $50 fee" configurations.

### 4.3 Retroactivity

Rate changes apply to future transactions only. Existing ledger entries retain their original `platform_fee_pct` in meta. The summary endpoint calculates totals from stored meta values, not current rates.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/fin-commission.spec.ts`

### Section 563: Commission Rates API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 563.1 | GET rates returns default commission rates | GET /commission/rates; 200; rates object has tips, unlocks, subscriptions keys |
| 563.2 | Admin can update commission rates | PUT /commission/rates with new rates; 200; GET reflects new values |
| 563.3 | Non-admin cannot update rates | Alice (USER) PUT /commission/rates; 403 |
| 563.4 | Rate update writes audit log entry | PUT rates; GET /commission/rates/audit; latest entry shows previous and new rates |

### Section 564: Fee Calculation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 564.1 | Tip credit includes commission meta | Send tip; query billing ledger; credit entry has meta.gross_amount_cents and meta.platform_fee_cents |
| 564.2 | Fee calculation uses correct rate | Set tips rate to 20%; send 1000 cent tip; fee = 200, net = 800 |
| 564.3 | Net credited amount matches gross minus fee | amount_cents on ledger entry equals meta.gross_amount_cents - meta.platform_fee_cents |
| 564.4 | Zero-rate produces zero fee | Set tips rate to 0%; send tip; platform_fee_cents = 0, net = gross |

### Section 565: Commission Summary API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 565.1 | Summary aggregates gross, fees, net | GET /commission/summary; total_gross > 0; total_fee > 0; total_net = total_gross - total_fee |
| 565.2 | Summary filters by date range | GET with from_ts/to_ts; only matching entries included |
| 565.3 | Breakdown groups by transaction type | breakdown array has entries for each revenue type with transactions |
| 565.4 | Summary is scoped to authenticated user | Alice sees only her own commission data; not Bob's |

### Section 566: Commission UI (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 566.1 | Commission page shows summary cards | Navigate to /billing/commission; "Total Gross", "Platform Fees", "Your Net" visible |
| 566.2 | Commission rates table displays all types | Rates table shows Tips, Unlocks, Subscriptions rows with percentages |
| 566.3 | Admin sees rate update form | Root navigates to commission page; editable rate inputs visible |
| 566.4 | Date range filter updates summary | Change date range; summary cards update with new values |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| GET rates | `require_ui_session` | Any authenticated user |
| PUT rates | `require_admin_session` | Admin only |
| GET rates/audit | `require_admin_session` | Admin only |
| GET summary | `require_ui_session` | Returns only caller's data |

### 6.2 Financial Integrity

- Fee calculations use integer arithmetic only (no floating-point currency math).
- The invariant `platform_fee_cents + net_amount_cents == gross_amount_cents` is enforced.
- Rate changes are audited with before/after snapshots.
- Historical ledger entries are immutable; rate changes do not alter past transactions.

### 6.3 Data Access

- Commission summary queries are scoped to `USER#{caller_user_id}`.
- Rate configuration is platform-wide (single record), readable by all creators.
- Rate update requires admin role.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/billing_shared.py` | Exists | Ledger entry meta extension |
| `app/services/tip_ledger.py` | Exists | First integration point for commission deduction |
| `app/services/creator_earnings.py` | Exists | Earnings aggregation must handle commission meta |
| `app/routers/creator_analytics.py` | Exists | Analytics dashboard to reference commission data |

---

## 8. Acceptance Criteria

1. Commission rates are stored in DynamoDB and returned via API.
2. Admin can update rates; changes are audit-logged.
3. Every new ledger credit entry includes gross, fee, and net in meta.
4. Commission summary shows total gross, fees, and net for a date range.
5. Summary breakdown groups by transaction type.
6. Fee calculation uses integer arithmetic with correct rounding.
7. Rate changes apply to future transactions only.
8. Non-admin users can view rates and their own summary but cannot update rates.
9. All 16 E2E tests pass.
