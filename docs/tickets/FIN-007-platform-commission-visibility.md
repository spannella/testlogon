# FIN-007: Platform Commission Visibility

**Ticket**: FIN-007
**Author**: Engineering
**Status**: Implemented
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
| Billing shared | `app/services/billing_shared.py:217` | `new_ledger_entry` writes credits; `meta` dict is extensible |
<!-- VERIFIED: app/services/billing_shared.py:217 — new_ledger_entry -->
| Creator earnings | `app/services/creator_earnings.py:47` | `get_earnings_summary` aggregates credits by category |
<!-- VERIFIED: app/services/creator_earnings.py:47 — get_earnings_summary; :117 — get_earnings_transactions -->
| Earnings transactions | `app/services/creator_earnings.py:117` | `get_earnings_transactions` returns paginated ledger entries |
| Tip ledger | `app/services/tip_ledger.py:88` | `write_tip_ledger` writes paired debit/credit entries for tips |
<!-- VERIFIED: app/services/tip_ledger.py:88 — write_tip_ledger -->
| Syndicate split | `app/services/syndicate_revenue_split.py` | Referenced as implementing `platform_fee_pct` deduction |
<!-- NOTE: app/services/syndicate_revenue_split.py does NOT exist — this is an incorrect reference. Platform fee logic will need to be newly implemented. -->
| Payout balance | `app/services/creator_payouts.py:55` | `get_available_balance` sums all credits |
<!-- VERIFIED: app/services/creator_payouts.py:55 — get_available_balance -->
| Settings | `app/core/settings.py` | Config via env vars; no commission rate settings yet |

### 2.2 Current Fee Handling

Today, platform fees are applied inconsistently:

1. **Tips**: The full tip amount is credited to the creator. No platform fee deducted.
2. **Unlocks**: The full unlock price is credited. No platform fee.
3. **Subscriptions**: Revenue recorded in `subscription_server.py` -- fee handling varies.
4. **Syndicate splits**: `syndicate_revenue_split.py` referenced as deducting `platform_fee_pct` before distributing.
<!-- NOTE: app/services/syndicate_revenue_split.py does NOT exist — this claim is incorrect. No existing fee deduction logic found. -->

### 2.3 Gaps

1. **No commission rate configuration** -- rates are either hardcoded or non-existent.
2. **No gross/fee/net fields** on billing ledger entries -- only net amount stored.
3. **No commission summary** dashboard or API endpoint.
4. **No per-transaction fee display** in billing history UI.
5. **No admin UI** for managing commission rates.
6. **No audit trail** for rate changes.

---

## 3. Technical Design

### 3.1 Architecture & Data Flow

```
Commission Rate Retrieval Flow
──────────────────────────────

  ┌──────────────┐     GET /commission/rates     ┌──────────────────┐
  │  Creator UI  │ ─────────────────────────────▶ │  platform_       │
  │ (Commission  │                                │  commission.py   │
  │   Page)      │ ◀───────────────────────────── │  router          │
  └──────────────┘     CommissionRatesOut          └────────┬─────────┘
                                                           │
                                                           ▼
                                                  ┌──────────────────┐
                                                  │  platform_       │
                                                  │  commission.py   │
                                                  │  service         │
                                                  └────────┬─────────┘
                                                           │
                                    ┌──────────────────────┼──────────────────────┐
                                    ▼                      ▼                      ▼
                           ┌──────────────┐    ┌────────────────┐    ┌──────────────────┐
                           │ Billing DDB  │    │ Billing DDB    │    │ Billing DDB      │
                           │ PK=PLATFORM  │    │ PK=PLATFORM    │    │ PK=USER#{uid}    │
                           │ SK=COMMISSION │    │ SK=COMMISSION_ │    │ SK=LEDGER#...    │
                           │   _RATES     │    │   AUDIT#...    │    │ (meta.gross_*)   │
                           └──────────────┘    └────────────────┘    └──────────────────┘


Fee Calculation Integration Flow
────────────────────────────────

  User pays $10 tip on content
       │
       ▼
  ┌──────────────────┐
  │ tip_ledger.py    │
  │ (or unlock /     │
  │  subscription)   │
  └────────┬─────────┘
           │ calls calculate_commission("tips", 1000)
           ▼
  ┌──────────────────┐
  │ platform_        │  ← reads rate from DDB (PK=PLATFORM, SK=COMMISSION_RATES)
  │ commission.py    │
  │ service          │  returns {gross: 1000, fee: 200, net: 800, rate: 20}
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │ billing_shared   │  new_ledger_entry(amount_cents=800,
  │ .py              │    meta={gross_amount_cents: 1000,
  │                  │          platform_fee_cents: 200,
  │                  │          platform_fee_pct: 20})
  └──────────────────┘
```

### 3.2 Detailed DynamoDB Access Patterns

| # | Access Pattern | Table | PK | SK / GSI | Operation | Example |
|---|---------------|-------|----|---------|-----------|---------| 
| 1 | Get current rates | billing | `PLATFORM` | `COMMISSION_RATES` | GetItem | `get_commission_rates()` → returns rates map |
| 2 | Update rates | billing | `PLATFORM` | `COMMISSION_RATES` | PutItem | `update_commission_rates(admin_id, new_rates)` → overwrites |
| 3 | Write audit entry | billing | `PLATFORM` | `COMMISSION_AUDIT#{ts}#{id}` | PutItem | Logged on every rate change |
| 4 | List audit log | billing | `PLATFORM` | `begins_with("COMMISSION_AUDIT#")` | Query(SIF=False) | `get_rate_audit_log(limit=50)` |
| 5 | Get user ledger with meta | billing | `USER#{user_id}` | `begins_with("LEDGER#")` | Query(SIF=False) | Paginated; filter `meta.gross_amount_cents exists` |
| 6 | Aggregate user commissions | billing | `USER#{user_id}` | `begins_with("LEDGER#")` | Query + filter | Sum meta.gross/fee/net for date range |
| 7 | Seed default rates | billing | `PLATFORM` | `COMMISSION_RATES` | PutItem(if_not_exists) | Called on first startup if no rates exist |
| 8 | Get single audit entry | billing | `PLATFORM` | `COMMISSION_AUDIT#{ts}#{id}` | GetItem | Admin drill-down on specific rate change |

### 3.3 Data Model

#### 3.3.1 Commission Rate Configuration (Billing Table)

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

#### 3.3.2 Commission Rate Audit Log (Billing Table)

**PK**: `PLATFORM`, **SK**: `COMMISSION_AUDIT#{timestamp}#{audit_id}`

| Field | Type | Description |
|-------|------|-------------|
| `audit_id` | S | Unique audit entry ID |
| `action` | S | `"rates_updated"` |
| `previous_rates` | M | Snapshot of rates before change |
| `new_rates` | M | Snapshot of rates after change |
| `changed_by` | S | Admin user ID |
| `created_at` | N | Timestamp |

#### 3.3.3 Enhanced Ledger Entry Meta

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

### 3.4 Backend Service

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

### 3.5 Backend Router

**New file**: `app/routers/platform_commission.py` (~120 lines)

### 3.6 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/commission/rates` | `require_ui_session` | Get current commission rates (public to all creators) |
| `PUT` | `/ui/commission/rates` | `require_admin_session` | Update commission rates (admin only) |
| `GET` | `/ui/commission/rates/audit` | `require_admin_session` | Get rate change audit log |
| `GET` | `/ui/commission/summary` | `require_ui_session` | Get commission summary for authenticated creator |

### 3.7 API Request/Response Examples

#### GET /ui/commission/rates

**Request**:
```http
GET /ui/commission/rates HTTP/1.1
Cookie: ui_session=...; ui_access_token=...
```

**Response** (200):
```json
{
  "rates": {
    "tips": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
    "unlocks": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
    "subscriptions": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
    "shop_sales": {"rate_pct": 15, "min_fee_cents": 0, "max_fee_cents": 0},
    "vod_purchases": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
    "call_revenue": {"rate_pct": 25, "min_fee_cents": 0, "max_fee_cents": 0}
  },
  "updated_at": 1748534400,
  "updated_by": "root.admin@testdev.local"
}
```

#### PUT /ui/commission/rates

**Request**:
```http
PUT /ui/commission/rates HTTP/1.1
Cookie: ui_session=...; ui_access_token=...
x-csrf-token: <csrf_token>
Content-Type: application/json

{
  "rates": {
    "tips": {"rate_pct": 18, "min_fee_cents": 10, "max_fee_cents": 5000},
    "unlocks": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0}
  }
}
```

**Response** (200):
```json
{
  "rates": {
    "tips": {"rate_pct": 18, "min_fee_cents": 10, "max_fee_cents": 5000},
    "unlocks": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
    "subscriptions": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
    "shop_sales": {"rate_pct": 15, "min_fee_cents": 0, "max_fee_cents": 0},
    "vod_purchases": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0},
    "call_revenue": {"rate_pct": 25, "min_fee_cents": 0, "max_fee_cents": 0}
  },
  "updated_at": 1748534500,
  "updated_by": "root.admin@testdev.local"
}
```

#### GET /ui/commission/rates/audit

**Request**:
```http
GET /ui/commission/rates/audit?limit=10 HTTP/1.1
Cookie: ui_session=...; ui_access_token=...
```

**Response** (200):
```json
{
  "items": [
    {
      "audit_id": "aud_abc123",
      "action": "rates_updated",
      "changed_by": "root.admin@testdev.local",
      "created_at": 1748534500,
      "previous_rates": {"tips": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0}},
      "new_rates": {"tips": {"rate_pct": 18, "min_fee_cents": 10, "max_fee_cents": 5000}}
    }
  ]
}
```

#### GET /ui/commission/summary

**Request**:
```http
GET /ui/commission/summary?from_ts=1746057600&to_ts=1748736000 HTTP/1.1
Cookie: ui_session=...; ui_access_token=...
```

**Response** (200):
```json
{
  "total_gross_cents": 150000,
  "total_fee_cents": 30000,
  "total_net_cents": 120000,
  "breakdown": [
    {
      "transaction_type": "tips",
      "gross_cents": 80000,
      "fee_cents": 16000,
      "net_cents": 64000,
      "rate_pct": 20,
      "transaction_count": 42
    },
    {
      "transaction_type": "unlocks",
      "gross_cents": 50000,
      "fee_cents": 10000,
      "net_cents": 40000,
      "rate_pct": 20,
      "transaction_count": 25
    },
    {
      "transaction_type": "shop_sales",
      "gross_cents": 20000,
      "fee_cents": 4000,
      "net_cents": 16000,
      "rate_pct": 15,
      "transaction_count": 8
    }
  ],
  "currency": "USD"
}
```

### 3.8 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Platform Commission Visibility (FIN-007) --

class CommissionRateEntry(BaseModel):
    rate_pct: int = Field(ge=0, le=100)
    min_fee_cents: int = Field(default=0, ge=0)
    max_fee_cents: int = Field(default=0, ge=0)

    class Config:
        json_schema_extra = {
            "example": {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0}
        }

class CommissionRatesOut(BaseModel):
    rates: Dict[str, CommissionRateEntry] = Field(default_factory=dict)
    updated_at: int = 0
    updated_by: str = ""

class CommissionRatesUpdateIn(BaseModel):
    rates: Dict[str, CommissionRateEntry]

    @field_validator("rates")
    @classmethod
    def validate_rates_keys(cls, v: Dict[str, CommissionRateEntry]) -> Dict[str, CommissionRateEntry]:
        allowed = {"tips", "unlocks", "subscriptions", "shop_sales", "vod_purchases", "call_revenue"}
        for key in v:
            if key not in allowed:
                raise ValueError(f"Unknown transaction type: {key}. Allowed: {allowed}")
        return v

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

class CommissionAuditListOut(BaseModel):
    items: List[CommissionAuditEntry] = Field(default_factory=list)
```

### 3.9 Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | Error Message | Recovery |
|---|----------|-------------|------------|---------------|----------|
| 1 | Non-admin tries PUT rates | 403 | `forbidden` | "Admin role required" | Use admin account |
| 2 | Invalid rate_pct (negative) | 422 | `validation_error` | "rate_pct must be >= 0" | Fix input value |
| 3 | Invalid rate_pct (>100) | 422 | `validation_error` | "rate_pct must be <= 100" | Fix input value |
| 4 | Unknown transaction type | 422 | `validation_error` | "Unknown transaction type: X" | Use allowed types |
| 5 | No rates configured (first request) | 200 | — | Returns DEFAULT_RATES | Automatic fallback |
| 6 | Summary with no transactions | 200 | — | All totals = 0, empty breakdown | Expected empty state |
| 7 | Invalid from_ts > to_ts | 400 | `invalid_range` | "from_ts must be before to_ts" | Swap dates |
| 8 | Unauthenticated request | 401 | `unauthorized` | "Authentication required" | Login first |
| 9 | Session expired | 401 | `session_expired` | "Session has expired" | Re-login |
| 10 | max_fee_cents < min_fee_cents | 422 | `validation_error` | "max_fee_cents must be >= min_fee_cents" | Fix input |
| 11 | DDB write fails (audit) | 500 | `internal_error` | "Failed to write audit log" | Retry; rate update still succeeds |
| 12 | DDB read fails (rates) | 500 | `internal_error` | "Failed to read commission rates" | Fallback to DEFAULT_RATES |

### 3.10 Integration with Existing Billing Flows

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

### 3.11 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/billing/CommissionPage.tsx` | Commission rates + summary dashboard | ~300 |
| `frontend/src/api/endpoints/commission.ts` | API wrappers | ~35 |

### 3.12 Frontend Component Tree

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

**TypeScript Props Interfaces**:

```typescript
interface CommissionPageProps {}

interface SummaryGridProps {
  totalGrossCents: number;
  totalFeeCents: number;
  totalNetCents: number;
  isLoading: boolean;
}

interface BreakdownTableProps {
  breakdown: CommissionSummaryBreakdown[];
  isLoading: boolean;
}

interface RateTableProps {
  rates: Record<string, CommissionRateEntry>;
  isLoading: boolean;
}

interface AdminRateEditorProps {
  currentRates: Record<string, CommissionRateEntry>;
  onSave: (rates: Record<string, CommissionRateEntry>) => void;
  isSaving: boolean;
}

interface DateRangePickerProps {
  fromTs: number;
  toTs: number;
  onChange: (from: number, to: number) => void;
}
```

### 3.13 Billing History Enhancement

The existing billing history page (`frontend/src/pages/billing/`) should be enhanced to show gross/fee/net columns when commission meta is present on a transaction. This is a display-only change in the existing `BillingHistory` component.

### 3.14 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/platform_commission.py` | Commission rate management + fee calculation | ~250 |
| `app/routers/platform_commission.py` | Commission API endpoints | ~120 |
| `frontend/src/pages/billing/CommissionPage.tsx` | Commission dashboard UI | ~300 |
| `frontend/src/api/endpoints/commission.ts` | API wrappers | ~35 |
| `frontend/e2e/fin-commission.spec.ts` | E2E tests | ~500 |

### 3.15 Files to Modify

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

```python
def calculate_commission(transaction_type: str, gross_amount_cents: int) -> Dict[str, int]:
    rates = get_commission_rates()
    rate_entry = rates["rates"].get(transaction_type, {"rate_pct": 20, "min_fee_cents": 0, "max_fee_cents": 0})
    rate_pct = rate_entry["rate_pct"]
    min_fee = rate_entry.get("min_fee_cents", 0)
    max_fee = rate_entry.get("max_fee_cents", 0)

    if gross_amount_cents <= 0:
        return {"gross_amount_cents": 0, "platform_fee_cents": 0, "net_amount_cents": 0, "rate_pct": rate_pct}

    fee = floor(gross_amount_cents * rate_pct / 100)

    if min_fee > 0 and fee < min_fee:
        fee = min(min_fee, gross_amount_cents)  # cannot exceed gross
    if max_fee > 0 and fee > max_fee:
        fee = max_fee

    net = gross_amount_cents - fee
    return {
        "gross_amount_cents": gross_amount_cents,
        "platform_fee_cents": fee,
        "net_amount_cents": net,
        "rate_pct": rate_pct,
    }
```

### 4.3 Retroactivity

Rate changes apply to future transactions only. Existing ledger entries retain their original `platform_fee_pct` in meta. The summary endpoint calculates totals from stored meta values, not current rates.

---

## 5. Observability

### 5.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `commission_fee_total_cents` | Counter | `transaction_type` | Total fee cents collected |
| `commission_gross_total_cents` | Counter | `transaction_type` | Total gross cents processed |
| `commission_net_total_cents` | Counter | `transaction_type` | Total net cents credited |
| `commission_rate_update_count` | Counter | `admin_id` | Number of rate changes |
| `commission_summary_latency_ms` | Histogram | — | Latency of summary aggregation |
| `commission_calculation_count` | Counter | `transaction_type` | Number of fee calculations |
| `commission_rates_cache_hits` | Counter | — | In-memory rate cache hits |
| `commission_rates_cache_misses` | Counter | — | Cache misses requiring DDB read |

### 5.2 Structured Logging

```python
logger.info(
    "commission.calculated",
    extra={
        "transaction_type": "tips",
        "gross_cents": 1000,
        "fee_cents": 200,
        "net_cents": 800,
        "rate_pct": 20,
        "user_id": user_id,
    }
)

logger.info(
    "commission.rates_updated",
    extra={
        "admin_id": admin_user_id,
        "changed_types": ["tips"],
        "audit_id": audit_id,
    }
)
```

### 5.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Fee calculation failure | `commission_calculation_errors > 0` in 5 min | High | Page on-call; revenue may be mis-credited |
| Rate update spike | `commission_rate_update_count > 5` in 1 hour | Medium | Notify admin channel; possible misconfiguration |
| Summary aggregation slow | `commission_summary_latency_ms p95 > 5000` | Low | Scale read capacity on billing table |
| Zero-rate applied unexpectedly | `commission_fee_total_cents = 0` for 1 hour during active transactions | High | Check DDB rates record; may be corrupted |

---

## 6. Rollout Plan

### 6.1 Feature Flag

```python
# app/core/settings.py
commission_visibility_enabled: bool = bool(os.environ.get("COMMISSION_VISIBILITY_ENABLED", "false").lower() in ("1", "true"))
```

### 6.2 Phased Rollout

| Phase | Scope | Duration | Gate |
|-------|-------|----------|------|
| 1 | Internal/dev only | 3 days | `COMMISSION_VISIBILITY_ENABLED=true` on dev |
| 2 | Admin rate management | 2 days | Admin can configure rates; no creator-facing display yet |
| 3 | Creator commission summary | 3 days | Creators see fees on existing billing; commission page live |
| 4 | Full rollout | Ongoing | Remove feature flag; all new transactions include commission meta |

### 6.3 Rollback Plan

1. Set `COMMISSION_VISIBILITY_ENABLED=false` — hides commission page in UI.
2. Fee calculation continues to return results but `meta` fields not written to ledger entries.
3. Existing commission meta in historical entries remains untouched.
4. No database migration needed for rollback.

---

## 7. Performance Considerations

### 7.1 Latency Targets

| Operation | Target P50 | Target P95 | Strategy |
|-----------|-----------|-----------|----------|
| GET rates | < 5 ms | < 20 ms | In-memory cache with 60s TTL |
| PUT rates | < 50 ms | < 200 ms | Single DDB PutItem + audit write |
| GET summary | < 200 ms | < 1000 ms | Paginated ledger scan + aggregation |
| calculate_commission | < 1 ms | < 5 ms | In-memory cached rates, integer math only |

### 7.2 Caching Strategy

Commission rates change infrequently (days/weeks). Cache in module-level variable with 60-second TTL:

```python
_rates_cache: Optional[Dict] = None
_rates_cache_ts: int = 0
RATES_CACHE_TTL = 60

def get_commission_rates() -> Dict[str, Any]:
    global _rates_cache, _rates_cache_ts
    now = now_ts()
    if _rates_cache and (now - _rates_cache_ts) < RATES_CACHE_TTL:
        return _rates_cache
    item = T.billing.get_item(Key={"pk": "PLATFORM", "sk": "COMMISSION_RATES"}).get("Item")
    if not item:
        _rates_cache = {"rates": DEFAULT_RATES, "updated_at": 0, "updated_by": ""}
    else:
        _rates_cache = item
    _rates_cache_ts = now
    return _rates_cache
```

Cache is invalidated on `update_commission_rates()` by setting `_rates_cache = None`.

### 7.3 Summary Aggregation

The `get_commission_summary` function scans ledger entries with `meta.gross_amount_cents` present. For creators with thousands of entries, this could be slow. Mitigations:

1. **Date range filter**: Always require `from_ts` and `to_ts` to limit scan scope.
2. **Pagination**: DDB query with `Limit=500` per page, max 4 pages (2000 entries).
3. **Future optimization**: Daily aggregation rollup (similar to FIN-013) would eliminate per-request scanning.

### 7.4 Memory Management

In-memory rate cache is a single dictionary (~500 bytes). No memory concern. Summary aggregation uses streaming accumulation (not loading all entries into memory).

---

## 8. E2E Test Plan

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

### Section 567: Edge Cases & Negative Tests (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 567.1 | Rate with min_fee_cents enforces minimum | Set min_fee=50; send $1 tip (100 cents); fee >= 50 regardless of rate |
| 567.2 | Rate with max_fee_cents caps maximum | Set max_fee=100; send $100 tip (10000 cents); fee = 100 |
| 567.3 | Concurrent rate updates don't corrupt data | Two rapid PUTs; final GET returns one of the two sets (last-writer-wins) |
| 567.4 | Summary with no transactions returns zeros | New user with no transactions; GET summary; all totals = 0 |
| 567.5 | Audit log ordered newest first | Multiple rate updates; GET audit; first entry has latest created_at |

### Section 568: Rollup & Rate Audit (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 568.1 | Audit log includes before and after snapshots | PUT rates changing tips from 20 to 15; audit entry has previous_rates.tips.rate_pct=20, new_rates.tips.rate_pct=15 |
| 568.2 | Multiple rate changes produce multiple audit entries | PUT 3 times; GET audit; >= 3 entries |
| 568.3 | Partial rate update preserves other rates | PUT only tips rate; GET rates; unlocks, subscriptions unchanged |
| 568.4 | Rate changes do not alter historical ledger entries | Change rate; GET old ledger entry; meta.platform_fee_pct still shows old rate |

**Total E2E tests: 25**

---

## 9. Security Considerations

### 9.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| GET rates | `require_ui_session` | Any authenticated user |
| PUT rates | `require_admin_session` | Admin only |
| GET rates/audit | `require_admin_session` | Admin only |
| GET summary | `require_ui_session` | Returns only caller's data |

### 9.2 Financial Integrity

- Fee calculations use integer arithmetic only (no floating-point currency math).
- The invariant `platform_fee_cents + net_amount_cents == gross_amount_cents` is enforced.
- Rate changes are audited with before/after snapshots.
- Historical ledger entries are immutable; rate changes do not alter past transactions.

### 9.3 Data Access

- Commission summary queries are scoped to `USER#{caller_user_id}`.
- Rate configuration is platform-wide (single record), readable by all creators.
- Rate update requires admin role.

---

## 10. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/billing_shared.py` | Exists | Ledger entry meta extension |
| `app/services/tip_ledger.py` | Exists | First integration point for commission deduction |
| `app/services/creator_earnings.py` | Exists | Earnings aggregation must handle commission meta |
| `app/routers/creator_analytics.py` | Exists | Analytics dashboard to reference commission data |

---

## 11. Acceptance Criteria

1. Commission rates are stored in DynamoDB and returned via API.
2. Admin can update rates; changes are audit-logged.
3. Every new ledger credit entry includes gross, fee, and net in meta.
4. Commission summary shows total gross, fees, and net for a date range.
5. Summary breakdown groups by transaction type.
6. Fee calculation uses integer arithmetic with correct rounding.
7. Rate changes apply to future transactions only.
8. Non-admin users can view rates and their own summary but cannot update rates.
9. All 25 E2E tests pass.

---

## Codebase References

### Existing Files (verified)
| File | Key Functions | Lines |
|------|--------------|-------|
| `app/services/billing_shared.py` | `new_ledger_entry` (meta dict extensible) | 217 |
| `app/services/creator_earnings.py` | `get_earnings_summary`, `get_earnings_transactions` | 47, 117 |
| `app/services/tip_ledger.py` | `write_tip_ledger` | 88 |
| `app/services/creator_payouts.py` | `get_available_balance` | 55 |
| `scripts/local-ddb-init.py` | `billing` table | 59 |

### Files That Do NOT Exist (incorrect references in ticket)
| File | Status |
|------|--------|
| `app/services/syndicate_revenue_split.py` | Does NOT exist -- ticket incorrectly references it as implementing `platform_fee_pct` deduction |
| `app/services/catalog_orders.py` | Does NOT exist |
| `app/services/vod_purchases.py` | Does NOT exist (string category name only in `creator_earnings.py:32`) |

### Files to Create (new implementation)
| File | Purpose |
|------|---------|
| `app/services/platform_commission.py` | Commission rate storage, fee calculation, summary aggregation |
| Commission rates DDB items | Stored in `app_single_table` or dedicated table |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_platform_commission.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_fin_007_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_fin_007_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_fin_007_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_fin_007_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_fin_007_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_fin_007_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_fin_007_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_fin_007_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/commission-visibility.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 10

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `COMMISSION_VISIBILITY_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `COMMISSION_VISIBILITY_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| (none) | -- | This ticket has no upstream ticket dependencies |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| (none currently) | -- |

### Merge Strategy

**Independent** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `COMMISSION_VISIBILITY_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
