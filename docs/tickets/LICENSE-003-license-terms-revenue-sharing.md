# LICENSE-003: License Terms & Revenue Sharing

**Ticket**: LICENSE-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-12 days

---

## 1. Overview & Motivation

### 1.1 Purpose

LICENSE-003 implements the financial layer of content licensing. When licensed content generates revenue -- through views, tips, subscription income, or direct sales -- the system automatically calculates and distributes the licensor's agreed share. Revenue splits are computed per qualifying transaction, and bilateral ledger entries are written for both parties: a credit for the licensor and a debit of the share portion for the licensee. Creators get a dedicated License Revenue Dashboard showing earned and paid amounts across all their licenses.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Licensor | As a licensor, I want to automatically receive my revenue share when a licensee's content earns money. | Each qualifying transaction writes a licensor credit entry to the billing ledger; wallet balance increases. |
| Licensee | As a licensee, I want to see what I owe to licensors from my content revenue. | Billing ledger shows debit entries for license revenue share; dashboard shows total paid. |
| Licensor | As a licensor, I want a fixed fee collected each time my licensed content is used in a new creation. | `fixed_cost_cents` charged to licensee on first use; ledger entry for both parties. |
| Licensor | As a licensor, I want an ongoing revenue share on content that uses my licensed material. | `revenue_share_pct` applied to each qualifying transaction; split calculated before platform fee. |
| Licensor | As a licensor, I want a profit share on net earnings from content using my material. | `profit_share_pct` applied to net profit (revenue minus platform fee) per transaction. |
| Creator | As any creator, I want to see a License Revenue Dashboard summarizing earnings and payments. | Dashboard page shows total earned (as licensor), total paid (as licensee), transaction history with filters. |
| System | Revenue splits should be calculated atomically with the original transaction to prevent inconsistencies. | Revenue split is written in the same DynamoDB batch as the original billing entry. |
| Admin | As an admin, I want to audit license revenue transactions across the platform. | Admin endpoint returns platform-wide license revenue data with creator-level aggregation. |

### 1.3 Why This Is Needed

LICENSE-002 established the legal framework (who can use what under which terms), but without an economic enforcement layer, license terms are purely informational. Creators need assurance that their licensing terms translate into real revenue. This ticket bridges the gap: every dollar earned from licensed content triggers an automatic, auditable revenue split. This makes content licensing economically viable and incentivizes creators to license their work rather than gatekeep it.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Billing shared | `app/services/billing_shared.py` (260 lines) | `new_ledger_entry`, `apply_wallet_delta`, `ledger_sk`; core financial primitives to reuse |
| Wallet balance | `app/services/billing_shared.py` | `get_wallet_balance`, `ensure_balance_row`; licensor credits deposited to wallet |
| Issued licenses | `app/services/issued_licenses.py` (LICENSE-002) | `check_license_for_use`, `get_issued_license`; provides active license terms for split calculation |
| Subscription server | `app/routers/subscription_server.py` (1735 lines) | Invoice/payment patterns; subscription revenue is a qualifying transaction for splits |
| Tip processing | `app/routers/messaging.py` | Tip payment flow writes billing ledger; needs hook for license revenue split |
| Post tips | `app/routers/newsfeed.py` | Post tip flow writes billing ledger; qualifying transaction for license splits |
| VOD purchase | `app/services/vod_purchase.py` | VOD sale writes billing entry; qualifying transaction |
| Alerts service | `app/services/alerts.py` | `write_alert` for revenue split notifications |
| Profile service | `app/services/profile.py` | Display names in revenue dashboard |
| DDB table init | `scripts/local-ddb-init.py` | `TableDef` pattern with GSIs and `attr_types` |

### 2.2 Gaps

1. **No revenue split engine** -- there is no mechanism to calculate and distribute revenue shares between creators based on license terms.
2. **No license-aware billing hooks** -- tip, subscription, and purchase flows write single-party ledger entries without checking for license obligations.
3. **No revenue dashboard** -- creators have a billing page but no license-specific revenue view.
4. **No fixed-fee collection** -- no mechanism to charge a one-time fee when licensed content is first used.
5. **No atomic split writes** -- billing ledger entries are written individually; need batch writes for split consistency.
6. **No admin revenue audit** -- admin billing views exist but have no license revenue aggregation.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 License Revenue Table

**Table name**: `license_revenue` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

**Single-table design** using prefix patterns:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `LICENSOR#{user_id}` | `TXN#{timestamp}#{txn_id}` | Revenue earned by licensor | `txn_id`, `issued_license_id`, `content_id`, `licensee_id`, `source_type` (tip/subscription/sale/view), `source_amount_cents`, `split_amount_cents`, `split_type` (profit_share/revenue_share/fixed), `currency`, `created_at` |
| `LICENSEE#{user_id}` | `TXN#{timestamp}#{txn_id}` | Revenue paid by licensee | Same fields as licensor row |
| `LICENSE#{issued_license_id}` | `TXN#{timestamp}#{txn_id}` | Transaction history per license | Same fields |
| `CONTENT#{content_id}` | `TXN#{timestamp}#{txn_id}` | Transaction history per content item | Same fields |
| `LICENSOR#{user_id}` | `SUMMARY` | Aggregate totals for licensor | `total_earned_cents`, `total_transactions`, `last_earned_at` |
| `LICENSEE#{user_id}` | `SUMMARY` | Aggregate totals for licensee | `total_paid_cents`, `total_transactions`, `last_paid_at` |
| `LICENSE#{issued_license_id}` | `USAGE#{content_id}` | Fixed-fee usage tracking | `content_id`, `licensee_id`, `fixed_fee_paid`, `first_used_at` |

#### 3.1.2 GSIs

**GSI1** (`GSI1PK` / `GSI1SK`): Platform-wide revenue reporting by time.
- `GSI1PK`: `PLATFORM_REV`
- `GSI1SK`: `created_at` (N) -- chronological ordering for admin audit
- `attr_types={"GSI1SK": "N"}`

**GSI2** (`GSI2PK` / `GSI2SK`): Revenue by source type for analytics.
- `GSI2PK`: `SOURCE#{source_type}` (e.g., `SOURCE#tip`, `SOURCE#subscription`)
- `GSI2SK`: `created_at` (N)

#### 3.1.3 TableDef Entry

```python
TableDef(
    "license_revenue", "pk", "sk",
    gsis=[
        {"name": "GSI1", "pk": "GSI1PK", "sk": "GSI1SK"},
        {"name": "GSI2", "pk": "GSI2PK", "sk": "GSI2SK"},
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N"},
),
```

#### 3.1.4 Example DynamoDB Items

**Licensor revenue entry**:
```json
{
  "pk": "LICENSOR#alice@test.local",
  "sk": "TXN#1748520100#txn_abc123",
  "txn_id": "txn_abc123",
  "issued_license_id": "il_def456",
  "content_id": "vid_xyz789",
  "licensee_id": "bob@test.local",
  "source_type": "tip",
  "source_amount_cents": 1000,
  "split_amount_cents": 100,
  "split_type": "revenue_share",
  "currency": "usd",
  "created_at": 1748520100,
  "GSI1PK": "PLATFORM_REV",
  "GSI1SK": 1748520100,
  "GSI2PK": "SOURCE#tip",
  "GSI2SK": 1748520100
}
```

**Licensor summary**:
```json
{
  "pk": "LICENSOR#alice@test.local",
  "sk": "SUMMARY",
  "total_earned_cents": 5500,
  "total_transactions": 23,
  "last_earned_at": 1748520100
}
```

**Fixed-fee usage tracker**:
```json
{
  "pk": "LICENSE#il_def456",
  "sk": "USAGE#vid_new123",
  "content_id": "vid_new123",
  "licensee_id": "bob@test.local",
  "fixed_fee_paid": true,
  "first_used_at": 1748520000
}
```

### 3.2 Revenue Split Calculation

#### 3.2.1 Split Types

Three split types, applied in this order:

1. **Fixed cost** (`fixed_cost_cents`): One-time charge when licensee first uses the licensed content in a new creation. Tracked by `USAGE#` record. Only charged once per (license, new content) pair.

2. **Revenue share** (`revenue_share_pct`): Percentage of gross revenue from each qualifying transaction. Applied before platform fee deduction. Example: $10 tip, 5% revenue share = $0.50 to licensor.

3. **Profit share** (`profit_share_pct`): Percentage of net profit (gross revenue minus platform fee) from each qualifying transaction. Example: $10 tip, 20% platform fee = $8 net, 10% profit share = $0.80 to licensor.

#### 3.2.2 Calculation Formula

```python
def calculate_split(
    source_amount_cents: int,
    platform_fee_pct: int,       # e.g., 20
    revenue_share_pct: int,      # from license terms
    profit_share_pct: int,       # from license terms
) -> int:
    """Calculate the licensor's share in cents."""
    revenue_split = (source_amount_cents * revenue_share_pct) // 100
    net_profit = source_amount_cents - (source_amount_cents * platform_fee_pct) // 100
    profit_split = (net_profit * profit_share_pct) // 100
    return revenue_split + profit_split
```

#### 3.2.3 Qualifying Transactions

| Source Type | Trigger | Amount Used |
|-------------|---------|-------------|
| `tip` | Tip on a message or post that uses licensed content | Tip amount |
| `subscription` | Subscription payment to a creator who uses licensed content | Pro-rated subscription amount |
| `sale` | VOD purchase or file bundle sale of licensed content | Sale price |
| `unlock` | Locked message/post unlock that uses licensed content | Unlock price |

### 3.3 Backend Service

**New file**: `app/services/license_revenue.py` (~400 lines)

```python
"""License revenue sharing -- split calculation and ledger integration (LICENSE-003)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import new_ledger_entry, apply_wallet_delta
from app.services.issued_licenses import list_licenses_for_content, check_license_for_use

logger = logging.getLogger(__name__)

PLATFORM_FEE_PCT = 20  # 20% platform fee


def process_revenue_split(
    *,
    content_id: str,
    licensee_id: str,
    source_type: str,
    source_amount_cents: int,
    source_txn_id: str,
    currency: str = "usd",
) -> List[Dict[str, Any]]:
    """Process revenue splits for all active licenses on a content item.

    Called by billing hooks (tips, subscriptions, sales, unlocks) whenever
    revenue is generated from content that uses licensed material.

    Returns list of split transactions created.
    """
    # 1. Find all active licenses for this content
    licenses = list_licenses_for_content(content_id=content_id, status_filter="active")
    if not licenses:
        return []

    splits = []
    ts = now_ts()

    for lic in licenses:
        licensor_id = lic["licensor_id"]
        if licensor_id == licensee_id:
            continue  # Don't split with yourself

        # 2. Check for fixed fee (one-time, only if not yet paid)
        fixed_cost = lic.get("fixed_cost_cents", 0)
        if fixed_cost > 0:
            _process_fixed_fee(lic, licensee_id, content_id, fixed_cost, currency, ts)

        # 3. Calculate revenue/profit split
        rev_share = lic.get("revenue_share_pct", 0)
        prof_share = lic.get("profit_share_pct", 0)
        split_cents = calculate_split(
            source_amount_cents, PLATFORM_FEE_PCT, rev_share, prof_share
        )
        if split_cents <= 0:
            continue

        # 4. Write bilateral ledger entries + revenue records
        txn_id = f"lrtxn_{uuid4().hex}"
        split_type = "revenue_share" if rev_share > 0 else "profit_share"

        # Licensor credit
        _write_revenue_record("LICENSOR", licensor_id, txn_id, lic, content_id,
                              licensee_id, source_type, source_amount_cents,
                              split_cents, split_type, currency, ts)
        apply_wallet_delta(T.billing, f"USER#{licensor_id}", split_cents, currency=currency)
        new_ledger_entry(
            T.billing, f"USER#{licensor_id}",
            amount_cents=split_cents,
            currency=currency,
            entry_type="credit",
            reason=f"License revenue share from {source_type}",
            details={"license_id": lic["issued_license_id"], "content_id": content_id,
                     "source_txn_id": source_txn_id},
        )

        # Licensee debit
        _write_revenue_record("LICENSEE", licensee_id, txn_id, lic, content_id,
                              licensor_id, source_type, source_amount_cents,
                              split_cents, split_type, currency, ts)
        new_ledger_entry(
            T.billing, f"USER#{licensee_id}",
            amount_cents=-split_cents,
            currency=currency,
            entry_type="debit",
            reason=f"License revenue share to {licensor_id}",
            details={"license_id": lic["issued_license_id"], "content_id": content_id,
                     "source_txn_id": source_txn_id},
        )

        # Update summaries
        _update_summary("LICENSOR", licensor_id, split_cents, ts)
        _update_summary("LICENSEE", licensee_id, split_cents, ts)

        splits.append({
            "txn_id": txn_id,
            "licensor_id": licensor_id,
            "split_cents": split_cents,
            "split_type": split_type,
        })

    return splits


def calculate_split(
    source_amount_cents: int,
    platform_fee_pct: int,
    revenue_share_pct: int,
    profit_share_pct: int,
) -> int:
    """Calculate licensor's share in cents."""
    revenue_split = (source_amount_cents * revenue_share_pct) // 100
    net_profit = source_amount_cents - (source_amount_cents * platform_fee_pct) // 100
    profit_split = (net_profit * profit_share_pct) // 100
    return revenue_split + profit_split


def get_revenue_summary(
    *,
    user_id: str,
    role: str,
) -> Dict[str, Any]:
    """Get aggregate revenue summary for a user as licensor or licensee."""
    # get_item pk=LICENSOR#{user_id} or LICENSEE#{user_id}, sk=SUMMARY


def list_revenue_transactions(
    *,
    user_id: str,
    role: str,
    source_type: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List revenue transactions for a user."""
    # Query LICENSOR#{user_id} or LICENSEE#{user_id}, sk begins_with TXN#


def list_license_transactions(
    *,
    issued_license_id: str,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List all transactions for a specific license."""
    # Query LICENSE#{issued_license_id}, sk begins_with TXN#


def admin_list_platform_revenue(
    *,
    limit: int = 100,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Admin: list platform-wide license revenue transactions."""
    # GSI1 query: PLATFORM_REV, ordered by created_at desc


# --- Internal helpers ---

def _write_revenue_record(prefix, user_id, txn_id, license_item, content_id,
                          counterparty_id, source_type, source_amount,
                          split_amount, split_type, currency, ts):
    """Write TXN record under the given prefix."""

def _update_summary(prefix, user_id, amount_cents, ts):
    """Atomically increment summary totals."""

def _process_fixed_fee(license_item, licensee_id, content_id, fixed_cost,
                       currency, ts):
    """Process one-time fixed fee if not already paid for this (license, content) pair."""
    # Check USAGE# record; if not exists, charge fixed fee and create USAGE# record
```

### 3.4 Billing Hook Integration

The revenue split engine is invoked as a hook from existing billing flows. Each qualifying transaction calls `process_revenue_split` after the primary billing entry is written.

**Files to modify with hooks**:

| File | Hook Point | Change |
|------|-----------|--------|
| `app/routers/messaging.py` | Tip processing (`/messages/{id}/tip`) | After tip ledger entry, call `process_revenue_split(content_id=message_id, source_type="tip")` |
| `app/routers/messaging.py` | Locked message unlock (`/messages/{id}/unlock`) | After unlock ledger entry, call `process_revenue_split(source_type="unlock")` |
| `app/routers/newsfeed.py` | Post tip (`/posts/{id}/tip`) | After tip ledger entry, call `process_revenue_split(source_type="tip")` |
| `app/routers/newsfeed.py` | Post unlock (`/posts/{id}/unlock`) | After unlock ledger entry, call `process_revenue_split(source_type="unlock")` |
| `app/services/vod_purchase.py` | VOD sale | After sale ledger entry, call `process_revenue_split(source_type="sale")` |

### 3.5 Backend Router

**New file**: `app/routers/license_revenue.py` (~200 lines)

```python
"""License revenue dashboard router (LICENSE-003)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from app.auth.deps import require_ui_session, require_admin_session
from app.services import license_revenue as svc

router = APIRouter(prefix="/ui/licenses/revenue", tags=["license-revenue"])
admin_router = APIRouter(prefix="/ui/admin/licenses/revenue", tags=["license-revenue-admin"])
```

### 3.6 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/licenses/revenue/earned` | `require_ui_session` | Get licensor revenue summary + transaction list |
| `GET` | `/ui/licenses/revenue/paid` | `require_ui_session` | Get licensee payments summary + transaction list |
| `GET` | `/ui/licenses/revenue/license/{issued_license_id}` | `require_ui_session` | Get transactions for a specific license |
| `GET` | `/ui/licenses/revenue/calculate` | `require_ui_session` | Preview split calculation for given terms + amount |
| `GET` | `/ui/admin/licenses/revenue` | `require_admin_session` | Admin platform-wide revenue audit |

### 3.7 Request/Response Models

**Add to `app/models.py`**:

```python
# -- License Revenue (LICENSE-003) --

class RevenueSummaryOut(BaseModel):
    total_cents: int = 0
    total_transactions: int = 0
    last_transaction_at: Optional[int] = None
    currency: str = "usd"

class RevenueTransactionOut(BaseModel):
    txn_id: str
    issued_license_id: str
    content_id: str
    counterparty_id: str
    counterparty_display_name: str = ""
    source_type: str  # tip, subscription, sale, unlock
    source_amount_cents: int = 0
    split_amount_cents: int = 0
    split_type: str  # revenue_share, profit_share, fixed
    currency: str = "usd"
    created_at: int = 0

class RevenueListOut(BaseModel):
    summary: RevenueSummaryOut
    transactions: List[RevenueTransactionOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None

class RevenueSplitPreviewOut(BaseModel):
    source_amount_cents: int
    platform_fee_cents: int
    revenue_share_cents: int
    profit_share_cents: int
    total_licensor_share_cents: int
    licensee_net_cents: int

class AdminRevenueEntryOut(BaseModel):
    txn_id: str
    licensor_id: str
    licensee_id: str
    content_id: str
    source_type: str
    source_amount_cents: int
    split_amount_cents: int
    created_at: int = 0
```

### 3.8 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/licenses/LicenseRevenuePage.tsx` | License revenue dashboard | ~300 |
| `frontend/src/pages/licenses/RevenueEarnedCard.tsx` | Summary card for earned revenue (as licensor) | ~100 |
| `frontend/src/pages/licenses/RevenuePaidCard.tsx` | Summary card for paid revenue (as licensee) | ~100 |
| `frontend/src/pages/licenses/RevenueTransactionTable.tsx` | Transaction history table with filters | ~150 |
| `frontend/src/pages/licenses/SplitCalculator.tsx` | Preview split calculation tool | ~80 |
| `frontend/src/api/endpoints/license-revenue.ts` | API client wrappers | ~80 |

**Component tree**:

```
LicenseRevenuePage
├── Tabs: "Earned" / "Paid"
├── RevenueEarnedCard (Earned tab)
│   ├── Total earned amount (large display)
│   ├── Transaction count
│   ├── Sparkline chart (last 30 days)
│   └── Breakdown by source type (tips, subs, sales)
├── RevenuePaidCard (Paid tab)
│   ├── Total paid amount (large display)
│   ├── Transaction count
│   └── Breakdown by licensor
├── RevenueTransactionTable (both tabs)
│   ├── Filter: source type dropdown, date range
│   ├── Sort: date, amount
│   └── For each transaction:
│       ├── Date, source type badge, content title
│       ├── Counterparty name
│       ├── Source amount → Split amount
│       └── Split type badge
└── SplitCalculator
    ├── Input: source amount, revenue share %, profit share %
    ├── Platform fee display (20%)
    └── Live calculation result
```

### 3.9 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/licenses/revenue" element={<LicenseRevenuePage />} />
```

### 3.10 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/license_revenue.py` | Revenue split engine + queries | ~400 |
| `app/routers/license_revenue.py` | REST API endpoints | ~200 |
| `frontend/src/pages/licenses/LicenseRevenuePage.tsx` | Revenue dashboard | ~300 |
| `frontend/src/pages/licenses/RevenueEarnedCard.tsx` | Earned summary card | ~100 |
| `frontend/src/pages/licenses/RevenuePaidCard.tsx` | Paid summary card | ~100 |
| `frontend/src/pages/licenses/RevenueTransactionTable.tsx` | Transaction table | ~150 |
| `frontend/src/pages/licenses/SplitCalculator.tsx` | Calculator tool | ~80 |
| `frontend/src/api/endpoints/license-revenue.ts` | API wrappers | ~80 |
| `frontend/e2e/license-revenue.spec.ts` | E2E tests | ~500 |

### 3.11 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `license_revenue_router` and `license_revenue_admin_router` |
| `app/models.py` | Add License Revenue Pydantic models |
| `app/core/settings.py` | Add `license_revenue_table_name` setting |
| `app/core/tables.py` | Add `T.license_revenue` table handle |
| `scripts/local-ddb-init.py` | Add `license_revenue` TableDef with 2 GSIs |
| `app/routers/messaging.py` | Add revenue split hook to tip and unlock endpoints |
| `app/routers/newsfeed.py` | Add revenue split hook to post tip and unlock endpoints |
| `frontend/src/api/types.ts` | Add License Revenue TypeScript interfaces |
| `frontend/src/App.tsx` | Add revenue route |

---

## 4. Revenue Split Processing

### 4.1 Transaction Flow

```
User tips $10 on Bob's video
  → Bob's video uses Alice's licensed music track
    → Tip ledger entry: Bob receives $10 (existing flow)
    → process_revenue_split called:
      1. Find active licenses for Bob's video content_id
      2. Find Alice's license: revenue_share_pct=5, profit_share_pct=0
      3. Calculate: $10 * 5% = $0.50
      4. Write licensor credit: Alice +$0.50
      5. Write licensee debit: Bob -$0.50
      6. Update summaries for both
      7. Write bilateral TXN records for audit trail
```

### 4.2 Fixed Fee Processing

Fixed fees are charged once per (issued_license, derivative_content) pair:

1. First time licensee uses licensed content in a new creation, check `USAGE#` record.
2. If no `USAGE#` record exists, charge `fixed_cost_cents`:
   - Debit licensee wallet.
   - Credit licensor wallet.
   - Write `USAGE#` record with `fixed_fee_paid=true`.
3. On subsequent revenue splits for the same pair, fixed fee is skipped.

### 4.3 Edge Cases

- **Split amount rounds down**: Integer division means some cents may be lost to rounding; this favors the licensee (conservative approach).
- **Zero split**: If the calculated split is $0.00 (e.g., 1% of a $5 amount = $0.05 rounds to 5 cents, but 1% of $1 = 1 cent), the split is still written if > 0.
- **Multiple licenses on same content**: Each license is processed independently; total splits can exceed source amount if terms are misconfigured. A safety cap limits total splits to 80% of source amount.
- **Licensor is also the licensee**: Self-splits are skipped (licensor_id == licensee_id check).
- **Revoked license**: Splits only process for `status=active` licenses; revoked licenses are excluded.
- **Insufficient licensee balance**: Revenue split is still recorded (debit goes negative); the licensee balance reflects the obligation. No blocking of the original transaction.

### 4.4 Safety Cap

Total license revenue splits for a single transaction are capped at 80% of the source amount. If multiple licenses would exceed this cap, splits are proportionally reduced. This prevents scenarios where aggressive license terms consume all revenue.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/license-revenue.spec.ts`

### Section 471: Revenue Split Calculation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 471.1 | Split preview returns correct calculation | GET `/ui/licenses/revenue/calculate?amount=1000&revenue_share_pct=5&profit_share_pct=10`; response: `revenue_share_cents=50`, `profit_share_cents=80`, `total=130` |
| 471.2 | Zero terms produce zero split | GET with all terms=0; `total_licensor_share_cents=0` |
| 471.3 | Max terms (100% + 100%) are capped at 80% | GET with both at 100%; total does not exceed 80% of source |
| 471.4 | Preview with fixed cost adds fixed component | GET with `fixed_cost_cents=500`; response includes fixed in total |

### Section 472: Revenue Split Processing API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 472.1 | Tip on licensed content triggers revenue split | Alice licenses content to Bob (5% rev share). Charlie tips Bob's content $10. Alice ledger shows +$0.50 credit. Bob ledger shows -$0.50 debit. |
| 472.2 | Fixed fee charged on first use only | Bob uses Alice's licensed content (fixed=$5). First transaction: fixed fee charged + revenue split. Second transaction: only revenue split, no fixed fee. |
| 472.3 | Profit share calculates on net after platform fee | License with 10% profit share. $10 tip → $8 net (20% platform fee) → $0.80 profit split. Verify ledger amounts. |
| 472.4 | Self-split is skipped | Alice tips her own content that has a license she issued. No split transaction created. |
| 472.5 | Revoked license produces no split | Revoke license, then tip. No new split transactions in licensor's history. |

### Section 473: Revenue Dashboard API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 473.1 | Licensor earned summary reflects splits | GET `/ui/licenses/revenue/earned` (as Alice); `total_cents` matches sum of splits from previous tests |
| 473.2 | Licensee paid summary reflects debits | GET `/ui/licenses/revenue/paid` (as Bob); `total_cents` matches sum of debits |
| 473.3 | Transaction list is paginated and filterable | GET with `source_type=tip&limit=2`; response has `transactions` array and `next_cursor` |
| 473.4 | Per-license transaction history | GET `/ui/licenses/revenue/license/{id}`; returns only transactions for that license |

### Section 474: Admin Revenue Audit API (2 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 474.1 | Admin sees platform-wide revenue transactions | GET `/ui/admin/licenses/revenue` (as root); response includes all split transactions |
| 474.2 | Non-admin cannot access admin revenue endpoint | Alice GET → 403 |

**Total E2E tests: 15**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Revenue earned / paid | `require_ui_session` | Only own data |
| Per-license transactions | `require_ui_session` | Must be licensor or licensee of the license |
| Split preview | `require_ui_session` | Any authenticated user |
| Admin revenue audit | `require_admin_session` | Platform admin or root only |

### 6.2 Financial Integrity

- Revenue splits use integer arithmetic (cents) to avoid floating-point errors.
- Summary counters use DynamoDB atomic `ADD` updates to prevent race conditions.
- Fixed fee `USAGE#` records use `ConditionExpression: attribute_not_exists(pk)` to prevent double-charging.
- Bilateral ledger entries (credit + debit) are written in the same function call; if either fails, the error is logged and the orphaned entry is flagged for reconciliation.

### 6.3 Rate Limiting

- Revenue endpoints: max 60 requests per user per minute.
- Split preview: max 100 requests per user per minute.
- Admin audit: standard admin rate limits.

### 6.4 Safety Caps

- Total splits per transaction capped at 80% of source amount.
- Individual split amounts must be >= 1 cent (sub-cent splits are dropped).
- Maximum 10 active licenses per content item (prevents excessive fan-out).

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| LICENSE-002 | Required | `list_licenses_for_content`, `check_license_for_use` for finding active licenses |
| `app/services/billing_shared.py` | Exists | `new_ledger_entry`, `apply_wallet_delta` for financial transactions |
| `app/routers/messaging.py` | Exists (modify) | Hook revenue splits into tip/unlock flows |
| `app/routers/newsfeed.py` | Exists (modify) | Hook revenue splits into post tip/unlock flows |
| `app/services/alerts.py` | Exists | Revenue split notifications |
| `app/auth/deps.py` | Exists | `require_ui_session`, `require_admin_session` |
| `app/core/tables.py` | Exists (modify) | Add `T.license_revenue` table handle |
| `scripts/local-ddb-init.py` | Exists (modify) | Add `license_revenue` table definition |
| LICENSE-005 | Not started | Syndicate open licensing terms feed into split calculation |

---

## 8. Acceptance Criteria

1. Revenue splits are automatically calculated when licensed content generates revenue.
2. Bilateral ledger entries (licensor credit + licensee debit) are written for each split.
3. Fixed fees are charged once per (license, content) pair on first use.
4. Revenue share is calculated on gross revenue; profit share on net (after platform fee).
5. Split preview endpoint returns accurate calculations for given terms and amount.
6. Licensor revenue dashboard shows total earned, transaction history, and per-source breakdown.
7. Licensee payment dashboard shows total paid and transaction history.
8. Admin can audit platform-wide license revenue.
9. Safety cap prevents total splits from exceeding 80% of source amount.
10. All 15 E2E tests pass.

---

## 9. Architecture Diagram

```
Revenue Split Flow:

  Tip/Unlock/Sale Event
         |
         v
  Billing Hook (messaging.py / newsfeed.py / vod_purchase.py)
    |  Writes primary billing ledger entry (existing flow)
    |
    +-> process_revenue_split()
         |
         | 1. list_licenses_for_content(content_id)
         |    -> Query issued_licenses table for active licenses
         |
         | 2. For each active license:
         |    a. Check fixed_cost_cents (one-time fee)
         |       -> Check USAGE# record in license_revenue table
         |       -> If not paid: charge fixed fee, create USAGE# record
         |
         |    b. calculate_split(source_amount, platform_fee, rev_share, prof_share)
         |       -> revenue_split = source * revenue_share_pct / 100
         |       -> net_profit = source - (source * platform_fee_pct / 100)
         |       -> profit_split = net_profit * profit_share_pct / 100
         |       -> total_split = revenue_split + profit_split
         |
         |    c. Safety cap check: total_splits <= 80% of source_amount
         |
         | 3. Write bilateral entries:
         |    a. Licensor TXN record (LICENSOR#{id}/TXN#{ts}#{txn_id})
         |    b. Licensee TXN record (LICENSEE#{id}/TXN#{ts}#{txn_id})
         |    c. License TXN record (LICENSE#{lic_id}/TXN#{ts}#{txn_id})
         |    d. Content TXN record (CONTENT#{cid}/TXN#{ts}#{txn_id})
         |    e. Licensor wallet credit (apply_wallet_delta)
         |    f. Licensor billing ledger credit (new_ledger_entry)
         |    g. Licensee billing ledger debit (new_ledger_entry)
         |
         | 4. Update summary records:
         |    a. LICENSOR#{id}/SUMMARY (atomic ADD total_earned_cents)
         |    b. LICENSEE#{id}/SUMMARY (atomic ADD total_paid_cents)
         |
         | 5. Send notification to licensor (alerts service)
         |
         +-> Return list of split transactions


Table Relationships:

  +---------------------+     +----------------------+
  |  issued_licenses    |     |  license_revenue     |
  |  (LICENSE-002)      |     |  (LICENSE-003)       |
  |                     |     |                      |
  |  issued_license_id  |<--->|  issued_license_id   |
  |  licensor_id        |     |  LICENSOR#{id}/TXN#  |
  |  licensee_id        |     |  LICENSEE#{id}/TXN#  |
  |  fixed_cost_cents   |     |  LICENSE#{id}/USAGE# |
  |  revenue_share_pct  |     |  CONTENT#{id}/TXN#   |
  |  profit_share_pct   |     |  GSI1: PLATFORM_REV  |
  +---------------------+     +----------------------+
         |                              |
         v                              v
  +---------------------+     +----------------------+
  |  billing table      |     |  alerts table        |
  |  (existing)         |     |  (existing)          |
  |                     |     |                      |
  |  USER#{id}/LEDGER#  |     |  Revenue split       |
  |  USER#{id}/WALLET   |     |  notifications       |
  +---------------------+     +----------------------+
```

---

## 10. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---|---|---|---|
| No active licenses for content | 200 | -- | No split transactions (empty list) | N/A -- content has no licensing obligations |
| License revoked before split | 200 | -- | Revoked license skipped | N/A -- no split for inactive licenses |
| Licensor == Licensee (self-split) | 200 | -- | Self-split skipped | N/A -- no circular transactions |
| Split amount rounds to 0 cents | 200 | -- | Zero split skipped | N/A -- sub-cent splits dropped |
| Total splits exceed 80% cap | 200 | -- | Splits proportionally reduced | Logged as `license_revenue.cap_applied` |
| Fixed fee USAGE record already exists | 200 | -- | Fixed fee skipped (already paid) | N/A -- idempotent |
| Licensee insufficient balance | 200 | -- | Debit still written (balance goes negative) | Licensee must deposit funds |
| Split preview: invalid parameters | 422 | `validation_error` | Pydantic validation error | Fix input values |
| Revenue earned: not authenticated | 401 | `unauthorized` | "Authentication required" | Log in |
| Admin audit: not admin | 403 | `admin_required` | "Admin access required" | Elevate role |
| License not found for per-license query | 404 | `license_not_found` | "License not found" | Check license ID |

---

## 11. Observability & Monitoring

### 11.1 Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `license_revenue_splits_total` | Counter | `source_type`, `split_type` | Total split transactions processed |
| `license_revenue_split_amount_cents` | Histogram | `source_type` | Distribution of split amounts |
| `license_revenue_fixed_fees_total` | Counter | -- | Fixed fee charges |
| `license_revenue_cap_applied_total` | Counter | -- | Times the 80% safety cap was triggered |
| `license_revenue_self_split_skipped_total` | Counter | -- | Self-splits skipped |
| `license_revenue_processing_latency_ms` | Histogram | `source_type` | Time to process all splits for a transaction |

### 11.2 Alerting Rules

| Alert | Condition | Severity |
|---|---|---|
| High split processing latency | P95 > 500ms for 10 minutes | P3 |
| Safety cap triggered frequently | `cap_applied_total` > 50 in 1 hour | P3 (misconfigured terms) |
| Split processing errors | Error rate > 5% for 5 minutes | P2 |

---

## 12. Performance Considerations

### 12.1 Query Cost Analysis

| Operation | DDB Operations | Estimated Cost |
|---|---|---|
| Process revenue split (per license) | 1 GetItem + 4 PutItem + 2 UpdateItem + 2 PutItem (ledger) | ~8 WCU + 1 RCU |
| Fixed fee check | 1 GetItem (USAGE#) + conditional PutItem | 1-2 WCU + 1 RCU |
| Revenue earned summary | 1 GetItem (SUMMARY) | 1 RCU |
| Transaction list (50 items) | 1 Query | ~13 RCU |
| Admin platform audit (100 items) | 1 GSI1 Query | ~25 RCU |

### 12.2 Caching Strategy

| Data | Cache | TTL | Invalidation |
|---|---|---|---|
| Revenue summaries | React Query | 60 seconds | Invalidated after new split |
| Transaction lists | React Query | 30 seconds | Invalidated after new split |
| Split preview calculation | No cache (stateless) | -- | N/A |
| License terms | In-memory per-request | Request scope | Fetched from issued_licenses |
