# MON-003: Creator Earnings Dashboard — Revenue Aggregation and Visualization

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: Medium  
**Estimated effort**: 5-7 days

---

## 1. Overview & Motivation

### The Gap

Creators on the platform earn revenue from multiple sources — subscriptions, tips (messages, posts, comments), locked content unlocks, and VOD pay-per-view purchases. However, there is **no unified view** of this revenue. Creators must mentally piece together their earnings from scattered indicators:

- **Subscriptions**: Visible in the subscription management UI, but only as individual subscriber records — no aggregation, no historical revenue totals.
- **Tips**: The `tip_amount_cents` field on messages/posts shows per-item totals, but there is no "total tips received this month" view anywhere.
- **Locked content**: Unlock revenue is recorded in the billing ledger (lines 12206-12228 of messaging.py), but only as individual entries with no aggregation.
- **VOD purchases**: After MON-001, purchase credits will exist in the ledger, but again without aggregation.

The billing ledger (`T.billing` table, `LEDGER#` sort key prefix) stores all transaction records, but there are no query endpoints that aggregate this data by recipient, time range, or revenue type.

### Why This Is Needed

1. **Creator visibility**: Creators need to understand their business performance. "How much did I earn this month?" is a fundamental question with no answer today.

2. **Foundation for payouts (MON-004)**: The payout system needs a reliable "available balance" calculation. The earnings dashboard backend provides this via ledger aggregation.

3. **Platform analytics**: Platform operators need revenue reports for financial planning, tax reporting, and creator program management.

4. **Trust and retention**: Transparent earnings reporting builds creator confidence in the platform and reduces support tickets asking "where is my money?"

### Architecture After This Change

```
Frontend (Creator)                  Backend                           DynamoDB
     |                                 |                                 |
     |-- GET /ui/earnings/summary ---->|                                 |
     |   ?period=month&from=...        |                                 |
     |                                 |-- query T.billing               |
     |                                 |   PK=USER#{creator_id}          |
     |                                 |   SK begins_with LEDGER#        |
     |                                 |   filter: type=credit           |
     |                                 |<-- LEDGER entries --------------|
     |                                 |                                 |
     |                                 |-- aggregate by reason/meta ----->|
     |                                 |   (in-process aggregation)       |
     |                                 |                                 |
     |<-- 200 {                        |                                 |
     |     total_cents: 45000,         |                                 |
     |     breakdown: {                |                                 |
     |       subscriptions: 25000,     |                                 |
     |       tips: 12000,              |                                 |
     |       unlocks: 5000,            |                                 |
     |       vod_purchases: 3000       |                                 |
     |     },                          |                                 |
     |     daily_series: [...],        |                                 |
     |     transactions: [...]         |                                 |
     |   }                             |                                 |
     |                                 |                                 |
     |-- GET /ui/earnings/txns ------->|                                 |
     |   ?cursor=...&limit=50          |                                 |
     |                                 |-- paginated query ------------->|
     |<-- 200 {items, next_cursor} ----|                                 |
```

### Revenue Categories

| Category | Ledger `reason` (new format) | Ledger `meta.content_type` | Source |
|----------|------------------------------|---------------------------|--------|
| Subscriptions | `"Subscription payment"` | N/A | `subscription_server.py` |
| Tips (message) | `"Tip: message"` | `"message"` | MON-002 |
| Tips (post) | `"Tip: post"` | `"post"` | MON-002 |
| Tips (comment) | `"Tip: comment"` | `"comment"` | MON-002 |
| Locked content | `"Message unlock"` | N/A | `messaging.py` |
| VOD purchases | `"VOD sale"` | N/A | MON-001 |
| Post unlocks | `"Post unlock"` | N/A | `newsfeed.py` |

---

## 2. Current State Analysis

### 2.1 Billing Ledger Query Patterns

The billing table (`T.billing`, PK=`USER#{user_sub}`, SK varies) stores all financial records. Credit entries for creators use the `LEDGER#{ts}#{entry_id}` SK pattern.

Current query capabilities:
- `PK = USER#{user_id} AND SK begins_with LEDGER#` — returns all ledger entries for a user (both debits and credits)
- No GSI exists for filtering by `type` (debit/credit) or `reason` — these must be FilterExpressions
- The SK includes a timestamp, enabling range queries: `SK BETWEEN LEDGER#1716681600 AND LEDGER#1719273600` for a time window

**DynamoDB limitation**: `FilterExpression` does not reduce the data scanned — DynamoDB reads up to 1 MB before filtering. For creators with thousands of transactions, pagination via `LastEvaluatedKey` is mandatory.

### 2.2 Subscription Revenue Tracking

The subscription server (`app/routers/subscription_server.py`) records billing via `record_billing_payment()` (line 223), which writes to `T.billing` with `sk=PAY#{invoice_id}` — not `LEDGER#`. These are separate from the general ledger entries.

Additionally, subscription cycle orders are written by `emit_subscription_cycle_order()` (from `app/services/subscription_cycle_orders.py`). These may also use different SK patterns.

**Implication**: The earnings aggregation must scan multiple SK prefixes or rely on a unified approach.

### 2.3 Existing Billing Endpoints (`app/routers/billing.py`)

- `GET /billing/balance` (line 717) — returns wallet balance, not earnings
- `GET /billing/settings` (line 697) — returns billing config
- No endpoint for "list my ledger entries" or "aggregate my revenue"

The billing router does have `list_payment_records_ddb()` (line 651), but this returns `PAY#` records (payment intents), not general ledger entries.

### 2.4 Subscription Access Service (`app/services/subscription_access.py`)

`has_active_subscription()` (line 55) queries `T.subscriptions` with `PK=SUBSCRIBER#{subscriber_id}` and `SK begins_with SUB#`. This tells us whether a subscriber is active, but not how much the creator earns from subscriptions.

Subscription pricing is stored on plan records: `plan["price_cents"]` (used in `_select_plan_price`, subscription_server.py line 170). Monthly and annual intervals supported.

### 2.5 Frontend State

No existing earnings-related pages, components, or API endpoint wrappers. The `/billing` page shows the user's payment methods, wallet balance, and billing history (as a payer), not as a payee/creator.

---

## 3. Technical Design

### 3.1 Earnings Ledger GSI

To efficiently query credit entries for a user within a time range, add a GSI to the billing table:

**Current billing table** (`scripts/local-ddb-init.py`, line 59):
```python
TableDef(_resolve_table_name(S.billing_table_name, "billing"), "pk", "sk")
```

**Add GSI**:
```python
TableDef(
    _resolve_table_name(S.billing_table_name, "billing"),
    "pk",
    "sk",
    gsi=[
        {
            "index_name": "ByPkTypeTs",
            "partition_key": "pk",
            "sort_key": "type_ts",
        },
    ],
),
```

Where `type_ts` is a composite sort key: `"{type}#{ts}"` (e.g., `"credit#1716681600"`). This allows querying `PK=USER#{id} AND type_ts BETWEEN credit#START AND credit#END` without FilterExpression.

**Alternative approach (no GSI)**: Since the billing table is relatively low-volume per user (hundreds to low thousands of entries), a simple query with `SK begins_with LEDGER#` plus a `FilterExpression` on `type = "credit"` may be sufficient. DDB will scan all LEDGER entries and filter, but for typical creator volumes this is under 1 MB. Use pagination as a safety net.

**Decision**: Start with the FilterExpression approach (no schema changes). Add the GSI later if performance profiling shows it is needed. This avoids a DDB table recreation.

### 3.2 Earnings Service: `app/services/creator_earnings.py`

```python
"""Creator earnings aggregation from billing ledger.

Queries LEDGER# entries with type=credit for a given creator,
aggregates by category and time period, and returns structured summaries.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key, Attr

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Revenue category classification based on ledger entry reason/meta
_CATEGORY_RULES: List[Tuple[str, ...]] = [
    # (category, reason_contains, meta_content_type)
    ("tips", "Tip:", None),
    ("subscriptions", "Subscription", None),
    ("unlocks", "unlock", None),           # "Message unlock", "Post unlock"
    ("vod_purchases", "VOD sale", None),
]


def classify_entry(entry: Dict[str, Any]) -> str:
    """Classify a ledger entry into a revenue category.
    
    Classification order:
    1. Check meta.content_type for new-format tip entries
    2. Check reason string for keyword matches
    3. Default to "other" for unrecognized entries
    
    Supports both old format (reason="Tip sent", no meta.content_type)
    and new format (reason="Tip: message", meta.content_type="message").
    
    Args:
        entry: A billing ledger DDB item dict.
    
    Returns:
        One of: "tips", "subscriptions", "unlocks", "vod_purchases", "other"
    """
    reason = (entry.get("reason") or "").lower()
    meta = entry.get("meta") or {}

    # New-format entries with content_type in meta
    content_type = meta.get("content_type", "")
    if content_type in ("message", "post", "comment"):
        return "tips"

    # Reason-based classification
    if "tip" in reason:
        return "tips"
    if "subscription" in reason:
        return "subscriptions"
    if "unlock" in reason:
        return "unlocks"
    if "vod" in reason:
        return "vod_purchases"

    return "other"


def _ts_to_date_key(ts: int, granularity: str) -> str:
    """Convert Unix timestamp to a date key for aggregation.
    
    Args:
        ts: Unix timestamp (seconds).
        granularity: "day", "week", or "month".
    
    Returns:
        Date key string: "2026-05-25" (day), "2026-W21" (week), "2026-05" (month).
    """
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    if granularity == "day":
        return dt.strftime("%Y-%m-%d")
    elif granularity == "week":
        # ISO week: Monday-based
        return dt.strftime("%Y-W%W")
    elif granularity == "month":
        return dt.strftime("%Y-%m")
    return dt.strftime("%Y-%m-%d")


def _query_credit_entries(
    *,
    user_id: str,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    limit: int = 5000,
) -> List[Dict[str, Any]]:
    """Query all credit LEDGER entries for a user within a time range.
    
    Uses SK range query with FilterExpression for type=credit.
    Paginates via LastEvaluatedKey to handle large ledgers.
    Caps at `limit` entries to prevent runaway aggregation.
    
    DDB access pattern:
      PK = USER#{user_id}
      SK BETWEEN LEDGER#{from_ts} AND LEDGER#{to_ts}~
      FilterExpression: type = "credit"
    
    Note: The FilterExpression does NOT reduce DDB scan volume.
    DDB reads up to 1 MB per page before applying the filter.
    For a creator with 50% credit/50% debit entries, the effective
    scan volume is 2x the returned data.
    """
    pk = f"USER#{user_id}"
    collected: List[Dict[str, Any]] = []
    exclusive_start_key = None

    # Build SK range
    sk_start = f"LEDGER#{from_ts or 0}"
    sk_end = f"LEDGER#{to_ts or 9999999999}~"  # ~ sorts after digits

    for _ in range(20):  # max 20 pages to prevent runaway
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").between(sk_start, sk_end),
            "FilterExpression": Attr("type").eq("credit"),
            "Limit": 500,
        }
        if exclusive_start_key:
            kwargs["ExclusiveStartKey"] = exclusive_start_key

        resp = T.billing.query(**kwargs)
        items = resp.get("Items", [])
        collected.extend(items)

        if len(collected) >= limit:
            collected = collected[:limit]
            break

        exclusive_start_key = resp.get("LastEvaluatedKey")
        if not exclusive_start_key:
            break

    return collected


class EarningsSummary:
    """Aggregated earnings summary for a creator.
    
    Accumulates credit entries into:
    - total_cents: Grand total across all categories
    - breakdown: Dict mapping category name to total cents
    - time_series: Dict mapping date keys to per-category totals
    - transaction_count: Number of individual transactions
    """

    def __init__(self):
        self.total_cents: int = 0
        self.currency: str = "USD"
        self.breakdown: Dict[str, int] = defaultdict(int)
        self.time_series: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.transaction_count: int = 0

    def add_entry(self, entry: Dict[str, Any], granularity: str = "day") -> None:
        """Add a single credit entry to the aggregation.
        
        Args:
            entry: A billing ledger DDB item dict with type=credit.
            granularity: Time series grouping ("day", "week", "month").
        """
        amount = int(entry.get("amount_cents", 0))
        ts = int(entry.get("ts", 0))
        category = classify_entry(entry)

        self.total_cents += amount
        self.breakdown[category] += amount
        self.transaction_count += 1

        date_key = _ts_to_date_key(ts, granularity)
        self.time_series[date_key]["total"] += amount
        self.time_series[date_key][category] += amount

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_cents": self.total_cents,
            "currency": self.currency,
            "breakdown": dict(self.breakdown),
            "time_series": [
                {"date": k, **v}
                for k, v in sorted(self.time_series.items())
            ],
            "transaction_count": self.transaction_count,
        }


def get_earnings_summary(
    *,
    user_id: str,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    granularity: str = "day",
) -> Dict[str, Any]:
    """Compute aggregated earnings summary for a creator.
    
    Data flow:
      1. Query all credit LEDGER entries in the time range
      2. Classify each entry into a revenue category
      3. Aggregate totals by category and time period
      4. Return structured summary dict
    """
    entries = _query_credit_entries(user_id=user_id, from_ts=from_ts, to_ts=to_ts)
    summary = EarningsSummary()
    for entry in entries:
        summary.add_entry(entry, granularity=granularity)
    return summary.to_dict()


def get_quick_stats(*, user_id: str) -> Dict[str, Any]:
    """Compute quick stats for common time windows.
    
    Returns pre-aggregated totals for: today, this week, this month, all time.
    Avoids heavy full-scan for dashboard card rendering by computing
    all four windows in a single ledger scan.
    """
    now = now_ts()
    today_start = _start_of_day_utc(now)
    week_start = today_start - (datetime.fromtimestamp(now, tz=timezone.utc).weekday() * 86400)
    month_start = _start_of_month_utc(now)

    entries = _query_credit_entries(user_id=user_id)
    today_cents = 0
    week_cents = 0
    month_cents = 0
    all_time_cents = 0

    for entry in entries:
        amount = int(entry.get("amount_cents", 0))
        ts = int(entry.get("ts", 0))
        all_time_cents += amount
        if ts >= month_start:
            month_cents += amount
        if ts >= week_start:
            week_cents += amount
        if ts >= today_start:
            today_cents += amount

    return {
        "today_cents": today_cents,
        "this_week_cents": week_cents,
        "this_month_cents": month_cents,
        "all_time_cents": all_time_cents,
        "currency": "USD",
        "pending_payout_cents": 0,  # Populated after MON-004
    }


def _start_of_day_utc(ts: int) -> int:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return int(dt.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())


def _start_of_month_utc(ts: int) -> int:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return int(dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp())


def list_earnings_transactions(
    *,
    user_id: str,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Paginated list of individual earning transactions.
    
    Returns newest-first credit entries with category classification.
    Uses DDB cursor-based pagination for efficient traversal.
    """
    pk = f"USER#{user_id}"
    sk_start = f"LEDGER#{from_ts or 0}"
    sk_end = f"LEDGER#{to_ts or 9999999999}~"

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").between(sk_start, sk_end),
        "FilterExpression": Attr("type").eq("credit"),
        "Limit": limit,
        "ScanIndexForward": False,  # newest first
    }

    if cursor:
        from app.core.cursor import decode_cursor
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.billing.query(**kwargs)
    items = resp.get("Items", [])

    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        from app.core.cursor import encode_cursor
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])

    transactions = []
    for item in items:
        transactions.append({
            "entry_id": item.get("entry_id"),
            "ts": int(item.get("ts", 0)),
            "amount_cents": int(item.get("amount_cents", 0)),
            "currency": item.get("currency", "USD"),
            "category": classify_entry(item),
            "reason": item.get("reason", ""),
            "meta": item.get("meta", {}),
        })

    return {
        "items": transactions,
        "next_cursor": next_cursor,
    }
```

### 3.3 API Endpoints

#### 3.3.1 Earnings Summary

```
GET /ui/earnings/summary
```

**Data flow diagram:**
```
Request ?from_date=2026-05-01&to_date=2026-05-31&granularity=day
  │
  ├── require_ui_session → user_sub
  ├── Parse from_date → from_ts (Unix seconds, start of day UTC)
  ├── Parse to_date → to_ts (Unix seconds, end of day UTC)
  ├── Validate granularity in ("day", "week", "month")
  │
  ├── get_earnings_summary(user_id, from_ts, to_ts, granularity)
  │     ├── _query_credit_entries() → paginated DDB query
  │     │     └── PK=USER#{user_sub}, SK BETWEEN LEDGER#{from_ts} AND LEDGER#{to_ts}~
  │     │         FilterExpression: type = "credit"
  │     │         (up to 20 pages, 500 items per page)
  │     │
  │     ├── For each entry: classify_entry() → category
  │     ├── EarningsSummary.add_entry() → accumulate totals
  │     └── summary.to_dict() → response
  │
  └── Return EarningsSummaryOut
```

**Query parameters:**
```python
class EarningsSummaryParams(BaseModel):
    from_date: Optional[str] = None    # ISO date: "2026-05-01"
    to_date: Optional[str] = None      # ISO date: "2026-05-31"
    granularity: str = "day"           # "day" | "week" | "month"
```

**Response model:**
```python
class EarningsSummaryOut(BaseModel):
    total_cents: int
    currency: str = "USD"
    breakdown: Dict[str, int]           # {"tips": 12000, "subscriptions": 25000, ...}
    time_series: List[TimeSeriesPoint]
    transaction_count: int

class TimeSeriesPoint(BaseModel):
    date: str                           # "2026-05-15" or "2026-W20" or "2026-05"
    total: int
    tips: int = 0
    subscriptions: int = 0
    unlocks: int = 0
    vod_purchases: int = 0
    other: int = 0
```

**Handler:**
```python
@router.get("/summary", response_model=EarningsSummaryOut)
def earnings_summary(
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    granularity: str = "day",
    user=Depends(require_ui_session),
):
    user_sub = user["user_sub"]
    from_ts = _parse_date_to_ts(from_date) if from_date else None
    to_ts = _parse_date_to_ts(to_date, end_of_day=True) if to_date else None

    if from_ts and to_ts and from_ts > to_ts:
        raise HTTPException(400, "from_date must be before to_date")
    if granularity not in ("day", "week", "month"):
        raise HTTPException(400, "granularity must be one of: day, week, month")

    return get_earnings_summary(
        user_id=user_sub,
        from_ts=from_ts,
        to_ts=to_ts,
        granularity=granularity,
    )


def _parse_date_to_ts(date_str: str, end_of_day: bool = False) -> int:
    """Parse ISO date string to Unix timestamp.
    
    Args:
        date_str: ISO date like "2026-05-25"
        end_of_day: If True, return timestamp at 23:59:59 UTC
    
    Returns:
        Unix timestamp (int)
    
    Raises:
        HTTPException(400) if date format is invalid
    """
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if end_of_day:
            dt = dt.replace(hour=23, minute=59, second=59)
        return int(dt.timestamp())
    except ValueError:
        raise HTTPException(400, f"Invalid date format: {date_str}. Expected YYYY-MM-DD.")
```

#### 3.3.2 Earnings Transactions (Paginated)

```
GET /ui/earnings/transactions
```

**Query parameters:**
```python
from_date: Optional[str] = None
to_date: Optional[str] = None
limit: int = 50                        # max 200
cursor: Optional[str] = None
```

**Response model:**
```python
class EarningsTransactionOut(BaseModel):
    entry_id: str
    ts: int
    amount_cents: int
    currency: str
    category: str                      # "tips" | "subscriptions" | "unlocks" | "vod_purchases" | "other"
    reason: str
    meta: Dict[str, Any]

class EarningsTransactionsListOut(BaseModel):
    items: List[EarningsTransactionOut]
    next_cursor: Optional[str] = None
```

#### 3.3.3 Earnings Quick Stats

```
GET /ui/earnings/quick-stats
```

Lightweight endpoint returning pre-aggregated totals for common time windows (today, this week, this month, all time). Avoids heavy scan for dashboard card rendering.

**Response model:**
```python
class EarningsQuickStatsOut(BaseModel):
    today_cents: int
    this_week_cents: int
    this_month_cents: int
    all_time_cents: int
    currency: str = "USD"
    pending_payout_cents: int = 0      # Populated after MON-004
```

### 3.4 Frontend Components

#### 3.4.1 EarningsPage (`frontend/src/pages/earnings/EarningsPage.tsx`)

Top-level page with:
- Quick stat cards (today, week, month, all time)
- Time range selector (date pickers + preset buttons: 7d, 30d, 90d, 1y)
- Revenue breakdown bar chart or donut chart (by category)
- Time series line/area chart (daily/weekly/monthly revenue)
- Transaction history table (paginated, sortable)

**Component tree:**
```
EarningsPage
  ├── QuickStatsCards
  │     ├── StatCard "Today" ($XX.XX)
  │     ├── StatCard "This Week" ($XX.XX)
  │     ├── StatCard "This Month" ($XX.XX)
  │     └── StatCard "All Time" ($XX.XX)
  ├── TimeRangeSelector
  │     ├── PresetButtons: "7d" | "30d" | "90d" | "1y" | "All"
  │     ├── DatePicker "From"
  │     └── DatePicker "To"
  ├── RevenueChart
  │     ├── StackedAreaChart (Recharts)
  │     ├── Legend: Tips | Subscriptions | Unlocks | VOD | Other
  │     └── Tooltip (hover shows exact amounts)
  ├── BreakdownChart
  │     └── DonutChart (Recharts) with category labels
  └── TransactionTable
        ├── TableHeader: Date | Category | Amount | Description
        ├── TableRows (one per transaction)
        └── LoadMoreButton (cursor pagination)
```

#### 3.4.2 RevenueChart Component

Uses a charting library (Recharts, already available in shadcn/ui ecosystem) to render:
- Stacked area chart for time series
- Legend showing category colors
- Tooltip with exact amounts on hover

#### 3.4.3 TransactionTable Component

Paginated table showing individual transactions:

| Date | Category | Amount | Description | Details |
|------|----------|--------|-------------|---------|
| May 25, 2026 | Tip | $5.00 | Tip: message | View |
| May 24, 2026 | Subscription | $9.99 | Subscription payment | View |

Clicking "View" opens a detail dialog with full `meta` information.

### 3.5 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface EarningsSummary {
  total_cents: number;
  currency: string;
  breakdown: Record<string, number>;
  time_series: TimeSeriesPoint[];
  transaction_count: number;
}

export interface TimeSeriesPoint {
  date: string;
  total: number;
  tips?: number;
  subscriptions?: number;
  unlocks?: number;
  vod_purchases?: number;
  other?: number;
}

export interface EarningsTransaction {
  entry_id: string;
  ts: number;
  amount_cents: number;
  currency: string;
  category: string;
  reason: string;
  meta: Record<string, unknown>;
}

export interface EarningsTransactionsList {
  items: EarningsTransaction[];
  next_cursor?: string;
}

export interface EarningsQuickStats {
  today_cents: number;
  this_week_cents: number;
  this_month_cents: number;
  all_time_cents: number;
  currency: string;
  pending_payout_cents: number;
}
```

### 3.6 Frontend API Endpoints (`frontend/src/api/endpoints/earnings.ts`)

```typescript
import { client } from "../client";
import type { EarningsSummary, EarningsTransactionsList, EarningsQuickStats } from "../types";

export async function getEarningsSummary(params: {
  from_date?: string;
  to_date?: string;
  granularity?: string;
}): Promise<EarningsSummary> {
  const resp = await client.get("/ui/earnings/summary", { params });
  return resp.data;
}

export async function getEarningsTransactions(params: {
  from_date?: string;
  to_date?: string;
  limit?: number;
  cursor?: string;
}): Promise<EarningsTransactionsList> {
  const resp = await client.get("/ui/earnings/transactions", { params });
  return resp.data;
}

export async function getEarningsQuickStats(): Promise<EarningsQuickStats> {
  const resp = await client.get("/ui/earnings/quick-stats");
  return resp.data;
}
```

### 3.7 Navigation Integration

Add "Earnings" to the sidebar in the Monetization group:

**File**: `frontend/src/components/layout/Sidebar.tsx`  
**File**: `frontend/src/components/layout/AppShell.tsx` (MobileSidebar)  
**File**: `frontend/src/components/layout/MobileNav.tsx`

Icon: `DollarSign` from lucide-react.

**File**: `frontend/src/App.tsx` — Add route:
```typescript
const EarningsPage = lazy(() => import("./pages/earnings/EarningsPage"));
// In router:
<Route path="/earnings" element={<EarningsPage />} />
```

### 3.8 Error Handling

| Scenario | HTTP Status | Error |
|----------|-------------|-------|
| Invalid date format | 400 | `invalid_date_format` |
| from_date > to_date | 400 | `invalid_date_range` |
| Invalid granularity | 400 | `invalid_granularity` |
| Invalid cursor | 400 | `invalid_cursor` |
| limit > 200 | 400 | `limit_exceeded` |

---

## 4. Implementation Plan

### Step 1: Create Earnings Service

**File**: `app/services/creator_earnings.py` (new, ~250 lines)

Contains: `classify_entry()`, `_ts_to_date_key()`, `_query_credit_entries()`, `EarningsSummary`, `get_earnings_summary()`, `list_earnings_transactions()`, `get_quick_stats()`, `_start_of_day_utc()`, `_start_of_month_utc()`.

**Line-by-line description:**
- Lines 1-15: Module docstring, imports
- Lines 17-25: `_CATEGORY_RULES` list
- Lines 28-55: `classify_entry()` with dual-format support
- Lines 58-70: `_ts_to_date_key()` for time series grouping
- Lines 73-110: `_query_credit_entries()` with paginated DDB query
- Lines 113-155: `EarningsSummary` class with `add_entry()` and `to_dict()`
- Lines 158-180: `get_earnings_summary()` top-level aggregation function
- Lines 183-220: `get_quick_stats()` for dashboard cards
- Lines 223-250: `list_earnings_transactions()` paginated transaction list

### Step 2: Create Earnings Router

**File**: `app/routers/earnings.py` (new, ~180 lines)

Three endpoints:
- `GET /ui/earnings/summary`
- `GET /ui/earnings/transactions`
- `GET /ui/earnings/quick-stats`

Also includes `_parse_date_to_ts()` helper and all Pydantic response models.

Register in `app/main.py`:
```python
from app.routers.earnings import router as earnings_router
app.include_router(earnings_router)
```

### Step 3: Add Pydantic Models

**File**: `app/routers/earnings.py` (inline models) or `app/models.py`

Define `EarningsSummaryOut`, `TimeSeriesPoint`, `EarningsTransactionOut`, `EarningsTransactionsListOut`, `EarningsQuickStatsOut`.

### Step 4: Frontend API Layer

**File**: `frontend/src/api/types.ts` — Add TypeScript types  
**File**: `frontend/src/api/endpoints/earnings.ts` (new) — Add API wrappers

### Step 5: Frontend Page

**File**: `frontend/src/pages/earnings/EarningsPage.tsx` (new, ~300 lines)
- Quick stat cards using `useQuery(["earnings", "quick-stats"])`
- Time range selector (local state)
- Revenue chart using `useQuery(["earnings", "summary", params])`
- Transaction table using `useInfiniteQuery(["earnings", "transactions", params])`

### Step 6: Navigation Integration

**Files**:
- `frontend/src/App.tsx` — Add lazy route
- `frontend/src/components/layout/Sidebar.tsx` — Add sidebar link
- `frontend/src/components/layout/AppShell.tsx` — Add mobile sidebar link
- `frontend/src/components/layout/MobileNav.tsx` — Add to MORE_LINKS

### Step 7: Vite Proxy Configuration

**File**: `frontend/vite.config.ts`

Add `/ui/earnings` to the proxy configuration (should already be covered by the `/ui` prefix proxy rule).

### Summary of Files Modified

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/services/creator_earnings.py` | New service | ~250 |
| `app/routers/earnings.py` | New router | ~180 |
| `app/main.py` | Register router | ~3 |
| `frontend/src/api/types.ts` | Add types | ~40 |
| `frontend/src/api/endpoints/earnings.ts` | New API file | ~30 |
| `frontend/src/pages/earnings/EarningsPage.tsx` | New page | ~300 |
| `frontend/src/App.tsx` | Add route | ~5 |
| `frontend/src/components/layout/Sidebar.tsx` | Add nav link | ~5 |
| `frontend/src/components/layout/AppShell.tsx` | Add mobile nav | ~5 |
| `frontend/src/components/layout/MobileNav.tsx` | Add MORE_LINKS | ~3 |
| **Total** | | **~821** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_creator_earnings.py`)

New file, ~500 lines. Tests the earnings service with moto-mocked DynamoDB.

**Complete test function signatures with assertions:**

```python
import pytest
from decimal import Decimal
from moto import mock_dynamodb
from app.services.creator_earnings import (
    classify_entry, get_earnings_summary, list_earnings_transactions,
    get_quick_stats, _ts_to_date_key, EarningsSummary,
)
from app.core.tables import T
from app.core.time import now_ts


@pytest.fixture
def billing_table_with_entries():
    """Create billing table and seed diverse credit entries."""
    # ... create table, seed entries ...


def test_classify_tip_message_new_format():
    """classify_entry: tip message (new format)."""
    entry = {"reason": "Tip: message", "meta": {"content_type": "message"}}
    assert classify_entry(entry) == "tips"


def test_classify_tip_post_new_format():
    """classify_entry: tip post (new format)."""
    entry = {"reason": "Tip: post", "meta": {"content_type": "post"}}
    assert classify_entry(entry) == "tips"


def test_classify_tip_legacy_format():
    """classify_entry: tip (legacy format)."""
    entry = {"reason": "Tip sent", "meta": {}}
    assert classify_entry(entry) == "tips"


def test_classify_tip_attached_legacy():
    """classify_entry: attached tip (legacy format)."""
    entry = {"reason": "Tip attached to message", "meta": {}}
    assert classify_entry(entry) == "tips"


def test_classify_subscription():
    """classify_entry: subscription."""
    entry = {"reason": "Subscription payment", "meta": {}}
    assert classify_entry(entry) == "subscriptions"


def test_classify_message_unlock():
    """classify_entry: message unlock."""
    entry = {"reason": "Message unlock", "meta": {}}
    assert classify_entry(entry) == "unlocks"


def test_classify_post_unlock():
    """classify_entry: post unlock."""
    entry = {"reason": "Post unlock", "meta": {}}
    assert classify_entry(entry) == "unlocks"


def test_classify_vod_sale():
    """classify_entry: VOD sale."""
    entry = {"reason": "VOD sale", "meta": {}}
    assert classify_entry(entry) == "vod_purchases"


def test_classify_unknown_reason():
    """classify_entry: unknown reason."""
    entry = {"reason": "Misc credit", "meta": {}}
    assert classify_entry(entry) == "other"


def test_empty_ledger_returns_zero(billing_table_empty):
    """get_earnings_summary: empty ledger returns zero totals."""
    result = get_earnings_summary(user_id="creator_empty")
    assert result["total_cents"] == 0
    assert result["breakdown"] == {}
    assert result["time_series"] == []
    assert result["transaction_count"] == 0


def test_single_entry_summary(billing_table_with_entries):
    """get_earnings_summary: single entry."""
    result = get_earnings_summary(user_id="creator_single")
    assert result["total_cents"] == 500
    assert result["breakdown"]["tips"] == 500
    assert result["transaction_count"] == 1


def test_multiple_categories_breakdown(billing_table_with_entries):
    """get_earnings_summary: multiple categories sum correctly."""
    result = get_earnings_summary(user_id="creator_multi")
    assert result["breakdown"]["tips"] == 1200
    assert result["breakdown"]["subscriptions"] == 2500
    assert result["breakdown"]["unlocks"] == 500
    assert result["total_cents"] == 4200
    assert result["transaction_count"] == 4


def test_time_range_filter(billing_table_with_entries):
    """get_earnings_summary: time range filter excludes out-of-range entries."""
    result = get_earnings_summary(user_id="creator_range", from_ts=150, to_ts=250)
    # Only entries at ts=200 should be included (not ts=100 or ts=300)
    assert result["transaction_count"] == 1


def test_granularity_day(billing_table_with_entries):
    """get_earnings_summary: day granularity produces per-day time series."""
    result = get_earnings_summary(user_id="creator_daily", granularity="day")
    dates = [p["date"] for p in result["time_series"]]
    assert all(len(d) == 10 for d in dates)  # YYYY-MM-DD format


def test_granularity_month(billing_table_with_entries):
    """get_earnings_summary: month granularity aggregates across days."""
    result = get_earnings_summary(user_id="creator_monthly", granularity="month")
    dates = [p["date"] for p in result["time_series"]]
    assert all(len(d) == 7 for d in dates)  # YYYY-MM format


def test_pagination(billing_table_with_entries):
    """list_earnings_transactions: pagination with limit."""
    result = list_earnings_transactions(user_id="creator_many", limit=20)
    assert len(result["items"]) == 20
    assert result["next_cursor"] is not None


def test_newest_first(billing_table_with_entries):
    """list_earnings_transactions: newest first ordering."""
    result = list_earnings_transactions(user_id="creator_ordered")
    timestamps = [item["ts"] for item in result["items"]]
    assert timestamps == sorted(timestamps, reverse=True)


def test_cursor_continuation(billing_table_with_entries):
    """list_earnings_transactions: cursor continuation."""
    page1 = list_earnings_transactions(user_id="creator_many", limit=10)
    page2 = list_earnings_transactions(user_id="creator_many", limit=10, cursor=page1["next_cursor"])
    all_ids = {i["entry_id"] for i in page1["items"]} | {i["entry_id"] for i in page2["items"]}
    assert len(all_ids) == 20  # No duplicates


def test_only_credits_included(billing_table_with_entries):
    """Only credit entries included (debits filtered)."""
    # Seed both debit and credit entries for the same user
    result = get_earnings_summary(user_id="creator_mixed")
    assert result["total_cents"] > 0  # Only credits counted


def test_decimal_amounts_coerced(billing_table_with_entries):
    """DDB Decimal amounts coerced to int."""
    result = list_earnings_transactions(user_id="creator_decimal")
    for item in result["items"]:
        assert isinstance(item["amount_cents"], int)


def test_multi_page_accumulation(billing_table_with_entries):
    """>500 entries forces multi-page DDB query. Total is correct."""
    result = get_earnings_summary(user_id="creator_large")
    assert result["transaction_count"] > 500
    assert result["total_cents"] > 0


def test_quick_stats_windows(billing_table_with_entries):
    """Quick stats: today/week/month/all-time windows."""
    result = get_quick_stats(user_id="creator_stats")
    assert result["all_time_cents"] >= result["this_month_cents"]
    assert result["this_month_cents"] >= result["this_week_cents"]
    assert result["this_week_cents"] >= result["today_cents"]
```

### 5.2 E2E Tests (`frontend/e2e/creator-earnings.spec.ts`)

New file, ~400 lines.

**Section 93: Earnings API (8 tests)**:

1. `Empty earnings returns zero totals` — new user, GET summary → total_cents=0
2. `Tip credit appears in earnings summary` — seed tip credit entry, verify total
3. `Multiple categories in breakdown` — seed tip + subscription + unlock credits, verify breakdown
4. `Time range filter excludes out-of-range entries` — seed entries at known timestamps
5. `Daily granularity produces per-day time series` — verify time_series dates
6. `Monthly granularity aggregates across days` — verify monthly rollup
7. `Transactions endpoint returns newest first` — verify ordering
8. `Transactions pagination with cursor` — first page + second page

**Section 94: Earnings API -- Edge Cases (4 tests)**:

1. `Only credit entries included in summary` — seed debit + credit, verify only credit counted
2. `Legacy reason format is classified correctly` — seed entry with reason="Tip sent"
3. `All-time query with no date range` — omit from_date/to_date, get everything
4. `Invalid date format returns 400` — from_date="not-a-date", verify error

**Section 95: Earnings UI (6 tests)**:

1. `Earnings page loads with quick stat cards` — navigate to /earnings, verify card elements
2. `Quick stats show correct totals` — seed data, verify card text
3. `Revenue breakdown chart renders categories` — verify chart legend items
4. `Date range selector filters data` — select "Last 7 Days", verify query refetch
5. `Transaction table shows recent earnings` — verify table rows
6. `Transaction table paginator loads more` — click "Load more", verify additional rows

**Test Setup (beforeAll)**:
- Seed sessions for Alice (creator)
- Write credit ledger entries directly to DDB for Alice:
  - 3 tip credits (content_type: message, post, comment)
  - 2 subscription credits
  - 1 unlock credit
  - 1 VOD sale credit
  - Entries spread across today, yesterday, last week

### 5.3 Edge Cases to Cover

1. **High-volume creators**: A creator with 10,000+ transactions per month. The query must paginate via `LastEvaluatedKey` and aggregate incrementally. The `_query_credit_entries` function caps at 5,000 entries per summary request with a 20-page scan limit.

2. **Time zone handling**: `from_date` and `to_date` are ISO dates interpreted as UTC. The frontend should convert local dates to UTC before sending. Document this in the API response.

3. **Currency consistency**: Currently all tips are USD. The aggregation sums all `amount_cents` regardless of `currency`. If multi-currency is added later, the summary must group by currency.

4. **Decimal coercion**: DDB returns `Decimal` for all numbers. All arithmetic and comparisons must use `int()` coercion to avoid `TypeError` in Python. The `_int_or_none` pattern from `video_metadata_store.py` should be reused.

5. **Empty time windows**: If a creator has no earnings on certain days, the time_series should either omit those days or include them with zero totals. Decision: omit them — the frontend chart library handles sparse data.

6. **Subscription revenue attribution**: Subscription payments are recorded under the subscriber's `pk` (USER#{subscriber_id}) with `sk=PAY#...`. To show them as creator revenue, the billing ledger must also have a credit entry under the creator's pk. This is currently handled by `record_billing_payment()` in `subscription_server.py` — verify that it writes a creator-side credit. If not, this must be added (same pattern as MON-002 tip credits).

7. **Race condition on concurrent reads/writes**: A new tip arriving while the earnings summary is being computed may be missed if it lands on a page already scanned. This is acceptable — the dashboard is eventually consistent, not transactional.

---

## 6. Security Considerations

### 6.1 Authentication & Authorization

- All earnings endpoints require `require_ui_session`. A user can only view their own earnings -- the `user_sub` is extracted from the session cookie JWT.
- There is no admin earnings endpoint in this ticket. Platform-wide analytics would require a separate admin endpoint with `require_admin_session`.
- No cross-user earnings queries are possible. The DDB query uses `PK=USER#{user_sub}` which is derived from the authenticated session, not from a request parameter.

### 6.2 Input Validation

- `from_date` / `to_date`: Validated via `_parse_date_to_ts()` which uses `datetime.strptime` with `"%Y-%m-%d"` format. Invalid formats raise HTTP 400.
- `granularity`: Validated against an explicit allowlist `("day", "week", "month")`.
- `limit`: Capped at 200 via Pydantic `le=200`. Default is 50.
- `cursor`: Decoded via `app.core.cursor.decode_cursor()`. Invalid cursors raise HTTP 400.

### 6.3 Rate Limiting

- The summary endpoint performs a potentially expensive DDB scan (up to 20 pages). Rate-limit to 10 requests per minute per user to prevent abuse.
- The quick-stats endpoint is lighter but still scans the full ledger. Same rate limit applies.
- Consider adding an in-memory TTL cache (60s) for quick-stats responses keyed by `user_id`.

### 6.4 Data Exposure

- Earnings transaction metadata (`meta` field) may contain IDs of other users (tipper_user_id, buyer_id). These are opaque identifiers, not PII. The frontend should not attempt to resolve them to display names without explicit creator consent.
- The `payment_method_id` in metadata is the tipper's PM, not the creator's. This is acceptable in the creator's earnings view -- it helps identify the payment channel.

### 6.5 OWASP Considerations

- **Broken Access Control**: PK-based DDB queries prevent cross-user access structurally.
- **Server-Side Request Forgery**: No external calls are made. All data comes from DDB.
- **Mass Assignment**: Pydantic models with explicit field definitions prevent unexpected input.

---

## 7. Migration & Rollback Plan

### 7.1 No Schema Changes (Initial)

The earnings service queries existing billing table data. No new tables or GSIs are created in the initial implementation.

### 7.2 Future GSI Addition

If performance profiling shows the FilterExpression approach is too slow (unlikely for <10K entries per creator), add the `ByPkTypeTs` GSI:

```python
# In scripts/local-ddb-init.py, update the billing TableDef:
gsi=[{
    "index_name": "ByPkTypeTs",
    "partition_key": "pk",
    "sort_key": "type_ts",
}]
```

This requires:
1. All existing LEDGER entries to have a `type_ts` attribute backfilled (`"{type}#{ts}"`)
2. Future ledger writes (MON-001, MON-002, messaging.py, newsfeed.py) to include `type_ts`
3. DDB GSI creation is online and non-destructive -- table remains available during creation

### 7.3 Feature Flag

```python
# In app/core/settings.py:
earnings_dashboard_enabled: bool = os.environ.get("EARNINGS_DASHBOARD_ENABLED", "0") not in ("0", "false", "False")
```

When disabled, the earnings router returns 404 for all endpoints. The frontend conditionally shows the sidebar link based on a feature flag API response.

### 7.4 Rollback Steps

1. Set `EARNINGS_DASHBOARD_ENABLED=0` -- endpoints return 404.
2. Remove the sidebar link from the frontend (or gate behind flag).
3. No data cleanup needed -- no writes are made by the earnings service.

### 7.5 Zero-Downtime

- Additive-only change: new service, new router, new frontend page.
- No existing endpoints or tables are modified.
- Frontend route addition is lazy-loaded; missing route falls back to 404 page.

---

## 8. Operational Runbook

### 8.1 Metrics to Add

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `earnings_summary_total` | Counter | `status={success,failure}` | Summary endpoint calls |
| `earnings_summary_latency_seconds` | Histogram | | End-to-end latency |
| `earnings_summary_entries_scanned` | Histogram | | Number of DDB items scanned per request |
| `earnings_summary_pages_scanned` | Histogram | | Number of DDB pages per request |
| `earnings_txns_total` | Counter | | Transaction list endpoint calls |
| `earnings_quick_stats_total` | Counter | | Quick stats endpoint calls |

### 8.2 Alerting Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Summary latency p99 > 2s | Histogram quantile | Medium |
| Summary scan > 15 pages | `earnings_summary_pages_scanned > 15` | Medium |
| Endpoint error rate > 5% | `rate(earnings_summary_total{status=failure}) > 0.05` | High |

### 8.3 Common Debugging Scenarios

**Scenario: Creator's earnings total does not match expected amount**
1. Query `T.billing` for `PK=USER#{creator_id}, SK begins_with LEDGER#, type=credit`.
2. Sum `amount_cents` manually.
3. Compare with the summary endpoint response.
4. If mismatch, check if the query hit the 5000-entry cap or 20-page limit.
5. Check for reversed entries (`state=refunded`) which should be excluded.

**Scenario: Summary endpoint is slow (>2s)**
1. Check DDB CloudWatch: `ConsumedReadCapacityUnits` for the billing table.
2. If high, the creator has many ledger entries. Consider adding the ByPkTypeTs GSI.
3. As a temporary fix, suggest the creator use a narrower date range.

**Scenario: Quick stats show stale data**
1. If TTL caching is enabled, wait 60 seconds for cache expiry.
2. New earnings appear in the ledger within 1-2 seconds of the tip/purchase.
3. The quick-stats scan reads from DDB (eventually consistent by default). If strong consistency is needed, add `ConsistentRead=True` to the query.

### 8.4 Log Patterns

```
{"level": "info", "event": "earnings_summary_computed", "user_id": "...", "total_cents": 45000, "entries": 127, "pages": 3}
{"level": "warning", "event": "earnings_summary_page_limit_reached", "user_id": "...", "pages": 20}
{"level": "info", "event": "earnings_txns_listed", "user_id": "...", "count": 50, "has_more": true}
```

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput

| Metric | Estimate | Basis |
|--------|----------|-------|
| Summary requests/sec | 2 | Creators checking dashboard |
| Quick stats requests/sec | 5 | Dashboard loads on page visit |
| Transaction list requests/sec | 3 | Scrolling/paginating |
| Total DDB reads/sec | 50 | ~5 pages per summary x 2/sec + pagination reads |

### 9.2 DDB Read Capacity Impact

**Per summary request:**
- Pages scanned: 1-20 (typical: 3-5 for a creator with <2000 entries)
- Items per page: up to 500
- RCUs per page: ~5-10 (depending on item size, eventually consistent reads)
- Total per request: ~15-50 RCUs

**Per quick-stats request:**
- Same as summary (full scan needed to compute all-time total)
- With caching: 0 RCUs for cache hits (60s TTL)

**Aggregate impact:**
- At 5 requests/sec, ~150 RCUs burst. On-demand billing handles this.

### 9.3 Caching Strategy

**In-memory TTL cache for quick-stats:**
```python
from functools import lru_cache
import time

_quick_stats_cache: Dict[str, Tuple[int, Dict]] = {}
_CACHE_TTL = 60  # seconds

def get_quick_stats_cached(user_id: str) -> Dict[str, Any]:
    now = int(time.time())
    cached = _quick_stats_cache.get(user_id)
    if cached and (now - cached[0]) < _CACHE_TTL:
        return cached[1]
    result = get_quick_stats(user_id=user_id)
    _quick_stats_cache[user_id] = (now, result)
    return result
```

Caveat: This cache is per-process. With `--workers 1` in dev mode (required for moto), this is fine. In production with multiple workers, use Redis or DDB-based caching.

### 9.4 Pre-Aggregation (Future)

For very high-volume creators (>10K transactions/month), consider a daily aggregation job:
1. Run nightly at UTC midnight
2. Scan previous day's credit entries
3. Write pre-computed daily totals to `sk=EARNINGS_DAILY#2026-05-25` under the creator's PK
4. Summary endpoint checks for pre-computed totals first, only scans live data for the current day

This is out of scope for the initial implementation.

### 9.5 Latency Budget

| Operation | Target p99 | Components |
|-----------|-----------|------------|
| GET /earnings/quick-stats | 500ms | Full ledger scan (or 1ms cache hit) |
| GET /earnings/summary | 1000ms | Time-range scan + aggregation |
| GET /earnings/transactions | 200ms | Single-page DDB query + cursor decode |

---

## 10. Dependency Analysis

### 10.1 Blocked By

| Ticket | Dependency |
|--------|-----------|
| MON-002 | Tip credit entries must exist for accurate tip revenue reporting |

Without MON-002, the dashboard will show:
- Subscriptions: correct (if subscription_server writes credits)
- Tips: incomplete (only old debit entries exist, no credits)
- Unlocks: correct (messaging.py writes credits for unlocks)
- VOD purchases: correct (MON-001 writes credits)

### 10.2 Blocks

| Ticket | Dependency |
|--------|-----------|
| MON-004 | Payout system uses `get_quick_stats().all_time_cents` for available balance |

### 10.3 Integration Points

- **Billing table (`T.billing`)**: Read-only queries on LEDGER entries.
- **Cursor utilities (`app/core/cursor.py`)**: Uses `encode_cursor()` and `decode_cursor()` for pagination.
- **Settings (`app/core/settings.py`)**: Feature flag for dashboard enablement.
- **Frontend navigation**: Sidebar.tsx, AppShell.tsx, MobileNav.tsx, App.tsx.

---

## 11. Acceptance Criteria

1. `GET /ui/earnings/summary` returns a correctly structured `EarningsSummaryOut` with `total_cents`, `breakdown`, `time_series`, and `transaction_count`.
2. The `breakdown` map correctly categorizes credits as "tips", "subscriptions", "unlocks", "vod_purchases", or "other".
3. Both old-format (`reason="Tip sent"`) and new-format (`meta.content_type="message"`) entries are classified correctly.
4. `from_date` and `to_date` query parameters correctly filter entries by timestamp.
5. `granularity` parameter produces time series grouped by day, week, or month.
6. `GET /ui/earnings/transactions` returns paginated credit entries in newest-first order.
7. Cursor-based pagination correctly continues from the previous page without duplicates.
8. `GET /ui/earnings/quick-stats` returns correct totals for today, this week, this month, and all time.
9. Only credit entries are included in all responses (debits are filtered out).
10. The earnings page is accessible at `/earnings` and renders quick stat cards, revenue chart, and transaction table.
11. The sidebar shows an "Earnings" link with the DollarSign icon.
12. Invalid date formats return HTTP 400 with a descriptive error message.
13. All 20 unit tests and 18 E2E tests pass.

---

## 12. Error Handling Matrix

| Endpoint | Condition | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-----------|-------------|------------|---------------------|-----------------|
| GET /earnings/summary | Invalid from_date format | 400 | `invalid_date_format` | "Invalid date format: X. Expected YYYY-MM-DD." | Fix date |
| GET /earnings/summary | from_date > to_date | 400 | `invalid_date_range` | "from_date must be before to_date" | Swap dates |
| GET /earnings/summary | Invalid granularity | 400 | `invalid_granularity` | "granularity must be one of: day, week, month" | Use valid value |
| GET /earnings/transactions | Invalid cursor | 400 | `invalid_cursor` | "Invalid pagination cursor" | Start from first page |
| GET /earnings/transactions | limit > 200 | 422 | `validation_error` | Pydantic error | Reduce limit |
| GET /earnings/transactions | limit < 1 | 422 | `validation_error` | Pydantic error | Use limit >= 1 |
| All endpoints | DDB throttling | 500 | `internal_error` | "Unable to load earnings. Try again." | Retry |
| All endpoints | Session expired | 401 | `unauthorized` | Redirect to login | Re-authenticate |

---

## 13. Frontend Component Specifications

### 13.1 EarningsPage Component

```typescript
interface EarningsPageProps {
  // No props -- top-level page component
}
```

**State management:**
- `dateRange: { from: string | null; to: string | null }` -- local React state
- `granularity: "day" | "week" | "month"` -- local React state
- Quick stats: `useQuery(["earnings", "quick-stats"], getEarningsQuickStats)`
- Summary: `useQuery(["earnings", "summary", dateRange, granularity], () => getEarningsSummary(...))`
- Transactions: `useInfiniteQuery(["earnings", "transactions", dateRange], ...)`

**Responsive breakpoints:**
- Mobile (<640px): Single-column layout; stat cards in 2x2 grid; chart full-width; table scrollable
- Tablet (640-1024px): 4 stat cards in a row; chart + breakdown side by side
- Desktop (>1024px): Full dashboard layout with chart, breakdown, and table visible simultaneously

**Accessibility:**
- Stat cards: `role="status"`, `aria-label="Today's earnings: $XX.XX"`
- Chart: `aria-label="Revenue chart"` with tabular fallback for screen readers
- Transaction table: Standard `<table>` with `<thead>`, `<tbody>`, proper `scope` attributes
- Date pickers: keyboard navigable, labeled with `aria-label`
- "Load more" button: `aria-label="Load more transactions"`

**Keyboard navigation:**
- Tab order: Stat cards → Date range presets → Date pickers → Chart → Table → Load more
- Enter on preset button updates date range and refetches data
- Enter on "Load more" fetches next page

### 13.2 QuickStatCard Component

```typescript
interface QuickStatCardProps {
  title: string;          // "Today", "This Week", etc.
  amountCents: number;
  currency: string;
  isLoading: boolean;
}
```

Renders a shadcn/ui `Card` with:
- Title in `CardHeader`
- Formatted amount (e.g., "$450.00") in `CardContent` with `text-2xl font-bold`
- Loading skeleton when `isLoading`

### 13.3 RevenueChart Component

```typescript
interface RevenueChartProps {
  timeSeries: TimeSeriesPoint[];
  isLoading: boolean;
}
```

Uses Recharts `<AreaChart>` with stacked areas for each category:
- Tips: `#10B981` (green)
- Subscriptions: `#3B82F6` (blue)
- Unlocks: `#F59E0B` (amber)
- VOD Purchases: `#8B5CF6` (purple)
- Other: `#6B7280` (gray)

### 13.4 TransactionTable Component

```typescript
interface TransactionTableProps {
  transactions: EarningsTransaction[];
  hasMore: boolean;
  onLoadMore: () => void;
  isLoading: boolean;
}
```

Columns:
- Date: formatted from `ts` using `Intl.DateTimeFormat`
- Category: Badge with color matching chart
- Amount: `$X.XX` format
- Description: `reason` field
- Actions: "View" button opening detail dialog

---

## 14. Related Tickets

- **MON-001**: VOD pay-per-view credits appear in earnings under "vod_purchases"
- **MON-002**: Tip ledger integration ensures all tips have credit entries
- **MON-004**: Payout system uses earnings totals for available balance
- **MON-005**: Subscription-gated VOD generates additional subscription credits
