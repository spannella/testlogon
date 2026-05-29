# INFRA-005: Compute Cost Tracking

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 6-8 days  
**Dependencies**: INFRA-003 (EC2 Launcher), INFRA-004 (K8s Launcher)

---

## 1. Overview & Motivation

### The Gap

INFRA-003 and INFRA-004 allow users to launch EC2 instances and K8s containers, but there is no mechanism to:

1. Track per-minute compute costs as resources run
2. Deduct charges from the user's wallet balance
3. Enforce spending budgets to prevent bill shock
4. Send spending alerts at configurable thresholds
5. Show users a breakdown of their compute spending
6. Give admins a platform-wide spending overview

The platform already has a mature billing system. The `billing` DDB table uses a ledger pattern (`pk=USER#{user_sub}`, `sk=LEDGER#{timestamp}#{entry_id}`) for wallet transactions. Per-minute billing is implemented in `app/routers/call_billing.py` for video calls, using a heartbeat model where the server deducts charges every 60 seconds. This same pattern can be adapted for compute resources.

### Why This Matters

1. **Monetization**: Compute resources have real costs. Without billing, the platform subsidizes every launched instance — unsustainable at scale.
2. **Cost transparency**: Users need to see how much they are spending before, during, and after compute usage.
3. **Abuse prevention**: Without budgets, a single user could launch 3 large instances for 24 hours, accumulating hundreds of dollars in charges.
4. **Existing pattern**: The `CallBillingLedger` pattern from `app/routers/call_billing.py` provides a proven blueprint for per-minute billing with heartbeats, pro-rated final charges, and ledger entries.

### Architecture After This Change

```
Compute Billing Flow

  Instance/Pod starts
       |
       v
  +------------------------+
  | compute_billing_timer  |  Background task (every 5 min)
  | (app/services/         |
  |  compute_billing.py)   |
  +------------------------+
       |
       | For each running resource:
       |   1. Calculate minutes since last tick
       |   2. Lookup rate (instance_type → cents/min)
       |   3. Check wallet balance >= charge
       |   4. Deduct from wallet (billing table LEDGER entry)
       |   5. If balance depleted → auto-terminate resource
       |   6. If threshold crossed → send spending alert
       |
       v
  +-------------------+
  | compute_billing    |  PK=user_sub, SK=LEDGER#{ts}#{id}
  | DDB table          |  GSIs: ByResourceId, ByMonth
  +-------------------+
       |
       +---> Spending dashboard (frontend)
       |     - Current month total
       |     - Per-resource breakdown
       |     - Budget meter with thresholds
       |
       +---> Admin spending report
             - Platform-wide totals
             - Per-user breakdown
```

### Detailed Data Flow Diagram

```
                  +-----------+
                  |  Frontend |
                  | (React)   |
                  +-----+-----+
                        |
          GET /ui/remote/billing/*
                        |
                        v
              +---------+---------+
              |   API Router      |
              | compute_billing   |
              | .py (FastAPI)     |
              +---------+---------+
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
  +-------+---+ +------+----+ +------+------+
  | compute   | | billing   | | alerts      |
  | _billing  | | table     | | table       |
  | table     | | (wallet)  | | (alerts)    |
  +-----------+ +-----------+ +-------------+
       ^                            |
       |                            v
  +----+---+                  +-----------+
  | Timer  |                  | User gets |
  | (bg    |                  | in-app    |
  | task)  |                  | alert     |
  +--------+                  +-----------+
       |
       +-- Reads running instances from ec2_instances / k8s_pods tables
       +-- Writes LEDGER entries to compute_billing table
       +-- Deducts from wallet via billing table conditional update
       +-- Terminates instances on zero balance via ec2_launcher / k8s_launcher
```

---

## 2. Current State Analysis

### 2.1 Call Billing Pattern (`app/routers/call_billing.py`)
<!-- VERIFIED: HeartbeatIn at :43, HeartbeatOut at :47, CallBillingStatusOut at :60, call_heartbeat at :148-149 -->

The call billing system provides a proven per-minute billing model:

```python
class CallRateIn(BaseModel):
    rate_cents_per_minute: int = Field(..., ge=1, le=10000)

class HeartbeatIn(BaseModel):
    call_id: str
    timestamp: int

class HeartbeatOut(BaseModel):
    ok: bool
    accumulated_cost_cents: int
    remaining_balance_cents: int
    ...

class CallBillingStatusOut(BaseModel):
    call_id: str
    accumulated_cost_cents: int
    duration_seconds: int
    ...
```

The `call_heartbeat()` endpoint (line 149) processes per-minute billing ticks. Each tick:
1. Calculates elapsed time since last tick
2. Multiplies by the per-minute rate
3. Writes a `LEDGER` entry to the `billing` table
4. Checks if wallet balance is sufficient for the next minute
5. Returns accumulated cost and remaining balance

### 2.2 Billing Table Schema (`billing` table)
<!-- VERIFIED: billing table at scripts/local-ddb-init.py:59; T.billing at app/core/tables.py:146; apply_wallet_delta at app/services/billing_shared.py:178 -->

```
PK: USER#{user_sub}
SK: LEDGER#{timestamp}#{entry_id}
Fields: amount_cents (N), currency (S), reason (S), resource_type (S), resource_id (S)

PK: USER#{user_sub}
SK: BILLING
Fields: default_payment_method_id (S), wallet_balance_cents (N)
```

The wallet balance is tracked as `wallet_balance_cents` on the `WALLET` row (SK=`WALLET`, NOT `BILLING` — see `app/services/billing_shared.py:166` where `WALLET_SK = "WALLET"`). Deductions use `ADD wallet_balance_cents :neg_amount` with a condition expression `wallet_balance_cents >= :amount` to prevent overdraft (see `apply_wallet_delta` at `app/services/billing_shared.py:178`).

### 2.3 Compute Rate Cards

INFRA-003 and INFRA-004 define cost metadata in their instance type and preset configurations:

```python
# EC2 (INFRA-003)
INSTANCE_TYPES = {
    "t3.micro":  {"cost_cents_per_min": 0.2},
    "t3.small":  {"cost_cents_per_min": 0.4},
    "t3.medium": {"cost_cents_per_min": 0.8},
    "t3.large":  {"cost_cents_per_min": 1.5},
}

# K8s (INFRA-004)
RESOURCE_PRESETS = {
    "small":  {"cost_cents_per_min": 0.1},
    "medium": {"cost_cents_per_min": 0.3},
    "large":  {"cost_cents_per_min": 0.6},
    "xlarge": {"cost_cents_per_min": 1.2},
}
```

### 2.4 Alerts System (`app/services/alerts.py`)

`write_alert()` (see `app/services/alerts.py:355`) creates in-app alerts. This is the integration point for spending threshold alerts.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `compute_billing`
<!-- NOTE: compute_billing table does not exist yet in scripts/local-ddb-init.py — new table required -->

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.compute_billing_table_name, "compute_billing"),
    "user_sub",            # PK — resource owner
    "sk",                  # SK — LEDGER#{timestamp}#{entry_id}
    gsis=[
        {"index_name": "ByResourceId", "partition_key": "resource_id", "sort_key": "created_at"},
        {"index_name": "ByMonth", "partition_key": "user_sub", "sort_key": "month_key"},
    ],
    attr_types={"created_at": "N"},
)
```

### 3.2 DynamoDB Access Patterns

| Access Pattern | Table/GSI | PK | SK / Filter | Example |
|---|---|---|---|---|
| Get all ledger entries for user | Main table | `user_sub` | `begins_with(sk, "LEDGER#")` | All billing events for Alice |
| Get entries for a specific resource | GSI: ByResourceId | `resource_id` | `created_at BETWEEN :start AND :end` | All charges for instance `i-abc123` |
| Get monthly summary for user | GSI: ByMonth | `user_sub` | `month_key = "2026-05"` | May 2026 spending summary |
| Get budget for user | Main table | `user_sub` | `sk = "BUDGET"` | Alice's monthly budget config |
| Get monthly running total | Main table | `user_sub` | `sk = "MONTH#2026-05"` | Running total for May |
| List all users with budgets | Scan | `sk = "BUDGET"` | FilterExpression | Admin report (infrequent) |

**Ledger entry schema**:

| Field | Type | Description |
|-------|------|-------------|
| `user_sub` | S (PK) | Resource owner |
| `sk` | S (SK) | `LEDGER#{timestamp}#{entry_id}` |
| `entry_id` | S | UUID |
| `resource_type` | S | `ec2` or `k8s` |
| `resource_id` | S | Instance/pod ID from INFRA-003/004 |
| `resource_label` | S | Human-readable label |
| `instance_type_or_preset` | S | e.g., `t3.micro` or `small` |
| `event` | S | `instance_start`, `periodic_tick`, `instance_stop` |
| `amount_cents` | N | Charge amount (positive = debit) |
| `duration_minutes` | N | Minutes covered by this entry |
| `rate_cents_per_min` | N | Rate used for calculation |
| `wallet_balance_after` | N | Balance after deduction |
| `created_at` | N | Unix timestamp |
| `month_key` | S | `YYYY-MM` for monthly aggregation |

**Budget/quota item schema** (same table, different SK pattern):

| Field | SK Pattern | Description |
|-------|-----------|-------------|
| `budget_monthly_cents` | `BUDGET` | Monthly spending cap (admin-set) |
| `budget_alert_thresholds` | `BUDGET` | List of threshold percentages [50, 80, 100] |
| `current_month_total_cents` | `MONTH#{YYYY-MM}` | Running total for the month |
| `alerts_sent` | `MONTH#{YYYY-MM}` | Set of thresholds already alerted |

### 3.3 Service Layer: `app/services/compute_billing.py`
<!-- NOTE: app/services/compute_billing.py does not exist yet — new implementation required -->

New file (~350 lines):

```python
"""Compute cost tracking — per-minute billing for EC2 instances and K8s pods."""

from __future__ import annotations
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert, audit_event

# Rate cards (imported from INFRA-003/004 modules)
from app.services.ec2_launcher import INSTANCE_TYPES
from app.services.k8s_launcher import RESOURCE_PRESETS

DEFAULT_BUDGET_MONTHLY_CENTS = 5000  # $50/month
DEFAULT_ALERT_THRESHOLDS = [50, 80, 100]  # percent


def record_billing_event(
    user_sub: str,
    *,
    resource_type: str,       # "ec2" or "k8s"
    resource_id: str,
    resource_label: str,
    instance_type_or_preset: str,
    event: str,               # "instance_start", "periodic_tick", "instance_stop"
    duration_minutes: float,
) -> Dict[str, Any]:
    """Write a billing ledger entry and deduct from wallet."""

def get_rate(resource_type: str, type_or_preset: str) -> float:
    """Lookup cents-per-minute rate for a resource type."""

def get_monthly_summary(user_sub: str, *, month: str | None = None) -> Dict[str, Any]:
    """Get spending summary for a month. Defaults to current month."""

def get_spending_ledger(
    user_sub: str,
    *,
    resource_id: str | None = None,
    limit: int = 100,
    cursor: str | None = None,
) -> Dict[str, Any]:
    """List billing ledger entries with optional resource filter."""

def get_resource_breakdown(user_sub: str, *, month: str | None = None) -> List[Dict[str, Any]]:
    """Per-resource spending breakdown for a month."""

def get_budget(user_sub: str) -> Dict[str, Any]:
    """Get user's budget settings."""

def set_budget(
    user_sub: str,
    *,
    budget_monthly_cents: int,
    alert_thresholds: List[int] | None = None,
) -> Dict[str, Any]:
    """Set monthly budget and alert thresholds. Admin-only."""

def check_spending_alerts(user_sub: str) -> List[str]:
    """Check if any threshold has been crossed and send alerts. Returns alerts sent."""

def deduct_from_wallet(user_sub: str, amount_cents: int) -> int:
    """Deduct amount from wallet. Returns new balance. Raises if insufficient."""
```

**Periodic billing tick implementation**:

```python
async def run_compute_billing_timer(*, poll_interval: int = 300):
    """Every 5 minutes, bill all running EC2 instances and K8s pods."""
    while True:
        try:
            now = now_ts()
            # Bill EC2 instances
            for instance in _get_all_running_ec2_instances():
                minutes = (now - instance["last_billed_at"]) / 60.0
                if minutes < 1:
                    continue
                try:
                    record_billing_event(
                        instance["user_sub"],
                        resource_type="ec2",
                        resource_id=instance["instance_id"],
                        resource_label=instance["label"],
                        instance_type_or_preset=instance["instance_type"],
                        event="periodic_tick",
                        duration_minutes=minutes,
                    )
                    _update_last_billed(instance)
                except InsufficientBalanceError:
                    # Auto-terminate on zero balance
                    terminate_instance(instance["user_sub"], instance["instance_id"])
                    write_alert(instance["user_sub"], event="compute.budget_exhausted",
                               outcome="terminated", title="Instance auto-terminated",
                               details={"resource_id": instance["instance_id"],
                                        "reason": "Insufficient wallet balance"})

            # Bill K8s pods (same pattern)
            for pod in _get_all_running_k8s_pods():
                # ... same logic ...
                pass

        except Exception:
            logger.exception("Compute billing timer error")
        await asyncio.sleep(poll_interval)
```

### 3.4 Wallet Deduction
<!-- NOTE: The code example below uses sk="BILLING" but the actual wallet row uses sk="WALLET" (see billing_shared.py:166). Consider using apply_wallet_delta() from billing_shared.py:178 instead of raw DDB update. -->

Uses the existing `billing` table's `WALLET` row with conditional update:

```python
def deduct_from_wallet(user_sub: str, amount_cents: int) -> int:
    try:
        resp = T.billing.update_item(
            Key={"pk": f"USER#{user_sub}", "sk": "BILLING"},
            UpdateExpression="ADD wallet_balance_cents :neg",
            ConditionExpression="wallet_balance_cents >= :amount",
            ExpressionAttributeValues={
                ":neg": Decimal(str(-amount_cents)),
                ":amount": Decimal(str(amount_cents)),
            },
            ReturnValues="ALL_NEW",
        )
        return int(resp["Attributes"]["wallet_balance_cents"])
    except T.billing.meta.client.exceptions.ConditionalCheckFailedException:
        raise InsufficientBalanceError(f"Wallet balance insufficient for {amount_cents}c deduction")
```

### 3.5 Spending Alerts

When a billing event pushes the monthly total past a threshold percentage of the budget:

```python
def check_spending_alerts(user_sub: str) -> List[str]:
    budget = get_budget(user_sub)
    month_key = _current_month_key()
    summary = get_monthly_summary(user_sub, month=month_key)
    total = summary["total_cents"]
    budget_cents = budget["budget_monthly_cents"]
    thresholds = budget.get("alert_thresholds", DEFAULT_ALERT_THRESHOLDS)
    already_sent = budget.get("alerts_sent", set())

    alerts_to_send = []
    for pct in thresholds:
        threshold_cents = budget_cents * pct / 100
        if total >= threshold_cents and pct not in already_sent:
            write_alert(
                user_sub,
                event="compute.spending_threshold",
                outcome="warning",
                title=f"Compute spending at {pct}% of monthly budget",
                details={"total_cents": total, "budget_cents": budget_cents, "threshold_pct": pct},
            )
            alerts_to_send.append(pct)

    if alerts_to_send:
        # Record which thresholds were sent
        _update_alerts_sent(user_sub, month_key, alerts_to_send)

    return alerts_to_send
```

### 3.6 API Router: `app/routers/compute_billing.py`

New file (~150 lines). Prefix: `/ui/remote/billing`.

| Method | Path | Request | Response | Description |
|--------|------|---------|----------|-------------|
| `GET` | `/ui/remote/billing/summary` | `?month=YYYY-MM` | `SpendingSummaryOut` | Monthly spending summary |
| `GET` | `/ui/remote/billing/ledger` | query params | `BillingLedgerOut` | Spending ledger entries |
| `GET` | `/ui/remote/billing/breakdown` | `?month=YYYY-MM` | `ResourceBreakdownOut` | Per-resource breakdown |
| `GET` | `/ui/remote/billing/budget` | — | `BudgetOut` | Get budget settings |
| `PATCH` | `/ui/remote/billing/budget` | `UpdateBudgetIn` | `BudgetOut` | Update budget (admin) |

### 3.7 API Request/Response Examples

**GET /ui/remote/billing/summary?month=2026-05**

```json
{
  "month": "2026-05",
  "total_cents": 2345,
  "budget_cents": 5000,
  "budget_pct": 46.9,
  "ec2_total_cents": 1800,
  "k8s_total_cents": 545,
  "resource_count": 3
}
```

**GET /ui/remote/billing/ledger?limit=3&resource_id=i-abc123**

```json
{
  "entries": [
    {
      "entry_id": "e_9f3a2b1c",
      "resource_type": "ec2",
      "resource_id": "i-abc123",
      "resource_label": "Dev Workspace",
      "instance_type_or_preset": "t3.small",
      "event": "periodic_tick",
      "amount_cents": 2,
      "duration_minutes": 5.0,
      "rate_cents_per_min": 0.4,
      "wallet_balance_after": 7655,
      "created_at": 1748520600
    },
    {
      "entry_id": "e_1d4e5f6a",
      "resource_type": "ec2",
      "resource_id": "i-abc123",
      "resource_label": "Dev Workspace",
      "instance_type_or_preset": "t3.small",
      "event": "periodic_tick",
      "amount_cents": 2,
      "duration_minutes": 5.0,
      "rate_cents_per_min": 0.4,
      "wallet_balance_after": 7657,
      "created_at": 1748520300
    },
    {
      "entry_id": "e_aa00bb11",
      "resource_type": "ec2",
      "resource_id": "i-abc123",
      "resource_label": "Dev Workspace",
      "instance_type_or_preset": "t3.small",
      "event": "instance_start",
      "amount_cents": 0,
      "duration_minutes": 0,
      "rate_cents_per_min": 0.4,
      "wallet_balance_after": 7659,
      "created_at": 1748520000
    }
  ],
  "count": 3,
  "cursor": "eyJzayI6IkxFREdFUiMxNzQ4NTIwMDAwI2VfYWEwMGJiMTEifQ=="
}
```

**GET /ui/remote/billing/breakdown?month=2026-05**

```json
{
  "resources": [
    {
      "resource_id": "i-abc123",
      "resource_label": "Dev Workspace",
      "resource_type": "ec2",
      "instance_type_or_preset": "t3.small",
      "total_cents": 1800,
      "total_minutes": 4500.0,
      "status": "running"
    },
    {
      "resource_id": "pod-def456",
      "resource_label": "ML Experiment",
      "resource_type": "k8s",
      "instance_type_or_preset": "large",
      "total_cents": 545,
      "total_minutes": 908.3,
      "status": "terminated"
    }
  ],
  "month": "2026-05"
}
```

**GET /ui/remote/billing/budget**

```json
{
  "budget_monthly_cents": 5000,
  "alert_thresholds": [50, 80, 100],
  "current_month_total_cents": 2345,
  "current_month_pct": 46.9
}
```

**PATCH /ui/remote/billing/budget**

Request:
```json
{
  "budget_monthly_cents": 10000,
  "alert_thresholds": [25, 50, 75, 100]
}
```

Response:
```json
{
  "budget_monthly_cents": 10000,
  "alert_thresholds": [25, 50, 75, 100],
  "current_month_total_cents": 2345,
  "current_month_pct": 23.45
}
```

### 3.8 Pydantic Models

```python
class SpendingSummaryOut(BaseModel):
    month: str
    total_cents: int
    budget_cents: int
    budget_pct: float
    ec2_total_cents: int
    k8s_total_cents: int
    resource_count: int

class BillingLedgerEntry(BaseModel):
    entry_id: str
    resource_type: str
    resource_id: str
    resource_label: str
    instance_type_or_preset: str
    event: str
    amount_cents: int
    duration_minutes: float
    rate_cents_per_min: float
    wallet_balance_after: int
    created_at: int

class BillingLedgerOut(BaseModel):
    entries: List[BillingLedgerEntry]
    count: int
    cursor: Optional[str] = None

class ResourceBreakdownEntry(BaseModel):
    resource_id: str
    resource_label: str
    resource_type: str
    instance_type_or_preset: str
    total_cents: int
    total_minutes: float
    status: str

class ResourceBreakdownOut(BaseModel):
    resources: List[ResourceBreakdownEntry]
    month: str

class BudgetOut(BaseModel):
    budget_monthly_cents: int
    alert_thresholds: List[int]
    current_month_total_cents: int
    current_month_pct: float

class UpdateBudgetIn(BaseModel):
    budget_monthly_cents: int = Field(..., ge=100, le=1_000_000)
    alert_thresholds: Optional[List[int]] = None
```

### 3.9 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|---|---|---|---|---|
| Wallet balance insufficient for charge | 402 | `insufficient_balance` | "Wallet balance insufficient for {amount}c deduction" | Auto-terminate resource; user adds funds |
| Budget not found for user | 200 | N/A | Returns defaults (5000 cents, [50,80,100]) | Budget is auto-created with defaults |
| Invalid month format in query | 400 | `invalid_month_format` | "Month must be in YYYY-MM format" | Client corrects format |
| Resource ID not found in ledger | 200 | N/A | Returns empty entries list | Normal — no billing events yet |
| Budget amount below minimum (100c) | 422 | `validation_error` | "budget_monthly_cents must be >= 100" | Client adjusts value |
| Budget amount above maximum (1Mc) | 422 | `validation_error` | "budget_monthly_cents must be <= 1000000" | Client adjusts value |
| Non-admin tries to set budget | 403 | `forbidden` | "Admin role required" | Use admin session |
| Timer fails to bill an instance | N/A | Internal | Logged; retried next cycle | Automatic retry on next 5-min tick |
| Duplicate billing entry (timer restart) | N/A | N/A | Skipped (minutes < 1) | Idempotent via last_billed_at check |
| Rate card lookup fails (unknown type) | 500 | `unknown_resource_type` | "No rate card for {type}" | Admin adds rate card config |

### 3.10 Frontend Components

#### ComputeBillingPage (`frontend/src/pages/remote/ComputeBillingPage.tsx`)

New page (~400 lines):

- **Spending header card**: Current month total in dollars, budget meter (progress bar with threshold markers at 50%/80%/100%), "of $50.00 budget" text
- **Resource breakdown table**: DataTable with resource name, type badge (EC2/K8s), instance type, total cost, total hours, status
- **Daily spending chart**: Bar chart showing daily compute costs for the current month (using recharts or similar)
- **Ledger tab**: Scrollable ledger entries with timestamp, resource, event type, amount, balance-after
- **Month selector**: Navigate to previous months

#### Frontend Component Tree

```
ComputeBillingPage
├── SpendingHeader
│   ├── MonthSelector (props: { month: string, onChange: (m: string) => void })
│   ├── BudgetMeter (props: { totalCents: number, budgetCents: number, thresholds: number[] })
│   └── SpendingSummaryCards (props: { ec2Total: number, k8sTotal: number, resourceCount: number })
├── Tabs
│   ├── TabPanel: "Breakdown"
│   │   └── ResourceBreakdownTable (props: { resources: ResourceBreakdownEntry[], month: string })
│   │       └── DataTable (shadcn)
│   │           └── ResourceRow
│   │               ├── Badge (EC2 | K8s)
│   │               └── StatusBadge (running | stopped | terminated)
│   ├── TabPanel: "Ledger"
│   │   └── BillingLedger (props: { entries: BillingLedgerEntry[], cursor?: string, onLoadMore: () => void })
│   │       └── InfiniteScroll
│   │           └── LedgerRow
│   │               ├── EventBadge (start | tick | stop)
│   │               └── AmountCell
│   └── TabPanel: "Budget"
│       └── BudgetSettings (props: { budget: BudgetOut, onSave: (b: UpdateBudgetIn) => void })
│           ├── Input (budget amount)
│           ├── ThresholdEditor (props: { thresholds: number[] })
│           └── Button ("Save Budget")
└── DailySpendingChart (props: { data: { day: string, cents: number }[] })
```

#### TypeScript Props Interfaces

```typescript
interface BudgetMeterProps {
  totalCents: number;
  budgetCents: number;
  thresholds: number[];
}

interface ResourceBreakdownTableProps {
  resources: ResourceBreakdownEntry[];
  month: string;
}

interface BillingLedgerProps {
  entries: BillingLedgerEntry[];
  cursor?: string;
  onLoadMore: () => void;
  isLoading: boolean;
}

interface BudgetSettingsProps {
  budget: BudgetOut;
  onSave: (data: UpdateBudgetIn) => Promise<void>;
  isAdmin: boolean;
}

interface DailySpendingChartProps {
  data: Array<{ day: string; cents: number }>;
}
```

#### Route & Navigation

```tsx
<Route path="/remote/billing" element={<ComputeBillingPage />} />
```

Sidebar: "Compute Billing" with `Receipt` icon under Infrastructure group.

---

## 4. Implementation Plan

### Phase 1: Backend Billing Service (3 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `compute_billing_table_name`, `compute_billing_enabled`, `compute_billing_poll_interval` |
| `app/core/tables.py` | Add `compute_billing` table handle |
| `scripts/local-ddb-init.py` | Add `compute_billing` TableDef with 2 GSIs |
| `app/services/compute_billing.py` | New file: billing events, wallet deduction, budgets, alerts |
| `app/models.py` | Add billing Pydantic models |

### Phase 2: API + Background Timer (1-2 days)

| File | Change |
|------|--------|
| `app/routers/compute_billing.py` | New file: 5 endpoints |
| `app/main.py` | Register router + billing timer background task |
| `app/services/ec2_launcher.py` | Integrate billing events on launch/stop/terminate |
| `app/services/k8s_launcher.py` | Integrate billing events on launch/terminate |

### Phase 3: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add billing types |
| `frontend/src/api/endpoints/compute-billing.ts` | New file: API wrappers |
| `frontend/src/pages/remote/ComputeBillingPage.tsx` | New file: spending dashboard |
| `frontend/src/App.tsx` | Add `/remote/billing` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Compute Billing" nav item |

### Phase 4: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/compute-billing.spec.ts` | New file: ~30 tests in 6 sections |

---

## 5. E2E Test Plan (`frontend/e2e/compute-billing.spec.ts`)

**Section 257: Billing Event API (5 tests)**

1. `Launch EC2 creates instance_start ledger entry` — Launch instance, GET `/ledger`. Verify entry with `event: "instance_start"`, `amount_cents: 0` (start event is free — billing begins on first tick).
2. `Stop EC2 creates instance_stop entry with pro-rated charge` — Launch, wait, stop. Verify `instance_stop` entry with `amount_cents > 0`.
3. `Launch K8s creates start entry` — Launch pod, GET `/ledger`. Verify K8s start entry.
4. `Wallet balance decreases after billing tick` — Seed wallet with 1000 cents. Launch `t3.micro` (0.2c/min). Manually trigger billing (POST to internal endpoint or wait for tick). Verify wallet decreased.
5. `Zero-balance auto-terminates instance` — Seed wallet with 1 cent. Launch instance. Trigger billing tick. Verify instance status is `terminated` and alert created.

**Section 258: Budget & Alerts API (5 tests)**

6. `Get budget returns defaults` — GET `/budget`. Verify `budget_monthly_cents: 5000`, `alert_thresholds: [50, 80, 100]`.
7. `Admin sets budget` — PATCH `/budget` with `budget_monthly_cents: 10000`. Verify updated.
8. `Spending threshold sends alert` — Seed wallet with 10000 cents, set budget to 100 cents. Launch + force billing to 51 cents. Verify alert created for 50% threshold.
9. `Alert not re-sent for same threshold` — Cross 50% again. Verify no duplicate alert.
10. `100% threshold auto-terminates` — Exceed budget completely. Verify resources terminated.

**Section 259: Spending Summary & Breakdown API (4 tests)**

11. `Monthly summary aggregates all billing` — Create multiple billing entries. GET `/summary`. Verify `total_cents` matches sum, `ec2_total_cents` and `k8s_total_cents` separated.
12. `Resource breakdown lists per-resource totals` — Launch 2 different instance types. GET `/breakdown`. Verify 2 entries with correct totals.
13. `Ledger pagination works` — Create 5 entries. GET with `?limit=2`. Verify cursor, request next page.
14. `Filter ledger by resource_id` — GET `/ledger?resource_id=xxx`. Verify only entries for that resource.

**Section 260: Compute Billing UI (4 tests)**

15. `ComputeBillingPage renders spending summary` — Navigate to `/remote/billing`. Verify budget meter, total amount, resource breakdown table visible.
16. `Budget meter shows correct percentage` — Seed billing data. Verify meter percentage matches `total / budget`.
17. `Resource breakdown table shows active resources` — Verify table rows with resource names and cost totals.
18. `Ledger tab shows billing entries` — Click "Ledger" tab. Verify entries with timestamps, amounts, event types.

**Section 261: Negative and Edge Cases (6 tests)**

19. `Budget below minimum (100 cents) returns 422` — PATCH `/budget` with `budget_monthly_cents: 50`. Expect 422 validation error.
20. `Budget above maximum (1M cents) returns 422` — PATCH `/budget` with `budget_monthly_cents: 2000000`. Expect 422.
21. `Non-admin cannot set budget for another user` — Alice tries PATCH as USER role. Expect 403.
22. `Invalid month format returns 400` — GET `/summary?month=May-2026`. Expect 400.
23. `Ledger for user with no billing history returns empty` — GET `/ledger` for new user. Verify `entries: [], count: 0`.
24. `Simultaneous billing ticks do not double-charge` — Trigger billing tick twice quickly. Verify only one charge for the period (idempotent via last_billed_at).

**Section 262: Admin Spending Overview (6 tests)**

25. `Admin can view platform-wide spending totals` — GET `/ui/remote/billing/admin/summary` as root. Verify aggregated totals across all users.
26. `Admin can view per-user spending breakdown` — GET `/ui/remote/billing/admin/users?month=2026-05`. Verify list of users with their totals.
27. `Admin can view a specific user's ledger` — GET `/ui/remote/billing/admin/users/{sub}/ledger`. Verify entries for that user.
28. `Regular user cannot access admin endpoints` — Alice GET `/ui/remote/billing/admin/summary`. Expect 403.
29. `Admin summary includes resource type breakdown` — Verify ec2_total_cents and k8s_total_cents at platform level.
30. `Admin can export billing report as CSV` — GET `/ui/remote/billing/admin/export?month=2026-05&format=csv`. Verify CSV content-type and structure.

**Test Setup**:

```typescript
test.beforeAll(async ({ browser }) => {
  sessions["alice"] = await getOrCreateSession("alice");
  sessions["root"] = await getOrCreateAdminSession("root");
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");

  // Seed wallet balance for billing tests
  await seedWalletBalance("alice", 10000);  // $100.00
});
```

---

## 6. Observability

### 6.1 Metrics

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `compute_billing_tick_total` | Counter | `resource_type`, `event` | Total billing tick events processed |
| `compute_billing_tick_duration_seconds` | Histogram | — | Time to process one billing timer cycle |
| `compute_billing_deduction_cents` | Counter | `resource_type` | Total cents deducted from wallets |
| `compute_billing_auto_terminate_total` | Counter | `resource_type` | Resources auto-terminated for zero balance |
| `compute_billing_alert_total` | Counter | `threshold_pct` | Spending alerts sent |
| `compute_billing_wallet_error_total` | Counter | `error_type` | Wallet deduction failures |

### 6.2 Logging

All billing events produce structured JSON log entries:

```json
{
  "logger": "compute_billing",
  "level": "INFO",
  "event": "billing_tick",
  "user_sub": "alice_sub",
  "resource_id": "i-abc123",
  "resource_type": "ec2",
  "amount_cents": 2,
  "duration_minutes": 5.0,
  "wallet_balance_after": 7655,
  "timestamp": 1748520600
}
```

Critical events (auto-terminate, budget exhausted) log at WARNING level.

### 6.3 Alerting Rules

| Alert | Condition | Severity | Action |
|---|---|---|---|
| Billing timer stalled | No billing ticks for > 15 minutes | Critical | Restart backend; investigate |
| High wallet error rate | > 10 wallet errors in 5 minutes | Warning | Check DDB throttling |
| Mass auto-termination | > 5 auto-terminates in 1 minute | Warning | Possible billing bug; investigate |

---

## 7. Performance Considerations

### 7.1 Latency Targets

| Operation | Target | Notes |
|---|---|---|
| GET /summary | < 200ms | Single DDB query on MONTH# item |
| GET /ledger | < 300ms | Paginated query, limit 100 |
| GET /breakdown | < 500ms | Aggregation query, may scan multiple items |
| Billing timer cycle | < 30s | Must complete before next 5-min interval |
| Wallet deduction | < 50ms | Single conditional update |

### 7.2 Caching Strategy

- **Monthly summary**: Cached in the `MONTH#{YYYY-MM}` item; updated atomically on each billing event via `ADD current_month_total_cents :amount`. No need to re-aggregate.
- **Budget settings**: Cached in memory per-user for the duration of a billing timer cycle (5 min TTL). Budget changes are infrequent.
- **Rate cards**: Static in-memory map. No DDB lookup needed.

### 7.3 Pagination

- Ledger entries use DDB `LastEvaluatedKey` cursor encoding via `app/core/cursor.py`.
- Default page size: 100 entries, max: 500.
- Resource breakdown is not paginated (max ~50 resources per user in practice).

### 7.4 Billing Timer Scalability

- Timer runs in the single backend process (dev mode single-worker constraint).
- For production, the timer should use a distributed lock (DDB conditional write) to prevent multiple workers from billing the same resources.
- Each cycle processes all running resources sequentially. With 1000 running resources at 50ms per deduction, a cycle takes ~50 seconds — within the 5-minute interval.

---

## 8. Rollout Plan

### Phase 1: Shadow Mode (Feature Flag: `compute_billing_enabled=false`)

- Deploy billing service and timer
- Timer runs and logs billing events but does NOT deduct from wallets
- Validates rate calculations against expected values
- Duration: 1 week

### Phase 2: Opt-In Beta (Feature Flag: `compute_billing_beta_users`)

- Enable billing deductions for a list of beta user_subs
- Monitor for billing accuracy, wallet deduction correctness
- Frontend displays billing page with "Beta" badge
- Duration: 1 week

### Phase 3: General Availability

- Enable `compute_billing_enabled=true` for all users
- All new instance launches include billing from the start
- Budget defaults apply to all users
- Admin override budget endpoint available

### Feature Flags

| Flag | Default | Description |
|---|---|---|
| `COMPUTE_BILLING_ENABLED` | `false` | Master toggle for compute billing |
| `COMPUTE_BILLING_POLL_INTERVAL` | `300` | Timer interval in seconds |
| `COMPUTE_BILLING_BETA_USERS` | `""` | Comma-separated user_subs for beta |
| `COMPUTE_BILLING_AUTO_TERMINATE` | `true` | Auto-terminate on zero balance |
| `COMPUTE_BILLING_DEFAULT_BUDGET` | `5000` | Default monthly budget in cents |

---

## 9. Security Considerations

### 9.1 Budget Modification

Only admins (via `require_admin_session`) can modify another user's budget. Users can view their own budget and spending but cannot change the limit.

### 9.2 Wallet Deduction Atomicity

The conditional update `wallet_balance_cents >= :amount` prevents overdraft. If the check fails, the resource is auto-terminated rather than allowing negative balance.

### 9.3 Billing Timer Idempotency

Each billing tick records `last_billed_at` on the resource. If the timer runs twice for the same period (e.g., during a restart), the second run sees `minutes < 1` and skips. Entry IDs are UUIDs, preventing duplicate entries.

### 9.4 Rate Card Integrity

Rate cards are defined in code (not user-configurable). Users cannot manipulate the rate used for billing. Any rate card change requires a code deployment.

### 9.5 Audit Trail

Every wallet deduction produces a LEDGER entry with amount, rate, duration, and balance-after. This creates a complete, immutable audit trail for all compute charges.

---

## 10. Acceptance Criteria

1. EC2 and K8s resources generate billing ledger entries (start, periodic tick, stop).
2. Per-minute charges are calculated from rate cards and deducted from wallet.
3. Resources are auto-terminated when wallet balance reaches zero.
4. Spending alerts fire at configurable thresholds (50%, 80%, 100%).
5. Monthly spending summary shows totals by resource type.
6. Per-resource breakdown shows individual resource costs.
7. Budget limits are admin-configurable per user.
8. Frontend displays spending dashboard with budget meter, breakdown, and ledger.
9. Billing timer runs as a background task with configurable interval.
10. All deductions are atomic with conditional checks to prevent overdraft.
11. Admin spending overview provides platform-wide totals and per-user breakdown.
12. Ledger pagination supports cursor-based navigation for large histories.

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| `call_heartbeat()` | `app/routers/call_billing.py` | 148-149 | Proven per-minute billing pattern; reusable for compute |
| `HeartbeatIn/Out` | `app/routers/call_billing.py` | 43, 47 | Per-tick billing model |
| `CallBillingStatusOut` | `app/routers/call_billing.py` | 60 | Accumulated cost model |
| `billing` DDB table | `scripts/local-ddb-init.py` | 59 | PK=pk, SK=sk; no GSIs |
| `T.billing` table handle | `app/core/tables.py` | 146 | `ddb.Table(S.billing_table_name)` |
| `apply_wallet_delta()` | `app/services/billing_shared.py` | 178 | Atomic wallet balance with overdraft protection |
| `WALLET_SK` constant | `app/services/billing_shared.py` | 166 | `"WALLET"` — NOT `"BILLING"` as ticket code example shows |
| `write_alert()` | `app/services/alerts.py` | 355 | In-app alert creation for spending thresholds |
| `audit_event()` | `app/services/alerts.py` | 695 | Audit logging |
| `compute_billing` DDB table | — | — | Does not exist yet in `scripts/local-ddb-init.py` |
| `app/services/compute_billing.py` | — | — | Does not exist yet |
| EC2 launcher (INFRA-003 dep) | — | — | Does not exist yet; provides `INSTANCE_TYPES` rate card |
| K8s launcher (INFRA-004 dep) | — | — | Does not exist yet; provides `RESOURCE_PRESETS` rate card |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_compute_costs.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_record_cost_event_ec2`
  - `test_record_cost_event_k8s`
  - `test_get_user_cost_summary`
  - `test_get_cost_breakdown_by_instance_type`
  - `test_daily_cost_rollup`
  - `test_cost_alert_threshold_exceeded`

### Integration Tests

  - EC2 instance start/stop events trigger cost records
  - K8s container lifecycle events trigger cost records
  - User cost summary aggregates across all compute resources

### E2E Tests (Playwright)

**File**: `frontend/e2e/compute-costs.spec.ts`
**Test count**: 12

**Auth pattern**: Use `injectAuth(page, "root")` for admin endpoints; use `injectAuth(page, "alice")` for user-level endpoints. All POST/PATCH/DELETE requests include `x-csrf-token` header matching the session's CSRF token.

**Negative tests**:
- 401: Unauthenticated request returns 401
- 403: Non-admin/non-owner access returns 403
- 404: Non-existent resource returns 404
- 409: Conflict on duplicate or already-processed resource
- 422: Invalid input (bad field values, missing required fields)

**Edge cases**:
- Empty result sets return 200 with empty arrays (not 404)
- Pagination cursor works correctly across pages
- Concurrent requests do not produce inconsistent state

### Test Data Requirements

- **DDB seeds**: Seed `compute_costs` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `COMPUTE_COST_TRACKING_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| INFRA-003 | EC2 Instance Launcher | Tracks EC2 instance runtime |
| INFRA-004 | K8s Container Launcher | Tracks container runtime |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| INFRA-012 | Admin Compute Dashboard | Aggregates cost data for admin view |

### Merge Strategy

**Sequential**

Merge after INFRA-003, INFRA-004. This ticket depends on tables/services introduced by those tickets.

### Merge Checklist

- [ ] All new DDB tables added to `scripts/local-ddb-init.py` with correct `attr_types` for numeric GSI keys
- [ ] New settings added to `app/core/settings.py` and `.env.local.example`
- [ ] New table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Pydantic models added to `app/models.py`
- [ ] TypeScript types added to `frontend/src/api/types.ts`
- [ ] Route added to `frontend/src/App.tsx`
- [ ] Feature flag defaults to `true` in `.env.local.example`
- [ ] E2E session setup updated if new test identities needed
- [ ] `just restart` completes cleanly with new tables
- [ ] All 12 E2E tests pass with `npx playwright test compute-costs.spec.ts`
