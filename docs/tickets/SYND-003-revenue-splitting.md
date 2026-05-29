# SYND-003: Revenue Splitting Engine

**Ticket**: SYND-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-14 days

---

## 1. Overview & Motivation

### 1.1 Purpose

SYND-003 implements the revenue splitting engine for syndicate bundled subscriptions. When a subscriber pays for a syndicate bundle, the revenue must be distributed among syndicate members according to configurable split rules. The admin configures the split model (equal, weighted, or performance-based), and after each payment the engine calculates each member's share and writes billing ledger entries for a complete audit trail.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Admin | As an admin, I want to configure an equal split so that all members get the same share. | POST split config with `mode=equal`; each member receives `total / member_count`. |
| Admin | As an admin, I want to configure weighted splits with percentages per member. | POST split config with `mode=weighted` and per-member percentages totaling 100%. |
| Admin | As an admin, I want to configure performance-based splits based on content engagement. | POST split config with `mode=performance`; splits proportional to each member's view/engagement metrics. |
| Admin | As an admin, I want to update split rules at any time, applying to future payments only. | PUT updates split config; historical splits unchanged; next payment uses new rules. |
| Member | As a member, I want to see my share of each bundle payment. | GET split history shows each payment with member's share amount and percentage. |
| Member | As a member, I want to see my total earnings from syndicate bundles. | GET earnings summary shows total earned from bundles, broken down by period. |
| System | After each bundle payment, revenue is automatically split and ledger entries written. | Background split processor runs after payment webhook; writes credit entries per member. |
| Admin | As an admin, I want to see the full split breakdown for each payment. | GET split detail shows payment amount, platform fee, net distributable, per-member amounts. |

### 1.3 Why This Is Needed

Without automated revenue splitting, syndicate admins would need to manually calculate and transfer each member's share after every payment -- an error-prone process that doesn't scale. The billing ledger already supports debit/credit entries (`app/services/billing_shared.py:new_ledger_entry`), so the split engine writes standard ledger credits that integrate with existing earnings dashboards and payout flows.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Billing shared | `app/services/billing_shared.py` (260 lines) | `new_ledger_entry` for creating audit-trail entries; `apply_wallet_delta` for crediting member wallets |
| Tip ledger | `app/services/tip_ledger.py` (149 lines) | Pattern for writing paired debit/credit entries; `_build_meta` for structured metadata |
| Creator earnings | `app/services/creator_earnings.py` | `_reason_to_category` maps reasons to categories; `get_earnings_summary` aggregates credits |
| Subscription server | `app/routers/subscription_server.py` | `record_billing_payment` writes invoice ledger entries; subscription lifecycle |
| Subscription cycle orders | `app/services/subscription_cycle_orders.py` | `emit_subscription_cycle_order` fires after payment; reconciliation gateway |
| Syndicate subscriptions | `app/services/syndicate_subscriptions.py` (SYND-002) | Bundle plan/subscription records; `plan_type=syndicate_bundle` |
| Syndicates service | `app/services/syndicates.py` (SYND-001) | `list_members`, `get_syndicate` for member roster |

### 2.2 Billing Ledger Entry Pattern

From `app/services/billing_shared.py:217-248`:

```python
def new_ledger_entry(
    table, pk: str, *,
    amount_cents: int,
    currency: str = "usd",
    entry_type: str,       # "debit" or "credit"
    reason: str,
    state: str = "settled",
    meta: Optional[Dict] = None,
) -> Dict[str, Any]:
    ts = now_ts()
    entry_id = ulidish()
    item = {
        "pk": pk,
        "sk": ledger_sk(ts, entry_id),
        "entry_id": entry_id,
        "ts": ts,
        "type": entry_type,
        "amount_cents": amount_cents,
        "currency": currency,
        "state": state,
        "reason": reason,
        "meta": meta or {},
    }
    table.put_item(Item=item)
    return item
```

The split engine will use this exact function to write per-member credit entries.

### 2.3 Gaps

1. **No split configuration model** -- there is no way to define how bundle revenue is divided among members.
2. **No split processor** -- after a bundle payment, no code distributes revenue to members.
3. **No split history** -- no record of individual split calculations or distributions.
4. **No performance-based metrics** -- content engagement data exists in various services but is not aggregated for split calculations.
5. **Subscription payment webhooks don't trigger splits** -- the existing `record_billing_payment` writes a single ledger entry for the plan owner, not per-member credits.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 Split Configuration (Syndicates Table)

**PK**: `SYND#{syndicate_id}`, **SK**: `SPLIT_CONFIG`

| Field | Type | Description |
|-------|------|-------------|
| `mode` | S | `"equal"`, `"weighted"`, or `"performance"` |
| `platform_fee_pct` | N | Platform fee percentage (e.g., 15 for 15%) |
| `weights` | M | Map of `{user_id: weight_pct}` when mode=weighted (must sum to 100) |
| `performance_metric` | S | When mode=performance: `"views"`, `"engagement"`, or `"subscribers"` |
| `performance_window_days` | N | When mode=performance: lookback window for metrics (default 30) |
| `updated_at` | N | Last configuration change timestamp |
| `updated_by` | S | User who last updated the config |

#### 3.1.2 Split Execution Record (Syndicates Table)

**PK**: `SYND#{syndicate_id}`, **SK**: `SPLIT#{timestamp}#{split_id}`

| Field | Type | Description |
|-------|------|-------------|
| `split_id` | S | `split_<uuid4_hex>` |
| `subscription_id` | S | Which subscription payment triggered this split |
| `invoice_id` | S | Invoice reference |
| `gross_amount_cents` | N | Total payment amount |
| `platform_fee_cents` | N | Platform fee deducted |
| `net_amount_cents` | N | Amount distributed to members |
| `mode` | S | Split mode used at time of execution |
| `distributions` | L | List of `{user_id, amount_cents, percentage, ledger_entry_id}` |
| `created_at` | N | Execution timestamp |

#### 3.1.3 Example Split Execution Item

```json
{
  "pk": "SYND#synd_abc123",
  "sk": "SPLIT#1748520000#split_def456",
  "split_id": "split_def456",
  "subscription_id": "sub_xyz789",
  "invoice_id": "inv_001",
  "gross_amount_cents": 2000,
  "platform_fee_cents": 300,
  "net_amount_cents": 1700,
  "mode": "weighted",
  "distributions": [
    {
      "user_id": "alice@test.local",
      "amount_cents": 1020,
      "percentage": 60,
      "ledger_entry_id": "le_aaa"
    },
    {
      "user_id": "bob@test.local",
      "amount_cents": 680,
      "percentage": 40,
      "ledger_entry_id": "le_bbb"
    }
  ],
  "created_at": 1748520000
}
```

### 3.2 Split Calculation Algorithms

#### 3.2.1 Equal Split

```
net_amount = gross - platform_fee
per_member = floor(net_amount / member_count)
remainder = net_amount - (per_member * member_count)
# Remainder goes to admin (or first member alphabetically)
```

#### 3.2.2 Weighted Split

```
net_amount = gross - platform_fee
for each member:
    share = floor(net_amount * member_weight_pct / 100)
# Rounding remainder distributed to highest-weighted member
# Weights MUST sum to exactly 100
```

#### 3.2.3 Performance-Based Split

```
net_amount = gross - platform_fee
metrics = get_member_metrics(syndicate_id, window_days)
total_score = sum(metrics.values())
for each member:
    if total_score == 0:
        share = floor(net_amount / member_count)  # fallback to equal
    else:
        share = floor(net_amount * member_score / total_score)
```

### 3.3 Backend Service

**New file**: `app/services/syndicate_revenue_split.py` (~350 lines)

```python
"""Syndicate revenue splitting engine (SYND-003)."""

from __future__ import annotations
import logging
from math import floor
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates as syndicate_svc
from app.services.billing_shared import new_ledger_entry, apply_wallet_delta

logger = logging.getLogger(__name__)

DEFAULT_PLATFORM_FEE_PCT = 15


def set_split_config(
    *,
    syndicate_id: str,
    admin_sub: str,
    mode: str,
    weights: Optional[Dict[str, float]] = None,
    performance_metric: Optional[str] = None,
    performance_window_days: int = 30,
    platform_fee_pct: int = DEFAULT_PLATFORM_FEE_PCT,
) -> Dict[str, Any]:
    """Set or update the split configuration for a syndicate."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)

    if mode == "weighted":
        if not weights:
            raise ValueError("Weights required for weighted split mode")
        total = sum(weights.values())
        if abs(total - 100) > 0.01:
            raise ValueError(f"Weights must sum to 100, got {total}")
        # Validate all user_ids are current members
        members = {m["user_id"] for m in syndicate_svc.list_members(syndicate_id)}
        for uid in weights:
            if uid not in members:
                raise ValueError(f"{uid} is not a syndicate member")

    if mode == "performance":
        valid_metrics = ("views", "engagement", "subscribers")
        if performance_metric not in valid_metrics:
            raise ValueError(f"Invalid metric: {performance_metric}")

    ts = now_ts()
    config = {
        "pk": f"SYND#{syndicate_id}",
        "sk": "SPLIT_CONFIG",
        "mode": mode,
        "platform_fee_pct": platform_fee_pct,
        "weights": weights or {},
        "performance_metric": performance_metric or "",
        "performance_window_days": performance_window_days,
        "updated_at": ts,
        "updated_by": admin_sub,
    }
    T.syndicates.put_item(Item=config)
    syndicate_svc._write_audit(syndicate_id, admin_sub, "split_config_updated", "", {"mode": mode})
    return config


def get_split_config(syndicate_id: str) -> Dict[str, Any]:
    """Get current split configuration. Returns default (equal) if none set."""
    resp = T.syndicates.get_item(Key={
        "pk": f"SYND#{syndicate_id}",
        "sk": "SPLIT_CONFIG",
    })
    item = resp.get("Item")
    if not item:
        return {
            "mode": "equal",
            "platform_fee_pct": DEFAULT_PLATFORM_FEE_PCT,
            "weights": {},
            "performance_metric": "",
            "performance_window_days": 30,
        }
    return item


def execute_split(
    *,
    syndicate_id: str,
    subscription_id: str,
    invoice_id: str,
    gross_amount_cents: int,
) -> Dict[str, Any]:
    """Execute revenue split for a bundle payment. Called after payment."""
    config = get_split_config(syndicate_id)
    members = syndicate_svc.list_members(syndicate_id)
    member_ids = [m["user_id"] for m in members]

    if not member_ids:
        logger.warning("No members in syndicate %s, skipping split", syndicate_id)
        return {"skipped": True}

    # Calculate platform fee
    platform_fee_pct = int(config.get("platform_fee_pct", DEFAULT_PLATFORM_FEE_PCT))
    platform_fee_cents = floor(gross_amount_cents * platform_fee_pct / 100)
    net_amount_cents = gross_amount_cents - platform_fee_cents

    # Calculate per-member distribution
    mode = config.get("mode", "equal")
    if mode == "weighted":
        distributions = _calculate_weighted(net_amount_cents, member_ids, config.get("weights", {}))
    elif mode == "performance":
        distributions = _calculate_performance(
            net_amount_cents, member_ids, syndicate_id,
            config.get("performance_metric", "views"),
            int(config.get("performance_window_days", 30)),
        )
    else:
        distributions = _calculate_equal(net_amount_cents, member_ids)

    # Write ledger entries for each member
    ts = now_ts()
    split_id = f"split_{uuid4().hex}"
    for dist in distributions:
        entry = new_ledger_entry(
            T.billing,
            f"USER#{dist['user_id']}",
            amount_cents=dist["amount_cents"],
            entry_type="credit",
            reason="Syndicate bundle revenue share",
            meta={
                "syndicate_id": syndicate_id,
                "subscription_id": subscription_id,
                "invoice_id": invoice_id,
                "split_id": split_id,
                "split_mode": mode,
                "percentage": dist["percentage"],
            },
        )
        dist["ledger_entry_id"] = entry["entry_id"]

        # Credit member wallet
        apply_wallet_delta(T.billing, f"USER#{dist['user_id']}", dist["amount_cents"])

    # Write split execution record
    split_record = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"SPLIT#{ts}#{split_id}",
        "split_id": split_id,
        "subscription_id": subscription_id,
        "invoice_id": invoice_id,
        "gross_amount_cents": gross_amount_cents,
        "platform_fee_cents": platform_fee_cents,
        "net_amount_cents": net_amount_cents,
        "mode": mode,
        "distributions": distributions,
        "created_at": ts,
    }
    T.syndicates.put_item(Item=split_record)
    return split_record


def get_split_history(
    syndicate_id: str,
    *,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Get split execution history for a syndicate."""
    # Query SYND#{syndicate_id} with sk begins_with "SPLIT#"
    # ScanIndexForward=False for newest first
    # Limit to `limit` items


def get_member_earnings(
    syndicate_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Get a member's total earnings from this syndicate's splits."""
    splits = get_split_history(syndicate_id, limit=1000)
    total = 0
    entries = []
    for split in splits:
        for dist in split.get("distributions", []):
            if dist["user_id"] == user_id:
                total += dist["amount_cents"]
                entries.append({
                    "split_id": split["split_id"],
                    "amount_cents": dist["amount_cents"],
                    "percentage": dist["percentage"],
                    "created_at": split["created_at"],
                })
    return {"total_cents": total, "entries": entries}


# --- Internal calculation helpers ---

def _calculate_equal(net_amount_cents: int, member_ids: List[str]) -> List[Dict[str, Any]]:
    """Equal split among all members."""
    count = len(member_ids)
    per_member = floor(net_amount_cents / count)
    remainder = net_amount_cents - (per_member * count)
    distributions = []
    for i, uid in enumerate(sorted(member_ids)):
        amount = per_member + (1 if i < remainder else 0)
        distributions.append({
            "user_id": uid,
            "amount_cents": amount,
            "percentage": round(100 / count, 2),
        })
    return distributions


def _calculate_weighted(
    net_amount_cents: int,
    member_ids: List[str],
    weights: Dict[str, float],
) -> List[Dict[str, Any]]:
    """Weighted split according to configured percentages."""
    distributions = []
    allocated = 0
    sorted_members = sorted(member_ids, key=lambda uid: weights.get(uid, 0), reverse=True)
    for i, uid in enumerate(sorted_members):
        pct = weights.get(uid, 0)
        if i == len(sorted_members) - 1:
            amount = net_amount_cents - allocated  # Last member gets remainder
        else:
            amount = floor(net_amount_cents * pct / 100)
        allocated += amount
        distributions.append({
            "user_id": uid,
            "amount_cents": amount,
            "percentage": pct,
        })
    return distributions


def _calculate_performance(
    net_amount_cents: int,
    member_ids: List[str],
    syndicate_id: str,
    metric: str,
    window_days: int,
) -> List[Dict[str, Any]]:
    """Performance-based split using content engagement metrics."""
    scores = _get_performance_scores(member_ids, metric, window_days)
    total_score = sum(scores.values())

    if total_score == 0:
        return _calculate_equal(net_amount_cents, member_ids)

    distributions = []
    allocated = 0
    sorted_members = sorted(member_ids, key=lambda uid: scores.get(uid, 0), reverse=True)
    for i, uid in enumerate(sorted_members):
        score = scores.get(uid, 0)
        pct = round(score / total_score * 100, 2)
        if i == len(sorted_members) - 1:
            amount = net_amount_cents - allocated
        else:
            amount = floor(net_amount_cents * score / total_score)
        allocated += amount
        distributions.append({
            "user_id": uid,
            "amount_cents": amount,
            "percentage": pct,
        })
    return distributions


def _get_performance_scores(
    member_ids: List[str],
    metric: str,
    window_days: int,
) -> Dict[str, float]:
    """Get performance scores for each member based on the selected metric."""
    # For v1: stub implementation using post count as proxy
    # Future: integrate with analytics service for views/engagement
    scores = {}
    for uid in member_ids:
        # Query newsfeed posts by user within window
        # Count total engagement (views, reactions, comments)
        scores[uid] = 1.0  # Default equal score; real impl queries analytics
    return scores
```

### 3.4 Backend Router

**Extend**: `app/routers/syndicates.py` (from SYND-001)

### 3.5 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/syndicates/{syndicate_id}/split-config` | `require_ui_session` | Get current split configuration (members can view) |
| `POST` | `/ui/syndicates/{syndicate_id}/split-config` | `require_ui_session` | Set/update split configuration (admin only) |
| `GET` | `/ui/syndicates/{syndicate_id}/splits` | `require_ui_session` | Get split execution history (all members) |
| `GET` | `/ui/syndicates/{syndicate_id}/splits/{split_id}` | `require_ui_session` | Get single split detail with distributions |
| `GET` | `/ui/syndicates/{syndicate_id}/my-earnings` | `require_ui_session` | Get caller's earnings from this syndicate |
| `POST` | `/internal/syndicates/{syndicate_id}/execute-split` | Internal | Trigger split after payment (called by subscription webhook) |

### 3.6 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Syndicate Revenue Splitting (SYND-003) --

class SplitConfigIn(BaseModel):
    mode: str = Field(pattern="^(equal|weighted|performance)$")
    weights: Optional[Dict[str, float]] = None
    performance_metric: Optional[str] = None
    performance_window_days: int = Field(default=30, ge=7, le=365)
    platform_fee_pct: int = Field(default=15, ge=0, le=50)

class SplitConfigOut(BaseModel):
    mode: str
    platform_fee_pct: int = 15
    weights: Dict[str, float] = Field(default_factory=dict)
    performance_metric: str = ""
    performance_window_days: int = 30
    updated_at: int = 0
    updated_by: str = ""

class SplitDistributionOut(BaseModel):
    user_id: str
    display_name: str = ""
    amount_cents: int = 0
    percentage: float = 0
    ledger_entry_id: str = ""

class SplitExecutionOut(BaseModel):
    split_id: str
    subscription_id: str
    invoice_id: str = ""
    gross_amount_cents: int = 0
    platform_fee_cents: int = 0
    net_amount_cents: int = 0
    mode: str
    distributions: List[SplitDistributionOut] = Field(default_factory=list)
    created_at: int = 0

class MemberEarningsOut(BaseModel):
    total_cents: int = 0
    entries: List[Dict[str, Any]] = Field(default_factory=list)
```

### 3.7 Integration with Subscription Payment Flow

After a bundle subscription payment is recorded by `record_billing_payment` in `subscription_server.py`, the split must be triggered. Two approaches:

**Option A (synchronous)**: Add a call to `execute_split` inside `record_billing_payment` when the subscription has `plan_type=syndicate_bundle`. Simple but couples payment recording to split logic.

**Option B (async/webhook, recommended)**: The existing `emit_subscription_cycle_order` function fires after payment. Add a listener in the reconciliation gateway that detects `plan_type=syndicate_bundle` and calls `execute_split`. This keeps split logic decoupled.

For v1, use **Option A** with a direct call, documented as a candidate for decoupling in a future iteration.

### 3.8 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/syndicates/SplitConfigTab.tsx` | Split configuration UI for admin | ~200 |
| `frontend/src/pages/syndicates/SplitHistoryTab.tsx` | Split history timeline with distributions | ~180 |
| `frontend/src/pages/syndicates/MemberEarningsCard.tsx` | Member's earnings summary card | ~100 |

**Component tree for SplitConfigTab**:

```
SplitConfigTab (within SyndicateDetailPage)
├── Card: "Revenue Split Configuration"
│   ├── ModeSelector (RadioGroup)
│   │   ├── "Equal Split" — each member gets the same share
│   │   ├── "Weighted Split" — custom percentages per member
│   │   └── "Performance-Based" — proportional to engagement
│   ├── WeightEditor (when mode=weighted)
│   │   └── For each member:
│   │       ├── Display name + avatar
│   │       └── Percentage input (number, 0-100)
│   │       └── Total validation: must sum to 100%
│   ├── PerformanceConfig (when mode=performance)
│   │   ├── MetricSelector: "Views", "Engagement", "Subscribers"
│   │   └── WindowSelector: 7/14/30/90 days
│   ├── PlatformFeeDisplay: "Platform fee: 15%"
│   └── Button: "Save Configuration" (admin only)
└── Card: "Split Preview"
    └── Preview calculation for a hypothetical $20 payment
```

### 3.9 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/syndicate_revenue_split.py` | Revenue split engine | ~350 |
| `frontend/src/pages/syndicates/SplitConfigTab.tsx` | Split config UI | ~200 |
| `frontend/src/pages/syndicates/SplitHistoryTab.tsx` | Split history UI | ~180 |
| `frontend/src/pages/syndicates/MemberEarningsCard.tsx` | Earnings card | ~100 |
| `frontend/e2e/syndicates-revenue-split.spec.ts` | E2E tests | ~400 |

### 3.10 Files to Modify

| File | Change |
|------|--------|
| `app/routers/syndicates.py` | Add split config + history + earnings endpoints |
| `app/routers/subscription_server.py` | Call `execute_split` after bundle payment in `record_billing_payment` |
| `app/models.py` | Add SplitConfig*, SplitExecution*, MemberEarnings* models |
| `frontend/src/api/types.ts` | Add TypeScript interfaces for split config/history/earnings |
| `frontend/src/api/endpoints/syndicates.ts` | Add split API wrappers |
| `frontend/src/pages/syndicates/SyndicateDetailPage.tsx` | Add "Revenue" tab with SplitConfigTab + SplitHistoryTab |

---

## 4. Rounding and Remainder Handling

### 4.1 Problem

Integer cent math with percentage-based splits creates rounding remainders. For example, splitting $17.00 (1700 cents) equally among 3 members: `1700 / 3 = 566.666...` cents. Each member gets 566 cents = $16.98 total, leaving 2 cents unallocated.

### 4.2 Solution

1. Calculate `floor(net / count)` for each member.
2. Compute `remainder = net - (per_member * count)`.
3. Distribute remainder 1 cent at a time to members in deterministic order (alphabetical by user_id for equal; highest-weight-first for weighted).
4. Record actual distributed amounts in the split execution record.
5. Invariant: `sum(distributions.amount_cents) == net_amount_cents` -- always holds.

### 4.3 Weighted Split Edge Case

When a member with 0% weight exists (e.g., new member before weights are updated):
- They receive 0 cents.
- Admin is warned in the UI that weights need updating.
- Validation: if `mode=weighted` and any member is missing from the weights map, the split falls back to equal until weights are updated.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/syndicates-revenue-split.spec.ts`

### Section 431: Split Configuration API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 431.1 | Admin sets equal split config | POST; 200; `mode=equal` in GET response |
| 431.2 | Admin sets weighted split config | POST with weights `{alice: 60, bob: 40}`; 200; weights reflected in GET |
| 431.3 | Weights must sum to 100 | POST with weights summing to 90; 400; error message mentions "100" |
| 431.4 | Non-admin cannot set split config | Bob (member) POST; 403 |

### Section 432: Split Execution API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 432.1 | Equal split divides payment evenly | Execute split for 2000 cents, 2 members; each gets ~850 (after 15% fee) |
| 432.2 | Weighted split respects percentages | Execute with 60/40 weights; amounts proportional |
| 432.3 | Platform fee deducted correctly | Gross 2000, 15% fee; net = 1700; fee = 300 |
| 432.4 | Ledger credit entries written for each member | Query billing ledger for each member; credit entry with reason "Syndicate bundle revenue share" |
| 432.5 | Split record includes all distributions | GET split detail; `distributions` array has entry per member with amounts |

### Section 433: Split History & Earnings API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 433.1 | Split history lists past splits | GET splits; array ordered by newest first |
| 433.2 | Member can see own earnings | GET my-earnings; `total_cents` matches sum of member's shares |
| 433.3 | Updated config applies to new splits only | Change mode from equal to weighted; next split uses weighted; historical splits unchanged |
| 433.4 | Split history accessible to all members | Bob (member, not admin) GET splits; 200 |

### Section 434: Split Config UI (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 434.1 | Revenue tab visible on syndicate page | Navigate to syndicate detail; "Revenue" tab visible |
| 434.2 | Mode selector changes config form | Select "Weighted Split"; per-member percentage inputs appear |
| 434.3 | Split history shows payment breakdowns | Navigate to split history; each entry shows gross, fee, net, per-member amounts |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| GET split-config | `require_ui_session` | Any syndicate member |
| POST split-config | `require_ui_session` | Syndicate admin only |
| GET splits (history) | `require_ui_session` | Any syndicate member |
| GET my-earnings | `require_ui_session` | Returns only caller's data |
| POST execute-split | Internal middleware | No user session; triggered by payment system |

### 6.2 Financial Integrity

- All split amounts are calculated from `gross_amount_cents` using integer arithmetic (no floating-point currency math).
- The invariant `platform_fee_cents + sum(distributions.amount_cents) == gross_amount_cents` is enforced and logged.
- Split execution records are immutable once written (no update or delete endpoint).
- Changing split config does not retroactively alter historical splits.

### 6.3 Audit Trail

- Every split execution writes individual billing ledger credit entries per member.
- The split execution record links to all ledger entry IDs for cross-reference.
- Split config changes are recorded in the syndicate audit log (SYND-001).

### 6.4 Rate Limiting

- Split config updates: max 10 per syndicate per day (prevent config churn).
- Split execution: triggered only by payment system (not user-callable).

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| SYND-001 | Required | Syndicate membership, admin checks, audit log |
| SYND-002 | Required | Bundle subscription payments that trigger splits |
| `app/services/billing_shared.py` | Exists | `new_ledger_entry`, `apply_wallet_delta` |
| `app/services/creator_earnings.py` | Exists | Earnings aggregation recognizes split credits |
| SYND-004 | Not started | Treasury contributions (separate from revenue splits) |

---

## 8. Acceptance Criteria

1. Admin can configure split mode (equal, weighted, or performance-based).
2. Weighted splits validate that percentages sum to exactly 100%.
3. After each bundle payment, revenue is split and ledger entries written per member.
4. Platform fee is deducted before split distribution.
5. All distributed amounts sum to exactly `net_amount_cents` (no rounding loss).
6. Split history is viewable by all syndicate members.
7. Each member can see their total earnings from the syndicate.
8. Config changes apply to future payments only; historical splits are immutable.
9. All 16 E2E tests pass.

---


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_revenue_splitting.py`

| # | Function | Assertion |
|---|----------|-----------|
| 1 | `test_equal_split_divides_evenly` | Equal split divides evenly verified |
| 2 | `test_weighted_split_respects_percentages` | Weighted split respects percentages verified |
| 3 | `test_rounding_remainder_to_first_member` | Rounding remainder to first member verified |
| 4 | `test_split_writes_per_member_credit_entries` | Split writes per member credit entries verified |
| 5 | `test_platform_fee_deducted_before_split` | Platform fee deducted before split verified |
| 6 | `test_split_history_recorded` | Split history recorded verified |
| 7 | `test_update_split_config_applies_to_future` | Update split config applies to future verified |
| 8 | `test_performance_split_uses_engagement_metrics` | Performance split uses engagement metrics verified |

**Mocking**: All DynamoDB tables mocked via `moto`; profile lookups patched via `unittest.mock.patch`.

### Integration Tests

1. Bundle payment triggers split processor -> per-member credits appear in billing ledger -> earnings dashboard shows bundle income
2. Admin changes split from equal to weighted -> next payment uses new percentages
3. Rounding: $10.00 split 3 ways -> $3.34 + $3.33 + $3.33 (remainder to first member)

### E2E Tests (Playwright)

**File**: `frontend/e2e/revenue-splitting.spec.ts`
**Sections**: 1-3 (10 tests)

**Auth pattern**: `injectAuth(page, identity)` for cookie auth; `x-csrf-token` header for POST/PUT/DELETE mutations.

| # | Test | Assertion |
|---|------|-----------|
| 1 | Configure equal split | 200; mode=equal stored |
| 2 | Trigger split after payment | Per-member credits in ledger |
| 3 | Member earnings show bundle income | GET /earnings includes split credit |
| 4 | Weighted split respects percentages | Members receive correct proportions |
| 5 | Update split config | 200; future payments use new rules |
| 6 | Split history shows all distributions | GET history returns itemized splits |
| 7 | Platform fee deducted | Net distributable = payment - fee |
| 8 | Admin views full breakdown | GET detail shows per-member amounts |

**Negative tests**: 400 weighted percentages not summing to 100%, 403 non-admin config change, 404 syndicate not found, 422 invalid split mode

**Edge cases**: Single member syndicate (100% to one), member joins mid-period (prorated?), $0.01 payment split 5 ways

### Test Data Requirements

- **DDB seeds**: Syndicate with split config; subscription payments in billing table; member profiles
- **Test users**: Alice (admin), Bob/Charlie (members), Dave (subscriber/payer)

### CI/Pipeline Considerations

- **Feature flags**: SYNDICATES_ENABLED=true
- **Serial execution**: Must run after SYND-002 subscription payment tests
- **Retry safety**: All tests are idempotent; use unique per-run identifiers (`TS` suffix) to avoid cross-run conflicts.

---

## Dependencies & Merge Safety

### Depends On

| Ticket/Component | Reason |
|------------------|--------|
| SYND-001 | Syndicate membership — list_members for member roster |
| SYND-002 | Bundle subscriptions — payment triggers split processing |
| Billing shared (existing) | new_ledger_entry for per-member credit entries |
| Tip ledger (existing) | Pattern for paired debit/credit entries |

### Depended On By

| Ticket | Reason |
|--------|--------|
| SYND-004 | Treasury receives platform fee share from splits |

### Merge Strategy: **Sequential**

Requires SYND-001 + SYND-002 for membership and payments. Extends billing ledger.

### Merge Checklist

- [ ] All unit tests pass (`just test`)
- [ ] All E2E tests pass (`just e2e`)
- [ ] Feature flag defaults to enabled in `.env.local.example`
- [ ] No breaking changes to existing API contracts
- [ ] DynamoDB table/GSI changes added to `scripts/local-ddb-init.py`
- [ ] Frontend types in `api/types.ts` match backend `models.py`
- [ ] New routes registered in `app/main.py` and `frontend/src/App.tsx`

## Codebase References

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| No syndicate/split code exists | All files | — | VERIFIED: grep "syndicate" returns zero |
| billing_shared.py exists | `app/services/billing_shared.py` | — | VERIFIED (260 lines) |
| creator_earnings.py exists | `app/services/creator_earnings.py` | — | VERIFIED |
