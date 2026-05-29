# SYND-004: Treasury & Fund Management

**Ticket**: SYND-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 12-14 days

---

## 1. Overview & Motivation

### 1.1 Purpose

SYND-004 implements a shared treasury wallet for syndicates. Members can contribute funds from their personal wallets to the syndicate treasury. The treasury can be spent on advertising (SYND-006) or platform services. A critical constraint governs the treasury: **money contributed by members cannot be withdrawn by the admin**. Contributed funds can only be spent on advertising or returned to contributors when they leave or the syndicate dissolves. This prevents abuse of pooled funds while enabling collaborative advertising spend.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Member | As a member, I want to contribute money from my personal wallet to the syndicate treasury. | POST transfer deducts from personal wallet, credits treasury; both ledger entries recorded. |
| Member | As a member, I want to see my total contributions to the treasury. | GET my-contributions returns sum and itemized history. |
| Admin | As an admin, I want to see the treasury balance and transaction history. | GET treasury returns current balance, contribution breakdown, and spending history. |
| Admin | As an admin, I want to spend treasury funds on advertising campaigns. | POST spend deducts from treasury; integrates with SYND-006 ad campaign creation. |
| System | When a member leaves, their unspent contributions are returned proportionally. | Leave triggers refund calculation; personal wallet credited; treasury debited. |
| System | When a syndicate dissolves, all unspent funds are returned to contributors. | Dissolution refunds each contributor proportionally based on remaining balance. |
| Admin | As an admin, I want to see how much each member has contributed. | GET contributions shows per-member totals and breakdown. |
| Member | As a member, I cannot withdraw my contribution directly. | No withdraw endpoint exists; treasury spend restricted to advertising. |

### 1.3 Critical Treasury Rules

These rules are non-negotiable security constraints:

1. **No admin withdrawal**: The admin cannot transfer treasury funds to their personal wallet. Treasury funds can ONLY flow out as:
   - Advertising spend (SYND-006)
   - Proportional refunds when a member leaves
   - Proportional refunds when the syndicate dissolves
2. **Proportional refund on leave**: When a member leaves, they receive `(their_unspent_contributions / total_unspent_contributions) * current_balance`.
3. **Full refund on dissolution**: When the last member leaves, all remaining balance is refunded proportionally to all historical contributors.
4. **No negative balance**: Treasury balance cannot go below zero. Advertising spend checks balance before deducting.
5. **Contribution tracking is permanent**: Even after spending occurs, the system tracks each member's total contributions for proportional refund calculations.

### 1.4 Why This Is Needed

Syndicates need shared funds for advertising (SYND-006). Without a treasury, each advertising campaign would require admin to collect money via side channels and manually reconcile. The treasury provides a transparent, auditable pool with automated refund guarantees that build trust among members who contribute funds to a shared cause.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Wallet system | `app/services/billing_shared.py:169-209` | `get_wallet_balance`, `apply_wallet_delta` for user wallets |
| Ledger entries | `app/services/billing_shared.py:217-248` | `new_ledger_entry` for debit/credit audit trail |
| Billing table | `scripts/local-ddb-init.py` line 59 | `pk`/`sk` single-table design used for wallets + ledger |
| Syndicates table | `scripts/local-ddb-init.py` (SYND-001) | `pk`/`sk` with GSIs; will host treasury items |
| Syndicates service | `app/services/syndicates.py` (SYND-001) | `leave_syndicate`, `_archive_syndicate` hooks for refund triggers |
| Ad placement | `app/services/ad_placement.py` | `record_ad_impression`, `_credit_ad_revenue`; SYND-006 integration point |

### 2.2 Wallet Implementation Details

From `app/services/billing_shared.py`:

```python
# get_wallet_balance (line 169)
# Returns {"wallet_balance_cents": int}
# Uses pk=USER#{user_id}, looks for wallet_balance_cents attribute

# apply_wallet_delta (line 178)
# Atomically adds delta_cents to wallet balance
# For withdrawals (delta < 0): uses ConditionExpression to ensure balance >= abs(delta)
# Returns new balance
```

The treasury will use the same billing table with a `TREASURY#{syndicate_id}` PK pattern for its wallet balance. This reuses the existing `apply_wallet_delta` function by passing the treasury PK instead of a user PK.

### 2.3 Gaps

1. **No treasury wallet concept** -- wallets exist only for individual users (`USER#{user_id}` PK).
2. **No contribution tracking** -- no mechanism to track who contributed what to a shared pool.
3. **No refund-on-leave logic** -- `leave_syndicate` in SYND-001 handles membership removal but has no financial hooks.
4. **No spend authorization** -- no system to authorize spending from a shared pool (different from individual wallet spending).
5. **No proportional refund calculator** -- no algorithm for dividing remaining balance among contributors.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 Treasury Balance (Billing Table)

**PK**: `TREASURY#{syndicate_id}`, **SK**: `BALANCE`

| Field | Type | Description |
|-------|------|-------------|
| `wallet_balance_cents` | N | Current treasury balance |
| `total_contributed_cents` | N | Lifetime total contributions |
| `total_spent_cents` | N | Lifetime total advertising spend |
| `total_refunded_cents` | N | Lifetime total refunds to members |
| `currency` | S | `"usd"` |
| `updated_at` | N | Last transaction timestamp |

This item follows the same schema as user wallet rows, allowing reuse of `apply_wallet_delta` by passing `pk="TREASURY#{syndicate_id}"`.

#### 3.1.2 Treasury Ledger Entries (Billing Table)

Uses the same `new_ledger_entry` pattern as user ledger entries:

**PK**: `TREASURY#{syndicate_id}`, **SK**: `LEDGER#{timestamp}#{entry_id}`

Reason strings:
- `"Treasury contribution from {user_id}"` -- credit (contribution)
- `"Treasury ad campaign spend: {campaign_id}"` -- debit (advertising)
- `"Treasury refund to {user_id}: member departure"` -- debit (refund)
- `"Treasury refund to {user_id}: syndicate dissolved"` -- debit (dissolution refund)

#### 3.1.3 Contribution Tracker (Syndicates Table)

**PK**: `SYND#{syndicate_id}`, **SK**: `CONTRIB#{user_id}`

| Field | Type | Description |
|-------|------|-------------|
| `user_id` | S | Contributing member |
| `total_contributed_cents` | N | Total contributed by this member |
| `total_refunded_cents` | N | Total refunded to this member |
| `net_contributed_cents` | N | `contributed - refunded` (unspent contribution) |
| `last_contribution_at` | N | Timestamp of last contribution |
| `contribution_count` | N | Number of individual contributions |

#### 3.1.4 Example Items

**Treasury balance**:
```json
{
  "pk": "TREASURY#synd_abc123",
  "sk": "BALANCE",
  "wallet_balance_cents": 5000,
  "total_contributed_cents": 8000,
  "total_spent_cents": 2500,
  "total_refunded_cents": 500,
  "currency": "usd",
  "updated_at": 1748520000
}
```

**Contribution tracker**:
```json
{
  "pk": "SYND#synd_abc123",
  "sk": "CONTRIB#alice@test.local",
  "user_id": "alice@test.local",
  "total_contributed_cents": 5000,
  "total_refunded_cents": 300,
  "net_contributed_cents": 4700,
  "last_contribution_at": 1748520000,
  "contribution_count": 3
}
```

**Contribution ledger entry (user side -- debit)**:
```json
{
  "pk": "USER#alice@test.local",
  "sk": "LEDGER#1748520000#le_abc",
  "entry_id": "le_abc",
  "ts": 1748520000,
  "type": "debit",
  "amount_cents": 2000,
  "currency": "usd",
  "state": "settled",
  "reason": "Syndicate treasury contribution",
  "meta": {
    "syndicate_id": "synd_abc123",
    "syndicate_name": "Creative Collective",
    "treasury_entry_id": "le_xyz"
  }
}
```

**Contribution ledger entry (treasury side -- credit)**:
```json
{
  "pk": "TREASURY#synd_abc123",
  "sk": "LEDGER#1748520000#le_xyz",
  "entry_id": "le_xyz",
  "ts": 1748520000,
  "type": "credit",
  "amount_cents": 2000,
  "currency": "usd",
  "state": "settled",
  "reason": "Treasury contribution from alice@test.local",
  "meta": {
    "contributor_user_id": "alice@test.local",
    "user_entry_id": "le_abc"
  }
}
```

### 3.2 Backend Service

**New file**: `app/services/syndicate_treasury.py` (~400 lines)

```python
"""Syndicate treasury and fund management (SYND-004)."""

from __future__ import annotations
import logging
from math import floor
from typing import Any, Dict, List, Optional
from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates as syndicate_svc
from app.services.billing_shared import (
    new_ledger_entry,
    apply_wallet_delta,
    get_wallet_balance,
)

logger = logging.getLogger(__name__)


def contribute(
    *,
    syndicate_id: str,
    user_id: str,
    amount_cents: int,
) -> Dict[str, Any]:
    """Transfer funds from member's personal wallet to syndicate treasury."""
    if amount_cents <= 0:
        raise ValueError("Contribution amount must be positive")

    syndicate_svc._require_is_member(syndicate_id, user_id)
    syndicate = syndicate_svc.get_syndicate(syndicate_id)

    # 1. Deduct from personal wallet (raises ConditionalCheckFailedException if insufficient)
    new_personal_balance = apply_wallet_delta(
        T.billing, f"USER#{user_id}", -amount_cents
    )

    # 2. Credit treasury wallet
    _ensure_treasury_row(syndicate_id)
    new_treasury_balance = apply_wallet_delta(
        T.billing, f"TREASURY#{syndicate_id}", amount_cents
    )

    # 3. Update contribution tracker
    _update_contribution_tracker(syndicate_id, user_id, amount_cents)

    # 4. Update treasury totals
    _increment_treasury_total(syndicate_id, "total_contributed_cents", amount_cents)

    ts = now_ts()

    # 5. Write paired ledger entries
    treasury_entry = new_ledger_entry(
        T.billing, f"TREASURY#{syndicate_id}",
        amount_cents=amount_cents,
        entry_type="credit",
        reason=f"Treasury contribution from {user_id}",
        meta={"contributor_user_id": user_id},
    )

    user_entry = new_ledger_entry(
        T.billing, f"USER#{user_id}",
        amount_cents=amount_cents,
        entry_type="debit",
        reason="Syndicate treasury contribution",
        meta={
            "syndicate_id": syndicate_id,
            "syndicate_name": syndicate.get("name", ""),
            "treasury_entry_id": treasury_entry["entry_id"],
        },
    )

    syndicate_svc._write_audit(
        syndicate_id, user_id, "treasury_contribution",
        "", {"amount_cents": amount_cents},
    )

    return {
        "ok": True,
        "amount_cents": amount_cents,
        "new_personal_balance": new_personal_balance,
        "new_treasury_balance": new_treasury_balance,
        "treasury_entry_id": treasury_entry["entry_id"],
        "user_entry_id": user_entry["entry_id"],
    }


def spend_on_advertising(
    *,
    syndicate_id: str,
    admin_sub: str,
    amount_cents: int,
    campaign_id: str,
    campaign_name: str = "",
) -> Dict[str, Any]:
    """Admin spends treasury funds on an advertising campaign."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)

    if amount_cents <= 0:
        raise ValueError("Spend amount must be positive")

    # Deduct from treasury (raises if insufficient balance)
    new_balance = apply_wallet_delta(
        T.billing, f"TREASURY#{syndicate_id}", -amount_cents
    )

    _increment_treasury_total(syndicate_id, "total_spent_cents", amount_cents)

    entry = new_ledger_entry(
        T.billing, f"TREASURY#{syndicate_id}",
        amount_cents=amount_cents,
        entry_type="debit",
        reason=f"Treasury ad campaign spend: {campaign_id}",
        meta={
            "campaign_id": campaign_id,
            "campaign_name": campaign_name,
            "authorized_by": admin_sub,
        },
    )

    syndicate_svc._write_audit(
        syndicate_id, admin_sub, "treasury_ad_spend",
        campaign_id, {"amount_cents": amount_cents},
    )

    return {
        "ok": True,
        "amount_cents": amount_cents,
        "new_balance": new_balance,
        "ledger_entry_id": entry["entry_id"],
    }


def refund_on_member_leave(
    *,
    syndicate_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Calculate and refund a leaving member's proportional share."""
    balance = get_treasury_balance(syndicate_id)
    current_balance = balance.get("wallet_balance_cents", 0)
    if current_balance <= 0:
        return {"refunded_cents": 0}

    # Get all contribution trackers
    contributors = _get_all_contributors(syndicate_id)
    total_net = sum(c.get("net_contributed_cents", 0) for c in contributors)

    if total_net <= 0:
        return {"refunded_cents": 0}

    # Find this member's contribution
    member_contrib = next(
        (c for c in contributors if c["user_id"] == user_id), None
    )
    if not member_contrib or member_contrib.get("net_contributed_cents", 0) <= 0:
        return {"refunded_cents": 0}

    member_net = member_contrib["net_contributed_cents"]
    refund_cents = floor(current_balance * member_net / total_net)

    if refund_cents <= 0:
        return {"refunded_cents": 0}

    # Deduct from treasury
    apply_wallet_delta(T.billing, f"TREASURY#{syndicate_id}", -refund_cents)

    # Credit member's personal wallet
    apply_wallet_delta(T.billing, f"USER#{user_id}", refund_cents)

    # Update contribution tracker
    _update_refund_tracker(syndicate_id, user_id, refund_cents)
    _increment_treasury_total(syndicate_id, "total_refunded_cents", refund_cents)

    # Ledger entries
    new_ledger_entry(
        T.billing, f"TREASURY#{syndicate_id}",
        amount_cents=refund_cents,
        entry_type="debit",
        reason=f"Treasury refund to {user_id}: member departure",
        meta={"refunded_user_id": user_id},
    )
    new_ledger_entry(
        T.billing, f"USER#{user_id}",
        amount_cents=refund_cents,
        entry_type="credit",
        reason="Syndicate treasury refund: departure",
        meta={"syndicate_id": syndicate_id},
    )

    return {"refunded_cents": refund_cents}


def refund_on_dissolution(syndicate_id: str) -> Dict[str, Any]:
    """Refund all remaining treasury funds to contributors proportionally."""
    balance = get_treasury_balance(syndicate_id)
    current_balance = balance.get("wallet_balance_cents", 0)

    if current_balance <= 0:
        return {"total_refunded": 0, "refunds": []}

    contributors = _get_all_contributors(syndicate_id)
    total_net = sum(c.get("net_contributed_cents", 0) for c in contributors)

    if total_net <= 0:
        return {"total_refunded": 0, "refunds": []}

    refunds = []
    remaining = current_balance

    # Sort by contribution descending for remainder distribution
    sorted_contribs = sorted(
        [c for c in contributors if c.get("net_contributed_cents", 0) > 0],
        key=lambda c: c["net_contributed_cents"],
        reverse=True,
    )

    for i, contrib in enumerate(sorted_contribs):
        if i == len(sorted_contribs) - 1:
            refund = remaining  # Last person gets any remainder
        else:
            refund = floor(current_balance * contrib["net_contributed_cents"] / total_net)
        remaining -= refund

        if refund > 0:
            apply_wallet_delta(T.billing, f"USER#{contrib['user_id']}", refund)
            new_ledger_entry(
                T.billing, f"USER#{contrib['user_id']}",
                amount_cents=refund,
                entry_type="credit",
                reason="Syndicate treasury refund: syndicate dissolved",
                meta={"syndicate_id": syndicate_id},
            )
            refunds.append({"user_id": contrib["user_id"], "refunded_cents": refund})

    # Zero out treasury
    apply_wallet_delta(T.billing, f"TREASURY#{syndicate_id}", -current_balance)

    return {"total_refunded": sum(r["refunded_cents"] for r in refunds), "refunds": refunds}


def get_treasury_balance(syndicate_id: str) -> Dict[str, Any]:
    """Get treasury balance and totals."""
    return get_wallet_balance(T.billing, f"TREASURY#{syndicate_id}")


def get_treasury_ledger(syndicate_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Get treasury transaction history."""
    # Query TREASURY#{syndicate_id} with sk begins_with "LEDGER#"
    # ScanIndexForward=False for newest first


def get_member_contributions(syndicate_id: str) -> List[Dict[str, Any]]:
    """Get contribution totals for all members."""
    # Query SYND#{syndicate_id} with sk begins_with "CONTRIB#"


def get_my_contributions(syndicate_id: str, user_id: str) -> Dict[str, Any]:
    """Get a member's contribution history."""
    resp = T.syndicates.get_item(Key={
        "pk": f"SYND#{syndicate_id}",
        "sk": f"CONTRIB#{user_id}",
    })
    return resp.get("Item", {
        "total_contributed_cents": 0,
        "total_refunded_cents": 0,
        "net_contributed_cents": 0,
        "contribution_count": 0,
    })


# --- Internal helpers ---

def _ensure_treasury_row(syndicate_id: str):
    """Create treasury balance row if it doesn't exist."""

def _update_contribution_tracker(syndicate_id: str, user_id: str, amount_cents: int):
    """Atomically increment contribution tracker."""

def _update_refund_tracker(syndicate_id: str, user_id: str, refund_cents: int):
    """Atomically increment refund tracker."""

def _increment_treasury_total(syndicate_id: str, field: str, amount_cents: int):
    """Atomically increment a treasury total field."""

def _get_all_contributors(syndicate_id: str) -> List[Dict[str, Any]]:
    """Get all contribution tracker items."""
```

### 3.3 Integration with SYND-001 Leave/Dissolution

**Modify**: `app/services/syndicates.py`

Hook `refund_on_member_leave` into `leave_syndicate`:

```python
def leave_syndicate(*, syndicate_id: str, user_id: str) -> Dict[str, Any]:
    meta = _get_meta(syndicate_id)
    is_admin = meta["admin_user_id"] == user_id

    # SYND-004: Refund treasury contributions before removing member
    from app.services.syndicate_treasury import refund_on_member_leave
    refund_result = refund_on_member_leave(syndicate_id=syndicate_id, user_id=user_id)

    _remove_member(syndicate_id, user_id)
    new_count = meta["member_count"] - 1

    if new_count <= 0:
        # SYND-004: Refund all remaining funds before dissolution
        from app.services.syndicate_treasury import refund_on_dissolution
        refund_on_dissolution(syndicate_id)
        _archive_syndicate(syndicate_id)
        return {"dissolved": True, "refund": refund_result}

    if is_admin:
        members = list_members(syndicate_id)
        members.sort(key=lambda m: m.get("joined_at", 0))
        new_admin = members[0]["user_id"]
        _promote_to_admin(syndicate_id, new_admin)

    return {"dissolved": False, "refund": refund_result}
```

### 3.4 Backend Router

**Extend**: `app/routers/syndicates.py`

### 3.5 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/syndicates/{syndicate_id}/treasury` | `require_ui_session` | Get treasury balance + totals (members only) |
| `POST` | `/ui/syndicates/{syndicate_id}/treasury/contribute` | `require_ui_session` | Contribute from personal wallet |
| `GET` | `/ui/syndicates/{syndicate_id}/treasury/ledger` | `require_ui_session` | Get treasury transaction history |
| `GET` | `/ui/syndicates/{syndicate_id}/treasury/contributions` | `require_ui_session` | Get per-member contribution breakdown |
| `GET` | `/ui/syndicates/{syndicate_id}/treasury/my-contributions` | `require_ui_session` | Get caller's contribution history |

Note: There is intentionally **no** `POST /treasury/withdraw` endpoint. Treasury funds can only leave via advertising spend (SYND-006) or automated refunds.

### 3.6 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Syndicate Treasury (SYND-004) --

class TreasuryContributeIn(BaseModel):
    amount_cents: int = Field(ge=100, le=1000000)  # $1 - $10,000

class TreasuryBalanceOut(BaseModel):
    syndicate_id: str
    wallet_balance_cents: int = 0
    total_contributed_cents: int = 0
    total_spent_cents: int = 0
    total_refunded_cents: int = 0
    currency: str = "usd"
    updated_at: int = 0

class TreasuryContributionOut(BaseModel):
    ok: bool = True
    amount_cents: int = 0
    new_personal_balance: int = 0
    new_treasury_balance: int = 0
    treasury_entry_id: str = ""
    user_entry_id: str = ""

class ContributorSummaryOut(BaseModel):
    user_id: str
    display_name: str = ""
    total_contributed_cents: int = 0
    total_refunded_cents: int = 0
    net_contributed_cents: int = 0
    contribution_count: int = 0
    last_contribution_at: int = 0

class TreasuryLedgerEntryOut(BaseModel):
    entry_id: str
    ts: int = 0
    type: str  # "credit" or "debit"
    amount_cents: int = 0
    reason: str = ""
    meta: Dict[str, Any] = Field(default_factory=dict)
```

### 3.7 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/syndicates/TreasuryTab.tsx` | Treasury overview with balance, contributions, spending | ~250 |
| `frontend/src/pages/syndicates/ContributeDialog.tsx` | Dialog for contributing to treasury | ~100 |
| `frontend/src/pages/syndicates/TreasuryLedgerTable.tsx` | Transaction history table | ~120 |
| `frontend/src/pages/syndicates/ContributorsTable.tsx` | Per-member contribution breakdown | ~100 |

**Component tree for TreasuryTab**:

```
TreasuryTab (within SyndicateDetailPage)
├── Card: "Treasury Balance"
│   ├── Balance display: "$50.00"
│   ├── Stats row: contributed / spent / refunded
│   └── Button: "Contribute" (opens ContributeDialog)
├── ContributeDialog
│   ├── Current personal wallet balance
│   ├── Amount input (min $1, max personal balance)
│   ├── Warning: "Contributions cannot be withdrawn"
│   └── "Confirm Contribution" button
├── Card: "Contributors"
│   └── ContributorsTable
│       └── Per member: name, total contributed, total refunded, net
├── Card: "Transaction History"
│   └── TreasuryLedgerTable
│       └── Per entry: date, type, amount, reason, icon
└── Info banner: "Treasury funds can only be spent on advertising or refunded when members leave"
```

### 3.8 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/syndicate_treasury.py` | Treasury management service | ~400 |
| `frontend/src/pages/syndicates/TreasuryTab.tsx` | Treasury overview tab | ~250 |
| `frontend/src/pages/syndicates/ContributeDialog.tsx` | Contribution dialog | ~100 |
| `frontend/src/pages/syndicates/TreasuryLedgerTable.tsx` | Ledger table | ~120 |
| `frontend/src/pages/syndicates/ContributorsTable.tsx` | Contributors table | ~100 |
| `frontend/e2e/syndicates-treasury.spec.ts` | E2E tests | ~450 |

### 3.9 Files to Modify

| File | Change |
|------|--------|
| `app/services/syndicates.py` | Hook `refund_on_member_leave` and `refund_on_dissolution` into leave/archive |
| `app/routers/syndicates.py` | Add treasury endpoints |
| `app/models.py` | Add Treasury* models |
| `frontend/src/api/types.ts` | Add Treasury TypeScript interfaces |
| `frontend/src/api/endpoints/syndicates.ts` | Add treasury API wrappers |
| `frontend/src/pages/syndicates/SyndicateDetailPage.tsx` | Add "Treasury" tab |

---

## 4. Proportional Refund Calculation

### 4.1 Algorithm

When a member leaves:

```
current_balance = treasury.wallet_balance_cents
contributors = all CONTRIB#{user_id} items for this syndicate
total_net = sum(c.net_contributed_cents for c in contributors where net > 0)
member_net = CONTRIB#{leaving_user_id}.net_contributed_cents

refund = floor(current_balance * member_net / total_net)
```

### 4.2 Example

Three members contributed to a treasury:
- Alice: contributed $50, refunded $0 → net = $50
- Bob: contributed $30, refunded $0 → net = $30
- Charlie: contributed $20, refunded $0 → net = $20

Total net = $100. Treasury spent $40 on ads. Current balance = $60.

Alice leaves:
- `refund = floor(6000 * 5000 / 10000) = floor(3000) = $30.00`
- Alice gets $30 refunded. Treasury balance: $30.
- Alice's CONTRIB updated: `total_refunded=3000, net_contributed=2000` (she "lost" $20 to ad spend proportionally).

### 4.3 Dissolution Example

After Alice left (balance = $30, Alice net now = $20):
- Bob net = $30, Charlie net = $20. Total net = $50.
- Bob leaves: `refund = floor(3000 * 3000 / 5000) = floor(1800) = $18.00`. Balance: $12.
- Charlie (last member): dissolution triggers. `refund = $12.00` (all remaining). Balance: $0.

### 4.4 Edge Cases

- Member contributed $0 → net_contributed = 0 → no refund.
- Treasury balance is $0 → no refund for anyone.
- Single contributor → gets 100% of remaining balance on leave.
- All funds spent on ads → no refunds possible (balance = 0).

---

## 5. E2E Test Plan

**File**: `frontend/e2e/syndicates-treasury.spec.ts`

### Section 435: Treasury Contribution API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 435.1 | Member contributes to treasury | POST contribute `2000` cents; 200; treasury balance = 2000; personal wallet decreased by 2000 |
| 435.2 | Insufficient personal balance returns error | POST contribute exceeding wallet balance; 400 or ConditionalCheckFailed |
| 435.3 | Non-member cannot contribute | Non-member POST; 403 or 404 |
| 435.4 | Multiple contributions accumulate | Alice contributes 1000, then 500; treasury balance = 1500; contribution tracker shows 2 contributions totaling 1500 |

### Section 436: Treasury Balance & Ledger API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 436.1 | GET treasury returns correct balance | After contributions; balance, total_contributed, total_spent all correct |
| 436.2 | Ledger shows contribution entries | GET ledger; credit entries with reason containing "contribution" |
| 436.3 | Per-member contributions breakdown | GET contributions; each contributor's total and count correct |
| 436.4 | My-contributions returns caller's data | GET my-contributions; returns only caller's contribution summary |

### Section 437: Refund on Leave API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 437.1 | Leaving member gets proportional refund | Alice (net $50) and Bob (net $30) contributed; $20 spent; balance = $60. Alice leaves; gets $37 (floor(6000*5000/8000)) |
| 437.2 | Refund credited to personal wallet | After leave; personal wallet increased by refund amount |
| 437.3 | Treasury balance decreased by refund | After leave; treasury balance = previous - refund |
| 437.4 | Member with zero contributions gets no refund | Charlie (contributed $0) leaves; refund = 0 |

### Section 438: Dissolution Refund & Treasury UI (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 438.1 | Dissolution refunds all remaining funds | Last member leaves; all contributors credited proportionally; treasury = 0 |
| 438.2 | Treasury tab shows balance and transaction history | Navigate to syndicate; "Treasury" tab shows balance card + ledger table |
| 438.3 | Contribute dialog shows wallet balance and warning | Click "Contribute"; dialog shows personal balance; "cannot be withdrawn" warning visible |
| 438.4 | No withdraw button exists | Treasury tab has no withdraw/transfer-out button; only "Contribute" and "Spend on Ads" (admin) |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| GET treasury | `require_ui_session` | Syndicate members only |
| POST contribute | `require_ui_session` | Syndicate members only |
| GET ledger | `require_ui_session` | Syndicate members only |
| GET contributions | `require_ui_session` | Syndicate members only |
| GET my-contributions | `require_ui_session` | Returns only caller's data |
| POST spend (SYND-006) | `require_ui_session` | Syndicate admin only |

### 6.2 Fund Safety

- **No withdrawal endpoint**: Intentionally omitted. Treasury funds cannot be transferred to any individual wallet except through the automated refund-on-leave/dissolution process.
- **Atomic balance operations**: `apply_wallet_delta` uses DDB `ConditionExpression` to prevent overdrafts on both personal wallets and treasury.
- **Paired ledger entries**: Every fund movement writes both a debit and credit entry for full double-entry audit trail.
- **Contribution tracking is append-only**: Contribution tracker totals are only incremented, never decremented (except `total_refunded_cents` during refunds).

### 6.3 Race Conditions

- **Concurrent contributions**: `apply_wallet_delta` uses atomic DDB `UpdateExpression` with `ADD`. Safe for concurrent calls.
- **Leave during contribution**: Member removal deletes `MEMBER#` item; contribution tracker `CONTRIB#` is separate and persists for refund calculation.
- **Concurrent leaves**: Each leave computes refund from current balance at time of execution. DDB `ConditionExpression` prevents double-spend.

### 6.4 Input Validation

- Contribution amount: min 100 cents ($1), max 1,000,000 cents ($10,000).
- Amount must be positive integer.
- Syndicate must be active (no contributions to archived syndicates).

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| SYND-001 | Required | Membership checks, leave/dissolution hooks, audit log |
| `app/services/billing_shared.py` | Exists | `apply_wallet_delta`, `new_ledger_entry`, `get_wallet_balance` |
| SYND-006 | Not started | `spend_on_advertising` will be called by ad campaign creation |
| Billing table | Exists | Treasury balance + ledger entries use same billing table |

---

## 8. Acceptance Criteria

1. Members can contribute from personal wallet to syndicate treasury.
2. Treasury balance updates atomically; no overdrafts possible.
3. Paired ledger entries written for every fund movement (contribution, spend, refund).
4. Per-member contribution tracking maintained accurately across multiple contributions.
5. Leaving member receives proportional refund based on their net contributions vs total net contributions.
6. Syndicate dissolution refunds all remaining funds proportionally to all contributors.
7. No withdrawal endpoint exists; funds can only flow out via advertising spend or automated refunds.
8. Treasury tab shows balance, contributors, and transaction history.
9. All 16 E2E tests pass.

---


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_treasury.py`

| # | Function | Assertion |
|---|----------|-----------|
| 1 | `test_contribute_deducts_from_personal_wallet` | Contribute deducts from personal wallet verified |
| 2 | `test_contribute_credits_treasury_balance` | Contribute credits treasury balance verified |
| 3 | `test_contribution_tracking_per_member` | Contribution tracking per member verified |
| 4 | `test_treasury_balance_query` | Treasury balance query verified |
| 5 | `test_spend_deducts_from_treasury` | Spend deducts from treasury verified |
| 6 | `test_no_admin_withdrawal` | No admin withdrawal verified |
| 7 | `test_proportional_refund_on_leave` | Proportional refund on leave verified |
| 8 | `test_full_refund_on_dissolution` | Full refund on dissolution verified |
| 9 | `test_no_negative_balance` | No negative balance verified |
| 10 | `test_contribution_ledger_entries` | Contribution ledger entries verified |

**Mocking**: All DynamoDB tables mocked via `moto`; profile lookups patched via `unittest.mock.patch`.

### Integration Tests

1. Member contributes -> personal wallet debited -> treasury credited -> both ledger entries written
2. Member leaves -> proportional refund calculated -> personal wallet credited -> treasury debited
3. Syndicate dissolves -> all remaining balance refunded proportionally to all contributors
4. Treasury spend on advertising -> balance decremented -> spend recorded in ledger

### E2E Tests (Playwright)

**File**: `frontend/e2e/treasury.spec.ts`
**Sections**: 1-4 (12 tests)

**Auth pattern**: `injectAuth(page, identity)` for cookie auth; `x-csrf-token` header for POST/PUT/DELETE mutations.

| # | Test | Assertion |
|---|------|-----------|
| 1 | Contribute to treasury | 200; personal wallet debited; treasury credited |
| 2 | Treasury balance reflects contribution | GET treasury shows correct balance |
| 3 | My contributions shows history | GET my-contributions returns itemized list |
| 4 | Spend from treasury | 200; balance decremented |
| 5 | No admin withdrawal | No withdraw endpoint exists; spend restricted to advertising |
| 6 | Proportional refund on leave | Leave; personal wallet credited proportionally |
| 7 | Full refund on dissolution | All contributors receive refund |
| 8 | Insufficient balance rejected | 400; cannot spend more than balance |

**Negative tests**: 400 contribute more than personal wallet balance, 400 spend exceeding treasury balance, 403 non-member contribution, 404 syndicate not found

**Edge cases**: Contribute $0.01, refund rounding with 3 contributors, treasury at $0 after full spend then member leaves (no refund)

### Test Data Requirements

- **DDB seeds**: Syndicate from SYND-001; personal wallet balances in billing table; treasury balance items
- **Test users**: Alice (admin), Bob/Charlie (contributing members)

### CI/Pipeline Considerations

- **Feature flags**: SYNDICATES_ENABLED=true
- **Serial execution**: Refund tests must run after contribution tests seed treasury balance
- **Retry safety**: All tests are idempotent; use unique per-run identifiers (`TS` suffix) to avoid cross-run conflicts.

---

## Dependencies & Merge Safety

### Depends On

| Ticket/Component | Reason |
|------------------|--------|
| SYND-001 | Syndicate membership — member verification for contributions |
| Billing shared (existing) | apply_wallet_delta and new_ledger_entry for fund transfers |

### Depended On By

| Ticket | Reason |
|--------|--------|
| SYND-006 | Advertising campaigns spend from treasury |

### Merge Strategy: **Sequential**

Requires SYND-001 for membership. Uses existing billing table with TREASURY# prefix.

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
| No treasury code exists | All files | — | VERIFIED: grep "treasury" returns zero in app/ |
| billing_shared.py exists with apply_wallet_delta | `app/services/billing_shared.py` | — | VERIFIED (260 lines) |
| Billing DDB table exists | `scripts/local-ddb-init.py` | 59 | VERIFIED |
