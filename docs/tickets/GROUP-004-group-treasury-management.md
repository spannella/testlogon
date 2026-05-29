# GROUP-004: Group Treasury Management

**Ticket**: GROUP-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 6-8 days
**Dependencies**: GROUP-001 (Membership), Billing shared (`app/services/billing_shared.py`)

---

## 1. Overview & Motivation

### 1.1 Purpose

GROUP-004 implements a shared treasury (wallet) for user groups. The treasury collects funds from member contributions (personal wallets) and external donations (GROUP-003). The admin can spend treasury on advertising campaigns (GROUP-003). Critical rule -- matching syndicate behavior: contributed funds cannot be withdrawn by the admin. Funds must be spent on group activities or returned to contributors if the group dissolves. Full transaction history provides financial transparency.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Member | As a member, I want to contribute from my wallet to the treasury. | POST transfers cents; ledger entries on both sides. |
| Member | As a member, I want to see the treasury balance. | GET returns balance, totals, goal. |
| Member | As a member, I want to see transaction history. | GET returns paginated ledger entries. |
| Admin | As an admin, I want to set a fundraising goal. | PATCH updates goal; shown with progress bar. |
| Admin | As an admin, I want to spend treasury on ads. | POST debit; validated against balance. |
| Admin | As an admin, I cannot withdraw funds to my wallet. | No withdrawal endpoint exists; 404/405 on attempt. |
| System | On dissolution, contributions returned pro-rata. | Pro-rata credits to contributor wallets. |
| System | On dissolution, external donations go to escrow. | External share to `PLATFORM#ESCROW`. |

### 1.3 Why This Is Needed

Groups need a financial primitive to fund activities. Without shared treasury, all spending falls on the admin's personal wallet -- neither transparent nor sustainable. The no-withdrawal rule ensures trust, and dissolution refunds protect contributors.

### 1.4 Treasury Flow

```
Member contributions + External donations -> Treasury Balance
  -> Spend on ads/activities (admin authorized)
  -> On dissolution: contributions -> pro-rata return; donations -> escrow
```

### 1.5 No-Withdrawal Rule

The admin CANNOT transfer treasury to any personal wallet. Funds leave the treasury only via: (1) authorized spending on group activities, (2) dissolution refunds (system-triggered), or (3) admin-approved contributor refund (up to contributor's total minus spent share).

---

## 2. Architecture & Data Flow

### 2.1 Contribution Flow

```
Member clicks "Contribute" on GroupTreasuryPage
  |
  v
POST /ui/groups/{group_id}/treasury/contribute
  { amount_cents: 5000 }
  |
  v
+-----------------------------------+
| group_treasury.py                 |
| contribute()                      |
+-----------------------------------+
  |
  +---> 1. Verify membership
  |        PK=GROUP#{group_id}, SK=MEMBER#{user_id}
  |
  +---> 2. Debit personal wallet
  |        apply_wallet_delta(user_sub, -amount_cents)
  |        PK=USER#{user_sub}, SK=WALLET
  |        ConditionExpression: wallet_balance_cents >= amount_cents
  |
  +---> 3. Credit group treasury
  |        apply_wallet_delta(f"GROUP#{group_id}", +amount_cents)
  |        PK=GROUP#{group_id}, SK=WALLET
  |
  +---> 4. Write personal ledger entry (debit)
  |        PK=USER#{user_sub}, SK=LEDGER#{ts}#{entry_id}
  |        reason="Contribution to group treasury"
  |
  +---> 5. Write treasury ledger entry (credit)
  |        PK=GROUP#{group_id}, SK=LEDGER#{ts}#{entry_id}
  |        category="contribution"
  |
  +---> 6. Update contribution tracker
  |        PK=GROUP#{group_id}, SK=CONTRIB#{user_id}
  |        ADD total_contributed_cents :amt, contribution_count :one
  |
  +---> 7. Increment total_contributed_cents on WALLET record
  |
  v
200 { balance_cents, total_contributed_cents }
```

### 2.2 Treasury Spend Flow

```
Admin clicks "Spend" on GroupTreasuryPage
  |
  v
POST /ui/groups/{group_id}/treasury/spend
  { amount_cents: 2000, reason: "Ad campaign", category: "ad_spend" }
  |
  v
+-----------------------------------+
| group_treasury.py                 |
| spend_treasury()                  |
+-----------------------------------+
  |
  +---> 1. Verify admin role
  |        PK=GROUP#{group_id}, SK=MEMBER#{user_id}
  |        role must be "admin"
  |
  +---> 2. Validate category in allowlist
  |        {"ad_spend", "event", "premium_feature", "other"}
  |
  +---> 3. Debit group treasury
  |        apply_wallet_delta(f"GROUP#{group_id}", -amount_cents)
  |        ConditionExpression: wallet_balance_cents >= amount_cents
  |
  +---> 4. Write treasury ledger entry (debit)
  |        PK=GROUP#{group_id}, SK=LEDGER#{ts}#{entry_id}
  |        category=category, reason=reason
  |
  +---> 5. Increment total_spent_cents on WALLET record
  |
  v
200 { balance_cents, total_spent_cents }
```

### 2.3 Dissolution Fund-Return Flow

```
Admin dissolves group (GROUP-001)
  |
  v
dissolve_group() calls dissolve_treasury(group_id)
  |
  v
+-----------------------------------+
| group_treasury.py                 |
| dissolve_treasury()               |
+-----------------------------------+
  |
  +---> 1. Get remaining balance, total_contributed, total_donated
  |
  +---> 2. Compute contribution_ratio
  |        = total_contributed / (total_contributed + total_donated)
  |
  +---> 3. contribution_remaining = remaining * contribution_ratio
  |
  +---> 4. For each contributor (CONTRIB# scan):
  |        share = contribution_remaining * their_total / total_contributed
  |        |
  |        +---> Credit contributor personal wallet
  |        +---> Write personal ledger (credit, "Group dissolution refund")
  |        +---> Write treasury ledger (debit, "dissolution_return")
  |
  +---> 5. donation_remaining = remaining - sum(all_shares)
  |        |
  |        +---> Credit PLATFORM#ESCROW wallet
  |        +---> Write escrow ledger entry
  |        +---> Write treasury ledger (debit, "escrow_transfer")
  |
  +---> 6. Zero out treasury balance
  |
  v
Treasury fully distributed, balance = 0
```

---

## 3. Current State Analysis

### 3.1 Existing Infrastructure

- **Wallet** (`app/services/billing_shared.py`): `billing` table (see `scripts/local-ddb-init.py:59`) with `pk=USER#{user_sub}`, `sk=WALLET`, `wallet_balance_cents`. `apply_wallet_delta()` (see `app/services/billing_shared.py:178`) atomically updates with overdraft protection via conditional expressions. Reusable for group treasury with `pk=GROUP#{group_id}`.
- **Ledger**: `new_ledger_entry()` (see `app/services/billing_shared.py:217`) writes `sk=LEDGER#{ts}#{entry_id}` with `amount_cents`, `reason`, `type`, `state` (NOT `direction` -- the existing function uses `entry_type` parameter mapping to `type` field and `state` field; there is no `direction` field in the existing schema). Same function works with group PK via `key_name`/`key_value` parameters.
- **Group dissolution** (GROUP-001): `dissolve_group()` sets status to `dissolved`. GROUP-004 hooks into this to return funds before membership cleanup. <!-- NOTE: dissolve_group() does not exist yet — must be created by GROUP-001 -->

### 3.2 Gaps

1. No group treasury balance record.
2. No contribution endpoint or tracking.
3. No treasury ledger.
4. No spend authorization mechanism.
5. No dissolution fund-return logic.
6. No withdrawal block enforcement.
7. No frontend treasury page.

---

## 4. Detailed DynamoDB Access Patterns

| # | Operation | Table | PK | SK / GSI | Condition / Filter | Notes |
|---|-----------|-------|-----|----------|-------------------|-------|
| 1 | Get treasury balance | `billing` | `GROUP#{group_id}` | `SK=WALLET` | None | Single get_item |
| 2 | Create treasury (first contribute) | `billing` | `GROUP#{group_id}` | `SK=WALLET` | `attribute_not_exists(pk)` or upsert | Sets initial balance |
| 3 | Debit personal wallet | `billing` | `USER#{user_sub}` | `SK=WALLET` | `wallet_balance_cents >= :amt` | Conditional update |
| 4 | Credit group treasury | `billing` | `GROUP#{group_id}` | `SK=WALLET` | None | `ADD wallet_balance_cents :amt` |
| 5 | Write personal ledger | `billing` | `USER#{user_sub}` | `SK=LEDGER#{ts}#{entry_id}` | None | put_item |
| 6 | Write treasury ledger | `billing` | `GROUP#{group_id}` | `SK=LEDGER#{ts}#{entry_id}` | None | put_item |
| 7 | Update contribution tracker | `billing` | `GROUP#{group_id}` | `SK=CONTRIB#{user_id}` | None | `ADD total_contributed_cents :amt` with `if_not_exists` |
| 8 | List treasury ledger | `billing` | `GROUP#{group_id}` | `SK begins_with LEDGER#` | `ScanIndexForward=False` | Paginated; newest first |
| 9 | List contributors | `billing` | `GROUP#{group_id}` | `SK begins_with CONTRIB#` | None | Full scan of CONTRIB prefix |
| 10 | Debit treasury (spend) | `billing` | `GROUP#{group_id}` | `SK=WALLET` | `wallet_balance_cents >= :amt` | Conditional update |
| 11 | Increment total_contributed | `billing` | `GROUP#{group_id}` | `SK=WALLET` | None | `ADD total_contributed_cents :amt` |
| 12 | Increment total_spent | `billing` | `GROUP#{group_id}` | `SK=WALLET` | None | `ADD total_spent_cents :amt` |
| 13 | Dissolution: scan contributors | `billing` | `GROUP#{group_id}` | `SK begins_with CONTRIB#` | None | Full scan; linear in contributor count |
| 14 | Dissolution: credit personal wallet | `billing` | `USER#{user_sub}` | `SK=WALLET` | None | `ADD wallet_balance_cents :share` |
| 15 | Dissolution: credit escrow | `billing` | `PLATFORM#ESCROW` | `SK=WALLET` | None | `ADD wallet_balance_cents :donation_share` |
| 16 | Set fundraising goal | `billing` | `GROUP#{group_id}` | `SK=WALLET` | `attribute_exists(pk)` | `SET fundraising_goal_cents = :goal` |
| 17 | Verify membership | `user_groups` | `GROUP#{group_id}` | `SK=MEMBER#{user_id}` | None | Cross-table check | <!-- NOTE: user_groups table does not exist yet — must be created by GROUP-001 -->

**Key query example -- contribution with overdraft protection:**
<!-- VERIFIED: T.billing table handle exists at app/core/tables.py:146 -->
```python
# Step 1: Debit personal wallet (atomic, with overdraft check)
T.billing.update_item(
    Key={"pk": f"USER#{user_sub}", "sk": "WALLET"},
    UpdateExpression="ADD wallet_balance_cents :neg_amt",
    ConditionExpression="wallet_balance_cents >= :amt",
    ExpressionAttributeValues={
        ":neg_amt": -amount_cents,
        ":amt": amount_cents,
    },
)

# Step 2: Credit group treasury (atomic increment)
T.billing.update_item(
    Key={"pk": f"GROUP#{group_id}", "sk": "WALLET"},
    UpdateExpression="ADD wallet_balance_cents :amt, total_contributed_cents :amt",
    ExpressionAttributeValues={":amt": amount_cents},
)
```

---

## 5. Technical Design

### 5.1 Data Model (in `billing` table)

Group treasury reuses the `billing` table with `pk=GROUP#{group_id}`, consistent with user wallet storage.

**Treasury balance** (`pk=GROUP#{group_id}`, `sk=WALLET`):

| Field | Type | Description |
|-------|------|-------------|
| `wallet_balance_cents` | N | Current balance |
| `currency` | S | `usd` |
| `total_contributed_cents` | N | Lifetime member contributions |
| `total_donated_cents` | N | Lifetime external donations |
| `total_spent_cents` | N | Lifetime spending |
| `fundraising_goal_cents` | N (optional) | Admin-set goal |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |

**Treasury ledger** (`pk=GROUP#{group_id}`, `sk=LEDGER#{ts}#{entry_id}`):

| Field | Type | Description |
|-------|------|-------------|
| `entry_id` | S | ULID-style ID |
| `amount_cents` | N | Transaction amount |
| `direction` | S | `credit` or `debit` | <!-- NOTE: Existing billing ledger uses `type` field (via new_ledger_entry's entry_type param), not `direction`. If reusing new_ledger_entry(), map direction to entry_type or add a new `direction` field alongside `type`. -->
| `reason` | S | Human-readable |
| `category` | S | `contribution`, `donation`, `ad_spend`, `refund`, `dissolution_return`, `escrow_transfer` |
| `actor_user_id` | S (optional) | Who performed action |
| `actor_display_name` | S (optional) | Denormalized |
| `reference_id` | S (optional) | Related entity ID |
| `created_at` | N | Unix timestamp |

**Contribution tracker** (`pk=GROUP#{group_id}`, `sk=CONTRIB#{user_id}`):

| Field | Type | Description |
|-------|------|-------------|
| `user_id` | S | Contributor |
| `display_name` | S | Denormalized |
| `total_contributed_cents` | N | Running total (atomic increment) |
| `contribution_count` | N | Number of contributions |
| `first_contributed_at` | N | Timestamp |
| `last_contributed_at` | N | Timestamp |

Enables pro-rata dissolution calculations.

### 5.2 Backend Service (`app/services/group_treasury.py`)
<!-- NOTE: app/services/group_treasury.py does not exist yet — new implementation required -->

| Function | Description |
|----------|-------------|
| `get_treasury_balance(group_id)` | Return balance, totals, goal from WALLET record |
| `contribute(group_id, user_id, amount_cents, display_name)` | Debit user wallet -> credit treasury -> ledger both sides -> update CONTRIB tracker -> increment `total_contributed_cents` |
| `credit_donation(group_id, amount_cents, donor_name, donation_id)` | Credit treasury -> ledger -> increment `total_donated_cents`. Called by GROUP-003 |
| `spend_treasury(group_id, admin_id, amount_cents, reason, category, reference_id)` | Verify admin + allowed category -> debit treasury -> ledger -> increment `total_spent_cents` |
| `list_treasury_ledger(group_id, cursor, limit)` | Query `LEDGER#` prefix, `ScanIndexForward=False`, paginated |
| `list_contributors(group_id)` | Query `CONTRIB#` prefix, sorted by total desc |
| `set_fundraising_goal(group_id, admin_id, goal_cents)` | Update WALLET with goal (or REMOVE if null) |
| `dissolve_treasury(group_id)` | Calculate contribution vs donation ratio -> return contributions pro-rata -> send donations to `PLATFORM#ESCROW` -> zero balance -> log |

**Allowed spend categories**: `{"ad_spend", "event", "premium_feature", "other"}` -- validated in `spend_treasury`.

**Dissolution algorithm**:
1. Get remaining balance, `total_contributed_cents`, `total_donated_cents`.
2. Compute `contribution_ratio = total_contributed / (total_contributed + total_donated)`.
3. `contribution_remaining = remaining * contribution_ratio` (integer).
4. For each contributor: `share = contribution_remaining * their_total / total_contributed`.
5. Credit each contributor's personal wallet + ledger entry.
6. Send `donation_remaining = remaining - contribution_remaining` to `PLATFORM#ESCROW`.
7. Zero out treasury balance.

### 5.3 Withdrawal Block

No `withdraw` endpoint exists in the router -- FastAPI returns 404/405. `spend_treasury` validates category against allowlist and only debits the group treasury (does not credit any personal wallet). The only treasury-to-wallet path is `dissolve_treasury`, which is triggered by group dissolution.

### 5.4 Backend Router (`app/routers/group_treasury.py`)
<!-- NOTE: app/routers/group_treasury.py does not exist yet — new implementation required -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/groups/{group_id}/treasury` | `require_ui_session` | Balance + metadata (any member) |
| POST | `/ui/groups/{group_id}/treasury/contribute` | `require_ui_session` | Contribute (any member) |
| GET | `/ui/groups/{group_id}/treasury/ledger` | `require_ui_session` | Transaction history (any member) |
| GET | `/ui/groups/{group_id}/treasury/contributors` | `require_ui_session` | Contributor list (any member) |
| PATCH | `/ui/groups/{group_id}/treasury/goal` | `require_ui_session` | Set goal (admin) |
| POST | `/ui/groups/{group_id}/treasury/spend` | `require_ui_session` | Spend (admin) |

All endpoints verify membership. Spend and goal endpoints verify admin role.

---

## 6. API Request/Response Examples

### 6.1 Get Treasury Balance

**Request:**
```http
GET /ui/groups/grp_abc123/treasury
Cookie: ui_session=...; ui_access_token=...
```

**Response (200):**
```json
{
  "balance_cents": 15000,
  "currency": "usd",
  "total_contributed_cents": 12000,
  "total_donated_cents": 5000,
  "total_spent_cents": 2000,
  "fundraising_goal_cents": 50000
}
```

### 6.2 Contribute to Treasury

**Request:**
```http
POST /ui/groups/grp_abc123/treasury/contribute
Content-Type: application/json
Cookie: ui_session=...; ui_csrf=...; ui_access_token=...
x-csrf-token: csrf_token_value

{
  "amount_cents": 5000
}
```

**Response (200):**
```json
{
  "ok": true,
  "balance_cents": 20000,
  "personal_balance_cents": 45000,
  "contribution_total_cents": 8000,
  "ledger_entry_id": "led_a1b2c3d4"
}
```

### 6.3 Spend Treasury

**Request:**
```http
POST /ui/groups/grp_abc123/treasury/spend
Content-Type: application/json
Cookie: ui_session=...; ui_csrf=...; ui_access_token=...
x-csrf-token: csrf_token_value

{
  "amount_cents": 2000,
  "reason": "Summer ad campaign budget",
  "category": "ad_spend",
  "reference_id": "camp_xyz789"
}
```

**Response (200):**
```json
{
  "ok": true,
  "balance_cents": 18000,
  "total_spent_cents": 4000,
  "ledger_entry_id": "led_e5f6a7b8"
}
```

### 6.4 Get Treasury Ledger

**Request:**
```http
GET /ui/groups/grp_abc123/treasury/ledger?limit=20&cursor=
Cookie: ui_session=...; ui_access_token=...
```

**Response (200):**
```json
{
  "entries": [
    {
      "entry_id": "led_e5f6a7b8",
      "amount_cents": 2000,
      "currency": "usd",
      "direction": "debit",
      "reason": "Summer ad campaign budget",
      "category": "ad_spend",
      "actor_user_id": "alice-sub-123",
      "actor_display_name": "Alice",
      "reference_id": "camp_xyz789",
      "created_at": 1748535000
    },
    {
      "entry_id": "led_a1b2c3d4",
      "amount_cents": 5000,
      "currency": "usd",
      "direction": "credit",
      "reason": "Contribution from Alice",
      "category": "contribution",
      "actor_user_id": "alice-sub-123",
      "actor_display_name": "Alice",
      "reference_id": null,
      "created_at": 1748534800
    }
  ],
  "cursor": null,
  "has_more": false
}
```

### 6.5 Get Contributors List

**Request:**
```http
GET /ui/groups/grp_abc123/treasury/contributors
Cookie: ui_session=...; ui_access_token=...
```

**Response (200):**
```json
{
  "contributors": [
    {
      "user_id": "alice-sub-123",
      "display_name": "Alice",
      "total_contributed_cents": 8000,
      "contribution_count": 3,
      "first_contributed_at": 1748530000,
      "last_contributed_at": 1748534800
    },
    {
      "user_id": "bob-sub-456",
      "display_name": "Bob",
      "total_contributed_cents": 4000,
      "contribution_count": 2,
      "first_contributed_at": 1748531000,
      "last_contributed_at": 1748533000
    }
  ],
  "count": 2
}
```

### 6.6 Set Fundraising Goal

**Request:**
```http
PATCH /ui/groups/grp_abc123/treasury/goal
Content-Type: application/json
Cookie: ui_session=...; ui_csrf=...; ui_access_token=...
x-csrf-token: csrf_token_value

{
  "goal_cents": 100000
}
```

**Response (200):**
```json
{
  "ok": true,
  "fundraising_goal_cents": 100000
}
```

---

## 7. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|---|----------|-------------|------------|---------------|-----------------|
| 1 | Not a member | 403 | `NOT_A_MEMBER` | "Not a member of this group" | Join the group |
| 2 | Not admin (spend/goal) | 403 | `NOT_ADMIN` | "Only the group admin can perform this action" | Request admin role |
| 3 | Insufficient personal wallet | 400 | `INSUFFICIENT_WALLET` | "Insufficient wallet balance" | Deposit funds to personal wallet |
| 4 | Insufficient treasury balance | 400 | `INSUFFICIENT_TREASURY` | "Insufficient treasury balance" | Contribute more or reduce spend |
| 5 | Contribution below minimum | 422 | `VALIDATION_ERROR` | "amount_cents: Input should be >= 100" | Contribute at least $1.00 |
| 6 | Contribution above maximum | 422 | `VALIDATION_ERROR` | "amount_cents: Input should be <= 10000000" | Max $100,000 per contribution |
| 7 | Invalid spend category | 400 | `INVALID_CATEGORY` | "Invalid spend category. Allowed: ad_spend, event, premium_feature, other" | Use allowed category |
| 8 | Group dissolved | 410 | `GROUP_DISSOLVED` | "This group has been dissolved" | No recovery |
| 9 | No withdrawal endpoint | 404 | N/A | "Not Found" | Withdrawal is not supported by design |
| 10 | Treasury not initialized | 404 | `TREASURY_NOT_FOUND` | "Group treasury has not been initialized" | First contribution auto-creates |
| 11 | Spend reason too short | 422 | `VALIDATION_ERROR` | "reason: ensure this value has at least 3 characters" | Provide descriptive reason |
| 12 | CSRF token mismatch | 403 | `CSRF_MISMATCH` | "CSRF validation failed" | Refresh page |
| 13 | Rate limit (contributions) | 429 | `RATE_LIMITED` | "Too many contributions. Try again later." | Wait and retry |
| 14 | Goal negative value | 422 | `VALIDATION_ERROR` | "goal_cents: Input should be >= 0" | Use non-negative value |
| 15 | Concurrent overdraft race | 400 | `CONDITIONAL_CHECK_FAILED` | "Balance changed during operation. Please retry." | Retry the operation |

---

## 8. Pydantic Model Definitions

```python
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal, List


class ContributeIn(BaseModel):
    amount_cents: int = Field(..., ge=100, le=10000000)  # $1.00 - $100,000.00

    @field_validator("amount_cents")
    @classmethod
    def amount_must_be_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Contribution amount must be positive")
        return v


class SpendIn(BaseModel):
    amount_cents: int = Field(..., ge=1)
    reason: str = Field(..., min_length=3, max_length=500)
    category: Literal["ad_spend", "event", "premium_feature", "other"] = "ad_spend"
    reference_id: Optional[str] = Field(default=None, max_length=200)

    @field_validator("reason")
    @classmethod
    def reason_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Spend reason cannot be blank")
        return v


class SetGoalIn(BaseModel):
    goal_cents: Optional[int] = Field(default=None, ge=0)  # None to clear goal


class TreasuryBalanceOut(BaseModel):
    balance_cents: int
    currency: str = "usd"
    total_contributed_cents: int
    total_donated_cents: int
    total_spent_cents: int
    fundraising_goal_cents: Optional[int] = None


class TreasuryLedgerEntry(BaseModel):
    entry_id: str
    amount_cents: int
    currency: str = "usd"
    direction: Literal["credit", "debit"]
    reason: str
    category: Literal["contribution", "donation", "ad_spend", "event",
                       "premium_feature", "other", "refund",
                       "dissolution_return", "escrow_transfer"]
    actor_user_id: Optional[str] = None
    actor_display_name: Optional[str] = None
    reference_id: Optional[str] = None
    created_at: int


class TreasuryLedgerResponse(BaseModel):
    entries: List[TreasuryLedgerEntry]
    cursor: Optional[str] = None
    has_more: bool = False


class ContributorOut(BaseModel):
    user_id: str
    display_name: str
    total_contributed_cents: int
    contribution_count: int
    first_contributed_at: int
    last_contributed_at: int


class ContributorListResponse(BaseModel):
    contributors: List[ContributorOut]
    count: int


class ContributeResponse(BaseModel):
    ok: bool = True
    balance_cents: int
    personal_balance_cents: int
    contribution_total_cents: int
    ledger_entry_id: str


class SpendResponse(BaseModel):
    ok: bool = True
    balance_cents: int
    total_spent_cents: int
    ledger_entry_id: str
```

---

## 9. Frontend Component Tree

```
GroupTreasuryPage (route: /groups/:groupId/treasury)
├── TreasuryHeader
│   ├── BalanceCard
│   │   ├── CurrentBalance (large, prominent)
│   │   ├── TotalContributed (green)
│   │   ├── TotalDonated (blue)
│   │   └── TotalSpent (red)
│   └── GoalProgressBar (admin can edit goal)
├── TabNav (Transactions | Contributors | Contribute)
├── ContributeSection (any member)
│   ├── PersonalWalletBalance (show available)
│   ├── AmountInput
│   ├── AmountPresets ($10, $25, $50, $100)
│   └── ContributeButton
├── TransactionHistory (infinite scroll)
│   └── LedgerEntryRow[]
│       ├── DirectionIcon (green arrow up / red arrow down)
│       ├── Amount (formatted as dollars)
│       ├── CategoryBadge (contribution/donation/ad_spend/etc.)
│       ├── Reason
│       ├── ActorName
│       └── Timestamp (relative)
├── ContributorsList
│   └── ContributorRow[]
│       ├── DisplayName
│       ├── TotalContributed
│       ├── ContributionCount
│       └── LastContributedAt
└── AdminSpendSection (admin only)
    ├── AmountInput
    ├── ReasonInput
    ├── CategorySelect (ad_spend/event/premium_feature/other)
    └── SpendButton

TreasuryWidget (embedded on GroupPage sidebar)
├── BalanceSummary (compact)
├── GoalProgress (if goal set)
├── ContributeQuickAction
└── ViewFullTreasury link
```

### TypeScript Props Interfaces

```typescript
interface TreasuryHeaderProps {
  balance: TreasuryBalance;
  isAdmin: boolean;
  onEditGoal: () => void;
}

interface ContributeSectionProps {
  groupId: string;
  personalBalance: number;
  onContributed: () => void;
}

interface LedgerEntryRowProps {
  entry: TreasuryLedgerEntry;
}

interface ContributorRowProps {
  contributor: Contributor;
  rank: number;
  totalTreasuryContributed: number;
}

interface AdminSpendSectionProps {
  groupId: string;
  treasuryBalance: number;
  onSpent: () => void;
}

interface TreasuryWidgetProps {
  groupId: string;
  balance: TreasuryBalance;
  isMember: boolean;
  onContribute: () => void;
}

interface GoalProgressBarProps {
  currentCents: number;
  goalCents: number;
  currency: string;
}

interface AmountPresetsProps {
  amounts: number[];
  selectedAmount: number | null;
  onSelect: (cents: number) => void;
  maxAmount: number;
}
```

---

## 10. Frontend Types & API

### Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface TreasuryBalance {
  balance_cents: number; currency: string;
  total_contributed_cents: number; total_donated_cents: number;
  total_spent_cents: number; fundraising_goal_cents?: number;
}
export interface TreasuryLedgerEntry {
  entry_id: string; amount_cents: number; currency: string;
  direction: "credit" | "debit"; reason: string; category: string;
  actor_user_id?: string; actor_display_name?: string;
  reference_id?: string; created_at: number;
}
export interface Contributor {
  user_id: string; display_name: string;
  total_contributed_cents: number; contribution_count: number;
  first_contributed_at: number; last_contributed_at: number;
}
```

### Frontend API (`frontend/src/api/endpoints/groups.ts`)

```typescript
export const getTreasuryBalance = (groupId: string) =>
  api.get<TreasuryBalance>(`/ui/groups/${groupId}/treasury`);

export const contributeToTreasury = (groupId: string, amountCents: number) =>
  api.post(`/ui/groups/${groupId}/treasury/contribute`, { amount_cents: amountCents });

export const getTreasuryLedger = (groupId: string, params?: { cursor?: string; limit?: number }) =>
  api.get(`/ui/groups/${groupId}/treasury/ledger`, { params });

export const getTreasuryContributors = (groupId: string) =>
  api.get(`/ui/groups/${groupId}/treasury/contributors`);

export const setFundraisingGoal = (groupId: string, goalCents: number | null) =>
  api.patch(`/ui/groups/${groupId}/treasury/goal`, { goal_cents: goalCents });

export const spendTreasury = (groupId: string, data: {
  amount_cents: number; reason: string; category?: string; reference_id?: string;
}) => api.post(`/ui/groups/${groupId}/treasury/spend`, data);
```

---

## 11. Observability

### 11.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `treasury_contribution_total` | Counter | `group_id` | Total contributions received |
| `treasury_contribution_amount_cents` | Histogram | `group_id` | Contribution amounts distribution |
| `treasury_spend_total` | Counter | `group_id`, `category` | Spending events |
| `treasury_spend_amount_cents` | Histogram | `group_id`, `category` | Spend amounts distribution |
| `treasury_balance_cents` | Gauge | `group_id` | Current balance (sampled) |
| `treasury_overdraft_rejected_total` | Counter | `group_id`, `type` (personal/treasury) | Overdraft protection triggers |
| `treasury_dissolution_total` | Counter | None | Group treasury dissolutions |
| `treasury_dissolution_refund_cents` | Histogram | None | Per-contributor refund amounts |

### 11.2 Structured Logging

```python
logger.info("treasury.contribute",
    extra={
        "group_id": group_id,
        "user_id": user_id,
        "amount_cents": amount_cents,
        "new_balance_cents": new_balance,
        "contributor_total_cents": contributor_total,
    })

logger.info("treasury.spend",
    extra={
        "group_id": group_id,
        "admin_id": admin_id,
        "amount_cents": amount_cents,
        "category": category,
        "reason": reason,
        "reference_id": reference_id,
        "remaining_balance_cents": remaining,
    })

logger.info("treasury.dissolution",
    extra={
        "group_id": group_id,
        "remaining_balance": remaining,
        "contributor_count": len(contributors),
        "contribution_ratio": contribution_ratio,
        "total_refunded_cents": total_refunded,
        "escrow_amount_cents": escrow_amount,
    })

logger.warning("treasury.overdraft_rejected",
    extra={
        "group_id": group_id,
        "user_id": user_id,
        "requested_cents": amount_cents,
        "available_cents": available,
        "type": "personal" if is_personal else "treasury",
    })
```

### 11.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High overdraft rejection rate | `rate(treasury_overdraft_rejected) > 10/min` for 5 min | Warning | May indicate UI not showing balance correctly |
| Dissolution refund failure | `treasury_dissolution_error_total > 0` | Critical | Manual intervention; contributor wallets may be inconsistent |
| Large single contribution | `treasury_contribution_amount_cents > 100000` (>$1000) | Info | Monitor for potential abuse |
| Treasury balance exceeds $10K | `treasury_balance_cents > 1000000` | Info | Notify group admin of large balance |

---

## 12. Rollout Plan

### 12.1 Feature Flag

```python
# app/core/settings.py
group_treasury_enabled: bool = True  # GROUP_TREASURY_ENABLED env var
```
<!-- NOTE: group_treasury_enabled setting does not exist yet in app/core/settings.py — must be added -->

### 12.2 Phased Rollout

| Phase | Scope | Duration | Flag State | Success Criteria |
|-------|-------|----------|------------|-----------------|
| 1 - Internal | Dev team only | 3 days | Enabled in dev | All E2E pass; ledger entries accurate |
| 2 - Beta | 10% of groups | 5 days | Percentage rollout | No overdraft bugs; dissolution tested on 3 groups |
| 3 - General | All groups | 5 days | Enabled for all | Error rate < 0.1%; balance consistency verified |
| 4 - Stable | Remove flag | 1 day | Flag removed | Clean up |

### 12.3 Rollback Plan

1. Set `GROUP_TREASURY_ENABLED=false`.
2. Treasury endpoints return 404; existing balances preserved.
3. Contributions and spending blocked; no data loss.
4. Dissolution still works (triggered by GROUP-001, not gated by flag).

---

## 13. Performance Considerations

| # | Concern | Target | Mitigation |
|---|---------|--------|------------|
| 1 | Ledger growth | Consistent pagination | Cursor-based with `Limit=20`; SK sort efficient |
| 2 | Contribution tracker updates | < 50ms | Atomic `update_item` with `if_not_exists`; single DDB call |
| 3 | Treasury balance accuracy | Exact | Atomic `apply_wallet_delta`; no read-modify-write races |
| 4 | Dissolution with many contributors | < 5s for 100 contributors | Linear scan of CONTRIB records; batch writes for > 25 |
| 5 | Concurrent contributions | No lost writes | DDB conditional expressions + atomic ADD |
| 6 | Personal + treasury ledger consistency | Eventual | Two separate writes; if treasury credit succeeds but personal ledger fails, background reconciliation job |
| 7 | Goal progress calculation | < 10ms | Client-side: `balance / goal * 100` |

### 13.1 Caching Strategy

- **Treasury balance**: React Query `staleTime: 10_000` (10 seconds). Invalidated on contribute/spend.
- **Ledger entries**: `staleTime: 30_000` (30 seconds). Invalidated on new entry.
- **Contributors**: `staleTime: 60_000` (1 minute). Rarely changes.

### 13.2 Pagination Strategy

```typescript
const { data, fetchNextPage, hasNextPage } = useInfiniteQuery({
  queryKey: ["treasury-ledger", groupId],
  queryFn: ({ pageParam }) => getTreasuryLedger(groupId, { cursor: pageParam, limit: 20 }),
  getNextPageParam: (lastPage) => lastPage.has_more ? lastPage.cursor : undefined,
});
```

---

## 14. Implementation Plan

### 14.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/group_treasury.py` | Balance, contributions, spending, dissolution | <!-- new -->
| `app/routers/group_treasury.py` | REST endpoints | <!-- new -->
| `frontend/src/pages/groups/GroupTreasuryPage.tsx` | Treasury management page | <!-- new -->
| `frontend/src/pages/groups/TreasuryWidget.tsx` | Balance widget | <!-- new -->

### 14.2 Files to Modify

| File | Changes |
|------|---------|
| `app/main.py` | Register group_treasury router |
| `app/models.py` | Add treasury Pydantic models |
| `app/services/user_groups.py` | Hook `dissolve_treasury` into `dissolve_group` | <!-- NOTE: app/services/user_groups.py does not exist yet — must be created by GROUP-001 -->
| `frontend/src/api/types.ts` | Add treasury types |
| `frontend/src/api/endpoints/groups.ts` | Add treasury API functions |
| `frontend/src/App.tsx` | Add route |
| `frontend/src/pages/groups/GroupPage.tsx` | Add TreasuryWidget + nav link |

---

## 15. E2E Test Plan

### 15.1 Test File

`frontend/e2e/group-treasury.spec.ts` -- 24 tests across 6 sections.

### 15.2 Test Setup

```typescript
const TS = Date.now();
let groupId: string;
let dissolveGroupId: string;
// Alice = admin, Bob = member, Charlie = non-member
// Seed personal wallets via DDB direct write (Alice: $500, Bob: $300)
// Create second group + seed contributions for dissolution test
```

### 15.3 Section 459: Treasury Balance & Contribution API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 459.1 | Get balance (initially zero) | GET treasury; 200; `balance_cents=0` |
| 459.2 | Alice contributes | POST contribute `amount_cents=5000`; 200; `balance_cents=5000` |
| 459.3 | Bob contributes | POST as Bob `amount_cents=3000`; 200; `balance_cents=8000` |
| 459.4 | Insufficient wallet fails | POST `amount_cents=99999999`; 400; "Insufficient wallet balance" |

### 15.4 Section 460: Ledger & Contributors API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 460.1 | Ledger shows contributions | GET ledger; entries include Alice and Bob credits |
| 460.2 | Contributors list | GET contributors; Alice=5000, Bob=3000 |
| 460.3 | Admin spends treasury | POST spend; balance decreased; debit entry in ledger |
| 460.4 | Non-admin cannot spend | POST as Bob; 403 |

### 15.5 Section 461: Goal & Withdrawal Block API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 461.1 | Set fundraising goal | PATCH goal `goal_cents=100000`; 200; `fundraising_goal_cents=100000` |
| 461.2 | Clear goal | PATCH `goal_cents=null`; 200; `fundraising_goal_cents=null` |
| 461.3 | Non-member cannot view treasury | GET as Charlie; 403 |
| 461.4 | No withdrawal endpoint | POST `/ui/groups/{id}/treasury/withdraw`; 404 or 405 |

### 15.6 Section 462: Dissolution Pro-Rata API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 462.1 | Dissolution returns contributions pro-rata | DELETE group; Alice gets ~62.5%; Bob gets ~37.5% |
| 462.2 | External donations to escrow | `PLATFORM#ESCROW` balance increased |
| 462.3 | Treasury balance zeroed after dissolution | GET treasury; 410 (group dissolved) |
| 462.4 | Personal wallets credited | GET Alice wallet; Bob wallet; balances increased |

### 15.7 Section 463: Treasury UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 463.1 | Treasury page shows balance and ledger | Navigate treasury; `[data-testid="group-treasury-page"]`; balance + entries visible |
| 463.2 | Contribute UI updates balance | Enter amount; submit; balance increases |
| 463.3 | Goal progress bar displays | Set goal; navigate; progress bar shows percentage |
| 463.4 | Admin sees spend section | As Alice (admin); spend section visible; as Bob (member); spend section hidden |

### 15.8 Section 464: Edge Cases & Negative Tests (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 464.1 | Contribute below minimum fails | POST amount_cents=50; 422 |
| 464.2 | Spend with invalid category fails | POST spend with category="withdrawal"; 400 |
| 464.3 | Spend exceeding balance fails | POST spend amount > balance; 400 "Insufficient treasury" |
| 464.4 | Concurrent contributions both succeed | Two parallel POSTs; both return 200; balance = sum |

---

## 16. Security Considerations

- **No-withdrawal enforcement**: No withdraw endpoint exists. `spend_treasury` validates category against allowlist and only debits treasury (never credits personal wallet). Only `dissolve_treasury` (system-triggered) moves funds to personal wallets.
- **Overdraft protection**: `apply_wallet_delta` uses DDB conditional expressions (`wallet_balance_cents >= needed`). Applies to both personal debits and treasury debits.
- **Financial transparency**: All members can view balance, ledger, and contributor list. Every transaction has actor, reason, category, and reference.
- **Dissolution integrity**: Pro-rata uses integer arithmetic. Rounding remainders stay in treasury (zeroed at end). Dissolution is irreversible.
- **Rate limiting**: Contributions 10/hour per user. Spending 10/hour per admin. Reads 60/min per user.

---

## 17. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| GROUP-001 (Membership) | GROUP-001 | Required -- membership check, dissolution hook |
| Billing shared | Existing | Available (`apply_wallet_delta`, `new_ledger_entry`) |
| Billing table | Existing | Available (reused with `GROUP#{group_id}` PK) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| GROUP-003 (Advertising) | `spend_treasury` for campaign funding |
| GROUP-003 (Fundraising) | `credit_donation` for incoming donations |

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| `apply_wallet_delta()` | `app/services/billing_shared.py` | 178 | Atomic wallet balance update with overdraft protection; accepts `table`, `pk`, `delta_cents` |
| `get_wallet_balance()` | `app/services/billing_shared.py` | 169 | Returns `wallet_balance_cents`, `currency`, `updated_at` |
| `new_ledger_entry()` | `app/services/billing_shared.py` | 217 | Uses `entry_type` param mapped to `type` field, plus `state`, `reason`; NOT `direction` |
| `ledger_sk()` | `app/services/billing_shared.py` | 213 | Constructs `LEDGER#{ts}#{entry_id}` sort key |
| `WALLET_SK` constant | `app/services/billing_shared.py` | 166 | `"WALLET"` — SK value for wallet records |
| `billing` DDB table | `scripts/local-ddb-init.py` | 59 | PK=pk, SK=sk; no GSIs; stores USER# and GROUP# records |
| `T.billing` table handle | `app/core/tables.py` | 146 | `ddb.Table(S.billing_table_name)` |
| `billing_table_name` setting | `app/core/settings.py` | 321 | `DDB_BILLING_TABLE` env var |
| `user_groups` table | — | — | Does not exist yet; must be created by GROUP-001 |
| `app/services/user_groups.py` | — | — | Does not exist yet; must be created by GROUP-001 |
| `group_treasury_enabled` setting | — | — | Does not exist yet in settings.py |
