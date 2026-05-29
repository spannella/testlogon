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

GROUP-004 implements a shared treasury (wallet) for user groups. The treasury collects funds from member contributions (personal wallets) and external donations (GROUP-003). The admin can spend treasury on advertising campaigns (GROUP-003). Critical rule — matching syndicate behavior: contributed funds cannot be withdrawn by the admin. Funds must be spent on group activities or returned to contributors if the group dissolves. Full transaction history provides financial transparency.

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

Groups need a financial primitive to fund activities. Without shared treasury, all spending falls on the admin's personal wallet — neither transparent nor sustainable. The no-withdrawal rule ensures trust, and dissolution refunds protect contributors.

### 1.4 Treasury Flow

```
Member contributions + External donations → Treasury Balance
  → Spend on ads/activities (admin authorized)
  → On dissolution: contributions → pro-rata return; donations → escrow
```

### 1.5 No-Withdrawal Rule

The admin CANNOT transfer treasury to any personal wallet. Funds leave the treasury only via: (1) authorized spending on group activities, (2) dissolution refunds (system-triggered), or (3) admin-approved contributor refund (up to contributor's total minus spent share).

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Wallet** (`app/services/billing_shared.py`): `billing` table with `pk=USER#{user_sub}`, `sk=WALLET`, `wallet_balance_cents`. `apply_wallet_delta()` atomically updates with overdraft protection via conditional expressions. Reusable for group treasury with `pk=GROUP#{group_id}`.
- **Ledger**: `new_ledger_entry()` writes `sk=LEDGER#{ts}#{entry_id}` with `amount_cents`, `currency`, `reason`, `direction`. Same function works with group PK.
- **Group dissolution** (GROUP-001): `dissolve_group()` sets status to `dissolved`. GROUP-004 hooks into this to return funds before membership cleanup.

### 2.2 Gaps

1. No group treasury balance record.
2. No contribution endpoint or tracking.
3. No treasury ledger.
4. No spend authorization mechanism.
5. No dissolution fund-return logic.
6. No withdrawal block enforcement.
7. No frontend treasury page.

---

## 3. Technical Design

### 3.1 Data Model (in `billing` table)

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
| `direction` | S | `credit` or `debit` |
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

### 3.2 Backend Service (`app/services/group_treasury.py`)

| Function | Description |
|----------|-------------|
| `get_treasury_balance(group_id)` | Return balance, totals, goal from WALLET record |
| `contribute(group_id, user_id, amount_cents, display_name)` | Debit user wallet → credit treasury → ledger both sides → update CONTRIB tracker → increment `total_contributed_cents` |
| `credit_donation(group_id, amount_cents, donor_name, donation_id)` | Credit treasury → ledger → increment `total_donated_cents`. Called by GROUP-003 |
| `spend_treasury(group_id, admin_id, amount_cents, reason, category, reference_id)` | Verify admin + allowed category → debit treasury → ledger → increment `total_spent_cents` |
| `list_treasury_ledger(group_id, cursor, limit)` | Query `LEDGER#` prefix, `ScanIndexForward=False`, paginated |
| `list_contributors(group_id)` | Query `CONTRIB#` prefix, sorted by total desc |
| `set_fundraising_goal(group_id, admin_id, goal_cents)` | Update WALLET with goal (or REMOVE if null) |
| `dissolve_treasury(group_id)` | Calculate contribution vs donation ratio → return contributions pro-rata → send donations to `PLATFORM#ESCROW` → zero balance → log |

**Allowed spend categories**: `{"ad_spend", "event", "premium_feature", "other"}` — validated in `spend_treasury`.

**Dissolution algorithm**:
1. Get remaining balance, `total_contributed_cents`, `total_donated_cents`.
2. Compute `contribution_ratio = total_contributed / (total_contributed + total_donated)`.
3. `contribution_remaining = remaining * contribution_ratio` (integer).
4. For each contributor: `share = contribution_remaining * their_total / total_contributed`.
5. Credit each contributor's personal wallet + ledger entry.
6. Send `donation_remaining = remaining - contribution_remaining` to `PLATFORM#ESCROW`.
7. Zero out treasury balance.

### 3.3 Withdrawal Block

No `withdraw` endpoint exists in the router — FastAPI returns 404/405. `spend_treasury` validates category against allowlist and only debits the group treasury (does not credit any personal wallet). The only treasury-to-wallet path is `dissolve_treasury`, which is triggered by group dissolution.

### 3.4 Backend Router (`app/routers/group_treasury.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/groups/{group_id}/treasury` | `require_ui_session` | Balance + metadata (any member) |
| POST | `/ui/groups/{group_id}/treasury/contribute` | `require_ui_session` | Contribute (any member) |
| GET | `/ui/groups/{group_id}/treasury/ledger` | `require_ui_session` | Transaction history (any member) |
| GET | `/ui/groups/{group_id}/treasury/contributors` | `require_ui_session` | Contributor list (any member) |
| PATCH | `/ui/groups/{group_id}/treasury/goal` | `require_ui_session` | Set goal (admin) |
| POST | `/ui/groups/{group_id}/treasury/spend` | `require_ui_session` | Spend (admin) |

All endpoints verify membership. Spend and goal endpoints verify admin role.

**Request models**: `ContributeIn(amount_cents ge=100 le=10000000)`, `SpendIn(amount_cents ge=1, reason, category, reference_id?)`, `SetGoalIn(goal_cents? ge=0)`.

### 3.5 Pydantic Models (`app/models.py`)

```python
class TreasuryBalanceOut(BaseModel):
    balance_cents: int; currency: str = "usd"
    total_contributed_cents: int; total_donated_cents: int; total_spent_cents: int
    fundraising_goal_cents: Optional[int] = None

class TreasuryLedgerEntry(BaseModel):
    entry_id: str; amount_cents: int; currency: str
    direction: str; reason: str; category: str
    actor_user_id: Optional[str] = None; actor_display_name: Optional[str] = None
    reference_id: Optional[str] = None; created_at: int

class ContributorOut(BaseModel):
    user_id: str; display_name: str; total_contributed_cents: int
    contribution_count: int; first_contributed_at: int; last_contributed_at: int
```

### 3.6 Frontend Types (`frontend/src/api/types.ts`)

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

### 3.7 Frontend API (`frontend/src/api/endpoints/groups.ts`)

Extend with: `getTreasuryBalance(groupId)`, `contributeToTreasury(groupId, amountCents)`, `getTreasuryLedger(groupId, params)`, `getTreasuryContributors(groupId)`, `setFundraisingGoal(groupId, goalCents)`, `spendTreasury(groupId, data)`.

### 3.8 Frontend Pages

- **GroupTreasuryPage** (`frontend/src/pages/groups/GroupTreasuryPage.tsx`): Route `/groups/:groupId/treasury`. Balance card (balance, contributed, donated, spent). Fundraising goal progress bar (admin can edit). Contribute section: amount input + personal wallet balance + "Contribute" button. Transaction history: paginated ledger with infinite scroll (green credits, red debits, category badge, actor name). Contributors tab: ranked list. Admin-only: "Spend" button. `data-testid="group-treasury-page"`.
- **TreasuryWidget**: Embeddable on GroupPage sidebar. Balance, goal progress, "Contribute" quick-action. Links to full treasury page.

### 3.9 Routes & Navigation

Add to `App.tsx`: `<Route path="/groups/:groupId/treasury" element={<GroupTreasuryPage />} />`.

Add "Treasury" link with `Wallet` icon to GroupPage navigation (visible to members).

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/group_treasury.py` | Balance, contributions, spending, dissolution |
| `app/routers/group_treasury.py` | REST endpoints |
| `frontend/src/pages/groups/GroupTreasuryPage.tsx` | Treasury management page |
| `frontend/src/pages/groups/TreasuryWidget.tsx` | Balance widget |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/main.py` | Register group_treasury router |
| `app/models.py` | Add treasury Pydantic models |
| `app/services/user_groups.py` | Hook `dissolve_treasury` into `dissolve_group` |
| `frontend/src/api/types.ts` | Add treasury types |
| `frontend/src/api/endpoints/groups.ts` | Add treasury API functions |
| `frontend/src/App.tsx` | Add route |
| `frontend/src/pages/groups/GroupPage.tsx` | Add TreasuryWidget + nav link |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/group-treasury.spec.ts` — 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let groupId: string;
let dissolveGroupId: string;
// Alice = admin, Bob = member
// Seed personal wallets via DDB direct write
// Create second group + seed contributions for dissolution test
```

### 5.3 Section 459: Treasury Balance & Contribution API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 459.1 | Get balance (initially zero) | GET treasury; 200; `balance_cents=0` |
| 459.2 | Alice contributes | POST contribute `amount_cents=5000`; 200; `balance_cents=5000` |
| 459.3 | Bob contributes | POST as Bob `amount_cents=3000`; 200; `balance_cents=8000` |
| 459.4 | Insufficient wallet fails | POST `amount_cents=99999999`; 400; "Insufficient wallet balance" |

### 5.4 Section 460: Ledger & Contributors API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 460.1 | Ledger shows contributions | GET ledger; entries include Alice and Bob credits |
| 460.2 | Contributors list | GET contributors; Alice=5000, Bob=3000 |
| 460.3 | Admin spends treasury | POST spend; balance decreased; debit entry in ledger |
| 460.4 | Non-admin cannot spend | POST as Bob; 403 |

### 5.5 Section 461: Goal & Withdrawal Block API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 461.1 | Set fundraising goal | PATCH goal `goal_cents=100000`; 200; `fundraising_goal_cents=100000` |
| 461.2 | Clear goal | PATCH `goal_cents=null`; 200; `fundraising_goal_cents=null` |
| 461.3 | Non-member cannot view treasury | GET as Charlie; 403 |
| 461.4 | No withdrawal endpoint | POST `/ui/groups/{id}/treasury/withdraw`; 404 or 405 |

### 5.6 Section 462: Dissolution & UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 462.1 | Dissolution returns contributions pro-rata | DELETE group; Alice gets ~62.5%; Bob gets ~37.5% |
| 462.2 | External donations to escrow | `PLATFORM#ESCROW` balance increased |
| 462.3 | Treasury page shows balance and ledger | Navigate treasury; `[data-testid="group-treasury-page"]`; balance + entries visible |
| 462.4 | Contribute UI updates balance | Enter amount; submit; balance increases |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Not a member | 403 | "Not a member of this group" |
| Not admin (spend/goal) | 403 | "Only the group admin can perform this action" |
| Insufficient wallet balance | 400 | "Insufficient wallet balance" |
| Insufficient treasury balance | 400 | "Insufficient treasury balance" |
| Contribution below minimum | 422 | Pydantic: `ge=100` ($1.00) |
| Invalid spend category | 400 | "Invalid spend category" |
| Group dissolved | 410 | "This group has been dissolved" |

---

## 7. Security Considerations

- **No-withdrawal enforcement**: No withdraw endpoint exists. `spend_treasury` validates category against allowlist and only debits treasury (never credits personal wallet). Only `dissolve_treasury` (system-triggered) moves funds to personal wallets.
- **Overdraft protection**: `apply_wallet_delta` uses DDB conditional expressions (`wallet_balance_cents >= needed`). Applies to both personal debits and treasury debits.
- **Financial transparency**: All members can view balance, ledger, and contributor list. Every transaction has actor, reason, category, and reference.
- **Dissolution integrity**: Pro-rata uses integer arithmetic. Rounding remainders stay in treasury (zeroed at end). Dissolution is irreversible.
- **Rate limiting**: Contributions 10/hour per user. Spending 10/hour per admin. Reads 60/min per user.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Ledger growth | Cursor pagination with `Limit=20`; SK sort ensures efficient range queries |
| Contribution tracker updates | Atomic `update_item` with `if_not_exists`; single DDB call |
| Treasury balance accuracy | Atomic `apply_wallet_delta`; no read-modify-write races |
| Dissolution with many contributors | Linear scan of CONTRIB records; batch for >10K (future) |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| GROUP-001 (Membership) | GROUP-001 | Required — membership check, dissolution hook |
| Billing shared | Existing | Available (`apply_wallet_delta`, `new_ledger_entry`) |
| Billing table | Existing | Available (reused with `GROUP#{group_id}` PK) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| GROUP-003 (Advertising) | `spend_treasury` for campaign funding |
| GROUP-003 (Fundraising) | `credit_donation` for incoming donations |
