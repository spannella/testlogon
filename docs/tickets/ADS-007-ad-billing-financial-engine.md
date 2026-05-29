# ADS-007: Ad Billing & Financial Engine

**Ticket**: ADS-007
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Dependencies**: ADS-001 (Accounts), ADS-004 (Ad Serving — impression tracking)

---

## 1. Overview & Motivation

### 1.1 Purpose

ADS-007 implements the complete financial system for the advertising platform. It covers three billing models (CPM, CPC, CPA), advertiser wallet management, budget enforcement, revenue sharing between the platform and content creators, invoice generation, and spending alerts. This ticket connects the ad serving engine's impression/click tracking to actual financial transactions.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Advertiser | As an advertiser, I want to deposit funds into my ad account. | POST deposit; wallet balance increases; payment method charged. |
| Advertiser | As an advertiser, I want to see my spending history. | Billing ledger with entries per impression/click charge. |
| Advertiser | As an advertiser, I want monthly invoices. | GET invoices; itemized PDF-like breakdown per campaign. |
| Advertiser | As an advertiser, I want spending alerts at 50%, 80%, 100% of budget. | In-app alert when budget thresholds crossed. |
| Creator | As a creator, I want to see my ad revenue share. | Creator dashboard shows ad revenue credited to billing ledger. |
| Platform | As the platform, I want to take a configurable revenue share (default 30%). | Each impression generates platform + creator ledger entries. |

### 1.3 Financial Flow

```
Billing Flow (per tracked ad event)
────────────────────────────────────

track_ad_event()
    │
    ├── 1. Determine charge amount
    │   ├── CPM: charge = bid_cpm / 1000 (per impression)
    │   ├── CPC: charge = bid_cpc (per click only)
    │   └── CPA: charge = bid_cpa (per conversion only)
    │
    ├── 2. Debit advertiser account
    │   └── ad_billing: LEDGER entry (type=impression_charge / click_charge)
    │   └── ad_accounts: decrement balance_cents, increment lifetime_spend_cents
    │   └── ad_campaigns: increment spent_today_cents + lifetime_spent_cents
    │
    ├── 3. Revenue split
    │   ├── Platform share (30%): ad_billing: LEDGER entry (type=platform_revenue)
    │   └── Creator share (70%): billing: LEDGER entry (type=ad_revenue_credit)
    │       └── Reuses existing creator billing ledger pattern
    │
    ├── 4. Budget check
    │   └── If spent >= budget → auto-pause campaign
    │
    └── 5. Spending alert check
        └── If crossing 50% / 80% / 100% threshold → write_alert()
```

### 1.4 Revenue Split Detail

```
$5 CPM (500 cents per 1000 impressions)
─────────────────────────────────────────
Per impression charge: 500 / 1000 = 0.5 cents (rounded to 1 cent minimum)

Revenue split (per impression):
  Advertiser debited:    1 cent
  Platform receives:     0.3 cents (30%) → rounded to 0 or 1
  Creator receives:      0.7 cents (70%) → rounded to 1 or 0

Rounding: uses integer cent accounting. Each impression credits at least 1 cent
to the creator (platform absorbs rounding loss at low CPMs). At scale,
fractional cents accumulate correctly.
```

---

## 2. Current State Analysis

### 2.1 Existing Billing Ledger (`app/services/billing_shared.py`)

The `billing` table stores user-scoped ledger entries with pattern `pk=USER#{user_sub}`, `sk=LEDGER#{ts}#{entry_id}`. The `new_ledger_entry()` helper (line 217) generates entries with `entry_type`, `amount_cents`, `state`, `reason`, and `meta`. This is used for tips, unlock payments, subscription charges, and ad revenue credits.

The existing `_credit_ad_revenue()` function in `ad_placement.py` (line 279) uses `new_ledger_entry()` to credit creators. ADS-007 adds the debit side (charging the advertiser) and the platform revenue split.

### 2.2 Advertiser Account Balance (ADS-001)

The `ad_accounts` table has `balance_cents` and `lifetime_spend_cents` fields. ADS-007 manages these fields through deposit and charge operations.

### 2.3 Campaign Budget (ADS-001)

The `ad_campaigns` table has `budget_cents`, `budget_type`, `daily_budget_cents`, `spent_today_cents`, and `lifetime_spent_cents`. ADS-007 increments spend counters on each charge and auto-pauses campaigns when budget is exhausted.

### 2.4 Alert System (`app/services/alerts.py`)

The `write_alert()` function (line 265) creates in-app alerts. Spending alerts follow the same pattern with `event="ad_budget_alert"`.

### 2.5 Gaps

1. **No ad billing table** — no separate ledger for advertiser transactions.
2. **No deposit endpoint** — no way to add funds to ad account.
3. **No charge-on-impression** — impressions credit creators but don't debit advertisers.
4. **No CPC/CPA billing** — only CPM exists (hardcoded in ad_placement.py).
5. **No revenue split** — no platform share calculation.
6. **No invoice generation** — no monthly billing summaries.
7. **No spending alerts** — no notifications at budget thresholds.
8. **No daily budget reset** — `spent_today_cents` never resets to 0.

---

## 3. Technical Design

### 3.1 DynamoDB Table

#### `ad_billing` Table

| PK | SK | Fields |
|----|----|--------|
| `ACCT#{account_id}` | `LEDGER#{ts}#{entry_id}` | `entry_id`, `account_id`, `campaign_id`, `entry_type` (impression_charge/click_charge/conversion_charge/budget_deposit/refund/adjustment/platform_revenue), `amount_cents`, `state` (settled/pending/refunded), `reason`, `meta` (dict), `created_at` |

**GSIs**:

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|--------------|----------|---------|
| `ByCampaign` | `campaign_id` (S) | `created_at` (N) | Spending breakdown by campaign |
| `ByMonth` | `month_key` (S) | `created_at` (N) | Monthly invoice aggregation; month_key = "YYYY-MM" |

**`scripts/local-ddb-init.py`**:
```python
TableDef(
    os.environ.get("DDB_AD_BILLING", "AdBilling"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByCampaign", "partition_key": "campaign_id", "sort_key": "created_at"},
        {"index_name": "ByMonth", "partition_key": "month_key", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

### 3.2 Backend Service

**File**: `app/services/ad_billing.py`

```python
"""Ad billing engine — charges, revenue splits, invoices, spending alerts."""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import new_ledger_entry, user_pk
from app.services.alerts import write_alert

logger = logging.getLogger(__name__)

# Revenue share: platform takes this percentage, creator gets remainder
PLATFORM_REVENUE_SHARE_PCT = 30
MIN_DEPOSIT_CENTS = 5000  # $50 minimum deposit


def deposit_funds(account_id: str, amount_cents: int, payment_method_id: str = "") -> dict:
    """Add funds to advertiser account balance."""
    if amount_cents < MIN_DEPOSIT_CENTS:
        raise ValueError(f"Minimum deposit is ${MIN_DEPOSIT_CENTS // 100}")

    ts = now_ts()
    entry_id = f"dep_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # Write billing ledger entry
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"LEDGER#{ts}#{entry_id}",
        "entry_id": entry_id,
        "account_id": account_id,
        "campaign_id": "",
        "entry_type": "budget_deposit",
        "amount_cents": amount_cents,
        "state": "settled",
        "reason": "Account deposit",
        "meta": {"payment_method_id": payment_method_id},
        "month_key": month_key,
        "created_at": ts,
    })

    # Increment account balance
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": "META"},
        UpdateExpression="SET balance_cents = if_not_exists(balance_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": amount_cents},
    )

    return {"ok": True, "entry_id": entry_id, "new_balance_cents": _get_balance(account_id)}


def charge_impression(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpm_cents: int,
) -> dict:
    """Charge advertiser for one impression (CPM model)."""
    charge_cents = max(1, bid_cpm_cents // 1000)
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="impression_charge", charge_cents=charge_cents,
        creator_id=creator_id, reason="Ad impression",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpm"},
    )


def charge_click(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpc_cents: int,
) -> dict:
    """Charge advertiser for one click (CPC model)."""
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="click_charge", charge_cents=bid_cpc_cents,
        creator_id=creator_id, reason="Ad click",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpc"},
    )


def charge_conversion(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpa_cents: int,
) -> dict:
    """Charge advertiser for one conversion (CPA model)."""
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="conversion_charge", charge_cents=bid_cpa_cents,
        creator_id=creator_id, reason="Ad conversion",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpa"},
    )


def _process_charge(
    *, account_id: str, campaign_id: str, entry_type: str,
    charge_cents: int, creator_id: str, reason: str, meta: dict,
) -> dict:
    """Process a charge: debit advertiser, split revenue, check budget."""
    ts = now_ts()
    entry_id = f"chg_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # 1. Write charge to ad_billing ledger
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"LEDGER#{ts}#{entry_id}",
        "entry_id": entry_id,
        "account_id": account_id,
        "campaign_id": campaign_id,
        "entry_type": entry_type,
        "amount_cents": charge_cents,
        "state": "settled",
        "reason": reason,
        "meta": meta,
        "month_key": month_key,
        "created_at": ts,
    })

    # 2. Debit advertiser account balance
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": "META"},
        UpdateExpression="SET balance_cents = balance_cents - :amt, lifetime_spend_cents = lifetime_spend_cents + :amt",
        ExpressionAttributeValues={":amt": charge_cents},
    )

    # 3. Increment campaign spend
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET spent_today_cents = if_not_exists(spent_today_cents, :z) + :amt, "
                         "lifetime_spent_cents = if_not_exists(lifetime_spent_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": charge_cents},
    )

    # 4. Revenue split
    _split_revenue(charge_cents=charge_cents, creator_id=creator_id, meta=meta, ts=ts)

    # 5. Budget check + spending alerts
    _check_budget_and_alert(account_id, campaign_id)

    return {"ok": True, "entry_id": entry_id, "charge_cents": charge_cents}


def _split_revenue(*, charge_cents: int, creator_id: str, meta: dict, ts: int) -> None:
    """Split ad revenue between platform and creator."""
    platform_share = max(0, (charge_cents * PLATFORM_REVENUE_SHARE_PCT) // 100)
    creator_share = charge_cents - platform_share

    # Credit creator
    if creator_share > 0 and creator_id:
        try:
            _sk, credit_item = new_ledger_entry(
                key_name="pk",
                key_value=user_pk(creator_id),
                entry_type="ad_revenue_credit",
                amount_cents=creator_share,
                state="settled",
                reason="Ad revenue share",
                meta={**meta, "platform_share_pct": PLATFORM_REVENUE_SHARE_PCT},
            )
            T.billing.put_item(Item=credit_item)
        except Exception:
            logger.warning("ad_revenue_creator_credit_failed", extra={"creator_id": creator_id})


def _check_budget_and_alert(account_id: str, campaign_id: str) -> None:
    """Check if campaign budget thresholds are crossed; send alerts."""
    from app.services.ad_campaigns import get_campaign
    from app.services.ad_accounts import get_ad_account

    campaign = get_campaign(account_id, campaign_id)
    if not campaign:
        return

    budget = campaign.get("budget_cents", 0)
    spent = campaign.get("lifetime_spent_cents", 0)
    if budget <= 0:
        return

    pct = (spent * 100) // budget
    acct = get_ad_account(account_id)
    owner_sub = acct.get("owner_sub", "") if acct else ""

    for threshold in [50, 80, 100]:
        if pct >= threshold:
            # Check if alert already sent (use DDB conditional write)
            alert_sk = f"AD_BUDGET_ALERT#{campaign_id}#{threshold}"
            try:
                T.billing.put_item(
                    Item={
                        "pk": f"USER#{owner_sub}",
                        "sk": alert_sk,
                        "threshold": threshold,
                        "campaign_id": campaign_id,
                        "created_at": now_ts(),
                    },
                    ConditionExpression="attribute_not_exists(pk)",
                )
                # Alert not yet sent — send it
                write_alert(
                    owner_sub,
                    event="ad_budget_alert",
                    outcome="warning" if threshold < 100 else "critical",
                    title=f"Campaign budget {threshold}% spent",
                    details={
                        "campaign_id": campaign_id,
                        "campaign_name": campaign.get("name", ""),
                        "budget_cents": budget,
                        "spent_cents": spent,
                        "threshold_pct": threshold,
                    },
                )
            except T.ad_accounts.meta.client.exceptions.ConditionalCheckFailedException:
                pass  # Alert already sent for this threshold

    # Auto-pause if budget exhausted
    if pct >= 100:
        from app.services.ad_campaigns import update_campaign_status
        try:
            T.ad_campaigns.update_item(
                Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
                UpdateExpression="SET #s = :completed",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":completed": "completed"},
                ConditionExpression="#s = :active",
            )
        except Exception:
            pass  # Already paused/completed


def get_billing_history(account_id: str, limit: int = 50) -> list[dict]:
    """Get billing ledger entries for an account."""
    resp = T.ad_billing.query(
        KeyConditionExpression=Key("pk").eq(f"ACCT#{account_id}") & Key("sk").begins_with("LEDGER#"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])


def get_campaign_spending(campaign_id: str, limit: int = 100) -> list[dict]:
    """Get spending entries for a specific campaign."""
    resp = T.ad_billing.query(
        IndexName="ByCampaign",
        KeyConditionExpression=Key("campaign_id").eq(campaign_id),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])


def generate_invoice(account_id: str, month: str) -> dict:
    """Generate a monthly invoice summary.

    month format: "YYYY-MM"
    """
    resp = T.ad_billing.query(
        IndexName="ByMonth",
        KeyConditionExpression=Key("month_key").eq(month),
        FilterExpression=Attr("account_id").eq(account_id),
    )
    entries = resp.get("Items", [])

    # Aggregate by campaign and entry type
    campaign_totals = {}
    grand_total = 0
    for entry in entries:
        cid = entry.get("campaign_id", "unknown")
        etype = entry.get("entry_type", "unknown")
        amt = int(entry.get("amount_cents", 0))

        if etype in ("impression_charge", "click_charge", "conversion_charge"):
            grand_total += amt
            if cid not in campaign_totals:
                campaign_totals[cid] = {"campaign_id": cid, "impressions": 0, "clicks": 0, "conversions": 0, "total_cents": 0}
            if etype == "impression_charge":
                campaign_totals[cid]["impressions"] += 1
            elif etype == "click_charge":
                campaign_totals[cid]["clicks"] += 1
            elif etype == "conversion_charge":
                campaign_totals[cid]["conversions"] += 1
            campaign_totals[cid]["total_cents"] += amt

    deposits = sum(int(e.get("amount_cents", 0)) for e in entries if e.get("entry_type") == "budget_deposit")

    return {
        "account_id": account_id,
        "month": month,
        "campaigns": list(campaign_totals.values()),
        "total_charges_cents": grand_total,
        "total_deposits_cents": deposits,
        "entry_count": len(entries),
    }


def _get_balance(account_id: str) -> int:
    resp = T.ad_accounts.get_item(Key={"pk": f"ACCT#{account_id}", "sk": "META"})
    item = resp.get("Item")
    return int(item.get("balance_cents", 0)) if item else 0
```

### 3.3 Backend Router

**File**: `app/routers/ads.py` (extend)

```python
# ── Ad Billing ──

@router.post("/accounts/{account_id}/deposit")
def deposit_endpoint(account_id: str, body: dict, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    amount = body.get("amount_cents", 0)
    pm_id = body.get("payment_method_id", "")
    return deposit_funds(account_id, amount, pm_id)

@router.get("/accounts/{account_id}/billing")
def billing_history_endpoint(account_id: str, limit: int = 50, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    return get_billing_history(account_id, limit)

@router.get("/accounts/{account_id}/billing/campaigns/{campaign_id}")
def campaign_spending_endpoint(account_id: str, campaign_id: str, limit: int = 100, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    return get_campaign_spending(campaign_id, limit)

@router.get("/accounts/{account_id}/invoices/{month}")
def invoice_endpoint(account_id: str, month: str, ctx=Depends(require_ui_session)):
    _require_account_owner(account_id, ctx["user_sub"])
    return generate_invoice(account_id, month)
```

### 3.4 Frontend Pages

**File**: `frontend/src/pages/ads/AdBillingPage.tsx`

- Route: `/ads/billing`
- Account selector (for users with multiple ad accounts)
- Balance card: current balance, lifetime spend, deposit button
- Spending chart: daily spend over last 30 days (bar chart)
- Budget meters: per-campaign progress bars showing spent/budget
- Recent transactions: scrollable ledger list with entry type, amount, campaign, timestamp
- Invoice list: monthly invoices with "View" button
- Deposit dialog: amount input (minimum $50), payment method selector
- `data-testid="ad-billing-page"`

### 3.5 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface AdBillingEntry {
  entry_id: string;
  account_id: string;
  campaign_id: string;
  entry_type: string;
  amount_cents: number;
  state: string;
  reason: string;
  meta: Record<string, unknown>;
  created_at: number;
}

export interface AdInvoice {
  account_id: string;
  month: string;
  campaigns: Array<{
    campaign_id: string;
    impressions: number;
    clicks: number;
    conversions: number;
    total_cents: number;
  }>;
  total_charges_cents: number;
  total_deposits_cents: number;
  entry_count: number;
}
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_billing.py` | Billing engine: charges, deposits, splits, invoices |
| `frontend/src/pages/ads/AdBillingPage.tsx` | Billing dashboard with spending chart + invoice list |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/ads.py` | Add deposit, billing history, invoice endpoints |
| `app/services/ad_serving.py` | Call `charge_impression()` / `charge_click()` from `track_ad_event()` |
| `app/core/settings.py` | Add `ad_billing_table_name` |
| `app/core/tables.py` | Add `ad_billing` table handle |
| `scripts/local-ddb-init.py` | Add `AdBilling` table definition |
| `frontend/src/api/types.ts` | Add `AdBillingEntry`, `AdInvoice` types |
| `frontend/src/api/endpoints/ads.ts` | Add billing API functions |
| `frontend/src/App.tsx` | Add `/ads/billing` route |

### 4.3 Step-by-Step Order

1. Add DDB table definition
2. Add settings + table handle
3. Implement `ad_billing.py` service
4. Add billing endpoints to router
5. Wire `track_ad_event()` to billing charges
6. Add frontend types + API endpoints
7. Build AdBillingPage
8. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/ads-billing.spec.ts` — 20 tests across 5 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let accountId: string;
let campaignId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice (advertiser with active account)
  // Create campaign with budget_cents=10000
  // Inject payment method for deposit
});
```

### 5.3 Section 369: Deposit API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 369.1 | Deposit funds to ad account | POST `/ui/ads/accounts/{id}/deposit` amount_cents=10000; 200; new_balance_cents=10000 |
| 369.2 | Minimum deposit enforced | POST amount_cents=1000 ($10); 400; "Minimum deposit is $50" |
| 369.3 | Deposit creates billing entry | GET billing history; entry_type=budget_deposit, amount=10000 |
| 369.4 | Multiple deposits accumulate | Second deposit 5000; balance=15000 |

### 5.4 Section 370: Impression Charging (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 370.1 | Track impression creates charge | POST track event=impression; billing ledger has impression_charge entry |
| 370.2 | Advertiser balance decremented | Account balance decreased by charge amount |
| 370.3 | Campaign spend incremented | Campaign lifetime_spent_cents increased |
| 370.4 | Creator receives revenue share | Creator billing ledger has ad_revenue_credit entry; amount = 70% of charge |

### 5.5 Section 371: Budget Enforcement (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 371.1 | Campaign auto-pauses at 100% budget | Set budget=100, spend impressions until spent>=100; campaign status=completed |
| 371.2 | Spending alert at 50% | Spend to 50% of budget; alert with "budget 50% spent" exists |
| 371.3 | Spending alert at 80% | Spend to 80%; alert with "budget 80% spent" exists |
| 371.4 | Daily budget reset works | Set budget_type=daily; spend today; verify spent_today_cents tracks correctly |

### 5.6 Section 372: Invoice Generation (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 372.1 | Generate monthly invoice | GET `/ui/ads/accounts/{id}/invoices/YYYY-MM`; 200; has campaigns array |
| 372.2 | Invoice aggregates by campaign | Invoice campaigns array has correct impression/click counts |
| 372.3 | Invoice shows total charges | total_charges_cents matches sum of campaign totals |
| 372.4 | Invoice shows deposits | total_deposits_cents matches deposited amount |

### 5.7 Section 373: Billing Dashboard UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 373.1 | Billing page shows balance | Navigate to `/ads/billing`; balance card shows current balance |
| 373.2 | Deposit dialog opens | Click "Deposit"; dialog with amount input visible |
| 373.3 | Spending history displays | Ledger entries visible with entry type and amount |
| 373.4 | Campaign budget meter shows progress | Budget progress bar for campaign with correct percentage |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Deposit below minimum | 400 | "Minimum deposit is $50" |
| Account not found | 404 | "Account not found" |
| Insufficient balance for charge | — | Best-effort; charge proceeds, balance can go negative (over-delivery) |
| Invalid month format for invoice | 400 | "Invalid month format, use YYYY-MM" |
| Billing write failure | — | Logged; charge still tracked in ad_impressions |

---

## 7. Security Considerations

- Deposit requires account ownership verification
- Billing history accessible only to account owner
- Revenue split percentages are server-side constants (not client-configurable)
- Budget alerts use conditional writes to prevent duplicate alerts
- Invoice data is read-only; no modification endpoints
- Payment method validation on deposit (reuses existing Stripe/PayPal mock)

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-001 | Ad accounts + campaigns | Required |
| ADS-004 | Ad tracking events (trigger charges) | Required |
| Billing infrastructure | `app/services/billing_shared.py` | Existing |
| Alert system | `app/services/alerts.py` | Existing |

### 8.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| ADS-008 (Analytics) | Spending data from billing ledger |
