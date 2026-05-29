# ADS-007: Ad Billing & Financial Engine

**Ticket**: ADS-007
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Dependencies**: ADS-001 (Accounts — sibling ticket, not yet implemented), ADS-004 (Ad Serving — sibling ticket, not yet implemented)
<!-- NOTE: ADS-001 and ADS-004 services/tables do not exist yet. The existing billing_shared.py and ad_placement.py are the integration points. -->

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

### 1.3 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Ad Billing Flow                                │
│                                                                         │
│  ┌──────────────────┐                                                   │
│  │ Ad Serving Engine │   track_ad_event(event="impression")             │
│  │ (ADS-004)         │──────────────────────┐                           │
│  └──────────────────┘                       │                           │
│                                              ▼                           │
│  ┌──────────────────────────────────────────────────────────────┐       │
│  │                   Ad Billing Engine                           │       │
│  │                   app/services/ad_billing.py                  │       │
│  │                                                               │       │
│  │  1. Determine billing model                                   │       │
│  │     ├── CPM: charge = bid_cpm / 1000  (per impression)       │       │
│  │     ├── CPC: charge = bid_cpc         (per click)            │       │
│  │     └── CPA: charge = bid_cpa         (per conversion)       │       │
│  │                                                               │       │
│  │  2. Process charge                                            │       │
│  │     ├── Write ad_billing LEDGER entry                        │       │
│  │     ├── Debit advertiser balance (ad_accounts)               │       │
│  │     └── Increment campaign spend counters                    │       │
│  │                                                               │       │
│  │  3. Revenue split (70/30)                                    │       │
│  │     ├── Creator (70%): billing LEDGER credit                 │       │
│  │     └── Platform (30%): internal accounting                  │       │
│  │                                                               │       │
│  │  4. Budget enforcement                                       │       │
│  │     ├── Check lifetime/daily budget thresholds               │       │
│  │     └── Auto-pause campaign if budget exhausted              │       │
│  │                                                               │       │
│  │  5. Spending alerts                                          │       │
│  │     ├── 50% threshold → warning alert                        │       │
│  │     ├── 80% threshold → warning alert                        │       │
│  │     └── 100% threshold → critical alert + auto-pause         │       │
│  └──────────┬────────────────────────────────┬──────────────────┘       │
│             │                                │                           │
│             ▼                                ▼                           │
│  ┌──────────────────┐            ┌────────────────────┐                 │
│  │    DynamoDB       │            │   Alerts Service    │                 │
│  │                   │            │   (write_alert)     │                 │
│  │  ad_billing       │            └────────────────────┘                 │
│  │  ad_accounts      │                                                   │
│  │  ad_campaigns     │                                                   │
│  │  billing (creator)│                                                   │
│  └──────────────────┘                                                   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────┐       │
│  │                   Frontend                                    │       │
│  │                                                               │       │
│  │  AdBillingPage (/ads/billing)                                │       │
│  │  ├── BalanceCard: current balance + deposit button           │       │
│  │  ├── SpendingChart: 30-day daily spend bar chart             │       │
│  │  ├── BudgetMeters: per-campaign progress bars                │       │
│  │  ├── TransactionList: scrollable ledger                      │       │
│  │  ├── InvoiceList: monthly invoices with "View" button        │       │
│  │  └── DepositDialog: amount input + payment method selector   │       │
│  └──────────────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.4 Financial Flow

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

### 1.5 Revenue Split Detail

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

The `billing` table stores user-scoped ledger entries with pattern `pk=USER#{user_sub}`, `sk=LEDGER#{ts}#{entry_id}`. The `new_ledger_entry()` helper generates entries with `entry_type`, `amount_cents`, `state`, `reason`, and `meta` (see `app/services/billing_shared.py`). This is used for tips, unlock payments, subscription charges, and ad revenue credits.

The existing `_credit_ad_revenue()` function in `ad_placement.py` (see `app/services/ad_placement.py:279`) uses `new_ledger_entry()` to credit creators. ADS-007 adds the debit side (charging the advertiser) and the platform revenue split.

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

### 3.2 DynamoDB Access Patterns

| Access Pattern | Table | Key | GSI | Example |
|---|---|---|---|---|
| Write charge ledger entry | `ad_billing` | PK=`ACCT#{account_id}`, SK=`LEDGER#{ts}#{entry_id}` | — | PutItem |
| Get billing history for account | `ad_billing` | PK=`ACCT#{account_id}`, SK begins_with `LEDGER#` | — | Query, ScanIndexForward=False, Limit=50 |
| Get spending by campaign | `ad_billing` | — | `ByCampaign` (PK=campaign_id) | Query GSI |
| Get entries for invoice month | `ad_billing` | — | `ByMonth` (PK=month_key) + FilterExpression(account_id) | Query GSI |
| Write deposit entry | `ad_billing` | PK=`ACCT#{account_id}`, SK=`LEDGER#{ts}#{dep_id}` | — | PutItem |
| Debit advertiser balance | `ad_accounts` | PK=`ACCT#{account_id}`, SK=`META` | — | UpdateItem (atomic decrement) |
| Increment campaign spend | `ad_campaigns` | PK=`ACCT#{account_id}`, SK=`CAMPAIGN#{campaign_id}` | — | UpdateItem (atomic increment) |
| Credit creator revenue | `billing` | PK=`USER#{creator_id}`, SK=`LEDGER#{ts}#{entry_id}` | — | PutItem |
| Write spending alert guard | `billing` | PK=`USER#{owner_sub}`, SK=`AD_BUDGET_ALERT#{campaign_id}#{threshold}` | — | PutItem (conditional) |
| Get account balance | `ad_accounts` | PK=`ACCT#{account_id}`, SK=`META` | — | GetItem |

#### Example DynamoDB Items (JSON)

**Impression Charge Entry**:
```json
{
  "pk": {"S": "ACCT#acct_adv001"},
  "sk": {"S": "LEDGER#1748534400#chg_a1b2c3d4e5f6"},
  "entry_id": {"S": "chg_a1b2c3d4e5f6"},
  "account_id": {"S": "acct_adv001"},
  "campaign_id": {"S": "camp_abc123"},
  "entry_type": {"S": "impression_charge"},
  "amount_cents": {"N": "1"},
  "state": {"S": "settled"},
  "reason": {"S": "Ad impression"},
  "meta": {"M": {
    "creative_id": {"S": "creat_xyz789"},
    "content_id": {"S": "post_12345"},
    "model": {"S": "cpm"}
  }},
  "month_key": {"S": "2026-05"},
  "created_at": {"N": "1748534400"}
}
```

**Budget Deposit Entry**:
```json
{
  "pk": {"S": "ACCT#acct_adv001"},
  "sk": {"S": "LEDGER#1748530000#dep_f6e5d4c3b2a1"},
  "entry_id": {"S": "dep_f6e5d4c3b2a1"},
  "account_id": {"S": "acct_adv001"},
  "campaign_id": {"S": ""},
  "entry_type": {"S": "budget_deposit"},
  "amount_cents": {"N": "10000"},
  "state": {"S": "settled"},
  "reason": {"S": "Account deposit"},
  "meta": {"M": {"payment_method_id": {"S": "pm_visa_4242"}}},
  "month_key": {"S": "2026-05"},
  "created_at": {"N": "1748530000"}
}
```

**Creator Revenue Credit (in billing table)**:
```json
{
  "pk": {"S": "USER#e2e_alice@test.local"},
  "sk": {"S": "LEDGER#1748534400#adrev_g7h8i9"},
  "entry_type": {"S": "ad_revenue_credit"},
  "amount_cents": {"N": "1"},
  "state": {"S": "settled"},
  "reason": {"S": "Ad revenue share"},
  "meta": {"M": {
    "creative_id": {"S": "creat_xyz789"},
    "content_id": {"S": "post_12345"},
    "model": {"S": "cpm"},
    "platform_share_pct": {"N": "30"}
  }}
}
```

### 3.3 Backend Service

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

### 3.4 Pydantic Models

**File**: `app/models.py`

```python
# -- Ad Billing (ADS-007) --

class AdDepositIn(BaseModel):
    """Request body for POST /ui/ads/accounts/{id}/deposit."""
    amount_cents: int = Field(..., ge=5000, le=10000000,
                              description="Deposit amount in cents ($50 minimum, $100k maximum)")
    payment_method_id: str = Field(default="",
                                    description="Payment method ID from billing system")

    model_config = ConfigDict(json_schema_extra={
        "example": {"amount_cents": 10000, "payment_method_id": "pm_visa_4242"}
    })


class AdDepositOut(BaseModel):
    """Response from POST /ui/ads/accounts/{id}/deposit."""
    ok: bool
    entry_id: str
    new_balance_cents: int


class AdBillingEntryOut(BaseModel):
    """Single billing ledger entry."""
    entry_id: str
    account_id: str
    campaign_id: str
    entry_type: str  # impression_charge, click_charge, conversion_charge, budget_deposit, refund, adjustment
    amount_cents: int
    state: str  # settled, pending, refunded
    reason: str
    meta: Dict[str, Any] = Field(default_factory=dict)
    created_at: int


class AdBillingHistoryOut(BaseModel):
    """Response from GET /ui/ads/accounts/{id}/billing."""
    entries: List[AdBillingEntryOut]
    count: int


class AdInvoiceCampaignLine(BaseModel):
    """One campaign's line item in an invoice."""
    campaign_id: str
    impressions: int
    clicks: int
    conversions: int
    total_cents: int


class AdInvoiceOut(BaseModel):
    """Monthly invoice summary."""
    account_id: str
    month: str
    campaigns: List[AdInvoiceCampaignLine]
    total_charges_cents: int
    total_deposits_cents: int
    entry_count: int
```

### 3.5 Backend Router

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

### 3.6 Frontend Pages

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

### 3.7 Frontend Types

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

### 3.8 Frontend Component Tree

```
AdBillingPage (/ads/billing)
├── Props: none (page component)
├── State: useQuery(["ad-billing", accountId], fetchBillingHistory)
│          useQuery(["ad-balance", accountId], fetchAccountBalance)
│          useQuery(["ad-invoices", accountId, month], fetchInvoice)
│
├── AccountSelector
│   ├── Props: { accounts: AdAccount[], selected: string, onChange }
│   └── Select dropdown listing user's ad accounts
│
├── BalanceCard
│   ├── Props: { balance_cents, lifetime_spend_cents }
│   ├── Current balance display (formatted as $XX.XX)
│   ├── Lifetime spend display
│   └── DepositButton → opens DepositDialog
│
├── DepositDialog
│   ├── Props: { open, onClose, accountId, onSuccess }
│   ├── Amount input with preset buttons ($50, $100, $250, $500)
│   ├── PaymentMethodSelector (reuses billing/PaymentMethods component)
│   ├── Form validation: amount >= $50
│   └── useMutation(depositFunds, { onSuccess: invalidateQueries })
│
├── SpendingChart
│   ├── Props: { entries: AdBillingEntry[], days: number }
│   ├── Bar chart (recharts) showing daily spend over last 30 days
│   └── Aggregates charge entries by date
│
├── BudgetMeters
│   ├── Props: { campaigns: CampaignBudgetInfo[] }
│   ├── For each active campaign:
│   │   ├── Campaign name label
│   │   ├── Progress bar (spent / budget * 100)
│   │   └── "$XX / $YY spent" text
│   └── Color coding: green (<50%), yellow (50-80%), red (>80%)
│
├── TransactionList
│   ├── Props: { entries: AdBillingEntry[], loading: boolean }
│   ├── ScrollArea with DataTable
│   ├── Columns: Date, Type (badge), Campaign, Amount, State
│   └── Entry type badges: deposit (green), charge (red), refund (blue)
│
└── InvoiceList
    ├── Props: { months: string[] }
    ├── List of monthly invoice cards
    ├── Each card: month name, total charges, total deposits, "View" button
    └── InvoiceDetailDialog (expandable per-campaign breakdown)
```

---

## 4. API Request/Response Examples

### 4.1 Deposit Funds

```bash
curl -X POST http://localhost:8000/ui/ads/accounts/acct_adv001/deposit \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_abc123; ui_access_token=eyJ...; ui_csrf=tok_csrf_001" \
  -H "x-csrf-token: tok_csrf_001" \
  -d '{"amount_cents": 10000, "payment_method_id": "pm_visa_4242"}'

# Response (200 OK)
{
  "ok": true,
  "entry_id": "dep_f6e5d4c3b2a1",
  "new_balance_cents": 10000
}

# Error: below minimum (400)
# Request: {"amount_cents": 1000}
{
  "detail": "Minimum deposit is $50"
}
```

### 4.2 Get Billing History

```bash
curl http://localhost:8000/ui/ads/accounts/acct_adv001/billing?limit=10 \
  -H "Cookie: ui_session=sess_abc123; ui_access_token=eyJ..."

# Response (200 OK)
[
  {
    "entry_id": "chg_a1b2c3d4e5f6",
    "account_id": "acct_adv001",
    "campaign_id": "camp_abc123",
    "entry_type": "impression_charge",
    "amount_cents": 1,
    "state": "settled",
    "reason": "Ad impression",
    "meta": {"creative_id": "creat_xyz789", "content_id": "post_12345", "model": "cpm"},
    "created_at": 1748534400
  },
  {
    "entry_id": "dep_f6e5d4c3b2a1",
    "account_id": "acct_adv001",
    "campaign_id": "",
    "entry_type": "budget_deposit",
    "amount_cents": 10000,
    "state": "settled",
    "reason": "Account deposit",
    "meta": {"payment_method_id": "pm_visa_4242"},
    "created_at": 1748530000
  }
]
```

### 4.3 Get Campaign Spending

```bash
curl http://localhost:8000/ui/ads/accounts/acct_adv001/billing/campaigns/camp_abc123?limit=50 \
  -H "Cookie: ui_session=sess_abc123; ui_access_token=eyJ..."

# Response (200 OK)
[
  {
    "entry_id": "chg_a1b2c3d4e5f6",
    "account_id": "acct_adv001",
    "campaign_id": "camp_abc123",
    "entry_type": "impression_charge",
    "amount_cents": 1,
    "state": "settled",
    "reason": "Ad impression",
    "meta": {"creative_id": "creat_xyz789", "model": "cpm"},
    "created_at": 1748534400
  }
]
```

### 4.4 Generate Invoice

```bash
curl http://localhost:8000/ui/ads/accounts/acct_adv001/invoices/2026-05 \
  -H "Cookie: ui_session=sess_abc123; ui_access_token=eyJ..."

# Response (200 OK)
{
  "account_id": "acct_adv001",
  "month": "2026-05",
  "campaigns": [
    {
      "campaign_id": "camp_abc123",
      "impressions": 5420,
      "clicks": 87,
      "conversions": 12,
      "total_cents": 6919
    }
  ],
  "total_charges_cents": 6919,
  "total_deposits_cents": 10000,
  "entry_count": 5519
}
```

---

## 5. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Deposit below minimum ($50) | 400 | `deposit_too_small` | "Minimum deposit is $50" | Increase deposit amount |
| Deposit exceeds maximum ($100,000) | 400 | `deposit_too_large` | "Maximum deposit is $100,000" | Decrease deposit amount |
| Account not found | 404 | `account_not_found` | "Ad account not found" | Verify account ID |
| Non-owner accessing billing | 403 | `forbidden` | "You do not own this account" | Use correct account |
| Invalid payment method | 400 | `invalid_payment_method` | "Payment method not found or expired" | Update payment method |
| Invalid month format for invoice | 400 | `invalid_month` | "Invalid month format, use YYYY-MM" | Fix month parameter |
| Insufficient balance for charge | 200 | — | (best-effort; balance goes negative) | Advertiser should deposit more funds |
| Campaign not found during budget check | 200 | — | (silent; charge proceeds without alert check) | No user action |
| Billing ledger write failure | 500 | `internal_error` | "Failed to process charge" | Retry; charge tracked in ad_impressions as fallback |
| Revenue split write failure | 200 | — | (logged as warning; charge succeeds, creator credit skipped) | Platform reconciliation job catches missed credits |
| Alert write failure | 200 | — | (silent; spending alert may not fire) | Budget alert sent on next threshold crossing |
| Session expired | 401 | `unauthorized` | "Session expired" | Re-authenticate |
| CSRF token mismatch | 403 | `csrf_invalid` | "Invalid CSRF token" | Refresh page |

---

## 6. Implementation Plan

### 6.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_billing.py` | Billing engine: charges, deposits, splits, invoices |
| `frontend/src/pages/ads/AdBillingPage.tsx` | Billing dashboard with spending chart + invoice list |

### 6.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/ads.py` | Add deposit, billing history, invoice endpoints |
| `app/services/ad_serving.py` | Call `charge_impression()` / `charge_click()` from `track_ad_event()` |
| `app/core/settings.py` | Add `ad_billing_table_name` |
| `app/core/tables.py` | Add `ad_billing` table handle |
| `scripts/local-ddb-init.py` | Add `AdBilling` table definition |
| `app/models.py` | Add `AdDepositIn`, `AdDepositOut`, `AdBillingEntryOut`, `AdInvoiceOut` models |
| `frontend/src/api/types.ts` | Add `AdBillingEntry`, `AdInvoice` types |
| `frontend/src/api/endpoints/ads.ts` | Add billing API functions |
| `frontend/src/App.tsx` | Add `/ads/billing` route |

### 6.3 Step-by-Step Order

1. Add DDB table definition
2. Add settings + table handle
3. Add Pydantic models
4. Implement `ad_billing.py` service
5. Add billing endpoints to router
6. Wire `track_ad_event()` to billing charges
7. Add frontend types + API endpoints
8. Build AdBillingPage
9. Write E2E tests

---

## 7. E2E Test Plan

### 7.1 Test File

`frontend/e2e/ads-billing.spec.ts` — 28 tests across 7 sections.

### 7.2 Test Setup

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

### 7.3 Section 369: Deposit API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 369.1 | Deposit funds to ad account | POST `/ui/ads/accounts/{id}/deposit` amount_cents=10000; 200; new_balance_cents=10000 |
| 369.2 | Minimum deposit enforced | POST amount_cents=1000 ($10); 400; "Minimum deposit is $50" |
| 369.3 | Deposit creates billing entry | GET billing history; entry_type=budget_deposit, amount=10000 |
| 369.4 | Multiple deposits accumulate | Second deposit 5000; balance=15000 |

### 7.4 Section 370: Impression Charging (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 370.1 | Track impression creates charge | POST track event=impression; billing ledger has impression_charge entry |
| 370.2 | Advertiser balance decremented | Account balance decreased by charge amount |
| 370.3 | Campaign spend incremented | Campaign lifetime_spent_cents increased |
| 370.4 | Creator receives revenue share | Creator billing ledger has ad_revenue_credit entry; amount = 70% of charge |

### 7.5 Section 371: Budget Enforcement (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 371.1 | Campaign auto-pauses at 100% budget | Set budget=100, spend impressions until spent>=100; campaign status=completed |
| 371.2 | Spending alert at 50% | Spend to 50% of budget; alert with "budget 50% spent" exists |
| 371.3 | Spending alert at 80% | Spend to 80%; alert with "budget 80% spent" exists |
| 371.4 | Daily budget reset works | Set budget_type=daily; spend today; verify spent_today_cents tracks correctly |

### 7.6 Section 372: Invoice Generation (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 372.1 | Generate monthly invoice | GET `/ui/ads/accounts/{id}/invoices/YYYY-MM`; 200; has campaigns array |
| 372.2 | Invoice aggregates by campaign | Invoice campaigns array has correct impression/click counts |
| 372.3 | Invoice shows total charges | total_charges_cents matches sum of campaign totals |
| 372.4 | Invoice shows deposits | total_deposits_cents matches deposited amount |

### 7.7 Section 373: Billing Dashboard UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 373.1 | Billing page shows balance | Navigate to `/ads/billing`; balance card shows current balance |
| 373.2 | Deposit dialog opens | Click "Deposit"; dialog with amount input visible |
| 373.3 | Spending history displays | Ledger entries visible with entry type and amount |
| 373.4 | Campaign budget meter shows progress | Budget progress bar for campaign with correct percentage |

### 7.8 Section 374: CPC/CPA Billing (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 374.1 | CPC click charge recorded | Track click event on CPC campaign; billing ledger has click_charge entry |
| 374.2 | CPC charge amount matches bid_cpc | Charge amount_cents equals campaign's bid_cpc_cents |
| 374.3 | CPA conversion charge recorded | Record conversion; billing ledger has conversion_charge entry |
| 374.4 | No charge for impression on CPC campaign | Track impression on CPC-only campaign; no impression_charge entry |

### 7.9 Section 375: Authorization & Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 375.1 | Non-owner cannot access billing | Bob tries GET billing for Alice's account; 403 |
| 375.2 | Non-owner cannot deposit | Bob tries POST deposit to Alice's account; 403 |
| 375.3 | Invalid month format returns 400 | GET invoices with month="May-2026"; 400 |
| 375.4 | Invoice for empty month returns zero totals | GET invoices for future month; total_charges_cents=0, campaigns=[] |

---

## 8. Observability & Monitoring

### 8.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ad_billing_charges_total` | Counter | `entry_type` (impression/click/conversion), `billing_model` (cpm/cpc/cpa) | Total charge events by type |
| `ad_billing_charge_cents_total` | Counter | `entry_type`, `billing_model` | Total cents charged |
| `ad_billing_deposits_total` | Counter | — | Total deposit events |
| `ad_billing_deposit_cents_total` | Counter | — | Total cents deposited |
| `ad_billing_revenue_split_cents` | Counter | `recipient` (platform/creator) | Revenue split tracking |
| `ad_billing_budget_alerts_total` | Counter | `threshold` (50/80/100) | Budget alert events |
| `ad_billing_auto_pause_total` | Counter | — | Campaigns auto-paused due to budget exhaustion |

### 8.2 Log Events

| Event | Level | Fields | Description |
|-------|-------|--------|-------------|
| `ad_billing_deposit` | INFO | `account_id`, `amount_cents`, `new_balance_cents` | Deposit processed |
| `ad_billing_charge` | INFO | `account_id`, `campaign_id`, `entry_type`, `charge_cents`, `creator_id` | Charge processed |
| `ad_billing_revenue_split` | INFO | `creator_id`, `creator_share_cents`, `platform_share_cents` | Revenue split applied |
| `ad_billing_budget_alert` | WARN | `account_id`, `campaign_id`, `threshold_pct`, `spent_cents`, `budget_cents` | Budget threshold crossed |
| `ad_billing_campaign_paused` | WARN | `account_id`, `campaign_id`, `lifetime_spent_cents` | Campaign auto-paused at 100% |
| `ad_billing_creator_credit_failed` | WARN | `creator_id`, `error` | Failed to credit creator revenue share |
| `ad_billing_invoice_generated` | INFO | `account_id`, `month`, `total_charges_cents`, `entry_count` | Invoice generated |

### 8.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Negative advertiser balance | Any account `balance_cents < -5000` | Warning | Review over-delivery; contact advertiser |
| Revenue split failure rate | `rate(ad_billing_creator_credit_failed) > 5/min` | Critical | Check billing table capacity; reconcile missed credits |
| High charge rate | `rate(ad_billing_charges_total) > 10000/min` | Warning | Investigate potential fraud or bot traffic |
| Zero deposits in 7 days | No deposit events for 7 consecutive days | Info | Marketing/sales follow-up with advertisers |

---

## 9. Rollout Plan

### 9.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `AD_BILLING_ENABLED` | `false` | Master switch: when false, track_ad_event skips billing charges |
| `AD_BILLING_REVENUE_SPLIT_ENABLED` | `true` | When false, charges are recorded but no creator credit is written |
| `AD_BILLING_ALERTS_ENABLED` | `true` | When false, budget threshold alerts are suppressed |

### 9.2 Migration Steps

1. **Phase 1 — Table creation**: Deploy `scripts/local-ddb-init.py` to create `AdBilling` table with GSIs.
2. **Phase 2 — Backend deployment**: Deploy `ad_billing.py` with `AD_BILLING_ENABLED=false`. Billing code is present but dormant.
3. **Phase 3 — Shadow billing**: Enable billing in shadow mode: process charges internally but don't debit advertiser balance. Log expected charges for reconciliation.
4. **Phase 4 — Deposit endpoint**: Enable deposit endpoint first. Advertisers can fund accounts before charges begin.
5. **Phase 5 — Charge activation**: Set `AD_BILLING_ENABLED=true`. Charges begin flowing.
6. **Phase 6 — Revenue split**: Verify creator credits are accurate. Enable `AD_BILLING_REVENUE_SPLIT_ENABLED=true`.

### 9.3 Rollback Procedure

1. Set `AD_BILLING_ENABLED=false` — charges stop immediately. Impressions still tracked in ad_impressions but no billing entries written.
2. Deposits already made remain in accounts — no money movement on rollback.
3. If revenue split is incorrect, set `AD_BILLING_REVENUE_SPLIT_ENABLED=false` and run reconciliation to correct creator credits.

---

## 10. Performance Considerations

### 10.1 Write Amplification per Impression

Each CPM impression charge requires 5 DDB writes:
1. `ad_billing` PutItem (ledger entry)
2. `ad_accounts` UpdateItem (balance decrement)
3. `ad_campaigns` UpdateItem (spend increment)
4. `billing` PutItem (creator revenue credit)
5. `billing` PutItem (spending alert guard — conditional, only on threshold crossings)

At 1000 impressions/second = ~4000-5000 WCUs total.

### 10.2 Invoice Query Cost

`generate_invoice` queries the `ByMonth` GSI with a `FilterExpression` on `account_id`. For months with high volume (>100K entries across all accounts), the filter scans all entries for that month. At scale, consider adding `ACCT#{account_id}#YYYY-MM` as a dedicated PK pattern instead of relying on FilterExpression.

### 10.3 Batch Charging

For high-volume impressions, consider batching charges:
- Accumulate charges in-memory for 5 seconds
- Write a single aggregate charge entry instead of one per impression
- Reduces DDB write costs by 10-50x at scale
- Trade-off: 5-second delay in billing visibility

### 10.4 Daily Budget Reset

`spent_today_cents` must be reset to 0 at midnight UTC. A background task runs every 5 minutes, scanning for campaigns with `budget_type=daily` and resetting `spent_today_cents` when the date changes. Uses `last_reset_date` field to prevent double-resets.

---

## 11. Security Considerations

- Deposit requires account ownership verification
- Billing history accessible only to account owner
- Revenue split percentages are server-side constants (not client-configurable)
- Budget alerts use conditional writes to prevent duplicate alerts
- Invoice data is read-only; no modification endpoints
- Payment method validation on deposit (reuses existing Stripe/PayPal mock)
- Charges cannot be manually created via API — only triggered by ad tracking events
- Negative balance is allowed (over-delivery) but triggers monitoring alerts

---

## 12. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-001 | Ad accounts + campaigns | Required |
| ADS-004 | Ad tracking events (trigger charges) | Required |
| Billing infrastructure | `app/services/billing_shared.py` | Existing |
| Alert system | `app/services/alerts.py` | Existing |

### 12.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| ADS-008 (Analytics) | Spending data from billing ledger |
| ADS-012 (Content Boosting) | Wallet deduction pattern reused |
| ADS-015 (Affiliate/Promo) | ROAS calculation uses ad spend data |

---

## 13. Acceptance Criteria

1. Advertisers can deposit funds ($50 minimum) into their ad account with immediate balance update.
2. CPM impressions charge `max(1, bid_cpm / 1000)` cents per impression.
3. CPC clicks charge `bid_cpc` cents per click.
4. CPA conversions charge `bid_cpa` cents per conversion.
5. Revenue split credits 70% to creator and retains 30% for platform on every charge.
6. Campaigns auto-pause when lifetime budget is exhausted (spent >= budget).
7. Spending alerts fire at 50%, 80%, and 100% budget thresholds (each fires exactly once).
8. Monthly invoices aggregate charges by campaign with impression/click/conversion counts.
9. Billing history is accessible only to the account owner.
10. All 28 E2E tests pass in `frontend/e2e/ads-billing.spec.ts`.

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/billing_shared.py` | — | Existing billing ledger helpers: `new_ledger_entry`, `user_pk` |
| `app/services/ad_placement.py` | 279 | Existing `_credit_ad_revenue()` — credits creators (debit side not implemented) |
| `app/services/alerts.py` | — | Existing alert system for spending notifications |
| `app/core/tables.py` | 93 | Existing `ad_impressions` table handle |
| `app/services/ad_billing.py` | — | Does not exist yet — new implementation required |
| `ad_billing` DDB table | — | Does not exist yet — new implementation required |
