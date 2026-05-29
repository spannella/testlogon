# SYND-006: Syndicate Advertising

**Ticket**: SYND-006
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 10-12 days

---

## 1. Overview & Motivation

### 1.1 Purpose

SYND-006 enables syndicates to create and manage advertising campaigns funded by the syndicate treasury (SYND-004). The admin creates campaigns through the platform's advertising system (ADS-001 through ADS-019), with the campaign budget deducted from the treasury. Campaign analytics are visible to all syndicate members, giving the group transparency into how their pooled funds are being spent on promotion.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Admin | As a syndicate admin, I want to create an ad campaign funded by the treasury. | POST creates campaign; treasury debited by budget amount; campaign appears in syndicate campaigns list. |
| Admin | As an admin, I want to set a campaign budget, targeting, and creative content. | Campaign creation form includes budget, target audience, ad creative, and schedule. |
| Admin | As an admin, I want to pause or stop a running campaign. | POST pause/stop; campaign status updated; no further ad impressions served. |
| Member | As a member, I want to see all active and past syndicate campaigns. | GET campaigns; list shows all campaigns with status, budget, spend, impressions. |
| Member | As a member, I want to see detailed analytics for each campaign. | GET campaign detail; shows impressions, clicks, CTR, spend-to-date, daily breakdown. |
| Admin | As an admin, I want to increase a campaign's budget from the treasury. | POST add-budget; additional treasury funds allocated; campaign budget increased. |
| Member | As a member, I want to see how treasury funds are being spent on advertising. | Campaign list cross-references treasury ledger entries for full transparency. |
| System | Ad impressions served through the campaign follow the platform's ad serving pipeline. | Campaigns use existing `ad_placement.py` infrastructure for impression delivery and tracking. |

### 1.3 How Syndicate Advertising Differs from Individual Advertising

| Feature | Individual Advertising (existing) | Syndicate Advertising (this ticket) |
|---------|-----------------------------------|--------------------------------------|
| Funding | Individual advertiser's payment method or wallet | Syndicate treasury (pooled member funds) |
| Authorization | Advertiser creates and manages own campaigns | Syndicate admin creates; all members can view |
| Creative | Promotes individual creator's content | Promotes the syndicate as a whole (or featured members) |
| Analytics | Private to the advertiser | Shared with all syndicate members |
| Budget control | Advertiser sets and adjusts | Admin sets; constrained by treasury balance |

### 1.4 Why This Is Needed

Individual creators often lack the advertising budget to compete for visibility. By pooling treasury funds from multiple members, syndicates can afford larger campaigns that promote the entire group. Members contribute to the treasury (SYND-004) knowing their funds will be spent on advertising that benefits all members. The transparency of shared analytics builds trust in how pooled funds are used.

---

## 2. Current State Analysis

### 2.1 Existing Advertising Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Ad placement | `app/services/ad_placement.py` (327 lines) | `calculate_ad_slots`, `record_ad_impression`, `get_ad_stats` |
| Ad config | `app/services/ad_placement.py:53-78` | `get_default_ad_config`, `validate_ad_config` for campaign setup |
| Ad impression recording | `app/services/ad_placement.py:222-279` | `record_ad_impression` with daily tracking, `_credit_ad_revenue` |
| Ad stats | `app/services/ad_placement.py:327+` | `get_ad_stats` for impression/click/revenue aggregation |
| ADS ticket specs | `docs/tickets/ADS-001` through `ADS-019` | Comprehensive ad system design covering accounts, creatives, targeting, serving, analytics |
| Syndicate treasury | `app/services/syndicate_treasury.py` (SYND-004) | `spend_on_advertising` for deducting campaign budget from treasury |
| Syndicates service | `app/services/syndicates.py` (SYND-001) | `_require_admin`, `list_members` for authorization and member visibility |

### 2.2 ADS System Key Patterns

From the ADS ticket specs, the advertising system uses:

- **Advertiser accounts**: Each advertiser has an account with balance, campaigns, and creatives.
- **Campaign lifecycle**: `draft` -> `active` -> `paused` -> `completed` / `cancelled`.
- **Budget tracking**: `budget_cents` (total), `spent_cents` (consumed), `remaining_cents` (available).
- **Impression tracking**: Daily aggregate counts in `ad_stats` items.
- **Targeting**: Audience segments, geo-targeting, interest categories.

### 2.3 Gaps

1. **No syndicate advertiser account** -- advertiser accounts are individual; there is no syndicate-as-advertiser concept.
2. **No treasury-to-campaign budget flow** -- `spend_on_advertising` in SYND-004 handles the treasury deduction but doesn't create the actual campaign.
3. **No shared campaign analytics** -- campaign stats are private to the advertiser account.
4. **No campaign budget top-up** -- existing campaigns have fixed budgets; there is no "add more budget" operation.
5. **No syndicate campaign listing** -- no way to list all campaigns belonging to a syndicate.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 Syndicate Campaign (Syndicates Table)

**PK**: `SYND#{syndicate_id}`, **SK**: `CAMPAIGN#{campaign_id}`

| Field | Type | Description |
|-------|------|-------------|
| `campaign_id` | S | `camp_{uuid4_hex}` |
| `syndicate_id` | S | Owning syndicate |
| `name` | S | Campaign name (e.g., "Summer promotion") |
| `description` | S | Campaign description |
| `status` | S | `draft`, `active`, `paused`, `completed`, `cancelled` |
| `budget_cents` | N | Total allocated budget from treasury |
| `spent_cents` | N | Amount consumed by ad impressions |
| `remaining_cents` | N | `budget_cents - spent_cents` |
| `creative` | M | Ad creative content: `{headline, body, image_url, cta_text, cta_url}` |
| `targeting` | M | Targeting config: `{audience, geo, interests, age_range}` |
| `start_date` | S | Campaign start date (ISO format) |
| `end_date` | S | Campaign end date (ISO format, optional) |
| `created_by` | S | Admin who created the campaign |
| `created_at` | N | Creation timestamp |
| `updated_at` | N | Last update timestamp |
| `stats_summary` | M | Denormalized stats: `{impressions, clicks, ctr}` |

#### 3.1.2 Campaign Analytics (Syndicates Table)

**PK**: `CAMPAIGN_STATS#{campaign_id}`, **SK**: `DATE#{date_string}`

| Field | Type | Description |
|-------|------|-------------|
| `date` | S | ISO date string (e.g., `2026-06-01`) |
| `impressions` | N | Number of ad impressions on this date |
| `clicks` | N | Number of ad clicks on this date |
| `spend_cents` | N | Amount spent on this date |
| `unique_viewers` | N | Approximate unique viewers |

#### 3.1.3 Syndicate Advertiser Link (Syndicates Table)

**PK**: `SYND#{syndicate_id}`, **SK**: `ADVERTISER`

| Field | Type | Description |
|-------|------|-------------|
| `advertiser_account_id` | S | Links to the platform's advertising account for this syndicate |
| `created_at` | N | When the account was created |

This links the syndicate to a platform advertiser account, enabling campaign creation through the existing ADS infrastructure.

#### 3.1.4 Example Items

**Campaign record**:
```json
{
  "pk": "SYND#synd_abc123",
  "sk": "CAMPAIGN#camp_def456",
  "campaign_id": "camp_def456",
  "syndicate_id": "synd_abc123",
  "name": "Summer Creative Collective Promo",
  "description": "Promoting our syndicate to new subscribers",
  "status": "active",
  "budget_cents": 5000,
  "spent_cents": 1200,
  "remaining_cents": 3800,
  "creative": {
    "headline": "Join Creative Collective",
    "body": "5 amazing creators, 1 subscription",
    "image_url": "/uploads/syndicate/banner.jpg",
    "cta_text": "Subscribe Now",
    "cta_url": "/syndicates/synd_abc123"
  },
  "targeting": {
    "audience": "all",
    "interests": ["art", "music", "photography"]
  },
  "start_date": "2026-06-01",
  "end_date": "2026-06-30",
  "created_by": "alice@test.local",
  "created_at": 1748520000,
  "updated_at": 1748520000,
  "stats_summary": {
    "impressions": 4500,
    "clicks": 180,
    "ctr": 4.0
  }
}
```

**Daily analytics**:
```json
{
  "pk": "CAMPAIGN_STATS#camp_def456",
  "sk": "DATE#2026-06-15",
  "date": "2026-06-15",
  "impressions": 320,
  "clicks": 12,
  "spend_cents": 85,
  "unique_viewers": 280
}
```

### 3.2 Backend Service

**New file**: `app/services/syndicate_advertising.py` (~350 lines)

```python
"""Syndicate advertising campaign management (SYND-006)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates as syndicate_svc
from app.services.syndicate_treasury import spend_on_advertising, get_treasury_balance

logger = logging.getLogger(__name__)

VALID_STATUSES = ("draft", "active", "paused", "completed", "cancelled")


def create_campaign(
    *,
    syndicate_id: str,
    admin_sub: str,
    name: str,
    description: str = "",
    budget_cents: int,
    creative: Dict[str, Any],
    targeting: Optional[Dict[str, Any]] = None,
    start_date: str,
    end_date: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new ad campaign funded by syndicate treasury."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)

    if budget_cents <= 0:
        raise ValueError("Budget must be positive")

    # Check treasury balance
    balance = get_treasury_balance(syndicate_id)
    if balance.get("wallet_balance_cents", 0) < budget_cents:
        raise ValueError("Insufficient treasury balance for campaign budget")

    campaign_id = f"camp_{uuid4().hex}"
    ts = now_ts()

    # Deduct budget from treasury
    spend_result = spend_on_advertising(
        syndicate_id=syndicate_id,
        admin_sub=admin_sub,
        amount_cents=budget_cents,
        campaign_id=campaign_id,
        campaign_name=name,
    )

    campaign = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"CAMPAIGN#{campaign_id}",
        "campaign_id": campaign_id,
        "syndicate_id": syndicate_id,
        "name": name,
        "description": description,
        "status": "active",
        "budget_cents": budget_cents,
        "spent_cents": 0,
        "remaining_cents": budget_cents,
        "creative": _validate_creative(creative),
        "targeting": targeting or {"audience": "all"},
        "start_date": start_date,
        "end_date": end_date or "",
        "created_by": admin_sub,
        "created_at": ts,
        "updated_at": ts,
        "stats_summary": {"impressions": 0, "clicks": 0, "ctr": 0},
        "treasury_ledger_entry_id": spend_result.get("ledger_entry_id", ""),
    }
    T.syndicates.put_item(Item=campaign)

    syndicate_svc._write_audit(
        syndicate_id, admin_sub, "campaign_created",
        campaign_id, {"budget_cents": budget_cents, "name": name},
    )

    return campaign


def update_campaign_status(
    *,
    syndicate_id: str,
    campaign_id: str,
    admin_sub: str,
    new_status: str,
) -> Dict[str, Any]:
    """Pause, resume, or cancel a campaign."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    campaign = _get_campaign(syndicate_id, campaign_id)

    current = campaign["status"]
    valid_transitions = {
        "active": ["paused", "cancelled"],
        "paused": ["active", "cancelled"],
        "draft": ["active", "cancelled"],
    }
    allowed = valid_transitions.get(current, [])
    if new_status not in allowed:
        raise ValueError(f"Cannot transition from {current} to {new_status}")

    ts = now_ts()
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET #s = :s, updated_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": new_status, ":t": ts},
    )

    # If cancelled, return remaining budget to treasury
    if new_status == "cancelled":
        remaining = campaign.get("remaining_cents", 0)
        if remaining > 0:
            from app.services.billing_shared import apply_wallet_delta, new_ledger_entry
            apply_wallet_delta(T.billing, f"TREASURY#{syndicate_id}", remaining)
            new_ledger_entry(
                T.billing, f"TREASURY#{syndicate_id}",
                amount_cents=remaining,
                entry_type="credit",
                reason=f"Cancelled campaign budget refund: {campaign_id}",
                meta={"campaign_id": campaign_id},
            )

    syndicate_svc._write_audit(
        syndicate_id, admin_sub, "campaign_status_changed",
        campaign_id, {"from": current, "to": new_status},
    )

    campaign["status"] = new_status
    campaign["updated_at"] = ts
    return campaign


def add_campaign_budget(
    *,
    syndicate_id: str,
    campaign_id: str,
    admin_sub: str,
    additional_cents: int,
) -> Dict[str, Any]:
    """Add more budget to an existing campaign from treasury."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)

    if additional_cents <= 0:
        raise ValueError("Additional budget must be positive")

    balance = get_treasury_balance(syndicate_id)
    if balance.get("wallet_balance_cents", 0) < additional_cents:
        raise ValueError("Insufficient treasury balance")

    # Deduct from treasury
    spend_on_advertising(
        syndicate_id=syndicate_id,
        admin_sub=admin_sub,
        amount_cents=additional_cents,
        campaign_id=campaign_id,
        campaign_name="Budget top-up",
    )

    # Update campaign budget
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression=(
            "SET budget_cents = budget_cents + :add, "
            "remaining_cents = remaining_cents + :add, "
            "updated_at = :t"
        ),
        ExpressionAttributeValues={":add": additional_cents, ":t": now_ts()},
    )

    return _get_campaign(syndicate_id, campaign_id)


def record_campaign_impression(
    *,
    campaign_id: str,
    syndicate_id: str,
    viewer_user_id: str,
    clicked: bool = False,
) -> None:
    """Record an ad impression/click for a syndicate campaign."""
    campaign = _get_campaign(syndicate_id, campaign_id)
    if campaign["status"] != "active":
        return
    if campaign.get("remaining_cents", 0) <= 0:
        return

    ts = now_ts()
    date_str = _date_str(ts)
    cost_per_impression = 1  # 1 cent per impression (configurable in future)

    # Update daily stats
    T.syndicates.update_item(
        Key={
            "pk": f"CAMPAIGN_STATS#{campaign_id}",
            "sk": f"DATE#{date_str}",
        },
        UpdateExpression=(
            "SET impressions = if_not_exists(impressions, :z) + :one, "
            "clicks = if_not_exists(clicks, :z) + :click, "
            "spend_cents = if_not_exists(spend_cents, :z) + :cost, "
            "#d = :date"
        ),
        ExpressionAttributeNames={"#d": "date"},
        ExpressionAttributeValues={
            ":z": 0,
            ":one": 1,
            ":click": 1 if clicked else 0,
            ":cost": cost_per_impression,
            ":date": date_str,
        },
    )

    # Update campaign summary
    click_incr = 1 if clicked else 0
    T.syndicates.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression=(
            "SET spent_cents = spent_cents + :cost, "
            "remaining_cents = remaining_cents - :cost, "
            "stats_summary.impressions = if_not_exists(stats_summary.impressions, :z) + :one, "
            "stats_summary.clicks = if_not_exists(stats_summary.clicks, :z) + :click"
        ),
        ExpressionAttributeValues={
            ":cost": cost_per_impression,
            ":one": 1,
            ":click": click_incr,
            ":z": 0,
        },
    )

    # Auto-complete if budget exhausted
    remaining = campaign.get("remaining_cents", 0) - cost_per_impression
    if remaining <= 0:
        T.syndicates.update_item(
            Key={"pk": f"SYND#{syndicate_id}", "sk": f"CAMPAIGN#{campaign_id}"},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "completed"},
        )


def list_campaigns(
    syndicate_id: str,
    *,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List all campaigns for a syndicate."""
    resp = T.syndicates.query(
        KeyConditionExpression=(
            Key("pk").eq(f"SYND#{syndicate_id}") &
            Key("sk").begins_with("CAMPAIGN#")
        ),
    )
    campaigns = resp.get("Items", [])
    if status:
        campaigns = [c for c in campaigns if c.get("status") == status]
    return sorted(campaigns, key=lambda c: c.get("created_at", 0), reverse=True)


def get_campaign(syndicate_id: str, campaign_id: str) -> Dict[str, Any]:
    """Get campaign details."""
    return _get_campaign(syndicate_id, campaign_id)


def get_campaign_analytics(
    campaign_id: str,
    *,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
) -> Dict[str, Any]:
    """Get daily analytics for a campaign."""
    query_kwargs = {
        "KeyConditionExpression": Key("pk").eq(f"CAMPAIGN_STATS#{campaign_id}"),
    }

    if from_date and to_date:
        query_kwargs["KeyConditionExpression"] &= Key("sk").between(
            f"DATE#{from_date}", f"DATE#{to_date}"
        )
    elif from_date:
        query_kwargs["KeyConditionExpression"] &= Key("sk").gte(f"DATE#{from_date}")

    resp = T.syndicates.query(**query_kwargs)
    daily = resp.get("Items", [])

    total_impressions = sum(int(d.get("impressions", 0)) for d in daily)
    total_clicks = sum(int(d.get("clicks", 0)) for d in daily)
    total_spend = sum(int(d.get("spend_cents", 0)) for d in daily)
    ctr = round(total_clicks / total_impressions * 100, 2) if total_impressions > 0 else 0

    return {
        "campaign_id": campaign_id,
        "daily": daily,
        "totals": {
            "impressions": total_impressions,
            "clicks": total_clicks,
            "spend_cents": total_spend,
            "ctr": ctr,
        },
    }


# --- Internal helpers ---

def _get_campaign(syndicate_id: str, campaign_id: str) -> Dict[str, Any]:
    """Get campaign or raise 404."""
    resp = T.syndicates.get_item(Key={
        "pk": f"SYND#{syndicate_id}",
        "sk": f"CAMPAIGN#{campaign_id}",
    })
    item = resp.get("Item")
    if not item:
        raise ValueError(f"Campaign {campaign_id} not found")
    return item


def _validate_creative(creative: Dict[str, Any]) -> Dict[str, Any]:
    """Validate ad creative content."""
    required = ("headline", "body", "cta_text", "cta_url")
    for field in required:
        if not creative.get(field):
            raise ValueError(f"Creative missing required field: {field}")
    return {
        "headline": creative["headline"][:100],
        "body": creative["body"][:500],
        "image_url": creative.get("image_url", ""),
        "cta_text": creative["cta_text"][:50],
        "cta_url": creative["cta_url"][:200],
    }


def _date_str(ts: int) -> str:
    """Convert Unix timestamp to ISO date string."""
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
```

### 3.3 Backend Router

**New file**: `app/routers/syndicate_advertising.py` (~150 lines)

### 3.4 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/syndicates/{syndicate_id}/campaigns` | `require_ui_session` | Create ad campaign (admin only) |
| `GET` | `/ui/syndicates/{syndicate_id}/campaigns` | `require_ui_session` | List all syndicate campaigns (members) |
| `GET` | `/ui/syndicates/{syndicate_id}/campaigns/{campaign_id}` | `require_ui_session` | Get campaign details (members) |
| `POST` | `/ui/syndicates/{syndicate_id}/campaigns/{campaign_id}/status` | `require_ui_session` | Update campaign status (admin only) |
| `POST` | `/ui/syndicates/{syndicate_id}/campaigns/{campaign_id}/add-budget` | `require_ui_session` | Add budget from treasury (admin only) |
| `GET` | `/ui/syndicates/{syndicate_id}/campaigns/{campaign_id}/analytics` | `require_ui_session` | Get campaign analytics (members) |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Syndicate Advertising (SYND-006) --

class CampaignCreativeIn(BaseModel):
    headline: str = Field(min_length=1, max_length=100)
    body: str = Field(min_length=1, max_length=500)
    image_url: Optional[str] = None
    cta_text: str = Field(min_length=1, max_length=50)
    cta_url: str = Field(min_length=1, max_length=200)

class CampaignTargetingIn(BaseModel):
    audience: str = Field(default="all")
    interests: List[str] = Field(default_factory=list, max_length=10)
    geo: Optional[str] = None
    age_min: Optional[int] = Field(default=None, ge=13, le=100)
    age_max: Optional[int] = Field(default=None, ge=13, le=100)

class CampaignCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)
    budget_cents: int = Field(ge=100, le=10000000)  # $1 - $100,000
    creative: CampaignCreativeIn
    targeting: Optional[CampaignTargetingIn] = None
    start_date: str  # ISO date
    end_date: Optional[str] = None

class CampaignStatusUpdateIn(BaseModel):
    status: str = Field(pattern="^(active|paused|cancelled)$")

class CampaignBudgetAddIn(BaseModel):
    additional_cents: int = Field(ge=100, le=10000000)

class CampaignOut(BaseModel):
    campaign_id: str
    syndicate_id: str
    name: str
    description: str = ""
    status: str
    budget_cents: int = 0
    spent_cents: int = 0
    remaining_cents: int = 0
    creative: Dict[str, Any] = Field(default_factory=dict)
    targeting: Dict[str, Any] = Field(default_factory=dict)
    start_date: str = ""
    end_date: str = ""
    created_by: str = ""
    created_at: int = 0
    updated_at: int = 0
    stats_summary: Dict[str, Any] = Field(default_factory=dict)

class CampaignDailyStatsOut(BaseModel):
    date: str
    impressions: int = 0
    clicks: int = 0
    spend_cents: int = 0
    unique_viewers: int = 0

class CampaignAnalyticsOut(BaseModel):
    campaign_id: str
    daily: List[CampaignDailyStatsOut] = Field(default_factory=list)
    totals: Dict[str, Any] = Field(default_factory=dict)
```

### 3.6 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/syndicates/CampaignsTab.tsx` | Campaign list with status badges | ~200 |
| `frontend/src/pages/syndicates/CreateCampaignDialog.tsx` | Campaign creation form (multi-step) | ~250 |
| `frontend/src/pages/syndicates/CampaignDetailPage.tsx` | Campaign detail with analytics charts | ~300 |
| `frontend/src/pages/syndicates/CampaignAnalyticsChart.tsx` | Daily analytics bar/line chart | ~120 |

**Component tree for CampaignsTab**:

```
CampaignsTab (within SyndicateDetailPage)
├── Card: "Advertising Campaigns"
│   ├── Treasury balance indicator: "$50.00 available"
│   ├── CreateCampaignDialog (admin only, Button: "New Campaign")
│   │   ├── Step 1: Name, description, budget
│   │   │   ├── Budget input with treasury balance check
│   │   │   └── Warning if budget > 50% of treasury
│   │   ├── Step 2: Creative content
│   │   │   ├── Headline, body, image upload
│   │   │   ├── CTA text and URL
│   │   │   └── Preview card
│   │   ├── Step 3: Targeting (optional)
│   │   │   ├── Audience selector
│   │   │   ├── Interest tags
│   │   │   └── Date range
│   │   └── Step 4: Review and confirm
│   └── CampaignList
│       └── For each campaign:
│           ├── Name + status badge (active=green, paused=yellow, completed=gray)
│           ├── Budget bar: spent / total
│           ├── Quick stats: impressions, clicks, CTR
│           ├── Actions (admin):
│           │   ├── "Pause" / "Resume" button
│           │   ├── "Add Budget" button
│           │   └── "Cancel" button (with confirmation)
│           └── Link → CampaignDetailPage

CampaignDetailPage
├── Header: campaign name + status badge
├── Stats cards row: Impressions, Clicks, CTR, Spend
├── CampaignAnalyticsChart
│   ├── Daily impressions bar chart
│   ├── Daily clicks line overlay
│   └── Date range selector
├── Card: "Creative"
│   └── Preview of ad creative (headline, body, image, CTA)
├── Card: "Targeting"
│   └── Targeting configuration display
├── Card: "Budget"
│   ├── Progress bar: spent / total
│   ├── "Add Budget" button (admin)
│   └── Treasury balance reference
└── Card: "Activity Log"
    └── Status change history
```

### 3.7 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/syndicates/:syndicateId/campaigns/:campaignId" element={<CampaignDetailPage />} />
```

### 3.8 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/syndicate_advertising.py` | Campaign management service | ~350 |
| `app/routers/syndicate_advertising.py` | Campaign REST API | ~150 |
| `frontend/src/pages/syndicates/CampaignsTab.tsx` | Campaign list tab | ~200 |
| `frontend/src/pages/syndicates/CreateCampaignDialog.tsx` | Multi-step creation dialog | ~250 |
| `frontend/src/pages/syndicates/CampaignDetailPage.tsx` | Campaign detail + analytics | ~300 |
| `frontend/src/pages/syndicates/CampaignAnalyticsChart.tsx` | Analytics chart | ~120 |
| `frontend/e2e/syndicates-advertising.spec.ts` | E2E tests | ~400 |

### 3.9 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `syndicate_advertising_router` |
| `app/models.py` | Add Campaign* models |
| `frontend/src/api/types.ts` | Add Campaign TypeScript interfaces |
| `frontend/src/api/endpoints/syndicates.ts` | Add campaign API wrappers |
| `frontend/src/pages/syndicates/SyndicateDetailPage.tsx` | Add "Advertising" tab with CampaignsTab |
| `frontend/src/App.tsx` | Add campaign detail route |

---

## 4. Campaign Lifecycle

### 4.1 State Machine

```
                +---------+
                |  draft  |
                +----+----+
                     |
                     v
     +----------> active <----------+
     |           +---+---+          |
     |               |              |
     |          +----+-----+        |
     |          |          |        |
     |          v          v        |
     |      paused    completed     |
     |      +--+--+                 |
     |         |                    |
     +---------+                    |
                                    |
     Any state ---> cancelled ------+
                    (refunds remaining budget)
```

### 4.2 Valid Transitions

| From | To | Triggered By |
|------|----|-------------|
| `draft` | `active` | Admin starts campaign |
| `draft` | `cancelled` | Admin cancels before launch |
| `active` | `paused` | Admin pauses campaign |
| `active` | `completed` | Budget exhausted (automatic) or admin completes |
| `active` | `cancelled` | Admin cancels (refunds remaining budget) |
| `paused` | `active` | Admin resumes campaign |
| `paused` | `cancelled` | Admin cancels (refunds remaining budget) |

### 4.3 Budget Refund on Cancellation

When a campaign is cancelled with remaining budget:
1. Calculate `remaining_cents = budget_cents - spent_cents`.
2. Credit `remaining_cents` back to treasury via `apply_wallet_delta`.
3. Write a treasury ledger credit entry: `"Cancelled campaign budget refund: {campaign_id}"`.
4. Update campaign `remaining_cents = 0`, `status = "cancelled"`.

### 4.4 Budget Exhaustion

The `record_campaign_impression` function checks `remaining_cents` after each impression. When `remaining_cents` reaches 0, the campaign status is automatically set to `"completed"`. No further impressions are served.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/syndicates-advertising.spec.ts`

### Section 443: Campaign Creation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 443.1 | Admin creates campaign with treasury budget | POST; 200; campaign `status=active`; treasury balance decreased by budget_cents |
| 443.2 | Insufficient treasury balance returns error | POST with budget exceeding balance; 400; error mentions "Insufficient treasury balance" |
| 443.3 | Non-admin cannot create campaign | Bob (member) POST; 403 |
| 443.4 | Creative validation rejects missing fields | POST with empty headline; 422 |

### Section 444: Campaign Lifecycle API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 444.1 | Admin pauses active campaign | POST status `paused`; 200; campaign `status=paused` |
| 444.2 | Admin resumes paused campaign | POST status `active`; 200; campaign `status=active` |
| 444.3 | Admin cancels campaign and gets budget refund | POST status `cancelled`; 200; treasury balance increased by remaining_cents |
| 444.4 | Admin adds budget from treasury | POST add-budget 1000 cents; 200; campaign `budget_cents` increased; treasury decreased |
| 444.5 | Invalid status transition rejected | POST status `completed` from `paused`; 400 |

### Section 445: Campaign Analytics API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 445.1 | Campaign list shows all campaigns | GET campaigns; array includes created campaigns with status and stats |
| 445.2 | Campaign detail includes creative and targeting | GET campaign by ID; response has `creative.headline`, `targeting` |
| 445.3 | Analytics shows daily breakdown | Record impressions; GET analytics; `daily` array has entries; `totals` correct |
| 445.4 | All members can view analytics | Bob (non-admin member) GET analytics; 200 |

### Section 446: Advertising UI (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 446.1 | Advertising tab visible on syndicate page | Navigate to syndicate detail; "Advertising" tab visible |
| 446.2 | Create campaign dialog opens for admin | Click "New Campaign"; multi-step dialog appears with budget input |
| 446.3 | Campaign list shows budget progress bar | Campaign card visible with spend / budget progress indicator |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| POST campaigns (create) | `require_ui_session` | Syndicate admin only |
| GET campaigns (list) | `require_ui_session` | Syndicate members only |
| GET campaign detail | `require_ui_session` | Syndicate members only |
| POST status update | `require_ui_session` | Syndicate admin only |
| POST add-budget | `require_ui_session` | Syndicate admin only |
| GET analytics | `require_ui_session` | Syndicate members only |

### 6.2 Financial Controls

- Campaign budget is deducted from treasury atomically at creation time (not on-demand spending).
- Cancelled campaign budget is refunded to treasury (not to any individual's wallet).
- `remaining_cents` is tracked on the campaign; ad serving stops when it reaches 0.
- Budget top-up requires admin authorization and sufficient treasury balance.
- All treasury movements (spend, refund) write ledger entries for audit trail.

### 6.3 Campaign Content Safety

- Creative content (headline, body, image) is validated for length limits but NOT content-moderated in v1.
- CTA URL is stored as-is; no URL validation beyond length. Future: validate URL points to platform pages only.
- Image URL should reference uploaded assets (not arbitrary external URLs). Enforced by frontend upload flow.

### 6.4 Rate Limiting

- Campaign creation: max 5 per syndicate per day.
- Status updates: max 20 per campaign per day (prevents rapid pause/resume abuse).
- Budget top-ups: max 10 per campaign per day.

### 6.5 Data Access Control

- Campaign analytics are visible to all syndicate members (shared transparency).
- Campaign creation details (who created, budget source) are in the syndicate audit log.
- Non-members cannot see any campaign data (membership check on all endpoints).

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| SYND-001 | Required | Syndicate admin checks, membership validation, audit log |
| SYND-004 | Required | Treasury `spend_on_advertising` for budget deduction and refund |
| `app/services/ad_placement.py` | Exists | Ad serving pipeline integration (impression recording patterns) |
| ADS-001 through ADS-019 | Design | Full advertising system design (this ticket creates a thin layer on top) |
| `app/services/billing_shared.py` | Exists | `apply_wallet_delta`, `new_ledger_entry` for budget refunds |

---

## 8. Acceptance Criteria

1. Admin can create ad campaigns funded by syndicate treasury.
2. Treasury balance is checked before campaign creation; insufficient balance returns an error.
3. Campaign budget is deducted from treasury at creation time.
4. Admin can pause, resume, and cancel campaigns.
5. Cancelled campaigns refund remaining budget to treasury (not individual wallets).
6. Admin can add more budget from treasury to an active campaign.
7. Campaign analytics (impressions, clicks, CTR, spend) are tracked daily.
8. All syndicate members can view campaign list and analytics.
9. Campaigns auto-complete when budget is exhausted.
10. All 16 E2E tests pass.
