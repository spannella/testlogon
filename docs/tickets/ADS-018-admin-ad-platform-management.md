# ADS-018: Admin Ad Platform Management

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 10-12 days  
**Dependencies**: ADS-001 (advertiser accounts), ADS-002 (creatives), ADS-004 (serving), ADS-007 (billing), ADS-008 (analytics), ADS-014 (fraud prevention)

---

## 1. Overview & Motivation

### The Gap

The advertising platform (ADS-001 through ADS-017) provides advertiser-facing tools for campaign management, creative upload, optimization, and analytics. However, there is no admin-facing interface for platform operators to manage the advertising system as a whole. Platform admins cannot:

- View total advertising revenue or revenue breakdown by period
- Review and approve/reject ad campaigns and creatives before they go live
- Manage advertiser accounts (suspend, unsuspend, set credit limits)
- Configure platform-wide ad settings (default CPM rates, revenue share, fill rate targets)
- Define content policies (blocked ad categories, prohibited content rules)
- Manage house ads (self-promotion ads shown when no paid ad is available)
- Execute a global ad kill switch in emergencies
- Generate financial reports for advertiser spending, creator earnings, and platform revenue

Without admin controls, the platform operates on autopilot — any advertiser can run any content, there is no moderation, no policy enforcement, and no revenue visibility. This is unacceptable for any commercial ad platform.

### Why This Is Needed

1. **Content moderation**: Ad creatives must be reviewed before going live to prevent inappropriate content, trademark violations, or policy violations. Without a moderation queue, objectionable ads reach users immediately.

2. **Revenue visibility**: Platform operators need real-time revenue dashboards showing total ad revenue, platform share vs. creator share, trends, and projections. This data drives business decisions (pricing, investment, hiring).

3. **Advertiser management**: Admins need to suspend bad actors, adjust credit limits for large advertisers, and manage account-level settings. Without this, individual advertiser problems escalate into platform-wide issues.

4. **Policy enforcement**: Every ad platform has policies: no adult content on family channels, no competitor ads on branded pages, minimum bid floors to maintain quality, etc. These need to be configurable by admins, not hardcoded.

5. **House ads**: When no paid ad is available for a placement (low fill rate), the platform should show its own promotional content rather than a blank space. House ads promote platform features, events, or partners.

6. **Emergency controls**: If an advertiser launches an offensive campaign or a system bug causes incorrect billing, admins need a kill switch to pause all advertising platform-wide instantly.

7. **Financial reporting**: Finance teams need detailed reports on ad revenue for accounting, tax, and investor reporting. Exportable reports with breakdowns by advertiser, creator, content category, and date range.

### Architecture After This Change

```
Admin Dashboard (/admin/ads)
│
├── Revenue Dashboard
│   ├── Total ad revenue (daily/weekly/monthly)
│   ├── Revenue breakdown: platform share vs. creator share
│   ├── Revenue by content type (newsfeed, VOD, broadcast)
│   ├── Top earning creators
│   ├── Top spending advertisers
│   └── Revenue projections
│
├── Campaign Moderation Queue
│   ├── Pending campaigns awaiting review
│   ├── Pending creatives awaiting review
│   ├── Approve / Reject with reason
│   ├── Review history
│   └── Auto-approve rules (optional)
│
├── Advertiser Accounts
│   ├── List all accounts with status
│   ├── Suspend / Unsuspend
│   ├── Set credit limits
│   ├── View account details + campaign history
│   └── Manual balance adjustments
│
├── Policy Management
│   ├── Blocked ad categories
│   ├── Prohibited content rules
│   ├── Minimum bid floors by category
│   ├── Maximum ad frequency per user per day
│   └── Auto-reject rules
│
├── Platform Settings
│   ├── Default CPM rates (by category)
│   ├── Revenue share % (platform vs. creator)
│   ├── Max ad frequency (ads per user per hour)
│   ├── Fill rate targets
│   └── Global ad kill switch
│
├── House Ads
│   ├── CRUD for house ad creatives
│   ├── Priority/weight configuration
│   ├── Display rules (when to show)
│   └── House ad impression analytics
│
└── Financial Reports
    ├── Advertiser spending report
    ├── Creator earnings report
    ├── Platform revenue report
    └── Export as CSV / JSON
```

### Data Flow — Campaign Moderation

```
Advertiser                      Backend                              Admin
    │                              │                                    │
    │── POST /campaigns ──────────>│                                    │
    │   { name, budget, ... }      │                                    │
    │                              │── create campaign ────────────────>│
    │                              │   status = "pending_review"        │
    │<── 201 { status:             │                                    │
    │     "pending_review" }       │                                    │
    │                              │── add to moderation queue ────────>│
    │                              │                                    │
    │                              │                     ┌──────────────│
    │                              │                     │ Admin reviews│
    │                              │                     │ campaign     │
    │                              │                     └──────────────│
    │                              │                                    │
    │                              │<── POST /admin/ads/moderation/     │
    │                              │    {id}/approve ──────────────────│
    │                              │                                    │
    │                              │── update status → "active" ────────│
    │                              │── notify advertiser ───────────────│
    │                              │                                    │
    │<── Notification:             │                                    │
    │    "Campaign approved"       │                                    │
```

---

## 2. Current State Analysis

### 2.1 Admin Auth (`app/auth/deps.py`, `app/auth/policy.py`)

<!-- NOTE: `require_admin_scope(AdminScope.AD_MANAGEMENT)` does not exist as a standalone function. The actual admin auth pattern is `require_admin_scope(AdminScope.XXX)` from `app/auth/policy.py:84`. See `app/routers/admin_moderation.py:36` for example usage. -->
The platform uses scope-based admin auth via `require_admin_scope(scope)` (see `app/auth/policy.py:84`), NOT a generic `require_admin_scope(AdminScope.AD_MANAGEMENT)`. Each admin feature defines its own scope. `require_root_session` exists at `app/auth/deps.py:273`.

Ad platform management should define an `AdminScope.AD_MANAGEMENT` scope (or similar) for most operations, with `require_root_session` for destructive operations (global kill switch, platform settings).

### 2.2 Existing Admin Patterns

The platform already has admin interfaces for other features:
- `app/routers/admin_usage.py`: Admin usage analytics
- Admin role management: Grant/revoke admin roles, audit logs
- Root session controls: Backend only accessible to ROOT role

These patterns establish conventions for admin endpoint design.

### 2.3 Ad Billing (`app/services/billing_shared.py`)

<!-- NOTE: The billing ledger (`T.billing`, see `app/core/tables.py:146`) uses `new_ledger_entry()` (see `billing_shared.py:217`) with a `type` field (not `entry_type`). The specific entry types `ad_revenue_credit` and `platform_ad_commission` do not exist yet — they would need to be added by the ADS-007 (Ad Billing) ticket or this ticket. -->
The billing ledger (`T.billing`) can store ad revenue entries via `new_ledger_entry()` (see `app/services/billing_shared.py:217`). The `type` field on ledger entries identifies the transaction kind. Ad-specific types like `ad_revenue_credit` and `platform_ad_commission` would need to be defined as part of this feature or ADS-007.

### 2.4 Ad Impressions (`T.ad_impressions`)

The `AdImpressions` table (see `scripts/local-ddb-init.py:831-840`, `app/core/tables.py:217`, `app/core/settings.py:1242`) stores impression events. GSIs: `ByVideoCreatedAt` (pk=`video_id`) and `ByCreatorCreatedAt` (pk=`creator_id`). Daily partitions enable efficient date-range aggregation for revenue dashboards.

### 2.5 Campaign/Creative Status Flow

<!-- NOTE: No `ad_campaigns` or `ad_creatives` DDB table, router, or service exists yet in the codebase. The ADS-001 (Advertiser Accounts & Campaign Manager) and ADS-002 (Ad Creative Management) tickets define these but they have not been implemented. The status values described below are from the ADS-001/ADS-002 ticket specs, not from existing code. -->
Campaigns (per ADS-001 spec) have `status` field. Expected values: `draft`, `active`, `paused`, `completed`, `archived`. This ticket adds: `pending_review`, `rejected`.

Creatives (per ADS-002 spec) have `status` field. Expected values: `draft`, `pending_review`, `approved`, `rejected`. The creative review flow is defined in ADS-002 — campaigns need the same pattern.

### 2.6 Gaps

1. No admin revenue dashboard
2. No campaign moderation queue (campaigns go live immediately)
3. No advertiser account management (suspend/unsuspend)
4. No configurable ad policies (hardcoded or nonexistent)
5. No house ads system
6. No global ad kill switch
7. No financial report generation
8. No platform-wide ad settings UI

---

## 3. Technical Design

### 3.1 Admin Revenue Service: `app/services/admin_ad_revenue.py`

```python
"""Admin ad revenue reporting service (ADS-018).

Aggregates ad revenue data for platform-wide dashboards and reports.
"""

def get_revenue_summary(
    *, start_date: str, end_date: str
) -> Dict[str, Any]:
    """Aggregate total ad revenue for a date range.

    Queries billing ledger for ad_revenue_credit and platform_ad_commission
    entries. Returns breakdown by platform share, creator share, and totals.
    """
    return {
        "total_revenue_cents": total,
        "platform_share_cents": platform_share,
        "creator_share_cents": creator_share,
        "revenue_share_percent": platform_share_pct,
        "impressions": total_impressions,
        "clicks": total_clicks,
        "effective_cpm_cents": effective_cpm,
        "period": {"start_date": start_date, "end_date": end_date},
    }

def get_revenue_by_content_type(
    *, start_date: str, end_date: str
) -> List[Dict[str, Any]]:
    """Revenue breakdown by content type (newsfeed, VOD, broadcast)."""
    ...

def get_top_earners(
    *, start_date: str, end_date: str, limit: int = 10
) -> List[Dict[str, Any]]:
    """Top creators by ad revenue."""
    ...

def get_top_spenders(
    *, start_date: str, end_date: str, limit: int = 10
) -> List[Dict[str, Any]]:
    """Top advertisers by ad spend."""
    ...

def get_daily_revenue_series(
    *, start_date: str, end_date: str
) -> List[Dict[str, Any]]:
    """Daily revenue time series for charts."""
    ...
```

### 3.2 Campaign Moderation Service: `app/services/admin_ad_moderation.py`

```python
"""Campaign and creative moderation service (ADS-018).

Manages the review queue for campaigns and creatives before they go live.
"""

MODERATION_STATUSES = ["pending_review", "approved", "rejected"]
AUTO_APPROVE_MAX_BUDGET = 10000  # Auto-approve campaigns with budget <= $100

def list_pending_reviews(
    *, item_type: str = "all",  # "campaign", "creative", "all"
    limit: int = 50, cursor: str = None,
) -> Dict[str, Any]:
    """List items awaiting moderation review.

    Queries campaigns and creatives with status="pending_review".
    Returns sorted by submission time (oldest first).
    """
    ...

def approve_campaign(
    *, campaign_id: str, admin_sub: str, notes: str = ""
) -> Dict[str, Any]:
    """Approve a campaign for serving.

    Updates status from pending_review → active.
    Records moderation event. Notifies advertiser.
    """
    ...

def reject_campaign(
    *, campaign_id: str, admin_sub: str, reason: str
) -> Dict[str, Any]:
    """Reject a campaign.

    Updates status from pending_review → rejected.
    Records moderation event with rejection reason.
    Notifies advertiser with reason.
    """
    ...

def approve_creative(
    *, creative_id: str, admin_sub: str, notes: str = ""
) -> Dict[str, Any]:
    """Approve a creative for use in campaigns."""
    ...

def reject_creative(
    *, creative_id: str, admin_sub: str, reason: str
) -> Dict[str, Any]:
    """Reject a creative."""
    ...

def get_moderation_history(
    *, item_type: str, item_id: str
) -> List[Dict[str, Any]]:
    """Get moderation review history for a campaign or creative."""
    ...
```

### 3.3 DynamoDB: Moderation Events

Stored in the same `ad_campaigns` or `ad_creatives` table (single-table pattern):

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `MODERATION#{item_type}#{item_id}` |
| `sk` | S | `EVENT#{ts}#{event_id}` |
| `action` | S | `"approved"`, `"rejected"`, `"appealed"` |
| `admin_sub` | S | Admin who took the action |
| `reason` | S | Rejection reason (empty for approvals) |
| `notes` | S | Admin notes |
| `created_at` | N | Unix timestamp |

### 3.4 Platform Ad Settings

**DDB storage**: Single item in a platform settings table:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `PLATFORM_ADS` |
| `sk` | S | `SETTINGS` |
| `default_cpm_cents` | N | Default CPM rate (500 = $5) |
| `revenue_share_bps` | N | Platform share in basis points (2000 = 20%) |
| `max_ad_frequency_per_hour` | N | Max ads per user per hour |
| `fill_rate_target` | N | Target fill rate percentage (80 = 80%) |
| `ads_enabled` | BOOL | Global ad kill switch |
| `moderation_required` | BOOL | Whether campaigns require approval |
| `auto_approve_budget_threshold_cents` | N | Auto-approve below this budget |
| `blocked_categories` | L | List of blocked ad category strings |
| `min_bid_floor_cents` | N | Minimum bid floor |
| `updated_at` | N | Unix timestamp |
| `updated_by` | S | Admin who last updated settings |

### 3.5 Advertiser Account Management

Extend advertiser account records with admin-managed fields:

```python
# Admin-managed fields on advertiser account
admin_status: str  # "active", "suspended", "under_review"
credit_limit_cents: int  # Maximum outstanding balance
admin_notes: str  # Admin notes on account
suspended_at: Optional[int]  # When suspended
suspended_by: Optional[str]  # Admin who suspended
suspension_reason: Optional[str]  # Why suspended
```

### 3.6 House Ads Service: `app/services/house_ads.py`

```python
"""House ads management (ADS-018).

House ads are platform self-promotion ads shown when no paid ad
is available for a placement (low fill rate / no matching campaigns).
"""

def create_house_ad(
    *, name: str, creative_url: str, creative_type: str,
    click_through_url: str, priority: int = 50,
    display_rules: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Create a house ad.

    House ads are stored in the ad_house_ads table.
    Priority: 1-100 (higher = more likely to be shown).
    Display rules: when to show (e.g., content_type, geo).
    """
    ...

def get_house_ad() -> Optional[Dict[str, Any]]:
    """Select a house ad for display.

    Weighted random selection based on priority.
    Returns None if no house ads exist.
    """
    ...

def list_house_ads() -> List[Dict[str, Any]]:
    """List all house ads."""
    ...

def update_house_ad(
    *, house_ad_id: str, **updates
) -> Dict[str, Any]:
    """Update a house ad."""
    ...

def delete_house_ad(*, house_ad_id: str) -> bool:
    """Delete a house ad."""
    ...
```

### 3.7 House Ads DDB Table: `ad_house_ads`

**Table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="ad_house_ads",
    pk="pk", sk="sk",
    gsis=[],
)
```

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `HOUSE_AD#{house_ad_id}` |
| `sk` | S | `META` |
| `house_ad_id` | S | Unique ID |
| `name` | S | Display name |
| `creative_url` | S | Asset URL |
| `creative_type` | S | `"image"`, `"video"` |
| `click_through_url` | S | Destination URL |
| `priority` | N | 1-100 weight |
| `display_rules` | M | Content type, geo filters |
| `active` | BOOL | Whether house ad is active |
| `impression_count` | N | Total impressions served |
| `click_count` | N | Total clicks |
| `created_at` | N | Unix timestamp |
| `created_by` | S | Admin who created |

**Settings** in `app/core/settings.py`:
```python
ad_house_ads_table_name: str = os.environ.get("DDB_AD_HOUSE_ADS", "ad_house_ads")
```

**Table handle** in `app/core/tables.py`:
```python
ad_house_ads=ddb.Table(S.ad_house_ads_table_name),
```

### 3.8 Global Ad Kill Switch

The kill switch is a boolean field `ads_enabled` in platform settings. When disabled:

```python
# In ad serving engine (ADS-004)
def serve_ad(*, context, viewer_id, ...):
    settings = get_platform_ad_settings()
    if not settings.get("ads_enabled", True):
        return {"ad": None, "reason": "ads_globally_disabled"}

    # ... normal ad serving logic ...
```

The kill switch endpoint requires ROOT role:

```python
@router.post("/v1/admin/ads/kill-switch")
async def toggle_kill_switch(
    body: KillSwitchToggle,
    session: dict = Depends(require_root_session),
):
    """Toggle global ad platform enable/disable.

    Requires ROOT role. When disabled, no ads are served anywhere.
    House ads are also disabled.
    """
    ...
```

### 3.9 Financial Reports

```python
def generate_financial_report(
    *, report_type: str,  # "advertiser_spending", "creator_earnings", "platform_revenue"
    start_date: str, end_date: str,
    format: str = "json",  # "json" or "csv"
) -> Dict[str, Any]:
    """Generate a financial report for the specified period.

    Advertiser spending: per-advertiser breakdown of campaign spend
    Creator earnings: per-creator breakdown of ad revenue + commissions
    Platform revenue: total platform share from all ad activities
    """
    ...
```

### 3.10 Router: `app/routers/admin_ads.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/ads/revenue` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Revenue summary |
| GET | `/v1/admin/ads/revenue/daily` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Daily revenue time series |
| GET | `/v1/admin/ads/revenue/by-content` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Revenue by content type |
| GET | `/v1/admin/ads/revenue/top-earners` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Top earning creators |
| GET | `/v1/admin/ads/revenue/top-spenders` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Top spending advertisers |
| GET | `/v1/admin/ads/moderation` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Moderation queue |
| POST | `/v1/admin/ads/moderation/{type}/{id}/approve` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Approve campaign/creative |
| POST | `/v1/admin/ads/moderation/{type}/{id}/reject` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Reject campaign/creative |
| GET | `/v1/admin/ads/moderation/{type}/{id}/history` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Moderation history |
| GET | `/v1/admin/ads/accounts` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | List all advertiser accounts |
| GET | `/v1/admin/ads/accounts/{id}` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Account details |
| POST | `/v1/admin/ads/accounts/{id}/suspend` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Suspend account |
| POST | `/v1/admin/ads/accounts/{id}/unsuspend` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Unsuspend account |
| PATCH | `/v1/admin/ads/accounts/{id}/credit-limit` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Set credit limit |
| GET | `/v1/admin/ads/settings` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Get platform ad settings |
| PATCH | `/v1/admin/ads/settings` | `require_root_session` | Update platform ad settings |
| POST | `/v1/admin/ads/kill-switch` | `require_root_session` | Toggle global ad kill switch |
| POST | `/v1/admin/ads/house-ads` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Create house ad |
| GET | `/v1/admin/ads/house-ads` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | List house ads |
| GET | `/v1/admin/ads/house-ads/{id}` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Get house ad details |
| PATCH | `/v1/admin/ads/house-ads/{id}` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Update house ad |
| DELETE | `/v1/admin/ads/house-ads/{id}` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Delete house ad |
| GET | `/v1/admin/ads/reports/{type}` | `require_admin_scope(AdminScope.AD_MANAGEMENT)` | Generate financial report |

### 3.11 Pydantic Models

**File**: `app/models.py`

```python
class AdminAdRevenueSummary(BaseModel):
    total_revenue_cents: int
    platform_share_cents: int
    creator_share_cents: int
    revenue_share_percent: float
    impressions: int
    clicks: int
    effective_cpm_cents: int
    period: Dict[str, str]

class AdminModerationItem(BaseModel):
    item_type: str  # "campaign" or "creative"
    item_id: str
    advertiser_id: str
    name: str
    status: str
    submitted_at: int
    details: Dict[str, Any]

class AdminModerationAction(BaseModel):
    action: str = Field(pattern=r"^(approve|reject)$")
    reason: str = Field(default="", max_length=500)
    notes: str = Field(default="", max_length=1000)

class AdminAccountSuspend(BaseModel):
    reason: str = Field(min_length=1, max_length=500)

class AdminCreditLimitUpdate(BaseModel):
    credit_limit_cents: int = Field(ge=0)

class AdminPlatformSettings(BaseModel):
    default_cpm_cents: Optional[int] = Field(default=None, ge=100, le=10000)
    revenue_share_bps: Optional[int] = Field(default=None, ge=500, le=5000)
    max_ad_frequency_per_hour: Optional[int] = Field(default=None, ge=1, le=100)
    fill_rate_target: Optional[int] = Field(default=None, ge=10, le=100)
    moderation_required: Optional[bool] = None
    auto_approve_budget_threshold_cents: Optional[int] = Field(default=None, ge=0)
    blocked_categories: Optional[List[str]] = None
    min_bid_floor_cents: Optional[int] = Field(default=None, ge=0)

class KillSwitchToggle(BaseModel):
    enabled: bool
    reason: str = Field(default="", max_length=500)

class HouseAdCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    creative_url: str
    creative_type: str = Field(pattern=r"^(image|video)$")
    click_through_url: str
    priority: int = Field(default=50, ge=1, le=100)
    display_rules: Optional[Dict[str, Any]] = None

class HouseAdUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    creative_url: Optional[str] = None
    click_through_url: Optional[str] = None
    priority: Optional[int] = Field(default=None, ge=1, le=100)
    active: Optional[bool] = None
    display_rules: Optional[Dict[str, Any]] = None

class FinancialReportRequest(BaseModel):
    start_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    end_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    format: str = Field(default="json", pattern=r"^(json|csv)$")
```

### 3.12 Frontend: Admin Ad Dashboard

**Route**: `/admin/ads` in `frontend/src/App.tsx`

**File**: `frontend/src/pages/admin/ads/AdminAdDashboard.tsx`

Tabbed layout:

```tsx
<Tabs defaultValue="revenue">
  <TabsList>
    <TabsTrigger value="revenue">Revenue</TabsTrigger>
    <TabsTrigger value="moderation">Moderation</TabsTrigger>
    <TabsTrigger value="accounts">Accounts</TabsTrigger>
    <TabsTrigger value="policies">Policies</TabsTrigger>
    <TabsTrigger value="settings">Settings</TabsTrigger>
    <TabsTrigger value="house-ads">House Ads</TabsTrigger>
    <TabsTrigger value="reports">Reports</TabsTrigger>
  </TabsList>
</Tabs>
```

**Revenue Tab**: Revenue summary cards, daily revenue chart (line graph), revenue by content type (pie chart), top earners table, top spenders table.

**Moderation Tab**: Queue of pending items with preview, approve/reject buttons, rejection reason dialog, review history accordion.

**Accounts Tab**: DataTable of advertiser accounts with status badges, search, sort. Row actions: suspend/unsuspend, set credit limit, view details.

**Policies Tab**: Form for blocked categories (tag input), prohibited content rules (text area), min bid floor (number input).

**Settings Tab**: Form for default CPM, revenue share %, max frequency, fill rate target, moderation toggle, auto-approve threshold. Global kill switch button (red, requires confirmation dialog).

**House Ads Tab**: CRUD list/cards for house ads with creative preview, priority slider, active toggle.

**Reports Tab**: Report type selector, date range picker, format selector, "Generate" button, download link.

### 3.13 Frontend API

**File**: `frontend/src/api/endpoints/adminAds.ts`

```typescript
// Revenue
export const getRevenueSummary = (params: { start_date: string; end_date: string }) =>
  client.get("/v1/admin/ads/revenue", { params });
export const getDailyRevenue = (params: { start_date: string; end_date: string }) =>
  client.get("/v1/admin/ads/revenue/daily", { params });
export const getRevenueByContent = (params: { start_date: string; end_date: string }) =>
  client.get("/v1/admin/ads/revenue/by-content", { params });
export const getTopEarners = (params: { start_date: string; end_date: string; limit?: number }) =>
  client.get("/v1/admin/ads/revenue/top-earners", { params });
export const getTopSpenders = (params: { start_date: string; end_date: string; limit?: number }) =>
  client.get("/v1/admin/ads/revenue/top-spenders", { params });

// Moderation
export const getModerationQueue = (params?: { item_type?: string; limit?: number; cursor?: string }) =>
  client.get("/v1/admin/ads/moderation", { params });
export const moderateItem = (type: string, id: string, data: AdminModerationAction) =>
  client.post(`/v1/admin/ads/moderation/${type}/${id}/${data.action}`, data);
export const getModerationHistory = (type: string, id: string) =>
  client.get(`/v1/admin/ads/moderation/${type}/${id}/history`);

// Accounts
export const getAdvertiserAccounts = () =>
  client.get("/v1/admin/ads/accounts");
export const getAdvertiserAccount = (id: string) =>
  client.get(`/v1/admin/ads/accounts/${id}`);
export const suspendAccount = (id: string, data: { reason: string }) =>
  client.post(`/v1/admin/ads/accounts/${id}/suspend`, data);
export const unsuspendAccount = (id: string) =>
  client.post(`/v1/admin/ads/accounts/${id}/unsuspend`);
export const setCreditLimit = (id: string, data: { credit_limit_cents: number }) =>
  client.patch(`/v1/admin/ads/accounts/${id}/credit-limit`, data);

// Settings
export const getAdSettings = () =>
  client.get("/v1/admin/ads/settings");
export const updateAdSettings = (data: AdminPlatformSettings) =>
  client.patch("/v1/admin/ads/settings", data);
export const toggleKillSwitch = (data: { enabled: boolean; reason?: string }) =>
  client.post("/v1/admin/ads/kill-switch", data);

// House Ads
export const createHouseAd = (data: HouseAdCreate) =>
  client.post("/v1/admin/ads/house-ads", data);
export const listHouseAds = () =>
  client.get("/v1/admin/ads/house-ads");
export const updateHouseAd = (id: string, data: HouseAdUpdate) =>
  client.patch(`/v1/admin/ads/house-ads/${id}`, data);
export const deleteHouseAd = (id: string) =>
  client.delete(`/v1/admin/ads/house-ads/${id}`);

// Reports
export const generateReport = (type: string, params: { start_date: string; end_date: string; format?: string }) =>
  client.get(`/v1/admin/ads/reports/${type}`, { params });
```

---

## 4. Implementation Plan

### 4.1 Backend — Phase 1: Revenue & Moderation (Days 1-3)

1. **`app/services/admin_ad_revenue.py`**: New file. Revenue aggregation functions.
2. **`app/services/admin_ad_moderation.py`**: New file. Moderation queue, approve/reject logic.
3. **`app/models.py`**: Add admin ad Pydantic models.

### 4.2 Backend — Phase 2: Accounts & Settings (Days 4-5)

4. **`app/services/admin_ad_settings.py`**: New file. Platform settings CRUD, kill switch.
5. **Advertiser account management**: Extend account service with suspend/unsuspend/credit-limit.
6. **Policy management**: Settings storage with blocked categories, bid floors.

### 4.3 Backend — Phase 3: House Ads & Reports (Days 6-7)

7. **`app/services/house_ads.py`**: New file. House ad CRUD, selection algorithm.
8. **`scripts/local-ddb-init.py`**: Add `ad_house_ads` table definition.
9. **`app/core/settings.py`**: Add `ad_house_ads_table_name`.
10. **`app/core/tables.py`**: Add `ad_house_ads` table handle.
11. **Financial report generation**: CSV/JSON export functions.

### 4.4 Backend — Phase 4: Router (Days 7-8)

12. **`app/routers/admin_ads.py`**: New router. All admin endpoints (23 endpoints). Register in `app/main.py`.
13. **`app/main.py`**: Register router with prefix `/v1/admin/ads`.

### 4.5 Frontend (Days 8-10)

14. **`frontend/src/api/types.ts`**: Add admin ad TypeScript types.
15. **`frontend/src/api/endpoints/adminAds.ts`**: New file. API wrappers.
16. **`frontend/src/pages/admin/ads/AdminAdDashboard.tsx`**: New page. Tabbed admin dashboard.
17. **`frontend/src/App.tsx`**: Add `/admin/ads` route.
18. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Ad Management" link under Admin section (visible to ADMIN+ roles).

### 4.6 E2E Tests (Days 10-12)

19. **`frontend/e2e/admin-ads.spec.ts`**: New file. 18 tests across 5 sections.

---

## 5. Security Considerations

### 5.1 Role-Based Access

- Revenue, moderation, accounts, house ads: require ADMIN role (`require_admin_scope(AdminScope.AD_MANAGEMENT)`)
- Platform settings, kill switch: require ROOT role (`require_root_session`)
- Financial reports: require ADMIN role (data is sensitive but not destructive)

### 5.2 Kill Switch Safety

- Kill switch toggle requires ROOT role (highest privilege level)
- Kill switch changes are logged with actor, timestamp, and reason
- Enabling the kill switch takes effect within 1 minute (next ad serving cycle)
- House ads are also suppressed when the kill switch is active

### 5.3 Account Suspension Audit

- All suspend/unsuspend actions are logged with actor, timestamp, and reason
- Suspended accounts cannot create or activate campaigns
- Existing active campaigns are paused when an account is suspended
- Campaigns are NOT automatically resumed when an account is unsuspended (manual action required)

### 5.4 Moderation History

- All moderation decisions (approve/reject) are recorded with admin identity and timestamp
- Rejected items include the rejection reason (visible to the advertiser)
- Moderation history is immutable (cannot be deleted or edited)

### 5.5 Financial Report Access

- Reports contain sensitive financial data (advertiser spend, creator earnings)
- Reports are generated on-demand and not cached (no stale data)
- CSV/JSON export should be transmitted over HTTPS only

---

## 6. Testing Strategy

### 6.1 Unit Tests (`tests/test_admin_ads.py`)

| # | Test | Description |
|---|------|-------------|
| 1 | Revenue summary aggregates correctly | Sum of platform + creator = total |
| 2 | Campaign approval changes status | status → "active" |
| 3 | Campaign rejection records reason | rejection event has reason text |
| 4 | Account suspend pauses campaigns | Active campaigns → paused |
| 5 | Kill switch disables ad serving | serve_ad returns null |
| 6 | House ad selection weighted by priority | Higher priority → more selections |
| 7 | Platform settings saved and loaded | Write → read → values match |
| 8 | Non-admin cannot access admin endpoints | 403 response |

### 6.2 E2E Tests (`frontend/e2e/admin-ads.spec.ts`)

**Test File**: `frontend/e2e/admin-ads.spec.ts`

**Test setup (beforeAll):**
- Seed sessions for Alice (advertiser), Root (admin), Charlie (admin)
- Create an advertiser account as Alice
- Create a campaign and creative (status="pending_review")

**Section 414: Revenue Dashboard API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Admin can view revenue summary` | GET /admin/ads/revenue as Root → 200, has total_revenue_cents, platform_share_cents |
| 2 | `Daily revenue returns time series` | GET /admin/ads/revenue/daily → 200, array of daily entries |
| 3 | `Top earners returns creator list` | GET /admin/ads/revenue/top-earners → 200, sorted array |
| 4 | `Non-admin cannot access revenue` | GET /admin/ads/revenue as Alice → 403 |

**Section 415: Campaign Moderation API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Moderation queue lists pending items` | GET /admin/ads/moderation → 200, includes the pending campaign |
| 6 | `Admin approves campaign` | POST /moderation/campaign/{id}/approve → 200, status="active" |
| 7 | `Admin rejects creative with reason` | POST /moderation/creative/{id}/reject with reason → 200, status="rejected" |
| 8 | `Moderation history records all actions` | GET /moderation/campaign/{id}/history → array with approve/reject events |

**Section 416: Advertiser Account Management API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Admin lists advertiser accounts` | GET /admin/ads/accounts → 200, includes Alice's account |
| 10 | `Admin suspends account` | POST /accounts/{id}/suspend → 200, status="suspended" |
| 11 | `Admin unsuspends account` | POST /accounts/{id}/unsuspend → 200, status="active" |
| 12 | `Admin sets credit limit` | PATCH /accounts/{id}/credit-limit → 200, credit_limit_cents updated |

**Section 417: Platform Settings & Kill Switch API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | `Root can update platform settings` | PATCH /admin/ads/settings as Root → 200, settings saved |
| 14 | `Root can toggle kill switch` | POST /admin/ads/kill-switch {enabled: false} → 200, ads_enabled=false |
| 15 | `Admin (non-root) cannot update settings` | PATCH /admin/ads/settings as Charlie → 403 |

**Section 418: House Ads CRUD API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 16 | `Admin creates house ad` | POST /admin/ads/house-ads → 201, house_ad_id present |
| 17 | `Admin lists house ads` | GET /admin/ads/house-ads → 200, array includes created house ad |
| 18 | `Admin deletes house ad` | DELETE /admin/ads/house-ads/{id} → 200, re-list excludes it |

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/admin_ad_revenue.py` | Revenue aggregation and reporting |
| `app/services/admin_ad_moderation.py` | Campaign/creative moderation queue |
| `app/services/admin_ad_settings.py` | Platform ad settings management |
| `app/services/house_ads.py` | House ad CRUD and selection |
| `app/routers/admin_ads.py` | Admin ad management router (23 endpoints) |
| `frontend/src/api/endpoints/adminAds.ts` | Admin ad API wrappers |
| `frontend/src/pages/admin/ads/AdminAdDashboard.tsx` | Admin ad management dashboard |
| `frontend/e2e/admin-ads.spec.ts` | E2E tests (18 tests, sections 414-418) |
| `tests/test_admin_ads.py` | Unit tests |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add admin ad Pydantic models |
| `app/main.py` | Register `admin_ads_router` |
| `app/core/settings.py` | Add `ad_house_ads_table_name` |
| `app/core/tables.py` | Add `ad_house_ads` table handle |
| `scripts/local-ddb-init.py` | Add `ad_house_ads` table |
| `frontend/src/api/types.ts` | Add admin ad TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/ads` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Ad Management" admin nav link |

## 9. Acceptance Criteria

1. Admin revenue dashboard shows total revenue, platform/creator split, impressions, clicks, and effective CPM for any date range
2. Daily revenue time series, revenue by content type, top earners, and top spenders available
3. Campaign moderation queue lists pending items with approve/reject actions and rejection reasons
4. Moderation history records all decisions with admin identity and timestamp
5. Advertiser accounts can be listed, suspended, unsuspended, and have credit limits adjusted
6. Platform ad settings are configurable (CPM, revenue share, frequency, fill rate, moderation toggle, blocked categories)
7. Global ad kill switch requires ROOT role and disables all ad serving when activated
8. House ads can be created, listed, updated, and deleted with priority-based selection
9. Financial reports can be generated for advertiser spending, creator earnings, and platform revenue
10. All 18 E2E tests pass in `frontend/e2e/admin-ads.spec.ts`

---

## Codebase References

| Reference | Path | Line(s) | Status |
|-----------|------|---------|--------|
| Admin auth (scope-based) | `app/auth/policy.py` | 84 (`require_admin_scope`) | Verified — use this instead of nonexistent `require_admin_session` |
| Root session auth | `app/auth/deps.py` | 273 (`require_root_session`) | Verified |
| Role enum | `app/auth/roles.py` | 8-11 (`Role.ROOT`, `Role.ADMIN`, `Role.USER`) | Verified |
| AdminScope enum | `app/auth/roles.py` | 26 (`CANONICAL_ADMIN_SCOPES`) | Verified — `AD_MANAGEMENT` scope needs to be added |
| Billing ledger helper | `app/services/billing_shared.py` | 217 (`new_ledger_entry`) | Verified |
| Billing table handle | `app/core/tables.py` | 146 (`T.billing`) | Verified |
| Ad impressions table handle | `app/core/tables.py` | 217 (`T.ad_impressions`) | Verified |
| Ad impressions DDB table | `scripts/local-ddb-init.py` | 831-840 (`AdImpressions`) | Verified |
| Ad impressions settings | `app/core/settings.py` | 1242 (`ad_impressions_table_name`) | Verified |
| Ad placement service | `app/services/ad_placement.py` | (entire file) | Verified — exists (VOD-018) |
| Admin usage router (pattern ref) | `app/routers/admin_usage.py` | (entire file) | Verified |
| Router registration pattern | `app/main.py` | 297-465 (`app.include_router(...)`) | Verified |
| Admin pages directory | `frontend/src/pages/admin/` | (directory) | Verified — exists |
| Ad campaigns table/service | — | — | **Does not exist** — requires ADS-001 implementation first |
| Ad creatives table/service | — | — | **Does not exist** — requires ADS-002 implementation first |
| `ad_house_ads` table | `scripts/local-ddb-init.py` | — | **Does not exist** — new table required |
| `ad_house_ads_table_name` setting | `app/core/settings.py` | — | **Does not exist** — new setting required |
| `admin_ads` router | `app/routers/admin_ads.py` | — | **Does not exist** — new file required |
