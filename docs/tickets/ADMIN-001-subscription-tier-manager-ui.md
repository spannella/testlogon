# ADMIN-001: Subscription Tier Manager UI

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 7-9 days  
**Dependencies**: Subscription access (`subscription_access.py` — see `app/services/subscription_access.py`), subscription entitlements (`subscription_entitlement_templates.py` — see `app/services/subscription_entitlement_templates.py`), subscription cycle orders (`subscription_cycle_orders.py` — see `app/services/subscription_cycle_orders.py`), UI session auth (`auth/deps.py` — see `app/auth/deps.py`)
<!-- NOTE: auth/deps.py provides `require_ui_session` (line 175) and `require_root_session` (line 273). There is no `require_admin_session` in deps.py. Admin auth helpers are in `app/auth/policy.py`: `require_admin_or_root` (line 67), `require_admin_scope` (line 84), `require_root` (line 63). -->

---

## 1. Overview & Motivation

### The Gap

The backend supports subscription tier CRUD through `subscription_access.py` (see `app/services/subscription_access.py`) and `subscription_entitlement_templates.py` (see `app/services/subscription_entitlement_templates.py`), and the subscription lifecycle is managed via `subscription_cycle_orders.py` (see `app/services/subscription_cycle_orders.py`). Subscription plans can be created, updated, and deleted through API endpoints. However, there is no creator-facing UI for managing subscription tiers. Creators cannot:

- Create new subscription tiers with name, price, billing cycle, and description
- Edit existing tier details (price, benefits, description)
- Delete or archive tiers (stop new signups while keeping existing subscribers)
- Preview how tiers appear to potential subscribers
- View subscriber counts per tier
- See revenue analytics per tier
- Reorder tiers for display presentation

Without a management UI, tier configuration requires API calls or database manipulation — both impractical for non-technical creators.

### Why This Is Needed

1. **Creator self-service**: Creators are the primary revenue generators. They need intuitive tools to configure their subscription offerings without platform support tickets.

2. **Tier optimization**: Creators who can easily add/edit/test tiers will experiment with pricing and benefits, leading to higher subscription conversion rates and platform revenue.

3. **Subscriber visibility**: Knowing how many subscribers are on each tier — and how much revenue each generates — helps creators make informed pricing decisions.

4. **Tier lifecycle**: When a creator wants to stop offering a tier (e.g., replacing "Bronze" with "Silver"), they need to archive it (no new signups) rather than delete it (which would break existing subscribers).

5. **Presentation control**: The order tiers appear in matters for conversion. Creators should be able to place their most popular or best-value tier first.

### User Stories

- As a **creator**, I want to create subscription tiers with name, price, and benefits so potential subscribers can choose a plan.
- As a **creator**, I want to edit a tier's price and description so I can adjust my offering over time.
- As a **creator**, I want to archive a tier so existing subscribers keep access but no new signups are allowed.
- As a **creator**, I want to see subscriber count and revenue per tier so I can optimize my pricing.
- As a **creator**, I want to reorder my tiers so the best-value option appears first.
- As a **creator**, I want to preview how my tiers look to potential subscribers.

### Architecture After This Change

```
Subscription Tier Manager (/subscriptions/manage)
│
├── Tier List
│   ├── Card per tier (name, price, cycle, subscriber count, revenue)
│   ├── Drag-and-drop reorder
│   ├── Status badge: active, archived
│   └── Actions: edit, archive, delete (if no subscribers)
│
├── Create/Edit Tier Dialog
│   ├── Name (text input)
│   ├── Price (currency input)
│   ├── Billing cycle (monthly, quarterly, yearly)
│   ├── Description (textarea)
│   ├── Benefits list (add/remove items)
│   ├── Access level (basic, premium, vip)
│   └── Save / Cancel
│
├── Tier Preview
│   ├── Subscriber-facing view of all tiers
│   ├── Comparison table (feature matrix)
│   └── Mobile-responsive preview
│
├── Tier Analytics
│   ├── Subscriber count per tier (bar chart)
│   ├── Revenue per tier (pie chart)
│   ├── Subscription growth over time (line chart)
│   └── Churn rate per tier
│
└── Tier Lifecycle
    ├── Active → Archived (no new signups)
    ├── Archived → Active (re-enable signups)
    └── Delete (only if zero subscribers)
```

### Architecture & Data Flow

```
┌──────────────────┐     ┌────────────────────────┐     ┌────────────────────┐
│  React Frontend  │     │  FastAPI Backend        │     │  DynamoDB          │
│  TierManager.tsx │────>│  /v1/subscriptions/     │────>│  billing table     │
│                  │<────│  tiers/*                 │<────│  PK=CREATOR#{}     │
│  - TierCard      │     │                          │     │  SK=TIER#{}        │
│  - TierDialog    │     │  tier_management.py      │     │                    │
│  - TierPreview   │     │  (service layer)         │     │  GSI: TiersByOrder │
│  - Analytics     │     │                          │     │                    │
└──────────────────┘     └────────────────────────┘     └────────────────────┘

Request Flow — Create Tier:
  Browser → POST /v1/subscriptions/tiers
    → require_ui_session (cookie auth + CSRF)
    → TierCreate model validation
    → tier_management.create_tier()
    → DynamoDB PutItem (CREATOR#{id}, TIER#{uuid})
    → 201 + TierOut response

Request Flow — Reorder Tiers:
  Browser → PUT /v1/subscriptions/tiers/reorder
    → require_ui_session
    → TierReorder model validation
    → tier_management.reorder_tiers()
    → DynamoDB BatchWriteItem (update display_order for each tier)
    → 200 + updated tier list

Request Flow — Analytics:
  Browser → GET /v1/subscriptions/tiers/analytics
    → require_ui_session
    → tier_management.get_tier_analytics()
    → DynamoDB Query (CREATOR#, SK begins_with TIER#)
    → DynamoDB Query (subscription table for counts)
    → Aggregate in Python
    → 200 + TierAnalytics response
```

---

## 2. Current State Analysis

### 2.1 Subscription Access (`app/services/subscription_access.py`)

Existing functions (verified):
- `get_subscription_settings(creator_id)` (line 20): Get creator's subscription settings
- `set_subscription_settings(creator_id, ...)` (line 34): Update settings
- `creator_requires_subscription(creator_id)` (line 51): Check if creator has subscriptions enabled
- `has_active_subscription(subscriber_id, creator_id)` (line 55): Check active subscription
- `can_access_creator(subscriber_id, creator_id)` (line 72): Access check

### 2.2 Subscription Entitlements (`app/services/subscription_entitlement_templates.py`)

Manages entitlement templates that define what each tier grants access to.

### 2.3 Subscription Cycle Orders (`app/services/subscription_cycle_orders.py`)

Handles subscription billing cycles, charges, and entitlement provisioning. The `SubscriptionCycleReconciliationGateway` processes webhook events for subscription lifecycle.

### 2.4 Frontend Subscription Page

`frontend/src/pages/subscriptions/` exists with subscriber-facing views. A `TierManager.tsx` (308 lines) already exists at `frontend/src/pages/subscriptions/TierManager.tsx` and is registered in `App.tsx` at line 182 (`/subscriptions/manage`). It uses `listPlans`, `archivePlan`, and `updatePlan` from `frontend/src/api/endpoints/subscriptions.ts` and includes components like `PlanEditor`, `DiscountCodeManager`, and `PlanBrowser`.
<!-- NOTE: TierManager.tsx already exists (308 lines) with plan listing, archiving, updating, and editing UI. The ticket's proposed implementation should build on top of or replace this existing page rather than creating it from scratch. -->

### 2.5 Gaps

1. No creator-facing tier management UI
2. No tier archive/lifecycle management
3. No subscriber count per tier endpoint
4. No revenue per tier analytics
5. No tier reorder (display order) functionality
6. No tier comparison preview
7. No tier benefits list editor

---

## 3. Technical Design

### 3.1 Subscription Tier Table Enhancements

Extend existing subscription data with tier management fields. Using the existing subscription-related tables (single-table pattern):

**Tier record fields** (additions to existing tier storage):

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `CREATOR#{creator_id}` |
| `sk` | S | `TIER#{tier_id}` |
| `tier_id` | S | Unique tier ID |
| `name` | S | Display name (e.g., "Gold Tier") |
| `price_cents` | N | Monthly price in cents |
| `billing_cycle` | S | `"monthly"`, `"quarterly"`, `"yearly"` |
| `description` | S | Tier description |
| `benefits` | L | List of benefit strings |
| `access_level` | S | `"basic"`, `"premium"`, `"vip"` |
| `display_order` | N | Sort order for display (lower = first) |
| `status` | S | `"active"`, `"archived"` |
| `subscriber_count` | N | Current subscriber count (denormalized) |
| `created_at` | N | When tier was created |
| `updated_at` | N | When tier was last updated |
| `archived_at` | N | When tier was archived (null if active) |

### 3.2 Detailed DynamoDB Access Patterns

| Access Pattern | PK | SK / GSI | Query | Example |
|---------------|-----|----------|-------|---------|
| Get single tier | `CREATOR#{creator_id}` | `TIER#{tier_id}` | GetItem | Get Gold tier for creator abc123 |
| List all tiers for creator | `CREATOR#{creator_id}` | `begins_with("TIER#")` | Query | List all tiers sorted by SK |
| List active tiers only | `CREATOR#{creator_id}` | `begins_with("TIER#")` + FilterExpression `status = :active` | Query + Filter | Subscriber-facing tier list |
| Update tier fields | `CREATOR#{creator_id}` | `TIER#{tier_id}` | UpdateItem | Change price, description |
| Delete tier (zero subs) | `CREATOR#{creator_id}` | `TIER#{tier_id}` | DeleteItem with ConditionExpression `subscriber_count = :zero` | Remove unused tier |
| Reorder tiers | `CREATOR#{creator_id}` | Multiple `TIER#` keys | BatchWriteItem (transact) | Set new display_order values |
| Increment subscriber count | `CREATOR#{creator_id}` | `TIER#{tier_id}` | UpdateItem `ADD subscriber_count :one` | New subscription |
| Decrement subscriber count | `CREATOR#{creator_id}` | `TIER#{tier_id}` | UpdateItem `ADD subscriber_count :neg_one` | Subscription cancelled |

### 3.3 Tier Management Service: `app/services/tier_management.py`
<!-- NOTE: app/services/tier_management.py does not exist yet — new implementation required -->

```python
"""Subscription tier management for creators (ADMIN-001).

CRUD operations for subscription tiers, including lifecycle
management (create, edit, archive, delete, reorder) and
analytics (subscriber count, revenue per tier).
"""

def create_tier(
    *, creator_id: str, name: str, price_cents: int,
    billing_cycle: str = "monthly", description: str = "",
    benefits: List[str] = None, access_level: str = "basic",
) -> Dict[str, Any]:
    """Create a new subscription tier.

    Assigns next display_order value automatically.
    """
    ...

def update_tier(
    *, creator_id: str, tier_id: str, **updates
) -> Dict[str, Any]:
    """Update tier details.

    Price changes only apply to new subscribers.
    Existing subscribers keep their original price until renewal.
    """
    ...

def archive_tier(
    *, creator_id: str, tier_id: str
) -> Dict[str, Any]:
    """Archive a tier (stop new signups, keep existing subscribers)."""
    ...

def unarchive_tier(
    *, creator_id: str, tier_id: str
) -> Dict[str, Any]:
    """Re-activate an archived tier."""
    ...

def delete_tier(
    *, creator_id: str, tier_id: str
) -> bool:
    """Delete a tier (only if subscriber_count == 0)."""
    ...

def list_tiers(
    creator_id: str, *, include_archived: bool = False
) -> List[Dict[str, Any]]:
    """List all tiers for a creator, sorted by display_order."""
    ...

def reorder_tiers(
    *, creator_id: str, tier_ids: List[str]
) -> List[Dict[str, Any]]:
    """Reorder tiers. tier_ids is the new order (first = display_order 0)."""
    ...

def get_tier_analytics(
    creator_id: str, *, start_date: str = None, end_date: str = None
) -> Dict[str, Any]:
    """Get analytics for all tiers: subscriber count, revenue, churn.

    Returns {
        tiers: [{tier_id, name, subscriber_count, revenue_cents, churn_rate}],
        total_subscribers, total_revenue_cents,
        growth_series: [{date, count}]
    }
    """
    ...

def get_tier_subscriber_count(
    creator_id: str, tier_id: str
) -> int:
    """Get current subscriber count for a specific tier."""
    ...

def preview_tiers(
    creator_id: str
) -> List[Dict[str, Any]]:
    """Get tiers formatted for subscriber-facing preview.

    Only returns active tiers in display order with
    formatted price, benefits, and comparison data.
    """
    ...
```

### 3.4 Router: `app/routers/tier_management.py`
<!-- NOTE: app/routers/tier_management.py does not exist yet — new implementation required. The prefix /v1/subscriptions/tiers is reasonable; existing subscription-related code uses /api/subscriptions (see app/routers/subscriptions.py) and /api/creators/{id}/plans. -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/subscriptions/tiers` | `require_ui_session` | Create tier |
| GET | `/v1/subscriptions/tiers` | `require_ui_session` | List my tiers |
| GET | `/v1/subscriptions/tiers/{tier_id}` | `require_ui_session` | Get tier detail |
| PATCH | `/v1/subscriptions/tiers/{tier_id}` | `require_ui_session` | Update tier |
| POST | `/v1/subscriptions/tiers/{tier_id}/archive` | `require_ui_session` | Archive tier |
| POST | `/v1/subscriptions/tiers/{tier_id}/unarchive` | `require_ui_session` | Unarchive tier |
| DELETE | `/v1/subscriptions/tiers/{tier_id}` | `require_ui_session` | Delete tier |
| PUT | `/v1/subscriptions/tiers/reorder` | `require_ui_session` | Reorder tiers |
| GET | `/v1/subscriptions/tiers/analytics` | `require_ui_session` | Tier analytics |
| GET | `/v1/subscriptions/tiers/preview` | `require_ui_session` | Subscriber-facing preview |

### 3.5 API Request/Response Examples

**POST /v1/subscriptions/tiers** — Create tier:
```json
// Request
{
  "name": "Silver Tier",
  "price_cents": 999,
  "billing_cycle": "monthly",
  "description": "Access to exclusive posts and early releases",
  "benefits": ["Exclusive posts", "Early access", "Monthly Q&A"],
  "access_level": "premium"
}

// Response 201
{
  "tier_id": "tier_a1b2c3d4",
  "name": "Silver Tier",
  "price_cents": 999,
  "billing_cycle": "monthly",
  "description": "Access to exclusive posts and early releases",
  "benefits": ["Exclusive posts", "Early access", "Monthly Q&A"],
  "access_level": "premium",
  "display_order": 1,
  "status": "active",
  "subscriber_count": 0,
  "created_at": 1748534400,
  "updated_at": 1748534400,
  "archived_at": null
}
```

**PATCH /v1/subscriptions/tiers/{tier_id}** — Update tier:
```json
// Request
{
  "description": "Best value tier — all benefits included",
  "price_cents": 1499
}

// Response 200
{
  "tier_id": "tier_a1b2c3d4",
  "name": "Silver Tier",
  "price_cents": 1499,
  "billing_cycle": "monthly",
  "description": "Best value tier — all benefits included",
  "benefits": ["Exclusive posts", "Early access", "Monthly Q&A"],
  "access_level": "premium",
  "display_order": 1,
  "status": "active",
  "subscriber_count": 5,
  "created_at": 1748534400,
  "updated_at": 1748620800,
  "archived_at": null
}
```

**POST /v1/subscriptions/tiers/{tier_id}/archive** — Archive tier:
```json
// Response 200
{
  "tier_id": "tier_a1b2c3d4",
  "status": "archived",
  "archived_at": 1748620900,
  "subscriber_count": 5
}
```

**PUT /v1/subscriptions/tiers/reorder** — Reorder tiers:
```json
// Request
{
  "tier_ids": ["tier_platinum", "tier_gold", "tier_silver"]
}

// Response 200
[
  {"tier_id": "tier_platinum", "display_order": 0},
  {"tier_id": "tier_gold", "display_order": 1},
  {"tier_id": "tier_silver", "display_order": 2}
]
```

**GET /v1/subscriptions/tiers/analytics** — Tier analytics:
```json
// Response 200
{
  "tiers": [
    {
      "tier_id": "tier_gold",
      "name": "Gold Tier",
      "subscriber_count": 42,
      "revenue_cents": 419958,
      "churn_rate": 0.05
    },
    {
      "tier_id": "tier_silver",
      "name": "Silver Tier",
      "subscriber_count": 108,
      "revenue_cents": 1078920,
      "churn_rate": 0.08
    }
  ],
  "total_subscribers": 150,
  "total_revenue_cents": 1498878,
  "growth_series": [
    {"date": "2026-05-01", "count": 140},
    {"date": "2026-05-08", "count": 145},
    {"date": "2026-05-15", "count": 148},
    {"date": "2026-05-22", "count": 150}
  ]
}
```

**DELETE /v1/subscriptions/tiers/{tier_id}** — Delete tier (zero subscribers):
```json
// Response 200
{"ok": true, "tier_id": "tier_bronze", "deleted": true}

// Response 409 (has subscribers)
{"detail": "Cannot delete tier with 42 active subscribers. Archive instead."}
```

### 3.6 Error Handling Matrix

| Scenario | HTTP Status | Error Message | Recovery Action |
|----------|-------------|---------------|-----------------|
| Tier not found | 404 | `Tier not found` | Verify tier_id belongs to current user |
| Tier name empty | 422 | `name: ensure this value has at least 1 characters` | Provide a non-empty name |
| Price below minimum | 422 | `price_cents: ensure this value is greater than or equal to 100` | Set price >= $1.00 |
| Price above maximum | 422 | `price_cents: ensure this value is less than or equal to 100000` | Set price <= $1,000.00 |
| Invalid billing cycle | 422 | `billing_cycle: string does not match regex` | Use monthly, quarterly, or yearly |
| Invalid access level | 422 | `access_level: string does not match regex` | Use basic, premium, or vip |
| Too many benefits | 422 | `benefits: ensure this value has at most 20 items` | Reduce benefits list to 20 or fewer |
| Delete tier with subscribers | 409 | `Cannot delete tier with N active subscribers` | Archive the tier instead |
| Archive already-archived tier | 400 | `Tier is already archived` | No action needed |
| Unarchive active tier | 400 | `Tier is already active` | No action needed |
| Reorder with invalid tier IDs | 400 | `tier_ids contains unknown tier ID: X` | Use only valid tier IDs for this creator |
| Reorder with duplicate IDs | 422 | `tier_ids must contain unique values` | Remove duplicates |
| Non-owner access | 403 | `Not authorized to manage this creator's tiers` | Only the creator can manage their own tiers |
| CSRF token missing | 403 | `CSRF token required` | Include x-csrf-token header |

### 3.7 Pydantic Models (`app/models.py`)

```python
class TierCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    price_cents: int = Field(ge=100, le=100000)  # $1 - $1000
    billing_cycle: str = Field(default="monthly", pattern=r"^(monthly|quarterly|yearly)$")
    description: str = Field(default="", max_length=500)
    benefits: List[str] = Field(default_factory=list, max_length=20)
    access_level: str = Field(default="basic", pattern=r"^(basic|premium|vip)$")

    @field_validator("benefits")
    @classmethod
    def validate_benefits(cls, v: List[str]) -> List[str]:
        for b in v:
            if len(b) > 200:
                raise ValueError("Each benefit must be 200 characters or fewer")
            if not b.strip():
                raise ValueError("Benefits must not be empty strings")
        return v

class TierUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=100)
    price_cents: Optional[int] = Field(default=None, ge=100, le=100000)
    billing_cycle: Optional[str] = Field(default=None, pattern=r"^(monthly|quarterly|yearly)$")
    description: Optional[str] = Field(default=None, max_length=500)
    benefits: Optional[List[str]] = Field(default=None, max_length=20)
    access_level: Optional[str] = Field(default=None, pattern=r"^(basic|premium|vip)$")

class TierOut(BaseModel):
    tier_id: str
    name: str
    price_cents: int
    billing_cycle: str
    description: str
    benefits: List[str]
    access_level: str
    display_order: int
    status: str
    subscriber_count: int
    created_at: int
    updated_at: int
    archived_at: Optional[int] = None

class TierReorder(BaseModel):
    tier_ids: List[str] = Field(min_length=1)

    @field_validator("tier_ids")
    @classmethod
    def validate_unique(cls, v: List[str]) -> List[str]:
        if len(v) != len(set(v)):
            raise ValueError("tier_ids must contain unique values")
        return v

class TierAnalytics(BaseModel):
    tiers: List[Dict[str, Any]]
    total_subscribers: int
    total_revenue_cents: int
    growth_series: List[Dict[str, Any]]

class TierPreviewOut(BaseModel):
    tiers: List[Dict[str, Any]]
    creator_id: str
```

### 3.8 Frontend: Tier Manager Page

**Route**: `/subscriptions/manage` in `frontend/src/App.tsx` (see line 182 — route already exists)  
**Page**: `frontend/src/pages/subscriptions/TierManager.tsx` (see existing 308-line file — already registered via lazy import at App.tsx line 35)
<!-- NOTE: The TierManager page and route already exist. This ticket should extend the existing page with the proposed features (tier cards, analytics, preview, reorder) rather than creating from scratch. -->

#### Frontend Component Tree

```
TierManager
├── PageHeader
│   ├── h1 "Subscription Tiers"
│   ├── Button "Preview" (opens TierPreviewDialog)
│   └── Button "Create Tier" (opens TierDialog in create mode)
│
├── TierCardList (draggable container for reorder)
│   └── TierCard (one per tier)
│       ├── CardHeader
│       │   ├── CardTitle (tier name)
│       │   ├── Price display (formatted)
│       │   ├── StatusBadge ("active" | "archived")
│       │   └── DropdownMenu (Edit, Archive/Unarchive, Delete)
│       └── CardContent
│           ├── Description paragraph
│           ├── BenefitsList (check icons + text)
│           └── Stats row (subscriber count, access level)
│
├── TierAnalyticsSection
│   ├── StatsCards (total subscribers, total revenue)
│   └── TierRevenueChart (bar/pie chart)
│
├── TierDialog (create/edit modal)
│   ├── Input name
│   ├── Input price_cents (with $ formatting)
│   ├── Select billing_cycle
│   ├── Textarea description
│   ├── BenefitsEditor (add/remove list items)
│   ├── Select access_level
│   └── Footer (Save / Cancel buttons)
│
└── TierPreviewDialog (subscriber-facing preview)
    ├── TierComparisonTable
    └── TierCardPreview (per tier)
```

#### Props Interfaces

```typescript
interface TierManagerProps {}

interface TierCardProps {
  tier: TierOut;
  onEdit: (tier: TierOut) => void;
  onArchive: (tierId: string) => void;
  onDelete: (tierId: string) => void;
  isDragging?: boolean;
}

interface TierDialogProps {
  open: boolean;
  tier: TierOut | null;  // null = create mode
  onSave: (data: TierCreate | TierUpdate) => void;
  onCancel: () => void;
}

interface TierPreviewDialogProps {
  open: boolean;
  tiers: TierPreviewOut[];
  onClose: () => void;
}

interface TierAnalyticsSectionProps {
  analytics: TierAnalytics;
  isLoading: boolean;
}

interface BenefitsEditorProps {
  benefits: string[];
  onChange: (benefits: string[]) => void;
  maxItems?: number;  // default 20
}
```

```tsx
<div className="space-y-6">
  <div className="flex justify-between items-center">
    <h1 className="text-2xl font-bold">Subscription Tiers</h1>
    <div className="flex gap-2">
      <Button onClick={() => setShowPreview(true)} variant="outline">
        <Eye className="mr-2 h-4 w-4" /> Preview
      </Button>
      <Button onClick={() => setShowCreate(true)}>
        <Plus className="mr-2 h-4 w-4" /> Create Tier
      </Button>
    </div>
  </div>

  {/* Tier Cards — draggable for reorder */}
  <div className="space-y-4">
    {tiers.map(tier => (
      <TierCard
        key={tier.tier_id}
        tier={tier}
        onEdit={() => setEditTier(tier)}
        onArchive={() => handleArchive(tier.tier_id)}
        onDelete={() => handleDelete(tier.tier_id)}
      />
    ))}
  </div>

  {/* Analytics section */}
  <Card>
    <CardHeader><CardTitle>Tier Analytics</CardTitle></CardHeader>
    <CardContent>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>Total Subscribers: {analytics.total_subscribers}</div>
        <div>Total Revenue: {formatCurrency(analytics.total_revenue_cents)}</div>
      </div>
      <TierRevenueChart data={analytics.tiers} />
    </CardContent>
  </Card>

  {/* Create/Edit dialog */}
  <TierDialog
    open={showCreate || !!editTier}
    tier={editTier}
    onSave={handleSave}
    onCancel={() => { setShowCreate(false); setEditTier(null); }}
  />

  {/* Preview dialog */}
  <TierPreviewDialog
    open={showPreview}
    tiers={preview}
    onClose={() => setShowPreview(false)}
  />
</div>
```

### 3.9 TierCard Component

```tsx
<Card className={tier.status === "archived" ? "opacity-60" : ""}>
  <CardHeader className="flex flex-row justify-between">
    <div>
      <CardTitle>{tier.name}</CardTitle>
      <p className="text-sm text-muted-foreground">
        {formatCurrency(tier.price_cents)} / {tier.billing_cycle}
      </p>
    </div>
    <div className="flex items-center gap-2">
      <Badge variant={tier.status === "active" ? "default" : "secondary"}>
        {tier.status}
      </Badge>
      <DropdownMenu>
        <DropdownMenuTrigger asChild><Button variant="ghost"><MoreVertical /></Button></DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem onClick={onEdit}>Edit</DropdownMenuItem>
          <DropdownMenuItem onClick={onArchive}>
            {tier.status === "active" ? "Archive" : "Unarchive"}
          </DropdownMenuItem>
          {tier.subscriber_count === 0 && (
            <DropdownMenuItem onClick={onDelete} className="text-red-600">Delete</DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  </CardHeader>
  <CardContent>
    <p>{tier.description}</p>
    <ul className="mt-2 space-y-1">
      {tier.benefits.map(b => <li key={b} className="flex items-center gap-2"><Check className="h-4 w-4 text-green-500" />{b}</li>)}
    </ul>
    <div className="mt-4 flex gap-4 text-sm text-muted-foreground">
      <span>{tier.subscriber_count} subscribers</span>
      <span>Access: {tier.access_level}</span>
    </div>
  </CardContent>
</Card>
```

### 3.10 Frontend API (`frontend/src/api/endpoints/tierManagement.ts`)
<!-- NOTE: frontend/src/api/endpoints/tierManagement.ts does not exist yet. The existing TierManager.tsx uses frontend/src/api/endpoints/subscriptions.ts which provides listPlans, archivePlan, updatePlan. The new tier management API calls should either extend subscriptions.ts or create this new file. -->

```typescript
export const createTier = (data: TierCreate) =>
  client.post("/v1/subscriptions/tiers", data);

export const listTiers = (params?: { include_archived?: boolean }) =>
  client.get("/v1/subscriptions/tiers", { params });

export const getTier = (tierId: string) =>
  client.get(`/v1/subscriptions/tiers/${tierId}`);

export const updateTier = (tierId: string, data: TierUpdate) =>
  client.patch(`/v1/subscriptions/tiers/${tierId}`, data);

export const archiveTier = (tierId: string) =>
  client.post(`/v1/subscriptions/tiers/${tierId}/archive`);

export const unarchiveTier = (tierId: string) =>
  client.post(`/v1/subscriptions/tiers/${tierId}/unarchive`);

export const deleteTier = (tierId: string) =>
  client.delete(`/v1/subscriptions/tiers/${tierId}`);

export const reorderTiers = (data: { tier_ids: string[] }) =>
  client.put("/v1/subscriptions/tiers/reorder", data);

export const getTierAnalytics = (params?: { start_date?: string; end_date?: string }) =>
  client.get("/v1/subscriptions/tiers/analytics", { params });

export const previewTiers = () =>
  client.get("/v1/subscriptions/tiers/preview");
```

### 3.11 Frontend TypeScript Types

```typescript
export interface TierCreate {
  name: string;
  price_cents: number;
  billing_cycle: "monthly" | "quarterly" | "yearly";
  description?: string;
  benefits?: string[];
  access_level?: "basic" | "premium" | "vip";
}

export interface TierUpdate {
  name?: string;
  price_cents?: number;
  billing_cycle?: "monthly" | "quarterly" | "yearly";
  description?: string;
  benefits?: string[];
  access_level?: "basic" | "premium" | "vip";
}

export interface TierOut {
  tier_id: string;
  name: string;
  price_cents: number;
  billing_cycle: string;
  description: string;
  benefits: string[];
  access_level: string;
  display_order: number;
  status: "active" | "archived";
  subscriber_count: number;
  created_at: number;
  updated_at: number;
  archived_at: number | null;
}

export interface TierAnalytics {
  tiers: Array<{
    tier_id: string;
    name: string;
    subscriber_count: number;
    revenue_cents: number;
    churn_rate: number;
  }>;
  total_subscribers: number;
  total_revenue_cents: number;
  growth_series: Array<{ date: string; count: number }>;
}
```

---

## 4. Implementation Plan

### Phase 1: Backend Service (Days 1-3)

1. **`app/services/tier_management.py`**: New file. Tier CRUD, archive/unarchive, delete, reorder, analytics, preview.
2. **DDB schema**: Extend existing subscription table structure with tier management fields (display_order, status, benefits, archived_at).

### Phase 2: Backend Router (Days 3-4)

3. **`app/models.py`**: Add tier management Pydantic models.
4. **`app/routers/tier_management.py`**: New router with 10 endpoints.
5. **`app/main.py`**: Register router with prefix `/v1/subscriptions/tiers`.

### Phase 3: Frontend (Days 4-7)

6. **`frontend/src/api/types.ts`**: Add TypeScript types.
7. **`frontend/src/api/endpoints/tierManagement.ts`**: New file.
8. **`frontend/src/pages/subscriptions/TierManager.tsx`**: New page with tier cards, create/edit dialog, preview, analytics.
9. **`frontend/src/App.tsx`**: Add `/subscriptions/manage` route.
10. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Manage Tiers" link under Subscriptions section.

### Phase 4: E2E Tests (Days 7-9)

11. **`frontend/e2e/tier-manager.spec.ts`**: 30 tests across 7 sections.

---

## 5. E2E Test Plan

**Test file**: `frontend/e2e/tier-manager.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Alice (creator), Bob (subscriber)
- Alice creates a subscription tier "Gold" via API

**Section 547: Tier CRUD API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Creator creates a subscription tier` | POST `/v1/subscriptions/tiers` as Alice with `{name: "Silver", price_cents: 999, billing_cycle: "monthly", benefits: ["Exclusive posts", "Early access"]}` -> 201; `tier_id` present, `status: "active"` |
| 2 | `Creator lists their tiers` | GET `/v1/subscriptions/tiers` -> 200; array includes "Gold" and "Silver" tiers sorted by display_order |
| 3 | `Creator updates tier description` | PATCH `/v1/subscriptions/tiers/{silver_id}` with `{description: "Best value tier"}` -> 200; re-GET shows updated description |
| 4 | `Creator deletes tier with zero subscribers` | DELETE `/v1/subscriptions/tiers/{silver_id}` -> 200; re-list excludes it |

**Section 548: Tier Lifecycle API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Creator archives a tier` | POST `/v1/subscriptions/tiers/{gold_id}/archive` -> 200; `status: "archived"`, `archived_at` is set |
| 6 | `Archived tier excluded from default list` | GET `/v1/subscriptions/tiers` without `include_archived` -> 200; "Gold" not in results |
| 7 | `Archived tier included with flag` | GET `/v1/subscriptions/tiers?include_archived=true` -> 200; "Gold" present with `status: "archived"` |
| 8 | `Creator unarchives a tier` | POST `/v1/subscriptions/tiers/{gold_id}/unarchive` -> 200; `status: "active"` |

**Section 549: Tier Reorder & Preview API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Creator creates second tier for reorder test` | POST with `{name: "Platinum", price_cents: 2999}` -> 201 |
| 10 | `Creator reorders tiers` | PUT `/v1/subscriptions/tiers/reorder` with `{tier_ids: [platinum_id, gold_id]}` -> 200; re-list shows Platinum first (display_order 0) |
| 11 | `Preview returns subscriber-facing data` | GET `/v1/subscriptions/tiers/preview` -> 200; array of active tiers only, each has `name`, `price_cents`, `benefits` |
| 12 | `Preview respects display order` | Preview tiers[0] is Platinum (the reordered first tier) |

**Section 550: Tier Analytics API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | `Creator views tier analytics` | GET `/v1/subscriptions/tiers/analytics` -> 200; `total_subscribers >= 0`, `total_revenue_cents >= 0`, `tiers` is array |
| 14 | `Analytics includes per-tier subscriber count` | Each tier in `tiers` array has `subscriber_count` field |
| 15 | `Delete tier with subscribers returns 409` | Seed a subscriber for Gold tier, then DELETE -> 409 |
| 16 | `Price validation rejects zero` | POST with `{name: "Free", price_cents: 0}` -> 422 |

**Section 547b: Input Validation Edge Cases (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 17 | `Name exceeding 100 chars rejected` | POST with name of 101 chars -> 422 |
| 18 | `Price above $1000 rejected` | POST with `price_cents: 100001` -> 422 |
| 19 | `Benefits exceeding 20 items rejected` | POST with 21 benefits -> 422 |
| 20 | `Invalid billing cycle rejected` | POST with `billing_cycle: "biannual"` -> 422 |
| 21 | `Empty name rejected` | POST with `name: ""` -> 422 |

**Section 548b: Concurrent & Idempotency (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 22 | `Archive already-archived tier returns 400` | Archive Gold, then archive again -> 400 |
| 23 | `Unarchive already-active tier returns 400` | Unarchive active tier -> 400 |
| 24 | `Reorder with unknown tier ID returns 400` | PUT reorder with fake ID -> 400 |
| 25 | `Reorder with duplicate IDs returns 422` | PUT reorder with same ID twice -> 422 |

**Section 549b: Authorization & CSRF (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 26 | `Bob cannot manage Alice's tiers` | Bob POST create tier -> creates for Bob (scoped to session user) |
| 27 | `Unauthenticated user gets 401` | Request without session cookie -> 401 |
| 28 | `Missing CSRF on POST returns 403` | POST without x-csrf-token header -> 403 |

**Section 550b: UI Tests (2 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 29 | `Tier manager page renders tier cards` | Navigate to `/subscriptions/manage`; heading "Subscription Tiers" visible; at least one tier card rendered |
| 30 | `Create tier dialog opens and submits` | Click "Create Tier"; fill name, price, billing cycle; click Save; new tier appears in list |

---

## 6. Security Considerations

### 6.1 Authorization
- All tier management endpoints use `require_ui_session` — creator manages only their own tiers
- Tier operations scoped to the authenticated user's `user_sub` (cannot manage another creator's tiers)

### 6.2 Price Changes
- Price changes apply only to new subscribers
- Existing subscribers keep their original price until they cancel and re-subscribe
- This prevents surprise price increases for current subscribers

### 6.3 Deletion Safety
- Delete only allowed if `subscriber_count == 0`
- Archive is the safe alternative (preserves existing subscribers)
- Delete is permanent and cannot be undone

### 6.4 Input Validation
- Tier name: 1-100 characters, no HTML
- Price: $1.00 minimum, $1,000.00 maximum
- Benefits list: maximum 20 items, each max 200 characters
- Description: maximum 500 characters

---

## 7. Observability

### 7.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `tier_created_total` | counter | `creator_id`, `billing_cycle` | Total tiers created |
| `tier_archived_total` | counter | `creator_id` | Total tiers archived |
| `tier_deleted_total` | counter | `creator_id` | Total tiers deleted |
| `tier_updated_total` | counter | `creator_id`, `field` | Total tier updates by field |
| `tier_reorder_total` | counter | `creator_id` | Total reorder operations |
| `tier_analytics_query_duration_seconds` | histogram | `creator_id` | Analytics query latency |
| `tier_subscriber_count` | gauge | `creator_id`, `tier_id` | Current subscriber count per tier |

### 7.2 Logging

All tier management operations log structured events:
- `tier.created` — tier_id, creator_id, name, price_cents, billing_cycle
- `tier.updated` — tier_id, creator_id, changed_fields
- `tier.archived` — tier_id, creator_id, subscriber_count
- `tier.unarchived` — tier_id, creator_id
- `tier.deleted` — tier_id, creator_id
- `tier.reordered` — creator_id, new_order (list of tier_ids)
- `tier.delete_blocked` — tier_id, creator_id, subscriber_count (409 case)

### 7.3 Alerting

| Alert | Condition | Severity |
|-------|-----------|----------|
| High deletion rate | > 10 tiers deleted in 1 hour (platform-wide) | Warning |
| Analytics query slow | p95 latency > 2s | Warning |
| Tier count anomaly | Creator with > 50 tiers | Info |

---

## 8. Rollout Plan

### Phase 1: Backend Only (Feature Flag: `TIER_MANAGEMENT_ENABLED=false`)
- Deploy backend service and router
- Endpoints return 404 when feature flag is off
- Internal testing via Swagger UI / curl

### Phase 2: Limited Access (Feature Flag: `TIER_MANAGEMENT_ENABLED=true`, `TIER_MANAGEMENT_ALLOWLIST`)
- Enable for specific creator IDs in the allowlist
- Monitor for DynamoDB errors, latency, data integrity
- Collect feedback from early adopters

### Phase 3: General Availability
- Remove allowlist restriction
- Add sidebar navigation link
- Announce to all creators

### Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `TIER_MANAGEMENT_ENABLED` | `false` | Master switch for tier management endpoints |
| `TIER_MANAGEMENT_ALLOWLIST` | `""` | Comma-separated creator IDs allowed early access |
| `TIER_ANALYTICS_ENABLED` | `true` | Enable analytics queries (can disable if DDB load too high) |

---

## 9. Performance Considerations

### 9.1 Latency Targets

| Operation | Target p50 | Target p95 | Notes |
|-----------|-----------|-----------|-------|
| Create tier | < 100ms | < 250ms | Single PutItem |
| List tiers | < 100ms | < 200ms | Query on PK, typically < 20 items |
| Update tier | < 100ms | < 250ms | Single UpdateItem |
| Reorder tiers | < 200ms | < 500ms | BatchWriteItem for N tiers |
| Analytics | < 500ms | < 2s | Aggregation across subscriptions table |
| Preview | < 100ms | < 200ms | Filtered query, cached in React Query |

### 9.2 Caching Strategy

- **React Query**: `staleTime: 30_000` (30s) for tier list; `staleTime: 60_000` (60s) for analytics
- **Optimistic updates**: Reorder and archive/unarchive use optimistic React Query cache updates for instant UI feedback
- **No server-side cache**: DynamoDB is fast enough; no Redis needed

### 9.3 Pagination

- Tier list is not paginated (creators typically have < 20 tiers)
- Analytics `growth_series` limited to 52 data points (weekly for 1 year)
- Preview limited to active tiers only

---

## 10. Files to Create

| File | Purpose |
|------|---------|
| `app/services/tier_management.py` | Tier CRUD, lifecycle, analytics <!-- NOTE: does not exist yet --> |
| `app/routers/tier_management.py` | Tier management API (10 endpoints) <!-- NOTE: does not exist yet --> |
| `frontend/src/api/endpoints/tierManagement.ts` | API wrappers <!-- NOTE: does not exist yet --> |
| `frontend/e2e/tier-manager.spec.ts` | E2E tests (30 tests, sections 547-550b) |

## 11. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add tier management Pydantic models (see `app/models.py`) |
| `app/main.py` | Register `tier_management_router` (see `app/main.py` for router registration pattern around lines 113-162, 430-439) |
| `frontend/src/api/types.ts` | Add tier management TypeScript types |
| `frontend/src/pages/subscriptions/TierManager.tsx` | Extend existing 308-line page with tier cards, analytics, preview, and reorder <!-- NOTE: this file already exists — modify, do not recreate --> |
| `frontend/src/App.tsx` | Route already exists at line 182 — no change needed <!-- NOTE: /subscriptions/manage route already registered --> |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Manage Tiers" nav link |

## 12. Acceptance Criteria

1. Creators can create tiers with name, price, billing cycle, description, benefits, and access level
2. Creators can update any tier field; price changes apply to new subscribers only
3. Tiers can be archived (stop signups) and unarchived (resume signups)
4. Tiers with zero subscribers can be deleted; tiers with subscribers return 409
5. Tiers can be reordered via PUT with new display order
6. Preview endpoint returns subscriber-facing tier data in display order
7. Analytics endpoint returns subscriber count and revenue per tier
8. All operations scoped to the authenticated creator's tiers
9. All 30 E2E tests pass in `frontend/e2e/tier-manager.spec.ts`
10. Observability metrics and structured logging in place for all operations

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_tier_management.py`

**Mock setup**: All DynamoDB operations mocked via `moto` (in-memory DDB). Subscription access functions mocked with `unittest.mock.patch` where cross-service calls occur.

**Fixtures**:
- `tier_table`: moto-backed DynamoDB table with PK=`CREATOR#{id}`, SK=`TIER#{id}` schema
- `creator_session`: Fake UI session dict `{"user_sub": "creator-alice", "role": "USER"}`
- `sample_tier`: Pre-built tier dict with all required fields for reuse across tests

**Test functions**:

| Function | What it tests |
|----------|---------------|
| `test_create_tier_returns_tier_out` | `create_tier()` writes to DDB and returns a valid `TierOut` with `status="active"`, auto-assigned `display_order`, and `subscriber_count=0` |
| `test_create_tier_validates_price_minimum` | `price_cents < 100` raises `ValueError` or returns 422 |
| `test_create_tier_validates_price_maximum` | `price_cents > 100000` raises `ValueError` or returns 422 |
| `test_create_tier_validates_name_length` | Empty name or name > 100 chars raises validation error |
| `test_create_tier_validates_billing_cycle` | Invalid billing cycle value (e.g., `"biannual"`) raises validation error |
| `test_create_tier_validates_benefits_count` | More than 20 benefits raises validation error |
| `test_create_tier_auto_increments_display_order` | Second tier gets `display_order = 1` when first has `display_order = 0` |
| `test_update_tier_partial_fields` | `update_tier()` with only `description` leaves other fields unchanged |
| `test_update_tier_not_found` | `update_tier()` for nonexistent tier_id raises 404 |
| `test_archive_tier_sets_status_and_timestamp` | `archive_tier()` sets `status="archived"` and populates `archived_at` |
| `test_archive_already_archived_returns_400` | Archiving an already-archived tier returns 400 |
| `test_unarchive_tier_clears_archived_at` | `unarchive_tier()` sets `status="active"` and clears `archived_at` |
| `test_unarchive_active_tier_returns_400` | Unarchiving an already-active tier returns 400 |
| `test_delete_tier_zero_subscribers` | `delete_tier()` succeeds when `subscriber_count == 0` |
| `test_delete_tier_with_subscribers_returns_409` | `delete_tier()` with `subscriber_count > 0` returns 409 with descriptive message |
| `test_list_tiers_sorted_by_display_order` | `list_tiers()` returns tiers in ascending `display_order` |
| `test_list_tiers_excludes_archived_by_default` | `list_tiers(include_archived=False)` omits archived tiers |
| `test_list_tiers_includes_archived_when_flagged` | `list_tiers(include_archived=True)` includes archived tiers |
| `test_reorder_tiers_updates_display_order` | `reorder_tiers()` sets `display_order` based on position in `tier_ids` list |
| `test_reorder_with_unknown_id_returns_400` | `reorder_tiers()` with an unknown tier ID returns 400 |
| `test_reorder_with_duplicate_ids_returns_422` | `reorder_tiers()` with duplicate IDs returns 422 |
| `test_get_tier_analytics_aggregates` | `get_tier_analytics()` returns `total_subscribers`, `total_revenue_cents`, per-tier breakdown |
| `test_preview_tiers_active_only` | `preview_tiers()` returns only active tiers in display order |
| `test_tier_scoped_to_creator` | Creator A cannot read or modify Creator B's tiers |

### Integration Tests

**Test file**: `tests/test_tier_management_integration.py`

Tests service functions with real moto DynamoDB (no patching of DDB calls). Validates cross-service interactions:

| Test | What it validates |
|------|-------------------|
| `test_create_then_list_roundtrip` | Create 3 tiers, list returns all 3 in correct order |
| `test_archive_then_filter_roundtrip` | Archive a tier, default list excludes it, `include_archived=true` includes it |
| `test_delete_condition_expression` | DDB ConditionExpression on `subscriber_count = 0` actually fires (not just Python-side check) |
| `test_reorder_batch_write` | BatchWriteItem updates all `display_order` values atomically |
| `test_analytics_with_subscription_data` | Seed subscription records, verify `get_tier_analytics()` counts match |
| `test_concurrent_archive_and_delete` | Archive + delete race condition handled by ConditionExpression |

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/tier-manager.spec.ts`  
**Sections**: 547-550b (30 tests) as detailed in section 5 above.

**Auth pattern**: `injectAuth(page, "alice")` for creator operations; `injectAuth(page, "bob")` for subscriber perspective.

**CSRF handling**: All POST/PATCH/PUT/DELETE requests via `page.request` include `headers: { "x-csrf-token": sessions["alice"].csrf_token }`.

**Setup/teardown**:
- `beforeAll`: Inject auth for Alice, create baseline "Gold" tier via API
- `afterAll`: Delete all test tiers created during the run (cleanup via DELETE endpoint, skipping 409s for tiers with subscribers)

**Negative tests**: 401 (no session), 403 (missing CSRF), 404 (nonexistent tier), 409 (delete with subscribers), 422 (validation failures for name, price, benefits, billing_cycle, duplicate tier_ids)

**Key selectors**:
- Tier card: `page.getByRole("heading", { name: "Gold Tier" })` or `page.locator(".card").filter({ hasText: "Gold Tier" })`
- Create button: `page.getByRole("button", { name: /create tier/i })`
- Archive action: `page.getByRole("menuitem", { name: /archive/i })`
- Status badge: `page.getByText("active")` scoped within tier card
- Analytics heading: `page.getByRole("heading", { name: /tier analytics/i })`

### Test Data Requirements

**DDB seed data**:
- `billing` table: `PK=CREATOR#{alice_sub}`, `SK=TIER#{tier_id}` — tier records with all required fields
- Subscription records for analytics tests: `PK=SUB#{subscriber_id}`, `SK=CREATOR#{creator_id}` with `tier_id` reference
- No special table creation needed — uses existing `billing` table (single-table pattern)

**Test user roles**:
- Alice (USER): Creator managing tiers
- Bob (USER): Subscriber for authorization boundary tests

**Cleanup strategy**: `afterAll` deletes all tiers created with test-specific prefixes (e.g., tier names starting with `"E2E_"`)

### CI/Pipeline Considerations

- **Feature flag**: `TIER_MANAGEMENT_ENABLED=true` must be set in `.env.local` for E2E tests
- **Serial execution**: E2E tests in sections 547-550b depend on shared state (tier created in beforeAll) — must run in declared order within the describe block (Playwright default)
- **Retry safety**: Each test uses unique tier names with timestamp suffix (`Silver_${Date.now()}`) to avoid collisions across retries
- **No database migration**: Uses existing DDB table with new PK/SK patterns — no schema change needed in `local-ddb-init.py`

---

## Dependencies & Merge Safety

### Depends On (upstream)

| Ticket / Component | What's needed | Status | Can work start before dependency merges? |
|-------------------|---------------|--------|------------------------------------------|
| `app/services/subscription_access.py` | `get_subscription_settings`, `has_active_subscription`, `can_access_creator` | **Implemented** (exists in codebase) | Yes — already merged |
| `app/services/subscription_entitlement_templates.py` | Entitlement template CRUD for tier benefits | **Implemented** (exists in codebase) | Yes — already merged |
| `app/services/subscription_cycle_orders.py` | Subscription lifecycle for subscriber count tracking | **Implemented** (exists in codebase) | Yes — already merged |
| `app/auth/deps.py` | `require_ui_session` for cookie auth + CSRF | **Implemented** (exists in codebase) | Yes — already merged |
| `frontend/src/pages/subscriptions/TierManager.tsx` | Existing 308-line page to extend | **Implemented** (exists in codebase) | Yes — already merged |
| `frontend/src/api/endpoints/subscriptions.ts` | Existing `listPlans`, `archivePlan`, `updatePlan` wrappers | **Implemented** (exists in codebase) | Yes — already merged |

All upstream dependencies are already implemented and merged. This ticket has no blocking dependencies.

### Depended On By (downstream)

| Ticket | What it needs from ADMIN-001 |
|--------|------------------------------|
| None identified | No other tickets reference ADMIN-001 as a dependency |

### Merge Strategy

**Classification**: **Independent**

This ticket is fully self-contained. It creates new service/router files and extends an existing frontend page. No other in-flight tickets modify the same files (TierManager.tsx, subscriptions.ts, billing table tier records).

- **No cross-ticket conflicts**: The `billing` table PK/SK patterns (`CREATOR#/TIER#`) are unique to this feature
- **Feature flag gated**: `TIER_MANAGEMENT_ENABLED` defaults to `false`, so the feature is inert until explicitly enabled
- **Safe to merge to main independently** at any time

### Merge Checklist

- [ ] **DDB tables**: No new tables required. Uses existing `billing` table with new PK/SK patterns (`CREATOR#{id}`, `TIER#{id}`). Verify no collision with existing billing records.
- [ ] **Settings**: Add `TIER_MANAGEMENT_ENABLED`, `TIER_MANAGEMENT_ALLOWLIST`, `TIER_ANALYTICS_ENABLED` to `app/core/settings.py` and `.env.local.example`
- [ ] **Router registration**: Register `tier_management_router` in `app/main.py` (follow pattern at lines 113-162)
- [ ] **Frontend route**: Route `/subscriptions/manage` already exists in `App.tsx` line 182 — no change needed
- [ ] **Frontend sidebar**: Add "Manage Tiers" link in `Sidebar.tsx` under Subscriptions group
- [ ] **E2E tests**: All 30 tests in `frontend/e2e/tier-manager.spec.ts` pass
- [ ] **Unit tests**: All tests in `tests/test_tier_management.py` pass
- [ ] **No breaking changes**: Existing subscription endpoints, frontend pages, and DDB records are unaffected
- [ ] **Feature flag default**: Verify `TIER_MANAGEMENT_ENABLED` defaults to `false` in production

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/subscription_access.py` | 20, 34, 51, 55, 72 | Existing subscription functions: `get_subscription_settings`, `set_subscription_settings`, `creator_requires_subscription`, `has_active_subscription`, `can_access_creator` |
| `app/services/subscription_entitlement_templates.py` | — | Entitlement template management (exists) |
| `app/services/subscription_cycle_orders.py` | — | Subscription billing cycle and lifecycle (exists) |
| `app/auth/deps.py` | 175, 273 | `require_ui_session` (line 175), `require_root_session` (line 273) |
| `app/auth/policy.py` | 63, 67, 84 | `require_root` (line 63), `require_admin_or_root` (line 67), `require_admin_scope` (line 84) |
| `frontend/src/pages/subscriptions/TierManager.tsx` | 1-308 | Existing tier manager page (308 lines) — already has plan list, archive, update, PlanEditor, DiscountCodeManager, PlanBrowser |
| `frontend/src/api/endpoints/subscriptions.ts` | — | Existing API wrappers: `listPlans`, `archivePlan`, `updatePlan` |
| `frontend/src/App.tsx` | 35, 182 | Lazy import of TierManager (line 35), route `/subscriptions/manage` (line 182) |
| `app/main.py` | 113-162, 430-439 | Router registration pattern (for reference when adding `tier_management_router`) |
| `app/services/tier_management.py` | — | Does not exist yet — new implementation required |
| `app/routers/tier_management.py` | — | Does not exist yet — new implementation required |
| `frontend/src/api/endpoints/tierManagement.ts` | — | Does not exist yet — new implementation required |
