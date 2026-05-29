# ADMIN-001: Subscription Tier Manager UI

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 7-9 days  
**Dependencies**: Subscription access (`subscription_access.py`), subscription entitlements (`subscription_entitlement_templates.py`), subscription cycle orders (`subscription_cycle_orders.py`), admin auth (`auth/deps.py`)

---

## 1. Overview & Motivation

### The Gap

The backend supports subscription tier CRUD through `subscription_access.py` and `subscription_entitlement_templates.py`, and the subscription lifecycle is managed via `subscription_cycle_orders.py`. Subscription plans can be created, updated, and deleted through API endpoints. However, there is no creator-facing UI for managing subscription tiers. Creators cannot:

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

---

## 2. Current State Analysis

### 2.1 Subscription Access (`app/services/subscription_access.py`)

Existing functions:
- `get_subscription_settings(creator_id)`: Get creator's subscription settings
- `set_subscription_settings(creator_id, ...)`: Update settings
- `creator_requires_subscription(creator_id)`: Check if creator has subscriptions enabled
- `has_active_subscription(subscriber_id, creator_id)`: Check active subscription
- `can_access_creator(subscriber_id, creator_id)`: Access check

### 2.2 Subscription Entitlements (`app/services/subscription_entitlement_templates.py`)

Manages entitlement templates that define what each tier grants access to.

### 2.3 Subscription Cycle Orders (`app/services/subscription_cycle_orders.py`)

Handles subscription billing cycles, charges, and entitlement provisioning. The `SubscriptionCycleReconciliationGateway` processes webhook events for subscription lifecycle.

### 2.4 Frontend Subscription Page

`frontend/src/pages/subscriptions/` exists with subscriber-facing views but no creator management interface.

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

### 3.2 Tier Management Service: `app/services/tier_management.py`

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

### 3.3 Router: `app/routers/tier_management.py`

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

### 3.4 Pydantic Models (`app/models.py`)

```python
class TierCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    price_cents: int = Field(ge=100, le=100000)  # $1 - $1000
    billing_cycle: str = Field(default="monthly", pattern=r"^(monthly|quarterly|yearly)$")
    description: str = Field(default="", max_length=500)
    benefits: List[str] = Field(default_factory=list, max_length=20)
    access_level: str = Field(default="basic", pattern=r"^(basic|premium|vip)$")

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

class TierAnalytics(BaseModel):
    tiers: List[Dict[str, Any]]
    total_subscribers: int
    total_revenue_cents: int
    growth_series: List[Dict[str, Any]]

class TierPreviewOut(BaseModel):
    tiers: List[Dict[str, Any]]
    creator_id: str
```

### 3.5 Frontend: Tier Manager Page

**Route**: `/subscriptions/manage` in `frontend/src/App.tsx`  
**Page**: `frontend/src/pages/subscriptions/TierManager.tsx`

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

### 3.6 TierCard Component

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

### 3.7 Frontend API (`frontend/src/api/endpoints/tierManagement.ts`)

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

11. **`frontend/e2e/tier-manager.spec.ts`**: 16 tests across 4 sections.

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

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/tier_management.py` | Tier CRUD, lifecycle, analytics |
| `app/routers/tier_management.py` | Tier management API (10 endpoints) |
| `frontend/src/api/endpoints/tierManagement.ts` | API wrappers |
| `frontend/src/pages/subscriptions/TierManager.tsx` | Tier management page |
| `frontend/e2e/tier-manager.spec.ts` | E2E tests (16 tests, sections 547-550) |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add tier management Pydantic models |
| `app/main.py` | Register `tier_management_router` |
| `frontend/src/api/types.ts` | Add tier management TypeScript types |
| `frontend/src/App.tsx` | Add `/subscriptions/manage` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Manage Tiers" nav link |

## 9. Acceptance Criteria

1. Creators can create tiers with name, price, billing cycle, description, benefits, and access level
2. Creators can update any tier field; price changes apply to new subscribers only
3. Tiers can be archived (stop signups) and unarchived (resume signups)
4. Tiers with zero subscribers can be deleted; tiers with subscribers return 409
5. Tiers can be reordered via PUT with new display order
6. Preview endpoint returns subscriber-facing tier data in display order
7. Analytics endpoint returns subscriber count and revenue per tier
8. All operations scoped to the authenticated creator's tiers
9. All 16 E2E tests pass in `frontend/e2e/tier-manager.spec.ts`
