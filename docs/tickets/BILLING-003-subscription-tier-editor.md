# BILLING-003: Subscription Tier Management UI (Creator-facing)

**Ticket**: BILLING-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Executive Summary

The platform has a complete backend subscription plan CRUD system: create plans (`POST /api/creators/{creator_id}/plans`), update plans (`PATCH /api/plans/{plan_id}`), archive plans (`POST /api/plans/{plan_id}/archive`), and pricing management (`PATCH /api/plans/{plan_id}/pricing`). Discount code management is equally complete: create, list, and disable codes (`subscription_server.py:1573-1669`). All endpoints authenticate via `X-User-Id` header and enforce creator ownership via `require_user(x_user_id, creator_id)`.

The frontend has only a subscriber-facing `PlanBrowser.tsx` (187 lines) that displays plan cards for purchasing -- it has no create, edit, or archive capabilities. No creator-facing plan management page exists. Creators cannot create subscription tiers, set pricing, manage assets/features, or configure discount codes through the UI.

This ticket builds a complete Subscription Tier Management interface for creators: a PlanEditor form for creating/editing tiers, a TierManager page listing all plans with status/actions, and a DiscountCodeManager for coupon administration. The page will be accessible at `/subscriptions/manage` and linked from the sidebar.

The business impact is critical: subscription revenue is the primary monetization model for creators on the platform. Without a management UI, creators must either rely on developer help to set up their tiers (unsustainable) or use API calls directly (impractical for non-technical creators). This creates a hard ceiling on platform revenue growth. Every day without this UI is a day where new creators cannot monetize their content through subscriptions.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Create Subscription Tier**

| Field | Value |
|-------|-------|
| Actor | Creator |
| Story | As a creator, I want to create a new subscription tier with name, description, and price so I can start earning recurring revenue. |
| Preconditions | Creator is authenticated. |
| Acceptance Criteria | 1. "Create Plan" button opens a dialog form. 2. Form has name (required, 2-128 chars), description (optional, max 1000), price (required, > $0), interval (month/year), annual price (optional). 3. On submit, plan appears in list with "active" status. 4. Toast confirms creation. 5. Form resets after successful submission. |

**US-2: Set Monthly and Annual Pricing**

| Field | Value |
|-------|-------|
| Actor | Creator |
| Story | As a creator, I want to set both monthly and annual pricing for a tier so I can incentivize longer commitments with discounts. |
| Preconditions | Creator is creating or editing a plan. |
| Acceptance Criteria | 1. Monthly price is always required. 2. Annual price field is optional. 3. Annual price field is only shown when interval is "month" (annual interval plans have a single price). 4. Annual price is entered in dollars, converted to cents on submit. 5. Both prices are displayed on plan cards with savings percentage. |

**US-3: Edit Existing Tier**

| Field | Value |
|-------|-------|
| Actor | Creator |
| Story | As a creator, I want to edit an existing tier's name, description, or pricing so I can adjust my offering over time. |
| Preconditions | Plan exists in the plan list. |
| Acceptance Criteria | 1. "Edit" button on each plan card opens a pre-filled dialog. 2. All fields show current values. 3. On save, changes are applied and the list updates. 4. Existing subscribers are not affected by name/description changes. 5. Price changes take effect for new subscribers only (existing subscribers keep their current pricing until renewal). |

**US-4: Archive a Tier**

| Field | Value |
|-------|-------|
| Actor | Creator |
| Story | As a creator, I want to archive a tier that I no longer offer so new subscribers cannot select it. |
| Preconditions | Plan exists with "active" status. |
| Acceptance Criteria | 1. "Archive" button shows confirmation dialog. 2. After confirming, plan status changes to "archived". 3. Archived plans show a grey "archived" badge. 4. Existing subscribers are not affected (they keep their subscription until they cancel). 5. Archived plans are NOT visible in the PlanBrowser (subscriber view). |

**US-5: Manage Content Assets**

| Field | Value |
|-------|-------|
| Actor | Creator |
| Story | As a creator, I want to attach content assets (files/videos) as tier benefits so subscribers know what they get. |
| Preconditions | Creator has uploaded files to the file manager. |
| Acceptance Criteria | 1. Asset paths input allows adding/removing file paths. 2. Each path is resolved to file metadata on save (via `resolve_plan_assets`). 3. Assets are displayed as feature bullet points on plan cards. 4. Maximum 50 asset paths per plan (enforced by `conlist(str, max_length=50)`). |

**US-6: Create Discount Codes**

| Field | Value |
|-------|-------|
| Actor | Creator |
| Story | As a creator, I want to create discount codes for my subscription tiers so I can run promotions and incentivize sign-ups. |
| Preconditions | Creator is on the Discount Codes tab. |
| Acceptance Criteria | 1. Create form has code (auto-uppercased, 3-32 chars), percent_off (1-100), duration (once/forever/repeating), duration_months (required if repeating). 2. On submit, code appears in the table. 3. Duplicate codes overwrite existing ones (DDB put_item). 4. Frontend warns if code already exists in the list. |

**US-7: Disable Discount Codes**

| Field | Value |
|-------|-------|
| Actor | Creator |
| Story | As a creator, I want to disable inactive discount codes so expired promotions cannot be used. |
| Preconditions | Discount code exists with active status. |
| Acceptance Criteria | 1. "Disable" button on active codes shows confirmation. 2. After confirming, code status changes to disabled. 3. Disabled codes show a red badge. 4. Disabled codes remain in the table (not deleted). |

**US-8: Preview Subscriber View**

| Field | Value |
|-------|-------|
| Actor | Creator |
| Story | As a creator, I want to preview how my tiers look to potential subscribers so I can verify the presentation. |
| Preconditions | Creator has at least one active plan. |
| Acceptance Criteria | 1. "Preview" tab shows the PlanBrowser component. 2. Only active plans are shown (matching subscriber view). 3. Subscribe buttons are functional (creator can test the flow). |

### 2.2 Pain Points

1. **Creators cannot monetize without developer help**: Creating subscription tiers requires API calls with `X-User-Id` headers and JSON bodies -- impossible for non-technical creators.
2. **No pricing experimentation**: Without a UI, creators cannot easily A/B test pricing, launch promotional tiers, or adjust prices for seasonal campaigns.
3. **Discount codes are invisible**: Despite a full backend CRUD system (`subscription_server.py:1573-1669`), creators have no way to create, view, or manage discount codes.
4. **No tier lifecycle management**: Archiving old tiers, updating descriptions, or reactivating seasonal tiers all require direct API access.
5. **No asset management**: The `asset_paths` field on plans allows attaching files as tier benefits, but there is no UI to manage these attachments.

---

## 3. Current State Analysis

### 3.1 Plan CRUD Endpoints (subscription_server.py:706-813)

| Endpoint | Method | Path | Auth | Lines |
|----------|--------|------|------|-------|
| `create_plan` | POST | `/api/creators/{creator_id}/plans` | `X-User-Id` = creator_id | 706-743 |
| `list_plans` | GET | `/api/creators/{creator_id}/plans` | None (public) | 746-753 |
| `update_plan` | PATCH | `/api/plans/{plan_id}` | `X-User-Id` = plan.creator_id | 756-789 |
| `archive_plan` | POST | `/api/plans/{plan_id}/archive` | `X-User-Id` = plan.creator_id | 792-812 |

**Create plan** (`subscription_server.py:706-743`):

```python
@router.post("/api/creators/{creator_id}/plans", response_model=PlanOut)
async def create_plan(
    creator_id: str,
    body: PlanCreateIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    require_user(x_user_id, creator_id)
    asset_paths = normalize_asset_paths(body.asset_paths)
    assets = resolve_plan_assets(creator_id, asset_paths) if asset_paths else []
    plan_id = new_id("plan")
    ts = now_ts()
    plan = {
        "plan_id": plan_id,
        "creator_id": creator_id,
        "name": body.name,
        "description": body.description,
        "price_cents": int(body.price_cents),
        "currency": body.currency.lower(),
        "interval": body.interval,
        "annual_price_cents": int(body.annual_price_cents) if body.annual_price_cents else None,
        "status": "active",
        "metadata": body.metadata,
        "assets": assets,
        "created_at": ts,
        "updated_at": ts,
    }
    save_plan(plan)
    audit_event("subscription_plan_created", creator_id, request, ...)
    return attach_creator_profile(plan)
```

Key observations:
- `require_user(x_user_id, creator_id)` at line 713 enforces ownership.
- `normalize_asset_paths` + `resolve_plan_assets` at lines 714-715 handle asset resolution.
- Status is always "active" on creation.
- `audit_event` records the action for compliance.

**Update plan** (`subscription_server.py:756-789`):

```python
@router.patch("/api/plans/{plan_id}", response_model=PlanOut)
async def update_plan(
    plan_id: str,
    body: PlanUpdateIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    plan = ddb_get_item(pk_plan(plan_id), "META")
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    require_user(x_user_id, plan["creator_id"])
    updated = plan.copy()
    for field in ("name", "description", "price_cents", "currency", "interval", "status", "metadata"):
        value = getattr(body, field)
        if value is not None:
            if field == "currency":
                value = value.lower()
            updated[field] = value
    if body.annual_price_cents is not None:
        updated["annual_price_cents"] = int(body.annual_price_cents)
    if body.asset_paths is not None:
        asset_paths = normalize_asset_paths(list(body.asset_paths))
        updated["assets"] = resolve_plan_assets(plan["creator_id"], asset_paths) if asset_paths else []
    updated["updated_at"] = now_ts()
    save_plan(updated)
```

Supports partial updates -- any subset of fields can be sent. This enables the frontend to send only changed fields.

**Citations**:
- `app/routers/subscription_server.py:706-743` -- `create_plan` with asset resolution
- `app/routers/subscription_server.py:713` -- `require_user(x_user_id, creator_id)` ownership check
- `app/routers/subscription_server.py:756-789` -- `update_plan` with partial field updates
- `app/routers/subscription_server.py:792-812` -- `archive_plan` sets status to "archived"

### 3.2 Plan Models (subscription_server.py:289-327)

**PlanCreateIn** (line 289):

```python
class PlanCreateIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1000)
    price_cents: conint(gt=0)
    currency: str = Field(default="usd", min_length=3, max_length=10)
    interval: Literal["month", "year"] = "month"
    annual_price_cents: Optional[conint(gt=0)] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    asset_paths: List[str] = Field(default_factory=list)
```

**PlanUpdateIn** (line 300):

```python
class PlanUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1000)
    price_cents: Optional[conint(gt=0)] = None
    currency: Optional[str] = Field(default=None, min_length=3, max_length=10)
    interval: Optional[Literal["month", "year"]] = None
    annual_price_cents: Optional[conint(gt=0)] = None
    status: Optional[Literal["active", "archived"]] = None
    metadata: Optional[Dict[str, Any]] = None
    asset_paths: Optional[conlist(str, max_length=50)] = None
```

**PlanOut** (line 312):

```python
class PlanOut(BaseModel):
    plan_id: str
    creator_id: str
    name: str
    description: Optional[str]
    price_cents: int
    currency: str
    interval: str
    annual_price_cents: Optional[int] = None
    status: str
    metadata: Dict[str, Any]
    assets: List[Dict[str, Any]]
    created_at: int
    updated_at: int
    creator_profile: Optional[Dict[str, Optional[str]]] = None
```

**Citations**:
- `app/routers/subscription_server.py:289-297` -- `PlanCreateIn` model
- `app/routers/subscription_server.py:300-309` -- `PlanUpdateIn` model (all fields optional)
- `app/routers/subscription_server.py:312-326` -- `PlanOut` response model

### 3.3 Discount Code Endpoints (subscription_server.py:1573-1669)

**Create discount** (`subscription_server.py:1573-1617`):

```python
@router.post("/api/creators/{creator_id}/discounts", response_model=DiscountCodeOut)
async def create_discount_code(
    creator_id: str,
    body: DiscountCodeCreateIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    require_user(x_user_id, creator_id)
    code = body.code.strip().upper()
    if body.duration == "repeating" and not body.duration_months:
        raise HTTPException(status_code=400, detail="duration_months required for repeating discounts")
    if body.duration != "repeating" and body.duration_months:
        raise HTTPException(status_code=400, detail="duration_months only valid for repeating discounts")
    ts = now_ts()
    item = {
        "pk": pk_creator(creator_id),
        "sk": _discount_sk(code),
        "entity": "discount",
        "code": code,
        "percent_off": int(body.percent_off),
        "duration": body.duration,
        "duration_months": body.duration_months,
        "active": bool(body.active),
        "created_at": ts,
        "updated_at": ts,
    }
    ddb_put_item(item)
```

Key observations:
- Code is auto-uppercased (line 1581).
- Duration validation: "repeating" requires `duration_months`, non-repeating rejects it (lines 1582-1585).
- Stored with `SK=DISCOUNT#{code}` under the creator's partition (line 1589).
- `ddb_put_item` is an unconditional put -- creating a duplicate code overwrites the existing one silently.

**List discounts** (`subscription_server.py:1620-1637`):

```python
@router.get("/api/creators/{creator_id}/discounts", response_model=List[DiscountCodeOut])
async def list_discount_codes(creator_id: str, x_user_id: Optional[str] = Header(default=None)):
    require_user(x_user_id, creator_id)
    items = ddb_query(pk_creator(creator_id))
    discounts = [it for it in items if it.get("sk", "").startswith("DISCOUNT#")]
    discounts.sort(key=lambda x: x.get("created_at", 0), reverse=True)
```

**Disable discount** (`subscription_server.py:1640-1669`):

```python
@router.post("/api/creators/{creator_id}/discounts/{code}/disable", response_model=DiscountCodeOut)
async def disable_discount_code(creator_id: str, code: str, ...):
    require_user(x_user_id, creator_id)
    item = _get_discount(creator_id, code)
    if not item:
        raise HTTPException(status_code=404, detail="Discount code not found")
    item["active"] = False
    item["updated_at"] = now_ts()
    ddb_put_item(item)
```

**Citations**:
- `app/routers/subscription_server.py:1573-1617` -- `create_discount_code` with validation
- `app/routers/subscription_server.py:1581` -- auto-uppercase code
- `app/routers/subscription_server.py:1582-1585` -- duration/duration_months validation
- `app/routers/subscription_server.py:1589` -- `_discount_sk(code)` storage key
- `app/routers/subscription_server.py:1620-1637` -- `list_discount_codes`
- `app/routers/subscription_server.py:1640-1669` -- `disable_discount_code`

### 3.4 Discount Code Models (subscription_server.py:466-483)

```python
class DiscountCodeCreateIn(BaseModel):
    code: str = Field(..., min_length=3, max_length=32)
    percent_off: conint(ge=1, le=100)
    duration: Literal["once", "repeating", "forever"] = "once"
    duration_months: Optional[conint(ge=1, le=36)] = None
    active: bool = True

class DiscountCodeOut(BaseModel):
    code: str
    percent_off: int
    duration: str
    duration_months: Optional[int] = None
    active: bool
    created_at: int
    updated_at: int
```

**Citations**:
- `app/routers/subscription_server.py:466-471` -- `DiscountCodeCreateIn` with constraints
- `app/routers/subscription_server.py:474-481` -- `DiscountCodeOut` response model

### 3.5 Asset Resolution (subscription_server.py:714-716)

Plan creation resolves `asset_paths` to actual file metadata:

```python
asset_paths = normalize_asset_paths(body.asset_paths)
assets = resolve_plan_assets(creator_id, asset_paths) if asset_paths else []
```

`resolve_plan_assets` looks up files in the creator's file manager and returns metadata (file name, size, type, URL). The resolved assets are stored in the `assets` field of the plan item.

**Citations**:
- `app/routers/subscription_server.py:714-715` -- asset path normalization and resolution

### 3.6 Existing Subscriber-Facing PlanBrowser (PlanBrowser.tsx:1-187)

The `PlanBrowser` component renders plan cards for subscribers:

```typescript
export function PlanBrowser({ creatorId }: PlanBrowserProps) {
  const { data: plans, isLoading } = useQuery({
    queryKey: ["plans", creatorId],
    queryFn: () => listPlans(creatorId),
    enabled: !!creatorId,
  });

  const activePlans = (plans ?? []).filter((p) => p.status === "active");
```

Features:
- Filters for `status === "active"` (hides archived plans).
- Shows plan cards with name, description, price, annual price, assets as features.
- Has discount code input field.
- Subscribe mutation with success/error toasts.
- Marks middle plan as "Popular" (if 3+ plans).
- Loading skeleton (3 cards).
- Empty state with Sparkles icon.

This component is read-only and subscriber-facing. The creator management UI needs separate components.

**Citations**:
- `frontend/src/pages/subscriptions/PlanBrowser.tsx:36-46` -- query with listPlans
- `frontend/src/pages/subscriptions/PlanBrowser.tsx:66` -- `status === "active"` filter

### 3.7 Frontend Subscription API Client (subscriptions.ts:1-79)

```typescript
function userIdHeader(): Record<string, string> {
  const userId = useAuthStore.getState().userId;
  return userId ? { "X-User-Id": userId } : {};
}

function subGet<T>(path: string, params?: Record<string, string>) {
  return api<T>(path, { method: "GET", headers: userIdHeader(), params });
}

function subPost<T>(path: string, body?: unknown) {
  return api<T>(path, {
    method: "POST",
    headers: { ...userIdHeader(), "Content-Type": "application/json" },
    body: body != null ? JSON.stringify(body) : undefined,
  });
}
```

Currently has:
- `listPlans(creatorId)` -- public endpoint, no X-User-Id needed
- `subscribe(planId, body)` -- subscriber action
- `listSubscriptions(params)` -- list user's own subscriptions
- `cancelSubscription`, `resumeSubscription`, `changePlan`, `updateRenewal`

<!-- NOTE: The creator CRUD functions listed below as "missing" have since been implemented at subscriptions.ts:94-112 (createPlan, updatePlan, archivePlan, createDiscount, listDiscounts, disableDiscount). -->
~~**Missing**: No `createPlan`, `updatePlan`, `archivePlan`, `createDiscount`, `listDiscounts`, `disableDiscount` functions.~~

**Citations**:
- `frontend/src/api/endpoints/subscriptions.ts:17-31` -- `userIdHeader()`, `subGet()`, `subPost()` helpers (see `frontend/src/api/endpoints/subscriptions.ts:17,22,26`)
- `frontend/src/api/endpoints/subscriptions.ts:37` -- `listPlans`
- `frontend/src/api/endpoints/subscriptions.ts:94-112` -- creator CRUD functions now exist: `createPlan`, `updatePlan`, `archivePlan`, `createDiscount`, `listDiscounts`, `disableDiscount`

---

## 4. Implementation Plan

### 4.1 API Client Extensions

**File: `frontend/src/api/endpoints/subscriptions.ts`** (additions)

```typescript
// ── Plan CRUD (Creator) ──────────────────────────────────────

export const createPlan = (creatorId: string, body: PlanCreateReq) =>
  subPost<SubscriptionPlan>(`/api/creators/${creatorId}/plans`, body);

export const updatePlan = (planId: string, body: PlanUpdateReq) => {
  const userId = useAuthStore.getState().userId;
  return api.patch<SubscriptionPlan>(`/api/plans/${planId}`, body, {
    headers: userId ? { "X-User-Id": userId } : {},
  });
};

export const archivePlan = (planId: string) =>
  subPost<SubscriptionPlan>(`/api/plans/${planId}/archive`, {});

// ── Discount Codes ───────────────────────────────────────────

export const createDiscount = (creatorId: string, body: DiscountCodeCreateReq) =>
  subPost<DiscountCode>(`/api/creators/${creatorId}/discounts`, body);

export const listDiscounts = (creatorId: string) =>
  subGet<DiscountCode[]>(`/api/creators/${creatorId}/discounts`);

export const disableDiscount = (creatorId: string, code: string) =>
  subPost<DiscountCode>(`/api/creators/${creatorId}/discounts/${encodeURIComponent(code)}/disable`, {});
```

### 4.2 TypeScript Types

**File: `frontend/src/api/types.ts`** (additions)

```typescript
// ── Plan CRUD Types ─────────────────────────────────────────

export interface PlanCreateReq {
  name: string;
  description?: string;
  price_cents: number;
  currency?: string;
  interval: "month" | "year";
  annual_price_cents?: number;
  metadata?: Record<string, unknown>;
  asset_paths?: string[];
}

export interface PlanUpdateReq {
  name?: string;
  description?: string;
  price_cents?: number;
  currency?: string;
  interval?: "month" | "year";
  annual_price_cents?: number;
  status?: "active" | "archived";
  metadata?: Record<string, unknown>;
  asset_paths?: string[];
}

// ── Discount Code Types ─────────────────────────────────────

export interface DiscountCodeCreateReq {
  code: string;
  percent_off: number;
  duration: "once" | "forever" | "repeating";
  duration_months?: number;
  active?: boolean;
}

export interface DiscountCode {
  code: string;
  percent_off: number;
  duration: string;
  duration_months?: number;
  active: boolean;
  created_at: number;
  updated_at: number;
}
```

### 4.3 Component: TierManager

**New file: `frontend/src/pages/subscriptions/TierManager.tsx`** (~300 lines)

The main page component at `/subscriptions/manage`:

```
TierManager
├── Header
│   ├── h1: "Subscription Tiers"
│   └── Subtitle: "Manage your subscription plans and discount codes"
├── Tabs (shadcn)
│   ├── TabsTrigger "Plans"
│   ├── TabsTrigger "Discount Codes"
│   └── TabsTrigger "Preview"
├── TabsContent "plans"
│   ├── "Create Plan" Button (top-right, opens PlanEditor dialog)
│   ├── Plan List (cards layout)
│   │   └── For each plan:
│   │       ├── Card with plan details
│   │       │   ├── Name (h3)
│   │       │   ├── Price: $X/month (formatted)
│   │       │   ├── Annual: $X/year (if set, with savings %)
│   │       │   ├── Description (truncated to 2 lines)
│   │       │   ├── Assets (bullet list, max 3 shown + "N more")
│   │       │   ├── Status Badge (active=green, archived=grey)
│   │       │   └── Created date
│   │       ├── Edit button → opens PlanEditor in edit mode
│   │       ├── Archive button → confirmation dialog (active plans only)
│   │       └── Reactivate button → PATCH status="active" (archived plans only)
│   └── Empty state: "No subscription tiers yet. Create your first tier to start earning."
├── TabsContent "discounts"
│   └── DiscountCodeManager
└── TabsContent "preview"
    └── PlanBrowser (existing component, creatorId = current user)
```

Key implementation:

```typescript
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Layers, Plus, Pencil, Archive, RefreshCw } from "lucide-react";
import {
  listPlans,
  createPlan,
  updatePlan,
  archivePlan,
  listDiscounts,
} from "@/api/endpoints/subscriptions";
import { useAuthStore } from "@/stores/authStore";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { PlanEditor } from "./PlanEditor";
import { DiscountCodeManager } from "./DiscountCodeManager";
import { PlanBrowser } from "./PlanBrowser";

export default function TierManager() {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingPlan, setEditingPlan] = useState<SubscriptionPlan | null>(null);

  const { data: plans, isLoading } = useQuery({
    queryKey: ["creator-plans", userId],
    queryFn: () => listPlans(userId!),
    enabled: !!userId,
  });

  const archiveMut = useMutation({
    mutationFn: (planId: string) => archivePlan(planId),
    onSuccess: () => {
      toast.success("Plan archived");
      queryClient.invalidateQueries({ queryKey: ["creator-plans", userId] });
    },
    onError: () => toast.error("Failed to archive plan"),
  });

  const reactivateMut = useMutation({
    mutationFn: (planId: string) => updatePlan(planId, { status: "active" }),
    onSuccess: () => {
      toast.success("Plan reactivated");
      queryClient.invalidateQueries({ queryKey: ["creator-plans", userId] });
    },
    onError: () => toast.error("Failed to reactivate plan"),
  });

  // ... render with Tabs, plan cards, PlanEditor dialog
}
```

React Query keys:
- `["creator-plans", userId]` -- creator's own plans (all statuses)
- `["creator-discounts", userId]` -- creator's discount codes
- `["plans", userId]` -- existing public plans query (used by PlanBrowser)

### 4.4 Component: PlanEditor

**New file: `frontend/src/pages/subscriptions/PlanEditor.tsx`** (~250 lines)

A dialog form for creating or editing a plan:

```
PlanEditor (Dialog)
├── DialogHeader
│   └── Title: "Create Plan" or "Edit Plan"
├── Form (React Hook Form + Zod)
│   ├── Name Input
│   │   └── required, min 2, max 128
│   ├── Description Textarea
│   │   └── optional, max 1000 chars, character counter
│   ├── Billing Interval Select
│   │   └── "Monthly" or "Yearly"
│   ├── Price Input (dollars, converted to cents)
│   │   └── required, > $0, formatted as currency
│   ├── Annual Price Input (dollars, converted to cents)
│   │   └── optional, shown only when interval="month"
│   │   └── Shows savings percentage below
│   ├── Currency Select
│   │   └── "USD" (default), "EUR", "GBP", etc.
│   ├── Asset Paths (dynamic list)
│   │   ├── Each: text input with remove button
│   │   └── "Add asset path" button
│   └── Metadata (advanced, collapsed by default)
│       └── Key-value pairs with add/remove
├── DialogFooter
│   ├── Cancel button (closes dialog)
│   └── Save button (Create or Update)
│       └── Loading spinner during mutation
```

Zod validation schema:

```typescript
import { z } from "zod";

const planSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters").max(128),
  description: z.string().max(1000).optional().or(z.literal("")),
  price_dollars: z.number().positive("Price must be greater than $0"),
  interval: z.enum(["month", "year"]),
  annual_price_dollars: z.number().positive().optional().nullable(),
  currency: z.string().min(3).max(10).default("usd"),
  asset_paths: z.array(z.string()).default([]),
});

type PlanFormValues = z.infer<typeof planSchema>;

// On submit, convert dollars to cents:
const body: PlanCreateReq = {
  name: values.name,
  description: values.description || undefined,
  price_cents: Math.round(values.price_dollars * 100),
  interval: values.interval,
  annual_price_cents: values.annual_price_dollars
    ? Math.round(values.annual_price_dollars * 100)
    : undefined,
  currency: values.currency,
  asset_paths: values.asset_paths.filter(Boolean),
};
```

### 4.5 Component: DiscountCodeManager

**New file: `frontend/src/pages/subscriptions/DiscountCodeManager.tsx`** (~200 lines)

```
DiscountCodeManager
├── "Create Code" Button (opens inline form or sheet)
├── Create Form
│   ├── Code Input (auto-uppercased on blur)
│   │   └── 3-32 chars, warning if duplicate
│   ├── Percent Off Input
│   │   └── 1-100, integer only
│   ├── Duration Select
│   │   └── "Once" | "Forever" | "Repeating"
│   ├── Duration Months Input (shown only for "Repeating")
│   │   └── 1-36
│   └── Submit Button
├── Discount Codes Table
│   ├── Columns: Code | % Off | Duration | Status | Created | Actions
│   ├── Status: "Active" (green badge) or "Disabled" (red badge)
│   ├── Actions: "Disable" button (active codes only) with confirmation
│   └── Empty state: "No discount codes yet. Create one to start promotions."
```

Discount code Zod schema:

```typescript
const discountSchema = z.object({
  code: z.string().min(3, "Code must be at least 3 characters").max(32),
  percent_off: z.number().int().min(1).max(100),
  duration: z.enum(["once", "forever", "repeating"]),
  duration_months: z.number().int().min(1).max(36).optional().nullable(),
}).refine(
  (data) => data.duration !== "repeating" || (data.duration_months != null && data.duration_months > 0),
  { message: "Duration months is required for repeating discounts", path: ["duration_months"] },
);
```

### 4.6 Route + Sidebar Registration

**File: `frontend/src/App.tsx`** (inside ProtectedRoute)

```typescript
<Route path="subscriptions/manage" element={<TierManager />} />
```

**File: `frontend/src/components/layout/Sidebar.tsx`** (Commerce group)

```typescript
{ label: "Tier Manager", i18nKey: "nav.tierManager", path: "/subscriptions/manage", icon: <Layers className="h-5 w-5" /> },
```

**File: `frontend/src/components/layout/AppShell.tsx`** (MobileSidebar)

Add "Tier Manager" entry to mobile navigation.

**File: `frontend/src/components/layout/MobileNav.tsx`** (MORE_LINKS)

```typescript
{ label: "Tier Manager", path: "/subscriptions/manage" },
```

---

## 5. Data Model

### 5.1 Subscription Plans (Existing Table)

Plans are stored in the `subscriptions` DynamoDB table:

| Attribute | Type | Example |
|-----------|------|---------|
| `pk` (PK) | S | `"CREATOR#user_abc123"` |
| `sk` (SK) | S | `"PLAN#plan_xyz789"` |
| `plan_id` | S | `"plan_xyz789"` |
| `creator_id` | S | `"user_abc123"` |
| `name` | S | `"Pro Tier"` |
| `description` | S | `"Access to all premium content"` |
| `price_cents` | N | `999` |
| `currency` | S | `"usd"` |
| `interval` | S | `"month"` |
| `annual_price_cents` | N | `9999` |
| `status` | S | `"active"` or `"archived"` |
| `metadata` | M | `{}` |
| `assets` | L | `[{"path": "/videos/intro.mp4", "name": "Intro Video", "size": 15000000}]` |
| `created_at` | N | `1716580000` |
| `updated_at` | N | `1716580000` |

### 5.2 Discount Codes (Same Table)

Discount codes share the subscriptions table:

| Attribute | Type | Example |
|-----------|------|---------|
| `pk` (PK) | S | `"CREATOR#user_abc123"` |
| `sk` (SK) | S | `"DISCOUNT#SAVE20"` |
| `entity` | S | `"discount"` |
| `code` | S | `"SAVE20"` |
| `percent_off` | N | `20` |
| `duration` | S | `"once"` |
| `duration_months` | N | `null` |
| `active` | BOOL | `true` |
| `created_at` | N | `1716580000` |
| `updated_at` | N | `1716580000` |

### 5.3 Access Patterns

| Pattern | Key Expression | Use Case |
|---------|---------------|----------|
| List creator's plans | `PK = CREATOR#{creator_id}`, filter `SK begins_with("PLAN#")` | TierManager plan list |
| Get single plan | `PK = PLAN#{plan_id}`, `SK = META` | Plan edit dialog pre-fill |
| List creator's discounts | `PK = CREATOR#{creator_id}`, filter `SK begins_with("DISCOUNT#")` | DiscountCodeManager table |
| Get single discount | `PK = CREATOR#{creator_id}`, `SK = DISCOUNT#{code}` | Disable discount lookup |

---

## 6. API Design

All endpoints are **existing** -- no new backend endpoints. This section documents the API contracts used by the frontend.

### 6.1 POST /api/creators/{creator_id}/plans

**Auth**: `X-User-Id` header (must match `creator_id`)
**Request**:
```json
{
  "name": "Pro Tier",
  "description": "Access to all premium content",
  "price_cents": 999,
  "currency": "usd",
  "interval": "month",
  "annual_price_cents": 9999,
  "asset_paths": ["/videos/intro.mp4"]
}
```
**Response** (200): `PlanOut` object
**Error codes**: 403 (not owner), 422 (validation error)

### 6.2 PATCH /api/plans/{plan_id}

**Auth**: `X-User-Id` header (must match plan's `creator_id`)
**Request** (partial update):
```json
{
  "name": "Pro Tier v2",
  "price_cents": 1499
}
```
**Response** (200): Updated `PlanOut` object
**Error codes**: 403 (not owner), 404 (plan not found), 422 (validation error)

### 6.3 POST /api/plans/{plan_id}/archive

**Auth**: `X-User-Id` header
**Request**: `{}` (empty body)
**Response** (200): `PlanOut` with `status: "archived"`

### 6.4 POST /api/creators/{creator_id}/discounts

**Auth**: `X-User-Id` header
**Request**:
```json
{
  "code": "SAVE20",
  "percent_off": 20,
  "duration": "once",
  "active": true
}
```
**Response** (200): `DiscountCodeOut` object
**Error codes**: 400 (duration_months validation), 403 (not owner)

### 6.5 GET /api/creators/{creator_id}/discounts

**Auth**: `X-User-Id` header
**Response** (200): `DiscountCodeOut[]` sorted by `created_at` descending

### 6.6 POST /api/creators/{creator_id}/discounts/{code}/disable

**Auth**: `X-User-Id` header
**Response** (200): `DiscountCodeOut` with `active: false`
**Error codes**: 404 (code not found)

---

## 7. Frontend Implementation Details

### 7.1 Component Tree

```
/subscriptions/manage (route)
└── TierManager
    ├── Page Header (h1 + subtitle)
    ├── Tabs
    │   ├── "Plans" Tab
    │   │   ├── Create Plan Button
    │   │   │   └── Opens PlanEditor (mode="create")
    │   │   └── Plan Cards Grid
    │   │       └── PlanCard (per plan)
    │   │           ├── Name, Price, Status Badge
    │   │           ├── Description (truncated)
    │   │           ├── Assets (bullet list)
    │   │           ├── Edit Button → PlanEditor (mode="edit")
    │   │           ├── Archive Button → AlertDialog
    │   │           └── Reactivate Button (archived only)
    │   ├── "Discount Codes" Tab
    │   │   └── DiscountCodeManager
    │   │       ├── Create Form (inline or dialog)
    │   │       └── Data Table
    │   │           └── Row: Code | % | Duration | Status Badge | Actions
    │   └── "Preview" Tab
    │       └── PlanBrowser (reused, creatorId=userId)
    └── PlanEditor Dialog (shared)
        ├── React Hook Form + Zod
        ├── Name, Description, Price, Interval, Annual, Currency, Assets
        └── Submit → createPlan or updatePlan
```

### 7.2 React Query Keys

| Key | Purpose | Invalidated On |
|-----|---------|----------------|
| `["creator-plans", userId]` | All plans (active + archived) for creator | Create, update, archive, reactivate |
| `["creator-discounts", userId]` | All discount codes for creator | Create, disable |
| `["plans", userId]` | Public plans (used by PlanBrowser) | Plan status changes |

### 7.3 State Management

Local component state (no Zustand store):
- `editorOpen: boolean` -- PlanEditor dialog visibility
- `editingPlan: SubscriptionPlan | null` -- plan being edited (null = create mode)
- `activeTab: "plans" | "discounts" | "preview"` -- current tab

### 7.4 Dollar-to-Cents Conversion

All prices are stored as cents in the backend but displayed and entered as dollars in the UI:

```typescript
// Display: cents → dollars
function formatPrice(cents: number, currency: string): string {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: currency || "USD",
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

// Input: dollars → cents (on submit)
const priceCents = Math.round(values.price_dollars * 100);
```

### 7.5 Responsive Design

- **Desktop**: Plan cards in a 3-column grid. Discount table with all columns.
- **Tablet**: Plan cards in a 2-column grid. Discount table with stacked mobile layout for small columns.
- **Mobile**: Plan cards in a single column. Discount codes as stacked cards instead of table rows.
- **PlanEditor dialog**: Full-width on mobile, 500px max-width on desktop.

---

## 8. Security Considerations

### 8.1 Creator Ownership Enforcement

All plan CRUD and discount endpoints validate that `X-User-Id` matches the plan's `creator_id`. The backend calls `require_user(x_user_id, creator_id)` which raises 403 if the IDs don't match.

```python
# subscription_server.py:713 (create)
require_user(x_user_id, creator_id)

# subscription_server.py:766 (update)
require_user(x_user_id, plan["creator_id"])

# subscription_server.py:801 (archive)
require_user(x_user_id, plan["creator_id"])
```

The frontend sends `X-User-Id` from `useAuthStore.getState().userId` via the `userIdHeader()` helper. A user cannot create/edit/archive plans belonging to another creator.

**Citations**:
- `app/routers/subscription_server.py:713` -- ownership on create
- `app/routers/subscription_server.py:766` -- ownership on update
- `app/routers/subscription_server.py:801` -- ownership on archive

### 8.2 Status Validation

- Archive only works on plans that exist (404 for missing plans).
- The frontend hides the archive button for already-archived plans to prevent confusion.
- Reactivation uses the PATCH endpoint to set `status: "active"` -- no separate endpoint needed.
- The backend does NOT prevent archiving a plan with active subscribers (subscribers keep their subscription).

### 8.3 Discount Code Security

- Discount codes are stored with `SK=DISCOUNT#{code}` under the creator's partition.
- Creating a duplicate code will overwrite the existing one (`ddb_put_item` is unconditional).
- The frontend checks the existing codes list and shows a warning before overwriting.
- Disabled codes cannot be re-enabled via the API (no enable endpoint). A creator must create a new code with the same name (which overwrites the disabled one).
- Discount code validation (code format, percent_off range, duration consistency) is enforced on both frontend (Zod) and backend (Pydantic).

### 8.4 Input Validation

| Field | Frontend (Zod) | Backend (Pydantic) |
|-------|----------------|-------------------|
| Plan name | min 2, max 128 | `min_length=2, max_length=128` |
| Plan description | max 1000 | `max_length=1000` |
| Price | > 0 (dollars) | `gt=0` (cents) |
| Interval | "month" or "year" | `Literal["month", "year"]` |
| Asset paths | array of strings | `conlist(str, max_length=50)` |
| Discount code | min 3, max 32 | `min_length=3, max_length=32` |
| Percent off | 1-100, integer | `ge=1, le=100` |
| Duration months | 1-36 (if repeating) | `ge=1, le=36` |

---

## 9. Testing Plan

### 9.1 E2E Tests

**Test file**: `frontend/e2e/tier-manager.spec.ts`

**Section 1: Plan CRUD UI (6 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | Navigate to /subscriptions/manage shows TierManager | injectAuth(alice) | "Subscription Tiers" heading visible |
| 2 | Create Plan dialog opens and submits | Click "Create Plan"; fill form; submit | New plan appears in list with "active" badge |
| 3 | Edit Plan dialog pre-fills existing data | Click Edit on plan | Name/price pre-populated; change name; save; list updated |
| 4 | Archive Plan with confirmation | Click Archive; confirm dialog | Status badge changes to "archived" |
| 5 | Archived plan shows in list with "archived" badge | After archive | Archived plan visible with grey badge |
| 6 | Reactivate archived plan | Click Reactivate on archived plan | Status changes back to "active" |

**Section 2: Plan Validation (4 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 7 | Name too short shows validation error | Enter 1-char name | "at least 2 characters" error visible |
| 8 | Price of 0 shows validation error | Enter $0.00 | "Price must be greater than 0" error visible |
| 9 | Annual price shown only for monthly plans | Select "Yearly" interval | Annual price field hidden |
| 10 | Asset paths are editable | Add 2 asset paths; remove 1; submit | Plan has 1 asset |

**Section 3: Discount Code Management (5 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 11 | Navigate to Discount Codes tab | Click "Discount Codes" tab | Table or empty state visible |
| 12 | Create discount code | Fill form: "SAVE20", 20%, "once"; submit | Code appears in table with "Active" badge |
| 13 | Repeating discount requires duration_months | Select "Repeating" duration | duration_months field appears; submit without it fails |
| 14 | Disable discount code | Click Disable on active code; confirm | Status changes to "Disabled" (red badge) |
| 15 | Disabled code shown in table | After disable | Code visible with red badge |

**Section 4: Preview Tab (2 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 16 | Preview tab shows PlanBrowser view | Click "Preview" tab | Plan cards visible with Subscribe buttons |
| 17 | Only active plans shown in preview | After archiving a plan | Preview tab does not show archived plan |

**Section 5: Navigation (2 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 18 | Tier Manager visible in sidebar | Navigate to any page | Sidebar shows "Tier Manager" link |
| 19 | Sidebar link navigates correctly | Click "Tier Manager" link | URL is /subscriptions/manage |

### 9.2 Test Implementation Details

Auth pattern (matching existing subscription tests):

```typescript
// Subscription server uses X-User-Id, not cookie auth
const ALICE_SUB = sessions["alice"].user_sub;

// Plan creation via API
const createResp = await request.post(`/api/creators/${ALICE_SUB}/plans`, {
  headers: { "X-User-Id": ALICE_SUB, "Content-Type": "application/json" },
  data: {
    name: `Test Plan ${Date.now()}`,
    price_cents: 999,
    interval: "month",
  },
});
expect(createResp.ok()).toBeTruthy();
const plan = await createResp.json();

// UI verification
await page.goto("/subscriptions/manage");
await expect(page.getByText(plan.name)).toBeVisible();
```

### 9.3 Unit Tests

No new backend code -- existing `subscription_server` tests cover the API layer. The frontend is tested via E2E tests.

---

## 10. Performance Considerations

### 10.1 Query Efficiency

- `listPlans(creatorId)` returns all plans (active + archived). The frontend filters locally. At typical volumes (< 20 plans per creator), this is efficient.
- `listDiscounts(creatorId)` queries all items under `CREATOR#{creatorId}` and filters for `DISCOUNT#` prefix. This is a DDB Query (not Scan) -- efficient even at 1000+ items per creator.

### 10.2 React Query Caching

| Key | staleTime | Rationale |
|-----|-----------|-----------|
| `["creator-plans", userId]` | 30s | Plans change infrequently; short stale time for edit responsiveness |
| `["creator-discounts", userId]` | 30s | Same rationale |
| `["plans", userId]` | 60s | Preview tab; subscriber-facing cache |

### 10.3 Optimistic Updates

Plan archiving and discount disabling use optimistic updates:

```typescript
const archiveMut = useMutation({
  mutationFn: (planId) => archivePlan(planId),
  onMutate: async (planId) => {
    await queryClient.cancelQueries({ queryKey: ["creator-plans", userId] });
    const prev = queryClient.getQueryData(["creator-plans", userId]);
    queryClient.setQueryData(["creator-plans", userId], (old) =>
      old?.map((p) => (p.plan_id === planId ? { ...p, status: "archived" } : p)),
    );
    return { prev };
  },
  onError: (err, planId, ctx) => {
    queryClient.setQueryData(["creator-plans", userId], ctx?.prev);
  },
  onSettled: () => {
    queryClient.invalidateQueries({ queryKey: ["creator-plans", userId] });
  },
});
```

---

## 11. Migration & Rollout

### 11.1 No Backend Changes

This is a purely frontend ticket. All backend endpoints already exist and are tested. No database migration needed.

### 11.2 Route Registration

Add the `/subscriptions/manage` route to `App.tsx` inside the authenticated route group. The route is only accessible to authenticated users.

### 11.3 Sidebar Addition

Add "Tier Manager" link to the Commerce group in `Sidebar.tsx`. Position it after the existing "Subscriptions" link.

### 11.4 Rollback

Remove the route from `App.tsx` and the sidebar link from `Sidebar.tsx`. Delete the three new component files. No backend or database changes to revert.

### 11.5 Backwards Compatibility

- No breaking changes to existing APIs.
- The `PlanBrowser` component is unchanged (it's reused in the Preview tab).
- Existing subscription flows (subscriber-facing) are unaffected.

---

## 12. Acceptance Criteria

1. `/subscriptions/manage` route renders the TierManager page.
2. Creators can create a new subscription plan with name, description, price, interval, and optional annual pricing.
3. Creators can edit an existing plan's name, description, price, and assets.
4. Creators can archive a plan (with confirmation dialog), and the plan shows as "archived" in the list.
5. Creators can reactivate an archived plan.
6. Discount Codes tab shows all codes with create, list, and disable functionality.
7. Repeating discounts require a `duration_months` value (enforced by both frontend and backend).
8. Preview tab shows the subscriber-facing PlanBrowser view with only active plans.
9. Form validation prevents invalid input (empty name, zero price, missing duration_months for repeating).
10. "Tier Manager" link appears in the sidebar Commerce group.
11. Price input is in dollars; conversion to cents happens on submit.
12. Discount codes are auto-uppercased.
13. All 19 E2E tests pass.

---

## 13. Dependencies

- **MON-005 (Subscription-Gated VOD)**: Backend plan CRUD endpoints. Already fully implemented in `subscription_server.py:706-812`.
- **PlanBrowser.tsx**: Existing subscriber-facing component reused for Preview tab. No changes needed.
- **Subscription API client** (`subscriptions.ts`): Extended with new functions but existing functions unchanged.
- **shadcn/ui components**: Tabs, Dialog, AlertDialog, Card, Badge, Button, Input, Select, Textarea -- all already in the project.
- **React Hook Form + Zod**: Already used throughout the codebase for form validation.

---

## 14. Open Questions & Risks

### 14.1 Open Questions

1. **Price change impact on existing subscribers**: When a creator changes `price_cents`, does it affect existing subscribers at their next renewal? The backend likely applies the plan's current price at renewal time. Should the UI warn creators about this?
2. **Plan deletion**: The backend has no delete endpoint (only archive). Should there be one? Deleting a plan with active subscribers is destructive. Archive is safer.
3. **Subscriber count**: Should plan cards show how many active subscribers each tier has? This would require a new backend query or a count field on the plan item.
4. **Asset picker**: Should the asset paths input be a file picker (browsing the file manager) or a text input? A file picker would be better UX but requires integrating the `FilePickerDialog` component.
5. **Multi-currency**: Should creators be able to set different prices for different currencies? Currently each plan has a single `currency` field.

### 14.2 Risks

1. **X-User-Id auth pattern**: The subscription server uses `X-User-Id` header auth, not cookie-based session auth. The frontend must correctly send this header via the `userIdHeader()` helper. If the auth store's `userId` is null or incorrect, all mutations will fail with 403.
2. **Discount code overwrites**: `ddb_put_item` is unconditional -- creating a discount code with an existing code name silently overwrites it. The frontend should warn, but a race condition between two browser tabs could still cause unexpected overwrites.
3. **PlanBrowser reuse in Preview tab**: The PlanBrowser's `subscribe` mutation uses `subPost` which sends `X-User-Id`. If a creator subscribes to their own plan in the preview, it would create a self-subscription. Consider disabling Subscribe buttons in the Preview tab or adding a "You are previewing your own plans" banner.

---

## 15. Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/subscriptions/TierManager.tsx` | Main page: plan list with create/edit/archive/preview | ~300 |
| `frontend/src/pages/subscriptions/PlanEditor.tsx` | Create/edit form dialog for a single plan | ~250 |
| `frontend/src/pages/subscriptions/DiscountCodeManager.tsx` | Discount code table with create form | ~200 |
| `frontend/e2e/tier-manager.spec.ts` | E2E tests (19 tests) | ~400 |

## 16. Files to Modify

| File | Change |
|------|--------|
| `frontend/src/api/endpoints/subscriptions.ts` | Add `createPlan`, `updatePlan`, `archivePlan`, `createDiscount`, `listDiscounts`, `disableDiscount` functions |
| `frontend/src/api/types.ts` | Add `PlanCreateReq`, `PlanUpdateReq`, `DiscountCodeCreateReq`, `DiscountCode` interfaces |
| `frontend/src/App.tsx` | Add `<Route path="subscriptions/manage" element={<TierManager />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Tier Manager" nav item under Commerce group |
| `frontend/src/components/layout/AppShell.tsx` | Add "Tier Manager" to MobileSidebar |
| `frontend/src/components/layout/MobileNav.tsx` | Add "Tier Manager" to MORE_LINKS |

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Plan create endpoint | `app/routers/subscription_server.py` | 706-743 | VERIFIED |
| Plan list endpoint (public) | `app/routers/subscription_server.py` | 746-753 | VERIFIED |
| Plan update endpoint | `app/routers/subscription_server.py` | 756-789 | VERIFIED |
| Plan archive endpoint | `app/routers/subscription_server.py` | 792-812 | VERIFIED |
| PlanCreateIn model | `app/routers/subscription_server.py` | 289-297 | VERIFIED |
| PlanUpdateIn model (all optional) | `app/routers/subscription_server.py` | 300-309 | VERIFIED |
| PlanOut model | `app/routers/subscription_server.py` | 312-326 | VERIFIED |
| Asset path limit (max 50) | `app/routers/subscription_server.py` | 309 | VERIFIED: `conlist(str, max_length=50)` |
| Asset resolution on creation | `app/routers/subscription_server.py` | 714-715 | VERIFIED |
| `require_user` on create | `app/routers/subscription_server.py` | 713 | VERIFIED |
| `require_user` on update | `app/routers/subscription_server.py` | 766 | VERIFIED |
| `require_user` on archive | `app/routers/subscription_server.py` | 801 | VERIFIED |
| Discount create endpoint | `app/routers/subscription_server.py` | 1573-1617 | VERIFIED |
| Discount code auto-uppercase | `app/routers/subscription_server.py` | 1581 | VERIFIED: `code.strip().upper()` |
| Duration validation logic | `app/routers/subscription_server.py` | 1582-1585 | VERIFIED |
| Discount SK pattern | `app/routers/subscription_server.py` | 1589 | VERIFIED: `_discount_sk(code)` |
| Discount list endpoint | `app/routers/subscription_server.py` | 1620-1637 | VERIFIED |
| Discount disable endpoint | `app/routers/subscription_server.py` | 1640-1669 | VERIFIED |
| DiscountCodeCreateIn model | `app/routers/subscription_server.py` | 466-471 | VERIFIED |
| DiscountCodeOut model | `app/routers/subscription_server.py` | 474-481 | VERIFIED |
| PlanBrowser is subscriber-facing only | `frontend/src/pages/subscriptions/PlanBrowser.tsx` | 1-186 | VERIFIED |
| PlanBrowser filters active plans | `frontend/src/pages/subscriptions/PlanBrowser.tsx` | 66 | VERIFIED |
| PlanEditor/TierManager/DiscountCodeManager | `frontend/src/pages/subscriptions/` | N/A | NOW EXIST (TierManager.tsx, PlanEditor.tsx, DiscountCodeManager.tsx) |
| `userIdHeader()` + `subPost()` helpers | `frontend/src/api/endpoints/subscriptions.ts` | 17-31 | VERIFIED |
| `listPlans` function | `frontend/src/api/endpoints/subscriptions.ts` | 37 | VERIFIED |
| Creator CRUD in subscriptions.ts | `frontend/src/api/endpoints/subscriptions.ts` | 94-112 | NOW EXISTS (createPlan, updatePlan, archivePlan, createDiscount, listDiscounts, disableDiscount) |
