# SYND-002: Bundled Subscription Plans

**Ticket**: SYND-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-12 days

---

## 1. Overview & Motivation

### 1.1 Purpose

SYND-002 adds bundled subscription plans to syndicates. A syndicate admin creates a bundle plan that gives subscribers access to every member creator's subscription-gated content through a single subscription. This integrates with the existing subscription server (`app/routers/subscription_server.py`) and the subscription access service (`app/services/subscription_access.py`) to extend entitlement checks for syndicate bundle subscribers.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Admin | As a syndicate admin, I want to create a bundled subscription plan with a price, billing cycle, and description. | POST creates plan with `plan_type=syndicate_bundle`; plan appears in syndicate detail. |
| Admin | As an admin, I want to update or archive a bundle plan. | PUT updates price/description; DELETE archives plan; existing subscribers unaffected until renewal. |
| Subscriber | As a subscriber, I want to subscribe to a syndicate bundle and gain access to all member creators' content. | POST subscribe; `has_active_subscription` returns true for every syndicate member. |
| Subscriber | As a subscriber, I want to see which creators are included in my bundle. | GET bundle details returns member list with profile info. |
| Creator | As a syndicate member, I want new bundle subscribers to automatically get access to my content. | When a user subscribes to the bundle, entitlement check for this creator passes. |
| Creator | As a creator joining a syndicate, I want existing bundle subscribers to gain access to my content. | Joining syndicate triggers entitlement expansion for all active bundle subscribers. |
| Creator | As a creator leaving a syndicate, I want bundle subscribers to lose access to my content. | Leaving syndicate triggers entitlement revocation for this creator (but not others). |
| Subscriber | As a subscriber, I want to cancel my bundle subscription. | POST cancel; access continues until period end; no renewal. |

### 1.3 Why This Is Needed

Individual subscriptions fragment the subscriber's spending across multiple creators. A $20/month bundle from a 5-creator syndicate costs less than 5 separate $8/month subscriptions ($40/month) while delivering more total content. This increases subscriber retention and average revenue per user through volume bundling. The subscription server already handles individual creator plans; extending it to syndicate bundles leverages existing billing, invoicing, and lifecycle infrastructure.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Subscription server | `app/routers/subscription_server.py` (1735 lines) | Plan CRUD, subscribe, cancel, resume, change-plan, invoices, earnings |
| Subscription access | `app/services/subscription_access.py` (80 lines) | `has_active_subscription(subscriber_id, creator_id)` checks `pk=SUBSCRIBER#{id}` |
| Subscription entitlement templates | `app/services/subscription_entitlement_templates.py` (129 lines) | Maps plans to entitlement templates; handles plan versioning |
| Subscription cycle orders | `app/services/subscription_cycle_orders.py` (354 lines) | Reconciliation gateway for webhook-driven billing cycles |
| Subscriptions DDB table | `scripts/local-ddb-init.py` line 78 | `pk`/`sk` pattern: `PLAN#{plan_id}`, `SUBSCRIBER#{id}`, `SUBSCRIPTION#{id}` |
| Billing shared | `app/services/billing_shared.py` | `new_ledger_entry`, `apply_wallet_delta` for payment processing |
| Syndicates service | `app/services/syndicates.py` (SYND-001) | `list_members`, `get_syndicate`, membership change hooks |
| Catalog subscription gating | `app/routers/subscription_server.py:816+` | `subscribe()` creates subscription + entitlement records |

### 2.2 Subscription Table Key Patterns (existing)

| PK Pattern | SK Pattern | Purpose |
|------------|------------|---------|
| `PLAN#{plan_id}` | `META` | Plan metadata (price, interval, creator_id, etc.) |
| `CREATOR#{creator_id}` | `PLAN#{plan_id}` | Creator's plans index |
| `SUBSCRIBER#{subscriber_id}` | `SUB#{subscription_id}` | Subscriber's active subscriptions |
| `SUBSCRIPTION#{subscription_id}` | `META` | Subscription record (status, dates, plan_id) |
| `SUBSCRIPTION#{subscription_id}` | `INVOICE#{invoice_id}` | Invoice records |

### 2.3 Gaps

1. **No `plan_type` field on plans** -- all plans are implicitly individual creator plans; there is no `plan_type=syndicate_bundle` discriminator.
2. **No syndicate-to-plan linkage** -- plans are tied to a single `creator_id`; a bundle plan needs to reference a `syndicate_id` instead.
3. **`has_active_subscription` is 1:1** -- it checks `SUBSCRIBER#{subscriber_id}` for a subscription to a specific `creator_id`. Syndicate bundles need to check if the subscriber has an active bundle that includes the creator.
4. **No entitlement expansion on member join** -- when a creator joins a syndicate, existing bundle subscribers don't automatically gain access.
5. **No entitlement revocation on member leave** -- when a creator leaves, existing bundle subscribers still have stale access.
6. **No bundle discovery** -- the plan listing endpoint filters by `creator_id`; there is no way to discover syndicate bundles.

---

## 3. Technical Design

### 3.1 Data Model Extensions

#### 3.1.1 Bundle Plan (Subscriptions Table)

**PK**: `PLAN#{plan_id}`, **SK**: `META`

Extended fields beyond existing plan schema:

| Field | Type | Description |
|-------|------|-------------|
| `plan_type` | S | `"individual"` (default/existing) or `"syndicate_bundle"` |
| `syndicate_id` | S | Required when `plan_type=syndicate_bundle`; references syndicate |
| `included_creator_ids` | L | Snapshot of member creator IDs at plan creation (informational; actual access is live) |

New index item for syndicate plan discovery:

**PK**: `SYNDICATE_PLANS#{syndicate_id}`, **SK**: `PLAN#{plan_id}` -- allows listing all bundle plans for a syndicate.

#### 3.1.2 Bundle Subscription Record

Uses the existing subscription schema with additional fields:

| Field | Type | Description |
|-------|------|-------------|
| `plan_type` | S | `"syndicate_bundle"` |
| `syndicate_id` | S | Which syndicate this bundle belongs to |

#### 3.1.3 Syndicate Entitlement Index (Syndicates Table)

New item pattern in the syndicates table for fast entitlement lookups:

**PK**: `BUNDLE_SUB#{subscriber_id}`, **SK**: `SYND#{syndicate_id}` -- records that this subscriber has an active bundle for this syndicate.

This enables the extended `has_active_subscription` check: for a given `(subscriber_id, creator_id)`, look up which syndicates the creator belongs to, then check if the subscriber has a bundle for any of those syndicates.

### 3.2 Backend Service

**New file**: `app/services/syndicate_subscriptions.py` (~300 lines)

```python
"""Syndicate bundled subscription management (SYND-002)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates as syndicate_svc
from app.services.subscription_access import has_active_subscription
from app.services.billing_shared import new_ledger_entry, apply_wallet_delta

logger = logging.getLogger(__name__)


def create_bundle_plan(
    *,
    syndicate_id: str,
    admin_sub: str,
    name: str,
    description: str = "",
    price_cents: int,
    interval: str = "month",   # "month" or "year"
) -> Dict[str, Any]:
    """Create a bundled subscription plan for a syndicate."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    syndicate = syndicate_svc.get_syndicate(syndicate_id)
    members = syndicate_svc.list_members(syndicate_id)

    plan_id = f"plan_{uuid4().hex}"
    ts = now_ts()

    plan = {
        "pk": f"PLAN#{plan_id}",
        "sk": "META",
        "plan_id": plan_id,
        "plan_type": "syndicate_bundle",
        "syndicate_id": syndicate_id,
        "name": name,
        "description": description,
        "price_cents": price_cents,
        "interval": interval,
        "status": "active",
        "included_creator_ids": [m["user_id"] for m in members],
        "created_at": ts,
        "updated_at": ts,
        "owner_id": syndicate_id,  # replaces creator_id for bundles
    }
    T.subscriptions.put_item(Item=plan)

    # Index for syndicate plan listing
    T.subscriptions.put_item(Item={
        "pk": f"SYNDICATE_PLANS#{syndicate_id}",
        "sk": f"PLAN#{plan_id}",
        "plan_id": plan_id,
        "name": name,
        "price_cents": price_cents,
        "status": "active",
    })
    return plan


def subscribe_to_bundle(
    *,
    subscriber_id: str,
    plan_id: str,
    payment_method_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Subscribe a user to a syndicate bundle plan."""
    plan = _get_plan(plan_id)
    if plan.get("plan_type") != "syndicate_bundle":
        raise ValueError("Plan is not a syndicate bundle")

    syndicate_id = plan["syndicate_id"]
    subscription_id = f"sub_{uuid4().hex}"
    ts = now_ts()

    # Create subscription record (reuses existing schema)
    sub = {
        "pk": f"SUBSCRIPTION#{subscription_id}",
        "sk": "META",
        "subscription_id": subscription_id,
        "subscriber_id": subscriber_id,
        "plan_id": plan_id,
        "plan_type": "syndicate_bundle",
        "syndicate_id": syndicate_id,
        "status": "active",
        "price_cents": plan["price_cents"],
        "interval": plan["interval"],
        "created_at": ts,
        "current_period_start": ts,
        "current_period_end": ts + _interval_seconds(plan["interval"]),
    }
    T.subscriptions.put_item(Item=sub)

    # Subscriber index
    T.subscriptions.put_item(Item={
        "pk": f"SUBSCRIBER#{subscriber_id}",
        "sk": f"SUB#{subscription_id}",
        "subscription_id": subscription_id,
        "plan_id": plan_id,
        "plan_type": "syndicate_bundle",
        "syndicate_id": syndicate_id,
        "status": "active",
    })

    # Bundle entitlement index (for fast access checks)
    T.syndicates.put_item(Item={
        "pk": f"BUNDLE_SUB#{subscriber_id}",
        "sk": f"SYND#{syndicate_id}",
        "syndicate_id": syndicate_id,
        "subscription_id": subscription_id,
        "status": "active",
        "created_at": ts,
    })

    return sub


def has_bundle_access(subscriber_id: str, creator_id: str) -> bool:
    """Check if subscriber has access to creator via any syndicate bundle."""
    # 1. Get creator's syndicates
    creator_syndicates = syndicate_svc.list_user_syndicates(creator_id)

    # 2. For each syndicate, check if subscriber has active bundle
    for synd in creator_syndicates:
        syndicate_id = synd["syndicate_id"]
        resp = T.syndicates.get_item(Key={
            "pk": f"BUNDLE_SUB#{subscriber_id}",
            "sk": f"SYND#{syndicate_id}",
        })
        item = resp.get("Item")
        if item and item.get("status") == "active":
            return True
    return False


def cancel_bundle_subscription(
    *,
    subscriber_id: str,
    subscription_id: str,
) -> Dict[str, Any]:
    """Cancel a bundle subscription (access continues until period end)."""
    # Update subscription status to "cancelled"
    # Keep BUNDLE_SUB index active until period_end
    # Background job cleans up expired bundle entitlements


def on_member_joined_syndicate(syndicate_id: str, creator_id: str) -> int:
    """Called when a creator joins a syndicate. Grants bundle access."""
    # No DDB changes needed -- has_bundle_access checks live membership
    # This hook is for cache invalidation or notifications
    return 0


def on_member_left_syndicate(syndicate_id: str, creator_id: str) -> int:
    """Called when a creator leaves a syndicate. Revokes bundle access."""
    # No DDB changes needed -- has_bundle_access checks live membership
    # This hook is for cache invalidation or notifications
    return 0


def list_bundle_plans(syndicate_id: str) -> List[Dict[str, Any]]:
    """List all bundle plans for a syndicate."""
    # Query SYNDICATE_PLANS#{syndicate_id} with sk begins_with "PLAN#"


def get_bundle_details(plan_id: str) -> Dict[str, Any]:
    """Get bundle plan details including current member list."""
    plan = _get_plan(plan_id)
    syndicate_id = plan["syndicate_id"]
    members = syndicate_svc.list_members(syndicate_id)
    plan["current_members"] = members
    return plan


def list_subscriber_bundles(subscriber_id: str) -> List[Dict[str, Any]]:
    """List all active bundle subscriptions for a subscriber."""
    # Query SUBSCRIBER#{subscriber_id} with sk begins_with "SUB#"
    # Filter plan_type = "syndicate_bundle"


# --- Internal helpers ---

def _get_plan(plan_id: str) -> Dict[str, Any]:
    """Get plan or raise 404."""

def _interval_seconds(interval: str) -> int:
    return {"month": 30 * 86400, "year": 365 * 86400}.get(interval, 30 * 86400)
```

### 3.3 Extending Subscription Access

**Modify**: `app/services/subscription_access.py`

The `can_access_creator` function currently only checks individual subscriptions. Extend it to also check syndicate bundle access:

```python
def can_access_creator(subscriber_id: str, creator_id: str) -> bool:
    """Check if subscriber can access creator's gated content."""
    if not creator_requires_subscription(creator_id):
        return True
    if has_active_subscription(subscriber_id, creator_id):
        return True
    # NEW: Check syndicate bundle access
    from app.services.syndicate_subscriptions import has_bundle_access
    if has_bundle_access(subscriber_id, creator_id):
        return True
    return False
```

### 3.4 Backend Router

**Extend**: `app/routers/syndicates.py` (from SYND-001)

Add bundle plan endpoints to the existing syndicates router:

### 3.5 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/syndicates/{syndicate_id}/plans` | `require_ui_session` | Create bundle plan (admin only) |
| `GET` | `/ui/syndicates/{syndicate_id}/plans` | `require_ui_session` | List bundle plans for syndicate |
| `GET` | `/ui/syndicates/{syndicate_id}/plans/{plan_id}` | `require_ui_session` | Get bundle plan details with current members |
| `PUT` | `/ui/syndicates/{syndicate_id}/plans/{plan_id}` | `require_ui_session` | Update bundle plan (admin only) |
| `DELETE` | `/ui/syndicates/{syndicate_id}/plans/{plan_id}` | `require_ui_session` | Archive bundle plan (admin only) |
| `POST` | `/ui/syndicates/{syndicate_id}/plans/{plan_id}/subscribe` | `require_ui_session` | Subscribe to bundle |
| `POST` | `/ui/syndicates/{syndicate_id}/subscriptions/{sub_id}/cancel` | `require_ui_session` | Cancel bundle subscription |
| `GET` | `/ui/syndicates/my-bundles` | `require_ui_session` | List user's active bundle subscriptions |

### 3.6 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Syndicate Bundle Subscriptions (SYND-002) --

class BundlePlanCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=1000)
    price_cents: int = Field(ge=100, le=100000)  # $1 - $1000
    interval: str = Field(default="month", pattern="^(month|year)$")

class BundlePlanUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)
    description: Optional[str] = Field(default=None, max_length=1000)
    price_cents: Optional[int] = Field(default=None, ge=100, le=100000)

class BundlePlanOut(BaseModel):
    plan_id: str
    plan_type: str = "syndicate_bundle"
    syndicate_id: str
    name: str
    description: str = ""
    price_cents: int = 0
    interval: str = "month"
    status: str = "active"
    included_creator_ids: List[str] = Field(default_factory=list)
    current_members: List[SyndicateMemberOut] = Field(default_factory=list)
    created_at: int = 0

class BundleSubscribeIn(BaseModel):
    payment_method_id: Optional[str] = None

class BundleSubscriptionOut(BaseModel):
    subscription_id: str
    plan_id: str
    plan_type: str = "syndicate_bundle"
    syndicate_id: str
    syndicate_name: str = ""
    status: str
    price_cents: int = 0
    interval: str = "month"
    current_period_start: int = 0
    current_period_end: int = 0
    created_at: int = 0
    included_creators: List[SyndicateMemberOut] = Field(default_factory=list)
```

### 3.7 Frontend Components

**New/modified files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/syndicates/BundlePlansTab.tsx` | Tab on SyndicateDetailPage for plan management | ~180 |
| `frontend/src/pages/syndicates/CreateBundlePlanDialog.tsx` | Dialog for creating a bundle plan | ~100 |
| `frontend/src/pages/syndicates/BundleSubscribeDialog.tsx` | Subscribe to bundle dialog with PM selection | ~120 |
| `frontend/src/pages/syndicates/MyBundlesPage.tsx` | User's active bundle subscriptions | ~150 |

**Component tree for BundlePlansTab**:

```
BundlePlansTab (within SyndicateDetailPage)
├── Card: "Bundle Plans"
│   ├── CreateBundlePlanDialog (admin only, Button: "Create Plan")
│   └── PlanList
│       └── For each plan:
│           ├── Plan name, price, interval
│           ├── Status badge (active/archived)
│           ├── Member count included
│           ├── Button: "Edit" (admin)
│           ├── Button: "Archive" (admin)
│           └── Button: "Subscribe" (non-member visitors)
├── BundleSubscribeDialog
│   ├── Plan details summary
│   ├── Included creators list with avatars
│   ├── Payment method selector
│   └── "Subscribe" confirmation button
└── EmptyState: "No bundle plans yet" (admin sees "Create your first plan")
```

### 3.8 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/syndicate_subscriptions.py` | Bundle subscription service | ~300 |
| `frontend/src/pages/syndicates/BundlePlansTab.tsx` | Plan management tab | ~180 |
| `frontend/src/pages/syndicates/CreateBundlePlanDialog.tsx` | Plan creation dialog | ~100 |
| `frontend/src/pages/syndicates/BundleSubscribeDialog.tsx` | Subscribe dialog | ~120 |
| `frontend/src/pages/syndicates/MyBundlesPage.tsx` | My bundles page | ~150 |
| `frontend/e2e/syndicates-bundles.spec.ts` | E2E tests | ~400 |

### 3.9 Files to Modify

| File | Change |
|------|--------|
| `app/services/subscription_access.py` | Extend `can_access_creator` to check bundle access |
| `app/routers/syndicates.py` | Add bundle plan + subscription endpoints |
| `app/models.py` | Add BundlePlan* and BundleSubscription* models |
| `app/services/syndicates.py` | Add hooks `on_member_joined`, `on_member_left` |
| `frontend/src/api/types.ts` | Add BundlePlan, BundleSubscription interfaces |
| `frontend/src/api/endpoints/syndicates.ts` | Add bundle plan/subscription API wrappers |
| `frontend/src/pages/syndicates/SyndicateDetailPage.tsx` | Add BundlePlansTab |
| `frontend/src/App.tsx` | Add `/syndicates/my-bundles` route |

---

## 4. Access Check Flow

### 4.1 How `can_access_creator` Works After This Ticket

```
can_access_creator(subscriber_id="user123", creator_id="bob@test.local")
│
├── 1. Check: Does bob require subscription? (subscription_access.py)
│   └── No → return True (free content)
│
├── 2. Check: Does user123 have direct subscription to bob?
│   └── Query SUBSCRIBER#user123, filter by bob's creator_id
│   └── Found active? → return True
│
├── 3. NEW: Check: Does user123 have bundle access to bob?
│   └── 3a. Get bob's syndicates: USER_SYND#bob → [synd_abc, synd_xyz]
│   └── 3b. For each syndicate:
│       └── Check BUNDLE_SUB#user123 + SYND#synd_abc → active? → return True
│   └── No match → return False
│
└── return False (no access)
```

### 4.2 Performance

- Step 3a: 1 DDB query (USER_SYND#{creator_id}).
- Step 3b: 1 DDB `get_item` per syndicate (typically 1-3 syndicates per creator).
- Total: 2-4 DDB reads for bundle check, only reached when no direct subscription exists.
- Acceptable latency: ~15-30ms additional per access check.

### 4.3 Live Membership Updates

When a creator joins or leaves a syndicate, bundle access updates automatically because `has_bundle_access` checks live membership (USER_SYND index). No batch entitlement update is needed. This is the key design choice: trade slightly higher read cost for zero write cost on membership changes.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/syndicates-bundles.spec.ts`

### Section 427: Bundle Plan CRUD API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 427.1 | Admin creates a bundle plan | POST; 200; response has `plan_id`, `plan_type=syndicate_bundle`, `price_cents`, `interval` |
| 427.2 | Plan appears in syndicate plan list | GET plans; response includes created plan |
| 427.3 | Admin updates plan price | PUT; 200; updated `price_cents` reflected in GET |
| 427.4 | Admin archives plan | DELETE; 200; plan `status=archived` in GET |

### Section 428: Bundle Subscription API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 428.1 | User subscribes to bundle plan | POST subscribe; 200; subscription `status=active` |
| 428.2 | Subscription appears in user's bundle list | GET my-bundles; includes new bundle subscription |
| 428.3 | Subscriber can access syndicate member's gated content | Check `can_access_creator` returns true for each syndicate member |
| 428.4 | Non-subscriber cannot access gated content | Check access returns false for user without bundle subscription |
| 428.5 | User cancels bundle subscription | POST cancel; 200; status changes; access ends at period end |

### Section 429: Dynamic Membership Access (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 429.1 | New member joining grants bundle subscribers access | Add creator to syndicate; existing subscriber can access new member's content |
| 429.2 | Member leaving revokes bundle subscriber access | Remove creator from syndicate; subscriber loses access to that creator |
| 429.3 | Bundle access survives creator profile update | Member updates profile; bundle access still works |
| 429.4 | Multiple bundle subscriptions grant cumulative access | Subscribe to two syndicates; access both sets of creators |

### Section 430: Bundle Plan UI (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 430.1 | Bundle plans tab visible on syndicate page | Navigate to syndicate detail; "Plans" tab visible |
| 430.2 | Create plan dialog works for admin | Click "Create Plan"; fill form; submit; plan appears in list |
| 430.3 | Subscribe dialog shows included creators | Click "Subscribe"; dialog lists all current syndicate members |
| 430.4 | My Bundles page shows active subscriptions | Navigate to `/syndicates/my-bundles`; active bundles listed |

**Total E2E tests: 17**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Plan CRUD | `require_ui_session` | Syndicate admin only (service layer check) |
| Subscribe/cancel | `require_ui_session` | Any authenticated user |
| List plans | `require_ui_session` | Any authenticated user |
| My bundles | `require_ui_session` | Returns only caller's subscriptions |

### 6.2 Payment Security

- Bundle subscription uses the same payment flow as individual subscriptions (existing `record_billing_payment` and `new_ledger_entry`).
- Payment method validation occurs before subscription creation.
- `price_cents` range: $1 - $1000 (enforced by Pydantic `ge=100, le=100000`).
- Archived plans cannot accept new subscriptions (checked in `subscribe_to_bundle`).

### 6.3 Access Control

- `has_bundle_access` only returns true for `status=active` bundle entitlements.
- Cancelled subscriptions remain active until `current_period_end` (no early revocation).
- Subscriber cannot access content of creators who have left the syndicate (live membership check).

### 6.4 IDOR Prevention

- Subscription cancellation validates that `subscriber_id` matches the session user's `user_sub`.
- Plan modification validates that the caller is the syndicate admin.
- Bundle details reveal member list (public information per SYND-001 design).

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| SYND-001 | Required | Syndicate metadata, member list, admin checks |
| `app/routers/subscription_server.py` | Exists | Plan/subscription record patterns |
| `app/services/subscription_access.py` | Exists (modify) | Extend `can_access_creator` for bundles |
| `app/services/billing_shared.py` | Exists | Ledger entries for bundle payments |
| SYND-003 | Not started | Revenue splitting for bundle payments (processes after this ticket) |

---

## 8. Acceptance Criteria

1. Syndicate admin can create, update, and archive bundled subscription plans.
2. Users can subscribe to a bundle plan and gain access to all member creators' subscription-gated content.
3. `can_access_creator` correctly returns `true` for bundle subscribers checking any syndicate member.
4. When a creator joins a syndicate, existing bundle subscribers automatically gain access to the new member's content.
5. When a creator leaves a syndicate, bundle subscribers lose access to that creator's content.
6. Subscribers can cancel bundles; access continues until period end.
7. My Bundles page lists all active bundle subscriptions with included creators.
8. All 17 E2E tests pass.
