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

### 3.1 Architecture Diagram

```
  +-----------+                 +------------------+                 +----------------+
  | Syndicate |                 |   Subscription   |                 |    Billing     |
  |   Admin   |                 |     Server       |                 |    Shared      |
  +-----------+                 +------------------+                 +----------------+
       |                               |                                    |
       | POST /syndicates/{id}/plans   |                                    |
       +------------------------------>|                                    |
       |                               |                                    |
       |  create_bundle_plan()         |                                    |
       |  +-----------------------+    |                                    |
       |  | 1. _require_admin()   |    |                                    |
       |  | 2. get_syndicate()    |    |                                    |
       |  | 3. list_members()     |    |                                    |
       |  | 4. put_item PLAN#     |    |                                    |
       |  | 5. put_item SYND_PLANS|    |                                    |
       |  +-----------------------+    |                                    |
       |                               |                                    |
  +-----------+                        |                                    |
  | Subscriber|                        |                                    |
  +-----------+                        |                                    |
       |                               |                                    |
       | POST /plans/{id}/subscribe    |                                    |
       +------------------------------>|                                    |
       |                               |                                    |
       |  subscribe_to_bundle()        |                                    |
       |  +--------------------------+ |                                    |
       |  | 1. _get_plan()           | |                                    |
       |  | 2. validate PM           | |-------- validate_pm() ----------->|
       |  | 3. put SUBSCRIPTION#     | |                                    |
       |  | 4. put SUBSCRIBER#       | |                                    |
       |  | 5. put BUNDLE_SUB#       | |                                    |
       |  | 6. new_ledger_entry()    | |-------- ledger write ------------>|
       |  +--------------------------+ |                                    |
       |                               |                                    |
  +-----------+                        |                                    |
  |  Content  |   can_access_creator() |                                    |
  |  Gateway  | ---------------------> |                                    |
  +-----------+                        |                                    |
       |    1. has_active_subscription(subscriber, creator) --- direct? --> DDB
       |    2. has_bundle_access(subscriber, creator)                       |
       |       a. list_user_syndicates(creator) --------------------------> DDB
       |       b. get_item(BUNDLE_SUB#{sub}, SYND#{id}) -----------------> DDB
       |    3. return True/False                                            |
       |                               |                                    |
  +-----------+   on_member_joined()   |                                    |
  | Syndicate |   on_member_left()     |                                    |
  | Membership|<-----------------------|                                    |
  |  Hook     |   (cache invalidation, |                                    |
  +-----------+    notifications)      |                                    |
```

### 3.2 Data Model Extensions

#### 3.2.1 Bundle Plan (Subscriptions Table)

**PK**: `PLAN#{plan_id}`, **SK**: `META`

Extended fields beyond existing plan schema:

| Field | Type | Description |
|-------|------|-------------|
| `plan_type` | S | `"individual"` (default/existing) or `"syndicate_bundle"` |
| `syndicate_id` | S | Required when `plan_type=syndicate_bundle`; references syndicate |
| `included_creator_ids` | L | Snapshot of member creator IDs at plan creation (informational; actual access is live) |

New index item for syndicate plan discovery:

**PK**: `SYNDICATE_PLANS#{syndicate_id}`, **SK**: `PLAN#{plan_id}` -- allows listing all bundle plans for a syndicate.

#### 3.2.2 Bundle Subscription Record

Uses the existing subscription schema with additional fields:

| Field | Type | Description |
|-------|------|-------------|
| `plan_type` | S | `"syndicate_bundle"` |
| `syndicate_id` | S | Which syndicate this bundle belongs to |

#### 3.2.3 Syndicate Entitlement Index (Syndicates Table)

New item pattern in the syndicates table for fast entitlement lookups:

**PK**: `BUNDLE_SUB#{subscriber_id}`, **SK**: `SYND#{syndicate_id}` -- records that this subscriber has an active bundle for this syndicate.

This enables the extended `has_active_subscription` check: for a given `(subscriber_id, creator_id)`, look up which syndicates the creator belongs to, then check if the subscriber has a bundle for any of those syndicates.

### 3.3 DynamoDB Access Patterns

| Access Pattern | Table | PK | SK | Index | Operation | Frequency |
|---------------|-------|-----|-----|-------|-----------|-----------|
| Get bundle plan metadata | subscriptions | `PLAN#{plan_id}` | `META` | Table | `get_item` | Per plan view |
| List syndicate's plans | subscriptions | `SYNDICATE_PLANS#{syndicate_id}` | begins_with `PLAN#` | Table | `query` | Per syndicate page load |
| Create bundle subscription | subscriptions | `SUBSCRIPTION#{sub_id}` | `META` | Table | `put_item` | Per subscribe action |
| List subscriber's bundles | subscriptions | `SUBSCRIBER#{subscriber_id}` | begins_with `SUB#` | Table | `query` + filter `plan_type` | Per my-bundles page |
| Check bundle entitlement | syndicates | `BUNDLE_SUB#{subscriber_id}` | `SYND#{syndicate_id}` | Table | `get_item` | Per content access check |
| List user's syndicates | syndicates | `USER_SYND#{user_id}` | begins_with `SYND#` | Table | `query` | Per bundle access check |
| Invoice for bundle | subscriptions | `SUBSCRIPTION#{sub_id}` | `INVOICE#{inv_id}` | Table | `put_item` | Per billing cycle |

#### Example DynamoDB Items

**Bundle Plan record** (`subscriptions` table):
```json
{
  "pk": "PLAN#plan_8a3f2b1c9d4e5f6a",
  "sk": "META",
  "plan_id": "plan_8a3f2b1c9d4e5f6a",
  "plan_type": "syndicate_bundle",
  "syndicate_id": "synd_abc123",
  "name": "All-Access Bundle",
  "description": "Access content from all 5 syndicate creators",
  "price_cents": 2000,
  "interval": "month",
  "status": "active",
  "included_creator_ids": ["creator_a", "creator_b", "creator_c", "creator_d", "creator_e"],
  "owner_id": "synd_abc123",
  "created_at": 1748500000,
  "updated_at": 1748500000
}
```

**Bundle Subscription record** (`subscriptions` table):
```json
{
  "pk": "SUBSCRIPTION#sub_7b2e4f1a8c3d9e0f",
  "sk": "META",
  "subscription_id": "sub_7b2e4f1a8c3d9e0f",
  "subscriber_id": "user_alice",
  "plan_id": "plan_8a3f2b1c9d4e5f6a",
  "plan_type": "syndicate_bundle",
  "syndicate_id": "synd_abc123",
  "status": "active",
  "price_cents": 2000,
  "interval": "month",
  "created_at": 1748501000,
  "current_period_start": 1748501000,
  "current_period_end": 1751093000
}
```

**Bundle Entitlement Index** (`syndicates` table):
```json
{
  "pk": "BUNDLE_SUB#user_alice",
  "sk": "SYND#synd_abc123",
  "syndicate_id": "synd_abc123",
  "subscription_id": "sub_7b2e4f1a8c3d9e0f",
  "status": "active",
  "created_at": 1748501000
}
```

**Syndicate Plan Index** (`subscriptions` table):
```json
{
  "pk": "SYNDICATE_PLANS#synd_abc123",
  "sk": "PLAN#plan_8a3f2b1c9d4e5f6a",
  "plan_id": "plan_8a3f2b1c9d4e5f6a",
  "name": "All-Access Bundle",
  "price_cents": 2000,
  "status": "active"
}
```

### 3.4 Backend Service

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

### 3.5 Extending Subscription Access

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

### 3.6 Backend Router

**Extend**: `app/routers/syndicates.py` (from SYND-001)

Add bundle plan endpoints to the existing syndicates router:

### 3.7 Router Endpoints

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

### 3.8 API Request/Response Examples

**Create bundle plan** (admin):
```bash
curl -X POST http://localhost:8000/ui/syndicates/synd_abc123/plans \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "All-Access Bundle",
    "description": "Access content from all 5 syndicate creators",
    "price_cents": 2000,
    "interval": "month"
  }'

# 200 OK
{
  "plan_id": "plan_8a3f2b1c9d4e5f6a",
  "plan_type": "syndicate_bundle",
  "syndicate_id": "synd_abc123",
  "name": "All-Access Bundle",
  "description": "Access content from all 5 syndicate creators",
  "price_cents": 2000,
  "interval": "month",
  "status": "active",
  "included_creator_ids": ["creator_a", "creator_b", "creator_c"],
  "current_members": [],
  "created_at": 1748500000
}
```

**List syndicate's bundle plans**:
```bash
curl http://localhost:8000/ui/syndicates/synd_abc123/plans \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx"

# 200 OK
[
  {
    "plan_id": "plan_8a3f2b1c9d4e5f6a",
    "plan_type": "syndicate_bundle",
    "syndicate_id": "synd_abc123",
    "name": "All-Access Bundle",
    "price_cents": 2000,
    "interval": "month",
    "status": "active",
    "created_at": 1748500000
  }
]
```

**Get bundle plan details** (with current member list):
```bash
curl http://localhost:8000/ui/syndicates/synd_abc123/plans/plan_8a3f2b1c9d4e5f6a \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx"

# 200 OK
{
  "plan_id": "plan_8a3f2b1c9d4e5f6a",
  "plan_type": "syndicate_bundle",
  "syndicate_id": "synd_abc123",
  "name": "All-Access Bundle",
  "description": "Access content from all 5 syndicate creators",
  "price_cents": 2000,
  "interval": "month",
  "status": "active",
  "included_creator_ids": ["creator_a", "creator_b", "creator_c"],
  "current_members": [
    {"user_id": "creator_a", "display_name": "Alice", "role": "admin"},
    {"user_id": "creator_b", "display_name": "Bob", "role": "member"},
    {"user_id": "creator_c", "display_name": "Charlie", "role": "member"}
  ],
  "created_at": 1748500000
}
```

**Subscribe to bundle**:
```bash
curl -X POST http://localhost:8000/ui/syndicates/synd_abc123/plans/plan_8a3f2b1c9d4e5f6a/subscribe \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -H "Content-Type: application/json" \
  -d '{"payment_method_id": "pm_visa_4242"}'

# 200 OK
{
  "subscription_id": "sub_7b2e4f1a8c3d9e0f",
  "plan_id": "plan_8a3f2b1c9d4e5f6a",
  "plan_type": "syndicate_bundle",
  "syndicate_id": "synd_abc123",
  "syndicate_name": "Creative Collective",
  "status": "active",
  "price_cents": 2000,
  "interval": "month",
  "current_period_start": 1748501000,
  "current_period_end": 1751093000,
  "created_at": 1748501000,
  "included_creators": [
    {"user_id": "creator_a", "display_name": "Alice", "role": "admin"}
  ]
}
```

**Cancel bundle subscription**:
```bash
curl -X POST http://localhost:8000/ui/syndicates/synd_abc123/subscriptions/sub_7b2e4f1a8c3d9e0f/cancel \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx"

# 200 OK
{
  "subscription_id": "sub_7b2e4f1a8c3d9e0f",
  "status": "cancelled",
  "current_period_end": 1751093000,
  "cancelled_at": 1748600000
}
```

**List my bundle subscriptions**:
```bash
curl http://localhost:8000/ui/syndicates/my-bundles \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx"

# 200 OK
[
  {
    "subscription_id": "sub_7b2e4f1a8c3d9e0f",
    "plan_id": "plan_8a3f2b1c9d4e5f6a",
    "plan_type": "syndicate_bundle",
    "syndicate_id": "synd_abc123",
    "syndicate_name": "Creative Collective",
    "status": "active",
    "price_cents": 2000,
    "interval": "month",
    "current_period_start": 1748501000,
    "current_period_end": 1751093000,
    "created_at": 1748501000,
    "included_creators": []
  }
]
```

**Update bundle plan** (admin):
```bash
curl -X PUT http://localhost:8000/ui/syndicates/synd_abc123/plans/plan_8a3f2b1c9d4e5f6a \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -H "Content-Type: application/json" \
  -d '{"price_cents": 2500, "description": "Updated premium bundle"}'

# 200 OK
{
  "plan_id": "plan_8a3f2b1c9d4e5f6a",
  "plan_type": "syndicate_bundle",
  "name": "All-Access Bundle",
  "description": "Updated premium bundle",
  "price_cents": 2500,
  "interval": "month",
  "status": "active",
  "updated_at": 1748510000
}
```

**Archive bundle plan** (admin):
```bash
curl -X DELETE http://localhost:8000/ui/syndicates/synd_abc123/plans/plan_8a3f2b1c9d4e5f6a \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx"

# 200 OK
{"ok": true, "plan_id": "plan_8a3f2b1c9d4e5f6a", "status": "archived"}
```

### 3.9 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---------------|-------------|------------|---------------------|-----------------|
| Non-admin tries to create plan | 403 | `SYNDICATE_NOT_ADMIN` | "Only syndicate admins can manage plans" | Contact syndicate admin |
| Syndicate not found | 404 | `SYNDICATE_NOT_FOUND` | "Syndicate not found" | Verify syndicate ID |
| Plan not found | 404 | `PLAN_NOT_FOUND` | "Bundle plan not found" | Verify plan ID |
| Plan not a bundle | 400 | `NOT_BUNDLE_PLAN` | "Plan is not a syndicate bundle" | Use correct plan type |
| Archived plan subscribe attempt | 400 | `PLAN_ARCHIVED` | "This plan is no longer available" | Choose an active plan |
| Subscriber already has bundle for this syndicate | 409 | `ALREADY_SUBSCRIBED` | "You already have an active subscription to this bundle" | Manage existing subscription |
| Invalid payment method | 400 | `INVALID_PAYMENT_METHOD` | "Payment method not found or expired" | Add valid payment method |
| Payment processing failed | 402 | `PAYMENT_FAILED` | "Payment could not be processed" | Try different payment method |
| Price range violation (< $1 or > $1000) | 422 | `VALIDATION_ERROR` | "Price must be between $1.00 and $1,000.00" | Adjust price |
| Interval invalid (not month/year) | 422 | `VALIDATION_ERROR` | "Interval must be 'month' or 'year'" | Use valid interval |
| Cancel non-owned subscription | 403 | `NOT_SUBSCRIPTION_OWNER` | "You can only cancel your own subscriptions" | None |
| Cancel already-cancelled subscription | 409 | `ALREADY_CANCELLED` | "Subscription is already cancelled" | No action needed |
| Subscription not found for cancel | 404 | `SUBSCRIPTION_NOT_FOUND` | "Subscription not found" | Verify subscription ID |
| Name too short/long | 422 | `VALIDATION_ERROR` | "Name must be 2-100 characters" | Adjust name length |
| Description too long | 422 | `VALIDATION_ERROR` | "Description must be under 1000 characters" | Shorten description |

### 3.10 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Syndicate Bundle Subscriptions (SYND-002) --

class BundlePlanCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=1000)
    price_cents: int = Field(ge=100, le=100000)  # $1 - $1000
    interval: str = Field(default="month", pattern="^(month|year)$")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "All-Access Bundle",
                "description": "Get full access to all syndicate creators' content",
                "price_cents": 2000,
                "interval": "month",
            }
        }

class BundlePlanUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)
    description: Optional[str] = Field(default=None, max_length=1000)
    price_cents: Optional[int] = Field(default=None, ge=100, le=100000)

    @model_validator(mode="before")
    @classmethod
    def at_least_one_field(cls, values):
        if isinstance(values, dict):
            non_none = {k: v for k, v in values.items() if v is not None}
            if not non_none:
                raise ValueError("At least one field must be provided")
        return values

    class Config:
        json_schema_extra = {
            "example": {
                "price_cents": 2500,
                "description": "Updated premium bundle access",
            }
        }

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

    class Config:
        json_schema_extra = {
            "example": {
                "plan_id": "plan_8a3f2b1c9d4e5f6a",
                "plan_type": "syndicate_bundle",
                "syndicate_id": "synd_abc123",
                "name": "All-Access Bundle",
                "description": "Get full access to all syndicate creators' content",
                "price_cents": 2000,
                "interval": "month",
                "status": "active",
                "included_creator_ids": ["creator_a", "creator_b"],
                "current_members": [],
                "created_at": 1748500000,
            }
        }

class BundleSubscribeIn(BaseModel):
    payment_method_id: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {"payment_method_id": "pm_visa_4242"}
        }

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
    cancelled_at: Optional[int] = None
    included_creators: List[SyndicateMemberOut] = Field(default_factory=list)

    class Config:
        json_schema_extra = {
            "example": {
                "subscription_id": "sub_7b2e4f1a8c3d9e0f",
                "plan_id": "plan_8a3f2b1c9d4e5f6a",
                "plan_type": "syndicate_bundle",
                "syndicate_id": "synd_abc123",
                "syndicate_name": "Creative Collective",
                "status": "active",
                "price_cents": 2000,
                "interval": "month",
                "current_period_start": 1748501000,
                "current_period_end": 1751093000,
                "created_at": 1748501000,
                "cancelled_at": None,
                "included_creators": [],
            }
        }
```

### 3.11 Frontend Components

**New/modified files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/syndicates/BundlePlansTab.tsx` | Tab on SyndicateDetailPage for plan management | ~180 |
| `frontend/src/pages/syndicates/CreateBundlePlanDialog.tsx` | Dialog for creating a bundle plan | ~100 |
| `frontend/src/pages/syndicates/BundleSubscribeDialog.tsx` | Subscribe to bundle dialog with PM selection | ~120 |
| `frontend/src/pages/syndicates/MyBundlesPage.tsx` | User's active bundle subscriptions | ~150 |

### 3.12 Frontend Component Tree

```
SyndicateDetailPage
├── Tabs
│   ├── "Members" Tab (existing from SYND-001)
│   └── "Plans" Tab (new — BundlePlansTab)
│       └── BundlePlansTab
│           ├── PageHeader
│           │   ├── title: "Bundle Plans"
│           │   └── actions: [CreateBundlePlanDialog trigger] (admin only)
│           ├── PlanList (if plans.length > 0)
│           │   └── For each plan: PlanCard
│           │       ├── Card
│           │       │   ├── CardHeader
│           │       │   │   ├── plan.name (h3)
│           │       │   │   └── Badge: plan.status ("active" | "archived")
│           │       │   ├── CardContent
│           │       │   │   ├── price display: "$20.00/month"
│           │       │   │   ├── description text
│           │       │   │   └── member count: "5 creators included"
│           │       │   └── CardFooter
│           │       │       ├── Button "Edit" (admin, opens EditPlanDialog)
│           │       │       ├── Button "Archive" (admin, confirms then DELETEs)
│           │       │       └── Button "Subscribe" (non-admin, opens BundleSubscribeDialog)
│           │       └── [end Card]
│           └── EmptyState (if plans.length === 0)
│               ├── text: "No bundle plans yet"
│               └── text (admin): "Create your first plan to attract subscribers"
│
├── CreateBundlePlanDialog
│   ├── Dialog
│   │   ├── DialogHeader: "Create Bundle Plan"
│   │   ├── DialogContent
│   │   │   ├── form (React Hook Form + Zod)
│   │   │   │   ├── Input: name (required, 2-100 chars)
│   │   │   │   ├── Textarea: description (optional, max 1000)
│   │   │   │   ├── Input: price (number, $1-$1000)
│   │   │   │   └── Select: interval ("Monthly" | "Yearly")
│   │   │   └── current member preview list (read-only)
│   │   └── DialogFooter
│   │       └── Button "Create Plan" (disabled while submitting)
│   └── [end Dialog]
│
└── BundleSubscribeDialog
    ├── Dialog
    │   ├── DialogHeader: "Subscribe to Bundle"
    │   ├── DialogContent
    │   │   ├── Plan summary card (name, price, interval)
    │   │   ├── Included creators list (avatars + names)
    │   │   └── PaymentMethodSelector (reused from billing)
    │   └── DialogFooter
    │       └── Button "Subscribe" (disabled without PM selection)
    └── [end Dialog]

MyBundlesPage
├── PageHeader
│   ├── title: "My Bundles"
│   └── description: "Manage your syndicate bundle subscriptions"
├── BundleList (if bundles.length > 0)
│   └── For each bundle: BundleCard
│       ├── Card
│       │   ├── CardHeader
│       │   │   ├── syndicate_name (h3)
│       │   │   └── Badge: status ("active" | "cancelled")
│       │   ├── CardContent
│       │   │   ├── price display: "$20.00/month"
│       │   │   ├── period display: "Current period: May 1 - May 31"
│       │   │   └── included_creators list (avatar + name links)
│       │   └── CardFooter
│       │       └── Button "Cancel" (if active, opens ConfirmDialog)
│       └── [end Card]
└── EmptyState (if bundles.length === 0)
    ├── text: "No active bundles"
    └── Link: "Browse syndicates to find bundles"
```

**State management (React Query keys)**:

| Query Key | Endpoint | Invalidated By |
|-----------|----------|----------------|
| `["syndicate-plans", syndicateId]` | `GET /ui/syndicates/{id}/plans` | Create, update, archive plan |
| `["syndicate-plan", syndicateId, planId]` | `GET /ui/syndicates/{id}/plans/{planId}` | Update plan, member change |
| `["my-bundles"]` | `GET /ui/syndicates/my-bundles` | Subscribe, cancel |
| `["billing", "payment-methods"]` | `GET /ui/billing/payment-methods` | (existing, reused by subscribe dialog) |

### 3.13 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/syndicate_subscriptions.py` | Bundle subscription service | ~300 |
| `frontend/src/pages/syndicates/BundlePlansTab.tsx` | Plan management tab | ~180 |
| `frontend/src/pages/syndicates/CreateBundlePlanDialog.tsx` | Plan creation dialog | ~100 |
| `frontend/src/pages/syndicates/BundleSubscribeDialog.tsx` | Subscribe dialog | ~120 |
| `frontend/src/pages/syndicates/MyBundlesPage.tsx` | My bundles page | ~150 |
| `frontend/e2e/syndicates-bundles.spec.ts` | E2E tests | ~400 |

### 3.14 Files to Modify

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
|
+-- 1. Check: Does bob require subscription? (subscription_access.py)
|   +-- No --> return True (free content)
|
+-- 2. Check: Does user123 have direct subscription to bob?
|   +-- Query SUBSCRIBER#user123, filter by bob's creator_id
|   +-- Found active? --> return True
|
+-- 3. NEW: Check: Does user123 have bundle access to bob?
|   +-- 3a. Get bob's syndicates: USER_SYND#bob --> [synd_abc, synd_xyz]
|   +-- 3b. For each syndicate:
|       +-- Check BUNDLE_SUB#user123 + SYND#synd_abc --> active? --> return True
|   +-- No match --> return False
|
+-- return False (no access)
```

### 4.2 Performance

- Step 3a: 1 DDB query (USER_SYND#{creator_id}).
- Step 3b: 1 DDB `get_item` per syndicate (typically 1-3 syndicates per creator).
- Total: 2-4 DDB reads for bundle check, only reached when no direct subscription exists.
- Acceptable latency: ~15-30ms additional per access check.

### 4.3 Live Membership Updates

When a creator joins or leaves a syndicate, bundle access updates automatically because `has_bundle_access` checks live membership (USER_SYND index). No batch entitlement update is needed. This is the key design choice: trade slightly higher read cost for zero write cost on membership changes.

---

## 5. Observability & Monitoring

### 5.1 Metrics to Track

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `bundle_plan_created_total` | Counter | `syndicate_id` | Bundle plans created |
| `bundle_subscription_created_total` | Counter | `syndicate_id`, `interval` | New bundle subscriptions |
| `bundle_subscription_cancelled_total` | Counter | `syndicate_id`, `reason` | Bundle cancellations |
| `bundle_access_check_total` | Counter | `result` (hit/miss) | Bundle entitlement checks |
| `bundle_access_check_duration_ms` | Histogram | | Time for `has_bundle_access()` call |
| `bundle_plan_revenue_cents` | Counter | `syndicate_id`, `plan_id` | Revenue from bundle subscriptions |
| `bundle_active_subscribers` | Gauge | `syndicate_id` | Current active subscribers per syndicate |
| `bundle_renewal_success_total` | Counter | `syndicate_id` | Successful auto-renewals |
| `bundle_renewal_failed_total` | Counter | `syndicate_id`, `reason` | Failed auto-renewals |

### 5.2 Log Events

| Event | Level | Fields | When |
|-------|-------|--------|------|
| `bundle_plan.created` | INFO | `syndicate_id`, `plan_id`, `price_cents`, `admin_sub` | Admin creates plan |
| `bundle_plan.updated` | INFO | `syndicate_id`, `plan_id`, `changed_fields` | Admin updates plan |
| `bundle_plan.archived` | INFO | `syndicate_id`, `plan_id`, `active_subscribers` | Admin archives plan |
| `bundle.subscribed` | INFO | `subscriber_id`, `syndicate_id`, `plan_id`, `price_cents` | User subscribes |
| `bundle.cancelled` | INFO | `subscriber_id`, `syndicate_id`, `subscription_id` | User cancels |
| `bundle.renewed` | INFO | `subscriber_id`, `syndicate_id`, `subscription_id`, `amount_cents` | Auto-renewal succeeds |
| `bundle.renewal_failed` | WARN | `subscriber_id`, `syndicate_id`, `subscription_id`, `error` | Auto-renewal fails |
| `bundle_access.checked` | DEBUG | `subscriber_id`, `creator_id`, `result`, `syndicates_checked` | Access check executed |
| `bundle_access.granted_via_syndicate` | INFO | `subscriber_id`, `creator_id`, `syndicate_id` | Bundle access granted |
| `bundle.period_expired` | INFO | `subscriber_id`, `syndicate_id`, `subscription_id` | Period end reached |

### 5.3 Alert Thresholds

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High cancellation rate | > 10% cancellations in 24h for a syndicate | Warning | Notify syndicate admin |
| Renewal failure spike | > 5 renewal failures in 1h | Warning | Check payment provider status |
| Bundle access check latency | p99 > 200ms | Warning | Investigate DDB read capacity |
| Zero new subscriptions | No new subscriptions for 7 days (active syndicate) | Info | Review pricing and visibility |
| Plan creation anomaly | > 10 plans created for one syndicate in 1h | Warning | Rate limit check |

### 5.4 Dashboard Queries

**Active bundle subscribers by syndicate** (admin dashboard):
```
SELECT syndicate_id, COUNT(*) as active_subs
FROM bundle_subscriptions
WHERE status = 'active'
GROUP BY syndicate_id
ORDER BY active_subs DESC
```

**Monthly recurring revenue from bundles**:
```
SELECT syndicate_id,
       SUM(price_cents) / 100.0 as mrr_usd
FROM bundle_subscriptions
WHERE status = 'active' AND interval = 'month'
GROUP BY syndicate_id
```

---

## 6. Rollout Plan

### 6.1 Feature Flag Strategy

| Flag | Default | Description |
|------|---------|-------------|
| `SYNDICATE_BUNDLES_ENABLED` | `false` (prod), `true` (dev) | Master switch for bundle plan endpoints |
| `SYNDICATE_BUNDLE_ACCESS_CHECK_ENABLED` | `false` (prod), `true` (dev) | Enable bundle check in `can_access_creator` |
| `SYNDICATE_BUNDLE_MAX_PLANS_PER_SYNDICATE` | `5` | Max number of active plans per syndicate |

### 6.2 Migration Steps

1. **Phase 1 -- Schema and API (no access check)**:
   - Deploy bundle plan CRUD endpoints with feature flag gating.
   - Deploy subscribe/cancel endpoints.
   - `can_access_creator` unchanged (flag off).
   - Allows admin testing of plan management without affecting content access.

2. **Phase 2 -- Enable access check**:
   - Turn on `SYNDICATE_BUNDLE_ACCESS_CHECK_ENABLED`.
   - `can_access_creator` now includes `has_bundle_access()`.
   - Monitor access check latency and error rate.

3. **Phase 3 -- Public availability**:
   - Turn on `SYNDICATE_BUNDLES_ENABLED` for all tenants.
   - Enable My Bundles page in frontend navigation.
   - Enable bundle plans tab on syndicate pages.

4. **Phase 4 -- Auto-renewal**:
   - Enable background renewal loop for bundle subscriptions.
   - Integrate with existing billing dunning flow.

### 6.3 Rollback Procedure

1. Set `SYNDICATE_BUNDLE_ACCESS_CHECK_ENABLED=false` to immediately stop bundle-based content access.
2. Set `SYNDICATE_BUNDLES_ENABLED=false` to hide all bundle UI and endpoints.
3. Existing subscriptions remain in DDB but are inert (no access checks, no renewals).
4. When re-enabling, all existing subscription records resume without data loss.

---

## 7. Performance Considerations

### 7.1 Query Cost Analysis

| Operation | DDB Reads | DDB Writes | Expected Latency |
|-----------|-----------|------------|-------------------|
| Create bundle plan | 2 (syndicate + members) | 2 (plan + index) | ~20ms |
| Subscribe to bundle | 1 (plan) + 1 (PM validation) | 3 (sub + index + entitlement) | ~30ms |
| Cancel subscription | 1 (get sub) | 2 (update sub + entitlement) | ~20ms |
| `has_bundle_access` | 1 (user syndicates) + N (entitlement checks) | 0 | ~15-30ms |
| List syndicate plans | 1 query | 0 | ~10ms |
| List my bundles | 1 query + filter | 0 | ~15ms |
| Get bundle details | 1 (plan) + 1 (members) | 0 | ~15ms |

### 7.2 Caching Strategy

| Cache Target | TTL | Invalidation | Storage |
|-------------|-----|-------------|---------|
| Syndicate member list | 60s | On member join/leave | In-memory (per-process) |
| Bundle plan list | 30s | On plan create/update/archive | React Query (client) |
| User's syndicate memberships | 120s | On membership change | In-memory (per-process) |
| `has_bundle_access` result | Not cached | N/A (real-time access checks) | N/A |

Note: `has_bundle_access` is intentionally NOT cached because membership changes must take effect immediately. The 2-4 DDB reads per check are acceptable given that this path is only reached when no direct subscription exists.

### 7.3 Pagination Limits

| Endpoint | Default Limit | Max Limit | Cursor Support |
|----------|---------------|-----------|----------------|
| List syndicate plans | 20 | 50 | No (typically < 10 plans per syndicate) |
| List my bundles | 20 | 50 | Yes (DDB cursor) |
| Get bundle details (members) | 100 | 100 | No (syndicates rarely exceed 100 members) |

### 7.4 Rate Limiting

| Endpoint | Rate Limit | Window | Key |
|----------|-----------|--------|-----|
| Create plan | 5 requests | 1 hour | `syndicate_id` |
| Subscribe | 10 requests | 1 hour | `user_sub` |
| Cancel | 10 requests | 1 hour | `user_sub` |
| List plans | 60 requests | 1 minute | `user_sub` |
| Get plan details | 60 requests | 1 minute | `user_sub` |

### 7.5 DDB Cost Optimization

- **Bundle entitlement index reads**: Each `has_bundle_access` call performs 1 query + N `get_item` calls. N is bounded by the number of syndicates a creator belongs to (typically 1-3). At scale with 10K access checks/minute, this is ~30K reads/minute, well within DDB on-demand pricing threshold.
- **Subscription index**: The `SUBSCRIBER#` prefix query for `list_subscriber_bundles` uses `FilterExpression` for `plan_type=syndicate_bundle`. If a user has many individual subscriptions (e.g., 50+), the filter discards most results. This is acceptable because the query still returns within a single page (subscriptions per user rarely exceed 100).

---

## 8. E2E Test Plan

**File**: `frontend/e2e/syndicates-bundles.spec.ts`

### Section 427: Bundle Plan CRUD API (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 427.1 | Admin creates a bundle plan | POST; 200; response has `plan_id`, `plan_type=syndicate_bundle`, `price_cents`, `interval` |
| 427.2 | Plan appears in syndicate plan list | GET plans; response includes created plan with correct name and price |
| 427.3 | Admin updates plan price | PUT; 200; updated `price_cents` reflected in GET |
| 427.4 | Admin updates plan description | PUT with description only; 200; description updated, price unchanged |
| 427.5 | Admin archives plan | DELETE; 200; plan `status=archived` in GET |
| 427.6 | Non-admin cannot create plan | Bob (non-admin member) POST; 403; error code `SYNDICATE_NOT_ADMIN` |

### Section 428: Bundle Subscription API (7 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 428.1 | User subscribes to bundle plan | POST subscribe; 200; subscription `status=active`, `plan_type=syndicate_bundle` |
| 428.2 | Subscription appears in user's bundle list | GET my-bundles; includes new bundle subscription with correct syndicate_name |
| 428.3 | Subscriber can access syndicate member's gated content | Check `can_access_creator` returns true for each syndicate member |
| 428.4 | Non-subscriber cannot access gated content | Check access returns false for user without bundle subscription |
| 428.5 | User cancels bundle subscription | POST cancel; 200; status changes to "cancelled"; `cancelled_at` set |
| 428.6 | Cannot subscribe to archived plan | Archive plan, then attempt subscribe; 400; error code `PLAN_ARCHIVED` |
| 428.7 | Duplicate subscription returns 409 | Subscribe twice to same syndicate bundle; second attempt returns 409 |

### Section 429: Dynamic Membership Access (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 429.1 | New member joining grants bundle subscribers access | Add creator to syndicate; existing subscriber can access new member's content |
| 429.2 | Member leaving revokes bundle subscriber access | Remove creator from syndicate; subscriber loses access to that creator |
| 429.3 | Bundle access survives creator profile update | Member updates profile; bundle access still works |
| 429.4 | Multiple bundle subscriptions grant cumulative access | Subscribe to two syndicates; access both sets of creators |
| 429.5 | Cancelled subscription retains access until period end | Cancel; immediately check access; still active until `current_period_end` |
| 429.6 | Access check falls back to direct subscription | User has direct sub AND bundle; remove bundle; direct sub still grants access |

### Section 430: Bundle Plan UI (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 430.1 | Bundle plans tab visible on syndicate page | Navigate to syndicate detail; "Plans" tab visible |
| 430.2 | Create plan dialog works for admin | Click "Create Plan"; fill form; submit; plan appears in list |
| 430.3 | Subscribe dialog shows included creators | Click "Subscribe"; dialog lists all current syndicate members with avatars |
| 430.4 | My Bundles page shows active subscriptions | Navigate to `/syndicates/my-bundles`; active bundles listed with syndicate name |
| 430.5 | Archive button hidden for non-admins | Non-admin member visits plan tab; "Archive" button not visible |
| 430.6 | Cancel button shows confirmation dialog | Click "Cancel" on my-bundles; confirmation dialog appears with period-end date |

**Total E2E tests: 25**

### Expanded E2E Edge Cases and Negative Tests

These additional tests cover concurrency and boundary conditions:

| # | Test Title | Category |
|---|-----------|----------|
| E1 | Concurrent subscribe from two users | Both succeed; both get `status=active` |
| E2 | Subscribe with zero-balance wallet | 402 PAYMENT_FAILED or wallet insufficient |
| E3 | Create plan with `price_cents=100` (minimum $1) | 200; boundary accepted |
| E4 | Create plan with `price_cents=100001` (exceeds max) | 422; validation error |
| E5 | Empty plan name | 422; validation error for `min_length=2` |
| E6 | Rapidly cancel and re-subscribe | Cancel succeeds; re-subscribe creates new subscription_id |
| E7 | Access check after syndicate dissolved | Syndicate deleted; access check returns false |
| E8 | List plans for non-existent syndicate | 404 SYNDICATE_NOT_FOUND |

---

## 9. Security Considerations

### 9.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Plan CRUD | `require_ui_session` | Syndicate admin only (service layer check) |
| Subscribe/cancel | `require_ui_session` | Any authenticated user |
| List plans | `require_ui_session` | Any authenticated user |
| My bundles | `require_ui_session` | Returns only caller's subscriptions |

### 9.2 Payment Security

- Bundle subscription uses the same payment flow as individual subscriptions (existing `record_billing_payment` and `new_ledger_entry`).
- Payment method validation occurs before subscription creation.
- `price_cents` range: $1 - $1000 (enforced by Pydantic `ge=100, le=100000`).
- Archived plans cannot accept new subscriptions (checked in `subscribe_to_bundle`).

### 9.3 Access Control

- `has_bundle_access` only returns true for `status=active` bundle entitlements.
- Cancelled subscriptions remain active until `current_period_end` (no early revocation).
- Subscriber cannot access content of creators who have left the syndicate (live membership check).

### 9.4 IDOR Prevention

- Subscription cancellation validates that `subscriber_id` matches the session user's `user_sub`.
- Plan modification validates that the caller is the syndicate admin.
- Bundle details reveal member list (public information per SYND-001 design).

---

## 10. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| SYND-001 | Required | Syndicate metadata, member list, admin checks |
| `app/routers/subscription_server.py` | Exists | Plan/subscription record patterns |
| `app/services/subscription_access.py` | Exists (modify) | Extend `can_access_creator` for bundles |
| `app/services/billing_shared.py` | Exists | Ledger entries for bundle payments |
| SYND-003 | Not started | Revenue splitting for bundle payments (processes after this ticket) |

---

## 11. Acceptance Criteria

1. Syndicate admin can create, update, and archive bundled subscription plans.
2. Users can subscribe to a bundle plan and gain access to all member creators' subscription-gated content.
3. `can_access_creator` correctly returns `true` for bundle subscribers checking any syndicate member.
4. When a creator joins a syndicate, existing bundle subscribers automatically gain access to the new member's content.
5. When a creator leaves a syndicate, bundle subscribers lose access to that creator's content.
6. Subscribers can cancel bundles; access continues until period end.
7. My Bundles page lists all active bundle subscriptions with included creators.
8. All 25 E2E tests pass.

---


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_syndicate_subscriptions.py`

| # | Function | Assertion |
|---|----------|-----------|
| 1 | `test_create_bundle_plan` | Create bundle plan verified |
| 2 | `test_subscribe_to_bundle` | Subscribe to bundle verified |
| 3 | `test_bundle_entitlement_for_all_members` | Bundle entitlement for all members verified |
| 4 | `test_cancel_bundle_subscription` | Cancel bundle subscription verified |
| 5 | `test_new_member_join_expands_entitlements` | New member join expands entitlements verified |
| 6 | `test_member_leave_revokes_entitlement` | Member leave revokes entitlement verified |
| 7 | `test_non_admin_cannot_create_bundle_plan` | Non admin cannot create bundle plan verified |
| 8 | `test_update_bundle_plan_price` | Update bundle plan price verified |

**Mocking**: All DynamoDB tables mocked via `moto`; profile lookups patched via `unittest.mock.patch`.

### Integration Tests

1. Create bundle plan -> subscriber subscribes -> has_active_subscription returns true for every syndicate member
2. Creator joins syndicate -> existing bundle subscribers gain access to new creator's content
3. Creator leaves syndicate -> bundle subscribers lose access to that creator only

### E2E Tests (Playwright)

**File**: `frontend/e2e/syndicate-subscriptions.spec.ts`
**Sections**: 1-4 (12 tests)

**Auth pattern**: `injectAuth(page, identity)` for cookie auth; `x-csrf-token` header for POST/PUT/DELETE mutations.

| # | Test | Assertion |
|---|------|-----------|
| 1 | Create bundle plan | 201; plan with plan_type=syndicate_bundle |
| 2 | Subscribe to bundle | 200; access to all member creators |
| 3 | Entitlement check passes for bundle member | has_active_subscription=true |
| 4 | Cancel bundle | 200; access until period end |
| 5 | Non-admin cannot create plan | 403 |
| 6 | Member join expands entitlements | New member content accessible to subscribers |
| 7 | Member leave revokes access | Left member content no longer accessible |
| 8 | Bundle details show member list | GET bundle returns member profiles |

**Negative tests**: 403 non-admin create plan, 404 syndicate not found, 400 invalid price, 409 already subscribed, 400 subscribe to archived syndicate

**Edge cases**: Bundle with 1 member (valid but degenerate), subscriber joins then creator leaves mid-period, plan price update during active subscriptions

### Test Data Requirements

- **DDB seeds**: Syndicate with 3 members (from SYND-001); subscription plans in subscriptions table; billing records
- **Test users**: Alice (admin), Bob/Charlie (members), Dave (subscriber)

### CI/Pipeline Considerations

- **Feature flags**: SYNDICATES_ENABLED=true
- **Serial execution**: Must run after SYND-001 syndicate creation tests
- **Retry safety**: All tests are idempotent; use unique per-run identifiers (`TS` suffix) to avoid cross-run conflicts.

---

## Dependencies & Merge Safety

### Depends On

| Ticket/Component | Reason |
|------------------|--------|
| SYND-001 | Syndicate membership infrastructure — list_members, get_syndicate |
| Subscription server (existing) | Plan CRUD and subscription lifecycle |
| Subscription access (existing) | has_active_subscription entitlement check |

### Depended On By

| Ticket | Reason |
|--------|--------|
| SYND-003 | Revenue splitting processes bundle payments |
| SYND-004 | Treasury funds advertising from bundle revenue |

### Merge Strategy: **Sequential**

Requires SYND-001 for membership. Extends subscription server with plan_type=syndicate_bundle.

### Merge Checklist

- [ ] All unit tests pass (`just test`)
- [ ] All E2E tests pass (`just e2e`)
- [ ] Feature flag defaults to enabled in `.env.local.example`
- [ ] No breaking changes to existing API contracts
- [ ] DynamoDB table/GSI changes added to `scripts/local-ddb-init.py`
- [ ] Frontend types in `api/types.ts` match backend `models.py`
- [ ] New routes registered in `app/main.py` and `frontend/src/App.tsx`

## Codebase References

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| No syndicate/bundle code exists | All files | — | VERIFIED: grep "syndicate" returns zero results |
| subscription_server.py (stated 1735 lines) | `app/routers/subscription_server.py` | — | **LINE COUNT OUTDATED**: now 1852 lines |
| subscription_access.py (stated 80 lines) | `app/services/subscription_access.py` | — | VERIFIED: 82 lines |
| `has_active_subscription` function | `app/services/subscription_access.py` | 55 | VERIFIED |
| `can_access_creator` function | `app/services/subscription_access.py` | 72 | VERIFIED |
| billing_shared.py exists | `app/services/billing_shared.py` | — | VERIFIED (260 lines) |
