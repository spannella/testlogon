# INFRA-012: Admin Compute Dashboard

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 6-8 days  
**Dependencies**: INFRA-003 (EC2 Launcher), INFRA-004 (K8s Launcher), INFRA-005 (Cost Tracking)

---

## 1. Overview & Motivation

### The Gap

INFRA-003 through INFRA-005 give individual users the ability to launch instances/pods, track costs, and manage budgets. However, platform administrators have no visibility into:

1. All compute resources across all users
2. Platform-wide spending totals and trends
3. Per-user resource usage and spending breakdown
4. The ability to force-terminate any instance (for abuse or cost control)
5. Per-user resource quotas (max instances, max spend, allowed instance types)
6. Instance type popularity metrics (which types are most used)

The platform already has admin infrastructure:

- **Admin auth**: `require_admin_session` in `app/auth/deps.py` (see `app/auth/deps.py:126`) (requires `role >= ADMIN`)
- **Root auth**: `require_root_session` (see `app/auth/deps.py:273`) (requires `role == ROOT`)
- **Admin roles**: `app/auth/roles.py` with `USER`, `ADMIN`, `ROOT` enum (see `app/auth/roles.py:8`)
- **Audit events**: `audit_event()` from `app/services/alerts.py` (see `app/services/alerts.py:695`)
- **Role audit table**: `role_audit` DDB table for tracking admin actions (see `scripts/local-ddb-init.py`)
- **Admin E2E pattern**: `e2e_admin_session_setup.py` seeds sessions for `root`, `charlie_admin`

However, there are no admin endpoints for compute resource management.

### Why This Matters

1. **Platform governance**: Admins need a single pane of glass to see all compute resources.
2. **Cost control**: Without platform-wide spending visibility, costs can spiral unchecked.
3. **Abuse prevention**: A user could launch max instances on multiple accounts. Admins need force-terminate capability.
4. **Quota management**: Different users/tiers should have different resource limits.
5. **Capacity planning**: Instance type popularity data informs infrastructure provisioning decisions.

### Architecture After This Change

```
Admin Compute Dashboard

  require_admin_session / require_root_session
       |
       v
  Admin API Endpoints (/v1/admin/compute/*)
       |
       +---> All instances across all users
       |     Query: Scan ec2_instances + k8s_pods tables
       |     Filters: by user, by status, by instance type
       |
       +---> Platform-wide spending
       |     Aggregate compute_billing table across all users
       |
       +---> Force-terminate any instance
       |     With audit trail: who terminated, why
       |
       +---> Per-user quotas
       |     DDB: compute_quotas table
       |     PK=user_sub, fields: max_instances, max_pods,
       |     max_monthly_spend, allowed_instance_types
       |
       +---> AdminComputeDashboard (frontend)
             Route: /admin/compute
             Instance table, spending charts, quota editor
```

---

## 2. Current State Analysis

### 2.1 Admin Auth Pattern (`app/auth/deps.py`)

```python
async def require_admin_session(request: Request) -> dict:
    """Requires role >= ADMIN. Returns {user_sub, role, admin_profile}."""

async def require_root_session(request: Request) -> dict:
    """Requires role == ROOT."""
```

Admin endpoints use `Depends(require_admin_session)`. Root-only operations (like modifying quotas) use `Depends(require_root_session)`.

### 2.2 Admin Router Pattern (`app/routers/admin_roles.py`)

Existing admin routers use the `/v1/admin/` prefix pattern:

```python
router = APIRouter(prefix="/v1/admin/roles", tags=["admin-roles"])

@router.post("/grant")
async def grant_role(..., ctx=Depends(require_root_session)):
    ...
```

### 2.3 Admin E2E Test Pattern

Admin E2E tests use `e2e_admin_session_setup.py`:

```typescript
const { getOrCreateAdminSession } = await import("../../e2e_admin_session_setup");
sessions["root"] = await getOrCreateAdminSession("root");
sessions["charlie_admin"] = await getOrCreateAdminSession("charlie_admin");
```

### 2.4 EC2/K8s Instance Tables

The `ec2_instances` and `k8s_pods` tables use `user_sub` as PK. To query across all users, the admin API must perform a table scan (acceptable for admin operations with < 10K total instances) or maintain a global secondary index.

### 2.5 Compute Billing Table (INFRA-005)

The `compute_billing` table stores per-user billing entries. Platform-wide aggregation requires scanning across all partition keys.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `compute_quotas`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.compute_quotas_table_name, "compute_quotas"),
    "user_sub",            # PK — user subject to quotas
)
```

**Item schema**:

| Field | Type | Description |
|-------|------|-------------|
| `user_sub` | S (PK) | User subject to these quotas |
| `max_ec2_instances` | N | Maximum concurrent EC2 instances (default: 3) |
| `max_k8s_pods` | N | Maximum concurrent K8s pods (default: 5) |
| `max_monthly_spend_cents` | N | Monthly spending cap in cents (default: 5000 = $50) |
| `allowed_instance_types` | L[S] | Allowed EC2 instance types (empty = all from INSTANCE_TYPES) |
| `allowed_k8s_presets` | L[S] | Allowed K8s presets (empty = all from RESOURCE_PRESETS) |
| `updated_at` | N | Last quota modification timestamp |
| `updated_by` | S | Admin who set the quotas |
| `notes` | S | Admin notes about this quota configuration |

### 3.2 Global Secondary Index for Cross-User Queries

Add a GSI to `ec2_instances` and `k8s_pods` for admin queries:

```python
# For ec2_instances — add GSI:
{"index_name": "ByGlobalStatus", "partition_key": "status", "sort_key": "created_at"},

# For k8s_pods — add GSI:
{"index_name": "ByGlobalStatus", "partition_key": "status", "sort_key": "created_at"},
```

This allows efficient queries like "all running instances across all users" without table scans.

### 3.3 Service Layer: `app/services/admin_compute.py`

New file (~300 lines):

```python
"""Admin compute resource management — cross-user instance visibility, quotas, force-terminate."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from decimal import Decimal

from boto3.dynamodb.conditions import Key, Attr
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event, write_alert
from app.services.ec2_launcher import terminate_instance as _user_terminate_ec2
from app.services.k8s_launcher import terminate_pod as _user_terminate_k8s


def list_all_instances(
    *,
    status: str | None = None,
    user_sub: str | None = None,
    instance_type: str | None = None,
    limit: int = 100,
    cursor: str | None = None,
) -> Dict[str, Any]:
    """List all EC2 instances across all users with optional filters."""

def list_all_pods(
    *,
    status: str | None = None,
    user_sub: str | None = None,
    limit: int = 100,
    cursor: str | None = None,
) -> Dict[str, Any]:
    """List all K8s pods across all users with optional filters."""

def force_terminate_instance(
    admin_sub: str,
    user_sub: str,
    instance_id: str,
    *,
    reason: str = "",
) -> Dict[str, Any]:
    """Force-terminate any user's instance. Audit-logged."""
    audit_event(admin_sub, event="admin.compute.force_terminate",
                outcome="success",
                details={"target_user": user_sub, "instance_id": instance_id, "reason": reason})
    write_alert(user_sub, event="compute.admin_terminated", outcome="warning",
                title="An administrator terminated your instance",
                details={"instance_id": instance_id, "reason": reason})
    return _user_terminate_ec2(user_sub, instance_id)

def force_terminate_pod(
    admin_sub: str,
    user_sub: str,
    pod_id: str,
    *,
    reason: str = "",
) -> Dict[str, Any]:
    """Force-terminate any user's pod. Audit-logged."""
    audit_event(admin_sub, event="admin.compute.force_terminate_pod",
                outcome="success",
                details={"target_user": user_sub, "pod_id": pod_id, "reason": reason})
    write_alert(user_sub, event="compute.admin_terminated", outcome="warning",
                title="An administrator terminated your container",
                details={"pod_id": pod_id, "reason": reason})
    return _user_terminate_k8s(user_sub, pod_id)

def get_platform_spending(*, month: str | None = None) -> Dict[str, Any]:
    """Aggregate spending across all users for a given month."""

def get_per_user_spending(*, month: str | None = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Per-user spending breakdown, sorted by total descending."""

def get_instance_type_stats() -> List[Dict[str, Any]]:
    """Instance type popularity: count of running instances per type."""

def get_quota(user_sub: str) -> Dict[str, Any]:
    """Get a user's compute quotas. Returns defaults if no custom quota set."""

def set_quota(
    admin_sub: str,
    user_sub: str,
    *,
    max_ec2_instances: int | None = None,
    max_k8s_pods: int | None = None,
    max_monthly_spend_cents: int | None = None,
    allowed_instance_types: list[str] | None = None,
    allowed_k8s_presets: list[str] | None = None,
    notes: str = "",
) -> Dict[str, Any]:
    """Set/update a user's compute quotas. Root-only."""
    audit_event(admin_sub, event="admin.compute.set_quota",
                outcome="success",
                details={"target_user": user_sub, "quotas": {
                    "max_ec2_instances": max_ec2_instances,
                    "max_k8s_pods": max_k8s_pods,
                    "max_monthly_spend_cents": max_monthly_spend_cents,
                }})

def delete_quota(admin_sub: str, user_sub: str) -> bool:
    """Remove custom quotas for a user (reverts to platform defaults). Root-only."""
```

### 3.4 Quota Enforcement Integration

Modify `app/services/ec2_launcher.py` and `app/services/k8s_launcher.py` to check quotas before launch:

```python
# In ec2_launcher.py::launch_instance()
from app.services.admin_compute import get_quota

def launch_instance(user_sub, *, instance_type, ...):
    quota = get_quota(user_sub)

    # Check instance count limit
    active = list_instances(user_sub, status="running") + list_instances(user_sub, status="stopped")
    if len(active) >= quota["max_ec2_instances"]:
        raise ValueError(f"Maximum {quota['max_ec2_instances']} instances allowed")

    # Check allowed instance types
    if quota["allowed_instance_types"] and instance_type not in quota["allowed_instance_types"]:
        raise ValueError(f"Instance type {instance_type} not allowed by your quota")

    # Check spending limit
    from app.services.compute_billing import get_monthly_summary
    summary = get_monthly_summary(user_sub)
    if summary["total_cents"] >= quota["max_monthly_spend_cents"]:
        raise ValueError("Monthly spending limit reached")

    # ... proceed with launch ...
```

### 3.5 API Router: `app/routers/admin_compute.py`

New file (~250 lines). Prefix: `/v1/admin/compute`.

| Method | Path | Auth | Request | Response | Description |
|--------|------|------|---------|----------|-------------|
| `GET` | `/v1/admin/compute/instances` | admin | query params | `AdminInstanceListOut` | All instances |
| `GET` | `/v1/admin/compute/pods` | admin | query params | `AdminPodListOut` | All pods |
| `POST` | `/v1/admin/compute/instances/{user_sub}/{id}/terminate` | admin | `ForceTerminateIn` | `InstanceOut` | Force-terminate |
| `POST` | `/v1/admin/compute/pods/{user_sub}/{id}/terminate` | admin | `ForceTerminateIn` | `PodOut` | Force-terminate pod |
| `GET` | `/v1/admin/compute/spending` | admin | `?month=YYYY-MM` | `PlatformSpendingOut` | Platform spending |
| `GET` | `/v1/admin/compute/spending/users` | admin | `?month=YYYY-MM` | `PerUserSpendingOut` | Per-user breakdown |
| `GET` | `/v1/admin/compute/stats/instance-types` | admin | — | `InstanceTypeStatsOut` | Type popularity |
| `GET` | `/v1/admin/compute/quotas/{user_sub}` | admin | — | `QuotaOut` | Get user quota |
| `PUT` | `/v1/admin/compute/quotas/{user_sub}` | root | `SetQuotaIn` | `QuotaOut` | Set user quota |
| `DELETE` | `/v1/admin/compute/quotas/{user_sub}` | root | — | `{"ok": true}` | Delete custom quota |

#### Pydantic Models

```python
class AdminInstanceOut(BaseModel):
    """Instance with owner information for admin views."""
    instance_id: str
    user_sub: str
    label: str
    instance_type: str
    ami_name: str
    status: str
    public_ip: str
    created_at: int
    last_activity_at: int
    auto_terminate_after: int

class AdminInstanceListOut(BaseModel):
    instances: List[AdminInstanceOut]
    count: int
    cursor: Optional[str] = None

class AdminPodOut(BaseModel):
    pod_id: str
    user_sub: str
    label: str
    image: str
    preset: str
    status: str
    pod_ip: str
    created_at: int
    ttl_seconds: int
    expires_at: int

class AdminPodListOut(BaseModel):
    pods: List[AdminPodOut]
    count: int
    cursor: Optional[str] = None

class ForceTerminateIn(BaseModel):
    reason: str = Field(default="", max_length=500)

class PlatformSpendingOut(BaseModel):
    month: str
    total_cents: int
    ec2_total_cents: int
    k8s_total_cents: int
    active_user_count: int
    active_instance_count: int
    active_pod_count: int

class PerUserSpendingEntry(BaseModel):
    user_sub: str
    total_cents: int
    ec2_cents: int
    k8s_cents: int
    instance_count: int
    pod_count: int

class PerUserSpendingOut(BaseModel):
    users: List[PerUserSpendingEntry]
    month: str

class InstanceTypeStatEntry(BaseModel):
    instance_type: str
    running_count: int
    total_launched: int

class InstanceTypeStatsOut(BaseModel):
    stats: List[InstanceTypeStatEntry]

class QuotaOut(BaseModel):
    user_sub: str
    max_ec2_instances: int
    max_k8s_pods: int
    max_monthly_spend_cents: int
    allowed_instance_types: List[str]
    allowed_k8s_presets: List[str]
    is_custom: bool  # False = using platform defaults
    updated_at: int = 0
    updated_by: str = ""
    notes: str = ""

class SetQuotaIn(BaseModel):
    max_ec2_instances: int = Field(default=3, ge=0, le=100)
    max_k8s_pods: int = Field(default=5, ge=0, le=100)
    max_monthly_spend_cents: int = Field(default=5000, ge=0, le=1_000_000)
    allowed_instance_types: List[str] = Field(default_factory=list)
    allowed_k8s_presets: List[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=500)
```

### 3.6 Frontend Components

#### AdminComputeDashboard (`frontend/src/pages/admin/AdminComputeDashboard.tsx`)

New page (~500 lines):

- **Header**: "Compute Dashboard" with platform-wide summary cards:
  - Total Spending (this month) — large dollar amount
  - Active Instances — count with breakdown (EC2/K8s)
  - Active Users — count of users with running resources
  - Budget Utilization — platform-wide percentage

- **Spending chart section**:
  - Daily spending bar chart for current month
  - Toggle: EC2 only / K8s only / Combined
  - Month navigation (previous/next)

- **Per-user spending table**:
  - DataTable: User, EC2 Spending, K8s Spending, Total, Instance Count, Pod Count, Quota Status
  - Sort by total spending (descending)
  - Click user → opens quota editor dialog

- **All instances table**:
  - Tab: EC2 Instances | K8s Pods
  - DataTable: User, Label, Type/Image, Status, IP, Created, Idle Time, Actions
  - Filter: by status, by user, by instance type
  - Action: Force Terminate (with reason dialog)

- **Instance type popularity**:
  - Horizontal bar chart showing running count per instance type
  - Helps with capacity planning

#### QuotaEditorDialog (`frontend/src/pages/admin/QuotaEditorDialog.tsx`)

Dialog (~150 lines):

- User ID display
- Current quota values (editable)
- Max EC2 instances slider (0-100)
- Max K8s pods slider (0-100)
- Monthly spending cap input (dollars)
- Allowed instance types checklist
- Admin notes textarea
- Save button (root-only)
- "Reset to Defaults" button (deletes custom quota)

#### Route & Navigation

```tsx
<Route path="/admin/compute" element={<AdminComputeDashboard />} />
```

Admin sidebar: "Compute" with `Server` icon (only visible to ADMIN/ROOT role).

---

## 4. Implementation Plan

### Phase 1: Backend Admin Service (2 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `compute_quotas_table_name` |
| `app/core/tables.py` | Add `compute_quotas` table handle |
| `scripts/local-ddb-init.py` | Add `compute_quotas` TableDef, add ByGlobalStatus GSI to ec2_instances and k8s_pods |
| `app/services/admin_compute.py` | New file: cross-user queries, force-terminate, quotas, spending aggregation |

### Phase 2: API Endpoints (1-2 days)

| File | Change |
|------|--------|
| `app/routers/admin_compute.py` | New file: 10 endpoints |
| `app/models.py` | Add admin compute Pydantic models |
| `app/main.py` | Register admin_compute router |

### Phase 3: Quota Enforcement (1 day)

| File | Change |
|------|--------|
| `app/services/ec2_launcher.py` | Check quotas before launch |
| `app/services/k8s_launcher.py` | Check quotas before launch |

### Phase 4: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add admin compute types |
| `frontend/src/api/endpoints/admin-compute.ts` | New file: API wrappers |
| `frontend/src/pages/admin/AdminComputeDashboard.tsx` | New file: dashboard page |
| `frontend/src/pages/admin/QuotaEditorDialog.tsx` | New file: quota editor |
| `frontend/src/App.tsx` | Add `/admin/compute` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Compute" to admin nav section |

### Phase 5: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/admin-compute.spec.ts` | New file: ~18 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/admin-compute.spec.ts`)

**Section 280: Admin Instance Visibility API (4 tests)**

1. `Admin lists all instances across users` — Alice launches instance, root GETs `/v1/admin/compute/instances`. Verify Alice's instance in list with `user_sub` populated.
2. `Admin filters by status` — GET `?status=running`. Verify only running instances.
3. `Admin filters by user` — GET `?user_sub=<alice_sub>`. Verify only Alice's instances.
4. `Non-admin cannot access admin endpoints` — Alice (USER role) GETs `/v1/admin/compute/instances` → 403.

**Section 281: Force-Terminate & Alerts API (5 tests)**

5. `Admin force-terminates user instance` — Alice launches instance. Root POSTs `/v1/admin/compute/instances/{alice_sub}/{id}/terminate` with `reason: "resource abuse"`. Verify instance `status: "terminated"`.
6. `User receives alert on admin termination` — After force-terminate, check Alice's alerts for `compute.admin_terminated` event with reason.
7. `Force-terminate is audit-logged` — Check audit events for `admin.compute.force_terminate` with admin's sub and target user.
8. `Admin force-terminates pod` — Alice launches pod. Root terminates. Verify pod terminated.
9. `Force-terminate non-existent returns 404` — POST with invalid instance_id → 404.

**Section 282: Quota Management API (5 tests)**

10. `Get default quota for user without custom quota` — GET `/quotas/{alice_sub}`. Verify defaults: `max_ec2_instances: 3`, `max_k8s_pods: 5`, `is_custom: false`.
11. `Root sets custom quota` — PUT `/quotas/{alice_sub}` with `max_ec2_instances: 1`. Verify `is_custom: true`, `max_ec2_instances: 1`.
12. `Quota limits instance launch` — Set Alice's quota to `max_ec2_instances: 0`. Alice tries to launch → 409 "Maximum 0 instances allowed".
13. `Delete custom quota reverts to defaults` — DELETE `/quotas/{alice_sub}`. GET, verify `is_custom: false`, default values.
14. `Admin (non-root) cannot set quotas` — Charlie (ADMIN) tries PUT quotas → 403 (root-only).

**Section 283: Platform Spending & Stats API (4 tests)**

15. `Platform spending summary` — Seed billing data for Alice and Bob. GET `/spending`. Verify `total_cents > 0`, `active_user_count >= 1`.
16. `Per-user spending breakdown` — GET `/spending/users`. Verify entries for Alice and Bob with individual totals.
17. `Instance type stats` — Launch instances of different types. GET `/stats/instance-types`. Verify breakdown.
18. `Admin compute dashboard renders` — Root navigates to `/admin/compute`. Verify "Compute Dashboard" heading, spending summary cards, instance table.

**Test Setup**:

```typescript
test.beforeAll(async ({ browser }) => {
  const { getOrCreateSession } = await import("../../e2e_session_setup");
  const { getOrCreateAdminSession } = await import("../../e2e_admin_session_setup");
  sessions["alice"] = await getOrCreateSession("alice");
  sessions["bob"] = await getOrCreateSession("bob");
  sessions["root"] = await getOrCreateAdminSession("root");
  sessions["charlie_admin"] = await getOrCreateAdminSession("charlie_admin");

  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");
  charliePage = await browser.newPage();
  await injectAuth(charliePage, "charlie_admin");
});

async function apiPost(page: Page, identity: string, path: string, body: any) {
  return page.request.post(`http://localhost:3000${path}`, {
    headers: { "x-csrf-token": sessions[identity].csrf_token },
    data: body,
  }).then(r => r.json());
}
```

---

## 6. Security Considerations

### 6.1 Role-Based Access

- **Instance/pod listing, spending, stats**: `require_admin_session` (ADMIN or ROOT)
- **Force-terminate**: `require_admin_session` (ADMIN or ROOT) — with audit trail
- **Quota management (set/delete)**: `require_root_session` (ROOT only) — prevents admins from self-escalating their own quotas
- **Quota viewing**: `require_admin_session` — admins can view any user's quota

### 6.2 Force-Terminate Audit Trail

Every force-terminate creates:
1. An audit event logged against the admin's user_sub
2. An in-app alert to the affected user
3. A timeline event on the resource (INFRA-008)

This creates a complete chain of accountability.

### 6.3 Cross-User Data Access

Admin endpoints deliberately expose `user_sub` on instance/pod/spending records. This is necessary for admin operations but would be a data leak if the endpoints were accessible to regular users. The `require_admin_session` dependency prevents this.

### 6.4 Quota Self-Service Restriction

Quota modification is root-only. This prevents:
- Admins from raising their own quotas
- Users from escalating through admin impersonation (impersonation doesn't grant ROOT)

---

## 7. Migration & Rollback

### 7.1 DDB Changes

- New table `compute_quotas` — simple PK-only table
- New GSI `ByGlobalStatus` on `ec2_instances` and `k8s_pods` tables — required for cross-user queries without table scans

### 7.2 Rollback

- Remove admin_compute router from `app/main.py`
- Remove quota checks from launch functions (launcher reverts to hardcoded limits)
- DDB changes are non-destructive (GSI removal is optional)

---

## 8. DynamoDB Access Patterns

### 8.1 Access Pattern Matrix

| Access Pattern | Table/GSI | PK | SK / Condition | Projection | Frequency |
|---------------|-----------|-----|----------------|------------|-----------|
| Get user quota | compute_quotas | `user_sub` | — | All | On every launch |
| Set user quota | compute_quotas | `user_sub` | — (put_item) | — | Low — root admin action |
| Delete user quota | compute_quotas | `user_sub` | — (delete_item) | — | Rare |
| All running instances | ec2_instances / ByGlobalStatus GSI | `status = running` | `created_at DESC` | All | Medium — admin dashboard |
| All running pods | k8s_pods / ByGlobalStatus GSI | `status = running` | `created_at DESC` | All | Medium — admin dashboard |
| Instances by user | ec2_instances | `user_sub` | `SK begins_with INST#` | All | Medium — user filter |
| Platform spending | compute_billing (Scan) | All | Filter by month prefix | Aggregation | Low — dashboard load |
| Per-user spending | compute_billing (Scan) | All | Filter by month prefix | Group by user_sub | Low — dashboard load |

### 8.2 Example DynamoDB Items

**Custom quota record:**

```json
{
  "user_sub":                 {"S": "abc-123-def"},
  "max_ec2_instances":        {"N": "10"},
  "max_k8s_pods":             {"N": "15"},
  "max_monthly_spend_cents":  {"N": "25000"},
  "allowed_instance_types":   {"L": [{"S": "t3.micro"}, {"S": "t3.small"}, {"S": "t3.medium"}]},
  "allowed_k8s_presets":      {"L": [{"S": "small"}, {"S": "medium"}, {"S": "large"}]},
  "updated_at":               {"N": "1748520000"},
  "updated_by":               {"S": "root.admin@testdev.local"},
  "notes":                    {"S": "Upgraded to premium tier quota"}
}
```

---

## 9. API Request/Response Examples

### 9.1 List All Instances (Admin)

```bash
curl -s "http://localhost:8000/v1/admin/compute/instances?status=running&limit=10" \
  -H "Cookie: ui_session=sess_root; ui_csrf=tok_root; ui_access_token=eyJ..."
```

**Response (200):**

```json
{
  "instances": [
    {
      "instance_id": "i_abc12345",
      "user_sub": "alice-uuid",
      "label": "Dev Server",
      "instance_type": "t3.small",
      "ami_name": "Ubuntu 22.04",
      "status": "running",
      "public_ip": "10.0.42.17",
      "created_at": 1748520000,
      "last_activity_at": 1748525000,
      "auto_terminate_after": 28800
    }
  ],
  "count": 1,
  "cursor": null
}
```

### 9.2 Force-Terminate Instance

```bash
curl -s -X POST "http://localhost:8000/v1/admin/compute/instances/alice-uuid/i_abc12345/terminate" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root; ui_csrf=tok_root; ui_access_token=eyJ..." \
  -H "x-csrf-token: tok_root" \
  -d '{"reason": "Suspected crypto mining — excessive CPU usage"}'
```

**Response (200):**

```json
{
  "instance_id": "i_abc12345",
  "status": "terminated",
  "terminated_at": 1748525100
}
```

### 9.3 Set User Quota (Root Only)

```bash
curl -s -X PUT "http://localhost:8000/v1/admin/compute/quotas/alice-uuid" \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root; ui_csrf=tok_root; ui_access_token=eyJ..." \
  -H "x-csrf-token: tok_root" \
  -d '{
    "max_ec2_instances": 10,
    "max_k8s_pods": 15,
    "max_monthly_spend_cents": 25000,
    "allowed_instance_types": ["t3.micro", "t3.small", "t3.medium"],
    "notes": "Upgraded to premium tier"
  }'
```

**Response (200):**

```json
{
  "user_sub": "alice-uuid",
  "max_ec2_instances": 10,
  "max_k8s_pods": 15,
  "max_monthly_spend_cents": 25000,
  "allowed_instance_types": ["t3.micro", "t3.small", "t3.medium"],
  "allowed_k8s_presets": [],
  "is_custom": true,
  "updated_at": 1748525200,
  "updated_by": "root.admin@testdev.local",
  "notes": "Upgraded to premium tier"
}
```

---

## 10. Error Handling Matrix

| HTTP | Error Code | Condition | Response Body | Client Recovery |
|------|-----------|-----------|---------------|-----------------|
| 403 | `FORBIDDEN` | Non-admin calls admin endpoint | `{"detail": "Admin access required"}` | N/A |
| 403 | `ROOT_REQUIRED` | Non-root calls quota set/delete | `{"detail": "Root access required"}` | N/A |
| 404 | `INSTANCE_NOT_FOUND` | Force-terminate with invalid ID | `{"detail": "Instance not found"}` | Refresh list |
| 404 | `POD_NOT_FOUND` | Force-terminate pod with invalid ID | `{"detail": "Pod not found"}` | Refresh list |
| 404 | `USER_NOT_FOUND` | Quota for non-existent user | `{"detail": "User not found"}` | Check user_sub |
| 409 | `ALREADY_TERMINATED` | Force-terminate already terminated instance | `{"detail": "Instance already terminated"}` | Refresh status |
| 409 | `QUOTA_EXCEEDED` | Launch blocked by quota | `{"detail": "Maximum 3 instances allowed"}` | Show quota info |
| 409 | `SPENDING_LIMIT_REACHED` | Launch blocked by spending cap | `{"detail": "Monthly spending limit reached"}` | Show spending |
| 422 | `INVALID_QUOTA` | Quota values out of range | `{"detail": "max_ec2_instances must be 0-100"}` | Fix input |
| 422 | `INVALID_INSTANCE_TYPE` | Allowed type not in platform list | `{"detail": "Unknown instance type: m5.24xlarge"}` | Show valid types |

---

## 11. Observability & Monitoring

### 11.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `admin_compute_force_terminate_total` | Counter | `resource_type` (ec2/k8s), `admin_sub` | Force-termination events |
| `admin_compute_quota_set_total` | Counter | `admin_sub` | Quota modifications |
| `admin_compute_quota_check_total` | Counter | `result` (allowed/denied) | Quota enforcement results |
| `admin_compute_spending_query_latency_seconds` | Histogram | `scope` (platform/per_user) | Spending aggregation latency |
| `admin_compute_instance_list_latency_seconds` | Histogram | `resource_type` | Cross-user listing latency |
| `admin_compute_dashboard_loads_total` | Counter | — | Dashboard page loads |

### 11.2 Structured Log Events

```json
{"logger": "admin_compute", "level": "warn", "event": "force_terminate", "admin_sub": "root-uuid", "target_user": "alice-uuid", "resource_type": "ec2", "instance_id": "i_abc12345", "reason": "resource abuse"}

{"logger": "admin_compute", "level": "info", "event": "quota_set", "admin_sub": "root-uuid", "target_user": "alice-uuid", "max_ec2": 10, "max_k8s": 15, "max_spend_cents": 25000}

{"logger": "admin_compute", "level": "info", "event": "quota_enforced", "user_sub": "alice-uuid", "resource_type": "ec2", "current": 3, "max": 3, "outcome": "denied"}

{"logger": "admin_compute", "level": "info", "event": "spending_query", "scope": "platform", "month": "2026-05", "total_cents": 142500, "duration_ms": 320}
```

### 11.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High force-terminate rate | `rate(admin_compute_force_terminate_total[1h]) > 10` | Warning | Review admin activity |
| Spending query slow | `p99(admin_compute_spending_query_latency_seconds) > 5s` | Warning | Optimize aggregation / add caching |
| Quota denial spike | `rate(admin_compute_quota_check_total{result=denied}[1h]) > 50` | Info | Review if quotas are too restrictive |
| Platform spend threshold | Monthly total > 80% of configured budget | Warning | Notify finance team |

---

## 12. Rollout Plan

### Phase 1: Backend Only (Days 1-2)

- **Feature flag**: `ADMIN_COMPUTE_DASHBOARD_ENABLED=false`
- Deploy admin service + quota table
- Quota enforcement disabled (no launch-time checks)
- Admin endpoints return 404 when flag is off

### Phase 2: Admin API (Days 3-4)

- **Feature flag**: `ADMIN_COMPUTE_DASHBOARD_ENABLED=true` for root users only
- Enable listing, force-terminate, and spending endpoints
- Test with root session in staging
- Validate audit logging for all operations

### Phase 3: Quota Enforcement (Day 5)

- Enable quota checks in launch paths
- Default quotas match current hardcoded limits (no user impact)
- Monitor quota denial rate
- **Rollback**: Remove quota check imports; launchers revert to hardcoded limits

### Phase 4: Frontend + GA (Days 6-8)

- Deploy AdminComputeDashboard page
- Enable for all admins
- Monitor dashboard load performance (spending aggregation can be slow)
- Add caching for spending queries if p99 > 3s

---

## 13. Performance Considerations

### 13.1 Latency Targets

| Operation | Target p50 | Target p99 | Notes |
|-----------|-----------|-----------|-------|
| List all instances | < 100ms | < 500ms | GSI query, paginated |
| Force-terminate | < 50ms | < 200ms | DDB update + audit write |
| Platform spending | < 300ms | < 2s | Full table scan + aggregation |
| Per-user spending | < 500ms | < 3s | Full scan + group by |
| Get quota | < 10ms | < 40ms | Single GetItem |
| Set quota | < 20ms | < 80ms | Single PutItem |
| Instance type stats | < 200ms | < 1s | GSI query + count |

### 13.2 Spending Aggregation Optimization

Platform spending requires scanning the `compute_billing` table. For large-scale deployments:

1. **Materialized summary**: Background task runs hourly, writes `platform_spending_summary` DDB item per month
2. **Dashboard reads summary**: Instead of scanning, reads pre-computed summary
3. **Per-user breakdown cached**: Store top-50 spenders in summary for instant display

### 13.3 DynamoDB Costs

| Operation | RCU | WCU | Notes |
|-----------|-----|-----|-------|
| List instances (GSI) | 5.0 | — | Eventually consistent, paginated |
| Force-terminate | — | 2.0 | Instance update + audit event |
| Spending scan | 50-200 | — | Depends on billing table size |
| Get quota | 0.5 | — | Single item |
| Set quota | — | 1.0 | Single item |

### 13.4 Caching Strategy

| Data | Cache | TTL | Invalidation |
|------|-------|-----|--------------|
| Platform spending | Server-side (in-memory) | 60s | On force-terminate |
| Instance list | React Query | 10s staleTime | On force-terminate |
| Quota | React Query | 30s staleTime | On set/delete |
| Instance type stats | Server-side | 300s | On instance launch/terminate |

### 13.5 Rate Limiting

| Action | Limit | Window | Key |
|--------|-------|--------|-----|
| List instances/pods | 30 | 1 minute | admin_sub |
| Force-terminate | 10 | 1 minute | admin_sub |
| Set quota | 20 | 1 minute | admin_sub |
| Spending queries | 10 | 1 minute | admin_sub |

---

## 14. Acceptance Criteria

1. Admins can view all instances and pods across all users.
2. Admins can force-terminate any user's instance or pod with a reason.
3. Force-terminated users receive an in-app alert with the termination reason.
4. All force-terminate actions are audit-logged with the admin's identity.
5. Root users can set per-user compute quotas (instance limits, spending caps, allowed types).
6. Quotas are enforced on instance/pod launch — users cannot exceed their limits.
7. Deleting a custom quota reverts the user to platform defaults.
8. Platform-wide spending summary shows monthly totals, user count, and resource count.
9. Per-user spending breakdown is available for admin review.
10. Instance type popularity stats are available for capacity planning.
11. Admin dashboard renders with summary cards, instance tables, and spending charts.
12. Non-admin users receive 403 on all admin compute endpoints.

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `require_admin_session` dependency | `app/auth/deps.py` | exists | VERIFIED |
| `require_root_session` dependency | `app/auth/deps.py` | 273 | VERIFIED |
| `Role` enum (USER, ADMIN, ROOT) | `app/auth/roles.py` | 8 | VERIFIED |
| `AdminScope` class | `app/auth/roles.py` | 14 | VERIFIED |
| `audit_event()` | `app/services/alerts.py` | 695 | VERIFIED |
| `write_alert()` | `app/services/alerts.py` | 355 | VERIFIED |
| `e2e_admin_session_setup.py` | project root | exists | VERIFIED |
| DDB table init script | `scripts/local-ddb-init.py` | exists | VERIFIED (1360 lines) |

### Not Yet Implemented (requires new code)

<!-- NOTE: INFRA-003 (EC2 Launcher), INFRA-004 (K8s Launcher), and INFRA-005 (Cost Tracking) are dependencies but do not exist yet. All admin compute dashboard infrastructure is new. -->

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| EC2 launcher (INFRA-003) | `app/services/ec2_launcher.py` | NOT FOUND -- new implementation required |
| K8s launcher (INFRA-004) | `app/services/k8s_launcher.py` | NOT FOUND -- new implementation required |
| Cost tracking (INFRA-005) | `app/services/` | NOT FOUND -- new implementation required |
| `compute_quotas` DDB table | `scripts/local-ddb-init.py` | NOT FOUND -- new table required |
| `app/routers/admin_compute.py` | `app/routers/` | NOT FOUND -- new router required |
| `app/services/admin_compute.py` | `app/services/` | NOT FOUND -- new service required |
| Admin compute router registration | `app/main.py` | NOT FOUND -- needs `app.include_router()` |
| Admin compute settings | `app/core/settings.py` | NOT FOUND -- new settings required |
| `frontend/src/pages/admin/ComputeDashboard.tsx` | `frontend/src/pages/admin/` | NOT FOUND -- new page required |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_admin_compute.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_get_compute_overview_stats`
  - `test_list_all_instances_admin`
  - `test_list_all_containers_admin`
  - `test_get_cost_summary_platform_wide`
  - `test_terminate_instance_admin`
  - `test_non_admin_403`

### Integration Tests

  - Dashboard queries across ec2_instances, k8s_containers, and compute_costs tables
  - Admin can force-terminate any user's instance
  - Platform-wide cost summary aggregates all user costs

### E2E Tests (Playwright)

**File**: `frontend/e2e/admin-compute.spec.ts`
**Test count**: 12

**Auth pattern**: Use `injectAuth(page, "root")` for admin endpoints; use `injectAuth(page, "alice")` for user-level endpoints. All POST/PATCH/DELETE requests include `x-csrf-token` header matching the session's CSRF token.

**Negative tests**:
- 401: Unauthenticated request returns 401
- 403: Non-admin/non-owner access returns 403
- 404: Non-existent resource returns 404
- 409: Conflict on duplicate or already-processed resource
- 422: Invalid input (bad field values, missing required fields)

**Edge cases**:
- Empty result sets return 200 with empty arrays (not 404)
- Pagination cursor works correctly across pages
- Concurrent requests do not produce inconsistent state

### Test Data Requirements

- **DDB seeds**: Seed `ec2_instances, k8s_containers, compute_costs` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `ADMIN_COMPUTE_DASHBOARD_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| INFRA-003 | EC2 Instance Launcher | Aggregates EC2 instance data |
| INFRA-004 | K8s Container Launcher | Aggregates container data |
| INFRA-005 | Compute Cost Tracking | Aggregates cost data |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| (none) | — | No other tickets depend on this one |

### Merge Strategy

**Sequential**

Merge after INFRA-003, INFRA-004, INFRA-005. This ticket depends on tables/services introduced by those tickets.

### Merge Checklist

- [ ] All new DDB tables added to `scripts/local-ddb-init.py` with correct `attr_types` for numeric GSI keys
- [ ] New settings added to `app/core/settings.py` and `.env.local.example`
- [ ] New table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Pydantic models added to `app/models.py`
- [ ] TypeScript types added to `frontend/src/api/types.ts`
- [ ] Route added to `frontend/src/App.tsx`
- [ ] Feature flag defaults to `true` in `.env.local.example`
- [ ] E2E session setup updated if new test identities needed
- [ ] `just restart` completes cleanly with new tables
- [ ] All 12 E2E tests pass with `npx playwright test admin-compute.spec.ts`
