# SYND-001: Syndicate Creation & Membership Management

**Ticket**: SYND-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-12 days

---

## 1. Overview & Motivation

### 1.1 Purpose

SYND-001 introduces Content Provider Syndicates -- groups of creators who band together for bundled subscriptions, shared advertising, and community. This ticket covers the foundational layer: creating syndicates, inviting/requesting membership, transferring admin roles, and dissolving syndicates when empty. All subsequent SYND tickets (002-006) depend on this membership infrastructure.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to create a syndicate so that I can bundle my content with other creators. | POST creates syndicate; creator becomes admin; syndicate appears in "My Syndicates" list. |
| Admin | As a syndicate admin, I want to invite other creators to join my syndicate. | POST creates pending invite; invitee sees invite in their notifications; invite has accept/decline actions. |
| Creator | As a creator, I want to request to join a syndicate so that I can be part of a group. | POST creates join request; admin sees pending requests; request has approve/reject actions. |
| Admin | As an admin, I want to approve or reject join requests so that I control syndicate membership. | POST approve adds member; POST reject removes request; member count updates. |
| Invitee | As an invited creator, I want to accept or decline a syndicate invite. | POST accept adds me as member; POST decline removes invite; admin is notified. |
| Admin | As an admin, I want to transfer admin role to another member so that I can step down. | POST transfer changes admin; old admin becomes regular member; audit trail recorded. |
| Member | As a member, I want to leave a syndicate at any time. | POST leave removes membership; if admin leaves, next oldest member becomes admin. |
| Admin | As an admin, I want to remove a member from the syndicate. | POST remove deletes member record; removed user loses syndicate access immediately. |
| System | When the last member leaves, the syndicate should be automatically dissolved. | Syndicate status set to `archived`; all associated resources marked inactive. |

### 1.3 Why This Is Needed

Individual creators compete for subscribers independently, leading to audience fragmentation. Syndicates enable creators in complementary niches to pool their audiences, offer bundled value, and share advertising costs. The membership layer must be robust because downstream features (bundled subscriptions in SYND-002, revenue splitting in SYND-003, treasury in SYND-004) all depend on accurate, real-time membership state.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Subscription server | `app/routers/subscription_server.py` (1852 lines) | Defines plan/subscription/invoice patterns; SYND-002 will extend with `plan_type=syndicate_bundle` |
| Billing shared | `app/services/billing_shared.py` (260 lines) | Wallet balance, ledger entries, `apply_wallet_delta`; SYND-004 treasury will reuse |
| Profile service | `app/services/profile.py` | `get_profile(user_id)` for display names and avatars in member lists |
| Newsfeed fanout | `app/services/newsfeed_fanout.py` | Fan-out patterns for follower-based content distribution; SYND-005 will adapt |
| Subscription access | `app/services/subscription_access.py` | `has_active_subscription`, `can_access_creator`; SYND-002 will extend for bundle checks |
| Ad placement | `app/services/ad_placement.py` | Ad config, impression recording, revenue credit; SYND-006 will integrate |
| DDB table init | `scripts/local-ddb-init.py` | `TableDef` pattern with GSIs and `attr_types` for numeric sort keys |
| Auth dependencies | `app/auth/deps.py` | `require_ui_session` returns `{user_sub, role, admin_profile}` |

### 2.2 Gaps

1. **No syndicate concept** -- there is no syndicate table, service, router, or frontend page anywhere in the codebase.
2. **No group membership model** -- the platform has individual creator-subscriber relationships but no creator-to-creator group model.
3. **No invite/request flow** -- the closest pattern is contact requests (`app/routers/contacts.py`), but those are 1:1 and lack admin approval workflows.
4. **No admin transfer mechanism** -- role management exists for platform-level roles (USER/ADMIN/ROOT in `app/auth/roles.py`) but not for entity-level ownership.
5. **No auto-dissolution logic** -- no precedent for archiving an entity when all participants leave.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 Syndicates Table

**Table name**: `syndicates` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

**Single-table design** using prefix patterns:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `SYND#{syndicate_id}` | `META` | Syndicate metadata | `name`, `description`, `admin_user_id`, `status`, `member_count`, `created_at`, `updated_at` |
| `SYND#{syndicate_id}` | `MEMBER#{user_id}` | Active member | `user_id`, `display_name`, `role` (admin/member), `joined_at` |
| `SYND#{syndicate_id}` | `INVITE#{user_id}` | Pending invite | `user_id`, `invited_by`, `invited_at`, `status` (pending/accepted/declined) |
| `SYND#{syndicate_id}` | `REQUEST#{user_id}` | Pending join request | `user_id`, `requested_at`, `message`, `status` (pending/approved/rejected) |
| `SYND#{syndicate_id}` | `AUDIT#{timestamp}#{event_id}` | Audit log entry | `actor_id`, `action`, `target_id`, `details`, `ts` |
| `USER_SYND#{user_id}` | `SYND#{syndicate_id}` | User's syndicate membership index | `syndicate_id`, `role`, `joined_at` |

#### 3.1.2 GSIs

**GSI1** (`GSI1PK` / `GSI1SK`): Lookup syndicates by status for discovery.
- `GSI1PK`: `STATUS#{status}` (e.g., `STATUS#active`)
- `GSI1SK`: `created_at` (N) -- enables sorting by creation date
- `attr_types={"created_at": "N"}` required for numeric sort key

**GSI2** (`GSI2PK` / `GSI2SK`): Lookup pending invites/requests for a user.
- `GSI2PK`: `INVITEE#{user_id}` or `REQUESTER#{user_id}`
- `GSI2SK`: `ts` (N) -- sorts by timestamp

#### 3.1.3 TableDef Entry

```python
TableDef(
    "syndicates", "pk", "sk",
    gsis=[
        {"name": "GSI1", "pk": "GSI1PK", "sk": "GSI1SK"},
        {"name": "GSI2", "pk": "GSI2PK", "sk": "GSI2SK"},
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N"},
),
```

#### 3.1.4 Example DynamoDB Items

**Syndicate metadata**:
```json
{
  "pk": "SYND#synd_abc123",
  "sk": "META",
  "syndicate_id": "synd_abc123",
  "name": "Creative Collective",
  "description": "A group of artists sharing subscribers",
  "admin_user_id": "alice@test.local",
  "status": "active",
  "member_count": 3,
  "created_at": 1748520000,
  "updated_at": 1748520000,
  "GSI1PK": "STATUS#active",
  "GSI1SK": 1748520000
}
```

**Member record**:
```json
{
  "pk": "SYND#synd_abc123",
  "sk": "MEMBER#bob@test.local",
  "user_id": "bob@test.local",
  "display_name": "Bob",
  "role": "member",
  "joined_at": 1748520100
}
```

**User syndicate index**:
```json
{
  "pk": "USER_SYND#bob@test.local",
  "sk": "SYND#synd_abc123",
  "syndicate_id": "synd_abc123",
  "syndicate_name": "Creative Collective",
  "role": "member",
  "joined_at": 1748520100
}
```

### 3.2 Backend Service

**New file**: `app/services/syndicates.py` (~350 lines)

```python
"""Syndicate creation, membership, and lifecycle management (SYND-001)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

MAX_MEMBERS = 50
MAX_SYNDICATES_PER_USER = 10


def create_syndicate(
    *,
    creator_sub: str,
    name: str,
    description: str = "",
) -> Dict[str, Any]:
    """Create a new syndicate. Creator becomes admin."""
    syndicate_id = f"synd_{uuid4().hex}"
    ts = now_ts()
    profile = get_profile(creator_sub) or {}

    # Check user isn't already in too many syndicates
    existing = list_user_syndicates(creator_sub)
    if len(existing) >= MAX_SYNDICATES_PER_USER:
        raise ValueError(f"User already in {MAX_SYNDICATES_PER_USER} syndicates")

    meta = {
        "pk": f"SYND#{syndicate_id}",
        "sk": "META",
        "syndicate_id": syndicate_id,
        "name": name,
        "description": description,
        "admin_user_id": creator_sub,
        "status": "active",
        "member_count": 1,
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": "STATUS#active",
        "GSI1SK": ts,
    }
    T.syndicates.put_item(Item=meta)

    # Add creator as admin member
    _add_member(syndicate_id, creator_sub, role="admin", ts=ts, profile=profile)
    return meta


def invite_member(
    *,
    syndicate_id: str,
    admin_sub: str,
    invitee_user_id: str,
) -> Dict[str, Any]:
    """Admin invites a creator to join the syndicate."""
    _require_admin(syndicate_id, admin_sub)
    _require_not_member(syndicate_id, invitee_user_id)
    ts = now_ts()

    invite = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"INVITE#{invitee_user_id}",
        "user_id": invitee_user_id,
        "invited_by": admin_sub,
        "invited_at": ts,
        "status": "pending",
        "GSI2PK": f"INVITEE#{invitee_user_id}",
        "GSI2SK": ts,
    }
    T.syndicates.put_item(Item=invite)
    _write_audit(syndicate_id, admin_sub, "invite_sent", invitee_user_id)
    return invite


def respond_to_invite(
    *,
    syndicate_id: str,
    user_id: str,
    accept: bool,
) -> Dict[str, Any]:
    """Invitee accepts or declines an invite."""
    # ... validates invite exists and is pending
    # If accept: calls _add_member, increments member_count
    # If decline: updates invite status to "declined"
    # Returns updated invite record


def request_to_join(
    *,
    syndicate_id: str,
    user_id: str,
    message: str = "",
) -> Dict[str, Any]:
    """Creator requests to join a syndicate."""
    _require_not_member(syndicate_id, user_id)
    ts = now_ts()

    request_item = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"REQUEST#{user_id}",
        "user_id": user_id,
        "requested_at": ts,
        "message": message,
        "status": "pending",
        "GSI2PK": f"REQUESTER#{user_id}",
        "GSI2SK": ts,
    }
    T.syndicates.put_item(Item=request_item)
    _write_audit(syndicate_id, user_id, "join_requested", user_id)
    return request_item


def approve_request(
    *,
    syndicate_id: str,
    admin_sub: str,
    requester_user_id: str,
) -> Dict[str, Any]:
    """Admin approves a join request."""
    # ... validates admin role, request exists, is pending
    # Calls _add_member, increments member_count
    # Updates request status to "approved"


def reject_request(
    *,
    syndicate_id: str,
    admin_sub: str,
    requester_user_id: str,
) -> Dict[str, Any]:
    """Admin rejects a join request."""
    # ... updates request status to "rejected"


def transfer_admin(
    *,
    syndicate_id: str,
    current_admin_sub: str,
    new_admin_user_id: str,
) -> Dict[str, Any]:
    """Transfer admin role to another member."""
    _require_admin(syndicate_id, current_admin_sub)
    _require_is_member(syndicate_id, new_admin_user_id)

    ts = now_ts()
    # Update META admin_user_id
    # Update old admin MEMBER role to "member"
    # Update new admin MEMBER role to "admin"
    # Update USER_SYND index for both users
    _write_audit(syndicate_id, current_admin_sub, "admin_transferred", new_admin_user_id)


def leave_syndicate(
    *,
    syndicate_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Member leaves the syndicate. If admin leaves, promote next oldest."""
    meta = _get_meta(syndicate_id)
    is_admin = meta["admin_user_id"] == user_id

    # Remove member + user index
    _remove_member(syndicate_id, user_id)

    new_count = meta["member_count"] - 1
    if new_count <= 0:
        # Dissolve syndicate
        _archive_syndicate(syndicate_id)
        return {"dissolved": True}

    if is_admin:
        # Promote next oldest member
        members = list_members(syndicate_id)
        members.sort(key=lambda m: m.get("joined_at", 0))
        new_admin = members[0]["user_id"]
        _promote_to_admin(syndicate_id, new_admin)

    _write_audit(syndicate_id, user_id, "member_left", user_id)
    return {"dissolved": False}


def remove_member(
    *,
    syndicate_id: str,
    admin_sub: str,
    target_user_id: str,
) -> Dict[str, Any]:
    """Admin removes a member from the syndicate."""
    _require_admin(syndicate_id, admin_sub)
    if admin_sub == target_user_id:
        raise ValueError("Admin cannot remove themselves; use leave instead")
    _remove_member(syndicate_id, target_user_id)
    _write_audit(syndicate_id, admin_sub, "member_removed", target_user_id)


def list_members(syndicate_id: str) -> List[Dict[str, Any]]:
    """List all active members of a syndicate."""
    # Query SYND#{syndicate_id} with sk begins_with "MEMBER#"


def list_user_syndicates(user_id: str) -> List[Dict[str, Any]]:
    """List all syndicates a user belongs to."""
    # Query USER_SYND#{user_id} with sk begins_with "SYND#"


def get_syndicate(syndicate_id: str) -> Optional[Dict[str, Any]]:
    """Get syndicate metadata."""
    # get_item pk=SYND#{syndicate_id}, sk=META


def list_pending_invites(user_id: str) -> List[Dict[str, Any]]:
    """List pending invites for a user."""
    # GSI2 query: GSI2PK = INVITEE#{user_id}


def list_pending_requests(syndicate_id: str) -> List[Dict[str, Any]]:
    """List pending join requests for a syndicate (admin only)."""
    # Query SYND#{syndicate_id} with sk begins_with "REQUEST#"
    # Filter status = "pending"


def get_audit_log(syndicate_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Get audit log for a syndicate."""
    # Query SYND#{syndicate_id} with sk begins_with "AUDIT#"
    # ScanIndexForward=False for newest first


# --- Internal helpers ---

def _add_member(syndicate_id, user_id, *, role="member", ts=None, profile=None):
    """Add member record + user index record."""

def _remove_member(syndicate_id, user_id):
    """Delete member record + user index record. Decrement member_count."""

def _require_admin(syndicate_id, user_id):
    """Raise 403 if user is not the syndicate admin."""

def _require_is_member(syndicate_id, user_id):
    """Raise 404 if user is not a member."""

def _require_not_member(syndicate_id, user_id):
    """Raise 409 if user is already a member."""

def _get_meta(syndicate_id):
    """Get META item or raise 404."""

def _archive_syndicate(syndicate_id):
    """Set status to archived, update GSI1PK."""

def _promote_to_admin(syndicate_id, user_id):
    """Update META admin_user_id + member role to admin."""

def _write_audit(syndicate_id, actor_id, action, target_id, details=None):
    """Write audit log entry."""
```

### 3.3 Backend Router

**New file**: `app/routers/syndicates.py` (~200 lines)

```python
"""Syndicate management router (SYND-001)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from app.auth.deps import require_ui_session
from app.services import syndicates as svc

router = APIRouter(prefix="/ui/syndicates", tags=["syndicates"])
```

### 3.4 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/syndicates` | `require_ui_session` | Create a new syndicate |
| `GET` | `/ui/syndicates` | `require_ui_session` | List user's syndicates |
| `GET` | `/ui/syndicates/{syndicate_id}` | `require_ui_session` | Get syndicate details (metadata + members) |
| `POST` | `/ui/syndicates/{syndicate_id}/invite` | `require_ui_session` | Invite a creator (admin only) |
| `POST` | `/ui/syndicates/{syndicate_id}/invite/respond` | `require_ui_session` | Accept or decline invite |
| `POST` | `/ui/syndicates/{syndicate_id}/request` | `require_ui_session` | Request to join syndicate |
| `POST` | `/ui/syndicates/{syndicate_id}/request/{user_id}/approve` | `require_ui_session` | Approve join request (admin only) |
| `POST` | `/ui/syndicates/{syndicate_id}/request/{user_id}/reject` | `require_ui_session` | Reject join request (admin only) |
| `POST` | `/ui/syndicates/{syndicate_id}/transfer-admin` | `require_ui_session` | Transfer admin to another member |
| `POST` | `/ui/syndicates/{syndicate_id}/leave` | `require_ui_session` | Leave syndicate |
| `POST` | `/ui/syndicates/{syndicate_id}/remove/{user_id}` | `require_ui_session` | Remove member (admin only) |
| `GET` | `/ui/syndicates/{syndicate_id}/members` | `require_ui_session` | List syndicate members |
| `GET` | `/ui/syndicates/{syndicate_id}/requests` | `require_ui_session` | List pending join requests (admin only) |
| `GET` | `/ui/syndicates/{syndicate_id}/audit` | `require_ui_session` | Get audit log (admin only) |
| `GET` | `/ui/syndicates/invites` | `require_ui_session` | List pending invites for current user |
| `GET` | `/ui/syndicates/discover` | `require_ui_session` | List active syndicates for discovery |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Syndicates (SYND-001) --

class SyndicateCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)

class SyndicateInviteIn(BaseModel):
    user_id: str

class SyndicateInviteRespondIn(BaseModel):
    accept: bool

class SyndicateJoinRequestIn(BaseModel):
    message: str = Field(default="", max_length=500)

class SyndicateTransferAdminIn(BaseModel):
    new_admin_user_id: str

class SyndicateMemberOut(BaseModel):
    user_id: str
    display_name: str = ""
    avatar_url: Optional[str] = None
    role: str  # "admin" or "member"
    joined_at: int = 0

class SyndicateOut(BaseModel):
    syndicate_id: str
    name: str
    description: str = ""
    admin_user_id: str
    status: str
    member_count: int = 0
    created_at: int = 0
    updated_at: int = 0
    members: List[SyndicateMemberOut] = Field(default_factory=list)

class SyndicateInviteOut(BaseModel):
    syndicate_id: str
    syndicate_name: str = ""
    user_id: str
    invited_by: str
    invited_at: int = 0
    status: str

class SyndicateRequestOut(BaseModel):
    syndicate_id: str
    user_id: str
    display_name: str = ""
    requested_at: int = 0
    message: str = ""
    status: str

class SyndicateAuditOut(BaseModel):
    event_id: str
    actor_id: str
    action: str
    target_id: str = ""
    details: Optional[Dict[str, Any]] = None
    ts: int = 0
```

### 3.6 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/syndicates/SyndicatesPage.tsx` | Main syndicates list page | ~200 |
| `frontend/src/pages/syndicates/SyndicateDetailPage.tsx` | Syndicate detail with members, invites, requests | ~250 |
| `frontend/src/pages/syndicates/CreateSyndicateDialog.tsx` | Dialog for creating a new syndicate | ~80 |
| `frontend/src/pages/syndicates/InviteMemberDialog.tsx` | Dialog for inviting a member | ~60 |
| `frontend/src/pages/syndicates/PendingInvitesCard.tsx` | Card showing pending invites for current user | ~80 |
| `frontend/src/api/endpoints/syndicates.ts` | API client wrappers | ~100 |

**Component tree**:

```
SyndicatesPage
├── Card: "My Syndicates"
│   ├── CreateSyndicateDialog (Button: "Create Syndicate")
│   └── SyndicateList
│       └── For each syndicate:
│           ├── Name, description, member count
│           ├── Role badge (Admin / Member)
│           └── Link → SyndicateDetailPage
├── Card: "Pending Invites"
│   └── PendingInvitesCard
│       └── For each invite:
│           ├── Syndicate name, invited by
│           ├── Button: "Accept"
│           └── Button: "Decline"
└── Card: "Discover Syndicates"
    └── Public syndicate list with "Request to Join" buttons

SyndicateDetailPage
├── Header: Syndicate name, description, status
├── Tabs
│   ├── Members Tab
│   │   ├── Member list with roles, joined dates
│   │   ├── InviteMemberDialog (admin only)
│   │   ├── "Remove" button per member (admin only)
│   │   └── "Transfer Admin" button (admin only)
│   ├── Requests Tab (admin only)
│   │   └── Pending request list with Approve/Reject buttons
│   └── Audit Tab (admin only)
│       └── Audit log timeline
├── "Leave Syndicate" button (always visible)
└── Dissolution warning when member_count = 1
```

### 3.7 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/syndicates" element={<SyndicatesPage />} />
<Route path="/syndicates/:syndicateId" element={<SyndicateDetailPage />} />
```

### 3.8 Sidebar Navigation

Add "Syndicates" entry to the Commerce/Community group in `Sidebar.tsx` and `AppShell.tsx` (MobileSidebar) with `Users` icon from lucide-react. Add to `MORE_LINKS` in `MobileNav.tsx`.

### 3.9 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/syndicates.py` | Core syndicate membership service | ~350 |
| `app/routers/syndicates.py` | REST API endpoints | ~200 |
| `frontend/src/pages/syndicates/SyndicatesPage.tsx` | Syndicates list page | ~200 |
| `frontend/src/pages/syndicates/SyndicateDetailPage.tsx` | Detail page | ~250 |
| `frontend/src/pages/syndicates/CreateSyndicateDialog.tsx` | Create dialog | ~80 |
| `frontend/src/pages/syndicates/InviteMemberDialog.tsx` | Invite dialog | ~60 |
| `frontend/src/pages/syndicates/PendingInvitesCard.tsx` | Pending invites | ~80 |
| `frontend/src/api/endpoints/syndicates.ts` | API wrappers | ~100 |
| `frontend/e2e/syndicates-membership.spec.ts` | E2E tests | ~450 |

### 3.10 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `syndicates_router` |
| `app/models.py` | Add Syndicate* Pydantic models |
| `app/core/settings.py` | Add `syndicates_table_name` setting |
| `app/core/tables.py` | Add `T.syndicates` table handle |
| `scripts/local-ddb-init.py` | Add `syndicates` TableDef with GSIs |
| `frontend/src/api/types.ts` | Add Syndicate TypeScript interfaces |
| `frontend/src/App.tsx` | Add syndicate routes |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Syndicates" nav entry |
| `frontend/src/components/layout/AppShell.tsx` | Add to mobile sidebar |
| `frontend/src/components/layout/MobileNav.tsx` | Add to MORE_LINKS |

---

## 4. Auto-Promotion & Dissolution Logic

### 4.1 Admin Leaves -- Promotion Rules

When the admin calls `leave_syndicate`:

1. Query all `MEMBER#` items for the syndicate.
2. Exclude the departing admin.
3. Sort remaining members by `joined_at` ascending (oldest first).
4. Promote the oldest member to admin:
   - Update `META.admin_user_id`
   - Update member's `MEMBER#` item `role` to `"admin"`
   - Update member's `USER_SYND#` index `role` to `"admin"`
5. Write audit entry: `action=admin_auto_promoted`.

### 4.2 Last Member Leaves -- Dissolution

When `member_count` reaches 0 after a leave/remove:

1. Update `META.status` to `"archived"`.
2. Update `META.GSI1PK` to `"STATUS#archived"`.
3. Write audit entry: `action=syndicate_dissolved`.
4. Future: SYND-004 treasury will handle fund return before dissolution.

### 4.3 Edge Cases

- Admin removes the only other member, then leaves → dissolution.
- Admin transfers to member B, then B leaves → next oldest member after B is promoted.
- Two members join at the exact same second → tie-break by `user_id` alphabetically.
- User invited AND requested → invite takes precedence (delete request on accept).

---

## 5. E2E Test Plan

**File**: `frontend/e2e/syndicates-membership.spec.ts`

### Section 423: Syndicate Creation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 423.1 | Alice creates a syndicate | POST `/ui/syndicates`; 200; response has `syndicate_id`, `admin_user_id=alice`, `member_count=1` |
| 423.2 | Syndicate appears in user's list | GET `/ui/syndicates`; response includes created syndicate with role `admin` |
| 423.3 | Syndicate detail includes creator as admin member | GET `/ui/syndicates/{id}`; members array has one entry with `role=admin` |
| 423.4 | Name validation rejects empty name | POST with `name=""`; 422 response |

### Section 424: Invite & Join Request API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 424.1 | Admin invites Bob to syndicate | POST `/ui/syndicates/{id}/invite`; 200; invite `status=pending` |
| 424.2 | Bob sees pending invite | GET `/ui/syndicates/invites`; response includes syndicate invite |
| 424.3 | Bob accepts invite and becomes member | POST respond with `accept=true`; GET members; Bob present with `role=member`; `member_count=2` |
| 424.4 | Charlie requests to join | POST `/ui/syndicates/{id}/request`; 200; request `status=pending` |
| 424.5 | Admin approves Charlie's request | POST approve; GET members; Charlie present; `member_count=3` |

### Section 425: Admin Transfer & Member Removal API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 425.1 | Admin transfers role to Bob | POST transfer-admin; GET syndicate; `admin_user_id=bob` |
| 425.2 | Old admin (Alice) is now regular member | GET members; Alice has `role=member` |
| 425.3 | New admin (Bob) removes Charlie | POST remove; GET members; Charlie absent; `member_count=2` |
| 425.4 | Non-admin cannot remove members | Alice POST remove → 403 |

### Section 426: Leave & Auto-Dissolution API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 426.1 | Alice leaves syndicate | POST leave; 200; Alice no longer in members list |
| 426.2 | Bob auto-promoted to admin after Alice left (when Bob is admin, Alice leaves, check next oldest) | Create fresh syndicate with Alice as admin, add Bob, add Charlie. Transfer admin to Alice. Alice leaves. Bob (next oldest) becomes admin |
| 426.3 | Admin leaves, next oldest member promoted | Create syndicate, add 2 members. Admin leaves. Oldest member is new admin |
| 426.4 | Last member leaves, syndicate dissolved | Create syndicate, admin leaves. GET returns `status=archived` |
| 426.5 | Audit log records all membership events | GET audit; entries include `syndicate_created`, `invite_sent`, `member_joined`, `member_left`, `syndicate_dissolved` |

**Total E2E tests: 18**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| All `/ui/syndicates/*` | `require_ui_session` | Any authenticated user |
| Admin-only endpoints (invite, approve, reject, remove, transfer) | `require_ui_session` | Must be syndicate admin (checked by service layer) |
| Audit log | `require_ui_session` | Admin only |

### 6.2 Authorization Enforcement

- Admin checks are performed in the service layer (`_require_admin`), not in middleware. This allows the router to return proper 403 responses with descriptive error messages.
- Member existence checks prevent duplicate joins and invalid removals.
- Admin cannot remove themselves (must use `leave` which triggers promotion/dissolution).

### 6.3 Rate Limiting

- Invite endpoint: max 20 invites per syndicate per hour (prevent spam).
- Join request endpoint: max 10 requests per user per hour.
- Syndicate creation: max 5 per user per day.
- All endpoints inherit global rate limiter.

### 6.4 Input Validation

- `name`: 2-100 characters, stripped of leading/trailing whitespace.
- `description`: 0-500 characters.
- `user_id` in invites/requests: validated as non-empty string.
- `message` in join requests: 0-500 characters.

### 6.5 Data Privacy

- Member lists are visible to all authenticated users (syndicates are public entities).
- Audit logs are restricted to admin only (contain action details with user IDs).
- Pending invites are only visible to the invitee and the syndicate admin.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/profile.py` | Exists | Display names and avatars in member lists |
| `app/auth/deps.py` | Exists | `require_ui_session` for all endpoints |
| `app/core/tables.py` | Exists (modify) | Add `T.syndicates` handle |
| `scripts/local-ddb-init.py` | Exists (modify) | Add `syndicates` table definition |
| SYND-002 | Not started | Depends on this ticket for membership queries |
| SYND-003 | Not started | Depends on this ticket for member list and admin checks |
| SYND-004 | Not started | Depends on this ticket for member leave/dissolution hooks |
| SYND-005 | Not started | Depends on this ticket for syndicate metadata and member list |
| SYND-006 | Not started | Depends on this ticket for admin authorization checks |

---

## 8. Acceptance Criteria

1. Creators can create syndicates and are automatically set as admin.
2. Admin can invite creators; invitees can accept or decline.
3. Creators can request to join; admin can approve or reject.
4. Admin can transfer admin role to any current member.
5. Members can leave at any time; admin role auto-promotes on admin departure.
6. Syndicate dissolves (archives) when last member leaves.
7. Admin can remove non-admin members.
8. All membership changes are recorded in the audit log.
9. User's syndicate list shows all syndicates they belong to with their role.
10. All 18 E2E tests pass.

---


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_syndicates.py`

| # | Function | Assertion |
|---|----------|-----------|
| 1 | `test_create_syndicate_writes_meta_and_member` | Create syndicate writes meta and member verified |
| 2 | `test_create_syndicate_creator_is_admin` | Create syndicate creator is admin verified |
| 3 | `test_invite_creates_pending_invite` | Invite creates pending invite verified |
| 4 | `test_accept_invite_adds_member` | Accept invite adds member verified |
| 5 | `test_decline_invite_updates_status` | Decline invite updates status verified |
| 6 | `test_join_request_creates_pending_request` | Join request creates pending request verified |
| 7 | `test_approve_request_adds_member` | Approve request adds member verified |
| 8 | `test_reject_request_updates_status` | Reject request updates status verified |
| 9 | `test_leave_syndicate_removes_member` | Leave syndicate removes member verified |
| 10 | `test_auto_dissolution_on_last_member_leave` | Auto dissolution on last member leave verified |

**Mocking**: All DynamoDB tables mocked via `moto`; profile lookups patched via `unittest.mock.patch`.

### Integration Tests

1. Create syndicate -> invite member -> accept -> member count increments -> member appears in list
2. Admin transfer -> old admin becomes member -> new admin can invite
3. Last member leaves -> syndicate status=archived -> discovery query excludes it

### E2E Tests (Playwright)

**File**: `frontend/e2e/syndicates.spec.ts`
**Sections**: 1-5 (15 tests)

**Auth pattern**: `injectAuth(page, identity)` for cookie auth; `x-csrf-token` header for POST/PUT/DELETE mutations.

| # | Test | Assertion |
|---|------|-----------|
| 1 | Create syndicate | 201; syndicate appears in My Syndicates |
| 2 | Invite member | 201; invitee sees pending invite |
| 3 | Accept invite | 200; member added; count increments |
| 4 | Decline invite | 200; invite status=declined |
| 5 | Join request | 201; admin sees pending request |
| 6 | Approve join request | 200; requester added as member |
| 7 | Leave syndicate | 200; membership removed |
| 8 | Transfer admin | 200; new admin can manage |
| 9 | Remove member | 200; member removed from list |
| 10 | Auto-dissolution | Last leave archives syndicate |

**Negative tests**: 400 self-invite, 404 syndicate not found, 403 non-admin actions, 409 already member, 409 already invited

**Edge cases**: Invite expired user, concurrent join requests, admin leaves with 1 other member (auto-promote)

### Test Data Requirements

- **DDB seeds**: New syndicates table created by local-ddb-init.py; user profiles for Alice/Bob/Charlie
- **Test users**: Alice (admin), Bob (invitee/member), Charlie (join requester)

### CI/Pipeline Considerations

- **Feature flags**: SYNDICATES_ENABLED=true
- **Serial execution**: All subsequent SYND tests depend on syndicates table existing
- **Retry safety**: All tests are idempotent; use unique per-run identifiers (`TS` suffix) to avoid cross-run conflicts.

---

## Dependencies & Merge Safety

### Depends On

| Ticket/Component | Reason |
|------------------|--------|
| Auth system (existing) | require_ui_session for authenticated endpoints |
| Profile service (existing) | get_profile() for member display names |

### Depended On By

| Ticket | Reason |
|--------|--------|
| SYND-002 | Bundled subscriptions require membership infrastructure |
| SYND-003 | Revenue splitting requires member roster |
| SYND-004 | Treasury requires syndicate membership for contributions |
| SYND-005 | Syndicate page requires syndicate existence and member list |
| SYND-006 | Advertising requires syndicate treasury and membership |

### Merge Strategy: **Sequential**

Foundation for all SYND-* tickets. Must merge first. Creates new syndicates DDB table.

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
| No syndicate code exists in codebase | All files | — | VERIFIED: grep "syndicate" returns zero results in app/ and frontend/src/ |
| subscription_server.py exists (1852 lines) | `app/routers/subscription_server.py` | — | VERIFIED |
| billing_shared.py exists (260 lines) | `app/services/billing_shared.py` | — | VERIFIED |
| profile service exists | `app/services/profile.py` | — | VERIFIED (345 lines) |
| newsfeed_fanout.py exists | `app/services/newsfeed_fanout.py` | — | VERIFIED (173 lines) |
| subscription_access.py exists | `app/services/subscription_access.py` | — | VERIFIED (82 lines) |
| ad_placement.py exists | `app/services/ad_placement.py` | — | VERIFIED (342 lines) |
| Contact requests in app/services/contacts.py | `app/routers/contacts.py` | — | **CORRECTED** — contacts is a router, not a service |
| require_ui_session auth dependency | `app/auth/deps.py` | — | VERIFIED |
| Role enum (USER/ADMIN/ROOT) | `app/auth/roles.py` | — | VERIFIED |
| DDB table init pattern | `scripts/local-ddb-init.py` | — | VERIFIED (1359 lines, TableDef pattern) |
