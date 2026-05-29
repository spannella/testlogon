# DELEGATE-001: Delegate Management & Permissions

**Ticket**: DELEGATE-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-12 days

---

## 1. Overview & Motivation

### 1.1 Purpose

DELEGATE-001 introduces the Provider Delegation system -- a mechanism for content creators to delegate management of their chat, newsfeed, and broadcast capabilities to other users (assistants, managers, social media teams). This ticket covers the foundational layer: adding/removing delegates, defining granular permission levels, preset permission sets, and a comprehensive audit log of all delegated actions. All subsequent DELEGATE tickets (002-005) depend on this permission infrastructure.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to add a delegate by user ID or email so that someone else can help manage my account. | POST creates delegate record; delegate appears in "My Delegates" list; delegate receives notification. |
| Creator | As a creator, I want to assign granular permissions to each delegate so that I control exactly what they can do. | POST update with permission list; only specified capabilities are granted; delegate sees restricted UI. |
| Creator | As a creator, I want to use permission presets ("Full Manager", "Chat Agent") so that I can quickly assign common roles. | Preset selection populates permission list; preset can be customized after selection. |
| Creator | As a creator, I want to revoke a delegate's access instantly so that I can protect my account. | DELETE removes delegate record; delegate loses access immediately; in-flight SSE connections are closed. |
| Creator | As a creator, I want to see an audit log of all delegated actions so that I know what happened on my behalf. | GET returns timestamped entries with actor, action type, and target details. |
| Delegate | As a delegate, I want to see which creators I manage so that I can switch between accounts. | GET returns list of creators who have delegated to me with my permission set for each. |
| Delegate | As a delegate, I want to accept or decline a delegation invite so that I control my workload. | POST accept/decline; creator notified; delegate only appears as active after accepting. |
| Admin | As a platform admin, I want to view delegation relationships for compliance auditing. | GET admin endpoint returns all delegates for a given creator. |

### 1.3 Why This Is Needed

Creators with large audiences cannot personally respond to every DM, moderate every broadcast chat session, or manage their newsfeed content calendar. They need trusted team members who can act on their behalf with controlled, auditable permissions. Without delegation, creators either share their login credentials (a security risk) or cannot scale their operations. The delegation system provides a secure, auditable alternative that preserves creator control while enabling team-based content management.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Messaging router | `app/routers/messaging.py` (~1200 lines) | Endpoints for DMs, group chats, mass messages; will need `on_behalf_of` parameter in DELEGATE-002 |
| Newsfeed router | `app/routers/newsfeed.py` (~800 lines) | Post CRUD, comments, reactions; will need delegation support in DELEGATE-003 |
| Broadcast chat store | `app/services/broadcast_chat_store.py` | Chat message CRUD, muting, rate limiting; will need moderator support in DELEGATE-004 |
| Broadcast store | `app/services/broadcast_store.py` | Broadcast session lifecycle; will need delegation in DELEGATE-004 |
| API key service | `app/services/api_keys.py` (~400 lines) | Key creation, capabilities, IP rules, rate limits; DELEGATE-005 will extend with `delegation_scope` |
| Auth dependencies | `app/auth/deps.py` | `require_ui_session` returns `{user_sub, role, admin_profile}`; delegation auth will layer on top |
| Profile service | `app/services/profile.py` | `get_profile(user_id)` for display names and avatars in delegate lists |
| Contacts service | `app/services/contacts.py` | Contact request pattern (invite/accept/decline) -- closest existing model for delegation invites |
| DDB table init | `scripts/local-ddb-init.py` | `TableDef` pattern with GSIs and `attr_types` for numeric sort keys |
| Newsfeed fanout | `app/services/newsfeed_fanout.py` | Fan-out patterns for follower-based content; DELEGATE-003 will use for delegated posts |
| Broadcast SSE | `app/services/broadcast_sse.py` | SSE event streaming; DELEGATE-002/004 will extend for delegate subscriptions |

### 2.2 Gaps

1. **No delegation concept** -- there is no delegate table, service, router, or frontend page anywhere in the codebase.
2. **No on-behalf-of model** -- all endpoints assume the authenticated user is the actor; there is no mechanism to act as another user with permission.
3. **No permission-set abstraction** -- platform roles (USER/ADMIN/ROOT) are coarse-grained and global; there is no entity-level, per-capability permission system.
4. **No delegation audit trail** -- the existing audit log patterns (e.g., syndicate audit in SYND-001) are entity-scoped, not cross-entity.
5. **No invite/accept flow for delegation** -- contacts have a request flow, but delegation requires creator-initiated invites with permission assignment.
6. **No delegate-aware SSE** -- SSE streams (`broadcast_sse.py`, messaging SSE) only deliver events to the entity owner, not to delegates.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 Delegates Table

**Table name**: `delegates` (new table)
**PK**: `pk` (S), **SK**: `sk` (S)

**Single-table design** using prefix patterns:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `CREATOR#{creator_id}` | `DELEGATE#{delegate_id}` | Active delegate relationship | `delegate_id`, `creator_id`, `permissions`, `preset`, `status`, `label`, `show_delegate_tag`, `delegate_tag_format`, `invited_at`, `accepted_at`, `updated_at` |
| `CREATOR#{creator_id}` | `SETTINGS` | Creator delegation settings | `require_acceptance`, `max_delegates`, `default_preset`, `delegate_tag_enabled`, `delegate_tag_format` |
| `CREATOR#{creator_id}` | `AUDIT#{ts}#{event_id}` | Audit log entry | `event_id`, `actor_id`, `actor_type` (creator/delegate/system), `action`, `target_id`, `details`, `ts` |

#### 3.1.2 GSIs

**GSI1** (`GSI1PK` / `GSI1SK`): Lookup creators by delegate (so delegates can list their creators).
- `GSI1PK`: `DELEGATE#{delegate_id}`
- `GSI1SK`: `accepted_at` (N) -- enables sorting by acceptance date
- Projected: ALL

**GSI2** (`GSI2PK` / `GSI2SK`): Lookup audit entries by actor across all creators.
- `GSI2PK`: `ACTOR#{actor_id}`
- `GSI2SK`: `ts` (N) -- enables chronological ordering
- Projected: ALL

#### 3.1.3 TableDef Entry

```python
TableDef(
    "delegates", "pk", "sk",
    gsis=[
        {"name": "GSI1", "pk": "GSI1PK", "sk": "GSI1SK"},
        {"name": "GSI2", "pk": "GSI2PK", "sk": "GSI2SK"},
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N"},
),
```

#### 3.1.4 Example DynamoDB Items

**Delegate relationship**:
```json
{
  "pk": "CREATOR#alice@test.local",
  "sk": "DELEGATE#bob@test.local",
  "delegate_id": "bob@test.local",
  "creator_id": "alice@test.local",
  "permissions": ["chat_read", "chat_respond", "feed_read", "feed_post"],
  "preset": "content_manager",
  "status": "active",
  "label": "Bob - Social Media Manager",
  "show_delegate_tag": true,
  "delegate_tag_format": "[via @{delegate_name}]",
  "invited_at": 1748520000,
  "accepted_at": 1748520300,
  "updated_at": 1748520300,
  "GSI1PK": "DELEGATE#bob@test.local",
  "GSI1SK": 1748520300
}
```

**Creator delegation settings**:
```json
{
  "pk": "CREATOR#alice@test.local",
  "sk": "SETTINGS",
  "require_acceptance": true,
  "max_delegates": 10,
  "default_preset": "chat_agent",
  "delegate_tag_enabled": true,
  "delegate_tag_format": "[via @{delegate_name}]"
}
```

**Audit log entry**:
```json
{
  "pk": "CREATOR#alice@test.local",
  "sk": "AUDIT#1748520400#evt_abc123",
  "event_id": "evt_abc123",
  "actor_id": "bob@test.local",
  "actor_type": "delegate",
  "action": "chat_message_sent",
  "target_id": "conv_xyz789",
  "details": {"message_id": "m_abc", "conversation_id": "conv_xyz789"},
  "ts": 1748520400,
  "GSI2PK": "ACTOR#bob@test.local",
  "GSI2SK": 1748520400
}
```

### 3.2 Permission Model

#### 3.2.1 Permission Definitions

| Permission | Scope | Description |
|------------|-------|-------------|
| `chat_read` | Messaging | View creator's DM conversation list and message history |
| `chat_respond` | Messaging | Send messages as/on behalf of creator in DMs and group chats |
| `feed_read` | Newsfeed | View creator's feed drafts, published posts, and analytics |
| `feed_post` | Newsfeed | Create, edit, delete posts on creator's newsfeed |
| `feed_moderate` | Newsfeed | Hide, pin, delete comments on creator's posts |
| `broadcast_moderate` | Broadcast | Moderate broadcast chat: pin, delete, mute, ban users |
| `broadcast_control` | Broadcast | Start, stop, schedule broadcasts on creator's behalf |

#### 3.2.2 Permission Presets

| Preset Key | Label | Permissions |
|------------|-------|-------------|
| `full_manager` | Full Manager | All 7 permissions |
| `chat_agent` | Chat Agent | `chat_read`, `chat_respond` |
| `content_manager` | Content Manager | `feed_read`, `feed_post`, `feed_moderate` |
| `broadcast_moderator` | Broadcast Moderator | `broadcast_moderate` |
| `broadcast_manager` | Broadcast Manager | `broadcast_moderate`, `broadcast_control` |
| `read_only` | Read Only | `chat_read`, `feed_read` |

### 3.3 Backend Service

**New file**: `app/services/delegates.py` (~400 lines)

```python
"""Delegate management and permission enforcement (DELEGATE-001)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4
from app.core.tables import T
from app.core.time import now_ts
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

MAX_DELEGATES_PER_CREATOR = 20
VALID_PERMISSIONS = {
    "chat_read", "chat_respond",
    "feed_read", "feed_post", "feed_moderate",
    "broadcast_moderate", "broadcast_control",
}
PERMISSION_PRESETS = {
    "full_manager": list(VALID_PERMISSIONS),
    "chat_agent": ["chat_read", "chat_respond"],
    "content_manager": ["feed_read", "feed_post", "feed_moderate"],
    "broadcast_moderator": ["broadcast_moderate"],
    "broadcast_manager": ["broadcast_moderate", "broadcast_control"],
    "read_only": ["chat_read", "feed_read"],
}


def add_delegate(
    *,
    creator_id: str,
    delegate_id: str,
    permissions: List[str],
    preset: Optional[str] = None,
    label: str = "",
) -> Dict[str, Any]:
    """Creator adds a delegate with specified permissions."""
    _validate_permissions(permissions)
    _require_not_self(creator_id, delegate_id)
    _require_not_already_delegate(creator_id, delegate_id)
    _enforce_delegate_limit(creator_id)

    ts = now_ts()
    settings = get_creator_settings(creator_id)
    status = "pending" if settings.get("require_acceptance", True) else "active"

    item = {
        "pk": f"CREATOR#{creator_id}",
        "sk": f"DELEGATE#{delegate_id}",
        "delegate_id": delegate_id,
        "creator_id": creator_id,
        "permissions": permissions,
        "preset": preset or _detect_preset(permissions),
        "status": status,
        "label": label,
        "show_delegate_tag": settings.get("delegate_tag_enabled", True),
        "delegate_tag_format": settings.get("delegate_tag_format", "[via @{delegate_name}]"),
        "invited_at": ts,
        "accepted_at": ts if status == "active" else 0,
        "updated_at": ts,
        "GSI1PK": f"DELEGATE#{delegate_id}",
        "GSI1SK": ts if status == "active" else 0,
    }
    T.delegates.put_item(Item=item)
    _write_audit(creator_id, creator_id, "creator", "delegate_invited", delegate_id,
                 {"permissions": permissions, "preset": preset})
    return item


def respond_to_invite(
    *,
    creator_id: str,
    delegate_id: str,
    accept: bool,
) -> Dict[str, Any]:
    """Delegate accepts or declines a delegation invite."""
    # Validates invite exists and is pending
    # If accept: set status=active, accepted_at=now, update GSI1SK
    # If decline: delete the delegate record
    # Write audit entry


def update_delegate_permissions(
    *,
    creator_id: str,
    delegate_id: str,
    permissions: List[str],
    preset: Optional[str] = None,
) -> Dict[str, Any]:
    """Creator updates a delegate's permissions."""
    _validate_permissions(permissions)
    # Update permissions list and preset on delegate record
    # Write audit entry


def revoke_delegate(
    *,
    creator_id: str,
    delegate_id: str,
) -> None:
    """Creator revokes a delegate's access. Immediate effect."""
    # Delete delegate record
    # Write audit entry: delegate_revoked


def list_delegates(creator_id: str) -> List[Dict[str, Any]]:
    """List all delegates for a creator."""
    # Query CREATOR#{creator_id} with sk begins_with "DELEGATE#"


def list_managed_creators(delegate_id: str) -> List[Dict[str, Any]]:
    """List all creators a delegate manages."""
    # GSI1 query: GSI1PK = DELEGATE#{delegate_id}


def get_delegate(creator_id: str, delegate_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific delegate relationship."""
    # get_item pk=CREATOR#{creator_id}, sk=DELEGATE#{delegate_id}


def check_delegate_permission(
    *,
    creator_id: str,
    delegate_id: str,
    required_permission: str,
) -> bool:
    """Check if delegate has a specific permission for a creator."""
    item = get_delegate(creator_id, delegate_id)
    if not item or item.get("status") != "active":
        return False
    return required_permission in item.get("permissions", [])


def require_delegate_permission(
    *,
    creator_id: str,
    delegate_id: str,
    required_permission: str,
) -> Dict[str, Any]:
    """Raise 403 if delegate lacks the required permission."""
    item = get_delegate(creator_id, delegate_id)
    if not item or item.get("status") != "active":
        raise HTTPException(403, "Not a delegate for this creator")
    if required_permission not in item.get("permissions", []):
        raise HTTPException(403, f"Missing delegation permission: {required_permission}")
    return item


def get_creator_settings(creator_id: str) -> Dict[str, Any]:
    """Get or create default creator delegation settings."""
    # get_item pk=CREATOR#{creator_id}, sk=SETTINGS
    # Return defaults if not found


def update_creator_settings(
    *,
    creator_id: str,
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    """Update creator delegation settings."""
    # Validate and update settings


def get_audit_log(
    creator_id: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Get delegation audit log for a creator."""
    # Query CREATOR#{creator_id} with sk begins_with "AUDIT#"
    # ScanIndexForward=False for newest first


def get_delegate_audit_log(
    delegate_id: str,
    *,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Get all audit entries for a specific delegate across all creators."""
    # GSI2 query: GSI2PK = ACTOR#{delegate_id}


# --- Internal helpers ---

def _validate_permissions(permissions: List[str]) -> None:
    """Raise 400 if any permission is invalid."""

def _require_not_self(creator_id: str, delegate_id: str) -> None:
    """Raise 400 if creator tries to delegate to themselves."""

def _require_not_already_delegate(creator_id: str, delegate_id: str) -> None:
    """Raise 409 if delegate relationship already exists."""

def _enforce_delegate_limit(creator_id: str) -> None:
    """Raise 400 if creator has too many delegates."""

def _detect_preset(permissions: List[str]) -> Optional[str]:
    """Detect which preset matches the given permission set, or None."""

def _write_audit(creator_id, actor_id, actor_type, action, target_id, details=None):
    """Write audit log entry to delegates table."""
```

### 3.4 Backend Router

**New file**: `app/routers/delegates.py` (~250 lines)

```python
"""Delegate management router (DELEGATE-001)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from app.auth.deps import require_ui_session
from app.services import delegates as svc

router = APIRouter(prefix="/ui/delegates", tags=["delegates"])
```

### 3.5 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/delegates` | `require_ui_session` | Add a new delegate (creator only) |
| `GET` | `/ui/delegates` | `require_ui_session` | List current user's delegates (as creator) |
| `GET` | `/ui/delegates/managed` | `require_ui_session` | List creators the current user delegates for |
| `GET` | `/ui/delegates/{delegate_id}` | `require_ui_session` | Get specific delegate details |
| `PUT` | `/ui/delegates/{delegate_id}/permissions` | `require_ui_session` | Update delegate permissions |
| `DELETE` | `/ui/delegates/{delegate_id}` | `require_ui_session` | Revoke delegate access |
| `POST` | `/ui/delegates/invites/{creator_id}/respond` | `require_ui_session` | Accept or decline delegation invite |
| `GET` | `/ui/delegates/invites` | `require_ui_session` | List pending delegation invites for current user |
| `GET` | `/ui/delegates/settings` | `require_ui_session` | Get creator delegation settings |
| `PUT` | `/ui/delegates/settings` | `require_ui_session` | Update creator delegation settings |
| `GET` | `/ui/delegates/audit` | `require_ui_session` | Get delegation audit log (creator only) |
| `GET` | `/ui/delegates/presets` | `require_ui_session` | List available permission presets |

### 3.6 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Delegates (DELEGATE-001) --

class DelegateAddIn(BaseModel):
    delegate_id: str = Field(min_length=1, max_length=255, description="User ID or email of the delegate")
    permissions: List[str] = Field(min_length=1, description="List of permission keys")
    preset: Optional[str] = Field(None, description="Permission preset key")
    label: str = Field(default="", max_length=200, description="Optional label for the delegate")

class DelegateUpdatePermissionsIn(BaseModel):
    permissions: List[str] = Field(min_length=1)
    preset: Optional[str] = None

class DelegateInviteRespondIn(BaseModel):
    accept: bool

class DelegateSettingsIn(BaseModel):
    require_acceptance: bool = True
    max_delegates: int = Field(default=10, ge=1, le=20)
    default_preset: Optional[str] = None
    delegate_tag_enabled: bool = True
    delegate_tag_format: str = Field(default="[via @{delegate_name}]", max_length=100)

class DelegateOut(BaseModel):
    delegate_id: str
    creator_id: str
    permissions: List[str] = Field(default_factory=list)
    preset: Optional[str] = None
    status: str  # "pending" | "active"
    label: str = ""
    show_delegate_tag: bool = True
    delegate_tag_format: str = "[via @{delegate_name}]"
    display_name: str = ""
    avatar_url: Optional[str] = None
    invited_at: int = 0
    accepted_at: int = 0
    updated_at: int = 0

class ManagedCreatorOut(BaseModel):
    creator_id: str
    display_name: str = ""
    avatar_url: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)
    preset: Optional[str] = None
    accepted_at: int = 0

class DelegateSettingsOut(BaseModel):
    require_acceptance: bool = True
    max_delegates: int = 10
    default_preset: Optional[str] = None
    delegate_tag_enabled: bool = True
    delegate_tag_format: str = "[via @{delegate_name}]"

class DelegateAuditOut(BaseModel):
    event_id: str
    actor_id: str
    actor_type: str  # "creator" | "delegate" | "system"
    action: str
    target_id: str = ""
    details: Optional[Dict[str, Any]] = None
    ts: int = 0

class PermissionPresetOut(BaseModel):
    key: str
    label: str
    permissions: List[str]
```

### 3.7 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/delegates/DelegatesPage.tsx` | Main delegates management page | ~250 |
| `frontend/src/pages/delegates/AddDelegateDialog.tsx` | Dialog for adding a new delegate | ~120 |
| `frontend/src/pages/delegates/EditPermissionsDialog.tsx` | Dialog for editing delegate permissions | ~100 |
| `frontend/src/pages/delegates/DelegateSettingsCard.tsx` | Creator delegation settings card | ~80 |
| `frontend/src/pages/delegates/ManagedCreatorsPage.tsx` | Page showing creators the user delegates for | ~150 |
| `frontend/src/pages/delegates/DelegateAuditLog.tsx` | Audit log timeline component | ~100 |
| `frontend/src/api/endpoints/delegates.ts` | API client wrappers | ~120 |

**Component tree**:

```
DelegatesPage
├── Tabs
│   ├── "My Delegates" Tab (creator view)
│   │   ├── AddDelegateDialog (Button: "Add Delegate")
│   │   ├── DelegateList
│   │   │   └── For each delegate:
│   │   │       ├── Avatar, name, label
│   │   │       ├── Permission badges (chat_read, feed_post, etc.)
│   │   │       ├── Preset badge ("Full Manager", "Chat Agent", etc.)
│   │   │       ├── Status badge (active / pending)
│   │   │       ├── EditPermissionsDialog button
│   │   │       └── "Revoke" button with confirmation dialog
│   │   └── DelegateSettingsCard
│   │       ├── Toggle: require acceptance
│   │       ├── Max delegates selector
│   │       ├── Default preset dropdown
│   │       └── Delegate tag format input
│   ├── "Managing" Tab (delegate view)
│   │   └── ManagedCreatorsPage
│   │       └── For each creator:
│   │           ├── Avatar, name
│   │           ├── Permission badges
│   │           └── Link: "Manage" → switches to creator context
│   └── "Audit Log" Tab (creator only)
│       └── DelegateAuditLog
│           └── Timestamped entries with actor, action, target
├── "Pending Invites" banner (if delegate has pending invites)
│   └── Accept / Decline buttons
```

### 3.8 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/delegates" element={<DelegatesPage />} />
<Route path="/delegates/managing" element={<ManagedCreatorsPage />} />
```

### 3.9 Sidebar Navigation

Add "Delegates" entry to the Settings/Account group in `Sidebar.tsx` and `AppShell.tsx` (MobileSidebar) with `UserCog` icon from lucide-react. Add to `MORE_LINKS` in `MobileNav.tsx`.

### 3.10 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/delegates.py` | Core delegate management service | ~400 |
| `app/routers/delegates.py` | REST API endpoints | ~250 |
| `frontend/src/pages/delegates/DelegatesPage.tsx` | Delegates management page | ~250 |
| `frontend/src/pages/delegates/AddDelegateDialog.tsx` | Add delegate dialog | ~120 |
| `frontend/src/pages/delegates/EditPermissionsDialog.tsx` | Permission editor | ~100 |
| `frontend/src/pages/delegates/DelegateSettingsCard.tsx` | Settings card | ~80 |
| `frontend/src/pages/delegates/ManagedCreatorsPage.tsx` | Managed creators view | ~150 |
| `frontend/src/pages/delegates/DelegateAuditLog.tsx` | Audit log | ~100 |
| `frontend/src/api/endpoints/delegates.ts` | API wrappers | ~120 |
| `frontend/e2e/delegates-management.spec.ts` | E2E tests | ~500 |

### 3.11 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `delegates_router` |
| `app/models.py` | Add Delegate* Pydantic models |
| `app/core/settings.py` | Add `delegates_table_name` setting |
| `app/core/tables.py` | Add `T.delegates` table handle |
| `scripts/local-ddb-init.py` | Add `delegates` TableDef with GSIs |
| `frontend/src/api/types.ts` | Add Delegate TypeScript interfaces |
| `frontend/src/App.tsx` | Add delegate routes |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Delegates" nav entry |
| `frontend/src/components/layout/AppShell.tsx` | Add to mobile sidebar |
| `frontend/src/components/layout/MobileNav.tsx` | Add to MORE_LINKS |

---

## 4. Permission Enforcement Architecture

### 4.1 Delegation Context

When a delegate performs an action on behalf of a creator, the system needs to track both identities. A `DelegationContext` dataclass encapsulates this:

```python
@dataclasses.dataclass
class DelegationContext:
    creator_id: str
    delegate_id: str
    permissions: List[str]
    preset: Optional[str]
    show_delegate_tag: bool
    delegate_tag_format: str
```

### 4.2 Delegation Header

Delegates include an `X-On-Behalf-Of` header with the creator's user ID. The auth dependency validates:

1. The caller is an active delegate for the specified creator.
2. The delegate has the required permission for the endpoint being called.
3. Returns both the delegate's identity and the delegation context.

```python
async def resolve_delegation_context(
    request: Request,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Optional[DelegationContext]:
    """Extract delegation context from X-On-Behalf-Of header, if present."""
    on_behalf_of = request.headers.get("x-on-behalf-of")
    if not on_behalf_of:
        return None
    delegate_item = require_delegate_permission(
        creator_id=on_behalf_of,
        delegate_id=user.user_sub,
        required_permission=_permission_for_route(request),
    )
    return DelegationContext(
        creator_id=on_behalf_of,
        delegate_id=user.user_sub,
        permissions=delegate_item["permissions"],
        preset=delegate_item.get("preset"),
        show_delegate_tag=delegate_item.get("show_delegate_tag", True),
        delegate_tag_format=delegate_item.get("delegate_tag_format", ""),
    )
```

### 4.3 Permission-Route Mapping

Each endpoint that supports delegation declares its required permission via a dependency or decorator. The mapping is stored in a constant:

```python
ROUTE_PERMISSION_MAP = {
    "/ui/messaging/conversations": "chat_read",
    "/ui/messaging/conversations/*/messages": "chat_read",
    "/ui/messaging/conversations/*/messages:POST": "chat_respond",
    "/ui/newsfeed/posts": "feed_read",
    "/ui/newsfeed/posts:POST": "feed_post",
    "/ui/newsfeed/posts/*/comments:DELETE": "feed_moderate",
    "/ui/broadcast/sessions:POST": "broadcast_control",
    "/ui/broadcast/chat/*/messages:DELETE": "broadcast_moderate",
}
```

### 4.4 Audit Trail

Every action performed via delegation writes an audit entry with:
- `actor_id`: the delegate who performed the action
- `actor_type`: `"delegate"`
- `action`: the specific action (e.g., `chat_message_sent`, `feed_post_created`, `broadcast_chat_muted`)
- `target_id`: the entity affected (conversation ID, post ID, etc.)
- `details`: action-specific metadata (message ID, post content summary, etc.)
- `ts`: Unix timestamp

### 4.5 Edge Cases

- **Creator removes delegate while delegate is mid-session**: Delegate's next API call returns 403; SSE connections close on next heartbeat check.
- **Creator adds delegate, then changes their own email**: Delegation is keyed by `user_sub`, not email, so it survives email changes.
- **Delegate is deleted from the platform**: Delegation records remain but `get_profile` returns empty; periodic cleanup job can remove stale records.
- **Circular delegation (A delegates to B, B delegates to A)**: Allowed; each direction is independent. Delegation does not chain (B acting as A cannot re-delegate to C).
- **Delegation depth**: No chaining. A delegate acts directly as the creator; they cannot further delegate.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/delegates-management.spec.ts`

### Section 487: Delegate CRUD API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 487.1 | Alice adds Bob as a delegate with chat_agent preset | POST `/ui/delegates`; 200; response has `delegate_id=bob`, `permissions` includes `chat_read` and `chat_respond`, `status=pending` |
| 487.2 | Alice lists her delegates | GET `/ui/delegates`; response includes Bob with correct permissions |
| 487.3 | Alice updates Bob's permissions to full_manager | PUT `/ui/delegates/bob/permissions`; 200; response permissions list has all 7 permissions |
| 487.4 | Alice revokes Bob's delegate access | DELETE `/ui/delegates/bob`; 200; GET delegates returns empty list |
| 487.5 | Adding self as delegate returns 400 | POST with `delegate_id=alice`; 400 response |

### Section 488: Invite Flow API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 488.1 | Bob receives pending delegation invite | Alice adds Bob (require_acceptance=true); Bob GET `/ui/delegates/invites`; response includes Alice's invite |
| 488.2 | Bob accepts delegation invite | POST `/ui/delegates/invites/alice/respond` with `accept=true`; 200; delegate status becomes `active` |
| 488.3 | Bob appears in Alice's active delegates | GET `/ui/delegates`; Bob `status=active` |
| 488.4 | Charlie declines delegation invite | Alice adds Charlie; Charlie POST respond with `accept=false`; GET invites returns empty; Alice's delegate list has no Charlie |

### Section 489: Permission Presets & Settings API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 489.1 | List available presets | GET `/ui/delegates/presets`; response includes all 6 presets with correct permission lists |
| 489.2 | Update creator delegation settings | PUT `/ui/delegates/settings` with `require_acceptance=false, max_delegates=5`; GET settings reflects changes |
| 489.3 | Delegate limit enforced | Set max_delegates=1; add one delegate; add second delegate returns 400 |
| 489.4 | Managed creators list shows Alice | Bob GET `/ui/delegates/managed`; response includes Alice with Bob's permissions |

### Section 490: Audit Log API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 490.1 | Audit log records delegate_invited event | Alice adds Bob; GET `/ui/delegates/audit`; first entry has `action=delegate_invited`, `target_id=bob` |
| 490.2 | Audit log records permission update | Alice updates Bob's permissions; audit shows `action=permissions_updated` with old and new permissions in details |
| 490.3 | Audit log records delegate_revoked event | Alice revokes Bob; audit shows `action=delegate_revoked` |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| All `/ui/delegates/*` | `require_ui_session` | Any authenticated user |
| Creator-only endpoints (add, update, revoke, settings, audit) | `require_ui_session` | Must be the creator (checked by service layer via `user_sub` match) |
| Delegate-only endpoints (respond to invite, managed list) | `require_ui_session` | Must be the delegate (checked by service layer) |

### 6.2 Authorization Enforcement

- Creator identity is verified by matching `user_sub` from the session against the `creator_id` in the delegation record.
- Delegates cannot escalate their own permissions -- only the creator can change a delegate's permission set.
- Delegation does not grant access to the creator's account settings, billing, security settings, or any non-delegated features.
- Revoking a delegate is immediate and atomic -- the DynamoDB delete is a single operation.

### 6.3 Rate Limiting

- Add delegate: max 10 invites per creator per hour.
- Respond to invite: max 20 per delegate per hour.
- Audit log queries: max 30 per user per minute.
- All endpoints inherit global rate limiter.

### 6.4 Input Validation

- `delegate_id`: 1-255 characters, validated as existing user ID or email via profile lookup.
- `permissions`: non-empty list; each value must be in `VALID_PERMISSIONS` set.
- `preset`: must be a key in `PERMISSION_PRESETS` or null.
- `label`: 0-200 characters.
- `delegate_tag_format`: 0-100 characters; must contain `{delegate_name}` placeholder if non-empty.

### 6.5 Data Privacy

- Delegate lists are only visible to the creator.
- Managed creator lists are only visible to the delegate.
- Audit logs are restricted to the creator only.
- Delegate profiles (display name, avatar) are resolved from the public profile service.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/profile.py` | Exists | Display names and avatars in delegate lists |
| `app/auth/deps.py` | Exists | `require_ui_session` for all endpoints |
| `app/core/tables.py` | Exists (modify) | Add `T.delegates` handle |
| `scripts/local-ddb-init.py` | Exists (modify) | Add `delegates` table definition |
| DELEGATE-002 | Not started | Depends on this ticket for `require_delegate_permission` and `DelegationContext` |
| DELEGATE-003 | Not started | Depends on this ticket for permission checks and audit logging |
| DELEGATE-004 | Not started | Depends on this ticket for permission checks and audit logging |
| DELEGATE-005 | Not started | Depends on this ticket for delegation scope validation on API keys |

---

## 8. Acceptance Criteria

1. Creators can add delegates by user ID with granular permissions.
2. Permission presets correctly populate permission lists.
3. Delegates must accept invites before gaining access (when require_acceptance=true).
4. Creators can update delegate permissions at any time.
5. Revoking a delegate removes access immediately.
6. Delegates can list all creators they manage with their permission sets.
7. All delegation actions are recorded in the audit log with actor, action, and target.
8. Creator delegation settings (max delegates, tag format, etc.) are persisted and enforced.
9. Self-delegation is rejected.
10. Delegate limits are enforced per creator settings.
11. All 16 E2E tests pass.
