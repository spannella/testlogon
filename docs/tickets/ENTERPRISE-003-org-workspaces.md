# ENTERPRISE-003: Organization / Team Workspaces

**Ticket**: ENTERPRISE-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform currently treats every user as an independent individual. There is no concept of an "organization" that groups users together for shared file access, team calendars, or unified billing. Enterprise and small-business customers need to create organizational units where:

- Multiple team members share a common file space with role-based access (viewer, editor, admin).
- A team calendar aggregates events from all members and supports group scheduling.
- A single payment method (company credit card) is billed for all members, with consolidated invoicing.
- An org-level admin dashboard shows activity, member usage, and spending across the organization.

Today, file sharing exists (`share_node` in `app/services/filemanager.py`), but it is peer-to-peer -- Alice shares a file with Bob. There is no "shared folder" that all members of an org can browse. Calendar sharing exists (`CalendarShareIn` model in `app/routers/calendar.py`), but only between two users, not across a group. Billing is strictly per-user (`pk=USER#{user_sub}` in `app/services/billing_shared.py`).

### 1.2 How It Works

1. A user creates an organization via `POST /ui/orgs` with a name and optional description.
2. The creator becomes the org **owner** (highest privilege). They invite members via email.
3. Invited members accept and join the org. Roles within the org are **owner**, **admin**, **member**, **viewer**.
4. A shared file space is automatically provisioned for the org. All members can browse files in the org root folder. Permissions (read/write/admin) are inherited from org role or set per-folder.
5. A team calendar is created, visible to all org members. Events on the team calendar appear alongside personal calendars.
6. The org owner can add an "org payment method" -- a credit card that covers subscriptions and purchases for all org members. Individual members can still use personal payment methods for personal purchases.
7. An org dashboard shows member activity, storage usage, and billing summary.

### 1.3 Design Principles

- **Additive, not replacing**: Orgs layer on top of the existing user model. A user can belong to multiple orgs and still use personal files/calendars/billing independently.
- **Role hierarchy**: Owner > Admin > Member > Viewer. Org admins can manage members but not billing. Only owners manage billing and delete the org.
- **Shared, not duplicated**: Shared files exist once in the org's file space. Members access them by reference, not copy.
- **Billing isolation**: Org billing is tracked under a separate partition (`ORG#{org_id}`) in the billing table, not mixed with user-level billing.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to create an organization and become its owner. | POST creates org; creator has owner role; org appears in my org list. |
| Org owner | As an org owner, I want to invite team members by email. | POST invite; invitee receives notification; accepting sets member role. |
| Org admin | As an org admin, I want to remove a member from the organization. | DELETE member; their access to shared files/calendar is revoked. |
| Org member | As an org member, I want to browse shared files uploaded by other members. | GET org file listing returns all files in org space; downloads work. |
| Org member | As an org member, I want to see team calendar events. | GET org calendar returns events from all members who opted in. |
| Org owner | As an org owner, I want to add a company credit card for org billing. | POST payment method on org; subsequent member purchases use org PM. |
| Org owner | As an org owner, I want to view a unified billing history for the org. | GET billing history filtered by org returns all member transactions. |
| Root admin | As a root admin, I want to list all organizations and their sizes. | GET admin endpoint returns paginated org list. |
| Org member | As an org member, I want to leave the organization. | POST leave; membership removed; personal files unaffected. |
| Org owner | As an org owner, I want to transfer ownership to another admin. | PATCH transfers owner role; previous owner becomes admin. |

---

## 2. Current State Analysis

### 2.1 File Sharing (`app/routers/filemanager.py`, `app/services/filemanager.py`)

The file manager router (lines 1-76) imports numerous functions including `share_node` and `unshare_node`:

```python
# app/routers/filemanager.py, lines 48-49
from app.services.filemanager import (
    ...
    share_node,
    unshare_node,
    ...
)
```
<!-- CORRECTED: was "lines 49-50", actually lines 48-49 -->

Current sharing is user-to-user. The `share_node` function creates a share record linking a file node to a target `user_sub`. Shared files appear in `list_shared_with_me()`. This pattern can be extended for org-level sharing by sharing with `ORG#{org_id}` instead of a `user_sub`, and modifying `list_shared_with_me` to also query by the user's org memberships.

The file manager uses DynamoDB with partition key patterns in `T.filemgr_table_name` (from settings line 752):
<!-- CORRECTED: filemgr_table_name is at line 752, not 749 -->

```python
# app/core/settings.py, line 752
filemgr_table_name: str = os.environ.get("FILEMGR_TABLE", "")
```

The file manager service has several key functions that need org-aware variants:

```python
# From app/services/filemanager.py (existing functions to wrap)
def upload_file(owner_pk: str, path: str, file_bytes: bytes, ...) -> dict:
    """Upload a file to a user's file space."""
    ...

def list_children(owner_pk: str, path: str, ...) -> list:
    """List files in a directory."""
    ...

def download_file(owner_pk: str, node_id: str, ...) -> StreamingResponse:
    """Download a file by node ID."""
    ...

def remove_file(owner_pk: str, node_id: str, ...) -> None:
    """Soft-delete a file."""
    ...
```

An org file space uses `pk=ORG#{org_id}` to create a separate namespace, functionally identical to a user's file tree but owned by the org. The existing functions accept `owner_pk` as a parameter, so the org file endpoints simply pass `f"ORG#{org_id}"` instead of `f"USER#{user_sub}"`.

### 2.2 Calendar System (`app/routers/calendar.py`)

The calendar router (lines 1-80) manages personal calendars with sharing support:
<!-- VERIFIED: app/routers/calendar.py:27 — CalendarShareIn import -->

```python
# app/routers/calendar.py, line 27
from app.models import (
    ...
    CalendarShareIn,
    CalendarShareOut,
    ...
)
```

Calendars are stored in `T.calendar` (settings line 417):
<!-- VERIFIED: app/core/settings.py:417 — calendar_table_name -->

```python
# app/core/settings.py, line 417
calendar_table_name: str = os.environ.get("CALENDAR_TABLE_NAME", "calendar")
```

The calendar data model uses `calendar_id` as PK. A team calendar for an org would have `calendar_id=f"ORG#{org_id}#TEAM"` with events stored under it. The `CalendarAccessOut` model already supports access control lists. Adding org membership as an implicit access grant extends this without changing the event storage model.

The calendar event creation pattern:

```python
# Existing pattern in calendar service
{
    "calendar_id": "CAL#user_sub",
    "sk": f"EVENT#{event_id}",
    "event_id": event_id,
    "title": "Team Standup",
    "start_time": "2026-05-28T09:00:00Z",
    "end_time": "2026-05-28T09:30:00Z",
    "created_by": user_sub,
    ...
}
```

For org team calendars, the pattern becomes:

```python
{
    "calendar_id": f"ORG#{org_id}#TEAM",
    "sk": f"EVENT#{event_id}",
    "event_id": event_id,
    "title": "Team Standup",
    "start_time": "2026-05-28T09:00:00Z",
    "end_time": "2026-05-28T09:30:00Z",
    "created_by": user_sub,         # who created the event
    "org_id": org_id,               # org context
    ...
}
```

### 2.3 Billing System (`app/routers/billing.py`, `app/services/billing_shared.py`)

The billing router (lines 1-80) handles payment methods, wallet operations, and billing history:
<!-- VERIFIED: app/routers/billing.py — AddCardReq at line 31, WalletDepositReq at line 45, WalletWithdrawReq at line 46 -->

```python
# app/routers/billing.py, lines 29-46
from app.models import (
    AddCardReq,
    WalletDepositReq,
    WalletWithdrawReq,
    ...
)
```

All billing records use `user_pk()`:
<!-- VERIFIED: app/services/billing_shared.py:16 — user_pk -->

```python
# app/services/billing_shared.py, line 16
def user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"
```

The billing table uses a single-table design with `pk=USER#{user_sub}`, `sk=PM#{pm_id}` for payment methods and `sk=LEDGER#{timestamp}` for history. Org billing replicates this pattern with `pk=ORG#{org_id}`, allowing the same CRUD operations to work for orgs. A helper function `org_pk(org_id)` returns `f"ORG#{org_id}"`.

The billing table name comes from settings (line 321):
<!-- VERIFIED: app/core/settings.py:321 — billing_table_name -->

```python
# app/core/settings.py, line 321
billing_table_name: str = os.environ.get("BILLING_TABLE_NAME", "billing")
```

The existing DDB helpers in `billing_shared.py` are PK-agnostic:

```python
def ddb_get(table, pk: str, sk: str) -> Optional[Dict]:
    resp = table.get_item(Key={"pk": pk, "sk": sk})
    return resp.get("Item")

def ddb_put(table, item: Dict, *, condition_expression=None) -> None:
    kwargs = {"Item": item}
    if condition_expression:
        kwargs["ConditionExpression"] = condition_expression
    table.put_item(**kwargs)
```

These already work with any PK format, so org billing just needs a `org_pk()` helper and routing logic.

### 2.4 Contacts System (`app/routers/contacts.py`)

The contacts table (settings line 449) stores user-to-user relationships:
<!-- VERIFIED: app/core/settings.py:449 — contacts_table_name -->

```python
# app/core/settings.py, line 449
contacts_table_name: str = os.environ.get("DDB_CONTACTS_TABLE", "Contacts")
```

Org member relationships are a superset of contacts. When two users are in the same org, they implicitly appear in each other's contact lists. The contacts service can be extended to include org members in `list_contacts` results.

### 2.5 Auth Scopes (`app/auth/roles.py`)

The `AdminScope` enum (lines 14-18) currently has:
<!-- VERIFIED: app/auth/roles.py:14-18 — AdminScope enum -->

```python
# app/auth/roles.py, lines 14-18
class AdminScope(str, Enum):
    AUTH_SUPPORT = "auth_support"
    BILLING_SUPPORT = "billing_support"
    CONTENT_MODERATION = "content_moderation"
    CONTENT_MODERATION_SENIOR = "content_moderation_senior"
```

Org-level permissions are separate from platform admin scopes. They are stored on the org membership record, not the user's global role. This avoids conflating org admin (manages team files) with platform admin (manages moderation, billing support).

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 Organizations Table

**Table**: `organizations` (new)
**PK**: `org_id`
**SK**: `#META`

```python
{
    "org_id": "org_abc123",
    "sk": "#META",
    "name": "Acme Engineering",
    "description": "Engineering team workspace",
    "slug": "acme-engineering",
    "owner_user_sub": "alice@acme.com",
    "status": "active",           # active | suspended | archived
    "plan": "team",               # free | team | enterprise
    "member_count": 12,
    "storage_used_bytes": 5368709120,
    "storage_limit_bytes": 107374182400,  # 100 GB
    "billing_mode": "org",        # org | individual
    "default_file_permission": "editor",  # viewer | editor | admin
    "team_calendar_id": "ORG#org_abc123#TEAM",
    "created_at": 1716883200,
    "updated_at": 1716883200,
    "tenant_id": "default",
}
```

**Full DDB schema for `#META` item:**

| Attribute | Type | Key | Description |
|-----------|------|-----|-------------|
| `org_id` | S | PK | Organization identifier |
| `sk` | S | SK | Always `#META` for the org metadata record |
| `name` | S | | Display name |
| `description` | S | | Optional description |
| `slug` | S | | URL-safe slug (unique within tenant) |
| `owner_user_sub` | S | | Current owner |
| `status` | S | | `active`, `suspended`, `archived` |
| `plan` | S | | `free`, `team`, `enterprise` |
| `member_count` | N | | Current member count (denormalized) |
| `storage_used_bytes` | N | | Current storage usage |
| `storage_limit_bytes` | N | | Plan-based storage limit |
| `billing_mode` | S | | `org` (centralized) or `individual` (each pays own) |
| `default_file_permission` | S | | Default role for new files: `viewer`, `editor`, `admin` |
| `team_calendar_id` | S | | Calendar ID for the org team calendar |
| `created_at` | N | | Unix timestamp |
| `updated_at` | N | | Unix timestamp |
| `tenant_id` | S | | Tenant this org belongs to (ENTERPRISE-001) |

#### 3.1.2 Org Memberships (same table, different SK)

**PK**: `org_id`
**SK**: `MEMBER#{user_sub}`

```python
{
    "org_id": "org_abc123",
    "sk": "MEMBER#bob@acme.com",
    "user_sub": "bob@acme.com",
    "org_role": "member",         # owner | admin | member | viewer
    "status": "active",           # active | invited | suspended
    "invited_by": "alice@acme.com",
    "joined_at": 1716883200,
    "updated_at": 1716883200,
    "storage_used_bytes": 0,
    "last_active_at": 1716883200,
}
```

**GSI**: `user-orgs-index` (PK: `user_sub`, SK: `org_id`) -- allows listing all orgs a user belongs to.

#### 3.1.3 Org Invitations (same table, different SK)

**PK**: `org_id`
**SK**: `INVITE#{invite_id}`

```python
{
    "org_id": "org_abc123",
    "sk": "INVITE#inv_xyz789",
    "invite_id": "inv_xyz789",
    "email": "charlie@acme.com",
    "org_role": "member",
    "invited_by": "alice@acme.com",
    "status": "pending",          # pending | accepted | declined | expired
    "created_at": 1716883200,
    "expires_at": 1717488000,     # 7 days
    "token_hash": "sha256:...",   # hashed invite token for email link
}
```

**GSI**: `invite-email-index` (PK: `email`, SK: `org_id`) -- allows looking up pending invites for a user.

### 3.2 Shared File Space

Each org gets a virtual file root at `pk=ORG#{org_id}` in the file manager table. Files uploaded to the org space use this PK instead of `USER#{user_sub}`. The file manager service is extended with:

```python
# app/services/org_files.py (new)
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import HTTPException, UploadFile

from app.core.tables import T
from app.services.filemanager import (
    download_file,
    list_children,
    remove_file,
    upload_file,
)
from app.services.org_service import assert_org_membership, get_org_membership


def org_file_owner_pk(org_id: str) -> str:
    """Return the file manager PK for an org's shared file space."""
    return f"ORG#{org_id}"


def org_upload_file(
    org_id: str,
    user_sub: str,
    path: str,
    file: UploadFile,
    **kwargs,
) -> Dict[str, Any]:
    """Upload a file to the org's shared space. user_sub is the uploader (for audit)."""
    membership = assert_org_membership(org_id, user_sub, min_role="editor")

    # Check org storage limit
    _check_storage_limit(org_id, file.size or 0)

    result = upload_file(
        owner_pk=org_file_owner_pk(org_id),
        path=path,
        file=file,
        uploaded_by=user_sub,
        **kwargs,
    )

    # Update org storage counter
    _increment_storage_used(org_id, file.size or 0)
    _increment_member_storage(org_id, user_sub, file.size or 0)

    return result


def org_list_children(
    org_id: str,
    user_sub: str,
    path: str = "/",
    **kwargs,
) -> List[Dict[str, Any]]:
    """List files in the org's shared space."""
    assert_org_membership(org_id, user_sub, min_role="viewer")
    return list_children(
        owner_pk=org_file_owner_pk(org_id),
        path=path,
        **kwargs,
    )


def org_download_file(
    org_id: str,
    user_sub: str,
    node_id: str,
) -> Any:
    """Download a file from the org's shared space."""
    assert_org_membership(org_id, user_sub, min_role="viewer")
    return download_file(
        owner_pk=org_file_owner_pk(org_id),
        node_id=node_id,
    )


def org_remove_file(
    org_id: str,
    user_sub: str,
    node_id: str,
) -> None:
    """Remove a file from the org's shared space.

    Editors can delete their own files. Admins and owners can delete any file.
    """
    membership = assert_org_membership(org_id, user_sub, min_role="editor")

    # Check if user can delete this file
    node = _get_org_file_node(org_id, node_id)
    if not node:
        raise HTTPException(404, "File not found")

    if membership["org_role"] not in ("admin", "owner"):
        if node.get("uploaded_by") != user_sub:
            raise HTTPException(403, "Can only delete your own files. Ask an admin to delete this file.")

    file_size = node.get("size_bytes", 0)
    remove_file(owner_pk=org_file_owner_pk(org_id), node_id=node_id)

    # Update storage counters
    _decrement_storage_used(org_id, file_size)


def _check_storage_limit(org_id: str, additional_bytes: int) -> None:
    """Raise 409 if upload would exceed org storage limit."""
    from app.services.org_service import get_org
    org = get_org(org_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    current = org.get("storage_used_bytes", 0)
    limit = org.get("storage_limit_bytes", 0)
    if limit > 0 and (current + additional_bytes) > limit:
        raise HTTPException(409, f"Storage limit exceeded ({limit} bytes)")


def _increment_storage_used(org_id: str, bytes_added: int) -> None:
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": "#META"},
        UpdateExpression="SET storage_used_bytes = storage_used_bytes + :b",
        ExpressionAttributeValues={":b": bytes_added},
    )


def _decrement_storage_used(org_id: str, bytes_removed: int) -> None:
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": "#META"},
        UpdateExpression="SET storage_used_bytes = storage_used_bytes - :b",
        ExpressionAttributeValues={":b": bytes_removed},
    )


def _increment_member_storage(org_id: str, user_sub: str, bytes_added: int) -> None:
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": f"MEMBER#{user_sub}"},
        UpdateExpression="SET storage_used_bytes = if_not_exists(storage_used_bytes, :zero) + :b",
        ExpressionAttributeValues={":b": bytes_added, ":zero": 0},
    )


def _get_org_file_node(org_id: str, node_id: str) -> Optional[Dict[str, Any]]:
    """Get a file node from the org's file space."""
    from app.services.filemanager import get_node
    return get_node(owner_pk=org_file_owner_pk(org_id), node_id=node_id)
```

Permission checks use the org membership role:
- **viewer**: read-only access (list, download)
- **editor**: read + upload + move + delete own files
- **admin**: full access including deleting any file and managing folder permissions
- **owner**: admin + org settings + billing

### 3.3 Team Calendar

A team calendar is automatically created when the org is created:

```python
# app/services/org_service.py -- in create_org()
def _create_team_calendar(org_id: str, org_name: str, owner_user_sub: str) -> str:
    """Create the team calendar for a new org. Returns calendar_id."""
    calendar_id = f"ORG#{org_id}#TEAM"
    T.calendar.put_item(Item={
        "calendar_id": calendar_id,
        "sk": "#META",
        "name": f"{org_name} Team Calendar",
        "owner_user_sub": owner_user_sub,
        "owner_type": "org",
        "org_id": org_id,
        "visibility": "org_members",
        "created_at": now_ts(),
    })
    return calendar_id
```

Events on the team calendar are accessible to all org members. The existing calendar query pattern (`T.calendar.query(KeyConditionExpression=Key("calendar_id").eq(...))`) works unchanged. The frontend adds a "Team" tab in the calendar view that shows the org calendar alongside personal calendars.

Members can opt to share their personal calendar events with the team calendar via a visibility toggle. This creates read-only event references on the team calendar, not copies.

Team calendar event creation:

```python
# app/services/org_calendar.py (new)
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.org_service import assert_org_membership, get_org


def create_org_event(
    org_id: str,
    user_sub: str,
    title: str,
    start_time: str,
    end_time: str,
    description: str = "",
    all_day: bool = False,
    attendees: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create an event on the org's team calendar."""
    membership = assert_org_membership(org_id, user_sub, min_role="member")
    org = get_org(org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    calendar_id = org.get("team_calendar_id", f"ORG#{org_id}#TEAM")
    event_id = f"evt_{uuid.uuid4().hex}"
    now = now_ts()

    event = {
        "calendar_id": calendar_id,
        "sk": f"EVENT#{event_id}",
        "event_id": event_id,
        "title": title,
        "description": description,
        "start_time": start_time,
        "end_time": end_time,
        "all_day": all_day,
        "created_by": user_sub,
        "org_id": org_id,
        "attendees": attendees or [],
        "created_at": now,
        "updated_at": now,
    }
    T.calendar.put_item(Item=event)
    return event


def list_org_events(
    org_id: str,
    user_sub: str,
    from_time: Optional[str] = None,
    to_time: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List events on the org's team calendar."""
    assert_org_membership(org_id, user_sub, min_role="viewer")
    org = get_org(org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    calendar_id = org.get("team_calendar_id", f"ORG#{org_id}#TEAM")

    key_expr = Key("calendar_id").eq(calendar_id) & Key("sk").begins_with("EVENT#")
    resp = T.calendar.query(
        KeyConditionExpression=key_expr,
        Limit=limit,
        ScanIndexForward=True,
    )
    events = resp.get("Items", [])

    # Filter by time range if specified
    if from_time:
        events = [e for e in events if e.get("end_time", "") >= from_time]
    if to_time:
        events = [e for e in events if e.get("start_time", "") <= to_time]

    return events


def update_org_event(
    org_id: str,
    user_sub: str,
    event_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> Dict[str, Any]:
    """Update an event. Creator or admin can update."""
    membership = assert_org_membership(org_id, user_sub, min_role="member")
    org = get_org(org_id)
    calendar_id = org.get("team_calendar_id", f"ORG#{org_id}#TEAM")

    # Get existing event
    resp = T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": f"EVENT#{event_id}"})
    event = resp.get("Item")
    if not event:
        raise HTTPException(404, "Event not found")

    # Only creator or admin+ can update
    if event["created_by"] != user_sub and membership["org_role"] not in ("admin", "owner"):
        raise HTTPException(403, "Only the event creator or an admin can update this event")

    update_parts = ["updated_at = :now"]
    values: Dict[str, Any] = {":now": now_ts()}

    if title is not None:
        update_parts.append("title = :t")
        values[":t"] = title
    if description is not None:
        update_parts.append("description = :d")
        values[":d"] = description
    if start_time is not None:
        update_parts.append("start_time = :st")
        values[":st"] = start_time
    if end_time is not None:
        update_parts.append("end_time = :et")
        values[":et"] = end_time

    T.calendar.update_item(
        Key={"calendar_id": calendar_id, "sk": f"EVENT#{event_id}"},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=values,
    )

    return {**event, **({"title": title} if title else {}),
            **({"description": description} if description else {}),
            **({"start_time": start_time} if start_time else {}),
            **({"end_time": end_time} if end_time else {})}


def delete_org_event(org_id: str, user_sub: str, event_id: str) -> None:
    """Delete an event. Creator or admin can delete."""
    membership = assert_org_membership(org_id, user_sub, min_role="member")
    org = get_org(org_id)
    calendar_id = org.get("team_calendar_id", f"ORG#{org_id}#TEAM")

    resp = T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": f"EVENT#{event_id}"})
    event = resp.get("Item")
    if not event:
        raise HTTPException(404, "Event not found")

    if event["created_by"] != user_sub and membership["org_role"] not in ("admin", "owner"):
        raise HTTPException(403, "Only the event creator or an admin can delete this event")

    T.calendar.delete_item(Key={"calendar_id": calendar_id, "sk": f"EVENT#{event_id}"})
```

### 3.4 Org Billing

#### 3.4.1 Org Payment Method

```python
# In billing table
{
    "pk": "ORG#org_abc123",
    "sk": "PM#pm_org_stripe_xyz",
    "payment_method_id": "pm_org_stripe_xyz",
    "provider": "stripe",
    "type": "card",
    "last4": "4242",
    "brand": "visa",
    "exp_month": 12,
    "exp_year": 2027,
    "billing_email": "billing@acme.com",
    "added_by": "alice@acme.com",
    "created_at": 1716883200,
}
```

#### 3.4.2 Billing Routing

When a user makes a purchase (tip, unlock, subscription), the billing system checks:

1. Does the user belong to an org with `billing_mode=org`?
2. Does the org have a valid default payment method?
3. If yes to both, charge the org payment method and record the ledger entry under `pk=ORG#{org_id}`.
4. If no, fall back to the user's personal payment method.

```python
# app/services/org_billing.py (new)
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ddb_get, ddb_put, ddb_query_pk


def org_pk(org_id: str) -> str:
    return f"ORG#{org_id}"


def resolve_payment_context(user_sub: str) -> Dict[str, Any]:
    """Determine whether to bill the user or their org.

    Returns:
        {"billing_entity": "org"|"user", "org_id": str|None, "payment_method": dict|None}
    """
    # Find user's active orgs with org billing mode
    from app.services.org_service import list_user_orgs
    orgs = list_user_orgs(user_sub, status="active")

    for org in orgs:
        if org.get("billing_mode") == "org":
            pm = get_org_default_payment_method(org["org_id"])
            if pm:
                return {
                    "billing_entity": "org",
                    "org_id": org["org_id"],
                    "org_name": org.get("name", ""),
                    "payment_method": pm,
                }

    # Fall back to user billing
    from app.services.billing_shared import user_pk
    user_billing = ddb_get(T.billing, user_pk(user_sub), "BILLING")
    pm_id = user_billing.get("default_payment_method_id") if user_billing else None
    pm = ddb_get(T.billing, user_pk(user_sub), f"PM#{pm_id}") if pm_id else None
    return {"billing_entity": "user", "org_id": None, "org_name": None, "payment_method": pm}


def get_org_default_payment_method(org_id: str) -> Optional[Dict[str, Any]]:
    """Get the org's default payment method."""
    billing = ddb_get(T.billing, org_pk(org_id), "BILLING")
    if not billing:
        return None
    pm_id = billing.get("default_payment_method_id")
    if not pm_id:
        return None
    return ddb_get(T.billing, org_pk(org_id), f"PM#{pm_id}")


def add_org_payment_method(
    org_id: str,
    user_sub: str,
    provider: str,
    pm_type: str,
    last4: str,
    brand: str,
    exp_month: int,
    exp_year: int,
    billing_email: str = "",
    stripe_pm_id: str = "",
) -> Dict[str, Any]:
    """Add a payment method to the org. Owner only."""
    from app.services.org_service import assert_org_membership
    assert_org_membership(org_id, user_sub, min_role="owner")

    import uuid
    pm_id = f"pm_org_{uuid.uuid4().hex[:16]}"
    now = now_ts()

    item = {
        "pk": org_pk(org_id),
        "sk": f"PM#{pm_id}",
        "payment_method_id": pm_id,
        "provider": provider,
        "type": pm_type,
        "last4": last4,
        "brand": brand,
        "exp_month": exp_month,
        "exp_year": exp_year,
        "billing_email": billing_email,
        "stripe_pm_id": stripe_pm_id,
        "added_by": user_sub,
        "created_at": now,
    }
    ddb_put(T.billing, item)

    # Set as default if first PM
    existing_billing = ddb_get(T.billing, org_pk(org_id), "BILLING")
    if not existing_billing:
        ddb_put(T.billing, {
            "pk": org_pk(org_id),
            "sk": "BILLING",
            "default_payment_method_id": pm_id,
            "created_at": now,
        })

    return item


def list_org_payment_methods(org_id: str) -> List[Dict[str, Any]]:
    """List all payment methods for an org."""
    items = ddb_query_pk(T.billing, org_pk(org_id))
    return [i for i in items if i.get("sk", "").startswith("PM#")]


def get_org_billing_history(
    org_id: str,
    limit: int = 50,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Get org billing ledger entries."""
    items = ddb_query_pk(T.billing, org_pk(org_id))
    ledger = [i for i in items if i.get("sk", "").startswith("LEDGER#")]

    # Filter by date range
    if from_ts:
        ledger = [i for i in ledger if i.get("created_at", 0) >= from_ts]
    if to_ts:
        ledger = [i for i in ledger if i.get("created_at", 0) <= to_ts]

    # Sort by timestamp descending
    ledger.sort(key=lambda i: i.get("created_at", 0), reverse=True)
    return ledger[:limit]


def record_org_ledger_entry(
    org_id: str,
    user_sub: str,
    amount_cents: int,
    reason: str,
    payment_method_id: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record a billing ledger entry for the org."""
    import uuid
    entry_id = f"ledger_{uuid.uuid4().hex[:16]}"
    now = now_ts()

    item = {
        "pk": org_pk(org_id),
        "sk": f"LEDGER#{now}#{entry_id}",
        "entry_id": entry_id,
        "amount_cents": amount_cents,
        "reason": reason,
        "user_sub": user_sub,  # who triggered the charge
        "payment_method_id": payment_method_id,
        "metadata": metadata or {},
        "created_at": now,
    }
    ddb_put(T.billing, item)
    return item
```

#### 3.4.3 Unified Invoice

A monthly invoice endpoint aggregates all ledger entries under `pk=ORG#{org_id}#LEDGER#*` for the billing period and generates a PDF invoice. This is a new endpoint, not a modification of the existing user billing endpoints.

### 3.5 Organization Service

```python
# app/services/org_service.py (new)
from __future__ import annotations

import hashlib
import secrets
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts


def create_org(
    name: str,
    owner_user_sub: str,
    description: str = "",
    billing_mode: str = "individual",
    tenant_id: str = "default",
) -> Dict[str, Any]:
    """Create a new organization. The caller becomes the owner."""
    # Check per-user org limit
    user_orgs = list_user_orgs(owner_user_sub)
    from app.core.settings import S
    if len(user_orgs) >= S.org_max_per_user:
        raise HTTPException(409, f"Maximum organizations per user reached ({S.org_max_per_user})")

    org_id = f"org_{uuid.uuid4().hex[:16]}"
    slug = _generate_slug(name)
    now = now_ts()

    # Plan limits
    plan_limits = _plan_storage_limits("free")

    # Create org metadata record
    meta_item = {
        "org_id": org_id,
        "sk": "#META",
        "name": name,
        "description": description,
        "slug": slug,
        "owner_user_sub": owner_user_sub,
        "status": "active",
        "plan": "free",
        "member_count": 1,  # owner counts as member
        "storage_used_bytes": 0,
        "storage_limit_bytes": plan_limits["storage_limit_bytes"],
        "billing_mode": billing_mode,
        "default_file_permission": "editor",
        "created_at": now,
        "updated_at": now,
        "tenant_id": tenant_id,
    }
    T.organizations.put_item(Item=meta_item)

    # Add owner as first member
    member_item = {
        "org_id": org_id,
        "sk": f"MEMBER#{owner_user_sub}",
        "user_sub": owner_user_sub,
        "org_role": "owner",
        "status": "active",
        "invited_by": owner_user_sub,
        "joined_at": now,
        "updated_at": now,
        "storage_used_bytes": 0,
    }
    T.organizations.put_item(Item=member_item)

    # Create team calendar
    from app.services.org_calendar import _create_team_calendar
    calendar_id = _create_team_calendar(org_id, name, owner_user_sub)

    # Update meta with calendar ID
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": "#META"},
        UpdateExpression="SET team_calendar_id = :cid",
        ExpressionAttributeValues={":cid": calendar_id},
    )

    meta_item["team_calendar_id"] = calendar_id
    return meta_item


def get_org(org_id: str) -> Optional[Dict[str, Any]]:
    resp = T.organizations.get_item(Key={"org_id": org_id, "sk": "#META"})
    return resp.get("Item")


def list_user_orgs(user_sub: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all orgs a user belongs to (via GSI)."""
    resp = T.organizations.query(
        IndexName="user-orgs-index",
        KeyConditionExpression=Key("user_sub").eq(user_sub),
    )
    memberships = resp.get("Items", [])

    if status:
        memberships = [m for m in memberships if m.get("status") == status]

    # Enrich with org metadata
    result = []
    for m in memberships:
        org = get_org(m["org_id"])
        if org:
            result.append({**org, "org_role": m["org_role"], "membership_status": m["status"]})
    return result


def get_org_membership(org_id: str, user_sub: str) -> Optional[Dict[str, Any]]:
    resp = T.organizations.get_item(Key={"org_id": org_id, "sk": f"MEMBER#{user_sub}"})
    return resp.get("Item")


def assert_org_membership(org_id: str, user_sub: str, min_role: str = "viewer") -> Dict[str, Any]:
    """Assert user is an active member of the org with at least min_role.

    Role hierarchy: owner(4) > admin(3) > member(2) > editor(1.5) > viewer(1)
    """
    membership = get_org_membership(org_id, user_sub)
    if not membership or membership.get("status") != "active":
        raise HTTPException(403, "Not a member of this organization")

    role_order = {"viewer": 1, "editor": 1.5, "member": 2, "admin": 3, "owner": 4}
    if role_order.get(membership["org_role"], 0) < role_order.get(min_role, 0):
        raise HTTPException(403, f"Requires {min_role} role or higher")

    return membership


def invite_member(
    org_id: str,
    inviter_sub: str,
    email: str,
    org_role: str = "member",
) -> Dict[str, Any]:
    """Invite a user to the org by email."""
    assert_org_membership(org_id, inviter_sub, min_role="admin")
    org = get_org(org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    # Check member limit
    from app.core.settings import S
    plan_limits = {"free": 5, "team": 50, "enterprise": 500}
    max_members = plan_limits.get(org.get("plan", "free"), S.org_max_members)
    if org.get("member_count", 0) >= max_members:
        raise HTTPException(409, "Member limit reached for this organization plan")

    # Check for existing membership
    existing = _get_membership_by_email(org_id, email)
    if existing:
        raise HTTPException(409, "User is already a member or has a pending invite")

    # Generate invite token
    invite_id = f"inv_{uuid.uuid4().hex[:16]}"
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    now = now_ts()
    from app.core.settings import S
    expires_at = now + S.org_invite_ttl_seconds

    invite_item = {
        "org_id": org_id,
        "sk": f"INVITE#{invite_id}",
        "invite_id": invite_id,
        "email": email,
        "org_role": org_role,
        "invited_by": inviter_sub,
        "status": "pending",
        "created_at": now,
        "expires_at": expires_at,
        "token_hash": f"sha256:{token_hash}",
    }
    T.organizations.put_item(Item=invite_item)

    return {**invite_item, "token": token, "org_name": org["name"]}


def accept_invite(invite_id: str, user_sub: str, token: str) -> Dict[str, Any]:
    """Accept an org invitation."""
    # Find the invite across all orgs (scan invite items)
    # In practice, the invite_id contains the org_id or we have a GSI
    invite = _find_invite(invite_id)
    if not invite:
        raise HTTPException(404, "Invitation not found")

    if invite["status"] != "pending":
        raise HTTPException(409, f"Invitation is already {invite['status']}")

    # Validate token
    expected_hash = invite.get("token_hash", "")
    actual_hash = f"sha256:{hashlib.sha256(token.encode()).hexdigest()}"
    if expected_hash != actual_hash:
        raise HTTPException(403, "Invalid invitation token")

    # Check expiry
    if invite.get("expires_at", 0) < now_ts():
        T.organizations.update_item(
            Key={"org_id": invite["org_id"], "sk": f"INVITE#{invite_id}"},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "expired"},
        )
        raise HTTPException(410, "Invitation has expired")

    org_id = invite["org_id"]
    now = now_ts()

    # Create membership
    T.organizations.put_item(Item={
        "org_id": org_id,
        "sk": f"MEMBER#{user_sub}",
        "user_sub": user_sub,
        "org_role": invite["org_role"],
        "status": "active",
        "invited_by": invite["invited_by"],
        "joined_at": now,
        "updated_at": now,
        "storage_used_bytes": 0,
    })

    # Update invite status
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": f"INVITE#{invite_id}"},
        UpdateExpression="SET #s = :s, accepted_by = :u, accepted_at = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "accepted", ":u": user_sub, ":now": now},
    )

    # Increment member count
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": "#META"},
        UpdateExpression="SET member_count = member_count + :one, updated_at = :now",
        ExpressionAttributeValues={":one": 1, ":now": now},
    )

    org = get_org(org_id)
    return {
        "org_id": org_id,
        "org_name": org["name"] if org else "",
        "org_role": invite["org_role"],
        "status": "active",
    }


def remove_member(org_id: str, remover_sub: str, target_sub: str) -> None:
    """Remove a member from the org. Requires admin+ role."""
    remover = assert_org_membership(org_id, remover_sub, min_role="admin")
    target = get_org_membership(org_id, target_sub)
    if not target:
        raise HTTPException(404, "Member not found")

    # Cannot remove the owner
    if target["org_role"] == "owner":
        raise HTTPException(409, "Cannot remove the org owner. Transfer ownership first.")

    # Admins cannot remove other admins (only owner can)
    if target["org_role"] == "admin" and remover["org_role"] != "owner":
        raise HTTPException(403, "Only the owner can remove admins")

    T.organizations.delete_item(Key={"org_id": org_id, "sk": f"MEMBER#{target_sub}"})

    # Decrement member count
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": "#META"},
        UpdateExpression="SET member_count = member_count - :one, updated_at = :now",
        ExpressionAttributeValues={":one": 1, ":now": now_ts()},
    )


def transfer_ownership(org_id: str, current_owner_sub: str, new_owner_sub: str) -> None:
    """Transfer org ownership from current owner to another admin."""
    current = assert_org_membership(org_id, current_owner_sub, min_role="owner")
    new_member = get_org_membership(org_id, new_owner_sub)
    if not new_member or new_member["status"] != "active":
        raise HTTPException(404, "New owner must be an active member")

    now = now_ts()

    # Promote new owner
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": f"MEMBER#{new_owner_sub}"},
        UpdateExpression="SET org_role = :role, updated_at = :now",
        ExpressionAttributeValues={":role": "owner", ":now": now},
    )

    # Demote current owner to admin
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": f"MEMBER#{current_owner_sub}"},
        UpdateExpression="SET org_role = :role, updated_at = :now",
        ExpressionAttributeValues={":role": "admin", ":now": now},
    )

    # Update org meta
    T.organizations.update_item(
        Key={"org_id": org_id, "sk": "#META"},
        UpdateExpression="SET owner_user_sub = :o, updated_at = :now",
        ExpressionAttributeValues={":o": new_owner_sub, ":now": now},
    )


def _generate_slug(name: str) -> str:
    import re
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug[:63] if slug else f"org-{uuid.uuid4().hex[:8]}"


def _plan_storage_limits(plan: str) -> Dict[str, int]:
    limits = {
        "free": {"storage_limit_bytes": 1073741824},           # 1 GB
        "team": {"storage_limit_bytes": 107374182400},          # 100 GB
        "enterprise": {"storage_limit_bytes": 1099511627776},   # 1 TB
    }
    return limits.get(plan, limits["free"])


def _get_membership_by_email(org_id: str, email: str) -> Optional[Dict[str, Any]]:
    # Check members
    resp = T.organizations.query(
        KeyConditionExpression=Key("org_id").eq(org_id) & Key("sk").begins_with("MEMBER#"),
    )
    for item in resp.get("Items", []):
        if item.get("user_sub", "").lower() == email.lower():
            return item

    # Check pending invites
    resp = T.organizations.query(
        KeyConditionExpression=Key("org_id").eq(org_id) & Key("sk").begins_with("INVITE#"),
    )
    for item in resp.get("Items", []):
        if item.get("email", "").lower() == email.lower() and item.get("status") == "pending":
            return item

    return None


def _find_invite(invite_id: str) -> Optional[Dict[str, Any]]:
    # Use invite-email-index or scan (in production, consider a dedicated GSI)
    # For now, the invite_id format encodes the org: inv_{org_hash}_{random}
    # Simplified approach: scan organizations table for INVITE#{invite_id}
    # In practice, add a GSI: invite-id-index (pk=invite_id)
    resp = T.organizations.scan(
        FilterExpression="sk = :sk",
        ExpressionAttributeValues={":sk": f"INVITE#{invite_id}"},
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None
```

---

## 4. API Endpoints

### 4.1 Organization CRUD

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/orgs` | `require_ui_session` | Create a new organization |
| GET | `/ui/orgs` | `require_ui_session` | List user's organizations |
| GET | `/ui/orgs/{org_id}` | `require_ui_session` | Get org details (members must belong to org) |
| PATCH | `/ui/orgs/{org_id}` | `require_ui_session` (owner/admin) | Update org name, description, settings |
| DELETE | `/ui/orgs/{org_id}` | `require_ui_session` (owner only) | Archive organization |

### 4.2 Member Management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/orgs/{org_id}/members` | `require_ui_session` (any member) | List org members |
| POST | `/ui/orgs/{org_id}/members/invite` | `require_ui_session` (owner/admin) | Invite member by email |
| PATCH | `/ui/orgs/{org_id}/members/{user_sub}/role` | `require_ui_session` (owner/admin) | Change member role |
| DELETE | `/ui/orgs/{org_id}/members/{user_sub}` | `require_ui_session` (owner/admin) | Remove member |
| POST | `/ui/orgs/invites/{invite_id}/accept` | `require_ui_session` | Accept invitation |
| POST | `/ui/orgs/invites/{invite_id}/decline` | `require_ui_session` | Decline invitation |
| GET | `/ui/orgs/invites/pending` | `require_ui_session` | List pending invitations for current user |
| POST | `/ui/orgs/{org_id}/leave` | `require_ui_session` | Leave org (non-owners only) |
| POST | `/ui/orgs/{org_id}/transfer-ownership` | `require_ui_session` (owner only) | Transfer ownership |

### 4.3 Org File Space

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/orgs/{org_id}/files` | `require_ui_session` (viewer+) | List files in org root |
| GET | `/ui/orgs/{org_id}/files/{path}` | `require_ui_session` (viewer+) | List files in subfolder |
| POST | `/ui/orgs/{org_id}/files/upload` | `require_ui_session` (editor+) | Upload file to org space |
| DELETE | `/ui/orgs/{org_id}/files/{node_id}` | `require_ui_session` (editor+ for own, admin+ for any) | Delete file |
| GET | `/ui/orgs/{org_id}/files/{node_id}/download` | `require_ui_session` (viewer+) | Download file |

### 4.4 Org Calendar

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/orgs/{org_id}/calendar/events` | `require_ui_session` (any member) | List team calendar events |
| POST | `/ui/orgs/{org_id}/calendar/events` | `require_ui_session` (member+) | Create team event |
| PATCH | `/ui/orgs/{org_id}/calendar/events/{event_id}` | `require_ui_session` (creator or admin) | Update team event |
| DELETE | `/ui/orgs/{org_id}/calendar/events/{event_id}` | `require_ui_session` (creator or admin) | Delete team event |

### 4.5 Org Billing

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/orgs/{org_id}/billing/payment-methods` | `require_ui_session` (owner) | List org payment methods |
| POST | `/ui/orgs/{org_id}/billing/payment-methods` | `require_ui_session` (owner) | Add org payment method |
| DELETE | `/ui/orgs/{org_id}/billing/payment-methods/{pm_id}` | `require_ui_session` (owner) | Remove org payment method |
| POST | `/ui/orgs/{org_id}/billing/set-default` | `require_ui_session` (owner) | Set default org payment method |
| GET | `/ui/orgs/{org_id}/billing/history` | `require_ui_session` (owner) | Paginated billing history |
| GET | `/ui/orgs/{org_id}/billing/invoice/{period}` | `require_ui_session` (owner) | Download monthly invoice PDF |

### 4.6 Request / Response Models

```python
# app/models.py -- new models

class OrgCreateReq(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1024)
    billing_mode: str = Field(default="individual", pattern=r"^(org|individual)$")

class OrgUpdateReq(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1024)
    billing_mode: Optional[str] = Field(default=None, pattern=r"^(org|individual)$")
    default_file_permission: Optional[str] = Field(default=None, pattern=r"^(viewer|editor|admin)$")

class OrgMemberInviteReq(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    org_role: str = Field(default="member", pattern=r"^(admin|member|viewer)$")

class OrgMemberRoleUpdateReq(BaseModel):
    org_role: str = Field(pattern=r"^(admin|member|viewer)$")

class OrgTransferOwnershipReq(BaseModel):
    new_owner_user_sub: str = Field(min_length=1)

class OrgInviteAcceptReq(BaseModel):
    token: str = Field(min_length=1)

class OrgBillingPmAddReq(BaseModel):
    provider: str = Field(default="stripe", pattern=r"^(stripe|paypal)$")
    stripe_token: Optional[str] = None
    billing_email: Optional[str] = None

class OrgOut(BaseModel):
    org_id: str
    name: str
    description: Optional[str]
    slug: str
    owner_user_sub: str
    status: str
    plan: str
    member_count: int
    storage_used_bytes: int
    storage_limit_bytes: int
    billing_mode: str
    created_at: int
    updated_at: int
    org_role: Optional[str] = None  # caller's role (populated in list)
    team_calendar_id: Optional[str] = None

class OrgMemberOut(BaseModel):
    user_sub: str
    org_role: str
    status: str
    display_name: Optional[str] = None
    email: Optional[str] = None
    joined_at: int
    storage_used_bytes: int = 0
    last_active_at: Optional[int] = None

class OrgInviteOut(BaseModel):
    invite_id: str
    org_id: str
    org_name: str
    email: str
    org_role: str
    status: str
    invited_by: str
    created_at: int
    expires_at: int

class OrgEventCreateReq(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4096)
    start_time: str = Field(description="ISO 8601 datetime")
    end_time: str = Field(description="ISO 8601 datetime")
    all_day: bool = False
    attendees: Optional[list[str]] = None

class OrgEventUpdateReq(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4096)
    start_time: Optional[str] = None
    end_time: Optional[str] = None

class OrgEventOut(BaseModel):
    event_id: str
    title: str
    description: Optional[str]
    start_time: str
    end_time: str
    all_day: bool
    created_by: str
    org_id: str
    attendees: list[str]
    created_at: int
    updated_at: int
```

---

## 5. Frontend Components

### 5.1 Organizations Page

**File**: `frontend/src/pages/orgs/OrgsPage.tsx` (new)

- Lists all organizations the user belongs to (cards with name, role, member count)
- "Create Organization" button opens a dialog
- Each card links to the org dashboard
- Pending invitations banner at top with accept/decline buttons

### 5.2 Org Dashboard

**File**: `frontend/src/pages/orgs/OrgDashboard.tsx` (new)

- Tabs: Overview, Members, Files, Calendar, Billing (owner only)
- Overview shows member count, storage usage pie chart, recent activity feed
- Members tab shows data table with role badges, invite button, role change dropdown

### 5.3 Org File Browser

**File**: `frontend/src/pages/orgs/OrgFiles.tsx` (new)

- Reuses `FileManagerView` component from `frontend/src/pages/files/`
- Overrides the API endpoints to use `/ui/orgs/{org_id}/files/*`
- Shows uploader avatar on each file row
- Permission badge (viewer/editor/admin) shown in toolbar

### 5.4 Org Calendar

**File**: `frontend/src/pages/orgs/OrgCalendar.tsx` (new)

- Reuses `CalendarView` component
- Adds a "Team" calendar layer with a distinct color
- Member availability sidebar for scheduling

### 5.5 Org Billing

**File**: `frontend/src/pages/orgs/OrgBilling.tsx` (new)

- Payment methods management (add Stripe card, set default)
- Billing history table with date, member, amount, description
- Monthly invoice download link

### 5.6 Sidebar Integration

**File**: `frontend/src/components/layout/Sidebar.tsx` (modified)

- New "Organizations" nav item with `Building2` icon in the Productivity group
- Dropdown showing org list for quick switching

### 5.7 Frontend API Endpoints

```typescript
// frontend/src/api/endpoints/orgs.ts (new)
import { client } from "@/api/client";
import type { OrgOut, OrgMemberOut, OrgInviteOut, OrgEventOut } from "@/api/types";

// Org CRUD
export const createOrg = (req: { name: string; description?: string; billing_mode?: string }) =>
  client.post<OrgOut>("/ui/orgs", req);

export const listOrgs = () =>
  client.get<OrgOut[]>("/ui/orgs");

export const getOrg = (orgId: string) =>
  client.get<OrgOut>(`/ui/orgs/${orgId}`);

export const updateOrg = (orgId: string, req: Partial<{ name: string; description: string }>) =>
  client.patch<OrgOut>(`/ui/orgs/${orgId}`, req);

export const archiveOrg = (orgId: string) =>
  client.delete(`/ui/orgs/${orgId}`);

// Members
export const listMembers = (orgId: string) =>
  client.get<OrgMemberOut[]>(`/ui/orgs/${orgId}/members`);

export const inviteMember = (orgId: string, req: { email: string; org_role?: string }) =>
  client.post<OrgInviteOut>(`/ui/orgs/${orgId}/members/invite`, req);

export const removeMember = (orgId: string, userSub: string) =>
  client.delete(`/ui/orgs/${orgId}/members/${userSub}`);

export const changeMemberRole = (orgId: string, userSub: string, req: { org_role: string }) =>
  client.patch(`/ui/orgs/${orgId}/members/${userSub}/role`, req);

export const acceptInvite = (inviteId: string, token: string) =>
  client.post(`/ui/orgs/invites/${inviteId}/accept`, { token });

export const listPendingInvites = () =>
  client.get<OrgInviteOut[]>("/ui/orgs/invites/pending");

// Calendar
export const listOrgEvents = (orgId: string, params?: { from?: string; to?: string }) =>
  client.get<OrgEventOut[]>(`/ui/orgs/${orgId}/calendar/events`, { params });

export const createOrgEvent = (orgId: string, req: any) =>
  client.post<OrgEventOut>(`/ui/orgs/${orgId}/calendar/events`, req);
```

### 5.8 Route Configuration

**File**: `frontend/src/App.tsx` (modified)

```typescript
<Route path="/orgs" element={<OrgsPage />} />
<Route path="/orgs/:orgId" element={<OrgDashboard />} />
<Route path="/orgs/:orgId/files/*" element={<OrgFiles />} />
<Route path="/orgs/:orgId/calendar" element={<OrgCalendar />} />
<Route path="/orgs/:orgId/billing" element={<OrgBilling />} />
```

---

## 6. DynamoDB Table Definitions

### 6.1 New Tables for `scripts/local-ddb-init.py`

```python
TableDef("organizations", pk="org_id", sk="sk",
    gsis=[
        GSIDef("user-orgs-index", pk="user_sub", sk="org_id"),
        GSIDef("invite-email-index", pk="email", sk="org_id"),
        GSIDef("slug-index", pk="slug", sk="org_id"),
    ]),
```

### 6.2 Settings Additions for `app/core/settings.py`

```python
# Organizations / Workspaces (ENTERPRISE-003)
orgs_enabled: bool = os.environ.get("ORGS_ENABLED", "0") not in ("0", "false", "False")
organizations_table_name: str = os.environ.get("ORGANIZATIONS_TABLE_NAME", "organizations")
org_max_members: int = int(os.environ.get("ORG_MAX_MEMBERS", "100"))
org_max_per_user: int = int(os.environ.get("ORG_MAX_PER_USER", "10"))
org_invite_ttl_seconds: int = int(os.environ.get("ORG_INVITE_TTL_SECONDS", str(7 * 24 * 3600)))
org_default_storage_limit_bytes: int = int(os.environ.get("ORG_DEFAULT_STORAGE_LIMIT_BYTES", str(100 * 1024 * 1024 * 1024)))
org_file_space_prefix: str = os.environ.get("ORG_FILE_SPACE_PREFIX", "ORG")
org_invite_rate_limit_per_hour: int = int(os.environ.get("ORG_INVITE_RATE_LIMIT_PER_HOUR", "20"))
```

---

## 7. E2E Test Plan

### 7.1 Test File

**File**: `frontend/e2e/org-workspaces.spec.ts` (new)

### 7.2 Test Sections

| Section | Tests | Description |
|---------|-------|-------------|
| 92 | 5 | Org CRUD API (create, list, get, update name, archive) |
| 93 | 7 | Member management API (invite, list, accept, decline, change role, remove, duplicate invite) |
| 94 | 5 | Org file space API (upload, list, download, delete, permission check for viewer) |
| 95 | 4 | Org calendar API (create event, list events, update, delete) |
| 96 | 5 | Org billing API (add PM, list PMs, set default, billing history, remove PM) |
| 97 | 4 | Orgs UI (create dialog, member list, file browser, calendar view) |
| 98 | 3 | Cross-org isolation (Alice's org files not visible to Bob who is not a member) |

### 7.3 Test Setup

```typescript
const TS = Date.now();
let orgId: string;
let inviteId: string;
let inviteToken: string;

test.describe("92 - Org CRUD API", () => {
    test("create org", async ({ request }) => {
        const resp = await request.post("/ui/orgs", {
            headers: { "x-csrf-token": sessions.alice.csrf_token },
            data: { name: `E2E Org ${TS}`, description: "Test org" }
        });
        expect(resp.status()).toBe(201);
        const data = await resp.json();
        orgId = data.org_id;
        expect(data.name).toBe(`E2E Org ${TS}`);
        expect(data.owner_user_sub).toBe("e2e_alice@test.local");
        expect(data.member_count).toBe(1);
        expect(data.status).toBe("active");
    });

    test("list orgs shows new org", async ({ request }) => {
        const resp = await request.get("/ui/orgs", {
            headers: { Cookie: sessions.alice.cookie },
        });
        expect(resp.status()).toBe(200);
        const orgs = await resp.json();
        const found = orgs.find((o: any) => o.org_id === orgId);
        expect(found).toBeTruthy();
        expect(found.org_role).toBe("owner");
    });

    test("get org details", async ({ request }) => {
        const resp = await request.get(`/ui/orgs/${orgId}`, {
            headers: { Cookie: sessions.alice.cookie },
        });
        expect(resp.status()).toBe(200);
        const data = await resp.json();
        expect(data.name).toBe(`E2E Org ${TS}`);
        expect(data.team_calendar_id).toBeTruthy();
    });

    test("update org name", async ({ request }) => {
        const resp = await request.patch(`/ui/orgs/${orgId}`, {
            headers: {
                "x-csrf-token": sessions.alice.csrf_token,
                Cookie: sessions.alice.cookie,
            },
            data: { name: `E2E Org Updated ${TS}` },
        });
        expect(resp.status()).toBe(200);
        const data = await resp.json();
        expect(data.name).toBe(`E2E Org Updated ${TS}`);
    });

    test("archive org", async ({ request }) => {
        // Create a throwaway org to archive
        const create = await request.post("/ui/orgs", {
            headers: { "x-csrf-token": sessions.alice.csrf_token },
            data: { name: `E2E Org Archive ${TS}` },
        });
        const archiveOrgId = (await create.json()).org_id;

        const resp = await request.delete(`/ui/orgs/${archiveOrgId}`, {
            headers: { "x-csrf-token": sessions.alice.csrf_token },
        });
        expect(resp.status()).toBe(204);
    });
});

test.describe("93 - Member management API", () => {
    test("invite Bob to org", async ({ request }) => {
        const resp = await request.post(`/ui/orgs/${orgId}/members/invite`, {
            headers: { "x-csrf-token": sessions.alice.csrf_token },
            data: { email: "e2e_bob@test.local", org_role: "member" },
        });
        expect(resp.status()).toBe(201);
        const data = await resp.json();
        inviteId = data.invite_id;
        inviteToken = data.token;
        expect(data.status).toBe("pending");
    });

    test("list members shows only Alice", async ({ request }) => {
        const resp = await request.get(`/ui/orgs/${orgId}/members`, {
            headers: { Cookie: sessions.alice.cookie },
        });
        expect(resp.status()).toBe(200);
        const members = await resp.json();
        expect(members.length).toBe(1);
        expect(members[0].user_sub).toBe("e2e_alice@test.local");
        expect(members[0].org_role).toBe("owner");
    });

    test("Bob accepts invite", async ({ request }) => {
        const resp = await request.post(`/ui/orgs/invites/${inviteId}/accept`, {
            headers: { "x-csrf-token": sessions.bob.csrf_token },
            data: { token: inviteToken },
        });
        expect(resp.status()).toBe(200);
        const data = await resp.json();
        expect(data.org_role).toBe("member");
    });

    // ... more tests
});
```

### 7.4 File Space Isolation Test

```typescript
test.describe("98 - Cross-org isolation", () => {
    test("Bob cannot access Alice's org files when not a member", async ({ request }) => {
        // Create a second org owned by Alice without Bob
        const create = await request.post("/ui/orgs", {
            headers: { "x-csrf-token": sessions.alice.csrf_token },
            data: { name: `E2E Private Org ${TS}` },
        });
        const privateOrgId = (await create.json()).org_id;

        // Bob tries to list files
        const resp = await request.get(`/ui/orgs/${privateOrgId}/files`, {
            headers: { Cookie: sessions.bob.cookie },
        });
        expect(resp.status()).toBe(403);
    });
});
```

---

## 8. Edge Cases & Error Handling

### 8.1 Owner Transfer

If the org owner wants to leave, they must first transfer ownership to another admin. Attempting to leave as the sole owner returns `409 Conflict: "Cannot leave org as sole owner. Transfer ownership first."`.

### 8.2 Org Deletion Cascading

Archiving an org soft-deletes it (status -> `archived`). Shared files remain in S3 for 90 days. Members lose access immediately. Billing stops. The org can be restored within 90 days by a root admin.

### 8.3 Billing Mode Switch

Switching from `individual` to `org` billing does not retroactively charge the org for past member purchases. It only affects future transactions. The switch requires the org to have at least one valid payment method.

### 8.4 Member Limit

Each org has a maximum member count based on plan (`free=5`, `team=50`, `enterprise=500`). Inviting beyond the limit returns `409 Conflict: "Member limit reached"`. The limit is configurable via `ORG_MAX_MEMBERS`.

### 8.5 Concurrent File Operations

Two members uploading a file with the same name to the same org folder concurrently: DynamoDB conditional writes ensure the second upload gets a conflict (`409`). The frontend shows a "file already exists" error with an option to rename or overwrite.

### 8.6 Invite Token Security

Invitation tokens are random 32-byte values. Only the SHA-256 hash is stored in DynamoDB. The plaintext token is sent in the invite email link. When accepting, the server hashes the provided token and compares with the stored hash.

### 8.7 Cross-Org File References

A user in two orgs cannot reference a file from org-A in org-B's file space. Files are strictly scoped to their org's PK. Users can download from one org and upload to another, but no cross-org linking.

### 8.8 Org Slug Conflicts

Org slugs must be unique within a tenant. The `slug-index` GSI enforces this. If a slug collision occurs, the system appends a random suffix.

### 8.9 Self-Removal

A member can leave an org voluntarily via `POST /ui/orgs/{org_id}/leave`. The owner cannot leave without transferring ownership first. If the owner is the only member, they must archive the org instead.

---

## 9. Security Considerations

### 9.1 Authorization Model

Every org endpoint verifies:
1. The authenticated user is a member of the org (`assert_org_membership`)
2. The user's org role meets the minimum required (`min_role` parameter)

```python
def assert_org_membership(org_id: str, user_sub: str, min_role: str = "viewer") -> dict:
    membership = get_org_membership(org_id, user_sub)
    if not membership or membership["status"] != "active":
        raise HTTPException(403, "Not a member of this organization")
    role_order = {"viewer": 0, "member": 1, "editor": 2, "admin": 3, "owner": 4}
    if role_order.get(membership["org_role"], 0) < role_order.get(min_role, 0):
        raise HTTPException(403, "Insufficient org role")
    return membership
```

### 9.2 Billing Isolation

Org billing records use `pk=ORG#{org_id}`. A user cannot access another org's billing data even if they are a platform admin. Only org owners and root admins can view org billing.

### 9.3 File Access Audit

All org file operations (upload, download, delete) are logged with `audit_event("org_file_*", ...)` including the user who performed the action and the org context.

### 9.4 Invite Enumeration Prevention

The `POST /ui/orgs/{org_id}/members/invite` endpoint does not reveal whether the email address belongs to an existing user. The invite is created regardless and a notification is sent. The accept flow handles both existing and new users.

### 9.5 Rate Limiting

Org invite endpoints are rate-limited to prevent spam:
- Max 20 invites per org per hour
- Max 50 invites per user per day

Using the existing rate limit infrastructure from `app/middleware/rate_limit.py` with key `ORG_INVITE#{org_id}`.

---

## 10. Observability

### 10.1 Metrics

- `org_count` -- total active organizations (gauge)
- `org_member_count{org_id}` -- members per org
- `org_storage_used_bytes{org_id}` -- storage consumption per org
- `org_billing_total_cents{org_id, period}` -- monthly spend per org
- `org_invite_acceptance_rate` -- percentage of invites accepted

### 10.2 Alerts

- Alert when org storage exceeds 90% of limit
- Alert when org billing exceeds a configurable monthly threshold
- Alert when org has >10 pending invites (possible spam)

---

## 11. Migration Plan

### 11.1 Phase 1: Core Infrastructure (Week 1-2)

1. Create `organizations` table with GSIs
2. Implement org CRUD service and router
3. Implement member management (invite, accept, remove, role change)
4. Register router in `app/main.py`

### 11.2 Phase 2: Shared Files (Week 3)

1. Extend file manager with org PK support
2. Implement org file endpoints
3. Add permission checks based on org membership role

### 11.3 Phase 3: Team Calendar (Week 4)

1. Auto-create team calendar on org creation
2. Implement org calendar event CRUD
3. Frontend team calendar layer

### 11.4 Phase 4: Org Billing (Week 5-6)

1. Org payment method CRUD
2. Billing routing logic (`resolve_payment_context`)
3. Unified invoice generation
4. Frontend org billing page

### 11.5 Phase 5: Frontend & E2E (Week 7)

1. Orgs page, dashboard, file browser, calendar, billing
2. Sidebar integration
3. Full E2E test suite

---

## Codebase References

| Ref | File | Line(s) | Status |
|-----|------|---------|--------|
| `filemgr_table_name` | `app/core/settings.py` | 752 | VERIFIED (ticket said 749) |
| `calendar_table_name` | `app/core/settings.py` | 417 | VERIFIED |
| `billing_table_name` | `app/core/settings.py` | 321 | VERIFIED |
| `contacts_table_name` | `app/core/settings.py` | 449 | VERIFIED |
| `CalendarShareIn` import | `app/routers/calendar.py` | 27 | VERIFIED |
| `user_pk` | `app/services/billing_shared.py` | 16 | VERIFIED |
| `AdminScope` enum | `app/auth/roles.py` | 14-18 | VERIFIED |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED (NOT in app/auth/deps.py) |
| Org service | `app/services/org_service.py` | exists | VERIFIED |
| Org billing | `app/services/org_billing.py` | exists | VERIFIED |
| Org calendar | `app/services/org_calendar.py` | exists | VERIFIED |
| Org files | `app/services/org_files.py` | exists | VERIFIED |
| Org router | `app/routers/orgs.py` | exists, registered at `app/main.py:119,454` | VERIFIED |
| Frontend orgs API | `frontend/src/api/endpoints/orgs.ts` | exists | VERIFIED |
| OrgsPage | `frontend/src/pages/orgs/OrgsPage.tsx` | exists | VERIFIED |
| OrgDashboard | `frontend/src/pages/orgs/OrgDashboard.tsx` | exists | VERIFIED |
