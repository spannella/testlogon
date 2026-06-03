# GROUP-001: User Group Creation & Membership

**Ticket**: GROUP-001
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

GROUP-001 introduces User Groups — lightweight communities that any user can create and manage. Unlike syndicates (subscription-based creator collectives), user groups are free to join and focused on community building. A group has an admin (the creator), optional moderators, and members. Groups can be `public` (anyone joins instantly) or `private` (invite/approval required). This ticket covers group CRUD, membership lifecycle, role management, discovery, and admin succession.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to create a group so I can build a community. | POST creates group; creator becomes admin; group appears in discovery. |
| Admin | As a group admin, I want to invite users to my group. | POST invite; invited user receives a pending invitation. |
| User | As a user, I want to request to join a private group. | POST join request; admin/moderator can approve or reject. |
| User | As a user, I want to instantly join a public group. | POST join on public group; membership immediately active. |
| Admin | As a group admin, I want to promote a member to moderator. | PATCH member role; moderator gains removal powers. |
| Admin | As a group admin, I want to remove members. | DELETE member; removed from group. |
| Moderator | As a moderator, I want to remove non-admin members. | DELETE member (non-admin only); 403 if target is admin. |
| User | As a user, I want to discover and search for public groups. | GET public groups list with name/topic search. |
| User | As a user, I want to leave a group I've joined. | POST leave; admin succession triggered if admin leaves. |

### 1.3 Why This Is Needed

The platform currently supports one-to-one interactions (DMs, follows) and creator-to-fan relationships (subscriptions). There is no peer-to-peer community primitive. User groups fill this gap and are the foundation for group newsfeeds (GROUP-002), advertising (GROUP-003), and treasury (GROUP-004).

### 1.4 Group Roles & Succession

**Roles**: Admin (full control) > Moderator (remove non-admin members, manage join requests) > Member (post, comment, react, contribute to treasury).

**Admin succession** (same as syndicates): If admin leaves, oldest moderator (by `promoted_at`) becomes admin. If no moderators, oldest member (by `joined_at`). If empty, group is dissolved.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Auth**: `require_ui_session` from `app/auth/deps.py` (**verified** — see `app/auth/deps.py`). Group-level roles (admin/mod/member) are checked by querying the membership record, not the platform auth role.
- **User profiles** (`T.profile`): **Verified** — Display names, avatars (see `app/core/tables.py`, `app/core/settings.py` `profile_table_name`).
- **Fan club channels** (`T.fan_club_channels`): **Verified** — Similar group membership pattern (see `app/core/tables.py:121,245`, `app/core/settings.py:1432`, `scripts/local-ddb-init.py:1077`).

### 2.2 Gaps

1. No `user_groups` DDB table.
2. No group service or router.
3. No invitation/join-request workflow.
4. No admin succession logic.
5. No group discovery/search.
6. No frontend pages for groups.

---

## 3. Technical Design

### 3.1 Architecture & Data Flow

```
Group Creation Flow
───────────────────
  User Browser                   Backend                      DynamoDB
  ────────────                   ───────                      ────────
  POST /ui/groups           ──> create_group()           ──> put_item(GROUP#{id}, META)
  { name, description,          validate inputs               put_item(GROUP#{id}, MEMBER#{user})
    visibility, topic }         check max groups/user          put_item(USERGROUPS#{user}, GROUP#{id})
                                create admin membership
                            <── 201 GroupOut

  Join Flow (Public Group)
  ────────────────────────
  POST /ui/groups/{id}/join ──> join_group()             ──> put_item(GROUP#{id}, MEMBER#{user})
                                check visibility=public       put_item(USERGROUPS#{user}, GROUP#{id})
                                set status=active             update_item(member_count += 1)
                            <── 200 { status: "active" }

  Join Flow (Private Group)
  ─────────────────────────
  POST /ui/groups/{id}/join ──> join_group()             ──> put_item(GROUP#{id}, MEMBER#{user})
                                check visibility=private       status=pending_approval
                            <── 200 { status: "pending_approval" }

  POST .../requests/{user}/review ──> approve_join_request() ──> update_item(status=active)
  { approved: true }                  check admin/mod role        put_item(USERGROUPS#{user}, GROUP#{id})
                                                                  update_item(member_count += 1)

  Admin Succession Flow
  ─────────────────────
  POST /ui/groups/{id}/leave ──> leave_group()           ──> delete_item(MEMBER#{admin})
                                  if admin:                   delete_item(USERGROUPS#{admin})
                                    _admin_succession()       update_item(member_count -= 1)
                                      1. find oldest mod
                                      2. if none: oldest member
                                      3. if empty: dissolve
                                      4. update META.admin_user_id
```

### 3.2 DynamoDB Access Patterns

| # | Access Pattern | Table | PK | SK / GSI | Query |
|---|----------------|-------|-----|----------|-------|
| 1 | Get group metadata | `user_groups` | `GROUP#{group_id}` | `META` | `get_item` |
| 2 | List group members | `user_groups` | `GROUP#{group_id}` | `SK begins_with MEMBER#` | `query` |
| 3 | Get single membership | `user_groups` | `GROUP#{group_id}` | `MEMBER#{user_id}` | `get_item` |
| 4 | List user's groups | `user_groups` | `USERGROUPS#{user_id}` | `SK begins_with GROUP#` | `query` |
| 5 | Discover public groups | `user_groups` | GSI1 PK=`public` | SK=`created_at` DESC | `query` with limit |
| 6 | Active groups by popularity | `user_groups` | GSI2 PK=`active` | SK=`member_count` DESC | `query` with limit |
| 7 | Pending invites/requests | `user_groups` | `GROUP#{group_id}` | `MEMBER#` prefix + filter `status in (invited, pending_approval)` | `query` + filter |
| 8 | Check max groups per user | `user_groups` | `USERGROUPS#{user_id}` | Count items | `query` with Select=COUNT |

### 3.3 DynamoDB Table: `user_groups`

Single-table design with group metadata and membership.

**Group metadata** (`pk=GROUP#{group_id}`, `sk=META`):

| Field | Type | Description |
|-------|------|-------------|
| `group_id` | S | `grp_<uuid4_hex>` |
| `name` | S | 3-100 chars |
| `description` | S | Max 2000 chars |
| `topic` | S | Optional topic/category |
| `visibility` | S | `public` or `private` |
| `status` | S | `active` or `dissolved` |
| `admin_user_id` | S | Current admin user_sub |
| `cover_image_url` | S | Optional S3 URL |
| `member_count` | N | Atomically incremented |
| `created_at` | N | Unix timestamp |

**Membership** (`pk=GROUP#{group_id}`, `sk=MEMBER#{user_id}`):

| Field | Type | Description |
|-------|------|-------------|
| `user_id` | S | Member's user_sub |
| `group_id` | S | Denormalized for GSI |
| `role` | S | `admin`, `moderator`, or `member` |
| `status` | S | `active`, `invited`, `pending_approval` |
| `display_name` | S | Denormalized from profile |
| `joined_at` | N | When status became active |
| `promoted_at` | N | When promoted to moderator/admin |

**User-to-Group index** (`pk=USERGROUPS#{user_id}`, `sk=GROUP#{group_id}`): Denormalized record with `group_name`, `role`, `joined_at` for listing "my groups".

**GSIs**:

| GSI | PK | SK | Purpose |
|-----|----|----|---------|
| `GSI1` | `visibility` | `created_at` | Public group discovery |
| `GSI2` | `status` | `member_count` | Active groups by popularity |

**`scripts/local-ddb-init.py`**: `attr_types={"created_at": "N", "joined_at": "N", "member_count": "N", "promoted_at": "N"}`

### 3.4 API Request/Response Examples

#### 3.4.1 Create Group

```
POST /ui/groups
x-csrf-token: <token>

{
  "name": "Photography Club",
  "description": "Share your best shots and learn new techniques.",
  "visibility": "public",
  "topic": "photography"
}

201 Created
{
  "group_id": "grp_a1b2c3d4e5f6",
  "name": "Photography Club",
  "description": "Share your best shots and learn new techniques.",
  "topic": "photography",
  "visibility": "public",
  "status": "active",
  "admin_user_id": "alice-sub-123",
  "cover_image_url": null,
  "member_count": 1,
  "created_at": 1748534400,
  "updated_at": 1748534400,
  "my_role": "admin"
}
```

#### 3.4.2 Join Public Group

```
POST /ui/groups/grp_a1b2c3d4e5f6/join
x-csrf-token: <token>

200 OK
{
  "user_id": "bob-sub-456",
  "role": "member",
  "status": "active",
  "display_name": "Bob",
  "joined_at": 1748534500
}
```

#### 3.4.3 Request to Join Private Group

```
POST /ui/groups/grp_private_id/join
x-csrf-token: <token>

200 OK
{
  "user_id": "bob-sub-456",
  "role": "member",
  "status": "pending_approval",
  "display_name": "Bob",
  "joined_at": null
}
```

#### 3.4.4 Approve Join Request

```
POST /ui/groups/grp_private_id/requests/bob-sub-456/review
x-csrf-token: <token>

{ "approved": true }

200 OK
{ "ok": true, "status": "active" }
```

#### 3.4.5 Promote Member to Moderator

```
PATCH /ui/groups/grp_a1b2c3d4e5f6/members/bob-sub-456/role
x-csrf-token: <token>

{ "role": "moderator" }

200 OK
{
  "user_id": "bob-sub-456",
  "role": "moderator",
  "status": "active",
  "promoted_at": 1748534600
}
```

#### 3.4.6 Discover Public Groups

```
GET /ui/groups/discover?query=photo&limit=10

200 OK
{
  "groups": [
    {
      "group_id": "grp_a1b2c3d4e5f6",
      "name": "Photography Club",
      "description": "Share your best shots...",
      "topic": "photography",
      "visibility": "public",
      "member_count": 42,
      "created_at": 1748534400
    }
  ],
  "cursor": null,
  "has_more": false
}
```

### 3.5 Error Handling Matrix

| # | Scenario | HTTP Status | Error Message | Recovery |
|---|----------|-------------|---------------|----------|
| 1 | Group not found | 404 | "Group not found" | Redirect to groups list |
| 2 | Not a member | 403 | "Not a member of this group" | Show join button |
| 3 | Not admin | 403 | "Only the group admin can perform this action" | Hide admin UI |
| 4 | Already a member | 409 | "Already a member of this group" | Show group page |
| 5 | Group dissolved | 410 | "This group has been dissolved" | Show dissolved message |
| 6 | Max groups exceeded | 400 | "Maximum number of groups reached (50)" | Show limit info |
| 7 | Moderator removing admin | 403 | "Moderators cannot remove the admin" | Disable remove button |
| 8 | Non-member trying to post | 403 | "Not a member of this group" | Show join CTA |
| 9 | Name too short | 422 | Pydantic: min_length 3 | Highlight field |
| 10 | Description too long | 422 | Pydantic: max_length 2000 | Show character count |
| 11 | Invalid visibility value | 422 | Pydantic: Literal constraint | Use radio buttons in UI |
| 12 | Join request already pending | 409 | "Join request already pending" | Show pending status |
| 13 | Cannot dissolve with active members (optional) | 400 | "Remove all members before dissolving" | Show member list |

### 3.6 Settings & Table Handle

**File**: `app/core/settings.py`

```python
ddb_user_groups_table: str = os.environ.get("DDB_USER_GROUPS_TABLE", "user_groups")
user_group_max_members: int = int(os.environ.get("USER_GROUP_MAX_MEMBERS", "10000"))
user_group_max_per_user: int = int(os.environ.get("USER_GROUP_MAX_PER_USER", "50"))
```

**File**: `app/core/tables.py` — Add `user_groups: Any` to the `Tables` dataclass and `user_groups=ddb.Table(S.ddb_user_groups_table)` to the `T` initialization block.

### 3.7 Backend Service (`app/services/user_groups.py`)

Key functions:

| Function | Description |
|----------|-------------|
| `create_group(creator_sub, name, description, visibility, topic)` | Create group + admin membership + user-group index |
| `get_group(group_id)` | Get group metadata |
| `update_group(group_id, user_id, **updates)` | Admin-only settings update |
| `join_group(group_id, user_id, display_name)` | Instant join (public) or request (private) |
| `invite_to_group(group_id, inviter_id, invitee_id)` | Create `status=invited` membership |
| `respond_to_invite(group_id, user_id, accept)` | Accept/decline invitation |
| `approve_join_request(group_id, approver_id, applicant_id, approved)` | Admin/mod approves or rejects |
| `promote_member(group_id, admin_id, target_id, new_role)` | Admin promotes/demotes |
| `remove_member(group_id, remover_id, target_id)` | Admin removes anyone; mod removes non-admins |
| `leave_group(group_id, user_id)` | Leave + trigger `_admin_succession()` if admin |
| `_admin_succession(group_id)` | Transfer admin to oldest mod/member or dissolve |
| `search_public_groups(query, topic, cursor, limit)` | GSI1 query + name/topic filter |
| `dissolve_group(group_id, admin_id)` | Set dissolved; trigger GROUP-004 treasury return |

### 3.8 Backend Router (`app/routers/user_groups.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/groups` | `require_ui_session` | Create group |
| GET | `/ui/groups` | `require_ui_session` | List user's groups |
| GET | `/ui/groups/discover` | `require_ui_session` | Browse/search public groups |
| GET | `/ui/groups/{group_id}` | `require_ui_session` | Get group details |
| PATCH | `/ui/groups/{group_id}` | `require_ui_session` | Update settings (admin) |
| DELETE | `/ui/groups/{group_id}` | `require_ui_session` | Dissolve group (admin) |
| GET | `/ui/groups/{group_id}/members` | `require_ui_session` | List members |
| POST | `/ui/groups/{group_id}/join` | `require_ui_session` | Join or request |
| POST | `/ui/groups/{group_id}/leave` | `require_ui_session` | Leave group |
| POST | `/ui/groups/{group_id}/invite` | `require_ui_session` | Invite user (admin/mod) |
| POST | `/ui/groups/{group_id}/invites/{user_id}/respond` | `require_ui_session` | Accept/decline |
| POST | `/ui/groups/{group_id}/requests/{user_id}/review` | `require_ui_session` | Approve/reject (admin/mod) |
| PATCH | `/ui/groups/{group_id}/members/{user_id}/role` | `require_ui_session` | Promote/demote (admin) |
| DELETE | `/ui/groups/{group_id}/members/{user_id}` | `require_ui_session` | Remove member |
| GET | `/ui/groups/{group_id}/pending` | `require_ui_session` | Pending invites/requests (admin/mod) |

### 3.9 Pydantic Model Definitions

```python
# -- User Groups (GROUP-001) --

class CreateGroupIn(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(default="", max_length=2000)
    visibility: Literal["public", "private"] = "public"
    topic: Optional[str] = Field(default=None, max_length=50)

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Group name cannot be blank")
        return v.strip()

class UpdateGroupIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=100)
    description: Optional[str] = Field(default=None, max_length=2000)
    visibility: Optional[Literal["public", "private"]] = None
    topic: Optional[str] = Field(default=None, max_length=50)

class InviteIn(BaseModel):
    user_id: str

class InviteResponseIn(BaseModel):
    accept: bool

class ReviewRequestIn(BaseModel):
    approved: bool

class UpdateRoleIn(BaseModel):
    role: Literal["moderator", "member"]

class GroupOut(BaseModel):
    group_id: str
    name: str
    description: str
    topic: Optional[str] = None
    visibility: str  # "public" or "private"
    status: str  # "active" or "dissolved"
    admin_user_id: str
    cover_image_url: Optional[str] = None
    member_count: int
    created_at: int
    updated_at: int
    my_role: Optional[str] = None  # Set when viewer is a member

class GroupMemberOut(BaseModel):
    user_id: str
    role: str  # "admin", "moderator", "member"
    status: str  # "active", "invited", "pending_approval"
    display_name: str
    joined_at: Optional[int] = None
    promoted_at: Optional[int] = None

class PendingMemberOut(BaseModel):
    user_id: str
    display_name: str
    status: str  # "invited" or "pending_approval"
    created_at: int
    invited_by: Optional[str] = None

class GroupListOut(BaseModel):
    groups: List[GroupOut] = Field(default_factory=list)
    cursor: Optional[str] = None
    has_more: bool = False

class GroupMemberListOut(BaseModel):
    members: List[GroupMemberOut] = Field(default_factory=list)
    count: int = 0
```

### 3.10 Frontend Component Tree & Props

```
GroupsListPage (route: /groups)
├── Tabs
│   ├── Tab: "My Groups"
│   │   ├── GroupCard (per group)
│   │   │   ├── Cover image / placeholder
│   │   │   ├── Name
│   │   │   ├── Description (truncated)
│   │   │   ├── Member count
│   │   │   ├── Role badge (admin/moderator/member)
│   │   │   └── Link to /groups/:groupId
│   │   ├── Empty state: "You haven't joined any groups yet."
│   │   └── Button: "Create Group" → CreateGroupDialog
│   └── Tab: "Discover"
│       ├── SearchInput (name/topic filter)
│       ├── GroupDiscoveryCard (per public group)
│       │   ├── Name, topic badge, member count
│       │   └── Button: "Join" (public) or "Request" (private)
│       └── Pagination
├── CreateGroupDialog
│   ├── Name input (3-100 chars)
│   ├── Description textarea (max 2000)
│   ├── Visibility radio: Public / Private
│   ├── Topic input (optional)
│   └── Button: "Create Group"
└── GroupSettingsPage (route: /groups/:groupId/settings)
    ├── Settings form (admin only)
    │   ├── Name, Description, Visibility, Topic inputs
    │   └── Save button
    ├── Members list
    │   ├── MemberRow (per member)
    │   │   ├── Display name, role badge
    │   │   ├── Promote/Demote button (admin only)
    │   │   └── Remove button (admin/mod)
    │   └── Invite input + button
    ├── Pending requests section (admin/mod)
    │   ├── PendingRow (per pending)
    │   │   ├── Display name, status badge
    │   │   └── Approve / Reject buttons
    └── Danger zone
        └── Button: "Dissolve Group" (admin only, with confirmation)
```

**TypeScript Props Interfaces**:

```typescript
interface GroupCardProps {
  group: UserGroup;
  myRole?: "admin" | "moderator" | "member";
}

interface GroupDiscoveryCardProps {
  group: UserGroup;
  onJoin: (groupId: string) => void;
  isJoining: boolean;
}

interface CreateGroupDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (group: UserGroup) => void;
}

interface MemberRowProps {
  member: GroupMember;
  viewerRole: "admin" | "moderator" | "member";
  onPromote: (userId: string, role: string) => void;
  onRemove: (userId: string) => void;
}

interface PendingRowProps {
  pending: PendingMemberOut;
  onApprove: (userId: string) => void;
  onReject: (userId: string) => void;
}
```

### 3.11 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface UserGroup {
  group_id: string; name: string; description: string; topic?: string;
  visibility: "public" | "private"; status: "active" | "dissolved";
  admin_user_id: string; cover_image_url?: string; member_count: number;
  created_at: number; updated_at: number; my_role?: "admin" | "moderator" | "member";
}
export interface GroupMember {
  user_id: string; role: "admin" | "moderator" | "member";
  status: "active" | "invited" | "pending_approval";
  display_name: string; joined_at?: number; promoted_at?: number;
}
```

### 3.12 Frontend API (`frontend/src/api/endpoints/groups.ts`)

Wrappers for all router endpoints: `createGroup`, `listMyGroups`, `discoverGroups`, `getGroup`, `updateGroup`, `deleteGroup`, `listGroupMembers`, `joinGroup`, `leaveGroup`, `inviteToGroup`, `respondToInvite`, `reviewJoinRequest`, `updateMemberRole`, `removeMember`, `listPendingMembers`.

### 3.13 Frontend Pages

- **GroupsListPage** (`frontend/src/pages/groups/GroupsListPage.tsx`): Route `/groups`. Two tabs: "My Groups" (role badges) and "Discover" (search + join). `data-testid="groups-list-page"`.
- **CreateGroupDialog** (`frontend/src/pages/groups/CreateGroupDialog.tsx`): Modal with name, description, visibility toggle, topic. React Hook Form + Zod.
- **GroupSettingsPage** (`frontend/src/pages/groups/GroupSettingsPage.tsx`): Route `/groups/:groupId/settings`. Admin-only: edit settings, member management, pending requests, dissolve.

### 3.14 Navigation

Add "Groups" with `Users` icon to Social section in `Sidebar.tsx` and `MobileNav.tsx`.

---

## 4. Observability

### 4.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `group_created_total` | Counter | `visibility` | Groups created |
| `group_joined_total` | Counter | `visibility`, `method` (instant/approved) | Members joining groups |
| `group_left_total` | Counter | - | Members leaving groups |
| `group_dissolved_total` | Counter | `reason` (admin/succession) | Groups dissolved |
| `group_admin_succession_total` | Counter | `new_role` (mod/member) | Admin succession events |
| `group_membership_query_latency_ms` | Histogram | `operation` | DDB query latency |

### 4.2 Structured Logging

```python
logger.info("group.created", extra={
    "group_id": group_id, "creator": creator_sub,
    "visibility": visibility, "topic": topic,
})

logger.info("group.admin_succession", extra={
    "group_id": group_id, "old_admin": old_admin,
    "new_admin": new_admin, "new_role": new_role,
})
```

### 4.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Group creation spike | `rate(group_created_total[5m]) > 20` | Warning | Check for spam accounts |
| Succession failure | `group.admin_succession` with `new_admin=null` (dissolved) | Info | Expected behavior |
| High membership churn | `rate(group_left_total[1h]) > 50` for single group | Warning | Investigate content issues |

---

## 5. Rollout Plan

### 5.1 Feature Flag

```python
# app/core/settings.py
user_groups_enabled: bool = field(default=True)
user_groups_discovery_enabled: bool = field(default=True)
```

### 5.2 Phased Rollout

| Phase | Scope | Duration | Criteria |
|-------|-------|----------|----------|
| 1 | Dev/staging | 3 days | All E2E tests pass; CRUD verified manually |
| 2 | Internal beta (staff accounts) | 5 days | Create groups, test succession, test discovery |
| 3 | 25% of users | 5 days | Monitor creation rate, join patterns, error rates |
| 4 | 100% GA | - | All metrics healthy; GROUP-002/003/004 ready |

### 5.3 Rollback

Disable `user_groups_enabled`. Groups page returns 404 in frontend. Existing DDB data is preserved but inaccessible via API.

---

## 6. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Member list for large groups | < 300ms p99 | Paginate with `Limit=100`; cursor-based pagination |
| Discovery search | < 500ms p99 | GSI1 on `visibility` + `created_at`; client-side name filter for small result sets |
| Member count accuracy | Eventually consistent | Atomic increment/decrement via `UpdateExpression`; eventual consistency acceptable |
| User-group index consistency | Immediate | Write in same transaction as membership record (`transact_write_items`) |
| Group name search | < 500ms p99 | `contains` FilterExpression on GSI1 query; acceptable for moderate group counts |
| Max groups check | < 100ms | `query` with `Select=COUNT` on USERGROUPS PK |

### 6.1 Caching Strategy

- Group metadata: React Query `staleTime: 30_000`.
- Member list: `staleTime: 15_000` with `refetchOnWindowFocus: true`.
- My groups list: `staleTime: 30_000`.
- Discovery results: `staleTime: 60_000`.

### 6.2 Pagination

- Member list: cursor-based, 100 per page.
- My groups: cursor-based, 50 per page.
- Discovery: cursor-based, 20 per page with search debounce (300ms).

---

## 7. Implementation Plan

### 7.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/user_groups.py` | Group CRUD, membership, succession, discovery |
| `app/routers/user_groups.py` | REST endpoints |
| `frontend/src/api/endpoints/groups.ts` | API client |
| `frontend/src/pages/groups/GroupsListPage.tsx` | My Groups + Discover |
| `frontend/src/pages/groups/CreateGroupDialog.tsx` | Group creation |
| `frontend/src/pages/groups/GroupSettingsPage.tsx` | Admin settings |

### 7.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `user_groups` TableDef |
| `app/core/settings.py` | Add group settings |
| `app/core/tables.py` | Add `T.user_groups` |
| `app/main.py` | Register router |
| `app/models.py` | Add group Pydantic models |
| `frontend/src/api/types.ts` | Add group types |
| `frontend/src/App.tsx` | Add routes |
| `frontend/src/components/layout/Sidebar.tsx` | Add Groups nav |
| `frontend/src/components/layout/MobileNav.tsx` | Add Groups to MORE_LINKS |

---

## 8. E2E Test Plan

### 8.1 Test File

`frontend/e2e/user-groups.spec.ts` — 24 tests across 6 sections.

### 8.2 Test Setup

```typescript
const TS = Date.now();
const GROUP_NAME = `E2E Group ${TS}`;
let groupId: string;
let privateGroupId: string;
```

### 8.3 Section 447: Group CRUD API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 447.1 | Create a public group | POST `/ui/groups`; 201; `group_id`, `visibility=public`, `admin_user_id=alice_sub` |
| 447.2 | Get group details | GET `/ui/groups/{id}`; 200; `member_count=1`, `my_role=admin` |
| 447.3 | Update group settings | PATCH `/ui/groups/{id}` with new description; 200; updated |
| 447.4 | Create private group | POST with `visibility=private`; 201; `visibility=private` |

### 8.4 Section 448: Membership Lifecycle API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 448.1 | Bob joins public group | POST `/ui/groups/{id}/join`; 200; `status=active` |
| 448.2 | List members includes Bob | GET members; Bob with `role=member` |
| 448.3 | Bob requests to join private group | POST join; 200; `status=pending_approval` |
| 448.4 | Alice approves join request | POST review with `approved=true`; 200 |
| 448.5 | Bob leaves group | POST leave; 200; member count decremented |

### 8.5 Section 449: Role Management & Succession API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 449.1 | Alice promotes Bob to moderator | PATCH role; 200; `role=moderator` |
| 449.2 | Moderator removes regular member | DELETE member; 200 |
| 449.3 | Moderator cannot remove admin | DELETE admin; 403 |
| 449.4 | Admin succession on leave | Alice leaves; GET group; `admin_user_id` changed |

### 8.6 Section 450: Groups UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 450.1 | Groups list shows user's groups | Navigate `/groups`; `[data-testid="groups-list-page"]` visible; group name shown |
| 450.2 | Discover tab shows public groups | Click "Discover"; public group with "Join" button |
| 450.3 | Settings page allows admin edits | Navigate settings; edit description; save; persisted |

### 8.7 Section 451: Edge Cases & Negative Tests (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 451.1 | Duplicate join returns 409 | Bob joins same group twice; 409 "Already a member" |
| 451.2 | Non-admin cannot update group | Bob PATCHes group; 403 |
| 451.3 | Non-member cannot view members of private group | Charlie GETs members of private group; 403 |
| 451.4 | Dissolved group returns 410 | Dissolve group; GET group; 410 "dissolved" |
| 451.5 | Name too short returns 422 | POST group with name "Ab"; 422 |

### 8.8 Section 452: Invitation Flow (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 452.1 | Admin invites user | POST invite; 200; status=invited |
| 452.2 | Invited user accepts | POST respond with accept=true; 200; status=active |
| 452.3 | Invited user declines | POST respond with accept=false; 200; membership removed |

**Total E2E tests: 24**

---

## 9. Security Considerations

- **Authorization**: Group-level roles checked per-request by querying membership record. Admin-only ops verify `role=admin`; moderator ops verify `role in (admin, moderator)`.
- **Data isolation**: Membership scoped by `GROUP#{group_id}` PK. User-group index scoped by `USERGROUPS#{user_id}`.
- **Discovery**: Only returns `visibility=public, status=active` groups.
- **Rate limiting**: Group creation 5/hour, join requests 10/hour, invitations 50/hour per user.
- **Input validation**: Name 3-100 chars, description max 2000, topic max 50 chars.

---

## 10. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Auth dependencies | Existing | Available |
| User profiles | Existing | Available (`T.profile`) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| GROUP-002 (Group Page & Newsfeed) | Group metadata + membership |
| GROUP-003 (Advertising & Fundraising) | Admin role check |
| GROUP-004 (Treasury Management) | Membership + dissolution |

---

## 11. Acceptance Criteria

1. Users can create public and private groups.
2. Public group join is instant; private requires approval.
3. Admin can invite users, promote/demote roles, and remove members.
4. Moderators can remove non-admin members and approve join requests.
5. Admin succession transfers admin role when admin leaves.
6. Discovery search returns public, active groups with name/topic filtering.
7. Per-user group limit (50) is enforced.
8. Group dissolution cleans up memberships and triggers treasury return.
9. Non-members cannot access private group data.
10. All 24 E2E tests pass.

---

## Codebase References

| File | Lines | What |
|------|-------|------|
| `app/auth/deps.py` | — | `require_ui_session` auth dependency |
| `app/core/tables.py` | :121, :245 | `T.fan_club_channels` handle — similar membership pattern |
| `app/core/settings.py` | :1431-1433 | `fan_clubs_enabled`, `fan_club_channels_table_name`, `fan_club_messages_table_name` |
| `scripts/local-ddb-init.py` | :1077 | `fan_club_channels` table definition — similar single-table pattern |
| `app/core/settings.py` | — | `profile_table_name` for user profile lookups |
| `scripts/local-ddb-init.py` | — | No `user_groups` table exists yet — new table required |
| `app/main.py` | — | No group router registered yet — new registration required |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_user_groups.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_create_group_sets_creator_as_admin`
  - `test_join_public_group_instant_active`
  - `test_join_private_group_pending_approval`
  - `test_approve_join_request_sets_active`
  - `test_reject_join_request_sets_rejected`
  - `test_promote_member_to_moderator`
  - `test_remove_member_by_admin`
  - `test_admin_succession_to_oldest_moderator`
  - `test_admin_succession_to_oldest_member`

### Integration Tests

  - Group creation writes META and MEMBER records to user_groups table
  - Leave as admin triggers succession and updates member role
  - Discovery endpoint lists only public groups matching search query
  - Invitation creates pending membership with invite notification

### E2E Tests (Playwright)

**File**: `frontend/e2e/user-groups.spec.ts`
**Test count**: 15

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

- **DDB seeds**: Seed `user_groups` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `USER_GROUPS_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| (none) | — | This ticket has no blocking dependencies |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| GROUP-002 | Group Page & Newsfeed | Requires group membership verification |
| GROUP-003 | Group Advertising & Fundraising | Requires group admin role check |
| GROUP-004 | Group Treasury Management | Requires group membership verification |

### Merge Strategy

**Independent**

This ticket can be merged independently of other tickets. It introduces new tables/endpoints without modifying existing ones in a breaking way.

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
- [ ] All 15 E2E tests pass with `npx playwright test user-groups.spec.ts`
