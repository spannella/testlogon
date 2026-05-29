# GROUP-001: User Group Creation & Membership

**Ticket**: GROUP-001
**Author**: Engineering
**Status**: Design
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

- **Auth**: `require_ui_session` from `app/auth/deps.py`. Group-level roles (admin/mod/member) are checked by querying the membership record, not the platform auth role.
- **User profiles** (`T.profile`): Display names, avatars. Denormalized into membership records for fast listing.
- **Fan club channels** (`T.fan_club_channels`): Similar group membership pattern (`pk=CHANNEL#{id}`, `sk=MEMBER#{user_id}`).

### 2.2 Gaps

1. No `user_groups` DDB table.
2. No group service or router.
3. No invitation/join-request workflow.
4. No admin succession logic.
5. No group discovery/search.
6. No frontend pages for groups.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `user_groups`

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

### 3.2 Settings & Table Handle

**File**: `app/core/settings.py`

```python
ddb_user_groups_table: str = os.environ.get("DDB_USER_GROUPS_TABLE", "user_groups")
user_group_max_members: int = int(os.environ.get("USER_GROUP_MAX_MEMBERS", "10000"))
user_group_max_per_user: int = int(os.environ.get("USER_GROUP_MAX_PER_USER", "50"))
```

**File**: `app/core/tables.py` — Add `user_groups: Any` to the `Tables` dataclass and `user_groups=ddb.Table(S.ddb_user_groups_table)` to the `T` initialization block.

### 3.3 Backend Service (`app/services/user_groups.py`)

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

### 3.4 Backend Router (`app/routers/user_groups.py`)

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

**Request models**:

```python
class CreateGroupIn(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(default="", max_length=2000)
    visibility: Literal["public", "private"] = "public"
    topic: Optional[str] = Field(default=None, max_length=50)

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
```

### 3.5 Pydantic Models (`app/models.py`)

```python
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
```

### 3.6 Frontend Types (`frontend/src/api/types.ts`)

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

### 3.7 Frontend API (`frontend/src/api/endpoints/groups.ts`)

Wrappers for all router endpoints: `createGroup`, `listMyGroups`, `discoverGroups`, `getGroup`, `updateGroup`, `deleteGroup`, `listGroupMembers`, `joinGroup`, `leaveGroup`, `inviteToGroup`, `respondToInvite`, `reviewJoinRequest`, `updateMemberRole`, `removeMember`, `listPendingMembers`.

### 3.8 Frontend Pages

- **GroupsListPage** (`frontend/src/pages/groups/GroupsListPage.tsx`): Route `/groups`. Two tabs: "My Groups" (role badges) and "Discover" (search + join). `data-testid="groups-list-page"`.
- **CreateGroupDialog** (`frontend/src/pages/groups/CreateGroupDialog.tsx`): Modal with name, description, visibility toggle, topic. React Hook Form + Zod.
- **GroupSettingsPage** (`frontend/src/pages/groups/GroupSettingsPage.tsx`): Route `/groups/:groupId/settings`. Admin-only: edit settings, member management, pending requests, dissolve.

### 3.9 Navigation

Add "Groups" with `Users` icon to Social section in `Sidebar.tsx` and `MobileNav.tsx`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/user_groups.py` | Group CRUD, membership, succession, discovery |
| `app/routers/user_groups.py` | REST endpoints |
| `frontend/src/api/endpoints/groups.ts` | API client |
| `frontend/src/pages/groups/GroupsListPage.tsx` | My Groups + Discover |
| `frontend/src/pages/groups/CreateGroupDialog.tsx` | Group creation |
| `frontend/src/pages/groups/GroupSettingsPage.tsx` | Admin settings |

### 4.2 Files to Modify

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

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/user-groups.spec.ts` — 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
const GROUP_NAME = `E2E Group ${TS}`;
let groupId: string;
let privateGroupId: string;
```

### 5.3 Section 447: Group CRUD API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 447.1 | Create a public group | POST `/ui/groups`; 201; `group_id`, `visibility=public`, `admin_user_id=alice_sub` |
| 447.2 | Get group details | GET `/ui/groups/{id}`; 200; `member_count=1`, `my_role=admin` |
| 447.3 | Update group settings | PATCH `/ui/groups/{id}` with new description; 200; updated |
| 447.4 | Create private group | POST with `visibility=private`; 201; `visibility=private` |

### 5.4 Section 448: Membership Lifecycle API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 448.1 | Bob joins public group | POST `/ui/groups/{id}/join`; 200; `status=active` |
| 448.2 | List members includes Bob | GET members; Bob with `role=member` |
| 448.3 | Bob requests to join private group | POST join; 200; `status=pending_approval` |
| 448.4 | Alice approves join request | POST review with `approved=true`; 200 |
| 448.5 | Bob leaves group | POST leave; 200; member count decremented |

### 5.5 Section 449: Role Management & Succession API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 449.1 | Alice promotes Bob to moderator | PATCH role; 200; `role=moderator` |
| 449.2 | Moderator removes regular member | DELETE member; 200 |
| 449.3 | Moderator cannot remove admin | DELETE admin; 403 |
| 449.4 | Admin succession on leave | Alice leaves; GET group; `admin_user_id` changed |

### 5.6 Section 450: Groups UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 450.1 | Groups list shows user's groups | Navigate `/groups`; `[data-testid="groups-list-page"]` visible; group name shown |
| 450.2 | Discover tab shows public groups | Click "Discover"; public group with "Join" button |
| 450.3 | Settings page allows admin edits | Navigate settings; edit description; save; persisted |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Group not found | 404 | "Group not found" |
| Not a member | 403 | "Not a member of this group" |
| Not admin | 403 | "Only the group admin can perform this action" |
| Already a member | 409 | "Already a member of this group" |
| Group dissolved | 410 | "This group has been dissolved" |
| Max groups exceeded | 400 | "Maximum number of groups reached" |
| Cannot remove admin (moderator) | 403 | "Moderators cannot remove the admin" |

---

## 7. Security Considerations

- **Authorization**: Group-level roles checked per-request by querying membership record. Admin-only ops verify `role=admin`; moderator ops verify `role in (admin, moderator)`.
- **Data isolation**: Membership scoped by `GROUP#{group_id}` PK. User-group index scoped by `USERGROUPS#{user_id}`.
- **Discovery**: Only returns `visibility=public, status=active` groups.
- **Rate limiting**: Group creation 5/hour, join requests 10/hour, invitations 50/hour per user.
- **Input validation**: Name 3-100 chars, description max 2000, topic max 50 chars.

---

## 8. Dependencies

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
