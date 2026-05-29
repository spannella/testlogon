# GROUP-002: Group Page & Newsfeed

**Ticket**: GROUP-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Dependencies**: GROUP-001 (User Group Creation & Membership)

---

## 1. Overview & Motivation

### 1.1 Purpose

GROUP-002 adds a public-facing group page and a group-scoped newsfeed. Each group gets a profile page displaying its name, description, member count, and cover image. The group newsfeed lets members create posts visible to other members or to anyone visiting the group page (public posts). This reuses the existing post infrastructure (`_post_to_dict`, `PostCard`, reactions, tips, comments) while scoping content to the group context. Admins and moderators can pin posts to the top of the feed.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Visitor | As a non-member, I want to view a group's public page. | Group page shows name, description, member count, public posts. |
| Visitor | As a non-member, I want to see public posts in the group feed. | Feed shows `audience=public` posts; members-only hidden behind CTA. |
| Member | As a member, I want to post in the group feed. | POST creates group post; appears in feed. |
| Member | As a member, I want to see all posts (public + members-only). | Full feed visible to members. |
| Member | As a member, I want to comment, react, and tip group posts. | Existing PostCard interactions work in group context. |
| Admin | As an admin, I want to pin a post to the top of the feed. | Pinned post appears first regardless of chronological order. |
| Moderator | As a moderator, I want to remove inappropriate posts. | DELETE post; removed from feed. |

### 1.3 Why This Is Needed

Groups without content are empty containers. The group newsfeed gives members a reason to engage. The public/members-only split lets groups attract new members via visible public content while reserving discussion for the community. Reusing post infrastructure avoids a parallel content system and ensures feature parity (reactions, tips, comments, locks, polls).

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Newsfeed** (`app/routers/newsfeed.py`): Posts stored in `app_single_table` with `PK=POST#{post_id}`, `SK=META`. `_post_to_dict()` (line ~1900) maps DDB items to `FeedPost` shape with `viewer_id` for lock/reaction resolution.
- **Fan-out** (`app/services/newsfeed_fanout.py`): `fan_out_post_to_followers()` writes per-follower `FEED#{follower_id}` index records. Group posts use a different pattern — scoped to `GROUPFEED#{group_id}`, not fanned out.
- **PostCard** (`frontend/src/pages/feed/PostCard.tsx`): Renders posts with reactions, comments, tips, locks, overflow menu. Reusable for group context with additional badges.
- **Comments & Reactions**: Comments at `PK=COMMENTS#{post_id}`, reactions as DDB map on post item. Both reference `post_id`, not feed context — group-agnostic.

### 2.2 Gaps

1. No `GROUPFEED#{group_id}` index for group-scoped posts.
2. No `audience` field (public vs. members-only) on posts.
3. No group post creation or feed query endpoints.
4. No pinned posts mechanism.
5. No group page UI or post composer.
6. No moderator deletion of group posts.

---

## 3. Technical Design

### 3.1 Data Model

Group posts are stored in `app_single_table` alongside regular posts, with additional fields.

**Post record extension** (on `PK=POST#{post_id}`, `SK=META`):

| Field | Type | Description |
|-------|------|-------------|
| `group_id` | S (optional) | Group the post belongs to (null for personal feed) |
| `audience` | S | `public` or `members_only` (default: `public`) |
| `pinned` | BOOL | Whether pinned to top (default: false) |
| `pinned_at` | N | Timestamp when pinned |
| `pinned_by` | S | user_sub of admin/mod who pinned |

**Group feed index** (in `app_single_table`):

| PK | SK | Fields |
|----|----|--------|
| `GROUPFEED#{group_id}` | `{created_at}#{post_id}` | `post_id`, `user_id`, `audience`, `pinned` |

Written alongside the post record. Enables efficient group feed queries without scanning all posts.

### 3.2 Backend Service (`app/services/group_feed.py`)

| Function | Description |
|----------|-------------|
| `create_group_post(group_id, user_id, text, audience, ...)` | Verify membership; create post with `group_id` + `audience`; write `GROUPFEED` index; no fan-out |
| `list_group_feed(group_id, viewer_id, cursor, limit)` | Query `GROUPFEED#{group_id}`; fetch full posts; filter `members_only` for non-members; sort pinned first |
| `pin_post(group_id, post_id, user_id)` | Verify admin/mod; set `pinned=true`, `pinned_at`, `pinned_by` |
| `unpin_post(group_id, post_id, user_id)` | Remove pin fields |
| `delete_group_post(group_id, post_id, user_id)` | Verify author/admin/mod; delete post + index record |

### 3.3 Post Interaction Reuse

Existing endpoints work without modification on group posts (same `post_id` pattern):
- `POST /ui/posts/{post_id}/reactions` — reactions
- `POST /ui/posts/{post_id}/tip` — tips
- `POST /ui/posts/{post_id}/comments` — comments
- `POST /ui/posts/{post_id}/unlock` — locked post unlock

### 3.4 `_post_to_dict` Enhancement (`app/routers/newsfeed.py`)

Add group context fields when `post.get("group_id")` is present: `group_id`, `audience`, `pinned`, `pinned_at`, `pinned_by`.

### 3.5 Backend Router (`app/routers/group_feed.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/groups/{group_id}/posts` | `require_ui_session` | Create group post |
| GET | `/ui/groups/{group_id}/feed` | `require_ui_session` | Group feed (all for members, public-only for non-members) |
| GET | `/public/groups/{group_id}/feed` | None | Public-only feed (no auth) |
| POST | `/ui/groups/{group_id}/posts/{post_id}/pin` | `require_ui_session` | Pin post (admin/mod) |
| DELETE | `/ui/groups/{group_id}/posts/{post_id}/pin` | `require_ui_session` | Unpin |
| DELETE | `/ui/groups/{group_id}/posts/{post_id}` | `require_ui_session` | Delete post |

**Request model**: `CreateGroupPostIn(text, body_format: plain|markdown|richtext, image_url?, audience: public|members_only, unlock_price_cents?)`.

Register both `router` (authenticated, prefix `/ui/groups`) and `public_group_feed_router` (prefix `/public/groups`) in `main.py`.

### 3.6 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface GroupFeedPost extends FeedPost {
  group_id: string;
  audience: "public" | "members_only";
  pinned: boolean;
  pinned_at?: number;
  pinned_by?: string;
}
export interface GroupFeedResponse {
  posts: GroupFeedPost[];
  cursor?: string;
  has_more: boolean;
}
```

### 3.7 Frontend API (`frontend/src/api/endpoints/groups.ts`)

Extend with: `createGroupPost(groupId, data)`, `getGroupFeed(groupId, params)`, `getPublicGroupFeed(groupId, params)` (via `axios`, no auth), `pinGroupPost(groupId, postId)`, `unpinGroupPost(groupId, postId)`, `deleteGroupPost(groupId, postId)`.

### 3.8 Frontend Pages

- **GroupPage** (`frontend/src/pages/groups/GroupPage.tsx`): Route `/groups/:groupId`. Header with cover image, name, description, member count. Join/Leave/Settings buttons. Feed section using `PostCard`. Post composer for members with audience toggle. Non-member view: public posts + "Join to see all posts" CTA. Pinned posts at top with "Pinned" badge. `data-testid="group-page"`.
- **GroupPostComposer** (`frontend/src/pages/groups/GroupPostComposer.tsx`): Inline composer above feed. Text area + body format + image upload + audience toggle + lock price. `data-testid="group-post-composer"`.

### 3.9 PostCard Enhancement

Add group context badge (`Posted in {group_name}`) and pin badge when `post.group_id` is set. Add "Pin to top" / "Unpin" to overflow menu when viewer is admin/mod.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/group_feed.py` | Group feed CRUD, pin/unpin, audience filtering |
| `app/routers/group_feed.py` | Authenticated + public feed endpoints |
| `frontend/src/pages/groups/GroupPage.tsx` | Group profile page with feed |
| `frontend/src/pages/groups/GroupPostComposer.tsx` | Post composer |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/newsfeed.py` | Add group fields to `_post_to_dict()` |
| `app/main.py` | Register group_feed routers |
| `frontend/src/api/types.ts` | Add `GroupFeedPost`, `GroupFeedResponse` |
| `frontend/src/api/endpoints/groups.ts` | Add feed API functions |
| `frontend/src/pages/feed/PostCard.tsx` | Group badge, pin badge, pin/unpin menu |
| `frontend/src/App.tsx` | Add `/groups/:groupId` route |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/group-feed.spec.ts` — 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let groupId: string;
let publicPostId: string;
let membersOnlyPostId: string;
// Alice = admin, Bob = member, Charlie = non-member
```

### 5.3 Section 451: Group Post Creation API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 451.1 | Member creates public post | POST `/ui/groups/{id}/posts` with `audience=public`; 201; `group_id`, `audience=public` |
| 451.2 | Member creates members-only post | POST with `audience=members_only`; 201 |
| 451.3 | Non-member cannot create post | POST as Charlie; 403 |
| 451.4 | Post appears in group feed | GET feed; includes new post |

### 5.4 Section 452: Group Feed Query API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 452.1 | Member sees all posts | GET feed as Bob; both public and members-only present |
| 452.2 | Non-member sees only public posts | GET feed as Charlie; only public post |
| 452.3 | Public feed endpoint returns public only | GET `/public/groups/{id}/feed` (no auth); only `audience=public` |
| 452.4 | Pinned post appears first | Pin a post; GET feed; pinned post first |

### 5.5 Section 453: Pin & Moderation API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 453.1 | Admin pins a post | POST pin; 200; `pinned=true` |
| 453.2 | Pinned post first in feed | GET feed; first entry is pinned |
| 453.3 | Admin unpins a post | DELETE pin; 200; `pinned=false` |
| 453.4 | Moderator deletes post | DELETE post as moderator; 200; gone from feed |

### 5.6 Section 454: Group Page UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 454.1 | Group page displays info | Navigate `/groups/{id}`; `[data-testid="group-page"]`; name, description, member count |
| 454.2 | Member sees composer | As Alice; composer visible with audience toggle |
| 454.3 | Non-member sees CTA | As Charlie; public post visible; "Join to see all posts" CTA |
| 454.4 | Pin badge displayed | Pin post; navigate; "Pinned" badge visible |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Group not found | 404 | "Group not found" |
| Not a member (post creation) | 403 | "Not a member of this group" |
| Not admin/moderator (pin) | 403 | "Only admins and moderators can pin posts" |
| Post not in group | 404 | "Post not found in this group" |
| Post already pinned | 409 | "Post is already pinned" |
| Group dissolved | 410 | "This group has been dissolved" |

---

## 7. Security Considerations

- **Audience enforcement**: `list_group_feed` checks membership before including `members_only` posts. Public endpoint never returns `members_only` posts.
- **Moderation**: Author deletes own; admin deletes any; moderator deletes non-admin posts.
- **Content safety**: Group posts use the same content moderation pipeline as regular posts.
- **Information disclosure**: Non-members cannot see members-only post content, only metadata ("Members Only" label).

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| GROUP-001 (Membership) | GROUP-001 | Required |
| Newsfeed infrastructure | Existing | Available (`_post_to_dict`, PostCard, reactions, comments) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| GROUP-003 (Advertising) | Group feed for ad placement context |
