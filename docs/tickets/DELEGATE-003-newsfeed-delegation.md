# DELEGATE-003: Newsfeed Delegation

**Ticket**: DELEGATE-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

DELEGATE-003 enables delegates to manage a creator's newsfeed on their behalf. Delegates with `feed_post` can create, edit, and delete posts; delegates with `feed_moderate` can hide, pin, and delete comments. The feature includes a draft/approval workflow where delegates can save posts as drafts for creator review before publishing. This allows creators to maintain consistent content schedules without personally managing every post.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Delegate | As a delegate with `feed_post`, I want to create posts on the creator's newsfeed so that content goes out on schedule. | POST creates post with `author_id=creator`; post appears on creator's feed; delegate attribution stored internally. |
| Delegate | As a delegate with `feed_post`, I want to edit existing posts so that I can fix typos or update content. | PUT updates post; edit is recorded in delegation audit; original author remains the creator. |
| Delegate | As a delegate with `feed_post`, I want to save drafts for creator approval so that the creator maintains quality control. | POST with `status=draft`; creator sees pending drafts; creator can approve (publish) or reject (delete). |
| Creator | As a creator, I want to require approval for delegate posts so that nothing goes live without my review. | Setting `require_post_approval=true`; delegate posts go to draft status; creator gets notification. |
| Creator | As a creator, I want to approve or reject delegate drafts so that I control what appears on my feed. | POST approve publishes draft; POST reject deletes it; both write audit entries. |
| Delegate | As a delegate with `feed_moderate`, I want to hide or delete offensive comments so that the creator's feed stays clean. | DELETE/PUT on comments; comment is hidden or deleted; moderation action logged. |
| Delegate | As a delegate with `feed_moderate`, I want to pin important comments so that they appear at the top. | PUT pin on comment; comment moves to top of thread; pin action logged. |
| Delegate | As a delegate with `feed_read`, I want to view the creator's feed analytics so that I can optimize content strategy. | GET analytics returns view counts, engagement metrics, revenue from locked posts. |
| Creator | As a creator, I want to see which posts and moderation actions were done by delegates. | Audit view shows all delegate actions on feed with actor, timestamp, and details. |

### 1.3 Why This Is Needed

Consistent posting schedules are critical for creator revenue and audience retention. Many successful creators work with content managers who draft posts, schedule content, and moderate comments. Without feed delegation, creators must either share account credentials (security risk) or manage everything themselves (does not scale). The draft/approval workflow bridges the gap between delegation efficiency and creator quality control.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Newsfeed router | `app/routers/newsfeed.py` (~800 lines) | Post CRUD, comments, reactions, locking, scheduling, drafts; all need delegation support |
| Newsfeed fanout | `app/services/newsfeed_fanout.py` | `fan_out_post_to_followers` for content distribution; delegated posts use same fan-out |
| Newsfeed scheduler | `app/services/newsfeed_scheduler.py` | Scheduled post promotion; delegated scheduled posts use same mechanism |
| Newsfeed polls | `app/services/newsfeed_polls.py` | Poll CRUD; delegates with `feed_post` can create polls |
| Newsfeed feed query | `app/services/newsfeed_feed_query.py` | Feed query patterns; delegates need creator-scoped queries |
| Delegates service | `app/services/delegates.py` (DELEGATE-001) | `require_delegate_permission`, audit logging |
| Feed page | `frontend/src/pages/feed/FeedPage.tsx` | Newsfeed UI; needs delegate mode for post creation and moderation |
| CreatePost | `frontend/src/pages/feed/CreatePost.tsx` | Post creation form; needs "posting as @creator" mode |
| PostCard | `frontend/src/pages/feed/PostCard.tsx` | Post display; needs moderation action buttons for delegates |

### 2.2 Gaps

1. **No `posted_by_delegate` metadata** -- posts do not carry delegate attribution fields. The `author_id` is always the session user.
2. **No creator-scoped post creation** -- the newsfeed router assumes the authenticated user is the post author.
3. **No approval workflow** -- drafts exist in the newsfeed system but there is no concept of "pending approval" status or creator review queue.
4. **No delegate moderation actions** -- comment hide/pin/delete are restricted to the post author; no delegate permission check.
5. **No delegate analytics access** -- feed analytics endpoints require the authenticated user to be the content owner.
6. **No delegate post audit** -- no tracking of which delegate created, edited, or moderated content.

---

## 3. Technical Design

### 3.1 DynamoDB Schema Changes

#### 3.1.1 Post Item Extensions

Add fields to post items in the `newsfeed` table:

| Field | Type | Purpose |
|-------|------|---------|
| `posted_by_delegate` | S | Delegate user ID who created/last edited the post (absent if creator posted directly) |
| `delegate_display_name` | S | Display name of the delegate at creation time |
| `delegate_tag` | S | Optional "[posted by @delegate]" attribution text |
| `approval_status` | S | `pending` / `approved` / `rejected` (only present for delegate posts when approval required) |
| `approval_note` | S | Creator's note when approving/rejecting (optional) |
| `approved_at` | N | Timestamp when creator approved the draft |
| `approved_by` | S | User ID who approved (always the creator) |

#### 3.1.2 Delegate Draft Queue GSI

Add a new GSI to the `newsfeed` table for efficient draft approval queries:

**GSI: DraftApprovalQueue**
- `GSI_DRAFT_PK`: `DRAFT_QUEUE#{creator_id}` (only set when `approval_status=pending`)
- `GSI_DRAFT_SK`: `created_at` (N) -- sorts by creation date

```python
# Add to existing newsfeed TableDef GSIs
{"name": "DraftApprovalQueue", "pk": "GSI_DRAFT_PK", "sk": "GSI_DRAFT_SK"},
# Add to attr_types
"GSI_DRAFT_SK": "N",
```

#### 3.1.3 Comment Moderation Log

Add moderation metadata to comment items:

| Field | Type | Purpose |
|-------|------|---------|
| `moderated_by` | S | Delegate or creator who performed moderation action |
| `moderation_action` | S | `hidden` / `pinned` / `unpinned` / `deleted` |
| `moderated_at` | N | Timestamp of moderation action |

### 3.2 Backend Service

**New file**: `app/services/delegate_feed.py` (~350 lines)

```python
"""Newsfeed delegation service (DELEGATE-003)."""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from app.core.tables import T
from app.core.time import now_ts
from app.services.delegates import (
    require_delegate_permission,
    get_delegate,
)
from app.services.profile import get_profile

logger = logging.getLogger(__name__)


def create_post_as_creator(
    *,
    creator_id: str,
    delegate_id: str,
    text: str,
    image_url: Optional[str] = None,
    lock_price_cents: int = 0,
    tags: List[str] = None,
    scheduled_at: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a newsfeed post on behalf of a creator.
    
    If the creator has require_post_approval enabled, the post
    is saved as a draft with approval_status=pending.
    """
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="feed_post",
    )
    
    delegate_item = get_delegate(creator_id, delegate_id)
    delegate_profile = get_profile(delegate_id) or {}
    creator_settings = _get_feed_delegation_settings(creator_id)
    
    requires_approval = creator_settings.get("require_post_approval", False)
    
    # Build post with creator as author + delegate metadata
    # If requires_approval: set status=draft, approval_status=pending, GSI_DRAFT_PK
    # If not: publish directly using existing post creation logic
    # Write delegation audit entry


def edit_post_as_creator(
    *,
    creator_id: str,
    delegate_id: str,
    post_id: str,
    text: Optional[str] = None,
    image_url: Optional[str] = None,
    lock_price_cents: Optional[int] = None,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Edit a creator's post on their behalf."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="feed_post",
    )
    # Verify post belongs to creator
    # Update fields; set posted_by_delegate to delegate_id
    # Write audit entry


def delete_post_as_creator(
    *,
    creator_id: str,
    delegate_id: str,
    post_id: str,
) -> None:
    """Delete a creator's post on their behalf."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="feed_post",
    )
    # Verify post belongs to creator
    # Delete post + fan-out delete
    # Write audit entry


def list_pending_drafts(
    *,
    creator_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List posts pending creator approval.
    
    Creator-only. Queries DraftApprovalQueue GSI.
    """
    # GSI query: GSI_DRAFT_PK = DRAFT_QUEUE#{creator_id}
    # Returns drafts with delegate attribution


def approve_draft(
    *,
    creator_id: str,
    post_id: str,
    note: str = "",
) -> Dict[str, Any]:
    """Creator approves a delegate's draft post, publishing it.
    
    Sets approval_status=approved, publishes the post,
    triggers fan-out to followers.
    """
    # Validate post exists, is a draft, has approval_status=pending
    # Set status=published, approval_status=approved
    # Remove GSI_DRAFT_PK (no longer in queue)
    # Trigger fan_out_post_to_followers
    # Write audit entry


def reject_draft(
    *,
    creator_id: str,
    post_id: str,
    note: str = "",
) -> Dict[str, Any]:
    """Creator rejects a delegate's draft post.
    
    Sets approval_status=rejected, removes from queue.
    """
    # Set approval_status=rejected
    # Remove GSI_DRAFT_PK
    # Write audit entry


def moderate_comment(
    *,
    creator_id: str,
    delegate_id: str,
    post_id: str,
    comment_id: str,
    action: str,  # "hide" | "pin" | "unpin" | "delete"
) -> Dict[str, Any]:
    """Delegate moderates a comment on creator's post."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="feed_moderate",
    )
    # Verify post belongs to creator
    # Perform moderation action
    # Write audit entry


def get_creator_feed_analytics(
    *,
    creator_id: str,
    delegate_id: str,
    period: str = "30d",
) -> Dict[str, Any]:
    """Get feed analytics for a creator (delegate with feed_read)."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="feed_read",
    )
    # Return post count, total views, engagement rate, locked post revenue


def list_delegate_feed_actions(
    *,
    creator_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List all delegate actions on creator's feed (creator audit view)."""
    # Query delegation audit log filtered to feed actions


# --- Internal helpers ---

def _get_feed_delegation_settings(creator_id: str) -> Dict[str, Any]:
    """Get creator's feed delegation settings."""
    # Read from delegates table CREATOR#{creator_id} SK=FEED_SETTINGS
    # Return defaults if not found
```

### 3.3 Backend Router

**New file**: `app/routers/delegate_feed.py` (~200 lines)

```python
"""Newsfeed delegation router (DELEGATE-003)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from app.auth.deps import require_ui_session
from app.services import delegate_feed as svc

router = APIRouter(prefix="/ui/newsfeed/delegate", tags=["newsfeed-delegation"])
```

### 3.4 Router Endpoints

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `POST` | `/ui/newsfeed/delegate/{creator_id}/posts` | `require_ui_session` | `feed_post` | Create post as creator |
| `PUT` | `/ui/newsfeed/delegate/{creator_id}/posts/{post_id}` | `require_ui_session` | `feed_post` | Edit creator's post |
| `DELETE` | `/ui/newsfeed/delegate/{creator_id}/posts/{post_id}` | `require_ui_session` | `feed_post` | Delete creator's post |
| `GET` | `/ui/newsfeed/delegate/{creator_id}/posts` | `require_ui_session` | `feed_read` | List creator's posts (published + drafts) |
| `GET` | `/ui/newsfeed/delegate/{creator_id}/drafts` | `require_ui_session` | creator only | List pending approval drafts |
| `POST` | `/ui/newsfeed/delegate/{creator_id}/drafts/{post_id}/approve` | `require_ui_session` | creator only | Approve draft |
| `POST` | `/ui/newsfeed/delegate/{creator_id}/drafts/{post_id}/reject` | `require_ui_session` | creator only | Reject draft |
| `POST` | `/ui/newsfeed/delegate/{creator_id}/posts/{post_id}/comments/{comment_id}/moderate` | `require_ui_session` | `feed_moderate` | Moderate comment (hide/pin/delete) |
| `GET` | `/ui/newsfeed/delegate/{creator_id}/analytics` | `require_ui_session` | `feed_read` | Get feed analytics |
| `GET` | `/ui/newsfeed/delegate/{creator_id}/audit` | `require_ui_session` | creator only | List delegate actions audit |
| `PUT` | `/ui/newsfeed/delegate/{creator_id}/settings` | `require_ui_session` | creator only | Update feed delegation settings |
| `GET` | `/ui/newsfeed/delegate/{creator_id}/settings` | `require_ui_session` | creator only | Get feed delegation settings |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Newsfeed Delegation (DELEGATE-003) --

class DelegatedPostCreateIn(BaseModel):
    text: str = Field(min_length=1, max_length=10000)
    image_url: Optional[str] = None
    lock_price_cents: int = Field(default=0, ge=0)
    tags: List[str] = Field(default_factory=list, max_length=20)
    scheduled_at: Optional[int] = None

class DelegatedPostEditIn(BaseModel):
    text: Optional[str] = Field(None, min_length=1, max_length=10000)
    image_url: Optional[str] = None
    lock_price_cents: Optional[int] = Field(None, ge=0)
    tags: Optional[List[str]] = None

class DraftApprovalIn(BaseModel):
    note: str = Field(default="", max_length=500)

class CommentModerationIn(BaseModel):
    action: str = Field(description="hide | pin | unpin | delete")

class FeedDelegationSettingsIn(BaseModel):
    require_post_approval: bool = False
    allow_delegate_scheduling: bool = True
    allow_delegate_locking: bool = False
    delegate_tag_on_posts: bool = False
    delegate_tag_format: str = Field(default="[posted by @{delegate_name}]", max_length=100)

class DelegatedPostOut(BaseModel):
    post_id: str
    author_id: str  # Always the creator
    text: str = ""
    image_url: Optional[str] = None
    lock_price_cents: int = 0
    tags: List[str] = Field(default_factory=list)
    status: str  # "published" | "draft" | "scheduled"
    posted_by_delegate: Optional[str] = None
    delegate_display_name: Optional[str] = None
    delegate_tag: Optional[str] = None
    approval_status: Optional[str] = None  # "pending" | "approved" | "rejected"
    approval_note: Optional[str] = None
    approved_at: Optional[int] = None
    created_at: int = 0
    updated_at: int = 0
    view_count: int = 0
    like_count: int = 0
    comment_count: int = 0

class FeedAnalyticsOut(BaseModel):
    period: str
    total_posts: int = 0
    total_views: int = 0
    total_likes: int = 0
    total_comments: int = 0
    engagement_rate: float = 0.0
    locked_post_revenue_cents: int = 0
    delegate_post_count: int = 0
    top_posts: List[Dict[str, Any]] = Field(default_factory=list)

class FeedDelegateAuditEntry(BaseModel):
    event_id: str
    delegate_id: str
    delegate_display_name: str = ""
    action: str  # "post_created" | "post_edited" | "post_deleted" | "comment_hidden" | "comment_pinned" | "comment_deleted" | "draft_submitted"
    target_id: str = ""
    details: Optional[Dict[str, Any]] = None
    ts: int = 0

class FeedDelegationSettingsOut(BaseModel):
    require_post_approval: bool = False
    allow_delegate_scheduling: bool = True
    allow_delegate_locking: bool = False
    delegate_tag_on_posts: bool = False
    delegate_tag_format: str = "[posted by @{delegate_name}]"
```

### 3.6 Frontend Components

**New files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/feed/DelegateFeedPage.tsx` | Delegate view of creator's feed management | ~250 |
| `frontend/src/pages/feed/DelegateCreatePost.tsx` | Post creation form in delegate mode | ~150 |
| `frontend/src/pages/feed/DraftApprovalQueue.tsx` | Creator's queue of pending delegate drafts | ~120 |
| `frontend/src/pages/feed/CommentModerationPanel.tsx` | Comment moderation controls for delegates | ~100 |
| `frontend/src/pages/feed/FeedAnalyticsSummary.tsx` | Analytics summary card for delegates | ~80 |
| `frontend/src/pages/feed/FeedDelegateAuditLog.tsx` | Audit log for feed delegation actions | ~100 |
| `frontend/src/api/endpoints/delegate-feed.ts` | API client wrappers | ~100 |

**Component tree**:

```
DelegateFeedPage
├── Header: "Managing @{creator_name}'s Feed"
│   ├── CreatorSelector dropdown (reused from DELEGATE-002)
│   └── "Exit" button
├── Tabs
│   ├── "Posts" Tab
│   │   ├── DelegateCreatePost (Button: "New Post")
│   │   │   ├── Text editor (markdown/rich text)
│   │   │   ├── Image upload
│   │   │   ├── Lock price input (if allow_delegate_locking)
│   │   │   ├── Schedule picker (if allow_delegate_scheduling)
│   │   │   ├── Tag input
│   │   │   └── "Submit for Approval" / "Publish" button
│   │   └── PostList (creator's published + draft posts)
│   │       └── For each post:
│   │           ├── PostCard (reused)
│   │           ├── "[Draft - Pending Approval]" badge (if pending)
│   │           ├── "[Posted by @delegate]" tag
│   │           └── Edit / Delete actions
│   ├── "Moderation" Tab (feed_moderate permission)
│   │   └── CommentModerationPanel
│   │       └── For each flagged/recent comment:
│   │           ├── Comment content + author
│   │           ├── "Hide" / "Pin" / "Delete" buttons
│   │           └── Moderation status badge
│   ├── "Analytics" Tab (feed_read permission)
│   │   └── FeedAnalyticsSummary
│   │       ├── Views, likes, comments charts
│   │       ├── Engagement rate trend
│   │       └── Locked post revenue
│   └── "Audit" Tab (creator only)
│       └── FeedDelegateAuditLog

DraftApprovalQueue (creator view, separate page)
├── Header: "Draft Approval Queue"
├── For each pending draft:
│   ├── Draft preview (text, image, tags)
│   ├── Delegate who submitted
│   ├── Submitted timestamp
│   ├── "Approve" button (publishes immediately)
│   ├── "Reject" button (with optional note)
│   └── "Edit & Approve" button (edit before publishing)
```

### 3.7 Frontend Routes

Add to `frontend/src/App.tsx`:

```typescript
<Route path="/feed/delegate/:creatorId" element={<DelegateFeedPage />} />
<Route path="/feed/drafts" element={<DraftApprovalQueue />} />
```

### 3.8 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/delegate_feed.py` | Feed delegation service | ~350 |
| `app/routers/delegate_feed.py` | REST API endpoints | ~200 |
| `frontend/src/pages/feed/DelegateFeedPage.tsx` | Delegate feed management | ~250 |
| `frontend/src/pages/feed/DelegateCreatePost.tsx` | Post creation in delegate mode | ~150 |
| `frontend/src/pages/feed/DraftApprovalQueue.tsx` | Draft approval queue | ~120 |
| `frontend/src/pages/feed/CommentModerationPanel.tsx` | Moderation controls | ~100 |
| `frontend/src/pages/feed/FeedAnalyticsSummary.tsx` | Analytics summary | ~80 |
| `frontend/src/pages/feed/FeedDelegateAuditLog.tsx` | Audit log | ~100 |
| `frontend/src/api/endpoints/delegate-feed.ts` | API wrappers | ~100 |
| `frontend/e2e/delegates-newsfeed.spec.ts` | E2E tests | ~500 |

### 3.9 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `delegate_feed_router` |
| `app/models.py` | Add DelegatedPost*, FeedAnalytics*, CommentModeration*, FeedDelegation* models |
| `app/routers/newsfeed.py` | Add `posted_by_delegate` field to post creation; add moderation metadata to comments |
| `scripts/local-ddb-init.py` | Add DraftApprovalQueue GSI to newsfeed table; add `GSI_DRAFT_SK` to attr_types |
| `frontend/src/api/types.ts` | Add DelegatedPost, FeedAnalytics, DraftApproval types |
| `frontend/src/App.tsx` | Add delegate feed routes |
| `frontend/src/pages/feed/PostCard.tsx` | Add delegate tag rendering; add moderation buttons for delegates |
| `frontend/src/pages/feed/FeedPage.tsx` | Add "Draft Queue" notification badge for creators with pending drafts |

---

## 4. Approval Workflow

### 4.1 Workflow States

```
Delegate creates post
    │
    ├── require_post_approval = false
    │   └── Post published immediately
    │       └── Fan-out to followers
    │
    └── require_post_approval = true
        └── Post saved as draft
            └── approval_status = "pending"
                └── GSI_DRAFT_PK = DRAFT_QUEUE#{creator_id}
                    │
                    ├── Creator approves
                    │   ├── approval_status = "approved"
                    │   ├── status = "published"
                    │   ├── Remove GSI_DRAFT_PK
                    │   └── Fan-out to followers
                    │
                    └── Creator rejects
                        ├── approval_status = "rejected"
                        ├── Remove GSI_DRAFT_PK
                        └── Delegate notified
```

### 4.2 Scheduled + Approval Interaction

When `require_post_approval` is true and a delegate creates a scheduled post:
1. The post is saved with `status=draft`, `approval_status=pending`, and `scheduled_at` preserved.
2. When the creator approves, the post transitions to `status=scheduled` (not immediately published).
3. The existing `newsfeed_scheduler` picks it up at the scheduled time and publishes it.
4. If the scheduled time has already passed when the creator approves, the post publishes immediately.

### 4.3 Edge Cases

- **Delegate edits post after approval**: The edit goes through immediately (no re-approval). Creator can enable `re_approval_on_edit` in future iteration.
- **Creator rejects with note**: The rejection note is stored and visible to the delegate in the draft list.
- **Delegate deletes pending draft**: Allowed; removes the draft and its queue entry.
- **Multiple delegates submit drafts**: Each draft is independent; creator reviews them in chronological order.
- **Delegate tries to lock a post without permission**: `allow_delegate_locking=false` rejects any non-zero `lock_price_cents`.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/delegates-newsfeed.spec.ts`

### Section 495: Delegated Post Creation API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 495.1 | Delegate creates a post on creator's feed | POST `/ui/newsfeed/delegate/alice/posts`; 200; response `author_id=alice`, `posted_by_delegate=bob` |
| 495.2 | Post appears on creator's feed | GET creator's feed; post present with correct text and author |
| 495.3 | Delegate tag appended when enabled | Creator settings `delegate_tag_on_posts=true`; post has `delegate_tag` field containing "[posted by @Bob]" |
| 495.4 | Delegate without feed_post gets 403 | Charlie with only chat_read; POST create post returns 403 |
| 495.5 | Delegate edits creator's post | PUT post; 200; text updated; `posted_by_delegate=bob` reflects last editor |

### Section 496: Draft Approval Workflow API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 496.1 | Delegate post saved as draft when approval required | Creator sets `require_post_approval=true`; delegate POST creates post; response `status=draft`, `approval_status=pending` |
| 496.2 | Pending drafts appear in creator's queue | GET `/ui/newsfeed/delegate/alice/drafts`; response includes the pending draft |
| 496.3 | Creator approves draft and it publishes | POST `.../drafts/{post_id}/approve`; 200; post `status=published`, `approval_status=approved` |
| 496.4 | Creator rejects draft with note | POST `.../drafts/{post_id}/reject` with `note="Not on brand"`; post `approval_status=rejected`; draft removed from queue |

### Section 497: Comment Moderation API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 497.1 | Delegate hides a comment | POST `.../comments/{comment_id}/moderate` with `action=hide`; 200; comment `moderated_by=bob`, `moderation_action=hidden` |
| 497.2 | Delegate pins a comment | POST with `action=pin`; 200; comment pinned; `moderation_action=pinned` |
| 497.3 | Delegate deletes a comment | POST with `action=delete`; 200; comment no longer returned in list |
| 497.4 | Delegate without feed_moderate gets 403 on moderation | Delegate with only feed_post; POST moderate returns 403 |

### Section 498: Feed Analytics & Audit API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 498.1 | Delegate views creator's feed analytics | GET `/ui/newsfeed/delegate/alice/analytics`; 200; response includes `total_posts`, `delegate_post_count` |
| 498.2 | Delegate without feed_read gets 403 on analytics | Delegate with only feed_post; GET analytics returns 403 |
| 498.3 | Creator audit log records all delegate actions | GET `.../audit`; entries include `post_created`, `comment_hidden`, `draft_submitted` with correct delegate IDs |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| POST/PUT/DELETE delegate posts | `require_ui_session` | `feed_post` permission |
| POST comment moderation | `require_ui_session` | `feed_moderate` permission |
| GET analytics | `require_ui_session` | `feed_read` permission |
| GET/POST drafts approve/reject | `require_ui_session` | Creator only |
| GET/PUT feed delegation settings | `require_ui_session` | Creator only |
| GET audit | `require_ui_session` | Creator only |

### 6.2 Authorization Enforcement

- Post ownership is verified: delegates can only modify posts where `author_id` matches the `creator_id` in the delegation.
- Comment moderation is restricted to comments on the creator's posts -- delegates cannot moderate comments on other users' posts.
- Draft approval endpoints verify the caller is the creator, not a delegate.
- The `allow_delegate_locking` setting is enforced at the service layer -- delegates cannot add lock prices unless explicitly allowed.
- Scheduled post creation respects `allow_delegate_scheduling` setting.

### 6.3 Rate Limiting

- Delegate post creation: max 30 posts per delegate per hour per creator.
- Comment moderation: max 100 moderation actions per delegate per hour per creator.
- Analytics queries: max 30 per delegate per minute.
- Draft approval: max 50 per creator per hour.

### 6.4 Input Validation

- `text`: 1-10000 characters for posts.
- `lock_price_cents`: 0-100000 (max $1000); only accepted when `allow_delegate_locking=true`.
- `tags`: max 20 tags per post, each 1-50 characters.
- `action` on moderation: must be one of `hide`, `pin`, `unpin`, `delete`.
- `note` on approval/rejection: 0-500 characters.

### 6.5 Content Safety

- Delegated posts go through the same content moderation pipeline as direct posts (if enabled).
- The `require_post_approval` setting adds an additional human review layer.
- Delegate tag visibility is controlled by the creator, not the delegate.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| DELEGATE-001 | Required (must complete first) | `require_delegate_permission`, delegation settings, audit infrastructure |
| `app/routers/newsfeed.py` | Exists (modify) | Add delegate metadata fields to post creation/editing |
| `app/services/newsfeed_fanout.py` | Exists | Fan-out for approved delegate posts |
| `app/services/newsfeed_scheduler.py` | Exists | Scheduled post support for delegated posts |
| `app/services/delegates.py` | From DELEGATE-001 | Permission checks and audit trail |
| `frontend/src/pages/feed/*` | Exists (modify) | Delegate mode in feed components |
| DELEGATE-005 | Not started | Will extend feed delegation to API clients |

---

## 8. Acceptance Criteria

1. Delegates with `feed_post` can create, edit, and delete posts on the creator's feed.
2. Posts created by delegates show the creator as author with optional delegate attribution.
3. Draft/approval workflow works: delegate submits, creator approves or rejects.
4. Approved drafts are published and fanned out to followers.
5. Delegates with `feed_moderate` can hide, pin, and delete comments on the creator's posts.
6. Delegates with `feed_read` can view the creator's feed analytics.
7. All delegated actions are recorded in the audit log.
8. Creator feed delegation settings are persisted and enforced.
9. Scheduled posts created by delegates respect the approval workflow.
10. All 16 E2E tests pass.

---

## 9. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                 Newsfeed Delegation Architecture                     │
└─────────────────────────────────────────────────────────────────────┘

  Delegate User                     Creator Account
       │                                │
       │ "Managing @creator" mode       │
       ▼                                │
  ┌──────────────────────────┐          │
  │ Delegate Actions:        │          │
  │ feed_post → create/edit  │          │
  │ feed_moderate → comments │          │
  │ feed_read → analytics    │          │
  └────────┬─────────────────┘          │
           │                            │
           ▼                            │
  ┌──────────────────────────┐          │
  │ Draft/Approval Workflow  │          │
  │                          │          │
  │ delegate creates draft ──┤          │
  │                          │     ┌────┴────┐
  │ creator reviews ─────────┼────▶│ Approve │
  │                          │     │ Reject  │
  │ approved → publish       │     └─────────┘
  │ + fanout to followers    │
  └──────────────────────────┘
```

---

## 10. DynamoDB Access Patterns

| Access Pattern | Table | PK | SK | Notes |
|----------------|-------|----|----|-------|
| Check feed delegation | `delegates` | `CREATOR#{id}` | `DELEGATE#{id}` | Verify feed_post/moderate/read |
| Create draft post | `posts` | `USER#{creator_id}` | `POST#{post_id}` | status=draft, delegate_sub set |
| List drafts for approval | `posts` | -- | -- | GSI: `DraftApprovalQueue`, status=pending_approval |
| Approve draft | `posts` | `USER#{creator_id}` | `POST#{post_id}` | Conditional: status=pending_approval |
| Moderate comment | `comments` | `POST#{post_id}` | `COMMENT#{id}` | SET hidden=true by delegate |
| Audit delegated posts | `posts` | `USER#{creator_id}` | begins_with `POST#` | Filter: delegate_sub is not null |

---

## 11. API Request/Response Examples

```bash
# --- POST /ui/feed/posts (as delegate, creates draft) ---
curl -X POST http://localhost:8000/ui/feed/posts \
  -H "Cookie: ui_session=delegate_sess; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "X-Managing-Creator: creator-sub-001" \
  -H "Content-Type: application/json" \
  -d '{"text": "New content dropping this weekend!", "media_urls": []}'

# Response 201:
{
  "post_id": "post-abc-123",
  "author_id": "creator-sub-001",
  "text": "New content dropping this weekend!",
  "status": "pending_approval",
  "delegate_sub": "delegate-sub-001",
  "created_at": 1748534400
}

# --- POST /ui/feed/posts/{post_id}/approve (creator approves) ---
curl -X POST http://localhost:8000/ui/feed/posts/post-abc-123/approve \
  -H "Cookie: ui_session=creator_sess; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123"

# Response 200:
{
  "post_id": "post-abc-123",
  "status": "published",
  "published_at": 1748534500
}
```

---

## 12. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------------|-------------|------------|---------------------|-----------------|
| No feed_post permission | 403 | `NO_FEED_POST_PERMISSION` | "No permission to post on this feed." | Request permission |
| No feed_moderate permission | 403 | `NO_FEED_MODERATE_PERMISSION` | "No permission to moderate comments." | Request permission |
| Draft not found | 404 | `DRAFT_NOT_FOUND` | "Draft post not found." | Verify post_id |
| Draft already approved | 409 | `ALREADY_APPROVED` | "This draft was already approved." | View published post |
| Draft already rejected | 409 | `ALREADY_REJECTED` | "This draft was already rejected." | Create new draft |
| Non-creator tries to approve | 403 | `NOT_CREATOR` | "Only the creator can approve drafts." | Ask creator to approve |

---

## 13. Observability & Monitoring

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `delegate_feed_posts_total` | Counter | `status={draft,published}` | Posts created by delegates |
| `delegate_feed_approvals_total` | Counter | `result={approved,rejected}` | Approval decisions |
| `delegate_feed_moderations_total` | Counter | `action={hide,delete,pin}` | Comment moderation actions |
| `delegate_draft_queue_gauge` | Gauge | -- | Pending drafts awaiting approval |

### Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Approval queue backlog | > 20 pending drafts | P3 |
| High rejection rate | > 50% rejections in 7d | P3 |

---

## 14. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Draft approval queue query | GSI with status filter; efficient query |
| Fan-out on approval | Same fan-out as creator publish; no extra cost |
| Permission check per action | Cache delegate permissions 30s TTL |
| Scheduled draft approval | Scheduled posts wait in draft until approved; publish at scheduled time |

---

## 15. Rollout Plan

| Flag | Default | Description |
|------|---------|-------------|
| `FEED_DELEGATION_ENABLED` | `false` | Master kill switch |
| `FEED_DRAFT_APPROVAL_REQUIRED` | `true` | Require creator approval for delegate posts |
| `FEED_DELEGATE_MODERATION_ENABLED` | `false` | Allow delegates to moderate comments |

### Canary

1. **Week 1**: Enable for test creators. Draft-approval only. No moderation.
2. **Week 2**: Enable moderation. Monitor abuse rate.
3. **Week 3**: Full rollout.
