# SOCIAL-002: Post Sharing / Public Reposts

**Ticket**: SOCIAL-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: P0 — Core User Experience
**Estimated effort**: 12-16 days

---

## 1. Executive Summary

The platform currently supports sharing posts only via direct message. The `SharePostDialog` component (`frontend/src/pages/feed/SharePostDialog.tsx`) sends a link preview to a selected conversation using `sendTextMessage()`. There is no public repost mechanism: a user cannot amplify a post to their own followers' feeds. This is the social media equivalent of having "email to a friend" but not "retweet".

Public reposts are a critical virality driver. On Twitter/X, retweets account for roughly 25% of all timeline content. Without reposts, content on this platform can only reach users who directly follow the original author or who happen to see it in a DM. Creators have no organic amplification beyond their own follower base. The lack of a repost feature directly limits content distribution, creator growth, and platform engagement metrics.

This feature adds a `POST /ui/posts/{post_id}/repost` endpoint that creates a repost entity in DynamoDB and fans it out to the reposter's followers' feeds (using the existing newsfeed fan-out infrastructure in `app/services/newsfeed_fanout.py`). Reposts appear in followers' feeds with "X reposted" attribution above the original post content. A repost count is added to `PostOut`. Users can undo a repost. The frontend adds a "Repost" button alongside the existing Share button on PostCard. Quote reposts (repost with commentary) are also supported.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Public repost (user)**
As a user, I want to repost another user's post to my own followers' feeds so that I can amplify content I find valuable.

*Acceptance criteria:*
- "Repost" button visible on PostCard in the action row.
- Clicking "Repost" creates a repost entity and fans it out to my followers' feeds.
- The repost appears in my followers' feed timeline with "X reposted" attribution.
- The original post content is shown in full below the attribution.
- A success toast confirms the repost was created.

**US-2: Repost count (viewer/creator)**
As a content viewer or creator, I want to see how many times a post has been reposted to gauge its virality.

*Acceptance criteria:*
- Repost count displayed in the PostCard action row next to the repost icon.
- Count updates optimistically on repost/undo.
- Count is accurate and atomically maintained.

**US-3: Undo repost (user)**
As a user, I want to undo a repost if I change my mind, removing it from my followers' feeds.

*Acceptance criteria:*
- Clicking the filled repost icon (already reposted state) shows an "Undo Repost" option.
- Undo removes the repost entity and decrements the count.
- Fan-out feed references are cleaned up from followers' feeds.
- The undo is reflected immediately in the UI (optimistic update).

**US-4: Feed attribution (viewer)**
As a feed viewer, I want to know who reposted content in my feed so I understand why it appeared.

*Acceptance criteria:*
- Reposted content in the feed shows "Alice reposted" above the original post card.
- The attribution links to the reposter's profile.
- The repost icon (Repeat2) is shown before the reposter's name.

**US-5: Quote repost (user)**
As a user, I want to repost with my own commentary (quote repost) so followers see my perspective alongside the original content.

*Acceptance criteria:*
- "Quote Repost" option in the repost popover.
- Opens a text input for the quote (max 500 characters).
- Quote text is displayed above the embedded original post in the feed.
- Quote reposts count toward the repost count of the original post.

**US-6: Repost restriction for locked/own posts**
As the platform, I want to prevent reposts of locked (paywalled) content and self-reposts to maintain content integrity.

*Acceptance criteria:*
- Repost button disabled (or hidden) on own posts with tooltip "Cannot repost your own post".
- Repost button disabled on locked posts with tooltip "Cannot repost locked content".
- Server returns 400 for self-repost attempts and 403 for locked post repost attempts.

### 2.2 Pain Points

1. **No content amplification**: Creators rely entirely on their own follower base. A small creator's great content has no organic path to a wider audience.
2. **Share-to-DM is private**: The existing `SharePostDialog` (`frontend/src/pages/feed/SharePostDialog.tsx:48-67`) sends to a single conversation. This is useful but is a private action, not a social amplification.
3. **No virality metric**: Without repost counts, creators cannot measure how "shareable" their content is. No analytics, no optimization loop.
4. **Missing engagement loop**: Reposts create notifications for the original author, driving them back to the platform (engagement loop). Without reposts, this loop doesn't exist.
5. **Feed staleness**: Without reposts, feeds only contain content from direct follows. Users who follow few people see less content, reducing time-on-platform.

### 2.3 Current Share Implementation

The `SharePostDialog` (`frontend/src/pages/feed/SharePostDialog.tsx:25-155`) is a dialog that:
1. Lists the user's conversations via `getConversations()`.
2. On share, calls `sendTextMessage(targetId, { preview: { url, title, image_url, site_name } })` (lines 48-57).
3. Navigates to `/messages` after successful share.
4. Uses React Query mutation with `["conversations"]` invalidation on success.

This is purely a DM-based share. The repost feature is complementary, not a replacement. Both buttons will coexist in the action row.

---

## 3. Current State Analysis

### 3.1 Post Data Model

`FeedPost` interface (`frontend/src/api/types.ts:1781-1834`) has no `repost_count`, `reposted_by_me`, or `is_repost` field. The backend `_post_to_dict()` function in `app/routers/newsfeed.py` returns post metadata but has no repost fields. The post item in DDB (`POST#{post_id}/META`) similarly has no `repost_count` attribute.

### 3.2 Feed Fan-out System

The newsfeed already has a fan-out mechanism for original posts. When a user creates a post, `newsfeed_fanout.py` writes feed reference items to each follower's feed index:
- `app/services/newsfeed_fanout.py` has `backfill_feed_on_follow()` (called from `app/services/social.py:86-88`)
- `app/services/newsfeed_fanout.py` also has `remove_feed_on_unfollow()` (called from `app/services/social.py:129-131`)
- Feed items use GSI1: `GSI1PK=FEED#{follower_id}`, `GSI1SK=<timestamp>#POST#{post_id}`

Reposts will use this same fan-out mechanism but with a different entity type (`REPOST#` instead of `POST#` in the sort key).

### 3.3 Newsfeed DDB Key Builders

Key builders in `app/routers/newsfeed.py:711-793`:
- `pk_user(user_id)` returns `USER#{user_id}` (line 711)
- `pk_post(post_id)` returns `POST#{post_id}` (line 715)
- `pk_like(user_id)` returns `LIKE#{user_id}` (line 775)
- No `pk_repost()` or repost-related key builder exists.

### 3.4 PostCard Action Row

The action row (`frontend/src/pages/feed/PostCard.tsx:512-560`) currently renders: Heart (like), MessageCircle (comments), DollarSign (Tip), Share2 (share). The action row is a flex container with gap-4. The repost button will be added between Tip and Share2.

### 3.5 Social Graph

`app/services/social.py:166-185` provides `get_following()` to list a user's follows. `app/services/social.py:141-163` provides `get_followers()` to list a user's followers. The repost fan-out needs `get_followers()` to determine which users' feeds should receive the repost reference. The function returns items from GSI5 with `GSI5PK=FOLLOWERS#{user_id}`.

### 3.6 Existing Fan-out Infrastructure

`app/services/newsfeed_fanout.py` provides the reusable fan-out pattern:
- `backfill_feed_on_follow(follower_id, followed_id)`: writes feed references for all of followed_id's posts into follower_id's feed.
- `remove_feed_on_unfollow(follower_id, followed_id)`: removes feed references.
- Both use batch write operations on the `app_single_table`.

The repost fan-out will follow the same pattern: for each follower of the reposter, write a feed reference item pointing to the repost.

### 3.7 Newsfeed Router Length

`app/routers/newsfeed.py` is ~4998 lines. The repost endpoints will be added near the existing social endpoints (around line 2657). The `_post_to_dict()` function (line 1792) needs to be extended.

### 3.8 Gaps

1. No repost endpoint in the newsfeed router (grep "repost" returns 0 in `app/routers/newsfeed.py`)
2. No `pk_repost()` key builder (lines 711-793)
3. No `repost_count` field on post metadata items
4. No `reposted_by_me` field in `_post_to_dict()` output
5. No `RepostButton` component in the frontend
6. No feed reference type `REPOST#` in the fan-out system
7. No deduplication logic for reposts in feed queries

---

## 4. Technical Architecture

### 4.1 System Diagram

```
PostCard                         Backend API                    DynamoDB (app_single_table)
  |                                |                               |
  |-- POST /posts/{id}/repost ---->|                               |
  |     { quote?: "..." }          |                               |
  |                                |-- put_item ------------------>| pk=REPOST#{user_id}
  |                                |                               | sk=POST#{post_id}
  |                                |                               |
  |                                |-- update_item (repost_count)->| pk=POST#{post_id}
  |                                |                               | sk=META
  |                                |                               |
  |                                |-- fan_out_repost() ---------->| For each follower:
  |                                |   (uses get_followers)        | pk=USER#{follower_id}
  |                                |                               | sk=FEEDREF#{ts}#REPOST#{repost_id}
  |                                |                               | GSI1PK=FEED#{follower_id}
  |                                |                               | GSI1SK={ts}#REPOST#{repost_id}
  |                                |                               |
Feed Timeline                      |                               |
  |-- GET /feed ------------------>|-- query GSI1 FEED#{uid} ----->|
  |                                |   (returns mix of posts +     |
  |                                |    repost references)         |
  |                                |-- resolve reposts:            |
  |                                |   get original post metadata  |
  |                                |   get reposter profile        |
  |<-- [{ post_id, reposted_by,  |                               |
  |       repost_quote, ... }]    |                               |
```

### 4.2 Data Flow -- Create Repost

1. User clicks "Repost" button on PostCard
2. Optional: user enters a quote comment (max 500 chars)
3. Frontend calls `POST /ui/posts/{post_id}/repost` with optional `{ quote: "..." }`
4. Backend validates:
   - Post exists and is published (not draft/scheduled)
   - Post is public (not locked/paywalled)
   - User is not the post author (no self-repost)
   - User hasn't already reposted this post (no duplicate)
   - User is not blocked by the post author
   - Rate limit not exceeded (30/hour)
5. Backend writes repost entity: `pk=REPOST#{user_id}, sk=POST#{post_id}`
6. Backend atomically increments `repost_count` on `POST#{post_id}/META`
7. Backend fans out repost to reposter's followers' feeds via batch write
8. Backend creates alert notification for original post author ("X reposted your post")
9. Returns `{ ok: true, repost_id, repost_count }`

### 4.3 Data Flow -- Undo Repost

1. User clicks "Undo Repost" in the repost popover
2. Frontend calls `DELETE /ui/posts/{post_id}/repost`
3. Backend validates: user has actually reposted this post
4. Backend deletes repost entity
5. Backend atomically decrements `repost_count` on post metadata (clamped at 0)
6. Backend removes fan-out feed references from all followers (batch delete)
7. Returns `{ ok: true, repost_count }`

### 4.4 Data Flow -- Feed with Reposts

1. `GET /feed` queries `GSI1PK=FEED#{viewer_id}` (existing flow)
2. Feed items now include both `POST#` and `REPOST#` references in `GSI1SK`
3. For each `REPOST#` reference, backend resolves:
   - Original post metadata from `POST#{post_id}/META`
   - Reposter profile from profiles table
4. Feed response includes `reposted_by` field on posts that are reposts
5. Deduplication: if multiple followed users repost the same post, show only the first occurrence (deduplicate by `post_id`)

### 4.5 Deduplication Strategy

If Alice follows both Bob and Charlie, and both repost Dave's post, Alice's feed should show the post once (with "Bob reposted" attribution, since Bob reposted first chronologically). Implementation:

1. During feed query result processing, track seen `post_id` values.
2. If a post appears as both a direct post reference and a repost reference, prefer the direct post (user follows the author).
3. If a post appears in multiple repost references, use the most recent repost.

---

## 5. Data Model Deep Dive

### 5.1 Repost Entity

Stored in the existing `app_single_table`.

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `REPOST#{user_id}` | `"REPOST#alice@test.local"` |
| `sk` | S | `POST#{post_id}` | `"POST#p_abc123"` |
| `Entity` | S | `"Repost"` | `"Repost"` |
| `repost_id` | S | Unique repost ID | `"rp_def456"` |
| `user_id` | S | User who reposted | `"alice@test.local"` |
| `post_id` | S | Original post ID | `"p_abc123"` |
| `original_author_id` | S | Original post author | `"bob@test.local"` |
| `quote` | S | Optional quote text | `"Great insight!"` |
| `created_at` | S | ISO timestamp | `"2026-05-27T10:00:00Z"` |
| `GSI1PK` | S | `REPOSTS#{post_id}` | `"REPOSTS#p_abc123"` |
| `GSI1SK` | S | `{created_at}#{user_id}` | `"2026-05-27T10:00:00Z#alice@test.local"` |

**Example DDB item (simple repost)**:
```json
{
  "pk": "REPOST#alice@test.local",
  "sk": "POST#p_abc123",
  "Entity": "Repost",
  "repost_id": "rp_def456",
  "user_id": "alice@test.local",
  "post_id": "p_abc123",
  "original_author_id": "bob@test.local",
  "created_at": "2026-05-27T10:00:00Z",
  "GSI1PK": "REPOSTS#p_abc123",
  "GSI1SK": "2026-05-27T10:00:00Z#alice@test.local"
}
```

**Example DDB item (quote repost)**:
```json
{
  "pk": "REPOST#alice@test.local",
  "sk": "POST#p_abc123",
  "Entity": "Repost",
  "repost_id": "rp_def456",
  "user_id": "alice@test.local",
  "post_id": "p_abc123",
  "original_author_id": "bob@test.local",
  "quote": "This completely changed how I think about content creation!",
  "created_at": "2026-05-27T10:00:00Z",
  "GSI1PK": "REPOSTS#p_abc123",
  "GSI1SK": "2026-05-27T10:00:00Z#alice@test.local"
}
```

### 5.2 Feed Reference for Reposts

When a repost is created, fan-out writes a feed reference to each follower's timeline:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pk` | S | `USER#{follower_id}` | `"USER#charlie@test.local"` |
| `sk` | S | `FEEDREF#{ts}#REPOST#{repost_id}` | `"FEEDREF#2026-05-27T10:00:00Z#REPOST#rp_def456"` |
| `Entity` | S | `"FeedRef"` | `"FeedRef"` |
| `ref_type` | S | `"repost"` | `"repost"` |
| `repost_id` | S | Repost ID | `"rp_def456"` |
| `post_id` | S | Original post ID | `"p_abc123"` |
| `reposter_id` | S | Who reposted | `"alice@test.local"` |
| `GSI1PK` | S | `FEED#{follower_id}` | `"FEED#charlie@test.local"` |
| `GSI1SK` | S | `{created_at}#REPOST#{repost_id}` | `"2026-05-27T10:00:00Z#REPOST#rp_def456"` |

### 5.3 Post Metadata Changes

Add `repost_count` field to the post metadata item (`POST#{post_id}/META`):

| Field | Type | Description |
|-------|------|-------------|
| `repost_count` | N | Number of reposts (atomically incremented/decremented) |

No DDB schema change needed -- this is just an additional attribute on an existing item.

### 5.4 Access Patterns

| Access Pattern | Key Condition | Index | Notes |
|---------------|---------------|-------|-------|
| Check if user reposted a post | `pk=REPOST#{uid}, sk=POST#{pid}` | Table | O(1) point read |
| List all reposts for a post | `GSI1PK=REPOSTS#{pid}` | GSI1 | Paginated, newest first |
| List user's reposts | `pk=REPOST#{uid}, sk begins_with POST#` | Table | Paginated |
| Feed query includes reposts | `GSI1PK=FEED#{uid}` | GSI1 (existing) | Mixed post + repost refs |
| Undo repost: find feed refs to delete | Scan with `FilterExpression ref_type=repost AND repost_id=X` | Table | Bounded by follower count |

### 5.5 DDB Init Script Changes

**File: `scripts/local-ddb-init.py`**

No new table or GSI needed. The repost entity uses the existing `app_single_table` with the existing `GSI1` index. The `GSI1PK`/`GSI1SK` attributes are added to repost items to enable the "list all reposts for a post" access pattern.

### 5.6 Settings

**File: `app/core/settings.py`**

```python
# Reposts (SOCIAL-002)
reposts_enabled: bool = os.environ.get("REPOSTS_ENABLED", "1") not in ("0", "false", "False")
reposts_rate_limit_per_hour: int = int(os.environ.get("REPOSTS_RATE_LIMIT_PER_HOUR", "30"))
reposts_quote_max_length: int = int(os.environ.get("REPOSTS_QUOTE_MAX_LENGTH", "500"))
```

---

## 6. API Contract Design

### 6.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/posts/{post_id}/repost` | `require_ui_session` | Create a repost |
| DELETE | `/ui/posts/{post_id}/repost` | `require_ui_session` | Undo a repost |
| GET | `/ui/posts/{post_id}/reposts` | `require_ui_session` | List who reposted |

### 6.2 POST `/ui/posts/{post_id}/repost`

**Request:**
```json
{
  "quote": "This is amazing content!"
}
```
`quote` is optional. Max 500 characters. HTML stripped server-side.

**curl example:**
```bash
curl -X POST http://localhost:8000/ui/posts/p_abc123/repost \
  -H "Cookie: ui_session=...; ui_access_token=...; ui_csrf=..." \
  -H "x-csrf-token: ..." \
  -H "Content-Type: application/json" \
  -d '{"quote": "This is amazing content!"}'
```

**Response (201):**
```json
{
  "ok": true,
  "repost_id": "rp_def456",
  "repost_count": 5
}
```

**Error Codes:**
| Status | Code | Condition |
|--------|------|-----------|
| 400 | `self_repost` | Cannot repost your own post |
| 400 | `quote_too_long` | Quote exceeds 500 characters |
| 403 | `post_locked` | Post is locked/paywalled |
| 403 | `blocked` | Post author has blocked the user |
| 404 | `post_not_found` | Post does not exist or is not published |
| 409 | `already_reposted` | User has already reposted this post |
| 429 | `rate_limited` | Rate limit exceeded (30/hour) |

### 6.3 DELETE `/ui/posts/{post_id}/repost`

**curl example:**
```bash
curl -X DELETE http://localhost:8000/ui/posts/p_abc123/repost \
  -H "Cookie: ui_session=...; ui_access_token=...; ui_csrf=..." \
  -H "x-csrf-token: ..."
```

**Response (200):**
```json
{
  "ok": true,
  "repost_count": 4
}
```

**Error Codes:**
| Status | Code | Condition |
|--------|------|-----------|
| 404 | `repost_not_found` | User has not reposted this post |

On undo: delete repost entity, decrement `repost_count`, remove fan-out feed references from all followers (batch delete in pages of 25).

### 6.4 GET `/ui/posts/{post_id}/reposts`

**Query parameters:**
- `limit` (int, default 20, max 50)
- `cursor` (string, optional)

**curl example:**
```bash
curl "http://localhost:8000/ui/posts/p_abc123/reposts?limit=20" \
  -H "Cookie: ui_session=...; ui_access_token=..."
```

**Response (200):**
```json
{
  "reposts": [
    {
      "repost_id": "rp_def456",
      "user_id": "alice@test.local",
      "display_name": "Alice",
      "profile_photo_url": "/mock/s3/uploads/alice_avatar.jpg",
      "quote": "This is amazing!",
      "created_at": "2026-05-27T10:00:00Z"
    }
  ],
  "next_cursor": "eyJHU0kxU0siOiAiMjAyNi0wNS0yN1QwOTowMDowMFoifQ==",
  "total_count": 5
}
```

### 6.5 Feed Response Changes

The existing `GET /feed` endpoint response is extended. Each post in the response can optionally include:

```json
{
  "post_id": "p_abc123",
  "reposted_by": {
    "user_id": "alice@test.local",
    "display_name": "Alice"
  },
  "repost_quote": "This is amazing!",
  "repost_count": 5,
  "reposted_by_me": true,
  ...existing fields...
}
```

The `_post_to_dict()` function in `app/routers/newsfeed.py` will be extended to include:
- `repost_count`: from the post metadata item's `repost_count` attribute
- `reposted_by_me`: requires a point read on `REPOST#{viewer_id}/POST#{post_id}` (viewer_id already available via the `viewer_id` parameter)
- `reposted_by`: populated only when the feed item is a repost reference (not on direct posts)
- `repost_quote`: from the repost entity's `quote` attribute

---

## 7. Frontend Component Design

### 7.1 New Files

| File | Purpose | Est. Lines |
|------|---------|------------|
| `frontend/src/pages/feed/RepostButton.tsx` | Repost toggle button with quote input | ~180 |
| `app/services/reposts.py` | Repost CRUD, fan-out, count management | ~300 |
| `frontend/e2e/reposts.spec.ts` | E2E tests | ~350 |

### 7.2 RepostButton Component

```tsx
interface RepostButtonProps {
  postId: string;
  authorId: string;
  repostCount: number;
  repostedByMe: boolean;
  isLocked?: boolean;
  isOwn?: boolean;
}
```

**Component behavior:**
- Renders `Repeat2` icon from lucide-react (green when `repostedByMe` is true)
- Disabled when `isOwn` or `isLocked` (with tooltip explaining why)
- On first click: opens small popover (Radix Popover or DropdownMenu) with two options:
  - "Repost" -- immediately creates simple repost
  - "Quote Repost" -- opens a text input dialog for the quote, then creates repost with quote
- When already reposted: clicking shows "Undo Repost" option (red text)
- Optimistic update for count and icon state

**React Query hooks:**
```typescript
// Mutation: create repost
const repostMut = useMutation({
  mutationFn: ({ postId, quote }: { postId: string; quote?: string }) =>
    repostPost(postId, quote ? { quote } : undefined),
  onMutate: async () => {
    // Optimistic: increment count, set repostedByMe
    await queryClient.cancelQueries({ queryKey: ["feed"] });
    queryClient.setQueriesData({ queryKey: ["feed"] }, (old: any) => {
      // Update matching post in feed pages
    });
  },
  onSettled: () => {
    queryClient.invalidateQueries({ queryKey: ["feed"] });
    queryClient.invalidateQueries({ queryKey: ["posts", postId] });
  },
});

// Mutation: undo repost
const undoMut = useMutation({
  mutationFn: (postId: string) => undoRepost(postId),
  onMutate: async () => {
    // Optimistic: decrement count, clear repostedByMe
  },
  onSettled: () => {
    queryClient.invalidateQueries({ queryKey: ["feed"] });
    queryClient.invalidateQueries({ queryKey: ["posts", postId] });
  },
});
```

### 7.3 PostCard Integration

Modify `PostCard.tsx` action row (around line 547) to add RepostButton between Tip and Share:

```tsx
<RepostButton
  postId={post.post_id}
  authorId={post.author_id}
  repostCount={post.repost_count ?? 0}
  repostedByMe={post.reposted_by_me ?? false}
  isLocked={post.lock_price_cents != null && post.lock_price_cents > 0}
  isOwn={isOwn}
/>
```

### 7.4 Feed Timeline Repost Attribution

When a feed item has `reposted_by`, render attribution above the PostCard. In the `NewsFeed` or `FeedPage` component that maps over feed posts:

```tsx
{post.reposted_by && (
  <div className="flex items-center gap-1 px-4 py-1.5 text-sm text-muted-foreground">
    <Repeat2 className="h-3.5 w-3.5" />
    <Link
      to={`/u/${post.reposted_by.user_id}`}
      className="font-medium hover:underline"
    >
      {post.reposted_by.display_name}
    </Link>
    <span>reposted</span>
  </div>
)}
{post.repost_quote && (
  <div className="px-4 pb-2 text-sm italic text-foreground">
    "{post.repost_quote}"
  </div>
)}
<PostCard post={post} ... />
```

### 7.5 TypeScript Types

Add to `frontend/src/api/types.ts` in the `FeedPost` interface (after `my_reactions` at line 1822):

```typescript
repost_count?: number;
reposted_by_me?: boolean;
reposted_by?: { user_id: string; display_name: string };
repost_quote?: string;
```

### 7.6 API Endpoints

```typescript
// frontend/src/api/endpoints/newsfeed.ts (add to existing file)
export const repostPost = (postId: string, body?: { quote?: string }) =>
  api.post<{ ok: boolean; repost_id: string; repost_count: number }>(
    `/ui/posts/${postId}/repost`, body ?? {}
  );

export const undoRepost = (postId: string) =>
  api.delete<{ ok: boolean; repost_count: number }>(`/ui/posts/${postId}/repost`);

export const getReposts = (postId: string, params?: { limit?: number; cursor?: string }) =>
  api.get<{ reposts: RepostUser[]; next_cursor?: string; total_count: number }>(
    `/ui/posts/${postId}/reposts`, { params }
  );
```

### 7.7 Component Tree for Feed with Reposts

```
FeedPage
  |-- useInfiniteQuery(["feed"])
  |
  |-- For each post in feed:
  |     |-- RepostAttribution (if post.reposted_by)
  |     |     |-- Repeat2 icon
  |     |     |-- Link to reposter profile
  |     |     |-- "reposted" text
  |     |
  |     |-- QuoteBlock (if post.repost_quote)
  |     |     |-- Italic quote text
  |     |
  |     |-- PostCard
  |           |-- ... existing content ...
  |           |-- Action row:
  |                 |-- Heart (like)
  |                 |-- MessageCircle (comments)
  |                 |-- DollarSign (tip)
  |                 |-- RepostButton (NEW)
  |                 |-- Share2 (DM share)
```

---

## 8. Security & Privacy

### 8.1 Authorization

- All repost endpoints use `require_ui_session` (cookie auth + CSRF enforcement for non-GET).
- Users cannot repost their own posts (enforced server-side: compare `session.user_sub` with post's `user_id`).
- Users cannot repost locked posts (enforced server-side: check `lock_price_cents > 0` on post metadata).
- Users cannot repost posts from users who have blocked them (uses `_is_blocked()` from `app/services/social.py:393-398`).
- The `GET /ui/posts/{post_id}/reposts` endpoint is accessible to any authenticated user (repost lists are public social data).

### 8.2 Abuse Prevention

- **Rate limit**: 30 reposts per hour per user. Uses the same sliding-window DDB counter pattern as `_enforce_signaling_rate_limit` in messaging.py. Key: `RATE#{user_id}/REPOST_RATE#{hour_bucket}`.
- **Quote text validation**: max 500 characters, stripped of HTML tags (`bleach.clean()` or regex strip). No images or links in quotes (plain text only).
- **Undo flood prevention**: Undo repost removes fan-out references, which is an expensive operation for users with many followers. Rate limit undo to 60/hour.
- **Repost-spam pattern detection**: If a user reposts more than 10 different posts in 5 minutes, flag for review (future enhancement).

### 8.3 Feed Fan-out Safety

- Fan-out is bounded to the reposter's follower count. The existing fan-out mechanism in `newsfeed_fanout.py` already handles pagination for large follower lists.
- For reposter follower counts > 100, fan-out is processed asynchronously if `EVENTS_SQS_URL` is set (`app/routers/newsfeed.py:57`). The endpoint returns immediately; fan-out completes in the background.
- The fan-out writes use `batch_writer()` with pages of 25 items to stay within DDB batch write limits.

### 8.4 Content Integrity

- Reposts always reference the original post. There is no "repost of a repost" chain. If Alice reposts Bob's post, and Charlie tries to "repost Alice's repost," it creates a repost of Bob's original post (not a nested repost).
- Deleted posts: if the original post is deleted after being reposted, the repost feed reference still exists but `_post_to_dict()` returns null for the resolved post. The frontend handles this by showing "[Post no longer available]" in place of the post content.

---

## 9. Performance & Scalability

### 9.1 Write Path Costs

| Operation | DDB Operations | Notes |
|-----------|---------------|-------|
| Create repost | 1 put_item + 1 update_item (count) + N put_items (fan-out) | N = follower count |
| Undo repost | 1 delete_item + 1 update_item (count) + N delete_items (fan-out cleanup) | N = follower count |
| Rate limit check | 1 update_item | Sliding window counter |

### 9.2 Read Path Costs

| Endpoint | DDB Operations | Latency |
|----------|---------------|---------|
| GET /feed (includes reposts) | Same as current feed query + resolution | ~50-80ms |
| GET /posts/{id}/reposts | 1 GSI1 query + N profile batch reads | ~20ms |
| Repost status check (in _post_to_dict) | +1 get_item per post | +5ms per post |

### 9.3 Fan-out Optimization

For users with many followers (>100), the fan-out should be processed asynchronously via the existing SQS event queue (`EVENTS_SQS_URL` at `app/routers/newsfeed.py:57`). The repost endpoint returns immediately with `repost_count` updated; fan-out completes in the background. Followers see the repost within 5-30 seconds depending on queue depth.

For users with <= 100 followers, fan-out is synchronous (adds ~200ms to the repost endpoint response time for 100 followers at 2ms per batch_write item).

### 9.4 Repost Count Consistency

`repost_count` is atomically incremented/decremented using DynamoDB `ADD` expressions. In rare race conditions, the count may drift. A reconciliation function (similar to `reconcile_follow_counts` in `social.py:294-338`) can recount by scanning `GSI1PK=REPOSTS#{post_id}` and comparing to the stored count.

### 9.5 Feed Deduplication Cost

Deduplication requires tracking seen `post_id` values while processing feed items. This is an O(n) in-memory operation where n = number of feed items in the page (typically 20-50). Trivial CPU cost.

### 9.6 `reposted_by_me` Query Cost

For each post in the feed response, determining `reposted_by_me` requires checking if `REPOST#{viewer_id}/POST#{post_id}` exists. For a feed page of 20 posts, this is 20 additional `get_item` calls. These can be batched using `BatchGetItem` (up to 25 keys per call) for a single DDB round-trip. Expected latency: ~10ms additional.

---

## 10. Migration & Rollback

### 10.1 Feature Flag

`REPOSTS_ENABLED` (default `true`). When false:
- Repost endpoints return 404
- `RepostButton` component renders nothing (early return `null`)
- Feed query skips repost references (filters `ref_type != "repost"`)
- Existing reposts remain in DDB but are invisible

### 10.2 Database Changes

No new DDB table needed. No new GSI needed. Repost entities use the existing `app_single_table` with existing `GSI1`. The `repost_count` attribute is added to existing post metadata items (additive, no schema migration).

### 10.3 Rollback Steps

1. Set `REPOSTS_ENABLED=false` in environment variables.
2. All repost UI and API become inactive.
3. Fan-out feed references for reposts remain in DDB but are filtered out of feed queries.
4. To fully remove data: scan and delete items with `pk` starting with `REPOST#` and feed refs with `ref_type=repost`.

### 10.4 Deployment Order

1. Deploy backend with repost endpoints + feature flag OFF.
2. Deploy frontend with RepostButton (hidden when flag is off).
3. Enable feature flag `REPOSTS_ENABLED=true`.
4. Monitor repost creation rate and feed query latency for 24 hours.
5. If issues: disable flag (instant rollback, no deploy needed).

---

## 11. Testing Strategy

### 11.1 Unit Tests (pytest)

**File: `tests/test_reposts.py`**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `test_repost_creates_entity_and_increments_count` | DDB item exists; `repost_count` incremented |
| 2 | `test_repost_own_post_returns_400` | 400 response with code `self_repost` |
| 3 | `test_duplicate_repost_returns_409` | 409 response with code `already_reposted` |
| 4 | `test_undo_repost_deletes_entity_and_decrements_count` | DDB item removed; count decremented |
| 5 | `test_repost_locked_post_returns_403` | 403 response with code `post_locked` |
| 6 | `test_quote_repost_stores_quote_text` | DDB item has `quote` attribute |
| 7 | `test_list_reposts_returns_correct_users` | Response includes reposter info |
| 8 | `test_reposted_by_me_correct_per_viewer` | True for reposter, false for others |
| 9 | `test_fanout_creates_feed_refs_for_followers` | FEEDREF items exist for each follower |
| 10 | `test_undo_repost_removes_fanout_refs` | FEEDREF items deleted for each follower |
| 11 | `test_repost_blocked_users_post_returns_403` | 403 response with code `blocked` |
| 12 | `test_rate_limit_enforced` | 31st repost in an hour returns 429 |
| 13 | `test_repost_nonexistent_post_returns_404` | 404 response with code `post_not_found` |
| 14 | `test_quote_too_long_returns_400` | 501-char quote returns 400 |
| 15 | `test_feed_includes_repost_with_attribution` | GET /feed shows `reposted_by` on reposted items |
| 16 | `test_feed_deduplicates_same_post_reposted_by_multiple` | Same post appears once in feed |
| 17 | `test_undo_repost_when_not_reposted_returns_404` | 404 response |
| 18 | `test_repost_count_clamps_at_zero` | After manual corruption, undo doesn't go negative |

### 11.2 E2E Tests

**Test File:** `frontend/e2e/reposts.spec.ts`

**Section 1: Repost API (6 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Alice reposts Bob's post | 201; repost_count incremented; repost_id returned |
| 2 | Alice reposts same post again returns 409 | 409 response |
| 3 | Alice undoes repost | 200; repost_count decremented |
| 4 | Alice cannot repost own post | 400 response |
| 5 | Quote repost stores quote | 201; GET /reposts shows quote text |
| 6 | Repost non-existent post returns 404 | 404 response |

**Section 2: Feed with Reposts (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 7 | Repost appears in follower's feed | Bob follows Alice; Alice reposts Charlie's post; Bob's feed shows it with `reposted_by` |
| 8 | Feed repost has attribution | `reposted_by.display_name` is Alice's display name |
| 9 | Feed repost has original post content | body, image_urls from original post present |
| 10 | Quote repost shows quote in feed | `repost_quote` field present in feed response |
| 11 | Undo repost removes from follower's feed | Alice undoes; Bob's feed no longer shows it |

**Section 3: PostCard UI (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 12 | Repost button visible on PostCard | Repeat2 icon visible in action row |
| 13 | Repost button disabled on own posts | Tooltip "Cannot repost your own post" |
| 14 | Click repost toggles icon color | Icon turns green after repost |
| 15 | Repost count updates optimistically | Count next to icon increments immediately |
| 16 | "X reposted" attribution visible | Text "Alice reposted" visible above repost card in feed |

---

## 12. Open Questions & Risks

### 12.1 Unresolved Decisions

| # | Question | Recommendation | Status |
|---|----------|---------------|--------|
| 1 | Repost vs. Share naming in UI | Keep both: "Repost" (Repeat2 icon, public) alongside "Share" (Share2 icon, DM). | DECIDED |
| 2 | Repost of repost | No chains. Reposts always reference the original post. Simplifies data model. | DECIDED |
| 3 | Repost of locked content | No. Locked posts cannot be reposted (would bypass paywall intent). | DECIDED |
| 4 | Should repost count be visible to all or only author? | Visible to all (like like_count). Social proof metric. | DECIDED |
| 5 | Notification for reposts | Yes. Alert notification to original author: "X reposted your post". | DECIDED |

### 12.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Fan-out storm for popular user (10K+ followers) | Medium | High | Async fan-out via SQS for followers > 100; rate limit reposts to 30/hour |
| Feed deduplication needed | Medium | Medium | If Alice and Bob both repost Charlie's post, viewer sees it once. Deduplicate by post_id in feed query. |
| Undo fan-out cleanup expensive | Low | Medium | Batch delete in pages of 25; process async for large follower counts |
| repost_count drift | Low | Low | Reconciliation function; count is non-critical (cosmetic) |
| Deleted original post after repost | Low | Low | Frontend shows "[Post no longer available]" placeholder |

---

## 13. Files to Create

| File | Purpose |
|------|---------|
| `app/services/reposts.py` | Repost CRUD, fan-out, count management, rate limiting |
| `frontend/src/pages/feed/RepostButton.tsx` | Repost button component with quote option and popover |
| `frontend/e2e/reposts.spec.ts` | E2E tests |
| `tests/test_reposts.py` | Backend unit tests |

## 14. Files to Modify

| File | Change |
|------|--------|
| `app/routers/newsfeed.py` | Add repost/undo-repost/list-reposts endpoints; extend `_post_to_dict()` with `repost_count`, `reposted_by_me`; extend feed query to resolve repost references and deduplicate |
| `app/main.py` | No change needed (newsfeed router already registered) |
| `app/core/settings.py` | Add `reposts_enabled`, `reposts_rate_limit_per_hour`, `reposts_quote_max_length` settings |
| `frontend/src/api/types.ts` | Add `repost_count`, `reposted_by_me`, `reposted_by`, `repost_quote` to FeedPost interface |
| `frontend/src/pages/feed/PostCard.tsx` | Add RepostButton to action row (line ~547) |
| `frontend/src/api/endpoints/newsfeed.ts` | Add `repostPost`, `undoRepost`, `getReposts` functions |
| `frontend/src/pages/feed/SharePostDialog.tsx` | No change (remains as DM share) |
| `frontend/src/pages/feed/FeedPage.tsx` | Add repost attribution rendering above PostCard when `reposted_by` is present |

---

## 15. Dependencies

- **Newsfeed fan-out (existing)**: `app/services/newsfeed_fanout.py` -- backfill/remove feed references. Reposts reuse this fan-out mechanism with a different entity type.
- **Social graph (existing)**: `app/services/social.py:141-163` -- `get_followers()` for fan-out target list; `_is_blocked()` (line 393-398) for blocking enforcement.
- **Alerts system (existing)**: Notification to original author when their post is reposted. Uses existing alert creation pattern from `app/services/alerts.py`.
- **SOC-001 (follow system)**: Must be implemented first for `get_followers()` to work correctly with GSI5.

---

## 16. Acceptance Criteria

1. Users can repost another user's published, unlocked post via `POST /ui/posts/{post_id}/repost`.
2. Users cannot repost their own posts (400 error).
3. Users cannot repost locked (paywalled) posts (403 error).
4. Repost count is displayed on PostCard alongside like and comment counts.
5. Reposts appear in the reposter's followers' feeds with "X reposted" attribution.
6. Quote reposts display the quote text alongside the original post content.
7. Users can undo a repost via `DELETE /ui/posts/{post_id}/repost`, removing it from followers' feeds.
8. Duplicate repost attempts return 409.
9. Repost button shows active state (green icon) when user has reposted.
10. Feed deduplicates when multiple followed users repost the same post.
11. Rate limiting enforced at 30 reposts per hour per user.
12. Repost of non-existent or deleted post returns 404.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| SharePostDialog uses sendTextMessage | `frontend/src/pages/feed/SharePostDialog.tsx` | 48-57 | VERIFIED |
| FeedPost has no repost fields | `frontend/src/api/types.ts` | 1781-1834 | VERIFIED |
| No repost endpoint in newsfeed router | `app/routers/newsfeed.py` | all 4998 lines | VERIFIED: grep "repost" returns 0 |
| Key builders have no repost prefix | `app/routers/newsfeed.py` | 711-793 | VERIFIED |
| PostCard action row location | `frontend/src/pages/feed/PostCard.tsx` | 512-560 | VERIFIED |
| PostCard Share2 button | `frontend/src/pages/feed/PostCard.tsx` | 548-554 | VERIFIED |
| get_followers() function | `app/services/social.py` | 141-163 | VERIFIED |
| _is_blocked() function | `app/services/social.py` | 393-398 | VERIFIED |
| backfill_feed_on_follow called from social.py | `app/services/social.py` | 86-88 | VERIFIED |
| Feed GSI1 key pattern | `app/routers/newsfeed.py` | GSI1PK=FEED# | VERIFIED |
| SQS event queue config | `app/routers/newsfeed.py` | 57 | VERIFIED: EVENTS_SQS_URL |
| app_single_table used for newsfeed | `app/routers/newsfeed.py` | 54, 59 | VERIFIED |
| PostCard Tip button between MessageCircle and Share2 | `frontend/src/pages/feed/PostCard.tsx` | 539-547 | VERIFIED |
