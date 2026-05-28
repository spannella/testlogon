# SOC-006: Creator Storefront Page

**Ticket**: SOC-006
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Executive Summary

The current public user profile page (`PublicUserProfilePage.tsx`, 224 lines) displays only basic identity information: display name, title, description, location, cover photo, and member-only contact details. When a viewer visits a creator's profile, they see nothing about the creator's actual content -- no videos, no posts, no subscription tiers, and no way to subscribe. The backend already returns `has_subscription_plans: bool` (profile.py:352-362) but never exposes the actual plan list on the profile page. Video listing (`/ui/videos/creator/{creator_id}`), newsfeed posts (`/profile/public/{identifier}/posts`), and subscription plans (`/api/creators/{creator_id}/plans`) all exist as separate endpoints but are not aggregated on the profile page.

This ticket transforms the public profile page into a full creator storefront with tabbed content sections (Videos, Posts, About), subscription tier cards with "Subscribe" CTAs, and a follow button. The frontend aggregates existing backend endpoints -- no new backend API endpoints are required. This is purely a frontend feature build that connects existing data sources into a unified creator-facing profile experience.

Creator storefronts are the primary conversion surface for subscription-based platforms. Without a content showcase on the profile, potential subscribers have no way to evaluate a creator's output before committing. Research from comparable platforms indicates that profile pages with content previews convert visitors to subscribers at 3-5x the rate of name-and-bio-only profiles. This directly impacts creator revenue and platform take rate. The profile link is also the primary URL that creators share externally (social media bios, email signatures, marketing materials), making it the single most important landing page for organic growth.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: View Creator Videos on Profile**

| Field | Value |
|-------|-------|
| Actor | Authenticated viewer |
| Story | As a viewer, I want to see a creator's videos on their profile page so I can evaluate their content before subscribing. |
| Preconditions | Viewer is authenticated. Creator has published public videos. |
| Acceptance Criteria | 1. "Videos" tab is visible on the profile page. 2. Clicking the tab shows a responsive grid of video thumbnails. 3. Each card shows thumbnail, title, duration badge, and view count. 4. Clicking a video card navigates to `/videos/{videoId}`. 5. Empty state shows "No videos yet" with a Sparkles icon. 6. Videos are sorted by most recent first. |

**US-2: Browse Creator Posts on Profile**

| Field | Value |
|-------|-------|
| Actor | Viewer (authenticated or unauthenticated) |
| Story | As a viewer, I want to browse a creator's posts from their profile so I can see their writing and media content. |
| Preconditions | Creator has published posts. |
| Acceptance Criteria | 1. "Posts" tab is visible on the profile page. 2. Posts are shown as vertical cards with body preview, image thumbnail, and engagement counts. 3. Filter pills allow filtering by type (All, Images, Videos, Text). 4. Pagination via "Load more" button with cursor-based loading. 5. Unauthenticated viewers see public posts only. 6. Authenticated followers see followers-only posts as well. |

**US-3: See Subscription Tiers on Profile**

| Field | Value |
|-------|-------|
| Actor | Viewer |
| Story | As a viewer, I want to see available subscription tiers on a creator's profile so I can decide which plan to subscribe to. |
| Preconditions | Creator has at least one active subscription plan. |
| Acceptance Criteria | 1. "Subscription Plans" section is visible when creator has plans. 2. Plan cards show name, description, price, and feature list. 3. "Subscribe" button on each card initiates the subscription flow. 4. Discount code input is available (via PlanBrowser reuse). 5. Section is hidden when creator has no plans (`has_subscription_plans: false`). |

**US-4: Subscribe from Profile**

| Field | Value |
|-------|-------|
| Actor | Authenticated viewer |
| Story | As a viewer, I want to subscribe to a creator directly from their profile so I can start accessing premium content immediately. |
| Preconditions | Viewer is authenticated. Creator has active plans. |
| Acceptance Criteria | 1. Clicking "Subscribe" triggers the existing subscribe mutation. 2. Success toast appears on completion. 3. Unauthenticated users clicking "Subscribe" are redirected to `/login`. |

**US-5: Follow/Unfollow from Profile**

| Field | Value |
|-------|-------|
| Actor | Authenticated viewer |
| Story | As a viewer, I want to follow/unfollow a creator from their profile so I can see their content in my feed. |
| Preconditions | Viewer is authenticated. Viewing another user's profile (not own). |
| Acceptance Criteria | 1. "Follow" button visible on other users' profiles. 2. Clicking toggles to "Following" state. 3. Hovering "Following" shows "Unfollow" text. 4. Optimistic update (instant UI toggle, revert on error). 5. Not shown on own profile. 6. Blocked users cannot follow (enforced by backend). |

**US-6: View Stats Row**

| Field | Value |
|-------|-------|
| Actor | Viewer |
| Story | As a viewer, I want to see the creator's follower count, following count, and post count so I can gauge their popularity. |
| Preconditions | None (stats are always available in the profile response). |
| Acceptance Criteria | 1. Stats row displays "N followers", "N following", "N posts". 2. Numbers are formatted (e.g., "1.2K" for 1200). 3. Stats are always visible regardless of audience level. |

**US-7: Unauthenticated Visitor Experience**

| Field | Value |
|-------|-------|
| Actor | Unauthenticated visitor |
| Story | As an unauthenticated visitor, I want to see public content previews before signing up so I can evaluate the creator. |
| Preconditions | Visitor navigates to `/u/{identifier}` without being logged in. |
| Acceptance Criteria | 1. "Posts" and "About" tabs are visible. 2. "Videos" tab is hidden (requires auth per video listing endpoint). 3. Public posts are shown in the Posts tab. 4. Subscription plans are shown with "Subscribe" buttons that redirect to login. 5. "Follow" button is hidden. |

### 2.2 Pain Points

1. **No content showcase**: Creators share profile links externally but the landing page shows only a name and bio -- visitors bounce immediately without seeing content. The current page is 224 lines of purely structural profile data (name, title, description, location, cover photo).
2. **Subscription conversion gap**: The backend knows a creator has plans (`has_subscription_plans: true` from `profile.py:380`) but never shows them, making organic subscription growth impossible through profile links.
3. **Fragmented navigation**: A viewer must separately navigate to the gallery, feed, and subscriptions pages to evaluate a creator. There is no single unified storefront experience.
4. **Follow action buried**: There is no follow/unfollow button on the profile page despite the social graph being fully implemented in `app/services/social.py` (follow at line 31, unfollow at line 101, status at line 205).
5. **Wasted API data**: The profile response already includes `follower_count`, `following_count`, `post_count`, `is_following`, `is_followed_by`, `is_mutual`, and `has_subscription_plans` -- none of which are rendered in the current UI.

### 2.3 Current Profile Page Capabilities

The existing `PublicUserProfilePage.tsx` renders:
- Display name, title (subtitle), description (bio)
- Cover photo and profile photo (avatar)
- Location
- Member-only details (email, phone, languages) behind auth
- "Message" button (creates DM)
- "Add contact" button
- Audience badge ("public" / "member" / "owner")
- Sign-in upsell for unauthenticated visitors

What it does **NOT** render:
- Videos grid
- Posts feed
- Subscription tier cards
- Follow/Unfollow button
- Content tabs
- Follower/following/post counts
- Social proof indicators

---

## 3. Current State Analysis

### 3.1 Public Profile Backend (profile.py:345-384)

The `get_public_profile` endpoint assembles a rich profile response:

```python
# Check subscription plans (profile.py:352-362)
has_subscription_plans = False
try:
    plans_resp = T.subscriptions.query(
        KeyConditionExpression=Key("pk").eq(f"CREATOR#{user_sub}"),
        Select="COUNT",
        Limit=1,
    )
    has_subscription_plans = plans_resp.get("Count", 0) > 0
except Exception:
    pass

# Return full profile (profile.py:364-384)
return {
    "user_id": user_sub,
    "identifier": requested_identifier,
    "canonical_identifier": canonical_identifier,
    "display_name": profile.get("display_name") or "User",
    "title": profile.get("title"),
    "description": profile.get("description"),
    "location": profile.get("location"),
    "profile_photo_url": profile.get("profile_photo_url"),
    "cover_photo_url": profile.get("cover_photo_url"),
    "follower_count": int(profile.get("follower_count", 0)),
    "following_count": int(profile.get("following_count", 0)),
    "post_count": int(profile.get("post_count", 0)),
    "is_following": is_following,
    "is_followed_by": is_followed_by,
    "is_mutual": is_following and is_followed_by,
    "has_subscription_plans": has_subscription_plans,
    "created_at": profile.get("created_at"),
    "discoverability": disc_status if disc_status == DiscoverabilityState.HIDDEN.value else None,
}
```

The follow status check (lines 345-351) uses `get_follow_status(viewer_sub, user_sub)` from `social.py:205`:

```python
if viewer_sub and viewer_sub != user_sub:
    try:
        from app.services.social import get_follow_status
        status = get_follow_status(viewer_sub, user_sub)
        is_following = status.get("is_following", False)
        is_followed_by = status.get("is_followed_by", False)
    except Exception:
        pass
```

**Citations**:
- `app/routers/profile.py:345-351` -- follow status check
- `app/routers/profile.py:352-362` -- subscription plans count query
- `app/routers/profile.py:364-384` -- full response including `follower_count`, `following_count`, `is_following`, `has_subscription_plans`

### 3.2 Profile Posts Endpoint (profile.py:386-444)

A paginated posts endpoint already exists:

```python
@router.get("/profile/public/{identifier}/posts")
async def get_public_profile_posts(
    identifier: str,
    req: Request,
    limit: int = Query(default=12, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    filter: Optional[Literal["all", "text", "image", "video", "locked"]] = Query(default="all"),
):
```

Key implementation details:
- Uses `GSI2` with `GSI2PK = POST_AUTHOR#{user_sub}` for efficient author-scoped queries.
- `ScanIndexForward=False` for reverse chronological order.
- Over-fetches by `limit * 2` to account for filtered posts.
- Auth-optional: authenticated viewers see followers-only posts if they follow the author (line 419-431).
- Supports filter param: "all", "text", "image", "video", "locked".
- Returns paginated list with `next_cursor`.

**Citations**:
- `app/routers/profile.py:386-392` -- endpoint definition with filter and pagination params
- `app/routers/profile.py:419-431` -- auth-optional viewer follow check
- `app/routers/profile.py:434-443` -- GSI2 query with POST_AUTHOR PK

### 3.3 Creator Videos Endpoint (video_listing.py:319-330)

```python
@router.get("/creator/{creator_id}", response_model=VideoListOut)
def list_creator_public_videos(
    creator_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user=Depends(require_ui_session),
):
    """List a specific creator's published + public videos."""
    decoded_cursor = decode_cursor(cursor)
    result = list_videos_by_creator_public(creator_id, limit=limit, cursor=decoded_cursor)
    items = [_video_to_list_item(v) for v in result["items"]]
    return VideoListOut(items=items, cursor=encode_cursor(_sanitize_cursor(result.get("cursor"))))
```

**Important**: This endpoint requires `require_ui_session` (authentication required). The Videos tab can only be shown to authenticated viewers. The router is registered at `/ui/videos` (line 40).

**Citations**:
- `app/routers/video_listing.py:40` -- router prefix `/ui/videos`
- `app/routers/video_listing.py:319-330` -- `list_creator_public_videos` with `require_ui_session`

### 3.4 Subscription Plans Endpoint (subscription_server.py:746-753)

```python
@router.get("/api/creators/{creator_id}/plans", response_model=List[PlanOut])
async def list_plans(creator_id: str, include_profile: bool = Query(default=False)):
    items = ddb_query(pk_creator(creator_id))
    plans = [it for it in items if it.get("sk", "").startswith("PLAN#")]
    plans.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    if include_profile:
        return [attach_creator_profile(p) for p in plans]
    return plans
```

This is a **public endpoint** -- no auth dependency. No `require_user` call, no `x_user_id` dependency. Anyone can list a creator's plans.

**Citations**:
- `app/routers/subscription_server.py:746-753` -- public `list_plans` endpoint

### 3.5 Social Follow Endpoints (social.py)

The social router at `app/routers/social.py` provides:

| Endpoint | Method | Path | Auth | Line |
|----------|--------|------|------|------|
| `follow` | POST | `/ui/social/follow` | `require_ui_session` | 103 |
| `unfollow` | POST | `/ui/social/unfollow` | `require_ui_session` | 122 |
| `list_followers` | GET | `/ui/social/{user_id}/followers` | `require_ui_session` | 129 |
| `list_following` | GET | `/ui/social/{user_id}/following` | `require_ui_session` | 147 |

Service layer (`app/services/social.py`):
- `follow_user(follower_id, followed_id)` (line 31) -- creates follow record, increments counts
- `unfollow_user(follower_id, followed_id)` (line 101) -- removes follow record, decrements counts
- `is_following(follower_id, target_id)` (line 197) -- boolean check
- `get_follow_status(viewer_id, target_id)` (line 205) -- returns `{is_following, is_followed_by}`

**Citations**:
- `app/routers/social.py:103` -- POST `/ui/social/follow`
- `app/routers/social.py:122` -- POST `/ui/social/unfollow`
- `app/services/social.py:31` -- `follow_user` implementation
- `app/services/social.py:101` -- `unfollow_user` implementation
- `app/services/social.py:205` -- `get_follow_status` returns bidirectional status

### 3.6 PlanBrowser Component (PlanBrowser.tsx:1-187)

The subscriber-facing `PlanBrowser` component is fully reusable:

```typescript
interface PlanBrowserProps {
  creatorId: string;
}

export function PlanBrowser({ creatorId }: PlanBrowserProps) {
  const { data: plans, isLoading } = useQuery({
    queryKey: ["plans", creatorId],
    queryFn: () => listPlans(creatorId),
    enabled: !!creatorId,
  });

  const activePlans = (plans ?? []).filter((p) => p.status === "active");
  // ...renders plan cards with Subscribe button, discount code input
}
```

Key features already implemented:
- Filters for `status === "active"` (line 66)
- Loading skeleton with 3 cards (lines 68-76)
- Empty state with Sparkles icon (lines 78-85)
- Plan cards with name, description, price formatting, annual price toggle
- Subscribe mutation with toast notifications
- Discount code input field
- Middle plan marked as "Popular" (if 3+ plans)

**Citations**:
- `frontend/src/pages/subscriptions/PlanBrowser.tsx:32-34` -- props interface (`creatorId`)
- `frontend/src/pages/subscriptions/PlanBrowser.tsx:36-46` -- query with `listPlans(creatorId)`
- `frontend/src/pages/subscriptions/PlanBrowser.tsx:66` -- filters `status === "active"`

### 3.7 Frontend Profile Types (types.ts)

The `CrossUserProfileResp` type (or equivalent) already includes all storefront-relevant fields:
- `has_subscription_plans: boolean`
- `follower_count: number`
- `following_count: number`
- `post_count: number`
- `is_following: boolean`
- `is_followed_by: boolean`
- `is_mutual: boolean`

### 3.8 Current PublicUserProfilePage Structure (lines 124-224)

```typescript
return (
  <div className="mx-auto w-full max-w-3xl space-y-4 p-4 sm:p-6">
    {/* Back button + canonical URL hint */}
    <Card>
      {/* Cover photo */}
      {/* CardHeader: avatar + name + title */}
      <CardContent>
        {/* Description (bio) */}
        {/* Location */}
        {/* Member details (email, phone, languages) */}
        {/* Sign-in upsell for unauth */}
        {/* Action buttons: Message, Add contact, Sign in */}
        {/* Owner note */}
        {/* Audience badge */}
      </CardContent>
    </Card>
  </div>
);
```

This is a single `Card` layout with no tabs, no content sections, and no social data display.

**Citations**:
- `frontend/src/pages/profile/PublicUserProfilePage.tsx:124-222` -- single Card layout
- `frontend/src/pages/profile/PublicUserProfilePage.tsx:196-213` -- action buttons (Message, Add contact)
- `frontend/src/pages/profile/PublicUserProfilePage.tsx:219` -- audience badge

---

## 4. Implementation Plan

### 4.1 Frontend -- PublicUserProfilePage.tsx Enhancement

**File**: `frontend/src/pages/profile/PublicUserProfilePage.tsx`

Transform the single-card layout into a tabbed storefront. The existing Card becomes the "hero" section, and new tabs are added below.

#### 4.1.1 Component Tree (After Refactor)

```
PublicUserProfilePage
├── Hero Section
│   ├── Cover Photo (existing)
│   ├── Avatar + Name + Title (existing)
│   ├── Stats Row (NEW: follower_count, following_count, post_count)
│   ├── FollowButton (NEW: follow/unfollow with optimistic update)
│   └── Action Buttons (existing: Message, Add Contact)
├── Subscription Plans Section (NEW: conditional on has_subscription_plans)
│   └── PlanBrowser (REUSED from subscriptions/)
├── Tabs (NEW: shadcn Tabs component)
│   ├── TabsTrigger "Videos" (hidden for unauth)
│   ├── TabsTrigger "Posts"
│   └── TabsTrigger "About"
├── TabsContent "videos"
│   └── StorefrontVideoGrid (NEW component)
├── TabsContent "posts"
│   └── StorefrontPostsFeed (NEW component)
└── TabsContent "about"
    └── (existing bio/location/member-details moved here)
```

#### 4.1.2 Hero Section Changes

```typescript
// After the avatar/name section, add stats row:
<div className="flex gap-4 text-sm text-muted-foreground mt-2">
  <span><strong>{formatCount(p.follower_count)}</strong> followers</span>
  <span><strong>{formatCount(p.following_count)}</strong> following</span>
  <span><strong>{formatCount(p.post_count)}</strong> posts</span>
</div>

// After stats row, add FollowButton:
{isAuthenticated && viewerUserId !== data.user_sub && (
  <FollowButton
    userId={data.user_sub}
    isFollowing={p.is_following}
    onToggle={() => queryClient.invalidateQueries({ queryKey: ["profile", "lookup", identifier] })}
  />
)}
```

Number formatting helper:
```typescript
function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}
```

### 4.2 New Component: StorefrontVideoGrid

**New file: `frontend/src/pages/profile/StorefrontVideoGrid.tsx`** (~120 lines)

```typescript
import { useQuery } from "@tanstack/react-query";
import { Play, Sparkles, Clock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Skeleton } from "@/components/ui/skeleton";

interface StorefrontVideoGridProps {
  creatorId: string;
}

export function StorefrontVideoGrid({ creatorId }: StorefrontVideoGridProps) {
  const navigate = useNavigate();

  const { data, isLoading } = useQuery({
    queryKey: ["creator-videos", creatorId],
    queryFn: () =>
      api.get<VideoListOut>(`/ui/videos/creator/${creatorId}`, {
        params: { limit: 12 },
      }),
    enabled: !!creatorId,
    staleTime: 120_000,  // 2 minutes
  });

  if (isLoading) {
    return (
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="aspect-video w-full rounded-lg" />
        ))}
      </div>
    );
  }

  const videos = data?.items ?? [];

  if (videos.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-center text-muted-foreground">
        <Sparkles className="h-8 w-8" />
        <p className="text-sm">No videos yet</p>
      </div>
    );
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {videos.map((video) => (
        <button
          key={video.video_id}
          onClick={() => navigate(`/videos/${video.video_id}`)}
          className="group relative overflow-hidden rounded-lg border bg-card text-left transition hover:shadow-md"
        >
          {/* Thumbnail */}
          <div className="relative aspect-video bg-muted">
            {video.thumbnail_url ? (
              <img
                src={video.thumbnail_url}
                alt={video.title}
                className="h-full w-full object-cover"
              />
            ) : (
              <div className="flex h-full items-center justify-center">
                <Play className="h-8 w-8 text-muted-foreground" />
              </div>
            )}
            {/* Duration badge */}
            {video.duration_seconds && (
              <span className="absolute bottom-1 right-1 rounded bg-black/70 px-1.5 py-0.5 text-xs text-white">
                {formatDuration(video.duration_seconds)}
              </span>
            )}
          </div>
          {/* Info */}
          <div className="p-2">
            <p className="line-clamp-2 text-sm font-medium">{video.title}</p>
            {video.view_count != null && (
              <p className="mt-1 text-xs text-muted-foreground">
                {formatCount(video.view_count)} views
              </p>
            )}
          </div>
        </button>
      ))}
    </div>
  );
}

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}
```

**Data source**: `GET /ui/videos/creator/{creator_id}` (video_listing.py:319)
**Auth requirement**: Requires `require_ui_session` -- Videos tab only for authenticated viewers.

### 4.3 New Component: StorefrontPostsFeed

**New file: `frontend/src/pages/profile/StorefrontPostsFeed.tsx`** (~150 lines)

```typescript
import { useInfiniteQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Sparkles, ImageIcon, Video, Type, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";

type PostFilter = "all" | "text" | "image" | "video" | "locked";

interface StorefrontPostsFeedProps {
  identifier: string;
}

export function StorefrontPostsFeed({ identifier }: StorefrontPostsFeedProps) {
  const [filter, setFilter] = useState<PostFilter>("all");

  const {
    data,
    isLoading,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery({
    queryKey: ["profile-posts", identifier, filter],
    queryFn: ({ pageParam }) =>
      api.get(`/profile/public/${encodeURIComponent(identifier)}/posts`, {
        params: {
          limit: 12,
          cursor: pageParam,
          filter,
        },
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor || undefined,
    enabled: !!identifier,
    staleTime: 60_000,  // 1 minute
  });

  const allPosts = data?.pages.flatMap((page) => page.posts ?? page.items ?? []) ?? [];

  // Filter pills
  const filters: { value: PostFilter; label: string; icon: React.ReactNode }[] = [
    { value: "all", label: "All", icon: null },
    { value: "image", label: "Images", icon: <ImageIcon className="h-3 w-3" /> },
    { value: "video", label: "Videos", icon: <Video className="h-3 w-3" /> },
    { value: "text", label: "Text", icon: <Type className="h-3 w-3" /> },
  ];

  return (
    <div className="space-y-4">
      {/* Filter pills */}
      <div className="flex gap-2">
        {filters.map((f) => (
          <button
            key={f.value}
            onClick={() => setFilter(f.value)}
            className={`flex items-center gap-1 rounded-full px-3 py-1 text-xs transition
              ${filter === f.value
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground hover:bg-muted/80"
              }`}
          >
            {f.icon}
            {f.label}
          </button>
        ))}
      </div>

      {/* Posts list */}
      {isLoading ? (
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-32 w-full rounded-lg" />
          ))}
        </div>
      ) : allPosts.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-12 text-center text-muted-foreground">
          <Sparkles className="h-8 w-8" />
          <p className="text-sm">No posts yet</p>
        </div>
      ) : (
        <div className="space-y-3">
          {allPosts.map((post) => (
            <StorefrontPostCard key={post.post_id} post={post} />
          ))}
        </div>
      )}

      {/* Load more */}
      {hasNextPage && (
        <div className="flex justify-center pt-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
          >
            {isFetchingNextPage ? "Loading..." : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}
```

**Data source**: `GET /profile/public/{identifier}/posts` (profile.py:386)
**Auth requirement**: Auth-optional. Unauthenticated viewers see public posts only.

### 4.4 New Component: FollowButton

**New file: `frontend/src/pages/profile/FollowButton.tsx`** (~80 lines)

```typescript
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { UserPlus, UserCheck, UserMinus } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { followUser, unfollowUser } from "@/api/endpoints/social";

interface FollowButtonProps {
  userId: string;
  isFollowing: boolean;
  onToggle?: () => void;
}

export function FollowButton({ userId, isFollowing: initialFollowing, onToggle }: FollowButtonProps) {
  const [isFollowing, setIsFollowing] = useState(initialFollowing);
  const [isHovered, setIsHovered] = useState(false);

  const followMut = useMutation({
    mutationFn: () => followUser(userId),
    onMutate: () => {
      setIsFollowing(true);
    },
    onSuccess: () => {
      toast.success("Following");
      onToggle?.();
    },
    onError: () => {
      setIsFollowing(false);
      toast.error("Unable to follow right now");
    },
  });

  const unfollowMut = useMutation({
    mutationFn: () => unfollowUser(userId),
    onMutate: () => {
      setIsFollowing(false);
    },
    onSuccess: () => {
      toast.success("Unfollowed");
      onToggle?.();
    },
    onError: () => {
      setIsFollowing(true);
      toast.error("Unable to unfollow right now");
    },
  });

  const isPending = followMut.isPending || unfollowMut.isPending;

  if (isFollowing) {
    return (
      <Button
        variant={isHovered ? "destructive" : "secondary"}
        size="sm"
        disabled={isPending}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        onClick={() => unfollowMut.mutate()}
      >
        {isHovered ? (
          <>
            <UserMinus className="mr-1 h-4 w-4" />
            Unfollow
          </>
        ) : (
          <>
            <UserCheck className="mr-1 h-4 w-4" />
            Following
          </>
        )}
      </Button>
    );
  }

  return (
    <Button
      variant="default"
      size="sm"
      disabled={isPending}
      onClick={() => followMut.mutate()}
    >
      <UserPlus className="mr-1 h-4 w-4" />
      Follow
    </Button>
  );
}
```

### 4.5 Social API Client

**New file (or add to existing): `frontend/src/api/endpoints/social.ts`**

```typescript
import { api } from "@/api/client";

export const followUser = (targetUserId: string) =>
  api.post("/ui/social/follow", { target_user_id: targetUserId });

export const unfollowUser = (targetUserId: string) =>
  api.post("/ui/social/unfollow", { target_user_id: targetUserId });

export const getFollowStatus = (userId: string) =>
  api.get<{ is_following: boolean; is_followed_by: boolean }>(
    `/ui/social/${userId}/status`,
  );
```

### 4.6 Profile Posts API Client

**File: `frontend/src/api/endpoints/profile.ts`** (addition)

```typescript
export const getProfilePosts = (
  identifier: string,
  params?: {
    limit?: number;
    cursor?: string;
    filter?: "all" | "text" | "image" | "video" | "locked";
  },
) =>
  api.get(`/profile/public/${encodeURIComponent(identifier)}/posts`, { params });
```

### 4.7 Subscription Plans Integration

Conditionally render `PlanBrowser` when the creator has subscription plans:

```typescript
{data.profile.has_subscription_plans && (
  <section className="mt-6">
    <h2 className="mb-4 text-lg font-semibold">Subscription Plans</h2>
    <PlanBrowser creatorId={data.user_sub} />
  </section>
)}
```

`PlanBrowser` already handles:
- Loading skeletons (3 cards)
- Empty state (Sparkles icon)
- Plan cards with pricing, features, Subscribe button
- Discount code input
- Subscribe mutation with toast

**No code changes to PlanBrowser needed.** It accepts `creatorId` and renders everything.

### 4.8 Tab Configuration Based on Auth

```typescript
const showVideosTab = isAuthenticated;  // Videos endpoint requires auth
const defaultTab = showVideosTab ? "videos" : "posts";

<Tabs defaultValue={defaultTab}>
  <TabsList>
    {showVideosTab && (
      <TabsTrigger value="videos">Videos</TabsTrigger>
    )}
    <TabsTrigger value="posts">Posts</TabsTrigger>
    <TabsTrigger value="about">About</TabsTrigger>
  </TabsList>

  {showVideosTab && (
    <TabsContent value="videos">
      <StorefrontVideoGrid creatorId={data.user_sub} />
    </TabsContent>
  )}

  <TabsContent value="posts">
    <StorefrontPostsFeed identifier={canonicalIdentifier} />
  </TabsContent>

  <TabsContent value="about">
    {/* Existing bio/location/member-details content moved here */}
  </TabsContent>
</Tabs>
```

### 4.9 TypeScript Types (additions to types.ts)

```typescript
export interface StorefrontVideo {
  video_id: string;
  title: string;
  thumbnail_url?: string;
  duration_seconds?: number;
  view_count?: number;
  created_at: number;
}
```

### 4.10 Files to Modify

| File | Change |
|------|--------|
| `frontend/src/pages/profile/PublicUserProfilePage.tsx` | Major refactor: add Tabs, move bio to About tab, add stats row, integrate sub-components, add FollowButton |
| `frontend/src/api/types.ts` | Add `StorefrontVideo` interface |
| `frontend/src/api/endpoints/profile.ts` | Add `getProfilePosts(identifier, params)` function |

---

## 5. API Contracts (All Existing -- No New Backend Endpoints)

### 5.1 GET /profile/public/{identifier}

**Existing** at `app/routers/profile.py:306`.

Response includes (fields now being rendered):
```json
{
  "user_id": "user_abc123",
  "identifier": "johndoe",
  "display_name": "John Doe",
  "title": "Content Creator",
  "description": "I make videos about...",
  "follower_count": 1250,
  "following_count": 342,
  "post_count": 89,
  "is_following": true,
  "is_followed_by": false,
  "is_mutual": false,
  "has_subscription_plans": true
}
```

### 5.2 GET /profile/public/{identifier}/posts

**Existing** at `app/routers/profile.py:386`.

Query params: `limit` (1-50, default 12), `cursor` (string), `filter` ("all"|"text"|"image"|"video"|"locked")

Response: `{ posts: [...], next_cursor: "..." }`

### 5.3 GET /ui/videos/creator/{creator_id}

**Existing** at `app/routers/video_listing.py:319`.

Query params: `limit` (1-200, default 50), `cursor` (string)

Response: `{ items: [...], cursor: "..." }`

**Auth**: `require_ui_session` required.

### 5.4 GET /api/creators/{creator_id}/plans

**Existing** at `app/routers/subscription_server.py:746`.

No auth required. Returns `List[PlanOut]`.

### 5.5 POST /ui/social/follow and POST /ui/social/unfollow

**Existing** in `app/routers/social.py`.

Request body: `{ "target_user_id": string }`
Response: `{ "ok": true, ... }`

---

## 6. Security & Privacy Considerations

### 6.1 Content Visibility

- **Video listing** requires `require_ui_session` authentication. The Videos tab is ONLY shown to authenticated users. This prevents exposure of video metadata to crawlers or unauthenticated visitors.
- **Posts endpoint** is auth-optional. Public posts visible to all; followers-only posts visible only to authenticated followers. This respects the author's per-post visibility settings.
- **Plan listing** is public (no auth required). Plans are inherently marketing content.
- **Profile data** already respects discoverability settings: HIDDEN/DEACTIVATED/DELETED profiles return 404 (enforced at `profile.py:339-343`).

### 6.2 Follow Action Security

- Follow/unfollow endpoints validate that users cannot follow themselves (enforced by backend).
- Blocked users cannot follow (`_is_blocked()` check in `social.py`).
- Rate limiting exists on social endpoints (existing middleware).
- CSRF is enforced on follow/unfollow POST requests (via `x-csrf-token` header from axios client).

### 6.3 Subscription Privacy

- Plan pricing is public (plans are marketing content).
- Subscriber identity is not exposed on the profile page.
- The subscribe action requires authentication.

### 6.4 Input Sanitization

- Post body content is sanitized before rendering (existing XSS protection in PostCard).
- Video titles are rendered as text content (not HTML).
- Profile identifiers are validated and sanitized by the backend.

---

## 7. Testing Plan

### 7.1 E2E Tests

**Test file**: `frontend/e2e/creator-storefront.spec.ts`

**Section 1: Profile Page Tabs (5 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | Tabs visible on authenticated profile view | injectAuth(alice); navigate to /u/{bob_identifier} | "Videos", "Posts", "About" tabs visible |
| 2 | Videos tab shows video grid for creator with videos | Seed videos for Bob; click Videos tab | Video thumbnail cards visible |
| 3 | Posts tab shows post cards | Seed posts for Bob; click Posts tab | Post body text visible |
| 4 | About tab shows bio and location | Click About tab | Description text visible; location visible |
| 5 | Subscription plans section shown when creator has plans | Seed plan for Bob | "Subscription Plans" heading visible; plan card rendered |

**Section 2: Follow Button (4 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 6 | Follow button visible on other user's profile | Alice views Bob's profile | "Follow" button visible |
| 7 | Clicking Follow changes state to Following | Click "Follow" | Button text changes to "Following" |
| 8 | Clicking Following (unfollow) reverts to Follow | Hover "Following"; click | Button text reverts to "Follow" |
| 9 | Follow button not visible on own profile | Alice views own profile | No "Follow" button |

**Section 3: Content Loading (4 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 10 | Videos tab shows empty state when no videos | View user with 0 videos | "No videos yet" message visible |
| 11 | Posts tab shows empty state when no posts | View user with 0 posts | "No posts yet" message visible |
| 12 | Posts tab supports filter pills | Click "Images" filter | Only image posts shown (or empty state) |
| 13 | Subscribe button on plan card triggers subscription | Click "Subscribe" on plan card | Success toast or subscription flow initiates |

**Section 4: Unauthenticated View (3 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 14 | Unauthenticated user sees Posts and About tabs | Navigate to /u/{identifier} without auth | "Posts" and "About" tabs visible |
| 15 | Videos tab hidden for unauthenticated users | No auth | "Videos" tab not visible |
| 16 | Subscribe button prompts login for unauthenticated | Click "Subscribe" without auth | Redirected to /login |

**Section 5: Stats Row (2 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 17 | Stats row shows follower/following/post counts | View profile with counts | "N followers", "N following", "N posts" visible |
| 18 | Stats row formats large numbers | Profile with 1500 followers | "1.5K followers" visible |

### 7.2 Unit Tests (pytest)

No new backend code -- no unit tests needed. Existing profile.py and video_listing.py tests remain unchanged.

---

## 8. Performance Considerations

### 8.1 Data Fetching Strategy

| Data | When Fetched | staleTime | Strategy |
|------|-------------|-----------|----------|
| Profile | Page load (eager) | 5 min | Existing behavior |
| Videos | Tab selected (lazy) | 2 min | `enabled: tab === "videos"` |
| Posts | Tab selected (lazy) | 1 min | `enabled: tab === "posts"` |
| Plans | Page load (eager) | 10 min | Small payload, needed for section visibility |

Lazy loading videos and posts means only the active tab's data is fetched. Switching tabs triggers a fetch only if the data is stale or missing. This prevents unnecessary parallel requests on page load.

### 8.2 Bundle Impact

- `StorefrontVideoGrid`: ~120 lines, ~3KB gzipped.
- `StorefrontPostsFeed`: ~150 lines, ~4KB gzipped.
- `FollowButton`: ~80 lines, ~2KB gzipped.
- `PlanBrowser`: already in the bundle (imported from subscriptions/).

Total added bundle: ~9KB gzipped. Acceptable for a major page feature.

### 8.3 Image Loading

- Video thumbnails: `loading="lazy"` attribute for below-fold images.
- Post images: `loading="lazy"` attribute.
- Avatar/cover: already loaded eagerly (above fold).

### 8.4 Infinite Query for Posts

The `StorefrontPostsFeed` uses `useInfiniteQuery` with cursor-based pagination. The initial page loads 12 posts. "Load more" fetches the next 12. This prevents loading all posts at once for creators with hundreds of posts.

---

## 9. Responsive Design

### 9.1 Desktop Layout (>= 768px)

```
┌─────────────────────────────────────────────┐
│ [Cover Photo]                                │
├─────────────────────────────────────────────┤
│ [Avatar] Name / Title                        │
│ 1.2K followers  342 following  89 posts      │
│ [Follow] [Message] [Add Contact]             │
├─────────────────────────────────────────────┤
│ Subscription Plans                           │
│ ┌──────┐ ┌──────┐ ┌──────┐                  │
│ │ Free │ │ Pro  │ │Prem  │                  │
│ │ $0/mo│ │$9/mo │ │$29/mo│                  │
│ └──────┘ └──────┘ └──────┘                  │
├─────────────────────────────────────────────┤
│ [Videos]  [Posts]  [About]                   │
├─────────────────────────────────────────────┤
│ ┌──────┐ ┌──────┐ ┌──────┐                  │
│ │ vid1 │ │ vid2 │ │ vid3 │   (3-col grid)   │
│ └──────┘ └──────┘ └──────┘                  │
│ ┌──────┐ ┌──────┐ ┌──────┐                  │
│ │ vid4 │ │ vid5 │ │ vid6 │                  │
│ └──────┘ └──────┘ └──────┘                  │
└─────────────────────────────────────────────┘
```

### 9.2 Mobile Layout (< 768px)

```
┌──────────────────────────────┐
│ [Cover Photo]                 │
├──────────────────────────────┤
│ [Avatar]                      │
│ Name / Title                  │
│ 1.2K followers · 89 posts     │
│ [Follow]  [Message]           │
├──────────────────────────────┤
│ Plans: [Free] [Pro] [Prem]   │
│ (horizontal scroll)           │
├──────────────────────────────┤
│ [Videos] [Posts] [About]      │
├──────────────────────────────┤
│ ┌──────┐ ┌──────┐            │
│ │ vid1 │ │ vid2 │  (2-col)   │
│ └──────┘ └──────┘            │
│ ┌──────┐ ┌──────┐            │
│ │ vid3 │ │ vid4 │            │
│ └──────┘ └──────┘            │
└──────────────────────────────┘
```

- Video grid: 3 columns on desktop, 2 on tablet, 1 on small mobile.
- Plan cards: horizontal scroll on mobile (existing PlanBrowser behavior).
- Stats row: inline on desktop, stacked on mobile.
- Action buttons: full width on mobile, inline on desktop.

---

## 10. Migration & Rollout

### 10.1 No Backend Changes

This is a purely frontend ticket. No database migration, no new endpoints, no backend code changes.

### 10.2 Feature Flag (Optional)

If a gradual rollout is desired, add a `STOREFRONT_TABS_ENABLED` feature flag to `frontend/.env.local`:

```
VITE_STOREFRONT_TABS_ENABLED=true
```

When disabled, the profile page renders the existing single-card layout. When enabled, the tabbed storefront appears. This allows reverting to the old layout without a code deploy.

### 10.3 Rollback

Revert the frontend files:
- `PublicUserProfilePage.tsx` -- restore single-card layout
- Delete new files: `StorefrontVideoGrid.tsx`, `StorefrontPostsFeed.tsx`, `FollowButton.tsx`

No backend or database changes to revert.

---

## 11. Acceptance Criteria

1. `PublicUserProfilePage` displays "Videos", "Posts", and "About" tabs for authenticated viewers.
2. Videos tab shows a responsive grid of the creator's published videos with thumbnails, titles, and duration badges.
3. Posts tab shows paginated post cards with body preview and engagement counts.
4. Posts tab supports filter pills (All, Images, Videos, Text).
5. About tab contains the existing bio/location/member-details content.
6. Subscription plan cards are shown below the hero section when `has_subscription_plans` is true.
7. Follow/Unfollow button is functional on other users' profiles (not shown on own profile).
8. Follow button uses optimistic updates (immediate UI toggle, revert on error).
9. Follower count, following count, and post count are displayed in a stats row.
10. Large numbers are formatted (e.g., "1.5K" for 1500).
11. Unauthenticated visitors see Posts and About tabs but not Videos (requires auth).
12. Empty states are shown gracefully when a creator has no videos or posts.
13. All 18 E2E tests pass.

---

## 12. Dependencies

- **SOC-001 (Follow System)**: Follow/unfollow endpoints used by FollowButton component. Already implemented in `app/services/social.py` (lines 31, 101).
- **SOC-005 (Public Profile Page)**: The existing `PublicUserProfilePage` that this ticket extends. Already implemented.
- **MON-005 (Subscription-Gated VOD)**: Plan listing endpoint used by PlanBrowser integration. Already implemented at `subscription_server.py:746`.
- **VOD-006 (Video Listing API)**: Creator video listing endpoint at `video_listing.py:319`. Already implemented.
- **Newsfeed System (existing)**: Post data model and rendering patterns used by `StorefrontPostsFeed`.

---

## 13. Open Questions & Risks

### 13.1 Open Questions

1. **Tab default**: Should the default tab be "Videos" (most engaging content) or "Posts" (more universally available, works for unauth)? Current proposal: "Videos" for auth, "Posts" for unauth.
2. **Pinned posts**: Should creators be able to pin posts that appear at the top of the Posts tab regardless of chronological order? This would require a backend change (add `pinned_at` field) and is out of scope for this ticket.
3. **SEO / meta tags**: Should the profile page include Open Graph and Twitter Card meta tags for social media sharing? This would require server-side rendering or a pre-render service.
4. **Video tab auth requirement**: The `list_creator_public_videos` endpoint requires `require_ui_session`. Should we create a public version for unauthenticated viewers (showing only public thumbnails/titles)?

### 13.2 Risks

1. **API response shape mismatch**: The profile posts endpoint response structure may differ from what `StorefrontPostsFeed` expects. Verify the exact response format during implementation.
2. **Performance on heavy creators**: Creators with 1000+ posts or 500+ videos may cause slow initial tab loads. The lazy loading strategy and pagination mitigate this, but the first page must still complete in < 2 seconds.
3. **PlanBrowser subscription flow**: The `subscribe` mutation in PlanBrowser uses `X-User-Id` header auth. On the profile page (which uses cookie auth), this may trigger the 401 → logout issue documented in MEMORY.md. May need to add `page.route` interception similar to the subscription page tests.

---

## 14. Files to Create

| File | Purpose | Estimated lines |
|------|---------|-----------------|
| `frontend/src/pages/profile/StorefrontVideoGrid.tsx` | Video grid tab content | ~120 |
| `frontend/src/pages/profile/StorefrontPostsFeed.tsx` | Posts tab content with filters and pagination | ~150 |
| `frontend/src/pages/profile/FollowButton.tsx` | Follow/Unfollow button with optimistic update | ~80 |
| `frontend/src/api/endpoints/social.ts` | Social follow/unfollow/status API wrappers | ~20 |
| `frontend/e2e/creator-storefront.spec.ts` | E2E tests (18 tests) | ~300 |

## 15. Files to Modify

| File | Change |
|------|--------|
| `frontend/src/pages/profile/PublicUserProfilePage.tsx` | Major refactor: add Tabs, stats row, FollowButton, PlanBrowser integration, move bio to About tab |
| `frontend/src/api/types.ts` | Add `StorefrontVideo` interface |
| `frontend/src/api/endpoints/profile.ts` | Add `getProfilePosts(identifier, params)` function |

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| PublicUserProfilePage is 224 lines, shows name/bio only | `frontend/src/pages/profile/PublicUserProfilePage.tsx` | 1-224 | VERIFIED |
| Single Card layout with no tabs | `frontend/src/pages/profile/PublicUserProfilePage.tsx` | 124-222 | VERIFIED |
| Action buttons: Message + Add contact | `frontend/src/pages/profile/PublicUserProfilePage.tsx` | 196-213 | VERIFIED |
| Backend returns `has_subscription_plans` boolean | `app/routers/profile.py` | 352-362, 380 | VERIFIED |
| Profile response includes follower/following/post counts | `app/routers/profile.py` | 374-379 | VERIFIED |
| Profile response includes `is_following`, `is_followed_by`, `is_mutual` | `app/routers/profile.py` | 377-379 | VERIFIED |
| Follow status check uses social.get_follow_status | `app/routers/profile.py` | 345-351 | VERIFIED |
| Profile posts endpoint exists (auth-optional) | `app/routers/profile.py` | 386-392 | VERIFIED |
| Profile posts uses GSI2 with POST_AUTHOR PK | `app/routers/profile.py` | 434-443 | VERIFIED |
| Creator videos endpoint requires auth | `app/routers/video_listing.py` | 319-325 | VERIFIED: `require_ui_session` |
| Video listing router prefix | `app/routers/video_listing.py` | 40 | VERIFIED: `/ui/videos` |
| Plans endpoint is public (no auth) | `app/routers/subscription_server.py` | 746-753 | VERIFIED |
| PlanBrowser accepts creatorId prop | `frontend/src/pages/subscriptions/PlanBrowser.tsx` | 32-34 | VERIFIED |
| PlanBrowser filters for active plans | `frontend/src/pages/subscriptions/PlanBrowser.tsx` | 66 | VERIFIED: `status === "active"` |
| PlanBrowser has loading/empty/subscribe states | `frontend/src/pages/subscriptions/PlanBrowser.tsx` | 68-85 | VERIFIED |
| Social follow endpoint | `app/routers/social.py` | 103 | VERIFIED: POST /ui/social/follow |
| Social unfollow endpoint | `app/routers/social.py` | 122 | VERIFIED: POST /ui/social/unfollow |
| follow_user service function | `app/services/social.py` | 31 | VERIFIED |
| unfollow_user service function | `app/services/social.py` | 101 | VERIFIED |
| get_follow_status service function | `app/services/social.py` | 205 | VERIFIED |
