# PLATFORM-017: Creator Storefront

**Ticket**: PLATFORM-017
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 10-12 days

---

## 1. Overview & Motivation

### 1.1 Purpose

PLATFORM-017 builds a comprehensive, tabbed creator storefront page. The codebase already has a basic public profile endpoint (`GET /profile/public/{identifier}`) returning display name, avatar, follower counts, and follow status, plus `StorefrontVideoGrid` and `StorefrontPostsFeed` components on the `PublicUserProfilePage`. However, the current page is a flat layout with no tab navigation, no subscription plan display, no shop item listing, no featured content curation, no social links, and no customizable banner. This ticket transforms the public profile into a full creator storefront at `/creator/{username}` with tabbed content sections, subscription CTAs, shop items, and creator-curated featured content.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Visitor | As a visitor, I want to browse a creator's storefront by URL so that I can discover their content and subscribe. | `/creator/{username}` loads the storefront with creator's profile, tabs, and subscription CTA. |
| Visitor | As a visitor, I want to see the creator's subscription plans with pricing and features so that I can compare and subscribe. | "Plans" tab shows plan cards with price, billing period, features list, and "Subscribe" button. |
| Visitor | As a visitor, I want to browse a creator's shop items so that I can purchase products. | "Shop" tab shows catalog items with thumbnails, prices, and "Add to Cart" button. |
| Visitor | As a visitor, I want to see featured content curated by the creator so that I find their best work. | "Featured" section at the top of the About tab shows pinned posts/videos. |
| Creator | As a creator, I want to customize my storefront banner and bio so that my page reflects my brand. | Settings page allows uploading banner image, editing bio, adding social links. |
| Creator | As a creator, I want to feature specific content on my storefront so that visitors see my best work first. | Creator can pin up to 6 items as featured; featured items appear in a carousel/grid at the top. |
| Creator | As a creator, I want to add social media links to my storefront so that visitors can find me elsewhere. | Social links (Twitter, Instagram, YouTube, etc.) appear as icons below the bio. |
| Admin | As an admin, I want to moderate creator storefronts so that inappropriate content is removed. | Admin can flag or hide a storefront via admin endpoint. |

### 1.3 Why This Is Needed

The current public profile page is a minimal landing page that does not showcase the creator's full offering. Visitors cannot browse subscription plans, shop items, or video content in a structured way. Creators have no way to curate what visitors see first. A tabbed storefront with subscription CTAs, featured content, and shop integration converts visitors into subscribers and customers, which is the primary monetization path for the platform.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Public profile endpoint | `app/routers/profile.py:294` `GET /profile/public/{identifier}` | Returns display_name, title, description, follower_count, post_count, has_subscription_plans, follow status |
| Public profile posts | `app/routers/profile.py:388` `GET /profile/public/{identifier}/posts` | Paginated posts for a profile with filter (all/text/image/video/locked) |
| Profile service | `app/services/profile.py` | `get_profile()`, `get_profile_for_requester()`, `store_profile_photo()` |
| Storefront video grid | `frontend/src/pages/profile/StorefrontVideoGrid.tsx` | Grid of public videos for a creator (queries video_metadata) |
| Storefront posts feed | `frontend/src/pages/profile/StorefrontPostsFeed.tsx` | Feed of public posts for a creator |
| Public profile page | `frontend/src/pages/profile/PublicUserProfilePage.tsx` | Current flat layout: banner, avatar, bio, follow button, video grid, posts feed |
| Subscription plans API | `GET /api/creators/{id}/plans` (public, no auth) | Returns creator's subscription plans |
| Catalog API | `app/routers/catalog.py` | Product CRUD for shop items; `GET /ui/catalog/items` |
| Social service | `app/services/social.py` | Follow/unfollow, follower counts |
| Frontend route | `frontend/src/App.tsx` | `/profile/:identifier` route exists; no `/creator/:username` alias |

### 2.2 Gaps

1. **No tabbed layout** -- `PublicUserProfilePage` renders everything in a single scrollable column with no tabs for Videos, Posts, Plans, Shop.
2. **No subscription plan display** -- `has_subscription_plans` boolean is returned but no plans are fetched or shown to the visitor. No plan comparison UI, no subscribe button.
3. **No shop integration** -- catalog items are not queryable by creator on the storefront. No public catalog endpoint filtered by creator.
4. **No featured content** -- no concept of "featured" or "pinned" content that the creator can curate for the storefront landing.
5. **No social links** -- profile model has no `social_links` field. No UI for adding/displaying Twitter, Instagram, YouTube, etc.
6. **No `/creator/{username}` route** -- only `/profile/:identifier` exists, which is not a user-friendly vanity URL.
7. **No storefront customization** -- creator cannot set a custom banner, accent color, or layout preference.
8. **No public catalog endpoint** -- `GET /ui/catalog/items` requires auth; no public-facing endpoint to browse a creator's shop.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

#### 3.1.1 Featured Content (stored in profile table)

No new table needed. Extend the existing profile item in `T.profile` with:

```json
{
  "user_sub": "alice@test.local",
  "featured_content": [
    {"content_id": "post_abc123", "content_type": "post", "pinned_at": 1748520000},
    {"content_id": "vid_xyz789", "content_type": "video", "pinned_at": 1748520100}
  ],
  "social_links": {
    "twitter": "https://twitter.com/alice",
    "instagram": "https://instagram.com/alice",
    "youtube": "https://youtube.com/@alice",
    "tiktok": "",
    "website": "https://alice.example.com"
  },
  "storefront_settings": {
    "accent_color": "#7C3AED",
    "default_tab": "about",
    "show_follower_count": true,
    "show_post_count": true,
    "banner_url": "https://cdn.example.com/banners/alice.jpg"
  }
}
```

#### 3.1.2 Public Catalog View (GSI on catalog table)

Add a GSI to the existing `catalog` table for querying by creator:

**GSI: ByCreator**
- `GSI1PK`: `CREATOR#{creator_id}`
- `GSI1SK`: `created_at` (N)
- Projected: ALL

This enables `GET /catalog/public/{creator_id}/items` to query items by creator without auth.

#### 3.1.3 TableDef Change

```python
# Modify existing catalog TableDef to add GSI:
# gsis=[..., {"name": "ByCreator", "pk": "GSI1PK", "sk": "GSI1SK"}]
# attr_types={..., "GSI1SK": "N"}
```

### 3.2 Backend Service

**Modify `app/services/profile.py`** (~60 lines added):

```python
SOCIAL_LINK_KEYS = {"twitter", "instagram", "youtube", "tiktok", "website", "discord", "twitch"}
MAX_FEATURED_ITEMS = 6

def get_featured_content(user_sub: str) -> List[Dict[str, Any]]:
    """Get creator's featured/pinned content items."""
    profile = get_profile(user_sub)
    return profile.get("featured_content", [])

def set_featured_content(user_sub: str, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Set creator's featured content (max 6 items)."""
    if len(items) > MAX_FEATURED_ITEMS:
        raise ValueError("too_many_items")
    ts = now_ts()
    featured = [
        {"content_id": it["content_id"], "content_type": it["content_type"], "pinned_at": ts}
        for it in items
    ]
    T.profile.update_item(
        Key={"user_sub": user_sub},
        UpdateExpression="SET featured_content = :fc, updated_at = :t",
        ExpressionAttributeValues={":fc": featured, ":t": ts},
    )
    return featured

def update_social_links(user_sub: str, links: Dict[str, str]) -> Dict[str, str]:
    """Update creator's social media links."""
    clean = {k: v.strip()[:500] for k, v in links.items() if k in SOCIAL_LINK_KEYS}
    T.profile.update_item(
        Key={"user_sub": user_sub},
        UpdateExpression="SET social_links = :sl, updated_at = :t",
        ExpressionAttributeValues={":sl": clean, ":t": now_ts()},
    )
    return clean

def update_storefront_settings(user_sub: str, settings: Dict[str, Any]) -> Dict[str, Any]:
    """Update storefront display settings."""
    allowed = {"accent_color", "default_tab", "show_follower_count", "show_post_count"}
    clean = {k: v for k, v in settings.items() if k in allowed}
    T.profile.update_item(
        Key={"user_sub": user_sub},
        UpdateExpression="SET storefront_settings = :ss, updated_at = :t",
        ExpressionAttributeValues={":ss": clean, ":t": now_ts()},
    )
    return clean
```

**New file: `app/services/public_catalog.py`** (~60 lines):

```python
def list_creator_catalog_items(creator_id: str, limit: int = 20, cursor: str = None) -> Dict[str, Any]:
    """List published catalog items for a creator (public, no auth)."""
    kwargs = {
        "IndexName": "ByCreator",
        "KeyConditionExpression": Key("GSI1PK").eq(f"CREATOR#{creator_id}"),
        "ScanIndexForward": False,
        "Limit": limit,
        "FilterExpression": Attr("status").eq("published"),
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
    resp = T.catalog.query(**kwargs)
    items = [_item_to_public(it) for it in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey")) if resp.get("LastEvaluatedKey") else None
    return {"items": items, "next_cursor": next_cursor}
```

### 3.3 Backend Router

**Modify `app/routers/profile.py`** (~100 lines added):

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/profile/public/{identifier}/storefront` | Optional | Full storefront data (profile + plans + stats + social links + featured) |
| `GET` | `/profile/public/{identifier}/plans` | None | Subscription plans for the creator |
| `GET` | `/profile/public/{identifier}/shop` | None | Public catalog items for the creator |
| `GET` | `/profile/public/{identifier}/featured` | None | Featured content items |
| `PUT` | `/ui/profile/featured` | `require_ui_session` | Set featured content (creator only) |
| `PUT` | `/ui/profile/social-links` | `require_ui_session` | Update social links |
| `PUT` | `/ui/profile/storefront-settings` | `require_ui_session` | Update storefront settings |

### 3.4 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Creator Storefront (PLATFORM-017) --

class SocialLinks(BaseModel):
    twitter: str = ""
    instagram: str = ""
    youtube: str = ""
    tiktok: str = ""
    website: str = ""
    discord: str = ""
    twitch: str = ""

class StorefrontSettings(BaseModel):
    accent_color: str = Field(default="#7C3AED", max_length=7)
    default_tab: str = Field(default="about", pattern="^(about|videos|posts|plans|shop)$")
    show_follower_count: bool = True
    show_post_count: bool = True

class FeaturedContentItem(BaseModel):
    content_id: str = Field(min_length=1, max_length=100)
    content_type: str = Field(..., pattern="^(post|video)$")

class FeaturedContentIn(BaseModel):
    items: List[FeaturedContentItem] = Field(max_length=6)

class FeaturedContentOut(BaseModel):
    content_id: str
    content_type: str
    pinned_at: int = 0
    title: Optional[str] = None
    thumbnail_url: Optional[str] = None
    preview_text: Optional[str] = None

class StorefrontPlanOut(BaseModel):
    plan_id: str
    name: str
    description: str = ""
    price_cents: int = 0
    currency: str = "USD"
    billing_period: str = "monthly"
    features: List[str] = Field(default_factory=list)
    is_popular: bool = False

class StorefrontOut(BaseModel):
    user_id: str
    identifier: str
    display_name: str
    title: Optional[str] = None
    description: Optional[str] = None
    location: Optional[str] = None
    profile_photo_url: Optional[str] = None
    cover_photo_url: Optional[str] = None
    banner_url: Optional[str] = None
    follower_count: int = 0
    following_count: int = 0
    post_count: int = 0
    video_count: int = 0
    is_following: bool = False
    is_followed_by: bool = False
    social_links: SocialLinks = Field(default_factory=SocialLinks)
    storefront_settings: StorefrontSettings = Field(default_factory=StorefrontSettings)
    featured_content: List[FeaturedContentOut] = Field(default_factory=list)
    subscription_plans: List[StorefrontPlanOut] = Field(default_factory=list)
    has_shop_items: bool = False
    created_at: Optional[int] = None

class PublicCatalogItemOut(BaseModel):
    item_id: str
    name: str
    description: str = ""
    price_cents: int = 0
    currency: str = "USD"
    thumbnail_url: Optional[str] = None
    category: str = ""

class PublicCatalogOut(BaseModel):
    items: List[PublicCatalogItemOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
```

### 3.5 Frontend Components

**New and modified files**:

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/profile/CreatorStorefrontPage.tsx` | Main storefront page with tabs | ~350 |
| `frontend/src/pages/profile/StorefrontAboutTab.tsx` | About tab: bio, social links, featured content | ~120 |
| `frontend/src/pages/profile/StorefrontPlansTab.tsx` | Plans tab: plan cards with subscribe CTA | ~150 |
| `frontend/src/pages/profile/StorefrontShopTab.tsx` | Shop tab: catalog items grid | ~120 |
| `frontend/src/pages/profile/FeaturedContentCarousel.tsx` | Featured content carousel/grid | ~80 |
| `frontend/src/pages/profile/SocialLinksBar.tsx` | Social media icon links | ~40 |
| `frontend/src/pages/settings/StorefrontSettingsCard.tsx` | Creator storefront settings (featured, links, accent) | ~150 |
| `frontend/src/api/endpoints/storefront.ts` | API client wrappers for storefront endpoints | ~60 |

**Component tree**:

```
CreatorStorefrontPage
├── Cover Banner (cover_photo_url or banner_url)
├── Profile Header
│   ├── Avatar
│   ├── Display Name + Title
│   ├── Description / Bio
│   ├── SocialLinksBar (Twitter, Instagram, YouTube icons)
│   ├── Stats (followers, posts, videos)
│   └── Follow Button / Subscribe CTA
├── Tabs
│   ├── "About" Tab
│   │   ├── FeaturedContentCarousel (pinned posts/videos)
│   │   ├── Full bio text
│   │   └── Recent activity summary
│   ├── "Videos" Tab
│   │   └── StorefrontVideoGrid (existing component)
│   ├── "Posts" Tab
│   │   └── StorefrontPostsFeed (existing component)
│   ├── "Plans" Tab (if has_subscription_plans)
│   │   └── StorefrontPlansTab
│   │       └── Plan cards with price, features, Subscribe button
│   └── "Shop" Tab (if has_shop_items)
│       └── StorefrontShopTab
│           └── Catalog item cards with Add to Cart
```

### 3.6 Frontend Routes

**Add to `frontend/src/App.tsx`**:

```typescript
<Route path="/creator/:identifier" element={<CreatorStorefrontPage />} />
```

Keep existing `/profile/:identifier` route as an alias (redirect to `/creator/:identifier`).

### 3.7 Sidebar Navigation

No sidebar entry needed -- storefront is accessed via direct URL or links from other pages (user mentions, follower lists, etc.).

### 3.8 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/services/public_catalog.py` | Public catalog query service | ~60 |
| `frontend/src/pages/profile/CreatorStorefrontPage.tsx` | Storefront page | ~350 |
| `frontend/src/pages/profile/StorefrontAboutTab.tsx` | About tab | ~120 |
| `frontend/src/pages/profile/StorefrontPlansTab.tsx` | Plans tab | ~150 |
| `frontend/src/pages/profile/StorefrontShopTab.tsx` | Shop tab | ~120 |
| `frontend/src/pages/profile/FeaturedContentCarousel.tsx` | Featured carousel | ~80 |
| `frontend/src/pages/profile/SocialLinksBar.tsx` | Social links | ~40 |
| `frontend/src/pages/settings/StorefrontSettingsCard.tsx` | Settings card | ~150 |
| `frontend/src/api/endpoints/storefront.ts` | API wrappers | ~60 |
| `frontend/e2e/creator-storefront.spec.ts` | E2E tests | ~500 |

### 3.9 Files to Modify

| File | Change |
|------|--------|
| `app/services/profile.py` | Add `get_featured_content`, `set_featured_content`, `update_social_links`, `update_storefront_settings` |
| `app/routers/profile.py` | Add storefront, plans, shop, featured public endpoints; add creator settings endpoints |
| `app/models.py` | Add storefront Pydantic models |
| `app/main.py` | Register new public catalog endpoints if separate router |
| `scripts/local-ddb-init.py` | Add ByCreator GSI to catalog table |
| `frontend/src/App.tsx` | Add `/creator/:identifier` route |
| `frontend/src/api/types.ts` | Add storefront TypeScript interfaces |
| `frontend/src/pages/profile/PublicUserProfilePage.tsx` | Redirect to `/creator/:identifier` or replace with new page |

---

## 4. Storefront Data Flow

### 4.1 Aggregated Storefront Endpoint

`GET /profile/public/{identifier}/storefront` returns all data needed to render the full page in a single request, reducing round trips:

1. Fetch profile from `T.profile` (display name, bio, avatar, banner, social links, featured content, storefront settings).
2. Resolve follow status (if authenticated viewer).
3. Fetch subscription plans from `T.subscriptions` (CREATOR#{user_sub}).
4. Check catalog item count from `T.catalog` (ByCreator GSI, COUNT only).
5. Resolve featured content metadata (post titles, video thumbnails).
6. Return `StorefrontOut` with all fields populated.

### 4.2 Lazy-Loaded Tabs

Individual tab content (videos, posts, shop items) is loaded on tab activation via separate endpoints to avoid fetching all content upfront:

- Videos tab: `GET /profile/public/{identifier}/videos` (existing via StorefrontVideoGrid)
- Posts tab: `GET /profile/public/{identifier}/posts` (existing)
- Plans tab: data already in `StorefrontOut.subscription_plans`
- Shop tab: `GET /profile/public/{identifier}/shop` (new, paginated)

### 4.3 Featured Content Resolution

Featured items are stored as `[{content_id, content_type, pinned_at}]` on the profile. The storefront endpoint resolves each to its metadata:

- **Posts**: query `app_single_table` for `POST#{content_id}` to get body preview, image URL.
- **Videos**: query `video_metadata` for `video_id` to get title, thumbnail_url, view_count.

Unresolvable items (deleted content) are silently filtered out.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/creator-storefront.spec.ts`

### Section 527: Storefront Public API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 527.1 | Get storefront data for a known user | GET `/profile/public/{identifier}/storefront`; 200; response has `display_name`, `social_links`, `storefront_settings` |
| 527.2 | Storefront returns subscription plans | Create a plan for Alice; GET storefront; `subscription_plans` array has at least 1 item with `plan_id`, `price_cents` |
| 527.3 | Storefront for non-existent user returns 404 | GET `/profile/public/nonexistent_user/storefront`; 404 |
| 527.4 | Featured content endpoint returns pinned items | PUT featured with 2 items; GET `/profile/public/{id}/featured`; response has 2 items with `content_id`, `content_type` |

### Section 528: Storefront Creator Settings API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 528.1 | Update social links | PUT `/ui/profile/social-links` with `twitter`, `instagram`; 200; GET storefront shows social_links populated |
| 528.2 | Update storefront settings | PUT `/ui/profile/storefront-settings` with `accent_color=#FF0000, default_tab=videos`; 200; GET confirms changes |
| 528.3 | Set featured content (max 6) | PUT `/ui/profile/featured` with 6 items; 200; GET returns 6 items |
| 528.4 | Exceed featured limit returns 400 | PUT `/ui/profile/featured` with 7 items; 400 response |

### Section 529: Public Catalog API (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 529.1 | List creator's public shop items | Create catalog item for Alice; GET `/profile/public/{id}/shop`; response has item with `name`, `price_cents` |
| 529.2 | Empty shop returns empty array | GET shop for user with no items; response `{ items: [], next_cursor: null }` |
| 529.3 | Shop pagination works | Create 3 items; GET with `limit=2`; response has 2 items and `next_cursor`; GET with cursor returns remaining 1 item |

### Section 530: Storefront UI (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 530.1 | Creator storefront page renders with tabs | Navigate to `/creator/{identifier}`; page shows display name, avatar, and tab bar with "About", "Videos", "Posts" |
| 530.2 | About tab shows social links | Set social links via API; navigate to storefront; social link icons are visible |
| 530.3 | Plans tab shows subscription plan cards | Create plan; navigate to storefront; click "Plans" tab; plan card visible with price |
| 530.4 | Featured content carousel renders | Pin 2 items; navigate to storefront; featured section shows 2 content cards |
| 530.5 | Follow button toggles follow state | Navigate as Bob to Alice's storefront; click Follow; button text changes to "Following" |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| `GET /profile/public/*/storefront` | Optional | Public; authenticated viewers see follow status |
| `GET /profile/public/*/plans` | None | Fully public |
| `GET /profile/public/*/shop` | None | Fully public; only `status=published` items shown |
| `GET /profile/public/*/featured` | None | Fully public |
| `PUT /ui/profile/featured` | `require_ui_session` | Creator only (own profile) |
| `PUT /ui/profile/social-links` | `require_ui_session` | Creator only (own profile) |
| `PUT /ui/profile/storefront-settings` | `require_ui_session` | Creator only (own profile) |

### 6.2 Content Filtering

- Public catalog endpoint only returns items with `status=published`. Draft, archived, and soft-deleted items are never exposed.
- Locked posts show title and lock indicator but no body content to unauthenticated visitors.
- Featured content references are validated -- deleted content IDs are silently filtered from the response.

### 6.3 Input Validation

- `social_links`: each URL max 500 characters; only allowed key names accepted.
- `accent_color`: validated as 7-character hex color string.
- `default_tab`: restricted to `about|videos|posts|plans|shop`.
- `featured_content.items`: max 6 items; `content_type` restricted to `post|video`.

### 6.4 Rate Limiting

- Public storefront GET: 60 requests per IP per minute (same as profile).
- Settings update endpoints: 20 per user per hour.
- All endpoints inherit global rate limiter.

### 6.5 Discoverability

- Deactivated or deleted profiles return 404 on all storefront endpoints (existing discoverability check in `get_public_profile` is reused).
- Hidden profiles are accessible by direct URL but excluded from search results (existing behavior).

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/routers/profile.py` | Exists (modify) | Public profile endpoints; extend with storefront |
| `app/services/profile.py` | Exists (modify) | Featured content, social links, storefront settings |
| `T.profile` table | Exists | Store featured content and social links |
| `T.catalog` table | Exists (modify GSI) | Public catalog query by creator |
| `T.subscriptions` table | Exists | Query creator plans |
| `StorefrontVideoGrid` component | Exists | Reuse in Videos tab |
| `StorefrontPostsFeed` component | Exists | Reuse in Posts tab |
| `PublicUserProfilePage` component | Exists (replace/redirect) | Current profile page replaced by storefront |
| `app/services/social.py` | Exists | Follow/unfollow from storefront |

---

## 8. Acceptance Criteria

1. `/creator/{identifier}` renders a tabbed storefront with About, Videos, Posts, Plans, and Shop tabs.
2. Subscription plans are displayed with pricing, features, and a Subscribe button.
3. Public catalog items are queryable by creator without authentication.
4. Creators can pin up to 6 featured content items that appear in a carousel.
5. Social links are editable and display as clickable icons.
6. Storefront settings (accent color, default tab) persist and render correctly.
7. Deactivated/deleted profiles return 404 on all storefront endpoints.
8. Existing `/profile/:identifier` route redirects to `/creator/:identifier`.
9. All 16 E2E tests pass.
10. Storefront loads all essential data in a single aggregated API call.
