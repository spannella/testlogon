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

## 2. Architecture Diagram

```
+-----------------------------------------------------------+
|                     Browser (Visitor)                       |
|                                                           |
|  /creator/:identifier                                     |
|  +-----------------------------------------------------+  |
|  | CreatorStorefrontPage                                |  |
|  | +--------+  +------+  +------+  +------+  +------+  |  |
|  | | About  |  |Videos|  |Posts |  |Plans |  | Shop |  |  |
|  | +----+---+  +--+---+  +--+---+  +--+---+  +--+---+  |  |
|  |      |         |         |         |         |       |  |
|  +------|---------|---------|---------|---------|-------+  |
+---------|---------|---------|---------|---------|---------+
          |         |         |         |         |
     1. GET         2. GET    3. GET    4. (from   5. GET
     /storefront    /videos   /posts   storefront) /shop
          |         |         |         |         |
          v         v         v         v         v
+-----------------------------------------------------------+
|                    Backend (FastAPI)                        |
|                                                           |
|  app/routers/profile.py                                   |
|  +-----------------------------------------------------+  |
|  | GET /profile/public/{id}/storefront                  |  |
|  |   -> profile.py:get_profile()                       |  |
|  |   -> social.py:get_follow_status()                  |  |
|  |   -> subscription_server.py:list_plans()            |  |
|  |   -> public_catalog.py:count_items()                |  |
|  |   -> resolve_featured_content()                     |  |
|  +-----------------------------------------------------+  |
|  | GET /profile/public/{id}/shop                        |  |
|  |   -> public_catalog.py:list_creator_catalog_items()  |  |
|  +-----------------------------------------------------+  |
|                                                           |
|  DynamoDB Tables:                                         |
|  +----------+  +-----------+  +----------+  +---------+  |
|  | T.profile|  | T.catalog |  | T.subscr.|  | T.posts |  |
|  | (featured|  | (ByCreator|  | (plans)  |  | (author)|  |
|  |  content,|  |  GSI)     |  |          |  |         |  |
|  |  social) |  |           |  |          |  |         |  |
|  +----------+  +-----------+  +----------+  +---------+  |
+-----------------------------------------------------------+
```

---

## 3. Current State Analysis

### 3.1 Existing Infrastructure

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

### 3.2 Gaps

1. **No tabbed layout** -- `PublicUserProfilePage` renders everything in a single scrollable column with no tabs for Videos, Posts, Plans, Shop.
2. **No subscription plan display** -- `has_subscription_plans` boolean is returned but no plans are fetched or shown to the visitor. No plan comparison UI, no subscribe button.
3. **No shop integration** -- catalog items are not queryable by creator on the storefront. No public catalog endpoint filtered by creator.
4. **No featured content** -- no concept of "featured" or "pinned" content that the creator can curate for the storefront landing.
5. **No social links** -- profile model has no `social_links` field. No UI for adding/displaying Twitter, Instagram, YouTube, etc.
6. **No `/creator/{username}` route** -- only `/profile/:identifier` exists, which is not a user-friendly vanity URL.
7. **No storefront customization** -- creator cannot set a custom banner, accent color, or layout preference.
8. **No public catalog endpoint** -- `GET /ui/catalog/items` requires auth; no public-facing endpoint to browse a creator's shop.

---

## 4. Technical Design

### 4.1 DynamoDB Schema

#### 4.1.1 Featured Content (stored in profile table)

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

#### 4.1.2 Public Catalog View (GSI on catalog table)

Add a GSI to the existing `catalog` table for querying by creator:

**GSI: ByCreator**
- `GSI1PK`: `CREATOR#{creator_id}`
- `GSI1SK`: `created_at` (N)
- Projected: ALL

This enables `GET /catalog/public/{creator_id}/items` to query items by creator without auth.

#### 4.1.3 TableDef Change

```python
# Modify existing catalog TableDef to add GSI:
# gsis=[..., {"name": "ByCreator", "pk": "GSI1PK", "sk": "GSI1SK"}]
# attr_types={..., "GSI1SK": "N"}
```

---

## 5. DynamoDB Access Patterns

### 5.1 Profile Table (extended)

| Access Pattern | PK | SK | Operation | Notes |
|---------------|----|----|-----------|-------|
| Get full profile with storefront data | `user_sub` | -- | get_item | Returns featured_content, social_links, storefront_settings |
| Update featured content | `user_sub` | -- | update_item SET | SET featured_content = :fc |
| Update social links | `user_sub` | -- | update_item SET | SET social_links = :sl |
| Update storefront settings | `user_sub` | -- | update_item SET | SET storefront_settings = :ss |

**Example profile item with storefront extensions:**

```json
{
  "user_sub": "e2e_alice@test.local",
  "display_name": "Alice Creator",
  "title": "Digital Artist & Content Creator",
  "description": "Creating digital art and tutorials since 2020.",
  "avatar_url": "/mock/s3/avatars/alice.jpg",
  "cover_photo_url": "/mock/s3/covers/alice_banner.jpg",
  "follower_count": 1523,
  "following_count": 42,
  "post_count": 89,
  "video_count": 23,
  "created_at": 1716566400,
  "updated_at": 1748520000,
  "featured_content": [
    {
      "content_id": "post_abc123def456",
      "content_type": "post",
      "pinned_at": 1748520000
    },
    {
      "content_id": "v_xyz789ghi012",
      "content_type": "video",
      "pinned_at": 1748520100
    }
  ],
  "social_links": {
    "twitter": "https://twitter.com/alicecreator",
    "instagram": "https://instagram.com/alicecreator",
    "youtube": "https://youtube.com/@alicecreator",
    "tiktok": "",
    "website": "https://alicecreator.art",
    "discord": "https://discord.gg/alice",
    "twitch": ""
  },
  "storefront_settings": {
    "accent_color": "#7C3AED",
    "default_tab": "about",
    "show_follower_count": true,
    "show_post_count": true
  }
}
```

### 5.2 Catalog Table (ByCreator GSI)

| Access Pattern | GSI1PK | GSI1SK | Operation | Notes |
|---------------|--------|--------|-----------|-------|
| List creator's published items | `CREATOR#{creator_id}` | (scan forward, newest first) | Query with FilterExpression | Filter `status=published` |
| Count creator's items | `CREATOR#{creator_id}` | -- | Query SELECT COUNT | For `has_shop_items` flag |
| Paginated listing | `CREATOR#{creator_id}` | with ExclusiveStartKey | Query | cursor-based pagination |

**Example catalog item with GSI keys:**

```json
{
  "pk": "CATALOG#item_abc123",
  "sk": "META",
  "item_id": "item_abc123",
  "creator_id": "e2e_alice@test.local",
  "name": "Digital Art Print - Mountain Sunset",
  "description": "High-resolution digital print, 4096x2160.",
  "price_cents": 1500,
  "currency": "USD",
  "status": "published",
  "thumbnail_url": "/mock/s3/catalog/mountain_sunset_thumb.jpg",
  "category": "digital_art",
  "created_at": 1748520000,
  "GSI1PK": "CREATOR#e2e_alice@test.local",
  "GSI1SK": 1748520000
}
```

---

## 6. API Request/Response Examples

### 6.1 GET /profile/public/{identifier}/storefront

```bash
curl -s "http://localhost:8000/profile/public/e2e_alice@test.local/storefront" \
  -H "Cookie: ui_session=sess_bob; ui_csrf=csrf_bob; ui_access_token=jwt_bob"
```

**Response (200):**
```json
{
  "user_id": "e2e_alice@test.local",
  "identifier": "e2e_alice@test.local",
  "display_name": "Alice Creator",
  "title": "Digital Artist",
  "description": "Creating digital art and tutorials since 2020.",
  "profile_photo_url": "/mock/s3/avatars/alice.jpg",
  "cover_photo_url": "/mock/s3/covers/alice_banner.jpg",
  "banner_url": null,
  "follower_count": 1523,
  "following_count": 42,
  "post_count": 89,
  "video_count": 23,
  "is_following": true,
  "is_followed_by": false,
  "social_links": {
    "twitter": "https://twitter.com/alicecreator",
    "instagram": "https://instagram.com/alicecreator",
    "youtube": "",
    "tiktok": "",
    "website": "https://alicecreator.art",
    "discord": "",
    "twitch": ""
  },
  "storefront_settings": {
    "accent_color": "#7C3AED",
    "default_tab": "about",
    "show_follower_count": true,
    "show_post_count": true
  },
  "featured_content": [
    {
      "content_id": "post_abc123",
      "content_type": "post",
      "pinned_at": 1748520000,
      "title": "My Best Tutorial",
      "thumbnail_url": "/mock/s3/posts/abc123_thumb.jpg",
      "preview_text": "Learn how to create stunning digital art..."
    }
  ],
  "subscription_plans": [
    {
      "plan_id": "plan_xyz789",
      "name": "Premium Access",
      "description": "Get access to all premium content",
      "price_cents": 999,
      "currency": "USD",
      "billing_period": "monthly",
      "features": ["All premium videos", "Early access", "Discord role"],
      "is_popular": true
    }
  ],
  "has_shop_items": true,
  "created_at": 1716566400
}
```

### 6.2 PUT /ui/profile/social-links

```bash
curl -s -X PUT http://localhost:8000/ui/profile/social-links \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -d '{
    "twitter": "https://twitter.com/alicecreator",
    "instagram": "https://instagram.com/alicecreator",
    "website": "https://alicecreator.art"
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "social_links": {
    "twitter": "https://twitter.com/alicecreator",
    "instagram": "https://instagram.com/alicecreator",
    "youtube": "",
    "tiktok": "",
    "website": "https://alicecreator.art",
    "discord": "",
    "twitch": ""
  }
}
```

### 6.3 PUT /ui/profile/featured

```bash
curl -s -X PUT http://localhost:8000/ui/profile/featured \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -d '{
    "items": [
      {"content_id": "post_abc123", "content_type": "post"},
      {"content_id": "v_xyz789", "content_type": "video"}
    ]
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "featured_content": [
    {"content_id": "post_abc123", "content_type": "post", "pinned_at": 1748523600},
    {"content_id": "v_xyz789", "content_type": "video", "pinned_at": 1748523600}
  ]
}
```

**Error (400 -- too many items):**
```json
{
  "detail": "Maximum 6 featured items allowed"
}
```

### 6.4 GET /profile/public/{identifier}/shop

```bash
curl -s "http://localhost:8000/profile/public/e2e_alice@test.local/shop?limit=2"
```

**Response (200):**
```json
{
  "items": [
    {
      "item_id": "item_abc123",
      "name": "Digital Art Print",
      "description": "High-res digital print",
      "price_cents": 1500,
      "currency": "USD",
      "thumbnail_url": "/mock/s3/catalog/thumb.jpg",
      "category": "digital_art"
    },
    {
      "item_id": "item_def456",
      "name": "Tutorial Bundle",
      "description": "5 video tutorials",
      "price_cents": 2999,
      "currency": "USD",
      "thumbnail_url": "/mock/s3/catalog/bundle_thumb.jpg",
      "category": "courses"
    }
  ],
  "next_cursor": "eyJHU0kxUEsiOi..."
}
```

### 6.5 PUT /ui/profile/storefront-settings

```bash
curl -s -X PUT http://localhost:8000/ui/profile/storefront-settings \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -d '{
    "accent_color": "#FF5733",
    "default_tab": "videos",
    "show_follower_count": true,
    "show_post_count": false
  }'
```

**Response (200):**
```json
{
  "ok": true,
  "storefront_settings": {
    "accent_color": "#FF5733",
    "default_tab": "videos",
    "show_follower_count": true,
    "show_post_count": false
  }
}
```

---

## 7. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---------------|-------------|------------|---------------------|-----------------|
| Storefront for non-existent user | 404 | `user_not_found` | "This creator profile could not be found." | Check URL or search |
| Storefront for deactivated account | 404 | `account_deactivated` | "This profile is no longer available." | None |
| Featured items exceed limit (>6) | 400 | `too_many_items` | "Maximum 6 featured items allowed." | Remove items before adding |
| Featured content_type invalid | 422 | `validation_error` | "Content type must be 'post' or 'video'." | Fix request |
| Social link URL too long (>500) | 422 | `validation_error` | "Social link URL must be under 500 characters." | Shorten URL |
| Invalid accent_color format | 422 | `validation_error` | "Accent color must be a valid hex color (e.g., #7C3AED)." | Fix color format |
| Invalid default_tab value | 422 | `validation_error` | "Default tab must be one of: about, videos, posts, plans, shop." | Use valid tab name |
| Unauthorized settings update | 403 | `forbidden` | "You can only edit your own storefront." | Log in as the creator |
| CSRF missing on PUT | 403 | `csrf_error` | "Session expired. Please refresh." | Reload page |
| Shop pagination cursor invalid | 400 | `invalid_cursor` | "Invalid pagination cursor." | Restart from first page |
| Social link key not recognized | 422 | `validation_error` | "Unknown social link platform." | Use supported platform |
| Catalog GSI query timeout | 500 | `internal_error` | "Unable to load shop items. Please try again." | Retry |

---

## 8. Pydantic Models

```python
# -- Creator Storefront (PLATFORM-017) --

from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator


class SocialLinks(BaseModel):
    """Social media links for a creator's storefront."""
    twitter: str = ""
    instagram: str = ""
    youtube: str = ""
    tiktok: str = ""
    website: str = ""
    discord: str = ""
    twitch: str = ""

    @validator("*", pre=True, always=True)
    def truncate_url(cls, v):
        if isinstance(v, str) and len(v) > 500:
            raise ValueError("URL must be under 500 characters")
        return v or ""


class StorefrontSettings(BaseModel):
    """Display settings for the creator storefront."""
    accent_color: str = Field(default="#7C3AED", max_length=7)
    default_tab: str = Field(default="about", pattern="^(about|videos|posts|plans|shop)$")
    show_follower_count: bool = True
    show_post_count: bool = True

    @validator("accent_color")
    def validate_hex_color(cls, v):
        import re
        if not re.match(r"^#[0-9A-Fa-f]{6}$", v):
            raise ValueError("Must be a valid 7-character hex color")
        return v


class FeaturedContentItem(BaseModel):
    """A single featured content item to pin on storefront."""
    content_id: str = Field(min_length=1, max_length=100)
    content_type: str = Field(..., pattern="^(post|video)$")


class FeaturedContentIn(BaseModel):
    """Request model for PUT /ui/profile/featured."""
    items: List[FeaturedContentItem] = Field(max_length=6)


class FeaturedContentOut(BaseModel):
    """Response model for a resolved featured content item."""
    content_id: str
    content_type: str
    pinned_at: int = 0
    title: Optional[str] = None
    thumbnail_url: Optional[str] = None
    preview_text: Optional[str] = None


class StorefrontPlanOut(BaseModel):
    """A subscription plan displayed on the storefront."""
    plan_id: str
    name: str
    description: str = ""
    price_cents: int = 0
    currency: str = "USD"
    billing_period: str = "monthly"
    features: List[str] = Field(default_factory=list)
    is_popular: bool = False


class StorefrontOut(BaseModel):
    """Aggregated storefront response - all data for one API call."""
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
    """A public catalog item for the storefront shop tab."""
    item_id: str
    name: str
    description: str = ""
    price_cents: int = 0
    currency: str = "USD"
    thumbnail_url: Optional[str] = None
    category: str = ""


class PublicCatalogOut(BaseModel):
    """Response for public catalog listing."""
    items: List[PublicCatalogItemOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
```

---

## 9. Frontend Component Tree

```
CreatorStorefrontPage (pages/profile/CreatorStorefrontPage.tsx)
├── useParams() -> { identifier }
├── useQuery(["storefront", identifier]) -> GET /profile/public/{identifier}/storefront
│
├── Cover Banner
│   ├── <img> src={cover_photo_url || banner_url}
│   └── Gradient overlay (uses accent_color from storefront_settings)
│
├── Profile Header
│   ├── Avatar (profile_photo_url)
│   ├── Display Name + Title
│   ├── Description / Bio (truncated with "Read more")
│   ├── SocialLinksBar
│   │   ├── For each non-empty link in social_links:
│   │   │   └── <a> with platform icon (Twitter, Instagram, YouTube, etc.)
│   │   └── Props: { links: SocialLinks }
│   ├── Stats Row
│   │   ├── "{follower_count} followers" (if show_follower_count)
│   │   ├── "{post_count} posts" (if show_post_count)
│   │   └── "{video_count} videos"
│   └── Action Buttons
│       ├── FollowButton (isFollowing state)
│       │   └── useMutation -> POST/DELETE /ui/profile/{id}/follow
│       └── "Subscribe" CTA (if has subscription_plans)
│           └── scrollTo Plans tab
│
├── Tabs (shadcn Tabs component)
│   ├── TabsTrigger: "About" (default_tab from settings)
│   │   └── StorefrontAboutTab
│   │       ├── FeaturedContentCarousel
│   │       │   ├── Props: { items: FeaturedContentOut[] }
│   │       │   └── For each item:
│   │       │       ├── Thumbnail image
│   │       │       ├── Title overlay
│   │       │       ├── Type badge ("Post" | "Video")
│   │       │       └── Link to /feed/{post_id} or /videos/{video_id}
│   │       ├── Full Bio Text (untruncated)
│   │       └── Recent Activity Summary
│   │
│   ├── TabsTrigger: "Videos"
│   │   └── StorefrontVideoGrid (existing component, reused)
│   │       └── useInfiniteQuery -> GET /profile/public/{id}/videos
│   │
│   ├── TabsTrigger: "Posts"
│   │   └── StorefrontPostsFeed (existing component, reused)
│   │       └── useInfiniteQuery -> GET /profile/public/{id}/posts
│   │
│   ├── TabsTrigger: "Plans" (if subscription_plans.length > 0)
│   │   └── StorefrontPlansTab
│   │       ├── Props: { plans: StorefrontPlanOut[] }
│   │       └── Plan Card Grid
│   │           └── For each plan:
│   │               ├── Plan name (h3)
│   │               ├── Price display ($X.XX/month)
│   │               ├── Feature checklist
│   │               ├── "Popular" badge (if is_popular)
│   │               └── "Subscribe" button
│   │                   └── onClick -> navigate to subscription flow
│   │
│   └── TabsTrigger: "Shop" (if has_shop_items)
│       └── StorefrontShopTab
│           ├── useInfiniteQuery(["storefront-shop", identifier])
│           │   -> GET /profile/public/{id}/shop
│           └── Item Card Grid
│               └── For each item:
│                   ├── Thumbnail image
│                   ├── Item name
│                   ├── Price ($X.XX)
│                   ├── Category badge
│                   └── "Add to Cart" button
│                       └── useMutation -> POST /ui/cart/add
│
└── (Creator-only) StorefrontSettingsCard
    ├── Only shown if viewer is the profile owner
    ├── "Edit Storefront" button -> opens dialog
    └── StorefrontSettingsDialog
        ├── FeaturedContentEditor (drag-and-drop list)
        ├── SocialLinksForm (text inputs per platform)
        ├── AccentColorPicker
        ├── DefaultTabSelector
        └── Save button -> PUT /ui/profile/storefront-settings + /social-links + /featured

State Management:
  - React Query for all server state
  - URL search params for active tab (e.g., ?tab=plans)
  - No Zustand store needed (all state derived from URL + API)
```

---

## 10. Observability & Monitoring

### 10.1 Metrics to Track

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `storefront_page_views` | Counter | `creator_id` | Total storefront page loads |
| `storefront_tab_views` | Counter | `creator_id`, `tab` | Views per tab (about, videos, posts, plans, shop) |
| `storefront_follow_clicks` | Counter | `creator_id` | Follow button clicks from storefront |
| `storefront_subscribe_clicks` | Counter | `creator_id`, `plan_id` | Subscribe CTA clicks |
| `storefront_shop_add_to_cart` | Counter | `creator_id`, `item_id` | Add to cart from storefront |
| `storefront_featured_resolves` | Histogram | -- | Time to resolve featured content metadata |
| `storefront_api_latency_ms` | Histogram | `endpoint` | Response time for storefront endpoints |

### 10.2 Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `storefront.view` | INFO | creator_id, viewer_id, tab | Page load or tab switch |
| `storefront.featured.updated` | INFO | creator_id, item_count | Featured content changed |
| `storefront.settings.updated` | INFO | creator_id, changed_fields | Storefront settings saved |
| `storefront.featured.resolve_failed` | WARN | creator_id, content_id | Featured item not found (deleted content) |

### 10.3 Alert Thresholds

| Condition | Threshold | Severity |
|-----------|-----------|----------|
| Storefront API P95 latency > 2s | 2000ms | Warning |
| Featured content resolution errors > 10/hour | 10 | Info |
| Storefront 500 errors > 5/minute | 5 | Critical |

---

## 11. Rollout Plan

### 11.1 Feature Flag Strategy

| Flag | Location | Default | Purpose |
|------|----------|---------|---------|
| `VITE_CREATOR_STOREFRONT_ENABLED` | `frontend/.env.local` | `true` | Show/hide storefront route |
| `S.storefront_shop_enabled` | `app/core/settings.py` | `True` | Enable shop tab (can disable if catalog not ready) |

### 11.2 Migration Steps

1. **Add ByCreator GSI** to catalog table (DDB migration -- GSI backfill runs automatically).
2. **Deploy backend** with new storefront/shop/featured endpoints.
3. **Deploy frontend** with new `CreatorStorefrontPage` and route.
4. **Redirect** `/profile/:identifier` to `/creator/:identifier`.
5. **Communicate** to creators that they can customize their storefront.

### 11.3 Rollback Procedure

1. Remove `/creator/:identifier` route; restore `/profile/:identifier` as primary.
2. No data migration needed (profile extensions are additive).
3. GSI can remain (no cost if unused).

---

## 12. Performance Considerations

### 12.1 Query Costs

| Operation | DDB Cost | Frequency | Notes |
|-----------|----------|-----------|-------|
| Get profile (with storefront data) | 1 RCU | Per storefront load | Single get_item |
| Resolve featured content (up to 6 items) | 6 RCU | Per storefront load | 6 get_items (batch_get available) |
| List subscription plans | 1-2 RCU | Per storefront load | GSI query (usually 1-5 plans) |
| Count catalog items | 1 RCU | Per storefront load | GSI query SELECT COUNT |
| List shop items (paginated) | 1-2 RCU | Per shop tab open | GSI query with limit |

### 12.2 Caching Strategy

- **Storefront data**: Cache in React Query with 60-second staleTime (visitors tolerate slightly stale data).
- **Tab data (videos, posts, shop)**: Lazy-loaded on tab activation; cached for 5 minutes.
- **Backend**: Profile data cached in-memory for 30 seconds per user_sub using TTL wrapper.

### 12.3 Aggregated Endpoint

`GET /profile/public/{identifier}/storefront` returns all data needed to render the header, about tab, plans preview, and shop indicator in a single request. This avoids 4-5 sequential API calls on initial page load.

### 12.4 Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| Public storefront GET | 60/min | Per IP |
| Settings update endpoints | 20/hour | Per user |
| Featured content update | 10/hour | Per user |

---

## 13. Backend Service

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

---

## 14. Storefront Data Flow

### 14.1 Aggregated Storefront Endpoint

`GET /profile/public/{identifier}/storefront` returns all data needed to render the full page in a single request, reducing round trips:

1. Fetch profile from `T.profile` (display name, bio, avatar, banner, social links, featured content, storefront settings).
2. Resolve follow status (if authenticated viewer).
3. Fetch subscription plans from `T.subscriptions` (CREATOR#{user_sub}).
4. Check catalog item count from `T.catalog` (ByCreator GSI, COUNT only).
5. Resolve featured content metadata (post titles, video thumbnails).
6. Return `StorefrontOut` with all fields populated.

### 14.2 Lazy-Loaded Tabs

Individual tab content (videos, posts, shop items) is loaded on tab activation via separate endpoints to avoid fetching all content upfront:

- Videos tab: `GET /profile/public/{identifier}/videos` (existing via StorefrontVideoGrid)
- Posts tab: `GET /profile/public/{identifier}/posts` (existing)
- Plans tab: data already in `StorefrontOut.subscription_plans`
- Shop tab: `GET /profile/public/{identifier}/shop` (new, paginated)

### 14.3 Featured Content Resolution

Featured items are stored as `[{content_id, content_type, pinned_at}]` on the profile. The storefront endpoint resolves each to its metadata:

- **Posts**: query `app_single_table` for `POST#{content_id}` to get body preview, image URL.
- **Videos**: query `video_metadata` for `video_id` to get title, thumbnail_url, view_count.

Unresolvable items (deleted content) are silently filtered out.

---

## 15. E2E Test Plan

**File**: `frontend/e2e/creator-storefront.spec.ts`

### Section 527: Storefront Public API (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 527.1 | Get storefront data for a known user | GET `/profile/public/{identifier}/storefront`; 200; response has `display_name`, `social_links`, `storefront_settings` |
| 527.2 | Storefront returns subscription plans | Create a plan for Alice; GET storefront; `subscription_plans` array has at least 1 item with `plan_id`, `price_cents` |
| 527.3 | Storefront for non-existent user returns 404 | GET `/profile/public/nonexistent_user/storefront`; 404 |
| 527.4 | Featured content endpoint returns pinned items | PUT featured with 2 items; GET `/profile/public/{id}/featured`; response has 2 items with `content_id`, `content_type` |
| 527.5 | Storefront includes follow status for authenticated viewer | Bob GETs Alice's storefront; `is_following` field present (true or false) |
| 527.6 | Storefront without auth returns profile without follow status | Unauthenticated GET; `is_following` is false |

### Section 528: Storefront Creator Settings API (6 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 528.1 | Update social links | PUT `/ui/profile/social-links` with `twitter`, `instagram`; 200; GET storefront shows social_links populated |
| 528.2 | Update storefront settings | PUT `/ui/profile/storefront-settings` with `accent_color=#FF0000, default_tab=videos`; 200; GET confirms changes |
| 528.3 | Set featured content (max 6) | PUT `/ui/profile/featured` with 6 items; 200; GET returns 6 items |
| 528.4 | Exceed featured limit returns 400 | PUT `/ui/profile/featured` with 7 items; 400 response |
| 528.5 | Invalid accent color returns 422 | PUT settings with `accent_color=notacolor`; 422 |
| 528.6 | Social link with unrecognized key is ignored | PUT with `{"twitter": "https://...", "fakebook": "https://..."}; "fakebook" not in response |

### Section 529: Public Catalog API (5 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 529.1 | List creator's public shop items | Create catalog item for Alice; GET `/profile/public/{id}/shop`; response has item with `name`, `price_cents` |
| 529.2 | Empty shop returns empty array | GET shop for user with no items; response `{ items: [], next_cursor: null }` |
| 529.3 | Shop pagination works | Create 3 items; GET with `limit=2`; response has 2 items and `next_cursor`; GET with cursor returns remaining 1 item |
| 529.4 | Draft items not shown in public shop | Create item with status=draft; GET shop; draft item not in results |
| 529.5 | Shop items sorted by creation date (newest first) | Create 3 items at different times; GET shop; items ordered newest first |

### Section 530: Storefront UI (7 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 530.1 | Creator storefront page renders with tabs | Navigate to `/creator/{identifier}`; page shows display name, avatar, and tab bar with "About", "Videos", "Posts" |
| 530.2 | About tab shows social links | Set social links via API; navigate to storefront; social link icons are visible |
| 530.3 | Plans tab shows subscription plan cards | Create plan; navigate to storefront; click "Plans" tab; plan card visible with price |
| 530.4 | Featured content carousel renders | Pin 2 items; navigate to storefront; featured section shows 2 content cards |
| 530.5 | Follow button toggles follow state | Navigate as Bob to Alice's storefront; click Follow; button text changes to "Following" |
| 530.6 | Shop tab shows catalog items | Create published item; navigate to storefront; click "Shop" tab; item card visible |
| 530.7 | Tab URL parameter works | Navigate to `/creator/{id}?tab=plans`; Plans tab is active |

### Section 531: Concurrent Access and Edge Cases (3 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 531.1 | Storefront loads correctly when user has no profile extensions | GET storefront for user with no social_links/featured; returns defaults (empty social_links, empty featured, default settings) |
| 531.2 | Featured content with deleted item is filtered | Pin an item, delete the underlying content; GET storefront; featured list excludes deleted item |
| 531.3 | Multiple concurrent settings updates do not corrupt | Two rapid PUT requests to different settings; final state reflects both changes |

**Total E2E tests: 27**

---

## 16. Security Considerations

### 16.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| `GET /profile/public/*/storefront` | Optional | Public; authenticated viewers see follow status |
| `GET /profile/public/*/plans` | None | Fully public |
| `GET /profile/public/*/shop` | None | Fully public; only `status=published` items shown |
| `GET /profile/public/*/featured` | None | Fully public |
| `PUT /ui/profile/featured` | `require_ui_session` | Creator only (own profile) |
| `PUT /ui/profile/social-links` | `require_ui_session` | Creator only (own profile) |
| `PUT /ui/profile/storefront-settings` | `require_ui_session` | Creator only (own profile) |

### 16.2 Content Filtering

- Public catalog endpoint only returns items with `status=published`. Draft, archived, and soft-deleted items are never exposed.
- Locked posts show title and lock indicator but no body content to unauthenticated visitors.
- Featured content references are validated -- deleted content IDs are silently filtered from the response.

### 16.3 Input Validation

- `social_links`: each URL max 500 characters; only allowed key names accepted.
- `accent_color`: validated as 7-character hex color string.
- `default_tab`: restricted to `about|videos|posts|plans|shop`.
- `featured_content.items`: max 6 items; `content_type` restricted to `post|video`.

### 16.4 Rate Limiting

- Public storefront GET: 60 requests per IP per minute (same as profile).
- Settings update endpoints: 20 per user per hour.
- All endpoints inherit global rate limiter.

### 16.5 Discoverability

- Deactivated or deleted profiles return 404 on all storefront endpoints (existing discoverability check in `get_public_profile` is reused).
- Hidden profiles are accessible by direct URL but excluded from search results (existing behavior).

---

## 17. Dependencies

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

## 18. Files to Create

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

## 19. Files to Modify

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

## 20. Acceptance Criteria

1. `/creator/{identifier}` renders a tabbed storefront with About, Videos, Posts, Plans, and Shop tabs.
2. Subscription plans are displayed with pricing, features, and a Subscribe button.
3. Public catalog items are queryable by creator without authentication.
4. Creators can pin up to 6 featured content items that appear in a carousel.
5. Social links are editable and display as clickable icons.
6. Storefront settings (accent color, default tab) persist and render correctly.
7. Deactivated/deleted profiles return 404 on all storefront endpoints.
8. Existing `/profile/:identifier` route redirects to `/creator/:identifier`.
9. All 27 E2E tests pass.
10. Storefront loads all essential data in a single aggregated API call.
