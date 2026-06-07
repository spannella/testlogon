# PLATFORM-017: Creator Storefront — Investigation & Implementation Write-up

> ~5 pages. Read from real code; all file:line references verified.

---

## 1. Summary & Classification

PLATFORM-017 requires a dedicated, tabbed creator storefront page at `/creator/:identifier` (or `/u/:identifier`) that replaces the current flat public profile layout with a structured experience including subscription plan CTAs, a shop/catalog tab, featured content curation, social links, a customizable banner, and admin moderation controls. None of these features exist today — the current `PublicUserProfilePage.tsx` has Tabs with Posts/Videos/Followers/Following/About but no Plans tab, no Shop tab, no featured content section, no social links UI, no customizable banner separate from cover_photo_url, and no `/creator/` route alias.

- **Type**: Feature
- **Priority**: Medium
- **Status**: UNBUILT
- **Owning area**: Profile / Storefront / Subscriptions
- **User personas**: Visitor (discovery, subscribe, purchase), Creator (branding, curation), Admin (moderation)
- **Cross-references**: PLATFORM-017 depends on the subscription plans API (`GET /api/creators/{id}/plans`) and catalog API (`GET /ui/catalog/items`) which both exist. No dependency on SECOPS-007 beyond the standard dev/prod pattern.

---

## 2. Current-State Investigation (what exists today)

### 2.1 Route and page

`frontend/src/App.tsx:279` registers one public profile route:
```
/u/:identifier  →  PublicUserProfilePage (lazy)
```
There is no `/creator/:identifier` route. The ticket calls for a new route alias.

### 2.2 PublicUserProfilePage (`frontend/src/pages/profile/PublicUserProfilePage.tsx`)

The component (`PublicUserProfilePage.tsx:33`) renders:
- Profile header: display_name, avatar, cover_photo_url, follower/following/post counts, Follow button, Message/Add Contact actions.
- Subscription plans section (line 270-278): shown only when `pub.has_subscription_plans` is truthy — renders `<PlanBrowser creatorId={pub.user_id} />` inline (not in a tab).
- Tabs (line 279-314): Videos (authenticated only), Posts, Followers, Following, About.

**Missing tabs**: Plans (dedicated tab with plan cards + Subscribe CTA), Shop (catalog items).
**Missing sections**: Featured content carousel/grid, social links (Twitter, Instagram, YouTube, etc.), customizable storefront banner distinct from cover_photo_url.
**Missing route**: `/creator/:identifier` alias — only `/u/:identifier` exists.
**Missing admin controls**: No flag/hide moderation endpoint or UI.

### 2.3 Public profile endpoint (`app/routers/profile.py:298`)

`GET /profile/public/{identifier}` returns:
```json
{
  "user_id", "identifier", "canonical_identifier",
  "display_name", "title", "description", "location",
  "profile_photo_url", "cover_photo_url",
  "follower_count", "following_count", "post_count",
  "is_following", "is_followed_by", "is_mutual",
  "has_subscription_plans",
  "created_at", "discoverability"
}
```

The response does **not** include:
- `social_links` (Twitter, Instagram, YouTube, TikTok, website)
- `featured_content` (list of up to 6 pinned post/video IDs)
- `storefront_banner_url` (separate customizable banner from cover_photo_url)
- `shop_item_count` (so the Shop tab can be shown/hidden)
- `is_hidden` / `moderation_flag` (for admin-controlled visibility)

### 2.4 Profile service (`app/services/profile.py`)

`get_profile(user_sub)` reads the `T.profile` DynamoDB table. The table schema does not include `social_links`, `featured_content`, or `storefront_banner_url` fields. Adding them requires:
1. New optional fields in the DDB item (no migration needed — DDB is schemaless).
2. Updated `get_profile()` to return them.
3. New endpoint or augmented `GET /profile/public/{identifier}` response.

### 2.5 Subscription plans API

`GET /api/creators/{id}/plans` is public (no auth) per the existing implementation. This endpoint already works and `PlanBrowser` uses it. The Plans tab just needs to promote `PlanBrowser` from an inline block (line 272) into a dedicated Tab.

### 2.6 Catalog API

`GET /ui/catalog/items` is authenticated. A public shop endpoint for a creator's catalog does not exist. The ticket requires `GET /profile/public/{id}/shop` returning paginated catalog items. The backend has `list_catalog_items` in `app/services/catalog.py` filtered by creator — it needs a public wrapper that strips private fields.

### 2.7 Dev vs prod

All required backend operations use DynamoDB (Local in dev, AWS in prod) and standard S3/moto for banner uploads. No AWS-specific gap for this feature.

---

## 3. Gap / Threat Analysis

### 3.1 Required code changes — full enumeration

**Backend (new/changed)**:
1. `app/models.py` — Add `StorefrontProfileOut` (augmented public profile with social_links, featured_content, storefront_banner_url, shop_item_count), `StorefrontSocialLink`, `StorefrontFeaturedItem`, `StorefrontUpdateIn`, `StorefrontAdminActionIn`.
2. `app/services/profile.py` — `get_profile()` returns new fields. New `update_storefront_settings(user_sub, social_links, featured_content, storefront_banner_url)` writer. New `set_storefront_hidden(user_sub, hidden, admin_sub)` for admin moderation.
3. `app/routers/profile.py` — Augment `GET /profile/public/{identifier}` with new fields OR add `GET /profile/public/{identifier}/storefront`. Add `PATCH /ui/settings/storefront` (creator edits social links, banner, featured items). Add `POST /admin/profile/{user_sub}/storefront/hide` and `.../unhide` (admin moderation).
4. `app/routers/catalog.py` — Add `GET /profile/public/{identifier}/shop?limit=20&cursor=` returning paginated catalog items for a creator (public, read-only, strips private admin fields).
5. `scripts/local-ddb-init.py` — No new tables; `social_links` and `featured_content` are stored as DDB list attributes in the existing profile table.

**Frontend (new/changed)**:
1. `frontend/src/api/types.ts` — Add `StorefrontProfile`, `SocialLink`, `FeaturedItem`, `ShopItem` types.
2. `frontend/src/api/endpoints/profile.ts` — Add `getPublicStorefront(identifier)`, `updateStorefrontSettings(body)`, `getCreatorShop(identifier, params)`.
3. `frontend/src/pages/profile/PublicUserProfilePage.tsx` — Restructure tabs: About, Plans (new, promotes PlanBrowser), Shop (new, loads catalog), Videos, Posts, Followers, Following. Add featured content section above tabs. Add social links row in header.
4. `frontend/src/pages/profile/StorefrontBannerEditor.tsx` (new) — Banner upload + crop dialog.
5. `frontend/src/pages/profile/SocialLinksEditor.tsx` (new) — Editable list of up to 8 social links (platform + URL).
6. `frontend/src/pages/profile/FeaturedContentPicker.tsx` (new) — Grid picker of up to 6 pinned posts/videos.
7. `frontend/src/pages/profile/StorefrontShopTab.tsx` (new) — Paginated shop catalog grid.
8. `frontend/src/App.tsx` — Add `/creator/:identifier` route alias pointing to `PublicUserProfilePage` (or a separate `CreatorStorefrontPage`).
9. `frontend/src/pages/settings/StorefrontSettings.tsx` (new) — Settings sub-page for banner, social links, featured content editing.
10. `frontend/src/pages/admin/StorefrontModerationPanel.tsx` (new) — Admin hide/flag controls.

### 3.2 Edge cases and abuse

- **Featured content owned by others**: The creator should only be able to pin content they authored. Server-side validation must check `post.author_id == user_sub` before adding to `featured_content`.
- **Deleted featured items**: If a featured post is deleted later, `get_profile()` must filter out missing post IDs rather than returning a broken reference.
- **Social link injection**: Social link URLs must be validated as HTTPS only (no `javascript:`, no data URIs). Backend `field_validator` on `StorefrontUpdateIn.social_links`.
- **Shop tab visibility**: Only show Shop tab when `shop_item_count > 0` (from storefront endpoint); empty tab degrades visitor experience.
- **Admin moderation**: `set_storefront_hidden` sets a `storefront_hidden` flag in the profile DDB item. `GET /profile/public/{identifier}` must return 404 when this flag is set (same as discoverability deactivation). Admin holds must be audited.
- **Banner size**: Enforce server-side max 5MB for banner uploads; client-side crop to 1200×400px before upload.

---

## 4. Proposed Design / Fix

### 4.1 Backend

**New response shape for storefront endpoint**:
```python
# GET /profile/public/{identifier}/storefront (new endpoint)
{
    # All existing public profile fields +
    "social_links": [{"platform": "twitter", "url": "https://..."}],  # max 8
    "featured_content": [{"content_id": str, "content_type": "post"|"video", "thumbnail_url": str, "title": str}],  # max 6
    "storefront_banner_url": Optional[str],
    "shop_item_count": int,
    "is_accepting_dms": bool,
}
```

**Creator PATCH endpoint**:
```
PATCH /ui/settings/storefront
  Body: StorefrontUpdateIn { social_links?, featured_content_ids?, storefront_banner_url? }
  Auth: require_ui_session (CSRF required)
  Response 200: { ok: true }
```

**Public shop endpoint**:
```
GET /profile/public/{identifier}/shop
  Query: limit=20, cursor=?
  Auth: none (public)
  Response 200: { items: [ShopItemPublicOut], next_cursor: ? }
```

**Admin moderation**:
```
POST /admin/profile/{user_sub}/storefront/hide
POST /admin/profile/{user_sub}/storefront/unhide
  Auth: require_admin_session
  Response 200: { ok: true }
```

### 4.2 Frontend tabs structure

```
/creator/:identifier or /u/:identifier
  CreatorStorefrontPage (header: banner, avatar, bio, social links, follow/message CTAs)
    |
    +-- [Featured] carousel (only if featured_content.length > 0)
    |
    +-- Tabs:
         About    — bio, location, member since
         Plans    — PlanBrowser component (existing)
         Shop     — StorefrontShopTab (new, paginated catalog grid)
         Posts    — StorefrontPostsFeed (existing)
         Videos   — StorefrontVideoGrid (existing, auth-only)
         Followers / Following
```

### 4.3 Dev/prod parity (SECOPS-007)

- `storefront_banner_url` is an S3 URL. In dev, moto S3 serves via `/mock/s3/...`. Same code path.
- Featured content validation queries DDB (local in dev, AWS in prod). Same code path.
- No new feature flags needed.

### 4.4 Backward compatibility

- The existing `GET /profile/public/{identifier}` is unchanged. New storefront fields are additive in a new `GET /profile/public/{identifier}/storefront` endpoint.
- `PublicUserProfilePage` can call the new endpoint with a fallback to the existing endpoint for graceful degradation.
- Old `/u/:identifier` route stays; `/creator/:identifier` is an alias.

---

## 5. Testing, Verification & Rollout

### 5.1 Unit tests (`tests/test_storefront.py`)

| # | Function | Description |
|---|----------|-------------|
| 1 | `test_storefront_public_endpoint_returns_social_links` | Social links stored in DDB are returned |
| 2 | `test_storefront_public_endpoint_no_auth` | No auth required; 200 response |
| 3 | `test_storefront_update_social_links` | PATCH with valid social links; 200 |
| 4 | `test_storefront_update_featured_content_max_6` | 7 items rejected with 422 |
| 5 | `test_storefront_featured_must_be_own_content` | Other user's post rejected with 403 |
| 6 | `test_storefront_shop_endpoint_public` | Public shop returns catalog items |
| 7 | `test_storefront_admin_hide` | Admin hide sets flag; profile returns 404 |
| 8 | `test_storefront_admin_unhide` | Admin unhide clears flag; profile visible again |
| 9 | `test_social_link_url_validation_rejects_javascript` | `javascript:alert()` rejected with 422 |
| 10 | `test_storefront_hidden_returns_404` | Hidden storefront returns 404 to all callers |

### 5.2 E2E tests (`frontend/e2e/creator-storefront.spec.ts`)

```
Section 135: Storefront page structure
  135.1  /u/:identifier loads storefront page (200, no 404)
  135.2  /creator/:identifier route alias works
  135.3  Plans tab shows subscription plans
  135.4  Shop tab shows catalog items (or hidden when count=0)
  135.5  Social links icons appear below bio
  135.6  Storefront banner renders above profile header

Section 136: Creator customization
  136.1  Creator updates social links via Settings > Storefront
  136.2  Creator adds a featured post; it appears above tabs
  136.3  Creator uploads a storefront banner; banner appears for visitors
  136.4  Creator pins max 6 items; 7th is rejected

Section 137: Admin moderation
  137.1  Admin hides a storefront; visitors get 404
  137.2  Admin unhides storefront; visitors can access it again
```

### 5.3 Rollout

1. Backend: deploy new endpoints behind `STOREFRONT_ENABLED` feature flag (default false in dev, opt-in in prod).
2. Frontend: new `/creator/` route rendered only when `showCanonicalStorefrontRoute` flag is set.
3. Enable for all creators after E2E pass.

### 5.4 Effort estimate

**L** (10-12 days as estimated in ticket):
- Backend: 3 days (models, service, 3 endpoints)
- Frontend: 6 days (4 new components, tab restructure, settings page)
- E2E: 2 days
- Polish/QA: 1 day
