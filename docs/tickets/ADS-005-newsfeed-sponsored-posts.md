# ADS-005: Newsfeed Sponsored Posts

**Ticket**: ADS-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 6-8 days
**Dependencies**: ADS-001 (Accounts), ADS-002 (Creatives — native_post format), ADS-004 (Ad Serving Engine)

---

## 1. Overview & Motivation

### 1.1 Purpose

ADS-005 adds native advertising to the newsfeed. Sponsored posts look like regular posts but carry a "Sponsored" badge, advertiser attribution, and a CTA button. They are injected into the feed at configurable intervals (default: 1 per 5 organic posts) using the ad serving engine from ADS-004. Users can hide sponsored posts (negative signal), react to them (engagement signal), and view a "Why am I seeing this?" summary.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Viewer | As a viewer, I want sponsored posts to be clearly labeled. | "Sponsored" badge + advertiser name visible on every sponsored post. |
| Viewer | As a viewer, I want to hide a sponsored post I don't want to see. | "Hide this ad" option; post disappears; negative signal recorded. |
| Viewer | As a viewer, I want to know why I'm seeing an ad. | "Why this ad?" popup shows targeting category (e.g., "Based on your interests"). |
| Viewer | As a viewer, I want to react to sponsored posts like regular posts. | Like/reaction buttons work; engagement tracked for advertiser analytics. |
| Advertiser | As an advertiser, I want my native_post creative shown in the newsfeed. | Creative from ADS-002 rendered as sponsored post with CTA. |
| Creator | As a creator, I want to control whether ads appear near my posts. | `allow_ads_near` toggle per post; default: allow. |

### 1.3 Sponsored Post Injection

```
Feed Response Assembly
──────────────────────

GET /feed (viewer_id)
    │
    ├── Fetch organic posts (existing logic)
    │   └── [post_1, post_2, post_3, post_4, post_5, post_6, ...]
    │
    ├── Fetch sponsored posts (ad serving engine)
    │   └── serve_ad(surface="newsfeed", ...) for each injection slot
    │
    └── Interleave:
        [post_1, post_2, post_3, post_4, post_5, SPONSORED, post_6, ...]
                                                  ↑
                                      Inserted every N organic posts
                                      (N = configurable, default 5)
```

### 1.4 Sponsored Post Rendering

```
┌──────────────────────────────────────────┐
│  🏷️ Sponsored · Acme Corp                │
│                                          │
│  [Ad Image or Text Content]              │
│                                          │
│  Headline text goes here                 │
│  Body text description of the ad...      │
│                                          │
│  ┌──────────────┐                        │
│  │  Shop Now  →  │  (CTA Button)         │
│  └──────────────┘                        │
│                                          │
│  👍 ❤️ 😂 🔥 😮        ··· (overflow)     │
│                     ├── Hide this ad     │
│                     ├── Why this ad?     │
│                     └── Report ad        │
└──────────────────────────────────────────┘
```

---

## 2. Current State Analysis

### 2.1 Feed Query (`app/routers/newsfeed.py`)

`GET /feed` queries `GSI1PK = FEED#{viewer_user_id}` to fetch the viewer's feed posts. The response iterates through items and calls `_post_to_dict()` for each. Currently there is no injection of additional content between organic posts. Adding sponsored post injection requires post-processing the results array.

### 2.2 Post Card (`frontend/src/pages/feed/PostCard.tsx`)

PostCard renders individual feed posts with author avatar, text/image content, reaction bar, comments, and overflow menu. The component accepts a `post` prop typed as `FeedPost`. Sponsored posts extend this with additional fields (`is_sponsored`, `sponsor_label`, `cta_text`, `cta_url`) and require rendering a Sponsored badge and CTA button.

### 2.3 Native Post Creatives (ADS-002)

The `native_post` creative format from ADS-002 contains `headline`, `body_text`, `cta_text`, and `cta_url`. These map directly to sponsored post fields. The ad serving engine returns these fields in the `AdServeResponse`.

### 2.4 Creator Ad Preferences (ADS-003)

The `creator_ad_prefs.py` service stores per-creator ad settings. ADS-005 adds a per-post field `allow_ads_near` that controls whether sponsored posts can appear adjacent to that post in the feed. This is separate from the creator-level `allow_ads` toggle (which controls ads on the creator's own content).

### 2.5 Gaps

1. **No sponsored post injection** — feed returns only organic posts.
2. **No "Sponsored" badge** — PostCard has no sponsored rendering path.
3. **No CTA button** — PostCard has no call-to-action button.
4. **No "Hide this ad"** — no mechanism for negative ad feedback.
5. **No "Why this ad?"** — no targeting transparency.
6. **No per-post ad control** — no `allow_ads_near` field on posts.
7. **No comment control on sponsored posts** — comments should be configurable.

---

## 3. Technical Design

### 3.1 Feed Response Modification

**File**: `app/routers/newsfeed.py`

After fetching organic posts in `GET /feed`, inject sponsored posts:

```python
def _inject_sponsored_posts(posts: list[dict], viewer_id: str, interval: int = 5) -> list[dict]:
    """Inject sponsored posts into the feed at regular intervals."""
    if not posts:
        return posts

    result = []
    sponsored_count = 0
    max_sponsored = 3  # Max sponsored posts per feed page

    for i, post in enumerate(posts):
        result.append(post)
        # Inject after every `interval` organic posts
        if (i + 1) % interval == 0 and sponsored_count < max_sponsored:
            # Check if the surrounding posts allow ads
            if post.get("allow_ads_near", True):
                sponsored = _fetch_sponsored_post(viewer_id, i)
                if sponsored:
                    result.append(sponsored)
                    sponsored_count += 1

    return result

def _fetch_sponsored_post(viewer_id: str, position: int) -> Optional[dict]:
    """Fetch a sponsored post from the ad serving engine."""
    from app.services.ad_serving import serve_ad
    ad = serve_ad(
        surface="newsfeed",
        content_type="post",
        creator_id="platform",  # Newsfeed ads are platform-level
        content_id=f"feed_slot_{position}",
        slot_type="sponsored_post",
        user_id=viewer_id,
    )
    if not ad.get("filled") or ad.get("is_house_ad"):
        return None

    return {
        "post_id": f"sponsored_{ad['creative_id']}_{position}",
        "is_sponsored": True,
        "sponsor_account_id": ad.get("campaign_id", ""),
        "sponsor_label": ad.get("title", "Sponsored"),
        "headline": ad.get("headline"),
        "body": ad.get("body_text", ""),
        "cta_text": ad.get("cta_text"),
        "cta_url": ad.get("cta_url"),
        "image_urls": [ad["image_url"]] if ad.get("image_url") else [],
        "impression_url": ad.get("impression_url"),
        "click_url": ad.get("click_url"),
        "creative_id": ad["creative_id"],
        "campaign_id": ad.get("campaign_id"),
        "reactions_counts": {},
        "comment_count": 0,
        "comments_enabled": False,
        "created_at": now_ts(),
    }
```

### 3.2 Post Model Extension

**File**: `app/models.py` / post creation in `newsfeed.py`

```python
# Add to CreatePostRequest:
allow_ads_near: bool = Field(default=True, description="Allow sponsored posts adjacent in feed")

# Add to _post_to_dict():
"allow_ads_near": post.get("allow_ads_near", True),
```

### 3.3 Ad Feedback Storage

**File**: `app/services/ad_feedback.py`

```python
def record_ad_feedback(user_id: str, creative_id: str, campaign_id: str, feedback_type: str, reason: str = "") -> dict:
    """Record user feedback on an ad (hide, not_relevant, repetitive, offensive)."""
    ts = now_ts()
    T.billing.put_item(Item={
        "pk": f"USER#{user_id}",
        "sk": f"AD_FEEDBACK#{creative_id}#{ts}",
        "creative_id": creative_id,
        "campaign_id": campaign_id,
        "feedback_type": feedback_type,
        "reason": reason,
        "created_at": ts,
    })
    return {"ok": True}

def get_hidden_ad_ids(user_id: str) -> set[str]:
    """Get creative IDs hidden by this user."""
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{user_id}") & Key("sk").begins_with("AD_FEEDBACK#"),
    )
    return {item["creative_id"] for item in resp.get("Items", []) if item.get("feedback_type") == "hide"}
```

### 3.4 "Why This Ad?" Endpoint

```python
@router.get("/ads/why/{creative_id}")
def why_this_ad(creative_id: str, ctx=Depends(require_ui_session)):
    """Return a vague targeting category for the ad."""
    # Never expose specific targeting details — only broad category
    return {
        "reason": "Based on your activity on the platform",
        "categories": ["general"],
        "note": "Ads are selected based on the content you view and your platform activity.",
    }
```

### 3.5 Backend Router

**File**: `app/routers/ads.py` (extend)

```python
@router.post("/feedback")
def ad_feedback_endpoint(body: dict, ctx=Depends(require_ui_session)):
    return record_ad_feedback(
        user_id=ctx["user_sub"],
        creative_id=body["creative_id"],
        campaign_id=body.get("campaign_id", ""),
        feedback_type=body["feedback_type"],
        reason=body.get("reason", ""),
    )
```

### 3.6 Frontend Components

**File**: `frontend/src/pages/feed/SponsoredPostCard.tsx`

- Extends PostCard visual structure with:
  - "Sponsored" badge with `Tag` icon in header area
  - Sponsor label (advertiser name/title)
  - Headline in bold, body text below
  - CTA button (full-width or inline, styled as primary button)
  - Overflow menu with "Hide this ad", "Why this ad?", "Report ad"
- Fires impression tracking beacon on mount (`IntersectionObserver` for viewability)
- Fires click tracking on CTA button click (then navigates to `cta_url`)
- Reactions work the same as regular posts (engagement signal forwarded to advertiser analytics)
- Comments disabled by default for sponsored posts
- `data-testid="sponsored-post"`

**File**: `frontend/src/pages/feed/WhyThisAdDialog.tsx`

- Dialog triggered by "Why this ad?" overflow menu item
- Shows vague targeting reason from `/ui/ads/why/{creative_id}`
- "Ad Preferences" link to settings page (ADS-009)

### 3.7 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface FeedPost {
  // ... existing fields ...
  is_sponsored?: boolean;
  sponsor_account_id?: string;
  sponsor_label?: string;
  headline?: string | null;
  cta_text?: string | null;
  cta_url?: string | null;
  impression_url?: string;
  click_url?: string;
  creative_id?: string;
  campaign_id?: string;
  comments_enabled?: boolean;
  allow_ads_near?: boolean;
}
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_feedback.py` | Ad hide/feedback storage |
| `frontend/src/pages/feed/SponsoredPostCard.tsx` | Sponsored post rendering |
| `frontend/src/pages/feed/WhyThisAdDialog.tsx` | "Why this ad?" dialog |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/newsfeed.py` | Add sponsored post injection to GET /feed; add `allow_ads_near` to post creation |
| `app/routers/ads.py` | Add feedback + why-this-ad endpoints |
| `frontend/src/api/types.ts` | Extend `FeedPost` with sponsored fields |
| `frontend/src/api/endpoints/ads.ts` | Add feedback + why-this-ad API functions |
| `frontend/src/pages/feed/PostCard.tsx` | Render SponsoredPostCard when `is_sponsored=true` |
| `frontend/src/pages/feed/CreatePost.tsx` | Add `allow_ads_near` toggle |

### 4.3 Step-by-Step Order

1. Implement `ad_feedback.py` service
2. Add sponsored post injection to feed endpoint
3. Add `allow_ads_near` to post creation
4. Add feedback + why-this-ad endpoints
5. Add frontend types
6. Build SponsoredPostCard component
7. Build WhyThisAdDialog
8. Integrate into PostCard rendering
9. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/ads-sponsored-posts.spec.ts` — 18 tests across 5 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let accountId: string;
let campaignId: string;
let nativeCreativeId: string;
let organicPostIds: string[] = [];

test.beforeAll(async ({ browser }) => {
  // Set up Alice (advertiser with active native_post creative)
  // Set up Bob (creator + viewer)
  // Create 10 organic posts by Bob (to trigger injection at interval=5)
  // Approve ad account + campaign + creative
});
```

### 5.3 Section 359: Sponsored Post Injection API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 359.1 | Feed contains sponsored posts | Bob GET `/feed`; response includes items with `is_sponsored=true` |
| 359.2 | Sponsored post has required fields | Sponsored item has `sponsor_label`, `headline`, `cta_text`, `impression_url` |
| 359.3 | Sponsored posts appear at correct interval | With 10 organic posts, sponsored post appears after position 5 |
| 359.4 | No sponsored posts when no active campaigns | Pause all campaigns; GET /feed; no `is_sponsored` items |

### 5.4 Section 360: Ad Feedback API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 360.1 | Hide ad records feedback | POST `/ui/ads/feedback` with feedback_type=hide; 200; ok=true |
| 360.2 | Hidden ad not shown again | Hide creative; GET /feed; hidden creative_id not in sponsored posts |
| 360.3 | Record negative reason | POST feedback with reason=not_relevant; 200 |
| 360.4 | "Why this ad?" returns reason | GET `/ui/ads/why/{creative_id}`; 200; response has `reason` string |

### 5.5 Section 361: Creator Ad Control API (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 361.1 | Post with allow_ads_near=true (default) | Create post; GET post; `allow_ads_near=true` |
| 361.2 | Post with allow_ads_near=false | Create post with `allow_ads_near=false`; field stored |
| 361.3 | No sponsored post after allow_ads_near=false post | In feed, sponsored posts not injected after posts with allow_ads_near=false |

### 5.6 Section 362: Sponsored Post Rendering UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 362.1 | Sponsored badge visible | Navigate to feed; `[data-testid="sponsored-post"]` visible; "Sponsored" text visible |
| 362.2 | CTA button visible and clickable | CTA button text matches creative's `cta_text` |
| 362.3 | "Hide this ad" in overflow menu | Click overflow (three-dot menu); "Hide this ad" option visible |
| 362.4 | Reactions work on sponsored posts | Click reaction emoji; reaction count increments |

### 5.7 Section 363: Impression Tracking UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 363.1 | Impression beacon fires on view | Navigate to feed with sponsored post; intercept `impression_url` request; request made |
| 363.2 | Click tracking fires on CTA click | Click CTA button; intercept `click_url` request; request made |
| 363.3 | No duplicate impression on re-scroll | Scroll away and back; impression fires only once per session |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Ad serving fails | — | Feed still returns organic posts (no sponsored injection) |
| Invalid feedback_type | 400 | "Invalid feedback type" |
| Creative not found for why-this-ad | 200 | Returns generic reason |
| Impression tracking fails | 200 | Best-effort; logged but doesn't affect user experience |

---

## 7. Security Considerations

- "Why this ad?" never exposes specific targeting dimensions (only broad category)
- CTA URLs are rendered as external links; no server-side redirect (user sees destination)
- Ad feedback is per-user; advertisers see aggregate feedback counts, not individual users
- Impression beacon uses same CSRF protection as other POST endpoints
- `allow_ads_near` only affects the post creator's posts; cannot affect other users' posts

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-001 | Campaign hierarchy | Required |
| ADS-002 | native_post creatives | Required |
| ADS-004 | serve_ad() engine | Required |

### 8.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| ADS-008 (Analytics) | Sponsored post impression/click data |
| ADS-009 (User Ad Prefs) | User hide signals from ADS-005 |
