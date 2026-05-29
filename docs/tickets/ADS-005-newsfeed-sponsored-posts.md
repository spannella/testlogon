# ADS-005: Newsfeed Sponsored Posts

**Ticket**: ADS-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 6-8 days
**Dependencies**: ADS-001 (Accounts), ADS-002 (Creatives — native_post format), ADS-004 (Ad Serving Engine) — all sibling tickets, not yet implemented
<!-- NOTE: All ADS dependencies are sibling tickets not yet in the codebase. The existing newsfeed router (app/routers/newsfeed.py) is the integration point. -->

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

---

## 9. Architecture & Data Flow

```
Sponsored Post Injection Pipeline
──────────────────────────────────

  GET /feed (viewer_id, cursor)
       │
       ▼
  ┌─────────────────────────────────────┐
  │  Fetch Organic Posts                │
  │  GSI1PK = FEED#{viewer_id}          │
  │  → [post_1, post_2, ..., post_N]   │
  └──────────┬──────────────────────────┘
             │
             ▼
  ┌─────────────────────────────────────┐
  │  _inject_sponsored_posts()          │
  │                                     │
  │  For every interval-th post:        │
  │    ├─ Check allow_ads_near on post  │
  │    ├─ Call serve_ad(surface=newsfeed)│
  │    │     └─ Check user ad prefs     │
  │    │     └─ Check targeting match   │
  │    │     └─ Check frequency cap     │
  │    │     └─ Check hidden ads        │
  │    ├─ If filled: insert sponsored   │
  │    └─ If not: skip slot             │
  │                                     │
  │  Max 3 sponsored per page           │
  └──────────┬──────────────────────────┘
             │
             ▼
  ┌─────────────────────────────────────┐
  │  Return interleaved feed            │
  │  [organic, organic, ..., SPONSORED, │
  │   organic, organic, ..., SPONSORED] │
  └─────────────────────────────────────┘

  Ad Feedback Flow
  ─────────────────
  User clicks "Hide this ad"
       │
       ▼
  POST /ui/ads/feedback
  { creative_id, feedback_type: "hide" }
       │
       ▼
  billing table: USER#{user_id} / AD_FEEDBACK#{creative_id}#{ts}
       │
       ▼
  get_hidden_ad_ids() → excluded from future injection
```

---

## 10. Detailed DynamoDB Access Patterns

| # | Access Pattern | Table | Key Condition | GSI | Notes |
|---|---------------|-------|---------------|-----|-------|
| 1 | Fetch viewer feed posts | `newsfeed` | `GSI1PK=FEED#{viewer_id}` | GSI1 | Existing feed query |
| 2 | Record ad feedback | `billing` | `pk=USER#{user_id}, sk=AD_FEEDBACK#{creative_id}#{ts}` | -- | PutItem |
| 3 | Get hidden ad IDs | `billing` | `pk=USER#{user_id}, sk begins_with AD_FEEDBACK#` | -- | Query, filter feedback_type=hide |
| 4 | Get post allow_ads_near | `newsfeed` | `pk=POST#{post_id}` | -- | GetItem, check field |
| 5 | Create post with allow_ads_near | `newsfeed` | `pk=POST#{post_id}` | -- | PutItem with field |

---

## 11. API Request/Response Examples

### 11.1 Ad Feedback (Hide)

```bash
curl -X POST http://localhost:8000/ui/ads/feedback \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_bob; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok" \
  -d '{
    "creative_id": "cre_abc123",
    "campaign_id": "camp_xyz",
    "feedback_type": "hide",
    "reason": "not_relevant"
  }'
```

**Response (200)**:
```json
{"ok": true}
```

### 11.2 Why This Ad

```bash
curl http://localhost:8000/ui/ads/why/cre_abc123 \
  -H "Cookie: ui_session=sess_bob; ui_access_token=jwt_tok"
```

**Response (200)**:
```json
{
  "reason": "Based on your activity on the platform",
  "categories": ["general"],
  "note": "Ads are selected based on the content you view and your platform activity."
}
```

### 11.3 Feed with Sponsored Posts

```bash
curl http://localhost:8000/feed?limit=10 \
  -H "Cookie: ui_session=sess_bob; ui_access_token=jwt_tok"
```

**Response (200)** (excerpt):
```json
[
  {"post_id": "post_001", "body": "Organic post...", "is_sponsored": false},
  {"post_id": "post_002", "body": "Another post...", "is_sponsored": false},
  {
    "post_id": "sponsored_cre_abc123_4",
    "is_sponsored": true,
    "sponsor_label": "Acme Corp",
    "headline": "Try our new product",
    "body": "Best thing since sliced bread...",
    "cta_text": "Shop Now",
    "cta_url": "https://acme.com/shop",
    "impression_url": "/ui/ads/impressions/cre_abc123/track",
    "click_url": "/ui/ads/clicks/cre_abc123/track",
    "creative_id": "cre_abc123",
    "campaign_id": "camp_xyz",
    "reactions_counts": {},
    "comment_count": 0,
    "comments_enabled": false
  }
]
```

---

## 12. Error Handling Matrix

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------------|-------------|------------|---------------------|-----------------|
| 1 | Ad serving engine fails | -- | -- | Feed returns organic posts only (graceful degradation) | Automatic |
| 2 | Invalid feedback_type | 400 | `INVALID_FEEDBACK_TYPE` | "Invalid feedback type." | Use: hide, not_relevant, repetitive, offensive |
| 3 | Missing creative_id in feedback | 422 | `MISSING_FIELD` | "creative_id is required." | Include creative_id |
| 4 | Creative not found for why-this-ad | 200 | -- | Returns generic reason (no error) | None needed |
| 5 | Impression tracking fails | 200 | -- | Best-effort; logged but no user impact | Automatic |
| 6 | allow_ads_near field missing on post | -- | -- | Defaults to true (ads allowed) | None needed |
| 7 | No active campaigns for feed | -- | -- | Feed returns organic posts only | None needed |
| 8 | Hidden creative ID stale | -- | -- | Old feedback entries auto-expire after 90 days | Automatic |

---

## 13. Expanded Pydantic Models

```python
from pydantic import BaseModel, Field, field_validator

VALID_FEEDBACK_TYPES = {"hide", "not_relevant", "repetitive", "offensive"}

class AdFeedbackIn(BaseModel):
    creative_id: str = Field(..., min_length=1, max_length=100)
    campaign_id: str = Field(default="", max_length=100)
    feedback_type: str = Field(..., min_length=1)
    reason: str = Field(default="", max_length=500)

    @field_validator("feedback_type")
    @classmethod
    def validate_feedback_type(cls, v):
        if v not in VALID_FEEDBACK_TYPES:
            raise ValueError(f"Invalid feedback type: {v}. Must be one of {VALID_FEEDBACK_TYPES}")
        return v

class SponsoredPostOut(BaseModel):
    post_id: str
    is_sponsored: bool = True
    sponsor_account_id: str
    sponsor_label: str
    headline: str | None = None
    body: str = ""
    cta_text: str | None = None
    cta_url: str | None = None
    image_urls: list[str] = Field(default_factory=list)
    impression_url: str | None = None
    click_url: str | None = None
    creative_id: str
    campaign_id: str | None = None
    reactions_counts: dict = Field(default_factory=dict)
    comment_count: int = 0
    comments_enabled: bool = False
    created_at: int

class WhyThisAdOut(BaseModel):
    reason: str
    categories: list[str]
    note: str
```

---

## 14. Frontend Component Tree

```
FeedPage
├── FeedPostList
│   ├── PostCard (organic posts)
│   └── SponsoredPostCard (sponsored posts, data-testid="sponsored-post")
│       ├── SponsoredBadge ("Sponsored" + Tag icon + sponsor_label)
│       ├── SponsoredContent
│       │   ├── HeadlineText (bold)
│       │   ├── BodyText
│       │   └── ImagePreview (if image_urls present)
│       ├── CTAButton (primary, full-width or inline)
│       ├── ReactionBar (same as PostCard)
│       ├── OverflowMenu
│       │   ├── "Hide this ad" → AdFeedbackDialog
│       │   ├── "Why this ad?" → WhyThisAdDialog
│       │   └── "Report ad" → ReportDialog
│       └── ImpressionTracker (IntersectionObserver, fires on mount)
└── WhyThisAdDialog (data-testid="why-this-ad-dialog")
    ├── ReasonText (from /ui/ads/why/{id})
    └── AdPreferencesLink (→ settings page)
```

### Props Interfaces

```typescript
interface SponsoredPostCardProps {
  post: FeedPost & { is_sponsored: true };
  onHide: (creativeId: string) => void;
  onReaction: (postId: string, emoji: string) => void;
}

interface WhyThisAdDialogProps {
  creativeId: string;
  open: boolean;
  onClose: () => void;
}

interface AdFeedbackDialogProps {
  creativeId: string;
  campaignId: string;
  open: boolean;
  onClose: () => void;
  onSubmit: (feedbackType: string, reason: string) => void;
}
```

---

## 15. Observability

### 15.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `sponsored_post_injected_total` | Counter | `campaign_id` | Sponsored posts injected into feeds |
| `sponsored_post_impression_total` | Counter | `creative_id` | Impression beacons fired |
| `sponsored_post_click_total` | Counter | `creative_id` | CTA button clicks tracked |
| `sponsored_post_hidden_total` | Counter | `reason` | Ads hidden by users |
| `sponsored_post_injection_rate` | Gauge | -- | Ratio of feeds with at least one sponsored post |
| `feed_request_duration_ms` | Histogram | `has_sponsored` | Feed endpoint latency |

### 15.2 Log Events

| Event | Level | Fields |
|-------|-------|--------|
| `sponsored_injected` | INFO | viewer_id, creative_id, position, campaign_id |
| `sponsored_hidden` | INFO | viewer_id, creative_id, feedback_type |
| `sponsored_impression` | DEBUG | viewer_id, creative_id |
| `sponsored_click` | INFO | viewer_id, creative_id, cta_url |
| `sponsored_injection_skipped` | DEBUG | viewer_id, reason (no_campaign, allow_ads_near_false, hidden) |
| `why_this_ad_viewed` | DEBUG | viewer_id, creative_id |

### 15.3 Alerting Rules

| Alert | Condition | Severity |
|-------|-----------|----------|
| Sponsored injection rate drops to 0% | No sponsored posts injected for 1 hour (with active campaigns) | P3 |
| Ad feedback spike | >100 hides in 15 minutes for a single creative | P2 |
| Feed latency regression | p99 feed response > 2s with sponsored injection enabled | P2 |

---

## 16. Rollout Plan

### 16.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `SPONSORED_POSTS_ENABLED` | `false` | Enable sponsored post injection in feed |
| `AD_FEEDBACK_ENABLED` | `true` | Enable hide/feedback on sponsored posts |

### 16.2 Phased Deployment

| Phase | Scope | Duration | Details |
|-------|-------|----------|---------|
| Phase 1: Backend only | Internal | Week 1 | Deploy ad_feedback service, "why this ad" endpoint. Sponsored injection runs in shadow mode (logged but not returned to client). |
| Phase 2: Limited rollout | 10% of users | Week 2 | `SPONSORED_POSTS_ENABLED=true` for cohort. Monitor hide rates, impression counts, feed latency. |
| Phase 3: Full GA | All users | Week 3 | Full rollout. SponsoredPostCard + WhyThisAdDialog deployed. Export documentation. |

---

## 17. Performance Considerations

### 17.1 Latency Targets

| Endpoint | Target p50 | Target p99 |
|----------|-----------|-----------|
| GET /feed (with injection) | 80ms | 300ms |
| POST /ui/ads/feedback | 30ms | 100ms |
| GET /ui/ads/why/{id} | 10ms | 50ms |
| serve_ad() per injection slot | 20ms | 80ms |

### 17.2 Caching Strategy

| Data | Cache | staleTime | Invalidation |
|------|-------|-----------|-------------|
| Feed posts + sponsored | React Query | 30_000ms | On new post creation, pull-to-refresh |
| Hidden ad IDs | Server-side set per request | Per-request | On new feedback submission |
| Why-this-ad response | React Query | 300_000ms | Static data, rarely changes |

### 17.3 Feed Injection Performance

The sponsored post injection adds at most 3 `serve_ad()` calls per feed page. Each call is independent and can be parallelized. If the ad serving engine is slow or unavailable, the feed falls back to organic-only with no user-visible error. The `get_hidden_ad_ids()` query is batched once per feed request (not per slot).

---

## 18. Expanded E2E Tests

### 18.1 Section 364: Input Validation (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 364.1 | Invalid feedback_type rejected | POST feedback with feedback_type="invalid"; 400; "Invalid feedback type" |
| 364.2 | Missing creative_id rejected | POST feedback without creative_id; 422 |
| 364.3 | Empty reason accepted | POST feedback with reason=""; 200 (reason is optional) |
| 364.4 | Very long reason truncated or rejected | POST feedback with 600-char reason; 422 or truncated |

### 18.2 Section 365: Concurrent Feed Operations (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 365.1 | Simultaneous feed requests both get sponsored posts | Two parallel GET /feed; both include sponsored items |
| 365.2 | Hide ad then fetch feed | Hide creative; GET /feed; hidden creative not in response |
| 365.3 | Multiple hides in rapid succession | Hide 3 different creatives; all recorded; none appear in next feed |
| 365.4 | Create post with allow_ads_near=false then verify feed | Create post; GET /feed; no sponsored adjacent to that post |

### 18.3 Section 366: Authorization Boundary (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 366.1 | Unauthenticated feed request | GET /feed without session; 401 |
| 366.2 | Feedback requires auth | POST feedback without session; 401 |
| 366.3 | Why-this-ad requires auth | GET /ui/ads/why/{id} without session; 401 |

### 18.4 Section 367: Sponsored Post UI Interactions (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 367.1 | Hide ad removes it from feed | Click "Hide this ad" on sponsored post; post disappears from DOM |
| 367.2 | Why this ad dialog shows reason | Click "Why this ad?"; dialog visible with reason text |
| 367.3 | CTA button navigates to URL | Click CTA; intercept navigation; URL matches cta_url |
| 367.4 | Sponsored badge text correct | Sponsored post shows "Sponsored" text and sponsor_label |
| 367.5 | Overflow menu has all options | Click three-dot menu; "Hide this ad", "Why this ad?", "Report ad" all visible |

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/routers/newsfeed.py` | — | Existing newsfeed router (5954 lines) — integration point for sponsored post injection |
| `app/services/ad_placement.py` | 25, 222 | Existing ad placement: `DEV_AD_CREATIVES` (line 25), `record_ad_impression` (line 222) |
| `app/core/tables.py` | 93 | Existing `ad_impressions` table handle |
| `app/services/ad_serving.py` | — | Does not exist yet (ADS-004) — required for sponsored post selection |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_ad_sponsored_posts.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_ad_sponsored_posts` | Creates record with correct fields and generated ID |
| `test_create_ad_sponsored_posts_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_ad_sponsored_posts_found` | Returns correct record by ID |
| `test_get_ad_sponsored_posts_not_found` | Returns None for non-existent ID |
| `test_list_ad_sponsored_posts` | Returns all records for the given scope/owner |
| `test_update_ad_sponsored_posts` | Updates mutable fields and sets updated_at |
| `test_delete_ad_sponsored_posts` | Removes record; subsequent get returns None |
| `test_ad_sponsored_posts_owner_check` | Rejects operations from non-owner users |
| `test_ad_sponsored_posts_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_ad_sponsored_posts_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/ads-sponsored-posts.spec.ts`


**Auth setup**:
- Cookie auth: `injectAuth(page, "alice")` for UI session tests
- CSRF header: `headers: { "x-csrf-token": sessions[identity].csrf_token }`
- Bearer auth: global `request` fixture for API-only tests (bypasses CSRF)
- Admin auth: `injectAuth(page, "root")` for admin endpoints

| # | Test | Key Assertion |
|---|------|--------------|
| 1 | Create resource via API | `expect(response.status()).toBe(201)` with correct fields |
| 2 | List resources returns array | `expect(response.status()).toBe(200)`; array length > 0 |
| 3 | Get single resource by ID | `expect(response.status()).toBe(200)`; fields match |
| 4 | Update resource | `expect(response.status()).toBe(200)`; GET confirms change |
| 5 | Delete resource | `expect(response.status()).toBe(200)`; subsequent GET 404 |
| 6 | Non-owner access blocked | `expect(response.status()).toBe(403)` or `toBe(404)` |
| 7 | Admin endpoint blocked for USER | `expect(response.status()).toBe(403)` |
| 8 | Unauthenticated request | `expect(response.status()).toBe(401)` |
| 9 | Invalid input rejected | `expect(response.status()).toBe(422)` |
| 10 | Duplicate/conflict handled | `expect(response.status()).toBe(409)` or idempotent 200 |
| 11 | UI page loads correctly | `page.getByRole("heading", { name: expectedTitle })` visible |
| 12 | UI create flow works | Click create -> fill form -> submit -> new item in list |
| 13 | UI status badges display | `page.getByText("Active")` or `page.getByText("Pending")` |
| 14 | Concurrent operations safe | Parallel requests both succeed or one gets 409 |
| 15 | Edge case: empty state | Empty list shows placeholder text, not error |

### Test Data Requirements


**Test users**: Alice = USER (primary actor), Bob = USER (secondary/viewer), Root = ROOT (admin reviewer), Charlie = ADMIN (scoped admin)


**DDB seed data**: Uses existing tables; no new tables required. See DDB access patterns in technical design section.


### CI/Pipeline


- **Feature flags**: `SPONSORED_POSTS_ENABLED` must be `true` in `.env.local`
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| ADS-001 | Campaign hierarchy | Pending | No |
| ADS-002 | native_post creatives | Pending | No |
| ADS-004 | `serve_ad()` engine | Pending | No |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| ADS-008 | Sponsored post impression data |
| ADS-009 | User hide signals |
| ADS-012 | Sponsored post rendering reuse |

### Merge Strategy


**Sequential (after ADS-004)**


- Must merge after: ADS-001, ADS-002, ADS-004
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB tables verified (uses existing tables only)
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/ads.py`)
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
