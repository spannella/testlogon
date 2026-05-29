# ADS-012: Self-Promotion & Content Boosting

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 6-8 days  
**Dependencies**: ADS-001 (advertiser accounts & campaign manager), ADS-005 (newsfeed sponsored posts), ADS-007 (ad billing & financial engine)

---

## 1. Overview & Motivation

### The Gap

Content creators currently have no mechanism to amplify the reach of their posts, videos, or broadcasts beyond their existing follower base. When a creator publishes a post to the newsfeed (`app/routers/newsfeed.py`), it appears only to users who follow the creator or browse the public feed. There is no paid promotion option — creators cannot pay to ensure their content reaches more viewers.

The advertising platform (ADS-001 through ADS-010) provides full campaign management, but it is designed for advertisers — external brands managing multiple campaigns with creative uploads, targeting engines, and analytics dashboards. For a creator who simply wants to say "show this post to more people for $10 over 3 days," the campaign manager is overwhelming overkill.

Content boosting bridges this gap: a one-click "Boost" button on any post, video, or broadcast that creates a simplified ad campaign behind the scenes. The creator selects a budget and duration, optionally adjusts targeting, and the system handles the rest. Boosted content appears as "Promoted" in feeds — reusing the same rendering pipeline as ADS-005 sponsored posts.

### Why This Is Needed

1. **Creator revenue growth**: Creators who boost their content reach more potential subscribers, increasing subscription revenue. The platform benefits from both the boost payment and subsequent subscription commissions.

2. **Simplicity**: Most creators are not professional marketers. A "Boost for $10" button is vastly more accessible than a full campaign manager with targeting configs, creative uploads, and bid strategies.

3. **Content diversity in feeds**: Without paid promotion, the feed is dominated by content from creators with the largest organic following. Boosting lets smaller creators compete for attention, improving content diversity.

4. **Platform ad revenue**: Every boost is a direct payment to the platform. Unlike external advertiser campaigns which require sales/onboarding, boosts are self-service and zero-friction.

### Architecture After This Change

```
Creator's PostCard / VideoDetail / BroadcastDashboard
        │
        │  Click "Boost" button
        ▼
┌───────────────────────────────────┐
│  BoostDialog (frontend)           │
│                                   │
│  Budget: [$5] [$10] [$25] [$50]  │
│  Duration: [1d] [3d] [7d] [14d]  │
│  Targeting: [Auto] [Custom]       │
│  Wallet balance: $47.50           │
│                                   │
│  [Cancel]  [Boost for $10]        │
└───────────────────────────────────┘
        │
        │  POST /ui/content/{type}/{id}/boost
        ▼
┌───────────────────────────────────┐
│  Backend (boost_service.py)       │
│                                   │
│  1. Validate wallet balance       │
│  2. Deduct from wallet            │
│  3. Create ad campaign (ADS-001)  │
│  4. Link campaign to content      │
│  5. Set status = "boosted"        │
│  6. Return boost details          │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  Ad Serving Engine (ADS-004)      │
│                                   │
│  Boosted content enters the ad    │
│  candidate pool. When a user's    │
│  feed is assembled, boosted posts │
│  compete with other ads for       │
│  placement. Displayed with        │
│  "Promoted" badge.                │
└───────────────────────────────────┘
```

### Data Flow — Boost Creation

```
Browser                          Backend                              DynamoDB
  │                                 │                                    │
  │── POST /ui/content/post/        │                                    │
  │   {post_id}/boost ─────────────>│                                    │
  │   { budget_cents: 1000,         │                                    │
  │     duration_days: 3,           │                                    │
  │     targeting: "auto" }         │                                    │
  │                                 │                                    │
  │                                 │── check wallet balance ───────────>│
  │                                 │   billing table: USER#{sub}/WALLET │
  │                                 │<── balance: 4750 ─────────────────│
  │                                 │                                    │
  │                                 │── deduct 1000 from wallet ────────>│
  │                                 │   billing table: LEDGER entry      │
  │                                 │   wallet update (atomic decrement) │
  │                                 │<── ok ────────────────────────────│
  │                                 │                                    │
  │                                 │── create ad campaign ─────────────>│
  │                                 │   ad_campaigns table               │
  │                                 │   status=active, type=boost        │
  │                                 │   content_ref={post, post_id}      │
  │                                 │<── campaign_id ───────────────────│
  │                                 │                                    │
  │                                 │── update content metadata ────────>│
  │                                 │   newsfeed/video_metadata table    │
  │                                 │   boost_campaign_id, boost_status  │
  │                                 │<── ok ────────────────────────────│
  │                                 │                                    │
  │<── 201 { boost_id, campaign_id, │                                    │
  │     status: "active",           │                                    │
  │     budget_cents: 1000,         │                                    │
  │     ends_at: 1748793600 }       │                                    │
```

---

## 2. Current State Analysis

### 2.1 Newsfeed Posts (`app/routers/newsfeed.py`)

Posts are created via `POST /ui/newsfeed/posts` and stored in the newsfeed DynamoDB table. Each post has `post_id`, `user_id`, `text`, `image_url`, `created_at`, and metadata fields. The `_post_to_dict()` function serializes posts for API responses.

Posts currently have no `boost_status`, `boost_campaign_id`, or `boost_budget_cents` fields. The feed query (`GET /ui/newsfeed/feed`) returns posts from followed creators, sorted by recency. There is no mechanism to inject promoted content into the feed.

### 2.2 Video Metadata (`app/services/video_metadata_store.py`)

Videos have metadata stored in the `video_metadata` table with fields including `video_id`, `owner_user_id`, `title`, `access_mode`, `ad_config`. Videos have no boost-related fields.

### 2.3 Broadcasts

Broadcast records include `broadcast_id`, `creator_id`, `title`, `status`, `scheduled_at`. No boost fields exist.

### 2.4 Billing & Wallet (`app/services/billing_shared.py`)

The billing system supports wallet operations:
- `new_ledger_entry()` creates debit/credit entries in the `billing` table
- Wallet balance tracked via `USER#{user_sub}` PK with `WALLET` SK
- `user_pk(user_id)` returns the PK format `USER#{user_id}`

Wallet deductions for boosts follow the same pattern as existing wallet operations (tips, unlocks, purchases).

### 2.5 ADS-005 Sponsored Posts

ADS-005 defines how sponsored content appears in feeds with a "Promoted" badge. Boosted content reuses this rendering pipeline — from the feed consumer's perspective, a boosted post looks identical to a sponsored post from an external advertiser.

### 2.6 Gaps

1. No "Boost" button on PostCard, VideoDetail, or BroadcastDashboard
2. No simplified campaign creation flow (budget + duration only)
3. No wallet deduction for boost payments
4. No boost status tracking on content metadata
5. No boost analytics (impressions, reach, engagement)
6. No prorated refund for early cancellation
7. No auto-targeting based on creator's audience demographics

---

## 3. Technical Design

### 3.1 Boost Service: `app/services/content_boost.py`

```python
"""Content boosting service (ADS-012).

Simplified promotion: creator pays from wallet, system creates an
ad campaign behind the scenes, content appears as "Promoted" in feeds.
"""

BUDGET_PRESETS_CENTS = [500, 1000, 2500, 5000]  # $5, $10, $25, $50
DURATION_PRESETS_DAYS = [1, 3, 7, 14]
MIN_BUDGET_CENTS = 500   # $5 minimum
MAX_BUDGET_CENTS = 50000  # $500 maximum

CONTENT_TYPES = ("post", "video", "broadcast")

def create_boost(
    *,
    user_id: str,
    content_type: str,       # "post" | "video" | "broadcast"
    content_id: str,
    budget_cents: int,
    duration_days: int,
    targeting: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a content boost.

    Steps:
    1. Validate content ownership
    2. Check wallet balance >= budget_cents
    3. Deduct from wallet (ledger debit)
    4. Create ad campaign with type="boost"
    5. Update content metadata with boost_campaign_id
    6. Return boost details

    Raises HTTPException on validation failure.
    """
    ...

def get_boost_stats(
    *, user_id: str, content_type: str, content_id: str
) -> Dict[str, Any]:
    """Return boost performance metrics.

    Aggregates from the linked ad campaign:
    - impressions: number of times content was shown
    - reach: unique users who saw the content
    - engagement: clicks, likes, comments from boosted views
    - cost_per_engagement: budget_spent / engagement_count
    - remaining_budget_cents: unspent budget
    - ends_at: when boost expires
    """
    ...

def cancel_boost(
    *, user_id: str, content_type: str, content_id: str
) -> Dict[str, Any]:
    """Cancel an active boost with prorated refund.

    Refund calculation:
    - remaining_ratio = remaining_seconds / total_seconds
    - refund_cents = floor(budget_cents * remaining_ratio)
    - Minimum refund: $0 (no refund in last 10% of duration)

    Credits refund to wallet, pauses ad campaign, clears boost metadata.
    """
    ...

def _auto_targeting(user_id: str) -> Dict[str, Any]:
    """Generate targeting config based on creator's audience.

    Uses existing follower demographics if available, otherwise
    defaults to broad targeting (all users, all geos).
    """
    return {
        "audience": "similar_to_followers",
        "geo": "all",
        "age_range": [18, 65],
    }
```

### 3.2 Router Endpoints

**File**: `app/routers/content_boost.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/content/{content_type}/{content_id}/boost` | `require_ui_session` | Create a boost |
| GET | `/ui/content/{content_type}/{content_id}/boost` | `require_ui_session` | Get boost status |
| GET | `/ui/content/{content_type}/{content_id}/boost/stats` | `require_ui_session` | Get boost analytics |
| DELETE | `/ui/content/{content_type}/{content_id}/boost` | `require_ui_session` | Cancel boost with refund |

### 3.3 Pydantic Models

**File**: `app/models.py`

```python
class ContentBoostCreate(BaseModel):
    budget_cents: int = Field(ge=500, le=50000)
    duration_days: int = Field(ge=1, le=14)
    targeting: Optional[Dict[str, Any]] = None  # None = auto-targeting

class ContentBoostOut(BaseModel):
    boost_id: str
    campaign_id: str
    content_type: str
    content_id: str
    status: str  # "active", "completed", "cancelled"
    budget_cents: int
    spent_cents: int
    remaining_cents: int
    duration_days: int
    started_at: int
    ends_at: int
    targeting: Dict[str, Any]

class ContentBoostStats(BaseModel):
    boost_id: str
    impressions: int
    reach: int
    engagement: int
    clicks: int
    cost_per_engagement_cents: int
    spent_cents: int
    remaining_cents: int
    status: str
    ends_at: int

class ContentBoostRefund(BaseModel):
    boost_id: str
    refund_cents: int
    original_budget_cents: int
    spent_cents: int
    status: str  # "cancelled"
```

### 3.4 Content Metadata Extension

When a boost is created, the content's metadata record is updated with boost fields:

**Newsfeed posts** (newsfeed table):
```python
# Additional fields on post record
boost_campaign_id: Optional[str]   # Links to ad campaign
boost_status: Optional[str]        # "active" | "completed" | "cancelled"
boost_started_at: Optional[int]    # Unix timestamp
boost_ends_at: Optional[int]       # Unix timestamp
```

**Videos** (video_metadata table):
```python
# Additional fields on video metadata
boost_campaign_id: Optional[str]
boost_status: Optional[str]
boost_started_at: Optional[int]
boost_ends_at: Optional[int]
```

**Broadcasts** (broadcasts table):
```python
# Additional fields on broadcast record
boost_campaign_id: Optional[str]
boost_status: Optional[str]
boost_started_at: Optional[int]
boost_ends_at: Optional[int]
```

### 3.5 Boost Campaign Record (ad_campaigns table)

Boost campaigns are stored as regular ad campaigns with `campaign_type: "boost"`:

```python
{
    "campaign_id": "camp_boost_abc123",
    "advertiser_account_id": "self_promo_{user_id}",
    "campaign_type": "boost",
    "name": "Boost: {content_type} {content_id}",
    "status": "active",
    "budget_cents": 1000,
    "daily_budget_cents": 334,  # budget / duration_days
    "spent_cents": 0,
    "content_ref": {
        "type": "post",
        "id": "post_abc123",
    },
    "targeting": { ... },
    "schedule": {
        "start_date": "2026-06-01",
        "end_date": "2026-06-03",
    },
    "created_at": 1748534400,
}
```

### 3.6 Prorated Refund Calculation

```python
def _calculate_refund(
    *, budget_cents: int, started_at: int, ends_at: int, spent_cents: int
) -> int:
    """Calculate prorated refund for early cancellation.

    Formula: refund = budget - spent (but never more than remaining time ratio)
    The refund is the lesser of:
    - Unspent budget: budget_cents - spent_cents
    - Time-prorated amount: budget_cents * (remaining_seconds / total_seconds)

    No refund if less than 10% of duration remains.
    """
    now = now_ts()
    total_seconds = ends_at - started_at
    elapsed_seconds = now - started_at
    remaining_seconds = ends_at - now

    if remaining_seconds <= 0 or remaining_seconds < total_seconds * 0.10:
        return 0

    time_ratio = remaining_seconds / total_seconds
    time_based_refund = int(budget_cents * time_ratio)
    unspent_refund = budget_cents - spent_cents

    return min(time_based_refund, unspent_refund)
```

### 3.7 Frontend Components

#### BoostDialog (`frontend/src/components/shared/BoostDialog.tsx`)

Modal dialog launched from the "Boost" button. Contains:
- Budget selector: preset buttons ($5, $10, $25, $50) + custom input
- Duration selector: preset buttons (1d, 3d, 7d, 14d)
- Targeting toggle: "Auto (recommended)" or "Custom" with geo/age fields
- Wallet balance display with "Insufficient balance" warning
- Estimated reach display (budget / estimated CPM * 1000)
- "Boost for $X" submit button

```typescript
interface BoostDialogProps {
  open: boolean;
  onClose: () => void;
  contentType: "post" | "video" | "broadcast";
  contentId: string;
}
```

#### BoostStatsCard (`frontend/src/components/shared/BoostStatsCard.tsx`)

Card component showing boost performance. Rendered inline on PostCard, VideoDetail, BroadcastDashboard when the content has an active boost.

```typescript
interface BoostStatsCardProps {
  contentType: "post" | "video" | "broadcast";
  contentId: string;
}
```

Displays: impressions, reach, engagement count, cost per engagement, remaining budget bar, time remaining countdown, "Cancel Boost" button.

#### PostCard Integration (`frontend/src/pages/feed/PostCard.tsx`)

Add "Boost" button to PostCard's action bar (only visible to post owner):
```tsx
{isOwner && !post.boost_status && (
  <Button variant="outline" size="sm" onClick={() => setBoostDialogOpen(true)}>
    <Zap className="h-4 w-4 mr-1" /> Boost
  </Button>
)}
{isOwner && post.boost_status === "active" && (
  <BoostStatsCard contentType="post" contentId={post.post_id} />
)}
```

#### "Promoted" Badge

When a non-owner sees boosted content in their feed, the PostCard/VideoCard renders a "Promoted" label:
```tsx
{post.is_promoted && (
  <span className="text-xs text-muted-foreground">Promoted</span>
)}
```

### 3.8 Frontend API

**File**: `frontend/src/api/endpoints/boost.ts`

```typescript
export function createBoost(contentType: string, contentId: string, data: BoostCreateInput) {
  return client.post(`/ui/content/${contentType}/${contentId}/boost`, data);
}

export function getBoostStatus(contentType: string, contentId: string) {
  return client.get(`/ui/content/${contentType}/${contentId}/boost`);
}

export function getBoostStats(contentType: string, contentId: string) {
  return client.get(`/ui/content/${contentType}/${contentId}/boost/stats`);
}

export function cancelBoost(contentType: string, contentId: string) {
  return client.delete(`/ui/content/${contentType}/${contentId}/boost`);
}
```

### 3.9 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface BoostCreateInput {
  budget_cents: number;
  duration_days: number;
  targeting?: Record<string, unknown> | null;
}

export interface BoostOut {
  boost_id: string;
  campaign_id: string;
  content_type: string;
  content_id: string;
  status: "active" | "completed" | "cancelled";
  budget_cents: number;
  spent_cents: number;
  remaining_cents: number;
  duration_days: number;
  started_at: number;
  ends_at: number;
  targeting: Record<string, unknown>;
}

export interface BoostStats {
  boost_id: string;
  impressions: number;
  reach: number;
  engagement: number;
  clicks: number;
  cost_per_engagement_cents: number;
  spent_cents: number;
  remaining_cents: number;
  status: string;
  ends_at: number;
}
```

---

## 4. Implementation Plan

### 4.1 Backend (Days 1-4)

1. **`app/models.py`**: Add `ContentBoostCreate`, `ContentBoostOut`, `ContentBoostStats`, `ContentBoostRefund` models.

2. **`app/services/content_boost.py`**: New file. Core boost logic: `create_boost()`, `get_boost_stats()`, `cancel_boost()`, `_auto_targeting()`, `_calculate_refund()`.

3. **`app/routers/content_boost.py`**: New router. Four endpoints: POST (create), GET (status), GET /stats (analytics), DELETE (cancel). All use `require_ui_session`. Register in `app/main.py`.

4. **`app/main.py`**: Register `content_boost_router` with prefix `/ui/content`.

### 4.2 Frontend (Days 5-7)

5. **`frontend/src/api/types.ts`**: Add `BoostCreateInput`, `BoostOut`, `BoostStats` types.

6. **`frontend/src/api/endpoints/boost.ts`**: New file. API wrappers for boost endpoints.

7. **`frontend/src/components/shared/BoostDialog.tsx`**: New component. Budget/duration/targeting selection dialog.

8. **`frontend/src/components/shared/BoostStatsCard.tsx`**: New component. Boost performance display card.

9. **`frontend/src/pages/feed/PostCard.tsx`**: Add "Boost" button and BoostStatsCard to PostCard action bar.

10. **`frontend/src/App.tsx`**: No route changes needed (boost dialog is a modal on existing pages).

### 4.3 E2E Tests (Day 7-8)

11. **`frontend/e2e/content-boost.spec.ts`**: New file. 15 tests across 4 sections.

---

## 5. Security Considerations

### 5.1 Content Ownership

- Only the content owner can create, view, or cancel a boost. `create_boost()` validates `content.owner_user_id == user_id`.
- Non-owners attempting to boost content receive 403.

### 5.2 Wallet Balance

- Boost amount is deducted atomically from wallet using DynamoDB conditional update (`wallet_balance >= budget_cents`).
- If concurrent requests race, only one succeeds; the other gets 402 (insufficient balance).
- Wallet deduction creates a ledger entry for audit trail.

### 5.3 Budget Limits

- Minimum boost: $5 (500 cents). Maximum: $500 (50000 cents).
- Maximum duration: 14 days.
- These limits are enforced by Pydantic model validation and service-layer checks.

### 5.4 Refund Integrity

- Refund amount is calculated server-side based on elapsed time and actual spend.
- Refund cannot exceed original budget minus actual spend.
- No refund if less than 10% of duration remains (prevents gaming).

---

## 6. Testing Strategy

### 6.1 Unit Tests (`tests/test_content_boost.py`)

| # | Test | Description |
|---|------|-------------|
| 1 | Create boost deducts from wallet | Wallet balance decreases by budget_cents |
| 2 | Insufficient balance returns 402 | No deduction, boost not created |
| 3 | Non-owner cannot boost | 403 response |
| 4 | Refund calculation: 50% elapsed | Refund = ~50% of budget minus spent |
| 5 | No refund when <10% remaining | Refund = 0 |
| 6 | Auto-targeting returns valid config | Targeting dict has required fields |

### 6.2 E2E Tests (`frontend/e2e/content-boost.spec.ts`)

**Test File**: `frontend/e2e/content-boost.spec.ts`

**Test setup (beforeAll):**
- Seed sessions for Alice (creator) and Bob (viewer)
- Create a newsfeed post as Alice
- Seed Alice's wallet with 10000 cents ($100)

**Section 392: Boost Creation API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Creator boosts own post with $10 budget` | POST /content/post/{id}/boost → 201, boost_id present, status="active" |
| 2 | `Boost deducts from wallet` | GET wallet balance → decreased by 1000 |
| 3 | `Non-owner cannot boost` | POST as Bob → 403 |
| 4 | `Insufficient wallet balance returns 402` | Set budget > wallet balance → 402 |

**Section 393: Boost Status & Analytics API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Get boost status` | GET /content/post/{id}/boost → 200, status="active", budget fields present |
| 6 | `Boost stats return metrics` | GET /content/post/{id}/boost/stats → 200, impressions/reach/engagement fields present |
| 7 | `Duplicate boost on same content returns 409` | POST boost on already-boosted post → 409 |
| 8 | `Boost on nonexistent content returns 404` | POST /content/post/fake_id/boost → 404 |

**Section 394: Boost Cancellation & Refund API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Cancel boost returns prorated refund` | DELETE /content/post/{id}/boost → 200, refund_cents > 0, wallet balance increased |
| 10 | `Cancelled boost shows status cancelled` | GET /content/post/{id}/boost → status="cancelled" |
| 11 | `Cancelling non-existent boost returns 404` | DELETE /content/post/fake_id/boost → 404 |

**Section 395: Boost Dialog UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 12 | `Boost button visible to post owner` | Navigate to feed; Alice's post shows "Boost" button |
| 13 | `Boost button not visible to non-owner` | Navigate as Bob; Alice's post does NOT show "Boost" button |
| 14 | `BoostDialog renders budget and duration options` | Click "Boost"; dialog shows $5/$10/$25/$50 buttons and 1d/3d/7d/14d buttons |
| 15 | `Submit boost from dialog` | Select $10 + 3 days; click "Boost for $10"; dialog closes; BoostStatsCard appears on post |

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/content_boost.py` | Boost creation, stats, cancellation logic |
| `app/routers/content_boost.py` | Boost API endpoints |
| `frontend/src/api/endpoints/boost.ts` | API wrappers |
| `frontend/src/components/shared/BoostDialog.tsx` | Boost creation dialog |
| `frontend/src/components/shared/BoostStatsCard.tsx` | Boost analytics card |
| `frontend/e2e/content-boost.spec.ts` | E2E tests (15 tests, sections 392-395) |
| `tests/test_content_boost.py` | Unit tests |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add boost Pydantic models |
| `app/main.py` | Register `content_boost_router` |
| `frontend/src/api/types.ts` | Add boost TypeScript types |
| `frontend/src/pages/feed/PostCard.tsx` | Add "Boost" button + BoostStatsCard |

## 9. Acceptance Criteria

1. Creators can boost their own posts, videos, and broadcasts with a budget ($5-$500) and duration (1-14 days)
2. Boost payment deducts from creator's wallet balance with ledger entry
3. Boosted content appears as "Promoted" in other users' feeds
4. Boost analytics show impressions, reach, engagement, and cost per engagement
5. Early cancellation provides prorated refund to wallet
6. Non-owners cannot boost or view boost details
7. All 15 E2E tests pass in `frontend/e2e/content-boost.spec.ts`
