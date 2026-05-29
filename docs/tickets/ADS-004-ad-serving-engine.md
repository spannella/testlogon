# ADS-004: Ad Serving Engine

**Ticket**: ADS-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Dependencies**: ADS-001 (Accounts), ADS-002 (Creatives), ADS-003 (Targeting) — all sibling tickets, not yet implemented
<!-- NOTE: ADS-001/002/003 services, tables, and routers do not exist yet. Only the existing ad_placement.py service and AdImpressions table are available. -->

---

## 1. Overview & Motivation

### 1.1 Purpose

ADS-004 implements the real-time ad serving engine — the central system that selects and serves ads for all surfaces (newsfeed, broadcast, VOD). When a frontend component needs an ad, it sends a request to the serving engine with viewer and content context. The engine evaluates all eligible campaigns against targeting rules, applies frequency capping and budget pacing, ranks candidates, and returns the winning creative with tracking URLs.

This replaces the hardcoded `DEV_AD_CREATIVES` selection in `app/services/ad_placement.py` with a dynamic campaign-driven system.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| System | As the platform, I want to serve the most relevant ad for each request. | Engine selects highest-scoring eligible campaign. |
| Viewer | As a viewer, I don't want to see the same ad repeatedly. | Frequency capping limits impressions per user per campaign. |
| Advertiser | As an advertiser, I want my budget spread evenly throughout the day. | Budget pacing distributes spend across serving hours. |
| Platform | As the platform, I want to track fill rate. | Logging records filled vs unfilled ad slots. |
| System | As the platform, I want to fall back to house ads when no paid ad matches. | Unfilled slots serve platform self-promotion or blank. |

### 1.3 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Frontend (Browser)                               │
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
│  │  NewsfeedPage │  │ BroadcastView│  │  VODPlayer   │                  │
│  │  (ADS-005)    │  │  (ADS-006)   │  │  (existing)  │                  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                  │
│         │                  │                  │                          │
│         └──────────────────┼──────────────────┘                          │
│                            │                                             │
│              POST /ui/ads/serve                                          │
│              { surface, content_type, creator_id,                        │
│                content_id, slot_type, user_context }                     │
│                            │                                             │
│  ┌─────────────────────────┼─────────────────────────┐                  │
│  │  Ad Creative Render     │   POST /ui/ads/track     │                  │
│  │  (impression_url,       │   event=impression|click  │                  │
│  │   click_url, skip_url)  │   |skip|complete          │                  │
│  └─────────────────────────┼─────────────────────────┘                  │
└─────────────────────────────┼───────────────────────────────────────────┘
                              │
                     ┌────────▼────────┐
                     │  Vite Proxy      │
                     │  /ui/* → :8000   │
                     └────────┬────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────────────┐
│                     Backend (FastAPI :8000)                              │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │  app/routers/ads.py                                       │           │
│  │                                                           │           │
│  │  POST /ui/ads/serve  ─── validates body ──► serve_ad()    │           │
│  │  POST /ui/ads/track  ─── query params ──► track_ad_event()│           │
│  └──────────┬───────────────────────────────────┬───────────┘           │
│             │                                   │                       │
│  ┌──────────▼──────────────┐   ┌────────────────▼──────────────┐       │
│  │ app/services/            │   │ app/services/                  │       │
│  │   ad_serving.py          │   │   ad_placement.py              │       │
│  │                          │   │   (record_ad_impression,       │       │
│  │ 1. Load active campaigns │   │    credit creator revenue)     │       │
│  │    (ad_campaigns.py)     │   │                                │       │
│  │ 2. Check creator prefs   │   └────────────────────────────────┘       │
│  │    (creator_ad_prefs.py) │                                           │
│  │ 3. Evaluate targeting    │                                           │
│  │    (ad_targeting.py)     │                                           │
│  │ 4. Check frequency caps  │                                           │
│  │ 5. Check budget          │                                           │
│  │ 6. Score & rank          │                                           │
│  │ 7. Select creative       │                                           │
│  │ 8. Build tracking URLs   │                                           │
│  └──────────┬───────────────┘                                           │
│             │                                                           │
│  ┌──────────▼───────────────────────────────────────────┐               │
│  │                    DynamoDB                            │               │
│  │                                                       │               │
│  │  ad_campaigns ─── active campaign records             │               │
│  │  ad_creatives ─── approved creative assets            │               │
│  │  ad_targeting ─── targeting rule sets                  │               │
│  │  ad_frequency_caps ─── user/campaign/window counters  │               │
│  │  ad_impressions ─── impression/click/skip events      │               │
│  │  creator_ad_prefs ─── creator allow/block settings    │               │
│  └───────────────────────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.4 Ad Serving Flow

```
Ad Request Flow
───────────────

Frontend (any surface)
    │
    │── POST /api/ads/serve
    │   { surface, content_type, creator_id, content_id, slot_type, user_context }
    │
    ▼
Ad Serving Engine
    │
    ├── 1. Load active campaigns (status=active, budget remaining, schedule in range)
    │
    ├── 2. Filter by targeting (evaluate_targeting for each campaign)
    │       └── Also check creator ad prefs + block list
    │
    ├── 3. Filter by frequency cap (user hasn't exceeded impression limit)
    │
    ├── 4. Filter by budget (daily budget not exhausted, lifetime budget not exhausted)
    │
    ├── 5. Rank candidates: score = bid_cpm * relevance_factor
    │       └── relevance_factor = targeting match quality (mock: 1.0 in dev)
    │
    ├── 6. Select winner (highest score)
    │       └── If multiple creatives in campaign: weighted random by rotation_weight
    │
    ├── 7. If no winner: serve house ad or return empty
    │
    └── 8. Return creative + tracking URLs
            {
              creative_id, format, content (URLs/text),
              impression_url: "/api/ads/track?event=impression&...",
              click_url: "/api/ads/track?event=click&...",
              skip_url: "/api/ads/track?event=skip&..."
            }
```

### 1.5 Tracking Flow

```
Impression Tracking
───────────────────

Browser                          Backend                           DynamoDB
  │                                │                                  │
  │── [Ad becomes visible]         │                                  │
  │── POST /api/ads/track          │                                  │
  │   event=impression             │                                  │
  │                                │── write ad_impressions ─────────>│
  │                                │── increment frequency cap ──────>│
  │                                │── debit advertiser budget ──────>│
  │                                │── credit creator revenue ───────>│
  │                                │                                  │
  │── [User clicks ad]             │                                  │
  │── POST /api/ads/track          │                                  │
  │   event=click                  │                                  │
  │                                │── write click record ───────────>│
  │                                │── (CPC: additional charge) ─────>│
  │                                │                                  │
  │── [User skips ad]              │                                  │
  │── POST /api/ads/track          │                                  │
  │   event=skip                   │                                  │
  │                                │── write skip record ────────────>│
  │                                │── (no charge for skipped ads) ──>│
```

---

## 2. Current State Analysis

### 2.1 Existing Ad Placement (`app/services/ad_placement.py`)

The current `calculate_ad_slots()` function selects creatives by index from the hardcoded `DEV_AD_CREATIVES` list (see `app/services/ad_placement.py:25`). There is no campaign selection, no targeting evaluation, no frequency capping, and no budget checks. The `record_ad_impression()` function (see `app/services/ad_placement.py:222`) writes to `ad_impressions` (see `app/core/tables.py:93,217`) and credits creator revenue via `_credit_ad_revenue()` (line 279), but does not debit any advertiser.

ADS-004 replaces the creative selection logic but preserves the impression tracking and creator revenue crediting. The `record_ad_impression()` function is extended with advertiser debit.

### 2.2 Ad Impressions Table

The `ad_impressions` table (PK=`AD_IMP#{date}`, SK=`VIDEO#{video_id}#{user_id}#{ts}`) stores impression events with GSIs `ByVideoCreatedAt` and `ByCreatorCreatedAt`. This table is reused for all surfaces; the `slot_type` field distinguishes surface types (pre_roll, mid_roll, overlay, sponsored_post, broadcast_preroll, broadcast_midroll).

### 2.3 Frequency Cap Pattern

The platform's rate limiting (`app/services/rate_limiter.py`) uses a token bucket algorithm. Frequency capping follows a simpler pattern: a DDB record per user-campaign-window with a counter and TTL. When the counter exceeds the cap, the campaign is excluded for that user.

### 2.4 Gaps

1. **No ad selection algorithm** — creatives are hardcoded, not selected by campaign ranking.
2. **No frequency capping** — no limit on how often a user sees the same campaign.
3. **No budget pacing** — no mechanism to spread budget across the day.
4. **No fill rate tracking** — no visibility into unfilled ad slots.
5. **No house ads** — no fallback when no paid campaign matches.
6. **No advertiser debit** — impressions credit creators but don't charge advertisers.
7. **No unified serve endpoint** — each surface has its own ad logic (or none).

---

## 3. Technical Design

### 3.1 DynamoDB Table

#### `ad_frequency_caps` Table

| PK | SK | Fields | TTL |
|----|-----|--------|-----|
| `USER#{user_sub}` | `CAMPAIGN#{campaign_id}#{window}` | `count: int`, `campaign_id: str`, `window: str`, `expires_at: int` | `expires_at` |

Windows: `1h`, `24h`, `7d`. Each record tracks how many times a user has seen a campaign in that window. Records auto-expire via DDB TTL.

**`scripts/local-ddb-init.py`**:
```python
TableDef(
    os.environ.get("DDB_AD_FREQUENCY_CAPS", "AdFrequencyCaps"),
    "pk",
    "sk",
    ttl_attribute="expires_at",
),
```

### 3.2 DynamoDB Access Patterns

| Access Pattern | Table | PK | SK / GSI | Example |
|---|---|---|---|---|
| Get frequency cap for user+campaign+window | `ad_frequency_caps` | `USER#{user_sub}` | `CAMPAIGN#{campaign_id}#{window}` | GetItem |
| Increment frequency cap | `ad_frequency_caps` | `USER#{user_sub}` | `CAMPAIGN#{campaign_id}#{window}` | UpdateItem (atomic ADD) |
| List all caps for a user | `ad_frequency_caps` | `USER#{user_sub}` | begins_with(`CAMPAIGN#`) | Query |
| Load active campaigns | `ad_campaigns` | `ACCT#{account_id}` | `CAMPAIGN#{campaign_id}` | Scan with FilterExpression `status=active` |
| Get approved creatives | `ad_creatives` | `ACCT#{account_id}` | `CREATIVE#{creative_id}` | Query with filter `status=approved` |
| Write impression event | `ad_impressions` | `AD_IMP#{date}` | `VIDEO#{video_id}#{user_id}#{ts}` | PutItem |
| Get creator ad settings | `creator_ad_prefs` | `CREATOR#{creator_id}` | `SETTINGS` | GetItem |
| Check blocked advertiser | `creator_ad_prefs` | `CREATOR#{creator_id}` | `BLOCK#{account_id}` | GetItem |

#### Example DynamoDB Items (JSON)

**Frequency Cap Record**:
```json
{
  "pk": {"S": "USER#e2e_alice@test.local"},
  "sk": {"S": "CAMPAIGN#camp_abc123#1h"},
  "count": {"N": "2"},
  "campaign_id": {"S": "camp_abc123"},
  "window": {"S": "1h"},
  "expires_at": {"N": "1748541600"}
}
```

**Ad Impression Record**:
```json
{
  "pk": {"S": "AD_IMP#2026-05-29"},
  "sk": {"S": "VIDEO#vid_001#e2e_bob@test.local#1748534400"},
  "creative_id": {"S": "creat_xyz789"},
  "campaign_id": {"S": "camp_abc123"},
  "account_id": {"S": "acct_adv001"},
  "slot_type": {"S": "pre_roll"},
  "event_type": {"S": "impression"},
  "user_id": {"S": "e2e_bob@test.local"},
  "creator_id": {"S": "e2e_alice@test.local"},
  "surface": {"S": "vod"},
  "created_at": {"N": "1748534400"}
}
```

### 3.3 Backend Service

**File**: `app/services/ad_serving.py`

```python
"""Ad serving engine — selects and serves ads for all surfaces."""

import logging
import random
import uuid
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.ad_campaigns import list_campaigns_by_status
from app.services.ad_creatives import list_approved_creatives
from app.services.ad_targeting import evaluate_targeting, list_targeting_sets
from app.services.creator_ad_prefs import get_creator_ad_settings, is_advertiser_blocked
from app.services.ad_placement import record_ad_impression, DEV_AD_CREATIVES

logger = logging.getLogger(__name__)

# Frequency cap defaults
DEFAULT_FREQ_CAPS = {"1h": 3, "24h": 10, "7d": 30}
WINDOW_SECONDS = {"1h": 3600, "24h": 86400, "7d": 604800}

# House ad (platform self-promotion)
HOUSE_AD = {
    "creative_id": "house_ad_001",
    "format": "native_post",
    "title": "Discover more on this platform",
    "headline": "Explore creators you'll love",
    "body_text": "Find new content, connect with creators, and join the community.",
    "cta_text": "Explore",
    "cta_url": "/feed",
    "is_house_ad": True,
}


def serve_ad(
    *,
    surface: str,            # "newsfeed", "broadcast", "vod"
    content_type: str,       # "post", "broadcast_session", "video"
    creator_id: str,
    content_id: str,
    slot_type: str,          # "pre_roll", "mid_roll", "overlay", "sponsored_post"
    user_id: str,
    user_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Select and return the best ad for the given context."""
    ctx = user_context or {}
    ctx.update({
        "content_type": surface,
        "creator_id": creator_id,
    })

    # 1. Check creator allows ads
    creator_settings = get_creator_ad_settings(creator_id)
    if not creator_settings.get("allow_ads", True):
        return _empty_response("creator_ads_disabled")

    # 2. Load active campaigns
    active_campaigns = _get_active_campaigns()
    if not active_campaigns:
        return _house_ad_response("no_active_campaigns")

    # 3. Filter + score candidates
    candidates = []
    for campaign in active_campaigns:
        account_id = campaign["account_id"]

        # Creator block check
        if is_advertiser_blocked(creator_id, account_id):
            continue

        # Budget check
        if not _has_budget(campaign):
            continue

        # Targeting check
        targeting_sets = list_targeting_sets(campaign["campaign_id"])
        if targeting_sets and not any(evaluate_targeting(ts, ctx) for ts in targeting_sets):
            continue

        # Frequency cap check
        if _is_frequency_capped(user_id, campaign["campaign_id"]):
            continue

        # Get approved creatives
        creatives = list_approved_creatives(campaign["campaign_id"])
        if not creatives:
            continue

        # Score: bid_cpm * relevance (mock relevance = 1.0)
        bid_cpm = campaign.get("bid_cpm_cents", 500)
        score = bid_cpm * 1.0

        candidates.append({
            "campaign": campaign,
            "creatives": creatives,
            "score": score,
        })

    if not candidates:
        return _house_ad_response("no_eligible_campaigns")

    # 4. Select winner (highest score)
    candidates.sort(key=lambda c: c["score"], reverse=True)
    winner = candidates[0]

    # 5. Select creative (weighted random by rotation_weight)
    creative = _weighted_random_creative(winner["creatives"])

    # 6. Build tracking URLs
    tracking_base = f"/api/ads/track"
    tracking_params = (
        f"creative_id={creative['creative_id']}"
        f"&campaign_id={winner['campaign']['campaign_id']}"
        f"&account_id={winner['campaign']['account_id']}"
        f"&surface={surface}&slot_type={slot_type}"
        f"&content_id={content_id}&creator_id={creator_id}"
    )

    return {
        "filled": True,
        "creative_id": creative["creative_id"],
        "format": creative["format"],
        "title": creative.get("title", ""),
        "headline": creative.get("headline"),
        "body_text": creative.get("body_text"),
        "cta_text": creative.get("cta_text"),
        "cta_url": creative.get("cta_url"),
        "image_url": creative.get("image_url"),
        "video_url": creative.get("video_url"),
        "thumbnail_url": creative.get("thumbnail_url"),
        "skip_after_seconds": creative.get("skip_after_seconds", 5),
        "impression_url": f"{tracking_base}?event=impression&{tracking_params}",
        "click_url": f"{tracking_base}?event=click&{tracking_params}",
        "skip_url": f"{tracking_base}?event=skip&{tracking_params}",
        "is_house_ad": False,
        "campaign_id": winner["campaign"]["campaign_id"],
        "promo_code_id": creative.get("promo_code_id"),
        "affiliate_link_id": creative.get("affiliate_link_id"),
    }


def track_ad_event(
    *,
    event: str,          # "impression", "click", "skip", "complete"
    creative_id: str,
    campaign_id: str,
    account_id: str,
    surface: str,
    slot_type: str,
    content_id: str,
    creator_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Record an ad event and process billing."""
    # Record impression in ad_impressions table
    result = record_ad_impression(
        video_id=content_id,
        user_id=user_id,
        slot_type=slot_type,
        slot_index=0,
        creative_id=creative_id,
        event_type=event,
    )

    # Update frequency cap on impression
    if event == "impression":
        _increment_frequency_cap(user_id, campaign_id)

    return {"ok": True, "event_id": result.get("event_id", "")}


def _get_active_campaigns() -> list[dict]:
    """Get all active campaigns."""
    from app.services.ad_campaigns import list_campaigns_by_status
    return list_campaigns_by_status("active")

def _has_budget(campaign: dict) -> bool:
    budget = campaign.get("budget_cents", 0)
    spent = campaign.get("lifetime_spent_cents", 0)
    if campaign.get("budget_type") == "lifetime" and spent >= budget:
        return False
    if campaign.get("budget_type") == "daily":
        daily_spent = campaign.get("spent_today_cents", 0)
        if daily_spent >= budget:
            return False
    return True

def _is_frequency_capped(user_id: str, campaign_id: str) -> bool:
    for window, max_count in DEFAULT_FREQ_CAPS.items():
        resp = T.ad_frequency_caps.get_item(
            Key={"pk": f"USER#{user_id}", "sk": f"CAMPAIGN#{campaign_id}#{window}"}
        )
        item = resp.get("Item")
        if item and int(item.get("count", 0)) >= max_count:
            return True
    return False

def _increment_frequency_cap(user_id: str, campaign_id: str) -> None:
    ts = now_ts()
    for window, ttl_seconds in WINDOW_SECONDS.items():
        T.ad_frequency_caps.update_item(
            Key={"pk": f"USER#{user_id}", "sk": f"CAMPAIGN#{campaign_id}#{window}"},
            UpdateExpression="SET #c = if_not_exists(#c, :z) + :one, expires_at = :exp, campaign_id = :cid, #w = :w",
            ExpressionAttributeNames={"#c": "count", "#w": "window"},
            ExpressionAttributeValues={
                ":z": 0, ":one": 1,
                ":exp": ts + ttl_seconds,
                ":cid": campaign_id,
                ":w": window,
            },
        )

def _weighted_random_creative(creatives: list[dict]) -> dict:
    if len(creatives) == 1:
        return creatives[0]
    weights = [c.get("rotation_weight", 50) for c in creatives]
    total = sum(weights)
    if total == 0:
        return random.choice(creatives)
    return random.choices(creatives, weights=weights, k=1)[0]

def _house_ad_response(reason: str) -> dict:
    return {"filled": True, "is_house_ad": True, **HOUSE_AD, "fill_reason": reason}

def _empty_response(reason: str) -> dict:
    return {"filled": False, "is_house_ad": False, "fill_reason": reason}
```

### 3.4 Pydantic Models

**File**: `app/models.py`

```python
# -- Ad Serving (ADS-004) --

class AdServeRequestIn(BaseModel):
    """Request body for POST /ui/ads/serve."""
    surface: str = Field(..., pattern="^(newsfeed|broadcast|vod)$",
                         description="Ad surface: newsfeed, broadcast, or vod")
    content_type: str = Field(default="",
                              description="Content type: post, broadcast_session, video")
    creator_id: str = Field(..., min_length=1,
                            description="Creator who owns the content being viewed")
    content_id: str = Field(..., min_length=1,
                            description="ID of the content item (post_id, video_id, etc.)")
    slot_type: str = Field(default="sponsored_post",
                           pattern="^(pre_roll|mid_roll|overlay|sponsored_post|broadcast_preroll|broadcast_midroll)$",
                           description="Type of ad slot within the surface")
    user_context: Optional[Dict[str, Any]] = Field(default=None,
                                                    description="Additional viewer context for targeting")

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "surface": "newsfeed",
            "creator_id": "user_creator_abc",
            "content_id": "post_12345",
            "slot_type": "sponsored_post",
            "user_context": {"geo": "US", "device": "mobile"}
        }
    })


class AdServeResponseOut(BaseModel):
    """Response from POST /ui/ads/serve."""
    filled: bool
    creative_id: Optional[str] = None
    format: Optional[str] = None
    title: str = ""
    headline: Optional[str] = None
    body_text: Optional[str] = None
    cta_text: Optional[str] = None
    cta_url: Optional[str] = None
    image_url: Optional[str] = None
    video_url: Optional[str] = None
    thumbnail_url: Optional[str] = None
    skip_after_seconds: int = 5
    impression_url: Optional[str] = None
    click_url: Optional[str] = None
    skip_url: Optional[str] = None
    is_house_ad: bool = False
    campaign_id: Optional[str] = None
    promo_code_id: Optional[str] = None
    affiliate_link_id: Optional[str] = None
    fill_reason: Optional[str] = None


class AdTrackEventIn(BaseModel):
    """Query parameters for POST /ui/ads/track."""
    event: str = Field(..., pattern="^(impression|click|skip|complete)$")
    creative_id: str = Field(..., min_length=1)
    campaign_id: str = Field(..., min_length=1)
    account_id: str = Field(..., min_length=1)
    surface: str = Field(..., min_length=1)
    slot_type: str = Field(..., min_length=1)
    content_id: str = Field(..., min_length=1)
    creator_id: str = Field(..., min_length=1)


class AdTrackEventOut(BaseModel):
    """Response from POST /ui/ads/track."""
    ok: bool
    event_id: str = ""
```

### 3.5 Backend Router

**File**: `app/routers/ads.py` (extend)

```python
# ── Ad Serving (public-ish, requires auth) ──

@router.post("/serve")
def serve_ad_endpoint(body: dict, ctx=Depends(require_ui_session)):
    result = serve_ad(
        surface=body["surface"],
        content_type=body.get("content_type", body["surface"]),
        creator_id=body["creator_id"],
        content_id=body["content_id"],
        slot_type=body.get("slot_type", "sponsored_post"),
        user_id=ctx["user_sub"],
        user_context=body.get("user_context"),
    )
    return result

@router.post("/track")
def track_ad_event_endpoint(
    event: str, creative_id: str, campaign_id: str, account_id: str,
    surface: str, slot_type: str, content_id: str, creator_id: str,
    ctx=Depends(require_ui_session),
):
    return track_ad_event(
        event=event, creative_id=creative_id, campaign_id=campaign_id,
        account_id=account_id, surface=surface, slot_type=slot_type,
        content_id=content_id, creator_id=creator_id, user_id=ctx["user_sub"],
    )
```

### 3.6 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface AdServeRequest {
  surface: "newsfeed" | "broadcast" | "vod";
  content_type?: string;
  creator_id: string;
  content_id: string;
  slot_type?: string;
  user_context?: Record<string, unknown>;
}

export interface AdServeResponse {
  filled: boolean;
  creative_id?: string;
  format?: string;
  title?: string;
  headline?: string | null;
  body_text?: string | null;
  cta_text?: string | null;
  cta_url?: string | null;
  image_url?: string | null;
  video_url?: string | null;
  thumbnail_url?: string | null;
  skip_after_seconds?: number;
  impression_url?: string;
  click_url?: string;
  skip_url?: string;
  is_house_ad: boolean;
  campaign_id?: string;
  promo_code_id?: string | null;
  affiliate_link_id?: string | null;
  fill_reason?: string;
}
```

### 3.7 Frontend API

**File**: `frontend/src/api/endpoints/ads.ts` (extend)

```typescript
export const serveAd = (data: AdServeRequest) =>
  api.post<AdServeResponse>("/ui/ads/serve", data);

export const trackAdEvent = (params: Record<string, string>) =>
  api.post("/ui/ads/track", null, { params });
```

### 3.8 Frontend Component Tree

```
AdSlot (shared wrapper)
├── Props: { surface, contentType, creatorId, contentId, slotType }
├── State: useQuery(["ad-serve", contentId], () => serveAd({...}))
├── Effect: on mount, fire impression tracking via trackAdEvent
│
├── AdCreativeRender
│   ├── Props: { creative: AdServeResponse, onImpression, onClick, onSkip }
│   │
│   ├── ImageAdCreative
│   │   ├── <img src={image_url} />
│   │   └── PromoBadge (if promo_code_id)
│   │
│   ├── VideoAdCreative
│   │   ├── <video src={video_url} autoPlay />
│   │   ├── SkipButton (appears after skip_after_seconds)
│   │   └── ProgressBar (video duration countdown)
│   │
│   └── NativePostAdCreative
│       ├── <h3>{title}</h3>
│       ├── <p>{body_text}</p>
│       ├── <Button>{cta_text}</Button>
│       └── "Promoted" badge (text-xs text-muted-foreground)
│
├── HouseAdFallback
│   ├── Renders HOUSE_AD content when is_house_ad=true
│   └── "Promoted" badge
│
└── EmptyAdSlot
    └── Renders nothing (filled=false, no house ad)

PostCard (newsfeed integration, ADS-005)
├── Existing post content
└── AdSlot (inserted between posts at position intervals)

BroadcastPlayer (broadcast integration, ADS-006)
├── Existing broadcast stream
├── PreRollAdSlot (before stream starts)
└── MidRollAdSlot (during ad breaks)

VODPlayer (video integration)
├── Existing video player
├── PreRollAdSlot (before video plays)
├── MidRollAdSlot (at configured breakpoints)
└── OverlayAdSlot (non-blocking overlay during playback)
```

---

## 4. API Request/Response Examples

### 4.1 Serve Ad

```bash
# Serve an ad for a newsfeed post
curl -X POST http://localhost:8000/ui/ads/serve \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_abc123; ui_access_token=eyJ...; ui_csrf=tok_csrf_001" \
  -H "x-csrf-token: tok_csrf_001" \
  -d '{
    "surface": "newsfeed",
    "creator_id": "e2e_alice@test.local",
    "content_id": "post_12345",
    "slot_type": "sponsored_post",
    "user_context": {"geo": "US", "device": "mobile"}
  }'

# Response (200 OK — paid ad served)
{
  "filled": true,
  "creative_id": "creat_xyz789",
  "format": "native_post",
  "title": "Try Premium Today",
  "headline": "Unlock all features",
  "body_text": "Get 30 days free with code WELCOME30",
  "cta_text": "Start Free Trial",
  "cta_url": "https://example.com/trial?ref=ABC123",
  "image_url": "https://cdn.example.com/ads/premium-banner.png",
  "video_url": null,
  "thumbnail_url": null,
  "skip_after_seconds": 5,
  "impression_url": "/api/ads/track?event=impression&creative_id=creat_xyz789&campaign_id=camp_abc123&account_id=acct_adv001&surface=newsfeed&slot_type=sponsored_post&content_id=post_12345&creator_id=e2e_alice@test.local",
  "click_url": "/api/ads/track?event=click&creative_id=creat_xyz789&campaign_id=camp_abc123&account_id=acct_adv001&surface=newsfeed&slot_type=sponsored_post&content_id=post_12345&creator_id=e2e_alice@test.local",
  "skip_url": "/api/ads/track?event=skip&creative_id=creat_xyz789&campaign_id=camp_abc123&account_id=acct_adv001&surface=newsfeed&slot_type=sponsored_post&content_id=post_12345&creator_id=e2e_alice@test.local",
  "is_house_ad": false,
  "campaign_id": "camp_abc123",
  "promo_code_id": "promo_welcome30",
  "affiliate_link_id": "aff_ABC123"
}

# Response (200 OK — house ad served, no paid campaign matched)
{
  "filled": true,
  "creative_id": "house_ad_001",
  "format": "native_post",
  "title": "Discover more on this platform",
  "headline": "Explore creators you'll love",
  "body_text": "Find new content, connect with creators, and join the community.",
  "cta_text": "Explore",
  "cta_url": "/feed",
  "is_house_ad": true,
  "fill_reason": "no_eligible_campaigns"
}

# Response (200 OK — empty, creator disabled ads)
{
  "filled": false,
  "is_house_ad": false,
  "fill_reason": "creator_ads_disabled"
}
```

### 4.2 Track Ad Event

```bash
# Track an impression
curl -X POST "http://localhost:8000/ui/ads/track?event=impression&creative_id=creat_xyz789&campaign_id=camp_abc123&account_id=acct_adv001&surface=newsfeed&slot_type=sponsored_post&content_id=post_12345&creator_id=e2e_alice@test.local" \
  -H "Cookie: ui_session=sess_abc123; ui_access_token=eyJ...; ui_csrf=tok_csrf_001" \
  -H "x-csrf-token: tok_csrf_001"

# Response (200 OK)
{
  "ok": true,
  "event_id": "evt_1748534400_creat_xyz789"
}

# Track a click
curl -X POST "http://localhost:8000/ui/ads/track?event=click&creative_id=creat_xyz789&campaign_id=camp_abc123&account_id=acct_adv001&surface=newsfeed&slot_type=sponsored_post&content_id=post_12345&creator_id=e2e_alice@test.local" \
  -H "Cookie: ui_session=sess_abc123; ui_access_token=eyJ...; ui_csrf=tok_csrf_001" \
  -H "x-csrf-token: tok_csrf_001"

# Response (200 OK)
{
  "ok": true,
  "event_id": "evt_1748534405_creat_xyz789"
}
```

---

## 5. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Missing required `surface` in serve request | 422 | `validation_error` | "surface is required" | Fix request body |
| Missing required `creator_id` in serve request | 422 | `validation_error` | "creator_id is required" | Fix request body |
| Missing required `content_id` in serve request | 422 | `validation_error` | "content_id is required" | Fix request body |
| Invalid surface value (not newsfeed/broadcast/vod) | 422 | `validation_error` | "surface must be newsfeed, broadcast, or vod" | Fix surface value |
| Invalid event type in track request | 400 | `invalid_event` | "Invalid event type; must be impression, click, skip, or complete" | Fix event parameter |
| Creative not found during tracking | 200 | — | (best-effort; still records event) | Log warning; no user action needed |
| DDB write failure for frequency cap | 200 | — | (best-effort; serve continues) | Log warning; cap may be inaccurate |
| DDB write failure for impression record | 500 | `internal_error` | "Failed to record ad event" | Retry the request |
| All campaigns exhausted (budget or frequency) | 200 | — | House ad served with `fill_reason` | No action; platform serves house ad |
| Creator has ads disabled | 200 | — | Empty response with `fill_reason: "creator_ads_disabled"` | No action; ad slot remains empty |
| No active campaigns in system | 200 | — | House ad served with `fill_reason: "no_active_campaigns"` | Advertiser needs to activate campaigns |
| Session expired / authentication failure | 401 | `unauthorized` | "Session expired" | Re-authenticate |
| CSRF token mismatch | 403 | `csrf_invalid` | "Invalid CSRF token" | Refresh page to get new CSRF token |
| Rate limit exceeded on serve endpoint | 429 | `rate_limited` | "Too many requests" | Wait and retry |
| Advertiser blocked by creator | 200 | — | Campaign excluded from candidates (transparent to viewer) | Advertiser contacts creator or targets different content |

---

## 6. Implementation Plan

### 6.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_serving.py` | Core ad selection + serving engine |

### 6.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/ads.py` | Add `/serve` and `/track` endpoints |
| `app/services/ad_placement.py` | Integrate with serving engine (fallback to dev creatives when no campaigns) |
| `app/core/settings.py` | Add `ad_frequency_caps_table_name` |
| `app/core/tables.py` | Add `ad_frequency_caps` table handle |
| `scripts/local-ddb-init.py` | Add `AdFrequencyCaps` table definition with TTL |
| `frontend/src/api/types.ts` | Add `AdServeRequest`, `AdServeResponse` types |
| `frontend/src/api/endpoints/ads.ts` | Add `serveAd`, `trackAdEvent` functions |
| `app/models.py` | Add `AdServeRequestIn`, `AdServeResponseOut`, `AdTrackEventIn`, `AdTrackEventOut` |

### 6.3 Step-by-Step Order

1. Add DDB table definition with TTL
2. Add settings + table handle
3. Add Pydantic models to `app/models.py`
4. Implement `ad_serving.py` service
5. Add serve/track endpoints to router
6. Update `ad_placement.py` to delegate to serving engine
7. Add frontend types + API endpoints
8. Write E2E tests

---

## 7. E2E Test Plan

### 7.1 Test File

`frontend/e2e/ads-serving.spec.ts` — 30 tests across 7 sections.

### 7.2 Test Setup

```typescript
const TS = Date.now();
let accountId: string;
let campaignId: string;
let campaignId2: string;
let creativeId: string;
let creativeId2: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice (advertiser), Bob (viewer/creator), Root (admin)
  // Create ad account + campaign + creative + targeting
  // Approve account, campaign, creative (all must be active/approved)
  // Create a second campaign with lower bid for ranking tests
  // Create a second creative with different rotation_weight
});
```

### 7.3 Section 354: Ad Serve Endpoint (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 354.1 | Serve ad with matching campaign | POST `/ui/ads/serve` with valid context; 200; `filled=true`, creative_id present |
| 354.2 | Serve returns tracking URLs | Response has `impression_url`, `click_url`, `skip_url` with query params |
| 354.3 | No active campaigns returns house ad | Pause all campaigns; POST serve; `is_house_ad=true` |
| 354.4 | Creator with ads disabled returns empty | Set Bob allow_ads=false; POST serve for Bob's content; `filled=false` |
| 354.5 | Blocked advertiser excluded | Bob blocks Alice's account; POST serve; house ad or empty (not Alice's creative) |

### 7.4 Section 355: Frequency Capping (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 355.1 | First impression under cap | POST serve; filled=true; track impression event |
| 355.2 | Multiple impressions tracked | Track 3 impressions; all succeed |
| 355.3 | Frequency cap triggers after limit | Track impressions until 1h cap (3); next serve returns different campaign or house ad |
| 355.4 | Frequency cap record has TTL | DDB record has `expires_at` field set to future timestamp |

### 7.5 Section 356: Budget Pacing (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 356.1 | Campaign with remaining budget serves | Campaign with budget_cents=10000, lifetime_spent=0; serve returns creative |
| 356.2 | Exhausted lifetime budget stops serving | Set lifetime_spent_cents >= budget_cents; serve excludes this campaign |
| 356.3 | Exhausted daily budget stops serving | Set spent_today_cents >= daily_budget_cents; serve excludes this campaign |

### 7.6 Section 357: Ad Tracking Events (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 357.1 | Track impression event | POST `/ui/ads/track?event=impression&...`; 200; `ok=true`, `event_id` present |
| 357.2 | Track click event | POST with event=click; 200; ok=true |
| 357.3 | Track skip event | POST with event=skip; 200; ok=true |
| 357.4 | Impression writes to ad_impressions table | After tracking, query ad_impressions; record exists with correct fields |

### 7.7 Section 358: Creative Selection (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 358.1 | Single creative always selected | Campaign with 1 creative; serve returns that creative_id |
| 358.2 | Weighted rotation distributes across creatives | Campaign with 2 creatives (weight 80/20); 10 serves; both creative_ids appear |
| 358.3 | Only approved creatives served | Add draft creative; serve never returns draft creative_id |
| 358.4 | Creative with promo_code_id returned | Serve returns `promo_code_id` from creative |

### 7.8 Section 359: Input Validation & Edge Cases (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 359.1 | Missing surface returns 422 | POST with empty surface; 422 validation error |
| 359.2 | Invalid surface value returns 422 | POST with `surface: "unknown"`; 422 |
| 359.3 | Missing creator_id returns 422 | POST without creator_id; 422 |
| 359.4 | Invalid track event type returns 400 | POST `/ui/ads/track?event=invalid_event&...`; 400 |
| 359.5 | Unauthenticated request returns 401 | POST `/ui/ads/serve` without session cookies; 401 |

### 7.9 Section 360: Concurrent Access & Campaign Ranking (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 360.1 | Higher bid campaign wins over lower bid | Campaign A (bid_cpm=1000) vs Campaign B (bid_cpm=500); serve returns Campaign A creative |
| 360.2 | Equal bid campaigns both serve across requests | Two campaigns with same bid_cpm; 10 serves; both campaign_ids appear (non-deterministic ranking tiebreak) |
| 360.3 | Concurrent serve requests return consistent results | Fire 5 parallel serve requests; all return filled=true; frequency caps update atomically |
| 360.4 | House ad fields are complete | When house ad is served, response includes title, headline, body_text, cta_text, cta_url |
| 360.5 | Serve endpoint latency under 200ms | Time 10 sequential serve calls; average latency < 200ms |

---

## 8. Observability & Monitoring

### 8.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ad_serve_requests_total` | Counter | `surface`, `slot_type`, `result` (filled/house/empty) | Total ad serve requests by outcome |
| `ad_serve_latency_seconds` | Histogram | `surface` | Latency of serve_ad() calls |
| `ad_track_events_total` | Counter | `event` (impression/click/skip/complete), `surface` | Total tracking events by type |
| `ad_frequency_cap_hits_total` | Counter | — | Number of times a campaign was excluded due to frequency cap |
| `ad_budget_exhausted_total` | Counter | — | Number of times a campaign was excluded due to budget exhaustion |
| `ad_fill_rate` | Gauge | `surface` | Percentage of serve requests that returned a paid ad (not house ad) |
| `ad_candidates_per_request` | Histogram | `surface` | Number of eligible campaigns after filtering per serve call |

### 8.2 Log Events

| Event | Level | Fields | Description |
|-------|-------|--------|-------------|
| `ad_serve_complete` | INFO | `surface`, `slot_type`, `filled`, `is_house_ad`, `campaign_id`, `creative_id`, `latency_ms` | Logged on every serve request completion |
| `ad_serve_empty` | INFO | `surface`, `slot_type`, `fill_reason` | Logged when no ad is served (empty response) |
| `ad_serve_house_ad` | INFO | `surface`, `slot_type`, `fill_reason` | Logged when house ad is served as fallback |
| `ad_track_event` | INFO | `event`, `creative_id`, `campaign_id`, `user_id` | Logged on every tracking event |
| `ad_frequency_cap_hit` | DEBUG | `user_id`, `campaign_id`, `window`, `count`, `max_count` | Logged when a user hits frequency cap for a campaign |
| `ad_budget_exhausted` | WARN | `campaign_id`, `budget_type`, `budget_cents`, `spent_cents` | Logged when a campaign's budget is fully consumed |
| `ad_freq_cap_write_failed` | WARN | `user_id`, `campaign_id`, `error` | Logged when frequency cap DDB write fails |

### 8.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Low fill rate | `ad_fill_rate < 0.3` for 15 minutes on any surface | Warning | Investigate campaign pipeline; check if campaigns are paused/exhausted |
| High serve latency | `p99(ad_serve_latency_seconds) > 0.5` for 5 minutes | Warning | Check DDB read latency; consider caching active campaigns |
| Zero serves | `rate(ad_serve_requests_total[5m]) == 0` during business hours | Critical | Verify frontend is making serve calls; check routing/proxy |
| Frequency cap write failures | `rate(ad_freq_cap_write_failed[5m]) > 10` | Warning | Check DDB table capacity; verify table exists |

---

## 9. Rollout Plan

### 9.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `AD_SERVING_ENABLED` | `false` | Master switch: when false, `/ui/ads/serve` returns empty response |
| `AD_SERVING_HOUSE_ADS_ENABLED` | `true` | When true, unfilled slots return house ads; when false, return empty |
| `AD_FREQUENCY_CAPPING_ENABLED` | `true` | When false, skip frequency cap checks (useful for testing) |

### 9.2 Migration Steps

1. **Phase 1 — Table creation**: Deploy `scripts/local-ddb-init.py` change to create `AdFrequencyCaps` table. No application changes.
2. **Phase 2 — Backend service**: Deploy `ad_serving.py` with `AD_SERVING_ENABLED=false`. Service code is deployed but dormant.
3. **Phase 3 — Shadow mode**: Enable serving for 1% of requests (randomly selected). Log results but don't return to frontend. Compare with existing hardcoded logic.
4. **Phase 4 — Gradual rollout**: Enable `AD_SERVING_ENABLED=true` for 10% -> 50% -> 100% of users over 1 week.
5. **Phase 5 — Legacy removal**: Remove hardcoded `DEV_AD_CREATIVES` selection logic from `ad_placement.py`.

### 9.3 Rollback Procedure

1. Set `AD_SERVING_ENABLED=false` — immediately falls back to existing `ad_placement.py` logic.
2. If frequency cap table has issues, set `AD_FREQUENCY_CAPPING_ENABLED=false` to skip cap checks without disabling serving.
3. No DDB data migration needed for rollback — frequency cap records auto-expire via TTL.

---

## 10. Performance Considerations

### 10.1 Latency Budget

| Operation | Target Latency | Approach |
|-----------|---------------|----------|
| Load active campaigns | < 50ms | Cache campaign list for 30 seconds (in-memory TTL cache) |
| Evaluate targeting per campaign | < 5ms each | Pre-filter by surface/slot_type before full targeting eval |
| Frequency cap check (3 GetItems) | < 30ms | Batch GetItem using `batch_get_item` for all 3 windows |
| Budget check | < 1ms | Denormalized budget fields already on campaign record |
| Creative selection | < 1ms | In-memory weighted random |
| **Total serve_ad() target** | **< 100ms** | |

### 10.2 Caching Strategy

- **Active campaigns**: Cache in-memory for 30 seconds. Campaign status changes (pause, budget exhaustion) take up to 30 seconds to take effect. Acceptable trade-off for latency.
- **Creator ad settings**: Cache per creator_id for 60 seconds. Settings change infrequently.
- **Targeting rule sets**: Cache per campaign_id for 60 seconds. Targeting rules are updated infrequently during a campaign's lifetime.
- **Frequency caps**: NOT cached. Must always read from DDB for accuracy. Batch GetItem reduces round trips.

### 10.3 Pagination & Rate Limits

- **Serve endpoint**: Rate limited to 60 req/min per user (matches page scroll rate).
- **Track endpoint**: Rate limited to 120 req/min per user (impression + click can fire simultaneously).
- **Campaign scan**: `list_campaigns_by_status("active")` scans the campaigns table. At scale (>10,000 campaigns), add a GSI on `status` with `created_at` sort key to avoid full table scan. For MVP with < 500 campaigns, scan is acceptable.

### 10.4 DynamoDB Capacity

- **Frequency caps table**: Write-heavy (one UpdateItem per impression per 3 windows = 3 WCUs per impression). At 1000 impressions/second = 3000 WCUs. TTL auto-deletes expired records.
- **Ad impressions table**: One PutItem per event = 1 WCU per event. Partitioned by date in PK to distribute hot keys.
- **Estimated monthly DDB cost at 1M impressions/day**: ~$15/month (on-demand pricing).

---

## 11. Security Considerations

- Ad serve endpoint requires authentication (no anonymous ad requests)
- Tracking URLs include all context params in query string (not user-modifiable in meaningful ways)
- Frequency cap records are per-user, per-campaign — no cross-user leakage
- Budget deductions are atomic (DDB update expression with increment)
- House ads are always safe fallback (no external content)
- Tracking event injection is mitigated by session auth — cannot fire fake impressions without a valid session
- Creative content (image_url, video_url) is served from the platform's CDN or S3 — no arbitrary external URLs

---

## 12. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-001 | Advertiser accounts + campaigns | Required |
| ADS-002 | Approved creatives | Required |
| ADS-003 | Targeting evaluation + creator prefs | Required |

### 12.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| ADS-005 (Sponsored Posts) | `serve_ad(surface="newsfeed")` |
| ADS-006 (Broadcast Ads) | `serve_ad(surface="broadcast")` |
| ADS-007 (Billing) | `track_ad_event()` triggers billing |
| ADS-008 (Analytics) | Impression/click data from tracking |
| ADS-009 (User Ad Preferences) | User ad pref tier checked during serve |
| ADS-015 (Affiliate/Promo) | `promo_code_id` and `affiliate_link_id` fields on serve response |

---

## 13. Acceptance Criteria

1. `POST /ui/ads/serve` selects the highest-scoring eligible campaign and returns the creative with tracking URLs.
2. Frequency capping limits impressions per user per campaign per window (1h: 3, 24h: 10, 7d: 30).
3. Budget-exhausted campaigns are excluded from serving.
4. Unfilled slots return house ads or empty responses (never errors).
5. `POST /ui/ads/track` records impression, click, skip, and complete events.
6. Frequency cap records auto-expire via DDB TTL.
7. Creative rotation distributes impressions across creatives by `rotation_weight`.
8. Creator ad preferences (allow_ads, block list) are respected.
9. All 30 E2E tests pass in `frontend/e2e/ads-serving.spec.ts`.
10. Serve endpoint p99 latency < 200ms under normal load.

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/ad_placement.py` | 25, 178, 222, 279 | Existing: `DEV_AD_CREATIVES` (line 25), `get_ad_config` (line 178), `record_ad_impression` (line 222), `_credit_ad_revenue` (line 279) |
| `app/core/tables.py` | 93, 217 | Existing `ad_impressions` table handle |
| `app/core/settings.py` | 1242 | Existing `ad_impressions_table_name` setting |
| `scripts/local-ddb-init.py` | 832 | Existing `AdImpressions` table definition |
| `app/services/ad_serving.py` | — | Does not exist yet — new implementation required |
| `ad_frequency_caps` DDB table | — | Does not exist yet — new implementation required |
