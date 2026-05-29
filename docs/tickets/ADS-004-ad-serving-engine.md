# ADS-004: Ad Serving Engine

**Ticket**: ADS-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Dependencies**: ADS-001 (Accounts), ADS-002 (Creatives), ADS-003 (Targeting)

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

### 1.3 Ad Serving Flow

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

### 1.4 Tracking Flow

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

The current `calculate_ad_slots()` function (line 116) selects creatives by index from the hardcoded `DEV_AD_CREATIVES` list. There is no campaign selection, no targeting evaluation, no frequency capping, and no budget checks. The `record_ad_impression()` function (line 222) writes to `ad_impressions` and credits creator revenue, but does not debit any advertiser.

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

### 3.2 Backend Service

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

### 3.3 Backend Router

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

### 3.4 Frontend Types

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

### 3.5 Frontend API

**File**: `frontend/src/api/endpoints/ads.ts` (extend)

```typescript
export const serveAd = (data: AdServeRequest) =>
  api.post<AdServeResponse>("/ui/ads/serve", data);

export const trackAdEvent = (params: Record<string, string>) =>
  api.post("/ui/ads/track", null, { params });
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_serving.py` | Core ad selection + serving engine |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/ads.py` | Add `/serve` and `/track` endpoints |
| `app/services/ad_placement.py` | Integrate with serving engine (fallback to dev creatives when no campaigns) |
| `app/core/settings.py` | Add `ad_frequency_caps_table_name` |
| `app/core/tables.py` | Add `ad_frequency_caps` table handle |
| `scripts/local-ddb-init.py` | Add `AdFrequencyCaps` table definition with TTL |
| `frontend/src/api/types.ts` | Add `AdServeRequest`, `AdServeResponse` types |
| `frontend/src/api/endpoints/ads.ts` | Add `serveAd`, `trackAdEvent` functions |

### 4.3 Step-by-Step Order

1. Add DDB table definition with TTL
2. Add settings + table handle
3. Implement `ad_serving.py` service
4. Add serve/track endpoints to router
5. Update `ad_placement.py` to delegate to serving engine
6. Add frontend types + API endpoints
7. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/ads-serving.spec.ts` — 20 tests across 5 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let accountId: string;
let campaignId: string;
let creativeId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice (advertiser), Bob (viewer/creator), Root (admin)
  // Create ad account + campaign + creative + targeting
  // Approve account, campaign, creative (all must be active/approved)
});
```

### 5.3 Section 354: Ad Serve Endpoint (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 354.1 | Serve ad with matching campaign | POST `/ui/ads/serve` with valid context; 200; `filled=true`, creative_id present |
| 354.2 | Serve returns tracking URLs | Response has `impression_url`, `click_url`, `skip_url` with query params |
| 354.3 | No active campaigns returns house ad | Pause all campaigns; POST serve; `is_house_ad=true` |
| 354.4 | Creator with ads disabled returns empty | Set Bob allow_ads=false; POST serve for Bob's content; `filled=false` |
| 354.5 | Blocked advertiser excluded | Bob blocks Alice's account; POST serve; house ad or empty (not Alice's creative) |

### 5.4 Section 355: Frequency Capping (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 355.1 | First impression under cap | POST serve; filled=true; track impression event |
| 355.2 | Multiple impressions tracked | Track 3 impressions; all succeed |
| 355.3 | Frequency cap triggers after limit | Track impressions until 1h cap (3); next serve returns different campaign or house ad |
| 355.4 | Frequency cap record has TTL | DDB record has `expires_at` field set to future timestamp |

### 5.5 Section 356: Budget Pacing (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 356.1 | Campaign with remaining budget serves | Campaign with budget_cents=10000, lifetime_spent=0; serve returns creative |
| 356.2 | Exhausted lifetime budget stops serving | Set lifetime_spent_cents >= budget_cents; serve excludes this campaign |
| 356.3 | Exhausted daily budget stops serving | Set spent_today_cents >= daily_budget_cents; serve excludes this campaign |

### 5.6 Section 357: Ad Tracking Events (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 357.1 | Track impression event | POST `/ui/ads/track?event=impression&...`; 200; `ok=true`, `event_id` present |
| 357.2 | Track click event | POST with event=click; 200; ok=true |
| 357.3 | Track skip event | POST with event=skip; 200; ok=true |
| 357.4 | Impression writes to ad_impressions table | After tracking, query ad_impressions; record exists with correct fields |

### 5.7 Section 358: Creative Selection (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 358.1 | Single creative always selected | Campaign with 1 creative; serve returns that creative_id |
| 358.2 | Weighted rotation distributes across creatives | Campaign with 2 creatives (weight 80/20); 10 serves; both creative_ids appear |
| 358.3 | Only approved creatives served | Add draft creative; serve never returns draft creative_id |
| 358.4 | Creative with promo_code_id returned | Serve returns `promo_code_id` from creative |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Missing required serve params | 422 | Pydantic validation |
| Invalid event type | 400 | "Invalid event type" |
| Creative not found during tracking | 200 | Best-effort; log warning, still record event |
| DDB write failure for frequency cap | 200 | Best-effort; log warning, don't fail the serve |

---

## 7. Security Considerations

- Ad serve endpoint requires authentication (no anonymous ad requests)
- Tracking URLs include all context params in query string (not user-modifiable in meaningful ways)
- Frequency cap records are per-user, per-campaign — no cross-user leakage
- Budget deductions are atomic (DDB update expression with increment)
- House ads are always safe fallback (no external content)

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-001 | Advertiser accounts + campaigns | Required |
| ADS-002 | Approved creatives | Required |
| ADS-003 | Targeting evaluation + creator prefs | Required |

### 8.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| ADS-005 (Sponsored Posts) | `serve_ad(surface="newsfeed")` |
| ADS-006 (Broadcast Ads) | `serve_ad(surface="broadcast")` |
| ADS-007 (Billing) | `track_ad_event()` triggers billing |
| ADS-008 (Analytics) | Impression/click data from tracking |
