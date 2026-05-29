# ADS-010: Content Provider Ad Controls

**Ticket**: ADS-010
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 6-8 days
**Dependencies**: ADS-003 (Targeting — creator ad prefs), ADS-004 (Ad Serving), ADS-007 (Billing — revenue split)

---

## 1. Overview & Motivation

### 1.1 Purpose

ADS-010 gives content creators (content providers) granular control over advertising on their content. Creators can configure global ad settings, per-content ad overrides, block specific advertisers, set minimum CPM requirements, and view their ad revenue breakdown. This ticket extends the basic creator ad preferences from ADS-003 into a complete content provider ad management system.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to enable or disable ads globally on my content. | Global `allow_ads` toggle in creator settings. |
| Creator | As a creator, I want to choose which ad categories appear on my content. | Category whitelist; only allowed categories served. |
| Creator | As a creator, I want to set a minimum CPM to maximize revenue. | Ads with bid below my minimum are not served on my content. |
| Creator | As a creator, I want to enable/disable ads per post, video, or broadcast. | Per-content `ad_enabled` toggle overrides global setting. |
| Creator | As a creator, I want to see which advertisers ran ads on my content. | Transparency page listing advertiser accounts + spend. |
| Creator | As a creator, I want to block specific advertisers from my content. | Block by account ID; blocked ads never served. |
| Creator | As a creator, I want to see my ad revenue vs other revenue sources. | Revenue card showing ad earnings breakdown by content. |

### 1.3 Ad Control Hierarchy

```
Ad Control Evaluation Order
───────────────────────────

1. Global Creator Setting (allow_ads)
   └── If false → No ads on ANY content by this creator
       └── Done

2. Per-Content Override (ad_enabled)
   └── If explicitly false → No ads on THIS content
       └── Done

3. Advertiser Block List
   └── If advertiser blocked → Skip this advertiser's ads
       └── Continue to next advertiser

4. Category Whitelist
   └── If ad category not in allowed_ad_categories → Skip
       └── Continue

5. Minimum CPM
   └── If bid_cpm < min_cpm_cents → Skip
       └── Serve ad

6. Revenue Share Override (negotiated rate)
   └── Default: 70% creator / 30% platform
   └── Override: custom split (e.g., 80/20 for top creators)
```

### 1.4 Per-Content Ad Settings

```
Content Type         Ad Fields                          Example
────────────         ──────────                         ───────
Newsfeed Post        allow_ads_near: bool               Post doesn't allow sponsored posts adjacent
                     ad_enabled: bool                   (Not applicable — posts don't have ads in them)

Video (VOD)          ad_enabled: bool                   Video has no ads
                     ad_config: {pre_roll, mid_roll}    Video has pre-roll only, no mid-roll
                     ads_free_for_subscribers: bool      Subscribers skip ads

Broadcast            pre_roll_enabled: bool              No pre-roll on this broadcast
                     mid_roll_enabled: bool              Mid-roll allowed
                     mid_roll_duration_seconds: int      30s mid-roll breaks
```

---

## 2. Current State Analysis

### 2.1 Creator Ad Preferences (ADS-003, `app/services/creator_ad_prefs.py`)

The `creator_ad_prefs.py` service stores basic creator settings (`allow_ads`, `allowed_ad_categories`, `min_cpm_cents`) and an advertiser block list. ADS-010 extends this with per-content overrides, revenue share management, and a transparency/analytics layer.

### 2.2 Video Ad Config (`app/services/ad_placement.py`)

Videos already have `ad_config` (pre_roll, mid_roll_intervals, overlay, skip_after_seconds), `ads_free_for_subscribers`, `ad_revenue_cents`, and `ad_impression_count` fields on `VideoMetadataModel`. These per-video settings override the global creator settings.

### 2.3 Broadcast Ad Config (ADS-006)

Broadcast sessions have `pre_roll_enabled`, `mid_roll_ad_break_duration_seconds`, and `mid_roll_skip_after_seconds` (added by ADS-006). These are per-session overrides.

### 2.4 Creator Analytics (`app/services/creator_analytics.py`)

The existing creator analytics service provides earnings dashboards. Ad revenue is already credited to the creator billing ledger as `ad_revenue_credit` entries. ADS-010 adds a dedicated ad revenue breakdown card.

### 2.5 Revenue Split (ADS-007)

The `PLATFORM_REVENUE_SHARE_PCT` constant in `ad_billing.py` is set to 30%. ADS-010 allows per-creator overrides stored in the creator's AD_SETTINGS record.

### 2.6 Gaps

1. **No per-content ad override UI** — creators cannot toggle ads per post/video/broadcast from a central location.
2. **No minimum CPM enforcement** — `min_cpm_cents` is stored but not checked in ad serving.
3. **No advertiser transparency** — creators cannot see which advertisers ran on their content.
4. **No ad revenue breakdown** — no per-content ad earnings view.
5. **No revenue share override** — all creators get the same 70/30 split.
6. **No creator ad settings page** — settings are scattered across different content creation forms.
7. **No ad serving integration for min_cpm** — `serve_ad()` doesn't check minimum CPM.

---

## 3. Technical Design

### 3.1 Extended Creator Ad Settings

Extend the `AD_SETTINGS` record in the `billing` table:

| PK | SK | Fields |
|----|----|--------|
| `USER#{creator_sub}` | `AD_SETTINGS` | `allow_ads`, `allowed_ad_categories`, `min_cpm_cents`, `revenue_share_pct` (default 70), `mid_roll_enabled` (default true), `default_pre_roll_enabled` (default true), `default_ads_free_for_subscribers` (default false), `updated_at` |

### 3.2 Ad Revenue Transparency Records

Add a new record type to the `billing` table for tracking which advertisers served on a creator's content:

| PK | SK | Fields |
|----|----|--------|
| `USER#{creator_sub}` | `AD_TRANSPARENCY#{account_id}#{month}` | `account_id`, `company_name`, `impression_count`, `click_count`, `revenue_cents`, `month`, `updated_at` |

Updated by the ad billing engine (ADS-007) on each charge event. Batched/incremented atomically.

### 3.3 Backend Service

**File**: `app/services/creator_ad_controls.py`

```python
"""Creator ad controls — settings, per-content overrides, transparency, revenue."""

from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts
from app.services.creator_ad_prefs import get_creator_ad_settings

DEFAULT_REVENUE_SHARE_PCT = 70


def get_full_ad_settings(creator_sub: str) -> dict:
    """Get complete ad settings for a creator including revenue share."""
    base = get_creator_ad_settings(creator_sub)
    base.setdefault("revenue_share_pct", DEFAULT_REVENUE_SHARE_PCT)
    base.setdefault("mid_roll_enabled", True)
    base.setdefault("default_pre_roll_enabled", True)
    base.setdefault("default_ads_free_for_subscribers", False)
    return base


def update_ad_settings(creator_sub: str, updates: dict) -> dict:
    """Update creator's global ad settings."""
    current = get_full_ad_settings(creator_sub)

    allowed_keys = {
        "allow_ads", "allowed_ad_categories", "min_cpm_cents",
        "mid_roll_enabled", "default_pre_roll_enabled",
        "default_ads_free_for_subscribers",
    }

    for k, v in updates.items():
        if k in allowed_keys:
            current[k] = v

    current["updated_at"] = now_ts()

    T.billing.put_item(Item={
        "pk": f"USER#{creator_sub}",
        "sk": "AD_SETTINGS",
        **{k: v for k, v in current.items() if v is not None},
    })
    return current


def get_ad_revenue_summary(creator_sub: str, days: int = 30) -> dict:
    """Get ad revenue summary for a creator."""
    from app.services.billing_shared import user_pk

    # Query billing ledger for ad_revenue_credit entries
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(user_pk(creator_sub)) & Key("sk").begins_with("LEDGER#"),
        ScanIndexForward=False,
        Limit=500,
    )

    ad_entries = [
        item for item in resp.get("Items", [])
        if item.get("entry_type") == "ad_revenue_credit"
    ]

    cutoff = now_ts() - (days * 86400)
    recent = [e for e in ad_entries if int(e.get("created_at", 0)) >= cutoff]

    total_cents = sum(int(e.get("amount_cents", 0)) for e in recent)

    # Group by content_id from meta
    by_content: Dict[str, int] = {}
    for entry in recent:
        meta = entry.get("meta", {})
        cid = meta.get("video_id") or meta.get("content_id") or "unknown"
        by_content[cid] = by_content.get(cid, 0) + int(entry.get("amount_cents", 0))

    # Sort by revenue descending
    top_content = sorted(by_content.items(), key=lambda x: x[1], reverse=True)[:20]

    return {
        "total_ad_revenue_cents": total_cents,
        "entry_count": len(recent),
        "days": days,
        "top_content": [{"content_id": cid, "revenue_cents": rev} for cid, rev in top_content],
    }


def get_advertiser_transparency(creator_sub: str, month: Optional[str] = None) -> list[dict]:
    """List advertisers who ran ads on this creator's content."""
    prefix = "AD_TRANSPARENCY#"
    if month:
        # Filter by specific month
        resp = T.billing.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{creator_sub}") & Key("sk").begins_with(prefix),
            FilterExpression=Attr("month").eq(month),
        )
    else:
        resp = T.billing.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{creator_sub}") & Key("sk").begins_with(prefix),
        )

    items = resp.get("Items", [])
    # Aggregate by account_id (may have entries for multiple months)
    accounts: Dict[str, dict] = {}
    for item in items:
        aid = item.get("account_id", "")
        if aid not in accounts:
            accounts[aid] = {
                "account_id": aid,
                "company_name": item.get("company_name", "Unknown"),
                "total_impressions": 0,
                "total_clicks": 0,
                "total_revenue_cents": 0,
            }
        accounts[aid]["total_impressions"] += int(item.get("impression_count", 0))
        accounts[aid]["total_clicks"] += int(item.get("click_count", 0))
        accounts[aid]["total_revenue_cents"] += int(item.get("revenue_cents", 0))

    return sorted(accounts.values(), key=lambda a: a["total_revenue_cents"], reverse=True)


def record_transparency(creator_id: str, account_id: str, company_name: str, month: str, *, impressions: int = 0, clicks: int = 0, revenue_cents: int = 0) -> None:
    """Increment transparency record for a creator-advertiser-month combination.

    Called from ad_billing._split_revenue() on each charge.
    """
    try:
        T.billing.update_item(
            Key={"pk": f"USER#{creator_id}", "sk": f"AD_TRANSPARENCY#{account_id}#{month}"},
            UpdateExpression=(
                "SET account_id = :aid, company_name = :cn, #m = :month, "
                "impression_count = if_not_exists(impression_count, :z) + :imp, "
                "click_count = if_not_exists(click_count, :z) + :clk, "
                "revenue_cents = if_not_exists(revenue_cents, :z) + :rev, "
                "updated_at = :ts"
            ),
            ExpressionAttributeNames={"#m": "month"},
            ExpressionAttributeValues={
                ":aid": account_id, ":cn": company_name, ":month": month,
                ":z": 0, ":imp": impressions, ":clk": clicks,
                ":rev": revenue_cents, ":ts": now_ts(),
            },
        )
    except Exception:
        pass  # Best-effort transparency tracking


def get_creator_revenue_share(creator_sub: str) -> int:
    """Get the revenue share percentage for a creator (default 70%)."""
    settings = get_full_ad_settings(creator_sub)
    return settings.get("revenue_share_pct", DEFAULT_REVENUE_SHARE_PCT)
```

### 3.4 Ad Serving Integration

Update `serve_ad()` in `app/services/ad_serving.py` to check minimum CPM:

```python
# Inside the campaign loop in serve_ad():
# After targeting check, before frequency cap check:

# Min CPM check
creator_settings = get_creator_ad_settings(creator_id)
min_cpm = creator_settings.get("min_cpm_cents", 0)
if min_cpm > 0:
    bid_cpm = campaign.get("bid_cpm_cents", 500)
    if bid_cpm < min_cpm:
        continue  # Skip campaigns that don't meet minimum
```

### 3.5 Backend Router

**File**: `app/routers/ads.py` (extend)

```python
# ── Creator Ad Controls ──

@router.get("/creator/ad-settings")
def get_creator_settings(ctx=Depends(require_ui_session)):
    return get_full_ad_settings(ctx["user_sub"])

@router.patch("/creator/ad-settings")
def update_creator_settings(body: dict, ctx=Depends(require_ui_session)):
    return update_ad_settings(ctx["user_sub"], body)

@router.get("/creator/ad-revenue")
def creator_revenue(days: int = 30, ctx=Depends(require_ui_session)):
    return get_ad_revenue_summary(ctx["user_sub"], days)

@router.get("/creator/ad-transparency")
def creator_transparency(month: Optional[str] = None, ctx=Depends(require_ui_session)):
    return get_advertiser_transparency(ctx["user_sub"], month)

@router.post("/creator/ad-blocks")
def block_advertiser_endpoint(body: dict, ctx=Depends(require_ui_session)):
    from app.services.creator_ad_prefs import block_advertiser
    return block_advertiser(ctx["user_sub"], body["account_id"], body.get("reason", ""))

@router.delete("/creator/ad-blocks/{account_id}")
def unblock_advertiser_endpoint(account_id: str, ctx=Depends(require_ui_session)):
    from app.services.creator_ad_prefs import unblock_advertiser
    return unblock_advertiser(ctx["user_sub"], account_id)

@router.get("/creator/ad-blocks")
def list_blocks(ctx=Depends(require_ui_session)):
    from app.services.creator_ad_prefs import list_blocked_advertisers
    return list_blocked_advertisers(ctx["user_sub"])
```

### 3.6 Frontend Pages

**File**: `frontend/src/pages/ads/CreatorAdSettingsPage.tsx`

- Route: `/creator/ad-settings`
- Global settings card:
  - `allow_ads` toggle (main on/off switch)
  - `allowed_ad_categories` checkbox list
  - `min_cpm_cents` numeric input with dollar display ($X.XX)
  - `default_pre_roll_enabled` toggle
  - `mid_roll_enabled` toggle
  - `default_ads_free_for_subscribers` toggle
- Save button
- `data-testid="creator-ad-settings"`

**File**: `frontend/src/pages/ads/AdRevenueCard.tsx`

- Card component for creator dashboard
- Total ad revenue for period (with period selector)
- Top earning content list (content_id + revenue)
- Bar chart of daily ad revenue
- Link to full transparency page

**File**: `frontend/src/pages/ads/AdTransparencyPage.tsx`

- Route: `/creator/ad-transparency`
- Month filter dropdown
- Table of advertisers: company_name, impressions, clicks, revenue
- "Block" button per advertiser
- Summary stats at top: total advertisers, total impressions, total revenue

### 3.7 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface CreatorAdSettings {
  allow_ads: boolean;
  allowed_ad_categories: string[];
  min_cpm_cents: number;
  revenue_share_pct: number;
  mid_roll_enabled: boolean;
  default_pre_roll_enabled: boolean;
  default_ads_free_for_subscribers: boolean;
  updated_at?: number;
}

export interface AdRevenueSummary {
  total_ad_revenue_cents: number;
  entry_count: number;
  days: number;
  top_content: Array<{ content_id: string; revenue_cents: number }>;
}

export interface AdvertiserTransparency {
  account_id: string;
  company_name: string;
  total_impressions: number;
  total_clicks: number;
  total_revenue_cents: number;
}
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/creator_ad_controls.py` | Full creator ad settings, revenue, transparency |
| `frontend/src/pages/ads/CreatorAdSettingsPage.tsx` | Creator ad settings page |
| `frontend/src/pages/ads/AdRevenueCard.tsx` | Ad revenue card for creator dashboard |
| `frontend/src/pages/ads/AdTransparencyPage.tsx` | Advertiser transparency page |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/ads.py` | Add creator settings, revenue, transparency, block endpoints |
| `app/services/ad_serving.py` | Add min_cpm check in campaign loop |
| `app/services/ad_billing.py` | Call `record_transparency()` in `_split_revenue()` |
| `frontend/src/api/types.ts` | Add `CreatorAdSettings`, `AdRevenueSummary`, `AdvertiserTransparency` types |
| `frontend/src/api/endpoints/ads.ts` | Add creator ad control API functions |
| `frontend/src/App.tsx` | Add `/creator/ad-settings`, `/creator/ad-transparency` routes |

### 4.3 Step-by-Step Order

1. Implement `creator_ad_controls.py` service
2. Add creator ad control endpoints to router
3. Wire min_cpm check into ad serving engine
4. Wire transparency recording into ad billing engine
5. Add frontend types + API endpoints
6. Build CreatorAdSettingsPage
7. Build AdRevenueCard
8. Build AdTransparencyPage
9. Add routes
10. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/ads-content-provider.spec.ts` — 18 tests across 5 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let advertiserAccountId: string;
let campaignId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice (advertiser), Bob (creator)
  // Create ad account + campaign + approved creative for Alice
  // Seed some ad transparency records for Bob
});
```

### 5.3 Section 383: Creator Ad Settings API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 383.1 | Get default creator ad settings | Bob GET `/ui/ads/creator/ad-settings`; 200; allow_ads=true, revenue_share_pct=70, min_cpm_cents=0 |
| 383.2 | Update allow_ads to false | Bob PATCH allow_ads=false; 200; GET confirms |
| 383.3 | Set minimum CPM | Bob PATCH min_cpm_cents=800 ($8 CPM); 200; GET confirms 800 |
| 383.4 | Set allowed categories | Bob PATCH allowed_ad_categories=["gaming","fitness"]; 200; only those categories stored |

### 5.4 Section 384: Min CPM Enforcement (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 384.1 | Ad with bid >= min_cpm served | Bob sets min_cpm=500; Alice campaign bid_cpm=600; serve_ad on Bob's content → filled=true |
| 384.2 | Ad with bid < min_cpm not served | Bob sets min_cpm=1000; Alice campaign bid_cpm=500; serve_ad → house ad or empty |
| 384.3 | Min CPM of 0 allows all bids | Bob sets min_cpm=0; any campaign bid → served |

### 5.5 Section 385: Advertiser Block List (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 385.1 | Block advertiser | Bob POST block with Alice's account_id; 200 |
| 385.2 | Blocked advertiser not served | serve_ad on Bob's content → Alice's ads excluded |
| 385.3 | List blocked advertisers | Bob GET blocks; array includes Alice's account_id |
| 385.4 | Unblock advertiser | Bob DELETE block; 200; serve_ad includes Alice's ads again |

### 5.6 Section 386: Ad Revenue & Transparency API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 386.1 | Get ad revenue summary | Bob GET `/ui/ads/creator/ad-revenue?days=30`; 200; has total_ad_revenue_cents, top_content |
| 386.2 | Revenue has per-content breakdown | top_content array has entries with content_id + revenue_cents |
| 386.3 | Get advertiser transparency | Bob GET `/ui/ads/creator/ad-transparency`; 200; array of advertisers with impressions/clicks/revenue |
| 386.4 | Transparency filters by month | Bob GET with ?month=YYYY-MM; 200; filtered results |

### 5.7 Section 387: Creator Ad Settings UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 387.1 | Settings page loads | Navigate to `/creator/ad-settings`; `[data-testid="creator-ad-settings"]` visible |
| 387.2 | Allow ads toggle works | Toggle "Allow Ads" off; save; reload; toggle reflects off state |
| 387.3 | Min CPM input updates | Enter $8.00 in min CPM field; save; reload; field shows $8.00 |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Invalid min_cpm (negative) | 400 | "min_cpm_cents must be >= 0" |
| Invalid ad category | 400 | "Invalid ad category: X" |
| Block non-existent account | 200 | Idempotent (no error) |
| Revenue query with invalid days | 400 | "days must be between 1 and 365" |
| Transparency query with invalid month | 400 | "Invalid month format, use YYYY-MM" |

---

## 7. Security Considerations

- Creator ad settings modifiable only by the creator themselves
- Revenue share percentage not modifiable via API (admin-only, set directly in DDB or admin endpoint)
- Advertiser transparency data is creator-scoped; advertisers cannot see which creators blocked them
- Block list is private; blocked advertisers are silently excluded
- Per-content ad overrides respect the content ownership check

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-003 | Creator ad prefs (base service) | Required |
| ADS-004 | Ad serving engine (min_cpm check) | Required |
| ADS-007 | Ad billing (transparency recording) | Required |

### 8.1 Downstream Dependents

None — ADS-010 is a terminal content provider control surface.
