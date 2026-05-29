# ADS-010: Content Provider Ad Controls

**Ticket**: ADS-010
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 6-8 days
**Dependencies**: ADS-003 (Targeting — creator ad prefs), ADS-004 (Ad Serving), ADS-007 (Billing — revenue split) — all sibling tickets, not yet implemented
<!-- NOTE: All ADS dependencies are sibling tickets not yet in the codebase. Existing: ad_placement.py, creator_analytics.py, billing_shared.py. -->

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

---

## 9. Architecture & Data Flow

```
Creator Ad Control Evaluation Hierarchy
────────────────────────────────────────

  serve_ad(creator_id, content_id, ...)
       │
       ▼
  ┌────────────────────────────────────┐
  │  1. Get Global Creator Settings    │
  │     billing: USER#{creator}/       │
  │             AD_SETTINGS            │
  │                                    │
  │     allow_ads == false?            │
  │     ├─ Yes → return empty (no ads) │
  │     └─ No  → continue             │
  └──────────┬─────────────────────────┘
             │
             ▼
  ┌────────────────────────────────────┐
  │  2. Per-Content Override Check     │
  │     (post: allow_ads_near,         │
  │      video: ad_enabled,            │
  │      broadcast: pre_roll_enabled)  │
  │                                    │
  │     ad_enabled == false?           │
  │     ├─ Yes → return empty          │
  │     └─ No  → continue             │
  └──────────┬─────────────────────────┘
             │
             ▼
  ┌────────────────────────────────────┐
  │  3. Advertiser Block List          │
  │     billing: USER#{creator}/       │
  │             AD_BLOCK#{account_id}  │
  │                                    │
  │     Blocked? → Skip this campaign  │
  └──────────┬─────────────────────────┘
             │
             ▼
  ┌────────────────────────────────────┐
  │  4. Category Whitelist             │
  │     allowed_ad_categories check    │
  │                                    │
  │     Not in list? → Skip            │
  └──────────┬─────────────────────────┘
             │
             ▼
  ┌────────────────────────────────────┐
  │  5. Minimum CPM Check              │
  │     bid_cpm < min_cpm_cents?       │
  │     ├─ Yes → Skip (too cheap)      │
  │     └─ No  → Serve ad             │
  └──────────┬─────────────────────────┘
             │
             ▼
  ┌────────────────────────────────────┐
  │  6. Revenue Split                  │
  │     revenue_share_pct (default 70) │
  │     Creator gets X%, Platform Y%   │
  └────────────────────────────────────┘
```

---

## 10. API Request/Response Examples

### 10.1 Get Full Creator Ad Settings

```bash
curl http://localhost:8000/ui/ads/creator/ad-settings \
  -H "Cookie: ui_session=sess_bob; ui_access_token=jwt_tok"
```

**Response (200)**:
```json
{
  "allow_ads": true,
  "allowed_ad_categories": [],
  "min_cpm_cents": 0,
  "revenue_share_pct": 70,
  "mid_roll_enabled": true,
  "default_pre_roll_enabled": true,
  "default_ads_free_for_subscribers": false,
  "updated_at": 1748534400
}
```

### 10.2 Get Ad Revenue Summary

```bash
curl "http://localhost:8000/ui/ads/creator/ad-revenue?days=30" \
  -H "Cookie: ui_session=sess_bob; ui_access_token=jwt_tok"
```

**Response (200)**:
```json
{
  "total_ad_revenue_cents": 15250,
  "entry_count": 42,
  "days": 30,
  "top_content": [
    {"content_id": "vid_001", "revenue_cents": 8500},
    {"content_id": "vid_002", "revenue_cents": 4200},
    {"content_id": "bcast_003", "revenue_cents": 2550}
  ]
}
```

### 10.3 Get Advertiser Transparency

```bash
curl "http://localhost:8000/ui/ads/creator/ad-transparency?month=2026-05" \
  -H "Cookie: ui_session=sess_bob; ui_access_token=jwt_tok"
```

**Response (200)**:
```json
[
  {
    "account_id": "adv_alice",
    "company_name": "Acme Corp",
    "total_impressions": 5200,
    "total_clicks": 120,
    "total_revenue_cents": 8500
  },
  {
    "account_id": "adv_charlie",
    "company_name": "Widget Inc",
    "total_impressions": 3100,
    "total_clicks": 75,
    "total_revenue_cents": 4200
  }
]
```

---

## 11. Error Handling Matrix

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------------|-------------|------------|---------------------|-----------------|
| 1 | Invalid min_cpm (negative) | 400 | `INVALID_MIN_CPM` | "min_cpm_cents must be >= 0." | Use non-negative value |
| 2 | Invalid ad category | 400 | `INVALID_CATEGORY` | "Invalid ad category: {cat}." | Use valid category |
| 3 | Block non-existent account | 200 | -- | Idempotent (no error) | None needed |
| 4 | Revenue query invalid days | 400 | `INVALID_DAYS` | "days must be between 1 and 365." | Use valid range |
| 5 | Invalid month format | 400 | `INVALID_MONTH` | "Invalid month format, use YYYY-MM." | Use format YYYY-MM |
| 6 | Revenue share not modifiable | 403 | `ADMIN_ONLY` | "Revenue share can only be set by admins." | Contact admin |
| 7 | Not content owner | 403 | `NOT_CONTENT_OWNER` | "You do not own this content." | Use own content |

---

## 12. Observability

### 12.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `creator_ad_settings_updated_total` | Counter | `field` | Settings updates by field |
| `creator_ad_revenue_cents` | Counter | `creator_id` | Revenue credited to creators |
| `creator_min_cpm_blocked_total` | Counter | `creator_id` | Ads blocked by min CPM |
| `creator_advertiser_blocked_total` | Counter | -- | Advertisers blocked by creators |
| `creator_transparency_queries_total` | Counter | -- | Transparency page views |

### 12.2 Log Events

| Event | Level | Fields |
|-------|-------|--------|
| `creator_settings_updated` | INFO | creator_sub, changed_fields |
| `creator_min_cpm_blocked` | INFO | creator_sub, campaign_id, bid_cpm, min_cpm |
| `creator_advertiser_blocked` | INFO | creator_sub, account_id |
| `creator_revenue_credited` | INFO | creator_sub, amount_cents, content_id |
| `transparency_recorded` | DEBUG | creator_sub, account_id, month, impressions |

### 12.3 Alerting Rules

| Alert | Condition | Severity |
|-------|-----------|----------|
| Revenue crediting failures | >5% failed revenue credits in 1 hour | P2 |
| Transparency recording lag | Records not updated for >6 hours | P3 |
| Settings update error rate | >5% errors on PATCH settings in 15 min | P3 |

---

## 13. Rollout Plan

### 13.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `CREATOR_AD_CONTROLS_ENABLED` | `false` | Enable full creator ad control UI |
| `CREATOR_MIN_CPM_ENFORCEMENT` | `false` | Enforce min CPM in ad serving |

### 13.2 Phased Deployment

| Phase | Scope | Duration | Details |
|-------|-------|----------|---------|
| Phase 1: Backend + Min CPM | Internal | Week 1 | Deploy creator_ad_controls service. Wire min_cpm check into ad serving. Transparency recording in billing pipeline. |
| Phase 2: Settings UI | All creators | Week 2 | CreatorAdSettingsPage deployed. Creators can manage allow_ads, categories, min_cpm, block list. |
| Phase 3: Revenue + Transparency | All creators | Week 3 | AdRevenueCard and AdTransparencyPage deployed. Full creator ad management suite. |

---

## 14. Performance Considerations

### 14.1 Latency Targets

| Endpoint | Target p50 | Target p99 |
|----------|-----------|-----------|
| GET /creator/ad-settings | 20ms | 100ms |
| PATCH /creator/ad-settings | 50ms | 200ms |
| GET /creator/ad-revenue | 100ms | 500ms |
| GET /creator/ad-transparency | 80ms | 400ms |
| Min CPM check (in serve_ad) | 2ms | 10ms |

### 14.2 Caching Strategy

| Data | Cache | staleTime | Invalidation |
|------|-------|-----------|-------------|
| Creator ad settings | React Query | 60_000ms | On PATCH mutation |
| Creator ad settings (server) | In-memory LRU | 60s | On update |
| Revenue summary | React Query | 120_000ms | On period change |
| Transparency list | React Query | 120_000ms | On month filter change |
| Block list | React Query | 60_000ms | On block/unblock mutation |

### 14.3 Transparency Recording

Transparency records are updated atomically using DDB `ADD` operations (increment counters). This avoids read-before-write and supports concurrent billing events. Records are keyed by `AD_TRANSPARENCY#{account_id}#{month}`, so each month gets a separate record. Historical months are immutable after month end.

---

## 15. Expanded E2E Tests

### 15.1 Section 388: Input Validation (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 388.1 | Negative min_cpm rejected | PATCH min_cpm_cents=-1; 400 |
| 388.2 | Invalid category rejected | PATCH allowed_ad_categories=["invalid"]; 400 |
| 388.3 | Revenue days=0 rejected | GET ad-revenue?days=0; 400 |
| 388.4 | Invalid month format rejected | GET ad-transparency?month=2026; 400 |

### 15.2 Section 389: Authorization Boundary (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 389.1 | Cannot modify other creator's settings | Alice PATCH Bob's settings; settings scoped to own session |
| 389.2 | Revenue share not modifiable via API | PATCH revenue_share_pct=90; field ignored or 403 |
| 389.3 | Transparency scoped to own account | GET transparency returns only own data |
| 389.4 | Block list scoped to own account | GET blocks returns only own blocks |

### 15.3 Section 390: Revenue & Transparency Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 390.1 | Revenue with no data returns zeros | New creator; GET ad-revenue; total=0, top_content=[] |
| 390.2 | Transparency with no advertisers | GET transparency; 200; empty array |
| 390.3 | Transparency month filter works | Seed data for 2 months; filter by one; only that month's data returned |
| 390.4 | Block then check serve_ad | Block advertiser; serve_ad for that advertiser; excluded |

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/ad_placement.py` | 178, 222 | Existing `get_ad_config` (line 178), `record_ad_impression` (line 222) |
| `app/services/creator_analytics.py` | — | Existing creator analytics service (reference for ad revenue reporting) |
| `app/services/billing_shared.py` | — | Existing billing ledger helpers |
| `app/services/creator_ad_controls.py` | — | Does not exist yet — new implementation required |
