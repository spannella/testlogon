# ADS-009: User Ad Preferences & Ad-Free Tiers

**Ticket**: ADS-009
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 5-7 days
**Dependencies**: ADS-004 (Ad Serving Engine — sibling ticket, not yet implemented), ADS-005 (Sponsored Posts — sibling ticket, not yet implemented)
<!-- NOTE: ADS-004 and ADS-005 services/tables do not exist yet. Existing: ad_placement.py for ad-free subscriber check. -->

---

## 1. Overview & Motivation

### 1.1 Purpose

ADS-009 gives users control over their ad experience. Users can choose between three ad levels (full, reduced, ad-free), opt out of specific ad categories, toggle ad personalization, and provide feedback on individual ads. The ticket also introduces a platform-level ad-free subscription tier that removes all ads across the platform.

The existing per-creator subscription ad-free benefit (already implemented in `ad_placement.py`) is complemented by this platform-wide ad-free option. The ad serving engine (ADS-004) checks user preferences before serving ads.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to choose how many ads I see. | Ad preferences page with full/reduced/ad-free options. |
| User | As a user, I want to opt out of specific ad categories. | Category toggles (gambling, alcohol, political, etc.); opted-out categories not served. |
| User | As a user, I want to disable personalized ads. | Toggle off; serve generic/non-targeted ads instead. |
| User | As a user, I want to subscribe to ad-free for the entire platform. | Platform ad-free plan in subscriptions; removes all ads everywhere. |
| User | As a user, I want to hide an ad and tell the platform why. | Feedback options: not relevant, repetitive, offensive, not interested. |
| Platform | As the platform, I want the ad serving engine to respect user preferences. | `serve_ad()` checks user tier, category prefs, and personalization toggle. |

### 1.3 Ad Experience Tiers

```
Ad Experience Levels
────────────────────

1. full_ads (default for free users)
   └── All ad surfaces active: sponsored posts, broadcast pre-roll/mid-roll, VOD ads
       Up to 1 sponsored post per 5 organic posts
       Full frequency cap limits (3/1h, 10/24h, 30/7d)

2. reduced_ads (opt-in setting)
   └── Fewer ad slots: 1 sponsored post per 10 organic posts
       Shorter video ads (skip after 5s instead of 15s for mid-roll)
       Lower frequency caps (1/1h, 5/24h, 15/7d)
       No overlay ads

3. ad_free (requires platform subscription or per-creator subscription)
   └── No ads on any surface
       Sponsored posts removed from feed
       Broadcast pre-roll and mid-roll skipped
       VOD plays without ad breaks
```

### 1.4 Preference Evaluation in Ad Serving

```
serve_ad() — User Preference Check (added to ADS-004 flow)
──────────────────────────────────────────────────────────

                        ┌──────────────────┐
                        │ Load user prefs  │
                        │ (ad_level,       │
                        │  excluded_cats,  │
                        │  personalized)   │
                        └────────┬─────────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
               ad_free     reduced_ads    full_ads
                    │            │            │
              return empty   apply reduced  apply full
              (no ad)        limits +       limits
                             filter cats    + filter cats
```

---

## 2. Current State Analysis

### 2.1 Per-Creator Ad-Free (`app/services/ad_placement.py`)

The `get_ad_config()` function (line 193) checks `has_active_subscription()` when `ads_free_for_subscribers=True` on a video. This is a per-creator, per-video setting. ADS-009 adds a platform-wide ad-free tier and user-level category preferences.

### 2.2 Subscription Plans

The subscription system (`app/services/subscription_plans.py`) supports creator-level plans with configurable benefits. Adding a platform-level ad-free plan follows the same structure but with `plan_type="platform"` and `benefit="ad_free"`.

### 2.3 User Preferences Storage

The `billing` table stores per-user data with `pk=USER#{user_sub}`, `sk=<TYPE>`. Ad preferences use `sk=AD_PREFS` — a single record with all preference fields.

### 2.4 Ad Feedback (ADS-005)

ADS-005 introduced `record_ad_feedback()` in `ad_feedback.py` for the "Hide this ad" feature. ADS-009 extends this with structured feedback categories and stores the data for targeting quality improvement.

### 2.5 Gaps

1. **No user ad preference record** — no storage for ad level, category exclusions, personalization toggle.
2. **No platform ad-free plan** — no subscription that removes all ads.
3. **No reduced_ads mode** — no intermediate ad experience level.
4. **No ad category opt-out** — users cannot exclude specific ad categories.
5. **No personalization toggle** — no way to opt out of targeted ads.
6. **No preference check in ad serving** — `serve_ad()` doesn't read user prefs.
7. **No ad preferences UI** — no settings page section for ad controls.

---

## 3. Technical Design

### 3.1 Data Model (existing `billing` table)

| PK | SK | Fields |
|----|----|--------|
| `USER#{user_sub}` | `AD_PREFS` | `ad_level: str` (full_ads/reduced_ads/ad_free), `excluded_categories: list[str]`, `personalized: bool` (default true), `platform_ad_free_until: int` (Unix timestamp, 0 if no subscription), `updated_at: int` |

No new table needed — reuses the `billing` table per-user pattern.

### 3.2 Platform Ad-Free Plan

Add a platform-level subscription plan to the subscriptions system:

```python
PLATFORM_AD_FREE_PLAN = {
    "plan_id": "platform_ad_free",
    "plan_type": "platform",
    "name": "Ad-Free Experience",
    "description": "Remove all ads across the platform",
    "price_cents": 999,  # $9.99/month
    "interval": "monthly",
    "benefit": "ad_free",
}
```

When a user subscribes, set `ad_level="ad_free"` and `platform_ad_free_until` in their AD_PREFS record.

### 3.3 Backend Service

**File**: `app/services/user_ad_prefs.py`

```python
"""User ad preferences — ad level, category exclusions, personalization."""

from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts

DEFAULT_PREFS = {
    "ad_level": "full_ads",
    "excluded_categories": [],
    "personalized": True,
    "platform_ad_free_until": 0,
}

AD_CATEGORIES = [
    "gambling", "alcohol", "tobacco", "political", "dating",
    "pharmaceutical", "weight_loss", "financial", "adult",
]


def get_ad_prefs(user_sub: str) -> dict:
    """Get user's ad preferences. Returns defaults if no record exists."""
    resp = T.billing.get_item(Key={"pk": f"USER#{user_sub}", "sk": "AD_PREFS"})
    item = resp.get("Item")
    if not item:
        return {**DEFAULT_PREFS}

    prefs = {**DEFAULT_PREFS}
    prefs.update({k: v for k, v in item.items() if k in DEFAULT_PREFS})

    # Check if platform ad-free is still active
    if prefs.get("platform_ad_free_until", 0) > 0:
        if prefs["platform_ad_free_until"] > now_ts():
            prefs["ad_level"] = "ad_free"
        else:
            prefs["platform_ad_free_until"] = 0
            # Revert to full_ads if subscription expired
            if prefs.get("ad_level") == "ad_free":
                prefs["ad_level"] = "full_ads"

    return prefs


def update_ad_prefs(user_sub: str, updates: dict) -> dict:
    """Update user's ad preferences."""
    current = get_ad_prefs(user_sub)

    if "ad_level" in updates:
        level = updates["ad_level"]
        if level not in ("full_ads", "reduced_ads"):
            raise ValueError("ad_level must be full_ads or reduced_ads (ad_free requires subscription)")
        current["ad_level"] = level

    if "excluded_categories" in updates:
        cats = updates["excluded_categories"]
        invalid = [c for c in cats if c not in AD_CATEGORIES]
        if invalid:
            raise ValueError(f"Invalid ad categories: {invalid}")
        current["excluded_categories"] = cats

    if "personalized" in updates:
        current["personalized"] = bool(updates["personalized"])

    current["updated_at"] = now_ts()

    T.billing.put_item(Item={
        "pk": f"USER#{user_sub}",
        "sk": "AD_PREFS",
        **current,
    })

    return current


def set_platform_ad_free(user_sub: str, until_ts: int) -> dict:
    """Grant platform ad-free access until a timestamp (called by subscription system)."""
    T.billing.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": "AD_PREFS"},
        UpdateExpression="SET ad_level = :level, platform_ad_free_until = :until, updated_at = :ts",
        ExpressionAttributeValues={":level": "ad_free", ":until": until_ts, ":ts": now_ts()},
    )
    return {"ok": True}


def is_ad_free(user_sub: str) -> bool:
    """Quick check if user has any ad-free access (platform subscription)."""
    prefs = get_ad_prefs(user_sub)
    return prefs.get("ad_level") == "ad_free"


def should_serve_ad(user_sub: str, ad_category: str = "") -> dict:
    """Check if an ad should be served to this user and with what parameters.

    Returns: {serve: bool, reduced: bool, reason: str}
    """
    prefs = get_ad_prefs(user_sub)
    ad_level = prefs.get("ad_level", "full_ads")

    if ad_level == "ad_free":
        return {"serve": False, "reduced": False, "reason": "ad_free_subscription"}

    # Category exclusion
    if ad_category and ad_category in prefs.get("excluded_categories", []):
        return {"serve": False, "reduced": False, "reason": "excluded_category"}

    if ad_level == "reduced_ads":
        return {"serve": True, "reduced": True, "reason": "reduced_ads"}

    return {"serve": True, "reduced": False, "reason": "full_ads"}
```

### 3.4 Ad Serving Integration

Modify `serve_ad()` in `app/services/ad_serving.py` to check user preferences:

```python
# At the top of serve_ad():
from app.services.user_ad_prefs import should_serve_ad

def serve_ad(*, surface, content_type, creator_id, content_id, slot_type, user_id, user_context=None):
    # 0. Check user ad preferences
    pref_check = should_serve_ad(user_id)
    if not pref_check["serve"]:
        return _empty_response(pref_check["reason"])

    reduced_mode = pref_check["reduced"]
    # ... rest of existing logic ...

    # If reduced mode: adjust frequency caps and skip overlays
    if reduced_mode:
        if slot_type == "overlay":
            return _empty_response("reduced_ads_no_overlay")
```

### 3.5 Backend Router

**File**: `app/routers/ads.py` (extend)

```python
# ── User Ad Preferences ──

@router.get("/preferences")
def get_preferences(ctx=Depends(require_ui_session)):
    return get_ad_prefs(ctx["user_sub"])

@router.patch("/preferences")
def update_preferences(body: dict, ctx=Depends(require_ui_session)):
    return update_ad_prefs(ctx["user_sub"], body)

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

**File**: `frontend/src/pages/settings/AdPreferencesSection.tsx`

- Section within the Settings page
- Ad experience level radio group: Full Ads, Reduced Ads, Ad-Free (disabled unless subscribed)
- Ad-free CTA: "Subscribe to Ad-Free for $9.99/mo" with link to subscription page
- Category exclusion toggles: checkbox list of ad categories (gambling, alcohol, etc.)
- Personalization toggle: on/off switch with explanation text
- Save button
- `data-testid="ad-preferences-section"`

**File**: `frontend/src/pages/feed/AdFeedbackDialog.tsx`

- Triggered by "Hide this ad" overflow menu item on SponsoredPostCard
- Radio options: "Not relevant to me", "I see this too often", "Offensive or inappropriate", "Not interested in this topic"
- Submit fires `POST /ui/ads/feedback`
- Optional: "Block this advertiser" checkbox
- `data-testid="ad-feedback-dialog"`

### 3.7 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface UserAdPreferences {
  ad_level: "full_ads" | "reduced_ads" | "ad_free";
  excluded_categories: string[];
  personalized: boolean;
  platform_ad_free_until: number;
  updated_at?: number;
}

export const AD_CATEGORIES = [
  "gambling", "alcohol", "tobacco", "political", "dating",
  "pharmaceutical", "weight_loss", "financial", "adult",
] as const;
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/user_ad_prefs.py` | User ad preferences CRUD + serving check |
| `frontend/src/pages/settings/AdPreferencesSection.tsx` | Ad preferences UI in settings |
| `frontend/src/pages/feed/AdFeedbackDialog.tsx` | Feedback dialog for hidden ads |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/ads.py` | Add preferences + feedback endpoints |
| `app/services/ad_serving.py` | Check user prefs before serving |
| `frontend/src/api/types.ts` | Add `UserAdPreferences` type |
| `frontend/src/api/endpoints/ads.ts` | Add preferences + feedback API functions |
| `frontend/src/pages/settings/SettingsPage.tsx` | Add AdPreferencesSection |
| `frontend/src/pages/feed/SponsoredPostCard.tsx` | Wire "Hide" to feedback dialog |

### 4.3 Step-by-Step Order

1. Implement `user_ad_prefs.py` service
2. Add preference + feedback endpoints
3. Wire user pref check into ad serving engine
4. Add frontend types + API endpoints
5. Build AdPreferencesSection
6. Build AdFeedbackDialog
7. Integrate into settings page and sponsored post card
8. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/ads-user-prefs.spec.ts` — 15 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();

test.beforeAll(async ({ browser }) => {
  // Set up Alice (user with default prefs), Bob (viewer)
  // Set up advertiser account + campaign + approved creative (for serve tests)
});
```

### 5.3 Section 379: Ad Preferences API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 379.1 | Get default preferences | GET `/ui/ads/preferences`; 200; ad_level=full_ads, excluded_categories=[], personalized=true |
| 379.2 | Update ad level to reduced | PATCH ad_level=reduced_ads; 200; GET confirms reduced_ads |
| 379.3 | Set category exclusions | PATCH excluded_categories=["gambling","alcohol"]; 200; GET confirms both categories |
| 379.4 | Toggle personalization off | PATCH personalized=false; 200; GET confirms false |
| 379.5 | Cannot set ad_free without subscription | PATCH ad_level=ad_free; 400; "ad_free requires subscription" |

### 5.4 Section 380: Preference Enforcement (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 380.1 | Full ads user sees ads | POST serve_ad as full_ads user; filled=true |
| 380.2 | Reduced ads user skips overlays | Set reduced_ads; POST serve with slot_type=overlay; filled=false, reason=reduced_ads_no_overlay |
| 380.3 | Ad-free user sees no ads | Set platform ad-free; POST serve; filled=false, reason=ad_free_subscription |
| 380.4 | Excluded category filtered | Exclude "gambling"; serve ad with category=gambling; filtered out |

### 5.5 Section 381: Ad Feedback API (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 381.1 | Submit hide feedback | POST `/ui/ads/feedback` with creative_id + feedback_type=not_relevant; 200; ok=true |
| 381.2 | Submit offensive feedback | POST feedback_type=offensive; 200 |
| 381.3 | Multiple feedback entries allowed | Submit two feedbacks for different creatives; both stored |

### 5.6 Section 382: Ad Preferences UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 382.1 | Preferences section visible in settings | Navigate to settings; `[data-testid="ad-preferences-section"]` visible |
| 382.2 | Category toggles work | Check "Gambling" checkbox; save; reload; checkbox still checked |
| 382.3 | Ad-free CTA visible for non-subscribers | "Subscribe to Ad-Free" text/button visible when ad_level != ad_free |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Invalid ad_level | 400 | "ad_level must be full_ads or reduced_ads" |
| Invalid category | 400 | "Invalid ad categories: [X]" |
| Set ad_free without subscription | 400 | "ad_free requires subscription" |
| Invalid feedback_type | 400 | "Invalid feedback type" |

---

## 7. Security Considerations

- Ad preferences are per-user; no cross-user access
- `set_platform_ad_free()` is internal-only (called by subscription system, not exposed via API)
- Category exclusions are enforced server-side in the ad serving engine
- Personalization opt-out is respected: non-personalized users get random (non-targeted) ads
- Feedback data is anonymous to advertisers (they see aggregate counts only)

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-004 | Ad serving engine | Required |
| ADS-005 | Sponsored post hide/feedback | Required (feedback storage) |
| Subscription system | `app/services/subscription_plans.py` | Existing |

### 8.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| ADS-010 (Content Provider) | User prefs complement creator ad controls |

---

## 9. Architecture & Data Flow

```
User Ad Preference Evaluation
─────────────────────────────

  serve_ad(user_id, surface, ...)
       │
       ▼
  ┌────────────────────────────────────┐
  │  should_serve_ad(user_sub, cat)    │
  │                                    │
  │  1. get_ad_prefs(user_sub)         │
  │     → billing table GET            │
  │     PK=USER#{sub}, SK=AD_PREFS    │
  │                                    │
  │  2. Check ad_level:                │
  │     ├─ ad_free → return {serve: F} │
  │     ├─ reduced_ads → limits apply  │
  │     └─ full_ads → normal limits    │
  │                                    │
  │  3. Check excluded_categories:     │
  │     ├─ cat in excluded → skip      │
  │     └─ cat not excluded → pass     │
  │                                    │
  │  4. Return {serve, reduced, reason}│
  └────────────────────────────────────┘

  Platform Ad-Free Subscription Flow
  ────────────────────────────────────

  User subscribes to ad-free plan
       │
       ▼
  Subscription system processes payment
       │
       ▼
  set_platform_ad_free(user_sub, until_ts)
       │
       ▼
  billing table UPDATE:
    AD_PREFS: ad_level="ad_free"
              platform_ad_free_until=ts
       │
       ▼
  All subsequent serve_ad() → {serve: false}
```

---

## 10. API Request/Response Examples

### 10.1 Get Preferences

```bash
curl http://localhost:8000/ui/ads/preferences \
  -H "Cookie: ui_session=sess_alice; ui_access_token=jwt_tok"
```

**Response (200)**:
```json
{
  "ad_level": "full_ads",
  "excluded_categories": [],
  "personalized": true,
  "platform_ad_free_until": 0
}
```

### 10.2 Update Preferences

```bash
curl -X PATCH http://localhost:8000/ui/ads/preferences \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok" \
  -d '{
    "ad_level": "reduced_ads",
    "excluded_categories": ["gambling", "alcohol"],
    "personalized": false
  }'
```

**Response (200)**:
```json
{
  "ad_level": "reduced_ads",
  "excluded_categories": ["gambling", "alcohol"],
  "personalized": false,
  "platform_ad_free_until": 0,
  "updated_at": 1748534400
}
```

### 10.3 Ad Feedback

```bash
curl -X POST http://localhost:8000/ui/ads/feedback \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok" \
  -d '{
    "creative_id": "cre_abc123",
    "campaign_id": "camp_xyz",
    "feedback_type": "not_relevant",
    "reason": "Not interested in this product"
  }'
```

**Response (200)**:
```json
{"ok": true}
```

---

## 11. Error Handling Matrix

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------------|-------------|------------|---------------------|-----------------|
| 1 | Invalid ad_level | 400 | `INVALID_AD_LEVEL` | "ad_level must be full_ads or reduced_ads." | Use valid value |
| 2 | Set ad_free without subscription | 400 | `AD_FREE_REQUIRES_SUBSCRIPTION` | "ad_free requires a platform subscription." | Subscribe first |
| 3 | Invalid category | 400 | `INVALID_CATEGORY` | "Invalid ad categories: [{cat}]." | Use valid enum values |
| 4 | Invalid feedback_type | 400 | `INVALID_FEEDBACK_TYPE` | "Invalid feedback type." | Use: hide, not_relevant, repetitive, offensive |
| 5 | Missing creative_id | 422 | `MISSING_FIELD` | "creative_id is required." | Include creative_id |
| 6 | Platform ad-free expired | -- | -- | Prefs auto-revert to full_ads on GET | Renew subscription |

---

## 12. Observability

### 12.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `ad_pref_updated_total` | Counter | `field` (ad_level, categories, personalized) | Preference updates |
| `ad_pref_level_gauge` | Gauge | `level` (full/reduced/ad_free) | Current user distribution by level |
| `ad_pref_category_excluded_total` | Counter | `category` | Category exclusion frequency |
| `ad_feedback_submitted_total` | Counter | `feedback_type` | Feedback submissions |
| `ad_serve_blocked_by_pref_total` | Counter | `reason` | Ads blocked by user prefs |

### 12.2 Log Events

| Event | Level | Fields |
|-------|-------|--------|
| `ad_pref_updated` | INFO | user_sub, field, old_value, new_value |
| `ad_pref_ad_free_set` | INFO | user_sub, until_ts |
| `ad_pref_ad_free_expired` | INFO | user_sub |
| `ad_serve_blocked` | DEBUG | user_sub, reason, creative_id |
| `ad_feedback_recorded` | INFO | user_sub, creative_id, feedback_type |

### 12.3 Alerting Rules

| Alert | Condition | Severity |
|-------|-----------|----------|
| Mass ad-free opt-in | >10% of users switch to ad_free in 1 hour | P2 |
| Feedback spike | >50 feedbacks for single creative in 15 min | P3 |
| Pref update errors | >5% error rate on PATCH preferences | P3 |

---

## 13. Rollout Plan

### 13.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `USER_AD_PREFS_ENABLED` | `false` | Enable user ad preference management |
| `PLATFORM_AD_FREE_PLAN_ENABLED` | `false` | Enable platform ad-free subscription |

### 13.2 Phased Deployment

| Phase | Scope | Duration | Details |
|-------|-------|----------|---------|
| Phase 1: Backend + Pref Enforcement | Internal | Week 1 | Deploy user_ad_prefs service. Wire should_serve_ad() into serving engine. Prefs default to full_ads. |
| Phase 2: Preferences UI | All users | Week 2 | AdPreferencesSection deployed in Settings. Category exclusions and reduced_ads mode available. |
| Phase 3: Ad-Free Plan | All users | Week 3 | `PLATFORM_AD_FREE_PLAN_ENABLED=true`. Ad-free subscription plan visible in billing. Full GA. |

---

## 14. Performance Considerations

### 14.1 Latency Targets

| Endpoint | Target p50 | Target p99 |
|----------|-----------|-----------|
| GET /preferences | 20ms | 100ms |
| PATCH /preferences | 50ms | 200ms |
| should_serve_ad() (inline) | 5ms | 20ms |
| POST /feedback | 30ms | 100ms |

### 14.2 Caching Strategy

| Data | Cache | staleTime | Invalidation |
|------|-------|-----------|-------------|
| User ad prefs | React Query | 60_000ms | On PATCH mutation |
| User ad prefs (server, in serve_ad) | In-memory LRU | 60s TTL | On update |
| Feedback dialog state | Local React state | -- | On submit |

### 14.3 Preference Read Hot Path

`should_serve_ad()` is called on every ad request. To avoid a DDB read per request, user preferences are cached in an in-memory LRU cache with 60s TTL. Cache key is `user_sub`. The cache is invalidated when `update_ad_prefs()` or `set_platform_ad_free()` is called. For dev mode with single-worker uvicorn, this provides consistent caching.

---

## 15. Expanded E2E Tests

### 15.1 Section 383: Input Validation (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 383.1 | Invalid ad_level rejected | PATCH ad_level="premium"; 400 |
| 383.2 | ad_free requires subscription | PATCH ad_level="ad_free"; 400; "requires subscription" |
| 383.3 | Invalid category rejected | PATCH excluded_categories=["invalid_cat"]; 400 |
| 383.4 | Empty category array accepted | PATCH excluded_categories=[]; 200 |

### 15.2 Section 384: Authorization Boundary (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 384.1 | Unauthenticated GET preferences | GET without session; 401 |
| 384.2 | Unauthenticated PATCH preferences | PATCH without session; 401 |
| 384.3 | Cannot view other user's preferences | No cross-user access (prefs are session-scoped) |

### 15.3 Section 385: Ad-Free Lifecycle (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 385.1 | Set platform ad-free (internal) | Direct DDB write: platform_ad_free_until=future; GET prefs; ad_level=ad_free |
| 385.2 | Ad-free user sees no ads | Set ad-free; should_serve_ad returns serve=false |
| 385.3 | Expired ad-free reverts to full_ads | Set until_ts to past; GET prefs; ad_level=full_ads |
| 385.4 | Reduced ads user sees fewer ads | Set reduced_ads; serve with overlay; serve=false reason=reduced |

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/ad_placement.py` | 178 | Existing `get_ad_config()` — checks subscriber ad-free status |
| `app/services/subscription_access.py` | 55 | Existing `has_active_subscription` — used for per-creator ad-free checks |
| `app/services/user_ad_prefs.py` | — | Does not exist yet — new implementation required |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_user_ad_prefs.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_user_ad_prefs` | Creates record with correct fields and generated ID |
| `test_create_user_ad_prefs_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_user_ad_prefs_found` | Returns correct record by ID |
| `test_get_user_ad_prefs_not_found` | Returns None for non-existent ID |
| `test_list_user_ad_prefs` | Returns all records for the given scope/owner |
| `test_update_user_ad_prefs` | Updates mutable fields and sets updated_at |
| `test_delete_user_ad_prefs` | Removes record; subsequent get returns None |
| `test_user_ad_prefs_owner_check` | Rejects operations from non-owner users |
| `test_user_ad_prefs_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_user_ad_prefs_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/ads-user-prefs.spec.ts`


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


- **Feature flags**: `USER_AD_PREFS_ENABLED` must be `true` in `.env.local`
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| ADS-004 | Ad serving engine (user pref checks) | Pending | Yes (parallel dev) |
| ADS-005 | Sponsored posts (hide signals) | Pending | Yes (parallel dev) |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| (none currently identified) | -- |

### Merge Strategy


**Feature-flag-gated**


- Gated behind feature flag(s): `USER_AD_PREFS_ENABLED`
- Can merge to `main` with flags disabled; enable when dependencies are ready
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB tables verified (uses existing tables only)
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/ads.py`)
- [ ] Frontend route(s) added to `App.tsx`: `/settings/ads`
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
