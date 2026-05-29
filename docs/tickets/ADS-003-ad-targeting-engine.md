# ADS-003: Ad Targeting Engine

**Ticket**: ADS-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 7-9 days
**Dependencies**: ADS-001 (Advertiser Accounts & Campaign Manager)

---

## 1. Overview & Motivation

### 1.1 Purpose

ADS-003 adds targeting definitions to ad campaigns. Advertisers define who should see their ads using demographic, geographic, behavioral, and content-based targeting dimensions. The targeting engine evaluates ad requests against targeting rules to determine which campaigns are eligible for a given viewer and context.

This ticket also covers the creator side: content providers opt into which ad categories they allow on their content, and can block specific advertisers. The targeting engine respects these creator preferences during ad selection.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Advertiser | As an advertiser, I want to target specific age ranges and genders. | Targeting editor shows demographic selectors; saved to targeting record. |
| Advertiser | As an advertiser, I want to target viewers in specific countries. | Country multi-select; ads only served to matching geolocations. |
| Advertiser | As an advertiser, I want to target viewers who watch specific creators. | Creator ID list; ads served on those creators' content. |
| Advertiser | As an advertiser, I want to see estimated audience size for my targeting. | Audience estimate endpoint returns count; updates as targeting changes. |
| Creator | As a creator, I want to choose which ad categories I allow on my content. | Ad category preferences in creator settings. |
| Creator | As a creator, I want to block specific advertisers from my content. | Block list management; blocked advertiser's ads never shown. |

### 1.3 Targeting Dimensions

```
Targeting Evaluation (per ad request)
─────────────────────────────────────

Viewer Context                  Targeting Rule              Match?
──────────────                  ──────────────              ──────
age=28                    →     age_range=[25-34]           ✓
country=US                →     country_codes=[US,CA,GB]    ✓
interests=[gaming,music]  →     categories=[gaming]         ✓
device=mobile             →     device_type=[mobile]        ✓
creator=creator_123       →     creator_ids=[creator_123]   ✓
─────────────────────────────────────────────────────────────
All dimensions match → Campaign ELIGIBLE

Creator Preferences (secondary filter)
──────────────────────────────────────
creator allows ad_category=gaming?    → ✓
creator blocks advertiser account?    → ✗ if blocked
```

---

## 2. Current State Analysis

### 2.1 Ad Placement Resolution (`app/services/ad_placement.py`)

The current `get_ad_config()` function (line 178) checks only two things: whether the video is `ad_supported` and whether the viewer is a subscriber with ad-free access. There is no targeting evaluation — every non-subscriber viewer sees the same hardcoded ads regardless of demographics or context.

### 2.2 User Profile Data

User profiles stored in the `sessions` table and `billing` table contain limited demographic data. The platform does not currently collect age, gender, or interests explicitly. For MVP targeting:
- **Country**: inferred from IP (mock: always `US` in dev mode)
- **Device type**: inferred from User-Agent header
- **Content categories**: derived from content metadata (creators tag their content)
- **Age/gender**: stored on user profile if provided (optional fields)

### 2.3 Creator Settings Pattern

Creator settings are stored in the `billing` table with pattern `pk=USER#{creator_sub}`, `sk=CREATOR_SETTINGS`. Existing settings include payout preferences. Ad category preferences follow the same pattern with `sk=AD_SETTINGS`.

### 2.4 Gaps

1. **No targeting table** — no storage for campaign targeting rules.
2. **No targeting evaluation** — ad placement doesn't consider viewer context.
3. **No audience estimation** — no way to preview audience size.
4. **No creator ad preferences** — creators cannot control which ads appear.
5. **No advertiser block list** — creators cannot block specific advertisers.
6. **No targeting editor UI** — no frontend for defining targeting rules.

---

## 3. Technical Design

### 3.1 DynamoDB Table

#### `ad_targeting` Table

| PK | SK | Fields |
|----|----|--------|
| `CAMP#{campaign_id}` | `TARGETING#{target_set_id}` | `target_set_id`, `campaign_id`, `account_id`, `name`, `age_ranges`, `genders`, `country_codes`, `regions`, `cities`, `content_categories`, `active_hours`, `device_types`, `new_user_only`, `creator_ids`, `content_types`, `exclude_creator_ids`, `exclude_categories`, `created_at`, `updated_at` |

**GSIs**:

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|--------------|----------|---------|
| `ByCampaignCreatedAt` | `campaign_id` (S) | `created_at` (N) | List targeting sets for a campaign |

**`scripts/local-ddb-init.py`**:
```python
TableDef(
    os.environ.get("DDB_AD_TARGETING", "AdTargeting"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByCampaignCreatedAt", "partition_key": "campaign_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

### 3.2 Creator Ad Preferences (existing `billing` table)

| PK | SK | Fields |
|----|----|--------|
| `USER#{creator_sub}` | `AD_SETTINGS` | `allow_ads: bool`, `allowed_ad_categories: list`, `min_cpm_cents: int`, `updated_at: int` |
| `USER#{creator_sub}` | `AD_BLOCK#{account_id}` | `account_id: str`, `blocked_at: int`, `reason: str` |

No new table needed — reuses the `billing` table with the established per-user pattern.

### 3.3 Backend Models

**File**: `app/models.py`

```python
class TargetingCreateIn(BaseModel):
    name: str = Field(default="Default", max_length=100)
    age_ranges: Optional[list[str]] = None  # ["18-24", "25-34", "35-44", "45-54", "55+"]
    genders: Optional[list[str]] = None     # ["male", "female", "other"]
    country_codes: Optional[list[str]] = None  # ISO 3166-1 alpha-2
    regions: Optional[list[str]] = None
    cities: Optional[list[str]] = None
    content_categories: Optional[list[str]] = None  # ["gaming", "music", "fitness", ...]
    active_hours: Optional[list[int]] = None  # [0-23] UTC hours
    device_types: Optional[list[str]] = None  # ["mobile", "desktop", "tablet"]
    new_user_only: bool = False
    creator_ids: Optional[list[str]] = None
    content_types: Optional[list[str]] = None  # ["newsfeed", "broadcast", "vod"]
    exclude_creator_ids: Optional[list[str]] = None
    exclude_categories: Optional[list[str]] = None

class TargetingOut(BaseModel):
    target_set_id: str
    campaign_id: str
    name: str
    age_ranges: Optional[list[str]] = None
    genders: Optional[list[str]] = None
    country_codes: Optional[list[str]] = None
    regions: Optional[list[str]] = None
    cities: Optional[list[str]] = None
    content_categories: Optional[list[str]] = None
    active_hours: Optional[list[int]] = None
    device_types: Optional[list[str]] = None
    new_user_only: bool = False
    creator_ids: Optional[list[str]] = None
    content_types: Optional[list[str]] = None
    exclude_creator_ids: Optional[list[str]] = None
    exclude_categories: Optional[list[str]] = None
    created_at: int
    updated_at: int

class AudienceEstimateOut(BaseModel):
    estimated_reach: int
    targeting_summary: dict

class CreatorAdSettingsIn(BaseModel):
    allow_ads: Optional[bool] = None
    allowed_ad_categories: Optional[list[str]] = None
    min_cpm_cents: Optional[int] = Field(default=None, ge=0)
```

### 3.4 Backend Service

**File**: `app/services/ad_targeting.py`

```python
def create_targeting(campaign_id: str, account_id: str, data: TargetingCreateIn) -> dict:
    target_set_id = f"tgt_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    item = {
        "pk": f"CAMP#{campaign_id}",
        "sk": f"TARGETING#{target_set_id}",
        "target_set_id": target_set_id,
        "campaign_id": campaign_id,
        "account_id": account_id,
        "name": data.name,
        "age_ranges": data.age_ranges,
        "genders": data.genders,
        "country_codes": data.country_codes,
        "regions": data.regions,
        "cities": data.cities,
        "content_categories": data.content_categories,
        "active_hours": data.active_hours,
        "device_types": data.device_types,
        "new_user_only": data.new_user_only,
        "creator_ids": data.creator_ids,
        "content_types": data.content_types,
        "exclude_creator_ids": data.exclude_creator_ids,
        "exclude_categories": data.exclude_categories,
        "created_at": ts,
        "updated_at": ts,
    }
    T.ad_targeting.put_item(Item={k: v for k, v in item.items() if v is not None})
    return item

def get_targeting(campaign_id: str, target_set_id: str) -> Optional[dict]:
    resp = T.ad_targeting.get_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"TARGETING#{target_set_id}"}
    )
    return resp.get("Item")

def list_targeting_sets(campaign_id: str) -> list[dict]:
    resp = T.ad_targeting.query(
        KeyConditionExpression=Key("pk").eq(f"CAMP#{campaign_id}") & Key("sk").begins_with("TARGETING#"),
    )
    return resp.get("Items", [])

def update_targeting(campaign_id: str, target_set_id: str, data: TargetingCreateIn) -> dict:
    """Replace targeting set with new values."""
    existing = get_targeting(campaign_id, target_set_id)
    if not existing:
        raise ValueError("Targeting set not found")
    updated = {**existing, **{k: v for k, v in data.dict().items() if v is not None}, "updated_at": now_ts()}
    T.ad_targeting.put_item(Item={k: v for k, v in updated.items() if v is not None})
    return updated

def delete_targeting(campaign_id: str, target_set_id: str) -> dict:
    T.ad_targeting.delete_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"TARGETING#{target_set_id}"}
    )
    return {"ok": True}

def estimate_audience(targeting: TargetingCreateIn) -> dict:
    """Estimate audience size based on targeting dimensions (mock implementation).

    In dev mode, returns a deterministic count based on targeting breadth.
    Each restriction reduces the base audience proportionally.
    """
    base = 100_000
    multiplier = 1.0
    if targeting.country_codes:
        multiplier *= min(1.0, len(targeting.country_codes) * 0.15)
    if targeting.age_ranges:
        multiplier *= min(1.0, len(targeting.age_ranges) * 0.2)
    if targeting.genders:
        multiplier *= min(1.0, len(targeting.genders) * 0.4)
    if targeting.device_types:
        multiplier *= min(1.0, len(targeting.device_types) * 0.4)
    if targeting.content_categories:
        multiplier *= min(1.0, len(targeting.content_categories) * 0.1)
    if targeting.creator_ids:
        multiplier *= min(1.0, len(targeting.creator_ids) * 0.01)
    estimated = int(base * multiplier)
    return {"estimated_reach": max(100, estimated), "targeting_summary": targeting.dict(exclude_none=True)}

def evaluate_targeting(targeting: dict, context: dict) -> bool:
    """Evaluate whether an ad request context matches a targeting set.

    context keys: user_age, user_gender, user_country, device_type,
                  content_type, creator_id, content_categories, user_created_at, hour_utc
    """
    # Age range check
    if targeting.get("age_ranges"):
        user_age = context.get("user_age")
        if user_age is not None and not _age_in_ranges(user_age, targeting["age_ranges"]):
            return False
    # Gender check
    if targeting.get("genders"):
        if context.get("user_gender") and context["user_gender"] not in targeting["genders"]:
            return False
    # Country check
    if targeting.get("country_codes"):
        if context.get("user_country") and context["user_country"] not in targeting["country_codes"]:
            return False
    # Device type check
    if targeting.get("device_types"):
        if context.get("device_type") and context["device_type"] not in targeting["device_types"]:
            return False
    # Content type check
    if targeting.get("content_types"):
        if context.get("content_type") and context["content_type"] not in targeting["content_types"]:
            return False
    # Creator targeting
    if targeting.get("creator_ids"):
        if context.get("creator_id") and context["creator_id"] not in targeting["creator_ids"]:
            return False
    # Creator exclusions
    if targeting.get("exclude_creator_ids"):
        if context.get("creator_id") and context["creator_id"] in targeting["exclude_creator_ids"]:
            return False
    # Category exclusions
    if targeting.get("exclude_categories"):
        content_cats = set(context.get("content_categories", []))
        if content_cats & set(targeting["exclude_categories"]):
            return False
    # New user check
    if targeting.get("new_user_only"):
        created_at = context.get("user_created_at", 0)
        if now_ts() - created_at > 30 * 86400:  # > 30 days old
            return False
    return True

def _age_in_ranges(age: int, ranges: list[str]) -> bool:
    for r in ranges:
        if r == "55+":
            if age >= 55:
                return True
        elif "-" in r:
            lo, hi = r.split("-")
            if int(lo) <= age <= int(hi):
                return True
    return False
```

**File**: `app/services/creator_ad_prefs.py`

```python
def get_creator_ad_settings(creator_sub: str) -> dict:
    resp = T.billing.get_item(Key={"pk": f"USER#{creator_sub}", "sk": "AD_SETTINGS"})
    item = resp.get("Item")
    if not item:
        return {"allow_ads": True, "allowed_ad_categories": [], "min_cpm_cents": 0}
    return item

def update_creator_ad_settings(creator_sub: str, data: CreatorAdSettingsIn) -> dict:
    updates = {k: v for k, v in data.dict(exclude_none=True).items()}
    updates["updated_at"] = now_ts()
    T.billing.put_item(Item={
        "pk": f"USER#{creator_sub}",
        "sk": "AD_SETTINGS",
        **updates,
    })
    return {"ok": True}

def block_advertiser(creator_sub: str, account_id: str, reason: str = "") -> dict:
    T.billing.put_item(Item={
        "pk": f"USER#{creator_sub}",
        "sk": f"AD_BLOCK#{account_id}",
        "account_id": account_id,
        "blocked_at": now_ts(),
        "reason": reason,
    })
    return {"ok": True}

def unblock_advertiser(creator_sub: str, account_id: str) -> dict:
    T.billing.delete_item(Key={"pk": f"USER#{creator_sub}", "sk": f"AD_BLOCK#{account_id}"})
    return {"ok": True}

def list_blocked_advertisers(creator_sub: str) -> list[dict]:
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{creator_sub}") & Key("sk").begins_with("AD_BLOCK#"),
    )
    return resp.get("Items", [])

def is_advertiser_blocked(creator_sub: str, account_id: str) -> bool:
    resp = T.billing.get_item(Key={"pk": f"USER#{creator_sub}", "sk": f"AD_BLOCK#{account_id}"})
    return resp.get("Item") is not None
```

### 3.5 Backend Router

**File**: `app/routers/ads.py` (extend)

```python
# ── Targeting ──

@router.post("/campaigns/{campaign_id}/targeting", status_code=201)
def create_targeting_endpoint(campaign_id: str, body: TargetingCreateIn, ctx=Depends(require_ui_session)):
    campaign = _require_campaign_owner(campaign_id, ctx["user_sub"])
    return create_targeting(campaign_id, campaign["account_id"], body)

@router.get("/campaigns/{campaign_id}/targeting")
def list_targeting_endpoint(campaign_id: str, ctx=Depends(require_ui_session)):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return list_targeting_sets(campaign_id)

@router.put("/campaigns/{campaign_id}/targeting/{target_set_id}")
def update_targeting_endpoint(campaign_id: str, target_set_id: str, body: TargetingCreateIn, ctx=Depends(require_ui_session)):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return update_targeting(campaign_id, target_set_id, body)

@router.delete("/campaigns/{campaign_id}/targeting/{target_set_id}")
def delete_targeting_endpoint(campaign_id: str, target_set_id: str, ctx=Depends(require_ui_session)):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return delete_targeting(campaign_id, target_set_id)

@router.post("/campaigns/{campaign_id}/targeting/estimate")
def estimate_audience_endpoint(campaign_id: str, body: TargetingCreateIn, ctx=Depends(require_ui_session)):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return estimate_audience(body)

# ── Creator Ad Preferences ──

@router.get("/creator/ad-settings")
def get_ad_settings(ctx=Depends(require_ui_session)):
    return get_creator_ad_settings(ctx["user_sub"])

@router.patch("/creator/ad-settings")
def update_ad_settings(body: CreatorAdSettingsIn, ctx=Depends(require_ui_session)):
    return update_creator_ad_settings(ctx["user_sub"], body)

@router.post("/creator/ad-blocks")
def block_advertiser_endpoint(body: dict, ctx=Depends(require_ui_session)):
    return block_advertiser(ctx["user_sub"], body["account_id"], body.get("reason", ""))

@router.delete("/creator/ad-blocks/{account_id}")
def unblock_advertiser_endpoint(account_id: str, ctx=Depends(require_ui_session)):
    return unblock_advertiser(ctx["user_sub"], account_id)
```

### 3.6 Frontend Pages

**File**: `frontend/src/pages/ads/TargetingEditor.tsx`

- Embedded in CampaignEditor or standalone page
- Dimension panels: Demographics (age range checkboxes, gender checkboxes), Geography (country multi-select), Interests (category tag input), Behavior (device type, active hours, new user toggle), Content (creator ID search, content type checkboxes)
- Exclusion section: exclude creators, exclude categories
- Audience size preview card: updates on each targeting change via debounced estimate API call
- `data-testid="targeting-editor"`

### 3.7 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface AdTargeting {
  target_set_id: string;
  campaign_id: string;
  name: string;
  age_ranges?: string[] | null;
  genders?: string[] | null;
  country_codes?: string[] | null;
  regions?: string[] | null;
  cities?: string[] | null;
  content_categories?: string[] | null;
  active_hours?: number[] | null;
  device_types?: string[] | null;
  new_user_only: boolean;
  creator_ids?: string[] | null;
  content_types?: string[] | null;
  exclude_creator_ids?: string[] | null;
  exclude_categories?: string[] | null;
  created_at: number;
  updated_at: number;
}

export interface AudienceEstimate {
  estimated_reach: number;
  targeting_summary: Record<string, unknown>;
}
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_targeting.py` | Targeting CRUD, evaluation, audience estimation |
| `app/services/creator_ad_prefs.py` | Creator ad settings + block list |
| `frontend/src/pages/ads/TargetingEditor.tsx` | Targeting dimension panels + audience preview |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/ads.py` | Add targeting + creator ad settings endpoints |
| `app/models.py` | Add targeting + creator ad settings models |
| `app/core/settings.py` | Add `ad_targeting_table_name` |
| `app/core/tables.py` | Add `ad_targeting` table handle |
| `scripts/local-ddb-init.py` | Add `AdTargeting` table definition |
| `frontend/src/api/types.ts` | Add `AdTargeting`, `AudienceEstimate` types |
| `frontend/src/api/endpoints/ads.ts` | Add targeting + creator settings API functions |

### 4.3 Step-by-Step Order

1. Add DDB table definition
2. Add settings + table handle
3. Implement `ad_targeting.py` service
4. Implement `creator_ad_prefs.py` service
5. Add Pydantic models
6. Add endpoints to ads router
7. Add frontend types + API endpoints
8. Build TargetingEditor
9. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/ads-targeting.spec.ts` — 18 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let accountId: string;
let campaignId: string;
let targetSetId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice (advertiser), Bob (creator), Root (admin)
  // Create and approve ad account + campaign
});
```

### 5.3 Section 350: Targeting CRUD API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 350.1 | Create targeting set | POST with age_ranges, country_codes, device_types; 201; target_set_id returned |
| 350.2 | List targeting sets | GET; 200; array includes created targeting set |
| 350.3 | Update targeting set | PUT with new country_codes; 200; GET confirms updated values |
| 350.4 | Delete targeting set | DELETE; 200; GET returns 404 |
| 350.5 | Create targeting with exclusions | POST with exclude_creator_ids + exclude_categories; 201; fields stored |

### 5.4 Section 351: Audience Estimation API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 351.1 | Broad targeting returns large estimate | POST estimate with no restrictions; `estimated_reach` >= 50000 |
| 351.2 | Narrow targeting returns smaller estimate | POST estimate with single country + single age range; `estimated_reach` < broad estimate |
| 351.3 | Creator-specific targeting returns smallest estimate | POST estimate with single creator_id; `estimated_reach` <= 1000 |
| 351.4 | Estimate returns targeting summary | Response `targeting_summary` contains submitted dimensions |

### 5.5 Section 352: Creator Ad Preferences API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 352.1 | Get default ad settings | Bob GET `/ui/ads/creator/ad-settings`; allow_ads=true, empty categories |
| 352.2 | Update ad settings | Bob PATCH allow_ads=false; 200; GET confirms allow_ads=false |
| 352.3 | Set allowed ad categories | Bob PATCH allowed_ad_categories=["gaming","fitness"]; 200; GET confirms |
| 352.4 | Block advertiser | Bob POST block with Alice's account_id; 200 |
| 352.5 | Unblock advertiser | Bob DELETE block; 200; block list empty |

### 5.6 Section 353: Targeting Editor UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 353.1 | Targeting editor shows dimension panels | Navigate to campaign targeting; age, country, device sections visible |
| 353.2 | Age range checkboxes are selectable | Check "25-34" checkbox; targeting state updates |
| 353.3 | Country multi-select works | Select "US" and "CA"; both appear as tags |
| 353.4 | Audience size preview displays | Estimate card visible with reach number; updates when targeting changes |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Campaign not found | 404 | "Campaign not found" |
| Targeting set not found | 404 | "Targeting set not found" |
| Invalid age range format | 422 | Pydantic validation |
| Invalid country code | 422 | Custom validator (ISO 3166-1 check) |
| Contradictory targeting (exclude = include) | 400 | "Cannot exclude and include the same creator" |
| Too many creator IDs (>100) | 400 | "Maximum 100 creator IDs per targeting set" |

---

## 7. Security Considerations

- Targeting data never exposed to viewers (no "why am I seeing this?" detail beyond category)
- Creator ad settings only modifiable by the creator themselves
- Block list is private; advertisers cannot see who blocked them
- Audience estimates are approximate; no individual user data exposed
- `evaluate_targeting()` runs server-side; clients cannot bypass targeting

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-001 | Campaign hierarchy | Required |

### 8.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| ADS-004 (Ad Serving) | Targeting evaluation from ADS-003 |
| ADS-005 (Sponsored Posts) | Creator ad preferences from ADS-003 |
| ADS-009 (User Ad Prefs) | User-side preference checks complement ADS-003 creator checks |
| ADS-010 (Content Provider Controls) | Extends creator ad settings from ADS-003 |
