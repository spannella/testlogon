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

---

## 9. Architecture & Data Flow

```
Ad Request Targeting Evaluation Flow
─────────────────────────────────────

  Client (ad surface)
       │
       │  POST /serve_ad { surface, content_type, creator_id, user_id, ... }
       ▼
  ┌──────────────────────────────┐
  │   Ad Serving Engine (ADS-004)│
  │                              │
  │ 1. Build viewer context:     │
  │    - IP → country (mock: US) │
  │    - UA → device_type        │
  │    - Profile → age, gender   │
  │    - Content → categories    │
  └──────────┬───────────────────┘
             │
             ▼
  ┌──────────────────────────────┐
  │   Campaign Selection Loop    │
  │                              │
  │ For each active campaign:    │
  │   ┌────────────────────────┐ │
  │   │ Load targeting sets    │ │
  │   │ (ad_targeting table)   │ │
  │   └──────────┬─────────────┘ │
  │              │               │
  │              ▼               │
  │   ┌────────────────────────┐ │
  │   │ evaluate_targeting()   │ │
  │   │ Check each dimension:  │ │
  │   │  age_ranges    ✓/✗    │ │
  │   │  genders       ✓/✗    │ │
  │   │  country_codes ✓/✗    │ │
  │   │  device_types  ✓/✗    │ │
  │   │  content_types ✓/✗    │ │
  │   │  creator_ids   ✓/✗    │ │
  │   │  exclude_*     ✓/✗    │ │
  │   │  new_user_only ✓/✗    │ │
  │   └──────────┬─────────────┘ │
  │              │               │
  │         ALL MATCH?           │
  │        yes │    │ no         │
  │            ▼    ▼            │
  │       eligible  skip         │
  └──────────┬───────────────────┘
             │
             ▼
  ┌──────────────────────────────┐
  │   Creator Preference Filter  │
  │                              │
  │ 1. get_creator_ad_settings() │
  │    - allow_ads? → if false,  │
  │      skip all ads            │
  │ 2. allowed_ad_categories     │
  │    - ad category in list?    │
  │ 3. is_advertiser_blocked()   │
  │    - advertiser on blocklist?│
  │ 4. min_cpm_cents             │
  │    - bid >= min?             │
  └──────────┬───────────────────┘
             │
             ▼
  ┌──────────────────────────────┐
  │   Return winning ad or empty │
  └──────────────────────────────┘
```

---

## 10. Detailed DynamoDB Access Patterns

| # | Access Pattern | Table | Key Condition | GSI | Query Type | Example |
|---|---------------|-------|---------------|-----|-----------|---------|
| 1 | Get targeting set by ID | `ad_targeting` | `pk=CAMP#{campaign_id}, sk=TARGETING#{target_set_id}` | -- | GetItem | Single targeting set fetch |
| 2 | List targeting sets for campaign | `ad_targeting` | `pk=CAMP#{campaign_id}, sk begins_with TARGETING#` | -- | Query | All targeting sets for a campaign |
| 3 | List targeting sets by created_at | `ad_targeting` | `campaign_id=X` | `ByCampaignCreatedAt` | Query | Targeting sets sorted by creation time |
| 4 | Delete targeting set | `ad_targeting` | `pk=CAMP#{campaign_id}, sk=TARGETING#{target_set_id}` | -- | DeleteItem | Remove single targeting set |
| 5 | Get creator ad settings | `billing` | `pk=USER#{creator_sub}, sk=AD_SETTINGS` | -- | GetItem | Creator's global ad preferences |
| 6 | Update creator ad settings | `billing` | `pk=USER#{creator_sub}, sk=AD_SETTINGS` | -- | PutItem | Overwrite creator ad settings |
| 7 | Check advertiser blocked | `billing` | `pk=USER#{creator_sub}, sk=AD_BLOCK#{account_id}` | -- | GetItem | Boolean blocked check |
| 8 | List blocked advertisers | `billing` | `pk=USER#{creator_sub}, sk begins_with AD_BLOCK#` | -- | Query | All blocked accounts for creator |
| 9 | Block advertiser | `billing` | `pk=USER#{creator_sub}, sk=AD_BLOCK#{account_id}` | -- | PutItem | Add to block list |
| 10 | Unblock advertiser | `billing` | `pk=USER#{creator_sub}, sk=AD_BLOCK#{account_id}` | -- | DeleteItem | Remove from block list |

---

## 11. API Request/Response Examples

### 11.1 Create Targeting Set

```bash
curl -X POST http://localhost:8000/ui/ads/campaigns/camp_abc123/targeting \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok" \
  -d '{
    "name": "US Gamers 25-34",
    "age_ranges": ["25-34"],
    "genders": ["male", "female"],
    "country_codes": ["US"],
    "device_types": ["mobile", "desktop"],
    "content_categories": ["gaming"],
    "new_user_only": false
  }'
```

**Response (201)**:
```json
{
  "target_set_id": "tgt_a1b2c3d4e5f6",
  "campaign_id": "camp_abc123",
  "name": "US Gamers 25-34",
  "age_ranges": ["25-34"],
  "genders": ["male", "female"],
  "country_codes": ["US"],
  "device_types": ["mobile", "desktop"],
  "content_categories": ["gaming"],
  "new_user_only": false,
  "created_at": 1748534400,
  "updated_at": 1748534400
}
```

### 11.2 Estimate Audience

```bash
curl -X POST http://localhost:8000/ui/ads/campaigns/camp_abc123/targeting/estimate \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok" \
  -d '{
    "country_codes": ["US"],
    "age_ranges": ["25-34"],
    "content_categories": ["gaming"]
  }'
```

**Response (200)**:
```json
{
  "estimated_reach": 3000,
  "targeting_summary": {
    "country_codes": ["US"],
    "age_ranges": ["25-34"],
    "content_categories": ["gaming"]
  }
}
```

### 11.3 Update Creator Ad Settings

```bash
curl -X PATCH http://localhost:8000/ui/ads/creator/ad-settings \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_bob; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok" \
  -d '{
    "allow_ads": true,
    "allowed_ad_categories": ["gaming", "fitness"],
    "min_cpm_cents": 500
  }'
```

**Response (200)**:
```json
{"ok": true}
```

### 11.4 Block Advertiser

```bash
curl -X POST http://localhost:8000/ui/ads/creator/ad-blocks \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_bob; ui_csrf=csrf_tok; ui_access_token=jwt_tok" \
  -H "x-csrf-token: csrf_tok" \
  -d '{"account_id": "adv_alice_001", "reason": "Competitor brand"}'
```

**Response (200)**:
```json
{"ok": true}
```

---

## 12. Error Handling Matrix

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------------|-------------|------------|---------------------|-----------------|
| 1 | Campaign not found | 404 | `CAMPAIGN_NOT_FOUND` | "Campaign not found." | Verify campaign_id exists |
| 2 | Not campaign owner | 403 | `NOT_CAMPAIGN_OWNER` | "You do not own this campaign." | Use the owning account |
| 3 | Targeting set not found | 404 | `TARGETING_NOT_FOUND` | "Targeting set not found." | Verify target_set_id |
| 4 | Invalid age range format | 422 | `INVALID_AGE_RANGE` | "Invalid age range: must be 'N-N' or '55+'." | Use format like "25-34" |
| 5 | Invalid country code | 422 | `INVALID_COUNTRY_CODE` | "Invalid country code: {code}." | Use ISO 3166-1 alpha-2 |
| 6 | Contradictory targeting | 400 | `CONTRADICTORY_TARGETING` | "Cannot include and exclude the same creator." | Remove from one list |
| 7 | Too many creator IDs | 400 | `TOO_MANY_CREATORS` | "Maximum 100 creator IDs per targeting set." | Reduce creator list |
| 8 | Invalid content type | 422 | `INVALID_CONTENT_TYPE` | "Content type must be newsfeed, broadcast, or vod." | Use valid content type |
| 9 | Invalid device type | 422 | `INVALID_DEVICE_TYPE` | "Device type must be mobile, desktop, or tablet." | Use valid device type |
| 10 | Active hours out of range | 422 | `INVALID_HOURS` | "Active hours must be 0-23." | Use valid UTC hour values |
| 11 | Invalid ad category (creator) | 400 | `INVALID_AD_CATEGORY` | "Invalid ad category: {cat}." | Use valid category enum |
| 12 | Negative min CPM | 422 | `INVALID_MIN_CPM` | "min_cpm_cents must be >= 0." | Use non-negative value |

---

## 13. Expanded Pydantic Models with Validators

```python
from pydantic import BaseModel, Field, field_validator
from typing import Optional
import re

VALID_AGE_RANGES = {"18-24", "25-34", "35-44", "45-54", "55+"}
VALID_GENDERS = {"male", "female", "other"}
VALID_DEVICE_TYPES = {"mobile", "desktop", "tablet"}
VALID_CONTENT_TYPES = {"newsfeed", "broadcast", "vod"}
ISO_3166_PATTERN = re.compile(r"^[A-Z]{2}$")

class TargetingCreateIn(BaseModel):
    name: str = Field(default="Default", max_length=100)
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

    @field_validator("age_ranges")
    @classmethod
    def validate_age_ranges(cls, v):
        if v is None:
            return v
        for r in v:
            if r not in VALID_AGE_RANGES:
                raise ValueError(f"Invalid age range: {r}. Must be one of {VALID_AGE_RANGES}")
        return v

    @field_validator("genders")
    @classmethod
    def validate_genders(cls, v):
        if v is None:
            return v
        for g in v:
            if g not in VALID_GENDERS:
                raise ValueError(f"Invalid gender: {g}. Must be one of {VALID_GENDERS}")
        return v

    @field_validator("country_codes")
    @classmethod
    def validate_country_codes(cls, v):
        if v is None:
            return v
        for code in v:
            if not ISO_3166_PATTERN.match(code):
                raise ValueError(f"Invalid country code: {code}. Must be ISO 3166-1 alpha-2")
        return v

    @field_validator("active_hours")
    @classmethod
    def validate_active_hours(cls, v):
        if v is None:
            return v
        for h in v:
            if not (0 <= h <= 23):
                raise ValueError(f"Active hour {h} out of range. Must be 0-23")
        return v

    @field_validator("device_types")
    @classmethod
    def validate_device_types(cls, v):
        if v is None:
            return v
        for d in v:
            if d not in VALID_DEVICE_TYPES:
                raise ValueError(f"Invalid device type: {d}. Must be one of {VALID_DEVICE_TYPES}")
        return v

    @field_validator("creator_ids")
    @classmethod
    def validate_creator_ids_limit(cls, v):
        if v is not None and len(v) > 100:
            raise ValueError("Maximum 100 creator IDs per targeting set")
        return v

    @field_validator("exclude_creator_ids")
    @classmethod
    def validate_no_contradictory_creators(cls, v, info):
        if v is None:
            return v
        creator_ids = info.data.get("creator_ids") or []
        overlap = set(v) & set(creator_ids)
        if overlap:
            raise ValueError(f"Cannot exclude and include the same creator: {overlap}")
        return v

class CreatorAdSettingsIn(BaseModel):
    allow_ads: Optional[bool] = None
    allowed_ad_categories: Optional[list[str]] = None
    min_cpm_cents: Optional[int] = Field(default=None, ge=0)

    @field_validator("allowed_ad_categories")
    @classmethod
    def validate_ad_categories(cls, v):
        if v is None:
            return v
        valid = {"gaming", "music", "fitness", "beauty", "tech", "food", "travel",
                 "finance", "education", "entertainment", "lifestyle", "sports"}
        for cat in v:
            if cat not in valid:
                raise ValueError(f"Invalid ad category: {cat}")
        return v
```

---

## 14. Frontend Component Tree

```
TargetingEditor (data-testid="targeting-editor")
├── DemographicsPanel
│   ├── AgeRangeCheckboxGroup (checkboxes: 18-24, 25-34, 35-44, 45-54, 55+)
│   └── GenderCheckboxGroup (checkboxes: male, female, other)
├── GeographyPanel
│   ├── CountryMultiSelect (searchable, ISO codes)
│   ├── RegionMultiSelect (optional, depends on selected countries)
│   └── CityMultiSelect (optional)
├── InterestsPanel
│   └── CategoryTagInput (tag chips for content categories)
├── BehaviorPanel
│   ├── DeviceTypeCheckboxGroup (mobile, desktop, tablet)
│   ├── ActiveHoursSlider (multi-range 0-23 UTC)
│   └── NewUserOnlyToggle (Switch component)
├── ContentPanel
│   ├── CreatorIdSearch (autocomplete search input)
│   └── ContentTypeCheckboxGroup (newsfeed, broadcast, vod)
├── ExclusionPanel
│   ├── ExcludeCreatorIdSearch
│   └── ExcludeCategoryTagInput
└── AudienceEstimateCard
    ├── ReachNumber (formatted integer)
    ├── TargetingSummaryList
    └── RefreshButton (debounced, fires on each targeting change)
```

### Props Interfaces

```typescript
interface TargetingEditorProps {
  campaignId: string;
  initialTargeting?: AdTargeting | null;
  onSave: (targeting: AdTargeting) => void;
  onCancel: () => void;
}

interface AudienceEstimateCardProps {
  campaignId: string;
  targeting: Partial<AdTargeting>;
  debounceMs?: number;  // default 500
}

interface CreatorAdSettingsFormProps {
  initialSettings?: CreatorAdSettings;
  onSave: (settings: CreatorAdSettingsIn) => void;
}

interface AdvertiserBlockListProps {
  blocks: Array<{ account_id: string; blocked_at: number; reason: string }>;
  onBlock: (accountId: string, reason: string) => void;
  onUnblock: (accountId: string) => void;
}
```

---

## 15. Observability

### 15.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `ad_targeting_created_total` | Counter | `campaign_id` | Targeting sets created |
| `ad_targeting_evaluated_total` | Counter | `result` (match/miss) | Targeting evaluations performed |
| `ad_targeting_dimension_miss_total` | Counter | `dimension` | Which dimension caused the miss |
| `ad_audience_estimate_requests_total` | Counter | -- | Audience estimate API calls |
| `ad_creator_ad_settings_updated_total` | Counter | `creator_id` | Creator settings updates |
| `ad_advertiser_blocked_total` | Counter | -- | Advertiser blocks recorded |
| `ad_targeting_evaluation_duration_ms` | Histogram | -- | Time spent in evaluate_targeting() |

### 15.2 Log Events

| Event | Level | Fields |
|-------|-------|--------|
| `targeting_created` | INFO | campaign_id, target_set_id, dimension_count |
| `targeting_updated` | INFO | campaign_id, target_set_id, changed_fields |
| `targeting_deleted` | INFO | campaign_id, target_set_id |
| `targeting_evaluated` | DEBUG | campaign_id, context_hash, result (match/miss), miss_dimension |
| `audience_estimated` | INFO | campaign_id, estimated_reach, dimension_count |
| `creator_settings_updated` | INFO | creator_sub, allow_ads, category_count |
| `advertiser_blocked` | INFO | creator_sub, account_id |
| `advertiser_unblocked` | INFO | creator_sub, account_id |

### 15.3 Alerting Rules

| Alert | Condition | Severity |
|-------|-----------|----------|
| High targeting miss rate | >95% of evaluations return miss over 1 hour | P3 — warn |
| Audience estimate latency | p99 > 2000ms over 15 minutes | P3 — warn |
| Creator settings error rate | >5% error rate on PATCH ad-settings | P2 — page |

---

## 16. Rollout Plan

### 16.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `AD_TARGETING_ENABLED` | `false` | Enable targeting evaluation in ad serving |
| `AD_CREATOR_PREFS_ENABLED` | `true` | Enable creator ad preference management |

### 16.2 Phased Deployment

| Phase | Scope | Duration | Details |
|-------|-------|----------|---------|
| Phase 1: Backend + Storage | Internal only | Week 1 | Deploy ad_targeting table, service, and endpoints. Targeting evaluation runs in shadow mode (logs results but does not filter ads). Creator settings endpoints live. |
| Phase 2: Targeting Active | All advertisers | Week 2 | `AD_TARGETING_ENABLED=true`. Targeting evaluation filters ad selection. Monitor miss rates and latency. Audience estimation available. |
| Phase 3: Frontend + GA | All users | Week 3 | TargetingEditor deployed. Creator ad settings UI live. Full documentation. Remove feature flag gate. |

### 16.3 Rollback

Set `AD_TARGETING_ENABLED=false`. All ads revert to untargeted serving. Targeting data remains in DDB for re-enablement.

---

## 17. Performance Considerations

### 17.1 Latency Targets

| Endpoint | Target p50 | Target p99 |
|----------|-----------|-----------|
| POST targeting (create) | 50ms | 200ms |
| GET targeting (list) | 30ms | 150ms |
| PUT targeting (update) | 50ms | 200ms |
| POST estimate | 100ms | 500ms |
| evaluate_targeting() (per campaign) | 1ms | 5ms |
| GET creator/ad-settings | 20ms | 100ms |
| PATCH creator/ad-settings | 50ms | 200ms |

### 17.2 Caching Strategy

| Data | Cache | staleTime | Invalidation |
|------|-------|-----------|-------------|
| Targeting sets (per campaign) | React Query | 30_000ms | On create/update/delete mutation |
| Audience estimate | React Query | 10_000ms | On targeting dimension change (debounced) |
| Creator ad settings | React Query | 60_000ms | On PATCH mutation |
| Blocked advertisers list | React Query | 60_000ms | On block/unblock mutation |
| Creator settings (server-side) | In-memory LRU | 60s TTL | On update |

### 17.3 Pagination

Targeting sets are queried per campaign using the table PK (`CAMP#{campaign_id}`). Most campaigns will have 1-5 targeting sets, so pagination is not required for the MVP. If a campaign has more than 50 targeting sets, standard `LastEvaluatedKey` cursor pagination applies. The `ByCampaignCreatedAt` GSI supports time-sorted listing.

---

## 18. Expanded E2E Tests

### 18.1 Section 354: Input Validation (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 354.1 | Invalid age range rejected | POST targeting with `age_ranges=["10-15"]`; 422; error mentions invalid age range |
| 354.2 | Invalid country code rejected | POST targeting with `country_codes=["ZZZ"]`; 422; error mentions ISO 3166-1 |
| 354.3 | Too many creator IDs rejected | POST targeting with 101 creator_ids; 400; "Maximum 100 creator IDs" |
| 354.4 | Contradictory creators rejected | POST with `creator_ids=["c1"]` and `exclude_creator_ids=["c1"]`; 400; "Cannot exclude and include" |
| 354.5 | Active hours out of range | POST targeting with `active_hours=[25]`; 422; error mentions 0-23 |

### 18.2 Section 355: Concurrent Operations (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 355.1 | Create two targeting sets simultaneously | Parallel POST requests; both succeed; list returns 2 sets |
| 355.2 | Update and delete same set concurrently | PUT and DELETE same target_set_id; one succeeds, one gets 404 |
| 355.3 | Estimate with empty targeting | POST estimate with no dimensions; estimated_reach >= 50000 |
| 355.4 | Estimate with all dimensions | POST with every dimension specified; estimated_reach < 1000 |

### 18.3 Section 356: Authorization Boundary (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 356.1 | Non-owner cannot create targeting | Bob POST to Alice's campaign targeting; 403 |
| 356.2 | Non-owner cannot list targeting | Bob GET Alice's campaign targeting; 403 |
| 356.3 | Non-owner cannot update targeting | Bob PUT on Alice's targeting set; 403 |
| 356.4 | Non-owner cannot delete targeting | Bob DELETE Alice's targeting set; 403 |
| 356.5 | Non-owner cannot estimate audience | Bob POST estimate on Alice's campaign; 403 |

### 18.4 Section 357: Creator Ad Settings Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 357.1 | Negative min_cpm rejected | Bob PATCH min_cpm_cents=-100; 422 |
| 357.2 | Invalid ad category rejected | Bob PATCH allowed_ad_categories=["invalid_cat"]; 400 |
| 357.3 | Block already-blocked advertiser is idempotent | Bob blocks Alice twice; 200 both times; block list has one entry |
| 357.4 | Unblock non-blocked advertiser is idempotent | Bob unblocks non-existent account; 200; block list unchanged |
