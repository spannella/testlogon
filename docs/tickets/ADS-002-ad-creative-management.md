# ADS-002: Ad Creative Management

**Ticket**: ADS-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 7-9 days
**Dependencies**: ADS-001 (Advertiser Accounts & Campaign Manager)

---

## 1. Overview & Motivation

### 1.1 Purpose

ADS-002 adds ad creative upload, management, and review within the campaign hierarchy established by ADS-001. A creative is the actual content shown to users: a banner image, a video pre-roll, or a sponsored native post. Advertisers create creatives, attach them to campaigns, submit them for admin review, and manage A/B test rotations. Admin reviewers approve or reject creatives based on content policy.

This ticket replaces the hardcoded `DEV_AD_CREATIVES` list in `app/services/ad_placement.py` with a proper creative storage and retrieval system.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Advertiser | As an advertiser, I want to upload a banner image as an ad creative. | Upload image; stored in S3; creative record created with metadata. |
| Advertiser | As an advertiser, I want to upload a video ad with a skippable flag. | Upload MP4; `skip_after_seconds` configurable; preview thumbnail generated. |
| Advertiser | As an advertiser, I want to create a sponsored native post creative. | Fill in headline, body, CTA text/URL; preview how it looks in feed. |
| Advertiser | As an advertiser, I want to A/B test multiple creatives with rotation weights. | Assign weights (0-100) to creatives; serving engine rotates proportionally. |
| Admin | As an admin, I want to review ad creatives before they serve. | Review queue shows pending creatives with preview; approve/reject with notes. |
| Advertiser | As an advertiser, I want to attach a promo code or affiliate link to a creative. | `promo_code_id` and `affiliate_link_id` fields on creative. |

### 1.3 Creative Formats

```
Ad Creative Formats
───────────────────

1. Image (Static Banner)
   ├── Landscape: 1200x628 px
   ├── Square: 1080x1080 px
   └── Max size: 5 MB (JPEG, PNG, WebP)

2. Video (Pre-roll / Mid-roll)
   ├── Format: MP4 (H.264)
   ├── Duration: 5-60 seconds
   ├── Resolution: min 720p
   ├── Max size: 50 MB
   └── Skippable: configurable (skip_after_seconds: 5/15/30)

3. Native Post (Sponsored Newsfeed Post)
   ├── Headline: max 100 chars
   ├── Body text: max 300 chars
   ├── CTA button: text (max 25 chars) + URL
   └── Optional: image attachment (same specs as image format)
```

### 1.4 Creative Review Workflow

```
Creative Lifecycle:
  draft ──→ pending_review ──→ approved ──→ archived
    │              │                │
    │              └── rejected ──→ draft (edit and resubmit)
    └── archived
```

---

## 2. Current State Analysis

### 2.1 Hardcoded Creatives (`app/services/ad_placement.py`, lines 25-47)

The `DEV_AD_CREATIVES` list contains three static placeholder creatives (pre-roll video, mid-roll video, overlay image). The `calculate_ad_slots()` function (line 116) selects from this list by index. ADS-002 replaces this with a database-backed creative selection.

### 2.2 S3 File Upload Pattern

The codebase uploads files to S3 in multiple places: `app/services/file_node_store.py` for the file manager, `app/routers/newsfeed.py` for post images. The pattern uses `T.s3_client.upload_fileobj()` or `T.s3_client.put_object()` with a structured key prefix. Ad creatives follow the same pattern with prefix `ads/creatives/{creative_id}/`.

### 2.3 Promo Codes (`app/services/promo_codes.py`)

The promo code service (462 lines) manages discount codes with creator-scoping, limits, and redemption tracking. Creatives can reference a `promo_code_id` to display a promo code alongside the ad.

### 2.4 Affiliate Links (`app/services/affiliate_links.py`)

The affiliate link service (383 lines) tracks clicks and conversions with commission calculation. Creatives can reference an `affiliate_link_id` to use the affiliate link as the click-through URL, enabling conversion attribution.

### 2.5 Gaps

1. **No creative storage table** — creatives exist only as hardcoded Python dicts.
2. **No creative upload** — no S3 upload path for ad images/videos.
3. **No creative review** — no admin approval workflow.
4. **No A/B testing** — no rotation weight system.
5. **No creative editor UI** — no frontend for creating/managing creatives.
6. **No promo/affiliate integration** — no linking creatives to promo codes or affiliate links.

---

## 3. Technical Design

### 3.1 DynamoDB Table

#### `ad_creatives` Table

| PK | SK | Fields |
|----|----|--------|
| `CAMP#{campaign_id}` | `CREATIVE#{creative_id}` | `creative_id`, `campaign_id`, `account_id`, `format` (image/video/native_post), `title`, `headline`, `body_text`, `cta_text`, `cta_url`, `image_url`, `video_url`, `thumbnail_url`, `alt_text`, `width`, `height`, `duration_seconds`, `skip_after_seconds`, `rotation_weight`, `status`, `review_notes`, `reviewed_by`, `promo_code_id`, `affiliate_link_id`, `created_at`, `updated_at` |

**GSIs**:

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|--------------|----------|---------|
| `ByStatus` | `status` (S) | `created_at` (N) | Admin: list creatives by review status |
| `ByFormat` | `format` (S) | `created_at` (N) | Filter creatives by format type |
| `ByCreativeId` | `creative_id` (S) | `created_at` (N) | Lookup creative by ID without knowing campaign |

**`scripts/local-ddb-init.py`**:
```python
TableDef(
    os.environ.get("DDB_AD_CREATIVES", "AdCreatives"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
        {"index_name": "ByFormat", "partition_key": "format", "sort_key": "created_at"},
        {"index_name": "ByCreativeId", "partition_key": "creative_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

### 3.2 Backend Models

**File**: `app/models.py`

```python
class CreativeCreateIn(BaseModel):
    format: str = Field(..., pattern=r"^(image|video|native_post)$")
    title: str = Field(..., min_length=1, max_length=200)
    headline: Optional[str] = Field(default=None, max_length=100)
    body_text: Optional[str] = Field(default=None, max_length=300)
    cta_text: Optional[str] = Field(default=None, max_length=25)
    cta_url: Optional[str] = Field(default=None, max_length=1024)
    alt_text: Optional[str] = Field(default=None, max_length=200)
    width: Optional[int] = Field(default=None, ge=100, le=4096)
    height: Optional[int] = Field(default=None, ge=100, le=4096)
    duration_seconds: Optional[int] = Field(default=None, ge=5, le=60)
    skip_after_seconds: Optional[int] = Field(default=5, ge=0, le=30)
    rotation_weight: int = Field(default=50, ge=0, le=100)
    promo_code_id: Optional[str] = None
    affiliate_link_id: Optional[str] = None

class CreativeUpdateIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    headline: Optional[str] = Field(default=None, max_length=100)
    body_text: Optional[str] = Field(default=None, max_length=300)
    cta_text: Optional[str] = Field(default=None, max_length=25)
    cta_url: Optional[str] = Field(default=None, max_length=1024)
    alt_text: Optional[str] = Field(default=None, max_length=200)
    rotation_weight: Optional[int] = Field(default=None, ge=0, le=100)
    skip_after_seconds: Optional[int] = Field(default=None, ge=0, le=30)

class CreativeOut(BaseModel):
    creative_id: str
    campaign_id: str
    account_id: str
    format: str
    title: str
    headline: Optional[str] = None
    body_text: Optional[str] = None
    cta_text: Optional[str] = None
    cta_url: Optional[str] = None
    image_url: Optional[str] = None
    video_url: Optional[str] = None
    thumbnail_url: Optional[str] = None
    alt_text: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    duration_seconds: Optional[int] = None
    skip_after_seconds: int = 5
    rotation_weight: int = 50
    status: str
    review_notes: Optional[str] = None
    promo_code_id: Optional[str] = None
    affiliate_link_id: Optional[str] = None
    created_at: int
    updated_at: int

class CreativeReviewIn(BaseModel):
    decision: str = Field(..., pattern=r"^(approve|reject)$")
    notes: Optional[str] = Field(default=None, max_length=1000)
```

### 3.3 Backend Service

**File**: `app/services/ad_creatives.py`

```python
def create_creative(campaign_id: str, account_id: str, data: CreativeCreateIn) -> dict:
    """Create a new creative in draft status."""
    creative_id = f"cr_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    item = {
        "pk": f"CAMP#{campaign_id}",
        "sk": f"CREATIVE#{creative_id}",
        "creative_id": creative_id,
        "campaign_id": campaign_id,
        "account_id": account_id,
        "format": data.format,
        "title": data.title,
        "headline": data.headline,
        "body_text": data.body_text,
        "cta_text": data.cta_text,
        "cta_url": data.cta_url,
        "alt_text": data.alt_text,
        "width": data.width,
        "height": data.height,
        "duration_seconds": data.duration_seconds,
        "skip_after_seconds": data.skip_after_seconds or 5,
        "rotation_weight": data.rotation_weight,
        "status": "draft",
        "promo_code_id": data.promo_code_id,
        "affiliate_link_id": data.affiliate_link_id,
        "created_at": ts,
        "updated_at": ts,
    }
    T.ad_creatives.put_item(Item={k: v for k, v in item.items() if v is not None})
    return item

def upload_creative_asset(creative_id: str, campaign_id: str, file_data: bytes, content_type: str, asset_type: str) -> str:
    """Upload image or video to S3, return URL."""
    ext = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "video/mp4": ".mp4"}.get(content_type, "")
    key = f"ads/creatives/{creative_id}/{asset_type}{ext}"
    T.s3_client.put_object(Bucket=S.s3_bucket, Key=key, Body=file_data, ContentType=content_type)
    url = f"/mock/s3/{S.s3_bucket}/{key}" if S.dev_mode else f"https://{S.s3_bucket}.s3.amazonaws.com/{key}"
    # Update creative record with URL
    url_field = "image_url" if asset_type == "image" else "video_url" if asset_type == "video" else "thumbnail_url"
    T.ad_creatives.update_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{creative_id}"},
        UpdateExpression=f"SET {url_field} = :u, updated_at = :t",
        ExpressionAttributeValues={":u": url, ":t": now_ts()},
    )
    return url

def list_creatives(campaign_id: str) -> list[dict]:
    resp = T.ad_creatives.query(
        KeyConditionExpression=Key("pk").eq(f"CAMP#{campaign_id}") & Key("sk").begins_with("CREATIVE#"),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])

def get_creative(campaign_id: str, creative_id: str) -> Optional[dict]:
    resp = T.ad_creatives.get_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{creative_id}"}
    )
    return resp.get("Item")

def submit_creative_for_review(campaign_id: str, creative_id: str) -> dict:
    T.ad_creatives.update_item(
        Key={"pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{creative_id}"},
        UpdateExpression="SET #s = :s, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "pending_review", ":u": now_ts()},
        ConditionExpression="#s = :draft",
    )
    return {"ok": True}

def review_creative(creative_id: str, reviewer_sub: str, decision: str, notes: str = "") -> dict:
    resp = T.ad_creatives.query(
        IndexName="ByCreativeId",
        KeyConditionExpression=Key("creative_id").eq(creative_id),
    )
    items = resp.get("Items", [])
    if not items:
        return None
    item = items[0]
    new_status = "approved" if decision == "approve" else "rejected"
    T.ad_creatives.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET #s = :s, reviewed_by = :r, review_notes = :n, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": new_status, ":r": reviewer_sub, ":n": notes, ":u": now_ts()},
    )
    return {"ok": True, "status": new_status}

def list_approved_creatives(campaign_id: str) -> list[dict]:
    """List only approved creatives for a campaign (used by ad serving)."""
    all_cr = list_creatives(campaign_id)
    return [c for c in all_cr if c.get("status") == "approved"]
```

### 3.4 Backend Router

**File**: `app/routers/ads.py` (extend from ADS-001)

```python
# ── Creatives ──

@router.post("/campaigns/{campaign_id}/creatives", status_code=201)
def create_creative_endpoint(campaign_id: str, body: CreativeCreateIn, ctx=Depends(require_ui_session)):
    campaign = _require_campaign_owner(campaign_id, ctx["user_sub"])
    return create_creative(campaign_id, campaign["account_id"], body)

@router.get("/campaigns/{campaign_id}/creatives")
def list_creatives_endpoint(campaign_id: str, ctx=Depends(require_ui_session)):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return list_creatives(campaign_id)

@router.post("/campaigns/{campaign_id}/creatives/{creative_id}/upload")
async def upload_asset(campaign_id: str, creative_id: str, file: UploadFile, asset_type: str = "image", ctx=Depends(require_ui_session)):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    data = await file.read()
    _validate_asset(data, file.content_type, asset_type)
    url = upload_creative_asset(creative_id, campaign_id, data, file.content_type, asset_type)
    return {"url": url}

@router.post("/campaigns/{campaign_id}/creatives/{creative_id}/submit")
def submit_creative_endpoint(campaign_id: str, creative_id: str, ctx=Depends(require_ui_session)):
    _require_campaign_owner(campaign_id, ctx["user_sub"])
    return submit_creative_for_review(campaign_id, creative_id)

# ── Admin Creative Review ──

@admin_router.get("/creatives/pending")
def list_pending_creatives(ctx=Depends(require_admin_session)):
    resp = T.ad_creatives.query(
        IndexName="ByStatus",
        KeyConditionExpression=Key("status").eq("pending_review"),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])

@admin_router.post("/creatives/{creative_id}/review")
def review_creative_endpoint(creative_id: str, body: CreativeReviewIn, ctx=Depends(require_admin_session)):
    result = review_creative(creative_id, ctx["user_sub"], body.decision, body.notes or "")
    if result is None:
        raise HTTPException(status_code=404, detail="Creative not found")
    return result
```

### 3.5 Asset Validation

```python
def _validate_asset(data: bytes, content_type: str, asset_type: str) -> None:
    if asset_type == "image":
        if content_type not in ("image/jpeg", "image/png", "image/webp"):
            raise HTTPException(400, "Image must be JPEG, PNG, or WebP")
        if len(data) > 5 * 1024 * 1024:
            raise HTTPException(400, "Image must be under 5 MB")
    elif asset_type == "video":
        if content_type != "video/mp4":
            raise HTTPException(400, "Video must be MP4")
        if len(data) > 50 * 1024 * 1024:
            raise HTTPException(400, "Video must be under 50 MB")
    elif asset_type == "thumbnail":
        if content_type not in ("image/jpeg", "image/png"):
            raise HTTPException(400, "Thumbnail must be JPEG or PNG")
        if len(data) > 2 * 1024 * 1024:
            raise HTTPException(400, "Thumbnail must be under 2 MB")
```

### 3.6 Frontend Pages

**File**: `frontend/src/pages/ads/CreativeEditor.tsx`

- Dialog/page for creating and editing creatives
- Format selector (image/video/native_post) changes visible fields
- Image upload zone with dimension validation preview
- Video upload zone with duration display
- Native post fields: headline, body_text, CTA text + URL
- Rotation weight slider (0-100)
- Promo code selector (loads from promo_codes API)
- Affiliate link selector (loads from affiliate_links API)
- Submit for Review button
- `data-testid="creative-editor"`

**File**: `frontend/src/pages/ads/CreativePreview.tsx`

- Preview component showing how creative will appear in each surface
- Image: renders banner at correct aspect ratio
- Video: plays uploaded video with skip button overlay
- Native post: renders as PostCard with "Sponsored" badge

**File**: `frontend/src/pages/ads/AdminCreativeReviewPage.tsx`

- Route: `/admin/ads/creatives/review`
- Lists pending creatives with preview
- Approve/Reject buttons with notes field
- Creative metadata display (format, dimensions, duration)

### 3.7 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface AdCreative {
  creative_id: string;
  campaign_id: string;
  account_id: string;
  format: "image" | "video" | "native_post";
  title: string;
  headline?: string | null;
  body_text?: string | null;
  cta_text?: string | null;
  cta_url?: string | null;
  image_url?: string | null;
  video_url?: string | null;
  thumbnail_url?: string | null;
  alt_text?: string | null;
  width?: number | null;
  height?: number | null;
  duration_seconds?: number | null;
  skip_after_seconds: number;
  rotation_weight: number;
  status: "draft" | "pending_review" | "approved" | "rejected" | "archived";
  review_notes?: string | null;
  promo_code_id?: string | null;
  affiliate_link_id?: string | null;
  created_at: number;
  updated_at: number;
}
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/ad_creatives.py` | Creative CRUD, upload, review |
| `frontend/src/pages/ads/CreativeEditor.tsx` | Creative create/edit form |
| `frontend/src/pages/ads/CreativePreview.tsx` | Creative preview component |
| `frontend/src/pages/ads/AdminCreativeReviewPage.tsx` | Admin review queue |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/ads.py` | Add creative + admin review endpoints |
| `app/models.py` | Add creative Pydantic models |
| `app/core/settings.py` | Add `ad_creatives_table_name` |
| `app/core/tables.py` | Add `ad_creatives` table handle |
| `scripts/local-ddb-init.py` | Add `AdCreatives` table definition |
| `frontend/src/api/types.ts` | Add `AdCreative` type |
| `frontend/src/api/endpoints/ads.ts` | Add creative API functions |
| `frontend/src/App.tsx` | Add admin review route |

### 4.3 Step-by-Step Order

1. Add DDB table definition
2. Add settings + table handle
3. Implement `ad_creatives.py` service
4. Add Pydantic models
5. Add creative endpoints to ads router
6. Add frontend types + API endpoints
7. Build CreativeEditor
8. Build CreativePreview
9. Build AdminCreativeReviewPage
10. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/ads-creatives.spec.ts` — 20 tests across 5 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let accountId: string;
let campaignId: string;
let imageCreativeId: string;
let videoCreativeId: string;
let nativeCreativeId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice (advertiser with active account + campaign from ADS-001 setup)
  // Set up Root (admin reviewer)
  // Create and approve ad account, create campaign
});
```

### 5.3 Section 345: Creative CRUD API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 345.1 | Create image creative | POST with format=image, title, dimensions; 201; status=draft |
| 345.2 | Create video creative | POST with format=video, duration=15, skip_after_seconds=5; 201 |
| 345.3 | Create native_post creative | POST with format=native_post, headline, body_text, cta_text, cta_url; 201 |
| 345.4 | List creatives for campaign | GET; 200; array length=3; all formats present |
| 345.5 | Update creative rotation weight | PATCH rotation_weight=80; 200; GET confirms new weight |

### 5.4 Section 346: Creative Asset Upload API (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 346.1 | Upload image asset | POST multipart with JPEG file; 200; `url` in response; creative `image_url` updated |
| 346.2 | Upload video asset | POST multipart with MP4 file; 200; creative `video_url` updated |
| 346.3 | Reject oversized image | POST 6 MB file; 400; "Image must be under 5 MB" |

### 5.5 Section 347: Creative Review Workflow API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 347.1 | Submit creative for review | POST `.../submit`; 200; status=pending_review |
| 347.2 | Admin lists pending creatives | Root GET `/v1/admin/ads/creatives/pending`; includes submitted creative |
| 347.3 | Admin approves creative | Root POST review decision=approve; status=approved |
| 347.4 | Admin rejects creative with notes | Root POST review decision=reject, notes="Inappropriate content"; status=rejected; review_notes set |

### 5.6 Section 348: Promo & Affiliate Integration API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 348.1 | Create creative with promo_code_id | POST with promo_code_id; 201; field stored |
| 348.2 | Create creative with affiliate_link_id | POST with affiliate_link_id; 201; field stored |
| 348.3 | Get creative returns promo and affiliate IDs | GET; both fields present in response |
| 348.4 | Update creative to clear promo_code_id | PATCH promo_code_id=null; field cleared |

### 5.7 Section 349: Creative Editor UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 349.1 | Creative editor opens with format selector | Navigate to campaign; click "New Creative"; format buttons visible |
| 349.2 | Image format shows dimension fields | Select "Image"; width and height inputs visible |
| 349.3 | Native post format shows headline + CTA fields | Select "Native Post"; headline, body, CTA text, CTA URL fields visible |
| 349.4 | Submit for review changes status badge | Click "Submit for Review"; status badge shows "Pending Review" |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Campaign not found | 404 | "Campaign not found" |
| Invalid format | 422 | Pydantic pattern validation |
| Invalid content type for upload | 400 | "Image must be JPEG, PNG, or WebP" / "Video must be MP4" |
| File too large | 400 | "Image must be under 5 MB" / "Video must be under 50 MB" |
| Submit non-draft creative | 400 | ConditionalCheckFailedException → "Creative must be in draft status" |
| Video duration out of range | 422 | Pydantic ge/le validation |

---

## 7. Security Considerations

- File uploads validated for content type and size server-side
- S3 keys use creative_id prefix — no path traversal
- Creative URLs in dev mode use `/mock/s3/` prefix; production uses signed S3 URLs
- Admin review required before creative can serve (status must be `approved`)
- Only campaign owner can upload assets; only admin can review

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-001 | Advertiser accounts + campaigns | Required |
| Promo Codes | `app/services/promo_codes.py` | Existing |
| Affiliate Links | `app/services/affiliate_links.py` | Existing |

### 8.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| ADS-004 (Ad Serving) | Approved creatives from ADS-002 |
| ADS-005 (Sponsored Posts) | Native post creatives from ADS-002 |
| ADS-006 (Broadcast Ads) | Video creatives from ADS-002 |
| ADS-008 (Analytics) | Creative-level performance breakdowns |
