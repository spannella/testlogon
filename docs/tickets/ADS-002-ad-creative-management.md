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

### 3.1 Architecture & Data Flow

```
Creative Upload Flow
────────────────────

Advertiser Browser                  Backend (FastAPI)                  AWS
─────────────────                   ────────────────                  ───
                                    
POST /campaigns/{id}/creatives      ┌─────────────────────────┐
  { format, title, ... }  ─────▶   │ create_creative()       │
                                    │ 1. Validate campaign     │
                                    │    ownership             │
                                    │ 2. Generate creative_id  │
                                    │ 3. Write to DDB          │
                                    └────────────┬────────────┘
                                                 │
                                                 ▼
                           ◄──── 201 { creative_id, status: "draft" }

POST /campaigns/{id}/creatives/     ┌─────────────────────────┐
  {creative_id}/upload              │ upload_creative_asset()  │
  [multipart: file]  ───────────▶  │ 1. Validate content_type │      ┌────────┐
                                    │ 2. Validate file size    │──▶   │   S3   │
                                    │ 3. Put object to S3      │      │ Bucket │
                                    │ 4. Update creative URL   │      └────────┘
                                    └────────────┬────────────┘
                                                 │
                                                 ▼
                           ◄──── 200 { url: "/mock/s3/..." }

POST .../submit                     ┌─────────────────────────┐
  ───────────────────────────────▶  │ submit_for_review()     │
                                    │ 1. ConditionExpression   │
                                    │    status = "draft"      │
                                    │ 2. SET status =          │
                                    │    "pending_review"      │
                                    └────────────┬────────────┘
                                                 │
                                                 ▼
                           ◄──── 200 { ok: true }


Admin Review Flow
─────────────────

Admin Browser                       Backend (FastAPI)
─────────────                       ────────────────

GET /admin/ads/creatives/pending    ┌─────────────────────────┐
  ───────────────────────────────▶  │ Query ByStatus GSI      │
                                    │ status = "pending_review"│
                                    └────────────┬────────────┘
                                                 │
                                                 ▼
                           ◄──── 200 [ { creative_id, title, format, ... }, ... ]

POST /admin/ads/creatives/          ┌─────────────────────────┐
  {creative_id}/review              │ review_creative()       │
  { decision, notes }  ──────────▶ │ 1. Query ByCreativeId   │
                                    │ 2. Update status to     │
                                    │    approved or rejected  │
                                    │ 3. Store reviewed_by,   │
                                    │    review_notes          │
                                    └────────────┬────────────┘
                                                 │
                                                 ▼
                           ◄──── 200 { ok: true, status: "approved" }
```

### 3.2 DynamoDB Table

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

### 3.3 Detailed DynamoDB Access Patterns

| # | Access Pattern | Table/GSI | PK | SK / Key Condition | Query Type | Example |
|---|----------------|-----------|----|--------------------|------------|---------|
| 1 | List creatives for campaign | `ad_creatives` | `CAMP#{campaign_id}` | `begins_with(sk, "CREATIVE#")` | Query | All creatives for campaign `camp_abc` |
| 2 | Get single creative | `ad_creatives` | `CAMP#{campaign_id}` | `CREATIVE#{creative_id}` | GetItem | Get creative `cr_xyz` in campaign `camp_abc` |
| 3 | List pending creatives (admin) | `ByStatus` GSI | `pending_review` | `ScanIndexForward=False` | Query | Admin review queue sorted newest first |
| 4 | List approved creatives (serving) | `ByStatus` GSI | `approved` | `ScanIndexForward=False` | Query | Active creatives for ad serving engine |
| 5 | List by format (filtering) | `ByFormat` GSI | `image` / `video` / `native_post` | `ScanIndexForward=False` | Query | All video creatives |
| 6 | Lookup creative by ID (review) | `ByCreativeId` GSI | `{creative_id}` | — | Query | Find creative without knowing campaign |
| 7 | Update creative metadata | `ad_creatives` | `CAMP#{campaign_id}` | `CREATIVE#{creative_id}` | UpdateItem | Change rotation weight |
| 8 | Update creative status | `ad_creatives` | `CAMP#{campaign_id}` | `CREATIVE#{creative_id}` | UpdateItem (conditional) | Submit for review (`status = "draft"` required) |
| 9 | List approved for campaign (serving) | `ad_creatives` | `CAMP#{campaign_id}` | `begins_with(sk, "CREATIVE#")` + filter `status=approved` | Query + Filter | Ad serving selects approved creatives |
| 10 | Delete creative | `ad_creatives` | `CAMP#{campaign_id}` | `CREATIVE#{creative_id}` | DeleteItem | Remove draft creative |

### 3.4 Backend Models

**File**: `app/models.py`

```python
from pydantic import BaseModel, Field, field_validator
from typing import Optional
import re


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

    @field_validator("cta_url")
    @classmethod
    def validate_cta_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not v.startswith(("http://", "https://")):
            raise ValueError("CTA URL must start with http:// or https://")
        return v

    @field_validator("title")
    @classmethod
    def strip_title(cls, v: str) -> str:
        return v.strip()

    @field_validator("headline")
    @classmethod
    def strip_headline(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if v else v

    @field_validator("body_text")
    @classmethod
    def sanitize_body(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        # Strip script tags
        return re.sub(r"<script[^>]*>.*?</script>", "", v, flags=re.DOTALL | re.IGNORECASE).strip()


class CreativeUpdateIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    headline: Optional[str] = Field(default=None, max_length=100)
    body_text: Optional[str] = Field(default=None, max_length=300)
    cta_text: Optional[str] = Field(default=None, max_length=25)
    cta_url: Optional[str] = Field(default=None, max_length=1024)
    alt_text: Optional[str] = Field(default=None, max_length=200)
    rotation_weight: Optional[int] = Field(default=None, ge=0, le=100)
    skip_after_seconds: Optional[int] = Field(default=None, ge=0, le=30)

    @field_validator("cta_url")
    @classmethod
    def validate_cta_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not v.startswith(("http://", "https://")):
            raise ValueError("CTA URL must start with http:// or https://")
        return v


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

### 3.5 Backend Service

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

### 3.6 API Request/Response Examples

```bash
# --- POST /ui/ads/campaigns/{campaign_id}/creatives ---
curl -X POST http://localhost:8000/ui/ads/campaigns/camp_abc123/creatives \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "image",
    "title": "Summer Sale Banner",
    "headline": "50% Off Everything",
    "body_text": "Limited time offer on all items",
    "cta_text": "Shop Now",
    "cta_url": "https://example.com/sale",
    "alt_text": "Summer sale promotional banner",
    "width": 1200,
    "height": 628,
    "rotation_weight": 70
  }'

# Response 201:
{
  "creative_id": "cr_a1b2c3d4e5f6",
  "campaign_id": "camp_abc123",
  "account_id": "adacc_xyz789",
  "format": "image",
  "title": "Summer Sale Banner",
  "headline": "50% Off Everything",
  "body_text": "Limited time offer on all items",
  "cta_text": "Shop Now",
  "cta_url": "https://example.com/sale",
  "alt_text": "Summer sale promotional banner",
  "width": 1200,
  "height": 628,
  "skip_after_seconds": 5,
  "rotation_weight": 70,
  "status": "draft",
  "created_at": 1748534400,
  "updated_at": 1748534400
}

# --- POST /ui/ads/campaigns/{campaign_id}/creatives/{creative_id}/upload ---
curl -X POST http://localhost:8000/ui/ads/campaigns/camp_abc123/creatives/cr_a1b2c3d4e5f6/upload \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -F "file=@banner.jpg" \
  -F "asset_type=image"

# Response 200:
{
  "url": "/mock/s3/test-bucket/ads/creatives/cr_a1b2c3d4e5f6/image.jpg"
}

# --- POST /ui/ads/campaigns/{campaign_id}/creatives/{creative_id}/submit ---
curl -X POST http://localhost:8000/ui/ads/campaigns/camp_abc123/creatives/cr_a1b2c3d4e5f6/submit \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123"

# Response 200:
{ "ok": true }

# --- GET /ui/ads/campaigns/{campaign_id}/creatives ---
curl http://localhost:8000/ui/ads/campaigns/camp_abc123/creatives \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
[
  {
    "creative_id": "cr_a1b2c3d4e5f6",
    "campaign_id": "camp_abc123",
    "account_id": "adacc_xyz789",
    "format": "image",
    "title": "Summer Sale Banner",
    "status": "pending_review",
    "image_url": "/mock/s3/test-bucket/ads/creatives/cr_a1b2c3d4e5f6/image.jpg",
    "rotation_weight": 70,
    "created_at": 1748534400,
    "updated_at": 1748534500
  }
]

# --- GET /v1/admin/ads/creatives/pending ---
curl http://localhost:8000/v1/admin/ads/creatives/pending \
  -H "Cookie: ui_session=admin_sess; ui_access_token=eyJ..."

# Response 200:
[
  {
    "creative_id": "cr_a1b2c3d4e5f6",
    "campaign_id": "camp_abc123",
    "account_id": "adacc_xyz789",
    "format": "image",
    "title": "Summer Sale Banner",
    "status": "pending_review",
    "image_url": "/mock/s3/test-bucket/ads/creatives/cr_a1b2c3d4e5f6/image.jpg",
    "created_at": 1748534400
  }
]

# --- POST /v1/admin/ads/creatives/{creative_id}/review ---
curl -X POST http://localhost:8000/v1/admin/ads/creatives/cr_a1b2c3d4e5f6/review \
  -H "Cookie: ui_session=admin_sess; ui_access_token=eyJ..." \
  -H "x-csrf-token: admin_csrf" \
  -H "Content-Type: application/json" \
  -d '{"decision": "approve", "notes": "Creative meets content policy requirements."}'

# Response 200:
{ "ok": true, "status": "approved" }

# --- POST /v1/admin/ads/creatives/{creative_id}/review (reject) ---
curl -X POST http://localhost:8000/v1/admin/ads/creatives/cr_a1b2c3d4e5f6/review \
  -H "Cookie: ui_session=admin_sess; ui_access_token=eyJ..." \
  -H "x-csrf-token: admin_csrf" \
  -H "Content-Type: application/json" \
  -d '{"decision": "reject", "notes": "Image contains prohibited content."}'

# Response 200:
{ "ok": true, "status": "rejected" }
```

### 3.7 Backend Router

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

### 3.8 Asset Validation

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

### 3.9 Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | User Message | Recovery Action |
|---|----------|-------------|------------|-------------|-----------------|
| 1 | Campaign not found | 404 | `CAMPAIGN_NOT_FOUND` | "Campaign not found" | Verify campaign_id exists |
| 2 | Not campaign owner | 403 | `CAMPAIGN_FORBIDDEN` | "You do not own this campaign" | Use your own campaign_id |
| 3 | Invalid format | 422 | `INVALID_FORMAT` | Pydantic pattern validation error | Use "image", "video", or "native_post" |
| 4 | Invalid content type for upload | 400 | `INVALID_CONTENT_TYPE` | "Image must be JPEG, PNG, or WebP" / "Video must be MP4" | Re-upload with correct file type |
| 5 | File too large (image) | 400 | `FILE_TOO_LARGE` | "Image must be under 5 MB" | Compress or resize the image |
| 6 | File too large (video) | 400 | `FILE_TOO_LARGE` | "Video must be under 50 MB" | Compress or trim the video |
| 7 | File too large (thumbnail) | 400 | `FILE_TOO_LARGE` | "Thumbnail must be under 2 MB" | Compress the thumbnail |
| 8 | Submit non-draft creative | 400 | `INVALID_STATUS` | "Creative must be in draft status" | Creative is already submitted or reviewed |
| 9 | Video duration out of range | 422 | `DURATION_OUT_OF_RANGE` | Pydantic ge/le validation | Use 5-60 seconds |
| 10 | Creative not found (review) | 404 | `CREATIVE_NOT_FOUND` | "Creative not found" | Verify creative_id |
| 11 | CTA URL not HTTPS | 422 | `INVALID_CTA_URL` | "CTA URL must start with http:// or https://" | Provide valid URL |
| 12 | Rotation weight out of range | 422 | `WEIGHT_OUT_OF_RANGE` | Pydantic ge/le validation | Use 0-100 |
| 13 | S3 upload failure | 500 | `S3_UPLOAD_FAILED` | "Failed to upload asset" | Retry; check S3 health |
| 14 | Title too long | 422 | `TITLE_TOO_LONG` | "Title must be at most 200 characters" | Shorten the title |
| 15 | Not admin (review endpoint) | 403 | `ADMIN_REQUIRED` | "Admin access required" | Log in as admin |
| 16 | Promo code not found | 404 | `PROMO_NOT_FOUND` | "Promo code not found" | Verify promo_code_id |

### 3.10 Frontend Pages

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

### 3.11 Frontend Component Tree

```
CreativeEditor                          data-testid="creative-editor"
├── Card
│   ├── CardHeader "Create Creative"
│   └── CardContent
│       ├── Select (format)             "image" | "video" | "native_post"
│       ├── Input (title)               required, max 200 chars
│       │
│       ├── div (image fields)          visible when format="image"
│       │   ├── DropZone                accept=".jpg,.png,.webp", maxSize=5MB
│       │   ├── Input (alt_text)        max 200 chars
│       │   ├── Input (width)           type="number", min=100, max=4096
│       │   └── Input (height)          type="number", min=100, max=4096
│       │
│       ├── div (video fields)          visible when format="video"
│       │   ├── DropZone                accept=".mp4", maxSize=50MB
│       │   ├── Input (duration_seconds) type="number", min=5, max=60
│       │   ├── Select (skip_after_seconds) 0 / 5 / 15 / 30
│       │   └── DropZone (thumbnail)    accept=".jpg,.png", maxSize=2MB
│       │
│       ├── div (native post fields)    visible when format="native_post"
│       │   ├── Input (headline)        max 100 chars
│       │   ├── Textarea (body_text)    max 300 chars
│       │   ├── Input (cta_text)        max 25 chars
│       │   └── Input (cta_url)         URL validation
│       │
│       ├── Slider (rotation_weight)    0-100, default 50
│       ├── Select (promo_code_id)      optional, loads from promo API
│       └── Select (affiliate_link_id)  optional, loads from affiliate API
│
└── div.flex.gap-2
    ├── Button "Save Draft"             onClick → POST create/PATCH update
    └── Button "Submit for Review"      onClick → POST submit; disabled if no asset

CreativePreview                         data-testid="creative-preview"
├── Tabs
│   ├── TabsTrigger "Banner"            image preview at correct aspect ratio
│   ├── TabsTrigger "Video"             video player with skip overlay
│   └── TabsTrigger "Feed"              PostCard-style native post preview

AdminCreativeReviewPage                 data-testid="admin-creative-review"
├── h1 "Creative Review Queue"
├── DataTable
│   ├── columns: [title, format, campaign_id, created_at, preview]
│   └── each row expandable to show CreativePreview
└── ReviewDialog
    ├── CreativePreview (full)
    ├── Textarea (notes)                max 1000 chars
    └── div.flex.gap-2
        ├── Button "Approve"            variant="default"
        └── Button "Reject"             variant="destructive"
```

**Props interfaces**:

```typescript
interface CreativeEditorProps {
  campaignId: string;
  creative?: AdCreative;              // undefined for create, populated for edit
  onSaved: (creative: AdCreative) => void;
}

interface CreativePreviewProps {
  creative: AdCreative;
  surface?: "banner" | "video" | "feed";
}

interface AdminCreativeReviewPageProps {}  // uses route params

interface ReviewDialogProps {
  creative: AdCreative;
  open: boolean;
  onClose: () => void;
  onReviewed: (result: { status: string }) => void;
}
```

### 3.12 Frontend Types

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

## 5. Observability

### 5.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `ad_creative_created_total` | Counter | `format` | Total creatives created |
| `ad_creative_submitted_total` | Counter | `format` | Creatives submitted for review |
| `ad_creative_reviewed_total` | Counter | `decision={approve,reject}` | Creatives reviewed by admin |
| `ad_creative_upload_bytes_total` | Counter | `asset_type={image,video,thumbnail}` | Total bytes uploaded |
| `ad_creative_upload_duration_seconds` | Histogram | `asset_type` | S3 upload latency |
| `ad_creative_review_queue_size` | Gauge | -- | Number of pending_review creatives |
| `ad_creative_s3_upload_errors_total` | Counter | -- | Failed S3 uploads |

### 5.2 Log Events

| Event | Level | Fields | When |
|-------|-------|--------|------|
| `creative_created` | INFO | creative_id, campaign_id, format, user_sub | New creative saved |
| `creative_asset_uploaded` | INFO | creative_id, asset_type, content_type, size_bytes | Asset uploaded to S3 |
| `creative_submitted` | INFO | creative_id, campaign_id | Submitted for review |
| `creative_reviewed` | INFO | creative_id, decision, reviewer_sub, notes | Admin decision recorded |
| `creative_upload_failed` | ERROR | creative_id, error, asset_type | S3 upload error |
| `creative_submit_invalid_status` | WARN | creative_id, current_status | Submit rejected (not draft) |
| `creative_review_not_found` | WARN | creative_id, reviewer_sub | Creative lookup failed during review |

### 5.3 Alerting Rules

| Alert | Condition | Severity | Channel |
|-------|-----------|----------|---------|
| Review queue backlog | `review_queue_size > 50` for 1 hour | P3 | Slack #ads-ops |
| S3 upload failure spike | `> 5 upload errors in 15 min` | P2 | Slack #infra |
| Zero reviews in 48h | `rate(creative_reviewed_total[48h]) == 0` AND `review_queue_size > 0` | P3 | Slack #ads-ops |

---

## 6. Rollout Plan

### 6.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `AD_CREATIVES_ENABLED` | `false` | Enable creative upload/management endpoints |
| `AD_CREATIVES_REVIEW_ENABLED` | `false` | Enable admin review queue |

### 6.2 Phased Rollout

| Phase | Scope | Duration | Flag State |
|-------|-------|----------|------------|
| Phase 1: Backend only | Service + router deployed; DDB table created; no frontend | 3 days | `AD_CREATIVES_ENABLED=true`, `AD_CREATIVES_REVIEW_ENABLED=false` |
| Phase 2: Admin review | Admin review queue enabled; limited advertiser access | 3 days | Both `true` |
| Phase 3: GA | Full frontend editor + preview; all advertisers | 2 days | Both `true`, flags removed |

### 6.3 Rollback Procedure

1. Set `AD_CREATIVES_ENABLED=false` to disable all creative endpoints.
2. Existing creatives remain in DDB and S3 (no data loss).
3. Ad serving falls back to hardcoded `DEV_AD_CREATIVES` when no approved creatives found.

---

## 7. Performance Considerations

### 7.1 Latency Targets

| Endpoint | Target p50 | Target p99 | Notes |
|----------|-----------|-----------|-------|
| POST create creative | < 50ms | < 200ms | Single DDB PutItem |
| POST upload asset (image) | < 500ms | < 2000ms | S3 PutObject, depends on file size |
| POST upload asset (video) | < 2000ms | < 5000ms | Up to 50MB upload |
| GET list creatives | < 100ms | < 300ms | DDB Query, typically < 50 items |
| GET admin pending | < 150ms | < 500ms | GSI Query on ByStatus |
| POST review creative | < 100ms | < 300ms | GSI Query + UpdateItem |
| POST submit for review | < 50ms | < 200ms | Conditional UpdateItem |

### 7.2 Caching Strategy

| Data | React Query staleTime | Invalidation |
|------|----------------------|-------------|
| Creative list (campaign) | 30s | On creative create/update/submit |
| Pending creatives (admin) | 10s | On review action |
| Single creative detail | 60s | On update/upload |

### 7.3 Pagination

- `list_creatives`: No pagination needed (campaigns typically have < 50 creatives). If needed, add `Limit=50` with `LastEvaluatedKey` cursor.
- `list_pending_creatives`: Paginated with `Limit=25` and cursor. Admin queue may grow across all campaigns.

---

## 8. E2E Test Plan

### 8.1 Test File

`frontend/e2e/ads-creatives.spec.ts` — 40 tests across 9 sections.

### 8.2 Test Setup

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

### 8.3 Section 345: Creative CRUD API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 345.1 | Create image creative | POST with format=image, title, dimensions; 201; status=draft |
| 345.2 | Create video creative | POST with format=video, duration=15, skip_after_seconds=5; 201 |
| 345.3 | Create native_post creative | POST with format=native_post, headline, body_text, cta_text, cta_url; 201 |
| 345.4 | List creatives for campaign | GET; 200; array length=3; all formats present |
| 345.5 | Update creative rotation weight | PATCH rotation_weight=80; 200; GET confirms new weight |

### 8.4 Section 346: Creative Asset Upload API (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 346.1 | Upload image asset | POST multipart with JPEG file; 200; `url` in response; creative `image_url` updated |
| 346.2 | Upload video asset | POST multipart with MP4 file; 200; creative `video_url` updated |
| 346.3 | Reject oversized image | POST 6 MB file; 400; "Image must be under 5 MB" |

### 8.5 Section 347: Creative Review Workflow API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 347.1 | Submit creative for review | POST `.../submit`; 200; status=pending_review |
| 347.2 | Admin lists pending creatives | Root GET `/v1/admin/ads/creatives/pending`; includes submitted creative |
| 347.3 | Admin approves creative | Root POST review decision=approve; status=approved |
| 347.4 | Admin rejects creative with notes | Root POST review decision=reject, notes="Inappropriate content"; status=rejected; review_notes set |

### 8.6 Section 348: Promo & Affiliate Integration API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 348.1 | Create creative with promo_code_id | POST with promo_code_id; 201; field stored |
| 348.2 | Create creative with affiliate_link_id | POST with affiliate_link_id; 201; field stored |
| 348.3 | Get creative returns promo and affiliate IDs | GET; both fields present in response |
| 348.4 | Update creative to clear promo_code_id | PATCH promo_code_id=null; field cleared |

### 8.7 Section 349: Creative Editor UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 349.1 | Creative editor opens with format selector | Navigate to campaign; click "New Creative"; format buttons visible |
| 349.2 | Image format shows dimension fields | Select "Image"; width and height inputs visible |
| 349.3 | Native post format shows headline + CTA fields | Select "Native Post"; headline, body, CTA text, CTA URL fields visible |
| 349.4 | Submit for review changes status badge | Click "Submit for Review"; status badge shows "Pending Review" |

### 8.8 Section 350: Input Validation (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 350.1 | Reject empty title | POST with title=""; 422 |
| 350.2 | Reject title over 200 chars | POST with 201-char title; 422 |
| 350.3 | Reject invalid format | POST with format="banner"; 422 |
| 350.4 | Reject CTA URL without scheme | POST with cta_url="example.com"; 422; "CTA URL must start with http://" |
| 350.5 | Reject rotation weight > 100 | POST with rotation_weight=150; 422 |

### 8.9 Section 351: Concurrent Operations (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 351.1 | Submit already pending creative | POST submit on pending_review creative; 400; ConditionalCheckFailed |
| 351.2 | Submit already approved creative | POST submit on approved creative; 400 |
| 351.3 | Review non-pending creative | POST review on draft creative; 400 or no-op (admin can review any status) |
| 351.4 | Upload to non-existent creative | POST upload with bad creative_id; 404 |
| 351.5 | Two uploads in rapid succession | POST upload twice; second overwrites first; last URL stored |

### 8.10 Section 352: Authorization Boundary (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 352.1 | Non-owner cannot create creative | Bob POST on Alice's campaign; 403 |
| 352.2 | Non-owner cannot list creatives | Bob GET on Alice's campaign; 403 |
| 352.3 | Non-owner cannot upload asset | Bob POST upload on Alice's creative; 403 |
| 352.4 | Non-admin cannot access review queue | Alice GET /admin/ads/creatives/pending; 403 |
| 352.5 | Non-admin cannot review creative | Alice POST review; 403 |

### 8.11 Section 353: Admin Review UI (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 353.1 | Review page loads pending list | Root navigates to /admin/ads/creatives/review; pending creative visible |
| 353.2 | Creative preview shows image | Click creative row; image preview visible |
| 353.3 | Approve button updates status | Click Approve; confirm dialog; status badge shows "Approved" |
| 353.4 | Reject with notes stores reason | Click Reject; enter notes; status shows "Rejected"; notes visible |
| 353.5 | Review queue updates after action | After approve; creative removed from pending list |

---

## 9. Security Considerations

- File uploads validated for content type and size server-side
- S3 keys use creative_id prefix — no path traversal
- Creative URLs in dev mode use `/mock/s3/` prefix; production uses signed S3 URLs
- Admin review required before creative can serve (status must be `approved`)
- Only campaign owner can upload assets; only admin can review

---

## 10. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| ADS-001 | Advertiser accounts + campaigns | Required |
| Promo Codes | `app/services/promo_codes.py` | Existing |
| Affiliate Links | `app/services/affiliate_links.py` | Existing |

### 10.1 Downstream Dependents

| Ticket | Depends On |
|--------|-----------|
| ADS-004 (Ad Serving) | Approved creatives from ADS-002 |
| ADS-005 (Sponsored Posts) | Native post creatives from ADS-002 |
| ADS-006 (Broadcast Ads) | Video creatives from ADS-002 |
| ADS-008 (Analytics) | Creative-level performance breakdowns |
