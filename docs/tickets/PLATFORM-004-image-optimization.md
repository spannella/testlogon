# PLATFORM-004: Image Optimization Pipeline

**Ticket**: PLATFORM-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 12-16 days

---

## 1. Executive Summary

The platform has no general image optimization pipeline. User-uploaded images (post images, profile photos, message attachments) are stored and served at their original resolution and format. The only image processing that exists is video poster extraction (`app/services/filemanager.py:1362-1410`), which uses FFmpeg to generate WebP thumbnails from video frames. No resize, no format conversion, no responsive image variants exist for any other image type.

Frontend components render images with bare `<img src={url}>` tags without `srcset`, `sizes`, or `<picture>` elements. PostCard.tsx (`frontend/src/pages/feed/PostCard.tsx:77-82`) uses `<img src={urls[0]} className="max-h-80 w-full object-cover">` -- a single source URL regardless of viewport width or device pixel ratio. A 4000x3000 DSLR photo uploaded to a post consumes the same bandwidth on a 320px mobile screen as on a 2560px desktop monitor.

This feature introduces server-side image processing on upload that generates multiple size variants (small, medium, large) in WebP format, stores them alongside the original in S3, returns a `variants` object in API responses, and updates frontend components to use `<img srcset>` for responsive image delivery. The pipeline uses Pillow (Python Imaging Library) for resize and format conversion, integrated into the existing upload endpoints. The expected bandwidth savings are 80-99% for mobile users -- the single largest performance improvement available for feed page load times.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Fast mobile page loads (viewer)**
As a mobile user on a cellular connection, I want images in the feed to load quickly without consuming my data plan.

*Acceptance criteria:*
- Post images served at ~480px width (sm variant) on mobile screens instead of original 4000px.
- WebP format used for all variants (25-34% smaller than equivalent JPEG).
- Feed page with 10 post images loads in under 2 seconds on 4G (currently 5-10+ seconds).
- Total image payload for a 10-post feed page is under 1 MB (currently 10-50 MB).

**US-2: High-quality desktop images (viewer)**
As a desktop user with a retina display, I want high-quality images that take advantage of my screen resolution.

*Acceptance criteria:*
- Large variant (1920px) served for high-DPI screens via `srcset` `2x` resolution.
- Medium variant (960px) served for standard desktop screens.
- Browser automatically selects the appropriate variant based on viewport width and device pixel ratio.
- No JavaScript intervention needed -- native `srcset` attribute handles selection.

**US-3: Seamless upload (creator)**
As a content creator, I want to upload full-resolution photos without worrying about file size or manually resizing.

*Acceptance criteria:*
- Upload accepts original resolution (up to 10 MB per existing limit).
- Variant generation happens automatically on the server during upload.
- Upload response time increases by at most 500-800ms (for a 5 MB image).
- If variant generation fails, the original is still stored and served (graceful degradation).

**US-4: Reduced infrastructure costs (admin)**
As a platform administrator, I want to minimize S3 storage and CloudFront bandwidth costs.

*Acceptance criteria:*
- WebP variants are 30-60% smaller than JPEG originals at equivalent visual quality.
- Immutable cache headers on variants (1-year cache, reducing repeated S3 fetches).
- Total S3 storage increases by ~30-50% per image (3 small variants vs 1 large original).
- Bandwidth savings far exceed storage cost increase.

**US-5: Progressive image loading (viewer)**
As a feed viewer, I want below-fold images to load lazily so the initial page render is fast.

*Acceptance criteria:*
- `loading="lazy"` attribute on all images below the first visible post.
- First image in the feed uses `loading="eager"` for immediate display.
- Browser handles lazy loading natively without JavaScript IntersectionObserver.

### 2.2 Pain Points

1. **Bandwidth waste**: A 5MB JPEG uploaded for a post is served at full resolution to all clients. Mobile users on 4G download the same 5MB. Average post image download should be ~100-300KB with optimization.
2. **Slow page loads**: Feed pages with 10+ posts each containing multiple images trigger multi-megabyte downloads. First Contentful Paint is delayed by image payload.
3. **No WebP for images**: WebP provides 25-34% smaller files than JPEG at equivalent quality. Only video posters use WebP (`filemanager.py:1368`). All user-uploaded images remain in their original format.
4. **No responsive images**: `<img src>` without `srcset` means the browser has no choice but to download the single provided URL. The `max-h-80 w-full object-cover` CSS scales visually but does not reduce payload.
5. **No CDN cache differentiation**: All image responses use `Cache-Control: private, max-age=300` (`newsfeed.py:2657`). Optimized variants could use much longer cache TTLs since they are immutable by size (the filename includes the variant name).
6. **No lazy loading**: All 6 `<img>` instances in PostCard lack `loading="lazy"`, causing above-the-fold and below-the-fold images to load simultaneously.

---

## 3. Current State Analysis

### 3.1 Video Poster Generation (Only Existing Image Processing)

`_extract_video_poster_bytes()` in `app/services/filemanager.py:1362-1410` is the only image processing in the codebase:

- Downloads video from S3 to temp directory (`filemanager.py:1371-1373`)
- Runs FFmpeg to extract a single frame as WebP at target height (`filemanager.py:1379-1391`): `ffmpeg -ss 1 -i input -frames:v 1 -vf scale=-2:{target_height} poster.webp`
- Falls back to JPEG if WebP generation fails (`filemanager.py:1403-1414`)
- Stores poster in S3 as `poster_image.webp` (`filemanager.py:1559-1560`)

This demonstrates the pattern (download from S3, process, re-upload) but uses FFmpeg, not a general-purpose image library. Pillow is more appropriate for still image operations (faster startup, better quality control, no subprocess overhead).

### 3.2 Post Image Upload

`upload_image()` in `app/routers/newsfeed.py:2620-2640`:

```python
@router.post("/uploads/image")
async def upload_image(
    file: UploadFile = File(...),
    user_id: UserIdDep = None,
):
    ensure_uploads_enabled()
    if not (file.content_type or "").startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image files are accepted")
    content = await file.read()
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="Image must be under 10 MB")
    attachment_id = new_id("att")
    safe_name = (file.filename or "upload.bin").replace("/", "_").replace("\\", "_")
    s3_key = f"uploads/{user_id}/{attachment_id}/{safe_name}"
    # ... s3.put_object, return URL ...
```

- Accepts `UploadFile` (max 10MB per `_MAX_UPLOAD_BYTES`)
- Validates content type starts with `image/`
- Writes to S3 at `uploads/{user_id}/{attachment_id}/{safe_name}` with original content type
- Returns a proxy URL: `/uploads/object?s3_key={encoded_key}`
- **No resize, no format conversion, no variant generation**

### 3.3 Upload Object Retrieval

`get_upload_object()` in `app/routers/newsfeed.py:2643-2657`:

```python
@router.get("/uploads/object")
async def get_upload_object(s3_key: str = Query(...)):
    # ... S3 get_object ...
    return StreamingResponse(
        _iter(), media_type=content_type,
        headers={"Cache-Control": "private, max-age=300"}
    )
```

- Streams the original object from S3
- Sets `Cache-Control: private, max-age=300` (5-minute cache, re-fetched frequently)
- No content negotiation, no variant selection, no `Accept` header inspection

### 3.4 Frontend Image Rendering

PostCard.tsx (`frontend/src/pages/feed/PostCard.tsx:77-82`):

```tsx
<img
  src={urls[0]}
  alt=""
  className="max-h-80 w-full rounded-lg object-cover transition-transform hover:scale-[1.02]"
/>
```

All 6 `<img>` instances in PostCard (lines 77, 97, 114, 125, 143, 162) use the same pattern: single `src`, no `srcset`, no `sizes`, no `loading="lazy"`. These cover the 1-image, 2-image, 3-image, 4-image, and 5+-image grid layouts.

No `<picture>` elements exist anywhere in the frontend (verified: zero results for `srcset` or `<picture` in `frontend/src/`).

### 3.5 Image Processing Dependencies

- No `Pillow`, `sharp`, `imagemagick`, `PIL`, or any image processing library in `requirements.txt` or `pyproject.toml`
- No `sharp`, `@squoosh/lib`, `imagemin`, or `imgix` in `frontend/package.json`
- FFmpeg is available (used for video processing) and could handle image resize, but Pillow is more appropriate for image-specific operations (faster, no subprocess overhead, better quality control)

### 3.6 S3 Bucket Configuration

Images are stored in the upload bucket (configured via `S3_UPLOAD_BUCKET` or `UPLOAD_BUCKET` env var). The S3 mock (moto) handles PUT and GET operations. The bucket does not have lifecycle rules for image variants.

### 3.7 Gaps

1. No image resize on upload (`newsfeed.py:2620-2640`)
2. No WebP/AVIF conversion for user images
3. No `srcset` or `<picture>` in any frontend component (zero results in `frontend/src/`)
4. No Pillow or image processing library in dependencies
5. No variant storage pattern in S3 (only original stored)
6. No responsive image metadata in API responses
7. No `loading="lazy"` on images below the fold (all 6 `<img>` in PostCard)
8. Short cache TTL on all images (`max-age=300`)

---

## 4. Implementation Plan

### 4.1 Backend: Add Pillow Dependency

**`requirements.txt`** (or `pyproject.toml`):

```
Pillow>=10.0.0
```

Pillow provides `Image.open()`, `Image.resize()`, `Image.save(format="WEBP")` with quality control. It is the standard Python imaging library with optimized C extensions for performance. Pillow 10.x supports WebP encoding/decoding out of the box.

### 4.2 Backend: Image Processing Service

**New file: `app/services/image_optimization.py`** (~100 lines)

```python
"""Image optimization pipeline: resize + WebP conversion."""
from __future__ import annotations

import io
import logging
from typing import Any, Dict, Tuple

from PIL import Image

logger = logging.getLogger(__name__)

# Variant definitions: name -> (max_width, max_height, quality)
VARIANTS: Dict[str, Tuple[int, int, int]] = {
    "sm": (480, 480, 75),    # Mobile screens, thumbnails
    "md": (960, 960, 80),    # Tablet, standard desktop
    "lg": (1920, 1920, 85),  # Retina desktop, full-width hero
}

# Safety limit: prevent decompression bomb attacks
# Default is ~178M pixels; we use a stricter limit
MAX_IMAGE_PIXELS = 89_478_485  # ~9500x9500


def generate_variants(
    image_bytes: bytes,
    content_type: str,
) -> Dict[str, Dict[str, Any]]:
    """Generate size variants in WebP format.

    Args:
        image_bytes: Raw bytes of the uploaded image.
        content_type: MIME type of the original (e.g. "image/jpeg").

    Returns:
        Dict of variant_name -> {
            "bytes": bytes,
            "content_type": "image/webp",
            "width": int,
            "height": int,
            "size_bytes": int,
        }.
        Returns empty dict on failure (graceful degradation).
    """
    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    results: Dict[str, Dict[str, Any]] = {}

    try:
        img = Image.open(io.BytesIO(image_bytes))
        orig_w, orig_h = img.size

        # Convert palette and grayscale modes to RGB/RGBA for WebP
        if img.mode == "RGBA" or (img.mode == "P" and "transparency" in img.info):
            img = img.convert("RGBA")
        elif img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGB")

        for name, (max_w, max_h, quality) in VARIANTS.items():
            # Skip variants that would be larger than or equal to the original
            # Always generate "sm" as a guaranteed small variant
            if name != "sm" and orig_w <= max_w and orig_h <= max_h:
                continue

            resized = img.copy()
            resized.thumbnail((max_w, max_h), Image.LANCZOS)

            buf = io.BytesIO()
            save_kwargs: Dict[str, Any] = {"quality": quality, "method": 4}

            if resized.mode == "RGBA":
                save_kwargs["lossless"] = False
            else:
                if resized.mode != "RGB":
                    resized = resized.convert("RGB")

            resized.save(buf, format="WEBP", **save_kwargs)
            variant_bytes = buf.getvalue()

            results[name] = {
                "bytes": variant_bytes,
                "content_type": "image/webp",
                "width": resized.size[0],
                "height": resized.size[1],
                "size_bytes": len(variant_bytes),
            }

    except Exception:
        logger.exception("Image variant generation failed; serving original only")

    return results
```

### 4.3 Backend: Modify Upload Endpoint

**`app/routers/newsfeed.py` -- `upload_image()` (~line 2620)**

After uploading the original, generate and upload variants:

```python
from app.services.image_optimization import generate_variants

@router.post("/uploads/image")
async def upload_image(
    file: UploadFile = File(...),
    user_id: UserIdDep = None,
):
    ensure_uploads_enabled()
    if not (file.content_type or "").startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image files are accepted")
    content = await file.read()
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="Image must be under 10 MB")
    attachment_id = new_id("att")
    safe_name = (file.filename or "upload.bin").replace("/", "_").replace("\\", "_")
    base_key = f"uploads/{user_id}/{attachment_id}"
    s3_key = f"{base_key}/{safe_name}"

    # Upload original
    try:
        s3.put_object(
            Bucket=UPLOAD_BUCKET, Key=s3_key, Body=content,
            ContentType=file.content_type or "application/octet-stream",
        )
    except ClientError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"S3 error: {exc.response['Error'].get('Message','unknown')}",
        ) from exc

    encoded_key = quote(s3_key, safe="")
    url = f"/uploads/object?s3_key={encoded_key}"

    # Generate and upload variants (gated by feature flag)
    variants: Dict[str, Dict] = {}
    if S.image_optimization_enabled:
        try:
            variant_map = generate_variants(content, file.content_type or "image/jpeg")
            for vname, vdata in variant_map.items():
                vkey = f"{base_key}/{vname}.webp"
                s3.put_object(
                    Bucket=UPLOAD_BUCKET, Key=vkey,
                    Body=vdata["bytes"],
                    ContentType=vdata["content_type"],
                )
                variants[vname] = {
                    "url": f"/uploads/object?s3_key={quote(vkey, safe='')}",
                    "width": vdata["width"],
                    "height": vdata["height"],
                    "size_bytes": vdata["size_bytes"],
                }
        except Exception:
            logger.exception("Variant upload failed; serving original only")

    return {"url": url, "s3_key": s3_key, "variants": variants}
```

### 4.4 Backend: Store Variants on Post Items

**`app/routers/newsfeed.py` -- `create_post()` (~line 2866)**

When a post is created with `image_urls`, store the variant metadata alongside:

```python
# The upload response includes variants for each image.
# The frontend passes image_urls (array of original URLs) to create_post.
# Variant metadata is stored separately on the post item.
if req.image_urls:
    post_item["image_urls"] = list(req.image_urls)
    # Frontend optionally passes image_variants from the upload responses
    if hasattr(req, "image_variants") and req.image_variants:
        post_item["image_variants"] = list(req.image_variants)
```

### 4.5 Backend: Return Variants in Post Response

**`app/routers/newsfeed.py` -- `_post_to_dict()` (line 1792)**

Modify to include `image_variants` alongside `image_urls`:

```python
# After building image_urls list:
image_variants = list(post.get("image_variants") or [])
# ...
return {
    # ... existing fields ...
    "image_urls": image_urls,
    "image_variants": image_variants,
    # ...
}
```

### 4.6 Backend: Settings

**`app/core/settings.py`**:

```python
# Image optimization (PLATFORM-004)
image_optimization_enabled: bool = os.environ.get(
    "IMAGE_OPTIMIZATION_ENABLED", "1"
) not in ("0", "false", "False")
image_variant_sm_max_width: int = int(os.environ.get("IMAGE_VARIANT_SM_MAX_WIDTH", "480"))
image_variant_md_max_width: int = int(os.environ.get("IMAGE_VARIANT_MD_MAX_WIDTH", "960"))
image_variant_lg_max_width: int = int(os.environ.get("IMAGE_VARIANT_LG_MAX_WIDTH", "1920"))
image_webp_quality: int = int(os.environ.get("IMAGE_WEBP_QUALITY", "80"))
```

### 4.7 Backend: Cache Headers for Variants

**`app/routers/newsfeed.py` -- `get_upload_object()` (~line 2643)**

Detect variant requests by key pattern and set longer cache:

```python
# Variants are immutable (keyed by attachment_id + size name)
is_variant = any(s3_key.endswith(f"/{v}.webp") for v in ("sm", "md", "lg"))
cache_control = (
    "public, max-age=31536000, immutable"
    if is_variant
    else "private, max-age=300"
)
return StreamingResponse(
    _iter(), media_type=content_type,
    headers={"Cache-Control": cache_control},
)
```

This allows CDNs and browsers to cache variant images for 1 year. Since variants are keyed by `{attachment_id}/{size}.webp` and attachments use randomly generated IDs, there is no cache invalidation concern -- re-uploading generates a new attachment ID.

### 4.8 Frontend: Types

**`frontend/src/api/types.ts` -- FeedPost interface (~line 1781)**:

```typescript
export interface ImageVariant {
  url: string;
  width: number;
  height: number;
  size_bytes?: number;
}

export interface FeedPost {
  // ... existing fields ...
  image_variants?: Array<Record<string, ImageVariant>>;
}
```

Each element in `image_variants` is a `Record<string, ImageVariant>` mapping variant name (`"sm"`, `"md"`, `"lg"`) to its metadata.

### 4.9 Frontend: Responsive Image Component

**New file: `frontend/src/components/shared/ResponsiveImage.tsx`** (~60 lines)

```tsx
import { cn } from "@/lib/utils";

interface ImageVariantInfo {
  url: string;
  width: number;
  height: number;
}

interface ResponsiveImageProps {
  src: string;
  variants?: Record<string, ImageVariantInfo>;
  alt?: string;
  className?: string;
  sizes?: string;
  loading?: "lazy" | "eager";
  onClick?: () => void;
}

/**
 * Renders an <img> with srcset when variants are available,
 * falling back to a plain <img src> when no variants exist.
 *
 * The browser selects the optimal variant based on viewport width
 * and device pixel ratio -- no JavaScript is needed.
 */
export function ResponsiveImage({
  src,
  variants,
  alt = "",
  className,
  sizes = "(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 33vw",
  loading = "lazy",
  onClick,
}: ResponsiveImageProps) {
  if (!variants || Object.keys(variants).length === 0) {
    return (
      <img
        src={src}
        alt={alt}
        className={className}
        loading={loading}
        onClick={onClick}
      />
    );
  }

  const srcset = Object.entries(variants)
    .sort(([, a], [, b]) => a.width - b.width)  // smallest to largest
    .map(([, v]) => `${v.url} ${v.width}w`)
    .join(", ");

  return (
    <img
      src={src}
      srcSet={srcset}
      sizes={sizes}
      alt={alt}
      className={className}
      loading={loading}
      onClick={onClick}
    />
  );
}
```

### 4.10 Frontend: Update PostCard

**`frontend/src/pages/feed/PostCard.tsx`** -- Replace `<img>` tags in all 6 image grid layouts:

Before (line 77-82):
```tsx
<img src={urls[0]} alt="" className="max-h-80 w-full rounded-lg object-cover ..." />
```

After:
```tsx
<ResponsiveImage
  src={urls[0]}
  variants={post.image_variants?.[0]}
  alt=""
  className="max-h-80 w-full rounded-lg object-cover transition-transform hover:scale-[1.02]"
  sizes="(max-width: 640px) 100vw, 640px"
  loading={isFirstInFeed ? "eager" : "lazy"}
  onClick={() => onClickImage(0)}
/>
```

Apply the same pattern to all 6 `<img>` instances in PostCard (lines 77, 97, 114, 125, 143, 162). Each instance maps to a different grid cell in the image gallery layouts (1-image, 2-image, 3-image, 4-image, 5+-image).

### 4.11 Frontend: Lazy Loading

Add `loading="lazy"` to all images below the fold. The `ResponsiveImage` component defaults to `loading="lazy"`. For the first visible image in the feed (above the fold), pass `loading="eager"`:

In the `FeedPage` component that renders PostCards:
```tsx
{posts.map((post, index) => (
  <PostCard
    key={post.post_id}
    post={post}
    isFirstInFeed={index === 0}  // NEW prop
    ...
  />
))}
```

---

## 5. Data Flow

```
Creator uploads image
       |
       v
POST /uploads/image
       |
       +--> Validate: content_type starts with image/, size <= 10MB
       |
       +--> Store original in S3: uploads/{uid}/{att_id}/{filename}
       |
       +--> generate_variants(image_bytes) [if IMAGE_OPTIMIZATION_ENABLED]
       |         |
       |         +--> Pillow: open, thumbnail to 480px  -> WebP q75 -> S3: uploads/{uid}/{att_id}/sm.webp
       |         +--> Pillow: open, thumbnail to 960px  -> WebP q80 -> S3: uploads/{uid}/{att_id}/md.webp
       |         +--> Pillow: open, thumbnail to 1920px -> WebP q85 -> S3: uploads/{uid}/{att_id}/lg.webp
       |         |
       |         +--> Skip variants larger than original (no upscaling)
       |
       v
Return { url, s3_key, variants: { sm: {url, w, h}, md: {url, w, h}, lg: {url, w, h} } }
       |
       v
Creator creates post with image_urls + image_variants stored in DDB
       |
       v
Viewer loads feed
       |
       v
GET /feed -> _post_to_dict includes image_variants
       |
       v
PostCard renders <ResponsiveImage>:
  <img srcset="sm.webp 480w, md.webp 960w, lg.webp 1920w"
       sizes="(max-width: 640px) 100vw, 640px"
       loading="lazy">
       |
       v
Browser selects optimal variant based on viewport width + device pixel ratio
       |
       v
GET /uploads/object?s3_key=...sm.webp
  -> Cache-Control: public, max-age=31536000, immutable
```

---

## 6. Performance Analysis

### 6.1 Upload-Time Processing Cost

| Image Size | Pillow Resize Time (3 variants) | Peak Memory | Additional S3 Uploads |
|------------|-------------------------------|-------------|----------------------|
| 1 MB JPEG (2000x1500) | ~200ms | ~20 MB | 3 |
| 5 MB JPEG (4000x3000) | ~500ms | ~60 MB | 3 |
| 10 MB JPEG (6000x4000) | ~800ms | ~100 MB | 3 |

Processing is synchronous during upload. For a 5 MB image, the upload response time increases from ~100ms to ~600ms. This is acceptable because image upload is a low-frequency, user-initiated action (users expect upload to take a moment).

Memory note: Pillow decompresses the full image into memory for processing. A 4000x3000 RGB image = 36 MB in memory. With 3 copies (original + 2 in-progress variants), peak is ~100 MB. Since `uvicorn` runs with `--workers 1` in dev mode (required for moto), this is safe. In production with multiple workers, each upload request peaks at ~100 MB but completes in < 1 second.

### 6.2 Bandwidth Savings (Per Image)

| Variant | Typical Size | Original JPEG | Bandwidth Saved |
|---------|-------------|---------------|----------------|
| sm (480px) | 20-50 KB WebP | 1-5 MB JPEG | 95-99% |
| md (960px) | 60-150 KB WebP | 1-5 MB JPEG | 90-97% |
| lg (1920px) | 150-400 KB WebP | 1-5 MB JPEG | 80-92% |

A feed page with 10 posts, each with one image, at `md` quality: ~1 MB total vs. ~30 MB original. **This is the single largest performance improvement possible for feed rendering.**

### 6.3 S3 Storage Impact

Each uploaded image generates 3 additional S3 objects (WebP variants). Total storage per image increases by ~30-50% of the original size. Given WebP efficiency, the additional storage is modest:

| Original | sm.webp | md.webp | lg.webp | Total Increase |
|----------|---------|---------|---------|---------------|
| 5 MB | 40 KB | 120 KB | 300 KB | +0.46 MB (+9%) |
| 10 MB | 50 KB | 150 KB | 400 KB | +0.6 MB (+6%) |

### 6.4 Cache Hit Rate Improvement

Variant responses use `max-age=31536000, immutable` (1 year). After the first load, variant images are served from browser/CDN cache. This eliminates repeated S3 fetches entirely. Current `max-age=300` forces re-fetch every 5 minutes.

---

## 7. Security

### 7.1 Decompression Bomb Protection

Pillow is configured with `Image.MAX_IMAGE_PIXELS = 89_478_485` (default ~9500x9500) to prevent decompression bomb attacks. Images exceeding this limit cause `DecompressionBombError`, which is caught and handled gracefully (original is stored, no variants generated).

### 7.2 Input Validation

Uploaded images are validated by:
1. Content type check: `file.content_type.startswith("image/")` (existing validation)
2. Pillow's ability to open them: `Image.open()` raises `UnidentifiedImageError` for non-image files
3. Size limit: 10 MB per `_MAX_UPLOAD_BYTES` (existing validation)

### 7.3 Variant Key Security

Variant S3 keys use the same bucket and auth model as originals. The `get_upload_object()` endpoint requires authentication (same as current). Variant URLs are not directly guessable because they include the randomly generated `attachment_id`.

### 7.4 No User-Controlled Parameters

Variant dimensions and quality are server-defined in `VARIANTS` dict. No user-controlled parameters affect resize dimensions, quality settings, or output format. This eliminates pixel-flooding or quality-bombing attack vectors.

### 7.5 EXIF Stripping

Pillow's `thumbnail()` method does not preserve EXIF data by default. This is a security benefit: uploaded images may contain GPS coordinates, camera serial numbers, or other PII in EXIF metadata. Variants are stripped of this data. The original retains its EXIF data (user's uploaded file is stored as-is).

---

## 8. Testing Strategy

### 8.1 Unit Tests (pytest)

**File: `tests/test_image_optimization.py`**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `test_generate_variants_produces_three_variants_from_jpeg` | sm, md, lg keys in result; all have content_type "image/webp" |
| 2 | `test_generate_variants_correct_dimensions` | sm width <= 480, md width <= 960, lg width <= 1920 |
| 3 | `test_generate_variants_preserves_aspect_ratio` | Width/height ratio of each variant matches original within 1px |
| 4 | `test_generate_variants_handles_png_with_alpha` | RGBA mode input produces valid WebP with transparency |
| 5 | `test_generate_variants_skips_variants_larger_than_original` | 400x300 image produces only sm variant (md, lg skipped) |
| 6 | `test_generate_variants_handles_corrupt_image` | Returns empty dict, no exception raised |
| 7 | `test_generate_variants_handles_grayscale` | Grayscale image converted to RGB, valid WebP output |
| 8 | `test_generate_variants_handles_palette_mode` | P-mode PNG converted correctly |
| 9 | `test_upload_endpoint_returns_variants` | POST /uploads/image returns `variants` dict with sm, md, lg |
| 10 | `test_variant_s3_keys_follow_naming_convention` | Keys end with `/sm.webp`, `/md.webp`, `/lg.webp` |
| 11 | `test_feature_flag_disables_variant_generation` | `IMAGE_OPTIMIZATION_ENABLED=0` -> `variants: {}` |
| 12 | `test_cache_headers_for_variants_are_immutable` | GET for variant URL returns `max-age=31536000, immutable` |
| 13 | `test_cache_headers_for_original_are_short` | GET for original URL returns `max-age=300` |
| 14 | `test_decompression_bomb_rejected` | 10000x10000 image returns empty variants (no crash) |
| 15 | `test_webp_quality_settings_applied` | sm=75, md=80, lg=85 quality in output metadata |

### 8.2 E2E Tests

**File:** `frontend/e2e/image-optimization.spec.ts`

**Section 1: Image Upload API (5 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | Upload image returns variants | Upload a test JPEG via API | 200; `variants.sm`, `variants.md`, `variants.lg` present in response |
| 2 | Variant URLs are accessible | Upload; GET each variant URL | 200 with `content-type: image/webp` |
| 3 | Small image skips large variants | Upload a 200x200 image | Only `variants.sm` present; `variants.md` and `variants.lg` absent |
| 4 | Post with optimized image includes variants | Create post with uploaded image URL | GET /feed shows `image_variants` on post |
| 5 | Variant cache headers are long-lived | GET variant URL | `cache-control` header contains `max-age=31536000` |

**Section 2: Responsive Image UI (4 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 6 | PostCard image has srcset attribute | Navigate to feed with image post | `img[srcset]` selector matches in post card |
| 7 | Image has loading=lazy | Scroll to below-fold post | `img[loading="lazy"]` present |
| 8 | First image has loading=eager | Navigate to feed | First post's image has `loading="eager"` |
| 9 | Fallback to src when no variants | Post with no image_variants | Plain `<img src>` without srcset |

### 8.3 Performance Regression Test

| Test | Measurement | Threshold |
|------|-------------|-----------|
| Upload with optimization adds < 1s latency | Time POST /uploads/image for a 5MB JPEG | < 1500ms total (was ~500ms) |
| Feed page total image payload reduced | Sum of image response sizes for 10-post feed | < 2 MB (was > 20 MB) |

---

## 9. Migration & Rollback

### 9.1 Feature Flag

`IMAGE_OPTIMIZATION_ENABLED` (default `true`). When false:
- `upload_image()` skips variant generation, returns `variants: {}`
- Frontend `ResponsiveImage` falls back to original `src` when no variants
- Existing posts without `image_variants` render as before (no change)

### 9.2 Backward Compatibility

- Existing posts have no `image_variants` field. `_post_to_dict` returns `image_variants: []` when the field is missing.
- `ResponsiveImage` component gracefully degrades to `<img src>` when no variants provided.
- No database migration needed. New field is additive to existing post items.
- The upload response format is backward compatible: the `url` and `s3_key` fields are unchanged; `variants` is a new optional field.

### 9.3 Backfill (Future)

A one-time backfill script can regenerate variants for existing post images:

1. Scan posts with `image_urls` but no `image_variants`.
2. For each image URL, extract the S3 key, download the original from S3.
3. Run through `generate_variants()`.
4. Upload variants to S3.
5. Update the post's DDB item with `image_variants`.
6. Throttle to 10 images/second to avoid overwhelming S3 or DDB.

### 9.4 Rollback Steps

1. Set `IMAGE_OPTIMIZATION_ENABLED=false`.
2. Upload endpoint stops generating variants.
3. Frontend falls back to original `src` for all images.
4. Existing variant S3 objects remain (harmless; can be cleaned up later).
5. No need to remove `image_variants` from DDB items (ignored when feature is off).

---

## 10. Acceptance Criteria

1. Uploading an image via `POST /uploads/image` generates sm (480px), md (960px), and lg (1920px) WebP variants.
2. Variant URLs are returned in the upload response alongside the original URL.
3. Variant metadata is stored on post items in DynamoDB.
4. `_post_to_dict` includes `image_variants` in the serialized post output.
5. PostCard renders images with `<img srcset>` using variant URLs when available.
6. Below-fold images use `loading="lazy"`.
7. Variant responses have immutable cache headers (`max-age=31536000`).
8. Feature flag `IMAGE_OPTIMIZATION_ENABLED` controls variant generation.
9. Pillow handles JPEG, PNG, and WebP inputs; outputs WebP for all variants.
10. Images smaller than the variant size are not upscaled (variant is skipped).
11. Corrupt or invalid images fail gracefully (original stored, no variants, no error to user).
12. Decompression bomb protection active (images > 89M pixels rejected).

---

## 11. Files to Create

| File | Purpose | Est. Lines |
|------|---------|------------|
| `app/services/image_optimization.py` | Pillow-based image resize + WebP conversion | ~100 |
| `frontend/src/components/shared/ResponsiveImage.tsx` | `<img srcset>` wrapper component | ~60 |
| `frontend/e2e/image-optimization.spec.ts` | E2E tests | ~200 |
| `tests/test_image_optimization.py` | Backend unit tests | ~250 |

## 12. Files to Modify

| File | Change |
|------|--------|
| `requirements.txt` or `pyproject.toml` | Add `Pillow>=10.0.0` |
| `app/routers/newsfeed.py` | Modify `upload_image()` to generate variants; modify `_post_to_dict` + `create_post` to store/return variants; update cache headers in `get_upload_object()` |
| `app/core/settings.py` | Add `image_optimization_enabled`, `image_variant_*` settings |
| `frontend/src/api/types.ts` | Add `ImageVariant` interface, `image_variants` field on `FeedPost` |
| `frontend/src/pages/feed/PostCard.tsx` | Replace `<img>` with `<ResponsiveImage>` in all 6 instances (lines 77, 97, 114, 125, 143, 162) |

---

## 13. Dependencies

- **Pillow**: Must be installed (`pip install Pillow>=10.0.0`). Pillow 10.x supports WebP, AVIF (with libavif), and all standard image formats. Available via PyPI.
- **FFmpeg**: Already available for video processing. Not used here (Pillow is more appropriate for still images -- faster startup, no subprocess overhead, better quality control via `thumbnail` with Lanczos resampling).
- **S3 mock (moto)**: Variant uploads use the same S3 bucket and mock infrastructure. No changes needed to moto configuration.

---

## 14. Open Questions

| # | Question | Recommendation | Status |
|---|----------|---------------|--------|
| 1 | Should we add AVIF support alongside WebP? | Not in v1. AVIF encoding is slower (2-5x) and browser support is less universal. WebP has 97%+ browser support. Track as PLATFORM-004b. | DEFERRED |
| 2 | Should variants be generated asynchronously? | Not in v1. Synchronous generation adds ~500ms to upload, which is acceptable. Async introduces complexity (SQS, variant availability race condition). Consider for v2 if upload latency becomes a concern. | DEFERRED |
| 3 | Should we support user-specified quality levels? | No. Server-defined quality prevents abuse and ensures consistent visual quality. | DECIDED |
| 4 | Should profile photos get variants too? | Yes, in a follow-up ticket. Profile photos are small (typically < 1MB) and served at thumbnail size, so the impact is lower priority. | DEFERRED |
| 5 | Should message image attachments get variants? | Yes, in a follow-up ticket. Same `generate_variants` service can be reused by the messaging upload endpoint. | DEFERRED |

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Video poster WebP extraction | `app/services/filemanager.py` | 1362-1410 | VERIFIED |
| PostCard uses single `<img src>` | `frontend/src/pages/feed/PostCard.tsx` | 77-82 | VERIFIED |
| Six `<img>` instances in PostCard | `frontend/src/pages/feed/PostCard.tsx` | 77, 97, 114, 125, 143, 162 | VERIFIED |
| No `srcset` or `<picture>` in frontend | `frontend/src/` (all files) | N/A | VERIFIED (zero results) |
| upload_image no resize | `app/routers/newsfeed.py` | 2737 | VERIFIED |
| _MAX_UPLOAD_BYTES = 10MB | `app/routers/newsfeed.py` | 2733 | VERIFIED |
| S3 UPLOAD_BUCKET env var | `app/routers/newsfeed.py` | 56 | VERIFIED |
| No Pillow in requirements | `requirements.txt` / `pyproject.toml` | N/A | VERIFIED (not present) |
| No image processing packages in frontend | `frontend/package.json` | N/A | VERIFIED (not present) |
| FeedPost has no image_variants | `frontend/src/api/types.ts` | 1781-1834 | VERIFIED |
| FFmpeg used for video poster | `app/services/filemanager.py` | 1379-1391 | VERIFIED |
| UPLOAD_BUCKET (duplicate entry removed) | — | — | See line 56 above |


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_image_optimization.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_generate_variants_jpeg` | sm, md, lg keys; all image/webp |
| 2 | `test_correct_dimensions` | sm<=480, md<=960, lg<=1920 |
| 3 | `test_preserves_aspect_ratio` | Ratio within 1px of original |
| 4 | `test_png_with_alpha` | RGBA produces valid WebP with transparency |
| 5 | `test_skip_larger_than_original` | 400x300 image; only sm generated |
| 6 | `test_handles_corrupt_image` | Returns empty dict, no exception |
| 7 | `test_upload_returns_variants` | POST /uploads/image returns variants dict |
| 8 | `test_feature_flag_disables` | IMAGE_OPTIMIZATION_ENABLED=0; variants={} |
| 9 | `test_cache_headers_immutable` | Variant GET returns max-age=31536000 |
| 10 | `test_decompression_bomb` | 10000x10000 image; empty variants |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Upload generates variants and stores in S3 | newsfeed router + image_optimization + S3 mock |
| 2 | Post with variants includes image_variants in response | newsfeed router + DDB posts |
| 3 | Variant cache headers differ from original | newsfeed router + S3 streaming response |

### E2E Tests (Playwright)

**File**: `frontend/e2e/image-optimization.spec.ts` -- 9 tests

**Auth**: `injectAuth(page, identity)` for cookie auth; CSRF header for mutations.

Sections: 1 (upload API, 5 tests), 2 (responsive image UI, 4 tests)

**Negative/edge tests**: Small image skips large variants, corrupt image degrades gracefully, feature flag disables generation

### Test Data Requirements

- DDB seeds: posts table
- S3 mock (moto) for upload/variant storage
- Test image files (JPEG, PNG)
- Pillow>=10.0.0 installed

### CI/Pipeline

- Feature flags: IMAGE_OPTIMIZATION_ENABLED=true
- Serial execution (1 worker), 1 retry per playwright.config.ts
- Retry-safe: unique timestamps in test data


---

## Dependencies & Merge Safety

### Depends On

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | Standalone feature |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | No downstream dependents identified |

### Merge Strategy

**Independent** -- No prerequisites. Requires adding Pillow dependency.

### Merge Checklist

- [ ] Pillow>=10.0.0 in requirements.txt
- [ ] image_optimization.py service created
- [ ] upload_image() generates variants
- [ ] _post_to_dict returns image_variants
- [ ] ResponsiveImage.tsx with srcset
- [ ] PostCard uses ResponsiveImage with loading=lazy
- [ ] E2E pass: `npx playwright test e2e/image-optimization.spec.ts`
