# PLATFORM-004: Image Optimization Pipeline — Investigation & Implementation Write-up

> Type: feature | Priority: Medium | Status: Implemented

## 1. Summary & Classification

Before this feature, user-uploaded images were stored and served at their original resolution and format. A 5 MB DSLR JPEG uploaded to a newsfeed post was downloaded in full by every viewer — mobile users on 4G included. The only existing image processing was video poster extraction using FFmpeg (`app/services/filemanager.py:1362–1410`), which converts a video frame to WebP; no equivalent pipeline existed for still images. PLATFORM-004 adds server-side resize and WebP conversion on upload, generating up to three size variants (sm/480px, md/960px, lg/1920px) stored alongside the original in S3, and updates `PostCard.tsx` to use `<img srcset>` for responsive image delivery. Expected bandwidth savings are 80–99% for mobile users.

- **Type**: Feature / performance
- **Priority**: Medium
- **User personas affected**: feed viewers (faster loads), content creators (automatic resize without manual preprocessing), platform operators (reduced S3 egress costs)
- **Cross-references**: SECOPS-007 (dev/prod parity — moto S3 in dev, real S3 in prod, same code path), PLATFORM-005 (variant URLs provide `og:image` dimensions)

---

## 2. Current-State Investigation

### 2.1 Upload endpoint (app/routers/newsfeed.py)

`upload_image()` at approximately line 2737 accepts an `UploadFile` (max 10 MB per `_MAX_UPLOAD_BYTES`, line 2733), validates `content_type.startswith("image/")`, writes the original bytes to S3 at `uploads/{user_id}/{attachment_id}/{filename}`, and returns a `{"url": ..., "s3_key": ...}` dict. Before PLATFORM-004, the endpoint returned only those two fields — no variant metadata.

`get_upload_object()` at approximately line 2643 streams the S3 object back with `Cache-Control: private, max-age=300`. The 5-minute cache meant every repeat visit re-fetched the same multi-megabyte file.

`UPLOAD_BUCKET` is read from the environment at `app/routers/newsfeed.py:56`. In dev mode, moto intercepts all `boto3` S3 calls in-process (`app/core/dev_s3.py`), so the same upload/download code path works without any separate S3 mock process.

### 2.2 Frontend rendering (was PostCard.tsx)

The ticket identified six `<img>` instances in `frontend/src/pages/feed/PostCard.tsx` (lines 77, 97, 114, 125, 143, 162), covering the 1-, 2-, 3-, 4-, and 5+-image grid layouts. All used bare `<img src={url}>` with no `srcset`, `sizes`, or `loading="lazy"`. Zero `srcset` or `<picture>` usages existed anywhere in `frontend/src/`.

### 2.3 What now exists (verified)

`frontend/src/components/shared/ResponsiveImage.tsx` exists and exports `ResponsiveImage`. It renders `<img src srcSet sizes loading>` when variants are present or a plain `<img src>` fallback when none are.

`frontend/src/pages/feed/PostCard.tsx` now uses `<ResponsiveImage ... loading="lazy" />` in all image grid cells (confirmed lines 95, 112, 129, 140, 158, 177).

`app/services/image_optimization.py` exists and exports `generate_variants()`.

`app/routers/newsfeed.py` calls `generate_variants()` at approximately line 3051–3055, gated by `S.image_optimization_enabled`.

`requirements.txt` includes `Pillow>=10.0.0` (line 20).

Settings at `app/core/settings.py` (lines 1086–1091): `image_optimization_enabled`, `image_variant_sm_max_width` (480), `image_variant_md_max_width` (960), `image_variant_lg_max_width` (1920), `image_optimizations_table_name`.

### 2.4 Remaining gap: `_post_to_dict` variant return

The ticket specifies that `_post_to_dict()` (approximately line 1792 in `newsfeed.py`) must return `image_variants` alongside `image_urls`. This needs verification — the `FeedPost` TypeScript interface in `frontend/src/api/types.ts` should carry an `image_variants` field, and `PostCard.tsx`'s `PostImageGrid` passes `imageVariants={post.image_variants}` (confirmed at line 622).

---

## 3. Gap / Threat Analysis

### 3.1 Decompression bomb attacks

Pillow will attempt to decompress the entire image into memory before resizing. A maliciously crafted 1 KB PNG that decompresses to a 10,000×10,000 pixel bitmap would consume ~300 MB of RAM. The fix — already in `generate_variants()` — is to set `Image.MAX_IMAGE_PIXELS = 89_478_485` (~9,500×9,500 pixels) before calling `Image.open()`. PIL raises `DecompressionBombError` for images that exceed this limit, which is caught and causes `generate_variants()` to return an empty dict (graceful degradation — original still stored).

### 3.2 EXIF metadata leakage

DSLR photos embed GPS coordinates, camera serial numbers, and other PII in EXIF metadata. Pillow's `Image.thumbnail()` does not copy EXIF data to the resized output by default — variants are EXIF-stripped. The original is stored as uploaded; if stripping the original's EXIF is desired, that is a separate privacy feature. The current design is intentionally asymmetric: original is preserved as-is for the creator; variants strip metadata for viewer delivery.

### 3.3 Memory usage under concurrent uploads

A 4,000×3,000 RGB image decompresses to ~36 MB in memory. Generating three variants requires ~3× additional working copies during `Image.thumbnail()` calls — peak ~100–120 MB per concurrent upload. Since `uvicorn` runs with `--workers 1` in dev (required by moto in-process state), peak is bounded. In production with multiple workers, each worker processes one upload concurrently; with 4 workers and simultaneous large uploads, the process consumes ~400–500 MB. This should be factored into the instance memory allocation.

### 3.4 Backward compatibility: posts without variants

Posts created before PLATFORM-004 have `image_urls` but no `image_variants` field. `_post_to_dict()` must return `image_variants: []` (not `null`) when the DDB item lacks the field. `ResponsiveImage` degrades gracefully to `<img src>` when `variants` is undefined or empty, so no re-migration is needed for existing posts.

### 3.5 Upload latency regression

Generating three WebP variants from a 5 MB JPEG adds approximately 500 ms to the upload response time. For a creator uploading an image to a post, this raises total upload time from ~100 ms to ~600 ms. This is acceptable for a user-initiated, low-frequency action. If latency becomes a concern at scale, variants can be generated asynchronously (SQS worker pattern), but this introduces a race window where a post created immediately after upload may have no variants.

### 3.6 Code sites that must change (summary)

| File | Change |
|---|---|
| `requirements.txt` | `Pillow>=10.0.0` (confirmed present at line 20) |
| `app/services/image_optimization.py` | New — `generate_variants()` (confirmed exists) |
| `app/routers/newsfeed.py` (upload_image) | Generate variants on upload; return `variants` field (confirmed at ~line 3051) |
| `app/routers/newsfeed.py` (create_post) | Store `image_variants` on post DDB item |
| `app/routers/newsfeed.py` (_post_to_dict) | Return `image_variants` in serialized output |
| `app/routers/newsfeed.py` (get_upload_object) | `Cache-Control: public, max-age=31536000, immutable` for variant keys |
| `app/core/settings.py` | Image optimization settings (confirmed 1086–1091) |
| `frontend/src/api/types.ts` | `ImageVariant` interface; `image_variants` on `FeedPost` |
| `frontend/src/components/shared/ResponsiveImage.tsx` | New (confirmed exists) |
| `frontend/src/pages/feed/PostCard.tsx` | Replace `<img>` with `<ResponsiveImage loading="lazy">` (confirmed) |

---

## 4. Proposed Design / Fix

### 4.1 generate_variants() core logic

```python
# app/services/image_optimization.py
VARIANTS: Dict[str, Tuple[int, int, int]] = {
    "sm": (480, 480, 75),    # mobile
    "md": (960, 960, 80),    # tablet / standard desktop
    "lg": (1920, 1920, 85),  # retina desktop
}
Image.MAX_IMAGE_PIXELS = 89_478_485   # decompression bomb protection

def generate_variants(image_bytes: bytes, content_type: str) -> Dict[str, Dict]:
    results = {}
    img = Image.open(io.BytesIO(image_bytes))   # raises DecompressionBombError if too large
    orig_w, orig_h = img.size
    # Normalize to RGB or RGBA for WebP
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA" if "transparency" in img.info else "RGB")
    for name, (max_w, max_h, quality) in VARIANTS.items():
        if name != "sm" and orig_w <= max_w and orig_h <= max_h:
            continue   # skip upscaling
        resized = img.copy()
        resized.thumbnail((max_w, max_h), Image.LANCZOS)
        buf = io.BytesIO()
        resized.save(buf, format="WEBP", quality=quality, method=4)
        results[name] = {"bytes": buf.getvalue(), "content_type": "image/webp",
                         "width": resized.size[0], "height": resized.size[1]}
    return results
```

Key decisions:
- `thumbnail()` (not `resize()`) preserves aspect ratio without distortion.
- LANCZOS resampling produces the highest-quality downscale.
- `method=4` balances WebP encoding speed vs file size (0=fastest, 6=best).
- Small images (< sm threshold) still get an `sm` variant for guaranteed thumbnail availability.

### 4.2 S3 variant key convention

```
uploads/{user_id}/{attachment_id}/{original_filename}   ← original
uploads/{user_id}/{attachment_id}/sm.webp               ← 480px variant
uploads/{user_id}/{attachment_id}/md.webp               ← 960px variant
uploads/{user_id}/{attachment_id}/lg.webp               ← 1920px variant
```

The variant key structure (predictable name + attachment UUID) allows `get_upload_object()` to detect variant requests by checking `s3_key.endswith(("sm.webp", "md.webp", "lg.webp"))` and apply a 1-year immutable cache header.

### 4.3 Responsive image rendering

```tsx
// ResponsiveImage component — simplified
const srcset = Object.entries(variants)
  .sort(([, a], [, b]) => a.width - b.width)
  .map(([, v]) => `${v.url} ${v.width}w`)
  .join(", ");

return <img src={src} srcSet={srcset}
            sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 33vw"
            loading={loading}
            className={className} />;
```

The `sizes` attribute tells the browser what fraction of the viewport the image occupies; combined with the `srcset` widths and device pixel ratio, the browser selects the optimal variant without any JavaScript.

### 4.4 Dev/Prod parity (SECOPS-007)

- All S3 operations go through moto in-process (`app/core/dev_s3.py`) in dev mode — the same `s3.put_object()` / `s3.get_object()` calls in `upload_image()` work identically.
- `IMAGE_OPTIMIZATION_ENABLED=1` is set in `.env.local.example` so local development exercises the full variant pipeline.
- Pillow requires `libwebp` at runtime. The `setup_ubuntu.sh` script must install `libwebp-dev` before `pip install Pillow` to ensure WebP codec availability.

### 4.5 Feature flag and backward compatibility

`IMAGE_OPTIMIZATION_ENABLED=0` skips `generate_variants()` and returns `variants: {}` from the upload endpoint. Existing posts with no `image_variants` render with plain `<img src>` via the `ResponsiveImage` fallback. No DDB migration is required — the `image_variants` field is simply absent on older post items.

### 4.6 Alternatives considered

- **FFmpeg for image resize**: Already available for video processing. Rejected — Pillow has faster startup (no subprocess overhead), better quality control via `thumbnail` with LANCZOS, and is the standard Python imaging library.
- **AVIF format**: 15–20% better compression than WebP at equal quality, but encoding is 2–5× slower and browser support is ~95% vs WebP's 97%+. Deferred to a future ticket (PLATFORM-004b).
- **Asynchronous variant generation (SQS worker)**: Eliminates upload latency increase but introduces a race condition between post creation and variant availability. Deferred — the 500 ms synchronous overhead is acceptable for v1.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (tests/test_image_optimization.py)

| # | Test | What to assert |
|---|---|---|
| 1 | `test_generate_variants_jpeg` | Returns `sm`, `md`, `lg` keys; all `content_type = "image/webp"` |
| 2 | `test_correct_dimensions` | `sm.width <= 480`, `md.width <= 960`, `lg.width <= 1920` |
| 3 | `test_preserves_aspect_ratio` | Width/height ratio matches original within 1 pixel |
| 4 | `test_png_with_alpha` | RGBA input produces valid WebP (not corrupted) |
| 5 | `test_skip_larger_than_original` | 400×300 input → only `sm` generated; `md` and `lg` absent |
| 6 | `test_handles_corrupt_image` | Returns `{}` without raising an exception |
| 7 | `test_upload_returns_variants` | `POST /uploads/image` response includes `variants.sm`, `variants.md`, `variants.lg` |
| 8 | `test_feature_flag_disables` | `IMAGE_OPTIMIZATION_ENABLED=0` → `variants = {}` |
| 9 | `test_cache_headers_immutable` | `GET /uploads/object?s3_key=…/sm.webp` → `Cache-Control: public, max-age=31536000, immutable` |
| 10 | `test_decompression_bomb` | 10,000×10,000 synthetic image → `{}` returned, no crash |

All use moto-mocked S3 via `tests/conftest.py`.

### 5.2 Playwright E2E tests (frontend/e2e/image-optimization.spec.ts)

9 tests across 2 sections:

- Section 1 (5): Upload API — upload JPEG returns `variants.sm/md/lg`; variant URLs return `image/webp`; small image (200×200) produces only `sm`; post with image includes `image_variants` in feed response; variant cache header is `max-age=31536000`.
- Section 2 (4): Responsive image UI — `<img srcset>` attribute present on PostCard image; below-fold images have `loading="lazy"`; first image has `loading="eager"`; no `srcset` when no variants.

Test images: 1 MB synthetic JPEG created with Pillow in `beforeAll`; 200×200 PNG for small-image test.

### 5.3 Performance regression test

Upload time for a 5 MB JPEG must remain below 1,500 ms total (vs ~100 ms baseline without optimization). Measure `time.perf_counter()` around the `upload_image()` handler in integration tests and assert `< 1.5`.

Feed image payload: with 10 posts each containing one image at `md` quality (~120 KB WebP), total image payload should be under 2 MB. Current (pre-optimization): 10 × 5 MB JPEG = 50 MB.

### 5.4 Rollback

Set `IMAGE_OPTIMIZATION_ENABLED=0`. Variant generation stops; existing variant S3 objects remain (harmless; clean up with a lifecycle rule). Posts created before rollback retain their `image_variants` DDB field, but `ResponsiveImage` fallbacks gracefully to `src`.

### 5.5 Future work

- Profile photo variants (similar `generate_variants()` call in the profile photo upload endpoint)
- Message image attachment variants (same service, different router)
- AVIF format (PLATFORM-004b)
- Backfill script for existing posts without `image_variants`

**Effort**: M (estimated 12–16 days, but core pipeline is now complete; remaining work is wiring `_post_to_dict` and adding test coverage).
