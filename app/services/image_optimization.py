"""Image optimization pipeline: resize + WebP conversion (PLATFORM-004).

Two layers live here:

1. ``generate_variants`` -- the pure, in-memory Pillow resize + WebP encoder.
   Reused by the newsfeed upload path and the on-demand optimization router.
2. ``optimize_source_image`` / ``get_optimization_record`` -- the on-demand
   serving-time layer. Given an already-uploaded source S3 key it generates
   the responsive variants, stores them in S3, persists an optimization
   *record* in the ``image_optimizations`` table, and caches the result so a
   repeated request for the same source returns the cached record instead of
   re-encoding.
"""
from __future__ import annotations

import hashlib
import io
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from PIL import Image

logger = logging.getLogger(__name__)

# Variant definitions: name -> (max_width, max_height, quality)
VARIANTS: Dict[str, Tuple[int, int, int]] = {
    "sm": (480, 480, 75),   # Mobile screens, thumbnails
    "md": (960, 960, 80),   # Tablet, standard desktop
    "lg": (1920, 1920, 85), # Retina desktop, full-width hero
}

# Safety limit: prevent decompression bomb attacks
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


# ---------------------------------------------------------------------------
# On-demand optimization layer (records + caching + S3 storage)
# ---------------------------------------------------------------------------

_VALID_FORMATS = {"webp", "jpeg"}


def _source_key_hash(source_key: str) -> str:
    """Stable hash of a source S3 key, used as the cache GSI partition key."""
    return hashlib.sha256(source_key.encode("utf-8")).hexdigest()


def _upload_object_url(s3_key: str) -> str:
    """Build the dev/proxy URL that serves an object from the upload bucket."""
    return f"/uploads/object?s3_key={quote(s3_key, safe='')}"


def get_cached_record(owner_sub: str, source_key: str) -> Optional[Dict[str, Any]]:
    """Return the most recent cached optimization record for a source key.

    Caching is per-owner: a record is only reused for the user who created it.
    Returns ``None`` when nothing is cached.
    """
    from boto3.dynamodb.conditions import Key

    from app.core.tables import T

    try:
        resp = T.image_optimizations.query(
            IndexName="BySourceKey",
            KeyConditionExpression=Key("source_key_hash").eq(_source_key_hash(source_key)),
            ScanIndexForward=False,
            Limit=10,
        )
    except Exception:
        logger.exception("image_optimizations cache lookup failed")
        return None
    for item in resp.get("Items", []) or []:
        if str(item.get("owner_sub") or "") == owner_sub:
            return _record_to_dict(item)
    return None


def get_optimization_record(owner_sub: str, optimization_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single optimization record owned by ``owner_sub``."""
    from app.core.tables import T

    try:
        resp = T.image_optimizations.get_item(
            Key={"pk": f"USER#{owner_sub}", "sk": f"OPT#{optimization_id}"}
        )
    except Exception:
        logger.exception("image_optimizations get_item failed")
        return None
    item = resp.get("Item")
    if not item:
        return None
    return _record_to_dict(item)


def _record_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize a stored DDB item into an API-friendly record dict."""
    variants = item.get("variants") or {}
    out_variants: Dict[str, Dict[str, Any]] = {}
    for name, v in variants.items():
        out_variants[name] = {
            "url": v.get("url"),
            "width": int(v.get("width") or 0),
            "height": int(v.get("height") or 0),
            "size_bytes": int(v.get("size_bytes") or 0),
            "format": v.get("format") or "webp",
        }
    return {
        "optimization_id": item.get("optimization_id"),
        "owner_sub": item.get("owner_sub"),
        "source_key": item.get("source_key"),
        "source_url": item.get("source_url"),
        "output_format": item.get("output_format") or "webp",
        "variants": out_variants,
        "cached": False,
        "created_at": int(item.get("created_at") or 0),
    }


def optimize_source_image(
    owner_sub: str,
    source_key: str,
    *,
    s3_client: Any,
    bucket: str,
    formats: Optional[List[str]] = None,
    use_cache: bool = True,
) -> Optional[Dict[str, Any]]:
    """Optimize an already-uploaded image on demand.

    Downloads ``source_key`` from S3, generates responsive variants (reusing
    :func:`generate_variants`), stores each variant in S3 next to the source,
    persists an optimization record, and returns the record. Repeated calls for
    the same ``source_key`` return the cached record when ``use_cache`` is set.

    Returns ``None`` if the source could not be fetched. Returns a record with
    an empty ``variants`` map (graceful degradation) if encoding fails.
    """
    from botocore.exceptions import ClientError

    from app.core.time import now_ts

    fmt = (formats[0].lower() if formats else "webp")
    if fmt not in _VALID_FORMATS:
        fmt = "webp"

    if use_cache:
        cached = get_cached_record(owner_sub, source_key)
        if cached is not None and cached.get("output_format") == fmt:
            cached["cached"] = True
            return cached

    try:
        obj = s3_client.get_object(Bucket=bucket, Key=source_key)
        content = obj["Body"].read()
        content_type = obj.get("ContentType", "image/jpeg")
    except ClientError:
        logger.warning("optimize_source_image: source not found: %s", source_key)
        return None
    except Exception:
        logger.exception("optimize_source_image: failed to read source")
        return None

    variant_map = generate_variants(content, content_type)

    base_key = source_key.rsplit("/", 1)[0] if "/" in source_key else source_key
    out_variants: Dict[str, Dict[str, Any]] = {}
    ext = "webp"  # generate_variants always emits WebP
    for name, vdata in variant_map.items():
        vkey = f"{base_key}/{name}.{ext}"
        try:
            s3_client.put_object(
                Bucket=bucket,
                Key=vkey,
                Body=vdata["bytes"],
                ContentType=vdata["content_type"],
            )
        except Exception:
            logger.exception("optimize_source_image: variant upload failed for %s", vkey)
            continue
        out_variants[name] = {
            "url": _upload_object_url(vkey),
            "width": vdata["width"],
            "height": vdata["height"],
            "size_bytes": vdata["size_bytes"],
            "format": ext,
        }

    optimization_id = uuid.uuid4().hex
    created_at = now_ts()
    item: Dict[str, Any] = {
        "pk": f"USER#{owner_sub}",
        "sk": f"OPT#{optimization_id}",
        "optimization_id": optimization_id,
        "owner_sub": owner_sub,
        "source_key": source_key,
        "source_url": _upload_object_url(source_key),
        "source_key_hash": _source_key_hash(source_key),
        "output_format": ext,
        "variants": out_variants,
        "created_at": created_at,
    }

    try:
        from app.core.tables import T

        T.image_optimizations.put_item(Item=item)
    except Exception:
        logger.exception("optimize_source_image: failed to persist record")

    record = _record_to_dict(item)
    record["cached"] = False
    return record
