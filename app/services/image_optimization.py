"""Image optimization pipeline: resize + WebP conversion (PLATFORM-004)."""
from __future__ import annotations

import io
import logging
from typing import Any, Dict, Tuple

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
