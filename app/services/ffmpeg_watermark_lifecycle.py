"""Watermark asset lifecycle management for FFmpeg VOD transcoding (VOD-004).

Handles downloading/copying watermark assets to a local scratch directory,
validating they are real raster images, and patching FFmpeg args to reference
the local copy.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from app.services.ffmpeg_executor_types import NonRetryableError

logger = logging.getLogger(__name__)

# Magic bytes for supported image formats
_PNG_MAGIC = b"\x89PNG"
_JPEG_MAGIC = b"\xff\xd8\xff"


async def prepare_watermark_asset(
    policy: dict, scratch_dir: Path
) -> Path | None:
    """Download or copy the watermark asset to a local scratch path.

    Args:
        policy: Watermark policy dict with at least 'mode' and optionally 'asset_uri'
        scratch_dir: Local directory for temporary files

    Returns:
        Local path to the watermark asset, or None if no watermark needed.

    Raises:
        NonRetryableError: If the asset is missing, invalid, or unsupported format.
    """
    mode = policy.get("mode", "none")
    if mode != "static_image":
        return None

    asset_uri = policy.get("asset_uri", "")
    if not asset_uri:
        return None

    local_wm_path = scratch_dir / "watermark_asset"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    if asset_uri.startswith("s3://"):
        await _download_from_s3(asset_uri, local_wm_path)
    elif asset_uri.startswith("file://"):
        src = Path(asset_uri[7:])  # strip file://
        _copy_local(src, local_wm_path)
    elif asset_uri.startswith("/"):
        src = Path(asset_uri)
        _copy_local(src, local_wm_path)
    elif asset_uri.startswith("http://") or asset_uri.startswith("https://"):
        await _download_from_url(asset_uri, local_wm_path)
    else:
        raise NonRetryableError(
            "invalid_watermark_uri", f"Unsupported URI scheme: {asset_uri}"
        )

    # Validate it is a real raster image
    _validate_image_file(local_wm_path)
    return local_wm_path


def patch_watermark_input(args: list[str], local_wm_path: Path) -> list[str]:
    """Replace the watermark asset URI in the FFmpeg args with the local path.

    The watermark is always the second -i argument in the command line.
    """
    patched: list[str] = []
    input_count = 0
    for i, arg in enumerate(args):
        if arg == "-i":
            input_count += 1
            patched.append(arg)
        elif i > 0 and args[i - 1] == "-i" and input_count == 2:
            # This is the value of the second -i (watermark input)
            patched.append(str(local_wm_path))
        else:
            patched.append(arg)
    return patched


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _copy_local(src: Path, dst: Path) -> None:
    """Copy a local file to the destination."""
    if not src.exists():
        raise NonRetryableError(
            "watermark_asset_not_found", f"Local watermark not found: {src}"
        )
    shutil.copy2(src, dst)


async def _download_from_s3(s3_uri: str, local_path: Path) -> None:
    """Download a watermark asset from S3."""
    import boto3

    from app.core.settings import S

    # Parse s3://bucket/key
    parts = s3_uri[5:].split("/", 1)
    if len(parts) != 2:
        raise NonRetryableError(
            "invalid_watermark_uri", f"Invalid S3 URI: {s3_uri}"
        )
    bucket, key = parts

    try:
        kwargs = {}
        if S.s3_endpoint_url:
            kwargs["endpoint_url"] = S.s3_endpoint_url
        s3 = boto3.client("s3", region_name=S.aws_region, **kwargs)
        s3.download_file(bucket, key, str(local_path))
    except Exception as e:
        raise NonRetryableError(
            "watermark_download_failed", f"S3 download failed: {e}"
        ) from e


async def _download_from_url(url: str, local_path: Path) -> None:
    """Download a watermark asset from HTTP(S)."""
    import urllib.request

    try:
        urllib.request.urlretrieve(url, str(local_path))
    except Exception as e:
        raise NonRetryableError(
            "watermark_download_failed", f"HTTP download failed: {e}"
        ) from e


def _validate_image_file(path: Path) -> None:
    """Validate that the file is a supported raster image (PNG or JPEG).

    Rejects SVG and other non-raster formats.
    """
    if not path.exists():
        raise NonRetryableError(
            "watermark_asset_not_found", f"Watermark file missing after download: {path}"
        )

    with open(path, "rb") as f:
        header = f.read(8)

    if len(header) < 4:
        raise NonRetryableError(
            "invalid_watermark_format", "Watermark file is too small to be a valid image"
        )

    # Check for SVG (XML-based)
    if header[:5] == b"<?xml" or header[:4] == b"<svg":
        raise NonRetryableError(
            "unsupported_watermark_format",
            "SVG watermarks are not supported. Please upload a PNG or JPEG file.",
        )

    # Check for valid raster formats
    if header[:4] == _PNG_MAGIC:
        return  # Valid PNG
    if header[:3] == _JPEG_MAGIC:
        return  # Valid JPEG

    raise NonRetryableError(
        "invalid_watermark_format",
        "Watermark must be a PNG or JPEG image. Detected unsupported format.",
    )
