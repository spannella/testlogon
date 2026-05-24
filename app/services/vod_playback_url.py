"""VOD playback URL generation (VOD-005).

Generates signed manifest URLs for VOD assets. Supports three modes:
- Dev mode: direct mock S3 access via /mock/s3/{bucket}/{key}
- CloudFront: HMAC-signed URLs (reuses broadcast_cloudfront signing)
- Presigned: S3 presigned GET URLs (fallback without CloudFront)
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from app.core.aws_clients import s3_client
from app.core.settings import S
from app.services.broadcast_cloudfront import (
    _b64url,
    _normalize_token_path,
    _sign,
    resolve_cloudfront_base_domain,
)

_s3 = s3_client()


@dataclass(frozen=True)
class VodPlaybackUrl:
    """Signed playback URL for a VOD asset."""
    url: str
    expires_at: int
    manifest_key: str
    mode: str = "dev"  # "dev" | "cloudfront" | "presigned"
    thumbnail_url: Optional[str] = None


def mint_vod_playback_url(
    video_id: str,
    tenant_id: str,
    *,
    ttl_seconds: Optional[int] = None,
) -> VodPlaybackUrl:
    """
    Generate a signed playback URL for a VOD asset.

    Dispatches to the appropriate mode based on settings:
    - dev_mode=True -> mock S3 URL
    - broadcast_cloudfront_domain set -> CloudFront signed URL
    - otherwise -> S3 presigned URL
    """
    if S.dev_mode:
        return _mint_dev_url(video_id=video_id, tenant_id=tenant_id)
    if S.vod_cloudfront_domain or S.broadcast_cloudfront_domain:
        return _mint_cloudfront_url(
            video_id=video_id, tenant_id=tenant_id, ttl_seconds=ttl_seconds
        )
    return _mint_presigned_url(
        video_id=video_id, tenant_id=tenant_id, ttl_seconds=ttl_seconds
    )


def validate_vod_playback_token(path: str, token: str, expires: int) -> bool:
    """
    Validate a VOD playback token.

    Checks that:
    - Token is non-empty
    - Expiry is in the future
    - Token matches the expected HMAC signature for the path
    """
    if not token:
        return False
    now = int(time.time())
    try:
        exp = int(expires)
    except (TypeError, ValueError):
        return False
    if exp <= now:
        return False

    # Max TTL check
    max_ttl = int(S.vod_playback_url_ttl_seconds or 3600)
    max_future_expiry = now + max(60, max_ttl) + 30  # clock skew buffer
    if exp > max_future_expiry:
        return False

    try:
        normalized_path = _normalize_token_path(path)
    except ValueError:
        return False

    expected = _vod_sign(normalized_path, exp)
    return hmac_mod.compare_digest(token, expected)


# ─── Internal helpers ────────────────────────────────────────────────────────


def _vod_sign(path: str, expires_at: int) -> str:
    """Sign a VOD path with the VOD-specific or broadcast CloudFront secret."""
    secret = (
        S.vod_cloudfront_signing_secret
        or S.broadcast_cloudfront_signing_secret
        or "dev-vod-cf-secret"
    ).encode("utf-8")
    payload = f"{path}:{expires_at}".encode("utf-8")
    return _b64url(hmac_mod.new(secret, payload, hashlib.sha256).digest())


def _manifest_key(video_id: str, tenant_id: str) -> str:
    prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"
    return f"{prefix}/{tenant_id}/assets/{video_id}/hls/master.m3u8"


def _mint_dev_url(*, video_id: str, tenant_id: str) -> VodPlaybackUrl:
    """Generate a dev-mode playback URL via the /mock/s3 proxy."""
    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    key = _manifest_key(video_id, tenant_id)
    url = f"http://localhost:8000/mock/s3/{bucket}/{key}"

    # Thumbnail URL
    prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"
    thumb_key = f"{prefix}/{tenant_id}/assets/{video_id}/thumbnails/poster_0s.jpg"
    thumb_url = f"http://localhost:8000/mock/s3/{bucket}/{thumb_key}"

    return VodPlaybackUrl(
        url=url,
        expires_at=0,
        manifest_key=key,
        mode="dev",
        thumbnail_url=thumb_url,
    )


def _mint_cloudfront_url(
    *,
    video_id: str,
    tenant_id: str,
    ttl_seconds: Optional[int] = None,
) -> VodPlaybackUrl:
    """Generate a CloudFront-signed playback URL for a VOD asset."""
    ttl = int(ttl_seconds or S.vod_playback_url_ttl_seconds or 3600)
    expires_at = int(time.time()) + max(60, ttl)

    prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"
    path = f"/{prefix}/{tenant_id}/assets/{video_id}/hls/master.m3u8"
    normalized = _normalize_token_path(path)
    token = _sign(normalized, expires_at)

    domain = S.vod_cloudfront_domain or resolve_cloudfront_base_domain()
    signed_url = f"https://{domain}{path}?cf_token={token}&cf_expires={expires_at}"

    # Also sign thumbnail URL
    thumb_path = f"/{prefix}/{tenant_id}/assets/{video_id}/thumbnails/poster_0s.jpg"
    thumb_token = _sign(_normalize_token_path(thumb_path), expires_at)
    thumb_url = f"https://{domain}{thumb_path}?cf_token={thumb_token}&cf_expires={expires_at}"

    key = _manifest_key(video_id, tenant_id)
    return VodPlaybackUrl(
        url=signed_url,
        expires_at=expires_at,
        manifest_key=key,
        mode="cloudfront",
        thumbnail_url=thumb_url,
    )


def _mint_presigned_url(
    *,
    video_id: str,
    tenant_id: str,
    ttl_seconds: Optional[int] = None,
) -> VodPlaybackUrl:
    """Generate an S3 presigned URL for direct bucket access."""
    ttl = int(ttl_seconds or S.vod_playback_url_ttl_seconds or 3600)
    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    key = _manifest_key(video_id, tenant_id)

    url = _s3.generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=ttl,
    )
    return VodPlaybackUrl(
        url=url,
        expires_at=int(time.time()) + ttl,
        manifest_key=key,
        mode="presigned",
    )
