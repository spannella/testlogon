from __future__ import annotations

import base64
import hashlib
import hmac
import posixpath
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from app.core.settings import S


@dataclass(frozen=True)
class CloudFrontSignedPlayback:
    playback_url: str
    expires_at: int
    token: str


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _sign(path: str, expires_at: int) -> str:
    secret = (S.broadcast_cloudfront_signing_secret or "dev-cloudfront-secret").encode("utf-8")
    payload = f"{path}:{expires_at}".encode("utf-8")
    return _b64url(hmac.new(secret, payload, hashlib.sha256).digest())


def _normalize_token_path(path: str) -> str:
    parsed = urlparse(path)
    raw_path = parsed.path if parsed.scheme or parsed.netloc else path
    candidate = (raw_path or "/").strip()
    if not candidate.startswith("/"):
        raise ValueError("path must start with '/'")
    normalized = posixpath.normpath(candidate)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    if ".." in normalized.split("/"):
        raise ValueError("path traversal is not allowed")
    return normalized


def resolve_cloudfront_base_domain() -> str:
    domain = (S.broadcast_cloudfront_domain or "").strip()
    if domain:
        return domain
    return "d111111abcdef8.cloudfront.net"


def map_origin_to_cloudfront_url(origin_url: str) -> str:
    parsed = urlparse(origin_url)
    path = parsed.path or "/"
    return f"https://{resolve_cloudfront_base_domain()}{path}"


def mint_cloudfront_signed_playback_url(*, origin_url: str, ttl_seconds: int | None = None) -> CloudFrontSignedPlayback:
    ttl = int(ttl_seconds or S.broadcast_cloudfront_token_ttl_seconds or 600)
    expires_at = int(time.time()) + max(30, ttl)
    mapped = map_origin_to_cloudfront_url(origin_url)
    path = _normalize_token_path(urlparse(mapped).path or "/")
    token = _sign(path, expires_at)
    signed = f"{mapped}?cf_token={token}&cf_expires={expires_at}"
    return CloudFrontSignedPlayback(playback_url=signed, expires_at=expires_at, token=token)


def validate_cloudfront_token(*, path: str, token: str, expires_at: int) -> bool:
    if not token:
        return False
    now = int(time.time())
    try:
        exp = int(expires_at)
    except (TypeError, ValueError):
        return False
    if exp <= now:
        return False
    max_ttl = int(S.broadcast_cloudfront_token_ttl_seconds or 600)
    max_future_expiry = now + max(30, max_ttl) + 30  # allow small clock skew buffer
    if exp > max_future_expiry:
        return False
    try:
        normalized_path = _normalize_token_path(path)
    except ValueError:
        return False
    expected = _sign(normalized_path, exp)
    return hmac.compare_digest(token, expected)


def cloudfront_security_defaults() -> dict:
    return {
        "cache_policy_id": S.broadcast_cloudfront_cache_policy_id,
        "response_headers_policy_id": S.broadcast_cloudfront_response_headers_policy_id,
        "waf_acl_arn": S.broadcast_cloudfront_waf_acl_arn or None,
        "geo_allowlist": [c.strip().upper() for c in (S.broadcast_cloudfront_geo_allowlist or "").split(",") if c.strip()],
    }
