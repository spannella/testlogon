from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass

from app.core.settings import S


@dataclass(frozen=True)
class LocalPlaybackUrl:
    url: str
    expires_at: int


_SAFE_STREAM_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _b64url_md5(payload: str) -> str:
    digest = hashlib.md5(payload.encode("utf-8")).digest()  # nosec B324 - compatible with nginx secure_link
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def _validate_stream_key(stream_key: str) -> str:
    candidate = (stream_key or "").strip()
    if not _SAFE_STREAM_KEY.fullmatch(candidate):
        raise ValueError("invalid stream key format")
    return candidate


def mint_local_playback_url(stream_key: str, *, ttl_seconds: int | None = None) -> LocalPlaybackUrl:
    key = _validate_stream_key(stream_key)
    ttl = int(ttl_seconds or S.broadcast_local_cache_token_ttl_seconds or 600)
    expires_at = int(time.time()) + max(30, ttl)
    path = f"/hls/{key}/master.m3u8"
    token_payload = f"{expires_at}{path} {S.broadcast_local_cache_token_secret or 'local-cache-secret'}"
    md5_token = _b64url_md5(token_payload)
    base = S.broadcast_local_cache_public_base_url or "http://localhost:8090"
    url = f"{base}{path}?md5={md5_token}&expires={expires_at}"
    return LocalPlaybackUrl(url=url, expires_at=expires_at)
