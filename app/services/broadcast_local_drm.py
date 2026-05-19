from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException

from app.core.settings import S


@dataclass(frozen=True)
class LocalDrmToken:
    token: str
    stream_key: str
    expires_at: int


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def mint_local_drm_token(stream_key: str, ttl_seconds: int = 3600) -> LocalDrmToken:
    exp = int(time.time()) + max(60, int(ttl_seconds))
    payload = f"{stream_key}:{exp}".encode("utf-8")
    secret = (S.broadcast_local_drm_token_secret or "local-drm-secret").encode("utf-8")
    sig = hmac.new(secret, payload, hashlib.sha256).digest()
    token = f"{_b64url(payload)}.{_b64url(sig)}"
    return LocalDrmToken(token=token, stream_key=stream_key, expires_at=exp)


def validate_local_drm_token(token: str, stream_key: str) -> bool:
    static_token = (S.broadcast_local_drm_static_token or "").strip()
    if static_token and token == static_token:
        return True

    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _b64url_decode(payload_b64)
        signature = _b64url_decode(sig_b64)
        secret = (S.broadcast_local_drm_token_secret or "local-drm-secret").encode("utf-8")
        expected = hmac.new(secret, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return False
        payload_str = payload.decode("utf-8")
        sk, exp_s = payload_str.split(":", 1)
        if sk != stream_key:
            return False
        return int(exp_s) > int(time.time())
    except Exception:
        return False


def local_drm_key_path(stream_key: str) -> Path:
    root = Path(S.broadcast_local_drm_key_root or "tmp/broadcast-hls/keys")
    return root / f"{stream_key}.key"


def load_local_drm_key(stream_key: str, token: str) -> bytes:
    if not validate_local_drm_token(token, stream_key):
        raise HTTPException(status_code=403, detail={"code": "BROADCAST_DRM_TOKEN_INVALID", "detail": "invalid drm token"})

    key_path = local_drm_key_path(stream_key)
    if not key_path.exists():
        raise HTTPException(status_code=404, detail={"code": "BROADCAST_DRM_KEY_NOT_FOUND", "detail": "local drm key not found"})

    data = key_path.read_bytes()
    if len(data) != 16:
        raise HTTPException(status_code=500, detail={"code": "BROADCAST_DRM_KEY_INVALID", "detail": "local drm key must be 16 bytes"})
    return data


def ensure_local_key_dir() -> None:
    os.makedirs(S.broadcast_local_drm_key_root or "tmp/broadcast-hls/keys", exist_ok=True)
