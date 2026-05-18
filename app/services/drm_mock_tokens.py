from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _unb64url(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def issue_mock_token(*, claims: dict[str, Any], secret: str, ttl_seconds: int = 300, now_epoch: int | None = None) -> str:
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    payload = {**claims, "iat": now, "exp": now + int(ttl_seconds)}
    header = {"alg": "HS256", "typ": "MOCKJWT"}

    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64url(sig)}"


def verify_mock_token(*, token: str, secret: str, now_epoch: int | None = None) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid token format")
    encoded_header, encoded_payload, encoded_sig = parts

    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    provided_sig = _unb64url(encoded_sig)
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise ValueError("invalid token signature")

    payload = json.loads(_unb64url(encoded_payload).decode("utf-8"))
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    if int(payload.get("exp", 0)) <= now:
        raise ValueError("token expired")
    return payload
