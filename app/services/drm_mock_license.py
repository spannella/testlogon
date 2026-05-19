from __future__ import annotations

import time
from typing import Any

from app.services.drm_entitlement_service import validate_license_request
from app.services.drm_mock_tokens import issue_mock_token, verify_mock_token


def issue_entitlement_token(
    *,
    asset_id: str,
    tenant_id: str,
    session_id: str,
    device_id: str,
    profile: str,
    key_id: str,
    secret: str,
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    now = int(time.time())
    token = issue_mock_token(
        claims={
            "asset_id": asset_id,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "device_id": device_id,
            "profile": profile,
            "key_id": key_id,
        },
        secret=secret,
        ttl_seconds=ttl_seconds,
        now_epoch=now,
    )
    return {"token": token, "expires_at_epoch": now + ttl_seconds}


def issue_mock_license(*, payload: dict[str, Any], token: str, secret: str, now_epoch: int | None = None) -> dict[str, Any]:
    req = validate_license_request(payload)
    claims = verify_mock_token(token=token, secret=secret, now_epoch=now_epoch)

    for field in ("asset_id", "tenant_id", "session_id", "device_id", "profile"):
        if str(claims.get(field)) != str(getattr(req, field)):
            raise ValueError(f"token claim mismatch: {field}")

    exp = int(claims["exp"])
    return {
        "contract_version": "2026-03-drm-entitlement-v1",
        "profile": req.profile,
        "key_id": str(claims.get("key_id", "local-dev-key")),
        "license_b64": "bG9jYWwtY2xlYXIta2V5LWxpY2Vuc2U=",
        "expires_at_epoch": exp,
        "renewal_url": None,
        "clear_key": {
            "kid": str(claims.get("key_id", "local-dev-key")),
            "k": "dGVzdC1sb2NhbC1jbGVhci1rZXk=",
        },
    }
