from __future__ import annotations

import pytest

from app.services.drm_entitlement_service import (
    build_entitlement_claims,
    validate_license_request,
    validate_license_response,
)


def test_build_entitlement_claims_with_ttl() -> None:
    claims = build_entitlement_claims(
        {
            "asset_id": "a1",
            "tenant_id": "t1",
            "session_id": "s1",
            "device_id": "d1",
            "profile": "multi_drm",
            "key_id": "key_1",
            "key_rotation_seconds": 300,
            "per_content_key": True,
            "offline_allowed": False,
            "ttl_seconds": 600,
        }
    )
    assert claims.profile == "multi_drm"
    assert claims.expires_at_epoch > claims.issued_at_epoch


def test_build_entitlement_claims_rejects_bad_expiry() -> None:
    with pytest.raises(ValueError) as exc:
        build_entitlement_claims(
            {
                "asset_id": "a1",
                "tenant_id": "t1",
                "session_id": "s1",
                "device_id": "d1",
                "profile": "widevine",
                "key_id": "key_1",
                "key_rotation_seconds": 300,
                "per_content_key": True,
                "offline_allowed": False,
                "issued_at_epoch": 200,
                "expires_at_epoch": 100,
            }
        )
    assert "expires_at_epoch must be greater" in str(exc.value)


def test_validate_license_request_and_response() -> None:
    req = validate_license_request(
        {
            "contract_version": "2026-03-drm-entitlement-v1",
            "profile": "playready",
            "asset_id": "a1",
            "tenant_id": "t1",
            "session_id": "s1",
            "device_id": "d1",
            "challenge_b64": "abc",
        }
    )
    assert req.profile == "playready"

    resp = validate_license_response(
        {
            "contract_version": "2026-03-drm-entitlement-v1",
            "profile": "playready",
            "key_id": "key_1",
            "license_b64": "xyz",
            "expires_at_epoch": 1200,
            "renewal_url": "https://license.example/renew",
        }
    )
    assert resp.renewal_url
