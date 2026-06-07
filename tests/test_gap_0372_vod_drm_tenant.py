"""GAP-0372 (VOD-010): tenant_id threaded into VOD DRM key derivation.

Cross-tenant key reuse fix. BEFORE the fix `derive_content_key(asset_id, key_slot=0)`
had no tenant component, so two tenants sharing the same asset_id received
IDENTICAL AES-128 keys. AFTER the fix the tenant_id is part of the HKDF
salt + info, so the same asset under two different tenants derives
cryptographically independent keys.

This module is hermetic: derivation is pure crypto (no AWS), and the endpoint
test calls the route handler directly with the entitlement-token validator
stubbed (no real token/AWS).
"""

from __future__ import annotations

import os

import pytest

# Required env before importing app modules (pure-crypto, no AWS).
os.environ.setdefault("VOD_DRM_ENABLED", "1")
os.environ.setdefault("VOD_DRM_KEY_ROOT", "test-root-key-for-gap-0372")
os.environ.setdefault("VOD_DRM_KEY_SERVER_BASE_URL", "http://localhost:8000/v1/vod/drm")
os.environ.setdefault("PLAYBACK_ENTITLEMENT_SECRET", "test-entitlement-secret")
os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
os.environ.setdefault("DEV_MODE", "1")


# ---------------------------------------------------------------------------
# Core derivation: tenant isolation (the heart of GAP-0372)
# ---------------------------------------------------------------------------

def test_same_asset_different_tenant_produces_different_content_keys():
    from app.services.vod_drm_keys import derive_content_key

    key_a = derive_content_key("asset-shared", tenant_id="tenant-alice")
    key_b = derive_content_key("asset-shared", tenant_id="tenant-bob")
    assert key_a != key_b, (
        "Cross-tenant key collision: same asset_id produced the same key for "
        "different tenants (GAP-0372 not fixed)"
    )
    assert len(key_a) == 16 and len(key_b) == 16


def test_same_asset_same_tenant_content_key_is_deterministic():
    from app.services.vod_drm_keys import derive_content_key

    k1 = derive_content_key("asset-shared", tenant_id="tenant-alice")
    k2 = derive_content_key("asset-shared", tenant_id="tenant-alice")
    assert k1 == k2


def test_different_asset_same_tenant_produces_different_content_keys():
    from app.services.vod_drm_keys import derive_content_key

    k1 = derive_content_key("asset-a", tenant_id="tenant-alice")
    k2 = derive_content_key("asset-b", tenant_id="tenant-alice")
    assert k1 != k2


def test_empty_tenant_id_raises_content_key():
    from app.services.vod_drm_keys import VodDrmKeyError, derive_content_key

    with pytest.raises(VodDrmKeyError, match="tenant_id must be non-empty"):
        derive_content_key("asset-x", tenant_id="")
    with pytest.raises(VodDrmKeyError, match="tenant_id must be non-empty"):
        derive_content_key("asset-x", tenant_id="   ")


def test_key_id_is_tenant_scoped():
    from app.services.vod_drm_keys import derive_key_id

    id_a = derive_key_id("asset-shared", tenant_id="tenant-alice")
    id_b = derive_key_id("asset-shared", tenant_id="tenant-bob")
    assert id_a != id_b
    # deterministic for same (asset, tenant)
    assert id_a == derive_key_id("asset-shared", tenant_id="tenant-alice")


def test_iv_is_tenant_scoped():
    from app.services.vod_drm_keys import derive_iv

    iv_a = derive_iv("asset-shared", tenant_id="tenant-alice")
    iv_b = derive_iv("asset-shared", tenant_id="tenant-bob")
    assert iv_a != iv_b
    assert len(iv_a) == 16
    assert iv_a == derive_iv("asset-shared", tenant_id="tenant-alice")


def test_iv_differs_from_content_key_for_same_tenant_asset():
    from app.services.vod_drm_keys import derive_content_key, derive_iv

    key = derive_content_key("asset-shared", tenant_id="tenant-alice")
    iv = derive_iv("asset-shared", tenant_id="tenant-alice")
    assert key != iv


def test_get_key_uri_embeds_tenant():
    from app.services.vod_drm_keys import derive_key_id, get_key_uri

    uri = get_key_uri("asset-shared", tenant_id="tenant-alice")
    key_id = derive_key_id("asset-shared", tenant_id="tenant-alice")
    assert f"/key/{key_id}" in uri
    assert "asset=asset-shared" in uri
    assert "tenant=tenant-alice" in uri


def test_validate_key_id_requires_matching_tenant():
    from app.services.vod_drm_keys import derive_key_id, validate_key_id

    key_id = derive_key_id("asset-shared", tenant_id="tenant-alice")
    assert validate_key_id(key_id, "asset-shared", "tenant-alice") is True
    # Same key_id is NOT valid under a different tenant namespace.
    assert validate_key_id(key_id, "asset-shared", "tenant-bob") is False


# ---------------------------------------------------------------------------
# Endpoint: tenant from verified claim + query-param mismatch rejection
# ---------------------------------------------------------------------------

def _call_endpoint(*, key_id, asset, token, tenant, claims):
    """Invoke the route handler directly with the token validator stubbed."""
    from unittest.mock import patch

    from fastapi import HTTPException

    import app.routers.vod_drm as vod_drm

    with patch.object(vod_drm, "validate_playback_entitlement", return_value=claims):
        try:
            return vod_drm.get_decryption_key(
                key_id=key_id, asset=asset, token=token, tenant=tenant
            )
        except HTTPException as exc:
            return exc


def test_endpoint_derives_key_from_verified_claim_tenant():
    from fastapi.responses import Response

    from app.services.vod_drm_keys import derive_content_key, derive_key_id

    tenant = "tenant-claim"
    asset = "asset-1"
    key_id = derive_key_id(asset, tenant)
    claims = {"asset_id": asset, "tenant_id": tenant}

    result = _call_endpoint(
        key_id=key_id, asset=asset, token="tok", tenant=None, claims=claims
    )
    assert isinstance(result, Response)
    assert result.body == derive_content_key(asset, tenant_id=tenant)
    assert result.media_type == "application/octet-stream"


def test_endpoint_matching_tenant_query_param_returns_key():
    from fastapi.responses import Response

    from app.services.vod_drm_keys import derive_key_id

    tenant = "tenant-claim"
    asset = "asset-1"
    key_id = derive_key_id(asset, tenant)
    claims = {"asset_id": asset, "tenant_id": tenant}

    result = _call_endpoint(
        key_id=key_id, asset=asset, token="tok", tenant=tenant, claims=claims
    )
    assert isinstance(result, Response)
    assert len(result.body) == 16


def test_endpoint_rejects_tenant_query_mismatch_with_403():
    from fastapi import HTTPException

    from app.services.vod_drm_keys import derive_key_id

    tenant = "tenant-claim"
    asset = "asset-1"
    key_id = derive_key_id(asset, tenant)
    claims = {"asset_id": asset, "tenant_id": tenant}

    result = _call_endpoint(
        key_id=key_id, asset=asset, token="tok", tenant="tenant-attacker", claims=claims
    )
    assert isinstance(result, HTTPException)
    assert result.status_code == 403
    assert result.detail["code"] == "tenant_mismatch"


def test_endpoint_rejects_token_without_tenant_claim_with_403():
    from fastapi import HTTPException

    from app.services.vod_drm_keys import derive_key_id

    asset = "asset-1"
    key_id = derive_key_id(asset, "tenant-claim")
    claims = {"asset_id": asset}  # no tenant_id

    result = _call_endpoint(
        key_id=key_id, asset=asset, token="tok", tenant=None, claims=claims
    )
    assert isinstance(result, HTTPException)
    assert result.status_code == 403
    assert result.detail["code"] == "missing_tenant"


def test_endpoint_key_id_for_wrong_tenant_returns_404():
    """A key_id derived under tenant B cannot be served under tenant A's claim."""
    from fastapi import HTTPException

    from app.services.vod_drm_keys import derive_key_id

    asset = "asset-1"
    # key_id derived for a DIFFERENT tenant than the claim
    foreign_key_id = derive_key_id(asset, "tenant-bob")
    claims = {"asset_id": asset, "tenant_id": "tenant-alice"}

    result = _call_endpoint(
        key_id=foreign_key_id, asset=asset, token="tok", tenant=None, claims=claims
    )
    assert isinstance(result, HTTPException)
    assert result.status_code == 404
    assert result.detail["code"] == "key_not_found"
