"""VOD DRM Key Server endpoint (VOD-010).

Serves AES-128 decryption keys to HLS players after validating
playback entitlement tokens. The key is returned as raw 16 bytes
(application/octet-stream) so the player can decrypt segments directly.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from app.core.settings import S
from app.services.playback_entitlements import (
    PlaybackEntitlementError,
    validate_playback_entitlement,
)
from app.services.vod_drm_keys import (
    VodDrmKeyError,
    derive_content_key,
    derive_key_id,
    is_drm_enabled,
    validate_key_id,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/vod/drm", tags=["vod-drm"])


@router.get("/key/{key_id}")
def get_decryption_key(
    key_id: str,
    asset: str = Query(..., min_length=1, description="Asset ID that this key belongs to"),
    token: str = Query(..., min_length=1, description="Playback entitlement token"),
):
    """Serve a decryption key for an HLS-encrypted asset.

    Flow:
    1. Validate the playback entitlement token (must be valid and contain matching asset_id).
    2. Verify the key_id matches the derived key for the asset.
    3. Derive and return the raw 16-byte AES key.

    Returns:
        Raw 16 bytes as application/octet-stream.
    """
    # 1. Validate entitlement token
    try:
        claims = validate_playback_entitlement(
            token=token,
            expected_audience=S.playback_entitlement_expected_audience or "playback",
        )
    except PlaybackEntitlementError as exc:
        status = 401 if exc.code in ("invalid_signature", "invalid_format", "token_expired",
                                      "missing_claims", "invalid_header", "invalid_header_alg",
                                      "invalid_header_typ", "invalid_payload",
                                      "invalid_signature", "token_too_large",
                                      "token_not_yet_valid") else 403
        raise HTTPException(
            status_code=status,
            detail={"code": exc.code, "message": exc.message},
        )

    # 2. Verify asset_id in token matches the requested asset
    token_asset_id = (claims.get("asset_id") or "").strip()
    if token_asset_id != asset.strip():
        raise HTTPException(
            status_code=403,
            detail={"code": "asset_mismatch", "message": "token asset_id does not match requested asset"},
        )

    # 3. Validate key_id matches expected derivation
    try:
        if not validate_key_id(key_id, asset):
            raise HTTPException(
                status_code=404,
                detail={"code": "key_not_found", "message": "key_id does not match any known key"},
            )
    except VodDrmKeyError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": exc.code, "message": exc.message},
        )

    # 4. Derive and return the content key
    try:
        content_key = derive_content_key(asset)
    except VodDrmKeyError as exc:
        raise HTTPException(
            status_code=500,
            detail={"code": exc.code, "message": exc.message},
        )

    return Response(
        content=content_key,
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/info/{asset_id}")
def get_drm_info(asset_id: str):
    """Return DRM metadata for an asset (key URI, key ID, DRM enabled status).

    This endpoint does NOT require authentication — it only reveals
    the key server URI structure, not the actual key material.
    """
    if not is_drm_enabled():
        return {
            "drm_enabled": False,
            "asset_id": asset_id,
            "key_id": None,
            "key_uri": None,
        }

    try:
        key_id = derive_key_id(asset_id)
    except VodDrmKeyError:
        return {
            "drm_enabled": True,
            "asset_id": asset_id,
            "key_id": None,
            "key_uri": None,
            "error": "key_derivation_failed",
        }

    base_url = (S.vod_drm_key_server_base_url or "http://localhost:8000/v1/vod/drm").rstrip("/")
    key_uri = f"{base_url}/key/{key_id}?asset={asset_id}"

    return {
        "drm_enabled": True,
        "asset_id": asset_id,
        "key_id": key_id,
        "key_uri": key_uri,
    }
