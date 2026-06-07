"""VOD DRM Key Server endpoint (VOD-010).

Serves AES-128 decryption keys to HLS players after validating
playback entitlement tokens. The key is returned as raw 16 bytes
(application/octet-stream) so the player can decrypt segments directly.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.core.settings import S
from app.services.playback_entitlements import (
    PlaybackEntitlementError,
    validate_playback_entitlement,
)
from app.services.vod_drm_keys import (
    VodDrmKeyError,
    derive_content_key,
    derive_key_id,
    is_asset_revoked,
    is_drm_enabled,
    is_key_revoked,
    revoke_all_keys_for_asset,
    revoke_key,
    validate_key_id,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/vod/drm", tags=["vod-drm"])


@router.get("/key/{key_id}")
def get_decryption_key(
    key_id: str,
    asset: str = Query(..., min_length=1, description="Asset ID that this key belongs to"),
    token: str = Query(..., min_length=1, description="Playback entitlement token"),
    tenant: str | None = Query(
        None,
        description="Tenant ID (must match the entitlement token's tenant_id claim)",
    ),
):
    """Serve a decryption key for an HLS-encrypted asset.

    Flow:
    1. Validate the playback entitlement token (must be valid and contain matching asset_id).
    2. Verify the asset_id and (GAP-0372) tenant_id in the token match the request.
    3. Verify the key_id matches the tenant-scoped derived key for the asset.
    4. Derive and return the raw 16-byte AES key (tenant-scoped).

    The AUTHORITATIVE tenant is the verified entitlement token's ``tenant_id``
    claim — the key is always derived from that claim so a caller can only
    obtain keys for their own tenant namespace. If a ``tenant`` query param is
    supplied it MUST match the claim (403 on mismatch); this lets the manifest
    URI carry the tenant for clarity without weakening the security check.

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

    # 2b. (GAP-0372) The tenant is taken from the verified token claim. Reject a
    # tokens that lack a tenant_id, and reject any supplied tenant query param
    # that does not match the claim.
    token_tenant_id = (claims.get("tenant_id") or "").strip()
    if not token_tenant_id:
        raise HTTPException(
            status_code=403,
            detail={"code": "missing_tenant", "message": "token does not carry a tenant_id claim"},
        )
    if tenant is not None and tenant.strip() and tenant.strip() != token_tenant_id:
        raise HTTPException(
            status_code=403,
            detail={"code": "tenant_mismatch", "message": "tenant does not match token tenant_id"},
        )

    # 3. Validate key_id matches expected tenant-scoped derivation
    try:
        if not validate_key_id(key_id, asset, token_tenant_id):
            raise HTTPException(
                status_code=404,
                detail={"code": "key_not_found", "message": "key_id does not match any known key"},
            )
    except VodDrmKeyError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": exc.code, "message": exc.message},
        )

    # 3b. (GAP-0374) Refuse to serve a revoked key. An admin can revoke a single
    # key (by key_id) or every key for an asset (revoke-all); either makes the
    # key unservable without a redeploy. 410 Gone signals the key is permanently
    # invalidated.
    if is_key_revoked(key_id, asset_id=asset.strip(), tenant_id=token_tenant_id):
        raise HTTPException(
            status_code=410,
            detail={"code": "key_revoked", "message": "this decryption key has been revoked"},
        )

    # 4. Derive and return the content key (tenant-scoped)
    try:
        content_key = derive_content_key(asset, tenant_id=token_tenant_id)
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
def get_drm_info(
    asset_id: str,
    tenant: str | None = Query(
        None,
        description="Tenant ID (owner) — required to derive the tenant-scoped key id/uri",
    ),
):
    """Return DRM metadata for an asset (key URI, key ID, DRM enabled status).

    This endpoint does NOT require authentication — it only reveals
    the key server URI structure, not the actual key material.

    (GAP-0372) Key IDs/URIs are now tenant-scoped, so a ``tenant`` query param is
    required to compute them. Without a tenant, only the DRM-enabled flag is
    returned (no key_id/key_uri).
    """
    if not is_drm_enabled():
        return {
            "drm_enabled": False,
            "asset_id": asset_id,
            "key_id": None,
            "key_uri": None,
        }

    if not tenant or not tenant.strip():
        return {
            "drm_enabled": True,
            "asset_id": asset_id,
            "key_id": None,
            "key_uri": None,
            "error": "tenant_required",
        }

    try:
        key_id = derive_key_id(asset_id, tenant.strip())
    except VodDrmKeyError:
        return {
            "drm_enabled": True,
            "asset_id": asset_id,
            "key_id": None,
            "key_uri": None,
            "error": "key_derivation_failed",
        }

    base_url = (S.vod_drm_key_server_base_url or "http://localhost:8000/v1/vod/drm").rstrip("/")
    key_uri = f"{base_url}/key/{key_id}?asset={asset_id}&tenant={tenant.strip()}"

    return {
        "drm_enabled": True,
        "asset_id": asset_id,
        "key_id": key_id,
        "key_uri": key_uri,
    }


# ---------------------------------------------------------------------------
# Admin key revocation endpoints (VOD-010 §4.3 / §6.5-6.7, GAP-0374)
#
# Admin-only. A compromised DRM key (or every key for an asset) can be
# invalidated at runtime without redeploying — the serve-time check in
# get_decryption_key() refuses to serve any revoked key (410 Gone).
# ---------------------------------------------------------------------------


class RevokeKeyIn(BaseModel):
    """Revoke a single DRM key, identified EITHER by key_id OR by
    (asset_id, tenant_id [, key_slot]) so it can be derived server-side."""

    key_id: str | None = Field(None, description="The derived key_id to revoke")
    asset_id: str | None = Field(None, description="Asset ID (with tenant_id, to derive the key_id)")
    tenant_id: str | None = Field(None, description="Owning tenant ID")
    key_slot: int | None = Field(None, description="Key rotation slot (default 0)")
    reason: str | None = Field(None, max_length=500, description="Audit reason for revocation")


class RevokeAllIn(BaseModel):
    tenant_id: str = Field(..., min_length=1, description="Owning tenant ID")
    reason: str | None = Field(None, max_length=500, description="Audit reason for revocation")


@router.post("/keys/revoke")
def revoke_drm_key(
    body: RevokeKeyIn,
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    """Revoke a single DRM key so it stops being served (admin-only).

    The key may be supplied directly as ``key_id`` or resolved from
    ``(asset_id, tenant_id, key_slot)``. A revocation record is persisted to the
    ContentKeys table; subsequent GET /key/{key_id} calls return 410.
    """
    asset_id = (body.asset_id or "").strip()
    tenant_id = (body.tenant_id or "").strip()
    key_id = (body.key_id or "").strip()
    key_slot = body.key_slot if body.key_slot is not None else 0

    if not key_id and not (asset_id and tenant_id):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "missing_key_identity",
                "message": "provide key_id, or both asset_id and tenant_id",
            },
        )

    # If only asset/tenant were supplied, derive the key_id. asset_id/tenant_id
    # are required on the persisted record for the audit GSIs, so derive them
    # back from a bare key_id is impossible — require them in that combination.
    if not key_id:
        try:
            key_id = derive_key_id(asset_id, tenant_id, key_slot)
        except VodDrmKeyError as exc:
            raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message})
    else:
        if not (asset_id and tenant_id):
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "missing_asset_tenant",
                    "message": "asset_id and tenant_id are required alongside key_id for the revocation record",
                },
            )

    try:
        record = revoke_key(
            key_id=key_id,
            asset_id=asset_id,
            tenant_id=tenant_id,
            revoked_by=getattr(actor, "sub", None) or "admin",
            reason=body.reason,
            key_slot=key_slot,
        )
    except VodDrmKeyError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message})

    return {
        "ok": True,
        "revoked": True,
        "key_id": record["key_id"],
        "asset_id": record["asset_id"],
        "tenant_id": record["tenant_id"],
        "revoked_by": record["revoked_by"],
        "revoked_at": record["created_at"],
    }


@router.post("/keys/{asset_id}/revoke-all")
def revoke_all_drm_keys(
    asset_id: str,
    body: RevokeAllIn,
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    """Revoke every DRM key for an asset+tenant (admin-only).

    Writes an asset-wide revocation marker; the serve-time check refuses ALL
    keys for the asset+tenant thereafter (410), regardless of rotation slot.
    """
    asset = (asset_id or "").strip()
    tenant_id = (body.tenant_id or "").strip()
    if not asset:
        raise HTTPException(status_code=400, detail={"code": "invalid_asset_id", "message": "asset_id is required"})
    if not tenant_id:
        raise HTTPException(status_code=400, detail={"code": "invalid_tenant_id", "message": "tenant_id is required"})

    try:
        record = revoke_all_keys_for_asset(
            asset_id=asset,
            tenant_id=tenant_id,
            revoked_by=getattr(actor, "sub", None) or "admin",
            reason=body.reason,
        )
    except VodDrmKeyError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message})

    return {
        "ok": True,
        "revoked_all": True,
        "asset_id": record["asset_id"],
        "tenant_id": record["tenant_id"],
        "revoked_by": record["revoked_by"],
        "revoked_at": record["created_at"],
    }
