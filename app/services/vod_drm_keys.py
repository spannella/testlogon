"""VOD DRM Key Derivation Service (VOD-010).

Provides deterministic AES-128 content key derivation for HLS encryption.
Keys are derived using HKDF (SHA-256) from a root secret + asset context,
ensuring the same asset always gets the same key without storing keys in a DB.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


class VodDrmKeyError(ValueError):
    """Raised when DRM key operations fail."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _get_root_secret() -> bytes:
    """Get the root DRM key material. Raises if not configured."""
    root = (S.vod_drm_key_root or "").strip()
    if not root:
        raise VodDrmKeyError("key_root_not_configured", "VOD DRM key root is not configured")
    return root.encode("utf-8")


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 16) -> bytes:
    """Simple HKDF-SHA256 extract-then-expand (RFC 5869).

    Args:
        ikm: Input keying material
        salt: Optional salt (if empty, uses zero-filled hash-length bytes)
        info: Context/application-specific info
        length: Output length in bytes (max 32 for single expand step)

    Returns:
        Derived key material of specified length.
    """
    # Extract phase
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # Expand phase (single iteration is enough for <= 32 bytes)
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm[:length]


def _require_tenant_id(tenant_id: str) -> str:
    """Validate and normalize a tenant_id used for key namespacing (GAP-0372)."""
    if not tenant_id or not tenant_id.strip():
        raise VodDrmKeyError("invalid_tenant_id", "tenant_id must be non-empty")
    return tenant_id.strip()


def _tenant_salt(prefix: bytes, tenant_id: str, asset_id: str) -> bytes:
    """Build a tenant-scoped HKDF salt via sha256(prefix|tenant_id|asset_id).

    Including tenant_id in the salt provides domain separation so two tenants
    sharing the same asset_id derive cryptographically independent keys
    (GAP-0372 / VOD-010).
    """
    salt_input = prefix + b"|" + tenant_id.encode("utf-8") + b"|" + asset_id.encode("utf-8")
    return hashlib.sha256(salt_input).digest()


def derive_content_key(asset_id: str, tenant_id: str, key_slot: int = 0) -> bytes:
    """Derive a deterministic 16-byte AES-128 content key for an asset+tenant.

    Uses HKDF(SHA-256) with:
    - IKM: root secret from settings
    - Salt: sha256("vod-drm-content-key-v1|{tenant_id}|{asset_id}")  (tenant-scoped)
    - Info: "{tenant_id}:{asset_id}:{key_slot}"

    The tenant_id is incorporated into BOTH the salt and the info string so that
    two tenants sharing the same asset_id receive cryptographically independent
    keys (GAP-0372 / VOD-010 cross-tenant key reuse fix).

    Args:
        asset_id: Unique identifier for the video asset.
        tenant_id: The owning tenant (video.owner_user_id). MUST be non-empty.
        key_slot: Key rotation slot (default 0 = no rotation).

    Returns:
        16 bytes suitable for AES-128 encryption.
    """
    if not asset_id or not asset_id.strip():
        raise VodDrmKeyError("invalid_asset_id", "asset_id must be non-empty")
    tenant = _require_tenant_id(tenant_id)
    asset = asset_id.strip()

    root = _get_root_secret()
    salt = _tenant_salt(b"vod-drm-content-key-v1", tenant, asset)
    info = f"{tenant}:{asset}:{key_slot}".encode("utf-8")
    return _hkdf_sha256(ikm=root, salt=salt, info=info, length=16)


def derive_key_id(asset_id: str, tenant_id: str, key_slot: int = 0) -> str:
    """Derive a URL-safe key ID for the asset, scoped to a tenant.

    Uses HMAC-SHA256 of the tenant+asset context, truncated to 32 hex chars.
    This ID is used in the #EXT-X-KEY URI to identify which key to fetch.
    Tenant-scoped so two tenants with the same asset_id get distinct key IDs
    (GAP-0372).

    Args:
        asset_id: Unique identifier for the video asset.
        tenant_id: The owning tenant. MUST be non-empty.
        key_slot: Key rotation slot.

    Returns:
        URL-safe hex string key identifier (32 hex chars).
    """
    if not asset_id or not asset_id.strip():
        raise VodDrmKeyError("invalid_asset_id", "asset_id must be non-empty")
    tenant = _require_tenant_id(tenant_id)
    asset = asset_id.strip()

    root = _get_root_secret()
    context = f"key-id:{tenant}:{asset}:{key_slot}".encode("utf-8")
    digest = hmac.new(root, context, hashlib.sha256).hexdigest()
    return digest[:32]


def get_key_uri(asset_id: str, tenant_id: str, key_slot: int = 0) -> str:
    """Build the key server URI for an asset, embedding the tenant.

    This URI is embedded in the HLS manifest's #EXT-X-KEY tag so the player
    knows where to fetch the decryption key. The tenant is embedded so the key
    server can validate it against the entitlement token claim (GAP-0372).

    Args:
        asset_id: Unique identifier for the video asset.
        tenant_id: The owning tenant. MUST be non-empty.
        key_slot: Key rotation slot.

    Returns:
        Full URL to the key server endpoint.
    """
    tenant = _require_tenant_id(tenant_id)
    key_id = derive_key_id(asset_id, tenant, key_slot)
    base_url = (S.vod_drm_key_server_base_url or "http://localhost:8000/v1/vod/drm").rstrip("/")
    return f"{base_url}/key/{key_id}?asset={asset_id}&tenant={tenant}"


def derive_iv(asset_id: str, tenant_id: str, key_slot: int = 0) -> bytes:
    """Derive a deterministic 16-byte IV for the asset, scoped to a tenant.

    Uses a separate HKDF derivation so IV is independent of the key.
    Tenant-scoped to match the content key namespacing (GAP-0372).

    Args:
        asset_id: Unique identifier for the video asset.
        tenant_id: The owning tenant. MUST be non-empty.
        key_slot: Key rotation slot.

    Returns:
        16 bytes IV.
    """
    if not asset_id or not asset_id.strip():
        raise VodDrmKeyError("invalid_asset_id", "asset_id must be non-empty")
    tenant = _require_tenant_id(tenant_id)
    asset = asset_id.strip()

    root = _get_root_secret()
    salt = _tenant_salt(b"vod-drm-iv-v1", tenant, asset)
    info = f"{tenant}:{asset}:{key_slot}".encode("utf-8")
    return _hkdf_sha256(ikm=root, salt=salt, info=info, length=16)


def is_drm_enabled() -> bool:
    """Check whether VOD DRM encryption is enabled globally."""
    return bool(S.vod_drm_enabled)


def validate_key_id(key_id: str, asset_id: str, tenant_id: str, key_slot: int = 0) -> bool:
    """Validate that a key_id matches the expected derivation for an asset+tenant.

    Args:
        key_id: The key ID from the request.
        asset_id: The asset ID from the request.
        tenant_id: The owning tenant (from the verified entitlement claim).
        key_slot: Key rotation slot.

    Returns:
        True if the key_id matches the derived key_id for the asset+tenant.
    """
    expected = derive_key_id(asset_id, tenant_id, key_slot)
    return hmac.compare_digest(key_id, expected)


# ---------------------------------------------------------------------------
# DRM key revocation (VOD-010 §4.3 / §6.5-6.7, GAP-0374)
#
# Compromised keys must be invalidatable without redeploying. Revocation
# records are persisted to the ContentKeys DynamoDB table and checked at key
# serve time. Two record shapes share the same table (pk=key_id):
#   - per-key   : key_id = "<derived key_id hex>"  (revokes one specific key)
#   - per-asset : key_id = "ASSET#{tenant_id}#{asset_id}" (revoke-all marker)
# Both carry asset_id / tenant_id / created_at so the ByAssetCreatedAt /
# ByTenantCreatedAt GSIs can drive audit queries.
# ---------------------------------------------------------------------------

_ASSET_REVOCATION_PREFIX = "ASSET#"


def _asset_revocation_pk(tenant_id: str, asset_id: str) -> str:
    return f"{_ASSET_REVOCATION_PREFIX}{tenant_id}#{asset_id}"


def revoke_key(
    *,
    key_id: str,
    asset_id: str,
    tenant_id: str,
    revoked_by: str,
    reason: str | None = None,
    key_slot: int | None = None,
) -> Dict[str, Any]:
    """Persist a revocation record for a single DRM key (GAP-0374).

    The record is written to the ContentKeys table keyed by ``key_id`` so that
    ``is_key_revoked`` can look it up directly at serve time.
    """
    if not key_id or not key_id.strip():
        raise VodDrmKeyError("invalid_key_id", "key_id must be non-empty")
    if not asset_id or not asset_id.strip():
        raise VodDrmKeyError("invalid_asset_id", "asset_id must be non-empty")
    tenant = _require_tenant_id(tenant_id)

    item: Dict[str, Any] = {
        "key_id": key_id.strip(),
        "record_type": "key_revocation",
        "asset_id": asset_id.strip(),
        "tenant_id": tenant,
        "revoked": True,
        "revoked_by": (revoked_by or "").strip() or "unknown",
        "reason": (reason or "").strip() or None,
        "created_at": now_ts(),
    }
    if key_slot is not None:
        item["key_slot"] = int(key_slot)
    T.content_keys.put_item(Item=item)
    return item


def revoke_all_keys_for_asset(
    *,
    asset_id: str,
    tenant_id: str,
    revoked_by: str,
    reason: str | None = None,
) -> Dict[str, Any]:
    """Persist an asset-wide revocation marker (revoke-all) for GAP-0374.

    A single marker record revokes EVERY key derived for the asset+tenant,
    regardless of key_slot — keys are deterministically derived, so the marker
    is matched by asset_id+tenant_id at serve time rather than by key_id.
    """
    if not asset_id or not asset_id.strip():
        raise VodDrmKeyError("invalid_asset_id", "asset_id must be non-empty")
    tenant = _require_tenant_id(tenant_id)
    asset = asset_id.strip()

    item: Dict[str, Any] = {
        "key_id": _asset_revocation_pk(tenant, asset),
        "record_type": "asset_revocation",
        "asset_id": asset,
        "tenant_id": tenant,
        "revoked": True,
        "revoked_by": (revoked_by or "").strip() or "unknown",
        "reason": (reason or "").strip() or None,
        "created_at": now_ts(),
    }
    T.content_keys.put_item(Item=item)
    return item


def is_asset_revoked(asset_id: str, tenant_id: str) -> bool:
    """Return True if an asset-wide revocation marker exists for asset+tenant."""
    if not asset_id or not asset_id.strip() or not tenant_id or not tenant_id.strip():
        return False
    try:
        resp = T.content_keys.get_item(
            Key={"key_id": _asset_revocation_pk(tenant_id.strip(), asset_id.strip())}
        )
    except Exception:  # pragma: no cover - never block serving on a lookup error path
        logger.exception("is_asset_revoked lookup failed")
        return False
    item = resp.get("Item")
    return bool(item and item.get("revoked"))


def is_key_revoked(key_id: str, asset_id: str | None = None, tenant_id: str | None = None) -> bool:
    """Return True if the key (or its owning asset) has been revoked (GAP-0374).

    Checks both the per-key revocation record and, when asset/tenant are known,
    the asset-wide revoke-all marker. Never raises — a lookup failure must not
    crash the key-serve path.
    """
    if not key_id or not key_id.strip():
        return False
    try:
        resp = T.content_keys.get_item(Key={"key_id": key_id.strip()})
        item = resp.get("Item")
        if item and item.get("revoked"):
            return True
    except Exception:  # pragma: no cover
        logger.exception("is_key_revoked lookup failed")
        return False
    if asset_id and tenant_id:
        return is_asset_revoked(asset_id, tenant_id)
    return False
