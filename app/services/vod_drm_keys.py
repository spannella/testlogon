"""VOD DRM Key Derivation Service (VOD-010).

Provides deterministic AES-128 content key derivation for HLS encryption.
Keys are derived using HKDF (SHA-256) from a root secret + asset context,
ensuring the same asset always gets the same key without storing keys in a DB.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional

from app.core.settings import S


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


def derive_content_key(asset_id: str, key_slot: int = 0) -> bytes:
    """Derive a deterministic 16-byte AES-128 content key for an asset.

    Uses HKDF(SHA-256) with:
    - IKM: root secret from settings
    - Salt: fixed "vod-drm-content-key-v1"
    - Info: "{asset_id}:{key_slot}"

    Args:
        asset_id: Unique identifier for the video asset.
        key_slot: Key rotation slot (default 0 = no rotation).

    Returns:
        16 bytes suitable for AES-128 encryption.
    """
    if not asset_id or not asset_id.strip():
        raise VodDrmKeyError("invalid_asset_id", "asset_id must be non-empty")

    root = _get_root_secret()
    salt = b"vod-drm-content-key-v1"
    info = f"{asset_id.strip()}:{key_slot}".encode("utf-8")
    return _hkdf_sha256(ikm=root, salt=salt, info=info, length=16)


def derive_key_id(asset_id: str, key_slot: int = 0) -> str:
    """Derive a URL-safe key ID for the asset.

    Uses HMAC-SHA256 of the asset context, truncated to 16 hex chars.
    This ID is used in the #EXT-X-KEY URI to identify which key to fetch.

    Args:
        asset_id: Unique identifier for the video asset.
        key_slot: Key rotation slot.

    Returns:
        URL-safe hex string key identifier (32 hex chars).
    """
    if not asset_id or not asset_id.strip():
        raise VodDrmKeyError("invalid_asset_id", "asset_id must be non-empty")

    root = _get_root_secret()
    context = f"key-id:{asset_id.strip()}:{key_slot}".encode("utf-8")
    digest = hmac.new(root, context, hashlib.sha256).hexdigest()
    return digest[:32]


def get_key_uri(asset_id: str, key_slot: int = 0) -> str:
    """Build the key server URI for an asset.

    This URI is embedded in the HLS manifest's #EXT-X-KEY tag so the player
    knows where to fetch the decryption key.

    Args:
        asset_id: Unique identifier for the video asset.
        key_slot: Key rotation slot.

    Returns:
        Full URL to the key server endpoint.
    """
    key_id = derive_key_id(asset_id, key_slot)
    base_url = (S.vod_drm_key_server_base_url or "http://localhost:8000/v1/vod/drm").rstrip("/")
    return f"{base_url}/key/{key_id}?asset={asset_id}"


def derive_iv(asset_id: str, key_slot: int = 0) -> bytes:
    """Derive a deterministic 16-byte IV for the asset.

    Uses a separate HKDF derivation so IV is independent of the key.

    Args:
        asset_id: Unique identifier for the video asset.
        key_slot: Key rotation slot.

    Returns:
        16 bytes IV.
    """
    if not asset_id or not asset_id.strip():
        raise VodDrmKeyError("invalid_asset_id", "asset_id must be non-empty")

    root = _get_root_secret()
    salt = b"vod-drm-iv-v1"
    info = f"{asset_id.strip()}:{key_slot}".encode("utf-8")
    return _hkdf_sha256(ikm=root, salt=salt, info=info, length=16)


def is_drm_enabled() -> bool:
    """Check whether VOD DRM encryption is enabled globally."""
    return bool(S.vod_drm_enabled)


def validate_key_id(key_id: str, asset_id: str, key_slot: int = 0) -> bool:
    """Validate that a key_id matches the expected derivation for an asset.

    Args:
        key_id: The key ID from the request.
        asset_id: The asset ID from the request.
        key_slot: Key rotation slot.

    Returns:
        True if the key_id matches the derived key_id for the asset.
    """
    expected = derive_key_id(asset_id, key_slot)
    return hmac.compare_digest(key_id, expected)
