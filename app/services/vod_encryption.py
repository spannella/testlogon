"""VOD HLS Encryption integration (VOD-010).

Provides helpers to generate FFmpeg encryption parameters for AES-128
HLS segment encryption. Works with the standard FFmpeg `-hls_key_info_file`
mechanism which handles all encryption automatically.

Keyinfo file format (3 lines):
  Line 1: Key URI (embedded in #EXT-X-KEY tag in manifest)
  Line 2: Path to local key file (used by FFmpeg for encryption)
  Line 3: IV as hex string (optional; FFmpeg uses segment sequence number if omitted)
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from app.core.settings import S
from app.services.vod_drm_keys import (
    VodDrmKeyError,
    derive_content_key,
    derive_iv,
    derive_key_id,
    get_key_uri,
    is_drm_enabled,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EncryptionParams:
    """Parameters needed to encrypt HLS segments via FFmpeg."""

    asset_id: str
    key_id: str
    key_bytes: bytes
    iv_hex: str
    key_uri: str
    key_file_path: str
    keyinfo_file_path: str


def prepare_encryption_params(
    asset_id: str,
    *,
    key_slot: int = 0,
    scratch_dir: Optional[Path] = None,
) -> Optional[EncryptionParams]:
    """Prepare encryption parameters for an asset if DRM is enabled.

    Creates temporary files needed by FFmpeg:
    - Key file: raw 16-byte AES key
    - Keyinfo file: 3-line file with URI, key path, and IV

    Args:
        asset_id: The video asset identifier.
        key_slot: Key rotation slot (default 0).
        scratch_dir: Directory to write temp files into. Defaults to system temp.

    Returns:
        EncryptionParams if DRM is enabled for this asset, None otherwise.
    """
    if not is_drm_enabled():
        return None

    if not asset_id or not asset_id.strip():
        logger.warning("prepare_encryption_params called with empty asset_id")
        return None

    try:
        key_bytes = derive_content_key(asset_id, key_slot)
        key_id = derive_key_id(asset_id, key_slot)
        iv_bytes = derive_iv(asset_id, key_slot)
        key_uri = get_key_uri(asset_id, key_slot)
    except VodDrmKeyError as exc:
        logger.error("DRM key derivation failed for asset %s: %s", asset_id, exc.message)
        return None

    iv_hex = iv_bytes.hex()

    # Determine output directory for key files
    if scratch_dir:
        out_dir = scratch_dir
    else:
        out_dir = Path(tempfile.gettempdir())

    out_dir.mkdir(parents=True, exist_ok=True)

    # Write the raw key to a file
    key_file_path = out_dir / f"hls_key_{asset_id}_{key_slot}.bin"
    key_file_path.write_bytes(key_bytes)

    # Write the keyinfo file (3 lines)
    keyinfo_path = out_dir / f"keyinfo_{asset_id}_{key_slot}.txt"
    keyinfo_content = f"{key_uri}\n{key_file_path}\n{iv_hex}\n"
    keyinfo_path.write_text(keyinfo_content)

    return EncryptionParams(
        asset_id=asset_id,
        key_id=key_id,
        key_bytes=key_bytes,
        iv_hex=iv_hex,
        key_uri=key_uri,
        key_file_path=str(key_file_path),
        keyinfo_file_path=str(keyinfo_path),
    )


def get_ffmpeg_encryption_args(params: EncryptionParams) -> List[str]:
    """Generate FFmpeg command-line arguments for AES-128 HLS encryption.

    These args should be appended to the FFmpeg command BEFORE the output
    file/playlist arguments.

    Args:
        params: EncryptionParams from prepare_encryption_params().

    Returns:
        List of FFmpeg CLI arguments for HLS encryption.
    """
    return ["-hls_key_info_file", params.keyinfo_file_path]


def cleanup_encryption_files(params: EncryptionParams) -> None:
    """Remove temporary key and keyinfo files after transcoding.

    Args:
        params: The EncryptionParams whose files should be cleaned up.
    """
    for path_str in (params.key_file_path, params.keyinfo_file_path):
        try:
            path = Path(path_str)
            if path.exists():
                path.unlink()
        except OSError:
            logger.debug("Could not remove temp encryption file: %s", path_str)


def build_encrypted_manifest_ext_x_key(
    asset_id: str,
    *,
    key_slot: int = 0,
    token_placeholder: str = "{TOKEN}",
) -> str:
    """Build the #EXT-X-KEY tag content for an encrypted HLS manifest.

    This is useful for post-processing manifests or for documentation.

    Args:
        asset_id: The video asset identifier.
        key_slot: Key rotation slot.
        token_placeholder: Placeholder for the entitlement token in the URI.

    Returns:
        The full #EXT-X-KEY tag line.
    """
    key_id = derive_key_id(asset_id, key_slot)
    iv_bytes = derive_iv(asset_id, key_slot)
    base_url = (S.vod_drm_key_server_base_url or "http://localhost:8000/v1/vod/drm").rstrip("/")
    uri = f"{base_url}/key/{key_id}?asset={asset_id}&token={token_placeholder}"
    iv_hex = iv_bytes.hex().upper()

    return f'#EXT-X-KEY:METHOD=AES-128,URI="{uri}",IV=0x{iv_hex}'
