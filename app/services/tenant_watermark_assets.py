from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

from app.core.settings import S
from app.core.time import now_ts

ALLOWED_MIME_TYPES = {"image/png", "image/svg+xml"}
MAX_WATERMARK_ASSET_BYTES = 2 * 1024 * 1024


@dataclass
class WatermarkAssetRecord:
    asset_id: str
    tenant_id: str
    file_name: str
    content_type: str
    size_bytes: int
    storage_url: str
    created_at: int
    assigned_profile_ids: set[str]


_ASSETS_BY_TENANT: dict[str, dict[str, WatermarkAssetRecord]] = {}
_DEFAULT_PROFILE_BY_TENANT: dict[str, str] = {}


def reset_tenant_watermark_asset_store() -> None:
    _ASSETS_BY_TENANT.clear()
    _DEFAULT_PROFILE_BY_TENANT.clear()


def _validate_tenant_id(tenant_id: str) -> str:
    cleaned = (tenant_id or "").strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail="tenant_id is required")
    return cleaned


def _validate_profile_id(profile_id: str) -> str:
    cleaned = (profile_id or "").strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail="profile_id is required")
    return cleaned


def _detect_content_type(content: bytes) -> str | None:
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"

    prefix = content[:512].lstrip().lower()
    if prefix.startswith(b"<?xml") or prefix.startswith(b"<svg"):
        if b"<svg" in content[:4096].lower():
            return "image/svg+xml"
    return None


def _validate_asset_payload(*, file_name: str, content: bytes, content_type: str | None) -> str:
    if not content:
        raise HTTPException(status_code=400, detail="watermark asset is empty")
    if len(content) > MAX_WATERMARK_ASSET_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"watermark asset exceeds {MAX_WATERMARK_ASSET_BYTES} bytes limit",
        )

    detected = _detect_content_type(content)
    if not detected:
        raise HTTPException(
            status_code=400,
            detail="unsupported watermark asset format; only PNG and SVG are allowed",
        )

    declared = (content_type or "").strip().lower()
    if declared and declared not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"unsupported content_type '{declared}'; allowed: image/png, image/svg+xml",
        )

    suffix = Path(file_name or "").suffix.lower()
    if suffix and suffix not in {".png", ".svg"}:
        raise HTTPException(status_code=400, detail="invalid watermark asset file extension; use .png or .svg")

    if declared and declared != detected:
        raise HTTPException(
            status_code=400,
            detail=f"content_type mismatch; declared '{declared}' but payload is '{detected}'",
        )

    return detected


def _storage_dir() -> Path:
    out_dir = Path(__file__).resolve().parents[1] / "static" / "uploads" / "watermarks"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def upload_tenant_watermark_asset(
    *,
    tenant_id: str,
    file_name: str,
    content: bytes,
    content_type: str | None = None,
) -> dict[str, Any]:
    tenant = _validate_tenant_id(tenant_id)
    detected_type = _validate_asset_payload(file_name=file_name, content=content, content_type=content_type)

    safe_file = (file_name or "watermark").replace("/", "_")
    asset_id = str(uuid4())
    timestamp = now_ts()
    out_name = f"{tenant}_{asset_id}_{safe_file}"

    out_path = _storage_dir() / out_name
    out_path.write_bytes(content)

    url = f"{S.public_base_url}/static/uploads/watermarks/{out_name}"
    record = WatermarkAssetRecord(
        asset_id=asset_id,
        tenant_id=tenant,
        file_name=safe_file,
        content_type=detected_type,
        size_bytes=len(content),
        storage_url=url,
        created_at=timestamp,
        assigned_profile_ids=set(),
    )
    _ASSETS_BY_TENANT.setdefault(tenant, {})[asset_id] = record
    return _serialize_asset(record)


def assign_tenant_watermark_asset(*, tenant_id: str, profile_id: str, asset_id: str) -> dict[str, Any]:
    tenant = _validate_tenant_id(tenant_id)
    profile = _validate_profile_id(profile_id)
    record = _ASSETS_BY_TENANT.get(tenant, {}).get(asset_id)
    if not record:
        raise HTTPException(status_code=404, detail="watermark asset not found")
    record.assigned_profile_ids.add(profile)
    return _serialize_asset(record)


def set_tenant_default_watermark_profile(*, tenant_id: str, profile_id: str) -> dict[str, str]:
    tenant = _validate_tenant_id(tenant_id)
    profile = _validate_profile_id(profile_id)
    _DEFAULT_PROFILE_BY_TENANT[tenant] = profile
    return {"tenant_id": tenant, "default_profile_id": profile}


def list_tenant_watermark_assets(*, tenant_id: str) -> dict[str, Any]:
    tenant = _validate_tenant_id(tenant_id)
    assets = [_serialize_asset(record) for record in _ASSETS_BY_TENANT.get(tenant, {}).values()]
    assets.sort(key=lambda row: row["created_at"], reverse=True)
    return {
        "tenant_id": tenant,
        "default_profile_id": _DEFAULT_PROFILE_BY_TENANT.get(tenant),
        "assets": assets,
    }


def _serialize_asset(record: WatermarkAssetRecord) -> dict[str, Any]:
    return {
        "asset_id": record.asset_id,
        "tenant_id": record.tenant_id,
        "file_name": record.file_name,
        "content_type": record.content_type,
        "size_bytes": record.size_bytes,
        "storage_url": record.storage_url,
        "created_at": record.created_at,
        "assigned_profile_ids": sorted(record.assigned_profile_ids),
    }
