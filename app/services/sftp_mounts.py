from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import HTTPException
from pydantic import BaseModel, Field, ValidationError

from app.core.aws import ddb
from app.services.sftp_destination_policy import enforce_sftp_destination_policy


_ALLOWED_MOUNT_STATUS = {"healthy", "degraded", "auth_failed", "unreachable", "disabled"}
_ALLOWED_PROTOCOLS = {"sftp", "scp", "ftp"}
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _table_name() -> str:
    from app.core.settings import S

    name = str(getattr(S, "filemgr_sftp_mounts_table_name", "") or "").strip()
    if not name:
        raise HTTPException(status_code=500, detail="sftp mounts table not configured")
    return name


def _table():
    return ddb.Table(_table_name())


def _pk(owner: str) -> str:
    return f"OWNER#{owner}"


def _sk(mount_id: str) -> str:
    return f"SFTP_MOUNT#{mount_id}"


class SftpMountModel(BaseModel):
    id: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    protocol: str = Field(default="sftp")
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    auth_credential_ref: str = Field(min_length=1)
    remote_root: str = Field(min_length=1)
    read_only: bool = False
    status: str = Field(default="healthy")
    created_at: str
    updated_at: str
    last_tested_at: Optional[str] = None
    last_status_change_at: Optional[str] = None
    last_error_code: Optional[str] = None
    last_error_message: Optional[str] = None


def _normalize_protocol(protocol: str) -> str:
    out = (protocol or "sftp").strip().lower()
    if out not in _ALLOWED_PROTOCOLS:
        raise HTTPException(status_code=400, detail="invalid mount protocol")
    return out


def _normalize_host(host: str) -> str:
    out = (host or "").strip().lower()
    if not out:
        raise HTTPException(status_code=400, detail="host is required")
    if "://" in out or "/" in out or "@" in out:
        raise HTTPException(status_code=400, detail="host must be hostname or ip without scheme/path")
    if not _HOST_RE.match(out):
        raise HTTPException(status_code=400, detail="host contains invalid characters")
    return out


def _normalize_remote_root(value: str) -> str:
    root = (value or "").strip()
    if not root:
        raise HTTPException(status_code=400, detail="remote_root is required")
    if not root.startswith("/"):
        raise HTTPException(status_code=400, detail="remote_root must start with '/'")
    parts: List[str] = []
    for part in root.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise HTTPException(status_code=400, detail="remote_root must not contain '..'")
        parts.append(part)
    return "/" + "/".join(parts)


def _validate_status(status: str) -> str:
    out = (status or "").strip().lower()
    if out not in _ALLOWED_MOUNT_STATUS:
        raise HTTPException(status_code=400, detail="invalid mount status")
    return out


def _to_item(m: SftpMountModel) -> Dict[str, Any]:
    return {
        "PK": _pk(m.owner),
        "SK": _sk(m.id),
        "entity_type": "sftp_mount",
        "id": m.id,
        "owner": m.owner,
        "protocol": m.protocol,
        "host": m.host,
        "port": int(m.port),
        "auth_credential_ref": m.auth_credential_ref,
        "remote_root": m.remote_root,
        "read_only": bool(m.read_only),
        "status": m.status,
        "created_at": m.created_at,
        "updated_at": m.updated_at,
        "last_tested_at": m.last_tested_at,
        "last_status_change_at": m.last_status_change_at,
        "last_error_code": m.last_error_code,
        "last_error_message": m.last_error_message,
        # Owner-scoped listing index
        "GSI1PK": f"OWNER#{m.owner}",
        "GSI1SK": f"UPDATED#{m.updated_at}#MOUNT#{m.id}",
        # Mount lookup index
        "GSI2PK": f"MOUNT#{m.id}",
        "GSI2SK": f"OWNER#{m.owner}",
    }


def _from_item(item: Dict[str, Any]) -> SftpMountModel:
    try:
        return SftpMountModel(
            id=str(item.get("id") or ""),
            owner=str(item.get("owner") or ""),
            protocol=str(item.get("protocol") or "sftp"),
            host=str(item.get("host") or ""),
            port=int(item.get("port") or 0),
            auth_credential_ref=str(item.get("auth_credential_ref") or ""),
            remote_root=str(item.get("remote_root") or ""),
            read_only=bool(item.get("read_only", False)),
            status=str(item.get("status") or ""),
            created_at=str(item.get("created_at") or ""),
            updated_at=str(item.get("updated_at") or ""),
            last_tested_at=item.get("last_tested_at"),
            last_status_change_at=item.get("last_status_change_at"),
            last_error_code=item.get("last_error_code"),
            last_error_message=item.get("last_error_message"),
        )
    except (ValidationError, ValueError, TypeError) as exc:
        raise HTTPException(status_code=500, detail="stored sftp mount record is invalid") from exc


def create_sftp_mount(
    *,
    owner: str,
    host: str,
    port: int,
    auth_credential_ref: str,
    remote_root: str,
    read_only: bool = False,
    status: str = "healthy",
    protocol: str = "sftp",
) -> SftpMountModel:
    owner_norm = (owner or "").strip()
    if not owner_norm:
        raise HTTPException(status_code=400, detail="owner is required")
    auth_ref = (auth_credential_ref or "").strip()
    if not auth_ref:
        raise HTTPException(status_code=400, detail="auth_credential_ref is required")

    ts = now_iso()
    try:
        mount = SftpMountModel(
            id=str(uuid4()),
            owner=owner_norm,
            protocol=_normalize_protocol(protocol),
            host=_normalize_host(host),
            port=int(port),
            auth_credential_ref=auth_ref,
            remote_root=_normalize_remote_root(remote_root),
            read_only=bool(read_only),
            status=_validate_status(status),
            created_at=ts,
            updated_at=ts,
            last_status_change_at=ts,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail="invalid sftp mount payload") from exc
    enforce_sftp_destination_policy(host=mount.host, owner=mount.owner, mount_id=mount.id, stage="mount_create")
    _table().put_item(Item=_to_item(mount), ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)")
    return mount


def get_sftp_mount(*, owner: str, mount_id: str) -> SftpMountModel:
    owner_norm = (owner or "").strip()
    mount_norm = (mount_id or "").strip()
    if not owner_norm or not mount_norm:
        raise HTTPException(status_code=400, detail="owner and mount_id are required")
    item = _table().get_item(Key={"PK": _pk(owner_norm), "SK": _sk(mount_norm)}, ConsistentRead=True).get("Item")
    if not item or item.get("entity_type") != "sftp_mount":
        raise HTTPException(status_code=404, detail="sftp mount not found")
    return _from_item(item)


def list_sftp_mounts(*, owner: str, limit: int = 100) -> List[SftpMountModel]:
    owner_norm = (owner or "").strip()
    if not owner_norm:
        raise HTTPException(status_code=400, detail="owner is required")
    if not isinstance(limit, int) or limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="invalid limit")

    resp = _table().scan(Limit=max(limit * 4, 100))
    items = []
    for item in resp.get("Items", []):
        if item.get("entity_type") != "sftp_mount":
            continue
        if item.get("owner") != owner_norm:
            continue
        items.append(_from_item(item))

    items.sort(key=lambda m: m.updated_at, reverse=True)
    return items[:limit]


def find_sftp_mount_by_id(*, mount_id: str) -> Optional[SftpMountModel]:
    mount_norm = (mount_id or "").strip()
    if not mount_norm:
        raise HTTPException(status_code=400, detail="mount_id is required")

    resp = _table().scan(Limit=200)
    for item in resp.get("Items", []):
        if item.get("entity_type") != "sftp_mount":
            continue
        if str(item.get("id") or "") == mount_norm or str(item.get("GSI2PK") or "") == f"MOUNT#{mount_norm}":
            return _from_item(item)
    return None


def update_sftp_mount(
    *,
    owner: str,
    mount_id: str,
    host: Optional[str] = None,
    port: Optional[int] = None,
    auth_credential_ref: Optional[str] = None,
    remote_root: Optional[str] = None,
    read_only: Optional[bool] = None,
    status: Optional[str] = None,
    protocol: Optional[str] = None,
    last_tested_at: Optional[str] = None,
    last_error_code: Optional[str] = None,
    last_error_message: Optional[str] = None,
) -> SftpMountModel:
    existing = get_sftp_mount(owner=owner, mount_id=mount_id)
    next_status = existing.status if status is None else _validate_status(status)

    try:
        updated = SftpMountModel(
            id=existing.id,
            owner=existing.owner,
            protocol=existing.protocol if protocol is None else _normalize_protocol(protocol),
            host=existing.host if host is None else _normalize_host(host),
            port=existing.port if port is None else int(port),
            auth_credential_ref=existing.auth_credential_ref if auth_credential_ref is None else (auth_credential_ref or "").strip(),
            remote_root=existing.remote_root if remote_root is None else _normalize_remote_root(remote_root),
            read_only=existing.read_only if read_only is None else bool(read_only),
            status=next_status,
            created_at=existing.created_at,
            updated_at=now_iso(),
            last_tested_at=existing.last_tested_at if last_tested_at is None else last_tested_at,
            last_status_change_at=(now_iso() if next_status != existing.status else existing.last_status_change_at),
            last_error_code=existing.last_error_code if last_error_code is None else last_error_code,
            last_error_message=existing.last_error_message if last_error_message is None else last_error_message,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail="invalid sftp mount payload") from exc

    if not updated.auth_credential_ref:
        raise HTTPException(status_code=400, detail="auth_credential_ref is required")

    enforce_sftp_destination_policy(host=updated.host, owner=updated.owner, mount_id=updated.id, stage="mount_update")
    _table().put_item(Item=_to_item(updated), ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)")
    return updated


def delete_sftp_mount(*, owner: str, mount_id: str) -> Dict[str, bool]:
    existing = get_sftp_mount(owner=owner, mount_id=mount_id)
    _table().delete_item(Key={"PK": _pk(existing.owner), "SK": _sk(existing.id)})
    return {"ok": True}
