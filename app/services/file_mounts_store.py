from __future__ import annotations

from typing import Any, Dict

from app.models import FileMountModel


def _mount_pk(owner: str) -> str:
    return f"OWNER#{owner}"


def _mount_sk(mount_id: str) -> str:
    return f"FILE_MOUNT#{mount_id}"


def file_mount_to_item(mount: FileMountModel) -> Dict[str, Any]:
    return {
        "PK": _mount_pk(mount.owner),
        "SK": _mount_sk(mount.id),
        "entity_type": "file_mount",
        "id": mount.id,
        "owner": mount.owner,
        "provider": mount.provider,
        "mount_path": mount.mount_path,
        "bucket": mount.bucket,
        "prefix": mount.prefix,
        "mode": mount.mode,
        "auth_ref": mount.auth_ref,
        "status": mount.status,
        "created_at": mount.created_at,
        "updated_at": mount.updated_at,
        "last_check_at": mount.last_check_at,
        "last_error": mount.last_error,
    }


def file_mount_from_item(item: Dict[str, Any]) -> FileMountModel:
    return FileMountModel(
        id=item["id"],
        owner=item["owner"],
        provider=item["provider"],
        mount_path=item["mount_path"],
        bucket=item["bucket"],
        prefix=item.get("prefix"),
        mode=item["mode"],
        auth_ref=item["auth_ref"],
        status=item.get("status", "active"),
        created_at=item["created_at"],
        updated_at=item["updated_at"],
        last_check_at=item.get("last_check_at"),
        last_error=item.get("last_error"),
    )
