from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.models import MountModel
from app.services.filemanager import norm_path


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _owner_pk(owner: str) -> str:
    return f"OWNER#{owner}"


def _mount_sk(mount_id: str) -> str:
    return f"MOUNT#{mount_id}"


def _normalize_mount_path(path: str) -> str:
    return norm_path(path, is_folder=True)


def _paths_overlap(a: str, b: str) -> bool:
    a_norm = _normalize_mount_path(a)
    b_norm = _normalize_mount_path(b)
    if a_norm == b_norm:
        return True
    if a_norm == "/":
        return True
    if b_norm == "/":
        return True
    return a_norm.startswith(b_norm.rstrip("/") + "/") or b_norm.startswith(a_norm.rstrip("/") + "/")


def mount_to_item(model: MountModel) -> Dict[str, Any]:
    return {
        "PK": _owner_pk(model.owner),
        "SK": _mount_sk(model.mount_id),
        "entity_type": "fs_mount",
        "mount_id": model.mount_id,
        "owner": model.owner,
        "provider": model.provider,
        "mount_path": model.mount_path,
        "provider_root_ref": model.provider_root_ref,
        "mode": model.mode,
        "status": model.status,
        "status_reason": model.status_reason,
        "reconnect_required": bool(model.reconnect_required),
        "last_checked_at": model.last_checked_at,
        "created_at": model.created_at,
        "updated_at": model.updated_at,
    }


def mount_from_item(item: Dict[str, Any]) -> MountModel:
    return MountModel(
        mount_id=item["mount_id"],
        owner=item["owner"],
        provider=item["provider"],
        mount_path=item["mount_path"],
        provider_root_ref=item["provider_root_ref"],
        mode=item.get("mode", "read_only"),
        status=item.get("status", "active"),
        status_reason=item.get("status_reason"),
        reconnect_required=bool(item.get("reconnect_required", False)),
        last_checked_at=item.get("last_checked_at"),
        created_at=item["created_at"],
        updated_at=item["updated_at"],
    )


def _list_mounts(owner: str) -> List[MountModel]:
    resp = T.projects.query(
        KeyConditionExpression=Key("PK").eq(_owner_pk(owner)) & Key("SK").begins_with("MOUNT#"),
        ScanIndexForward=False,
    )
    out: List[MountModel] = []
    for raw in resp.get("Items", []):
        if raw.get("entity_type") != "fs_mount":
            continue
        out.append(mount_from_item(raw))
    return out


def _assert_mount_path_constraints(owner: str, mount_path: str, *, ignore_mount_id: Optional[str] = None) -> None:
    normalized = _normalize_mount_path(mount_path)
    for existing in _list_mounts(owner):
        if ignore_mount_id and existing.mount_id == ignore_mount_id:
            continue
        if _normalize_mount_path(existing.mount_path) == normalized:
            raise HTTPException(status_code=409, detail="mount path already exists")
        if _paths_overlap(existing.mount_path, normalized):
            raise HTTPException(status_code=409, detail="mount path overlaps existing mount")


def create_mount(
    owner: str,
    *,
    provider: str,
    mount_path: str,
    provider_root_ref: str,
    mode: str = "read_only",
) -> MountModel:
    owner_norm = (owner or "").strip()
    if not owner_norm:
        raise HTTPException(status_code=400, detail="owner is required")

    mount_path_norm = _normalize_mount_path(mount_path)
    _assert_mount_path_constraints(owner_norm, mount_path_norm)

    ts = now_iso()
    model = MountModel(
        mount_id=str(uuid4()),
        owner=owner_norm,
        provider=(provider or "").strip().lower(),
        mount_path=mount_path_norm,
        provider_root_ref=(provider_root_ref or "").strip(),
        mode=(mode or "read_only").strip().lower(),
        status="active",
        status_reason=None,
        reconnect_required=False,
        last_checked_at=None,
        created_at=ts,
        updated_at=ts,
    )
    T.projects.put_item(
        Item=mount_to_item(model),
        ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
    )
    return model


def get_mount(owner: str, mount_id: str) -> MountModel:
    resp = T.projects.get_item(
        Key={"PK": _owner_pk(owner), "SK": _mount_sk(mount_id)},
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item or item.get("entity_type") != "fs_mount":
        raise HTTPException(status_code=404, detail="mount not found")
    return mount_from_item(item)


def list_mounts(owner: str) -> List[MountModel]:
    return _list_mounts(owner)


def update_mount(
    owner: str,
    mount_id: str,
    *,
    mount_path: Optional[str] = None,
    provider_root_ref: Optional[str] = None,
    mode: Optional[str] = None,
) -> MountModel:
    existing = get_mount(owner, mount_id)

    next_mount_path = existing.mount_path if mount_path is None else _normalize_mount_path(mount_path)
    if next_mount_path != existing.mount_path:
        _assert_mount_path_constraints(owner, next_mount_path, ignore_mount_id=mount_id)

    updated = existing.model_copy(
        update={
            "mount_path": next_mount_path,
            "provider_root_ref": existing.provider_root_ref if provider_root_ref is None else provider_root_ref.strip(),
            "mode": existing.mode if mode is None else mode.strip().lower(),
            "updated_at": now_iso(),
        }
    )
    T.projects.put_item(Item=mount_to_item(updated))
    return updated


def delete_mount(owner: str, mount_id: str) -> Dict[str, bool]:
    key = {"PK": _owner_pk(owner), "SK": _mount_sk(mount_id)}
    resp = T.projects.get_item(Key=key, ConsistentRead=True)
    item = resp.get("Item")
    if not item:
        return {"ok": True, "deleted": False}
    if item.get("entity_type") != "fs_mount":
        raise HTTPException(status_code=404, detail="mount not found")
    T.projects.delete_item(Key=key)
    return {"ok": True, "deleted": True}


def set_mount_status(
    owner: str,
    mount_id: str,
    *,
    status: str,
    status_reason: Optional[str] = None,
    reconnect_required: Optional[bool] = None,
) -> MountModel:
    existing = get_mount(owner, mount_id)
    updated = existing.model_copy(
        update={
            "status": (status or existing.status).strip().lower(),
            "status_reason": status_reason if status_reason is not None else existing.status_reason,
            "reconnect_required": bool(existing.reconnect_required if reconnect_required is None else reconnect_required),
            "last_checked_at": now_iso(),
            "updated_at": now_iso(),
        }
    )
    T.projects.put_item(Item=mount_to_item(updated))
    return updated


def reconcile_mount_health(owner: str, mount_id: str) -> Dict[str, Any]:
    from app.services.file_providers import default_provider_registry
    from app.services.provider_credentials import get_provider_credential

    mount = get_mount(owner, mount_id)
    issues: List[str] = []
    actions: List[str] = []
    reconnect_required = False

    try:
        cred = get_provider_credential(owner, mount.provider)
    except HTTPException as exc:
        if exc.status_code == 404:
            issues.append("revoked_credential")
            reconnect_required = True
            actions.extend(["prompt_reconnect", "disable_mount"])
            return {
                "owner": owner,
                "mount_id": mount.mount_id,
                "provider": mount.provider,
                "mount_path": mount.mount_path,
                "provider_root_ref": mount.provider_root_ref,
                "stale": True,
                "issues": issues,
                "recommended_actions": actions,
                "status": mount.status,
                "reconnect_required": reconnect_required,
            }
        raise

    cred_meta = dict(cred.metadata or {})
    if bool(cred_meta.get("reconnect_required")):
        issues.append("revoked_credential")
        reconnect_required = True
        actions.append("prompt_reconnect")

    registry = default_provider_registry()
    provider = registry.get(owner, mount.provider)
    try:
        root_exists = provider.exists(mount.provider_root_ref)
    except HTTPException as exc:
        if exc.status_code in (401, 403):
            issue = "inaccessible_shared_drive" if mount.provider_root_ref.startswith("gdrive://drive/") else "revoked_credential"
            issues.append(issue)
            reconnect_required = True
            actions.extend(["prompt_reconnect", "disable_mount"])
            root_exists = False
        elif exc.status_code == 404:
            issues.append("orphaned_mount_root")
            actions.append("disable_mount")
            root_exists = False
        else:
            raise

    if not root_exists:
        if mount.provider_root_ref.startswith("gdrive://drive/") and "inaccessible_shared_drive" not in issues:
            issues.append("inaccessible_shared_drive")
            actions.append("disable_mount")
        elif "orphaned_mount_root" not in issues:
            issues.append("orphaned_mount_root")
            actions.append("disable_mount")

    stale = bool(issues)
    if stale and "disable_mount" not in actions:
        actions.append("disable_mount")
    return {
        "owner": owner,
        "mount_id": mount.mount_id,
        "provider": mount.provider,
        "mount_path": mount.mount_path,
        "provider_root_ref": mount.provider_root_ref,
        "stale": stale,
        "issues": sorted(set(issues)),
        "recommended_actions": sorted(set(actions)),
        "status": mount.status,
        "reconnect_required": reconnect_required,
    }


def reconcile_mounts(owner: str) -> List[Dict[str, Any]]:
    return [reconcile_mount_health(owner, m.mount_id) for m in list_mounts(owner)]
