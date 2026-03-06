from __future__ import annotations

from datetime import datetime, timezone
import fnmatch
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.models import FileMountModel
from app.services.alerts import audit_event
from app.services.file_mounts_store import file_mount_from_item, file_mount_to_item
from app.services.file_mounts_adapter import check_mount_health
from app.services import filemanager


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mount_pk(owner: str) -> str:
    return f"OWNER#{owner}"


def _mount_sk(mount_id: str) -> str:
    return f"FILE_MOUNT#{mount_id}"


def _normalize_mount_path(value: str) -> str:
    return filemanager.norm_path(value, is_folder=True)


def _paths_overlap(a: str, b: str) -> bool:
    return a.startswith(b) or b.startswith(a)


def _load_mount(owner: str, mount_id: str) -> FileMountModel:
    resp = T.projects.get_item(Key={"PK": _mount_pk(owner), "SK": _mount_sk(mount_id)}, ConsistentRead=True)
    item = resp.get("Item")
    if not item or item.get("entity_type") != "file_mount" or item.get("owner") != owner:
        raise HTTPException(status_code=404, detail="file mount not found")
    return file_mount_from_item(item)


def list_file_mounts(owner: str) -> List[FileMountModel]:
    resp = T.projects.query(
        KeyConditionExpression=Key("PK").eq(_mount_pk(owner)) & Key("SK").begins_with("FILE_MOUNT#"),
        ScanIndexForward=False,
    )
    out: List[FileMountModel] = []
    for item in resp.get("Items", []):
        if item.get("entity_type") != "file_mount" or item.get("owner") != owner:
            continue
        out.append(file_mount_from_item(item))
    return out


def get_file_mount(owner: str, mount_id: str) -> FileMountModel:
    return _load_mount(owner, mount_id)


def _save_mount(model: FileMountModel) -> None:
    T.projects.put_item(
        Item=file_mount_to_item(model),
        ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
    )


def _list_all_mounts() -> List[FileMountModel]:
    out: List[FileMountModel] = []
    eks: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {}
        if eks:
            kwargs["ExclusiveStartKey"] = eks
        resp = T.projects.scan(**kwargs)
        for item in resp.get("Items", []):
            if item.get("entity_type") != "file_mount":
                continue
            try:
                out.append(file_mount_from_item(item))
            except Exception:
                continue
        eks = resp.get("LastEvaluatedKey")
        if not eks:
            break
    return out




def _allowed_bucket_patterns() -> List[str]:
    raw = str(getattr(S, "filemgr_s3_mounts_allowed_bucket_patterns", "") or "")
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def _enforce_bucket_allowlist(bucket: str) -> None:
    patterns = _allowed_bucket_patterns()
    if not patterns:
        return
    candidate = str(bucket or "").strip().lower()
    if any(fnmatch.fnmatch(candidate, pat) for pat in patterns):
        return
    raise HTTPException(status_code=403, detail={"code": "mount_bucket_not_allowed", "message": "bucket is not allowlisted"})

def _assert_no_local_node_conflict(owner: str, mount_path: str) -> None:
    try:
        filemanager.get_node(owner, mount_path)
    except HTTPException as exc:
        if exc.status_code == 404:
            return
        raise
    raise HTTPException(status_code=409, detail="mount path conflicts with existing local node")


def _assert_no_mount_overlap(owner: str, mount_path: str, *, exclude_mount_id: Optional[str] = None) -> None:
    for m in list_file_mounts(owner):
        if exclude_mount_id and m.id == exclude_mount_id:
            continue
        if _paths_overlap(m.mount_path, mount_path):
            raise HTTPException(status_code=409, detail="mount path overlaps existing mount")


def create_file_mount(
    owner: str,
    *,
    mount_path: str,
    bucket: str,
    prefix: Optional[str],
    mode: str,
    auth_ref: str,
    status: str = "active",
) -> FileMountModel:
    normalized_mount_path = _normalize_mount_path(mount_path)
    _enforce_bucket_allowlist(bucket)
    _assert_no_local_node_conflict(owner, normalized_mount_path)
    _assert_no_mount_overlap(owner, normalized_mount_path)

    ts = now_iso()
    model = FileMountModel(
        id=str(uuid4()),
        owner=owner,
        provider="s3",
        mount_path=normalized_mount_path,
        bucket=bucket,
        prefix=prefix,
        mode=mode,
        auth_ref=auth_ref,
        status=status,
        created_at=ts,
        updated_at=ts,
    )
    T.projects.put_item(
        Item=file_mount_to_item(model),
        ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
    )
    audit_event(
        "file_mount_created",
        owner,
        None,
        outcome="success",
        mount_id=model.id,
        provider=model.provider,
        mount_path=model.mount_path,
        bucket=model.bucket,
        mode=model.mode,
        status=model.status,
        created_at=model.created_at,
    )
    return model


def update_file_mount(
    owner: str,
    mount_id: str,
    *,
    mount_path: Optional[str] = None,
    bucket: Optional[str] = None,
    prefix: Optional[str] = None,
    mode: Optional[str] = None,
    auth_ref: Optional[str] = None,
    status: Optional[str] = None,
) -> FileMountModel:
    existing = _load_mount(owner, mount_id)

    candidate_path = existing.mount_path if mount_path is None else _normalize_mount_path(mount_path)
    if candidate_path != existing.mount_path:
        _assert_no_local_node_conflict(owner, candidate_path)
        _assert_no_mount_overlap(owner, candidate_path, exclude_mount_id=mount_id)

    next_bucket = existing.bucket if bucket is None else bucket
    _enforce_bucket_allowlist(next_bucket)

    updated = existing.model_copy(
        update={
            "mount_path": candidate_path,
            "bucket": next_bucket,
            "prefix": existing.prefix if prefix is None else prefix,
            "mode": existing.mode if mode is None else mode,
            "auth_ref": existing.auth_ref if auth_ref is None else auth_ref,
            "status": existing.status if status is None else status,
            "updated_at": now_iso(),
        }
    )

    _save_mount(updated)
    audit_event(
        "file_mount_updated",
        owner,
        None,
        outcome="success",
        mount_id=updated.id,
        provider=updated.provider,
        mount_path=updated.mount_path,
        bucket=updated.bucket,
        mode=updated.mode,
        status=updated.status,
        updated_at=updated.updated_at,
    )
    return updated


def delete_file_mount(owner: str, mount_id: str) -> Dict[str, bool]:
    try:
        mount = _load_mount(owner, mount_id)
    except HTTPException as exc:
        if exc.status_code == 404:
            return {"ok": True, "deleted": False}
        raise

    try:
        T.projects.delete_item(
            Key={"PK": _mount_pk(owner), "SK": _mount_sk(mount_id)},
            ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            return {"ok": True, "deleted": False}
        raise

    audit_event(
        "file_mount_deleted",
        owner,
        None,
        outcome="success",
        mount_id=mount.id,
        provider=mount.provider,
        mount_path=mount.mount_path,
        bucket=mount.bucket,
        mode=mount.mode,
        status=mount.status,
        deleted=True,
    )
    return {"ok": True, "deleted": True}


def run_file_mount_health_check_worker(*, owner: Optional[str] = None, limit: Optional[int] = None) -> Dict[str, Any]:
    mounts = list_file_mounts(owner) if owner else _list_all_mounts()
    if limit is not None:
        mounts = mounts[: max(0, int(limit))]

    checked = 0
    healthy = 0
    degraded = 0
    errors = 0

    for mount in mounts:
        checked += 1
        check_at = now_iso()
        try:
            probe = check_mount_health(mount)
            next_status = str(probe.get("status") or "degraded")
            next_error = probe.get("error")
            updated = mount.model_copy(
                update={
                    "status": next_status,
                    "last_check_at": check_at,
                    "last_error": None if next_status == "active" else (str(next_error) if next_error else "health check failed"),
                    "updated_at": check_at,
                }
            )
            _save_mount(updated)
            if next_status == "active":
                healthy += 1
            else:
                degraded += 1
        except Exception as exc:
            errors += 1
            degraded += 1
            try:
                fallback = mount.model_copy(
                    update={
                        "status": "degraded",
                        "last_check_at": check_at,
                        "last_error": str(exc),
                        "updated_at": check_at,
                    }
                )
                _save_mount(fallback)
            except Exception:
                pass
            continue

    return {
        "checked": checked,
        "healthy": healthy,
        "degraded": degraded,
        "errors": errors,
        "owner": owner,
    }
