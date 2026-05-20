from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.aws import ddb
from app.core.settings import S
from app.services.filemanager import norm_path

_ALLOWED_CONFLICT_POLICIES = {"fail", "rename", "last_write_wins"}

_ALLOWED_STATUSES = {
    "pending",
    "active",
    "degraded",
    "unavailable",
    "reauth_required",
    "revoking",
    "revoked",
    "revocation_failed",
}

_ALLOWED_STATUS_TRANSITIONS = {
    "pending": {"pending", "active", "revoked", "revocation_failed"},
    "active": {"active", "degraded", "unavailable", "reauth_required", "revoking", "revoked"},
    "degraded": {"degraded", "active", "unavailable", "reauth_required", "revoking", "revoked"},
    "unavailable": {"unavailable", "degraded", "active", "reauth_required", "revoking", "revoked"},
    "reauth_required": {"reauth_required", "active", "degraded", "unavailable", "revoking", "revoked"},
    "revoking": {"revoking", "revoked", "revocation_failed"},
    "revoked": {"revoked", "pending", "active", "revoking"},
    "revocation_failed": {"revocation_failed", "revoking", "revoked", "pending", "active"},
}



def _health_fail_degraded_threshold() -> int:
    return max(1, int(getattr(S, "filemgr_mount_degraded_fail_threshold", 3)))


def _health_fail_reauth_threshold() -> int:
    return max(1, int(getattr(S, "filemgr_mount_reauth_fail_threshold", 2)))


def _health_fail_unavailable_threshold() -> int:
    return max(_health_fail_degraded_threshold() + 1, int(getattr(S, "filemgr_mount_unavailable_fail_threshold", 6)))


def _health_success_recovery_threshold() -> int:
    return max(1, int(getattr(S, "filemgr_mount_recovery_success_threshold", 2)))
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _table():
    if not S.filemgr_mounts_table_name:
        raise HTTPException(status_code=500, detail="file manager mounts table not configured")
    return ddb.Table(S.filemgr_mounts_table_name)


def _mount_pk(mount_id: str) -> str:
    return f"MOUNT#{mount_id}"


def _owner_pk(owner_user_sub: str) -> str:
    return f"OWNER#{owner_user_sub}"


def _path_sk(mount_path: str) -> str:
    return f"PATH#{mount_path}"


def _validate_provider(provider: str) -> str:
    out = str(provider or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{2,32}", out):
        raise HTTPException(status_code=400, detail="invalid provider")
    return out


def _validate_status(status: str) -> str:
    out = str(status or "").strip().lower()
    if out not in _ALLOWED_STATUSES:
        raise HTTPException(status_code=400, detail="invalid mount status")
    return out


def _validate_conflict_policy(conflict_policy: str) -> str:
    out = str(conflict_policy or "").strip().lower() or "fail"
    if out not in _ALLOWED_CONFLICT_POLICIES:
        raise HTTPException(status_code=400, detail="invalid conflict policy")
    return out


def _assert_status_transition_allowed(*, current_status: str, next_status: str, manual_override: Optional[bool]) -> None:
    cur = _validate_status(current_status)
    nxt = _validate_status(next_status)
    # Operators can force transitions when an explicit manual override update is requested.
    if manual_override is True:
        return
    allowed = _ALLOWED_STATUS_TRANSITIONS.get(cur, {cur})
    if nxt not in allowed:
        raise HTTPException(status_code=409, detail=f"invalid mount status transition: {cur} -> {nxt}")


def _normalize_mount_path(mount_path: str) -> str:
    p = norm_path(mount_path, is_folder=True)
    if p == "/":
        raise HTTPException(status_code=400, detail="root mount path is not allowed")
    return p


def _mount_paths_overlap(path_a: str, path_b: str) -> bool:
    a = _normalize_mount_path(path_a)
    b = _normalize_mount_path(path_b)
    return a.startswith(b) or b.startswith(a)


def _ensure_mount_path_not_overlapping(*, owner_user_sub: str, mount_path: str, exclude_mount_id: Optional[str] = None) -> None:
    for existing in list_mounts(owner_user_sub=owner_user_sub):
        existing_id = str(existing.get("mount_id") or "")
        if exclude_mount_id and existing_id == str(exclude_mount_id):
            continue
        existing_path = str(existing.get("mount_path") or "")
        if existing_path and _mount_paths_overlap(existing_path, mount_path):
            raise HTTPException(status_code=409, detail="mount path overlaps existing mount for user")


def _mount_item_to_out(it: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "mount_id": str(it.get("mount_id") or ""),
        "owner_user_sub": str(it.get("owner_user_sub") or ""),
        "provider": str(it.get("provider") or ""),
        "mount_path": str(it.get("mount_path") or ""),
        "status": str(it.get("status") or ""),
        "secret_ref": it.get("secret_ref"),
        "conflict_policy": str(it.get("conflict_policy") or "fail"),
        "created_at": it.get("created_at"),
        "updated_at": it.get("updated_at"),
        "health_failures": int(it.get("health_failures") or 0),
        "health_successes": int(it.get("health_successes") or 0),
        "health_last_failure_at": it.get("health_last_failure_at"),
        "health_last_success_at": it.get("health_last_success_at"),
        "manual_override": bool(it.get("manual_override") or False),
        "status_updated_at": it.get("status_updated_at"),
        "status_update_sla_seconds": int(getattr(S, "filemgr_mount_status_update_sla_seconds", 30)),
    }


def _marshal_s(item: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare an item for ``transact_write_items`` via the DynamoDB
    *resource* client (``table.meta.client``).

    The resource client auto-serializes native Python types so we must
    NOT wrap values in ``{"S": ...}`` ourselves — doing so causes
    "Invalid attribute value type" errors from DynamoDB Local.
    We just strip ``None`` values (DynamoDB rejects NULL key attrs).
    """
    return {k: v for k, v in item.items() if v is not None}


def create_mount(
    *,
    owner_user_sub: str,
    provider: str,
    mount_path: str,
    status: str = "pending",
    secret_ref: Optional[str] = None,
    mount_id: Optional[str] = None,
    conflict_policy: str = "fail",
) -> Dict[str, Any]:
    owner = str(owner_user_sub or "").strip()
    if not owner:
        raise HTTPException(status_code=400, detail="owner_user_sub is required")
    provider_norm = _validate_provider(provider)
    status_norm = _validate_status(status)
    conflict_policy_norm = _validate_conflict_policy(conflict_policy)
    path_norm = _normalize_mount_path(mount_path)
    _ensure_mount_path_not_overlapping(owner_user_sub=owner, mount_path=path_norm)
    mount_id = str(mount_id or uuid.uuid4())
    now = _now_iso()

    tbl = _table()
    mount_item = {
        "pk": _mount_pk(mount_id),
        "sk": "META",
        "entity_type": "mount",
        "mount_id": mount_id,
        "owner_user_sub": owner,
        "provider": provider_norm,
        "mount_path": path_norm,
        "status": status_norm,
        "secret_ref": secret_ref,
        "conflict_policy": conflict_policy_norm,
        "created_at": now,
        "updated_at": now,
        "status_updated_at": now,
        "health_failures": 0,
        "health_successes": 0,
        "health_last_failure_at": None,
        "health_last_success_at": None,
        "manual_override": False,
        "gsi_owner_pk": _owner_pk(owner),
        "gsi_owner_sk": _path_sk(path_norm),
    }
    unique_item = {
        "pk": _owner_pk(owner),
        "sk": _path_sk(path_norm),
        "entity_type": "mount_path",
        "mount_id": mount_id,
        "provider": provider_norm,
        "created_at": now,
        "updated_at": now,
    }
    try:
        tbl.meta.client.transact_write_items(
            TransactItems=[
                {
                    "Put": {
                        "TableName": tbl.name,
                        "Item": _marshal_s(mount_item),
                        "ConditionExpression": "attribute_not_exists(pk) AND attribute_not_exists(sk)",
                    }
                },
                {
                    "Put": {
                        "TableName": tbl.name,
                        "Item": _marshal_s(unique_item),
                        "ConditionExpression": "attribute_not_exists(pk) AND attribute_not_exists(sk)",
                    }
                },
            ]
        )
    except Exception as exc:
        raise HTTPException(status_code=409, detail="mount path already exists for user") from exc
    return _mount_item_to_out(mount_item)


def get_mount(*, owner_user_sub: str, mount_id: str) -> Dict[str, Any]:
    resp = _table().get_item(Key={"pk": _mount_pk(mount_id), "sk": "META"}, ConsistentRead=True)
    it = resp.get("Item")
    if not it or str(it.get("owner_user_sub") or "") != str(owner_user_sub):
        raise HTTPException(status_code=404, detail="mount not found")
    return _mount_item_to_out(it)


def list_mounts(*, owner_user_sub: str) -> List[Dict[str, Any]]:
    owner = str(owner_user_sub or "").strip()
    if not owner:
        raise HTTPException(status_code=400, detail="owner_user_sub is required")
    owner_pk = _owner_pk(owner)
    out: List[Dict[str, Any]] = []
    last_evaluated_key: Optional[Dict[str, Any]] = None
    while True:
        query_kwargs: Dict[str, Any] = {
            "IndexName": "GSI1",
            "KeyConditionExpression": Key("gsi_owner_pk").eq(owner_pk),
        }
        if last_evaluated_key:
            query_kwargs["ExclusiveStartKey"] = last_evaluated_key
        resp = _table().query(**query_kwargs)
        out.extend(
            _mount_item_to_out(it)
            for it in resp.get("Items", [])
            if str(it.get("entity_type") or "") == "mount"
        )
        last_evaluated_key = resp.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break
    out.sort(key=lambda x: str(x.get("mount_path") or ""))
    return out


def resolve_mount_for_path(*, owner_user_sub: str, path: str) -> Optional[Dict[str, Any]]:
    """Resolve the most specific mounted prefix for a path.

    Returns `None` when no mount applies.
    """
    p = norm_path(path, is_folder=None)
    mounts = [m for m in list_mounts(owner_user_sub=owner_user_sub) if m.get("status") in {"active", "degraded", "unavailable", "reauth_required"}]
    if not mounts:
        return None

    best: Optional[Dict[str, Any]] = None
    best_len = -1
    for mount in mounts:
        mount_path = str(mount.get("mount_path") or "")
        if not mount_path:
            continue
        mount_root = mount_path[:-1] if mount_path.endswith("/") else mount_path
        if p == mount_root or p.startswith(mount_path):
            if len(mount_path) > best_len:
                best = mount
                best_len = len(mount_path)
    return best


def update_mount(
    *,
    owner_user_sub: str,
    mount_id: str,
    status: Optional[str] = None,
    secret_ref: Optional[str] = None,
    manual_override: Optional[bool] = None,
) -> Dict[str, Any]:
    cur = get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)
    new_status = _validate_status(status) if status is not None else cur["status"]
    _assert_status_transition_allowed(
        current_status=str(cur.get("status") or "pending"),
        next_status=new_status,
        manual_override=manual_override,
    )
    now = _now_iso()

    expr = "SET #updated_at=:updated_at, #status=:status"
    names = {"#updated_at": "updated_at", "#status": "status"}
    values: Dict[str, Any] = {":updated_at": now, ":status": new_status, ":owner": str(owner_user_sub)}

    if secret_ref is not None:
        expr += ", #secret_ref=:secret_ref"
        names["#secret_ref"] = "secret_ref"
        values[":secret_ref"] = secret_ref

    if manual_override is not None:
        expr += ", #manual_override=:manual_override"
        names["#manual_override"] = "manual_override"
        values[":manual_override"] = bool(manual_override)

    if status is not None:
        expr += ", #status_updated_at=:status_updated_at"
        names["#status_updated_at"] = "status_updated_at"
        values[":status_updated_at"] = now

    _table().update_item(
        Key={"pk": _mount_pk(mount_id), "sk": "META"},
        UpdateExpression=expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ConditionExpression="owner_user_sub = :owner",
    )
    return get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)


def update_mount_secret_ref_atomic(
    *,
    owner_user_sub: str,
    mount_id: str,
    expected_secret_ref: Optional[str],
    new_secret_ref: str,
) -> Dict[str, Any]:
    cur = get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)
    current_ref = str(cur.get("secret_ref") or "")
    expected_ref = str(expected_secret_ref or "")
    if current_ref != expected_ref:
        raise HTTPException(status_code=409, detail="mount secret changed concurrently")

    now = _now_iso()
    _table().update_item(
        Key={"pk": _mount_pk(mount_id), "sk": "META"},
        UpdateExpression="SET #updated_at=:updated_at, #secret_ref=:new_ref",
        ExpressionAttributeNames={"#updated_at": "updated_at", "#secret_ref": "secret_ref"},
        ExpressionAttributeValues={
            ":updated_at": now,
            ":new_ref": str(new_secret_ref or ""),
            ":owner": str(owner_user_sub),
            ":expected_ref": expected_ref,
        },
        ConditionExpression="owner_user_sub = :owner AND secret_ref = :expected_ref",
    )
    return get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)




def set_mount_status_override(*, owner_user_sub: str, mount_id: str, status: str) -> Dict[str, Any]:
    return update_mount(owner_user_sub=owner_user_sub, mount_id=mount_id, status=status, manual_override=True)


def clear_mount_status_override(*, owner_user_sub: str, mount_id: str, target_status: str = "active") -> Dict[str, Any]:
    return update_mount(owner_user_sub=owner_user_sub, mount_id=mount_id, status=target_status, manual_override=False)


def apply_mount_health_signal(
    *,
    owner_user_sub: str,
    mount_id: str,
    outcome: str,
    error_class: str = "none",
) -> Dict[str, Any]:
    current = get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)
    now = _now_iso()

    failures = int(current.get("health_failures") or 0)
    successes = int(current.get("health_successes") or 0)
    status = str(current.get("status") or "active")
    manual_override = bool(current.get("manual_override") or False)

    is_success = str(outcome or "").lower() == "success" and str(error_class or "none").lower() == "none"
    if is_success:
        failures = 0
        successes += 1
        status_next = status
        if not manual_override and status in {"degraded", "unavailable", "reauth_required"} and successes >= _health_success_recovery_threshold():
            status_next = "active"
        _table().update_item(
            Key={"pk": _mount_pk(mount_id), "sk": "META"},
            UpdateExpression=(
                "SET #updated_at=:updated_at, #health_failures=:health_failures, #health_successes=:health_successes, "
                "#health_last_success_at=:health_last_success_at, #status=:status, #status_updated_at=:status_updated_at"
            ),
            ExpressionAttributeNames={
                "#updated_at": "updated_at",
                "#health_failures": "health_failures",
                "#health_successes": "health_successes",
                "#health_last_success_at": "health_last_success_at",
                "#status": "status",
                "#status_updated_at": "status_updated_at",
            },
            ExpressionAttributeValues={
                ":updated_at": now,
                ":health_failures": failures,
                ":health_successes": successes,
                ":health_last_success_at": now,
                ":status": status_next,
                ":status_updated_at": now,
                ":owner": str(owner_user_sub),
            },
            ConditionExpression="owner_user_sub = :owner",
        )
        return get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)

    failures += 1
    successes = 0
    err = str(error_class or "none").lower()
    status_next = status
    if not manual_override:
        if err == "auth_failed" and failures >= _health_fail_reauth_threshold():
            status_next = "reauth_required"
        elif err in {"server_error", "throttled"}:
            if failures >= _health_fail_unavailable_threshold():
                status_next = "unavailable"
            elif failures >= _health_fail_degraded_threshold():
                status_next = "degraded"

    _table().update_item(
        Key={"pk": _mount_pk(mount_id), "sk": "META"},
        UpdateExpression=(
            "SET #updated_at=:updated_at, #health_failures=:health_failures, #health_successes=:health_successes, "
            "#health_last_failure_at=:health_last_failure_at, #status=:status, #status_updated_at=:status_updated_at"
        ),
        ExpressionAttributeNames={
            "#updated_at": "updated_at",
            "#health_failures": "health_failures",
            "#health_successes": "health_successes",
            "#health_last_failure_at": "health_last_failure_at",
            "#status": "status",
            "#status_updated_at": "status_updated_at",
        },
        ExpressionAttributeValues={
            ":updated_at": now,
            ":health_failures": failures,
            ":health_successes": successes,
            ":health_last_failure_at": now,
            ":status": status_next,
            ":status_updated_at": now,
            ":owner": str(owner_user_sub),
        },
        ConditionExpression="owner_user_sub = :owner",
    )
    return get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)



def scan_mounts_page_for_reconcile(*, limit: int = 100, cursor: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "Limit": max(1, int(limit)),
        "FilterExpression": Attr("entity_type").eq("mount") & Attr("provider").eq("icloud") & Attr("status").is_in(["active", "degraded", "unavailable", "reauth_required"]),
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = cursor
    resp = _table().scan(**kwargs)
    mounts = [_mount_item_to_out(it) | {"reconcile_cursor": it.get("reconcile_cursor")} for it in resp.get("Items", [])]
    return {"items": mounts, "cursor": resp.get("LastEvaluatedKey")}


def update_mount_reconcile_state(
    *,
    owner_user_sub: str,
    mount_id: str,
    cursor: Optional[Dict[str, Any]],
    dry_run: bool,
    completed: bool,
    last_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    now = _now_iso()
    cursor_raw = cursor or None
    _table().update_item(
        Key={"pk": _mount_pk(mount_id), "sk": "META"},
        UpdateExpression=(
            "SET #updated_at=:updated_at, #reconcile_cursor=:reconcile_cursor, #reconcile_last_run_at=:reconcile_last_run_at, "
            "#reconcile_last_dry_run=:reconcile_last_dry_run, #reconcile_last_completed=:reconcile_last_completed, #reconcile_last_report=:reconcile_last_report"
        ),
        ExpressionAttributeNames={
            "#updated_at": "updated_at",
            "#reconcile_cursor": "reconcile_cursor",
            "#reconcile_last_run_at": "reconcile_last_run_at",
            "#reconcile_last_dry_run": "reconcile_last_dry_run",
            "#reconcile_last_completed": "reconcile_last_completed",
            "#reconcile_last_report": "reconcile_last_report",
        },
        ExpressionAttributeValues={
            ":updated_at": now,
            ":reconcile_cursor": cursor_raw,
            ":reconcile_last_run_at": now,
            ":reconcile_last_dry_run": bool(dry_run),
            ":reconcile_last_completed": bool(completed),
            ":reconcile_last_report": last_report or {},
            ":owner": str(owner_user_sub),
        },
        ConditionExpression="owner_user_sub = :owner",
    )
    return get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)

def delete_mount(*, owner_user_sub: str, mount_id: str) -> None:
    cur = get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)
    owner_pk = _owner_pk(owner_user_sub)
    path_sk = _path_sk(cur["mount_path"])
    tbl = _table()
    tbl.meta.client.transact_write_items(
        TransactItems=[
            {
                "Delete": {
                    "TableName": tbl.name,
                    "Key": {"pk": {"S": _mount_pk(mount_id)}, "sk": {"S": "META"}},
                    "ConditionExpression": "owner_user_sub = :owner",
                    "ExpressionAttributeValues": {":owner": {"S": str(owner_user_sub)}},
                }
            },
            {
                "Delete": {
                    "TableName": tbl.name,
                    "Key": {"pk": {"S": owner_pk}, "sk": {"S": path_sk}},
                }
            },
        ]
    )
