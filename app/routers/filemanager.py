from __future__ import annotations

import base64
import json
import os
import uuid
import time
import threading
from typing import Annotated, Any, Dict, List, Optional, Literal

from fastapi import APIRouter, Depends, File, Query, UploadFile, Body, Request, HTTPException
from pydantic import BaseModel, Field
from fastapi.responses import StreamingResponse

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_scope, require_role_value
from app.auth.roles import AdminScope, Role, admin_profile_has_scope, normalize_role
from app.core.tables import T
from app.core.settings import S
from app.services.filemanager import (
    create_empty_folder,
    download_file,
    download_thumbnail,
    download_zip,
    is_previewable,
    list_children,
    list_children_page,
    list_mounted_directory,
    download_mounted_file,
    resolve_path_mount,
    list_shared_with,
    list_shared_with_me,
    move_node,
    resume_move,
    rollback_move,
    norm_path,
    remove_file,
    delete_mounted_file,
    remove_folder,
    search_prefix,
    share_node,
    unshare_node,
    split_parent_name,
    upload_file,
    upload_mounted_file,
    upload_zip,
    upload_archive,
    get_node,
    search_text,
    presign_upload,
    register_presigned_upload,
    purge_deleted_nodes,
    require_shared_access,
    admin_search_metadata,
    encryption_info_from_node,
    preview_capability_from_node,
    record_download_usage,
    record_upload_usage,
    record_operation_usage,
    assert_upload_allowed,
    get_usage_summary,
    get_usage_daily,
    get_usage_storage,
    assert_download_allowed,
)
from app.services.alerts import audit_event
from app.metrics import (
    record_filemgr_encryption_event,
    record_filemgr_shared_download,
    record_filemgr_preview_attempt,
    record_filemgr_preview_latency,
    record_filemgr_preview_bytes,
    record_filemgr_preview_fallback,
    record_filemgr_preview_hover_play_start,
    record_filemgr_preview_hover_play_failure,
)
from app.services.purchase_history import record_receipt_download
from app.services.file_bundle_entitlements import assert_file_bundle_access
from app.services.internal_api_entitlements import enforce_internal_api_entitlement
from app.services.sessions import require_ui_session
from app.services.file_mounts import (
    create_file_mount as create_file_mount_record,
    delete_file_mount as delete_file_mount_record,
    get_file_mount as get_file_mount_record,
    list_file_mounts as list_file_mounts_records,
    update_file_mount as update_file_mount_record,
)
from app.services.sftp_mounts import (
    create_sftp_mount,
    delete_sftp_mount,
    get_sftp_mount,
    list_sftp_mounts as list_sftp_mount_records,
    update_sftp_mount,
)
from app.services.sftp_credentials import (
    delete_sftp_credential,
    get_sftp_credential,
    upsert_sftp_credential,
)
from app.services.sftp_client import (
    SftpConnectionConfig,
    acquire_sftp_session,
    release_sftp_session,
)
from app.services.filemanager_storage import resolve_storage_provider

router = APIRouter(prefix="/v1/fs", tags=["filemanager"])

_SFTP_HEALTH_REFRESH_LOCK = threading.Lock()
_SFTP_HEALTH_REFRESH_LAST_RUN_TS = 0.0
_SFTP_MOCK_INSPECT_RATE_LOCK = threading.Lock()
_SFTP_MOCK_INSPECT_RATE: Dict[str, List[float]] = {}


def _enforce_filemanager_internal_entitlement(
    *,
    user: str,
    action: str,
    request_id: Optional[str] = None,
) -> None:
    req_id = (request_id or "").strip() or f"filemanager:{action}:{user}:{int(time.time() * 1000)}"
    enforce_internal_api_entitlement(
        user_id=user,
        namespace="filemanager",
        action=action,
        request_id=req_id,
    )


def _require_s3_mounts_enabled() -> None:
    if not bool(getattr(S, "filemgr_s3_mounts_enabled", False)):
        raise HTTPException(status_code=404, detail="not found")


def _require_s3_mounts_write_enabled() -> None:
    if not bool(getattr(S, "filemgr_s3_mounts_write_enabled", False)):
        raise HTTPException(status_code=403, detail={"code": "feature_disabled", "feature": "filemgr_s3_mounts_write"})


def _encode_cursor(cursor: Optional[Dict[str, Any]]) -> Optional[str]:
    if not cursor:
        return None
    payload = json.dumps(cursor).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("utf-8")


def _decode_cursor(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor or not isinstance(cursor, str):
        return None
    try:
        payload = base64.urlsafe_b64decode(cursor.encode("utf-8"))
        return json.loads(payload.decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid cursor") from exc


def _current_user(ctx=Depends(require_ui_session)) -> str:
    return ctx["user_sub"]


require_content_moderation_admin = require_admin_scope("content_moderation")


async def require_content_moderation_operator(user: AuthenticatedUser = Depends(get_authenticated_user), request: Request = None) -> AuthenticatedUser:
    if bool(getattr(S, "admin_scope_enforce_content_moderation", True)):
        return await require_content_moderation_admin(request=request, user=user)
    require_role_value(normalize_role(user.role).value, {Role.ADMIN, Role.ROOT})
    return user


def _resolve_actor_from_context(ctx: Dict[str, Any], actor: AuthenticatedUser | Any) -> AuthenticatedUser:
    if isinstance(actor, AuthenticatedUser):
        return actor
    role = normalize_role((ctx or {}).get("role"))
    return AuthenticatedUser(sub=str((ctx or {}).get("user_sub") or ""), role=role)


def _require_content_moderation_actor(actor: AuthenticatedUser) -> None:
    if not bool(getattr(S, "admin_scope_enforce_content_moderation", True)):
        require_role_value(normalize_role(actor.role).value, {Role.ADMIN, Role.ROOT})
        return
    role = normalize_role(actor.role)
    if role is Role.ROOT:
        return
    if role is Role.ADMIN:
        if admin_profile_has_scope(actor.admin_profile, AdminScope.CONTENT_MODERATION):
            return
        raise HTTPException(
            status_code=403,
            detail={
                "code": "role_required_scope",
                "required_scope": AdminScope.CONTENT_MODERATION.value,
                "actual_role": role.value,
                "actual_admin_profile": actor.admin_profile.to_dict(),
            },
        )
    require_role_value(role.value, {Role.ADMIN, Role.ROOT})


def _admin_or_root_ctx(ctx=Depends(require_ui_session), actor: AuthenticatedUser | Any = Depends(require_content_moderation_operator)) -> Dict[str, Any]:
    resolved_actor = _resolve_actor_from_context(ctx, actor)
    _require_content_moderation_actor(resolved_actor)
    return ctx


def _admin_can_read_content(ctx: Dict[str, Any]) -> bool:
    tier = str(getattr(S, "filemgr_admin_content_access_tier", "none") or "none").lower()
    role = str(ctx.get("role") or "")
    if tier == "admin_root":
        return role in {Role.ADMIN.value, Role.ROOT.value}
    if tier == "root_only":
        return role == Role.ROOT.value
    return False


def _is_admin_or_root_ctx(ctx: Optional[Dict[str, Any]]) -> bool:
    role = normalize_role((ctx or {}).get("role"))
    return role in {Role.ADMIN, Role.ROOT}


def _resolve_mount_owner(*, ctx: Dict[str, Any], owner: Optional[str]) -> str:
    current_user = str((ctx or {}).get("user_sub") or "").strip()
    requested_owner = str(owner).strip() if isinstance(owner, str) else ""
    if not requested_owner or requested_owner == current_user:
        return current_user
    if not _is_admin_or_root_ctx(ctx):
        raise HTTPException(status_code=403, detail={"code": "mount_forbidden_owner", "message": "cannot access mounts for another owner"})
    return requested_owner


def _mount_to_api(mount: Any) -> Dict[str, Any]:
    return {
        "id": str(mount.id),
        "owner": str(mount.owner),
        "protocol": str(getattr(mount, "protocol", "sftp") or "sftp"),
        "host": str(mount.host),
        "port": int(mount.port),
        "auth_credential_ref": str(mount.auth_credential_ref),
        "remote_root": str(mount.remote_root),
        "read_only": bool(mount.read_only),
        "status": str(mount.status),
        "created_at": mount.created_at,
        "updated_at": mount.updated_at,
        "last_tested_at": mount.last_tested_at,
        "last_status_change_at": mount.last_status_change_at,
        "last_error_code": mount.last_error_code,
        "last_error_message": mount.last_error_message,
    }


def _file_audit_fields(
    *,
    ctx: Optional[Dict[str, Any]] = None,
    owner: Optional[str] = None,
    file_path: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if ctx:
        out["actor_sub"] = str(ctx.get("actor_sub") or ctx.get("user_sub") or "")
        out["target_user_sub"] = str(ctx.get("effective_sub") or owner or ctx.get("user_sub") or "")
        if ctx.get("effective_sub"):
            out["impersonation"] = True
            out["effective_sub"] = str(ctx.get("effective_sub"))
            if ctx.get("impersonation_id"):
                out["impersonation_id"] = str(ctx.get("impersonation_id"))
    elif owner:
        out["target_user_sub"] = owner
    if owner:
        out.setdefault("target_user_sub", owner)
    if file_path:
        out["file_path"] = file_path
    if correlation_id:
        out["correlation_id"] = correlation_id
    return out
def _parse_encryption_meta(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        return None
    try:
        obj = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="invalid encryption metadata") from exc
    if not isinstance(obj, dict):
        raise HTTPException(status_code=400, detail="invalid encryption metadata")
    return obj


def _looks_like_sftp_mount_path(path: Optional[str]) -> bool:
    if not isinstance(path, str):
        return False
    p = path.strip()
    if not p:
        return False
    if not p.startswith("/"):
        p = "/" + p
    return p == "/mounts" or p == "/mounts/" or p.startswith("/mounts/")


def _raise_sftp_mount_flag_error(code: str, message: str) -> None:
    raise HTTPException(status_code=403, detail={"code": code, "message": message})


def _enforce_sftp_mount_flags_for_path(path: Optional[str], *, operation: str) -> None:
    if not _looks_like_sftp_mount_path(path):
        return
    if not bool(getattr(S, "filemgr_sftp_mounts_enabled", False)):
        _raise_sftp_mount_flag_error("sftp_mounts_disabled", "sftp mounts are not enabled")
    if operation == "write" and not bool(getattr(S, "filemgr_sftp_mounts_write_enabled", False)):
        _raise_sftp_mount_flag_error("sftp_mount_writes_disabled", "sftp mount write operations are disabled")
    if operation == "share" and not bool(getattr(S, "filemgr_sftp_mounts_share_enabled", False)):
        _raise_sftp_mount_flag_error("sftp_mount_shares_disabled", "sftp mount sharing is disabled")


def _enforce_sftp_mount_flags_for_paths(paths: List[str], *, operation: str) -> None:
    for p in paths:
        _enforce_sftp_mount_flags_for_path(p, operation=operation)


def _extract_mount_id_from_path(path: Optional[str]) -> Optional[str]:
    if not _looks_like_sftp_mount_path(path):
        return None
    p = str(path or "").strip()
    if not p.startswith("/"):
        p = "/" + p
    parts = [seg for seg in p.split("/") if seg]
    if len(parts) < 2 or parts[0] != "mounts":
        raise HTTPException(status_code=400, detail={"code": "invalid_mount_path", "message": "invalid mount path"})
    mount_id = str(parts[1] or "").strip()
    if not mount_id:
        raise HTTPException(status_code=400, detail={"code": "invalid_mount_path", "message": "invalid mount id"})
    return mount_id


def _enforce_sftp_mount_status_for_path(path: Optional[str], *, owner: str, operation: str) -> None:
    if operation not in {"read", "write", "share"}:
        return
    mount_id = _extract_mount_id_from_path(path)
    if not mount_id:
        return
    mount = get_sftp_mount(owner=owner, mount_id=mount_id)
    if str(mount.status or "").lower() == "disabled":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "mount_disabled",
                "message": "sftp mount is disabled or revoked",
                "mount_id": mount_id,
            },
        )


def _enforce_sftp_mount_status_for_paths(paths: List[str], *, owner: str, operation: str) -> None:
    for p in paths:
        _enforce_sftp_mount_status_for_path(p, owner=owner, operation=operation)




def _enforce_sftp_mount_share_policy(path: Optional[str]) -> None:
    if not _looks_like_sftp_mount_path(path):
        return
    raise HTTPException(
        status_code=403,
        detail={
            "code": "sftp_mount_share_not_allowed",
            "message": "sharing mounted sftp paths is not currently supported",
        },
    )
def _storage_audit_fields_for_path(path: Optional[str]) -> Dict[str, Any]:
    mount_id = _extract_mount_id_from_path(path)
    if mount_id:
        return {"storage_backend": "sftp", "mount_id": mount_id}
    return {"storage_backend": "s3"}




def _emit_sftp_mount_audit(
    event: str,
    *,
    actor_sub: str,
    req: Optional[Request] = None,
    owner: str,
    mount_id: Optional[str] = None,
    path: Optional[str] = None,
    outcome: str = "success",
    **extra: Any,
) -> None:
    details: Dict[str, Any] = {
        "owner": owner,
        "storage_backend": "sftp",
    }
    if mount_id:
        details["mount_id"] = mount_id
    if path:
        details["path"] = path
    details.update(extra)
    audit_event(event, actor_sub, req, outcome=outcome, **details)
def _storage_audit_fields_for_move(src: Optional[str], dst: Optional[str]) -> Dict[str, Any]:
    src_mount_id = _extract_mount_id_from_path(src)
    dst_mount_id = _extract_mount_id_from_path(dst)
    if src_mount_id or dst_mount_id:
        out: Dict[str, Any] = {"storage_backend": "sftp"}
        if src_mount_id:
            out["src_mount_id"] = src_mount_id
        if dst_mount_id:
            out["dst_mount_id"] = dst_mount_id
        if src_mount_id and src_mount_id == dst_mount_id:
            out["mount_id"] = src_mount_id
        return out
    return {"storage_backend": "s3"}

def _enforce_mock_inspection_rate_limit(*, actor_sub: str, owner: str, mount_id: str) -> None:
    per_minute = max(1, int(getattr(S, "filemgr_sftp_mock_rate_limit_per_minute", 120) or 120))
    now = time.time()
    window_start = now - 60.0
    key = f"{actor_sub}|{owner}|{mount_id}"
    with _SFTP_MOCK_INSPECT_RATE_LOCK:
        seq = [ts for ts in _SFTP_MOCK_INSPECT_RATE.get(key, []) if ts >= window_start]
        if len(seq) >= per_minute:
            _SFTP_MOCK_INSPECT_RATE[key] = seq
            raise _mock_files_error(429, "sftp_mock_rate_limited", "mock inspection rate limit exceeded")
        seq.append(now)
        _SFTP_MOCK_INSPECT_RATE[key] = seq


def _mock_files_error(status_code: int, code: str, message: str, *, path: Optional[str] = None) -> HTTPException:
    detail: Dict[str, Any] = {"code": code, "message": message}
    if path is not None:
        detail["path"] = path
    return HTTPException(status_code=status_code, detail=detail)


def _list_mock_sftp_dir(
    *,
    owner: str,
    mount_id: str,
    sub_path: str,
    limit: int = 200,
    cursor: Optional[str] = None,
    actor_sub: Optional[str] = None,
) -> Dict[str, Any]:
    backend = str(getattr(S, "filemgr_sftp_backend", "paramiko") or "paramiko").strip().lower()
    rel = (sub_path or "/").strip() or "/"
    if backend != "mock":
        raise _mock_files_error(409, "sftp_mock_backend_disabled", "mock backend is disabled", path=rel)

    if actor_sub:
        _enforce_mock_inspection_rate_limit(actor_sub=actor_sub, owner=owner, mount_id=mount_id)

    if not isinstance(limit, int) or limit < 1 or limit > 1000:
        raise _mock_files_error(400, "mock_path_invalid_limit", "limit must be between 1 and 1000", path=rel)

    cursor_payload = _decode_cursor(cursor)
    if cursor_payload and cursor_payload.get("mode") not in {"offset", None}:
        raise _mock_files_error(400, "mock_path_invalid_cursor", "invalid cursor", path=rel)
    offset = int((cursor_payload or {}).get("offset", 0) or 0)
    if offset < 0:
        raise _mock_files_error(400, "mock_path_invalid_cursor", "invalid cursor", path=rel)

    depth_max = max(1, int(getattr(S, "filemgr_sftp_mock_path_max_depth", 32) or 32))
    rel_parts = [p for p in rel.split("/") if p and p not in {"."}]
    if any(p == ".." for p in rel_parts) or len(rel_parts) > depth_max:
        raise _mock_files_error(400, "mock_path_invalid", "invalid mock path", path=rel)

    root = str(getattr(S, "filemgr_sftp_mock_root_dir", "/tmp/filemgr-sftp-mock") or "/tmp/filemgr-sftp-mock")
    mount_root = os.path.abspath(os.path.join(root, owner, mount_id))
    rel_clean = rel.lstrip("/")
    target = os.path.abspath(os.path.join(mount_root, rel_clean))
    if not target.startswith(mount_root):
        raise _mock_files_error(400, "mock_path_invalid", "invalid mock path", path=rel)
    if not os.path.exists(target):
        raise _mock_files_error(404, "mock_path_not_found", "mock path not found", path=rel)
    if not os.path.isdir(target):
        raise _mock_files_error(400, "mock_path_not_directory", "mock path must be a directory", path=rel)

    scan_cap = max(1, int(getattr(S, "filemgr_sftp_mock_scan_max_entries", 5000) or 5000))
    entries: List[os.DirEntry] = []
    with os.scandir(target) as it:
        for idx, ent in enumerate(it, start=1):
            if idx > scan_cap:
                raise _mock_files_error(413, "mock_path_scan_limit_exceeded", "mock directory scan limit exceeded", path=rel)
            entries.append(ent)

    entries.sort(key=lambda ent: str(ent.name).lower())
    items: List[Dict[str, Any]] = []
    for ent in entries:
        full = ent.path
        st = ent.stat()
        rel_item = os.path.relpath(full, mount_root).replace("\\", "/")
        rel_item = "/" + rel_item.lstrip("/")
        is_dir = ent.is_dir()
        if is_dir:
            rel_item = rel_item.rstrip("/") + "/"
        items.append({
            "name": ent.name,
            "path": rel_item,
            "type": "folder" if is_dir else "file",
            "size": int(st.st_size) if ent.is_file() else 0,
            "modified_at": int(st.st_mtime),
        })

    paged = items[offset: offset + limit]
    next_payload = None
    if offset + len(paged) < len(items):
        next_payload = {"mode": "offset", "offset": offset + len(paged)}

    return {
        "backend": backend,
        "root": mount_root,
        "filesystem_path": target,
        "path": "/" + rel_clean if rel_clean else "/",
        "items": paged,
        "limit": limit,
        "cursor": _encode_cursor(next_payload),
    }


class PresignUploadIn(BaseModel):
    path: str = Field(..., description="Full file path, e.g. /docs/a.txt")
    content_type: Optional[str] = Field(default=None, description="Optional content type")


class PresignUploadOut(BaseModel):
    upload_url: str
    bucket: str
    key: str
    ticket_id: str
    path: str
    content_type: str


class CompleteUploadIn(BaseModel):
    path: str = Field(..., description="Full file path, e.g. /docs/a.txt")
    key: str = Field(..., description="S3 object key from presign response")
    ticket_id: str = Field(..., description="Upload ticket id from presign response")
    content_type: Optional[str] = Field(default=None, description="Optional content type override")
    encrypted: bool = Field(default=False, description="Whether payload was client-side encrypted")
    enc_meta: Optional[Dict[str, Any]] = Field(default=None, description="Client-side encryption metadata")


class MoveCheckpointIn(BaseModel):
    move_id: str = Field(..., description="Move checkpoint id")


class FileCryptoTelemetryIn(BaseModel):
    event: str = Field(..., pattern="^(decrypt_failure|remembered_password_used|hover_play_start|hover_play_failure)$")
    path: Optional[str] = Field(default=None)
    reason: Optional[str] = Field(default=None, pattern="^(wrong_password|corrupted_metadata|crypto_error|playback_error|autoplay_blocked|unsupported_capability|unknown)?$")
    remembered_password_used: bool = Field(default=False)


class FileMountOut(BaseModel):
    id: str
    owner: str
    provider: str
    mount_path: str
    bucket: str
    prefix: Optional[str] = None
    mode: str
    auth_ref: str
    status: str
    created_at: str
    updated_at: str
    last_check_at: Optional[str] = None
    last_error: Optional[str] = None


class FileMountsListOut(BaseModel):
    items: List[FileMountOut] = Field(default_factory=list)


class FileMountCreateIn(BaseModel):
    mount_path: str = Field(..., min_length=1, max_length=2048)
    bucket: str = Field(..., min_length=3, max_length=255)
    prefix: Optional[str] = Field(default=None, max_length=2048)
    mode: Literal["read_only", "read_write"] = "read_only"
    auth_ref: str = Field(..., min_length=1, max_length=256)
    status: Literal["active", "degraded", "error", "disabled"] = "active"


class FileMountUpdateIn(BaseModel):
    mount_path: Optional[str] = Field(default=None, min_length=1, max_length=2048)
    bucket: Optional[str] = Field(default=None, min_length=3, max_length=255)
    prefix: Optional[str] = Field(default=None, max_length=2048)
    mode: Optional[Literal["read_only", "read_write"]] = None
    auth_ref: Optional[str] = Field(default=None, min_length=1, max_length=256)
    status: Optional[Literal["active", "degraded", "error", "disabled"]] = None


class DeleteFileMountOut(BaseModel):
    ok: bool
    deleted: bool


class ValidateFileMountOut(BaseModel):
    ok: bool
    mount_id: str
    status: str


@router.get("/mounts", response_model=FileMountsListOut)
def list_file_mounts(user: str = Depends(_current_user)):
    _require_s3_mounts_enabled()
    items = [FileMountOut(**m.model_dump()) for m in list_file_mounts_records(user)]
    return FileMountsListOut(items=items)


@router.post("/mounts", response_model=FileMountOut)
def create_file_mount(body: FileMountCreateIn, user: str = Depends(_current_user)):
    _require_s3_mounts_enabled()
    _require_s3_mounts_write_enabled()
    out = create_file_mount_record(
        user,
        mount_path=body.mount_path,
        bucket=body.bucket,
        prefix=body.prefix,
        mode=body.mode,
        auth_ref=body.auth_ref,
        status=body.status,
    )
    return FileMountOut(**out.model_dump())


@router.get("/mounts/{mount_id}", response_model=FileMountOut)
def get_file_mount(mount_id: str, user: str = Depends(_current_user)):
    _require_s3_mounts_enabled()
    out = get_file_mount_record(user, mount_id)
    return FileMountOut(**out.model_dump())


@router.patch("/mounts/{mount_id}", response_model=FileMountOut)
def update_file_mount(mount_id: str, body: FileMountUpdateIn, user: str = Depends(_current_user)):
    _require_s3_mounts_enabled()
    _require_s3_mounts_write_enabled()
    out = update_file_mount_record(
        user,
        mount_id,
        mount_path=body.mount_path,
        bucket=body.bucket,
        prefix=body.prefix,
        mode=body.mode,
        auth_ref=body.auth_ref,
        status=body.status,
    )
    return FileMountOut(**out.model_dump())


@router.delete("/mounts/{mount_id}", response_model=DeleteFileMountOut)
def delete_file_mount(mount_id: str, user: str = Depends(_current_user)):
    _require_s3_mounts_enabled()
    _require_s3_mounts_write_enabled()
    return DeleteFileMountOut(**delete_file_mount_record(user, mount_id))


@router.post("/mounts/{mount_id}/validate", response_model=ValidateFileMountOut)
def validate_file_mount(mount_id: str, user: str = Depends(_current_user)):
    _require_s3_mounts_enabled()
    mount = get_file_mount_record(user, mount_id)
    return ValidateFileMountOut(ok=True, mount_id=mount.id, status=mount.status)


class CreateSftpMountIn(BaseModel):
    protocol: str = Field(default="sftp", pattern="^(sftp|scp|ftp)$")
    host: str = Field(..., min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    auth_credential_ref: str = Field(..., min_length=1)
    remote_root: str = Field(..., min_length=1)
    read_only: bool = Field(default=False)


class UpdateSftpMountIn(BaseModel):
    protocol: Optional[str] = Field(default=None, pattern="^(sftp|scp|ftp)$")
    host: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    auth_credential_ref: Optional[str] = None
    remote_root: Optional[str] = None
    read_only: Optional[bool] = None
    status: Optional[str] = Field(default=None, pattern="^(healthy|degraded|auth_failed|unreachable|disabled)$")


class RotateSftpMountCredentialIn(BaseModel):
    auth_mode: str = Field(..., pattern="^(password|private_key)$")
    username: str = Field(..., min_length=1)
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    auth_credential_ref: Optional[str] = None


class RevokeSftpMountIn(BaseModel):
    revoke_credential: bool = Field(default=True)
    disable_mount: bool = Field(default=True)


@router.get("/list")
def list_files(
    path: str = Query("/", description="Folder path"),
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    sort_by: str = Query("name", pattern="^(name|updated|size)$"),
    sort_dir: str = Query("asc", pattern="^(asc|desc)$"),
    user: str = Depends(_current_user),
):
    _enforce_filemanager_internal_entitlement(user=user, action="list_directory")
    if not isinstance(limit, int):
        limit = 50
    if not isinstance(sort_by, str):
        sort_by = "name"
    if not isinstance(sort_dir, str):
        sort_dir = "asc"
    _enforce_sftp_mount_flags_for_path(path, operation="read")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="read")
    folder = norm_path(path, is_folder=True)
    cursor_payload = _decode_cursor(cursor)
    resolved_provider = resolve_storage_provider(user, folder)
    if resolved_provider.backend == "sftp":
        if cursor_payload and cursor_payload.get("mode") not in {"offset", None}:
            raise HTTPException(status_code=400, detail="invalid cursor")
        items = resolved_provider.provider.list_dir(user, folder)
        out = []
        for it in items:
            if it.get("parent") == folder:
                out.append({
                    "path": it.get("path"),
                    "type": it.get("type"),
                    "name": it.get("name"),
                    "size": it.get("size"),
                    "updated_at": it.get("updated_at"),
                    "content_type": it.get("content_type"),
                    **encryption_info_from_node(it),
                    **preview_capability_from_node(it),
                })
        scan_forward = sort_dir == "asc"
        if sort_by == "updated":
            out.sort(key=lambda x: (x["type"] != "folder", x.get("updated_at") or ""), reverse=not scan_forward)
        elif sort_by == "size":
            out.sort(key=lambda x: (x["type"] != "folder", x.get("size") or 0, (x.get("name") or "").lower()), reverse=not scan_forward)
        else:
            out.sort(key=lambda x: (x["type"] != "folder", (x.get("name") or "").lower()), reverse=not scan_forward)
        offset = 0
        if cursor_payload:
            offset = int(cursor_payload.get("offset", 0) or 0)
        paged = out[offset:offset + limit]
        next_offset = offset + limit
        next_payload = {"mode": "offset", "offset": next_offset} if next_offset < len(out) else None
        record_operation_usage(user, folder, operation="list", backend="sftp")
        _emit_sftp_mount_audit(
            "filemgr_sftp_data_listed",
            actor_sub=user,
            owner=user,
            mount_id=_extract_mount_id_from_path(folder),
            path=folder,
            item_count=len(paged),
        )
        return {"path": folder, "items": paged, "cursor": _encode_cursor(next_payload)}
    scan_forward = sort_dir == "asc"

    mount = resolve_path_mount(user, folder, is_folder=True)
    if mount:
        if cursor_payload and cursor_payload.get("mode") not in {"mount", None}:
            raise HTTPException(status_code=400, detail="invalid cursor")
        mount_cursor = cursor_payload.get("token") if cursor_payload else None
        listing = list_mounted_directory(user, folder, limit=limit, cursor=mount_cursor)
        out = listing.get("items") or []
        if sort_by == "updated":
            out.sort(key=lambda x: (x["type"] != "folder", x.get("updated_at") or ""), reverse=not scan_forward)
        elif sort_by == "size":
            out.sort(key=lambda x: (x["type"] != "folder", x.get("size") or 0, (x.get("name") or "").lower()), reverse=not scan_forward)
        elif sort_by == "name":
            out.sort(key=lambda x: (x["type"] != "folder", (x.get("name") or "").lower()), reverse=not scan_forward)
        next_token = listing.get("cursor")
        next_payload = {"mode": "mount", "token": next_token} if next_token else None
        return {"path": folder, "items": out, "cursor": _encode_cursor(next_payload)}

    if sort_by == "name":
        if cursor_payload and cursor_payload.get("mode") not in {"ddb", None}:
            raise HTTPException(status_code=400, detail="invalid cursor")
        cursor_key = cursor_payload.get("key") if cursor_payload else None
        try:
            items, next_cursor = list_children_page(
                user,
                folder,
                limit=limit,
                cursor=cursor_key,
                scan_forward=scan_forward,
            )
        except HTTPException:
            items = list_children(user, folder)
            next_cursor = None
    else:
        if cursor_payload and cursor_payload.get("mode") != "offset":
            raise HTTPException(status_code=400, detail="invalid cursor")
        items = list_children(user, folder)
        next_cursor = None
    out = []
    for it in items:
        if it.get("parent") == folder:
            out.append({
                "path": it["path"],
                "type": it["type"],
                "name": it["name"],
                "size": it.get("size"),
                "updated_at": it.get("updated_at"),
                "content_type": it.get("content_type"),
                **encryption_info_from_node(it),
                **preview_capability_from_node(it),
            })
    if sort_by == "updated":
        out.sort(key=lambda x: (x["type"] != "folder", x.get("updated_at") or ""), reverse=not scan_forward)
    elif sort_by == "size":
        out.sort(
            key=lambda x: (x["type"] != "folder", x.get("size") or 0, (x.get("name") or "").lower()),
            reverse=not scan_forward,
        )
    elif sort_by == "name":
        if cursor_payload and cursor_payload.get("mode") == "offset":
            raise HTTPException(status_code=400, detail="invalid cursor")
        if not next_cursor:
            return {"path": folder, "items": out, "cursor": None}
        return {"path": folder, "items": out, "cursor": _encode_cursor({"mode": "ddb", "key": next_cursor})}

    offset = 0
    if cursor_payload:
        offset = int(cursor_payload.get("offset", 0) or 0)
    paged = out[offset:offset + limit]
    next_offset = offset + limit
    next_payload = {"mode": "offset", "offset": next_offset} if next_offset < len(out) else None
    return {"path": folder, "items": paged, "cursor": _encode_cursor(next_payload)}


@router.get("/info")
def file_info(path: str = Query(...), user: str = Depends(_current_user)):
    _enforce_sftp_mount_flags_for_path(path, operation="read")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="read")
    p = norm_path(path, is_folder=None)
    resolved_provider = resolve_storage_provider(user, p)
    if resolved_provider.backend == "sftp":
        it = resolved_provider.provider.stat(user, p)
        record_operation_usage(user, p, operation="read", backend="sftp")
        _emit_sftp_mount_audit(
            "filemgr_sftp_data_read",
            actor_sub=user,
            owner=user,
            mount_id=_extract_mount_id_from_path(p),
            path=p,
            node_type=str(it.get("type") or "unknown"),
        )
    else:
        it = get_node(user, p if p.endswith("/") else p)
    encryption_info = encryption_info_from_node(it)
    preview_info = preview_capability_from_node(it)
    return {
        "path": it["path"],
        "type": it["type"],
        "name": it["name"],
        "parent": it.get("parent"),
        "created_at": it.get("created_at"),
        "updated_at": it.get("updated_at"),
        "upload_at": it.get("upload_at"),
        "upload_by": it.get("upload_by"),
        "last_download_at": it.get("last_download_at"),
        "last_download_by": it.get("last_download_by"),
        "size": it.get("size"),
        "duration_seconds": it.get("duration_seconds"),
        "thumbnail": it.get("thumbnail"),
        "content_type": it.get("content_type"),
        "shared": it.get("shared", False),
        **encryption_info,
        **preview_info,
    }


@router.get("/search")
def search_filenames(
    prefix: str = Query(..., description="Filename prefix"),
    limit: int = Query(50, ge=1, le=200),
    user: str = Depends(_current_user),
):
    return {"prefix": prefix, "results": search_prefix(user, prefix, limit=limit)}


@router.get("/search-text")
def search_text_files(
    q: str = Query(..., description="Search text"),
    limit: int = Query(200, ge=1, le=200),
    user: str = Depends(_current_user),
):
    return {"query": q, "results": search_text(user, q, limit=limit)}


@router.get("/admin/list")
def admin_list_files(
    path: str = Query("/", description="Folder path"),
    owner: Optional[str] = Query(default=None, description="Optional owner user_sub filter"),
    limit: int = Query(200, ge=1, le=500),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(_admin_or_root_ctx),
):
    folder = norm_path(path, is_folder=True)
    items = admin_search_metadata(owner=(owner or None), folder=folder, limit=limit)
    audit_event(
        "filemgr_admin_metadata_list",
        ctx["user_sub"],
        req,
        outcome="success",
        owner_filter=owner,
        path=folder,
        result_count=len(items),
        actor_sub=str(ctx.get("actor_sub") or ctx["user_sub"]),
    )
    return {"path": folder, "owner": owner, "items": items}


@router.get("/admin/search")
def admin_search_files(
    q: Optional[str] = Query(default=None, description="Optional free-text match against name/path"),
    prefix: Optional[str] = Query(default=None, description="Optional filename prefix"),
    owner: Optional[str] = Query(default=None, description="Optional owner user_sub filter"),
    limit: int = Query(200, ge=1, le=500),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(_admin_or_root_ctx),
):
    if not (q or prefix):
        raise HTTPException(status_code=400, detail="q or prefix is required")
    items = admin_search_metadata(owner=(owner or None), query=q, prefix=prefix, limit=limit)
    audit_event(
        "filemgr_admin_metadata_search",
        ctx["user_sub"],
        req,
        outcome="success",
        owner_filter=owner,
        q=q,
        prefix=prefix,
        result_count=len(items),
        actor_sub=str(ctx.get("actor_sub") or ctx["user_sub"]),
    )
    return {"owner": owner, "q": q, "prefix": prefix, "items": items}


@router.get("/admin/read")
def admin_read_file(
    owner: str = Query(..., description="Owner user_sub"),
    path: str = Query(..., description="File path"),
    include_content: bool = Query(False, description="Whether to return file content stream"),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(_admin_or_root_ctx),
):
    normalized_path = norm_path(path, is_folder=False)
    actor_sub = str(ctx.get("actor_sub") or ctx["user_sub"])
    if include_content and not _admin_can_read_content(ctx):
        raise HTTPException(status_code=403, detail="admin_content_access_disabled")

    node = get_node(owner, normalized_path)
    if not include_content:
        audit_event(
            "filemgr_admin_metadata_read",
            ctx["user_sub"],
            req,
            outcome="success",
            owner=owner,
            path=node.get("path"),
            include_content=False,
            **_file_audit_fields(ctx=ctx, owner=owner, file_path=str(node.get("path") or normalized_path)),
        )
        return {
            "owner": owner,
            "path": node.get("path"),
            "type": node.get("type"),
            "name": node.get("name"),
            "size": node.get("size"),
            "updated_at": node.get("updated_at"),
            "content_type": node.get("content_type"),
        }
    result = download_file(owner, normalized_path)
    node = result["node"]
    obj = result["object"]
    audit_event(
        "filemgr_admin_content_read",
        ctx["user_sub"],
        req,
        outcome="success",
        owner=owner,
        path=node.get("path"),
        size=node.get("size"),
        include_content=True,
        **_file_audit_fields(ctx=ctx, owner=owner, file_path=str(node.get("path") or normalized_path)),
    )

    def gen():
        body = obj["Body"]
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            yield chunk

    return StreamingResponse(
        gen(),
        media_type=node.get("content_type", "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{node["name"]}"',
            **({"Content-Length": str(node["size"])} if node.get("size") is not None else {}),
        },
    )


@router.get("/admin/audit")
def admin_file_audit(
    actor_sub: Optional[str] = Query(default=None),
    target_user_sub: Optional[str] = Query(default=None),
    file_path: Optional[str] = Query(default=None),
    start_ts: Optional[int] = Query(default=None),
    end_ts: Optional[int] = Query(default=None),
    limit: int = Query(100, ge=1, le=500),
    cursor: Optional[str] = Query(default=None),
    _ctx: Dict[str, Any] = Depends(_admin_or_root_ctx),
):
    offset = 0
    if cursor:
        payload = _decode_cursor(cursor) or {}
        offset = int(payload.get("offset", 0) or 0)

    items: List[Dict[str, Any]] = []
    eks: Optional[Dict[str, Any]] = None
    scanned = 0
    max_scan = 40
    while scanned < max_scan:
        scanned += 1
        kwargs: Dict[str, Any] = {"Limit": 250}
        if eks:
            kwargs["ExclusiveStartKey"] = eks
        resp = T.alerts.scan(**kwargs)
        for it in resp.get("Items", []):
            event = str(it.get("event") or "")
            if not event.startswith("filemgr_"):
                continue
            ts = int(it.get("ts") or 0)
            if start_ts and ts < start_ts:
                continue
            if end_ts and ts > end_ts:
                continue
            details = it.get("details") or {}
            if actor_sub and str(details.get("actor_sub") or "") != actor_sub:
                continue
            if target_user_sub and str(details.get("target_user_sub") or "") != target_user_sub:
                continue
            if file_path and str(details.get("file_path") or "") != file_path:
                continue
            items.append(
                {
                    "ts": ts,
                    "event": event,
                    "outcome": it.get("outcome"),
                    "actor_sub": details.get("actor_sub"),
                    "target_user_sub": details.get("target_user_sub"),
                    "file_path": details.get("file_path"),
                    "correlation_id": details.get("correlation_id"),
                    "details": details,
                }
            )
        eks = resp.get("LastEvaluatedKey")
        if not eks:
            break

    items.sort(key=lambda x: int(x.get("ts") or 0), reverse=True)
    page = items[offset: offset + limit]
    next_cursor = _encode_cursor({"offset": offset + limit}) if (offset + limit) < len(items) else None
    return {"items": page, "cursor": next_cursor}


def _probe_sftp_mount_health(*, owner: str, mount_id: str, actor_sub: str) -> Dict[str, Any]:
    mount = get_sftp_mount(owner=owner, mount_id=mount_id)
    previous_status = str(mount.status or "")
    next_status = "healthy"
    err_code = None
    err_message = None
    ok = True
    try:
        cred = get_sftp_credential(owner=owner, mount_id=str(mount.auth_credential_ref), include_secret=True, actor_sub=actor_sub)
        secret = cred.get("secret") or {}
        session = acquire_sftp_session(
            SftpConnectionConfig(
                owner=owner,
                mount_id=str(mount.id),
                host=str(mount.host),
                port=int(mount.port),
                username=str(cred.get("username") or ""),
                auth_mode=str(cred.get("auth_mode") or ""),
                password=secret.get("password"),
                private_key=secret.get("private_key"),
                private_key_passphrase=secret.get("private_key_passphrase"),
                expected_host_key=None,
            )
        )
        release_sftp_session(session)
    except HTTPException as exc:
        ok = False
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        if exc.status_code == 404:
            next_status = "auth_failed"
            err_code = "credential_not_found"
            err_message = "credential reference for mount could not be resolved"
        elif str(detail.get("code") or "").startswith("auth_"):
            next_status = "auth_failed"
            err_code = str(detail.get("code") or "auth_failed")
            err_message = str(detail.get("message") or "sftp authentication failed")
        elif str(detail.get("code") or "").startswith("host_key"):
            next_status = "auth_failed"
            err_code = str(detail.get("code") or "host_key_verification_failed")
            err_message = str(detail.get("message") or "sftp host key verification failed")
        elif str(detail.get("code") or "") in {"network_timeout", "network_unreachable", "connection_failed", "pool_exhausted"}:
            next_status = "unreachable"
            err_code = str(detail.get("code") or "connection_test_failed")
            err_message = str(detail.get("message") or "sftp endpoint is currently unreachable")
        else:
            next_status = "degraded"
            err_code = str(detail.get("code") or "connection_test_failed")
            err_message = str(detail.get("message") or "unable to access credential for mount test")

    updated = update_sftp_mount(
        owner=owner,
        mount_id=mount_id,
        status=next_status,
        last_tested_at=str(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        last_error_code=err_code,
        last_error_message=err_message,
    )
    return {
        "ok": ok,
        "mount": updated,
        "previous_status": previous_status,
        "status_changed": previous_status != str(updated.status or ""),
    }


def _maybe_refresh_mount_health_for_owner(*, owner: str, actor_sub: str, req: Optional[Request] = None) -> None:
    global _SFTP_HEALTH_REFRESH_LAST_RUN_TS
    if not bool(getattr(S, "filemgr_sftp_health_refresh_enabled", False)):
        return
    interval_seconds = max(5, int(getattr(S, "filemgr_sftp_health_refresh_interval_seconds", 300) or 300))
    limit = max(1, int(getattr(S, "filemgr_sftp_health_refresh_limit", 20) or 20))
    now = time.time()
    with _SFTP_HEALTH_REFRESH_LOCK:
        if now - _SFTP_HEALTH_REFRESH_LAST_RUN_TS < interval_seconds:
            return
        _SFTP_HEALTH_REFRESH_LAST_RUN_TS = now

    mounts = list_sftp_mount_records(owner=owner, limit=limit)
    for mount in mounts:
        if str(getattr(mount, "status", "")).lower() == "disabled":
            continue
        try:
            probe = _probe_sftp_mount_health(owner=owner, mount_id=str(mount.id), actor_sub=actor_sub)
            audit_event(
                "filemgr_sftp_mount_health_refresh",
                actor_sub,
                req,
                outcome=("success" if probe["ok"] else "failure"),
                owner=owner,
                mount_id=str(mount.id),
                previous_status=probe["previous_status"],
                status=str(probe["mount"].status),
                status_changed=bool(probe["status_changed"]),
                last_error_code=probe["mount"].last_error_code,
            )
        except HTTPException as exc:
            audit_event(
                "filemgr_sftp_mount_health_refresh",
                actor_sub,
                req,
                outcome="failure",
                owner=owner,
                mount_id=str(mount.id),
                status="unknown",
                status_changed=False,
                last_error_code=(exc.detail.get("code") if isinstance(exc.detail, dict) else None),
            )


@router.post("/mounts/sftp")
def create_sftp_mount_endpoint(
    inp: CreateSftpMountIn,
    owner: Optional[str] = Query(default=None, description="Optional owner (admin/root only)"),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    resolved_owner = _resolve_mount_owner(ctx=ctx, owner=owner)
    mount = create_sftp_mount(
        owner=resolved_owner,
        host=inp.host,
        port=inp.port,
        auth_credential_ref=inp.auth_credential_ref,
        remote_root=inp.remote_root,
        read_only=inp.read_only,
        protocol=inp.protocol,
    )
    audit_event(
        "filemgr_sftp_mount_created",
        str(ctx.get("user_sub") or resolved_owner),
        req,
        outcome="success",
        owner=resolved_owner,
        mount_id=str(mount.id),
    )
    return {"ok": True, "mount": _mount_to_api(mount)}


@router.get("/mounts")
def list_sftp_mounts_endpoint(
    owner: Optional[str] = Query(default=None, description="Optional owner (admin/root only)"),
    limit: int = Query(100, ge=1, le=500),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    resolved_owner = _resolve_mount_owner(ctx=ctx, owner=owner)
    if not isinstance(limit, int):
        limit = 100
    _maybe_refresh_mount_health_for_owner(owner=resolved_owner, actor_sub=str(ctx.get("user_sub") or resolved_owner), req=req)
    items = list_sftp_mount_records(owner=resolved_owner, limit=limit)
    audit_event(
        "filemgr_sftp_mount_listed",
        str(ctx.get("user_sub") or resolved_owner),
        req,
        outcome="success",
        owner=resolved_owner,
        count=len(items),
    )
    return {"items": [_mount_to_api(m) for m in items]}


@router.get("/mounts/{mount_id}/mock-files")
def list_sftp_mount_mock_files_endpoint(
    mount_id: str,
    path: str = Query("/"),
    limit: int = Query(200, ge=1, le=1000),
    cursor: Optional[str] = Query(default=None),
    owner: Optional[str] = Query(default=None),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    actor_sub = str(ctx.get("user_sub") or "")
    resolved_owner = _resolve_mount_owner(ctx=ctx, owner=owner)
    owner_scope = "self" if resolved_owner == actor_sub else "admin_scoped"
    _ = get_sftp_mount(owner=resolved_owner, mount_id=mount_id)
    try:
        listing = _list_mock_sftp_dir(
            owner=resolved_owner,
            mount_id=mount_id,
            sub_path=path,
            limit=limit,
            cursor=cursor,
            actor_sub=actor_sub,
        )
    except HTTPException as exc:
        audit_event(
            "filemgr_sftp_mock_inspection",
            actor_sub or resolved_owner,
            req,
            outcome="failure",
            owner=resolved_owner,
            mount_id=mount_id,
            path=path,
            owner_scope=owner_scope,
            code=(exc.detail.get("code") if isinstance(exc.detail, dict) else None),
        )
        raise

    audit_event(
        "filemgr_sftp_mock_inspection",
        actor_sub or resolved_owner,
        req,
        outcome="success",
        owner=resolved_owner,
        mount_id=mount_id,
        path=listing.get("path") or path,
        owner_scope=owner_scope,
        item_count=len(listing.get("items") or []),
        has_more=bool(listing.get("cursor")),
    )
    return {
        "mount_id": mount_id,
        "owner": resolved_owner,
        "backend": listing["backend"],
        "path": listing["path"],
        "items": listing["items"],
        "limit": listing["limit"],
        "cursor": listing["cursor"],
        "filesystem_path": listing.get("filesystem_path"),
    }


@router.patch("/mounts/{mount_id}")
def update_sftp_mount_endpoint(
    mount_id: str,
    inp: UpdateSftpMountIn,
    owner: Optional[str] = Query(default=None, description="Optional owner (admin/root only)"),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    resolved_owner = _resolve_mount_owner(ctx=ctx, owner=owner)
    mount = update_sftp_mount(
        owner=resolved_owner,
        mount_id=mount_id,
        host=inp.host,
        port=inp.port,
        auth_credential_ref=inp.auth_credential_ref,
        remote_root=inp.remote_root,
        read_only=inp.read_only,
        status=inp.status,
        protocol=inp.protocol,
    )
    audit_event(
        "filemgr_sftp_mount_updated",
        str(ctx.get("user_sub") or resolved_owner),
        req,
        outcome="success",
        owner=resolved_owner,
        mount_id=mount_id,
    )
    return {"ok": True, "mount": _mount_to_api(mount)}


@router.delete("/mounts/{mount_id}")
def delete_sftp_mount_endpoint(
    mount_id: str,
    owner: Optional[str] = Query(default=None, description="Optional owner (admin/root only)"),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    resolved_owner = _resolve_mount_owner(ctx=ctx, owner=owner)
    delete_sftp_mount(owner=resolved_owner, mount_id=mount_id)
    audit_event(
        "filemgr_sftp_mount_deleted",
        str(ctx.get("user_sub") or resolved_owner),
        req,
        outcome="success",
        owner=resolved_owner,
        mount_id=mount_id,
    )
    return {"ok": True, "mount_id": mount_id}


@router.post("/mounts/{mount_id}/test")
def test_sftp_mount_endpoint(
    mount_id: str,
    owner: Optional[str] = Query(default=None, description="Optional owner (admin/root only)"),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    resolved_owner = _resolve_mount_owner(ctx=ctx, owner=owner)
    actor_sub = str(ctx.get("user_sub") or resolved_owner)
    probe = _probe_sftp_mount_health(owner=resolved_owner, mount_id=mount_id, actor_sub=actor_sub)
    updated = probe["mount"]
    audit_event(
        "filemgr_sftp_mount_tested",
        actor_sub,
        req,
        outcome=("success" if probe["ok"] else "failure"),
        owner=resolved_owner,
        mount_id=mount_id,
        previous_status=probe["previous_status"],
        status=updated.status,
        status_changed=bool(probe["status_changed"]),
        last_error_code=updated.last_error_code,
    )
    return {"ok": bool(probe["ok"]), "mount": _mount_to_api(updated)}


@router.post("/mounts/{mount_id}/rotate-credential")
def rotate_sftp_mount_credential_endpoint(
    mount_id: str,
    inp: RotateSftpMountCredentialIn,
    owner: Optional[str] = Query(default=None, description="Optional owner (admin/root only)"),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    resolved_owner = _resolve_mount_owner(ctx=ctx, owner=owner)
    mount = get_sftp_mount(owner=resolved_owner, mount_id=mount_id)
    credential_ref = str(inp.auth_credential_ref or mount.auth_credential_ref or "").strip()
    if not credential_ref:
        raise HTTPException(status_code=400, detail={"code": "invalid_auth_credential_ref", "message": "auth credential reference is required"})

    upsert_sftp_credential(
        owner=resolved_owner,
        mount_id=credential_ref,
        auth_mode=inp.auth_mode,
        username=inp.username,
        password=inp.password,
        private_key=inp.private_key,
        private_key_passphrase=inp.private_key_passphrase,
        actor_sub=str(ctx.get("user_sub") or resolved_owner),
    )

    updated_mount = mount
    if credential_ref != str(mount.auth_credential_ref):
        updated_mount = update_sftp_mount(owner=resolved_owner, mount_id=mount_id, auth_credential_ref=credential_ref)

    audit_event(
        "filemgr_sftp_mount_credential_rotated",
        str(ctx.get("user_sub") or resolved_owner),
        req,
        outcome="success",
        owner=resolved_owner,
        mount_id=mount_id,
        auth_credential_ref=credential_ref,
    )
    return {"ok": True, "mount": _mount_to_api(updated_mount), "auth_credential_ref": credential_ref}


@router.post("/mounts/{mount_id}/revoke")
def revoke_sftp_mount_endpoint(
    mount_id: str,
    inp: RevokeSftpMountIn,
    owner: Optional[str] = Query(default=None, description="Optional owner (admin/root only)"),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    resolved_owner = _resolve_mount_owner(ctx=ctx, owner=owner)
    mount = get_sftp_mount(owner=resolved_owner, mount_id=mount_id)

    credential_revoked = False
    if inp.revoke_credential:
        try:
            delete_sftp_credential(owner=resolved_owner, mount_id=str(mount.auth_credential_ref), actor_sub=str(ctx.get("user_sub") or resolved_owner))
            credential_revoked = True
        except HTTPException as exc:
            if exc.status_code != 404:
                raise

    next_status = "disabled" if inp.disable_mount else mount.status
    updated_mount = update_sftp_mount(
        owner=resolved_owner,
        mount_id=mount_id,
        status=next_status,
        last_error_code=("mount_revoked" if inp.disable_mount else mount.last_error_code),
        last_error_message=("mount revoked by owner/admin" if inp.disable_mount else mount.last_error_message),
    )

    audit_event(
        "filemgr_sftp_mount_revoked",
        str(ctx.get("user_sub") or resolved_owner),
        req,
        outcome="success",
        owner=resolved_owner,
        mount_id=mount_id,
        mount_disabled=bool(inp.disable_mount),
        credential_revoked=credential_revoked,
    )
    return {"ok": True, "mount": _mount_to_api(updated_mount), "credential_revoked": credential_revoked}


@router.post("/folder")
def create_folder(path: str = Body(..., embed=True), req: Request = None, user: str = Depends(_current_user)):
    _enforce_sftp_mount_flags_for_path(path, operation="write")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="write")
    resolved_provider = resolve_storage_provider(user, path)
    if resolved_provider.backend == "sftp":
        out = resolved_provider.provider.mkdir(user, path)
        folder = out.get("path") or norm_path(path, is_folder=True)
    else:
        folder = create_empty_folder(user, path)
    audit_event("filemgr_folder_created", user, req, outcome="success", path=folder, **_storage_audit_fields_for_path(path))
    return {"ok": True, "path": folder}


@router.post("/upload")
def upload_fs_file(
    path: str = Query(..., description="Full file path, e.g. /docs/a.txt"),
    file: UploadFile = File(...),
    encrypted: bool = Query(False),
    enc_meta: Optional[str] = Query(default=None, description="JSON encryption metadata"),
    req: Request = None,
    user: str = Depends(_current_user),
):
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="upload_file",
        request_id=(req.headers.get("X-Request-Id") if req else None),
    )
    _enforce_sftp_mount_flags_for_path(path, operation="write")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="write")
    encrypted_flag = encrypted if isinstance(encrypted, bool) else False
    encryption_meta = _parse_encryption_meta(enc_meta) if encrypted_flag else None
    resolved_provider = resolve_storage_provider(user, path)
    if resolved_provider.backend == "sftp":
        if encrypted_flag or encryption_meta:
            raise HTTPException(status_code=400, detail={"code": "encryption_not_supported_for_mount", "message": "encryption metadata is not supported for sftp mounted uploads"})
        payload = file.file.read()
        assert_upload_allowed(user, incoming_bytes=len(payload))
        result = resolved_provider.provider.write_stream(
            user,
            path,
            payload,
            content_type=file.content_type,
            overwrite=True,
        )
        request_id = req.headers.get("X-Request-Id") if req else None
        record_upload_usage(user, path, len(payload), source="upload_sftp", request_id=request_id)
        record_operation_usage(user, path, operation="write", backend="sftp", request_id=request_id)
        _emit_sftp_mount_audit(
            "filemgr_sftp_data_written",
            actor_sub=user,
            req=req,
            owner=user,
            mount_id=_extract_mount_id_from_path(path),
            path=path,
            bytes_written=len(payload),
        )
    else:
        mount = resolve_path_mount(user, norm_path(path, is_folder=False), is_folder=False)
        if mount:
            _require_s3_mounts_enabled()
            _require_s3_mounts_write_enabled()
            result = upload_mounted_file(user, path, file)
        else:
            result = upload_file(user, path, file, encryption_meta=encryption_meta)
    audit_event(
        "filemgr_file_uploaded",
        user,
        req,
        outcome="success",
        path=result.get("path"),
        size=result.get("size"),
        content_type=file.content_type,
        encrypted_upload=encrypted_flag,
        **_storage_audit_fields_for_path(path),
    )
    record_filemgr_encryption_event("upload", encrypted=encrypted_flag)
    return {"ok": True, **result}


@router.post("/presign-upload", response_model=PresignUploadOut)
def presign_fs_upload(inp: PresignUploadIn, user: str = Depends(_current_user)):
    _enforce_sftp_mount_flags_for_path(inp.path, operation="write")
    _enforce_sftp_mount_status_for_path(inp.path, owner=user, operation="write")
    mount = resolve_path_mount(user, norm_path(inp.path, is_folder=False), is_folder=False)
    if mount:
        _require_s3_mounts_enabled()
        _require_s3_mounts_write_enabled()
        raise HTTPException(status_code=400, detail="mounted presign upload not supported")
    result = presign_upload(user, inp.path, content_type=inp.content_type)
    return PresignUploadOut(
        upload_url=result["upload_url"],
        bucket=result["bucket"],
        key=result["key"],
        ticket_id=result["ticket_id"],
        path=result["path"],
        content_type=result["content_type"],
    )


@router.post("/complete-upload")
def complete_fs_upload(inp: CompleteUploadIn, req: Request = None, user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="upload_file",
        request_id=(req.headers.get("X-Request-Id") if req else inp.ticket_id),
    )
    _enforce_sftp_mount_flags_for_path(inp.path, operation="write")
    _enforce_sftp_mount_status_for_path(inp.path, owner=user, operation="write")
    mount = resolve_path_mount(user, norm_path(inp.path, is_folder=False), is_folder=False)
    if mount:
        _require_s3_mounts_enabled()
        _require_s3_mounts_write_enabled()
        raise HTTPException(status_code=400, detail="mounted presign upload not supported")
    result = register_presigned_upload(
        user,
        inp.path,
        s3_key=inp.key,
        ticket_id=inp.ticket_id,
        content_type=inp.content_type,
        encryption_meta=inp.enc_meta if inp.encrypted else None,
    )
    audit_event(
        "filemgr_file_uploaded",
        user,
        req,
        outcome="success",
        path=result.get("path"),
        size=result.get("size"),
        content_type=result.get("content_type"),
        encrypted_upload=inp.encrypted,
    )
    record_filemgr_encryption_event("upload", encrypted=inp.encrypted)
    return {"ok": True, **result}


@router.get("/download")
def download_fs_file(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="download_file",
        request_id=(req.headers.get("X-Request-Id") if req else None),
    )
    _enforce_sftp_mount_flags_for_path(path, operation="read")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="read")
    resolved_provider = resolve_storage_provider(user, path)
    if resolved_provider.backend == "sftp":
        result = resolved_provider.provider.read_stream(user, path)
        record_operation_usage(user, path, operation="read", backend="sftp")
        _emit_sftp_mount_audit(
            "filemgr_sftp_data_read",
            actor_sub=user,
            req=req,
            owner=user,
            mount_id=_extract_mount_id_from_path(path),
            path=path,
            bytes_requested=int(result.get("node", {}).get("size") or 0),
        )
    elif resolve_path_mount(user, path, is_folder=False):
        result = download_mounted_file(user, path)
        assert_file_bundle_access(user, result["node"])
    else:
        result = download_file(user, path)
        assert_file_bundle_access(user, result["node"])
    assert_download_allowed(user, requested_bytes=int(result["node"].get("size") or 0))
    node = result["node"]
    obj = result["object"]
    audit_event(
        "filemgr_file_downloaded",
        user,
        req,
        outcome="success",
        path=node.get("path"),
        size=node.get("size"),
        encrypted_download_attempt=bool(node.get("is_encrypted")),
    )
    record_filemgr_encryption_event("download_attempt", encrypted=bool(node.get("is_encrypted")))
    receipt_path = norm_path(path, is_folder=False)
    if receipt_path.startswith("/billing/receipts/") and receipt_path.lower().endswith(".pdf"):
        _, name = split_parent_name(receipt_path)
        txn_id = name[:-4]
        if txn_id:
            record_receipt_download(user, txn_id, receipt_path)

    def gen():
        body = obj["Body"]
        sent = 0
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            sent += len(chunk)
            yield chunk
        request_id = req.headers.get("X-Request-Id") if req else None
        record_download_usage(user, path, sent, source=("download_sftp" if resolved_provider.backend == "sftp" else "download_s3"), request_id=request_id)

    return StreamingResponse(
        gen(),
        media_type=node.get("content_type", "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{node["name"]}"',
            **({"Content-Length": str(node["size"])} if node.get("size") is not None else {}),
        },
    )


@router.get("/preview")
def preview_fs_file(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="preview_file",
        request_id=(req.headers.get("X-Request-Id") if req else None),
    )
    started = time.perf_counter()
    result = download_mounted_file(user, path) if resolve_path_mount(user, path, is_folder=False) else download_file(user, path)
    assert_file_bundle_access(user, result["node"])
    node = result["node"]
    obj = result["object"]
    preview_info = preview_capability_from_node(node)
    preview_kind = preview_info.get("preview_kind", "none")
    if not is_previewable(node):
        reason = preview_info.get("preview_reason") or "unsupported_type"
        audit_event(
            "filemgr_file_previewed",
            user,
            req,
            outcome="fallback",
            path=node.get("path"),
            size=node.get("size"),
            preview_kind=preview_kind,
            preview_supported=False,
            preview_reason=reason,
            is_encrypted=bool(node.get("is_encrypted")),
        )
        record_filemgr_preview_attempt(kind=preview_kind, outcome="fallback", reason=reason)
        record_filemgr_preview_fallback(kind=preview_kind, reason=reason)
        record_filemgr_preview_latency(kind=preview_kind, elapsed_seconds=time.perf_counter() - started)
        raise HTTPException(status_code=415, detail="preview not available for this file type")
    audit_event(
        "filemgr_file_previewed",
        user,
        req,
        outcome="success",
        path=node.get("path"),
        size=node.get("size"),
        preview_kind=preview_kind,
        preview_supported=True,
        preview_reason="none",
        is_encrypted=bool(node.get("is_encrypted")),
    )
    record_filemgr_preview_attempt(kind=preview_kind, outcome="success", reason="none")
    record_filemgr_preview_bytes(kind=preview_kind, nbytes=int(node.get("size") or 0))
    record_filemgr_preview_latency(kind=preview_kind, elapsed_seconds=time.perf_counter() - started)

    def gen():
        body = obj["Body"]
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            yield chunk

    return StreamingResponse(
        gen(),
        media_type=node.get("content_type", "application/octet-stream"),
        headers={"Content-Disposition": f'inline; filename="{node["name"]}"'},
    )


@router.get("/thumbnail")
def thumbnail_fs_file(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    started = time.perf_counter()
    result = download_thumbnail(user, path)
    node = result["node"]
    preview_info = preview_capability_from_node(node)
    preview_kind = preview_info.get("preview_kind", "none")
    if node.get("is_encrypted"):
        reason = preview_info.get("preview_reason") or "encrypted"
        audit_event(
            "filemgr_file_thumbnailed",
            user,
            req,
            outcome="fallback",
            path=node.get("path"),
            size=node.get("size"),
            preview_kind=preview_kind,
            preview_supported=False,
            preview_reason=reason,
            is_encrypted=True,
        )
        record_filemgr_preview_attempt(kind=preview_kind, outcome="fallback", reason=reason)
        record_filemgr_preview_fallback(kind=preview_kind, reason=reason)
        record_filemgr_preview_latency(kind=preview_kind, elapsed_seconds=time.perf_counter() - started)
        raise HTTPException(status_code=415, detail="thumbnail not available for encrypted files")
    thumb = result["thumbnail"]
    obj = result["object"]
    audit_event(
        "filemgr_file_thumbnailed",
        user,
        req,
        outcome="success",
        path=node.get("path"),
        size=node.get("size"),
        preview_kind=preview_kind,
        preview_supported=True,
        preview_reason="none",
        is_encrypted=bool(node.get("is_encrypted")),
    )
    record_filemgr_preview_attempt(kind=preview_kind, outcome="success", reason="none")
    record_filemgr_preview_bytes(kind=preview_kind, nbytes=int(node.get("size") or 0))
    record_filemgr_preview_latency(kind=preview_kind, elapsed_seconds=time.perf_counter() - started)

    def gen():
        body = obj["Body"]
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            yield chunk

    return StreamingResponse(
        gen(),
        media_type=thumb.get("content_type", "image/jpeg"),
        headers={"Content-Disposition": f'inline; filename="{node["name"]}_thumb.jpg"'},
    )




@router.delete("")
def remove_fs(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    raw = str(path or "").strip()
    is_folder_path = raw.endswith("/")
    normalized = norm_path(path, is_folder=True if is_folder_path else False)
    if is_folder_path:
        mount = resolve_path_mount(user, normalized, is_folder=True)
        if mount:
            raise HTTPException(status_code=400, detail="mounted folder delete not supported")
        return remove_fs_folder(path=normalized, req=req, user=user)
    return remove_fs_file(path=normalized, req=req, user=user)

@router.delete("/file")
def remove_fs_file(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="delete_file",
        request_id=(req.headers.get("X-Request-Id") if req else None),
    )
    _enforce_sftp_mount_flags_for_path(path, operation="write")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="write")
    resolved_provider = resolve_storage_provider(user, path)
    if resolved_provider.backend == "sftp":
        resolved_provider.provider.delete(user, path)
        request_id = req.headers.get("X-Request-Id") if req else None
        record_operation_usage(user, path, operation="delete", backend="sftp", request_id=request_id)
        _emit_sftp_mount_audit(
            "filemgr_sftp_data_deleted",
            actor_sub=user,
            req=req,
            owner=user,
            mount_id=_extract_mount_id_from_path(path),
            path=path,
            node_type="file",
        )
    else:
        mount = resolve_path_mount(user, norm_path(path, is_folder=False), is_folder=False)
        if mount:
            _require_s3_mounts_enabled()
            _require_s3_mounts_write_enabled()
            delete_mounted_file(user, path)
        else:
            remove_file(user, path)
    audit_event("filemgr_file_removed", user, req, outcome="success", path=path, **_file_audit_fields(file_path=norm_path(path, is_folder=False), owner=user), **_storage_audit_fields_for_path(path))
    return {"ok": True}


@router.delete("/folder")
def remove_fs_folder(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    _enforce_sftp_mount_flags_for_path(path, operation="write")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="write")
    resolved_provider = resolve_storage_provider(user, path)
    if resolved_provider.backend == "sftp":
        out = resolved_provider.provider.delete(user, path)
        deleted_count = int(out.get("deleted_count") or 0)
        request_id = req.headers.get("X-Request-Id") if req else None
        record_operation_usage(user, path, operation="delete", backend="sftp", request_id=request_id)
    else:
        deleted_count = remove_folder(user, path)
    correlation_id = uuid.uuid4().hex
    audit_event(
        "filemgr_folder_removed",
        user,
        req,
        outcome="success",
        path=path,
        deleted_count=deleted_count,
        **_file_audit_fields(file_path=norm_path(path, is_folder=True), owner=user, correlation_id=correlation_id),
        **_storage_audit_fields_for_path(path),
    )
    return {"ok": True, "deleted_count": deleted_count}


@router.post("/move")
def move_fs_node(
    src: str = Body(..., embed=True),
    dst: str = Body(..., embed=True),
    req: Request = None,
    user: str = Depends(_current_user),
):
    _enforce_sftp_mount_flags_for_path(src, operation="write")
    _enforce_sftp_mount_flags_for_path(dst, operation="write")
    _enforce_sftp_mount_status_for_path(src, owner=user, operation="write")
    _enforce_sftp_mount_status_for_path(dst, owner=user, operation="write")
    src_provider = resolve_storage_provider(user, src)
    dst_provider = resolve_storage_provider(user, dst)
    if src_provider.backend != dst_provider.backend:
        raise HTTPException(status_code=400, detail={"code": "cross_backend_move_not_supported", "message": "moving between native and mounted paths is not supported"})
    if src_provider.backend == "sftp":
        result = src_provider.provider.move(user, src, dst, overwrite=False)
        request_id = req.headers.get("X-Request-Id") if req else None
        record_operation_usage(user, src, operation="move", backend="sftp", request_id=request_id)
        _emit_sftp_mount_audit(
            "filemgr_sftp_data_moved",
            actor_sub=user,
            req=req,
            owner=user,
            mount_id=_extract_mount_id_from_path(src),
            path=src,
            src=src,
            dst=dst,
        )
    else:
        result = move_node(user, src, dst)
    audit_event(
        "filemgr_node_moved",
        user,
        req,
        outcome="success",
        src=result.get("src"),
        dst=result.get("dst"),
        node_type=result.get("type"),
        **_file_audit_fields(file_path=str(result.get("src") or norm_path(src, is_folder=None)), owner=user),
        **_storage_audit_fields_for_move(src, dst),
    )
    return {"ok": True, **result}


@router.post("/move-resume")
def resume_fs_move(inp: MoveCheckpointIn, req: Request = None, user: str = Depends(_current_user)):
    result = resume_move(user, inp.move_id)
    audit_event(
        "filemgr_move_resumed",
        user,
        req,
        outcome="success",
        move_id=inp.move_id,
        moved_now=result.get("moved_now"),
        already_done=result.get("already_done"),
    )
    return {"ok": True, **result}


@router.post("/move-rollback")
def rollback_fs_move(inp: MoveCheckpointIn, req: Request = None, user: str = Depends(_current_user)):
    result = rollback_move(user, inp.move_id)
    audit_event(
        "filemgr_move_rolled_back",
        user,
        req,
        outcome="success",
        move_id=inp.move_id,
        moved_now=result.get("moved_now"),
        already_done=result.get("already_done"),
    )
    return {"ok": True, **result}


@router.post("/rename-file")
def rename_file(
    path: str = Body(..., embed=True),
    new_name: str = Body(..., embed=True),
    req: Request = None,
    user: str = Depends(_current_user),
):
    _enforce_sftp_mount_flags_for_path(path, operation="write")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="write")
    parent, _ = split_parent_name(norm_path(path, is_folder=False))
    dst = parent + new_name
    resolved_provider = resolve_storage_provider(user, path)
    if resolved_provider.backend == "sftp":
        result = resolved_provider.provider.move(user, path, dst, overwrite=False)
        request_id = req.headers.get("X-Request-Id") if req else None
        record_operation_usage(user, path, operation="move", backend="sftp", request_id=request_id)
        _emit_sftp_mount_audit(
            "filemgr_sftp_data_moved",
            actor_sub=user,
            req=req,
            owner=user,
            mount_id=_extract_mount_id_from_path(path),
            path=path,
            src=path,
            dst=dst,
        )
    else:
        result = move_node(user, path, dst)
    audit_event(
        "filemgr_file_renamed",
        user,
        req,
        outcome="success",
        src=result.get("src"),
        dst=result.get("dst"),
    )
    return {"ok": True, **result}


@router.post("/rename-folder")
def rename_folder(
    path: str = Body(..., embed=True),
    new_name: str = Body(..., embed=True),
    req: Request = None,
    user: str = Depends(_current_user),
):
    folder = norm_path(path, is_folder=True)
    parent, _ = split_parent_name(folder)
    dst = parent + new_name + "/"
    resolved_provider = resolve_storage_provider(user, folder)
    if resolved_provider.backend == "sftp":
        result = resolved_provider.provider.move(user, folder, dst, overwrite=False)
        request_id = req.headers.get("X-Request-Id") if req else None
        record_operation_usage(user, folder, operation="move", backend="sftp", request_id=request_id)
        _emit_sftp_mount_audit(
            "filemgr_sftp_data_moved",
            actor_sub=user,
            req=req,
            owner=user,
            mount_id=_extract_mount_id_from_path(folder),
            path=folder,
            src=folder,
            dst=dst,
        )
    else:
        result = move_node(user, folder, dst)
    audit_event(
        "filemgr_folder_renamed",
        user,
        req,
        outcome="success",
        src=result.get("src"),
        dst=result.get("dst"),
    )
    return {"ok": True, **result}


@router.post("/download-zip")
def download_multiple_as_zip(paths: List[str] = Body(...), req: Request = None, user: str = Depends(_current_user)):
    _enforce_sftp_mount_flags_for_paths(paths, operation="read")
    _enforce_sftp_mount_status_for_paths(paths, owner=user, operation="read")
    result = download_zip(user, paths)
    assert_download_allowed(user, requested_bytes=0)
    if isinstance(result, tuple):
        zip_stream, file_count = result
    else:
        zip_stream = result
        file_count = None
    correlation_id = uuid.uuid4().hex
    audit_event(
        "filemgr_zip_downloaded",
        user,
        req,
        outcome="success",
        count=file_count or 0,
        paths=paths,
        **_file_audit_fields(owner=user, correlation_id=correlation_id),
    )

    def metered_zip_stream():
        sent = 0
        for chunk in zip_stream:
            sent += len(chunk)
            yield chunk
        request_id = req.headers.get("X-Request-Id") if req else None
        record_download_usage(user, "/_zip/download.zip", sent, source="download_zip", request_id=request_id)

    return StreamingResponse(
        metered_zip_stream(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="download.zip"'},
    )


@router.post("/upload-zip")
def upload_zip_and_extract(
    dest_folder: str = Query("/", description="Folder to extract into"),
    zip_file: UploadFile = File(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    _enforce_sftp_mount_flags_for_path(dest_folder, operation="write")
    _enforce_sftp_mount_status_for_path(dest_folder, owner=user, operation="write")
    created = upload_zip(user, dest_folder, zip_file)
    audit_event(
        "filemgr_zip_uploaded",
        user,
        req,
        outcome="success",
        dest_folder=dest_folder,
        count=len(created),
    )
    return {"ok": True, "created": created, "count": len(created)}


@router.post("/upload-archive")
def upload_archive_and_extract(
    dest_folder: str = Query("/", description="Folder to extract into"),
    archive_file: UploadFile = File(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    _enforce_sftp_mount_flags_for_path(dest_folder, operation="write")
    _enforce_sftp_mount_status_for_path(dest_folder, owner=user, operation="write")
    created = upload_archive(user, dest_folder, archive_file)
    audit_event(
        "filemgr_archive_uploaded",
        user,
        req,
        outcome="success",
        dest_folder=dest_folder,
        count=len(created),
        filename=archive_file.filename,
    )
    return {"ok": True, "created": created, "count": len(created)}


@router.post("/share")
def share_fs_node(
    path: str = Body(..., embed=True),
    to_user: str = Body(..., embed=True),
    permission: Annotated[str, Body(embed=True)] = "read",
    expires_at: Annotated[Optional[str], Body(embed=True)] = None,
    signature_packet_id: Annotated[Optional[str], Body(embed=True)] = None,
    req: Request = None,
    user: str = Depends(_current_user),
):
    _enforce_sftp_mount_flags_for_path(path, operation="share")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="share")
    _enforce_sftp_mount_share_policy(path)
    share_node(
        user,
        path,
        to_user,
        permission=permission,
        expires_at=expires_at,
        signature_packet_id=signature_packet_id,
    )
    audit_event(
        "filemgr_node_shared",
        user,
        req,
        outcome="success",
        path=path,
        shared_with=to_user,
        permission=permission,
        expires_at=expires_at,
        signature_packet_id=signature_packet_id,
        **_file_audit_fields(file_path=norm_path(path, is_folder=None), owner=user),
    )
    return {"ok": True}


@router.post("/unshare")
def unshare_fs_node(
    path: str = Body(..., embed=True),
    to_user: str = Body(..., embed=True),
    req: Request = None,
    user: str = Depends(_current_user),
):
    _enforce_sftp_mount_flags_for_path(path, operation="share")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="share")
    _enforce_sftp_mount_share_policy(path)
    unshare_node(user, path, to_user)
    audit_event(
        "filemgr_node_unshared",
        user,
        req,
        outcome="success",
        path=path,
        unshared_with=to_user,
        **_file_audit_fields(file_path=norm_path(path, is_folder=None), owner=user),
    )
    return {"ok": True}


@router.get("/shared-with")
def list_shared(path: str = Query(...), user: str = Depends(_current_user)):
    _enforce_sftp_mount_flags_for_path(path, operation="share")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="share")
    _enforce_sftp_mount_share_policy(path)
    return {"path": norm_path(path, is_folder=None), "shared_with": list_shared_with(user, path)}


@router.get("/shared-with-me")
def list_shared_me(user: str = Depends(_current_user)):
    return {"items": list_shared_with_me(user)}


@router.get("/shared-list")
def list_shared_files(
    owner: str = Query(...),
    path: str = Query("/", description="Folder path"),
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    sort_by: str = Query("name", pattern="^(name|updated|size)$"),
    sort_dir: str = Query("asc", pattern="^(asc|desc)$"),
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="read")
    folder = norm_path(path, is_folder=True)
    cursor_payload = _decode_cursor(cursor)
    scan_forward = sort_dir == "asc"
    if sort_by == "name":
        if cursor_payload and cursor_payload.get("mode") not in {"ddb", None}:
            raise HTTPException(status_code=400, detail="invalid cursor")
        cursor_key = cursor_payload.get("key") if cursor_payload else None
        items, next_cursor = list_children_page(
            owner,
            folder,
            limit=limit,
            cursor=cursor_key,
            scan_forward=scan_forward,
        )
    else:
        if cursor_payload and cursor_payload.get("mode") != "offset":
            raise HTTPException(status_code=400, detail="invalid cursor")
        items = list_children(owner, folder)
        next_cursor = None
    out = []
    for it in items:
        if it.get("parent") == folder:
            out.append({
                "path": it["path"],
                "type": it["type"],
                "name": it["name"],
                "size": it.get("size"),
                "updated_at": it.get("updated_at"),
                "content_type": it.get("content_type"),
                **encryption_info_from_node(it),
                **preview_capability_from_node(it),
            })
    if sort_by == "updated":
        out.sort(key=lambda x: (x["type"] != "folder", x.get("updated_at") or ""), reverse=not scan_forward)
    elif sort_by == "size":
        out.sort(
            key=lambda x: (x["type"] != "folder", x.get("size") or 0, (x.get("name") or "").lower()),
            reverse=not scan_forward,
        )
    elif sort_by == "name":
        if cursor_payload and cursor_payload.get("mode") == "offset":
            raise HTTPException(status_code=400, detail="invalid cursor")
        if not next_cursor:
            return {"path": folder, "items": out, "cursor": None}
        return {"path": folder, "items": out, "cursor": _encode_cursor({"mode": "ddb", "key": next_cursor})}

    offset = 0
    if cursor_payload:
        offset = int(cursor_payload.get("offset", 0) or 0)
    paged = out[offset:offset + limit]
    next_offset = offset + limit
    next_payload = {"mode": "offset", "offset": next_offset} if next_offset < len(out) else None
    return {"path": folder, "items": paged, "cursor": _encode_cursor(next_payload)}


@router.get("/shared-info")
def shared_file_info(
    owner: str = Query(...),
    path: str = Query(...),
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="read")
    p = norm_path(path, is_folder=None)
    it = get_node(owner, p if p.endswith("/") else p)
    encryption_info = encryption_info_from_node(it)
    preview_info = preview_capability_from_node(it)
    return {
        "path": it["path"],
        "type": it["type"],
        "name": it["name"],
        "parent": it.get("parent"),
        "created_at": it.get("created_at"),
        "updated_at": it.get("updated_at"),
        "upload_at": it.get("upload_at"),
        "upload_by": it.get("upload_by"),
        "last_download_at": it.get("last_download_at"),
        "last_download_by": it.get("last_download_by"),
        "size": it.get("size"),
        "duration_seconds": it.get("duration_seconds"),
        "thumbnail": it.get("thumbnail"),
        "content_type": it.get("content_type"),
        "shared": it.get("shared", False),
        **encryption_info,
        **preview_info,
    }


@router.get("/shared-download")
def shared_download_fs_file(
    owner: str = Query(...),
    path: str = Query(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="download_file",
        request_id=(req.headers.get("X-Request-Id") if req else None),
    )
    require_shared_access(user, owner, path, permission="read")
    result = download_file(owner, path)
    assert_file_bundle_access(user, result["node"])
    assert_download_allowed(user, requested_bytes=int(result["node"].get("size") or 0))
    node = result["node"]
    obj = result["object"]
    is_encrypted = bool(node.get("is_encrypted"))
    audit_event(
        "filemgr_file_downloaded",
        user,
        req,
        outcome="success",
        path=node.get("path"),
        size=node.get("size"),
        owner=owner,
        **_file_audit_fields(file_path=str(node.get("path") or norm_path(path, is_folder=False)), owner=owner),
        encrypted_download_attempt=is_encrypted,
        encrypted_shared_access_attempt=is_encrypted,
        share_scope="direct",
    )
    record_filemgr_encryption_event("download_attempt", encrypted=is_encrypted)
    record_filemgr_shared_download(encrypted=is_encrypted, outcome="attempt")

    def gen():
        body = obj["Body"]
        sent = 0
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            sent += len(chunk)
            yield chunk
        request_id = req.headers.get("X-Request-Id") if req else None
        record_download_usage(user, path, sent, source="shared_download", request_id=request_id)

    return StreamingResponse(
        gen(),
        media_type=node.get("content_type", "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{node["name"]}"',
            **({"Content-Length": str(node["size"])} if node.get("size") is not None else {}),
        },
    )


@router.get("/shared-preview")
def shared_preview_fs_file(
    owner: str = Query(...),
    path: str = Query(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="preview_file",
        request_id=(req.headers.get("X-Request-Id") if req else None),
    )
    started = time.perf_counter()
    require_shared_access(user, owner, path, permission="read")
    result = download_file(owner, path)
    assert_file_bundle_access(user, result["node"])
    node = result["node"]
    obj = result["object"]
    preview_info = preview_capability_from_node(node)
    preview_kind = preview_info.get("preview_kind", "none")
    if not is_previewable(node):
        reason = preview_info.get("preview_reason") or "unsupported_type"
        audit_event(
            "filemgr_file_previewed",
            user,
            req,
            outcome="fallback",
            path=node.get("path"),
            size=node.get("size"),
            owner=owner,
            encrypted_shared_access_attempt=bool(node.get("is_encrypted")),
            share_scope="direct",
            preview_kind=preview_kind,
            preview_supported=False,
            preview_reason=reason,
            is_encrypted=bool(node.get("is_encrypted")),
        )
        record_filemgr_preview_attempt(kind=preview_kind, outcome="fallback", reason=reason)
        record_filemgr_preview_fallback(kind=preview_kind, reason=reason)
        record_filemgr_preview_latency(kind=preview_kind, elapsed_seconds=time.perf_counter() - started)
        raise HTTPException(status_code=415, detail="preview not available for this file type")
    audit_event(
        "filemgr_file_previewed",
        user,
        req,
        outcome="success",
        path=node.get("path"),
        size=node.get("size"),
        owner=owner,
        encrypted_shared_access_attempt=bool(node.get("is_encrypted")),
        share_scope="direct",
        preview_kind=preview_kind,
        preview_supported=True,
        preview_reason="none",
        is_encrypted=bool(node.get("is_encrypted")),
    )
    record_filemgr_preview_attempt(kind=preview_kind, outcome="success", reason="none")
    record_filemgr_preview_bytes(kind=preview_kind, nbytes=int(node.get("size") or 0))
    record_filemgr_preview_latency(kind=preview_kind, elapsed_seconds=time.perf_counter() - started)

    def gen():
        body = obj["Body"]
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            yield chunk

    return StreamingResponse(
        gen(),
        media_type=node.get("content_type", "application/octet-stream"),
        headers={"Content-Disposition": f'inline; filename="{node["name"]}"'},
    )


@router.get("/shared-thumbnail")
def shared_thumbnail_fs_file(
    owner: str = Query(...),
    path: str = Query(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    started = time.perf_counter()
    require_shared_access(user, owner, path, permission="read")
    result = download_thumbnail(owner, path)
    node = result["node"]
    preview_info = preview_capability_from_node(node)
    preview_kind = preview_info.get("preview_kind", "none")
    if node.get("is_encrypted"):
        reason = preview_info.get("preview_reason") or "encrypted"
        audit_event(
            "filemgr_file_thumbnailed",
            user,
            req,
            outcome="fallback",
            path=node.get("path"),
            size=node.get("size"),
            preview_kind=preview_kind,
            preview_supported=False,
            preview_reason=reason,
            is_encrypted=True,
        )
        record_filemgr_preview_attempt(kind=preview_kind, outcome="fallback", reason=reason)
        record_filemgr_preview_fallback(kind=preview_kind, reason=reason)
        record_filemgr_preview_latency(kind=preview_kind, elapsed_seconds=time.perf_counter() - started)
        raise HTTPException(status_code=415, detail="thumbnail not available for encrypted files")
    thumb = result["thumbnail"]
    obj = result["object"]
    audit_event(
        "filemgr_file_thumbnailed",
        user,
        req,
        outcome="success",
        path=node.get("path"),
        size=node.get("size"),
        preview_kind=preview_kind,
        preview_supported=True,
        preview_reason="none",
        is_encrypted=bool(node.get("is_encrypted")),
    )
    record_filemgr_preview_attempt(kind=preview_kind, outcome="success", reason="none")
    record_filemgr_preview_bytes(kind=preview_kind, nbytes=int(node.get("size") or 0))
    record_filemgr_preview_latency(kind=preview_kind, elapsed_seconds=time.perf_counter() - started)

    def gen():
        body = obj["Body"]
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            yield chunk

    return StreamingResponse(
        gen(),
        media_type=thumb.get("content_type", "image/jpeg"),
        headers={"Content-Disposition": f'inline; filename="{node["name"]}_thumb.jpg"'},
    )


@router.delete("/shared-file")
def remove_shared_file(
    owner: str = Query(...),
    path: str = Query(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="write")
    remove_file(owner, path)
    audit_event("filemgr_file_removed", user, req, outcome="success", path=path, owner=owner)
    return {"ok": True}


@router.delete("/shared-folder")
def remove_shared_folder(
    owner: str = Query(...),
    path: str = Query(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="write")
    deleted_count = remove_folder(owner, path)
    audit_event(
        "filemgr_folder_removed",
        user,
        req,
        outcome="success",
        path=path,
        deleted_count=deleted_count,
        owner=owner,
    )
    return {"ok": True, "deleted_count": deleted_count}


@router.post("/shared-move")
def move_shared_node(
    owner: str = Query(...),
    src: str = Body(...),
    dst: str = Body(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    access = require_shared_access(user, owner, src, permission="write")
    shared_root = access["path"]
    if shared_root.endswith("/") and not norm_path(dst, is_folder=None).startswith(shared_root):
        raise HTTPException(status_code=403, detail="destination must be within shared root")
    result = move_node(owner, src, dst)
    audit_event(
        "filemgr_node_moved",
        user,
        req,
        outcome="success",
        src=src,
        dst=dst,
        owner=owner,
    )
    return {"ok": True, **result}


@router.post("/shared-rename-file")
def rename_shared_file(
    owner: str = Query(...),
    path: str = Body(...),
    new_name: str = Body(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="write")
    result = move_node(owner, path, norm_path(path, is_folder=False).rsplit("/", 1)[0] + "/" + new_name)
    audit_event("filemgr_file_renamed", user, req, outcome="success", path=path, new_name=new_name, owner=owner)
    return {"ok": True, **result}


@router.post("/shared-rename-folder")
def rename_shared_folder(
    owner: str = Query(...),
    path: str = Body(...),
    new_name: str = Body(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="write")
    current = norm_path(path, is_folder=True)
    parent = current.rstrip("/").rsplit("/", 1)[0] + "/"
    dst = norm_path(parent + new_name + "/", is_folder=True)
    result = move_node(owner, current, dst)
    audit_event("filemgr_folder_renamed", user, req, outcome="success", path=path, new_name=new_name, owner=owner)
    return {"ok": True, **result}


@router.post("/shared-folder")
def create_shared_folder(
    owner: str = Query(...),
    path: str = Body(..., embed=True),
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="write")
    folder = create_empty_folder(owner, path)
    audit_event("filemgr_folder_created", user, req, outcome="success", path=folder, owner=owner)
    return {"ok": True, "path": folder}


@router.post("/shared-upload")
def upload_shared_file(
    owner: str = Query(...),
    path: str = Query(..., description="Full file path, e.g. /docs/a.txt"),
    file: UploadFile = File(...),
    encrypted: bool = Query(False),
    enc_meta: Optional[str] = Query(default=None, description="JSON encryption metadata"),
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="write")
    encrypted_flag = encrypted if isinstance(encrypted, bool) else False
    encryption_meta = _parse_encryption_meta(enc_meta) if encrypted_flag else None
    result = upload_file(owner, path, file, encryption_meta=encryption_meta)
    audit_event(
        "filemgr_file_uploaded",
        user,
        req,
        outcome="success",
        path=result.get("path"),
        size=result.get("size"),
        content_type=file.content_type,
        owner=owner,
        encrypted_upload=encrypted_flag,
    )
    record_filemgr_encryption_event("upload", encrypted=encrypted_flag)
    return {"ok": True, **result}


@router.post("/client-telemetry")
def file_crypto_client_telemetry(inp: FileCryptoTelemetryIn, req: Request = None, user: str = Depends(_current_user)):
    if inp.event == "decrypt_failure":
        reason = inp.reason or "crypto_error"
        audit_event(
            "filemgr_client_decrypt_failure",
            user,
            req,
            outcome="failure",
            reason=reason,
            path=inp.path,
            remembered_password_used=inp.remembered_password_used,
        )
        record_filemgr_encryption_event("decrypt_failure", encrypted=True, reason=reason)
        return {"ok": True}

    if inp.event == "hover_play_start":
        audit_event("filemgr_preview_hover_play_start", user, req, outcome="success", path=inp.path)
        record_filemgr_preview_hover_play_start()
        return {"ok": True}

    if inp.event == "hover_play_failure":
        reason = inp.reason or "unknown"
        audit_event("filemgr_preview_hover_play_failure", user, req, outcome="failure", reason=reason, path=inp.path)
        record_filemgr_preview_hover_play_failure(reason=reason)
        return {"ok": True}

    audit_event(
        "filemgr_client_remembered_password_used",
        user,
        req,
        outcome="success",
        path=inp.path,
        remembered_password_used=inp.remembered_password_used,
    )
    record_filemgr_encryption_event("remembered_password_used", encrypted=True)
    return {"ok": True}


@router.post("/shared-upload-zip")
def upload_shared_zip(
    owner: str = Query(...),
    dest_folder: str = Query(..., description="Destination folder"),
    zip_file: UploadFile = File(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, dest_folder, permission="write")
    created = upload_zip(owner, dest_folder, zip_file)
    audit_event(
        "filemgr_zip_uploaded",
        user,
        req,
        outcome="success",
        path=dest_folder,
        count=len(created),
        owner=owner,
    )
    return {"ok": True, "paths": created}


@router.post("/shared-upload-archive")
def upload_shared_archive(
    owner: str = Query(...),
    dest_folder: str = Query(..., description="Destination folder"),
    archive_file: UploadFile = File(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, dest_folder, permission="write")
    created = upload_archive(owner, dest_folder, archive_file)
    audit_event(
        "filemgr_archive_uploaded",
        user,
        req,
        outcome="success",
        path=dest_folder,
        count=len(created),
        owner=owner,
        filename=archive_file.filename,
    )
    return {"ok": True, "paths": created}


@router.post("/shared-download-zip")
def shared_download_zip(
    owner: str = Query(...),
    paths: List[str] = Body(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    for path in paths:
        require_shared_access(user, owner, path, permission="read")
    zf, count = download_zip(owner, paths)
    correlation_id = uuid.uuid4().hex
    assert_download_allowed(user, requested_bytes=0)
    audit_event(
        "filemgr_download_zip",
        user,
        req,
        outcome="success",
        path="(zip)",
        count=count,
        owner=owner,
        paths=paths,
        **_file_audit_fields(owner=owner, correlation_id=correlation_id),
    )
    def metered_shared_zip_stream():
        sent = 0
        for chunk in zf:
            sent += len(chunk)
            yield chunk
        request_id = req.headers.get("X-Request-Id") if req else None
        record_download_usage(user, "/_zip/shared-download.zip", sent, source="shared_download_zip", request_id=request_id)

    return StreamingResponse(
        metered_shared_zip_stream(),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=download.zip"},
    )


@router.get("/usage/summary")
def usage_summary(
    period: Optional[str] = Query(default=None, description="Billing period YYYY-MM in UTC"),
    user: str = Depends(_current_user),
):
    return get_usage_summary(user, period_id=period)


@router.get("/usage/daily")
def usage_daily(
    from_day: Optional[str] = Query(default=None, alias="from", description="Start date YYYY-MM-DD UTC"),
    to_day: Optional[str] = Query(default=None, alias="to", description="End date YYYY-MM-DD UTC"),
    user: str = Depends(_current_user),
):
    return get_usage_daily(user, from_day=from_day, to_day=to_day)


@router.get("/usage/storage")
def usage_storage(
    top_n: int = Query(default=10, ge=1, le=100),
    user: str = Depends(_current_user),
):
    return get_usage_storage(user, top_n=top_n)


@router.post("/purge-deleted")
def purge_deleted(req: Request = None, ctx: Dict[str, Any] = Depends(_admin_or_root_ctx)):
    user = ctx["user_sub"]
    result = purge_deleted_nodes(user)
    audit_event(
        "filemgr_purge_deleted",
        user,
        req,
        outcome="success",
        purged=result.get("purged"),
        skipped=result.get("skipped"),
        errors=result.get("errors"),
    )
    return {"ok": True, **result}
