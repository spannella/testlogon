from __future__ import annotations

import base64
import json
import os
import re
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
    create_empty_folder_dispatched,
    download_file,
    download_file_dispatched,
    download_thumbnail,
    download_zip,
    is_previewable,
    list_children,
    list_children_dispatched,
    list_children_page,
    list_mounted_directory,
    download_mounted_file,
    resolve_path_mount,
    list_shared_with,
    list_shared_with_me,
    move_node,
    move_node_dispatched,
    resume_move,
    rollback_move,
    norm_path,
    remove_file,
    remove_file_dispatched,
    delete_mounted_file,
    remove_folder,
    remove_folder_dispatched,
    search_prefix,
    share_node,
    unshare_node,
    split_parent_name,
    upload_file,
    upload_file_dispatched,
    upload_mounted_file,
    upload_zip,
    upload_archive,
    get_node,
    get_node_dispatched,
    search_text,
    presign_upload,
    register_presigned_upload,
    purge_deleted_nodes,
    require_shared_access,
    admin_search_metadata,
    encryption_info_from_node,
    preview_capability_from_node,
    record_download_usage,
    resolve_path_dispatch,
    record_upload_usage,
    record_operation_usage,
    assert_upload_allowed,
    get_usage_summary,
    get_usage_daily,
    get_usage_storage,
    assert_download_allowed,
    assert_mount_write_allowed,
)
from app.services.alerts import audit_event
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from app.metrics import (
    record_filemgr_provider_operation,
    record_filemgr_provider_auth_failure,
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
from app.services.file_providers import default_provider_registry
from app.services.mounts_store import (
    create_mount,
    delete_mount,
    get_mount as get_mount_store,
    list_mounts as list_mounts_store,
    reconcile_mount_health,
    reconcile_mounts,
    set_mount_status,
    update_mount as update_mount_store,
)
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
from app.services.filemanager_provider import build_default_dispatcher
from app.services.filemanager_mount_secrets import (
    create_mount_with_secret,
    get_mount_secret,
    revoke_mount_secret,
    rotate_mount_secret,
)
from app.services.filemanager_mount_onboarding import (
    clear_onboarding_sessions_for_mount,
    create_onboarding_session,
    get_onboarding_session,
    update_onboarding_session,
)
from app.services.rate_limit import (
    clear_lockout,
    enforce_lockout,
    rate_limit_filemgr_mount_onboarding,
    rate_limit_filemgr_mount_revoke,
    rate_limit_filemgr_mount_rotate,
    rate_limit_filemgr_mount_verify,
    record_lockout_failure,
)
from app.services.filemanager_mounts import (
    apply_mount_health_signal,
    clear_mount_status_override,
    get_mount,
    list_mounts,
    set_mount_status_override,
    update_mount,
)
from app.services.filemanager_mount_flags import enforce_icloud_mount_enabled
from app.core.normalize import client_ip_from_request
from app.core.crypto import sha256_str

router = APIRouter(prefix="/v1/fs", tags=["filemanager"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])
_storage_dispatcher = build_default_dispatcher()


def _request_tenant_id(req: Optional[Request]) -> Optional[str]:
    if req is None:
        return None
    return (req.headers.get("X-Tenant-Id") or req.headers.get("x-tenant-id") or "").strip() or None


def _enforce_icloud_feature_for_request(user: str, req: Optional[Request]) -> None:
    enforce_icloud_mount_enabled(user_sub=user, tenant_id=_request_tenant_id(req))


def _storage_context(user: str, path: str, req: Optional[Request] = None) -> tuple[str, Optional[str], bool]:
    resolution = _storage_dispatcher.resolve(user, path)
    if not resolution:
        return "s3", None, False
    provider = str(resolution.provider or "s3")
    if provider == "icloud":
        _enforce_icloud_feature_for_request(user, req)
    mount_id = str(resolution.mount_id or "") or None
    return provider, mount_id, True


def _provider_error_class(exc: Optional[HTTPException]) -> str:
    if exc is None:
        return "none"
    if exc.status_code == 401:
        return "auth_failed"
    if exc.status_code == 429:
        return "throttled"
    if exc.status_code >= 500:
        return "server_error"
    return "client_error"

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


async def _current_user(request: Request, auth_user: Optional[AuthenticatedUser] = Depends(get_authenticated_user)) -> str:
    principal = getattr(request.state, "api_key_principal", None)
    if isinstance(principal, dict) and str(principal.get("user_sub") or "").strip():
        return str(principal["user_sub"])
    ctx = await require_ui_session(request=request, auth_user=auth_user)
    return str(ctx["user_sub"])


def _require_google_drive_mounts_enabled() -> None:
    if bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        return
    raise HTTPException(
        status_code=501,
        detail={
            "code": "feature_not_enabled",
            "feature": "filemgr_google_drive_mounts",
            "message": "Google Drive mounts are not enabled in this environment",
        },
    )


def _enforce_mount_write_paths(owner: str, *paths: str, action: str) -> None:
    for path in paths:
        if isinstance(path, str) and path.strip():
            assert_mount_write_allowed(owner, path, action=action)


def _move_node_for_owner(owner: str, src: str, dst: str) -> Dict[str, Any]:
    if bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        return move_node_dispatched(owner, src, dst)
    return move_node(owner, src, dst)


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


class ICloudInitiateIn(BaseModel):
    mount_path: str = Field(default="/icloud/", description="Mount path prefix, e.g. /icloud/")
    apple_id: str = Field(..., min_length=3, max_length=320, description="Apple account identifier")
    auth_mode: str = Field(..., pattern="^(session_token|app_password)$")
    auth_value: str = Field(..., min_length=1, max_length=4096, description="Sensitive auth artifact")
    device_label: Optional[str] = Field(default=None, max_length=128)


class ICloudInitiateOut(BaseModel):
    onboarding_session_id: str
    mount_id: str
    status: str
    next_action: str
    expires_at: str


def _validate_icloud_apple_id(value: str) -> str:
    apple_id = str(value or "").strip()
    if "@" not in apple_id or apple_id.startswith("@") or apple_id.endswith("@"):
        raise HTTPException(status_code=400, detail="invalid apple_id")
    return apple_id


def _validate_icloud_auth_artifact(*, auth_mode: str, auth_value: str) -> str:
    val = str(auth_value or "").strip()
    if not val:
        raise HTTPException(status_code=400, detail="invalid auth_value")

    if auth_mode == "session_token":
        if len(val) < 16:
            raise HTTPException(status_code=400, detail="invalid auth_value")
        if "\n" in val or "\r" in val:
            raise HTTPException(status_code=400, detail="invalid auth_value")
        return val

    # Apple app-specific passwords are 16 lowercase letters displayed as 4 blocks.
    app_pw = val.replace("-", "")
    if not re.fullmatch(r"[a-z]{16}", app_pw):
        raise HTTPException(status_code=400, detail="invalid auth_value")
    return val


def _session_verify_attempt_limit() -> int:
    return max(1, int(getattr(S, "filemgr_mount_verify_session_max_attempts", 5)))


class ICloudVerifyIn(BaseModel):
    onboarding_session_id: str = Field(..., min_length=8, max_length=128)
    mfa_code: Optional[str] = Field(default=None, min_length=4, max_length=16)


class ICloudVerifyOut(BaseModel):
    onboarding_session_id: str
    mount_id: str
    status: str
    next_action: str
    outcome: str


class ICloudRotateIn(BaseModel):
    mount_id: str = Field(..., min_length=2, max_length=128)
    auth_mode: str = Field(..., pattern="^(session_token|app_password)$")
    auth_value: str = Field(..., min_length=1, max_length=4096)
    device_label: Optional[str] = Field(default=None, max_length=128)


class ICloudRotateOut(BaseModel):
    mount_id: str
    secret_ref: str
    status: str


class ICloudRevokeIn(BaseModel):
    mount_id: str = Field(..., min_length=2, max_length=128)


class ICloudRevokeOut(BaseModel):
    mount_id: str
    status: str
    sessions_cleared: int


class FileMountOut(BaseModel):
    mount_id: str
    provider: str
    mount_path: str
    status: str
    updated_at: Optional[str] = None
    can_rotate: bool
    can_reconnect: bool
    can_disconnect: bool


class MountStatusOverrideIn(BaseModel):
    status: str = Field(..., pattern="^(active|degraded|reauth_required|revoked)$")
    clear_override: bool = Field(default=False)


class FileCryptoTelemetryIn(BaseModel):
    event: str = Field(..., pattern="^(decrypt_failure|remembered_password_used|hover_play_start|hover_play_failure)$")
    path: Optional[str] = Field(default=None)
    reason: Optional[str] = Field(default=None, pattern="^(wrong_password|corrupted_metadata|crypto_error|playback_error|autoplay_blocked|unsupported_capability|unknown)?$")
    remembered_password_used: bool = Field(default=False)


class MountCreateIn(BaseModel):
    provider: str = Field(default="google_drive", min_length=1, max_length=64)
    mount_path: str = Field(..., min_length=1, max_length=2048)
    provider_root_ref: str = Field(..., min_length=1, max_length=2048)
    mode: str = Field(default="read_only", pattern="^(read_only|read_write)$")


class MountUpdateIn(BaseModel):
    mount_path: Optional[str] = Field(default=None, min_length=1, max_length=2048)
    provider_root_ref: Optional[str] = Field(default=None, min_length=1, max_length=2048)
    mode: Optional[str] = Field(default=None, pattern="^(read_only|read_write)$")


class MountOut(BaseModel):
    mount_id: str
    owner: str
    provider: str
    mount_path: str
    provider_root_ref: str
    mode: str
    status: str = "active"
    status_reason: Optional[str] = None
    reconnect_required: bool = False
    last_checked_at: Optional[str] = None
    created_at: str
    updated_at: str


class MountListOut(BaseModel):
    items: List[MountOut] = Field(default_factory=list)


class DeleteMountOut(BaseModel):
    ok: bool
    deleted: bool


class MountReconcileOut(BaseModel):
    owner: str
    mount_id: str
    provider: str
    mount_path: str
    provider_root_ref: str
    stale: bool
    issues: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    status: str
    reconnect_required: bool = False


class MountReconcileListOut(BaseModel):
    items: List[MountReconcileOut] = Field(default_factory=list)


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
    req: Request = None,
    user: str = Depends(_current_user),
):
    started = time.perf_counter()
    provider, mount_id, is_mounted = _storage_context(user, path, req=req)
    outcome = "success"
    err: Optional[HTTPException] = None
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
    dispatch = resolve_path_dispatch(user, folder)
    if dispatch["kind"] == "mount":
        if cursor_payload and cursor_payload.get("mode") != "offset":
            raise HTTPException(status_code=400, detail="invalid cursor")
        items = list_children_dispatched(user, folder)
        next_cursor = None
    else:
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

    if dispatch["kind"] != "mount":
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
    # Defensive de-dup by path: a duplicate folder node must never reach the client's path-keyed list
    # (Compose LazyColumn crashes with "key already used"). Keep first occurrence, preserve order.
    _seen_paths: set = set()
    _deduped: list = []
    for _it in out:
        _k = str(_it.get("path") or "")
        if _k and _k in _seen_paths:
            continue
        _seen_paths.add(_k)
        _deduped.append(_it)
    out = _deduped
    next_payload_ddb = {"mode": "ddb", "key": next_cursor} if next_cursor else None
    return {"path": folder, "items": out, "cursor": _encode_cursor(next_payload_ddb)}


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
    elif bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        it = get_node_dispatched(user, p if p.endswith("/") else p)
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


# ── iCloud revoke ─────────────────────────────────────────────────────────
# Registered BEFORE the parametric ``{mount_id}/revoke`` route so that
# ``/mounts/icloud/revoke`` is matched as a static path rather than being
# captured by the SFTP handler with ``mount_id="icloud"``.
@router.post("/mounts/icloud/revoke", response_model=ICloudRevokeOut)
def revoke_icloud_mount_credentials(inp: ICloudRevokeIn, req: Request = None, user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="mount_icloud_revoke",
        request_id=(req.headers.get("X-Request-Id") if req else inp.mount_id),
    )
    _enforce_icloud_feature_for_request(user, req)
    try:
        rate_limit_filemgr_mount_revoke(user, client_ip_from_request(req))
    except HTTPException as exc:
        if exc.status_code == 429:
            audit_event(
                "filemgr_mount_icloud_revoke",
                user,
                req,
                outcome="failure",
                provider="icloud",
                mount_id=inp.mount_id,
                reason="rate_limited",
                status_code=429,
            )
        raise
    try:
        revoked = revoke_mount_secret(owner_user_sub=user, mount_id=inp.mount_id)
        sessions_cleared = clear_onboarding_sessions_for_mount(user_sub=user, mount_id=inp.mount_id)
    except HTTPException as exc:
        audit_event(
            "filemgr_mount_icloud_revoke",
            user,
            req,
            outcome="failure",
            provider="icloud",
            mount_id=inp.mount_id,
            reason="revoke_failed",
            status_code=exc.status_code,
        )
        raise
    audit_event(
        "filemgr_mount_icloud_revoke",
        user,
        req,
        outcome="success",
        provider="icloud",
        mount_id=inp.mount_id,
        mount_status=revoked.get("mount_status") or "revoked",
        sessions_cleared=sessions_cleared,
    )
    return ICloudRevokeOut(
        mount_id=inp.mount_id,
        status=str(revoked.get("mount_status") or "revoked"),
        sessions_cleared=int(sessions_cleared),
    )


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
    elif bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        _enforce_mount_write_paths(user, path, action="create_folder")
        folder = create_empty_folder_dispatched(user, path)
    else:
        folder = create_empty_folder(user, path)
    audit_event("filemgr_folder_created", user, req, outcome="success", path=folder, **_storage_audit_fields_for_path(path))
    return {"ok": True, "path": folder}


@router.post("/upload")
def upload_fs_file(
    path: str = Query(..., description="Full file path, e.g. /docs/a.txt"),
    file: UploadFile = File(...),
    encrypted: bool = Query(False),
    overwrite: bool = Query(False),
    enc_meta: Optional[str] = Query(default=None, description="JSON encryption metadata"),
    req: Request = None,
    user: str = Depends(_current_user),
):
    started = time.perf_counter()
    provider, mount_id, is_mounted = _storage_context(user, path, req=req)
    outcome = "success"
    err: Optional[HTTPException] = None
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="upload_file",
        request_id=(req.headers.get("X-Request-Id") if req else None),
    )
    _enforce_sftp_mount_flags_for_path(path, operation="write")
    _enforce_sftp_mount_status_for_path(path, owner=user, operation="write")
    encrypted_flag = encrypted if isinstance(encrypted, bool) else False
    encryption_meta = _parse_encryption_meta(enc_meta) if encrypted_flag else None
    overwrite_flag = overwrite if isinstance(overwrite, bool) else False
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
    elif bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        _enforce_mount_write_paths(user, path, action="upload_file")
        result = upload_file_dispatched(user, path, file, overwrite=overwrite_flag, encryption_meta=encryption_meta)
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


@router.post("/batch-upload")
def batch_upload(
    files: List[UploadFile] = File(...),
    target_path: str = Query(..., description="Target folder path, e.g. /docs/"),
    user: str = Depends(_current_user),
):
    """Upload multiple files in a single request (up to 20)."""
    if len(files) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 files per batch")

    total_size = 0
    for f in files:
        if f.size is not None:
            total_size += f.size

    if total_size > 500 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Total upload size exceeds 500MB")

    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    uploaded: list[dict] = []
    failed: list[dict] = []

    for f in files:
        try:
            dest = target_path.rstrip("/") + "/" + (f.filename or "unnamed")
            from app.services.filemanager import upload_file as svc_upload_file
            result = svc_upload_file(
                user=user,
                path=dest,
                file=f,
            )
            uploaded.append({"path": dest, "name": f.filename or "unnamed", "size": result.get("size", 0)})
        except Exception as exc:
            failed.append({"name": f.filename or "unnamed", "error": str(exc)})

    return {"uploaded": uploaded, "failed": failed}


@router.post("/presign-upload", response_model=PresignUploadOut)
def presign_fs_upload(inp: PresignUploadIn, user: str = Depends(_current_user)):
    _enforce_sftp_mount_flags_for_path(inp.path, operation="write")
    _enforce_sftp_mount_status_for_path(inp.path, owner=user, operation="write")
    mount = resolve_path_mount(user, norm_path(inp.path, is_folder=False), is_folder=False)
    if mount:
        _require_s3_mounts_enabled()
        _require_s3_mounts_write_enabled()
        raise HTTPException(status_code=400, detail="mounted presign upload not supported")
    _enforce_mount_write_paths(user, inp.path, action="presign_upload")
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
    _enforce_mount_write_paths(user, inp.path, action="complete_upload")
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




@router.get("/mounts", response_model=List[FileMountOut])
def list_file_mounts(user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(user=user, action="mount_list")
    _enforce_icloud_feature_for_request(user, None)
    items = list_mounts(owner_user_sub=user)
    out: List[FileMountOut] = []
    for mount in items:
        status = str(mount.get("status") or "")
        provider = str(mount.get("provider") or "")
        is_icloud = provider == "icloud"
        can_rotate = is_icloud and status in {"active", "degraded", "reauth_required"}
        can_reconnect = is_icloud and status in {"degraded", "reauth_required", "revoked", "revocation_failed"}
        can_disconnect = status in {"pending", "active", "degraded", "reauth_required", "revoking", "revocation_failed"}
        out.append(
            FileMountOut(
                mount_id=str(mount.get("mount_id") or ""),
                provider=provider,
                mount_path=str(mount.get("mount_path") or ""),
                status=status,
                updated_at=mount.get("updated_at"),
                can_rotate=can_rotate,
                can_reconnect=can_reconnect,
                can_disconnect=can_disconnect,
            )
        )
    return out

@router.post("/mounts/{mount_id}/status-override", response_model=FileMountOut)
def set_file_mount_status_override(
    mount_id: str,
    inp: MountStatusOverrideIn,
    req: Request = None,
    user: str = Depends(_current_user),
):
    _enforce_filemanager_internal_entitlement(user=user, action="mount_status_override")
    _enforce_icloud_feature_for_request(user, req)
    if inp.clear_override:
        mount = clear_mount_status_override(owner_user_sub=user, mount_id=mount_id, target_status=inp.status)
    else:
        mount = set_mount_status_override(owner_user_sub=user, mount_id=mount_id, status=inp.status)
    status = str(mount.get("status") or "")
    provider = str(mount.get("provider") or "")
    is_icloud = provider == "icloud"
    return FileMountOut(
        mount_id=str(mount.get("mount_id") or ""),
        provider=provider,
        mount_path=str(mount.get("mount_path") or ""),
        status=status,
        updated_at=mount.get("updated_at"),
        can_rotate=is_icloud and status in {"active", "degraded", "reauth_required"},
        can_reconnect=is_icloud and status in {"degraded", "reauth_required", "revoked", "revocation_failed"},
        can_disconnect=status in {"pending", "active", "degraded", "reauth_required", "revoking", "revocation_failed"},
    )


@router.post("/mounts/icloud/initiate", response_model=ICloudInitiateOut)
def initiate_icloud_mount(inp: ICloudInitiateIn, req: Request = None, user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="mount_icloud_initiate",
        request_id=(req.headers.get("X-Request-Id") if req else None),
    )
    _enforce_icloud_feature_for_request(user, req)
    rate_limit_filemgr_mount_onboarding(user, client_ip_from_request(req))

    apple_id = _validate_icloud_apple_id(inp.apple_id)
    auth_value = _validate_icloud_auth_artifact(auth_mode=inp.auth_mode, auth_value=inp.auth_value)

    payload = {
        "apple_id": apple_id,
        "auth_mode": inp.auth_mode,
        "auth_value": auth_value,
        "device_label": inp.device_label,
    }
    try:
        mount = create_mount_with_secret(
            owner_user_sub=user,
            provider="icloud",
            mount_path=inp.mount_path,
            secret_payload=payload,
            status="pending",
        )
    except HTTPException as exc:
        # Keep outbound error details generic to avoid exposing sensitive auth artifacts.
        if exc.status_code >= 500:
            raise HTTPException(status_code=502, detail="unable to initiate iCloud mount onboarding") from exc
        raise
    out = create_onboarding_session(user_sub=user, mount_id=mount["mount_id"], provider="icloud", next_action="verify")
    audit_event(
        "filemgr_mount_icloud_initiated",
        user,
        req,
        outcome="success",
        provider="icloud",
        mount_id=mount.get("mount_id"),
        mount_path=mount.get("mount_path"),
        onboarding_session_id=out.get("onboarding_session_id"),
        apple_id_hash=sha256_str(apple_id.lower()),
    )
    return ICloudInitiateOut(**out)


@router.post("/mounts/icloud/verify", response_model=ICloudVerifyOut)
def verify_icloud_mount(inp: ICloudVerifyIn, req: Request = None, user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="mount_icloud_verify",
        request_id=(req.headers.get("X-Request-Id") if req else inp.onboarding_session_id),
    )
    _enforce_icloud_feature_for_request(user, req)
    ip = client_ip_from_request(req)
    try:
        enforce_lockout(user, ip, "filemgr_mount_verify")
    except HTTPException as exc:
        if exc.status_code == 429:
            audit_event(
                "filemgr_mount_icloud_verify",
                user,
                req,
                outcome="failure",
                reason="lockout",
                provider="icloud",
                onboarding_session_id=inp.onboarding_session_id,
                status_code=429,
            )
        raise
    try:
        rate_limit_filemgr_mount_verify(user, ip)
    except HTTPException as exc:
        if exc.status_code == 429:
            audit_event(
                "filemgr_mount_icloud_verify",
                user,
                req,
                outcome="failure",
                reason="rate_limited",
                provider="icloud",
                onboarding_session_id=inp.onboarding_session_id,
                status_code=429,
            )
        raise

    session = get_onboarding_session(user_sub=user, onboarding_session_id=inp.onboarding_session_id)
    session_provider = str(session.get("provider") or "icloud").strip().lower()
    if session_provider != "icloud":
        audit_event(
            "filemgr_mount_icloud_verify",
            user,
            req,
            outcome="failure",
            reason="invalid_session_provider",
            provider=session_provider or "unknown",
            onboarding_session_id=inp.onboarding_session_id,
        )
        raise HTTPException(status_code=400, detail="invalid onboarding session provider")
    mount_id = str(session.get("mount_id") or "")
    if not mount_id:
        raise HTTPException(status_code=400, detail="onboarding session missing mount_id")
    session_status = str(session.get("status") or "pending")
    if session_status in {"failed", "active"}:
        raise HTTPException(status_code=409, detail="onboarding session is no longer verifiable")
    next_action = str(session.get("next_action") or "verify").strip().lower()
    if next_action not in {"verify", "mfa_required", "reconnect"}:
        audit_event(
            "filemgr_mount_icloud_verify",
            user,
            req,
            outcome="failure",
            reason="invalid_session_step",
            provider="icloud",
            mount_id=mount_id,
            onboarding_session_id=inp.onboarding_session_id,
            next_action=next_action,
        )
        raise HTTPException(status_code=409, detail="onboarding session is not in a verifiable step")
    verify_attempts = int(session.get("verify_attempts") or 0)
    if verify_attempts >= _session_verify_attempt_limit():
        record_lockout_failure(user, ip, "filemgr_mount_verify")
        update_onboarding_session(
            user_sub=user,
            onboarding_session_id=inp.onboarding_session_id,
            status="failed",
            next_action="reconnect",
            attempts_inc=0,
        )
        raise HTTPException(status_code=429, detail="Too many mount verify attempts; reconnect required")

    secret = get_mount_secret(owner_user_sub=user, mount_id=mount_id)
    auth_mode = str(secret.get("auth_mode") or "")
    auth_value = str(secret.get("auth_value") or "")
    if not auth_value:
        record_lockout_failure(user, ip, "filemgr_mount_verify")
        update_onboarding_session(
            user_sub=user,
            onboarding_session_id=inp.onboarding_session_id,
            status="failed",
            next_action="reconnect",
            attempts_inc=1,
        )
        record_filemgr_provider_auth_failure(provider="icloud", mount_id=mount_id, reason="auth_failed")
        audit_event(
            "filemgr_mount_icloud_verify",
            user,
            req,
            outcome="failure",
            reason="auth_failed",
            provider="icloud",
            mount_id=mount_id,
            onboarding_session_id=inp.onboarding_session_id,
        )
        return ICloudVerifyOut(
            onboarding_session_id=inp.onboarding_session_id,
            mount_id=mount_id,
            status="failed",
            next_action="reconnect",
            outcome="auth_failed",
        )

    force_mfa = bool(secret.get("force_mfa_required")) or auth_mode == "app_password"
    if force_mfa and not (inp.mfa_code or "").strip():
        update_onboarding_session(
            user_sub=user,
            onboarding_session_id=inp.onboarding_session_id,
            status="pending",
            next_action="mfa_required",
            attempts_inc=1,
        )
        audit_event(
            "filemgr_mount_icloud_verify",
            user,
            req,
            outcome="success",
            reason="mfa_required",
            provider="icloud",
            mount_id=mount_id,
            onboarding_session_id=inp.onboarding_session_id,
        )
        return ICloudVerifyOut(
            onboarding_session_id=inp.onboarding_session_id,
            mount_id=mount_id,
            status="pending",
            next_action="mfa_required",
            outcome="mfa_required",
        )

    force_auth_failed = bool(secret.get("force_auth_failed"))
    if force_auth_failed:
        record_lockout_failure(user, ip, "filemgr_mount_verify")
        record_filemgr_provider_auth_failure(provider="icloud", mount_id=mount_id, reason="auth_failed")
        update_onboarding_session(
            user_sub=user,
            onboarding_session_id=inp.onboarding_session_id,
            status="failed",
            next_action="reconnect",
            attempts_inc=1,
        )
        audit_event(
            "filemgr_mount_icloud_verify",
            user,
            req,
            outcome="failure",
            reason="auth_failed",
            provider="icloud",
            mount_id=mount_id,
            onboarding_session_id=inp.onboarding_session_id,
        )
        return ICloudVerifyOut(
            onboarding_session_id=inp.onboarding_session_id,
            mount_id=mount_id,
            status="failed",
            next_action="reconnect",
            outcome="auth_failed",
        )

    update_mount(owner_user_sub=user, mount_id=mount_id, status="active")
    update_onboarding_session(
        user_sub=user,
        onboarding_session_id=inp.onboarding_session_id,
        status="active",
        next_action="none",
        attempts_inc=0,
    )
    clear_lockout(user, ip, "filemgr_mount_verify")
    audit_event(
        "filemgr_mount_icloud_verify",
        user,
        req,
        outcome="success",
        reason="active",
        provider="icloud",
        mount_id=mount_id,
        onboarding_session_id=inp.onboarding_session_id,
    )
    return ICloudVerifyOut(
        onboarding_session_id=inp.onboarding_session_id,
        mount_id=mount_id,
        status="active",
        next_action="none",
        outcome="active",
    )


@router.post("/mounts/icloud/rotate", response_model=ICloudRotateOut)
def rotate_icloud_mount_credentials(inp: ICloudRotateIn, req: Request = None, user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(
        user=user,
        action="mount_icloud_rotate",
        request_id=(req.headers.get("X-Request-Id") if req else inp.mount_id),
    )
    _enforce_icloud_feature_for_request(user, req)
    try:
        rate_limit_filemgr_mount_rotate(user, client_ip_from_request(req))
    except HTTPException as exc:
        if exc.status_code == 429:
            audit_event(
                "filemgr_mount_icloud_rotate",
                user,
                req,
                outcome="failure",
                provider="icloud",
                mount_id=inp.mount_id,
                reason="rate_limited",
                status_code=429,
            )
        raise
    mount = get_mount(owner_user_sub=user, mount_id=inp.mount_id)
    mount_status = str(mount.get("status") or "pending").lower()
    if mount_status not in {"active", "degraded", "reauth_required"}:
        audit_event(
            "filemgr_mount_icloud_rotate",
            user,
            req,
            outcome="failure",
            provider="icloud",
            mount_id=inp.mount_id,
            reason="invalid_mount_status",
            mount_status=mount_status,
        )
        raise HTTPException(status_code=409, detail="mount is not in a rotatable status")
    auth_value = _validate_icloud_auth_artifact(auth_mode=inp.auth_mode, auth_value=inp.auth_value)
    payload = {
        "auth_mode": inp.auth_mode,
        "auth_value": auth_value,
        "device_label": inp.device_label,
    }
    try:
        rotated = rotate_mount_secret(owner_user_sub=user, mount_id=inp.mount_id, secret_payload=payload)
    except HTTPException as exc:
        audit_event(
            "filemgr_mount_icloud_rotate",
            user,
            req,
            outcome="failure",
            provider="icloud",
            mount_id=inp.mount_id,
            reason="rotate_failed",
            status_code=exc.status_code,
        )
        raise
    audit_event(
        "filemgr_mount_icloud_rotate",
        user,
        req,
        outcome="success",
        provider="icloud",
        mount_id=inp.mount_id,
        secret_ref=rotated.get("secret_ref"),
    )
    return ICloudRotateOut(mount_id=inp.mount_id, secret_ref=str(rotated.get("secret_ref") or ""), status="active")


@router.get("/download")
def download_fs_file(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    started = time.perf_counter()
    provider, mount_id, is_mounted = _storage_context(user, path, req=req)
    outcome = "success"
    err: Optional[HTTPException] = None
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
    elif bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        result = download_file_dispatched(user, path)
        assert_file_bundle_access(user, result["node"])
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
    started = time.perf_counter()
    provider, mount_id, is_mounted = _storage_context(user, path, req=req)
    outcome = "success"
    err: Optional[HTTPException] = None
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
    elif bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        _enforce_mount_write_paths(user, path, action="delete_file")
        remove_file_dispatched(user, path)
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
    elif bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        _enforce_filemanager_internal_entitlement(
            user=user,
            action="delete_folder",
            request_id=(req.headers.get("X-Request-Id") if req else None),
        )
        _enforce_mount_write_paths(user, path, action="delete_folder")
        deleted_count = remove_folder_dispatched(user, path)
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
    elif bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        _enforce_mount_write_paths(user, src, dst, action="move_node")
        result = _move_node_for_owner(user, src, dst)
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


@router.post("/copy")
def copy_fs_node(
    src: str = Body(..., embed=True),
    dst: str = Body(..., embed=True),
    req: Request = None,
    user: str = Depends(_current_user),
):
    from app.services.filemanager import copy_node as _copy_node
    _enforce_sftp_mount_flags_for_path(src, operation="write")
    _enforce_sftp_mount_flags_for_path(dst, operation="write")
    _enforce_sftp_mount_status_for_path(src, owner=user, operation="write")
    _enforce_sftp_mount_status_for_path(dst, owner=user, operation="write")
    src_provider = resolve_storage_provider(user, src)
    dst_provider = resolve_storage_provider(user, dst)
    if src_provider.backend != dst_provider.backend:
        raise HTTPException(status_code=400, detail={"code": "cross_backend_copy_not_supported", "message": "copying between native and mounted paths is not supported"})
    if src_provider.backend == "sftp":
        raise HTTPException(status_code=400, detail={"code": "copy_not_supported_for_mount", "message": "copy is only supported for native storage"})
    result = _copy_node(user, src, dst)
    audit_event(
        "filemgr_node_copied",
        user,
        req,
        outcome="success",
        src=result.get("src"),
        dst=result.get("dst"),
        node_type=result.get("type"),
        **_file_audit_fields(file_path=str(result.get("dst") or norm_path(dst, is_folder=None)), owner=user),
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
    elif bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        _enforce_mount_write_paths(user, path, action="rename_file")
        result = _move_node_for_owner(user, path, dst)
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
    _enforce_mount_write_paths(user, path, action="rename_folder")
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
    elif bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        _enforce_mount_write_paths(user, folder, action="rename_folder")
        result = _move_node_for_owner(user, folder, dst)
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
    _enforce_mount_write_paths(user, dest_folder, action="upload_zip")
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
    _enforce_mount_write_paths(user, dest_folder, action="upload_archive")
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
    _enforce_mount_write_paths(user, path, action="share_node")
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
    _enforce_mount_write_paths(user, path, action="unshare_node")
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
    _enforce_mount_write_paths(owner, path, action="shared_delete_file")
    if bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        remove_file_dispatched(owner, path)
    else:
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
    _enforce_mount_write_paths(owner, path, action="shared_delete_folder")
    if bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        deleted_count = remove_folder_dispatched(owner, path)
    else:
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
    _enforce_mount_write_paths(owner, src, dst, action="shared_move_node")
    shared_root = access["path"]
    if shared_root.endswith("/") and not norm_path(dst, is_folder=None).startswith(shared_root):
        raise HTTPException(status_code=403, detail="destination must be within shared root")
    result = _move_node_for_owner(owner, src, dst)
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
    _enforce_mount_write_paths(owner, path, action="shared_rename_file")
    result = _move_node_for_owner(owner, path, norm_path(path, is_folder=False).rsplit("/", 1)[0] + "/" + new_name)
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
    _enforce_mount_write_paths(owner, path, action="shared_rename_folder")
    current = norm_path(path, is_folder=True)
    parent = current.rstrip("/").rsplit("/", 1)[0] + "/"
    dst = norm_path(parent + new_name + "/", is_folder=True)
    result = _move_node_for_owner(owner, current, dst)
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
    _enforce_mount_write_paths(owner, path, action="shared_create_folder")
    if bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        folder = create_empty_folder_dispatched(owner, path)
    else:
        folder = create_empty_folder(owner, path)
    audit_event("filemgr_folder_created", user, req, outcome="success", path=folder, owner=owner)
    return {"ok": True, "path": folder}


@router.post("/shared-upload")
def upload_shared_file(
    owner: str = Query(...),
    path: str = Query(..., description="Full file path, e.g. /docs/a.txt"),
    file: UploadFile = File(...),
    encrypted: bool = Query(False),
    overwrite: bool = Query(False),
    enc_meta: Optional[str] = Query(default=None, description="JSON encryption metadata"),
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="write")
    _enforce_mount_write_paths(owner, path, action="shared_upload_file")
    encrypted_flag = encrypted if isinstance(encrypted, bool) else False
    encryption_meta = _parse_encryption_meta(enc_meta) if encrypted_flag else None
    overwrite_flag = overwrite if isinstance(overwrite, bool) else False
    if bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        result = upload_file_dispatched(owner, path, file, overwrite=overwrite_flag, encryption_meta=encryption_meta)
    else:
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
    _enforce_mount_write_paths(owner, dest_folder, action="shared_upload_zip")
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
    _enforce_mount_write_paths(owner, dest_folder, action="shared_upload_archive")
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


@router.post("/mounts", response_model=MountOut)
def create_mount_route(body: MountCreateIn, user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(user=user, action="mount_create")
    _require_google_drive_mounts_enabled()
    registry = default_provider_registry()
    provider_client = registry.get(user, body.provider)
    canonical_root_ref = provider_client.resolve(body.provider_root_ref)
    if not provider_client.exists(canonical_root_ref):
        raise HTTPException(status_code=404, detail="mount provider_root_ref not found")

    mount = create_mount(
        user,
        provider=body.provider,
        mount_path=body.mount_path,
        provider_root_ref=canonical_root_ref,
        mode=body.mode,
    )
    return MountOut(**mount.model_dump())


@router.get("/mounts", response_model=MountListOut)
def list_mounts_route(user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(user=user, action="mount_list")
    _require_google_drive_mounts_enabled()
    items = [MountOut(**item.model_dump()) for item in list_mounts(user)]
    return MountListOut(items=items)


@router.patch("/mounts/{mount_id}", response_model=MountOut)
def update_mount_route(mount_id: str, body: MountUpdateIn, user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(user=user, action="mount_update")
    _require_google_drive_mounts_enabled()
    provider_root_ref = body.provider_root_ref
    if provider_root_ref is not None:
        existing = get_mount(user, mount_id)
        registry = default_provider_registry()
        provider_client = registry.get(user, existing.provider)
        canonical_root_ref = provider_client.resolve(provider_root_ref)
        if not provider_client.exists(canonical_root_ref):
            raise HTTPException(status_code=404, detail="mount provider_root_ref not found")
        provider_root_ref = canonical_root_ref

    mount = update_mount(
        user,
        mount_id,
        mount_path=body.mount_path,
        provider_root_ref=provider_root_ref,
        mode=body.mode,
    )
    return MountOut(**mount.model_dump())


@router.delete("/mounts/{mount_id}", response_model=DeleteMountOut)
def delete_mount_route(mount_id: str, user: str = Depends(_current_user)):
    _enforce_filemanager_internal_entitlement(user=user, action="mount_delete")
    _require_google_drive_mounts_enabled()
    return DeleteMountOut(**delete_mount(user, mount_id))


@router.get("/admin/mounts/reconcile", response_model=MountReconcileListOut)
def admin_reconcile_mounts_route(
    owner: str = Query(..., description="Mount owner user_sub"),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(_admin_or_root_ctx),
):
    _require_google_drive_mounts_enabled()
    items = [MountReconcileOut(**row) for row in reconcile_mounts(owner)]
    audit_event(
        "filemgr_mount_reconcile_scan",
        ctx["user_sub"],
        req,
        outcome="success",
        owner=owner,
        stale_count=sum(1 for item in items if item.stale),
        total_count=len(items),
    )
    return MountReconcileListOut(items=items)


@router.post("/admin/mounts/{mount_id}/disable", response_model=MountOut)
def admin_disable_mount_route(
    mount_id: str,
    owner: str = Query(..., description="Mount owner user_sub"),
    reason: str = Query("admin_disabled", description="Disable reason"),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(_admin_or_root_ctx),
):
    _require_google_drive_mounts_enabled()
    updated = set_mount_status(
        owner,
        mount_id,
        status="disabled",
        status_reason=(reason or "admin_disabled"),
        reconnect_required=True,
    )
    audit_event(
        "filemgr_mount_disabled",
        ctx["user_sub"],
        req,
        outcome="success",
        owner=owner,
        mount_id=mount_id,
        reason=(reason or "admin_disabled"),
    )
    return MountOut(**updated.model_dump())


@router.post("/admin/mounts/{mount_id}/reconcile-disable", response_model=MountOut)
def admin_reconcile_disable_mount_route(
    mount_id: str,
    owner: str = Query(..., description="Mount owner user_sub"),
    req: Request = None,
    ctx: Dict[str, Any] = Depends(_admin_or_root_ctx),
):
    _require_google_drive_mounts_enabled()
    result = reconcile_mount_health(owner, mount_id)
    if not result.get("stale"):
        raise HTTPException(status_code=409, detail="mount is not stale")
    reason = ",".join(result.get("issues") or ["stale_mount"])
    updated = set_mount_status(owner, mount_id, status="disabled", status_reason=reason, reconnect_required=bool(result.get("reconnect_required")))
    audit_event(
        "filemgr_mount_reconcile_disable",
        ctx["user_sub"],
        req,
        outcome="success",
        owner=owner,
        mount_id=mount_id,
        issues=result.get("issues"),
    )
    return MountOut(**updated.model_dump())


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


# ── EVT-011: CRM Document Library metadata + search ───────────────────────

from pydantic import BaseModel as _FMBaseModel, Field as _FMField
from typing import Optional as _FMOpt, List as _FMList


class CrmMetadataIn(_FMBaseModel):
    crm_category: _FMOpt[str] = _FMField(default=None, max_length=200)
    crm_description: _FMOpt[str] = _FMField(default=None, max_length=2000)
    linked_record_type: _FMOpt[str] = _FMField(default=None)
    linked_record_id: _FMOpt[str] = _FMField(default=None, max_length=200)


class CrmMetadataOut(_FMBaseModel):
    path: str
    crm_category: _FMOpt[str]
    crm_description: _FMOpt[str]
    linked_record_type: _FMOpt[str]
    linked_record_id: _FMOpt[str]
    crm_metadata_updated_at: _FMOpt[str]


class CrmSearchOut(_FMBaseModel):
    items: _FMList[CrmMetadataOut]
    cursor: _FMOpt[str]
    count: int


def _require_crm_document_library_enabled() -> None:
    if not S.crm_document_library_enabled:
        raise HTTPException(status_code=404, detail="not found")


@router.patch("/crm-metadata")
def update_crm_metadata_endpoint(
    path: str = Query(..., description="File path, e.g. /docs/contract.pdf"),
    body: CrmMetadataIn = ...,
    req: Request = None,
    user: str = Depends(_current_user),
) -> CrmMetadataOut:
    _require_crm_document_library_enabled()
    _enforce_sftp_mount_flags_for_path(path, operation="write")
    from app.services.filemanager import update_crm_metadata  # lazy (RULE-1)
    node = update_crm_metadata(
        user,
        path,
        crm_category=body.crm_category,
        crm_description=body.crm_description,
        linked_record_type=body.linked_record_type,
        linked_record_id=body.linked_record_id,
    )
    audit_event(
        "filemgr_crm_metadata_updated",
        user,
        req,
        outcome="success",
        path=path,
        linked_record_type=body.linked_record_type,
        linked_record_id=body.linked_record_id,
    )
    return CrmMetadataOut(
        path=node.get("path", path),
        crm_category=node.get("crm_category"),
        crm_description=node.get("crm_description"),
        linked_record_type=node.get("linked_record_type"),
        linked_record_id=node.get("linked_record_id"),
        crm_metadata_updated_at=node.get("crm_metadata_updated_at"),
    )


@router.get("/crm-search")
def crm_search_endpoint(
    linked_record_type: str = Query(...),
    linked_record_id: str = Query(...),
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user: str = Depends(_current_user),
) -> CrmSearchOut:
    _require_crm_document_library_enabled()
    cursor_payload = _decode_cursor(cursor)
    from app.services.filemanager import search_by_linked_record  # lazy (RULE-1)
    items, next_key = search_by_linked_record(
        user,
        linked_record_type,
        linked_record_id,
        limit=limit,
        cursor=cursor_payload,
    )
    next_cursor = _encode_cursor(next_key) if next_key else None
    return CrmSearchOut(
        items=[
            CrmMetadataOut(
                path=it.get("path", ""),
                crm_category=it.get("crm_category"),
                crm_description=it.get("crm_description"),
                linked_record_type=it.get("linked_record_type"),
                linked_record_id=it.get("linked_record_id"),
                crm_metadata_updated_at=it.get("crm_metadata_updated_at"),
            )
            for it in items
        ],
        cursor=next_cursor,
        count=len(items),
    )
