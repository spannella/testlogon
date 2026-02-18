from __future__ import annotations

import base64
import json
import uuid
from typing import Annotated, Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Query, UploadFile, Body, Request, HTTPException
from pydantic import BaseModel, Field
from fastapi.responses import StreamingResponse

from app.auth.policy import require_role_value
from app.auth.roles import Role
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
    list_shared_with,
    list_shared_with_me,
    move_node,
    norm_path,
    remove_file,
    remove_folder,
    search_prefix,
    share_node,
    unshare_node,
    split_parent_name,
    upload_file,
    upload_zip,
    get_node,
    search_text,
    presign_upload,
    register_presigned_upload,
    purge_deleted_nodes,
    require_shared_access,
    admin_search_metadata,
)
from app.services.alerts import audit_event
from app.services.purchase_history import record_receipt_download
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/v1/fs", tags=["filemanager"])


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


def _admin_or_root_ctx(ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    require_role_value(ctx.get("role"), {Role.ADMIN, Role.ROOT})
    return ctx


def _admin_can_read_content(ctx: Dict[str, Any]) -> bool:
    tier = str(getattr(S, "filemgr_admin_content_access_tier", "none") or "none").lower()
    role = str(ctx.get("role") or "")
    if tier == "admin_root":
        return role in {Role.ADMIN.value, Role.ROOT.value}
    if tier == "root_only":
        return role == Role.ROOT.value
    return False


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


class PresignUploadIn(BaseModel):
    path: str = Field(..., description="Full file path, e.g. /docs/a.txt")
    content_type: Optional[str] = Field(default=None, description="Optional content type")


class PresignUploadOut(BaseModel):
    upload_url: str
    bucket: str
    key: str
    path: str
    content_type: str


class CompleteUploadIn(BaseModel):
    path: str = Field(..., description="Full file path, e.g. /docs/a.txt")
    key: str = Field(..., description="S3 object key from presign response")
    content_type: Optional[str] = Field(default=None, description="Optional content type override")


@router.get("/list")
def list_files(
    path: str = Query("/", description="Folder path"),
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    sort_by: str = Query("name", pattern="^(name|updated|size)$"),
    sort_dir: str = Query("asc", pattern="^(asc|desc)$"),
    user: str = Depends(_current_user),
):
    if not isinstance(limit, int):
        limit = 50
    if not isinstance(sort_by, str):
        sort_by = "name"
    if not isinstance(sort_dir, str):
        sort_dir = "asc"
    folder = norm_path(path, is_folder=True)
    cursor_payload = _decode_cursor(cursor)
    scan_forward = sort_dir == "asc"
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
    p = norm_path(path, is_folder=None)
    it = get_node(user, p if p.endswith("/") else p)
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


@router.post("/folder")
def create_folder(path: str = Body(..., embed=True), req: Request = None, user: str = Depends(_current_user)):
    folder = create_empty_folder(user, path)
    audit_event("filemgr_folder_created", user, req, outcome="success", path=folder)
    return {"ok": True, "path": folder}


@router.post("/upload")
def upload_fs_file(
    path: str = Query(..., description="Full file path, e.g. /docs/a.txt"),
    file: UploadFile = File(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    result = upload_file(user, path, file)
    audit_event(
        "filemgr_file_uploaded",
        user,
        req,
        outcome="success",
        path=result.get("path"),
        size=result.get("size"),
        content_type=file.content_type,
    )
    return {"ok": True, **result}


@router.post("/presign-upload", response_model=PresignUploadOut)
def presign_fs_upload(inp: PresignUploadIn, user: str = Depends(_current_user)):
    result = presign_upload(user, inp.path, content_type=inp.content_type)
    return PresignUploadOut(
        upload_url=result["upload_url"],
        bucket=result["bucket"],
        key=result["key"],
        path=result["path"],
        content_type=result["content_type"],
    )


@router.post("/complete-upload")
def complete_fs_upload(inp: CompleteUploadIn, req: Request = None, user: str = Depends(_current_user)):
    result = register_presigned_upload(user, inp.path, s3_key=inp.key, content_type=inp.content_type)
    audit_event(
        "filemgr_file_uploaded",
        user,
        req,
        outcome="success",
        path=result.get("path"),
        size=result.get("size"),
        content_type=result.get("content_type"),
    )
    return {"ok": True, **result}


@router.get("/download")
def download_fs_file(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    result = download_file(user, path)
    node = result["node"]
    obj = result["object"]
    audit_event(
        "filemgr_file_downloaded",
        user,
        req,
        outcome="success",
        path=node.get("path"),
        size=node.get("size"),
    )
    receipt_path = norm_path(path, is_folder=False)
    if receipt_path.startswith("/billing/receipts/") and receipt_path.lower().endswith(".pdf"):
        _, name = split_parent_name(receipt_path)
        txn_id = name[:-4]
        if txn_id:
            record_receipt_download(user, txn_id, receipt_path)

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


@router.get("/preview")
def preview_fs_file(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    result = download_file(user, path)
    node = result["node"]
    obj = result["object"]
    if not is_previewable(node):
        raise HTTPException(status_code=415, detail="preview not available for this file type")
    audit_event(
        "filemgr_file_previewed",
        user,
        req,
        outcome="success",
        path=node.get("path"),
        size=node.get("size"),
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
        headers={"Content-Disposition": f'inline; filename="{node["name"]}"'},
    )


@router.get("/thumbnail")
def thumbnail_fs_file(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    result = download_thumbnail(user, path)
    node = result["node"]
    thumb = result["thumbnail"]
    obj = result["object"]

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


@router.delete("/file")
def remove_fs_file(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    remove_file(user, path)
    audit_event("filemgr_file_removed", user, req, outcome="success", path=path, **_file_audit_fields(file_path=norm_path(path, is_folder=False), owner=user))
    return {"ok": True}


@router.delete("/folder")
def remove_fs_folder(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
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
    )
    return {"ok": True, "deleted_count": deleted_count}


@router.post("/move")
def move_fs_node(
    src: str = Body(..., embed=True),
    dst: str = Body(..., embed=True),
    req: Request = None,
    user: str = Depends(_current_user),
):
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
    )
    return {"ok": True, **result}


@router.post("/rename-file")
def rename_file(
    path: str = Body(..., embed=True),
    new_name: str = Body(..., embed=True),
    req: Request = None,
    user: str = Depends(_current_user),
):
    parent, _ = split_parent_name(norm_path(path, is_folder=False))
    dst = parent + new_name
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
    result = download_zip(user, paths)
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

    return StreamingResponse(
        zip_stream,
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


@router.post("/share")
def share_fs_node(
    path: str = Body(..., embed=True),
    to_user: str = Body(..., embed=True),
    permission: Annotated[str, Body(embed=True)] = "read",
    expires_at: Annotated[Optional[str], Body(embed=True)] = None,
    req: Request = None,
    user: str = Depends(_current_user),
):
    if permission == "read" and expires_at is None:
        share_node(user, path, to_user)
    else:
        share_node(user, path, to_user, permission=permission, expires_at=expires_at)
    audit_event(
        "filemgr_node_shared",
        user,
        req,
        outcome="success",
        path=path,
        shared_with=to_user,
        permission=permission,
        expires_at=expires_at,
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
    }


@router.get("/shared-download")
def shared_download_fs_file(
    owner: str = Query(...),
    path: str = Query(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="read")
    result = download_file(owner, path)
    node = result["node"]
    obj = result["object"]
    audit_event(
        "filemgr_file_downloaded",
        user,
        req,
        outcome="success",
        path=node.get("path"),
        size=node.get("size"),
        owner=owner,
        **_file_audit_fields(file_path=str(node.get("path") or norm_path(path, is_folder=False)), owner=owner),
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


@router.get("/shared-preview")
def shared_preview_fs_file(
    owner: str = Query(...),
    path: str = Query(...),
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="read")
    result = download_file(owner, path)
    node = result["node"]
    obj = result["object"]
    if not is_previewable(node):
        raise HTTPException(status_code=415, detail="preview not available for this file type")
    audit_event(
        "filemgr_file_previewed",
        user,
        req,
        outcome="success",
        path=node.get("path"),
        size=node.get("size"),
        owner=owner,
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
        headers={"Content-Disposition": f'inline; filename="{node["name"]}"'},
    )


@router.get("/shared-thumbnail")
def shared_thumbnail_fs_file(
    owner: str = Query(...),
    path: str = Query(...),
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="read")
    result = download_thumbnail(owner, path)
    node = result["node"]
    thumb = result["thumbnail"]
    obj = result["object"]

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
    req: Request = None,
    user: str = Depends(_current_user),
):
    require_shared_access(user, owner, path, permission="write")
    result = upload_file(owner, path, file)
    audit_event(
        "filemgr_file_uploaded",
        user,
        req,
        outcome="success",
        path=result.get("path"),
        size=result.get("size"),
        content_type=file.content_type,
        owner=owner,
    )
    return {"ok": True, **result}


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
    return StreamingResponse(
        zf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=download.zip"},
    )


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
