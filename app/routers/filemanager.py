from __future__ import annotations

import base64
import json
from typing import Annotated, Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Query, UploadFile, Body, Request, HTTPException
from pydantic import BaseModel, Field
from fastapi.responses import StreamingResponse

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
    audit_event("filemgr_file_removed", user, req, outcome="success", path=path)
    return {"ok": True}


@router.delete("/folder")
def remove_fs_folder(path: str = Query(...), req: Request = None, user: str = Depends(_current_user)):
    deleted_count = remove_folder(user, path)
    audit_event(
        "filemgr_folder_removed",
        user,
        req,
        outcome="success",
        path=path,
        deleted_count=deleted_count,
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
    audit_event(
        "filemgr_zip_downloaded",
        user,
        req,
        outcome="success",
        count=file_count or 0,
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
    audit_event(
        "filemgr_download_zip",
        user,
        req,
        outcome="success",
        path="(zip)",
        count=count,
        owner=owner,
    )
    return StreamingResponse(
        zf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=download.zip"},
    )


@router.post("/purge-deleted")
def purge_deleted(req: Request = None, user: str = Depends(_current_user)):
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
