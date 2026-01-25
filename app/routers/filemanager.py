from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, File, Query, UploadFile, Body, Request
from fastapi.responses import StreamingResponse

from app.services.filemanager import (
    create_empty_folder,
    download_file,
    download_zip,
    list_children,
    list_shared_with,
    list_shared_with_me,
    move_node,
    norm_path,
    remove_file,
    remove_folder,
    search_prefix,
    share_node,
    split_parent_name,
    upload_file,
    upload_zip,
    get_node,
)
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/v1/fs", tags=["filemanager"])


def _current_user(ctx=Depends(require_ui_session)) -> str:
    return ctx["user_sub"]


@router.get("/list")
def list_files(path: str = Query("/", description="Folder path"), user: str = Depends(_current_user)):
    folder = norm_path(path, is_folder=True)
    items = list_children(user, folder)
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
    out.sort(key=lambda x: (x["type"] != "folder", x["name"].lower()))
    return {"path": folder, "items": out}


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
        headers={"Content-Disposition": f'attachment; filename="{node["name"]}"'},
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
    buf = download_zip(user, paths)
    audit_event(
        "filemgr_zip_downloaded",
        user,
        req,
        outcome="success",
        count=len(paths),
    )

    def zip_stream():
        yield from iter(lambda: buf.read(1024 * 1024), b"")

    return StreamingResponse(
        zip_stream(),
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
    req: Request = None,
    user: str = Depends(_current_user),
):
    share_node(user, path, to_user)
    audit_event(
        "filemgr_node_shared",
        user,
        req,
        outcome="success",
        path=path,
        shared_with=to_user,
    )
    return {"ok": True}


@router.get("/shared-with")
def list_shared(path: str = Query(...), user: str = Depends(_current_user)):
    return {"path": norm_path(path, is_folder=None), "shared_with": list_shared_with(user, path)}


@router.get("/shared-with-me")
def list_shared_me(user: str = Depends(_current_user)):
    return {"items": list_shared_with_me(user)}
