"""Stateful in-memory mock for Google Drive API v3 endpoints."""
from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request, Response

from app.core.settings import S

router = APIRouter(tags=["mock"])

_FILES: Dict[str, Dict[str, Any]] = {}
_FILE_CONTENT: Dict[str, bytes] = {}

FOLDER_MIME = "application/vnd.google-apps.folder"


def _ensure_mock_enabled() -> None:
    if not S.google_drive_mock_enabled:
        raise HTTPException(404, "Not found")


def _require_bearer(req: Request) -> str:
    auth = req.headers.get("authorization", "")
    if not auth.lower().startswith("bearer ") or not auth.split(" ", 1)[1].strip():
        raise HTTPException(401, "Missing or empty Bearer token")
    return auth.split(" ", 1)[1].strip()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _make_file(
    *,
    file_id: Optional[str] = None,
    name: str = "Untitled",
    mime_type: str = "application/octet-stream",
    parents: Optional[List[str]] = None,
    size: int = 0,
    trashed: bool = False,
    drive_id: Optional[str] = None,
) -> Dict[str, Any]:
    fid = file_id or uuid.uuid4().hex
    return {
        "id": fid,
        "name": name,
        "mimeType": mime_type,
        "size": str(size),
        "modifiedTime": _now_iso(),
        "parents": parents or ["root"],
        "trashed": trashed,
        "kind": "drive#file",
        **({"driveId": drive_id} if drive_id is not None else {}),
    }


def _matches_query(f: Dict[str, Any], q: str) -> bool:
    if not q:
        return True
    parts = [p.strip() for p in q.split(" and ")]
    for part in parts:
        if part == "trashed=false":
            if f.get("trashed", False):
                return False
        elif part == "trashed=true":
            if not f.get("trashed", False):
                return False
        elif part.endswith("in parents"):
            parent_id = part.split("in parents")[0].strip().strip("'\"")
            if parent_id not in (f.get("parents") or []):
                return False
        elif part.startswith("name="):
            val = part.split("=", 1)[1].strip().strip("'\"")
            if f.get("name") != val:
                return False
        elif part.startswith("mimeType="):
            val = part.split("=", 1)[1].strip().strip("'\"")
            if f.get("mimeType") != val:
                return False
        elif part.startswith("mimeType!="):
            val = part.split("!=", 1)[1].strip().strip("'\"")
            if f.get("mimeType") == val:
                return False
    return True


# ---------------------------------------------------------------------------
# Metadata API — prefix /mock/google-drive/drive/v3
# ---------------------------------------------------------------------------

@router.get("/mock/google-drive/drive/v3/files/{file_id}")
async def drive_get_file(file_id: str, req: Request) -> Response:
    _ensure_mock_enabled()
    _require_bearer(req)
    f = _FILES.get(file_id)
    if not f:
        raise HTTPException(404, {"error": {"code": 404, "message": "File not found"}})
    if req.query_params.get("alt") == "media":
        content = _FILE_CONTENT.get(file_id, b"")
        return Response(content=content, media_type=f.get("mimeType", "application/octet-stream"))
    return Response(content=json.dumps(f), media_type="application/json")


@router.get("/mock/google-drive/drive/v3/files")
async def drive_list_files(req: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _require_bearer(req)
    q = req.query_params.get("q", "")
    page_size = int(req.query_params.get("pageSize", "100"))
    matched = [f for f in _FILES.values() if _matches_query(f, q)]
    return {"kind": "drive#fileList", "files": matched[:page_size]}


@router.post("/mock/google-drive/drive/v3/files")
async def drive_create_metadata(req: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _require_bearer(req)
    body = await req.json()
    f = _make_file(
        name=body.get("name", "Untitled"),
        mime_type=body.get("mimeType", "application/octet-stream"),
        parents=body.get("parents"),
    )
    _FILES[f["id"]] = f
    return f


@router.patch("/mock/google-drive/drive/v3/files/{file_id}")
async def drive_patch_metadata(file_id: str, req: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _require_bearer(req)
    f = _FILES.get(file_id)
    if not f:
        raise HTTPException(404, {"error": {"code": 404, "message": "File not found"}})
    body = await req.json()
    for key in ("name", "mimeType", "trashed", "description"):
        if key in body:
            f[key] = body[key]
    add_parents = req.query_params.get("addParents", "")
    remove_parents = req.query_params.get("removeParents", "")
    if remove_parents:
        for pid in remove_parents.split(","):
            pid = pid.strip()
            if pid in f.get("parents", []):
                f["parents"].remove(pid)
    if add_parents:
        for pid in add_parents.split(","):
            pid = pid.strip()
            if pid not in f.get("parents", []):
                f.setdefault("parents", []).append(pid)
    f["modifiedTime"] = _now_iso()
    return f


@router.delete("/mock/google-drive/drive/v3/files/{file_id}")
async def drive_delete_file(file_id: str, req: Request) -> Response:
    _ensure_mock_enabled()
    _require_bearer(req)
    if file_id not in _FILES:
        raise HTTPException(404, {"error": {"code": 404, "message": "File not found"}})
    del _FILES[file_id]
    _FILE_CONTENT.pop(file_id, None)
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Upload API — prefix /mock/google-drive/upload/drive/v3
# ---------------------------------------------------------------------------

def _parse_multipart_body(content_type: str, body: bytes) -> tuple[Dict[str, Any], bytes]:
    boundary = ""
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part.split("=", 1)[1].strip().strip('"')
            break
    if not boundary:
        return {}, body

    sep = f"--{boundary}".encode()
    parts = body.split(sep)
    metadata: Dict[str, Any] = {}
    file_bytes: bytes = b""

    for p in parts:
        p = p.strip()
        if not p or p == b"--":
            continue
        if b"\r\n\r\n" in p:
            header_block, payload = p.split(b"\r\n\r\n", 1)
        elif b"\n\n" in p:
            header_block, payload = p.split(b"\n\n", 1)
        else:
            continue
        header_lower = header_block.lower()
        if b"application/json" in header_lower:
            try:
                metadata = json.loads(payload.rstrip(b"\r\n-"))
            except Exception:
                pass
        else:
            file_bytes = payload.rstrip(b"\r\n-")

    return metadata, file_bytes


@router.post("/mock/google-drive/upload/drive/v3/files")
async def drive_upload_file(req: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _require_bearer(req)
    body = await req.body()
    content_type = req.headers.get("content-type", "")
    metadata: Dict[str, Any] = {}
    file_bytes: bytes = body

    if "multipart" in content_type:
        metadata, file_bytes = _parse_multipart_body(content_type, body)
    else:
        try:
            metadata = json.loads(body)
            file_bytes = b""
        except Exception:
            pass

    f = _make_file(
        name=metadata.get("name", "Untitled"),
        mime_type=metadata.get("mimeType", req.headers.get("content-type", "application/octet-stream").split(";")[0].strip()),
        parents=metadata.get("parents"),
        size=len(file_bytes),
    )
    _FILES[f["id"]] = f
    if file_bytes:
        _FILE_CONTENT[f["id"]] = file_bytes
    return f


@router.patch("/mock/google-drive/upload/drive/v3/files/{file_id}")
async def drive_upload_update(file_id: str, req: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    _require_bearer(req)
    f = _FILES.get(file_id)
    if not f:
        raise HTTPException(404, {"error": {"code": 404, "message": "File not found"}})
    body = await req.body()
    content_type = req.headers.get("content-type", "")
    metadata: Dict[str, Any] = {}
    file_bytes: bytes = body

    if "multipart" in content_type:
        metadata, file_bytes = _parse_multipart_body(content_type, body)
    else:
        file_bytes = body

    for key in ("name", "mimeType"):
        if key in metadata:
            f[key] = metadata[key]

    f["size"] = str(len(file_bytes))
    f["modifiedTime"] = _now_iso()
    _FILE_CONTENT[file_id] = file_bytes
    return f


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

@router.post("/mock/google-drive/seed")
async def drive_seed(req: Request) -> Dict[str, Any]:
    _ensure_mock_enabled()
    body = await req.json()
    files = body.get("files") or []
    file_content = body.get("file_content") or {}
    for fm in files:
        fid = fm.get("id") or uuid.uuid4().hex
        fm.setdefault("id", fid)
        fm.setdefault("kind", "drive#file")
        fm.setdefault("mimeType", "application/octet-stream")
        fm.setdefault("size", "0")
        fm.setdefault("modifiedTime", _now_iso())
        fm.setdefault("parents", ["root"])
        fm.setdefault("trashed", False)
        _FILES[fid] = fm
    for fid, b64 in file_content.items():
        _FILE_CONTENT[fid] = base64.b64decode(b64)
    return {"ok": True, "seeded_files": len(files), "seeded_content": len(file_content)}


@router.post("/mock/google-drive/reset")
async def drive_reset() -> Dict[str, Any]:
    _ensure_mock_enabled()
    _FILES.clear()
    _FILE_CONTENT.clear()
    return {"ok": True}
