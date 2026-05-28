"""Google Drive integration endpoints for the frontend picker UI.

Provides OAuth connect/disconnect lifecycle, a browse proxy for the Drive
file picker dialog, and a file import endpoint that copies Drive files into
the local file manager.

All endpoints use cookie-based session auth (require_ui_session).
"""
from __future__ import annotations

import asyncio
import io
import logging
from typing import Any, Dict, List, Optional

import requests
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.sessions import require_ui_session
from app.core.settings import S
from app.core.time import now_ts
from app.services.provider_credentials import (
    get_provider_credential,
    upsert_provider_credential,
    delete_provider_credential,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/integrations/google-drive", tags=["integrations"])

FOLDER_MIME = "application/vnd.google-apps.folder"


# ─── Request/Response Models ──────────────────────────────────────────────────


class DriveConnectResp(BaseModel):
    auth_url: str
    mock: bool = False


class DriveCallbackReq(BaseModel):
    code: str = Field(..., min_length=1, max_length=2048)
    redirect_uri: str = Field("", max_length=2048)
    state: Optional[str] = None


class DriveStatusResp(BaseModel):
    connected: bool
    email: Optional[str] = None
    scopes: Optional[List[str]] = None
    connected_at: Optional[str] = None


class DriveImportReq(BaseModel):
    file_id: str = Field(..., min_length=1, max_length=256)
    destination_path: Optional[str] = Field(None, max_length=1024)


class DriveImportResp(BaseModel):
    ok: bool = True
    node_id: str
    path: str


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _get_cred_safe(user_sub: str):
    """Return credential or None (no exception on missing)."""
    return get_provider_credential(user_sub, "google_drive", allow_missing=True)


def _build_drive_headers(user_sub: str) -> Dict[str, str]:
    """Build authorization headers for Drive API calls using stored credential."""
    from app.services.provider_credentials import get_provider_auth_context
    auth = get_provider_auth_context(user_sub, "google_drive")
    token = auth["token"]
    return {"Authorization": f"Bearer {token}"}


async def _drive_api_get(user_sub: str, path: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
    """Make an authenticated GET request to the Google Drive API (or mock).

    Runs the synchronous ``requests.get`` in a thread so that the async event
    loop is not blocked — this is critical when the target URL is the local
    mock server running in the same process.
    """
    url = f"{S.google_drive_api_base_url}/{path}"
    headers = _build_drive_headers(user_sub)
    return await asyncio.to_thread(
        requests.get, url, params=params, headers=headers, timeout=S.google_drive_api_timeout_seconds,
    )


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/status")
async def google_drive_status(ctx=Depends(require_ui_session)) -> DriveStatusResp:
    """Check if Google Drive is connected for the current user."""
    user_sub = ctx["user_sub"]
    cred = _get_cred_safe(user_sub)
    if not cred:
        return DriveStatusResp(connected=False)
    return DriveStatusResp(
        connected=True,
        email=(cred.metadata or {}).get("email"),
        scopes=cred.scopes or [],
        connected_at=cred.created_at,
    )


@router.get("/connect")
async def initiate_google_drive_connect(ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    """Generate OAuth authorization URL (or mock connect URL in dev mode)."""
    user_sub = ctx["user_sub"]

    if S.dev_mode and S.google_drive_mock_enabled:
        return {
            "auth_url": f"/files?drive-callback=1&code=mock_auth_code_{user_sub}&state=mock",
            "mock": True,
        }

    # Real OAuth flow would go here
    return {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "mock": False,
    }


@router.post("/callback")
async def complete_google_drive_connect(body: DriveCallbackReq, ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    """Exchange OAuth code for tokens and store credential.

    In dev mode with google_drive_mock_enabled=true, accepts any code and stores
    a mock credential.
    """
    user_sub = ctx["user_sub"]

    if S.dev_mode and S.google_drive_mock_enabled:
        # Mock mode: store a credential with a simple token
        mock_token = f"mock-drive-token-{user_sub}"
        upsert_provider_credential(
            user_sub,
            "google_drive",
            mock_token,
            scopes_override=["https://www.googleapis.com/auth/drive.file"],
            metadata_override={"email": f"{user_sub}@drive.mock"},
        )
        return {"ok": True, "connected": True}

    # Real OAuth exchange would go here
    raise HTTPException(501, "Real OAuth not implemented in this environment")


@router.post("/disconnect")
async def disconnect_google_drive(ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    """Revoke and delete Google Drive credentials."""
    user_sub = ctx["user_sub"]
    delete_provider_credential(user_sub, "google_drive")
    return {"ok": True}


@router.get("/files")
async def browse_drive_files(
    folder_id: str = Query("root", max_length=256),
    q: Optional[str] = Query(None, max_length=500),
    page_token: Optional[str] = Query(None, max_length=2048),
    page_size: int = Query(50, ge=1, le=200),
    ctx=Depends(require_ui_session),
) -> Dict[str, Any]:
    """List files in a Google Drive folder via the provider proxy.

    Returns files and folders in the specified parent folder.
    """
    user_sub = ctx["user_sub"]

    # Ensure connected
    cred = _get_cred_safe(user_sub)
    if not cred:
        raise HTTPException(401, "Google Drive not connected")

    # Build query
    query_parts = [f"'{folder_id}' in parents", "trashed=false"]
    if q:
        # Sanitize search query
        safe_q = q.replace("'", "").replace("\\", "")
        query_parts.append(f"name contains '{safe_q}'")

    params: Dict[str, Any] = {
        "q": " and ".join(query_parts),
        "pageSize": str(page_size),
        "fields": "files(id,name,mimeType,size,modifiedTime,parents,kind),nextPageToken",
        "supportsAllDrives": "true",
        "includeItemsFromAllDrives": "true",
    }
    if page_token:
        params["pageToken"] = page_token

    response = await _drive_api_get(user_sub, "files", params)
    if response.status_code == 401:
        raise HTTPException(401, "Google Drive credential expired or revoked")
    if response.status_code >= 400:
        raise HTTPException(502, f"Google Drive API error ({response.status_code})")

    body = response.json() if response.content else {}
    files = body.get("files", [])
    next_page_token = body.get("nextPageToken")

    return {"files": files, "nextPageToken": next_page_token}


@router.post("/import")
async def import_drive_file(body: DriveImportReq, ctx=Depends(require_ui_session)) -> Dict[str, Any]:
    """Import (copy) a Drive file into the local file manager.

    Downloads the file from Drive via the backend proxy and uploads it
    to the user's file manager at the specified destination path.
    """
    from fastapi import UploadFile
    from app.services.filemanager import upload_file as fm_upload_file

    user_sub = ctx["user_sub"]

    # Ensure connected
    cred = _get_cred_safe(user_sub)
    if not cred:
        raise HTTPException(401, "Google Drive not connected")

    # Get file metadata
    meta_resp = await _drive_api_get(user_sub, f"files/{body.file_id}", {
        "fields": "id,name,mimeType,size",
        "supportsAllDrives": "true",
    })
    if meta_resp.status_code == 404:
        raise HTTPException(404, "Drive file not found")
    if meta_resp.status_code >= 400:
        raise HTTPException(502, f"Drive API error fetching metadata ({meta_resp.status_code})")

    file_meta = meta_resp.json() if meta_resp.content else {}
    file_name = file_meta.get("name", "imported_file")
    mime_type = file_meta.get("mimeType", "application/octet-stream")

    # Download file content
    download_url = f"{S.google_drive_api_base_url}/files/{body.file_id}"
    headers = _build_drive_headers(user_sub)
    download_resp = await asyncio.to_thread(
        requests.get,
        download_url,
        params={"alt": "media", "supportsAllDrives": "true"},
        headers=headers,
        timeout=S.google_drive_api_timeout_seconds,
    )
    if download_resp.status_code >= 400:
        raise HTTPException(502, f"Drive API error downloading file ({download_resp.status_code})")

    content = download_resp.content

    # Determine destination path
    dest_path = body.destination_path or f"/{file_name}"
    if not dest_path.startswith("/"):
        dest_path = f"/{dest_path}"

    # Upload to local file manager
    file_obj = UploadFile(
        filename=file_name,
        file=io.BytesIO(content),
        headers={"content-type": mime_type},
    )

    try:
        result = fm_upload_file(user_sub, dest_path, file_obj)
    except HTTPException as exc:
        if exc.status_code == 409:
            # File already exists - append timestamp suffix
            import os
            base, ext = os.path.splitext(dest_path)
            dest_path = f"{base}_{now_ts()}{ext}"
            file_obj = UploadFile(
                filename=file_name,
                file=io.BytesIO(content),
                headers={"content-type": mime_type},
            )
            result = fm_upload_file(user_sub, dest_path, file_obj)
        else:
            raise

    node_id = result.get("node_id", result.get("id", "")) or result.get("path", dest_path)
    return {"ok": True, "node_id": node_id, "path": dest_path}
