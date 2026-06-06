"""Google Drive integration endpoints for the frontend picker UI.

Provides OAuth connect/disconnect lifecycle, a browse proxy for the Drive
file picker dialog, and a file import endpoint that copies Drive files into
the local file manager.

All endpoints use cookie-based session auth (require_ui_session).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import logging
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
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
from app.services.provider_oauth import (
    build_google_oauth_start,
    complete_google_oauth_callback,
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


def _mock_state_secret() -> str:
    """Resolve the HMAC secret for mock-mode OAuth state, mirroring the service layer.

    Uses the same precedence as ``app.services.provider_oauth._state_signing_secret``:
    the dedicated ``google_oauth_state_signing_secret`` if set, otherwise the
    ``ui_access_token_secret`` fallback. This keeps the security primitive (HMAC over
    user_sub + timestamp with the same key) identical between dev/mock and prod paths
    (SECOPS-007), even though the real path additionally uses a single-use, DDB-backed
    state token via ``build_google_oauth_start`` / ``complete_google_oauth_callback``.
    """
    secret = (getattr(S, "google_oauth_state_signing_secret", "") or "").strip()
    if secret:
        return secret
    fallback = (getattr(S, "ui_access_token_secret", "") or "").strip()
    if fallback:
        return fallback
    raise HTTPException(500, "OAuth state signing secret not configured")


def _sign_mock_oauth_state(user_sub: str) -> str:
    """Generate a signed, time-limited OAuth state token for the dev/mock flow.

    Format: base64url("<user_sub>|<ts>|<nonce>|<hmac-sha256>")
    """
    secret = _mock_state_secret()
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    payload = f"{user_sub}|{ts}|{nonce}"
    sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    raw = f"{payload}|{sig}"
    return urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def _verify_mock_oauth_state(state: str, expected_user_sub: str) -> None:
    """Verify a signed mock-mode state token; raise HTTP 400 on any failure."""
    secret = _mock_state_secret()
    try:
        pad = "=" * ((4 - (len(state) % 4)) % 4)
        raw = urlsafe_b64decode((state + pad).encode("ascii")).decode("utf-8")
        sub, ts, nonce, sig = raw.split("|", 3)
    except Exception as exc:  # noqa: BLE001 - any malformed token is a 400
        raise HTTPException(400, "Invalid OAuth state") from exc

    payload = f"{sub}|{ts}|{nonce}"
    expected_sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(400, "Invalid OAuth state signature")
    if not hmac.compare_digest(sub, expected_user_sub):
        raise HTTPException(400, "OAuth state user mismatch")
    try:
        age = int(time.time()) - int(ts)
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, "Invalid OAuth state") from exc
    ttl = int(getattr(S, "google_oauth_state_ttl_seconds", 600) or 600)
    if age < 0 or age > ttl:
        raise HTTPException(400, "OAuth state expired")


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
        # GAP-0241: embed an HMAC-signed, time-limited state (not the predictable
        # "mock" literal) so the callback can verify the flow originated here.
        state = _sign_mock_oauth_state(user_sub)
        return {
            "auth_url": f"/files?drive-callback=1&code=mock_auth_code_{user_sub}&state={state}",
            "mock": True,
        }

    # GAP-0241 + GAP-0242: real OAuth flow delegates to the shared, tested provider
    # service which mints a single-use, HMAC-signed, DDB-backed state token and builds
    # the full Google authorization URL (client_id, redirect_uri, scope, state).
    start = build_google_oauth_start(user_sub)
    return {
        "auth_url": start["authorization_url"],
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
        # GAP-0241: verify the signed state before touching any credential store.
        if not body.state:
            raise HTTPException(400, "Missing OAuth state")
        _verify_mock_oauth_state(body.state, user_sub)

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

    # GAP-0241 + GAP-0242: real OAuth code exchange delegates to the shared provider
    # service, which (1) verifies the single-use HMAC-signed state, then (2) POSTs the
    # authorization code to S.google_oauth_token_url and stores access_token,
    # encrypted refresh_token, and expires_at. Runs in a thread so the (synchronous)
    # network call does not block the event loop.
    if not body.state:
        raise HTTPException(400, "Missing OAuth state")
    await asyncio.to_thread(
        complete_google_oauth_callback,
        user_sub,
        code=body.code,
        state=body.state,
    )
    return {"ok": True, "connected": True}


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
