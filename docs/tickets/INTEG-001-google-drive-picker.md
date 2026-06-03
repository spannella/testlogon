# INTEG-001: Google Drive File Picker UI

**Ticket**: INTEG-001
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-27
**Priority**: P3 (Nice to Have)
**Estimated effort**: 5-7 days

---

## 1. Executive Summary

The backend has a complete Google Drive integration: a mock API (see `app/routers/google_drive_mock.py` with 10 endpoints), a `GoogleDriveProvider` class (see `app/services/file_providers.py:366`) that handles file operations via configurable URLs, a credential storage system (see `app/services/provider_credentials.py:482`), and a file mount system that bridges external providers into the file manager. E2E tests exist for the mock API (`google-drive-mock.spec.ts`). However, there is no frontend UI for connecting a Google Drive account, browsing Drive files, or importing/mounting Drive folders into the file manager.

This feature adds a "Connect Google Drive" OAuth flow in the Files settings, a Drive file browser dialog for selecting files to import or mount, and integration with the existing file mount system to make Drive files appear in the file manager tree. The Google Drive provider infrastructure represents a significant backend investment (over 750 lines across `GoogleDriveProvider`, credential management, and mock endpoints) that is currently invisible to end users. Without a frontend surface, this entire subsystem is dead code from the user's perspective.

The business case is straightforward: users store documents, images, and videos across cloud providers. Requiring manual download-then-upload to bring files into the platform creates friction that drives users toward simpler competitors. By surfacing the existing Google Drive integration, we unlock a zero-download import workflow and persistent mount points that keep Drive folders synchronized in the file manager tree. This directly reduces onboarding friction for users who already organize their content in Google Drive.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Connect Google Drive Account**

| Field | Value |
|-------|-------|
| Actor | Authenticated user |
| Story | As a user, I want to connect my Google Drive account from the Files settings so that I can access my Drive files within the platform. |
| Preconditions | User has a Google account with Drive access. |
| Acceptance Criteria | 1. "Connect Google Drive" button visible in Files settings panel. 2. Clicking opens OAuth popup/redirect. 3. After consent, connection status shows "Connected" with green indicator. 4. Connection persists across sessions (credentials stored encrypted in DDB). 5. In dev mode with `google_drive_mock_enabled=true`, the flow bypasses real OAuth and creates a mock credential automatically. |

**US-2: Browse Google Drive Files**

| Field | Value |
|-------|-------|
| Actor | User with connected Drive account |
| Story | As a user, I want to browse my Google Drive files in a picker dialog so that I can find and select files to import. |
| Preconditions | Google Drive account is connected (credential exists). |
| Acceptance Criteria | 1. "Browse Drive" button opens a dialog. 2. Dialog shows folder tree starting from "My Drive" root. 3. Clicking a folder navigates into it; breadcrumbs update. 4. Files show name, type icon, modified date, and size. 5. Search input filters files by name. 6. Only non-trashed files are shown. |

**US-3: Import a Drive File**

| Field | Value |
|-------|-------|
| Actor | User browsing Drive files |
| Story | As a user, I want to import a selected Drive file into my local file manager so that I have a platform-native copy. |
| Preconditions | Drive picker dialog is open with files listed. |
| Acceptance Criteria | 1. Selecting a file and clicking "Import" downloads it from Drive via the backend proxy. 2. The file appears in the user's current file manager directory. 3. Import progress is shown (spinner or progress bar). 4. After import, the dialog closes and the file list refreshes. 5. Duplicate file names are handled (append suffix or prompt). |

**US-4: Mount a Drive Folder**

| Field | Value |
|-------|-------|
| Actor | User browsing Drive folders |
| Story | As a user, I want to mount a Drive folder so it appears as a virtual directory in my file tree, synchronized with Drive. |
| Preconditions | `filemgr_google_drive_mounts_enabled=true` in settings. Drive account is connected. |
| Acceptance Criteria | 1. Selecting a folder and clicking "Mount" opens a mount configuration form. 2. User specifies the mount path in their file tree. 3. After mounting, the folder appears in the file manager sidebar with a Google Drive icon badge. 4. Files within the mount are listed via the `GoogleDriveProvider.list_files()` method. 5. Mount operations (list, get, upload) work through the provider abstraction. 6. Mount status (active/degraded/reauth_required) is displayed. |

**US-5: Disconnect Google Drive**

| Field | Value |
|-------|-------|
| Actor | User with connected Drive account |
| Story | As a user, I want to disconnect my Google Drive account so that the platform no longer has access to my Drive files. |
| Preconditions | Google Drive account is connected. |
| Acceptance Criteria | 1. "Disconnect" button visible when connected. 2. Clicking shows confirmation dialog. 3. After confirmation, credentials are revoked and deleted from DDB. 4. Connection status reverts to "Not connected". 5. Existing mounts show "revoked" status and stop syncing. 6. Imported files (copies) remain in the file manager. |

### 2.2 Pain Points

1. **Backend investment not surfaced**: Over 750 lines of Google Drive provider code (see `app/services/file_providers.py:366`), 300 lines of mock API (see `app/routers/google_drive_mock.py`), and credential management (see `app/services/provider_credentials.py:482`) exist but are invisible to users.
2. **No import workflow**: Users cannot bring Drive files into the platform without manual download/upload. This is particularly painful for media-heavy creators who store assets in Google Drive.
3. **No mount browsing**: The mount system supports Google Drive (see `app/routers/filemanager.py:3530`) but there is no UI to create a Drive mount. Only iCloud currently has UI mount support.
4. **OAuth flow is backend-only**: The `provider_oauth.py` module handles token exchange, but no frontend initiates or completes the flow.

---

## 3. Current State Analysis

### 3.1 Google Drive Mock API

`app/routers/google_drive_mock.py` provides a stateful in-memory mock that mirrors the Google Drive v3 API. The module defines two internal stores: `_FILES: Dict[str, Dict[str, Any]]` for file metadata and `_FILE_CONTENT: Dict[str, bytes]` for file content (line 16-17). The mock is gated by `S.google_drive_mock_enabled` (line 23).

Key mock endpoints:

| Endpoint | Line | Purpose |
|----------|------|---------|
| `GET /mock/google-drive/drive/v3/files/{file_id}` | 96 | Get file metadata |
| `GET /mock/google-drive/drive/v3/files` | 109 | List/search files (supports `q` param with parent, name, mimeType, trashed filters) |
| `POST /mock/google-drive/drive/v3/files` | 119 | Create file metadata |
| `PATCH /mock/google-drive/drive/v3/files/{file_id}` | 133 | Update metadata |
| `DELETE /mock/google-drive/drive/v3/files/{file_id}` | 160 | Delete file |
| Upload endpoints | 212, 242 | Simple and resumable upload |
| `POST /mock/google-drive/seed` | 273 | Seed test data |
| `POST /mock/google-drive/reset` | 294 | Reset state |

The mock query parser (`_matches_query`, line 62-89) supports the `q` parameter syntax used by the real Google Drive API:

```python
def _matches_query(f: Dict[str, Any], q: str) -> bool:
    if not q:
        return True
    parts = [p.strip() for p in q.split(" and ")]
    for part in parts:
        if part == "trashed=false":
            if f.get("trashed", False):
                return False
        elif part.endswith("in parents"):
            parent_id = part.split("in parents")[0].strip().strip("'\"")
            if parent_id not in (f.get("parents") or []):
                return False
        elif part.startswith("name="):
            val = part.split("=", 1)[1].strip().strip("'\"")
            if f.get("name") != val:
                return False
        # ... mimeType filters
```

The `_make_file` helper (line 38-59) creates file metadata objects with `id`, `name`, `mimeType`, `size`, `modifiedTime`, `parents`, `trashed`, and `kind` fields. Folders use `FOLDER_MIME = "application/vnd.google-apps.folder"` (line 19).

Bearer token authentication is enforced on all endpoints via `_require_bearer(req)` (line 27-31).

**Citations**:
- `app/routers/google_drive_mock.py:16-17` -- `_FILES` and `_FILE_CONTENT` in-memory stores
- `app/routers/google_drive_mock.py:22-24` -- `_ensure_mock_enabled()` guard
- `app/routers/google_drive_mock.py:62-89` -- `_matches_query()` Drive query parser
- `app/routers/google_drive_mock.py:96-294` -- 10 mock endpoints

### 3.2 Google Drive Provider

`app/services/file_providers.py:366` defines `GoogleDriveProvider`, a class implementing the file provider interface for Google Drive. Key implementation details:

```python
class GoogleDriveProvider:
    provider_name = "google_drive"

    def __init__(self, owner: str):
        self.owner = owner

    def _build_headers(self) -> Dict[str, str]:
        auth = get_provider_auth_context(self.owner, "google_drive")
        token = auth["token"]
        return {"Authorization": f"Bearer {token}"}
```

The provider supports:

- **Reference parsing** (`_parse_ref`, line 372-394): Parses `gdrive://me/items/<item_id>` for personal files and `gdrive://drive/<drive_id>/items/<item_id>` for shared drive files.
- **Retry logic** (`_request_with_retry`, line 422-460): Configurable retry with exponential backoff and jitter. Retries on 429 (rate limit) and 5xx errors. Respects `Retry-After` headers.
- **File operations**: `_get_file` (line 462) with field selection, `_list_files` (line 468) with parent folder query and pagination, shared drive support (`corpora=drive`, `driveId`).
- **Resumable uploads** (line 709+): Files above `google_drive_resumable_upload_threshold_bytes` (default 8MB) use the resumable upload protocol.
- **Error tracking**: All API errors are recorded via `record_filemgr_mount_api_error("google_drive", operation, ...)`.

The provider uses configurable base URLs from settings:

```python
url = f"{S.google_drive_api_base_url}/files/{quote(parsed['item_id'], safe='')}"
```

This means in dev mode, the base URL can be pointed at the mock API (`http://localhost:8000/mock/google-drive/drive/v3`).

**Citations**:
- `app/services/file_providers.py:366-367` -- `class GoogleDriveProvider`
- `app/services/file_providers.py:402-405` -- `_build_headers` with `get_provider_auth_context`
- `app/services/file_providers.py:407-417` -- `_request_retry_config()` with settings
- `app/services/file_providers.py:419-420` -- retryable status codes (429, 5xx)
- `app/services/file_providers.py:462-466` -- `_get_file` with field selection
- `app/services/file_providers.py:468-479` -- `_list_files` with shared drive support

### 3.3 Provider Credentials System

`app/services/provider_credentials.py:482-530` provides `get_provider_auth_context()` which:

1. Retrieves stored OAuth credentials by `(owner, provider)` tuple.
2. Checks required scopes against granted scopes (lines 491-494). Missing scopes raise 400.
3. For `google_drive` provider specifically:
   - Checks `reconnect_required` metadata flag (lines 496-508). If set, raises 401 with `provider_reconnect_required` error code, provider name, and reason string.
   - Checks token expiry (`expires_at` epoch, line 509-519). If expired or expiring within 60 seconds, triggers `refresh_google_oauth_access_token()` from `provider_oauth.py`.
4. Decrypts the stored token via `kms_decrypt(cred.token_ct_b64)` (line 522).

```python
def get_provider_auth_context(
    owner: str,
    provider: str,
    *,
    org: Optional[str] = None,
    required_scopes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    cred = get_provider_credential(owner, provider, org=org)
    granted = cred.scopes or []
    required = [s.strip().lower() for s in (required_scopes or []) if s and s.strip()]
    missing = [scope for scope in required if scope not in granted]
    if missing:
        raise HTTPException(status_code=400, detail=f"stored token missing scopes: {', '.join(missing)}")

    if cred.provider == "google_drive":
        metadata = dict(cred.metadata or {})
        if bool(metadata.get("reconnect_required")):
            reason = str(metadata.get("auth_failure_reason") or "revoked")
            raise HTTPException(
                status_code=401,
                detail={
                    "code": "provider_reconnect_required",
                    "provider": "google_drive",
                    "reason": reason,
                    "reconnect_required": True,
                },
            )
```

Credentials are encrypted with KMS and stored in DynamoDB. The storage schema uses `owner` as the lookup key and `provider` as a secondary discriminator.

**Citations**:
- `app/services/provider_credentials.py:482-530` -- full `get_provider_auth_context` implementation
- `app/services/provider_credentials.py:496-508` -- Google Drive reconnect check
- `app/services/provider_credentials.py:509-519` -- token expiry check and refresh

### 3.4 Google Drive Settings

`app/core/settings.py:852-868` defines the complete Google Drive configuration block:

```python
# OAuth settings
google_oauth_redirect_uri_allowlist: str = os.environ.get("GOOGLE_OAUTH_REDIRECT_URI_ALLOWLIST", "")
google_oauth_scopes: str = os.environ.get("GOOGLE_OAUTH_SCOPES", "https://www.googleapis.com/auth/drive.file")
google_oauth_state_ttl_seconds: int = int(os.environ.get("GOOGLE_OAUTH_STATE_TTL_SECONDS", "600"))
google_oauth_state_signing_secret: str = os.environ.get("GOOGLE_OAUTH_STATE_SIGNING_SECRET", "")
google_oauth_token_url: str = os.environ.get("GOOGLE_OAUTH_TOKEN_URL", "https://oauth2.googleapis.com/token")

# API settings
google_drive_api_base_url: str = "https://www.googleapis.com/drive/v3"
google_drive_upload_api_base_url: str = "https://www.googleapis.com/upload/drive/v3"
google_drive_mock_enabled: bool = False  # gated by GOOGLE_DRIVE_MOCK_ENABLED env
google_drive_api_timeout_seconds: float = 10.0
google_drive_api_retry_max_attempts: int = 3
google_drive_api_retry_base_delay_seconds: float = 0.2
google_drive_api_retry_jitter_seconds: float = 0.1
google_drive_resumable_upload_threshold_bytes: int = 8388608  # 8MB

# Mount feature flag
filemgr_google_drive_mounts_enabled: bool = False
```

Key observations:
- `google_drive_mock_enabled` defaults to `false`. Must be set to `true` in `.env.local` for development.
- `filemgr_google_drive_mounts_enabled` defaults to `false`. This gates the mount creation endpoints (`filemanager.py:3492`).
- Default OAuth scope is `drive.file` (limited to files created/opened by the app). For full browse capability, may need `drive.readonly` scope.
- OAuth state TTL is 600 seconds (10 minutes) with HMAC-signed state parameters.

**Citations**:
- `app/core/settings.py:852-859` -- OAuth settings (scopes, state TTL, signing secret, token URL)
- `app/core/settings.py:860-868` -- Drive API settings (base URLs, mock toggle, timeout, retry, resumable threshold, mount toggle)

### 3.5 File Mount System

The file manager has a complete mount CRUD system in `app/routers/filemanager.py`:

```python
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
```

Additional mount endpoints:
- `GET /mounts` (see `app/routers/filemanager.py:3550`) -- list all mounts for a user
- `PATCH /mounts/{mount_id}` (see `app/routers/filemanager.py:3558`) -- update mount path or provider ref
- `DELETE /mounts/{mount_id}` (see `app/routers/filemanager.py:3582`) -- remove a mount

The frontend `FilesPage.tsx` already has mount infrastructure:
- `mountStatusLabel()` (line 118-125) -- converts status codes to display strings
- `mountStatusVariant()` (line 127-133) -- maps status to Badge variants (default/secondary/destructive/outline)
- `resolveMountForPath()` (line 148-164) -- resolves which mount a given path belongs to, preferring longest prefix match
- Import of `initiateICloudMount`, `verifyICloudMount`, `listMounts`, `rotateICloudMount`, `revokeICloudMount` from files API (lines 72-76)

**Citations**:
- `app/routers/filemanager.py:3530` -- `create_mount_route` endpoint
- `app/routers/filemanager.py:3550` -- `list_mounts_route` endpoint
- `app/routers/filemanager.py:3558` -- `update_mount_route` endpoint
- `frontend/src/pages/files/FilesPage.tsx:118-133` -- mount status helpers
- `frontend/src/pages/files/FilesPage.tsx:148-164` -- `resolveMountForPath` function

### 3.6 E2E Tests (Existing)

`frontend/e2e/google-drive-mock.spec.ts` tests the mock API endpoints (seed, list, get, create, update, delete, upload, reset). These tests validate that the mock faithfully emulates the Google Drive v3 API. The new E2E tests for the picker UI will build on this foundation.

### 3.7 Gaps

1. No frontend Google Drive file picker or browser component.
2. No "Connect Google Drive" UI flow or OAuth redirect handling in the frontend.
3. No `frontend/src/api/endpoints/google-drive.ts` endpoint file.
4. No backend OAuth initiation endpoint (the credential storage exists but no connect/callback endpoints).
5. No mount creation UI for Google Drive (only iCloud has UI mount support).
6. No Drive browse proxy endpoint (the `GoogleDriveProvider` exists but is only used for mount operations, not for user-facing browsing).
7. No disconnect endpoint to revoke credentials.
8. No integration status check endpoint.

---

## 4. Implementation Plan

### 4.1 Backend: Integration Router

**New file: `app/routers/google_drive_integration.py`**

This router handles the OAuth connect/disconnect lifecycle and provides a browse proxy for the frontend picker dialog. All endpoints are under `/ui/integrations/google-drive/` and use cookie-based session auth.

#### 4.1.1 OAuth Connect Flow

```python
from fastapi import APIRouter, Depends, Query
from app.auth.deps import require_ui_session
from app.core.settings import S
from app.core.time import now_ts
from app.services.provider_credentials import (
    has_provider_credential,
    store_provider_credential,
    delete_provider_credential,
)

router = APIRouter(prefix="/ui/integrations/google-drive", tags=["integrations"])


class GoogleDriveCallbackReq(BaseModel):
    code: str = Field(..., min_length=1, max_length=2048)
    redirect_uri: str = Field(..., min_length=1, max_length=2048)
    state: Optional[str] = None


class GoogleDriveStatusResp(BaseModel):
    connected: bool
    email: Optional[str] = None
    scopes: Optional[List[str]] = None
    connected_at: Optional[int] = None


@router.get("/status", response_model=GoogleDriveStatusResp)
async def google_drive_status(ctx=Depends(require_ui_session)):
    """Check if Google Drive is connected for the current user."""
    user_sub = ctx["user_sub"]
    cred = _get_cred_safe(user_sub)
    if not cred:
        return GoogleDriveStatusResp(connected=False)
    return GoogleDriveStatusResp(
        connected=True,
        email=cred.metadata.get("email") if cred.metadata else None,
        scopes=cred.scopes,
        connected_at=cred.created_at,
    )


@router.get("/connect")
async def initiate_google_drive_connect(ctx=Depends(require_ui_session)):
    """Generate OAuth authorization URL for Google Drive.

    In dev mode with google_drive_mock_enabled=true, returns a mock
    callback URL that auto-completes the connection.
    """
    user_sub = ctx["user_sub"]
    redirect_uri = f"{S.app_base_url}/files?drive-callback=1"

    if S.dev_mode and S.google_drive_mock_enabled:
        # Mock mode: skip real OAuth, return a mock code
        return {
            "auth_url": f"{redirect_uri}&code=mock_auth_code_{user_sub}&state=mock",
            "mock": True,
        }

    state = _sign_oauth_state(user_sub)
    scopes = S.google_oauth_scopes
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={S.google_oauth_client_id}"
        f"&redirect_uri={quote(redirect_uri)}"
        f"&response_type=code"
        f"&scope={quote(scopes)}"
        f"&access_type=offline"
        f"&prompt=consent"
        f"&state={state}"
    )
    return {"auth_url": auth_url}


@router.post("/callback")
async def complete_google_drive_connect(
    body: GoogleDriveCallbackReq,
    ctx=Depends(require_ui_session),
):
    """Exchange OAuth code for tokens and store encrypted credentials."""
    user_sub = ctx["user_sub"]

    if S.dev_mode and S.google_drive_mock_enabled:
        # Mock mode: store a mock credential
        _store_mock_credential(user_sub)
        return {"ok": True, "connected": True}

    # Validate state parameter
    if not _verify_oauth_state(body.state, user_sub):
        raise HTTPException(400, "Invalid or expired OAuth state")

    # Exchange code for tokens
    tokens = _exchange_code(body.code, body.redirect_uri)
    store_provider_credential(
        user_sub,
        provider="google_drive",
        access_token=tokens["access_token"],
        refresh_token=tokens.get("refresh_token"),
        scopes=tokens.get("scope", "").split(),
        expires_at=now_ts() + int(tokens.get("expires_in", 3600)),
        metadata={"email": tokens.get("email")},
    )
    return {"ok": True, "connected": True}


@router.post("/disconnect")
async def disconnect_google_drive(ctx=Depends(require_ui_session)):
    """Revoke and delete Google Drive credentials."""
    user_sub = ctx["user_sub"]
    delete_provider_credential(user_sub, "google_drive")
    return {"ok": True}
```

#### 4.1.2 Drive Browse Proxy

```python
@router.get("/files")
async def browse_drive_files(
    folder_id: str = Query("root", max_length=256),
    q: Optional[str] = Query(None, max_length=500),
    page_token: Optional[str] = Query(None, max_length=2048),
    page_size: int = Query(50, ge=1, le=200),
    ctx=Depends(require_ui_session),
):
    """List files in a Google Drive folder. Proxies to Google Drive API
    (or mock) using stored credentials.

    Returns:
        {
            "files": [
                {
                    "id": "abc123",
                    "name": "My Document.pdf",
                    "mimeType": "application/pdf",
                    "size": "1048576",
                    "modifiedTime": "2026-05-27T10:00:00.000Z",
                    "parents": ["root"],
                    "kind": "drive#file"
                }
            ],
            "nextPageToken": "..."
        }
    """
    user_sub = ctx["user_sub"]
    provider = GoogleDriveProvider(user_sub)

    query_parts = [f"'{folder_id}' in parents", "trashed=false"]
    if q:
        query_parts.append(f"name contains '{_sanitize_drive_query(q)}'")

    files, next_token = provider.list_files_paginated(
        query=" and ".join(query_parts),
        page_size=page_size,
        page_token=page_token,
    )
    return {"files": files, "nextPageToken": next_token}


@router.get("/files/{file_id}")
async def get_drive_file(
    file_id: str,
    ctx=Depends(require_ui_session),
):
    """Get metadata for a single Drive file."""
    user_sub = ctx["user_sub"]
    provider = GoogleDriveProvider(user_sub)
    file_meta = provider.get_file_metadata(file_id)
    return file_meta


@router.post("/import")
async def import_drive_file(
    body: DriveImportReq,
    ctx=Depends(require_ui_session),
):
    """Import (copy) a Drive file into the local file manager.

    Downloads the file from Drive via the provider and uploads it
    to the user's file manager at the specified destination path.
    """
    user_sub = ctx["user_sub"]
    provider = GoogleDriveProvider(user_sub)

    # Download from Drive
    content, metadata = provider.download_file(body.file_id)

    # Upload to local file manager
    dest_path = body.destination_path or f"/{metadata['name']}"
    node = create_file_node(user_sub, dest_path, content, metadata["mimeType"])

    return {"ok": True, "node_id": node["node_id"], "path": dest_path}
```

#### 4.1.3 Pydantic Models (add to `app/models.py`)

```python
class GoogleDriveCallbackReq(BaseModel):
    code: str = Field(..., min_length=1, max_length=2048)
    redirect_uri: str = Field(..., min_length=1, max_length=2048)
    state: Optional[str] = None


class DriveImportReq(BaseModel):
    file_id: str = Field(..., min_length=1, max_length=256)
    destination_path: Optional[str] = Field(None, max_length=1024)


class DriveFileOut(BaseModel):
    id: str
    name: str
    mimeType: str
    size: Optional[str] = None
    modifiedTime: Optional[str] = None
    parents: Optional[List[str]] = None
    kind: str = "drive#file"
```

### 4.2 Backend: Router Registration

**File: `app/main.py`**

Add import and registration:

```python
from app.routers.google_drive_integration import router as google_drive_integration_router

app.include_router(google_drive_integration_router)
```

### 4.3 Frontend: API Client

**New file: `frontend/src/api/endpoints/google-drive.ts`**

```typescript
import { api } from "@/api/client";
import type { DriveFile, DriveStatusResp, DriveFilesResp } from "@/api/types";

// ── Status ─────────────────────────────────────────────────────

export const getGoogleDriveStatus = () =>
  api.get<DriveStatusResp>("/ui/integrations/google-drive/status");

// ── Connect / Disconnect ───────────────────────────────────────

export const initiateGoogleDriveConnect = () =>
  api.get<{ auth_url: string; mock?: boolean }>(
    "/ui/integrations/google-drive/connect",
  );

export const completeGoogleDriveConnect = (
  code: string,
  redirectUri: string,
  state?: string,
) =>
  api.post("/ui/integrations/google-drive/callback", {
    code,
    redirect_uri: redirectUri,
    state,
  });

export const disconnectGoogleDrive = () =>
  api.post("/ui/integrations/google-drive/disconnect");

// ── Browse ─────────────────────────────────────────────────────

export const browseGoogleDriveFiles = (params: {
  folder_id?: string;
  q?: string;
  page_token?: string;
  page_size?: number;
}) =>
  api.get<DriveFilesResp>("/ui/integrations/google-drive/files", { params });

export const getGoogleDriveFile = (fileId: string) =>
  api.get<DriveFile>(`/ui/integrations/google-drive/files/${fileId}`);

// ── Import ─────────────────────────────────────────────────────

export const importDriveFile = (
  fileId: string,
  destinationPath?: string,
) =>
  api.post<{ ok: boolean; node_id: string; path: string }>(
    "/ui/integrations/google-drive/import",
    { file_id: fileId, destination_path: destinationPath },
  );
```

### 4.4 Frontend: TypeScript Types

**File: `frontend/src/api/types.ts`** (additions)

```typescript
// ── Google Drive ────────────────────────────────────────────────

export interface DriveFile {
  id: string;
  name: string;
  mimeType: string;
  size?: string;
  modifiedTime?: string;
  parents?: string[];
  kind: string;
}

export interface DriveStatusResp {
  connected: boolean;
  email?: string;
  scopes?: string[];
  connected_at?: number;
}

export interface DriveFilesResp {
  files: DriveFile[];
  nextPageToken?: string;
}
```

### 4.5 Frontend: Google Drive Picker Dialog

**New file: `frontend/src/components/shared/GoogleDrivePickerDialog.tsx`**

Component architecture:

```
GoogleDrivePickerDialog
├── Dialog (shadcn)
│   ├── DialogHeader
│   │   ├── Title: "Google Drive"
│   │   └── Search Input
│   ├── Breadcrumbs
│   │   └── [My Drive] > [Subfolder] > [Current]
│   ├── File List (scrollable)
│   │   ├── DriveFileRow (folder — clickable to navigate)
│   │   │   ├── FolderIcon
│   │   │   ├── Name
│   │   │   └── Modified date
│   │   └── DriveFileRow (file — selectable)
│   │       ├── FileIcon (by mimeType)
│   │       ├── Name
│   │       ├── Size (formatted)
│   │       ├── Modified date
│   │       └── Checkbox (for selection)
│   ├── Pagination ("Load more" button when nextPageToken exists)
│   └── DialogFooter
│       ├── Cancel button
│       ├── Import button (enabled when files selected)
│       └── Mount button (enabled when folder selected, hidden if mounts disabled)
```

Key implementation details:

```typescript
import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Folder, FileText, Image, Video, Search, ChevronRight } from "lucide-react";
import { toast } from "sonner";
import {
  browseGoogleDriveFiles,
  importDriveFile,
} from "@/api/endpoints/google-drive";
import { createMount } from "@/api/endpoints/files";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";

const FOLDER_MIME = "application/vnd.google-apps.folder";

interface BreadcrumbEntry {
  id: string;
  name: string;
}

interface GoogleDrivePickerDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onImportComplete?: (path: string) => void;
  mountsEnabled?: boolean;
  currentPath?: string;  // destination path for imports
}

export function GoogleDrivePickerDialog({
  open,
  onOpenChange,
  onImportComplete,
  mountsEnabled = false,
  currentPath = "/",
}: GoogleDrivePickerDialogProps) {
  const queryClient = useQueryClient();
  const [breadcrumbs, setBreadcrumbs] = useState<BreadcrumbEntry[]>([
    { id: "root", name: "My Drive" },
  ]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedFiles, setSelectedFiles] = useState<Set<string>>(new Set());
  const [selectedFolder, setSelectedFolder] = useState<string | null>(null);

  const currentFolderId = breadcrumbs[breadcrumbs.length - 1]?.id ?? "root";

  const { data, isLoading } = useQuery({
    queryKey: ["drive-files", currentFolderId, searchQuery],
    queryFn: () =>
      browseGoogleDriveFiles({
        folder_id: currentFolderId,
        q: searchQuery || undefined,
        page_size: 100,
      }),
    enabled: open,
    staleTime: 30_000,
  });

  const importMut = useMutation({
    mutationFn: (fileId: string) => importDriveFile(fileId, currentPath),
    onSuccess: (result) => {
      toast.success("File imported successfully");
      onImportComplete?.(result.path);
      queryClient.invalidateQueries({ queryKey: ["files"] });
    },
    onError: () => toast.error("Failed to import file"),
  });

  const navigateToFolder = useCallback(
    (folderId: string, folderName: string) => {
      setBreadcrumbs((prev) => [...prev, { id: folderId, name: folderName }]);
      setSelectedFiles(new Set());
      setSelectedFolder(null);
    },
    [],
  );

  const navigateToBreadcrumb = useCallback((index: number) => {
    setBreadcrumbs((prev) => prev.slice(0, index + 1));
    setSelectedFiles(new Set());
    setSelectedFolder(null);
  }, []);

  // ... render logic
}
```

React Query keys:
- `["drive-status"]` -- connection status
- `["drive-files", folderId, searchQuery]` -- file listing per folder
- `["drive-file", fileId]` -- single file metadata

### 4.6 Frontend: Connect Button in Files Settings

**File: `frontend/src/pages/files/FilesPage.tsx`** (modification)

Add a "Google Drive" integration section. The section appears alongside the existing iCloud mount management area. It shows connection status and provides connect/disconnect/browse actions.

```typescript
// New state and queries for Google Drive
const driveStatusQuery = useQuery({
  queryKey: ["drive-status"],
  queryFn: getGoogleDriveStatus,
  staleTime: 60_000,
});

const driveConnected = driveStatusQuery.data?.connected ?? false;

// In the settings/integrations area of FilesPage:
<div className="mt-4 rounded-md border p-4">
  <div className="flex items-center justify-between">
    <div className="flex items-center gap-2">
      <HardDrive className="h-5 w-5 text-muted-foreground" />
      <span className="font-medium">Google Drive</span>
      {driveConnected ? (
        <Badge variant="default" className="ml-2">Connected</Badge>
      ) : (
        <Badge variant="outline" className="ml-2">Not connected</Badge>
      )}
    </div>
    <div className="flex gap-2">
      {driveConnected ? (
        <>
          <Button size="sm" onClick={() => setDrivePickerOpen(true)}>
            Browse Files
          </Button>
          <Button size="sm" variant="destructive" onClick={handleDisconnect}>
            Disconnect
          </Button>
        </>
      ) : (
        <Button size="sm" onClick={handleConnect}>
          Connect Google Drive
        </Button>
      )}
    </div>
  </div>
  {driveConnected && driveStatusQuery.data?.email && (
    <p className="mt-1 text-xs text-muted-foreground">
      Connected as {driveStatusQuery.data.email}
    </p>
  )}
</div>
```

### 4.7 Frontend: Mount Integration

When a user selects "Mount" on a Drive folder in the picker dialog, the mount creation flow:

1. Prompt for a mount path (default: `/<folder_name>`).
2. Call `POST /mounts` with `provider: "google_drive"`, `mount_path`, `provider_root_ref: "gdrive://me/items/<folder_id>"`, `mode: "readonly"`.
3. On success, invalidate `["mounts"]` query and show success toast.
4. The mounted folder appears in the file tree with a Google Drive icon badge (using existing `resolveMountForPath`).

The mount button is only shown when `filemgr_google_drive_mounts_enabled` is `true`. This can be determined by checking if `listMounts()` returns 200 (vs. 400/404 when disabled).

### 4.8 OAuth Popup/Redirect Flow

The frontend connect flow uses a popup window pattern:

```typescript
async function handleConnect() {
  const { auth_url } = await initiateGoogleDriveConnect();

  // Open OAuth in popup
  const popup = window.open(auth_url, "google-drive-connect", "width=600,height=700");

  // Listen for callback via postMessage or URL change
  const interval = setInterval(() => {
    try {
      if (popup?.closed) {
        clearInterval(interval);
        return;
      }
      const url = popup?.location?.href;
      if (url?.includes("drive-callback=1")) {
        const params = new URLSearchParams(new URL(url).search);
        const code = params.get("code");
        const state = params.get("state");
        if (code) {
          popup.close();
          clearInterval(interval);
          handleCallback(code, state);
        }
      }
    } catch {
      // Cross-origin — ignore until redirect completes
    }
  }, 500);
}
```

In mock mode (`mock: true` response), the callback URL points to the same origin, so the popup completes immediately.

---

## 5. Data Model

### 5.1 Provider Credentials (Existing Table)

No new DynamoDB table is needed. Google Drive credentials are stored in the existing provider credentials table:

| Attribute | Type | Example |
|-----------|------|---------|
| `owner` (PK) | S | `"user_abc123"` |
| `provider` (SK) | S | `"google_drive"` |
| `token_ct_b64` | S | KMS-encrypted access token (base64) |
| `refresh_token_ct_b64` | S | KMS-encrypted refresh token (base64) |
| `scopes` | L | `["https://www.googleapis.com/auth/drive.file"]` |
| `metadata` | M | `{"email": "user@gmail.com", "expires_at": "1716580000", "reconnect_required": false}` |
| `created_at` | N | `1716580000` |
| `updated_at` | N | `1716580000` |

### 5.2 File Mounts (Existing Table)

Mount records for Google Drive folders use the existing mounts table:

| Attribute | Type | Example |
|-----------|------|---------|
| `owner` (PK) | S | `"user_abc123"` |
| `mount_id` (SK) | S | `"mnt_def456"` |
| `provider` | S | `"google_drive"` |
| `mount_path` | S | `"/Google Drive/My Folder"` |
| `provider_root_ref` | S | `"gdrive://me/items/abc123folderid"` |
| `mode` | S | `"readonly"` or `"readwrite"` |
| `status` | S | `"active"` |
| `created_at` | N | `1716580000` |

---

## 6. API Design

### 6.1 GET /ui/integrations/google-drive/status

Check connection status.

**Auth**: Cookie session (`require_ui_session`)
**Response** (200):
```json
{
  "connected": true,
  "email": "user@gmail.com",
  "scopes": ["https://www.googleapis.com/auth/drive.file"],
  "connected_at": 1716580000
}
```

**Error codes**: 401 (not authenticated)

### 6.2 GET /ui/integrations/google-drive/connect

Generate OAuth authorization URL.

**Auth**: Cookie session
**Response** (200):
```json
{
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&redirect_uri=...&response_type=code&scope=...&access_type=offline&prompt=consent&state=...",
  "mock": false
}
```

### 6.3 POST /ui/integrations/google-drive/callback

Exchange OAuth code for tokens.

**Auth**: Cookie session + CSRF
**Request**:
```json
{
  "code": "4/0AX4XfWi...",
  "redirect_uri": "https://app.example.com/files?drive-callback=1",
  "state": "signed_state_token"
}
```
**Response** (200): `{"ok": true, "connected": true}`
**Error codes**: 400 (invalid state), 502 (token exchange failed)

### 6.4 POST /ui/integrations/google-drive/disconnect

Revoke credentials.

**Auth**: Cookie session + CSRF
**Response** (200): `{"ok": true}`

### 6.5 GET /ui/integrations/google-drive/files

Browse Drive files.

**Auth**: Cookie session
**Query params**: `folder_id` (default "root"), `q` (search), `page_token`, `page_size` (1-200, default 50)
**Response** (200):
```json
{
  "files": [
    {
      "id": "abc123",
      "name": "Documents",
      "mimeType": "application/vnd.google-apps.folder",
      "size": null,
      "modifiedTime": "2026-05-27T10:00:00.000Z",
      "parents": ["root"],
      "kind": "drive#file"
    },
    {
      "id": "def456",
      "name": "photo.jpg",
      "mimeType": "image/jpeg",
      "size": "2048000",
      "modifiedTime": "2026-05-26T15:30:00.000Z",
      "parents": ["root"],
      "kind": "drive#file"
    }
  ],
  "nextPageToken": "eyJ..."
}
```
**Error codes**: 401 (not connected), 502 (Drive API error)

### 6.6 POST /ui/integrations/google-drive/import

Import a file from Drive to local file manager.

**Auth**: Cookie session + CSRF
**Request**:
```json
{
  "file_id": "abc123",
  "destination_path": "/imported/photo.jpg"
}
```
**Response** (200):
```json
{
  "ok": true,
  "node_id": "nd_xyz789",
  "path": "/imported/photo.jpg"
}
```
**Error codes**: 400 (invalid path), 404 (Drive file not found), 409 (destination exists), 502 (download failed)

---

## 7. Frontend Implementation Details

### 7.1 Component Tree

```
FilesPage
├── [existing file manager UI]
├── Google Drive Integration Section
│   ├── Connection Status Badge
│   ├── Connect/Disconnect Button
│   └── Browse Files Button (opens picker)
└── GoogleDrivePickerDialog
    ├── DialogHeader
    │   ├── DialogTitle: "Google Drive"
    │   └── Search Input (debounced 300ms)
    ├── Breadcrumbs (clickable folder chain)
    │   └── ChevronRight separator
    ├── ScrollArea (file list)
    │   ├── DriveFileRow[] (folders first, then files)
    │   │   ├── TypeIcon (Folder/FileText/Image/Video by mimeType)
    │   │   ├── File name
    │   │   ├── Size (formatted via formatBytesCompact)
    │   │   ├── Modified date
    │   │   └── Select checkbox (files only)
    │   ├── Empty state ("No files in this folder")
    │   └── Loading skeleton (3 rows)
    ├── Load More button (when nextPageToken exists)
    └── DialogFooter
        ├── Cancel (closes dialog)
        ├── Import Selected (N files) -- disabled when 0 selected
        └── Mount Folder (shown only when mountsEnabled && folder selected)
```

### 7.2 React Query Keys

| Key | Purpose | staleTime |
|-----|---------|-----------|
| `["drive-status"]` | Connection status check | 60s |
| `["drive-files", folderId, searchQuery]` | File listing per folder | 30s |
| `["drive-file", fileId]` | Single file metadata | 60s |
| `["mounts"]` | Mount list (existing) | 30s |
| `["files"]` | File manager contents (existing, invalidated on import) | - |

### 7.3 State Management

Local component state only (no Zustand store needed):
- `drivePickerOpen: boolean` -- dialog visibility
- `breadcrumbs: BreadcrumbEntry[]` -- folder navigation stack
- `searchQuery: string` -- debounced search input
- `selectedFiles: Set<string>` -- selected file IDs for import
- `selectedFolder: string | null` -- selected folder ID for mount

### 7.4 File Type Icon Mapping

```typescript
function driveFileIcon(mimeType: string) {
  if (mimeType === FOLDER_MIME) return <Folder className="h-4 w-4 text-blue-500" />;
  if (mimeType.startsWith("image/")) return <Image className="h-4 w-4 text-green-500" />;
  if (mimeType.startsWith("video/")) return <Video className="h-4 w-4 text-purple-500" />;
  if (mimeType === "application/pdf") return <FileText className="h-4 w-4 text-red-500" />;
  return <FileText className="h-4 w-4 text-muted-foreground" />;
}
```

### 7.5 Responsive Design

- Desktop: Dialog is 640px wide with 400px tall scroll area.
- Mobile: Dialog fills width, scroll area fills remaining height.
- File rows: icon, name, and size on mobile; full row with modified date on desktop.
- Breadcrumbs: horizontal scroll with overflow on mobile.

---

## 8. Testing Plan

### 8.1 Unit Tests (pytest)

**File**: `tests/test_google_drive_integration.py`

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | `test_status_not_connected` | No credential stored | GET /status returns `{"connected": false}` |
| 2 | `test_status_connected` | Store mock credential | GET /status returns `{"connected": true, "email": "..."}` |
| 3 | `test_connect_mock_mode` | `google_drive_mock_enabled=true` | GET /connect returns mock auth_url with `mock: true` |
| 4 | `test_callback_stores_credential` | Mock mode | POST /callback with mock code; subsequent GET /status returns connected |
| 5 | `test_disconnect_removes_credential` | Store credential | POST /disconnect; GET /status returns not connected |
| 6 | `test_browse_files_requires_connection` | No credential | GET /files returns 401 |
| 7 | `test_browse_files_returns_list` | Mock mode, seed files | GET /files returns non-empty files array |
| 8 | `test_browse_subfolder` | Seed folder + child files | GET /files?folder_id=X returns children only |
| 9 | `test_browse_search` | Seed files with known names | GET /files?q=keyword returns matching files |
| 10 | `test_import_copies_file` | Seed Drive file | POST /import returns ok + node_id; file exists in file manager |
| 11 | `test_callback_invalid_state` | Real OAuth mode | POST /callback with bad state returns 400 |
| 12 | `test_disconnect_clears_mounts` | Create mount, then disconnect | Mount status changes to "revoked" |

### 8.2 E2E Tests

**File**: `frontend/e2e/google-drive-picker.spec.ts`

**Section 1: Connection Status API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | GET /status returns connection state | 200; `connected` field is boolean |
| 2 | Mock connect flow creates credential | POST /callback with mock code; status returns `connected: true` |
| 3 | Disconnect revokes credential | After disconnect, status returns `connected: false` |

**Section 2: Browse API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 4 | Browse files after connect returns file list | Seed mock files; GET /files returns non-empty array |
| 5 | Browse subfolder returns children | GET /files?folder_id=X returns only children of X |
| 6 | Search filters by name | GET /files?q=keyword returns matching files |
| 7 | File metadata includes required fields | Each file has id, name, mimeType, kind |

**Section 3: Import API (2 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 8 | Import copies file to file manager | POST /import; file exists at destination path |
| 9 | Import with destination path works | POST /import with custom path; path matches |

**Section 4: Picker UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 10 | Drive picker dialog opens when connected | Click "Browse Files"; dialog title "Google Drive" visible |
| 11 | Folder navigation updates breadcrumbs | Click folder; breadcrumb shows folder name |
| 12 | File selection enables Import button | Select a file; "Import" button becomes enabled |
| 13 | Search input filters displayed files | Type search term; file list updates |

**Section 5: Connect/Disconnect UI (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 14 | Connect button visible when disconnected | "Connect Google Drive" button visible |
| 15 | After connect, status shows "Connected" | Badge text changes to "Connected" |
| 16 | Disconnect shows confirmation and reverts status | "Disconnect" button; confirm; badge changes to "Not connected" |

### 8.3 Manual Testing Checklist

1. Start dev stack with `GOOGLE_DRIVE_MOCK_ENABLED=1` in `.env.local`.
2. Navigate to Files page. Verify "Google Drive" section shows "Not connected".
3. Click "Connect Google Drive". Verify mock connection completes instantly.
4. Click "Browse Files". Verify picker dialog opens with empty state.
5. Seed mock data via POST /mock/google-drive/seed. Refresh picker. Verify files appear.
6. Click a folder. Verify breadcrumbs update and children are listed.
7. Select a file and click "Import". Verify file appears in file manager.
8. Click "Disconnect". Verify status reverts to "Not connected".

---

## 9. Security Considerations

### 9.1 OAuth Security

- **State parameter**: The OAuth state parameter is HMAC-signed with `google_oauth_state_signing_secret` and includes a timestamp. The `_verify_oauth_state` function rejects states older than `google_oauth_state_ttl_seconds` (default 600s). This prevents CSRF attacks on the OAuth callback.
- **Redirect URI allowlist**: `google_oauth_redirect_uri_allowlist` restricts valid redirect URIs. The callback endpoint validates that the provided `redirect_uri` matches the allowlist.
- **PKCE**: If supported by the Google OAuth implementation, use S256 PKCE challenge for additional security.

### 9.2 Credential Storage

- Access tokens and refresh tokens are encrypted at rest via KMS (`kms_encrypt` in `provider_credentials.py`).
- Credentials are scoped per-user (`owner` PK). Users cannot access another user's Drive credentials.
- Token refresh happens server-side; refresh tokens are never exposed to the frontend.

### 9.3 Drive API Proxy

- All Drive API calls go through the backend proxy. The frontend never receives raw Drive API tokens.
- The `_sanitize_drive_query` function strips potentially dangerous characters from search queries before forwarding to the Drive API.
- File size limits should be enforced on imports to prevent abuse (e.g., max 500MB per import).

### 9.4 CSRF Protection

All mutating endpoints (POST /callback, POST /disconnect, POST /import) require the `x-csrf-token` header, which is automatically included by the axios client in `api/client.ts`.

### 9.5 Input Validation

- `file_id` is validated as a non-empty string with max length 256.
- `folder_id` defaults to "root" and has max length 256.
- `destination_path` is validated as a valid file path (max length 1024).
- `q` (search query) has max length 500 to prevent abuse.
- `page_size` is bounded 1-200.

---

## 10. Performance Considerations

### 10.1 Drive API Rate Limits

Google Drive API has a per-user rate limit of 12,000 queries per minute. The backend should:
- Cache file listings in memory (or a short-lived DDB cache) for 30 seconds to avoid redundant API calls when the user navigates back to a previously visited folder.
- Use exponential backoff on 429 responses (already implemented in `GoogleDriveProvider._request_with_retry`, line 422).
- Limit `page_size` to 200 to avoid large responses.

### 10.2 Import Performance

- Small files (< 5MB): Direct download + upload in a single request.
- Large files (5MB - 100MB): Stream download from Drive to S3 without buffering the entire file in memory.
- Very large files (> 100MB): Consider returning a "pending" status with a background job that completes the import asynchronously.

### 10.3 Frontend Caching

- Drive status: staleTime 60s (connection status rarely changes).
- File listings: staleTime 30s (files may be modified in Drive).
- Single file metadata: staleTime 60s.
- Search results: no cache (always fresh for query changes).

### 10.4 Dialog Performance

- Lazy-load the `GoogleDrivePickerDialog` component via React.lazy() to avoid adding to the initial bundle.
- File list uses windowed rendering (react-window) if more than 100 files to prevent DOM bloat.

---

## 11. Migration & Rollout

### 11.1 Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `GOOGLE_DRIVE_MOCK_ENABLED` | `false` | Enables mock API for dev/test |
| `FILEMGR_GOOGLE_DRIVE_MOUNTS_ENABLED` | `false` | Gates mount creation (import-only when false) |

Both flags already exist in `app/core/settings.py:862,868`. No new flags needed.

### 11.2 Rollout Plan

1. **Phase 1** (this ticket): Ship connect/browse/import with mounts disabled. This surfaces the existing backend investment with minimal risk.
2. **Phase 2** (future): Enable `filemgr_google_drive_mounts_enabled`. This requires additional testing of mount sync reliability and error handling.

### 11.3 Backwards Compatibility

- No database migration needed. Uses existing provider credentials and mounts tables.
- No breaking changes to existing APIs.
- The new router is additive (new endpoints only).

### 11.4 Rollback

Disable the feature by:
1. Removing the router registration from `app/main.py`.
2. The frontend integration section will show an error (API 404) and can be hidden with a simple feature flag check.

---

## 12. Acceptance Criteria

1. A "Connect Google Drive" button in Files settings initiates the OAuth flow (or mock connection in dev mode).
2. After connecting, the connection status shows "Connected" with a green indicator and the connected email address.
3. A Google Drive file picker dialog allows browsing folders and searching files.
4. Files show correct type icons, names, sizes, and modification dates.
5. Folder navigation updates breadcrumbs and lists children correctly.
6. Files can be imported (copied) from Google Drive into the local file manager.
7. Folders can be mounted from Google Drive, appearing in the file manager tree (when `filemgr_google_drive_mounts_enabled=true`).
8. A "Disconnect" button revokes the Google Drive connection and clears stored credentials.
9. In dev mode (`google_drive_mock_enabled=true`), the flow works against the mock API without requiring real Google credentials.
10. The `filemgr_google_drive_mounts_enabled` setting gates mount creation (when `false`, only import is available).
11. All 16 E2E tests pass.
12. OAuth state parameter is HMAC-signed and time-limited.
13. Credentials are encrypted at rest via KMS.

---

## 13. Dependencies

- **File Manager (existing)**: Mount creation endpoint (see `app/routers/filemanager.py:3530`), file upload API.
- **Provider Credentials (existing)**: `provider_credentials.py` credential storage and retrieval.
- **Google Drive Mock (existing)**: `google_drive_mock.py` mock API for development.
- **GoogleDriveProvider (existing)**: `file_providers.py:366` provider class for API calls.
- **Provider OAuth (existing)**: `provider_oauth.py` token exchange and refresh.

---

## 14. Open Questions & Risks

### 14.1 Open Questions

1. **OAuth scope**: Should we request `drive.file` (limited to app-created files) or `drive.readonly` (full read access)? `drive.readonly` provides full browsing but is a broader scope that may concern privacy-sensitive users.
2. **Shared drives**: Should the picker show Shared Drives in addition to "My Drive"? The `GoogleDriveProvider` already supports shared drives (`corpora=drive`, `driveId` params) but the UI would need a drive selector.
3. **File size limit for imports**: What is the maximum file size for a single import? The upload infrastructure supports presigned uploads for files > 5MB, but very large files (> 1GB) may time out.
4. **Conflict resolution**: When importing a file whose name already exists at the destination, should we rename, overwrite, or prompt?

### 14.2 Risks

1. **Google OAuth review**: If the app uses restricted scopes, Google requires OAuth verification review (2-4 weeks). The mock mode mitigates this for development.
2. **Token refresh reliability**: Access tokens expire after 1 hour. The refresh flow in `provider_credentials.py:509-519` handles this, but edge cases (revoked refresh token, network errors during refresh) need robust error handling and user-visible reconnect prompts.
3. **Rate limiting**: Heavy Drive users with thousands of files may hit the 12,000 queries/minute limit. The caching strategy mitigates this, but aggressive browsing + search could still trigger throttling.

---

## 15. Files to Create

| File | Purpose |
|------|---------|
| `app/routers/google_drive_integration.py` | OAuth connect/disconnect, browse proxy, import endpoint |
| `frontend/src/api/endpoints/google-drive.ts` | API client functions |
| `frontend/src/components/shared/GoogleDrivePickerDialog.tsx` | Drive file browser and picker dialog |
| `frontend/e2e/google-drive-picker.spec.ts` | E2E tests |
| `tests/test_google_drive_integration.py` | Unit tests |

## 16. Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `google_drive_integration` router |
| `app/models.py` | Add `GoogleDriveCallbackReq`, `DriveImportReq`, `DriveFileOut` models |
| `frontend/src/pages/files/FilesPage.tsx` | Add "Google Drive" integration section with connect/browse/disconnect |
| `frontend/src/api/types.ts` | Add `DriveFile`, `DriveStatusResp`, `DriveFilesResp` interfaces |

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Google Drive mock API | `app/routers/google_drive_mock.py` | 96-294 | VERIFIED: 10 endpoints |
| Mock gated by setting | `app/routers/google_drive_mock.py` | 22-24 | VERIFIED: `_ensure_mock_enabled()` |
| Mock in-memory stores | `app/routers/google_drive_mock.py` | 16-17 | VERIFIED: `_FILES`, `_FILE_CONTENT` |
| Mock query parser | `app/routers/google_drive_mock.py` | 62-89 | VERIFIED: `_matches_query()` |
| Mock bearer auth | `app/routers/google_drive_mock.py` | 27-31 | VERIFIED: `_require_bearer()` |
| GoogleDriveProvider class | `app/services/file_providers.py` | 366-737 | VERIFIED |
| Provider auth context | `app/services/file_providers.py` | 402-405 | VERIFIED: `get_provider_auth_context(self.owner, "google_drive")` |
| Retry logic with backoff | `app/services/file_providers.py` | 422-460 | VERIFIED: `_request_with_retry` |
| API base URL config | `app/services/file_providers.py` | 464 | VERIFIED: `f"{S.google_drive_api_base_url}/files/..."` |
| Shared drive support | `app/services/file_providers.py` | 477-479 | VERIFIED: `corpora=drive`, `driveId` params |
| Provider credentials system | `app/services/provider_credentials.py` | 482-530 | VERIFIED: `get_provider_auth_context` |
| Google Drive reconnect check | `app/services/provider_credentials.py` | 496-508 | VERIFIED: `reconnect_required` metadata |
| Token expiry and refresh | `app/services/provider_credentials.py` | 509-519 | VERIFIED: early refresh at 60s before expiry |
| OAuth settings | `app/core/settings.py` | 852-859 | VERIFIED: client_id, scopes, state TTL, token URL |
| Google Drive settings | `app/core/settings.py` | 860-868 | VERIFIED: base URLs, mock, timeout, retry, mount toggle |
| Mount creation endpoint | `app/routers/filemanager.py` | 3530 | VERIFIED: `create_mount_route` |
| Mount list endpoint | `app/routers/filemanager.py` | 3550 | VERIFIED: `list_mounts_route` |
| Mount update endpoint | `app/routers/filemanager.py` | 3558 | VERIFIED: `update_mount_route` |
| FilesPage mount status helpers | `frontend/src/pages/files/FilesPage.tsx` | 118-133 | VERIFIED: `mountStatusLabel`, `mountStatusVariant` |
| FilesPage mount path resolution | `frontend/src/pages/files/FilesPage.tsx` | 148-164 | VERIFIED: `resolveMountForPath` |
| FilesPage iCloud mount imports | `frontend/src/pages/files/FilesPage.tsx` | 72-76 | VERIFIED: iCloud-specific imports |
| Google Drive mock E2E tests | `frontend/e2e/google-drive-mock.spec.ts` | exists | VERIFIED |
| No frontend Google Drive UI | `frontend/src/pages/files/` | all | VERIFIED: no Drive picker or browser component |
| No google-drive endpoint file | `frontend/src/api/endpoints/` | all | VERIFIED: no google-drive.ts file |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_google_drive_picker.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_connect_google_drive_stores_credentials`
  - `test_list_drive_files`
  - `test_import_drive_file_to_file_manager`
  - `test_mount_drive_folder`
  - `test_disconnect_google_drive_removes_credentials`
  - `test_refresh_token_flow`

### Integration Tests

  - OAuth flow stores encrypted credentials via provider_credentials service
  - Drive file import downloads content and creates file manager entry
  - Mount creates bidirectional sync between Drive folder and file manager

### E2E Tests (Playwright)

**File**: `frontend/e2e/google-drive-picker.spec.ts`
**Test count**: 10

**Auth pattern**: Use `injectAuth(page, "root")` for admin endpoints; use `injectAuth(page, "alice")` for user-level endpoints. All POST/PATCH/DELETE requests include `x-csrf-token` header matching the session's CSRF token.

**Negative tests**:
- 401: Unauthenticated request returns 401
- 403: Non-admin/non-owner access returns 403
- 404: Non-existent resource returns 404
- 409: Conflict on duplicate or already-processed resource
- 422: Invalid input (bad field values, missing required fields)

**Edge cases**:
- Empty result sets return 200 with empty arrays (not 404)
- Pagination cursor works correctly across pages
- Concurrent requests do not produce inconsistent state

### Test Data Requirements

- **DDB seeds**: Seed `No new tables (uses existing file provider and credential tables)` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `GOOGLE_DRIVE_PICKER_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| (none) | — | This ticket has no blocking dependencies |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| (none) | — | No other tickets depend on this one |

### Merge Strategy

**Independent**

This ticket can be merged independently of other tickets. It introduces new tables/endpoints without modifying existing ones in a breaking way.

### Merge Checklist

- [ ] All new DDB tables added to `scripts/local-ddb-init.py` with correct `attr_types` for numeric GSI keys
- [ ] New settings added to `app/core/settings.py` and `.env.local.example`
- [ ] New table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Pydantic models added to `app/models.py`
- [ ] TypeScript types added to `frontend/src/api/types.ts`
- [ ] Route added to `frontend/src/App.tsx`
- [ ] Feature flag defaults to `true` in `.env.local.example`
- [ ] E2E session setup updated if new test identities needed
- [ ] `just restart` completes cleanly with new tables
- [ ] All 10 E2E tests pass with `npx playwright test google-drive-picker.spec.ts`
