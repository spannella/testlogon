# FILES-001: Encrypted One-Time Share Links

**Ticket**: FILES-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FILES-001 adds the ability to share files with external (non-platform) users via time-limited, encrypted, one-time-use download links. This bridges the gap between the platform's internal file sharing (which requires recipients to have accounts) and the common need to share files with clients, partners, or other external parties. Links are optionally password-protected, expire after a configurable duration, and become invalid after a set number of downloads.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Owner | As a file owner, I want to generate a one-time share link for a file so I can send it to someone without an account. | POST creates link; response includes shareable URL; link works without authentication. |
| Owner | As a file owner, I want to set an expiration time on the link. | Link expires after configured duration (1h, 6h, 24h, 7d, 30d). |
| Owner | As a file owner, I want to optionally set a password on the link. | Password required to download; bcrypt-hashed, not stored in plaintext. |
| Owner | As a file owner, I want the link to become invalid after the first download. | `max_downloads=1`; after first download, link returns 410 Gone. |
| Owner | As a file owner, I want to see all my active share links and revoke any of them. | Management page lists links; revoke button sets `is_revoked=true`. |
| External user | As a recipient, I want to open the link and download the file without creating an account. | Public endpoint; no auth; optional password prompt; file streams directly. |
| External user | As a recipient, I want to know if a link has expired or been used. | Clear error messages: "Link expired", "Link already used", "Link revoked". |

### 1.3 Why This Is Needed Now

Internal file sharing via `share_node()` requires the recipient to be a platform user. Many workflows require sharing with external parties — sending contracts to clients, sharing deliverables with partners, distributing resources to event attendees. Without external sharing, users resort to downloading files and re-uploading them to email or cloud storage, breaking the platform's value proposition as a single file management hub.

### 1.4 Security Design Principles

- **Encryption at rest**: File content is encrypted with a random AES-256 key before link creation. The key is encrypted with KMS and stored alongside the link record. On download, the key is decrypted via KMS and the file content is decrypted in-stream.
- **Short-lived by default**: Links default to 24-hour expiry and 1 download.
- **Password protection**: Optional but recommended. Bcrypt hash stored; password verified before download begins.
- **Audit trail**: Every link creation, download attempt, and revocation is logged.
- **Rate limiting**: Public download endpoint rate-limited by IP (10 requests/minute per link).

---

## 2. Current State Analysis

### 2.1 File Manager Infrastructure

`app/services/filemanager.py` provides full file tree management:
<!-- VERIFIED: app/services/filemanager.py — share_node:3919, download_file:2609, get_node:450 -->
- File nodes stored in DDB with `owner_sub`, `node_id`, `file_name`, `s3_key`, `content_type`, `size_bytes`
- S3 storage for file content (mocked via moto in dev)
- `share_node()` (line 3919) shares files to other platform users
- Download: `download_file()` (line 2609) streams file content from S3

### 2.2 KMS / Crypto Infrastructure

`app/core/crypto.py` provides:
<!-- VERIFIED: app/core/crypto.py:16 — kms_encrypt; kms_decrypt also present -->
- `kms_encrypt(plaintext: str) -> str` (line 16) — encrypt data with KMS
- `kms_decrypt(ciphertext: str) -> str` — decrypt data with KMS
- In dev mode, uses mock KMS server on port 7999

### 2.3 S3 Storage

Files are stored in S3 (mocked via moto). The file manager stores content at S3 keys like `files/{owner_sub}/{node_id}/{filename}`. For encrypted share links, the encrypted file content will be stored at a separate S3 key: `share-links/{link_id}/encrypted`.

### 2.4 Public Endpoints

The platform has existing public endpoints (no auth required):
- `GET /calendar/public/event/{cal_id}/{event_id}` — public calendar event
- `GET /public/...` prefix used for unauthenticated access

### 2.5 Gaps

1. **No `file_share_links` DDB table** — no storage for link metadata.
2. **No public download endpoint** — no unauthenticated file access.
3. **No file encryption for sharing** — files stored unencrypted in S3.
4. **No link management UI** — no page to view/revoke links.
5. **No password protection** — no bcrypt integration for link passwords.
6. **No download counting** — no mechanism to track and limit downloads.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `file_share_links`

| Attribute | Type | Description |
|-----------|------|-------------|
| `link_id` (PK) | String | `fsl_<uuid4_hex>` — also used in public URL |
| `sk` (SK) | String | `META` (single item per link) |
| `file_node_id` | String | File manager node ID of the shared file |
| `file_name` | String | Original filename (denormalized for display) |
| `file_size_bytes` | Number | Original file size |
| `content_type` | String | MIME type |
| `owner_sub` | String | User who created the link |
| `created_at` | Number | Unix timestamp |
| `expires_at` | Number | Unix timestamp when link expires |
| `max_downloads` | Number | Maximum allowed downloads (default: 1) |
| `download_count` | Number | Current download count |
| `password_hash` | String (optional) | Bcrypt hash of password (null if no password) |
| `encrypted_s3_key` | String | S3 key of encrypted file content |
| `encryption_key_encrypted` | Binary | AES-256 key encrypted with KMS |
| `is_revoked` | Boolean | Whether link has been revoked |
| `ttl` | Number | DynamoDB TTL for auto-deletion (set to `expires_at + 86400`) |

**GSIs**:

| GSI | PK | SK | Purpose |
|-----|----|----|---------|
| `GSI1` | `owner_sub` | `created_at` | List links by owner, sorted by creation time |
| `GSI2` | `file_node_id` | `created_at` | List links for a specific file |

**File**: `scripts/local-ddb-init.py`

```python
TableDef(
    name=S.ddb_file_share_links_table,
    pk="link_id",
    sk="sk",
    gsis=[
        GsiDef(name="GSI1", pk="owner_sub", sk="created_at"),
        GsiDef(name="GSI2", pk="file_node_id", sk="created_at"),
    ],
    attr_types={"created_at": "N", "expires_at": "N", "max_downloads": "N",
                "download_count": "N", "file_size_bytes": "N", "ttl": "N"},
),
```

### 3.2 Settings

**File**: `app/core/settings.py`

```python
# Encrypted share links (FILES-001)
ddb_file_share_links_table: str = os.environ.get("DDB_FILE_SHARE_LINKS_TABLE", "file_share_links")
share_link_default_expiry_hours: int = int(os.environ.get("SHARE_LINK_DEFAULT_EXPIRY_HOURS", "24"))
share_link_max_expiry_hours: int = int(os.environ.get("SHARE_LINK_MAX_EXPIRY_HOURS", "720"))  # 30 days
share_link_max_file_size_bytes: int = int(os.environ.get("SHARE_LINK_MAX_FILE_SIZE", "1073741824"))  # 1GB
share_link_s3_prefix: str = os.environ.get("SHARE_LINK_S3_PREFIX", "share-links")
share_link_base_url: str = os.environ.get("SHARE_LINK_BASE_URL", "http://localhost:3000/share")
```

### 3.3 Backend Service

**File**: `app/services/file_share_links.py`

```python
import bcrypt
from app.core.crypto import kms_encrypt, kms_decrypt

def create_share_link(
    *,
    file_node_id: str,
    owner_sub: str,
    expiry_hours: int = 24,
    max_downloads: int = 1,
    password: str | None = None,
) -> dict:
    """Create an encrypted one-time share link for a file."""
    # 1. Validate file exists and is owned by owner_sub
    # 2. Validate file size <= max
    # 3. Generate link_id = f"fsl_{uuid4().hex}"
    # 4. Generate random AES-256 key (32 bytes)
    # 5. Download file from S3
    # 6. Encrypt file content with AES-256-GCM
    # 7. Upload encrypted content to S3 at share-links/{link_id}/encrypted
    # 8. Encrypt AES key with KMS
    # 9. Hash password with bcrypt (if provided)
    # 10. Store DDB record
    # 11. Return link metadata + shareable URL

def download_share_link(
    *,
    link_id: str,
    password: str | None = None,
) -> StreamingResponse:
    """Download a file via share link (public, no auth)."""
    # 1. Get link record from DDB
    # 2. Validate: not revoked, not expired, download_count < max_downloads
    # 3. If password_hash set: verify password with bcrypt
    # 4. Increment download_count (conditional update to prevent race)
    # 5. Decrypt AES key with KMS
    # 6. Stream encrypted content from S3, decrypt in-stream
    # 7. Return StreamingResponse with correct content_type and filename

def list_share_links(owner_sub: str) -> list[dict]:
    """List all share links for a user."""
    # Query GSI1 by owner_sub, sorted by created_at desc

def revoke_share_link(link_id: str, owner_sub: str) -> bool:
    """Revoke a share link."""
    # 1. Get link; verify owner
    # 2. Set is_revoked=True
    # 3. Optionally delete encrypted S3 object

def get_share_link_info(link_id: str) -> dict | None:
    """Get link metadata (public — used by download page to show file info before download)."""
    # Return: file_name, file_size_bytes, is_expired, is_used, requires_password
    # Do NOT return: encrypted key, s3 key, owner info
```

### 3.4 Encryption Implementation

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_file_content(content: bytes, key: bytes) -> bytes:
    """Encrypt file content with AES-256-GCM."""
    nonce = os.urandom(12)  # 96-bit nonce
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, content, None)
    return nonce + ciphertext  # Prepend nonce for decryption

def decrypt_file_content(encrypted: bytes, key: bytes) -> bytes:
    """Decrypt file content with AES-256-GCM."""
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
```

### 3.5 Backend Router

**File**: `app/routers/file_share_links.py`

```python
# Authenticated endpoints (link management)
router = APIRouter(prefix="/ui/files/share-links", tags=["file-share-links"])

class CreateShareLinkIn(BaseModel):
    file_node_id: str = Field(..., max_length=128)
    expiry_hours: int = Field(default=24, ge=1, le=720)
    max_downloads: int = Field(default=1, ge=1, le=100)
    password: Optional[str] = Field(default=None, min_length=4, max_length=128)

@router.post("", status_code=201)
def create_share_link_endpoint(body: CreateShareLinkIn, ctx=Depends(require_ui_session)):
    """Create a new encrypted share link for a file."""

@router.get("")
def list_share_links_endpoint(ctx=Depends(require_ui_session)):
    """List all share links created by the current user."""

@router.delete("/{link_id}")
def revoke_share_link_endpoint(link_id: str, ctx=Depends(require_ui_session)):
    """Revoke a share link."""

# Public endpoints (no auth)
public_router = APIRouter(prefix="/public/files/share", tags=["public-file-share"])

@public_router.get("/{link_id}/info")
def get_share_link_info_endpoint(link_id: str):
    """Get share link info (file name, size, status). No auth required."""

@public_router.post("/{link_id}/download")
def download_share_link_endpoint(
    link_id: str,
    password: Optional[str] = Body(default=None),
):
    """Download a file via share link. No auth required. Password in body if needed."""
```

### 3.6 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface ShareLink {
  link_id: string;
  file_node_id: string;
  file_name: string;
  file_size_bytes: number;
  content_type: string;
  created_at: number;
  expires_at: number;
  max_downloads: number;
  download_count: number;
  has_password: boolean;
  is_revoked: boolean;
  share_url: string;
}

export interface ShareLinkPublicInfo {
  file_name: string;
  file_size_bytes: number;
  content_type: string;
  requires_password: boolean;
  is_expired: boolean;
  is_used: boolean;
  is_revoked: boolean;
}
```

### 3.7 Frontend API

**File**: `frontend/src/api/endpoints/files.ts`

```typescript
export const createShareLink = (data: {
  file_node_id: string;
  expiry_hours?: number;
  max_downloads?: number;
  password?: string;
}) => api.post<ShareLink>("/ui/files/share-links", data);

export const listShareLinks = () =>
  api.get<ShareLink[]>("/ui/files/share-links");

export const revokeShareLink = (linkId: string) =>
  api.delete(`/ui/files/share-links/${linkId}`);

// Public (no auth)
export const getShareLinkInfo = (linkId: string) =>
  axios.get<ShareLinkPublicInfo>(`/public/files/share/${linkId}/info`);

export const downloadShareLink = (linkId: string, password?: string) =>
  axios.post(`/public/files/share/${linkId}/download`, { password }, {
    responseType: "blob",
  });
```

### 3.8 Frontend Pages

**ShareLinkDialog** (`frontend/src/pages/files/ShareLinkDialog.tsx`):

- Triggered from file context menu in FilesPage: "Create Share Link"
- Form: expiry duration dropdown, max downloads input, optional password input
- On submit: calls `createShareLink`; shows generated URL with copy button
- `data-testid="share-link-dialog"`

**ShareLinksPage** (`frontend/src/pages/files/ShareLinksPage.tsx`):

- Route: `/files/share-links`
- Table of active share links: file name, created, expires, downloads used/max, status
- Revoke button per link
- Copy link button
- Filter: active / expired / revoked
- `data-testid="share-links-page"`

**PublicDownloadPage** (`frontend/src/pages/files/PublicDownloadPage.tsx`):

- Route: `/share/:linkId` (no auth required)
- Fetches link info via `getShareLinkInfo`
- Shows: file name, file size, formatted content type
- If password required: shows password input
- "Download" button triggers `downloadShareLink`
- Error states: "This link has expired", "This link has already been used", "This link has been revoked"
- `data-testid="public-download-page"`

### 3.9 Routes

**File**: `frontend/src/App.tsx`

```tsx
// Protected route
<Route path="/files/share-links" element={<ShareLinksPage />} />

// Public route (no auth wrapper)
<Route path="/share/:linkId" element={<PublicDownloadPage />} />
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/file_share_links.py` | Share link business logic + encryption + S3 |
| `app/routers/file_share_links.py` | REST endpoints (authenticated + public) |
| `frontend/src/pages/files/ShareLinkDialog.tsx` | Create share link dialog |
| `frontend/src/pages/files/ShareLinksPage.tsx` | Manage share links page |
| `frontend/src/pages/files/PublicDownloadPage.tsx` | Public download page (no auth) |
| `frontend/src/api/endpoints/fileShareLinks.ts` | API client functions |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `file_share_links` TableDef |
| `app/core/settings.py` | Add share link settings |
| `app/core/tables.py` | Add `T.file_share_links` |
| `app/main.py` | Register share link routers |
| `frontend/src/api/types.ts` | Add share link types |
| `frontend/src/App.tsx` | Add routes |
| `frontend/src/pages/files/FilesPage.tsx` | Add "Create Share Link" to context menu |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Share Links" nav item under Files |

### 4.3 Step-by-Step Order

1. Add DDB table, settings, table handle
2. Implement encryption utilities (AES-256-GCM)
3. Implement `file_share_links.py` service (create, download, list, revoke)
4. Implement router (authenticated + public endpoints)
5. Register routers in main.py
6. Add frontend types and API client
7. Build ShareLinkDialog (create flow)
8. Build ShareLinksPage (management)
9. Build PublicDownloadPage (public download)
10. Integrate into FilesPage context menu
11. Add routes
12. Write E2E tests

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/file-share-links.spec.ts` — 20 tests across 5 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let testFileNodeId: string;
let shareLinkId: string;
let shareLinkUrl: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice session
  // Upload a test file to file manager
  // Record node_id for share link creation
});
```

### 5.3 Section 312: Share Link Creation API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 312.1 | Create share link for owned file | POST `/ui/files/share-links`; 201; response has `link_id`, `share_url`, `expires_at` |
| 312.2 | Create share link with password | POST with `password`; 201; `has_password=true` |
| 312.3 | Create share link with custom expiry and max_downloads | POST `expiry_hours=168, max_downloads=5`; 201; fields match |
| 312.4 | Reject share link for non-owned file | POST with Bob's file; 403 |
| 312.5 | Reject share link for non-existent file | POST with fake node_id; 404 |

### 5.4 Section 313: Share Link Download API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 313.1 | Download via share link (no password) | POST `/public/files/share/{id}/download`; 200; response is file blob |
| 313.2 | Download with correct password | POST with `password`; 200; file downloads |
| 313.3 | Reject download with wrong password | POST with incorrect password; 403; "Invalid password" |
| 313.4 | Link becomes used after max_downloads reached | Download once (max_downloads=1); try again; 410; "Link already used" |
| 313.5 | Revoked link returns 410 | Revoke link; try download; 410; "Link revoked" |

### 5.5 Section 314: Share Link Management API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 314.1 | List share links returns created links | GET `/ui/files/share-links`; 200; array includes created link |
| 314.2 | Revoke share link | DELETE `/ui/files/share-links/{id}`; 200 |
| 314.3 | Revoked link no longer downloadable | POST download on revoked link; 410 |
| 314.4 | List shows revoked link with is_revoked=true | GET list; find link; `is_revoked=true` |

### 5.6 Section 315: Public Link Info API (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 315.1 | Get link info shows file details | GET `/public/files/share/{id}/info`; 200; `file_name`, `file_size_bytes` present |
| 315.2 | Info for expired link shows is_expired=true | Create link with expiry_hours=0 (edge); or mock; info shows `is_expired=true` |
| 315.3 | Info for password-protected link shows requires_password=true | Create link with password; get info; `requires_password=true` |

### 5.7 Section 316: Share Links UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 316.1 | Share link dialog opens from file context menu | Navigate to files; right-click/menu on file; click "Create Share Link"; dialog visible |
| 316.2 | Share links management page shows links | Navigate to `/files/share-links`; `[data-testid="share-links-page"]` visible; link listed |
| 316.3 | Public download page shows file info | Navigate to `/share/{linkId}` (unauthenticated); file name and download button visible |

### 5.8 Section 317: Concurrent Access & Edge Cases (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 317.1 | Two simultaneous downloads on max_downloads=2 link | Both succeed; download_count=2; third attempt gets 410 |
| 317.2 | Create link for soft-deleted file fails | Soft-delete file; POST create link; 404 "File not found" |
| 317.3 | Download with expired password link | Create link with password + 1h expiry; mock time past expiry; download returns 410 "expired" (not password prompt) |
| 317.4 | Large file share (near size limit) | Create link for file near max_file_size; encryption completes; download succeeds |
| 317.5 | Revoke link cleans up S3 encrypted object | Revoke link; verify S3 encrypted object deleted via mock S3 list |

### 5.9 Section 318: Share Link Info Endpoint (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 318.1 | Info endpoint returns file metadata without auth | GET `/public/files/share/{id}/info` with no cookies; 200; file_name, file_size_bytes present |
| 318.2 | Info endpoint does not reveal owner or S3 key | Response does NOT contain `owner_sub`, `s3_key`, or `encryption_key_encrypted` |
| 318.3 | Info for used link shows remaining_downloads=0 | Download link to exhaustion; GET info; `remaining_downloads=0`, `is_expired=false`, `is_used=true` |

### 5.10 API Request/Response Examples

**Create a share link** (curl):

```bash
curl -X POST http://localhost:8000/ui/files/share-links \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_a; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_a" \
  -d '{
    "file_node_id": "node_abc123",
    "expiry_hours": 24,
    "max_downloads": 3,
    "password": "s3cretP@ss"
  }'
```

**Response (201)**:
```json
{
  "link_id": "fsl_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "share_url": "http://localhost:3000/share/fsl_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "file_name": "project-plan.pdf",
  "expires_at": 1748606500,
  "max_downloads": 3,
  "has_password": true,
  "created_at": 1748520100
}
```

**Download via share link** (curl):

```bash
curl -X POST http://localhost:8000/public/files/share/fsl_a1b2c3d4/download \
  -H "Content-Type: application/json" \
  -d '{"password": "s3cretP@ss"}' \
  -o downloaded-file.pdf
```

**Response (200)**: Binary file stream with `Content-Disposition: attachment; filename="project-plan.pdf"` header.

**Get link info** (curl, no auth):

```bash
curl -X GET http://localhost:8000/public/files/share/fsl_a1b2c3d4/info
```

**Response (200)**:
```json
{
  "file_name": "project-plan.pdf",
  "file_size_bytes": 245760,
  "content_type": "application/pdf",
  "requires_password": true,
  "is_expired": false,
  "is_used": false,
  "remaining_downloads": 3
}
```

---

## 6. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| File not found | 404 | `file_not_found` | "File not found" | Verify file exists in file manager |
| File not owned by user | 403 | `forbidden` | "You don't have permission to share this file" | Only owner can create share links |
| File too large for sharing | 400 | `file_too_large` | "File exceeds 5GB maximum for sharing" | Use direct sharing instead |
| Link expired | 410 | `link_expired` | "This link has expired" | Request a new link from the owner |
| Link already used (downloads exhausted) | 410 | `link_used` | "This link has already been used" | Request a new link from the owner |
| Link revoked | 410 | `link_revoked` | "This link has been revoked by the owner" | Contact the owner |
| Wrong password | 403 | `invalid_password` | "Invalid password" | Re-enter correct password |
| Password attempts exceeded | 429 | `too_many_attempts` | "Too many password attempts. Try again in 1 minute." | Wait 60 seconds |
| Link not found | 404 | `link_not_found` | "Share link not found" | Check URL is correct |
| KMS decryption failure | 500 | `internal_error` | "Unable to process download" | Retry; contact support if persistent |
| S3 object missing | 500 | `internal_error` | "File content unavailable" | Owner must re-create share link |
| Unauthenticated (management endpoints) | 401 | `unauthorized` | "Authentication required" | Log in |
| CSRF mismatch | 403 | `csrf_invalid` | "Invalid CSRF token" | Refresh page |
| Rate limited (public download) | 429 | `rate_limited` | "Too many download attempts" | Wait and retry |
| Max active links per file exceeded | 400 | `max_links` | "Maximum of 10 active share links per file" | Revoke old links first |

---

## 7. Security Considerations

### 7.1 Encryption

- AES-256-GCM for file content encryption (authenticated encryption)
- Random 32-byte key per link (not derived from password)
- Key encrypted with KMS before storage
- Nonce (12 bytes) prepended to ciphertext; unique per encryption operation
- Original file in S3 is untouched; encrypted copy stored separately

### 7.2 Password Protection

- Bcrypt with work factor 12 for password hashing
- Password never stored in plaintext
- Password verified before download begins (before any decryption)
- Rate limiting on password attempts: 5 per minute per link ID per IP

### 7.3 Link ID Security

- Link IDs are 32-character hex UUIDs — 128 bits of entropy
- Not sequential or predictable
- Rate limiting on public download endpoint: 10 requests/minute per IP

### 7.4 Cleanup

- DynamoDB TTL auto-deletes expired link records (24h after `expires_at`)
- S3 encrypted objects cleaned up by TTL-triggered Lambda (or periodic cron in dev)
- Revoked links: S3 object deleted immediately on revocation

### 7.5 Information Disclosure

- Public info endpoint reveals only: file name, size, content type, link status
- Does not reveal: owner identity, S3 keys, encryption details

---

## 8. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| File encryption time | < 2s for 100MB file | AES-256-GCM with streaming encryption; process in 64KB chunks |
| Download latency | < 500ms TTFB | S3 streaming response with chunked transfer encoding |
| KMS key decryption | < 100ms | Single KMS decrypt call per download; key cached in-memory for duration of request |
| Password hashing latency | < 300ms | bcrypt work factor 12; acceptable for security-sensitive operation |
| Public endpoint abuse | < 10 req/min per IP | IP-based rate limiting via middleware |
| S3 encrypted object storage | Same as original | Encrypted copy stored in separate S3 prefix; TTL cleanup removes expired |
| DDB query for link status | < 5ms | Direct GetItem by link_id PK |
| Concurrent downloads | Support 100 concurrent | Each download is independent streaming response; no shared state |

### 8.1 Rate Limiting

| Endpoint | Limit | Scope | Window |
|----------|-------|-------|--------|
| POST `/public/files/share/{id}/download` | 10 requests | Per IP | 1 minute |
| POST `/public/files/share/{id}/download` (password) | 5 attempts | Per link ID + IP | 1 minute |
| POST `/ui/files/share-links` (create) | 20 links | Per user | 1 hour |
| GET `/public/files/share/{id}/info` | 30 requests | Per IP | 1 minute |

---

## 9. Observability

### 9.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `share_link_created_total` | Counter | `has_password`, `expiry_hours` | Share links created |
| `share_link_downloaded_total` | Counter | `has_password` | Successful downloads |
| `share_link_download_failed_total` | Counter | `reason` (expired/used/revoked/bad_password) | Failed download attempts |
| `share_link_revoked_total` | Counter | — | Links revoked by owner |
| `share_link_download_latency_ms` | Histogram | — | Download request latency (TTFB) |
| `share_link_encryption_latency_ms` | Histogram | — | File encryption time on link creation |
| `share_link_password_attempts_total` | Counter | `result` (success/failure) | Password verification attempts |

### 9.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Share link created | INFO | `user_sub`, `link_id`, `file_name`, `expiry_hours`, `max_downloads`, `has_password` |
| Share link downloaded | INFO | `link_id`, `download_ip`, `download_count`, `file_size_bytes` |
| Share link download rejected | WARN | `link_id`, `reason`, `download_ip` |
| Wrong password attempt | WARN | `link_id`, `attempt_ip`, `attempt_count` |
| Share link revoked | INFO | `user_sub`, `link_id` |
| KMS decryption error | ERROR | `link_id`, `error_message` |
| S3 object missing | ERROR | `link_id`, `s3_key` |

### 9.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High password failure rate | > 10 failures/min on single link | High | Possible brute force; increase rate limit |
| KMS decryption errors | Any KMS error | Critical | Check KMS key status and permissions |
| Download error rate | > 5% of downloads fail | High | Check S3 availability |
| Encryption time spike | p95 > 5s | Medium | Check file sizes and CPU |

---

## 10. Rollout Plan

### 10.1 Feature Flag

```python
# app/core/settings.py
share_links_enabled: bool = os.environ.get("SHARE_LINKS_ENABLED", "true").lower() == "true"
```

### 10.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend + table | Deploy DDB table + endpoints; flag OFF | 2 days | Unit tests pass; encryption validated |
| Phase 2: Internal | Enable for internal accounts | 3 days | E2E pass; security review |
| Phase 3: Canary 5% | Enable for 5% of users | 3 days | No KMS errors; download success rate > 99% |
| Phase 4: GA | Enable for all users | Permanent | No security incidents |

### 10.3 Migration

1. Create `file_share_links` table via `scripts/local-ddb-init.py` with TTL on `ttl_delete_at`
2. Add `bcrypt` and `cryptography` to `requirements.txt`
3. Create S3 prefix `encrypted-shares/` for encrypted file copies
4. Deploy KMS key alias for share link encryption (or reuse existing platform key)

### 10.4 Rollback

1. Set `SHARE_LINKS_ENABLED=false` — disables creation and download endpoints
2. Existing links become non-downloadable (404 from gated endpoint)
3. S3 encrypted objects remain (cleaned up by TTL or manual cleanup)
4. DDB records auto-expire via TTL
5. No impact on original files in S3

---

## 11. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| File manager service | Existing | Available (`app/services/filemanager.py` — `share_node:3919`, `download_file:2609`) |
| KMS crypto utilities | Existing | Available (`app/core/crypto.py:16` — `kms_encrypt`) |
| bcrypt | New pip dependency | Add to requirements |
| cryptography (AESGCM) | New pip dependency | Add to requirements |

---

## Codebase References

### Existing Files (verified)
| File | Key References | Lines |
|------|---------------|-------|
| `app/services/filemanager.py` | `share_node`, `download_file`, `get_node` | 3919, 2609, 450 |
| `app/core/crypto.py` | `kms_encrypt`, `kms_decrypt` | 16 |
| `scripts/local-ddb-init.py` | `file_manager` table definition | 158 |

### Files to Create (new implementation)
| File | Purpose |
|------|---------|
| `app/services/file_share_links.py` | Link CRUD, encryption, download logic |
| `app/routers/file_share_links.py` | API endpoints (authenticated + public) |
| `file_share_links` DDB table | Table definition in `scripts/local-ddb-init.py` |
| Frontend share links management page | UI for creating/managing share links |
