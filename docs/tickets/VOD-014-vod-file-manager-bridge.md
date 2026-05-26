# VOD-014: VOD ↔ File Manager Bridge

**Ticket**: VOD-014
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-25

---

## 1. Overview & Motivation

The platform has two independent systems for handling video content:

1. **VOD Pipeline** (`app/routers/vod.py`, `app/services/video_metadata_store.py`, `app/services/transcode_worker.py`): Handles presigned upload → S3 storage in `local-uploads` → transcoding to HLS in `vod-output` → playback via VideoPlayerPage. Videos are tracked in the `VideoMetadata` DynamoDB table with full lifecycle state (probing → encoding → published).

2. **File Manager** (`app/services/filemanager.py`, `app/routers/filemanager.py`): Hierarchical virtual filesystem backed by DynamoDB (`file_manager` table) with S3 object storage. Supports folders, uploads, sharing, search, encryption, media preview extraction (poster frames, hover clips), usage metering, and mount integrations (Google Drive, SFTP, iCloud).

These systems are completely disconnected today:
- A video uploaded through the VOD pipeline does not appear in the user's file manager.
- A video file uploaded through the file manager cannot be sent to the transcoding pipeline for HLS packaging.
- Users must mentally track which videos live where, and there is no unified view.

**This ticket bridges the two systems**, enabling:
- Videos that complete transcoding to automatically appear as file manager nodes (with special video metadata and "Watch" action).
- File manager video files to be imported into the VOD pipeline with a single action, reusing the existing S3 object rather than re-uploading.
- Storage deduplication: the same S3 object is referenced by both systems — never copied.

---

## 2. Current State Analysis

### 2.1 VOD Video Record Structure

From `app/models_video.py`, a `VideoMetadataModel` contains:

```python
id: str                              # "v_<uuid4_hex>"
owner_user_id: str
title: str
status: VideoStatus                  # created → probing → encoding → published
source_type: VideoSourceType         # "upload" | "broadcast_archive" | "api"
source_file_node_id: Optional[str]   # <-- already exists but unused
source_s3_key: Optional[str]         # S3 key in local-uploads bucket
thumbnail_s3_key: Optional[str]
thumbnail_url: Optional[str]
hls_manifest_s3_key: Optional[str]
hls_manifest_url: Optional[str]
duration_seconds: Optional[float]
width: Optional[int]
height: Optional[int]
file_size_bytes: Optional[int]
```

Key observation: `source_file_node_id` already exists on the model but is never populated. This is the designed join point from VOD → File Manager.

### 2.2 File Manager Node Structure

From `filemanager.py::upload_file()`, a file node DynamoDB item contains:

```python
{
    "PK": "USER#{user_sub}",
    "SK": "NODE#{/path/to/file.mp4}",
    "type": "file",
    "path": "/Videos/my-video.mp4",
    "name": "my-video.mp4",
    "name_lc": "my-video.mp4",
    "parent": "/Videos/",
    "created_at": "2026-05-25T00:00:00+00:00",
    "updated_at": "2026-05-25T00:00:00+00:00",
    "size": 104857600,
    "content_type": "video/mp4",
    "duration_seconds": 120,
    "thumbnail": {"bucket": "...", "key": "..._thumb.jpg", "content_type": "image/jpeg"},
    "s3_bucket": "local-filemgr",
    "s3_key": "{user}/objects/{uuid}",
    "etag": "\"abc123\"",
    "media_inspection": {...},          # ffprobe output
    "media_preview_keys": {...},        # poster_image, hover_clip paths
    "media_preview_status": "ready",    # or pending/failed
    "poster_url": "...",
    "hover_preview_url": "...",
    "is_encrypted": false,
    "GSI1PK": "USER#{user}",
    "GSI1SK": "NAME#my-video.mp4#PATH#/Videos/my-video.mp4",
    "GSI2PK": "PARENT#/Videos/",
    "GSI2SK": "TYPE#file#NAME#my-video.mp4#PATH#/Videos/my-video.mp4",
}
```

### 2.3 Transcode Worker Completion Hook

In `app/services/transcode_worker.py::execute_transcode_job()`, after successful transcoding:

```python
# Line 188: transitions video status to published
from app.services.video_metadata_store import transition_video_status
transition_video_status(video_id=job["video_id"], to_status="published")
```

This is the ideal injection point for the VOD → File Manager auto-link: immediately after successful transcoding, before the function returns.

### 2.4 VOD Upload Flow

From `app/routers/vod.py`:
1. `POST /ui/videos/upload/presign` — creates a `VideoMetadataModel` (status=`created`), generates S3 key `videos/{user}/{video_id}/{filename}`, returns presigned PUT URL.
2. Client uploads directly to S3 via the presigned URL.
3. `POST /ui/videos/{video_id}/upload/complete` — verifies S3 object exists via HeadObject, transitions status to `probing`, triggers pipeline.

The S3 key pattern is `videos/{user_sub}/{video_id}/{filename}` in bucket `local-uploads`.

### 2.5 File Manager S3 Key Pattern

File manager uses `{user_sub}/objects/{uuid}` in bucket `local-filemgr` (`S.filemgr_bucket`, from `FILEMGR_BUCKET` env var). VOD uses `local-uploads` (`S.video_upload_bucket`). **These are different S3 buckets.** When linking VOD videos to the file manager, the file node's `s3_bucket` field is set to the VOD bucket (`S.video_upload_bucket`), creating a cross-bucket reference. This works because the file manager reads `item["s3_bucket"]` per-node for downloads, so each node can reference any bucket.

---

## 3. Technical Design

### 3.1 New Service: `app/services/vod_file_bridge.py`

Central bridge service that orchestrates both directions of the integration.

```python
"""VOD ↔ File Manager bridge service (VOD-014).

Provides two integration directions:
1. link_video_to_filemanager() — creates a file node for a transcoded VOD video
2. import_file_to_vod() — creates a VOD record from an existing file manager video
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import HTTPException

from app.core.settings import S
from app.core.time import now_ts
from app.services.filemanager import (
    create_empty_folder,
    ensure_folder_exists,
    get_node,
    node_key,
    norm_path,
    now_iso,
    pk_user,
    put_node,
    sk_node,
    split_parent_name,
    build_media_derivative_layout,
    _enqueue_media_preview_job,
    _put_token_entries,
    _table,
)
from app.services.video_metadata_store import (
    create_video,
    get_video,
    video_to_item,
    transition_video_status,
)

logger = logging.getLogger(__name__)

DEFAULT_VIDEO_FOLDER = "/Videos/"
```

### 3.2 Direction 1: VOD → File Manager (Auto-Link)

#### 3.2.1 Bridge Function

```python
def link_video_to_filemanager(
    video_id: str,
    *,
    target_folder: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a file manager node that soft-links to a VOD video.

    Called after transcoding completes. Creates a virtual file node
    in the user's file manager that references the original S3 object.
    The node carries VOD-specific metadata for UI rendering.

    Args:
        video_id: The VOD video_id (e.g., "v_abc123")
        target_folder: Optional folder path (default: /Videos/)

    Returns:
        Dict with "path", "video_id", "linked" fields.
    """
    video = get_video(video_id)
    owner = video.owner_user_id
    folder = norm_path(target_folder or DEFAULT_VIDEO_FOLDER, is_folder=True)

    # Auto-create /Videos/ folder if it doesn't exist
    _ensure_videos_folder(owner, folder)

    # Determine file name from video title
    filename = _safe_filename(video.title, video.source_s3_key)
    file_path = norm_path(f"{folder}{filename}", is_folder=False)

    # Check if already linked (idempotent)
    try:
        existing = get_node(owner, file_path)
        if existing.get("vod_video_id") == video_id:
            return {"path": file_path, "video_id": video_id, "linked": False}
    except HTTPException as exc:
        if exc.status_code != 404:
            raise

    # Resolve S3 location — cross-bucket reference: file node points to VOD bucket, not filemgr bucket.
    # This works because file manager reads item["s3_bucket"] per-node for downloads.
    s3_bucket = S.video_upload_bucket or "local-uploads"
    s3_key = video.source_s3_key or ""
    if not s3_key:
        logger.warning("Cannot link video %s: no source_s3_key", video_id)
        return {"path": "", "video_id": video_id, "linked": False}

    # Build file node with VOD metadata overlay
    parent, name = split_parent_name(file_path)
    content_type = _infer_content_type(video.source_s3_key)
    size = video.file_size_bytes or 0

    item = {
        "PK": pk_user(owner),
        "SK": sk_node(file_path),
        "type": "file",
        "path": file_path,
        "name": name,
        "name_lc": name.lower(),
        "parent": parent,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "upload_at": now_iso(),
        "upload_by": owner,
        "size": size,
        "content_type": content_type,
        "duration_seconds": video.duration_seconds,
        "s3_bucket": s3_bucket,
        "s3_key": s3_key,
        "is_encrypted": False,
        # ── VOD bridge fields ──
        "vod_video_id": video_id,
        "vod_linked": True,
        "vod_status": video.status,
        "vod_hls_manifest_url": video.hls_manifest_url,
        "vod_thumbnail_url": video.thumbnail_url,
        "vod_duration_seconds": video.duration_seconds,
        "vod_width": video.width,
        "vod_height": video.height,
        "vod_linked_at": now_iso(),
        # ── GSI keys ──
        "GSI1PK": pk_user(owner),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{file_path}",
        "GSI2PK": f"PARENT#{parent}",
        "GSI2SK": f"TYPE#file#NAME#{name.lower()}#PATH#{file_path}",
    }

    # Reuse VOD thumbnail as poster_url if available
    if video.thumbnail_url:
        item["poster_url"] = video.thumbnail_url
        item["media_preview_status"] = "ready"
    else:
        # Enqueue media preview job to generate poster/hover clip from source
        item.update(build_media_derivative_layout(owner, s3_key, None, size))

    put_node(item)

    if not video.thumbnail_url:
        _enqueue_media_preview_job(owner, item)

    _put_token_entries(owner, item)

    # Update VOD record with the file node reference
    _update_video_source_file_node(video_id, file_path)

    logger.info("Linked VOD video %s to file manager path %s", video_id, file_path)
    return {"path": file_path, "video_id": video_id, "linked": True}
```

#### 3.2.2 Helper Functions

```python
def _ensure_videos_folder(owner: str, folder: str) -> None:
    """Create the target folder (and parents) if it doesn't exist."""
    try:
        ensure_folder_exists(owner, folder)
    except HTTPException as exc:
        if exc.status_code == 400 and "does not exist" in str(exc.detail):
            # Create the folder hierarchy
            create_empty_folder(owner, folder)
        else:
            raise


def _safe_filename(title: str, s3_key: Optional[str]) -> str:
    """Generate a filesystem-safe filename from video title."""
    import re
    # Extract extension from original S3 key
    ext = ".mp4"
    if s3_key and "." in s3_key.split("/")[-1]:
        ext = "." + s3_key.split("/")[-1].rsplit(".", 1)[-1]

    # Sanitize title
    safe = re.sub(r"[^\w\s\-.]", "", title.strip())[:200]
    if not safe:
        safe = "video"
    return f"{safe}{ext}"


def _infer_content_type(s3_key: Optional[str]) -> str:
    """Infer MIME type from S3 key extension."""
    if not s3_key:
        return "video/mp4"
    lower = s3_key.lower()
    if lower.endswith(".webm"):
        return "video/webm"
    if lower.endswith(".mov"):
        return "video/quicktime"
    if lower.endswith(".mkv"):
        return "video/x-matroska"
    if lower.endswith(".avi"):
        return "video/x-msvideo"
    return "video/mp4"


def _update_video_source_file_node(video_id: str, file_path: str) -> None:
    """Set source_file_node_id on the video record (back-link)."""
    from app.core.tables import T
    try:
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET source_file_node_id = :p, updated_at = :t",
            ExpressionAttributeValues={":p": file_path, ":t": now_ts()},
        )
    except Exception:
        logger.warning("Failed to set source_file_node_id on video %s", video_id)
```

#### 3.2.3 Integration Point in Transcode Worker

Modify `app/services/transcode_worker.py::execute_transcode_job()` — after the existing `transition_video_status` call (line ~188):

```python
# Existing code:
try:
    from app.services.video_metadata_store import transition_video_status
    transition_video_status(video_id=job["video_id"], to_status="published")
except Exception:
    logger.warning("Could not transition video %s to published", job["video_id"])

# NEW: VOD-014 — Auto-link to file manager
try:
    from app.services.vod_file_bridge import link_video_to_filemanager
    link_video_to_filemanager(job["video_id"])
except Exception:
    logger.warning(
        "VOD-014: Could not link video %s to file manager",
        job["video_id"],
        exc_info=True,
    )
```

The bridge call is wrapped in a try/except to ensure transcoding completion is never blocked by a file manager error.

#### 3.2.4 Deletion Semantics

Deleting the file manager node does NOT delete the VOD record. The `_soft_delete_node` function in `filemanager.py` marks the node with `deleted_at` and tags the S3 object — but since the VOD system also references the same S3 key, we must prevent S3 object purge for VOD-linked nodes.

Add a guard in the existing purge logic:

```python
def _can_purge_s3_object(item: Dict[str, Any]) -> bool:
    """Return False if the S3 object is still referenced by a VOD record."""
    if item.get("vod_linked"):
        return False
    return True
```

This check is inserted into `purge_deleted_nodes()` before it calls `_s3.delete_object()`.

### 3.3 Direction 2: File Manager → VOD (Import)

#### 3.3.1 Import Function

```python
def import_file_to_vod(
    owner: str,
    file_path: str,
    *,
    title: Optional[str] = None,
    visibility: str = "private",
) -> Dict[str, Any]:
    """Import a file manager video file into the VOD pipeline.

    Creates a new VideoMetadataModel using the file's existing S3 key
    as the source (no re-upload). Transitions to 'probing' to trigger
    the transcode pipeline.

    Args:
        owner: User sub who owns the file.
        file_path: Normalized path in file manager (e.g., /Videos/raw.mp4).
        title: Optional title override (defaults to file name).
        visibility: "private" | "unlisted" | "public".

    Returns:
        Dict with "video_id", "status", "file_path".
    """
    # Fetch existing file node
    node = get_node(owner, norm_path(file_path, is_folder=False))

    # Validate it's a video file
    content_type = str(node.get("content_type") or "").lower()
    if not content_type.startswith("video/"):
        raise HTTPException(400, "file is not a video")

    # Check not already linked to a VOD record
    existing_video_id = node.get("vod_video_id")
    if existing_video_id:
        raise HTTPException(
            409,
            {
                "code": "already_linked",
                "video_id": existing_video_id,
                "message": "file is already linked to a VOD record",
            },
        )

    s3_key = node.get("s3_key")
    s3_bucket = node.get("s3_bucket")
    if not s3_key or not s3_bucket:
        raise HTTPException(400, "file has no S3 backing object")

    # Create VOD record referencing same S3 key
    video_title = title or node.get("name") or "Imported Video"
    video = create_video(
        owner_user_id=owner,
        title=video_title,
        source_type="upload",
        source_file_node_id=file_path,
        source_s3_key=s3_key,
        visibility=visibility,
    )

    # Set file_size_bytes from node
    from app.core.tables import T
    if node.get("size"):
        T.video_metadata.update_item(
            Key={"video_id": video.id},
            UpdateExpression="SET file_size_bytes = :s",
            ExpressionAttributeValues={":s": int(node["size"])},
        )

    # Transition to probing (triggers pipeline pickup)
    transition_video_status(
        video_id=video.id,
        to_status="probing",
        reason="imported from file manager",
        actor=owner,
    )

    # Update file manager node with VOD link
    _table().update_item(
        Key=node_key(owner, norm_path(file_path, is_folder=False)),
        UpdateExpression=(
            "SET vod_video_id = :vid, vod_linked = :t, vod_status = :s, "
            "vod_linked_at = :ts, updated_at = :ts"
        ),
        ExpressionAttributeValues={
            ":vid": video.id,
            ":t": True,
            ":s": "probing",
            ":ts": now_iso(),
        },
    )

    # Enqueue transcode job
    _enqueue_transcode_for_import(video.id, owner, s3_bucket, s3_key)

    logger.info("Imported file %s to VOD pipeline as video %s", file_path, video.id)
    return {"video_id": video.id, "status": "probing", "file_path": file_path}


def _enqueue_transcode_for_import(
    video_id: str, owner: str, bucket: str, s3_key: str
) -> None:
    """Create a transcode job for the imported file."""
    from app.services.transcode_job_store import create_job

    create_job(
        video_id=video_id,
        tenant_id=owner,
        source_uri=f"s3://{bucket}/{s3_key}",
        rendition_profiles=[],  # Use default encoding profile
    )
```

#### 3.3.2 Post-Transcode Update for Imported Files

After transcoding completes for an imported file, the `link_video_to_filemanager` function is called (same as for direct uploads). Since the file node already exists with `vod_video_id` set, the function detects the existing link and updates VOD metadata in-place rather than creating a duplicate node:

```python
# In link_video_to_filemanager, after checking existing node:
existing = get_node(owner, file_path)
if existing.get("vod_video_id") == video_id:
    # Update metadata only (imported file, transcoding just finished)
    _update_linked_node_vod_metadata(owner, file_path, video)
    return {"path": file_path, "video_id": video_id, "linked": False}
```

```python
def _update_linked_node_vod_metadata(
    owner: str, file_path: str, video: "VideoMetadataModel"
) -> None:
    """Update an existing linked file node with fresh VOD metadata."""
    updates: Dict[str, Any] = {
        ":s": video.status,
        ":t": now_iso(),
    }
    expr_parts = ["SET vod_status = :s, updated_at = :t"]

    if video.hls_manifest_url:
        updates[":hls"] = video.hls_manifest_url
        expr_parts.append("vod_hls_manifest_url = :hls")
    if video.thumbnail_url:
        updates[":thumb"] = video.thumbnail_url
        expr_parts.append("vod_thumbnail_url = :thumb")
        expr_parts.append("poster_url = :thumb")
        updates[":pstatus"] = "ready"
        expr_parts.append("media_preview_status = :pstatus")
    if video.duration_seconds is not None:
        updates[":dur"] = video.duration_seconds
        expr_parts.append("vod_duration_seconds = :dur")
        expr_parts.append("duration_seconds = :dur")
    if video.width:
        updates[":w"] = video.width
        expr_parts.append("vod_width = :w")
    if video.height:
        updates[":h"] = video.height
        expr_parts.append("vod_height = :h")

    _table().update_item(
        Key=node_key(owner, norm_path(file_path, is_folder=False)),
        UpdateExpression=", ".join(expr_parts),
        ExpressionAttributeValues=updates,
    )
```

### 3.4 New Router Endpoints: `app/routers/vod_bridge.py`

```python
router = APIRouter(prefix="/ui/vod-bridge", tags=["vod-bridge"])
```

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/vod-bridge/import` | `require_ui_session` | Import a file manager video to VOD pipeline |
| GET | `/ui/vod-bridge/status/{video_id}` | `require_ui_session` | Get bridge status for a video |
| PATCH | `/ui/vod-bridge/{video_id}/folder` | `require_ui_session` | Change the target folder for a linked video |
| DELETE | `/ui/vod-bridge/{video_id}/link` | `require_ui_session` | Unlink a file node from its VOD record (removes `vod_*` fields from node) |

#### Endpoint: Import File to VOD

```python
class ImportToVodIn(BaseModel):
    file_path: str = Field(..., min_length=1, description="File manager path")
    title: Optional[str] = Field(default=None, max_length=256)
    visibility: Literal["private", "unlisted", "public"] = "private"

class ImportToVodOut(BaseModel):
    video_id: str
    status: str
    file_path: str

@router.post("/import", response_model=ImportToVodOut)
def import_to_vod(inp: ImportToVodIn, user=Depends(require_ui_session)):
    result = import_file_to_vod(
        owner=user["user_sub"],
        file_path=inp.file_path,
        title=inp.title,
        visibility=inp.visibility,
    )
    return ImportToVodOut(**result)
```

#### Endpoint: Get Bridge Status

```python
class BridgeStatusOut(BaseModel):
    video_id: str
    vod_status: str
    file_path: Optional[str] = None
    hls_manifest_url: Optional[str] = None
    thumbnail_url: Optional[str] = None
    duration_seconds: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None

@router.get("/status/{video_id}", response_model=BridgeStatusOut)
def get_bridge_status(video_id: str, user=Depends(require_ui_session)):
    video = get_video(video_id)
    if video.owner_user_id != user["user_sub"]:
        raise HTTPException(403, "not your video")
    return BridgeStatusOut(
        video_id=video_id,
        vod_status=video.status,
        file_path=video.source_file_node_id,
        hls_manifest_url=video.hls_manifest_url,
        thumbnail_url=video.thumbnail_url,
        duration_seconds=video.duration_seconds,
        width=video.width,
        height=video.height,
    )
```

### 3.5 DynamoDB Schema Changes

No new tables are required. The bridge uses existing tables with additional attributes:

#### File Manager Table — New Attributes on Linked Nodes

| Attribute | Type | Description |
|-----------|------|-------------|
| `vod_video_id` | S | Video ID from `VideoMetadata` table (e.g., `v_abc123`) |
| `vod_linked` | BOOL | `true` if this node is linked to a VOD record |
| `vod_status` | S | Current VOD status (mirrors `VideoMetadata.status`) |
| `vod_hls_manifest_url` | S | HLS playback URL (populated after transcoding) |
| `vod_thumbnail_url` | S | Poster frame URL from VOD pipeline |
| `vod_duration_seconds` | N | Video duration from VOD probe |
| `vod_width` | N | Video width in pixels |
| `vod_height` | N | Video height in pixels |
| `vod_linked_at` | S | ISO timestamp of when the link was created |

#### VideoMetadata Table — Existing Field Usage

| Attribute | Usage |
|-----------|-------|
| `source_file_node_id` | Set to the file manager path (e.g., `/Videos/my-video.mp4`) when linked. Already defined in `VideoMetadataModel` but previously unused. |

### 3.6 Storage Deduplication

Both systems reference the same S3 object — no copy is made:

- **VOD → File Manager**: The file node's `s3_key` points to the same `videos/{user}/{video_id}/{filename}` key in `local-uploads` that the VOD system uploaded to.
- **File Manager → VOD**: The VOD record's `source_s3_key` points to the same `{user}/objects/{uuid}` key in `local-uploads` that the file manager created.

The purge guard (`_can_purge_s3_object`) ensures that soft-deleting a file manager node doesn't destroy the S3 object if it's still referenced by an active VOD record.

### 3.7 Settings

Add to `app/core/settings.py`:

```python
# VOD File Bridge (VOD-014)
vod_file_bridge_enabled: bool = os.environ.get("VOD_FILE_BRIDGE_ENABLED", "1") == "1"
vod_file_bridge_default_folder: str = os.environ.get("VOD_FILE_BRIDGE_DEFAULT_FOLDER", "/Videos/")
vod_file_bridge_auto_link: bool = os.environ.get("VOD_FILE_BRIDGE_AUTO_LINK", "1") == "1"
```

Add to `.env.local.example`:

```bash
VOD_FILE_BRIDGE_ENABLED=true
VOD_FILE_BRIDGE_DEFAULT_FOLDER=/Videos/
VOD_FILE_BRIDGE_AUTO_LINK=true
```

---

## 4. Frontend Changes

### 4.1 FilesPage — Video-Specific Rendering

In `frontend/src/pages/files/FilesPage.tsx` and `FileTable.tsx`:

**Badge**: Files with `vod_linked: true` display a "Video" badge (purple, with Film icon) next to the filename.

**Actions dropdown** gains two new items for VOD-linked files:
- **Watch** — navigates to `/videos/{vod_video_id}` (VideoPlayerPage).
- **Edit Metadata** — navigates to `/videos` with the video selected for editing.

For video files that are NOT yet linked (no `vod_video_id`), show:
- **Send to VOD** — calls `POST /ui/vod-bridge/import` and shows a toast.

**Poster thumbnail**: If `vod_thumbnail_url` is present, use it as the file's poster in the grid/list view. If not, fall back to the existing `poster_url` from file manager preview generation.

### 4.2 New Types in `frontend/src/api/types.ts`

```typescript
export interface FileEntry {
  // ... existing fields ...
  vod_video_id?: string;
  vod_linked?: boolean;
  vod_status?: string;
  vod_hls_manifest_url?: string;
  vod_thumbnail_url?: string;
  vod_duration_seconds?: number;
  vod_width?: number;
  vod_height?: number;
}
```

### 4.3 New API Endpoints in `frontend/src/api/endpoints/videos.ts`

```typescript
export async function importFileToVod(params: {
  file_path: string;
  title?: string;
  visibility?: "private" | "unlisted" | "public";
}): Promise<{ video_id: string; status: string; file_path: string }> {
  const { data } = await client.post("/ui/vod-bridge/import", params);
  return data;
}

export async function getVodBridgeStatus(videoId: string): Promise<{
  video_id: string;
  vod_status: string;
  file_path: string | null;
  hls_manifest_url: string | null;
  thumbnail_url: string | null;
  duration_seconds: number | null;
  width: number | null;
  height: number | null;
}> {
  const { data } = await client.get(`/ui/vod-bridge/status/${videoId}`);
  return data;
}
```

### 4.4 VideosPage — File Manager Link Indicator

In `frontend/src/pages/videos/VideosPage.tsx`, each video card that has `source_file_node_id` set displays a small "In Files" link/badge that navigates to the file manager at the appropriate folder.

### 4.5 File Manager `/list` Response Enhancement

The existing `GET /v1/fs/list` endpoint already returns all node attributes. The `vod_*` fields will automatically appear in the response for linked nodes since `list_children` returns raw DynamoDB items. The frontend file list query response will include these fields with no backend changes to the list endpoint itself.

---

## 5. Implementation Plan

### Phase 1: Backend Bridge Service + Endpoints

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/vod_file_bridge.py` | New | Bridge service: `link_video_to_filemanager`, `import_file_to_vod`, helpers |
| `app/routers/vod_bridge.py` | New | 4 endpoints: import, status, folder change, unlink |
| `app/main.py` | Modify | Register `vod_bridge_router` |
| `app/core/settings.py` | Modify | Add `vod_file_bridge_*` settings |
| `.env.local.example` | Modify | Add bridge env vars |
| `app/services/transcode_worker.py` | Modify | Add `link_video_to_filemanager` call after status transition |
| `app/services/filemanager.py` | Modify | Add `_can_purge_s3_object` guard in purge logic |

### Phase 2: Frontend UI

| File | Change Type | Description |
|------|-------------|-------------|
| `frontend/src/api/types.ts` | Modify | Add `vod_*` fields to `FileEntry` |
| `frontend/src/api/endpoints/videos.ts` | Modify | Add `importFileToVod`, `getVodBridgeStatus` |
| `frontend/src/pages/files/FileTable.tsx` | Modify | Video badge, Watch/Send-to-VOD actions |
| `frontend/src/pages/files/FilesPage.tsx` | Modify | Import dialog, VOD status polling |
| `frontend/src/pages/videos/VideosPage.tsx` | Modify | "In Files" badge/link |

### Phase 3: E2E Tests

| File | Change Type | Description |
|------|-------------|-------------|
| `frontend/e2e/vod-file-bridge.spec.ts` | New | Full E2E test suite |

---

## 6. Testing Strategy

### 6.1 Unit Tests: `tests/test_vod_file_bridge.py`

| Test | What It Validates |
|------|-------------------|
| `test_link_video_creates_file_node` | After `link_video_to_filemanager`, file node exists at `/Videos/{title}.mp4` with correct `vod_video_id`. |
| `test_link_video_idempotent` | Calling `link_video_to_filemanager` twice returns `linked=False` on second call, no duplicate node. |
| `test_link_video_creates_videos_folder` | If `/Videos/` doesn't exist, it is auto-created. |
| `test_link_video_sets_source_file_node_id` | Video record has `source_file_node_id` set to the file path. |
| `test_link_video_uses_vod_thumbnail` | If video has `thumbnail_url`, file node gets `poster_url` set. |
| `test_link_video_no_s3_key_returns_unlinked` | Video without `source_s3_key` returns `linked=False`. |
| `test_import_file_creates_vod_record` | `import_file_to_vod` creates a video with correct `source_s3_key` and `source_file_node_id`. |
| `test_import_file_transitions_to_probing` | After import, video status is `probing`. |
| `test_import_file_updates_node_vod_fields` | File node gets `vod_video_id`, `vod_linked=True`, `vod_status="probing"`. |
| `test_import_file_rejects_non_video` | Importing a `.txt` file raises 400. |
| `test_import_file_rejects_already_linked` | Importing a file with existing `vod_video_id` raises 409. |
| `test_import_file_rejects_no_s3_key` | File without `s3_key` raises 400. |
| `test_safe_filename_sanitizes_special_chars` | Title with `<>"/\` characters produces valid filename. |
| `test_safe_filename_preserves_extension` | S3 key ending in `.webm` produces `.webm` filename. |
| `test_can_purge_returns_false_for_linked` | `_can_purge_s3_object({"vod_linked": True})` returns `False`. |
| `test_update_linked_node_metadata` | After transcoding completes, node gets updated `vod_status`, `duration_seconds`, `poster_url`. |

### 6.2 E2E Tests: `frontend/e2e/vod-file-bridge.spec.ts`

Follows existing E2E patterns (cookie auth via `injectAuth`, CSRF headers).

**Section 1: VOD → File Manager Auto-Link API**

| # | Test | Description |
|---|------|-------------|
| 1.1 | Upload via VOD presign → appears in /Videos/ | Upload a video via `/ui/videos/upload/presign` + complete, verify file node appears at `/Videos/{title}.mp4` via `/v1/fs/info`. |
| 1.2 | Linked node has VOD metadata | Assert `vod_video_id`, `vod_linked`, `vod_status` on the file node. |
| 1.3 | Deleting file node preserves VOD record | DELETE the file node, GET video by ID still returns 200. |
| 1.4 | Linked node has poster_url | Assert `poster_url` or `vod_thumbnail_url` is non-null after transcoding. |
| 1.5 | Auto-creates /Videos/ folder | Delete `/Videos/` folder, upload a new video, verify folder is recreated. |

**Section 2: File Manager → VOD Import API**

| # | Test | Description |
|---|------|-------------|
| 2.1 | Import video file to VOD | Upload a `.mp4` via file manager, call `POST /ui/vod-bridge/import`, assert 200 with `video_id`. |
| 2.2 | Import sets node vod_video_id | After import, `GET /v1/fs/info` returns `vod_video_id`. |
| 2.3 | Import rejects non-video file | Upload a `.txt`, attempt import, assert 400. |
| 2.4 | Import rejects already-linked file | Import same file twice, second call returns 409. |
| 2.5 | Bridge status endpoint | Call `GET /ui/vod-bridge/status/{id}`, assert `vod_status` and `file_path`. |

**Section 3: File Manager UI (VOD-linked files)**

| # | Test | Description |
|---|------|-------------|
| 3.1 | Video badge visible | Navigate to `/files`, assert "Video" badge on linked file. |
| 3.2 | Watch action navigates to player | Click "Watch" dropdown item, assert URL contains `/videos/`. |
| 3.3 | Send to VOD action for unlinked video | Upload a video via file manager, click "Send to VOD", assert toast + file refreshes with badge. |
| 3.4 | Thumbnail displays from VOD | Assert poster image element uses `vod_thumbnail_url` source. |

---

## 7. Edge Cases & Error Handling

### 7.1 Filename Collisions

If `/Videos/my-video.mp4` already exists (from a previous upload or manual file), append a numeric suffix:

```python
def _resolve_unique_path(owner: str, base_path: str) -> str:
    """Append (1), (2), etc. if path already exists."""
    try:
        get_node(owner, base_path)
    except HTTPException:
        return base_path  # 404 means path is available

    stem, ext = base_path.rsplit(".", 1) if "." in base_path.split("/")[-1] else (base_path, "")
    for i in range(1, 100):
        candidate = f"{stem} ({i}).{ext}" if ext else f"{stem} ({i})"
        try:
            get_node(owner, candidate)
        except HTTPException:
            return candidate
    raise HTTPException(409, "too many filename collisions")
```

### 7.2 VOD Record Deleted Before File Node

If a user deletes a video via the VOD system (`DELETE /ui/videos/{id}`), the file node remains but becomes "orphaned" — `vod_status` won't update. The frontend should handle `vod_status = "deleted"` by removing the Watch action and showing a "Source deleted" indicator.

### 7.3 File Manager Node Deleted Before VOD Record

Since the file node is a soft-link, deleting it has no effect on the VOD system. The video remains playable via VideoPlayerPage. The `source_file_node_id` field on the video becomes a stale reference, which is acceptable (it's informational only).

### 7.4 Concurrent Transcoding Completion

The `link_video_to_filemanager` function is idempotent — if called multiple times (e.g., worker retry), it detects the existing node and skips creation.

### 7.5 Feature Flag Disabled

If `VOD_FILE_BRIDGE_ENABLED=false`, the transcode worker skips the auto-link call, and the import endpoint returns 404. This allows gradual rollout.

---

## 8. Sequence Diagrams

### 8.1 VOD Upload → File Manager Link

```
User → VideosPage: Select file, upload
VideosPage → POST /ui/videos/upload/presign: {filename, content_type, size}
Backend → S3: Generate presigned URL
VideosPage → S3 PUT: Upload file bytes
VideosPage → POST /ui/videos/{id}/upload/complete
Backend → VideoMetadata: status = probing
Backend → TranscodeJobStore: Create transcode job
TranscodeWorker → S3: Download source, encode HLS
TranscodeWorker → S3 (vod-output): Upload segments + manifest
TranscodeWorker → VideoMetadata: status = published
TranscodeWorker → vod_file_bridge.link_video_to_filemanager():
    → Ensure /Videos/ folder exists
    → Create file node (s3_key = original source)
    → Set poster_url from VOD thumbnail
    → Update VideoMetadata.source_file_node_id
```

### 8.2 File Manager → VOD Import

```
User → FilesPage: Right-click video → "Send to VOD"
FilesPage → POST /ui/vod-bridge/import: {file_path, title, visibility}
Backend → FileManager: get_node(file_path) — validate video type
Backend → VideoMetadata: create_video(source_s3_key=node.s3_key)
Backend → VideoMetadata: transition_video_status(probing)
Backend → FileManager: Update node with vod_video_id
Backend → TranscodeJobStore: Create job (source_uri = s3://{bucket}/{key})
TranscodeWorker → (same flow as above)
TranscodeWorker → vod_file_bridge.link_video_to_filemanager():
    → Detects existing node with matching vod_video_id
    → Updates vod_status, vod_hls_manifest_url, poster_url
```

---

## Appendix: File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/vod_file_bridge.py` | New | Bridge service with `link_video_to_filemanager`, `import_file_to_vod`, helpers |
| `app/routers/vod_bridge.py` | New | 4 endpoints: import, status, folder change, unlink |
| `app/main.py` | Modify | Register `vod_bridge_router` |
| `app/core/settings.py` | Modify | Add 3 bridge settings |
| `.env.local.example` | Modify | Add `VOD_FILE_BRIDGE_*` env vars |
| `app/services/transcode_worker.py` | Modify | Add auto-link call after `transition_video_status` |
| `app/services/filemanager.py` | Modify | Add `_can_purge_s3_object` guard in purge path |
| `frontend/src/api/types.ts` | Modify | Add `vod_*` fields to `FileEntry` |
| `frontend/src/api/endpoints/videos.ts` | Modify | Add `importFileToVod`, `getVodBridgeStatus` |
| `frontend/src/pages/files/FileTable.tsx` | Modify | Video badge, Watch action, Send-to-VOD action |
| `frontend/src/pages/files/FilesPage.tsx` | Modify | Import confirmation dialog |
| `frontend/src/pages/videos/VideosPage.tsx` | Modify | "In Files" indicator badge |
| `tests/test_vod_file_bridge.py` | New | 16 unit tests |
| `frontend/e2e/vod-file-bridge.spec.ts` | New | 14 E2E tests across 3 sections |
