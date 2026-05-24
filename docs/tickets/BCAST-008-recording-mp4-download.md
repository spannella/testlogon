# BCAST-008: Recording MP4 Download

**Ticket**: BCAST-008
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-24
**Depends on**: BCAST-006 (Recording + VOD Archive)

---

## 1. Overview & Motivation

### Problem Statement

The broadcast recording system (BCAST-006) produces VOD recordings as multi-rendition HLS
streams. While this is ideal for browser-based playback, it does not support a common and
critical creator workflow: **downloading the recording as a single file** for offline use.

Broadcasters want to:
- Edit recordings in external tools (Premiere Pro, DaVinci Resolve, CapCut)
- Upload to other platforms (YouTube, TikTok, Instagram, Vimeo)
- Share directly via file transfer (email, cloud drives, messaging)
- Archive locally as a backup independent of platform retention policies

HLS playlists consist of hundreds of small `.ts` segment files and a manifest. They cannot
be opened by video editors, uploaded to other platforms, or meaningfully shared. Broadcasters
currently have **no way** to get their own content out of the platform in a portable format.

### Viewer Downloads

Beyond broadcaster self-service, there is demand for viewer-side downloads. Some creators
want to offer recordings as downloadable content (e.g., course materials, paid tutorials,
exclusive behind-the-scenes content). This must be an opt-in toggle controlled exclusively
by the broadcaster -- viewers should never be able to download recordings without explicit
permission from the content owner.

### Solution: Progressive MP4 Generation

The recording pipeline (BCAST-006) already produces a concatenated transport stream file
(`full.ts`) at `s3_concatenated_key` as an intermediate artifact during processing. This
file contains H.264 video and AAC audio in an MPEG-TS container. Converting this to an MP4
container is a **remux operation** (container format change, no re-encoding), which is
effectively instant regardless of file duration because no transcoding occurs.

The generated MP4 uses `-movflags +faststart` to relocate the moov atom to the beginning of
the file, enabling progressive download (the file can begin playing before fully downloaded).

### Security Model

- Download URLs are **time-limited presigned S3 URLs** with configurable TTL (default 4 hours)
- Presigned URLs include `Content-Disposition: attachment; filename="recording.mp4"` to force
  browser download behavior
- Broadcaster access: unconditional (they own the content)
- Viewer access: gated by `allow_viewer_download` flag, which defaults to `false`
- Expired recordings (past retention) return 410 Gone for download requests
- Recording must be in `status="ready"` before downloads are available

### User Stories

1. **As a broadcaster**, I want to download my recording as an MP4 file after the broadcast
   ends, so I can edit it in my preferred video editing software and upload to YouTube.

2. **As a broadcaster**, I want to enable viewer downloads for specific recordings, so my
   audience can save tutorial content for offline viewing.

3. **As a viewer**, I want to download a recording when the broadcaster has enabled it, so I
   can watch it offline or keep a personal copy of educational content I purchased.

4. **As a broadcaster**, I want to disable viewer downloads at any time (even after initially
   enabling them), so I retain control over how my content is distributed.

5. **As a broadcaster**, I want the download URL to expire after a reasonable time, so that
   shared links do not grant permanent access to my content.

6. **As a platform operator**, I want MP4 generation to happen automatically (not on-demand),
   so download requests are served instantly without queueing lag.

### Key Acceptance Criteria

- Broadcaster can download recording as MP4 within seconds of recording reaching `ready` status
- MP4 file is playable in VLC, QuickTime, and all major video editors
- `Content-Disposition: attachment` header forces download (not in-browser playback)
- Presigned URL expires after configurable TTL (default 4h)
- Viewer download returns 403 when `allow_viewer_download=false`
- Toggle `allow_viewer_download` is persistent and can be changed at any time
- MP4 file has `moov` atom at start (faststart) for progressive download support
- Recording in `expired` status returns 410 for download requests
- Recording in processing status returns 202 for download requests

---

## 2. Current State Analysis

### 2.1 Recording Pipeline (BCAST-006)

The existing recording pipeline in `app/services/broadcast_recording_worker.py` processes
recordings through these stages:

```
inventory_segments() → concatenate_segments() → transcode_recording() → generate_thumbnail() → finalize_recording()
```

The critical artifact for this ticket is the **concatenated transport stream** that would be
produced in step 2. However, `concatenate_segments()` currently returns `None` in all code
paths (both mock and non-mock). No `.ts` file is actually produced by the current
implementation. The `s3_archive_prefix` field is used only by `inventory_segments` as a
directory prefix to list segment files from.

**Important**: BCAST-008 implementation must first complete the `concatenate_segments()`
function so that it actually produces a `full.ts` file at
`{session_id}/recording/full.ts`. Without this, the MP4 remux step has no input file.

In mock mode (`_should_mock()` returns `True`), the concatenation step remains a no-op and
`generate_mp4` returns placeholder metadata (same pattern as current mock behavior).

In production mode, `concatenate_segments()` must be implemented to download all HLS
segments listed by `inventory_segments()` and concatenate them into a single MPEG-TS file
before the MP4 remux step can proceed.

### 2.2 Current RecordingRecord Data Model

From `app/services/broadcast_recording.py`:

```python
@dataclass
class RecordingRecord:
    recording_id: str
    session_id: str
    profile_id: str
    created_by: str
    status: str  # pending, processing, ready, failed, expired
    s3_archive_prefix: str = ""
    s3_manifest_key: str = ""
    s3_thumbnail_key: str = ""
    duration_seconds: float = 0.0
    segment_count: int = 0
    total_bytes: int = 0
    renditions: List[Dict[str, Any]] = field(default_factory=list)
    error_code: str = ""
    error_message: str = ""
    retention_days: int = 30
    scope: str = "ALL"
    created_at: int = 0
    completed_at: int = 0
    expires_at: int = 0
```

Notable: there is **no** `s3_concatenated_key` field currently stored on the record. The
concatenated path is an ephemeral intermediate used during processing. For MP4 generation,
we either need to store this path or derive it deterministically from `session_id`.

### 2.3 Current BroadcastRecordingOut API Response

From `app/routers/broadcast.py` (line 597):

```python
class BroadcastRecordingOut(BaseModel):
    recording_id: str
    session_id: str
    status: str
    duration_seconds: Optional[float] = None
    playback_url: Optional[str] = None
    playback_expires_at: Optional[int] = None
    thumbnail_url: Optional[str] = None
    segment_count: Optional[int] = None
    total_bytes: Optional[int] = None
    renditions: list = Field(default_factory=list)
    created_at: int
    completed_at: Optional[int] = None
    expires_at: Optional[int] = None
```

No download-related fields exist in the response model.

### 2.4 Current Settings (`app/core/settings.py`, lines 1075-1082)

```python
broadcast_recordings_table_name: str = os.environ.get("BROADCAST_RECORDINGS_TABLE", "BroadcastRecordings")
broadcast_recording_enabled: bool = ...
broadcast_recording_playback_ttl_seconds: int = int(os.environ.get("BROADCAST_RECORDING_PLAYBACK_TTL_SECONDS", "14400"))
broadcast_recording_vod_bucket: str = os.environ.get("BROADCAST_RECORDING_VOD_BUCKET", "broadcast-vod")
broadcast_recording_vod_prefix: str = os.environ.get("BROADCAST_RECORDING_VOD_PREFIX", "recordings")
broadcast_recording_max_segments: int = ...
broadcast_recording_worker_inline: bool = ...
broadcast_recording_mock_on_no_ffmpeg: bool = ...
```

**NOTE**: `broadcast_recording_vod_prefix` exists in settings but is **never actually used**
in S3 path construction in the current codebase. All S3 keys are constructed directly as
`{session_id}/recording/...` without incorporating the `vod_prefix` setting. This spec
follows the actual codebase convention (no prefix), not the unused setting value.

The `broadcast_recording_playback_ttl_seconds` (default 14400 = 4 hours) is reusable for
download URL TTL, or a separate setting can be introduced for download-specific TTL.

### 2.5 S3 Presigned URL Patterns in the Platform

The platform already generates presigned S3 URLs in several places:

1. **File manager downloads** (`app/services/file_manager.py`): Uses `s3.generate_presigned_url`
   with `ClientMethod='get_object'` and `Params` including `ResponseContentDisposition`.
2. **Mock S3 serve** (`app/routers/mock_s3.py`): In dev mode, serves objects directly from
   moto S3 via `/mock/s3/{bucket}/{key}` routes.
3. **Recording playback** (`app/services/broadcast_recording.py`): `mint_recording_playback_url`
   generates `/mock/s3/...` URLs in dev mode (lines 187-198).

For the download endpoint, in dev mode we will use the same `/mock/s3/...` pattern with an
additional query parameter to signal attachment disposition. In production, a real S3
presigned URL with `ResponseContentDisposition` will be generated.

### 2.6 Existing Download Patterns

The file manager already implements a download flow:
- `GET /ui/files/{node_id}/download` returns a presigned URL (or direct content in dev)
- Frontend uses `window.open(url)` or `<a download>` to trigger browser download
- Content-Disposition is set to `attachment; filename="<original_name>"`

This pattern will be replicated for broadcast recording downloads.

### 2.7 Integration Points

| Component | Connection to MP4 download |
|-----------|---------------------------|
| `broadcast_recording_worker.py` | Add MP4 remux step after HLS transcode |
| `broadcast_recording.py` | Add download URL minting, download permission fields |
| `app/routers/broadcast.py` | Add download endpoint + toggle endpoint |
| `app/core/settings.py` | Add download-specific settings |
| `BroadcastRecordings` DDB table | Store `mp4_s3_key`, `mp4_size_bytes`, `allow_download`, `allow_viewer_download` |
| Frontend: `SessionDetailDialog` (inline in `BroadcastPage.tsx`) | Add "Download Recording" button |
| Frontend: viewer recording page | Conditional "Download" button (route must be created; see section 3.12) |

---

## 3. Technical Design

### 3.1 Architecture Overview

```
[Recording Pipeline (BCAST-006)]
       |
       | (after HLS transcode, before finalize)
       v
[MP4 Remux Step]
       |
       |  ffmpeg -i full.ts -c copy -movflags +faststart full.mp4
       v
[Upload MP4 to S3] ──> s3://{bucket}/{session_id}/recording/full.mp4
       |
       v
[Update DDB Record] ──> mp4_s3_key, mp4_size_bytes, mp4_generated_at
       |
       v
[Finalize Recording] ──> status = "ready"

                        ┌─────────────────────────────────────────────┐
                        │  Download Request Flow                        │
                        └─────────────────────────────────────────────┘

[GET /broadcast/sessions/{id}/recording/download]
       |
       | Auth check: require_ui_session
       v
[Check recording status]
       |
       |── 404: no recording
       |── 410: expired
       |── 202: still processing
       |── 403: viewer without allow_viewer_download
       v
[Generate presigned S3 URL]
       |
       | Content-Disposition: attachment; filename="recording-{session_id}.mp4"
       | Expires: now + download_ttl_seconds
       v
[Return { download_url, download_expires_at, file_size_bytes }]
```

### 3.2 MP4 Remux: FFmpeg Command

The remux converts the MPEG-TS container to MP4 without re-encoding:

```bash
ffmpeg -hide_banner -loglevel warning -y \
  -i {session_id}/recording/full.ts \
  -c copy \
  -movflags +faststart \
  {session_id}/recording/full.mp4
```

Key flags:
- **`-c copy`**: Stream copy (no transcoding). This makes the operation near-instant regardless
  of file duration since it only rewrites container metadata.
- **`-movflags +faststart`**: Moves the `moov` atom (file index/metadata) from the end to the
  beginning of the MP4 file. This is critical for progressive download -- without it, the
  browser/player must download the entire file before playback can begin.
- **`-y`**: Overwrite output without prompting.

**Performance characteristics**:
- A 2-hour recording (~4GB .ts file) remuxes to MP4 in approximately 10-30 seconds
  (limited by I/O, not CPU, since no encoding occurs)
- Output MP4 is typically 1-3% smaller than input .ts due to container overhead differences

### 3.3 Data Model Changes

**Add to `RecordingRecord` dataclass** (`app/services/broadcast_recording.py`):

```python
@dataclass
class RecordingRecord:
    # ... existing fields ...
    
    # Download fields (BCAST-008)
    allow_download: bool = True            # broadcaster can download (always True by default)
    allow_viewer_download: bool = False     # viewers can download (opt-in by broadcaster)
    mp4_s3_key: str = ""                   # S3 key: {session_id}/recording/full.mp4
    mp4_size_bytes: int = 0                # File size for display/progress
    mp4_generated_at: int = 0              # Unix timestamp when MP4 was generated
    s3_concatenated_key: str = ""          # S3 key for full.ts (persisted for MP4 remux)
```

**Add to `_record_from_item` and `_record_to_item`** the corresponding serialization fields.

**Add to `BroadcastRecordingOut` response model** (`app/routers/broadcast.py`):

```python
class BroadcastRecordingOut(BaseModel):
    # ... existing fields ...
    
    # Download fields (BCAST-008)
    allow_download: bool = True
    allow_viewer_download: bool = False
    download_available: bool = False       # True when mp4_s3_key is set and status=ready
    mp4_size_bytes: Optional[int] = None   # File size for UI display (human-readable conversion)
```

### 3.4 DynamoDB Schema Update

No new table is needed. The existing `BroadcastRecordings` table gains additional attributes
on each recording item:

| Attribute | Type | Description |
|-----------|------|-------------|
| `allow_download` | BOOL | Broadcaster download enabled (default: true) |
| `allow_viewer_download` | BOOL | Viewer download enabled (default: false) |
| `mp4_s3_key` | S | S3 key for the MP4 file |
| `mp4_size_bytes` | N | MP4 file size in bytes |
| `mp4_generated_at` | N | Unix timestamp of MP4 generation |
| `s3_concatenated_key` | S | S3 key for the intermediate .ts file |

These are non-key attributes that do not require GSI changes. The existing table schema
remains unchanged.

### 3.5 Download Endpoint

**Path**: `GET /broadcast/sessions/{session_id}/recording/download`

**Query parameters**:
- `viewer` (optional, bool, default `false`): When `true`, requests a viewer-mode download.
  The endpoint checks `allow_viewer_download` permission.

**Auth**: `Depends(require_ui_session)` -- same as the existing recording endpoint.

**Response model**:

```python
class BroadcastRecordingDownloadOut(BaseModel):
    download_url: str                  # Presigned S3 URL with Content-Disposition: attachment
    download_expires_at: int           # Unix timestamp when URL expires
    file_size_bytes: int               # MP4 file size
    filename: str                      # Suggested filename (e.g., "recording-abc123.mp4")
    content_type: str = "video/mp4"    # MIME type
```

**Implementation logic**:

```python
@router.get("/sessions/{session_id}/recording/download", response_model=BroadcastRecordingDownloadOut)
def download_recording_route(
    session_id: str,
    viewer: bool = False,
    ctx: dict = Depends(_ctx),
):
    """Generate a presigned download URL for the recording MP4."""
    if not S.broadcast_recording_download_enabled:
        raise HTTPException(503, detail={"code": "BROADCAST_RECORDING_DOWNLOAD_DISABLED"})
    
    recording = get_recording_by_session(session_id)
    if not recording:
        raise HTTPException(404, detail={"code": "BROADCAST_RECORDING_NOT_FOUND"})
    if recording.status == "expired":
        raise HTTPException(410, detail={"code": "BROADCAST_RECORDING_EXPIRED"})
    if recording.status != "ready":
        raise HTTPException(202, detail={"code": "BROADCAST_RECORDING_PROCESSING"})
    if not recording.mp4_s3_key:
        raise HTTPException(404, detail={"code": "BROADCAST_RECORDING_MP4_NOT_AVAILABLE",
                                         "detail": "MP4 file has not been generated for this recording"})
    
    # Permission check
    user_sub = ctx["user_sub"]
    if viewer:
        if not recording.allow_viewer_download:
            raise HTTPException(403, detail={"code": "BROADCAST_RECORDING_DOWNLOAD_FORBIDDEN",
                                             "detail": "Broadcaster has not enabled viewer downloads"})
    else:
        # Broadcaster download: verify the requester is the owner
        if user_sub != recording.created_by:
            raise HTTPException(403, detail={"code": "BROADCAST_RECORDING_DOWNLOAD_FORBIDDEN",
                                             "detail": "Only the broadcaster can download this recording"})
    
    # Mint presigned URL
    download = mint_recording_download_url(recording)
    return BroadcastRecordingDownloadOut(**download)
```

### 3.6 Presigned URL Generation

**New function in `app/services/broadcast_recording.py`**:

```python
def mint_recording_download_url(recording: RecordingRecord) -> Dict[str, Any]:
    """Generate a presigned S3 download URL for the recording MP4.
    
    The URL includes Content-Disposition: attachment to force browser download.
    """
    ttl = S.broadcast_recording_download_ttl_seconds
    expires_at = _now_ts() + ttl
    bucket = S.broadcast_recording_vod_bucket
    filename = f"recording-{recording.session_id[:12]}.mp4"
    
    if S.dev_mode:
        # Dev mode: return mock URL
        download_url = f"/mock/s3/{bucket}/{recording.mp4_s3_key}?expires={expires_at}&disposition=attachment"
    else:
        # Production: generate real S3 presigned URL
        import boto3
        s3_client = boto3.client("s3")
        download_url = s3_client.generate_presigned_url(
            ClientMethod="get_object",
            Params={
                "Bucket": bucket,
                "Key": recording.mp4_s3_key,
                "ResponseContentDisposition": f'attachment; filename="{filename}"',
                "ResponseContentType": "video/mp4",
            },
            ExpiresIn=ttl,
        )
    
    return {
        "download_url": download_url,
        "download_expires_at": expires_at,
        "file_size_bytes": recording.mp4_size_bytes,
        "filename": filename,
        "content_type": "video/mp4",
    }
```

### 3.7 Download Permission Toggle Endpoint

**Path**: `PATCH /broadcast/sessions/{session_id}/recording/download-settings`

**Request body**:

```python
class BroadcastRecordingDownloadSettingsIn(BaseModel):
    allow_viewer_download: bool
```

**Auth**: `Depends(require_ui_session)` with ownership check (only the broadcaster who
created the session can modify download settings).

**Implementation**:

```python
@router.patch("/sessions/{session_id}/recording/download-settings")
def update_download_settings_route(
    session_id: str,
    body: BroadcastRecordingDownloadSettingsIn,
    ctx: dict = Depends(_ctx),
):
    """Toggle viewer download permission for a recording."""
    recording = get_recording_by_session(session_id)
    if not recording:
        raise HTTPException(404, detail={"code": "BROADCAST_RECORDING_NOT_FOUND"})
    if ctx["user_sub"] != recording.created_by:
        raise HTTPException(403, detail={"code": "FORBIDDEN", "detail": "Only the broadcaster can modify settings"})
    
    update_recording_status(
        recording.recording_id,
        recording.status,  # status unchanged
        allow_viewer_download=body.allow_viewer_download,
    )
    return {"ok": True, "allow_viewer_download": body.allow_viewer_download}
```

### 3.8 MP4 Generation in Recording Worker

**Modification to `app/services/broadcast_recording_worker.py`**:

Add a new pipeline step `generate_mp4` between `transcode_recording` and `generate_thumbnail`:

```python
def generate_mp4(recording: RecordingRecord, concat_path: Optional[str]) -> Dict[str, Any]:
    """Remux the concatenated .ts file to progressive MP4.
    
    Uses -c copy (no re-encoding) and -movflags +faststart for progressive download.
    Returns dict with mp4_s3_key and mp4_size_bytes, or mock values.
    """
    if _should_mock() or concat_path is None:
        # Mock: no real media exists, produce placeholder metadata
        mp4_key = f"{recording.session_id}/recording/full.mp4"
        logger.info("Recording %s: mock MP4 at %s", recording.recording_id, mp4_key)
        return {
            "mp4_s3_key": mp4_key,
            "mp4_size_bytes": 0,
            "mp4_generated_at": _now_ts(),
        }
    
    # Production: FFmpeg remux
    import subprocess
    mp4_path = concat_path.replace(".ts", ".mp4")
    args = [
        S.ffmpeg_binary_path, "-hide_banner", "-loglevel", "warning", "-y",
        "-i", concat_path,
        "-c", "copy",
        "-movflags", "+faststart",
        mp4_path,
    ]
    logger.info("Recording %s: remuxing to MP4: %s", recording.recording_id, " ".join(args))
    result = subprocess.run(args, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"FFmpeg MP4 remux failed: {result.stderr[:500]}")
    
    # Get file size
    import os
    mp4_size = os.path.getsize(mp4_path)
    
    # Upload to S3 (NOTE: _upload_to_s3 does not exist yet — must be created as part of BCAST-008)
    mp4_key = f"{recording.session_id}/recording/full.mp4"
    _upload_to_s3(mp4_path, bucket=S.broadcast_recording_vod_bucket, key=mp4_key)
    
    return {
        "mp4_s3_key": mp4_key,
        "mp4_size_bytes": mp4_size,
        "mp4_generated_at": _now_ts(),
    }
```

**Updated `process_recording` pipeline**:

```python
def process_recording(recording_id: str) -> Optional[RecordingRecord]:
    recording = get_recording(recording_id)
    if not recording:
        return None

    update_recording_status(recording_id, "processing")

    try:
        # Step 1: Inventory
        segments = inventory_segments(recording)
        # Step 2: Concatenate
        concat_path = concatenate_segments(recording, segments)
        # Step 3: Transcode to HLS
        transcode_result = transcode_recording(recording, concat_path)
        # Step 4: Generate MP4 download (NEW - BCAST-008)
        mp4_result = generate_mp4(recording, concat_path)
        # Step 5: Thumbnail
        thumbnail_key = generate_thumbnail(recording, concat_path)
        # Step 6: Finalize (includes MP4 metadata)
        result = finalize_recording(recording, transcode_result, thumbnail_key, mp4_result)
        return result

    except Exception as exc:
        logger.exception("Recording %s failed: %s", recording_id, exc)
        update_recording_status(recording_id, "failed", error_code=type(exc).__name__, error_message=str(exc)[:500])
        return get_recording(recording_id)
```

### 3.9 S3 Storage Layout

After BCAST-008, the complete recording storage for a session looks like:

```
s3://broadcast-vod/{session_id}/recording/
    full.ts             # Concatenated transport stream (from BCAST-006, must be implemented)
    full.mp4            # Progressive MP4 remux (NEW - BCAST-008)
    master.m3u8         # HLS master playlist (from BCAST-006)
    720p/
        index.m3u8      # 720p variant playlist
        seg_00001.ts    # HLS segments
        ...
    thumbnail.jpg       # Thumbnail frame (from BCAST-006)
```

### 3.10 Settings

**New settings** to add to `app/core/settings.py` (after existing recording settings at line 1082):

```python
# Recording MP4 download (BCAST-008)
broadcast_recording_download_enabled: bool = os.environ.get("BROADCAST_RECORDING_DOWNLOAD_ENABLED", "1") not in ("0", "false", "False")
broadcast_recording_download_ttl_seconds: int = int(os.environ.get("BROADCAST_RECORDING_DOWNLOAD_TTL_SECONDS", "14400"))  # 4 hours
broadcast_recording_mp4_auto_generate: bool = os.environ.get("BROADCAST_RECORDING_MP4_AUTO_GENERATE", "1") not in ("0", "false", "False")
```

| Setting | Default | Description |
|---------|---------|-------------|
| `BROADCAST_RECORDING_DOWNLOAD_ENABLED` | `true` | Master switch for download feature |
| `BROADCAST_RECORDING_DOWNLOAD_TTL_SECONDS` | `14400` | Presigned URL lifetime (4 hours) |
| `BROADCAST_RECORDING_MP4_AUTO_GENERATE` | `true` | Generate MP4 automatically in pipeline (vs on-demand) |

### 3.11 Dev Mode Behavior

In dev mode (`S.dev_mode=True`), no real FFmpeg processing occurs:

1. **MP4 generation**: `generate_mp4` returns mock metadata (`mp4_s3_key` set but no real
   file exists, `mp4_size_bytes=0`).
2. **Download URL**: `mint_recording_download_url` returns `/mock/s3/broadcast-vod/{id}/recording/full.mp4?expires=...`
3. **Mock S3 serve**: The existing `/mock/s3/{bucket}/{key}` route in dev mode will return
   404 for the non-existent mock MP4, which is acceptable for E2E tests that only validate
   the URL format and auth behavior (not actual file download).

For E2E tests that need to verify an actual download works, a small placeholder MP4 can be
seeded into moto S3 during test setup.

### 3.12 Frontend Integration

**Broadcaster Dashboard** (`SessionDetailDialog` component, inline in `frontend/src/pages/broadcast/BroadcastPage.tsx`):

Add a "Download Recording" button alongside the existing "Watch Recording" button:

```tsx
{recording?.status === "ready" && recording.download_available && (
  <Button
    variant="outline"
    onClick={() => handleDownload(recording.session_id)}
    disabled={downloadLoading}
  >
    <Download className="h-4 w-4 mr-2" />
    Download MP4
    {recording.mp4_size_bytes ? ` (${formatFileSize(recording.mp4_size_bytes)})` : ""}
  </Button>
)}
```

Download handler:
```tsx
const handleDownload = async (sessionId: string) => {
  setDownloadLoading(true);
  try {
    const resp = await api.get(`/broadcast/sessions/${sessionId}/recording/download`);
    window.open(resp.data.download_url, "_blank");
  } finally {
    setDownloadLoading(false);
  }
};
```

**Viewer Download Toggle** (broadcaster settings):

```tsx
<div className="flex items-center justify-between">
  <div>
    <Label>Allow viewer downloads</Label>
    <p className="text-sm text-muted-foreground">
      Let viewers download this recording as an MP4 file
    </p>
  </div>
  <Switch
    checked={allowViewerDownload}
    onCheckedChange={handleToggleViewerDownload}
  />
</div>
```

**Viewer Recording Page** (NOTE: the route `/broadcast/watch/{sessionId}` does NOT currently
exist in the codebase. The existing `SessionDetailDialog` links directly to the recording
playback URL rather than a dedicated viewer page. BCAST-008 must either create this route
or add the viewer download button within the existing `SessionDetailDialog` when viewed by
a non-owner):

```tsx
{recording?.allow_viewer_download && recording.download_available && (
  <Button variant="outline" onClick={handleViewerDownload}>
    <Download className="h-4 w-4 mr-2" />
    Download Recording
  </Button>
)}
```

### 3.13 API Client Types

**Add to `frontend/src/api/endpoints/broadcast.ts`**:

```typescript
export interface BroadcastRecordingDownload {
  download_url: string;
  download_expires_at: number;
  file_size_bytes: number;
  filename: string;
  content_type: string;
}

export const getRecordingDownload = (sessionId: string, viewer = false) =>
  api.get<BroadcastRecordingDownload>(
    `/broadcast/sessions/${sessionId}/recording/download`,
    { params: viewer ? { viewer: true } : undefined }
  );

export const updateRecordingDownloadSettings = (sessionId: string, allowViewerDownload: boolean) =>
  api.patch(`/broadcast/sessions/${sessionId}/recording/download-settings`, {
    allow_viewer_download: allowViewerDownload,
  });
```

---

## 4. Implementation Plan

### 4.1 Files to Modify

| File | Changes |
|------|---------|
| `app/services/broadcast_recording.py` | Add `mp4_s3_key`, `mp4_size_bytes`, `mp4_generated_at`, `allow_download`, `allow_viewer_download`, `s3_concatenated_key` to `RecordingRecord`; add `mint_recording_download_url()`; update `_record_from_item` / `_record_to_item` |
| `app/services/broadcast_recording_worker.py` | Add `generate_mp4()` step; modify `process_recording()` pipeline; modify `finalize_recording()` to accept `mp4_result` |
| `app/routers/broadcast.py` | Add `GET .../recording/download` endpoint; add `PATCH .../recording/download-settings` endpoint; add `BroadcastRecordingDownloadOut` + `BroadcastRecordingDownloadSettingsIn` models; update `BroadcastRecordingOut` with download fields |
| `app/core/settings.py` | Add `broadcast_recording_download_enabled`, `broadcast_recording_download_ttl_seconds`, `broadcast_recording_mp4_auto_generate` |
| `frontend/src/api/endpoints/broadcast.ts` | Add `BroadcastRecordingDownload` type, `getRecordingDownload()`, `updateRecordingDownloadSettings()` |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Add "Download Recording" button + viewer download toggle (in inline `SessionDetailDialog` component) |

### 4.2 New Files to Create

| File | Purpose |
|------|---------|
| `tests/test_broadcast_recording_download.py` | Unit tests for download endpoint + MP4 generation |
| `frontend/e2e/broadcast-recording-download.spec.ts` | E2E tests for download API + UI |

### 4.3 Step-by-Step Implementation Order

**Phase 1: Data Model + Settings (1 hour)**

1. Add download-related settings to `app/core/settings.py` (3 new settings after line 1082)
2. Add new fields to `RecordingRecord` dataclass in `app/services/broadcast_recording.py`
3. Update `_record_from_item()` to deserialize new fields from DDB item
4. Update `_record_to_item()` to serialize new fields to DDB item
5. Add `mint_recording_download_url()` function

**Phase 2: Worker Pipeline Extension (1.5 hours)**

1. Add `generate_mp4()` function to `broadcast_recording_worker.py`
2. Create `_upload_to_s3()` helper for uploading the MP4 file to S3 (does not exist yet in the codebase)
3. Modify `process_recording()` to call `generate_mp4()` between transcode and thumbnail steps
4. Modify `finalize_recording()` to accept and persist `mp4_result` dict
5. Ensure mock mode sets `mp4_s3_key` and `mp4_size_bytes` (even with value 0)
6. Gate the MP4 step behind `S.broadcast_recording_mp4_auto_generate` setting

**Phase 3: API Endpoints (1.5 hours)**

1. Add `BroadcastRecordingDownloadOut` response model to `app/routers/broadcast.py`
2. Add `BroadcastRecordingDownloadSettingsIn` request model
3. Implement `GET /broadcast/sessions/{session_id}/recording/download`:
   - Auth check (require_ui_session)
   - Feature flag check (`broadcast_recording_download_enabled`)
   - Recording existence + status checks (404, 410, 202)
   - MP4 availability check (404 if `mp4_s3_key` is empty)
   - Permission check: broadcaster ownership OR viewer with `allow_viewer_download=true`
   - Mint and return presigned download URL
4. Implement `PATCH /broadcast/sessions/{session_id}/recording/download-settings`:
   - Auth check + ownership verification
   - Update `allow_viewer_download` field via `update_recording_status()`
5. Update `BroadcastRecordingOut` to include `allow_download`, `allow_viewer_download`, `download_available`, `mp4_size_bytes`
6. Update `get_recording_route` to populate new response fields

**Phase 4: Frontend Integration (2 hours)**

1. Add TypeScript types and API wrappers to `frontend/src/api/endpoints/broadcast.ts`
2. Add "Download Recording" button to `SessionDetailDialog` (inline in `BroadcastPage.tsx`):
   - Visible when `recording.download_available === true`
   - Shows file size in human-readable format (e.g., "Download MP4 (1.2 GB)")
   - Loading state while fetching presigned URL
   - Opens URL in new tab to trigger download
3. Add viewer download toggle (Switch component) in broadcaster session settings:
   - Uses `useMutation` with `updateRecordingDownloadSettings`
   - Invalidates recording query on success
   - Shows toast confirmation
4. Add "Download Recording" button to viewer recording page (NOTE: route `/broadcast/watch/{sessionId}` does not exist yet and must be created, or the download button can be added to the existing `SessionDetailDialog` when viewed by a non-owner):
   - Only visible when `recording.allow_viewer_download === true`
   - Calls `getRecordingDownload(sessionId, true)` with viewer flag
   - Same download trigger pattern as broadcaster

**Phase 5: Environment Configuration (0.5 hours)**

1. Add to `.env.local.example`:
   ```bash
   # Broadcast recording download (BCAST-008)
   BROADCAST_RECORDING_DOWNLOAD_ENABLED=true
   BROADCAST_RECORDING_DOWNLOAD_TTL_SECONDS=14400
   BROADCAST_RECORDING_MP4_AUTO_GENERATE=true
   ```
2. Add to `.env.local` on dev hosts (or rely on defaults)

### 4.4 Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| BCAST-006 (Recording Archive) | Complete | Provides recording pipeline, DDB table, worker |
| FFmpeg on host | Optional | Mock mode if unavailable (same as BCAST-006) |
| S3 `broadcast-vod` bucket | Exists | Created during stack startup |
| `broadcast_recording_worker.py` | Exists | Extended with MP4 step |
| `broadcast_recording.py` | Exists | Extended with download URL minting |
| `app/routers/broadcast.py` | Exists | New endpoints added |

### 4.5 Rollout / Feature Flag Strategy

The feature is gated behind `BROADCAST_RECORDING_DOWNLOAD_ENABLED`:
- Set `false` in production initially while monitoring MP4 generation performance
- Enable per-tenant if needed (not in this ticket; per-tenant gating would require a
  profile-level setting)
- `BROADCAST_RECORDING_MP4_AUTO_GENERATE` can be disabled to skip MP4 generation entirely
  (useful if storage costs are a concern during initial rollout)

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_recording_download.py`)

**Test Group 1: MP4 Remux Function (5 tests)**

```python
def test_generate_mp4_mock_mode_returns_placeholder():
    """In mock mode, generate_mp4 returns mock metadata without calling FFmpeg."""
    # Assert: mp4_s3_key is set, mp4_size_bytes=0, no subprocess call

def test_generate_mp4_with_concat_path_calls_ffmpeg():
    """When concat_path is provided and FFmpeg available, subprocess.run is called."""
    # Mock subprocess.run, verify args include -c copy -movflags +faststart

def test_generate_mp4_ffmpeg_failure_raises_runtime_error():
    """If FFmpeg returns non-zero, RuntimeError is raised with stderr excerpt."""
    # Mock subprocess.run with returncode=1

def test_generate_mp4_output_key_format():
    """MP4 S3 key follows format: {session_id}/recording/full.mp4."""
    # Verify key derivation from session_id

def test_generate_mp4_no_concat_path_returns_mock():
    """When concat_path is None (no segments), mock metadata is returned."""
```

**Test Group 2: Download URL Minting (4 tests)**

```python
def test_mint_download_url_dev_mode_returns_mock_path():
    """In dev mode, URL is /mock/s3/... with expires and disposition params."""

def test_mint_download_url_includes_content_disposition():
    """Presigned URL params include ResponseContentDisposition: attachment."""

def test_mint_download_url_respects_ttl_setting():
    """download_expires_at = now + broadcast_recording_download_ttl_seconds."""

def test_mint_download_url_filename_contains_session_id():
    """Filename is 'recording-{session_id_prefix}.mp4'."""
```

**Test Group 3: Download Endpoint Auth + Permissions (8 tests)**

```python
def test_download_requires_authentication():
    """Unauthenticated request returns 401."""

def test_download_returns_404_no_recording():
    """Session with no recording returns 404."""

def test_download_returns_410_expired_recording():
    """Expired recording returns 410 Gone."""

def test_download_returns_202_processing_recording():
    """Recording still processing returns 202."""

def test_download_returns_404_no_mp4():
    """Recording ready but mp4_s3_key empty returns 404 with MP4_NOT_AVAILABLE."""

def test_broadcaster_can_download_own_recording():
    """Broadcaster (created_by matches user_sub) gets 200 with download URL."""

def test_other_user_cannot_download_broadcaster_recording():
    """Non-owner, non-viewer request returns 403."""

def test_viewer_download_forbidden_when_disabled():
    """viewer=true returns 403 when allow_viewer_download=false."""
```

**Test Group 4: Viewer Download Permissions (5 tests)**

```python
def test_viewer_download_allowed_when_enabled():
    """viewer=true returns 200 when allow_viewer_download=true."""

def test_toggle_viewer_download_on():
    """PATCH with allow_viewer_download=true updates the record."""

def test_toggle_viewer_download_off():
    """PATCH with allow_viewer_download=false updates the record."""

def test_toggle_requires_ownership():
    """Non-owner PATCH returns 403."""

def test_toggle_returns_404_no_recording():
    """PATCH on non-existent session returns 404."""
```

**Test Group 5: Feature Flag (3 tests)**

```python
def test_download_disabled_returns_503():
    """When BROADCAST_RECORDING_DOWNLOAD_ENABLED=false, returns 503."""

def test_mp4_not_generated_when_auto_generate_disabled():
    """When BROADCAST_RECORDING_MP4_AUTO_GENERATE=false, generate_mp4 is skipped."""

def test_pipeline_completes_without_mp4_when_disabled():
    """Recording reaches ready status even when MP4 generation is disabled."""
```

### 5.2 Unit Test Setup

Tests use the existing `moto` mock for DynamoDB with the `BroadcastRecordings` table:

```python
@pytest.fixture(autouse=True)
def recording_table(ddb_resource, monkeypatch):
    """Create BroadcastRecordings table and patch settings."""
    table = ddb_resource.create_table(
        TableName="BroadcastRecordings",
        KeySchema=[{"AttributeName": "recording_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "recording_id", "AttributeType": "S"},
            {"AttributeName": "session_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "scope", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "expires_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[...],
        BillingMode="PAY_PER_REQUEST",
    )
    monkeypatch.setattr("app.core.settings.S.broadcast_recording_download_enabled", True)
    monkeypatch.setattr("app.core.settings.S.broadcast_recording_download_ttl_seconds", 14400)
    yield table


@pytest.fixture
def ready_recording(recording_table):
    """Create a recording in 'ready' status with mp4_s3_key set."""
    from app.services.broadcast_recording import create_recording, update_recording_status
    rec = create_recording(session_id="sess_test123", profile_id="prof_1", created_by="user_broadcaster")
    update_recording_status(rec.recording_id, "ready",
        mp4_s3_key="sess_test123/recording/full.mp4",
        mp4_size_bytes=1048576,
        mp4_generated_at=int(time.time()),
        s3_manifest_key="sess_test123/recording/master.m3u8",
    )
    return get_recording(rec.recording_id)
```

FFmpeg is mocked using `unittest.mock.patch` on `subprocess.run`:

```python
@pytest.fixture
def mock_ffmpeg(monkeypatch):
    def fake_run(args, **kwargs):
        # Create a dummy output file if -i and output path are present
        if len(args) > 2 and args[-1].endswith(".mp4"):
            Path(args[-1]).write_bytes(b"\x00" * 1024)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
    monkeypatch.setattr("subprocess.run", fake_run)
```

### 5.3 E2E Tests (`frontend/e2e/broadcast-recording-download.spec.ts`)

**Section 93: Recording Download API -- Broadcaster Flow (7 tests)**

```typescript
test.describe("Section 93: Broadcaster recording download", () => {
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    // Create profile + session + start + stop (triggers recording with MP4)
    const rootPage = await newIdentityPage(browser, "root");
    profileId = await createTestProfile(rootPage, "root");
    sessionId = await createTestSession(rootPage, "root", profileId);
    await startSession(rootPage, "root", sessionId);
    await stopSession(rootPage, "root", sessionId);
  });

  test("93.1 download endpoint returns presigned URL for broadcaster", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/recording/download`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.download_url).toContain("/mock/s3/broadcast-vod/");
    expect(body.download_url).toContain("full.mp4");
    expect(body.download_expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(body.filename).toContain("recording-");
    expect(body.content_type).toBe("video/mp4");
  });

  test("93.2 download URL expires within configured TTL", async () => {
    const body = await (await apiGet(rootPage, `/broadcast/sessions/${sessionId}/recording/download`)).json();
    const now = Math.floor(Date.now() / 1000);
    const maxTtl = 14400 + 10; // 4 hours + 10s tolerance
    expect(body.download_expires_at - now).toBeLessThanOrEqual(maxTtl);
    expect(body.download_expires_at - now).toBeGreaterThan(0);
  });

  test("93.3 recording response includes download_available=true", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/recording`);
    const body = await resp.json();
    expect(body.download_available).toBe(true);
    expect(body.allow_viewer_download).toBe(false);
  });

  test("93.4 download for non-existent session returns 404", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/nonexistent-session/recording/download`);
    expect(resp.status()).toBe(404);
  });

  test("93.5 download requires authentication", async () => {
    const resp = await fetch(`http://localhost:8000/broadcast/sessions/${sessionId}/recording/download`);
    expect(resp.status).toBe(401);
  });

  test("93.6 non-owner cannot download broadcaster recording", async () => {
    // Alice tries to download root's recording
    const resp = await apiGet(alicePage, `/broadcast/sessions/${sessionId}/recording/download`);
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("BROADCAST_RECORDING_DOWNLOAD_FORBIDDEN");
  });

  test("93.7 file_size_bytes is returned in response", async () => {
    const body = await (await apiGet(rootPage, `/broadcast/sessions/${sessionId}/recording/download`)).json();
    expect(typeof body.file_size_bytes).toBe("number");
    expect(body.file_size_bytes).toBeGreaterThanOrEqual(0);
  });
});
```

**Section 94: Viewer Download Permissions (6 tests)**

```typescript
test.describe("Section 94: Viewer download permissions", () => {
  test("94.1 viewer download disabled by default", async () => {
    const resp = await apiGet(alicePage, `/broadcast/sessions/${sessionId}/recording/download?viewer=true`);
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("BROADCAST_RECORDING_DOWNLOAD_FORBIDDEN");
  });

  test("94.2 broadcaster enables viewer download", async () => {
    const resp = await apiPatch(rootPage, "root",
      `/broadcast/sessions/${sessionId}/recording/download-settings`,
      { allow_viewer_download: true }
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.allow_viewer_download).toBe(true);
  });

  test("94.3 viewer can download after broadcaster enables it", async () => {
    const resp = await apiGet(alicePage, `/broadcast/sessions/${sessionId}/recording/download?viewer=true`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.download_url).toContain("full.mp4");
  });

  test("94.4 broadcaster disables viewer download", async () => {
    const resp = await apiPatch(rootPage, "root",
      `/broadcast/sessions/${sessionId}/recording/download-settings`,
      { allow_viewer_download: false }
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).allow_viewer_download).toBe(false);
  });

  test("94.5 viewer download blocked again after disable", async () => {
    const resp = await apiGet(alicePage, `/broadcast/sessions/${sessionId}/recording/download?viewer=true`);
    expect(resp.status()).toBe(403);
  });

  test("94.6 non-owner cannot toggle viewer download", async () => {
    const resp = await apiPatch(alicePage, "alice",
      `/broadcast/sessions/${sessionId}/recording/download-settings`,
      { allow_viewer_download: true }
    );
    expect(resp.status()).toBe(403);
  });
});
```

**Section 95: Download Edge Cases (5 tests)**

```typescript
test.describe("Section 95: Download edge cases", () => {
  test("95.1 download for expired recording returns 410", async () => {
    // Directly set recording status to "expired" in DDB
    await setRecordingStatus(expiredSessionId, "expired");
    const resp = await apiGet(rootPage, `/broadcast/sessions/${expiredSessionId}/recording/download`);
    expect(resp.status()).toBe(410);
  });

  test("95.2 download for processing recording returns 202", async () => {
    // Create a recording stuck in "processing" state
    const resp = await apiGet(rootPage, `/broadcast/sessions/${processingSessionId}/recording/download`);
    expect(resp.status()).toBe(202);
  });

  test("95.3 recording response shows allow_viewer_download state", async () => {
    // Verify the GET /recording endpoint reflects download settings
    await apiPatch(rootPage, "root",
      `/broadcast/sessions/${sessionId}/recording/download-settings`,
      { allow_viewer_download: true }
    );
    const body = await (await apiGet(rootPage, `/broadcast/sessions/${sessionId}/recording`)).json();
    expect(body.allow_viewer_download).toBe(true);
  });

  test("95.4 download URL contains correct filename", async () => {
    const body = await (await apiGet(rootPage, `/broadcast/sessions/${sessionId}/recording/download`)).json();
    expect(body.filename).toMatch(/^recording-[a-z0-9]+\.mp4$/);
  });

  test("95.5 multiple download requests produce fresh URLs", async () => {
    const body1 = await (await apiGet(rootPage, `/broadcast/sessions/${sessionId}/recording/download`)).json();
    // Small delay to ensure different timestamp
    await new Promise(r => setTimeout(r, 1100));
    const body2 = await (await apiGet(rootPage, `/broadcast/sessions/${sessionId}/recording/download`)).json();
    // URLs should be different (different expiry timestamps)
    expect(body1.download_expires_at).not.toBe(body2.download_expires_at);
  });
});
```

**Section 96: Download UI (4 tests)**

```typescript
test.describe("Section 96: Download Recording UI", () => {
  test("96.1 'Download MP4' button visible on stopped session with recording", async () => {
    await injectAuth(rootPage, "root");
    await rootPage.goto("/broadcaster");
    await rootPage.getByRole("button", { name: /view details/i }).first().click();
    await expect(rootPage.getByRole("button", { name: /download mp4/i })).toBeVisible();
  });

  test("96.2 'Download MP4' button not visible on live session", async () => {
    // Navigate to a live session detail
    await expect(rootPage.getByRole("button", { name: /download mp4/i })).not.toBeVisible();
  });

  test("96.3 viewer download toggle visible to broadcaster", async () => {
    await expect(rootPage.getByLabel(/allow viewer download/i)).toBeVisible();
  });

  test("96.4 viewer sees download button only when enabled", async () => {
    // NOTE: /broadcast/watch/{sessionId} does NOT exist yet — must be created as part of
    // BCAST-008, OR this test should be adapted to use the existing SessionDetailDialog
    // (which currently links directly to the playback URL, not a dedicated viewer page).
    // Enable viewer download, then check from Alice's page
    await apiPatch(rootPage, "root",
      `/broadcast/sessions/${sessionId}/recording/download-settings`,
      { allow_viewer_download: true }
    );
    await injectAuth(alicePage, "alice");
    await alicePage.goto(`/broadcast/watch/${sessionId}`);  // Route must be created
    await expect(alicePage.getByRole("button", { name: /download recording/i })).toBeVisible();
  });
});
```

### 5.4 Mock Recording Flow for E2E

Since E2E tests run against the local dev stack (no real media exists), the MP4 generation
step produces mock metadata:

1. `generate_mp4()` detects mock mode → returns `{ mp4_s3_key: "{session_id}/recording/full.mp4", mp4_size_bytes: 0, mp4_generated_at: <now> }`
2. `finalize_recording()` persists these values in DDB
3. `GET .../recording/download` sees `mp4_s3_key` is non-empty → mints a mock presigned URL
4. Tests verify URL format, auth behavior, and permission logic (not actual file download)

For tests that need to verify actual download behavior (e.g., testing `Content-Disposition`),
seed a small MP4 file into moto S3:

```typescript
// In test setup:
const smallMp4 = Buffer.from([
  0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70,  // ftyp box header
  0x69, 0x73, 0x6F, 0x6D, 0x00, 0x00, 0x02, 0x00,  // isom brand
  // ... minimal valid MP4 header
]);
// Upload via internal/dev endpoint or DDB manipulation
```

### 5.5 Test Data Isolation

Following established E2E patterns:
- Use timestamp-suffixed session names: `E2E Download Test ${Date.now()}`
- Track created session IDs for cleanup in `afterAll`
- Use `root` identity for broadcaster operations
- Use `alice` identity for viewer operations
- Download permission changes are scoped to specific sessions (no cross-test interference)

### 5.6 Potential Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| Recording not ready (MP4 not generated) | Inline worker in dev mode processes synchronously; MP4 step is instant in mock mode |
| FFmpeg not installed in CI | Mock mode produces placeholder MP4 metadata |
| Timing-dependent URL expiry assertions | Use >= / <= comparisons with 10s tolerance |
| Concurrent test runs modifying same session | Unique session IDs per test run |
| Viewer download toggle race | Assert on API response before checking viewer page |

---

## Appendix A: Response Models

### BroadcastRecordingOut (updated)

```python
class BroadcastRecordingOut(BaseModel):
    recording_id: str
    session_id: str
    status: str
    duration_seconds: Optional[float] = None
    playback_url: Optional[str] = None
    playback_expires_at: Optional[int] = None
    thumbnail_url: Optional[str] = None
    segment_count: Optional[int] = None
    total_bytes: Optional[int] = None
    renditions: list = Field(default_factory=list)
    created_at: int
    completed_at: Optional[int] = None
    expires_at: Optional[int] = None
    # Download fields (BCAST-008)
    allow_download: bool = True
    allow_viewer_download: bool = False
    download_available: bool = False       # True when mp4_s3_key is non-empty and status=ready
    mp4_size_bytes: Optional[int] = None   # File size for display
```

### BroadcastRecordingDownloadOut

```python
class BroadcastRecordingDownloadOut(BaseModel):
    download_url: str                      # Presigned S3 URL
    download_expires_at: int               # Unix timestamp
    file_size_bytes: int                   # MP4 file size in bytes
    filename: str                          # e.g., "recording-abc123def4.mp4"
    content_type: str = "video/mp4"        # MIME type
```

### BroadcastRecordingDownloadSettingsIn

```python
class BroadcastRecordingDownloadSettingsIn(BaseModel):
    allow_viewer_download: bool
```

### Error Codes

| Code | HTTP | Condition |
|------|------|-----------|
| `BROADCAST_RECORDING_NOT_FOUND` | 404 | No recording exists for the session |
| `BROADCAST_RECORDING_EXPIRED` | 410 | Recording past retention period |
| `BROADCAST_RECORDING_PROCESSING` | 202 | Recording still being processed |
| `BROADCAST_RECORDING_MP4_NOT_AVAILABLE` | 404 | Recording ready but MP4 not generated |
| `BROADCAST_RECORDING_DOWNLOAD_FORBIDDEN` | 403 | Viewer download not allowed, or non-owner |
| `BROADCAST_RECORDING_DOWNLOAD_DISABLED` | 503 | Feature disabled via setting |

---

## Appendix B: Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `BROADCAST_RECORDING_DOWNLOAD_ENABLED` | `true` | Master switch for MP4 download feature |
| `BROADCAST_RECORDING_DOWNLOAD_TTL_SECONDS` | `14400` | Presigned download URL lifetime (4 hours) |
| `BROADCAST_RECORDING_MP4_AUTO_GENERATE` | `true` | Auto-generate MP4 during recording pipeline |
| `BROADCAST_RECORDINGS_TABLE` | `BroadcastRecordings` | DynamoDB table (existing) |
| `BROADCAST_RECORDING_VOD_BUCKET` | `broadcast-vod` | S3 bucket for recording files (existing) |

---

## Appendix C: File Reference

| File | Role in MP4 download feature |
|------|------------------------------|
| `app/services/broadcast_recording.py` | Recording store + download URL minting |
| `app/services/broadcast_recording_worker.py` | MP4 remux pipeline step |
| `app/routers/broadcast.py` | Download + settings endpoints |
| `app/core/settings.py` | Feature configuration |
| `frontend/src/api/endpoints/broadcast.ts` | API client wrappers |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Download button + toggle UI (in inline `SessionDetailDialog` component) |
| `tests/test_broadcast_recording_download.py` | Unit tests (NEW) |
| `frontend/e2e/broadcast-recording-download.spec.ts` | E2E tests (NEW) |

---

## Appendix D: FFmpeg Remux Performance Estimates

The MP4 remux (`-c copy -movflags +faststart`) performs no encoding. Performance is bounded
by disk I/O and S3 transfer speeds:

| Recording Duration | Approx .ts Size | Remux Time (local SSD) | Remux Time (S3 → local → S3) |
|-------------------|-----------------|------------------------|-------------------------------|
| 30 minutes | ~1 GB | ~3 seconds | ~20 seconds |
| 1 hour | ~2 GB | ~6 seconds | ~40 seconds |
| 2 hours | ~4 GB | ~12 seconds | ~80 seconds |
| 4 hours | ~8 GB | ~25 seconds | ~160 seconds |

The `+faststart` flag adds a second pass that relocates the moov atom. For very large files
(>4GB), this requires reading and rewriting the file header, adding 1-5 seconds to the
operation. Total time remains well under the recording pipeline's existing transcode step.
