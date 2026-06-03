# BCAST-008: Recording MP4 Download

**Ticket**: BCAST-008
**Author**: Engineering
**Status**: Implemented
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
<!-- NOTE: This claim is NOW OUTDATED. MP4 download infrastructure exists:
  `app/routers/broadcast.py:762-808` (download endpoint with `broadcast_recording_download_enabled` gate),
  `mint_recording_download_url` (broadcast.py:29 import),
  `app/core/settings.py:1147-1148` (download_enabled, download_ttl_seconds),
  `frontend/e2e/broadcast-recording-download.spec.ts` -->

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

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_broadcast_recording_download.py`

**Mock setup**: moto mock for DynamoDB (broadcast tables). Mock broadcast provider for instant state transitions.

| Test Function | Description |
|---|---|
| `test_create_bcast008_resource` | Create primary resource; verify stored in DDB with correct fields |
| `test_get_bcast008_resource` | Get resource by ID; verify all fields returned |
| `test_list_bcast008_resources` | List resources; verify pagination and filtering |
| `test_update_bcast008_resource` | Update resource; verify changed fields persisted |
| `test_delete_bcast008_resource` | Delete resource; verify removed from DDB |
| `test_validation_rejects_invalid_input` | Missing required fields returns 422; invalid values return 400 |
| `test_authorization_enforced` | Non-owner/non-admin access returns 403 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full lifecycle: create -> read -> update -> delete through real DDB
2. Cross-service integration with broadcast session store
3. Concurrent operations do not corrupt shared state

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/broadcast-recording-download.spec.ts`

**Auth pattern**: `injectAuth(page, "root")` for admin operations; `injectAuth(page, "alice")` for viewer operations; CSRF header for mutations

| # | Test Name | Assertion |
|---|---|---|
| 1 | API creates resource successfully | POST returns 200/201 with resource ID |
| 2 | API returns resource by ID | GET returns full resource with all expected fields |
| 3 | API lists resources with pagination | GET list returns array; supports cursor pagination |
| 4 | API updates resource fields | PATCH/PUT returns updated resource |
| 5 | API deletes resource | DELETE returns 200; subsequent GET returns 404 |
| 6 | UI page loads with expected heading | Navigate to page; heading visible |
| 7 | UI form creates new resource | Fill form; submit; resource appears in list |
| 8 | UI shows error for invalid input | Submit empty form; validation messages visible |
| 9 | Unauthenticated request returns 401 | No session cookies -> 401 |
| 10 | Non-owner access returns 403 | Wrong user -> 403 |
| 11 | Non-existent resource returns 404 | GET invalid ID -> 404 |
| 12 | Duplicate creation returns 409 | Create same resource twice -> 409 or idempotent success |

**Negative tests**: 401 unauthenticated, 403 non-owner, 404 not found, 409 conflict/duplicate, 422 validation

**Edge cases**: Empty state (no resources), concurrent mutations, resource with max-length fields, Unicode content

### Test Data Requirements

Seed broadcast session in `beforeAll`. Create test resources via API with unique `Date.now()` suffixed names.

**Test users**: Root (ROOT, admin operations), Alice (USER, standard operations), Bob (USER, cross-user isolation)

### CI/Pipeline

Serial execution. `BROADCAST_PROVIDER=local`. Retry-safe with unique resource names.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| BCAST-006 | Recording VOD archive with `s3_concatenated_key` | Implemented | No -- must merge after |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Sequential after BCAST-006. Adds download endpoint and remux logic. Feature-flag-gated via `broadcast_recording_download_enabled`.

### Merge Checklist

- [ ] DDB table/fields added to `scripts/local-ddb-init.py` (if new table needed)
- [ ] Settings added to `app/core/settings.py`
- [ ] Service and router files created/modified
- [ ] Frontend components and API wrappers created
- [ ] E2E test passes in CI
- [ ] No breaking changes to existing endpoints

---

## Codebase References

| File | Line(s) | Status | Notes |
|------|---------|--------|-------|
| `app/routers/broadcast.py` | 762-808 | EXISTS | Download endpoint with `broadcast_recording_download_enabled` gate |
| `app/routers/broadcast.py` | 27, 29 | EXISTS | Imports `mint_recording_playback_url`, `mint_recording_download_url` |
| `app/services/broadcast_recording.py` | — | EXISTS | Recording service with download URL minting |
| `app/core/settings.py` | 1147-1148 | EXISTS | `broadcast_recording_download_enabled`, `broadcast_recording_download_ttl_seconds` |
| `app/core/tables.py` | 82 | EXISTS | `T.broadcast_recordings` handle |
| `scripts/local-ddb-init.py` | 567-576 | EXISTS | BroadcastRecordings table |
| `frontend/e2e/broadcast-recording-download.spec.ts` | — | EXISTS | E2E tests for download |
