# VOD-015: Video Clipping / Trimming

**Ticket**: VOD-015
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27

---

## 1. Overview & Motivation

### 1.1 Problem Statement

Creators frequently need to extract a specific segment from a longer video -- cutting an intro, isolating a highlight, or trimming dead air from a broadcast recording. Today, creators must download the source, use external editing software, and re-upload the trimmed result as a brand-new video. This workflow is slow, requires desktop software, and produces a duplicate upload that bypasses the platform's existing transcode pipeline, watermark policy, and metadata lineage.

A first-party clipping tool eliminates this friction by letting creators select a time range directly on the platform and produce a new video from the sub-section without ever leaving the browser.

### 1.2 How It Works

1. Creator navigates to a video they own and clicks the "Clip" button (scissors icon).
2. A dialog opens showing the video timeline with draggable start/end handles.
3. Creator adjusts the handles to define the desired range, optionally sets a title.
4. Clicking "Create Clip" sends a `POST /ui/videos/{video_id}/clip` request.
5. The backend validates the range, creates a new video metadata record, and enqueues a clip job.
6. The clip job runs ffmpeg with `-ss` / `-to` flags, first attempting stream copy (fast, no re-encode) and falling back to re-encode if the stream copy produces keyframe-alignment artifacts.
7. After the clip is produced, it runs through the same ABR pipeline as regular uploads (HLS renditions, thumbnails).
8. The new video appears in the creator's library with a link back to the original.

### 1.3 Design Principles

- **Non-destructive**: The original video is never modified. Clipping always produces a new video record.
- **Fast path first**: Stream copy (`-c copy`) is attempted before re-encode. For most modern H.264/H.265 content with frequent keyframes, stream copy produces correct output in seconds rather than minutes.
- **Lineage tracking**: Clipped videos store `source_video_id`, `clip_start_seconds`, `clip_end_seconds`, and `created_via: "clip"` for provenance.
- **Permission simplicity**: Only the video owner can clip their own videos. The clipped video inherits visibility and access_mode by default but can be changed independently.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to clip a 30-second highlight from a 2-hour broadcast recording. | POST clip with valid range; new video created; original unchanged; clip inherits title "(clip)". |
| Creator | As a creator, I want to see the clip processing status while it runs. | Clip job appears in transcode jobs list; status transitions from queued -> running -> completed. |
| Creator | As a creator, I want my clip to go through the same HLS pipeline as a regular upload. | After clip extraction, ABR pipeline produces renditions + thumbnails; HLS playback works. |
| Creator | As a creator, I want to know which video a clip came from. | Clipped video detail shows `source_video_id` linking to the original. |
| Viewer | As a viewer, I see a clipped video in my feed and can play it like any other video. | Clipped video is indistinguishable from uploads in the player; HLS streaming works normally. |

---

## 2. Current State Analysis

### 2.1 FFmpeg Clipping Capabilities

FFmpeg supports time-range extraction via `-ss` (start) and `-to` (end) flags. Two modes are relevant:

**Stream copy (fast, no re-encode)**:
```bash
ffmpeg -ss 30 -to 90 -i input.mp4 -c copy -avoid_negative_ts make_zero output.mp4
```

- Pros: Completes in seconds regardless of video length; no quality loss.
- Cons: Start point snaps to the nearest preceding keyframe. If the source has infrequent keyframes (e.g., every 10 seconds), the clip may include up to ~10 seconds of unwanted footage at the beginning. The end point has the same keyframe granularity issue.
- Artifacts: Some players show a frozen frame or green artifacts for the frames between the keyframe and the requested start time.

**Re-encode (accurate, slower)**:
```bash
ffmpeg -ss 30 -to 90 -i input.mp4 -c:v libx264 -preset medium -crf 22 -c:a aac -b:a 128k output.mp4
```

- Pros: Frame-accurate start/end; no keyframe alignment issues.
- Cons: Full decode + encode cycle; takes minutes for long clips; slight generation loss (mitigated by CRF quality targeting).

**Chosen strategy**: Attempt stream copy first. If the output duration deviates from the expected duration by more than 2 seconds (indicating keyframe misalignment), retry with re-encode. This gives most clips the fast path while ensuring accuracy when needed.

### 2.2 Existing FFmpeg Infrastructure

**`app/services/ffmpeg_executor.py`** (VOD-004):
- `execute_rendition()` -- Async subprocess wrapper with progress parsing, timeout, cancellation, resource limits.
- Builds restricted environment (`_build_restricted_env`), applies resource limits (`_apply_resource_limits`).
- Error classification via `classify_error()`.
- The clip job will use `execute_rendition()` directly, passing clip-specific ffmpeg args.

**`app/services/ffmpeg_manager.py`** (MEDIA-002):
- `get_ffmpeg_path()` -- Validated binary path resolution.
- `is_ffmpeg_available()` -- Quick availability check.
- `validate_ffmpeg()` -- Full health check with codec verification.
- Clip operations require `libx264` and `aac` codecs (already in `REQUIRED_CODECS`).

**`app/services/ffmpeg_abr_pipeline.py`**:
- `build_rendition_ffmpeg_args()` -- Builds per-rendition ffmpeg args with watermark support.
- After clip extraction, the clipped file is fed through this pipeline as if it were a new upload.

**`app/services/transcode_job_store.py`** (VOD-003):
- `create_job()` -- Creates a job in the `transcode_jobs` table with `status="queued"`.
- `claim_job()`, `complete_job()`, `fail_job()` -- State machine for job processing.
- **Note:** The existing `create_job()` does not have a `job_type` field. A `job_type` field (value `"clip"`) must be added to distinguish clip jobs from standard transcodes. This requires modifying `create_job()` or using a separate `create_clip_job()` helper that writes `job_type` directly.

### 2.3 Video Metadata Model

**`app/models_video.py`** -- `VideoMetadataModel` fields relevant to clipping:
- `id`, `owner_user_id`, `title`, `status`, `source_type`, `visibility`, `access_mode`
- `duration_seconds` -- Used to validate clip range (`end_seconds <= duration_seconds`)
- `source_s3_key` -- S3 key of the original upload; the clip reads from this file
- No existing fields for clip provenance -- these will be added

### 2.4 Source File Availability

The original upload is stored at `videos/{user_sub}/{video_id}/{filename}` in the upload bucket and is retained indefinitely (see VOD-012, Section 2.2). The clip operation downloads this source file to scratch disk, extracts the time range, and uploads the result as a new file. This is the same source retrieval pattern used by VOD-012's MP4 download generator.

### 2.5 Probe Data

There is no `app/services/ffmpeg_prober.py` file in the codebase today -- it needs to be created (or the probe logic needs to be added to an existing service module). Currently, probe results (duration, codec, keyframe interval) are expected on the video metadata record after upload. The clip endpoint uses `duration_seconds` for range validation and `video_codec` to decide whether stream copy is likely to succeed without artifacts. **Implementation note:** the probe service must be created before or alongside this ticket.

---

## 3. Technical Design

### 3.1 Approach Evaluation

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| **A: Stream copy only** | Always use `-c copy` | Fastest; no quality loss | Keyframe misalignment causes artifacts; inaccurate start/end |
| **B: Re-encode only** | Always re-encode with libx264 | Frame-accurate; no artifacts | Slow (minutes per clip); unnecessary for well-keyframed content |
| **C: Stream copy with re-encode fallback** | Try `-c copy` first; if output duration deviates >2s from expected, retry with re-encode | Fast for most content; accurate when needed; quality preserved | Slightly more complex; two ffmpeg invocations in worst case |

### 3.2 Recommended Approach: Stream Copy with Fallback (Option C)

This balances speed and accuracy. The fallback is triggered by comparing the actual output duration (from ffprobe on the output file) against the expected duration (`end_seconds - start_seconds`). A 2-second tolerance accounts for keyframe granularity without triggering unnecessary re-encodes.

### 3.3 Data Model Changes

**File: `app/models_video.py`** -- Add fields to `VideoMetadataModel`:

```python
# Clipping provenance (VOD-015)
source_video_id: Optional[str] = None          # ID of the video this was clipped from
clip_start_seconds: Optional[float] = None     # Start of clip range in source video
clip_end_seconds: Optional[float] = None       # End of clip range in source video
created_via: Optional[str] = None              # "upload" | "clip" | "concat" | "broadcast_archive"
```

**File: `app/models_video.py`** -- New request model:

```python
class ClipVideoIn(BaseModel):
    start_seconds: float = Field(ge=0)
    end_seconds: float = Field(gt=0)
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
```

**File: `app/models_video.py`** -- Add to `VideoOut`:

```python
source_video_id: Optional[str] = None
clip_start_seconds: Optional[float] = None
clip_end_seconds: Optional[float] = None
created_via: Optional[str] = None
```

### 3.4 API Endpoint

**Path**: `POST /ui/videos/{video_id}/clip`

**Auth**: `require_ui_session` (cookie-based)

**Request body**:
```json
{
  "start_seconds": 30.0,
  "end_seconds": 90.0,
  "title": "Best moment from stream"
}
```

**Validation rules**:
1. `start_seconds >= 0`
2. `end_seconds > start_seconds`
3. `end_seconds <= video.duration_seconds` (source video must have been probed)
4. `end_seconds - start_seconds >= 5` (minimum clip length: 5 seconds)
5. Source video `status` must be `"published"` or `"approved"` (fully transcoded)
6. Requester must be the video owner (`ctx["user_sub"] == video.owner_user_id`)

**Response** (201 Created):
```json
{
  "video_id": "v_abc123",
  "title": "Best moment from stream (clip)",
  "status": "created",
  "source_video_id": "v_original",
  "clip_start_seconds": 30.0,
  "clip_end_seconds": 90.0,
  "created_via": "clip",
  "clip_job_id": "tj_def456"
}
```

**Error responses**:

| Status | Condition | Detail |
|--------|-----------|--------|
| 400 | `start_seconds >= end_seconds` | "start_seconds must be less than end_seconds" |
| 400 | Clip duration < 5 seconds | "minimum clip length is 5 seconds" |
| 400 | `end_seconds > duration_seconds` | "end_seconds exceeds video duration" |
| 403 | Not the video owner | "forbidden" |
| 404 | Video not found | "video not found" |
| 409 | Video not in published/approved status | "video must be published or approved" |
| 409 | Source video has no `source_s3_key` | "source file not available" |

```python
@router.post("/{video_id}/clip", status_code=201)
def clip_video(
    video_id: str,
    body: ClipVideoIn,
    ctx=Depends(require_ui_session),
):
    video = get_video(video_id)
    user_sub = ctx["user_sub"]

    if video.owner_user_id != user_sub:
        raise HTTPException(status_code=403, detail="forbidden")

    if video.status not in ("published", "approved"):
        raise HTTPException(status_code=409, detail="video must be published or approved")

    if not video.source_s3_key:
        raise HTTPException(status_code=409, detail="source file not available")

    if video.duration_seconds is None:
        raise HTTPException(status_code=409, detail="video duration unknown")

    if body.end_seconds > video.duration_seconds:
        raise HTTPException(status_code=400, detail="end_seconds exceeds video duration")

    if body.start_seconds >= body.end_seconds:
        raise HTTPException(status_code=400, detail="start_seconds must be less than end_seconds")

    clip_duration = body.end_seconds - body.start_seconds
    if clip_duration < 5:
        raise HTTPException(status_code=400, detail="minimum clip length is 5 seconds")

    # Create new video metadata for the clip
    title = body.title or f"{video.title} (clip)"
    new_video = create_video(
        owner_user_id=user_sub,
        title=title,
        description=video.description,
        source_type="upload",
        visibility=video.visibility,
    )

    # Set clip provenance fields
    update_clip_fields(
        video_id=new_video.id,
        source_video_id=video_id,
        clip_start_seconds=body.start_seconds,
        clip_end_seconds=body.end_seconds,
        created_via="clip",
    )

    # Enqueue clip job
    job = create_clip_job(
        video_id=new_video.id,
        source_video_id=video_id,
        source_s3_key=video.source_s3_key,
        start_seconds=body.start_seconds,
        end_seconds=body.end_seconds,
        owner_user_id=user_sub,
    )

    return {
        "video_id": new_video.id,
        "title": title,
        "status": "created",
        "source_video_id": video_id,
        "clip_start_seconds": body.start_seconds,
        "clip_end_seconds": body.end_seconds,
        "created_via": "clip",
        "clip_job_id": job["job_id"],
    }
```

### 3.5 Clip Job Processing

#### 3.5.1 Job Creation

The clip job is created via `create_job()` from `transcode_job_store.py` with additional clip-specific fields:

```python
def create_clip_job(
    *,
    video_id: str,
    source_video_id: str,
    source_s3_key: str,
    start_seconds: float,
    end_seconds: float,
    owner_user_id: str,
) -> Dict[str, Any]:
    """Create a clip extraction job in the transcode job queue."""
    job_id = f"tj_{uuid4().hex}"
    ts = now_ts()

    item = {
        "job_id": job_id,
        "video_id": video_id,
        "tenant_id": owner_user_id,
        "status": "queued",
        "status_created_at": f"queued#{ts}",
        "created_at": ts,
        "updated_at": ts,
        "attempt": 0,
        "max_attempts": S.transcode_max_attempts,
        "priority": 0,
        "job_type": "clip",
        "source_uri": source_s3_key,
        "clip_source_video_id": source_video_id,
        "clip_start_seconds": Decimal(str(start_seconds)),
        "clip_end_seconds": Decimal(str(end_seconds)),
        "progress_pct": 0,
        "renditions_completed": [],
        "renditions": [],
    }

    T.transcode_jobs.put_item(Item=item)
    return item
```

#### 3.5.2 Clip Extraction Logic

```python
async def execute_clip(
    *,
    source_path: Path,
    output_path: Path,
    start_seconds: float,
    end_seconds: float,
    timeout_seconds: int = 300,
) -> ClipResult:
    """Extract a clip from source using stream copy, falling back to re-encode.

    Returns:
        ClipResult with output path, duration, and method used ("copy" or "reencode")
    """
    expected_duration = end_seconds - start_seconds

    # Phase 1: Try stream copy
    copy_result = await _run_clip_ffmpeg(
        source_path=source_path,
        output_path=output_path,
        start_seconds=start_seconds,
        end_seconds=end_seconds,
        stream_copy=True,
        timeout_seconds=timeout_seconds,
    )

    if copy_result.success:
        actual_duration = await _probe_duration(output_path)
        if actual_duration is not None and abs(actual_duration - expected_duration) <= 2.0:
            return ClipResult(
                output_path=output_path,
                duration_seconds=actual_duration,
                method="copy",
            )
        else:
            logger.info(
                "Stream copy duration mismatch (expected=%.1f, actual=%.1f), retrying with re-encode",
                expected_duration,
                actual_duration or 0,
            )

    # Phase 2: Re-encode fallback
    reencode_result = await _run_clip_ffmpeg(
        source_path=source_path,
        output_path=output_path,
        start_seconds=start_seconds,
        end_seconds=end_seconds,
        stream_copy=False,
        timeout_seconds=timeout_seconds,
    )

    if not reencode_result.success:
        raise ClipExtractionError(
            f"Clip extraction failed: {reencode_result.stderr_tail[:200]}"
        )

    actual_duration = await _probe_duration(output_path)
    return ClipResult(
        output_path=output_path,
        duration_seconds=actual_duration or expected_duration,
        method="reencode",
    )
```

#### 3.5.3 FFmpeg Commands

**Stream copy attempt**:
```bash
ffmpeg -hide_banner -loglevel warning -y \
  -ss {start_seconds} -to {end_seconds} \
  -i /tmp/scratch/{job_id}/source.mp4 \
  -c copy \
  -avoid_negative_ts make_zero \
  -movflags +faststart \
  /tmp/scratch/{job_id}/clip.mp4
```

**Re-encode fallback**:
```bash
ffmpeg -hide_banner -loglevel warning -y \
  -ss {start_seconds} -to {end_seconds} \
  -i /tmp/scratch/{job_id}/source.mp4 \
  -c:v libx264 -preset medium -crf 22 \
  -c:a aac -b:a 128k \
  -movflags +faststart \
  /tmp/scratch/{job_id}/clip.mp4
```

Note: `-ss` is placed before `-i` for input seeking (fast seek to nearest keyframe, then decode forward). For stream copy this is the standard approach. For re-encode, placing `-ss` before `-i` is still preferred for performance -- ffmpeg seeks to the nearest keyframe before the start time and decodes forward to the exact frame.

#### 3.5.4 Post-Clip Pipeline

After the clip MP4 is extracted:

1. **Upload clip to S3** as a new source file at `videos/{user_sub}/{new_video_id}/clip.mp4`.
2. **Update video metadata**: Set `source_s3_key` to the uploaded clip's S3 key, transition status to `"pending_encoding"`.
3. **Create a standard transcode job**: Enqueue a regular transcode job (job_type `"transcode"`) referencing the clip file. This produces HLS renditions, thumbnails, etc., through the existing ABR pipeline.
4. **Clip job completion**: Mark the clip job as completed once the clip MP4 is uploaded and the transcode job is enqueued.

This two-stage approach (clip extraction -> standard transcode) reuses the entire existing pipeline without modification. The clip extraction is fast (seconds for stream copy), and the subsequent transcode runs normally.

#### 3.5.5 Duration Validation

After the clip MP4 is produced, `ffprobe` checks the output duration:

```python
async def _probe_duration(path: Path) -> Optional[float]:
    """Get duration of a media file via ffprobe."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ffprobe", "-v", "quiet",
            "-print_format", "json",
            "-show_format", str(path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        data = json.loads(stdout)
        return float(data["format"]["duration"])
    except Exception:
        return None
```

### 3.6 S3 Path Convention

The clipped source file is stored alongside other uploads:

```
s3://{local-uploads}/videos/{user_sub}/{new_video_id}/clip.mp4
```

After the clip goes through the ABR pipeline, HLS outputs land at:

```
s3://{vod-output}/{prefix}/{tenant_id}/assets/{new_video_id}/
  hls/
    master.m3u8
    1080p/index.m3u8
    ...
  thumbnails/
    poster_0s.jpg
    ...
```

### 3.7 Scratch Directory Management

```python
scratch_dir = Path(S.transcode_scratch_dir) / f"clip-{job_id}"
scratch_dir.mkdir(parents=True, exist_ok=True)

source_path = scratch_dir / f"source{ext}"
clip_path = scratch_dir / "clip.mp4"

try:
    # Download source, extract clip, upload result
    ...
finally:
    # Clean up scratch directory
    shutil.rmtree(scratch_dir, ignore_errors=True)
```

### 3.8 Settings

**File: `app/core/settings.py`** -- New settings:

```python
# Video Clipping (VOD-015)
video_clip_enabled: bool = os.environ.get("VIDEO_CLIP_ENABLED", "1") not in ("0", "false", "False")
video_clip_min_duration_seconds: int = int(os.environ.get("VIDEO_CLIP_MIN_DURATION_SECONDS", "5"))
video_clip_max_duration_seconds: int = int(os.environ.get("VIDEO_CLIP_MAX_DURATION_SECONDS", "14400"))  # 4 hours
video_clip_copy_tolerance_seconds: float = float(os.environ.get("VIDEO_CLIP_COPY_TOLERANCE_SECONDS", "2.0"))
video_clip_timeout_seconds: int = int(os.environ.get("VIDEO_CLIP_TIMEOUT_SECONDS", "600"))
```

### 3.9 Frontend: Clip Dialog

#### 3.9.1 Clip Button

On `VideoPlayerPage.tsx`, the owner sees a "Clip" button next to existing action buttons:

```tsx
{isOwner && video.status === "published" && (
  <Button
    variant="outline"
    onClick={() => setClipDialogOpen(true)}
    className="gap-2"
  >
    <Scissors className="h-4 w-4" />
    Clip
  </Button>
)}
```

#### 3.9.2 ClipDialog Component

```tsx
// frontend/src/components/shared/ClipDialog.tsx

interface ClipDialogProps {
  videoId: string;
  durationSeconds: number;
  title: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function ClipDialog({ videoId, durationSeconds, title, open, onOpenChange }: ClipDialogProps) {
  const [startSeconds, setStartSeconds] = useState(0);
  const [endSeconds, setEndSeconds] = useState(Math.min(durationSeconds, 60));
  const [clipTitle, setClipTitle] = useState(`${title} (clip)`);

  const clipMutation = useMutation({
    mutationFn: (body: { start_seconds: number; end_seconds: number; title: string }) =>
      apiClient.post(`/ui/videos/${videoId}/clip`, body),
    onSuccess: (data) => {
      toast.success("Clip job started");
      onOpenChange(false);
      navigate(`/videos/${data.data.video_id}`);
    },
  });

  const clipDuration = endSeconds - startSeconds;
  const isValid = clipDuration >= 5 && endSeconds <= durationSeconds && startSeconds < endSeconds;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Create Clip</DialogTitle>
          <DialogDescription>
            Select a time range to extract from this video.
          </DialogDescription>
        </DialogHeader>

        {/* Timeline scrubber with dual handles */}
        <div className="space-y-4">
          <DualRangeSlider
            min={0}
            max={durationSeconds}
            value={[startSeconds, endSeconds]}
            onValueChange={([s, e]) => { setStartSeconds(s); setEndSeconds(e); }}
            step={0.1}
          />
          <div className="flex justify-between text-sm text-muted-foreground">
            <span>Start: {formatTimestamp(startSeconds)}</span>
            <span>Duration: {formatTimestamp(clipDuration)}</span>
            <span>End: {formatTimestamp(endSeconds)}</span>
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="clip-title">Title</Label>
          <Input
            id="clip-title"
            value={clipTitle}
            onChange={(e) => setClipTitle(e.target.value)}
            maxLength={256}
          />
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            onClick={() => clipMutation.mutate({
              start_seconds: startSeconds,
              end_seconds: endSeconds,
              title: clipTitle,
            })}
            disabled={!isValid || clipMutation.isPending}
            className="gap-2"
          >
            {clipMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Scissors className="h-4 w-4" />
            )}
            Create Clip
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

#### 3.9.3 Frontend API

**File: `frontend/src/api/endpoints/videos.ts`**:

```typescript
export interface ClipVideoRequest {
  start_seconds: number;
  end_seconds: number;
  title?: string;
}

export interface ClipVideoResponse {
  video_id: string;
  title: string;
  status: string;
  source_video_id: string;
  clip_start_seconds: number;
  clip_end_seconds: number;
  created_via: string;
  clip_job_id: string;
}

export function clipVideo(videoId: string, body: ClipVideoRequest): Promise<ClipVideoResponse> {
  return apiClient.post(`/ui/videos/${videoId}/clip`, body).then((r) => r.data);
}
```

### 3.10 Dependency Graph

```
VOD-001 (metadata model) ─────────┐
VOD-003 (transcode job queue) ────┤
VOD-004 (FFmpeg execution) ───────┤
VOD-005 (S3 upload outputs) ──────┤
VOD-006 (listing API) ────────────┤
                                   v
                        VOD-015 (this ticket)
                                   │
                                   v
                        VOD-008 (player page update)
```

VOD-015 depends on the existing transcode pipeline (VOD-001 through VOD-005) for the post-clip ABR processing. The ffmpeg executor (VOD-004) provides the subprocess wrapper used for clip extraction. The video listing API (VOD-006) provides the video detail endpoint extended with clip provenance fields.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/video_clipper.py` | Clip extraction logic: stream copy attempt, re-encode fallback, duration validation, S3 upload of clip, transcode job enqueue |
| `frontend/src/components/shared/ClipDialog.tsx` | Clip dialog component with timeline scrubber, start/end handles, title field |
| `tests/test_video_clipper.py` | Unit tests for clip extraction service |
| `frontend/e2e/video-clipping.spec.ts` | E2E tests for clip API and processing |

### 4.2 Files to Modify

| File | Change |
|------|--------|
| `app/models_video.py` | Add `source_video_id`, `clip_start_seconds`, `clip_end_seconds`, `created_via` to `VideoMetadataModel`; add `ClipVideoIn` model; add clip fields to `VideoOut` |
| `app/services/video_metadata_store.py` | Serialize/deserialize clip provenance fields in `video_to_item` / `video_from_item`; add `update_clip_fields()` helper |
| `app/services/transcode_job_store.py` | Add `job_type` field (does not exist today); clip jobs carry `clip_start_seconds`, `clip_end_seconds`, `clip_source_video_id` |
| `app/routers/video_listing.py` | Add `POST /{video_id}/clip` endpoint; include clip provenance fields in video detail response |
| `app/core/settings.py` | Add `video_clip_enabled`, `video_clip_min_duration_seconds`, `video_clip_max_duration_seconds`, `video_clip_copy_tolerance_seconds`, `video_clip_timeout_seconds` |
| `.env.local.example` | Add `VIDEO_CLIP_*` environment variables |
| `frontend/src/api/endpoints/videos.ts` | Add `clipVideo()` function; add `ClipVideoRequest`, `ClipVideoResponse` interfaces; add clip provenance fields to `VideoDetail` |
| `frontend/src/pages/videos/VideoPlayerPage.tsx` | Add "Clip" button (owner-only, published videos); wire ClipDialog |

### 4.3 Step-by-Step Implementation Order

**Step 1: Data model + settings** (no behavior change)
1. Add `source_video_id`, `clip_start_seconds`, `clip_end_seconds`, `created_via` to `VideoMetadataModel`.
2. Add `ClipVideoIn` request model.
3. Update `video_to_item` / `video_from_item` for new fields.
4. Add settings to `app/core/settings.py`.
5. Add env vars to `.env.local.example`.

**Step 2: Clip extraction service**
1. Create `app/services/video_clipper.py` with:
   - `execute_clip(source_path, output_path, start_seconds, end_seconds)` -- Two-phase clip extraction.
   - `_run_clip_ffmpeg(source_path, output_path, start_seconds, end_seconds, stream_copy)` -- FFmpeg subprocess call via `execute_rendition()`.
   - `_probe_duration(path)` -- Duration check on output file.
   - `process_clip_job(job)` -- End-to-end job processor: download source, extract clip, upload to S3, enqueue transcode.

**Step 3: API endpoint**
1. Add `POST /ui/videos/{video_id}/clip` to `app/routers/video_listing.py`.
2. Validate range, permissions, video status.
3. Create new video metadata record with clip provenance.
4. Enqueue clip job.

**Step 4: Job processing integration**
1. The existing transcode worker has no `job_type` dispatch -- it processes all jobs the same way. The worker must be extended to check the `job_type` field and dispatch `"clip"` jobs to `process_clip_job` instead of the standard transcode path.
2. After clip extraction + upload, create a follow-up standard transcode job for ABR processing.

**Step 5: Frontend**
1. Create `ClipDialog.tsx` component.
2. Add `clipVideo()` to `frontend/src/api/endpoints/videos.ts`.
3. Add "Clip" button to `VideoPlayerPage.tsx`.
4. Add clip provenance display to video detail view.

---

## 5. Testing Strategy

### 5.1 Unit Tests: Clip Extraction (`tests/test_video_clipper.py`)

| Test | What It Validates |
|------|-------------------|
| `test_clip_stream_copy_builds_correct_args` | FFmpeg args include `-ss`, `-to`, `-c copy`, `-avoid_negative_ts make_zero`, `-movflags +faststart`. |
| `test_clip_reencode_builds_correct_args` | Fallback args include `-c:v libx264 -preset medium -crf 22 -c:a aac -b:a 128k`. |
| `test_clip_stream_copy_succeeds_within_tolerance` | Output duration within 2s of expected -> returns method="copy". |
| `test_clip_stream_copy_exceeds_tolerance_triggers_reencode` | Output duration off by >2s -> falls back to re-encode. |
| `test_clip_stream_copy_fails_triggers_reencode` | FFmpeg exit code non-zero on copy -> falls back to re-encode. |
| `test_clip_both_methods_fail_raises` | Both stream copy and re-encode fail -> raises `ClipExtractionError`. |
| `test_clip_uploads_to_correct_s3_path` | Clip MP4 uploaded to `videos/{user_sub}/{new_video_id}/clip.mp4`. |
| `test_clip_enqueues_transcode_job` | After clip upload, a standard transcode job is created for the new video ID. |
| `test_clip_scratch_dir_cleaned_on_success` | Scratch directory removed after successful extraction. |
| `test_clip_scratch_dir_cleaned_on_failure` | Scratch directory removed even when extraction fails. |

### 5.2 Unit Tests: Clip Endpoint (`tests/test_video_clip_endpoint.py`)

| Test | What It Validates |
|------|-------------------|
| `test_clip_valid_range_201` | POST with valid range -> 201 with new video_id, source_video_id, clip_job_id. |
| `test_clip_start_ge_end_400` | `start_seconds=60, end_seconds=30` -> 400. |
| `test_clip_duration_too_short_400` | Clip < 5 seconds -> 400 "minimum clip length is 5 seconds". |
| `test_clip_end_exceeds_duration_400` | `end_seconds > video.duration_seconds` -> 400. |
| `test_clip_not_owner_403` | Non-owner tries to clip -> 403. |
| `test_clip_unpublished_video_409` | Video in "encoding" status -> 409. |
| `test_clip_no_source_key_409` | Video with no `source_s3_key` -> 409 "source file not available". |
| `test_clip_default_title_appends_clip` | No title in body -> title defaults to "{original title} (clip)". |
| `test_clip_custom_title` | Custom title in body -> used as-is. |
| `test_clip_inherits_visibility` | New video inherits source video's visibility. |
| `test_clip_video_not_found_404` | Non-existent video_id -> 404. |

### 5.3 E2E Tests: `frontend/e2e/video-clipping.spec.ts`

**Section 127: Video clipping API** (5 tests)

```typescript
test("127.1 Creator clips a published video with valid range", async ({ page }) => {
  // POST /ui/videos/{id}/clip with start=10, end=40
  // Expect 201 with new video_id, source_video_id, created_via="clip"
});

test("127.2 Clip with start >= end returns 400", async ({ page }) => {
  // POST with start=60, end=30
  // Expect 400 "start_seconds must be less than end_seconds"
});

test("127.3 Clip shorter than 5 seconds returns 400", async ({ page }) => {
  // POST with start=10, end=13
  // Expect 400 "minimum clip length is 5 seconds"
});

test("127.4 Clip end exceeding duration returns 400", async ({ page }) => {
  // POST with end > video duration
  // Expect 400 "end_seconds exceeds video duration"
});

test("127.5 Non-owner cannot clip another user's video", async ({ page }) => {
  // Bob tries to clip Alice's video
  // Expect 403
});
```

**Section 128: Clip job processing** (3 tests)

```typescript
test("128.1 Clip job transitions from queued to completed", async ({ page }) => {
  // Create clip, poll job status until completed or timeout
  // Verify job has job_type="clip"
});

test("128.2 Clipped video has correct provenance fields", async ({ page }) => {
  // After clip job completes, GET the new video detail
  // Verify source_video_id, clip_start_seconds, clip_end_seconds, created_via="clip"
});

test("128.3 Clip default title is original title with (clip) suffix", async ({ page }) => {
  // Create clip without specifying title
  // Verify new video title ends with "(clip)"
});
```

### 5.4 Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Clip at very start of video (start=0) | Works normally; `-ss 0` is valid. |
| Clip at very end of video (end=duration) | Works; `-to {duration}` clips to the end. |
| Clip of entire video (start=0, end=duration) | Allowed if duration >= 5s; effectively a re-mux/re-encode of the full source. |
| Source file deleted from S3 | Clip job fails with "source_not_found"; job status="failed". |
| Source is non-MP4 (MKV, MOV, WebM) | Stream copy attempt may fail due to container incompatibility; re-encode fallback handles all formats. |
| Clip of a video that is itself a clip | Allowed; `source_video_id` points to the immediate parent (not the original root). `created_via="clip"` on both. |
| Very long video (4+ hours) | Clip extraction is fast (stream copy); subsequent ABR transcode time scales with clip length, not source length. |
| Concurrent clip requests for same video | Each produces an independent new video; no conflict since the source is read-only. |
| FFmpeg binary not available | `get_ffmpeg_path()` raises; job fails with "FFmpeg not available". |
| Disk space exhausted | Pre-flight check via `_check_disk_space()`; job fails with retryable "disk_full" error. |

### 5.5 Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Stream copy is almost instant | Expected: <5 seconds for any clip length. No decode/encode step. |
| Re-encode fallback scales with clip duration | 1 minute of clip ~ 5-15 seconds of encode time. Acceptable for the rare fallback case. |
| Source file download from S3 | Download speed depends on source size and network. Large sources (multi-GB) may take minutes. Could be optimized with byte-range requests in the future but not needed for Phase 1. |
| Scratch disk for source + clip | Two files on disk: source (potentially large) + clip (smaller). Pre-flight disk check. Cleaned up in `finally` block. |
| Clip job does not block request | POST returns immediately with 201. Job runs asynchronously. |
| Post-clip ABR transcode | Standard transcode time applies to the clip (not the full source). A 60-second clip transcodes much faster than a 2-hour source. |

---

## Appendix A: Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `VIDEO_CLIP_ENABLED` | `true` | Master kill switch for clipping functionality |
| `VIDEO_CLIP_MIN_DURATION_SECONDS` | `5` | Minimum allowed clip duration |
| `VIDEO_CLIP_MAX_DURATION_SECONDS` | `14400` (4 hours) | Maximum allowed clip duration |
| `VIDEO_CLIP_COPY_TOLERANCE_SECONDS` | `2.0` | Duration deviation threshold before re-encode fallback |
| `VIDEO_CLIP_TIMEOUT_SECONDS` | `600` | FFmpeg process timeout for clip extraction |

---

## Appendix B: File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/models_video.py` | Modify | Add `source_video_id`, `clip_start_seconds`, `clip_end_seconds`, `created_via` to `VideoMetadataModel`; add `ClipVideoIn` model |
| `app/services/video_metadata_store.py` | Modify | Serialize/deserialize clip provenance fields; add `update_clip_fields()` |
| `app/services/transcode_job_store.py` | Modify | Add `job_type` field (does not exist today) and clip-specific metadata on jobs |
| `app/services/video_clipper.py` | **New** | Clip extraction: stream copy + re-encode fallback, duration validation, S3 upload, transcode enqueue |
| `app/routers/video_listing.py` | Modify | Add `POST /{video_id}/clip` endpoint |
| `app/core/settings.py` | Modify | Add 5 clip-related settings |
| `.env.local.example` | Modify | Add `VIDEO_CLIP_*` env vars |
| `frontend/src/api/endpoints/videos.ts` | Modify | Add `clipVideo()` function and clip-related interfaces |
| `frontend/src/components/shared/ClipDialog.tsx` | **New** | Clip dialog with timeline scrubber, dual handles, title input |
| `frontend/src/pages/videos/VideoPlayerPage.tsx` | Modify | Add "Clip" button for owners; wire ClipDialog |
| `tests/test_video_clipper.py` | **New** | 10 unit tests for clip extraction |
| `tests/test_video_clip_endpoint.py` | **New** | 11 unit tests for clip endpoint |
| `frontend/e2e/video-clipping.spec.ts` | **New** | 8 E2E tests across 2 sections (127-128) |

---

## Appendix C: API Endpoint Summary

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/videos/{video_id}/clip` | `require_ui_session` | Create a clipped version of an existing video |
| GET | `/ui/videos/{video_id}` | `require_ui_session` | (Existing) Extended: response includes clip provenance fields |

---

## Appendix D: State Flow for Clip Processing

```
POST /ui/videos/{video_id}/clip
         │
         v
┌─────────────────┐
│ Create new video │ (status="created", created_via="clip")
│  metadata record │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Enqueue clip job │ (job_type="clip", status="queued")
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Worker claims    │ (job status="running")
│  clip job        │
└────────┬────────┘
         │
         v
┌─────────────────┐      ┌──────────────────┐
│ Download source  │─────>│ Try stream copy   │
│  from S3         │      │  (-c copy)        │
└─────────────────┘      └────────┬─────────┘
                                  │
                         success  │  duration mismatch
                         (<=2s)   │  (>2s) or failure
                                  │
                    ┌─────────────┼─────────────┐
                    v                             v
             ┌────────────┐              ┌───────────────┐
             │ Use output  │              │ Re-encode     │
             │ as-is       │              │ (-c:v libx264)│
             └──────┬─────┘              └──────┬────────┘
                    │                            │
                    └────────────┬───────────────┘
                                 v
                    ┌────────────────────┐
                    │ Upload clip to S3   │
                    │ as new source file  │
                    └────────┬───────────┘
                             │
                             v
                    ┌────────────────────┐
                    │ Enqueue standard    │
                    │ transcode job       │ (job_type="transcode")
                    └────────┬───────────┘
                             │
                             v
                    ┌────────────────────┐
                    │ ABR pipeline:       │
                    │ HLS renditions +    │
                    │ thumbnails          │
                    └────────┬───────────┘
                             │
                             v
                    ┌────────────────────┐
                    │ Video status =      │
                    │ "published"         │
                    └────────────────────┘
```

---

## 6. Detailed Sequence Diagrams

### 6.1 Full Clip Flow: User Click to Final Playback

```
 Browser (Creator)          Backend (FastAPI)         DynamoDB           S3 (moto)          Worker Process
 ──────────────────         ─────────────────         ────────           ─────────           ──────────────
        │                          │                      │                  │                     │
        │  POST /ui/videos/        │                      │                  │                     │
        │    /{video_id}/clip      │                      │                  │                     │
        │  {start: 30, end: 90}    │                      │                  │                     │
        │─────────────────────────>│                      │                  │                     │
        │                          │                      │                  │                     │
        │                          │  GetItem(video_id)   │                  │                     │
        │                          │─────────────────────>│                  │                     │
        │                          │  video record        │                  │                     │
        │                          │<─────────────────────│                  │                     │
        │                          │                      │                  │                     │
        │                          │  Validate:           │                  │                     │
        │                          │  - owner match       │                  │                     │
        │                          │  - status=published  │                  │                     │
        │                          │  - range valid       │                  │                     │
        │                          │  - duration check    │                  │                     │
        │                          │                      │                  │                     │
        │                          │  PutItem(new video   │                  │                     │
        │                          │    metadata, status= │                  │                     │
        │                          │    "created",        │                  │                     │
        │                          │    created_via="clip")│                 │                     │
        │                          │─────────────────────>│                  │                     │
        │                          │  OK                  │                  │                     │
        │                          │<─────────────────────│                  │                     │
        │                          │                      │                  │                     │
        │                          │  PutItem(clip job,   │                  │                     │
        │                          │    job_type="clip",  │                  │                     │
        │                          │    status="queued")  │                  │                     │
        │                          │─────────────────────>│                  │                     │
        │                          │  OK                  │                  │                     │
        │                          │<─────────────────────│                  │                     │
        │                          │                      │                  │                     │
        │  201 {video_id,          │                      │                  │                     │
        │   clip_job_id, ...}      │                      │                  │                     │
        │<─────────────────────────│                      │                  │                     │
        │                          │                      │                  │                     │
        │  Navigate to new         │                      │                  │                     │
        │  video page (polling)    │                      │                  │                     │
        │                          │                      │                  │                     │
        │                          │                      │                  │        ┌────────────┤
        │                          │                      │                  │        │ Poll for   │
        │                          │                      │                  │        │ queued jobs│
        │                          │                      │                  │        │            │
        │                          │                      │  Query(status=   │        │            │
        │                          │                      │  "queued",       │<───────┤            │
        │                          │                      │  job_type="clip")│        │            │
        │                          │                      │  clip job item   │        │            │
        │                          │                      │───────────────>──┼───────>│            │
        │                          │                      │                  │        │            │
        │                          │                      │  UpdateItem(     │        │            │
        │                          │                      │  status="running"│<───────┤            │
        │                          │                      │  )               │        │            │
        │                          │                      │                  │        │            │
        │                          │                      │                  │  GetObject(         │
        │                          │                      │                  │  source_s3_key)     │
        │                          │                      │                  │<───────┤            │
        │                          │                      │                  │  source│bytes       │
        │                          │                      │                  │───────>│            │
        │                          │                      │                  │        │            │
        │                          │                      │                  │        │ Write to   │
        │                          │                      │                  │        │ scratch/   │
        │                          │                      │                  │        │ source.mp4 │
        │                          │                      │                  │        │            │
        │                          │                      │                  │        │ Phase 1:   │
        │                          │                      │                  │        │ ffmpeg     │
        │                          │                      │                  │        │  -ss 30    │
        │                          │                      │                  │        │  -to 90    │
        │                          │                      │                  │        │  -c copy   │
        │                          │                      │                  │        │            │
        │                          │                      │                  │        │ ffprobe    │
        │                          │                      │                  │        │ clip.mp4   │
        │                          │                      │                  │        │ duration=  │
        │                          │                      │                  │        │ 60.02s     │
        │                          │                      │                  │        │ (within 2s │
        │                          │                      │                  │        │ tolerance) │
        │                          │                      │                  │        │            │
        │                          │                      │                  │  PutObject(         │
        │                          │                      │                  │  videos/{sub}/      │
        │                          │                      │                  │  {new_id}/clip.mp4) │
        │                          │                      │                  │<───────┤            │
        │                          │                      │                  │  OK    │            │
        │                          │                      │                  │───────>│            │
        │                          │                      │                  │        │            │
        │                          │                      │  UpdateItem(     │        │            │
        │                          │                      │  video status=   │<───────┤            │
        │                          │                      │  "pending_       │        │            │
        │                          │                      │   encoding",     │        │            │
        │                          │                      │  source_s3_key)  │        │            │
        │                          │                      │                  │        │            │
        │                          │                      │  PutItem(        │        │            │
        │                          │                      │  transcode job,  │<───────┤            │
        │                          │                      │  job_type=       │        │            │
        │                          │                      │  "transcode",    │        │            │
        │                          │                      │  status="queued")│        │            │
        │                          │                      │                  │        │            │
        │                          │                      │  UpdateItem(     │        │            │
        │                          │                      │  clip job status │<───────┤            │
        │                          │                      │  ="completed")   │        │            │
        │                          │                      │                  │        │            │
        │                          │                      │                  │  rmtree(scratch/)   │
        │                          │                      │                  │        └────────────┤
        │                          │                      │                  │                     │
        │                          │                      │                  │        ┌────────────┤
        │                          │                      │                  │        │ Worker     │
        │                          │                      │                  │        │ claims     │
        │                          │                      │                  │        │ transcode  │
        │                          │                      │                  │        │ job        │
        │                          │                      │                  │        │            │
        │                          │                      │                  │        │ ABR pipe:  │
        │                          │                      │                  │        │ - 1080p    │
        │                          │                      │                  │        │ - 720p     │
        │                          │                      │                  │        │ - 480p     │
        │                          │                      │                  │        │ HLS m3u8   │
        │                          │                      │                  │        │ Thumbnails │
        │                          │                      │                  │        │            │
        │                          │                      │                  │  PutObject(         │
        │                          │                      │                  │  hls/master.m3u8)   │
        │                          │                      │                  │<───────┤            │
        │                          │                      │                  │  PutObject(         │
        │                          │                      │                  │  thumbnails/*)      │
        │                          │                      │                  │<───────┤            │
        │                          │                      │                  │        │            │
        │                          │                      │  UpdateItem(     │        │            │
        │                          │                      │  video status=   │<───────┤            │
        │                          │                      │  "published")    │        │            │
        │                          │                      │                  │        └────────────┘
        │                          │                      │                  │
        │  GET /ui/videos/{new_id} │                      │                  │
        │─────────────────────────>│  GetItem(new_id)     │                  │
        │                          │─────────────────────>│                  │
        │                          │  video(status=       │                  │
        │                          │  "published")        │                  │
        │                          │<─────────────────────│                  │
        │  200 {video detail,      │                      │                  │
        │   hls_url, thumbnails}   │                      │                  │
        │<─────────────────────────│                      │                  │
        │                          │                      │                  │
        │  Load HLS player         │                      │                  │
        │  GET master.m3u8         │                      │                  │
        │──────────────────────────┼──────────────────────┼─────────────────>│
        │  m3u8 content            │                      │                  │
        │<─────────────────────────┼──────────────────────┼──────────────────│
        │                          │                      │                  │
        │  Playback begins         │                      │                  │
        │                          │                      │                  │
```

### 6.2 Re-Encode Fallback Path

```
 Worker Process
 ──────────────
      │
      │  ffmpeg -c copy -ss 30 -to 90 ...
      │  -> clip.mp4 produced
      │
      │  ffprobe clip.mp4
      │  -> actual_duration = 67.4s
      │  -> expected_duration = 60.0s
      │  -> deviation = 7.4s > 2.0s tolerance
      │
      │  LOG: "Stream copy duration mismatch
      │        (expected=60.0, actual=67.4),
      │        retrying with re-encode"
      │
      │  ffmpeg -c:v libx264 -preset medium
      │         -crf 22 -c:a aac -b:a 128k
      │         -ss 30 -to 90 ...
      │  -> clip.mp4 overwritten
      │
      │  ffprobe clip.mp4
      │  -> actual_duration = 60.01s
      │  -> deviation = 0.01s <= 2.0s
      │
      │  Upload clip.mp4 to S3
      │  Enqueue standard transcode job
      │  Mark clip job as completed (method="reencode")
      │
```

### 6.3 Error Path: Source Deleted Mid-Clip

```
 Worker Process                            S3 (moto)
 ──────────────                            ─────────
      │                                        │
      │  GetObject(source_s3_key)              │
      │───────────────────────────────────────>│
      │  404 NoSuchKey                         │
      │<───────────────────────────────────────│
      │                                        │
      │  LOG: "Source file not found in S3:    │
      │        videos/{sub}/{id}/source.mp4"   │
      │                                        │
      │  UpdateItem(clip job status="failed",  │
      │   error_code="source_not_found",       │
      │   error_message="Source video file     │
      │   has been deleted from storage")      │
      │                                        │
      │  Clean up scratch directory            │
      │                                        │
```

---

## 7. Error Handling Matrix

### 7.1 Request-Time Errors (returned synchronously by POST /ui/videos/{video_id}/clip)

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------------|-------------|------------|---------------------|-----------------|
| 1 | `start_seconds >= end_seconds` | 400 | `invalid_range` | "start_seconds must be less than end_seconds" | Fix start/end values in the clip dialog |
| 2 | Clip duration < 5 seconds | 400 | `clip_too_short` | "minimum clip length is 5 seconds" | Extend the time range to at least 5 seconds |
| 3 | `end_seconds > video.duration_seconds` | 400 | `range_exceeds_duration` | "end_seconds exceeds video duration" | Reduce end time to within video duration |
| 4 | `start_seconds < 0` | 422 | `validation_error` | "start_seconds must be >= 0" | Set start to 0 or positive value |
| 5 | Title exceeds 256 characters | 422 | `validation_error` | "title must be at most 256 characters" | Shorten the clip title |
| 6 | Empty title (length < 1 when provided) | 422 | `validation_error` | "title must be at least 1 character" | Provide a non-empty title or omit the field |
| 7 | Video not found | 404 | `not_found` | "video not found" | Verify the video ID; the video may have been deleted |
| 8 | Not the video owner | 403 | `forbidden` | "forbidden" | Only the video owner can create clips |
| 9 | Video not in published/approved status | 409 | `invalid_status` | "video must be published or approved" | Wait for the video to finish transcoding before clipping |
| 10 | No source S3 key on video | 409 | `source_unavailable` | "source file not available" | The original upload file is missing; re-upload the video |
| 11 | Video duration unknown (no probe data) | 409 | `duration_unknown` | "video duration unknown" | Wait for the probe step to complete; check for probe errors |
| 12 | Feature flag disabled (`VIDEO_CLIP_ENABLED=false`) | 403 | `feature_disabled` | "video clipping is not enabled" | Contact platform admin to enable clipping |
| 13 | Clip duration exceeds `VIDEO_CLIP_MAX_DURATION_SECONDS` | 400 | `clip_too_long` | "clip duration exceeds maximum of {max} seconds" | Reduce the clip time range |
| 14 | Concurrent clip limit exceeded (user) | 429 | `clip_limit_exceeded` | "too many clip jobs in progress; please wait for current clips to finish" | Wait for existing clip jobs to complete before starting new ones |

### 7.2 Asynchronous Errors (during clip job processing by the worker)

| # | Error Scenario | Job Status | Error Code | Error Detail (stored on job) | Recovery Action |
|---|----------------|------------|------------|------------------------------|-----------------|
| 15 | Source video file deleted from S3 | `failed` | `source_not_found` | "Source video file has been deleted from storage" | Re-upload the source video; create a new clip |
| 16 | S3 GetObject access denied | `failed` | `source_access_denied` | "Permission denied reading source file" | Check S3 bucket policy and IAM permissions |
| 17 | S3 GetObject network timeout | `failed` (retryable) | `source_download_timeout` | "Timed out downloading source file from S3" | Job will be retried up to `max_attempts`; check network |
| 18 | S3 PutObject upload failure | `failed` (retryable) | `upload_failed` | "Failed to upload clip file to S3" | Job will be retried; check S3 availability |
| 19 | FFmpeg stream copy crash (non-zero exit) | N/A (fallback) | N/A | Logged; falls through to re-encode | Transparent to user; re-encode handles it |
| 20 | FFmpeg re-encode crash (non-zero exit) | `failed` | `ffmpeg_crash` | "FFmpeg process exited with code {N}: {stderr_tail}" | Inspect ffmpeg logs; source may be corrupt |
| 21 | FFmpeg process timeout (> `VIDEO_CLIP_TIMEOUT_SECONDS`) | `failed` | `ffmpeg_timeout` | "FFmpeg process timed out after {N} seconds" | Increase timeout via `VIDEO_CLIP_TIMEOUT_SECONDS`; check source file integrity |
| 22 | FFmpeg killed by OOM killer | `failed` | `ffmpeg_oom` | "FFmpeg process killed (OOM)" | Reduce concurrent jobs; increase instance memory |
| 23 | Disk space exhausted before ffmpeg starts | `failed` (retryable) | `disk_full` | "Insufficient disk space for clip extraction" | Free disk space or increase volume; job retries automatically |
| 24 | Disk space exhausted during ffmpeg write | `failed` | `ffmpeg_crash` | "FFmpeg write error: No space left on device" | Free disk space; clip job must be manually retried |
| 25 | Output file is 0 bytes | `failed` | `empty_output` | "Clip extraction produced empty output file" | Source may be corrupt or ffmpeg args invalid; inspect logs |
| 26 | Output duration deviates >2s AND re-encode also deviates | `failed` | `duration_mismatch` | "Clip output duration {actual}s does not match expected {expected}s" | Source file may have corrupt timestamps; try re-uploading |
| 27 | Scratch directory creation fails (permissions) | `failed` | `scratch_dir_error` | "Cannot create scratch directory: {error}" | Check filesystem permissions on `transcode_scratch_dir` |
| 28 | DynamoDB update fails (job status transition) | `failed` | `ddb_error` | "Failed to update job status: {error}" | Transient DDB issue; job will be retried |
| 29 | Follow-up transcode job creation fails | `failed` | `transcode_enqueue_failed` | "Clip extracted but failed to enqueue ABR transcode" | Clip MP4 exists in S3; manually create transcode job |
| 30 | FFmpeg binary not found | `failed` | `ffmpeg_not_available` | "FFmpeg binary not found at configured path" | Install ffmpeg or fix `FFMPEG_PATH` configuration |

### 7.3 Error Response Format

All synchronous errors return the standard FastAPI `HTTPException` format:

```json
{
  "detail": "start_seconds must be less than end_seconds"
}
```

Asynchronous errors are stored on the job record:

```json
{
  "job_id": "tj_abc123",
  "status": "failed",
  "error_code": "ffmpeg_crash",
  "error_message": "FFmpeg process exited with code 1: ...",
  "attempt": 2,
  "max_attempts": 3,
  "updated_at": 1748352000
}
```

---

## 8. Security Considerations

### 8.1 Input Validation

#### 8.1.1 Time Range Bounds

All numeric inputs are validated via Pydantic `Field` constraints:

```python
class ClipVideoIn(BaseModel):
    start_seconds: float = Field(ge=0, le=86400)       # Max 24 hours
    end_seconds: float = Field(gt=0, le=86400)          # Max 24 hours
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
```

Additional server-side checks:
- `start_seconds < end_seconds` (prevents zero-length or negative-length clips)
- `end_seconds <= video.duration_seconds` (prevents out-of-range seeks)
- `clip_duration >= VIDEO_CLIP_MIN_DURATION_SECONDS` (prevents trivially short clips)
- `clip_duration <= VIDEO_CLIP_MAX_DURATION_SECONDS` (prevents extremely long clips that exhaust resources)
- `start_seconds` and `end_seconds` are validated as finite floats (no `NaN`, no `Infinity`) by Pydantic

#### 8.1.2 Command Injection Prevention

FFmpeg arguments are constructed programmatically via Python lists, never through shell string interpolation:

```python
# SAFE: Arguments passed as list elements, not shell-interpolated
cmd = [
    ffmpeg_path,
    "-hide_banner", "-loglevel", "warning", "-y",
    "-ss", str(start_seconds),
    "-to", str(end_seconds),
    "-i", str(source_path),
    "-c", "copy",
    "-avoid_negative_ts", "make_zero",
    "-movflags", "+faststart",
    str(output_path),
]
proc = await asyncio.create_subprocess_exec(*cmd, ...)

# UNSAFE (never done): Shell interpolation with user input
# os.system(f"ffmpeg -ss {start_seconds} -to {end_seconds} ...")  # DO NOT DO THIS
```

Key protections:
- `asyncio.create_subprocess_exec` does NOT invoke a shell -- arguments are passed directly to `execvp`.
- `start_seconds` and `end_seconds` are validated floats, never arbitrary strings.
- `source_path` and `output_path` are constructed from controlled UUIDs and constants, never from user input.
- The `title` field is stored in DynamoDB only; it is never passed to ffmpeg or used in file paths.

#### 8.1.3 Path Traversal Prevention

All file paths are constructed from sanitized components:

```python
# video_id is a UUID hex string (validated pattern: "v_" + 32 hex chars)
# user_sub is from the authenticated session (Cognito sub or session record)
scratch_dir = Path(S.transcode_scratch_dir) / f"clip-{job_id}"
source_path = scratch_dir / f"source{ext}"
clip_path = scratch_dir / "clip.mp4"

# S3 keys use the same sanitized components
s3_key = f"videos/{user_sub}/{new_video_id}/clip.mp4"
```

- No user-supplied strings appear in file paths.
- `ext` is extracted from the existing S3 key using `os.path.splitext`, which cannot produce path separators.
- Scratch directories use job IDs (UUID hex), which contain only `[a-f0-9]`.

#### 8.1.4 Title Sanitization

The `title` field is stored in DynamoDB and rendered in the frontend. Protections:
- Pydantic enforces `min_length=1, max_length=256`.
- The frontend renders titles via React JSX `{video.title}`, which auto-escapes HTML entities (no XSS).
- The title is never used in SQL queries (DynamoDB is NoSQL), ffmpeg commands, or file paths.

### 8.2 Authorization

#### 8.2.1 Ownership Check

Only the video owner can create clips:

```python
if video.owner_user_id != ctx["user_sub"]:
    raise HTTPException(status_code=403, detail="forbidden")
```

- `ctx["user_sub"]` comes from the authenticated session (cookie JWT or Bearer token), verified by `require_ui_session`.
- There is no admin override for clipping. Admins who need to clip a video must use direct backend access or the rootctl CLI.
- The ownership check runs before any side effects (no partial state on auth failure).

#### 8.2.2 Clipped Video Ownership

The clipped video is always owned by the same user who owns the source:
- `create_video()` sets `owner_user_id=user_sub` (the authenticated requester).
- The clipped video inherits the source's visibility but can be independently modified by the owner.

#### 8.2.3 Source Video Access During Job Processing

The worker process accesses S3 using the backend's AWS credentials (service account), not the user's credentials. This is consistent with how standard transcode jobs work. The authorization gate is at the API layer (POST endpoint), not at the S3 layer.

### 8.3 Rate Limiting

#### 8.3.1 Concurrent Clip Limit Per User

To prevent resource exhaustion from excessive clip requests:

```python
MAX_CONCURRENT_CLIPS_PER_USER = 3

def _check_concurrent_clip_limit(user_sub: str) -> None:
    """Raise 429 if user has too many active clip jobs."""
    resp = T.transcode_jobs.query(
        IndexName="ByTenantStatus",
        KeyConditionExpression=Key("tenant_id").eq(user_sub)
            & Key("status_created_at").begins_with("queued#"),
    )
    queued_count = resp.get("Count", 0)

    resp2 = T.transcode_jobs.query(
        IndexName="ByTenantStatus",
        KeyConditionExpression=Key("tenant_id").eq(user_sub)
            & Key("status_created_at").begins_with("running#"),
    )
    running_count = resp2.get("Count", 0)

    active_clips = queued_count + running_count
    if active_clips >= MAX_CONCURRENT_CLIPS_PER_USER:
        raise HTTPException(
            status_code=429,
            detail="too many clip jobs in progress; please wait for current clips to finish",
        )
```

#### 8.3.2 Global Rate Limiting

The existing `require_ui_session` middleware applies per-user rate limits on all authenticated endpoints. No additional global rate limit is needed for clipping beyond the concurrent job cap.

#### 8.3.3 Clip Frequency Throttle

Optional future enhancement: limit clips to N per hour per user via a sliding window counter in DynamoDB. Not implemented in Phase 1 because the concurrent job limit provides sufficient protection.

### 8.4 Resource Exhaustion Prevention

#### 8.4.1 Disk Space Guard

Before starting a clip job, the worker checks available disk space:

```python
import shutil

def _check_disk_space(scratch_dir: Path, required_bytes: int) -> None:
    """Raise if insufficient disk space for clip extraction."""
    usage = shutil.disk_usage(scratch_dir.parent)
    available = usage.free
    if available < required_bytes:
        raise DiskFullError(
            f"Insufficient disk space: {available} bytes available, "
            f"{required_bytes} bytes required"
        )
```

The `required_bytes` estimate is `2 * source_file_size` (source download + clip output). For re-encode fallback, the clip output is typically smaller than the source, so `2x` is a conservative estimate.

#### 8.4.2 FFmpeg Process Timeout

Every ffmpeg invocation has a timeout enforced via `asyncio.wait_for`:

```python
try:
    stdout, stderr = await asyncio.wait_for(
        proc.communicate(),
        timeout=S.video_clip_timeout_seconds,
    )
except asyncio.TimeoutError:
    proc.kill()
    await proc.wait()
    raise ClipTimeoutError(f"FFmpeg timed out after {S.video_clip_timeout_seconds}s")
```

Default timeout is 600 seconds (10 minutes), configurable via `VIDEO_CLIP_TIMEOUT_SECONDS`.

#### 8.4.3 FFmpeg Resource Limits

The existing `_apply_resource_limits` from `ffmpeg_executor.py` is applied to clip processes:
- CPU time limit: `RLIMIT_CPU` set to `timeout_seconds * 2`
- Virtual memory limit: `RLIMIT_AS` set based on available system memory
- Nice priority: 10 (lower priority than web server)

#### 8.4.4 Scratch Directory Cleanup

The `finally` block in `process_clip_job` guarantees scratch cleanup:

```python
try:
    result = await execute_clip(...)
    await upload_to_s3(...)
    await enqueue_transcode(...)
finally:
    shutil.rmtree(scratch_dir, ignore_errors=True)
```

If the worker process crashes (OOM kill, segfault), a periodic cleanup cron removes scratch directories older than 1 hour.

#### 8.4.5 Output File Size Validation

After clip extraction, the output file is checked:
- 0-byte file: Job fails with `empty_output` error.
- File larger than source: Logged as warning (possible for re-encode with different codec settings, but valid).

### 8.5 Data Privacy

- Clip operations do not expose source video content to other users. The S3 download and upload use the backend service account.
- The `source_video_id` provenance field is visible only to the clip owner (same user). The video detail API returns clip provenance only to the owner.
- Clip job records in DynamoDB store `tenant_id` (owner) and are queryable only by the owner or admin roles.

---

## 9. Migration & Rollback Plan

### 9.1 Feature Flag Stages

| Stage | `VIDEO_CLIP_ENABLED` | Who Sees It | Duration |
|-------|---------------------|-------------|----------|
| **Stage 0: Deploy** | `false` | Nobody | Day 0: Deploy code to all instances |
| **Stage 1: Internal testing** | `true` (via per-user override) | Engineering team only | Days 1-3: Manual testing with real videos |
| **Stage 2: Beta rollout** | `true` (for users with `feature_flags.video_clip=true`) | Opted-in beta creators | Days 4-10: Collect feedback, monitor metrics |
| **Stage 3: General availability** | `true` (global) | All creators | Day 11+: Full rollout |

The feature flag check is in the API endpoint:

```python
if not S.video_clip_enabled:
    raise HTTPException(status_code=403, detail="video clipping is not enabled")
```

The frontend checks the flag via a `/ui/features` endpoint response and hides the Clip button when disabled.

### 9.2 Zero-Downtime Deployment

The deployment follows the standard rolling update procedure:

1. **Schema changes are additive**: New fields (`source_video_id`, `clip_start_seconds`, `clip_end_seconds`, `created_via`) are all `Optional` with `default=None`. Existing code ignores them.
2. **New endpoint is gated**: `POST /ui/videos/{video_id}/clip` returns 403 until the feature flag is enabled. No client changes needed until flag is on.
3. **Worker compatibility**: The existing worker has no `job_type` dispatch -- it processes all jobs identically. Old workers that claim a `job_type="clip"` job will attempt to process it as a standard transcode and fail (the clip-specific fields like `clip_start_seconds` are not handled). During rolling deployment, clip jobs claimed by old workers will fail and be retried. New workers check `job_type` and dispatch accordingly.
4. **Frontend bundle**: The Clip button and ClipDialog are lazy-loaded. Old frontend bundles (before cache refresh) simply don't render the button. No breaking change.

Deployment sequence:
```
1. Deploy backend (new code, flag=false)     -- No behavior change
2. Deploy frontend                           -- Clip button hidden (flag=false)
3. Run DDB migration (no-op; fields are Optional) -- No schema change needed
4. Enable flag for internal users             -- Internal testing begins
5. Enable flag globally                       -- GA
```

### 9.3 Handling In-Flight Clip Jobs During Rollback

If a rollback is needed after the feature is enabled:

#### Scenario A: Rollback code but keep data

1. Set `VIDEO_CLIP_ENABLED=false` -- prevents new clips.
2. In-flight clip jobs (status="running") will continue on existing worker instances until they complete or the worker is replaced.
3. Queued clip jobs (status="queued") will remain in DynamoDB. After rollback, no worker will claim them (old code doesn't recognize `job_type="clip"`). They stay queued indefinitely.
4. **Cleanup**: A manual script marks all `job_type="clip"` jobs with `status="queued"` as `status="cancelled"`.

```python
# rollback_clip_jobs.py
import boto3
from boto3.dynamodb.conditions import Attr

table = boto3.resource("dynamodb", endpoint_url="http://localhost:8001").Table("transcode_jobs")
resp = table.scan(
    FilterExpression=Attr("job_type").eq("clip") & Attr("status").eq("queued")
)
for item in resp["Items"]:
    table.update_item(
        Key={"job_id": item["job_id"]},
        UpdateExpression="SET #s = :s, updated_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "cancelled", ":t": int(time.time())},
    )
    print(f"Cancelled clip job {item['job_id']}")
```

#### Scenario B: Rollback code and remove data

1. Disable feature flag.
2. Run cleanup script above for queued jobs.
3. Videos created via clipping (`created_via="clip"`) remain valid -- they are standalone videos with their own S3 files and HLS outputs. They do NOT depend on the source video's continued existence.
4. The `source_video_id`, `clip_start_seconds`, `clip_end_seconds`, `created_via` fields on these videos are harmless -- old code ignores them (they're `Optional` and not referenced by existing queries).
5. **No data deletion needed**: Clip-created videos are fully independent and playable.

### 9.4 DynamoDB Backward Compatibility

| Change | Forward Compatible | Backward Compatible | Notes |
|--------|-------------------|---------------------|-------|
| New fields on video metadata (`source_video_id`, etc.) | Yes: `Optional[str] = None` | Yes: old code ignores unknown fields | DynamoDB is schemaless; no migration |
| `job_type` field on transcode jobs | Yes: new code reads it | Yes: old code doesn't read it (treats all jobs as standard transcode) | `job_type` is a new field that does not exist today; old workers ignore unknown fields and process all jobs the same way |
| `clip_start_seconds` / `clip_end_seconds` on jobs | Yes: used by clip processor | Yes: old code ignores them | No index uses these fields |
| No new tables | N/A | N/A | All data fits in existing `videos` and `transcode_jobs` tables |
| No new GSIs | N/A | N/A | Concurrent clip count uses existing `ByTenantStatus` |

---

## 10. Operational Runbook

### 10.1 Prometheus Metrics

The clip service exposes the following metrics via the existing `app/metrics.py` instrumentation:

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `clip_jobs_total` | Counter | `status` (queued, completed, failed, cancelled) | Total clip jobs by final status |
| `clip_jobs_active` | Gauge | `phase` (downloading, extracting, uploading, enqueueing_transcode) | Currently active clip jobs by processing phase |
| `clip_extraction_duration_seconds` | Histogram | `method` (copy, reencode), `result` (success, fallback, failure) | Time spent in ffmpeg clip extraction (excluding S3 I/O) |
| `clip_source_download_duration_seconds` | Histogram | | Time to download source file from S3 |
| `clip_source_download_bytes` | Histogram | | Size of source file downloaded |
| `clip_output_upload_duration_seconds` | Histogram | | Time to upload clip output to S3 |
| `clip_output_size_bytes` | Histogram | | Size of clip output file |
| `clip_copy_fallback_total` | Counter | `reason` (duration_mismatch, ffmpeg_error) | Stream copy attempts that fell back to re-encode |
| `clip_queue_depth` | Gauge | | Number of clip jobs in `queued` status |
| `clip_queue_wait_seconds` | Histogram | | Time from job creation to worker claim |
| `clip_disk_space_bytes` | Gauge | `path` (scratch directory mount) | Available disk space on the scratch volume |

Implementation example:

```python
from prometheus_client import Counter, Histogram, Gauge

clip_jobs_total = Counter(
    "clip_jobs_total",
    "Total clip jobs by final status",
    ["status"],
)

clip_extraction_duration = Histogram(
    "clip_extraction_duration_seconds",
    "Clip extraction duration",
    ["method", "result"],
    buckets=[1, 2, 5, 10, 30, 60, 120, 300, 600],
)

clip_jobs_active = Gauge(
    "clip_jobs_active",
    "Currently active clip jobs",
    ["phase"],
)

clip_copy_fallback = Counter(
    "clip_copy_fallback_total",
    "Stream copy fallbacks to re-encode",
    ["reason"],
)
```

### 10.2 Alerts

| Alert | Condition | Severity | Response |
|-------|-----------|----------|----------|
| **ClipHighFailureRate** | `rate(clip_jobs_total{status="failed"}[15m]) / rate(clip_jobs_total[15m]) > 0.2` | P2 (Warning) | Check ffmpeg binary availability, S3 connectivity, disk space. Inspect recent failed jobs for common `error_code`. |
| **ClipStuckJobs** | `clip_jobs_active > 0` for any single job lasting `> 20 minutes` | P2 (Warning) | Worker may have hung ffmpeg process. Check worker logs for PID. Kill the stuck ffmpeg process. Job will be retried. |
| **ClipQueueBacklog** | `clip_queue_depth > 50` for `> 10 minutes` | P3 (Info) | Workers may be overloaded. Scale up worker processes or increase concurrent job limit. |
| **ClipDiskSpaceLow** | `clip_disk_space_bytes < 5_000_000_000` (5 GB) | P1 (Critical) | Scratch directory running low. Check for leaked scratch dirs (cleanup cron). Expand volume. Pause new clip jobs via feature flag. |
| **ClipDiskSpaceCritical** | `clip_disk_space_bytes < 1_000_000_000` (1 GB) | P0 (Emergency) | Immediate intervention. Set `VIDEO_CLIP_ENABLED=false`. Manually clean `/tmp/scratch/clip-*`. Expand volume. |
| **ClipQueueWaitHigh** | `histogram_quantile(0.95, clip_queue_wait_seconds) > 300` | P3 (Info) | 95th percentile wait exceeds 5 minutes. Scale workers or increase priority for clip jobs. |
| **ClipCopyFallbackRateHigh** | `rate(clip_copy_fallback_total[1h]) / rate(clip_jobs_total[1h]) > 0.5` | P3 (Info) | Over half of clips require re-encode. Source videos may have infrequent keyframes. Consider adjusting `VIDEO_CLIP_COPY_TOLERANCE_SECONDS` or recommending keyframe settings to creators. |

### 10.3 Debugging Scenarios

#### 10.3.1 Clip Produces 0-Byte Output

**Symptoms**: Job fails with `error_code="empty_output"`. Output file exists but is 0 bytes.

**Investigation steps**:
1. Check the source video:
   ```bash
   aws s3 ls s3://{bucket}/{source_s3_key} --endpoint-url http://localhost:4566
   ```
   If the source is also 0 bytes, the original upload was corrupt.

2. Check ffmpeg stderr in the job record:
   ```python
   job = T.transcode_jobs.get_item(Key={"job_id": "tj_xxx"})["Item"]
   print(job.get("error_message"))
   ```

3. Reproduce locally:
   ```bash
   aws s3 cp s3://{bucket}/{source_s3_key} /tmp/debug_source.mp4 --endpoint-url http://localhost:4566
   ffprobe /tmp/debug_source.mp4
   ffmpeg -ss {start} -to {end} -i /tmp/debug_source.mp4 -c copy /tmp/debug_clip.mp4
   ls -la /tmp/debug_clip.mp4
   ```

4. Common causes:
   - Source file is corrupt or truncated (incomplete upload).
   - Start time is beyond the actual file duration (metadata `duration_seconds` is wrong).
   - Source uses a codec/container that ffmpeg cannot demux without additional libraries.

**Resolution**: If the source is valid, file a bug with the ffmpeg stderr output. If the source is corrupt, notify the creator that the original upload is damaged.

#### 10.3.2 Audio/Video Desync in Clip

**Symptoms**: The clip plays but audio is offset from video by a noticeable amount (typically 0.5-2 seconds).

**Investigation steps**:
1. Check if stream copy was used (look for `method="copy"` in job metadata or logs).
2. Probe the source and clip for audio/video stream start times:
   ```bash
   ffprobe -show_streams -select_streams v:0 /tmp/source.mp4 2>/dev/null | grep start_time
   ffprobe -show_streams -select_streams a:0 /tmp/source.mp4 2>/dev/null | grep start_time
   ffprobe -show_streams -select_streams v:0 /tmp/clip.mp4 2>/dev/null | grep start_time
   ffprobe -show_streams -select_streams a:0 /tmp/clip.mp4 2>/dev/null | grep start_time
   ```
3. If the source has different `start_time` values for audio and video streams, stream copy may preserve this offset incorrectly.

**Resolution**: Force re-encode for this clip by updating the tolerance to 0 (ensuring fallback):
```bash
# One-off manual re-encode with explicit audio sync
ffmpeg -ss {start} -to {end} -i source.mp4 \
  -c:v libx264 -preset medium -crf 22 \
  -c:a aac -b:a 128k \
  -async 1 \
  -movflags +faststart \
  clip_fixed.mp4
```
The `-async 1` flag resamples audio to sync with video timestamps.

#### 10.3.3 Keyframe Misalignment Artifacts

**Symptoms**: First few frames of the clip show green blocks, frozen frames, or corrupted video. Audio plays correctly. Only happens with stream copy method.

**Investigation steps**:
1. Confirm `method="copy"` in job metadata.
2. Check keyframe interval of source:
   ```bash
   ffprobe -show_frames -select_streams v:0 -show_entries frame=key_frame,pts_time \
     source.mp4 2>/dev/null | grep -A1 "key_frame=1" | head -20
   ```
3. If keyframe interval is >5 seconds, stream copy is likely to produce artifacts when the start time does not align with a keyframe.

**Root cause**: Stream copy (`-c copy`) can only cut at keyframes. If `start_seconds=30` but the nearest preceding keyframe is at 25s, the output includes frames 25-30 that cannot be decoded without the preceding keyframe's reference data.

**Resolution**: The automatic fallback should have caught this (duration deviation >2s). If it didn't:
- The source may have closely-spaced keyframes but still produce visual artifacts (duration was within tolerance but the IDR frame was slightly misplaced).
- Adjust `VIDEO_CLIP_COPY_TOLERANCE_SECONDS` to `0.5` for stricter fallback triggering.
- For the specific clip, manually re-encode.

#### 10.3.4 Clip Job Stuck in "Running" State

**Symptoms**: Job has been in `status="running"` for longer than `VIDEO_CLIP_TIMEOUT_SECONDS + 60` seconds.

**Investigation steps**:
1. Check if the worker process is still alive:
   ```bash
   ps aux | grep "clip-{job_id}" | grep -v grep
   ```
2. Check if ffmpeg is running:
   ```bash
   ps aux | grep ffmpeg | grep -v grep
   ```
3. Check worker logs for the job ID:
   ```bash
   grep "tj_xxx" .logs/uvicorn.log | tail -20
   ```

**Resolution**:
- If ffmpeg is running: it may be legitimately slow (very long re-encode). Wait or kill if clearly stuck.
- If ffmpeg is not running but the worker is alive: the worker may be stuck on S3 I/O. Check network connectivity.
- If the worker is dead: the job is orphaned. Manually update the job status:
  ```python
  T.transcode_jobs.update_item(
      Key={"job_id": "tj_xxx"},
      UpdateExpression="SET #s = :s, status_created_at = :sc, updated_at = :t, error_code = :ec, error_message = :em",
      ExpressionAttributeNames={"#s": "status"},
      ExpressionAttributeValues={
          ":s": "failed",
          ":sc": f"failed#{now_ts()}",
          ":t": now_ts(),
          ":ec": "worker_died",
          ":em": "Worker process died while processing clip job",
      },
  )
  ```
  If `attempt < max_attempts`, the job will be retried when a worker next polls.

#### 10.3.5 Source Video Corruption Detected During Clip

**Symptoms**: ffmpeg produces warnings like `Invalid NAL unit size`, `non-existing PPS`, or `decode_slice_header error`.

**Investigation**:
```bash
ffmpeg -v verbose -i source.mp4 -f null - 2>&1 | grep -i "error\|warning\|invalid" | head -20
```

**Resolution**: The source file is partially corrupt. Stream copy will propagate the corruption. Re-encode may work (ffmpeg can often decode past minor corruption). If re-encode also fails, the source is too damaged and the creator should re-upload.

---

## 11. Performance & Capacity Planning

### 11.1 Throughput Estimates

#### 11.1.1 Stream Copy Path (Fast Path)

| Step | Duration (typical) | Bottleneck |
|------|-------------------|------------|
| S3 download of source (1 GB file) | 5-15s | Network bandwidth (~100 MB/s to moto/S3) |
| ffmpeg stream copy extraction | 1-3s | Disk I/O (sequential read + write) |
| ffprobe duration check | 0.5s | CPU (negligible) |
| S3 upload of clip (50 MB) | 1-3s | Network bandwidth |
| DDB updates (2-3 writes) | <0.5s | DDB latency |
| **Total (stream copy)** | **8-22s** | **S3 download of large source** |

Throughput on a single worker: ~120-400 clips/hour (depending on source file size).

#### 11.1.2 Re-Encode Path (Fallback)

| Step | Duration (60s clip) | Duration (300s clip) | Bottleneck |
|------|--------------------|-----------------------|------------|
| S3 download | 5-15s | 5-15s | Network |
| ffmpeg re-encode (libx264 medium) | 15-45s | 60-180s | CPU (single-threaded x264) |
| ffprobe check | 0.5s | 0.5s | Negligible |
| S3 upload | 1-3s | 3-8s | Network |
| **Total (re-encode, 60s clip)** | **22-64s** | | **CPU (x264)** |
| **Total (re-encode, 300s clip)** | | **69-204s** | **CPU (x264)** |

Throughput on a single worker (re-encode only): ~18-60 clips/hour for 60-second clips.

#### 11.1.3 By Instance Size

| Instance Type | vCPUs | RAM | Concurrent Clips | Stream Copy/hr | Re-Encode/hr (60s clips) |
|---------------|-------|-----|-------------------|----------------|--------------------------|
| t3.medium | 2 | 4 GB | 1 | ~200 | ~40 |
| t3.large | 2 | 8 GB | 2 | ~400 | ~70 |
| c5.xlarge | 4 | 8 GB | 3 | ~600 | ~120 |
| c5.2xlarge | 8 | 16 GB | 5 | ~1000 | ~200 |

Note: Re-encode throughput assumes `libx264 -preset medium`. Using `-preset fast` doubles encode speed at ~10% quality cost.

### 11.2 Disk I/O Requirements

| Operation | Read IOPS | Write IOPS | Bandwidth |
|-----------|-----------|------------|-----------|
| Source download to scratch | 0 | 500-2000 | 50-200 MB/s (write) |
| Stream copy extraction | 1000-3000 (seq read) | 500-1500 (seq write) | 50-150 MB/s |
| Re-encode extraction | 2000-5000 (random read) | 500-1500 (seq write) | 20-80 MB/s |
| Scratch cleanup | 0 | 50-200 | Negligible |

Recommended: SSD-backed scratch volume with at least 3000 IOPS and 125 MB/s throughput (AWS gp3 default).

### 11.3 Disk Space Requirements

Per active clip job:
- Source file: 100 MB - 10 GB (depends on original video length and bitrate)
- Clip output: 5 MB - 2 GB (proportional to clip duration / source duration)
- ffmpeg temp buffers: ~50 MB (moov atom rewrite for faststart)
- **Per-job peak**: source_size + clip_size + 50 MB

With 3 concurrent jobs and 2 GB average source:
```
Peak disk usage = 3 * (2 GB + 200 MB + 50 MB) = ~6.75 GB
Safety margin: 2x = ~14 GB
Recommended scratch volume: 20 GB minimum, 50 GB for headroom
```

### 11.4 S3 Bandwidth

| Direction | Per Clip (avg) | Per 100 Clips/hr |
|-----------|---------------|------------------|
| Download (source) | 500 MB - 2 GB | 50-200 GB/hr |
| Upload (clip output) | 30-200 MB | 3-20 GB/hr |
| **Total S3 traffic** | | **53-220 GB/hr** |

In the local dev stack (moto in-process), S3 I/O is loopback and does not consume real network bandwidth.

### 11.5 Concurrent Job Limits

| Config | Default | Purpose |
|--------|---------|---------|
| `MAX_CONCURRENT_CLIPS_PER_USER` | 3 | Prevents a single user from monopolizing the queue |
| `MAX_CONCURRENT_CLIP_WORKERS` | 2 | Per-process clip worker threads (shared with transcode workers) |
| `clip_queue_depth` alert threshold | 50 | Alerts when queue backs up beyond expected throughput |

Worker capacity planning formula:
```
Required workers = (clips_per_hour * avg_clip_duration_seconds) / 3600
Example: 200 clips/hr * 20s avg = 4000 worker-seconds/hr → ~1.1 workers needed
```

### 11.6 Queue Depth Monitoring

The worker loop polls for queued clip jobs on a configurable interval (default: 5 seconds). Queue depth is monitored via the `clip_queue_depth` gauge metric.

Expected steady-state queue depth:
```
queue_depth = arrival_rate * avg_processing_time
Example: 3 clips/min * 15s/clip = 0.75 (less than 1 -- queue stays near-empty)
```

Alert at queue_depth > 50 indicates arrival rate exceeds processing capacity for >12 minutes.

---

## 12. Dependency Analysis

### 12.1 Integration Points with Existing Systems

| System | Integration Type | How VOD-015 Uses It | Failure Impact |
|--------|-----------------|---------------------|----------------|
| **Transcode Job Queue** (`transcode_job_store.py`, VOD-003) | Read/Write | Creates clip jobs (`job_type="clip"`); creates follow-up transcode jobs | Clip jobs cannot be enqueued or tracked; clips fail silently |
| **FFmpeg Executor** (`ffmpeg_executor.py`, VOD-004) | Function call | `execute_rendition()` runs ffmpeg subprocess with resource limits | Clip extraction fails; no ffmpeg invocation possible |
| **FFmpeg Manager** (`ffmpeg_manager.py`, MEDIA-002) | Function call | `get_ffmpeg_path()` resolves binary; `validate_ffmpeg()` checks codec support | Cannot locate ffmpeg; clip jobs fail with `ffmpeg_not_available` |
| **ABR Pipeline** (`ffmpeg_abr_pipeline.py`) | Indirect (via transcode job) | After clip extraction, a standard transcode job sends the clip through ABR | Clip MP4 exists in S3 but has no HLS renditions; video stays in "pending_encoding" |
| **S3 Uploader** (`app/core/aws.py`) | Function call | Downloads source file; uploads clip output | Cannot access source or store clip; job fails |
| **Video Metadata Store** (`video_metadata_store.py`, VOD-001) | Read/Write | Reads source video metadata; creates new clip video record; updates clip provenance fields | Cannot validate source video or create clip record |
| **FFmpeg Prober** (`ffmpeg_prober.py` -- does not exist yet, must be created) | Read | Uses `duration_seconds` from probe data for range validation | Range validation impossible if video was never probed |
| **Thumbnail Extractor** (via ABR pipeline) | Indirect | Generates poster images for the clip video after ABR transcode | Clip plays but has no thumbnail/poster |
| **Video Listing API** (`video_listing.py`, VOD-006) | Modify | Extended to include clip provenance fields in response | Clip provenance not visible in API responses |
| **Billing/Wallet** (future) | None (Phase 1) | No billing for clipping in Phase 1 | N/A |

### 12.2 Blocked/Blocking Tickets

#### Tickets that block VOD-015:

| Ticket | What It Provides | Status | Hard/Soft Block |
|--------|-----------------|--------|-----------------|
| VOD-001 | Video metadata model and store | Completed | Hard: clip provenance fields extend this model |
| VOD-003 | Transcode job queue | Completed | Hard: clip jobs use this queue |
| VOD-004 | FFmpeg executor with resource limits | Completed | Hard: clip extraction uses `execute_rendition()` |
| VOD-005 | S3 upload outputs | Completed | Hard: clip files are uploaded to S3 |
| VOD-006 | Video listing API | Completed | Soft: clip endpoint is added to this router |
| MEDIA-002 | FFmpeg manager (path resolution, validation) | Completed | Hard: clip needs validated ffmpeg binary |

#### Tickets blocked by VOD-015:

| Ticket | What It Needs from VOD-015 | Status |
|--------|---------------------------|--------|
| VOD-016 (video concatenation) | Reuses clip extraction for segment pre-processing; shares `created_via` lineage model | Design |
| VOD-017 (video highlights reel) | Chains multiple clips into a reel; depends on clip provenance for source tracking | Backlog |
| BCAST-010 (broadcast clip sharing) | Creates clips from broadcast recordings; extends the clip API with `source_type="broadcast"` | Backlog |
| SOC-006 (clip sharing in feed) | Allows sharing clip links in newsfeed posts; depends on clip video existence | Backlog |

### 12.3 API Contract Commitments

The following API contracts are established by VOD-015 and must remain stable for downstream consumers:

| Contract | Consumers | Stability |
|----------|-----------|-----------|
| `POST /ui/videos/{video_id}/clip` request shape (`ClipVideoIn`) | Frontend `ClipDialog`, future mobile apps | Must remain backward-compatible; new optional fields only |
| Response shape (201 body with `video_id`, `clip_job_id`, etc.) | Frontend navigation to new video, job polling | Fields may be added but not removed or renamed |
| `source_video_id`, `clip_start_seconds`, `clip_end_seconds`, `created_via` on `VideoOut` | Frontend video detail display, VOD-016/VOD-017 | Must persist; `created_via` values may be extended (new enum values) |
| `job_type="clip"` in transcode_jobs table | Worker dispatch, monitoring dashboards | Fixed string; cannot be renamed |
| Error codes in error matrix (Section 7) | Frontend error handling, monitoring alerts | Codes may be added but not removed or reassigned |

---

## 13. Frontend Component Specifications

### 13.1 ClipDialog Component

**File**: `frontend/src/components/shared/ClipDialog.tsx`

```typescript
// ---- Props ----
interface ClipDialogProps {
  /** ID of the source video to clip */
  videoId: string;
  /** Total duration of the source video in seconds */
  durationSeconds: number;
  /** Original video title (used for default clip title) */
  title: string;
  /** Dialog open state */
  open: boolean;
  /** Callback when dialog open state changes */
  onOpenChange: (open: boolean) => void;
  /** Optional: source video poster URL for preview thumbnail */
  posterUrl?: string;
  /** Optional: HLS URL for in-dialog preview playback */
  hlsUrl?: string;
}

// ---- Internal State ----
interface ClipDialogState {
  /** Start of the clip range in seconds */
  startSeconds: number;                   // default: 0
  /** End of the clip range in seconds */
  endSeconds: number;                     // default: min(durationSeconds, 60)
  /** User-specified title for the clip */
  clipTitle: string;                      // default: `${title} (clip)`
  /** Whether the preview is currently playing */
  previewPlaying: boolean;                // default: false
  /** Current playback position in the preview (for scrubber sync) */
  previewPosition: number;               // default: startSeconds
  /** Whether to force re-encode (bypass stream copy) */
  forceReencode: boolean;                 // default: false
  /** Validation errors keyed by field name */
  errors: Record<string, string | null>;  // default: {}
}

// ---- Validation Logic ----
function validateClipRange(
  startSeconds: number,
  endSeconds: number,
  durationSeconds: number,
  minClipDuration: number = 5,
  maxClipDuration: number = 14400,
): Record<string, string | null> {
  const errors: Record<string, string | null> = {};
  if (startSeconds < 0) errors.start = "Start must be 0 or later";
  if (endSeconds > durationSeconds) errors.end = "End exceeds video duration";
  if (startSeconds >= endSeconds) errors.range = "Start must be before end";
  const dur = endSeconds - startSeconds;
  if (dur < minClipDuration) errors.duration = `Clip must be at least ${minClipDuration} seconds`;
  if (dur > maxClipDuration) errors.duration = `Clip cannot exceed ${maxClipDuration} seconds`;
  return errors;
}

// ---- React Query Hook ----
function useClipVideo() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (params: { videoId: string; body: ClipVideoRequest }) =>
      clipVideo(params.videoId, params.body),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["videos"] });
      queryClient.invalidateQueries({ queryKey: ["transcode-jobs"] });
      toast.success("Clip job started! You'll be notified when it's ready.");
    },
    onError: (error: AxiosError<{ detail: string }>) => {
      toast.error(error.response?.data?.detail || "Failed to create clip");
    },
  });
}
```

### 13.2 TimelineSlider Component

**File**: `frontend/src/components/shared/TimelineSlider.tsx`

```typescript
// ---- Props ----
interface TimelineSliderProps {
  /** Total duration of the source video in seconds */
  durationSeconds: number;
  /** Current start position in seconds */
  startSeconds: number;
  /** Current end position in seconds */
  endSeconds: number;
  /** Callback when start or end changes */
  onRangeChange: (start: number, end: number) => void;
  /** Step size in seconds (default: 0.1 for 100ms precision) */
  step?: number;
  /** Optional: keyframe positions for snap indicators */
  keyframes?: number[];
  /** Optional: thumbnail sprites for visual timeline */
  thumbnailSpriteUrl?: string;
  /** Optional: number of thumbnail sprites in the sprite sheet */
  thumbnailCount?: number;
  /** Whether the slider is disabled */
  disabled?: boolean;
  /** Optional: current playback position for preview indicator */
  playbackPosition?: number;
}

// ---- Internal State ----
interface TimelineSliderState {
  /** Which handle is being dragged ("start" | "end" | null) */
  activeHandle: "start" | "end" | null;
  /** Whether the user is hovering over the timeline (shows time tooltip) */
  hovering: boolean;
  /** X position of hover for time tooltip */
  hoverX: number;
  /** Computed time at the hover position */
  hoverTime: number;
}

// ---- Keyboard Shortcuts ----
// When the timeline slider is focused:
//
// Arrow Left / Arrow Right:  Move active handle by 1 step (0.1s)
// Shift + Arrow Left/Right:  Move active handle by 1 second
// Ctrl + Arrow Left/Right:   Move active handle by 10 seconds
// Alt + Arrow Left/Right:    Move active handle to previous/next keyframe
// Home:                      Set active handle to 0 (start) or startSeconds (end)
// End:                       Set active handle to endSeconds (start) or durationSeconds (end)
// Tab:                       Switch active handle between start and end
// Space:                     Toggle preview playback
// [ (left bracket):          Set start to current playback position
// ] (right bracket):         Set end to current playback position

// ---- Accessibility ----
// - Uses role="slider" with aria-valuemin, aria-valuemax, aria-valuenow
// - Each handle is independently focusable
// - aria-label: "Clip start time" / "Clip end time"
// - Announces time changes via aria-live="polite" region
```

### 13.3 ClipPreview Component

**File**: `frontend/src/components/shared/ClipPreview.tsx`

```typescript
// ---- Props ----
interface ClipPreviewProps {
  /** HLS URL of the source video */
  hlsUrl: string;
  /** Start of the preview range in seconds */
  startSeconds: number;
  /** End of the preview range in seconds */
  endSeconds: number;
  /** Callback when playback position changes (for scrubber sync) */
  onPositionChange?: (positionSeconds: number) => void;
  /** Whether to auto-play the preview when range changes */
  autoPlay?: boolean;
  /** CSS class for the video container */
  className?: string;
}

// ---- Internal State ----
interface ClipPreviewState {
  /** Whether the preview is currently playing */
  playing: boolean;
  /** Current playback position in seconds */
  currentTime: number;
  /** Whether the video source is loaded and ready */
  ready: boolean;
  /** Whether the preview is looping */
  looping: boolean;   // default: true
}

// ---- Behavior ----
// - Uses hls.js (or native HLS) to load the source video
// - Seeks to startSeconds when the range changes
// - Pauses playback when currentTime reaches endSeconds
// - If looping is enabled, seeks back to startSeconds after reaching endSeconds
// - Throttles onPositionChange callbacks to 100ms intervals to avoid excessive
//   re-renders of the timeline slider
// - Displays current time overlay: "00:30 / 01:00" (currentTime / clipDuration)

// ---- React Query Integration ----
// No server calls; purely client-side video playback
// Uses the same hls.js instance pattern as LivePlayer.tsx
```

### 13.4 Video Detail Provenance Display

When viewing a clip in the video detail page, the following provenance information is shown:

```typescript
// In VideoPlayerPage.tsx, added below the video title
interface ClipProvenanceProps {
  sourceVideoId: string;
  clipStartSeconds: number;
  clipEndSeconds: number;
  createdVia: string;
}

function ClipProvenance({ sourceVideoId, clipStartSeconds, clipEndSeconds, createdVia }: ClipProvenanceProps) {
  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground">
      <Scissors className="h-3.5 w-3.5" />
      <span>
        Clipped from{" "}
        <Link to={`/videos/${sourceVideoId}`} className="underline hover:text-foreground">
          original video
        </Link>
        {" "}({formatTimestamp(clipStartSeconds)} – {formatTimestamp(clipEndSeconds)})
      </span>
    </div>
  );
}
```

### 13.5 Clip Status Polling

While a clip job is processing, the video detail page polls for status:

```typescript
function useClipJobStatus(clipJobId: string | null) {
  return useQuery({
    queryKey: ["transcode-jobs", clipJobId],
    queryFn: () => getTranscodeJob(clipJobId!),
    enabled: !!clipJobId,
    refetchInterval: (data) => {
      if (!data) return 3000;
      const status = data.status;
      if (status === "completed" || status === "failed" || status === "cancelled") {
        return false; // Stop polling
      }
      return 3000; // Poll every 3 seconds
    },
  });
}
```

---

## 14. Acceptance Criteria

### 14.1 Happy Path

| # | Criterion | Pass Condition |
|---|-----------|----------------|
| AC-01 | Creator clips a published video with a valid time range | POST returns 201; new video record created with `created_via="clip"` and correct `source_video_id`, `clip_start_seconds`, `clip_end_seconds` |
| AC-02 | Clip job completes via stream copy path | Job transitions queued -> running -> completed; `method="copy"`; total processing time < 30 seconds for a 1 GB source |
| AC-03 | Clip video has HLS renditions after processing | After clip job + transcode job complete, `GET /ui/videos/{clip_id}` returns HLS URL; video plays in the browser |
| AC-04 | Clip title defaults to "{original title} (clip)" | When no title is provided in the request, the new video's title ends with "(clip)" |
| AC-05 | Clip title accepts custom value | When a title is provided, the new video uses that title verbatim |
| AC-06 | Clip appears in creator's video library | `GET /ui/videos` for the owner includes the new clip video |
| AC-07 | Clip video detail shows provenance link | Video detail page shows "Clipped from [original video]" with link to source and time range |

### 14.2 Edge Cases

| # | Criterion | Pass Condition |
|---|-----------|----------------|
| AC-08 | Clip at video start (start=0) | Produces valid clip; no leading artifacts |
| AC-09 | Clip at video end (end=duration) | Produces valid clip; no trailing silence or black frames |
| AC-10 | Clip of entire video (start=0, end=duration) | Produces a re-muxed copy; original unchanged |
| AC-11 | Clip of a clip (re-clip) | Produces a new video; `source_video_id` points to the intermediate clip, not the root original |
| AC-12 | Clip with keyframe misalignment triggers re-encode | When stream copy output deviates >2s from expected duration, job automatically retries with re-encode and succeeds |
| AC-13 | Concurrent clips of the same source video | Both clips succeed independently; source video unchanged |

### 14.3 Error Handling

| # | Criterion | Pass Condition |
|---|-----------|----------------|
| AC-14 | Invalid range returns 400 | `start >= end`, `end > duration`, `duration < 5s` all return 400 with descriptive message |
| AC-15 | Non-owner receives 403 | A user who does not own the video receives 403 "forbidden" |
| AC-16 | Unpublished video returns 409 | Video in "encoding" or "created" status returns 409 "video must be published or approved" |
| AC-17 | Source file missing from S3 during job | Job fails with `error_code="source_not_found"`; job status="failed"; no orphaned files on disk |

### 14.4 Performance

| # | Criterion | Pass Condition |
|---|-----------|----------------|
| AC-18 | Stream copy clip completes within 30 seconds | For a 1 GB source video, the clip job (download + extract + upload) finishes in < 30s |
| AC-19 | POST endpoint responds within 500ms | The clip creation request (validation + DDB writes) returns within 500ms p99 |
| AC-20 | Scratch directory is cleaned up after job | After job completion (success or failure), no files remain in the scratch directory |

### 14.5 UX

| # | Criterion | Pass Condition |
|---|-----------|----------------|
| AC-21 | Clip button only visible to video owner | Non-owners and unauthenticated users do not see the Clip button |
| AC-22 | Clip button only visible for published videos | Videos in "encoding", "created", or "failed" status do not show the Clip button |
| AC-23 | Timeline slider supports keyboard navigation | Left/Right arrows move handles; Shift+arrow for 1s steps; frame-by-frame scrubbing works |
| AC-24 | Clip dialog shows validation errors inline | Invalid time range shows red error text below the slider; Create Clip button is disabled |
| AC-25 | Clip creation shows success toast and navigates | After successful POST, a success toast appears and the page navigates to the new video's detail page |
| AC-26 | Clip job status is visible during processing | The new video's detail page shows a progress indicator while the clip job is running |

---

## Appendix E: ffmpeg Command Reference

### E.1 Stream Copy Clip (Fast, No Re-Encode)

```bash
ffmpeg -hide_banner -loglevel warning -y \
  -ss 30.0 \
  -to 90.0 \
  -i /tmp/scratch/clip-tj_abc123/source.mp4 \
  -c copy \
  -avoid_negative_ts make_zero \
  -movflags +faststart \
  /tmp/scratch/clip-tj_abc123/clip.mp4
```

**Flag breakdown**:

| Flag | Purpose |
|------|---------|
| `-hide_banner` | Suppress ffmpeg version/build info in output |
| `-loglevel warning` | Only show warnings and errors (reduce log noise) |
| `-y` | Overwrite output file without prompting (required for re-encode fallback to overwrite the stream copy attempt) |
| `-ss 30.0` | Seek to 30 seconds in the input. Placed BEFORE `-i` for input seeking: ffmpeg seeks to the nearest keyframe before 30s, then discards frames until exactly 30s. This is much faster than output seeking (placed after `-i`) because it avoids decoding the skipped portion. |
| `-to 90.0` | Stop reading input at 90 seconds (absolute timestamp). Note: `-to` is an absolute position; `-t` would be a relative duration (60 seconds). We use `-to` for clarity. |
| `-i source.mp4` | Input file path |
| `-c copy` | Copy all streams (video + audio + subtitles) without re-encoding. This is a "stream copy" or "remux" operation. Extremely fast because it just copies compressed packets. |
| `-avoid_negative_ts make_zero` | Shift timestamps so the output starts at PTS=0. Without this, stream copy may produce negative timestamps at the cut point, causing playback issues in some players. `make_zero` shifts all streams' timestamps by the same offset. |
| `-movflags +faststart` | Move the MP4 moov atom to the beginning of the file. This enables progressive download / streaming without buffering the entire file. Requires a second pass over the output to rewrite the header. |

**When this works well**: H.264/H.265 content with keyframe intervals <= 2 seconds (typical for live-encoded content with `-g 60` at 30fps).

**When this fails**: Content with infrequent keyframes (10+ seconds apart), variable frame rate, or mixed codec streams.

### E.2 Re-Encode Clip (Frame-Accurate, Slower)

```bash
ffmpeg -hide_banner -loglevel warning -y \
  -ss 30.0 \
  -to 90.0 \
  -i /tmp/scratch/clip-tj_abc123/source.mp4 \
  -c:v libx264 -preset medium -crf 22 \
  -c:a aac -b:a 128k \
  -movflags +faststart \
  /tmp/scratch/clip-tj_abc123/clip.mp4
```

**Additional flags (beyond stream copy)**:

| Flag | Purpose |
|------|---------|
| `-c:v libx264` | Encode the video stream using the H.264 (AVC) codec via libx264. This is the most widely supported codec for web playback. |
| `-preset medium` | x264 encoding speed preset. `medium` is the default balance of speed vs. compression efficiency. Faster presets (`fast`, `ultrafast`) produce larger files but encode faster. Slower presets (`slow`, `veryslow`) compress better but take much longer. |
| `-crf 22` | Constant Rate Factor: quality target for x264. Range 0-51 where 0=lossless, 23=default, 51=worst. CRF 22 is slightly better than default quality. Each +-6 roughly halves/doubles the bitrate. CRF ensures consistent visual quality regardless of scene complexity. |
| `-c:a aac` | Encode the audio stream using the AAC codec (built-in ffmpeg AAC encoder). |
| `-b:a 128k` | Target audio bitrate: 128 kbps. Standard quality for stereo audio. |

**Why `-avoid_negative_ts` is omitted**: Re-encode always produces correct timestamps starting from 0 because it fully decodes and re-encodes. The negative timestamp issue only affects stream copy.

### E.3 Keyframe-Aligned Clip (Precise Stream Copy)

For cases where stream copy is desired but exact keyframe alignment is needed:

```bash
# Step 1: Find the nearest keyframe before the start time
ffprobe -v quiet -select_streams v:0 \
  -show_entries frame=key_frame,pts_time \
  -read_intervals "25%+#20" \
  -of csv=p=0 \
  /tmp/scratch/clip-tj_abc123/source.mp4 \
  | awk -F',' '$1==1 && $2<=30 {last=$2} END {print last}'
# Output: 28.5 (nearest keyframe at or before 30s)

# Step 2: Find the nearest keyframe after the end time
ffprobe -v quiet -select_streams v:0 \
  -show_entries frame=key_frame,pts_time \
  -read_intervals "88%+#20" \
  -of csv=p=0 \
  /tmp/scratch/clip-tj_abc123/source.mp4 \
  | awk -F',' '$1==1 && $2>=90 {print $2; exit}'
# Output: 91.0 (nearest keyframe at or after 90s)

# Step 3: Stream copy using aligned keyframe boundaries
ffmpeg -hide_banner -loglevel warning -y \
  -ss 28.5 \
  -to 91.0 \
  -i /tmp/scratch/clip-tj_abc123/source.mp4 \
  -c copy \
  -avoid_negative_ts make_zero \
  -movflags +faststart \
  /tmp/scratch/clip-tj_abc123/clip.mp4
```

**Flag breakdown for ffprobe**:

| Flag | Purpose |
|------|---------|
| `-select_streams v:0` | Only examine the first video stream |
| `-show_entries frame=key_frame,pts_time` | Output only keyframe flag and presentation timestamp |
| `-read_intervals "25%+#20"` | Start reading at 25 seconds, read 20 frames. Avoids scanning the entire file. |
| `-of csv=p=0` | Output as CSV without section headers |

**Note**: This approach is NOT used in the default Phase 1 implementation. It is documented for future optimization. The current approach uses the simpler "try stream copy, fall back to re-encode" strategy. Keyframe-aligned clipping would eliminate the fallback in most cases but adds complexity (two ffprobe calls per clip).

### E.4 Audio-Only Clip

For extracting audio-only segments (future feature, not in Phase 1 scope):

```bash
ffmpeg -hide_banner -loglevel warning -y \
  -ss 30.0 \
  -to 90.0 \
  -i /tmp/scratch/clip-tj_abc123/source.mp4 \
  -vn \
  -c:a copy \
  -movflags +faststart \
  /tmp/scratch/clip-tj_abc123/clip.m4a
```

**Additional flags**:

| Flag | Purpose |
|------|---------|
| `-vn` | Disable video stream entirely. Only audio is output. |
| `-c:a copy` | Copy the audio stream without re-encoding. Audio codecs (AAC, MP3, Opus) have much smaller keyframe alignment issues than video, so stream copy almost always works. |
| Output: `clip.m4a` | M4A container (MPEG-4 audio). Alternatively use `.mp3` with `-c:a libmp3lame -q:a 2` for MP3 output. |

**When to re-encode audio**:

```bash
ffmpeg -hide_banner -loglevel warning -y \
  -ss 30.0 \
  -to 90.0 \
  -i /tmp/scratch/clip-tj_abc123/source.mp4 \
  -vn \
  -c:a aac -b:a 192k \
  -movflags +faststart \
  /tmp/scratch/clip-tj_abc123/clip.m4a
```

Use re-encode when the source audio codec is not AAC (e.g., PCM, FLAC, Vorbis) and the target container requires AAC.

### E.5 Clip with Watermark Overlay (Future Enhancement)

For branded clips with a watermark burned in during re-encode:

```bash
ffmpeg -hide_banner -loglevel warning -y \
  -ss 30.0 \
  -to 90.0 \
  -i /tmp/scratch/clip-tj_abc123/source.mp4 \
  -i /app/static/uploads/watermarks/user_watermark.png \
  -filter_complex "[0:v][1:v]overlay=W-w-10:H-h-10:format=auto[out]" \
  -map "[out]" -map 0:a \
  -c:v libx264 -preset medium -crf 22 \
  -c:a aac -b:a 128k \
  -movflags +faststart \
  /tmp/scratch/clip-tj_abc123/clip.mp4
```

**Additional flags**:

| Flag | Purpose |
|------|---------|
| `-i watermark.png` | Second input: the watermark image |
| `-filter_complex "[0:v][1:v]overlay=W-w-10:H-h-10"` | Overlay the watermark on the bottom-right corner, 10px from edges. `W`/`H` = main video dimensions; `w`/`h` = watermark dimensions. |
| `-map "[out]"` | Use the composited video output |
| `-map 0:a` | Use audio from the first input (source video) |

**Note**: Watermark overlay requires re-encode (cannot use stream copy with filters). This is handled by the existing `build_rendition_ffmpeg_args()` in the ABR pipeline, not in the clip extraction step. The clip extraction produces a clean MP4; the watermark is applied during the subsequent ABR transcode if the user has a watermark configured.

### E.6 Diagnostic Commands

Useful commands for debugging clip issues:

```bash
# Check video duration and format
ffprobe -v quiet -print_format json -show_format source.mp4

# List all keyframes with timestamps
ffprobe -v quiet -select_streams v:0 \
  -show_entries frame=key_frame,pts_time \
  -of csv=p=0 source.mp4 | grep "^1," | head -20

# Count total keyframes
ffprobe -v quiet -select_streams v:0 \
  -show_entries frame=key_frame \
  -of csv=p=0 source.mp4 | grep -c "^1"

# Check codec and stream info
ffprobe -v quiet -show_streams source.mp4

# Verify output integrity (decode entire file, check for errors)
ffmpeg -v error -i clip.mp4 -f null - 2>&1

# Compare source and clip durations
echo "Source:" && ffprobe -v quiet -show_entries format=duration -of csv=p=0 source.mp4
echo "Clip:" && ffprobe -v quiet -show_entries format=duration -of csv=p=0 clip.mp4

# Check if moov atom is at the beginning (faststart)
ffprobe -v trace clip.mp4 2>&1 | grep -i "moov" | head -5
```
